;;; landlock.lisp
;;;
;;; SPDX-License-Identifier: MIT
;;;
;;; Copyright (C) 2026 Anthony Green

(in-package #:scute)

;;; The filesystem layer, spoken to the kernel directly.
;;;
;;; Scute builds one Landlock ruleset and enforces it once.  Installing
;;; filesystem and network rights as two stacked rulesets is what makes
;;; LANDLOCK_ACCESS_FS_REFER implicitly denied, turning legal cross-directory
;;; renames into EXDEV; a single ruleset cannot stack with itself, so the
;;; hazard does not arise.
;;;
;;; The work splits along the same line as everything else here: the parent
;;; resolves paths and builds the ruleset, because that needs Lisp, and the
;;; child spends one syscall enforcing it.

;;── Syscalls ───────────────────────────────────────────────────────────────────

(defconstant +sys-landlock-create-ruleset+ 444)
(defconstant +sys-landlock-add-rule+       445)
(defconstant +sys-landlock-restrict-self+  446)

(defconstant +landlock-create-ruleset-version+ 1)
(defconstant +landlock-rule-path-beneath+      1)

(defconstant +o-path+      #o10000000)
(defconstant +o-directory+   #o200000)

;;── Access rights ──────────────────────────────────────────────────────────────

(defconstant +fs-execute+     (ash 1  0))
(defconstant +fs-write-file+  (ash 1  1))
(defconstant +fs-read-file+   (ash 1  2))
(defconstant +fs-read-dir+    (ash 1  3))
(defconstant +fs-remove-dir+  (ash 1  4))
(defconstant +fs-remove-file+ (ash 1  5))
(defconstant +fs-make-char+   (ash 1  6))
(defconstant +fs-make-dir+    (ash 1  7))
(defconstant +fs-make-reg+    (ash 1  8))
(defconstant +fs-make-sock+   (ash 1  9))
(defconstant +fs-make-fifo+   (ash 1 10))
(defconstant +fs-make-block+  (ash 1 11))
(defconstant +fs-make-sym+    (ash 1 12))
(defconstant +fs-refer+       (ash 1 13))   ; ABI 2
(defconstant +fs-truncate+    (ash 1 14))   ; ABI 3
(defconstant +fs-ioctl-dev+   (ash 1 15))   ; ABI 5

;;; The rights each ABI version added.  Scute handles everything the running
;;; kernel understands, so that whatever a rule does not grant is denied.
(defparameter +rights-by-abi+
  (list (cons 1 (logior +fs-execute+ +fs-write-file+ +fs-read-file+ +fs-read-dir+
                        +fs-remove-dir+ +fs-remove-file+ +fs-make-char+
                        +fs-make-dir+ +fs-make-reg+ +fs-make-sock+
                        +fs-make-fifo+ +fs-make-block+ +fs-make-sym+))
        (cons 2 +fs-refer+)
        (cons 3 +fs-truncate+)))

;;; LANDLOCK_ACCESS_FS_IOCTL_DEV is deliberately left unhandled in v0.  Handling
;;; it without granting it breaks tcsetattr on a terminal, and an interactive
;;; shell nobody can run is not a useful sandbox.  Device ioctls are out of
;;; scope for v0, not silently weakened: the design says so.

(defun supported-rights (abi)
  "Every access right the kernel at ABI understands."
  (reduce #'logior +rights-by-abi+
          :key (lambda (entry) (if (<= (car entry) abi) (cdr entry) 0))
          :initial-value 0))

(defparameter +directory-only-rights+
  (logior +fs-read-dir+ +fs-remove-dir+ +fs-remove-file+ +fs-make-char+
          +fs-make-dir+ +fs-make-reg+ +fs-make-sock+ +fs-make-fifo+
          +fs-make-block+ +fs-make-sym+ +fs-refer+)
  "Rights the kernel accepts only on a directory.  Offer one of these for a
regular file or a device and landlock_add_rule answers EINVAL.")

(defparameter +access-kinds+
  '(:read :read-execute :read-write :read-write-execute)
  "The filesystem permissions a policy may ask for, weakest first.")

(defun kind-rights (kind abi &key (directoryp t))
  "The access rights KIND stands for on a kernel at ABI.
A rule on anything but a directory keeps only the rights that apply to a
file; asking for the rest is an error, not a stronger sandbox."
  (let* ((read (logior +fs-read-file+ +fs-read-dir+))
         (write (logior +fs-write-file+ +fs-remove-dir+ +fs-remove-file+
                        +fs-make-char+ +fs-make-dir+ +fs-make-reg+
                        +fs-make-sock+ +fs-make-fifo+ +fs-make-block+
                        +fs-make-sym+ +fs-refer+ +fs-truncate+))
         (rights (ecase kind
                   (:read read)
                   (:read-execute (logior read +fs-execute+))
                   (:read-write (logior read write))
                   (:read-write-execute (logior read write +fs-execute+)))))
    (logand rights (supported-rights abi)
            (if directoryp #xffffffffffffffff (lognot +directory-only-rights+)))))

;;── Probing ────────────────────────────────────────────────────────────────────

(defun landlock-abi-version ()
  "The Landlock ABI version this kernel supports, or NIL if it has none."
  (let ((version (cffi:foreign-funcall "syscall"
                                       :long +sys-landlock-create-ruleset+
                                       :pointer (cffi:null-pointer)
                                       :unsigned-long 0
                                       :unsigned-long +landlock-create-ruleset-version+
                                       :long)))
    (when (plusp version) version)))

(defun require-landlock ()
  "The kernel's Landlock ABI version, or a refusal to continue without one."
  (or (landlock-abi-version)
      (setup-error :probe-landlock
                   :detail "this kernel does not implement Landlock")))

;;── Rules ──────────────────────────────────────────────────────────────────────

(defstruct (path-rule (:constructor make-path-rule (kind path directoryp)))
  "A resolved rule: one canonical path, and the access granted beneath it.
Policies declare FILESYSTEM-RULEs; compiling a launch plan resolves each into
one of these, which is what the kernel is eventually told about."
  (kind nil :read-only t)
  (path nil :read-only t)
  (directoryp nil :read-only t))

(defun rule-rights (rule abi)
  "The rights RULE grants, as the kernel will accept them for its path."
  (kind-rights (path-rule-kind rule) abi
               :directoryp (path-rule-directoryp rule)))

(defun rule-covers-p (rule path)
  "Whether PATH lies at or beneath RULE's path."
  (let ((base (string-right-trim "/" (path-rule-path rule))))
    (or (string= base path)
        (and (<= (length base) (length path))
             (string= base path :end2 (length base))
             (char= #\/ (char path (length base)))))))

(defun ensure-executable-permitted (rules executable abi)
  "Refuse a launch whose own command no rule allows to execute.
Landlock would answer EACCES at execve, which reads as a broken command
rather than as the policy decision it is."
  (let ((path (namestring (or (probe-file executable)
                              (setup-error :resolve-executable
                                           :detail (format nil "~A does not exist"
                                                           executable))))))
    (unless (some (lambda (rule)
                    (and (rule-covers-p rule path)
                         (plusp (logand +fs-execute+ (rule-rights rule abi)))))
                  rules)
      (setup-error :executable-not-permitted
                   :detail (format nil "no rule grants execute access to ~A" path)))))

;;── One ruleset ────────────────────────────────────────────────────────────────

(defun create-ruleset (handled-rights)
  "Create a Landlock ruleset handling HANDLED-RIGHTS.  Returns its descriptor."
  (cffi:with-foreign-object (attr :uint64 2)
    (setf (cffi:mem-aref attr :uint64 0) handled-rights   ; handled_access_fs
          (cffi:mem-aref attr :uint64 1) 0)               ; handled_access_net
    (let ((fd (cffi:foreign-funcall "syscall"
                                    :long +sys-landlock-create-ruleset+
                                    :pointer attr
                                    :unsigned-long 16
                                    :unsigned-long 0
                                    :long)))
      (when (minusp fd)
        (setup-error :landlock-create-ruleset :errno (errno)))
      fd)))

(defun add-path-rule (ruleset path allowed-rights)
  "Allow ALLOWED-RIGHTS at and beneath PATH in RULESET."
  (let ((parent (%open path (logior +o-path+ +o-cloexec+))))
    (when (minusp parent)
      (setup-error :landlock-open-rule-path :errno (errno) :detail path))
    (unwind-protect
         ;; struct landlock_path_beneath_attr is packed: a u64 followed
         ;; immediately by an s32, twelve bytes rather than sixteen.  Pad it
         ;; and the kernel answers EINVAL.
         (cffi:with-foreign-object (attr :uint8 12)
           (setf (cffi:mem-ref attr :uint64 0) allowed-rights
                 (cffi:mem-ref attr :int32 8) parent)
           (when (minusp (cffi:foreign-funcall "syscall"
                                               :long +sys-landlock-add-rule+
                                               :int ruleset
                                               :unsigned-long +landlock-rule-path-beneath+
                                               :pointer attr
                                               :unsigned-long 0
                                               :long))
             (setup-error :landlock-add-rule :errno (errno) :detail path)))
      (%close parent))))

(defun compile-filesystem-ruleset (rules executable)
  "Build the one ruleset that RULES describe, or NIL when there are none.
Returns the ruleset descriptor and the ABI version it was built for."
  (when rules
    (let ((abi (require-landlock)))
      (ensure-executable-permitted rules executable abi)
      (let ((ruleset (create-ruleset (supported-rights abi))))
        (handler-bind ((error (lambda (condition)
                                (declare (ignore condition))
                                (%close ruleset))))
          (dolist (rule rules)
            (add-path-rule ruleset (path-rule-path rule)
                           (rule-rights rule abi))))
        (values ruleset abi)))))

(declaim (inline %landlock-restrict-self))
(defun %landlock-restrict-self (ruleset)
  "Enforce RULESET on the calling thread.  Needs no_new_privs already set."
  (cffi:foreign-funcall "syscall"
                        :long +sys-landlock-restrict-self+
                        :int ruleset
                        :unsigned-long 0
                        :long))
