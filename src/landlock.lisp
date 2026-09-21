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
(defconstant +landlock-rule-net-port+          2)

;;; Network access rights, from ABI 4.  Landlock governs ports rather than
;;; addresses: it can say "TCP 443 and nothing else", not "api.example.com".
;;; That is less than a proxy offers and far more than nothing, and it needs no
;;; proxy, no certificate authority and no second process.
(defconstant +access-net-bind-tcp+    (ash 1 0))
(defconstant +access-net-connect-tcp+ (ash 1 1))
(defconstant +landlock-net-abi+ 4)

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
(defconstant +fs-resolve-unix+ (ash 1 16)) ; ABI 9

(defun require-unix-isolation (abi)
  (when (< abi 9)
    (setup-error :landlock-unix
                 :detail "Unix sockets and learning require Landlock ABI 9 to isolate host control sockets")))

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
file; asking for the rest is an error, not a stronger sandbox.

:CONNECT is the one kind that does not go through the ABI mask, because
RESOLVE_UNIX is deliberately absent from it: no ordinary rule may grant it, not
even a rule on \"/\", so it is written here and nowhere else."
  (if (eq kind :connect)
      +fs-resolve-unix+
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
                (if directoryp #xffffffffffffffff (lognot +directory-only-rights+))))))

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

(defun trim-trailing-slash (path)
  "PATH without a trailing slash -- except the root, which is only a slash.
Trimming the root down to an empty string is how a policy naming \"/\" would
turn into a rule the kernel cannot open."
  (let ((trimmed (string-right-trim "/" path)))
    (if (zerop (length trimmed)) "/" trimmed)))

(defun rule-covers-p (rule path)
  "Whether PATH lies at or beneath RULE's path."
  (let ((base (trim-trailing-slash (path-rule-path rule))))
    (cond ((string= "/" base)
           (and (plusp (length path)) (char= #\/ (char path 0))))
          ((string= base path) t)
          (t (and (< (length base) (length path))
                  (string= base path :end2 (length base))
                  (char= #\/ (char path (length base))))))))

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

(defun create-ruleset (handled-rights &optional (handled-net 0))
  "Create a Landlock ruleset handling HANDLED-RIGHTS and HANDLED-NET.
One ruleset carries both, which is the whole of Cave's constraint: rights that
are handled in separate rulesets deny each other by implication."
  (cffi:with-foreign-object (attr :uint64 2)
    (setf (cffi:mem-aref attr :uint64 0) handled-rights   ; handled_access_fs
          (cffi:mem-aref attr :uint64 1) handled-net)     ; handled_access_net
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

(defun add-port-rule (ruleset port rights)
  "Allow RIGHTS on PORT in RULESET."
  ;; struct landlock_net_port_attr: an access mask and a port, both 64 bits.
  (cffi:with-foreign-object (attr :uint64 2)
    (setf (cffi:mem-aref attr :uint64 0) rights
          (cffi:mem-aref attr :uint64 1) port)
    (when (minusp (cffi:foreign-funcall "syscall"
                                        :long +sys-landlock-add-rule+
                                        :int ruleset
                                        :unsigned-long +landlock-rule-net-port+
                                        :pointer attr
                                        :unsigned-long 0
                                        :long))
      (setup-error :landlock-add-port-rule :errno (errno)
                   :detail (format nil "tcp port ~D" port)))))

(defun handled-network-rights (connect-ports bind-ports abi)
  "What the ruleset must handle for the ports a policy named.
Handling a right is what makes everything not granted a refusal, so a policy
that names no ports handles nothing and leaves the network as it found it."
  (when (or connect-ports bind-ports)
    (when (< abi +landlock-net-abi+)
      (setup-error :landlock-network
                   :detail (format nil "this kernel's Landlock is ABI ~D, and ~
                                        network rules arrived in ABI ~D"
                                   abi +landlock-net-abi+)))
    (logior (if connect-ports +access-net-connect-tcp+ 0)
            (if bind-ports +access-net-bind-tcp+ 0))))

(defun compile-filesystem-ruleset (rules executable &key connect-ports bind-ports isolate-unix)
  "Build the one ruleset that RULES and the named ports describe.
Answers NIL when a policy asked for none of them.  Returns the ruleset
descriptor and the ABI version it was built for.

Paths and ports go in the same ruleset, which is the whole of Cave's
constraint: rights handled in separate rulesets deny each other by implication."
  (when (or rules connect-ports bind-ports isolate-unix)
    (let* ((abi (require-landlock))
           (handled-net (or (handled-network-rights connect-ports bind-ports abi) 0)))
      (when (or isolate-unix (find :connect rules :key #'path-rule-kind))
        (require-unix-isolation abi))
      (when rules
        (ensure-executable-permitted rules executable abi))
      ;; Never grant RESOLVE_UNIX through an ordinary path rule, even a grant of
      ;; /.  ABI 9 permits sockets created in this domain without granting access
      ;; to preexisting host sockets, including the same-uid broker control API.
      ;; One kind of rule does grant it, and only for the path it names: connect,
      ;; which a policy writes out socket by socket and which the validator keeps
      ;; away from the broker's own.
      (let ((ruleset (create-ruleset (logior (if rules (supported-rights abi) 0)
                                            (if (or isolate-unix
                                                    (find :connect rules
                                                          :key #'path-rule-kind))
                                                +fs-resolve-unix+
                                                0))
                                     handled-net)))
        (handler-bind ((error (lambda (condition)
                                (declare (ignore condition))
                                (%close ruleset))))
          (dolist (rule rules)
            (add-path-rule ruleset (path-rule-path rule)
                           (rule-rights rule abi)))
          (dolist (port connect-ports)
            (add-port-rule ruleset port +access-net-connect-tcp+))
          (dolist (port bind-ports)
            (add-port-rule ruleset port +access-net-bind-tcp+)))
        (values ruleset abi)))))

(declaim (inline %landlock-restrict-self))
(defun %landlock-restrict-self (ruleset)
  "Enforce RULESET on the calling thread.  Needs no_new_privs already set."
  (cffi:foreign-funcall "syscall"
                        :long +sys-landlock-restrict-self+
                        :int ruleset
                        :unsigned-long 0
                        :long))

;;── Reading a ruleset back ─────────────────────────────────────────────────────
;;
;;; A policy is a set of rules; what a person wants to know is whether their
;;; build will be able to write somewhere.  Answering that by hand means holding
;;; Landlock's access rights in your head, so Scute answers it instead.

(defparameter +access-questions+
  (list (cons :read +fs-read-file+)
        (cons :write +fs-write-file+)
        (cons :execute +fs-execute+))
  "The three things anyone actually asks of a path, and the right each needs.

One right each, and deliberately not the directory-only ones.  READ_DIR and
MAKE_REG are stripped from any rule that names a file rather than a directory,
so asking for them would make every rule on a file -- /dev/null and /dev/tty
being the everyday cases -- look as though it granted nothing at all.")

(defun nearest-existing-path (path)
  "PATH if it exists, or the deepest ancestor of it that does.
A policy is often checked against a path a command has yet to create, and what
governs creating it is the directory it will appear in."
  (labels ((walk (pathname)
             (cond ((probe-file pathname) (probe-file pathname))
                   (t (let ((parent (uiop:pathname-parent-directory-pathname
                                     (uiop:ensure-directory-pathname pathname))))
                        (unless (equal parent (uiop:ensure-directory-pathname pathname))
                          (walk parent)))))))
    (walk path)))

(defun granting-rule (rules path access abi)
  "The rule in RULES that grants ACCESS at PATH, or NIL if none does."
  (let ((wanted (cdr (assoc access +access-questions+))))
    (find-if (lambda (rule)
               (and (rule-covers-p rule path)
                    (= wanted (logand wanted (rule-rights rule abi)))))
             rules)))

(defun path-access-report (rules path)
  "What RULES allow at PATH: an alist of access kind to the rule granting it.
Answers the path actually examined as a second value, which differs from PATH
when PATH does not exist yet."
  (let* ((abi (or (landlock-abi-version) 1))
         (existing (nearest-existing-path path))
         (examined (and existing (trim-trailing-slash (namestring existing)))))
    (values (when examined
              (loop for (access . nil) in +access-questions+
                    collect (cons access (granting-rule rules examined access abi))))
            examined)))
