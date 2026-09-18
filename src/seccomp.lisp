;;; seccomp.lisp
;;;
;;; SPDX-License-Identifier: MIT
;;;
;;; Copyright (C) 2026 Anthony Green

(in-package #:scute)

;;; The v0 system-call filter.
;;;
;;; The split is the one Landlock uses.  The parent builds the filter with
;;; libseccomp, where a mistake is an error before anything is created, and
;;; exports it as a BPF program; the child installs it with a single seccomp(2)
;;; call and never touches libseccomp, so nothing between clone3 and execve
;;; allocates.
;;;
;;; The filter is a denylist: a sandboxed command is ordinary software doing
;;; ordinary work, and an allowlist of everything glibc might call is a
;;; maintenance burden that fails closed on the wrong things.  What is denied is
;;; the surface a confined command has no business touching.

;;── libseccomp ─────────────────────────────────────────────────────────────────

(defconstant +scmp-act-allow+ #x7fff0000)

(defun scmp-act-errno (errno)
  (logior #x00050000 (logand errno #xffff)))

(defconstant +scmp-error+ -1
  "What seccomp_syscall_resolve_name answers for a name it does not know.")

;;; The seccomp(2) syscall, and the one operation Scute uses.
(defconstant +sys-seccomp+ 317)
(defconstant +seccomp-set-mode-filter+ 1)

(defvar *libseccomp* nil)

(defun ensure-libseccomp ()
  "Load libseccomp, or refuse the launch.
Loaded on demand rather than at startup: a dumped image cannot carry an open
shared library across the dump, and this way the failure arrives as a launch
error rather than as a broken executable."
  (or *libseccomp*
      (setf *libseccomp*
            (handler-case
                (cffi:load-foreign-library '(:or "libseccomp.so.2" "libseccomp.so"))
              (error ()
                (setup-error :load-libseccomp
                             :detail "libseccomp.so.2 could not be loaded"))))))

;;── What v0 denies ─────────────────────────────────────────────────────────────

(defparameter +denied-syscalls+
  '(("kernel modules and machine control"
     "init_module" "finit_module" "delete_module" "kexec_load" "kexec_file_load"
     "reboot" "ioperm" "iopl" "swapon" "swapoff" "acct" "uselib" "nfsservctl"
     "_sysctl" "vm86" "vm86old" "pciconfig_read" "pciconfig_write")
    ("the kernel keyring, which no namespace confines"
     "add_key" "request_key" "keyctl")
    ("tracing, profiling, and BPF"
     "bpf" "perf_event_open" "ptrace" "process_vm_readv" "process_vm_writev"
     "kcmp" "lookup_dcookie")
    ("namespace and mount changes after setup"
     "unshare" "setns" "mount" "umount2" "pivot_root" "chroot" "mount_setattr"
     "open_tree" "move_mount" "fsopen" "fsconfig" "fsmount" "fspick")
    ("opening a file by handle, which path rules cannot see"
     "name_to_handle_at" "open_by_handle_at")
    ("primitives that exist in exploits more than in programs"
     "userfaultfd" "io_uring_setup" "io_uring_enter" "io_uring_register")
    ("setting the system clock"
     "clock_settime" "clock_adjtime" "settimeofday" "stime")
    ("quotas, NUMA placement, and other machine-wide state"
     "quotactl" "quotactl_fd" "sysfs" "ustat" "mbind" "set_mempolicy"
     "migrate_pages" "move_pages"))
  "What the v0 filter refuses, grouped by the reason it refuses them.

Most of these also need a capability the sandbox does not have.  They are
denied anyway: a syscall that cannot be reached is a syscall whose bugs cannot
be reached either.

One limit is worth stating plainly rather than leaving to be discovered.
Denying unshare does not stop a program from creating a nested user namespace,
because clone and clone3 can do the same thing and seccomp cannot read the
struct clone3 takes its flags from.  This is defence in depth, not a boundary.")

(defun denied-syscall-names ()
  (loop for (nil . names) in +denied-syscalls+ append names))

;;── Closing the nested user namespace ──────────────────────────────────────────
;;
;;; Denying unshare alone does not stop a program from creating a user
;;; namespace, because clone and clone3 can do the same thing.  A nested user
;;; namespace hands its creator a full capability set inside itself, which is
;;; where a large share of kernel exploits begin, so the gap is worth closing
;;; rather than documenting.
;;;
;;; clone takes its flags in a register, so seccomp can look at them: a clone
;;; asking for CLONE_NEWUSER is refused and every other clone is untouched.
;;; clone3 takes them in a struct that seccomp cannot read, so it is refused
;;; whole -- with ENOSYS rather than EPERM, because that is the answer a C
;;; library is looking for when it decides whether to fall back to clone.

(defconstant +clone-newuser+ #x10000000)
(defconstant +scmp-cmp-masked-eq+ 7)
(defconstant +enosys+ 38)

(defun add-masked-argument-rule (context action name argument mask value)
  "Refuse NAME when (ARGUMENT & MASK) equals VALUE.
seccomp_rule_add takes its comparisons as varargs; the _array form takes them
as a struct, which is the one a foreign call can build."
  (let ((number (cffi:foreign-funcall "seccomp_syscall_resolve_name"
                                      :string name :int)))
    (when (<= number +scmp-error+)
      (return-from add-masked-argument-rule nil))
    ;; struct scmp_arg_cmp: an unsigned int, an enum, then two 64-bit data.
    (cffi:with-foreign-object (comparison :uint8 24)
      (dotimes (index 24) (setf (cffi:mem-aref comparison :uint8 index) 0))
      (setf (cffi:mem-ref comparison :uint32 0) argument
            (cffi:mem-ref comparison :uint32 4) +scmp-cmp-masked-eq+
            (cffi:mem-ref comparison :uint64 8) mask
            (cffi:mem-ref comparison :uint64 16) value)
      (let ((result (cffi:foreign-funcall "seccomp_rule_add_array"
                                          :pointer context
                                          :uint32 action
                                          :int number
                                          :unsigned-int 1
                                          :pointer comparison
                                          :int)))
        (unless (zerop result)
          (setup-error :seccomp-rule-add
                       :detail (format nil "~A with an argument test: libseccomp ~
                                            answered ~D"
                                       name result)))
        t))))

(defun deny-nested-user-namespaces (context)
  "Refuse the two ways a command could put itself in a new user namespace."
  (let ((denied '()))
    (when (add-masked-argument-rule context (scmp-act-errno +eperm+) "clone" 0
                                    +clone-newuser+ +clone-newuser+)
      (push "clone(CLONE_NEWUSER)" denied))
    (let ((number (cffi:foreign-funcall "seccomp_syscall_resolve_name"
                                        :string "clone3" :int)))
      (unless (<= number +scmp-error+)
        (when (zerop (cffi:foreign-funcall "seccomp_rule_add" :pointer context
                                           :uint32 (scmp-act-errno +enosys+)
                                           :int number :unsigned-int 0 :int))
          (push "clone3" denied))))
    denied))

;;── Building the filter ────────────────────────────────────────────────────────

(defstruct (seccomp-filter (:constructor %make-seccomp-filter))
  "An exported BPF program, ready for a child to install."
  (program      nil :read-only t)   ; foreign struct sock_fprog
  (instructions 0   :read-only t)
  (denied       nil :read-only t)
  (unavailable  nil :read-only t))  ; names this kernel has no number for

(defun export-filter-program (context)
  "Export CONTEXT as a struct sock_fprog in freshly allocated foreign memory."
  (let ((bytes (cffi:with-foreign-object (length :unsigned-long)
                 (setf (cffi:mem-ref length :unsigned-long) 0)
                 (cffi:foreign-funcall "seccomp_export_bpf_mem"
                                       :pointer context
                                       :pointer (cffi:null-pointer)
                                       :pointer length
                                       :int)
                 (cffi:mem-ref length :unsigned-long))))
    (when (zerop bytes)
      (setup-error :seccomp-export :detail "libseccomp exported an empty filter"))
    (let ((instructions (cffi:foreign-alloc :uint8 :count bytes))
          (program (cffi:foreign-alloc :uint8 :count 16 :initial-element 0)))
      (cffi:with-foreign-object (length :unsigned-long)
        (setf (cffi:mem-ref length :unsigned-long) bytes)
        (let ((result (cffi:foreign-funcall "seccomp_export_bpf_mem"
                                            :pointer context
                                            :pointer instructions
                                            :pointer length
                                            :int)))
          (unless (zerop result)
            (cffi:foreign-free instructions)
            (cffi:foreign-free program)
            (setup-error :seccomp-export
                         :detail (format nil "libseccomp answered ~D" result)))))
      ;; struct sock_fprog: an unsigned short count, then the instructions.
      (setf (cffi:mem-ref program :uint16 0) (floor bytes 8)
            (cffi:mem-ref program :pointer 8) instructions)
      (values program (floor bytes 8)))))

(defun compile-seccomp-filter ()
  "Build the v0 filter.  Every failure here happens before the child exists."
  (ensure-libseccomp)
  (let ((context (cffi:foreign-funcall "seccomp_init"
                                       :uint32 +scmp-act-allow+ :pointer)))
    (when (cffi:null-pointer-p context)
      (setup-error :seccomp-init :detail "libseccomp would not start a filter"))
    (unwind-protect
         (let ((denied '()) (unavailable '())
               (refuse (scmp-act-errno +eperm+)))
           (dolist (name (denied-syscall-names))
             (let ((number (cffi:foreign-funcall "seccomp_syscall_resolve_name"
                                                 :string name :int)))
               (if (<= number +scmp-error+)
                   ;; This kernel and architecture have no such call, so there
                   ;; is nothing to deny.
                   (push name unavailable)
                   (let ((result (cffi:foreign-funcall "seccomp_rule_add"
                                                       :pointer context
                                                       :uint32 refuse
                                                       :int number
                                                       :unsigned-int 0
                                                       :int)))
                     (cond ((zerop result) (push name denied))
                           ;; -EDOM: the name belongs to another architecture.
                           ((= result (- 33)) (push name unavailable))
                           (t
                            (setup-error :seccomp-rule-add
                                         :detail (format nil "~A: libseccomp answered ~D"
                                                         name result))))))))
           (setf denied (append (deny-nested-user-namespaces context) denied))
           (multiple-value-bind (program instructions) (export-filter-program context)
             (%make-seccomp-filter :program program
                                   :instructions instructions
                                   :denied (nreverse denied)
                                   :unavailable (nreverse unavailable))))
      (cffi:foreign-funcall "seccomp_release" :pointer context :void))))

(defvar *seccomp-filter* nil
  "The v0 filter, built once.  It is the same for every launch, holds no
per-launch state, and a child only ever reads it.")

(defun v0-seccomp-filter ()
  (or *seccomp-filter* (setf *seccomp-filter* (compile-seccomp-filter))))

(declaim (inline %seccomp-install))
(defun %seccomp-install (program flags)
  "Install PROGRAM on the calling thread.  Needs no_new_privs already set.
With SECCOMP_FILTER_FLAG_NEW_LISTENER among FLAGS the answer is a descriptor
for the notifications the filter will raise, rather than zero."
  (cffi:foreign-funcall "syscall"
                        :long +sys-seccomp+
                        :unsigned-long +seccomp-set-mode-filter+
                        :unsigned-long flags
                        :pointer program
                        :long))
