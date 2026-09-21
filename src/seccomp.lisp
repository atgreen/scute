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

(defparameter +nested-sandbox-syscalls+
  '("unshare")
  "Denied calls that a watching run notifies on rather than refuses outright.

clone is the other half of this and is not here, because it is denied by an
argument test rather than by name: a clone that does not ask for CLONE_NEWUSER
is an ordinary fork and must stay untouched.")

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

(defconstant +af-unix+ 1)

(defun deny-unix-domain-sockets (context)
  "Refuse a socket in the unix domain, which no namespace confines.

A network namespace of its own gives a sandbox no route and no abstract socket,
and Landlock governs what it can open -- but neither covers connect(2) to a
unix socket by path, so a command could reach systemd-resolved, the system
D-Bus, an ssh-agent, or a container daemon while the policy said the network
was off.  It was off; that traffic never went near it.

socketpair is a different syscall and stays allowed, so a program can still
talk to itself."
  (when (add-masked-argument-rule context (scmp-act-errno +eperm+) "socket" 0
                                  #xffffffff +af-unix+)
    (list "socket(AF_UNIX)")))

(defun deny-ipv6-sockets (context)
  "The cgroup guards cover IPv4 only; IPv6 must not bypass them."
  (when (add-masked-argument-rule context (scmp-act-errno +eperm+) "socket" 0
                                  #xffffffff 10) ; AF_INET6
    (list "socket(AF_INET6)")))

(defconstant +tiocsti+   #x5412
  "ioctl: push a character into a terminal's own input queue.")
(defconstant +tioclinux+ #x541c
  "ioctl: the console's selection and paste, which can do the same on a VT.")

(defun deny-terminal-injection (context)
  "Refuse the ioctls that let a command type into the terminal it was given.

The sandbox is started from a terminal and keeps it: the policies name /dev/tty,
and standard input arrives as an already-open descriptor whatever the policy
says.  TIOCSTI pushes characters into that terminal's input queue, and the shell
that reads them back after the sandboxed command exits runs them as though you
had typed them.  That is a way out of the sandbox and into the session that
started it.

Landlock cannot answer this one.  Its ioctl right is checked when a device is
opened, and this descriptor was never opened inside the sandbox -- it was
inherited.  Seccomp can: ioctl takes its request number in a register, so the
two that matter are refused by an argument test and every other ioctl, including
all the ones a terminal actually needs, is untouched.

Linux 6.2 and later can turn TIOCSTI off for the whole machine, and Fedora ships
it off.  This does not depend on that: Scute says it runs on 5.13 and newer, and
a boundary that holds only where the host already closed the hole is not one."
  (let ((denied '()))
    (dolist (request (list (cons "TIOCSTI" +tiocsti+)
                           (cons "TIOCLINUX" +tioclinux+)))
      (when (add-masked-argument-rule context (scmp-act-errno +eperm+) "ioctl" 1
                                      #xffffffff (cdr request))
        (push (format nil "ioctl(~A)" (car request)) denied)))
    (nreverse denied)))

(defun deny-nested-user-namespaces (context &optional action)
  "Refuse the two ways a command could put itself in a new user namespace.

ACTION is how clone(CLONE_NEWUSER) is answered, EPERM unless a caller says
otherwise.  A watching run passes SCMP_ACT_NOTIFY instead and answers with the
same EPERM itself, which is how Scute comes to know that the command it is
watching was trying to sandbox itself -- a fact worth telling somebody, since
the message the command prints about it blames the kernel."
  (let ((denied '())
        (action (or action (scmp-act-errno +eperm+))))
    (when (add-masked-argument-rule context action "clone" 0
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

(defun compile-seccomp-filter (&key unix-sockets (ipv6 t))
  "Build the v0 filter.  Every failure here happens before the child exists.
With UNIX-SOCKETS the AF_UNIX refusal is left out, because a policy said so."
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
           (setf denied (append (unless unix-sockets
                                  (deny-unix-domain-sockets context))
                                (unless ipv6 (deny-ipv6-sockets context))
                                (deny-nested-user-namespaces context)
                                (deny-terminal-injection context)
                                denied))
           (multiple-value-bind (program instructions) (export-filter-program context)
             (%make-seccomp-filter :program program
                                   :instructions instructions
                                   :denied (nreverse denied)
                                   :unavailable (nreverse unavailable))))
      (cffi:foreign-funcall "seccomp_release" :pointer context :void))))

(defvar *seccomp-filters* (make-hash-table :test #'eql)
  "Filters cached by the two independent socket permissions.")

(defun v0-seccomp-filter (&key unix-sockets (ipv6 t))
  (let ((key (+ (if unix-sockets 1 0) (if ipv6 2 0))))
    (or (gethash key *seccomp-filters*)
        (setf (gethash key *seccomp-filters*)
              (compile-seccomp-filter :unix-sockets unix-sockets :ipv6 ipv6)))))

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
