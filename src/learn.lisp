;;; learn.lisp
;;;
;;; SPDX-License-Identifier: MIT
;;;
;;; Copyright (C) 2026 Anthony Green

(in-package #:scute)

;;; Watching a command to find out what it needs.
;;;
;;; Writing a least-privilege policy by hand is the main cost of using any
;;; sandbox: you guess, the command fails somewhere deep in a library, you guess
;;; again.  Scute can do the guessing by running the command once and recording
;;; what it actually reached for.
;;;
;;; The mechanism is seccomp user notification.  A filter whose action for the
;;; path-taking syscalls is SCMP_ACT_NOTIFY makes the kernel park the child and
;;; hand a description of the call to whoever holds the listener descriptor;
;;; the supervisor reads the path out of the child's memory, records it, and
;;; tells the kernel to let the call continue.  It needs no privilege, no
;;; ptrace, and no cooperation from the command.
;;;
;;; This observes, it does not enforce: SECCOMP_USER_NOTIF_FLAG_CONTINUE is
;;; unsound as a security decision, because the path can change between the
;;; notification and the syscall.  For learning, where the answer is a draft a
;;; person reviews, that is exactly the right trade.

(defconstant +scmp-act-notify+ #x7fc00000)
(defconstant +seccomp-filter-flag-new-listener+ 8)
(defconstant +seccomp-get-notif-sizes+ 3)
(defconstant +user-notif-flag-continue+ 1)

(defconstant +sys-pidfd-open+ 434)
(defconstant +sys-pidfd-getfd+ 438)
(defconstant +sys-process-vm-readv+ 310)

(defconstant +at-fdcwd+ -100)
(defconstant +o-accmode+ 3)
(defconstant +o-creat+ #o100)
(defconstant +o-trunc+ #o1000)

;;── The syscalls worth watching ────────────────────────────────────────────────

(defstruct (watched-syscall (:constructor make-watched-syscall (name path-argument
                                                                &key dirfd-argument
                                                                     flags-argument
                                                                     access)))
  "A syscall Scute watches, and where its path is among the arguments."
  (name nil :read-only t)
  (path-argument nil :read-only t)
  (dirfd-argument nil :read-only t)
  (flags-argument nil :read-only t)
  (access nil :read-only t))          ; NIL means: work it out from the flags

(defparameter +watched-syscalls+
  (list (make-watched-syscall "openat" 1 :dirfd-argument 0 :flags-argument 2)
        (make-watched-syscall "open" 0 :flags-argument 1)
        (make-watched-syscall "creat" 0 :access :write)
        (make-watched-syscall "execve" 0 :access :execute)
        (make-watched-syscall "execveat" 1 :dirfd-argument 0 :access :execute)
        (make-watched-syscall "mkdirat" 1 :dirfd-argument 0 :access :write)
        (make-watched-syscall "unlinkat" 1 :dirfd-argument 0 :access :write)
        (make-watched-syscall "renameat2" 1 :dirfd-argument 0 :access :write)
        ;; Not a path at all: whether the command wants a unix-domain socket,
        ;; which a policy has to allow before it can have one.
        (make-watched-syscall "socket" nil :flags-argument 0 :access :unix-socket)
        ;; Nor is this: where the command tried to connect, which is what an
        ;; address allowlist has to name and nobody wants to write by hand.
        (make-watched-syscall "connect" nil :flags-argument 1 :access :connect)
        ;; Nor this, and it is not even allowed: a command asking for a user
        ;; namespace of its own is refused either way, and the notification is
        ;; how Scute learns that the refusal it is about to be blamed for was
        ;; an agent trying to sandbox itself.
        (make-watched-syscall "unshare" nil :access :nested-sandbox))
  "What a learning run listens for.

Not openat2: its flags live in a struct in the target's memory rather than in a
register, and the programs that use it also use openat.  Not stat and its
relatives: Landlock does not govern them, so a policy has nothing to say about
them.")

(defun learn-seccomp-filter (&key unix-sockets (ipv6 t))
  "The v0 denylist, plus a notification for every syscall worth watching.

One filter rather than two stacked ones: a command's own syscalls should meet
the same refusals during a learning run as during a real one. UNIX-SOCKETS is
enabled explicitly for permissive policy learning; audit and explanation pass the policy permission unchanged."
  (ensure-libseccomp)
  (let ((context (cffi:foreign-funcall "seccomp_init"
                                       :uint32 +scmp-act-allow+ :pointer)))
    (when (cffi:null-pointer-p context)
      (setup-error :seccomp-init :detail "libseccomp would not start a filter"))
    (unwind-protect
         (let ((refuse (scmp-act-errno +eperm+))
               (watched '()))
           (dolist (name (denied-syscall-names))
             ;; Except the ones a watching run notifies on instead. A syscall
             ;; may not be both refused and notified by one filter, and these
             ;; end up refused all the same: the answer is written by the
             ;; supervisor rather than by the kernel, and is the same EPERM.
             (unless (member name +nested-sandbox-syscalls+ :test #'string=)
               (let ((number (cffi:foreign-funcall "seccomp_syscall_resolve_name"
                                                   :string name :int)))
                 (unless (<= number +scmp-error+)
                   (cffi:foreign-funcall "seccomp_rule_add" :pointer context
                                         :uint32 refuse :int number
                                         :unsigned-int 0 :int)))))
           (unless unix-sockets (deny-unix-domain-sockets context))
           (unless ipv6 (deny-ipv6-sockets context))
           (deny-nested-user-namespaces context +scmp-act-notify+)
           (deny-terminal-injection context)
           (let ((number (cffi:foreign-funcall "seccomp_syscall_resolve_name"
                                               :string "clone" :int)))
             (unless (<= number +scmp-error+)
               (push (cons number (make-watched-syscall "clone" nil
                                                        :access :nested-sandbox))
                     watched)))
           (dolist (syscall +watched-syscalls+)
             (let ((number (cffi:foreign-funcall "seccomp_syscall_resolve_name"
                                                 :string (watched-syscall-name syscall)
                                                 :int)))
               (unless (<= number +scmp-error+)
                 ;; A catch-all socket notification would replace its conditional
                 ;; denials in libseccomp. Only Unix sockets are worth recording,
                 ;; and only when this run actually permits them.
                 (when (if (eq :unix-socket (watched-syscall-access syscall))
                           (and unix-sockets
                                (add-masked-argument-rule context +scmp-act-notify+
                                                          "socket" 0 #xffffffff +af-unix+))
                           (zerop (cffi:foreign-funcall "seccomp_rule_add"
                                                       :pointer context
                                                       :uint32 +scmp-act-notify+
                                                       :int number :unsigned-int 0 :int)))
                   (push (cons number syscall) watched)))))
           (multiple-value-bind (program instructions) (export-filter-program context)
             (declare (ignore instructions))
             (values program watched)))
      (cffi:foreign-funcall "seccomp_release" :pointer context :void))))

(defun reachable-path-p (path)
  "Whether PATH is somewhere a rule could name.

A dynamic loader probes for library variants that are not installed, and those
attempts fail because there is nothing there, not because a policy refused
them.  Suggesting rules for paths that do not exist would also produce a policy
that will not load, since a rule naming a missing path is an error.  A path
about to be created counts: its directory is what governs it."
  (or (probe-file path)
      (let ((slash (position #\/ path :from-end t)))
        (and slash (plusp slash) (probe-file (subseq path 0 slash))))))

;;── What was seen ──────────────────────────────────────────────────────────────

(defstruct (observations (:constructor make-observations (watched)))
  "What a learning run saw: paths, and the access each was reached for with."
  (watched nil :read-only t)          ; syscall number -> watched-syscall
  (nested-sandbox nil)                ; it tried to sandbox itself inside this one
  (paths (make-hash-table :test #'equal) :read-only t)
  (unix-sockets nil)                  ; the command asked for one
  (connections (make-hash-table :test #'equal) :read-only t)
  (skipped 0))                        ; notifications whose path could not be read

(defun canonical-observed-path (path)
  "PATH with its symlinks resolved, so that a policy names one place once.
On a merged-/usr host /lib64/libc.so.6 and /usr/lib64/libc.so.6 are the same
file, and a learned policy that says both is noise.  A path that does not exist
yet -- a file about to be created -- is answered through its directory."
  (or (ignore-errors (and (probe-file path) (namestring (truename path))))
      (let ((slash (position #\/ path :from-end t)))
        (when (and slash (plusp slash))
          (let ((parent (ignore-errors
                         (let ((directory (subseq path 0 slash)))
                           (and (probe-file directory)
                                (namestring (truename directory)))))))
            (when parent
              (format nil "~A~A" parent (subseq path (1+ slash)))))))
      path))

(defun record-observation (observations pid path access &optional still-valid)
  "Record that PATH was reached for with ACCESS.
STILL-VALID, when given, is asked after the path has been read: an answer of NIL
means the task that asked has gone and the path may have come from whatever
process now holds its pid, so it is discarded rather than believed."
  (declare (ignore pid))
  (when (and path (plusp (length path))
             (or (null still-valid) (funcall still-valid)))
    (let* ((canonical (canonical-observed-path path))
           (known (gethash canonical (observations-paths observations))))
      (setf (gethash canonical (observations-paths observations))
            (union (list access) known)))))

;;── Watching ───────────────────────────────────────────────────────────────────

(defun notification-sizes ()
  "The kernel's own sizes for the notification structs.
Guessing instead of asking overruns the allocation libseccomp made, and the
symptom is every receive answering ECANCELED."
  (cffi:with-foreign-object (sizes :uint16 3)
    (when (minusp (cffi:foreign-funcall "syscall" :long +sys-seccomp+
                                        :unsigned-long +seccomp-get-notif-sizes+
                                        :unsigned-long 0 :pointer sizes :long))
      (setup-error :seccomp-notif-sizes :errno (errno)))
    (values (cffi:mem-aref sizes :uint16 0) (cffi:mem-aref sizes :uint16 1))))

(defun notification-valid-p (listener request)
  "Whether the notification in REQUEST still refers to a living task."
  (zerop (cffi:foreign-funcall "seccomp_notify_id_valid"
                               :int listener
                               :uint64 (cffi:mem-ref request :uint64 0)
                               :int)))

(defun steal-listener (pid child-fd)
  "Take the listener CHILD-FD out of PID, so the supervisor holds it.
The child cannot keep it: a command able to answer its own notifications could
wave anything through."
  (let ((pidfd (cffi:foreign-funcall "syscall" :long +sys-pidfd-open+
                                     :int pid :unsigned-long 0 :long)))
    (when (minusp pidfd)
      (setup-error :pidfd-open :errno (errno)))
    (unwind-protect
         (let ((listener (cffi:foreign-funcall "syscall" :long +sys-pidfd-getfd+
                                               :int pidfd :int child-fd
                                               :unsigned-long 0 :long)))
           (when (minusp listener)
             (setup-error :pidfd-getfd :errno (errno)))
           listener)
      (%close pidfd))))

(defun read-target-bytes (pid address buffer size)
  "Read SIZE bytes of another process's memory.  Answers whether it worked."
  (cffi:with-foreign-objects ((local :uint64 2) (remote :uint64 2))
    (setf (cffi:mem-aref local :uint64 0) (cffi:pointer-address buffer)
          (cffi:mem-aref local :uint64 1) size
          (cffi:mem-aref remote :uint64 0) address
          (cffi:mem-aref remote :uint64 1) size)
    (plusp (cffi:foreign-funcall "syscall" :long +sys-process-vm-readv+
                                 :int pid :pointer local :unsigned-long 1
                                 :pointer remote :unsigned-long 1
                                 :unsigned-long 0 :long))))

(defconstant +af-inet+ 2)

(defun read-target-connection (pid address buffer)
  "The IPv4 endpoint a connect(2) was aimed at, or NIL for anything else.

struct sockaddr_in is a family, a port in network byte order, and an address in
network byte order.  Only IPv4 is read: a policy's allowlist guards IPv4, so an
IPv6 attempt recorded here would produce a rule that guards nothing."
  (when (read-target-bytes pid address buffer 16)
    (let ((family (cffi:mem-ref buffer :uint16 0)))
      (when (= family +af-inet+)
        (let ((port (let ((network (cffi:mem-ref buffer :uint16 2)))
                      (logior (ash (logand network #xff) 8) (ash network -8))))
              (octets (make-array 4 :element-type '(unsigned-byte 8))))
          (dotimes (index 4)
            (setf (aref octets index) (cffi:mem-aref buffer :uint8 (+ 4 index))))
          (cons octets port))))))

(defun record-connection (observations endpoint)
  (when endpoint
    (setf (gethash (cons (coerce (car endpoint) 'list) (cdr endpoint))
                   (observations-connections observations))
          t)))

(defun read-target-string (pid address buffer size)
  "Read a NUL-terminated string from another process's memory."
  (cffi:with-foreign-objects ((local :uint64 2) (remote :uint64 2))
    (setf (cffi:mem-aref local :uint64 0) (cffi:pointer-address buffer)
          (cffi:mem-aref local :uint64 1) size
          (cffi:mem-aref remote :uint64 0) address
          (cffi:mem-aref remote :uint64 1) size)
    (let ((count (cffi:foreign-funcall "syscall" :long +sys-process-vm-readv+
                                       :int pid :pointer local :unsigned-long 1
                                       :pointer remote :unsigned-long 1
                                       :unsigned-long 0 :long)))
      (when (plusp count)
        (setf (cffi:mem-aref buffer :uint8 (1- size)) 0)
        (cffi:foreign-string-to-lisp buffer)))))

(defun descriptor-path (pid descriptor)
  "Where PID's DESCRIPTOR points, as /proc reports it."
  (ignore-errors
   (sb-posix:readlink (format nil "/proc/~D/fd/~D" pid descriptor))))

(defun resolve-target-path (pid path dirfd)
  "PATH as the kernel will see it, from a process whose cwd is not ours."
  (cond ((null path) nil)
        ((and (plusp (length path)) (char= #\/ (char path 0))) path)
        ((or (null dirfd) (= dirfd +at-fdcwd+))
         (let ((cwd (ignore-errors (sb-posix:readlink (format nil "/proc/~D/cwd" pid)))))
           (and cwd (format nil "~A/~A" (string-right-trim "/" cwd) path))))
        (t
         (let ((base (descriptor-path pid dirfd)))
           (and base (format nil "~A/~A" (string-right-trim "/" base) path))))))

(defun signed-argument (value)
  "A syscall argument that is an int, read out of its 64-bit register.
The register holds the value sign-extended, so AT_FDCWD arrives as
0xFFFFFFFFFFFFFF9C: the sign lives in the low 32 bits, and reading the whole
register as unsigned turns -100 into a descriptor number nothing can resolve."
  (let ((low (logand value #xffffffff)))
    (if (> low #x7fffffff) (- low #x100000000) low)))

(defun flags-access (flags)
  "What opening a path with FLAGS amounts to."
  (if (or (plusp (logand flags +o-accmode+))
          (plusp (logand flags (logior +o-creat+ +o-trunc+))))
      :write
      :read))

(defun watch-child (listener pid observations)
  "Record what PID reaches for, letting every call through, until it ends.

The listener is closed on the way out whatever happens: a watched process
blocked on a notification nobody will answer would otherwise hang for ever."
  (multiple-value-bind (request-size response-size) (notification-sizes)
    (cffi:with-foreign-objects ((request-pointer :pointer) (response-pointer :pointer))
      (unless (zerop (cffi:foreign-funcall "seccomp_notify_alloc"
                                           :pointer request-pointer
                                           :pointer response-pointer :int))
        (setup-error :seccomp-notify-alloc
                     :detail "libseccomp would not allocate a notification"))
      (let ((request (cffi:mem-ref request-pointer :pointer))
            (response (cffi:mem-ref response-pointer :pointer))
            (scratch (cffi:foreign-alloc :uint8 :count 4096)))
        (unwind-protect
             (loop
               (dotimes (index request-size)
                 (setf (cffi:mem-aref request :uint8 index) 0))
               (unless (zerop (cffi:foreign-funcall "seccomp_notify_receive"
                                                    :int listener :pointer request :int))
                 (return))                    ; the child is gone
               (let* ((number (cffi:mem-ref request :int32 16))
                      (from (cffi:mem-ref request :uint32 8))
                      (syscall (cdr (assoc number (observations-watched observations)))))
                 ;; Validate, read, then validate again.  A notification names a
                 ;; pid, and a pid can be reused: if the task exits between the
                 ;; check and the read, process_vm_readv answers with some other
                 ;; process's memory and the path belongs to whatever now holds
                 ;; that number.  This is how a watched shell came to report
                 ;; reading dbus's libraries.  The second check is what makes the
                 ;; answer belong to the task that asked.
                 ;; A socket is not a path: what is worth recording is that the
                 ;; command wanted one at all.
                 (handler-case
                  (when (and syscall (null (watched-syscall-path-argument syscall)))
                   (case (watched-syscall-access syscall)
                     (:unix-socket
                      (when (= +af-unix+
                               (logand #xffffffff
                                       (cffi:mem-ref request :uint64 32)))
                        (setf (observations-unix-sockets observations) t)))
                     (:connect
                      (when (notification-valid-p listener request)
                        (record-connection
                         observations
                         (read-target-connection
                          from (cffi:mem-ref request :uint64 40) scratch))))
                     (:nested-sandbox
                      (setf (observations-nested-sandbox observations) t))))
                  (error () (incf (observations-skipped observations))))
                 ;; Recording is best-effort, and failing at it must not fail the
                 ;; syscall.  An error here used to unwind out of this loop, which
                 ;; left that notification unanswered -- the kernel answers an
                 ;; unanswered notification with ENOSYS -- and left every
                 ;; notification after it unanswered too, because the watcher was
                 ;; gone.  One unreadable path turned a working command into
                 ;; "mkdir: function not implemented" for the rest of the run.
                 ;;
                 ;; What is dropped is counted, because a report that quietly saw
                 ;; less than it claims is the other way to be wrong here.
                 (handler-case
                     (when (and syscall (watched-syscall-path-argument syscall)
                                (notification-valid-p listener request))
                       (record-observation
                        observations from
                        (resolve-target-path
                         from
                         (read-target-string
                          from
                          (cffi:mem-ref request :uint64
                                        (+ 32 (* 8 (watched-syscall-path-argument syscall))))
                          scratch 4096)
                         (let ((index (watched-syscall-dirfd-argument syscall)))
                           (when index
                             (signed-argument
                              (cffi:mem-ref request :uint64 (+ 32 (* 8 index)))))))
                        (or (watched-syscall-access syscall)
                            (let ((index (watched-syscall-flags-argument syscall)))
                              (if index
                                  (flags-access (cffi:mem-ref request :uint64 (+ 32 (* 8 index))))
                                  :read)))
                        (lambda () (notification-valid-p listener request))))
                   (error () (incf (observations-skipped observations))))
                 ;; Answering: let it through, unless this is one of the calls
                 ;; that is only notified so that it can be refused here.  A
                 ;; response carries either a continuation or an error, never
                 ;; both, and the error is the one the filter would have given
                 ;; had it refused the call itself.
                 (dotimes (index response-size)
                   (setf (cffi:mem-aref response :uint8 index) 0))
                 (setf (cffi:mem-ref response :uint64 0) (cffi:mem-ref request :uint64 0))
                 (if (and syscall (eq :nested-sandbox (watched-syscall-access syscall)))
                     (setf (cffi:mem-ref response :int32 16) (- +eperm+))
                     (setf (cffi:mem-ref response :uint32 20) +user-notif-flag-continue+))
                 (cffi:foreign-funcall "seccomp_notify_respond"
                                       :int listener :pointer response :int)))
          (cffi:foreign-free scratch)
          (cffi:foreign-funcall "seccomp_notify_free" :pointer request
                                :pointer response :void)
          (%close listener))))
    observations))

(defparameter +policy-anchors+
  '("/usr" "/bin" "/sbin" "/lib" "/lib64" "/etc" "/opt" "/proc" "/sys"
    "/run" "/tmp" "/var/tmp" "/var/cache" "/var/lib")
  "Directories a learned policy names whole rather than file by file.

A command opens forty files under /usr and nobody wants forty rules.  Anywhere
else -- a project directory, a cache under $HOME -- the containing directory is
named instead, which keeps a learned policy close to what was actually used.

/proc has to be here even though it is coarse: a path like /proc/self/status
resolves to /proc/<pid>/status, and a policy naming a process that has already
exited would be worse than useless.

/dev is deliberately absent.  Device nodes are worth naming one at a time --
/dev/null and /dev/tty are the usual pair -- rather than handing over the whole
directory because a shell wanted a terminal.")

(defun beneath-p (path directory)
  (let ((base (trim-trailing-slash directory)))
    (and (< (length base) (length path))
         (string= base path :end2 (length base))
         (char= #\/ (char path (length base))))))

(defun policy-path-for (path directory)
  "The path a rule should name, given that PATH was used.

Relative to DIRECTORY when it lies beneath it, so a learned policy travels with
the project rather than naming somebody's home.  Inside one of the anchors, the
anchor, because nobody wants a rule per file under /usr.  Anywhere else, the
thing itself: a directory if a directory was opened, and otherwise the file.
Naming /dev/tty is worth the extra line; handing over all of /dev because a
shell wanted a terminal is not."
  (cond ((or (string= path directory) (beneath-p path directory)) ".")
        ((find-if (lambda (anchor) (beneath-p path anchor)) +policy-anchors+))
        ((string= "/" path) "/")
        ((uiop:directory-exists-p path) (trim-trailing-slash path))
        ((probe-file path) path)
        ;; Not there yet -- a file about to be created.  What governs creating it
        ;; is the directory it will appear in, and a rule must name something
        ;; that exists or the policy will not load at all.
        (t (let ((slash (position #\/ path :from-end t)))
             (if (and slash (plusp slash)) (subseq path 0 slash) "/")))))

(defun learned-rules (observations directory)
  "Fold what was observed into as few rules as say the same thing.
Answers an alist of access kind to the paths it should name.

Paths that exist nowhere are left out.  A loader probes for library variants
that are not installed, and a rule naming a missing path is an error -- so a
learned policy that kept them would be a policy that will not load, which is a
worse outcome than a policy that is slightly too narrow."
  (let ((accesses (make-hash-table :test #'equal)))
    (maphash (lambda (path seen)
               (when (reachable-path-p path)
               (let ((rule-path (policy-path-for path (trim-trailing-slash directory))))
                 (setf (gethash rule-path accesses)
                       (union seen (gethash rule-path accesses))))))
             (observations-paths observations))
    ;; A path covered by a shallower rule needs no rule of its own.
    (let ((paths (sort (loop for path being the hash-keys of accesses collect path)
                       #'< :key #'length)))
      (dolist (path paths)
        (dolist (other paths)
          (when (and (not (string= path other)) (beneath-p other path))
            (setf (gethash path accesses)
                  (union (gethash other accesses) (gethash path accesses))
                  (gethash other accesses) nil))))
      (let ((kinds (make-hash-table :test #'eq)))
        (dolist (path paths)
          (let ((seen (gethash path accesses)))
            (when seen
              (push path (gethash (access-kind seen) kinds)))))
        (loop for kind in +access-kinds+
              for named = (sort (copy-list (gethash kind kinds)) #'string<)
              when named collect (cons kind named))))))

(defun kind-accesses (kind)
  "The accesses KIND stands for: the inverse of ACCESS-KIND."
  (ecase kind
    (:read '(:read))
    (:read-execute '(:read :execute))
    (:read-write '(:read :write))
    (:read-write-execute '(:read :write :execute))))

(defun merge-learned-rules (rules policy)
  "RULES widened by what POLICY already allows.
Both sides are already policy-shaped -- \".\" for the working directory, an
anchor for a system tree -- so they merge by name."
  (if (null policy)
      rules
      (let ((accesses (make-hash-table :test #'equal)))
        (flet ((absorb (kind path)
                 (setf (gethash path accesses)
                       (union (kind-accesses kind) (gethash path accesses)))))
          (dolist (rule (sandbox-policy-filesystem policy))
            (absorb (filesystem-rule-kind rule) (filesystem-rule-path rule)))
          (loop for (kind . paths) in rules
                do (dolist (path paths) (absorb kind path))))
        (let ((kinds (make-hash-table :test #'eq)))
          (maphash (lambda (path seen) (push path (gethash (access-kind seen) kinds)))
                   accesses)
          (loop for kind in +access-kinds+
                for named = (sort (copy-list (gethash kind kinds)) #'string<)
                when named collect (cons kind named))))))

(defun access-kind (seen)
  "The policy permission covering every access in SEEN."
  (let ((write (member :write seen))
        (execute (member :execute seen)))
    (cond ((and write execute) :read-write-execute)
          (write :read-write)
          (execute :read-execute)
          (t :read))))

(defvar *learned-connections* nil
  "The endpoints the run being written up tried to reach.")

(defvar *learned-unix-sockets* nil
  "Whether the run being written up asked for a unix-domain socket.")

(defun write-policy-section (name entries stream)
  (when entries
    (format stream "~%[~A]~%~{~A~%~}" name entries)))

(defun write-learned-policy (rules stream &key command carry)
  "Write RULES as a policy, with the caveats a learned policy deserves.
CARRY, when given, is a policy whose other sections are kept: merging into an
existing policy must not quietly drop the limits it asked for."
  (format stream "# Learned by watching~@[ ~{~A~^ ~}~] run~:[ once~; and merged ~
                  with what was already here~].~%"
          command carry)
  (format stream "# A starting point, not a finished policy: one run sees one ~
                  path through~%# the program.  Narrow it, then check it with ~
                  scute check.~%~%[filesystem]~%")
  (loop for (kind . paths) in rules
        do (format stream "~(~A~) = [~{~S~^, ~}]~%" kind paths))
  ;; One mode line.  TOML forbids a duplicate key and so does scute, so a policy
  ;; that said both "none" and "host" would not load at all.
  (format stream "~%[network]~%mode = ~S~%"
          (if *learned-connections* "host" "none"))
  (when (or (and carry (sandbox-policy-unix-sockets carry))
            *learned-unix-sockets*)
    (format stream "unix-sockets = true~%"))
  (when *learned-connections*
    (format stream "allow = [~{~S~^, ~}]~%"
            (sort (mapcar (lambda (connection)
                            (format nil "~{~D~^.~}:~D" (car connection) (cdr connection)))
                          *learned-connections*)
                  #'string<)))
  (let ((limits (and carry (sandbox-policy-limits carry))))
    (write-policy-section
     "limits"
     (when limits
       (remove nil
               (list (let ((memory (resource-limits-memory limits)))
                       (and memory (format nil "memory = ~S" (format nil "~D" memory))))
                     (let ((processes (resource-limits-processes limits)))
                       (and processes (format nil "processes = ~D" processes)))
                     (let ((cpu (resource-limits-cpu-percent limits)))
                       (and cpu (format nil "cpu-percent = ~D" cpu)))
                     (let ((clock (resource-limits-wall-clock limits)))
                       (and clock (format nil "wall-clock = ~S"
                                          (format nil "~Ds" clock)))))))
     stream))
  (let ((audit (and carry (sandbox-policy-audit carry))))
    (write-policy-section
     "audit"
     (when audit
       (list (format nil "events = [~{~S~^, ~}]"
                     (mapcar #'string-downcase (audit-policy-events audit)))))
     stream))
  (let ((environment (and carry (sandbox-policy-environment carry))))
    (write-policy-section
     "environment"
     (when environment
       (list (format nil "keep = [~{~S~^, ~}]" environment)))
     stream))
  rules)

;;── Explaining a refusal ───────────────────────────────────────────────────────
;;
;;; A sandboxed command that is refused something reports its own confusion --
;;; "Permission denied", from somewhere deep inside a library -- and the person
;;; running it has to guess which path a policy forgot.  Scute watches the same
;;; way it does when learning, and afterwards says which of the paths the
;;; command reached for its own rules would not have allowed.
;;;
;;; A seccomp filter runs at syscall entry, before the security modules decide
;;; anything, so an attempt Landlock went on to refuse is still seen here.

(defun permitted-access-p (rules path access abi)
  (and (granting-rule rules path access abi) t))

(defun refused-observations (observations rules)
  "The paths in OBSERVATIONS that RULES do not allow, and what was wanted.
Answers an alist of path to the accesses that were not permitted."
  (let ((abi (or (landlock-abi-version) 1))
        (refused '()))
    (maphash (lambda (path accesses)
               (when (reachable-path-p path)
                 (let ((missing (remove-if (lambda (access)
                                             (permitted-access-p rules path access abi))
                                           accesses)))
                   (when missing (push (cons path missing) refused)))))
             (observations-paths observations))
    (sort refused #'string< :key #'car)))

(defun refusal-rules (refused directory)
  "The rules that would have allowed REFUSED, folded the way a policy is."
  (let ((observations (make-observations nil)))
    (loop for (path . accesses) in refused
          do (dolist (access accesses)
               (record-observation observations nil path access)))
    (learned-rules observations directory)))

(defun report-nested-sandbox (stream)
  "Say that the command was refused a sandbox of its own, and what to do.

Worth saying because the command's own account of it is wrong.  A tool that
wraps what it runs in bubblewrap -- codex does, for every command the model
produces -- reports the refusal as \"the kernel does not allow non-privileged
user namespaces\" and names a sysctl to set.  Unprivileged user namespaces are
enabled: Scute made several on the way to starting this command.  What refused
the inner sandbox was Scute's own seccomp filter, and that is deliberate, since
a command able to build namespaces is a command able to rearrange the mounts it
was confined with."
  (format stream
          "~&scute: the command tried to build a sandbox of its own and was refused.~%~
           ~&       Scute's filter did that, not your kernel -- so any advice the~%~
           ~&       command gave about kernel.unprivileged_userns_clone is a wrong~%~
           ~&       guess at why it failed.  Scute is the containment; turn the~%~
           ~&       inner one off:~%~
           ~&~%~
           ~&         codex --dangerously-bypass-approvals-and-sandbox~%~
           ~&~%~
           ~&       Anything else that wraps its commands in bubblewrap needs the~%~
           ~&       same, by whatever name that tool gives the flag.~%"))

(defun report-refusals (refused directory stream)
  "Say what was refused, and what would allow it."
  (when refused
    (format stream "~&scute: the command was refused ~D path~:P:~%" (length refused))
    (loop for (path . accesses) in refused
          do (format stream "  ~A~48T~{~(~A~)~^ ~}~%" path accesses))
    (format stream "~&Adding this to the policy would allow them:~%~%[filesystem]~%")
    (loop for (kind . paths) in (refusal-rules refused directory)
          do (format stream "~(~A~) = [~{~S~^, ~}]~%" kind paths))
    (terpri stream))
  refused)

;;── An audit trail ─────────────────────────────────────────────────────────────
;;
;;; The same watching, kept rather than folded into a policy.  A record per
;;; event, one JSON object to a line, so that reading it needs nothing but the
;;; usual tools.

(defparameter +audit-event-syscalls+
  '((:exec . (:execute))
    (:open . (:read :write)))
  "Which accesses each auditable event covers.")

(defun audited-access-p (events access)
  (loop for (event . accesses) in +audit-event-syscalls+
        thereis (and (member event events) (member access accesses))))

(defun write-audit-connections (observations stream)
  "Write every address the command connected to, and answer how many.

A connection is not a path, which is why this is a second pass rather than
another access kind: what a policy asks about an address is where it went, not
what it did there."
  (let ((written 0))
    (maphash (lambda (endpoint present)
               (declare (ignore present))
               (incf written)
               (format stream "{\"event\": \"connect\", \"address\": \"~{~D~^.~}\", ~
                               \"port\": ~D}~%"
                       (car endpoint) (cdr endpoint)))
             (observations-connections observations))
    written))

(defun write-audit-trail (observations events stream &key command)
  "Write what OBSERVATIONS saw, keeping the EVENTS a policy asked for."
  (let ((written 0))
    (format stream "{\"event\": \"start\", \"command\": [~{~S~^, ~}]}~%"
            (or command '()))
    (when (member :connect events)
      (incf written (write-audit-connections observations stream)))
    (maphash (lambda (path accesses)
               (dolist (access accesses)
                 (when (audited-access-p events access)
                   (incf written)
                   (format stream "{\"event\": ~S, \"access\": ~S, \"path\": "
                           (if (eq access :execute) "exec" "open")
                           (string-downcase access))
                   (write-json-string path stream)
                   (format stream "}~%"))))
             (observations-paths observations))
    written))
