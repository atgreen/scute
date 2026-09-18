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
        (make-watched-syscall "renameat2" 1 :dirfd-argument 0 :access :write))
  "What a learning run listens for.

Not openat2: its flags live in a struct in the target's memory rather than in a
register, and the programs that use it also use openat.  Not stat and its
relatives: Landlock does not govern them, so a policy has nothing to say about
them.")

(defun learn-seccomp-filter ()
  "The v0 denylist, plus a notification for every syscall worth watching.
One filter rather than two stacked ones: a command's own syscalls should meet
the same refusals during a learning run as during a real one."
  (ensure-libseccomp)
  (let ((context (cffi:foreign-funcall "seccomp_init"
                                       :uint32 +scmp-act-allow+ :pointer)))
    (when (cffi:null-pointer-p context)
      (setup-error :seccomp-init :detail "libseccomp would not start a filter"))
    (unwind-protect
         (let ((refuse (scmp-act-errno +eperm+))
               (watched '()))
           (dolist (name (denied-syscall-names))
             (let ((number (cffi:foreign-funcall "seccomp_syscall_resolve_name"
                                                 :string name :int)))
               (unless (<= number +scmp-error+)
                 (cffi:foreign-funcall "seccomp_rule_add" :pointer context
                                       :uint32 refuse :int number
                                       :unsigned-int 0 :int))))
           (dolist (syscall +watched-syscalls+)
             (let ((number (cffi:foreign-funcall "seccomp_syscall_resolve_name"
                                                 :string (watched-syscall-name syscall)
                                                 :int)))
               (unless (<= number +scmp-error+)
                 (when (zerop (cffi:foreign-funcall "seccomp_rule_add"
                                                    :pointer context
                                                    :uint32 +scmp-act-notify+
                                                    :int number :unsigned-int 0 :int))
                   (push (cons number syscall) watched)))))
           (multiple-value-bind (program instructions) (export-filter-program context)
             (declare (ignore instructions))
             (values program watched)))
      (cffi:foreign-funcall "seccomp_release" :pointer context :void))))

;;── What was seen ──────────────────────────────────────────────────────────────

(defstruct (observations (:constructor make-observations (watched)))
  "What a learning run saw: paths, and the access each was reached for with."
  (watched nil :read-only t)          ; syscall number -> watched-syscall
  (paths (make-hash-table :test #'equal) :read-only t))

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

(defun record-observation (observations pid path access)
  (declare (ignore pid))
  (when (and path (plusp (length path)))
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
                 (when (and syscall
                            (zerop (cffi:foreign-funcall "seccomp_notify_id_valid"
                                                         :int listener
                                                         :uint64 (cffi:mem-ref request :uint64 0)
                                                         :int)))
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
                              :read)))))
                 (dotimes (index response-size)
                   (setf (cffi:mem-aref response :uint8 index) 0))
                 (setf (cffi:mem-ref response :uint64 0) (cffi:mem-ref request :uint64 0)
                       (cffi:mem-ref response :uint32 20) +user-notif-flag-continue+)
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
        (t path)))

(defun learned-rules (observations directory)
  "Fold what was observed into as few rules as say the same thing.
Answers an alist of access kind to the paths it should name."
  (let ((accesses (make-hash-table :test #'equal)))
    (maphash (lambda (path seen)
               (let ((rule-path (policy-path-for path (trim-trailing-slash directory))))
                 (setf (gethash rule-path accesses)
                       (union seen (gethash rule-path accesses)))))
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

(defun access-kind (seen)
  "The policy permission covering every access in SEEN."
  (let ((write (member :write seen))
        (execute (member :execute seen)))
    (cond ((and write execute) :read-write-execute)
          (write :read-write)
          (execute :read-execute)
          (t :read))))

(defun write-learned-policy (rules stream &key command)
  "Write RULES as a policy, with the caveats a learned policy deserves."
  (format stream "# Learned by watching~@[ ~{~A~^ ~}~] run once.~%" command)
  (format stream "# A starting point, not a finished policy: one run sees one ~
                  path through~%# the program.  Narrow it, then check it with ~
                  scute check.~%~%[filesystem]~%")
  (loop for (kind . paths) in rules
        do (format stream "~(~A~) = [~{~S~^, ~}]~%" kind paths))
  (format stream "~%[network]~%mode = \"none\"~%")
  rules)
