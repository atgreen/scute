;;; linux.lisp
;;;
;;; SPDX-License-Identifier: MIT
;;;
;;; Copyright (C) 2026 Anthony Green

(in-package #:scute)

;;; The narrow foreign surface Scute needs and no more: clone3, the
;;; synchronization pipe, capability removal, prctl, and wait-status decoding.
;;; Everything here is Linux-specific by construction.

#-(and sbcl linux x86-64)
(error "Scute requires SBCL on Linux/x86-64.")

;;── Constants ──────────────────────────────────────────────────────────────────

(defconstant +sys-clone3+ 435)

(defconstant +clone-newns+    #x00020000)
(defconstant +clone-newuts+   #x04000000)
(defconstant +clone-newpid+   #x20000000)
(defconstant +clone-newuser+  #x10000000)
(defconstant +clone-newnet+   #x40000000)

;;; clone3 is the only fork Scute performs.  sb-posix:fork cannot be used: SBCL
;;; recreates a helper thread in the child, and a multi-threaded task cannot
;;; enter a new user namespace.
(defconstant +sandbox-clone-flags+
  (logior +clone-newuser+ +clone-newns+ +clone-newpid+
          +clone-newuts+ +clone-newnet+))

(defun clone-flags-for-network (mode)
  "The clone flags for a sandbox whose policy asked for network MODE.

A network namespace of its own is how a sandbox has no network: leaving it out
is how a policy says the command shares the host's, which some builds need and
which the policy therefore has to say out loud."
  (ecase mode
    (:none +sandbox-clone-flags+)
    ;; Proxied is the host's network with every outbound connection rewritten to
    ;; the proxy, so it needs the same namespace arrangement as :host.
    ((:host :proxied) (logandc2 +sandbox-clone-flags+ +clone-newnet+))))

(defconstant +clone-args-size-ver0+ 64)

(defconstant +sigchld+ 17)
(defconstant +sighup+   1)
(defconstant +sigint+   2)
(defconstant +sigquit+  3)
(defconstant +sigkill+  9)
(defconstant +sigalrm+ 14)
(defconstant +sigterm+ 15)

(defconstant +o-cloexec+ #o2000000)

(defconstant +x-ok+ 1)
(defconstant +w-ok+ 2)


(defconstant +pr-set-pdeathsig+           1)
(defconstant +pr-set-dumpable+            4)
(defconstant +pr-capbset-drop+           24)
(defconstant +pr-set-no-new-privs+       38)
(defconstant +pr-cap-ambient+            47)
(defconstant +pr-cap-ambient-clear-all+   4)

(defconstant +linux-capability-version-3+ #x20080522)

(defconstant +itimer-real+ 0)

(defconstant +eintr+  4)
(defconstant +eperm+  1)
(defconstant +enoent+ 2)
(defconstant +eacces+ 13)
(defconstant +enosys+ 38)

;;; Exit codes the child reports for its own setup failures.  They are distinct
;;; from anything the sandboxed command is likely to produce, and the supervisor
;;; translates them back into conditions.
(defconstant +child-exit-sync-failed+   126)
(defconstant +child-exit-setup-failed+  125)
(defconstant +child-exit-exec-failed+   127)

;;── Errno ──────────────────────────────────────────────────────────────────────

(declaim (inline errno))
(defun errno ()
  "The calling thread's current errno."
  (cffi:mem-ref (cffi:foreign-funcall "__errno_location" :pointer) :int))

;;── Raw calls ──────────────────────────────────────────────────────────────────
;;
;;; These are the only operations the post-clone3 child performs.  They are
;;; inline so that the child path makes foreign calls and nothing else: no
;;; allocation, no streams, no condition system, no GC.

(declaim (inline %close %read %write %prctl %capset %execve %exit %kill %access %open
                 %chdir))

(defun %close (fd)
  (cffi:foreign-funcall "close" :int fd :int))

(defun %read (fd buffer count)
  (cffi:foreign-funcall "read" :int fd :pointer buffer :unsigned-long count :long))

(defun %write (fd buffer count)
  (cffi:foreign-funcall "write" :int fd :pointer buffer :unsigned-long count :long))

(defun %prctl (option arg2 arg3 arg4 arg5)
  (cffi:foreign-funcall "prctl" :int option :unsigned-long arg2 :unsigned-long arg3
                                :unsigned-long arg4 :unsigned-long arg5 :int))

(defun %capset (header data)
  (cffi:foreign-funcall "capset" :pointer header :pointer data :int))

(defun %execve (path argv envp)
  (cffi:foreign-funcall "execve" :pointer path :pointer argv :pointer envp :int))

(defun %exit (code)
  (cffi:foreign-funcall "_exit" :int code :void))

(defun %kill (pid signal)
  (cffi:foreign-funcall "kill" :int pid :int signal :int))

(defun %chdir (path)
  (cffi:foreign-funcall "chdir" :pointer path :int))

(defun %open (path flags)
  (cffi:foreign-funcall "open" :string path :int flags :int))

(defun %access (path mode)
  (cffi:foreign-funcall "access" :string path :int mode :int))

(defun %waitpid (pid status-pointer options)
  (cffi:foreign-funcall "waitpid" :int pid :pointer status-pointer :int options :int))

;;── Wait status ────────────────────────────────────────────────────────────────

(defun exited-p (status)
  (zerop (logand status #x7f)))

(defun exit-status (status)
  (logand (ash status -8) #xff))

(defun termination-signal (status)
  "The signal that killed the child, or NIL if it exited normally."
  (let ((signal (logand status #x7f)))
    (unless (or (zerop signal) (= signal #x7f))
      signal)))

;;── Capabilities ───────────────────────────────────────────────────────────────

(defun cap-last-cap ()
  "The highest capability number this kernel knows about."
  (with-open-file (stream "/proc/sys/kernel/cap_last_cap"
                          :direction :input :if-does-not-exist nil)
    (or (and stream (let ((value (read stream nil nil)))
                      (and (typep value '(integer 0 1024)) value)))
        (setup-error :probe-cap-last-cap
                     :detail "/proc/sys/kernel/cap_last_cap is unreadable"))))

(defun make-empty-capability-request ()
  "Allocate a zeroed capset(2) header and data block addressed at this task.
Returns the header and data pointers; both are caller-owned foreign memory."
  (let ((header (cffi:foreign-alloc :uint8 :count 8 :initial-element 0))
        (data   (cffi:foreign-alloc :uint8 :count 24 :initial-element 0)))
    (setf (cffi:mem-ref header :uint32 0) +linux-capability-version-3+
          (cffi:mem-ref header :int32 4) 0)      ; pid 0: the calling task
    (values header data)))

(defun drop-all-capabilities ()
  "Permanently clear every capability set of the calling process.
Bounding-set removal needs CAP_SETPCAP; a process that never held it has
nothing to drop, so EPERM there is not a failure."
  (when (minusp (%prctl +pr-cap-ambient+ +pr-cap-ambient-clear-all+ 0 0 0))
    (setup-error :clear-ambient-capabilities :errno (errno)))
  (loop for capability from 0 to (cap-last-cap)
        do (when (and (minusp (%prctl +pr-capbset-drop+ capability 0 0 0))
                      (/= (errno) +eperm+))
             (setup-error :drop-bounding-capability :errno (errno)
                          :detail (format nil "capability ~D" capability))))
  (multiple-value-bind (header data) (make-empty-capability-request)
    (unwind-protect
         (when (minusp (%capset header data))
           (setup-error :clear-capabilities :errno (errno)))
      (cffi:foreign-free header)
      (cffi:foreign-free data))))

(defparameter +verified-capability-sets+ '("CapEff" "CapPrm" "CapInh" "CapAmb")
  "The sets that must be empty before the parent releases the child.

Not CapBnd.  Clearing the bounding set needs CAP_SETPCAP, which an unprivileged
Scute never had, and it does not need it: the bounding set limits only what an
exec could add, and nothing can be added to an empty permitted set under
no_new_privs.  The child is a different matter -- it holds CAP_SETPCAP inside
its own user namespace, clears its bounding set there, and the tests check it.")

(defun catches-signal-p (pid signal)
  "Whether PID has a handler installed for SIGNAL, as /proc reports it.

This decides whether a grace period is worth waiting out.  The sandboxed command
is PID 1 of its namespace, and pid_namespaces(7) discards a signal sent to PID 1
unless PID 1 installed a handler for it -- so giving a command that catches
nothing five seconds to tidy up means five seconds of nothing happening."
  (with-open-file (stream (format nil "/proc/~D/status" pid)
                          :direction :input :if-does-not-exist nil)
    (when stream
      (loop for line = (read-line stream nil nil)
            while line
            when (and (> (length line) 7) (string= "SigCgt:" line :end2 7))
              do (let ((mask (ignore-errors
                              (parse-integer line :start 7 :radix 16 :junk-allowed t))))
                   (return (and mask (logbitp (1- signal) mask))))))))

(defun make-dumpable ()
  "Undo the non-dumpable state a credential-changing exec leaves behind.

A binary that gains file capabilities is marked non-dumpable, and a
non-dumpable process's /proc files belong to root rather than to the user
running it -- including those of the children it forks.  The supervisor has to
write its child's uid map through /proc, so with a capability granted and this
left alone, every launch fails with EPERM on a file the caller appears to own.

Called only after the parent has dropped its capabilities, so that scute is
never both privileged and open to being traced by anything sharing its uid."
  (when (minusp (%prctl +pr-set-dumpable+ 1 0 0 0))
    (setup-error :set-dumpable :errno (errno))))

(defun verify-no-capabilities ()
  "Check that this process holds no capability it could pass to a child.
The design says drop and verify, because dropping is a syscall and a syscall
can fail in ways worth noticing before a sandbox is released."
  (loop for (name . bits) in (capability-sets)
        when (and (member name +verified-capability-sets+ :test #'string=)
                  (not (zerop bits)))
          do (setup-error :verify-no-capabilities
                          :detail (format nil "~A is still ~(~16,'0X~)" name bits))))

(defun capability-sets (&optional (pathname "/proc/self/status"))
  "Return an alist of the Cap* lines in PATHNAME as (NAME . INTEGER)."
  (with-open-file (stream pathname :direction :input)
    (loop for line = (read-line stream nil nil)
          while line
          when (and (> (length line) 4) (string= "Cap" line :end2 3))
            collect (let ((colon (position #\: line)))
                      (cons (subseq line 0 colon)
                            (parse-integer line :start (1+ colon) :radix 16))))))

;;── Namespaces ─────────────────────────────────────────────────────────────────

(defun write-proc-file (pathname contents operation)
  "Write CONTENTS to PATHNAME in a single write, as /proc requires."
  (handler-case
      (with-open-file (stream pathname :direction :output :if-exists :overwrite
                                       :external-format :latin-1)
        (write-string contents stream)
        (finish-output stream))
    (error (condition)
      (setup-error operation :detail (princ-to-string condition)))))

(defun write-identity-maps (pid)
  "Map the caller's user and group to root inside PID's user namespace.
setgroups must be denied first; an unprivileged process may not otherwise
write a gid map."
  (write-proc-file (format nil "/proc/~D/setgroups" pid) "deny" :deny-setgroups)
  (write-proc-file (format nil "/proc/~D/uid_map" pid)
                   (format nil "0 ~D 1~%" (sb-posix:geteuid)) :write-uid-map)
  (write-proc-file (format nil "/proc/~D/gid_map" pid)
                   (format nil "0 ~D 1~%" (sb-posix:getegid)) :write-gid-map))

(defun namespace-id (name &optional (pid "self"))
  "The inode identifier of namespace NAME, as reported by /proc."
  (let ((link (sb-posix:readlink (format nil "/proc/~A/ns/~A" pid name))))
    link))

;;── clone3 ─────────────────────────────────────────────────────────────────────

(defun seccomp-mode ()
  "This process's seccomp mode, as /proc reports it: 0 when unconfined."
  (with-open-file (stream "/proc/self/status" :direction :input
                                              :if-does-not-exist nil)
    (when stream
      (loop for line = (read-line stream nil nil)
            while line
            when (and (> (length line) 8) (string= "Seccomp:" line :end2 8))
              do (return (or (parse-integer line :start 8 :junk-allowed t) 0))
            finally (return 0)))))

(defun clone3 (flags)
  "Create a child process in fresh namespaces.
Returns the child pid in the parent and 0 in the child.  The child is the
calling thread only: it must not touch Lisp runtime services before execve."
  (cffi:with-foreign-object (args :uint8 +clone-args-size-ver0+)
    (dotimes (index +clone-args-size-ver0+)
      (setf (cffi:mem-aref args :uint8 index) 0))
    (setf (cffi:mem-ref args :uint64 0) flags           ; flags
          (cffi:mem-ref args :uint64 32) +sigchld+)     ; exit_signal
    (let ((result (cffi:foreign-funcall "syscall"
                                        :long +sys-clone3+
                                        :pointer args
                                        :unsigned-long +clone-args-size-ver0+
                                        :long)))
      (when (minusp result)
        (let ((failure (errno)))
          ;; A sandbox refuses the calls a sandbox needs, so scute inside scute
          ;; fails here -- with ENOSYS, which reads as "this kernel is too old"
          ;; and means nothing of the sort.
          (if (and (member failure (list +enosys+ +eperm+))
                   (plusp (or (seccomp-mode) 0)))
              (setup-error
               :clone3
               ;; Through format, because a tilde continuation is format's and
               ;; not the reader's: a plain string keeps the tilde and newline.
               :detail (format nil "scute cannot start a sandbox from inside ~
                                    one: this process is already under a seccomp ~
                                    filter, which refuses the clone3 a new ~
                                    sandbox needs.  Run scute from outside the ~
                                    sandbox."))
              (setup-error :clone3 :errno failure))))
      result)))

(defun make-sync-pipe ()
  "Create the close-on-exec pipe that holds the child until setup completes.
Returns the read and write descriptors."
  (cffi:with-foreign-object (fds :int 2)
    (when (minusp (cffi:foreign-funcall "pipe2" :pointer fds :int +o-cloexec+ :int))
      (setup-error :pipe2 :errno (errno)))
    (values (cffi:mem-aref fds :int 0) (cffi:mem-aref fds :int 1))))

(defun library-loadable-p (soname)
  "Whether SONAME can be resolved and loaded right now."
  (not (cffi:null-pointer-p
        (cffi:foreign-funcall "dlopen" :string soname :int 2 :pointer))))

(defun arm-real-timer (seconds)
  "Ask for SIGALRM in SECONDS, or cancel a pending request when SECONDS is 0.
Whole seconds are not enough: a stop grace period is a deadline a person waits
through, and the tests need one short enough to sit in a suite."
  (cffi:with-foreign-object (timer :uint8 32)       ; two struct timevals
    (dotimes (index 32)
      (setf (cffi:mem-aref timer :uint8 index) 0))
    (multiple-value-bind (whole fraction) (floor seconds)
      (setf (cffi:mem-ref timer :uint64 16) whole   ; it_value.tv_sec
            (cffi:mem-ref timer :uint64 24) (round (* fraction 1000000))))
    (when (minusp (cffi:foreign-funcall "setitimer"
                                        :int +itimer-real+
                                        :pointer timer
                                        :pointer (cffi:null-pointer)
                                        :int))
      (setup-error :setitimer :errno (errno)))))
