;;; sandbox.lisp
;;;
;;; SPDX-License-Identifier: MIT
;;;
;;; Copyright (C) 2026 Anthony Green

(in-package #:scute)

;;; The kernel-boundary launch sequence.  A long-lived parent supervises one
;;; child that becomes the sandboxed command.  Every control is established
;;; before the child is released, and the child performs nothing but foreign
;;; calls between clone3 and execve.

;;── Results ────────────────────────────────────────────────────────────────────

(defstruct (sandbox-result
            (:constructor make-sandbox-result (pid exit-code term-signal
                                               &optional events)))
  "How a sandboxed command ended.  Exactly one of EXIT-CODE and TERM-SIGNAL is
non-NIL.  EVENTS carries what the kernel recorded about the sandbox's limits,
when limits were asked for."
  (pid         nil :read-only t)
  (exit-code   nil :read-only t)
  (term-signal nil :read-only t)
  (events      nil :read-only t))

(defun sandbox-result-oom-killed-p (result)
  "Whether the memory limit is what ended this command.
A command killed for running out of its own memory looks exactly like one
killed from outside; the cgroup is what tells them apart."
  (and (eql +sigkill+ (sandbox-result-term-signal result))
       (plusp (or (cdr (assoc "memory.oom_kill" (sandbox-result-events result)
                              :test #'string=))
                  0))))

;;── The child's resources ──────────────────────────────────────────────────────
;;
;;; Everything the child touches is allocated here, in the parent, before
;;; clone3.  Slots are untyped on purpose: SBCL stores a foreign pointer in a
;;; typed slot unboxed and would allocate a fresh box on every read, which the
;;; child cannot afford.

(defstruct (launch-resources (:constructor %make-launch-resources))
  command path directory argv envp envp-count landlock-ruleset seccomp-program
  errno-location learn-up-read learn-up-write learn-go-read learn-go-write
  sync-read sync-write status-read status-write
  sync-buffer status-buffer
  cap-header cap-data cap-last)

;;; Stages the child can fail at, reported over the status pipe as one byte.
(defconstant +stage-pdeathsig+     0)
(defconstant +stage-sync+          1)
(defconstant +stage-clear-ambient+ 2)
(defconstant +stage-drop-bounding+ 3)
(defconstant +stage-capset+        4)
(defconstant +stage-no-new-privs+  5)
(defconstant +stage-seccomp+       7)
(defconstant +stage-learn-handshake+ 9)
(defconstant +stage-chdir+        10)
(defconstant +stage-landlock+      8)
(defconstant +stage-execve+        6)

(defun child-stage-name (stage)
  (case stage
    (#.+stage-pdeathsig+     :child-set-parent-death-signal)
    (#.+stage-sync+          :child-synchronization)
    (#.+stage-clear-ambient+ :child-clear-ambient-capabilities)
    (#.+stage-drop-bounding+ :child-drop-bounding-capabilities)
    (#.+stage-capset+        :child-clear-capabilities)
    (#.+stage-no-new-privs+  :child-set-no-new-privs)
    (#.+stage-seccomp+       :child-install-seccomp-filter)
    (#.+stage-learn-handshake+ :child-hand-over-listener)
    (#.+stage-chdir+         :child-enter-directory)
    (#.+stage-landlock+      :child-restrict-self)
    (#.+stage-execve+        :child-execve)
    (t                       :child-unknown)))

(defun foreign-string-vector (strings)
  "Allocate a NULL-terminated char ** holding STRINGS."
  (let ((vector (cffi:foreign-alloc :pointer :count (1+ (length strings)))))
    (loop for string in strings
          for index from 0
          do (setf (cffi:mem-aref vector :pointer index)
                   (cffi:foreign-string-alloc string)))
    (setf (cffi:mem-aref vector :pointer (length strings)) (cffi:null-pointer))
    vector))

(defun free-foreign-string-vector (vector count)
  (dotimes (index count)
    (cffi:foreign-free (cffi:mem-aref vector :pointer index)))
  (cffi:foreign-free vector))

(defun acquire-launch-resources (plan &key learn)
  "Preallocate everything the child will need to enact PLAN.
The Landlock ruleset is built here too: the parent owns every resource, and
the child only uses what is already in its hands."
  (let* ((command (launch-plan-command plan))
         (path (first command))
         (environment (launch-plan-environment plan))
         (last-capability (cap-last-cap))
         (ruleset (compile-filesystem-ruleset (launch-plan-filesystem plan) path))
         ;; Built before the child exists, so a filter that will not build is a
         ;; launch that does not happen.  The program is shared and read-only:
         ;; these resources borrow it rather than owning it.
         (watched nil)
         (filter (if learn
                     (multiple-value-bind (program table) (learn-seccomp-filter)
                       (setf watched table)
                       program)
                     (seccomp-filter-program (v0-seccomp-filter)))))
    (multiple-value-bind (sync-read sync-write) (make-sync-pipe)
      (multiple-value-bind (status-read status-write) (make-sync-pipe)
        (multiple-value-bind (cap-header cap-data) (make-empty-capability-request)
         (multiple-value-bind (learn-up-read learn-up-write)
             (if learn (make-sync-pipe) (values nil nil))
          (multiple-value-bind (learn-go-read learn-go-write)
              (if learn (make-sync-pipe) (values nil nil))
          (values
           (%make-launch-resources
           :command command
           :path (cffi:foreign-string-alloc path)
           :directory (cffi:foreign-string-alloc (launch-plan-directory plan))
           :argv (foreign-string-vector command)
           :envp (foreign-string-vector environment)
           :envp-count (length environment)
           :sync-read sync-read :sync-write sync-write
           :status-read status-read :status-write status-write
           :sync-buffer (cffi:foreign-alloc :uint8 :count 1 :initial-element 0)
           :status-buffer (cffi:foreign-alloc :uint8 :count 8 :initial-element 0)
           ;; Where errno lives for this thread, resolved now: reading it in the
           ;; child must not allocate, and the child is this same thread.
           :errno-location (cffi:foreign-funcall "__errno_location" :pointer)
           :cap-header cap-header :cap-data cap-data
           :cap-last last-capability
           :landlock-ruleset ruleset
           :seccomp-program filter
            :learn-up-read learn-up-read :learn-up-write learn-up-write
            :learn-go-read learn-go-read :learn-go-write learn-go-write)
           watched))))))))

(defun release-launch-resources (resources)
  "Release every parent-side resource RESOURCES holds."
  (dolist (fd (list (launch-resources-sync-read resources)
                    (launch-resources-sync-write resources)
                    (launch-resources-status-read resources)
                    (launch-resources-status-write resources)
                    (launch-resources-landlock-ruleset resources)
                    (launch-resources-learn-up-read resources)
                    (launch-resources-learn-up-write resources)
                    (launch-resources-learn-go-read resources)
                    (launch-resources-learn-go-write resources)))
    (when (and fd (<= 0 fd)) (%close fd)))
  (cffi:foreign-string-free (launch-resources-path resources))
  (cffi:foreign-string-free (launch-resources-directory resources))
  (free-foreign-string-vector (launch-resources-argv resources)
                              (length (launch-resources-command resources)))
  (free-foreign-string-vector (launch-resources-envp resources)
                              (launch-resources-envp-count resources))
  (dolist (pointer (list (launch-resources-sync-buffer resources)
                         (launch-resources-status-buffer resources)
                         (launch-resources-cap-header resources)
                         (launch-resources-cap-data resources)))
    (cffi:foreign-free pointer)))

;;── The child ──────────────────────────────────────────────────────────────────

(defun run-child (resources)
  "Become the sandboxed command.  Never returns.

This runs in the process clone3 created, which holds a copy of a Lisp heap no
other thread is maintaining.  It therefore makes foreign calls only: no
allocation, no streams, no conditions, and nothing that could wake the garbage
collector."
  (declare (optimize (speed 3) (safety 0) (debug 0)))
  (let ((status-fd (launch-resources-status-write resources))
        (status-buffer (launch-resources-status-buffer resources))
        (errno-location (launch-resources-errno-location resources)))
    (macrolet ((die (stage exit-code)
                 ;; errno first: %write would overwrite it.
                 `(progn
                    (setf (cffi:mem-ref status-buffer :uint8 1)
                          (logand 255 (cffi:mem-ref errno-location :int))
                          (cffi:mem-ref status-buffer :uint8 0) ,stage)
                    (%write status-fd status-buffer 2)
                    (%exit ,exit-code))))
      (%close (launch-resources-sync-write resources))
      ;; Ask the kernel to kill this process if the supervisor dies.  Set
      ;; before the synchronization read, so a supervisor that dies at any
      ;; point either never releases the child or has already armed this.
      (when (minusp (%prctl +pr-set-pdeathsig+ +sigkill+ 0 0 0))
        (die +stage-pdeathsig+ +child-exit-setup-failed+))
      (unless (= 1 (%read (launch-resources-sync-read resources)
                          (launch-resources-sync-buffer resources) 1))
        (die +stage-sync+ +child-exit-sync-failed+))
      (%close (launch-resources-sync-read resources))
      (when (minusp (%prctl +pr-cap-ambient+ +pr-cap-ambient-clear-all+ 0 0 0))
        (die +stage-clear-ambient+ +child-exit-setup-failed+))
      (let ((last-capability (launch-resources-cap-last resources)))
        (declare (type fixnum last-capability))
        (loop for capability of-type fixnum from 0 to last-capability
              do (when (minusp (%prctl +pr-capbset-drop+ capability 0 0 0))
                   (die +stage-drop-bounding+ +child-exit-setup-failed+))))
      (when (minusp (%capset (launch-resources-cap-header resources)
                             (launch-resources-cap-data resources)))
        (die +stage-capset+ +child-exit-setup-failed+))
      (when (minusp (%prctl +pr-set-no-new-privs+ 1 0 0 0))
        (die +stage-no-new-privs+ +child-exit-setup-failed+))
      ;; Seccomp before Landlock, and both after no_new_privs, which each
      ;; requires.  The filter allows landlock_restrict_self and execve.
      (let ((listener (%seccomp-install (launch-resources-seccomp-program resources)
                                        (if (launch-resources-learn-up-write resources)
                                            +seccomp-filter-flag-new-listener+
                                            0))))
        (when (minusp listener)
          (die +stage-seccomp+ +child-exit-setup-failed+))
        ;; Learning: hand the listener to the supervisor, wait for it to have
        ;; it, and let go.  A command that kept the listener could answer its
        ;; own notifications.
        (when (launch-resources-learn-up-write resources)
          (setf (cffi:mem-ref status-buffer :int32 0) listener)
          (unless (= 4 (%write (launch-resources-learn-up-write resources)
                               status-buffer 4))
            (die +stage-learn-handshake+ +child-exit-setup-failed+))
          (unless (= 1 (%read (launch-resources-learn-go-read resources)
                              status-buffer 1))
            (die +stage-learn-handshake+ +child-exit-setup-failed+))
          (%close listener)))
      ;; The plan names the directory the command runs in, and --dry-run says
      ;; so; entering it here is what makes that true.  Before Landlock, so that
      ;; a policy need not grant anything merely to arrive.
      (when (minusp (%chdir (launch-resources-directory resources)))
        (die +stage-chdir+ +child-exit-setup-failed+))
      ;; Landlock last, and only after no_new_privs: restrict_self requires it.
      (let ((ruleset (launch-resources-landlock-ruleset resources)))
        (when ruleset
          (when (minusp (%landlock-restrict-self ruleset))
            (die +stage-landlock+ +child-exit-setup-failed+))
          (%close ruleset)))
      (%execve (launch-resources-path resources) (launch-resources-argv resources)
               (launch-resources-envp resources))
      (die +stage-execve+ +child-exit-exec-failed+))))

;;── The parent ─────────────────────────────────────────────────────────────────

(defparameter *stop-grace-seconds* 5
  "How long a sandboxed command is given to act on a stop signal before it is
killed.  A command is free to trap a signal and exit as it likes; it is not
free to ignore one forever.")

(defun observe-child (resources pid observations)
  "Take the listener the child made, let it go, and watch it until it ends.

The child is parked waiting for this: it will not exec until the supervisor
holds the listener, because a command that kept it could answer its own
notifications and wave anything through."
  (cffi:with-foreign-object (buffer :uint8 4)
    (unless (= 4 (%read (launch-resources-learn-up-read resources) buffer 4))
      (setup-error :learn-handshake
                   :detail "the child did not hand over its listener"))
    (let ((listener (steal-listener pid (cffi:mem-ref buffer :int32 0))))
      (setf (cffi:mem-ref buffer :uint8 0) 1)
      (%write (launch-resources-learn-go-write resources) buffer 1)
      (watch-child listener pid observations))))

(defun call-with-forwarded-signals (pid function)
  "Run FUNCTION with terminating signals forwarded to PID, then enforced.

Forwarding alone is not enough.  The command is PID 1 of its namespace, and
pid_namespaces(7) delivers a signal from an ancestor namespace to PID 1 only if
it has a handler installed: SIGKILL and SIGSTOP are the exceptions.  So a
command that installs no handler never sees a forwarded SIGTERM, and a
supervisor that only forwarded would wait for a command that was never told to
stop.  Scute forwards, waits *STOP-GRACE-SECONDS*, and then sends SIGKILL,
which cannot be ignored.  Asking twice does not wait again.

Afterwards the signals are left at their default disposition, which for the
scute process means \"terminate\", so a supervisor whose command is gone can
still be stopped.  SBCL offers no way to read a signal's current handler back
-- ENABLE-INTERRUPT answers NIL, not the handler it replaced -- so a caller
embedding Scute in a larger image must reinstate its own handlers."
  (let* ((signals (list +sighup+ +sigint+ +sigquit+ +sigterm+))
         (state :running)
         (forward (lambda (signal info context)
                    (declare (ignore info context))
                    (%kill pid signal)
                    (case state
                      (:running (setf state :stopping)
                                (arm-real-timer *stop-grace-seconds*))
                      (:stopping (%kill pid +sigkill+)))))
         (enforce (lambda (signal info context)
                    (declare (ignore signal info context))
                    (when (eq state :stopping)
                      (%kill pid +sigkill+)))))
    (dolist (signal signals)
      (sb-sys:enable-interrupt signal forward))
    (sb-sys:enable-interrupt +sigalrm+ enforce)
    (unwind-protect (funcall function)
      ;; Once this runs the child is ours no longer, so a timer that fires from
      ;; here on must do nothing.
      (setf state :finished)
      (arm-real-timer 0)
      (dolist (signal (cons +sigalrm+ signals))
        (sb-sys:enable-interrupt signal :default)))))

(defmacro with-forwarded-signals ((pid) &body body)
  `(call-with-forwarded-signals ,pid (lambda () ,@body)))

(defun read-child-stage (resources)
  "Wait for the child to reach execve.
Answers NIL once the close-on-exec status pipe reports the exec, or the stage
the child failed at and the errno it failed with."
  (let ((fd (launch-resources-status-read resources))
        (buffer (launch-resources-status-buffer resources)))
    (loop for count = (%read fd buffer 2)
          do (cond ((zerop count) (return nil))
                   ((plusp count)
                    (return (values (cffi:mem-ref buffer :uint8 0)
                                    (and (= count 2)
                                         (cffi:mem-ref buffer :uint8 1)))))
                   ((= (errno) +eintr+))
                   (t (setup-error :read-child-status :errno (errno)))))))

(defun wait-for-child (pid)
  "Reap PID and return its raw wait status, retrying across forwarded signals."
  (cffi:with-foreign-object (status :int)
    (loop for result = (%waitpid pid status 0)
          do (cond ((<= 0 result) (return (cffi:mem-ref status :int)))
                   ((= (errno) +eintr+))
                   (t (setup-error :waitpid :errno (errno)))))))

(defun classify-wait-status (pid status &optional events)
  (if (exited-p status)
      (make-sandbox-result pid (exit-status status) nil events)
      (make-sandbox-result pid nil (termination-signal status) events)))

(defun supervise-child (resources pid &optional observe)
  "Release PID into the sandbox and supervise it until it ends.
Returns its raw wait status, and the stage it failed at if it never reached
the command.  Reaping PID is this function's job alone: nothing above it may
signal a pid that has already been collected."
  (with-forwarded-signals (pid)
    (%close (launch-resources-sync-read resources))
    (setf (launch-resources-sync-read resources) nil)
    (unless (= 1 (%write (launch-resources-sync-write resources)
                         (launch-resources-sync-buffer resources) 1))
      (setup-error :release-child :errno (errno)))
    (%close (launch-resources-sync-write resources))
    (setf (launch-resources-sync-write resources) nil)
    (%close (launch-resources-status-write resources))
    (setf (launch-resources-status-write resources) nil)
    (when observe (funcall observe pid))
    (multiple-value-bind (stage child-errno) (read-child-stage resources)
      (values (wait-for-child pid) stage child-errno))))

(defun user-namespaces-available-p ()
  "Whether this kernel will let an unprivileged process create a user namespace."
  (let ((maximum (read-first-line "/proc/sys/user/max_user_namespaces"))
        (permitted (read-first-line "/proc/sys/kernel/unprivileged_userns_clone")))
    (and (or (null maximum) (plusp (or (parse-integer maximum :junk-allowed t) 0)))
         ;; Debian and its descendants carry this switch; most kernels do not.
         (or (null permitted) (string= "1" (string-trim " " permitted))))))

(defun preflight (plan)
  "Check everything PLAN asks for before acquiring any of it.

Failures would surface anyway, one at a time, as each control was installed.
Asking first serves two purposes: nothing is created that then has to be
unwound, and an operator on a host that cannot do the job learns everything
that is wrong at once instead of once per attempt."
  (let ((missing '()))
    (flet ((note (control detail)
             (push (format nil "~A: ~A" control detail) missing)))
      (unless (user-namespaces-available-p)
        (note "user namespaces" "this kernel will not let an unprivileged ~
                                 process create one"))
      (when (launch-plan-filesystem plan)
        (unless (landlock-abi-version)
          (note "landlock" "this kernel does not implement it, and the plan ~
                            asks for filesystem rules")))
      (handler-case (v0-seccomp-filter)
        (scute-error (condition) (note "seccomp" (princ-to-string condition))))
      (when (launch-plan-limits plan)
        (multiple-value-bind (installable root explanation) (limits-installable-p)
          (declare (ignore root))
          (unless installable
            (note "resource limits"
                  (format nil "~A. ~A" explanation +delegation-remedy+))))))
    (when missing
      (setup-error :preflight
                   :detail (format nil "~{~A~^; ~}" (nreverse missing))))
    (refuse-unimplemented-controls plan)))

(defun spawn-sandbox-child (resources)
  "Create the child that will become the command, and answer its pid.

In the child this never returns: it becomes the command, or exits saying which
stage refused.  Buffered output is flushed first, because the child inherits a
copy of it and would write it a second time."
  (finish-output *standard-output*)
  (finish-output *error-output*)
  (let ((pid (clone3 +sandbox-clone-flags+)))
    (when (zerop pid)
      (run-child resources))                ; never returns
    pid))

(defun run-launch-plan (plan &key learn)
  "Enact PLAN: launch its command in the sandbox it describes and supervise it.

Everything PLAN asks for is established before the command exists.  A control
PLAN requests that this build cannot install is an error, not an omission.

With LEARN, the command runs under a filter that reports every path it reaches
for, and what it reached for comes back as a second value."
  (preflight plan)
  ;; Acquisition order follows the design's startup sequence, and every step is
  ;; unwound in reverse by the unwind-protects below.
  (let ((cgroup (let ((limits (launch-plan-limits plan)))
                  (and limits (create-sandbox-cgroup limits))))
        (resources nil)
        (observations nil))
    (unwind-protect
         (progn
           (multiple-value-bind (acquired watched)
               (acquire-launch-resources plan :learn learn)
             (setf resources acquired
                   observations (and learn (make-observations watched))))
           (let ((pid (spawn-sandbox-child resources))
                 (reaped nil))
             (unwind-protect
                  (progn
                    (write-identity-maps pid)
                    (when cgroup
                      (move-process-to-cgroup pid cgroup))
                    (drop-all-capabilities)
                    (verify-no-capabilities)
                    (multiple-value-bind (status stage child-errno)
                        (supervise-child resources pid
                                         (when learn
                                           (lambda (child)
                                             (observe-child resources child observations))))
                      (setf reaped t)
                      (when stage
                        (error 'child-failure :operation (child-stage-name stage)
                                              :status status
                                              :errno child-errno))
                      (values (classify-wait-status
                               pid status
                               (and cgroup (read-cgroup-events cgroup)))
                              observations)))
               ;; Setup failed with the child still parked on the pipe, or the
               ;; wait was abandoned: it must not be left behind.  Once PID has
               ;; been reaped it is no longer ours to signal.
               (unless reaped
                 (%kill pid +sigkill+)
                 (%waitpid pid (cffi:null-pointer) 0)))))
      (when resources (release-launch-resources resources))
      (when cgroup (delete-sandbox-cgroup cgroup)))))

(defun run-namespaced-command (command &key filesystem directory)
  "Run COMMAND in the sandbox that FILESYSTEM describes.

COMMAND is a list whose first element is an absolute executable path.  The
child becomes PID 1 of fresh user, mount, pid, uts, and network namespaces
with no capabilities in any set and no_new_privs set; the parent forwards
terminating signals to it and returns a SANDBOX-RESULT describing how it
ended.  FILESYSTEM is a list of (KIND PATH) forms compiled into one Landlock
ruleset; with none, the filesystem is not restricted.

This is the path a caller with no policy file takes.  It builds the same
launch plan a policy would and enacts it."
  (run-launch-plan (compile-command-launch-plan command filesystem directory)))
