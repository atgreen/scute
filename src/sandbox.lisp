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
            (:constructor make-sandbox-result (pid exit-code term-signal)))
  "How a sandboxed command ended.  Exactly one of EXIT-CODE and TERM-SIGNAL is
non-NIL."
  (pid         nil :read-only t)
  (exit-code   nil :read-only t)
  (term-signal nil :read-only t))

;;── The child's resources ──────────────────────────────────────────────────────
;;
;;; Everything the child touches is allocated here, in the parent, before
;;; clone3.  Slots are untyped on purpose: SBCL stores a foreign pointer in a
;;; typed slot unboxed and would allocate a fresh box on every read, which the
;;; child cannot afford.

(defstruct (launch-resources (:constructor %make-launch-resources))
  command path argv envp envp-count landlock-ruleset seccomp-program
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

(defun acquire-launch-resources (plan)
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
         (filter (v0-seccomp-filter)))
    (multiple-value-bind (sync-read sync-write) (make-sync-pipe)
      (multiple-value-bind (status-read status-write) (make-sync-pipe)
        (multiple-value-bind (cap-header cap-data) (make-empty-capability-request)
          (%make-launch-resources
           :command command
           :path (cffi:foreign-string-alloc path)
           :argv (foreign-string-vector command)
           :envp (foreign-string-vector environment)
           :envp-count (length environment)
           :sync-read sync-read :sync-write sync-write
           :status-read status-read :status-write status-write
           :sync-buffer (cffi:foreign-alloc :uint8 :count 1 :initial-element 0)
           :status-buffer (cffi:foreign-alloc :uint8 :count 1 :initial-element 0)
           :cap-header cap-header :cap-data cap-data
           :cap-last last-capability
           :landlock-ruleset ruleset
           :seccomp-program (seccomp-filter-program filter)))))))

(defun release-launch-resources (resources)
  "Release every parent-side resource RESOURCES holds."
  (dolist (fd (list (launch-resources-sync-read resources)
                    (launch-resources-sync-write resources)
                    (launch-resources-status-read resources)
                    (launch-resources-status-write resources)
                    (launch-resources-landlock-ruleset resources)))
    (when (and fd (<= 0 fd)) (%close fd)))
  (cffi:foreign-string-free (launch-resources-path resources))
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
        (status-buffer (launch-resources-status-buffer resources)))
    (macrolet ((die (stage exit-code)
                 `(progn
                    (setf (cffi:mem-ref status-buffer :uint8 0) ,stage)
                    (%write status-fd status-buffer 1)
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
      (when (minusp (%seccomp-install (launch-resources-seccomp-program resources)))
        (die +stage-seccomp+ +child-exit-setup-failed+))
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

(defun call-with-forwarded-signals (pid function)
  "Run FUNCTION with terminating signals forwarded to PID.

Afterwards the signals are left at their default disposition, which for the
scute process means \"terminate\", so a supervisor whose command is gone can
still be stopped.  SBCL offers no way to read a signal's current handler back
-- ENABLE-INTERRUPT answers NIL, not the handler it replaced -- so a caller
embedding Scute in a larger image must reinstate its own handlers."
  (let* ((signals (list +sighup+ +sigint+ +sigquit+ +sigterm+))
         (forward (lambda (signal info context)
                    (declare (ignore info context))
                    (%kill pid signal))))
    (dolist (signal signals)
      (sb-sys:enable-interrupt signal forward))
    (unwind-protect (funcall function)
      (dolist (signal signals)
        (sb-sys:enable-interrupt signal :default)))))

(defmacro with-forwarded-signals ((pid) &body body)
  `(call-with-forwarded-signals ,pid (lambda () ,@body)))

(defun read-child-stage (resources)
  "Wait for the child to reach execve.
Returns NIL once the close-on-exec status pipe reports the exec, or the stage
byte the child wrote just before giving up."
  (let ((fd (launch-resources-status-read resources))
        (buffer (launch-resources-status-buffer resources)))
    (loop for count = (%read fd buffer 1)
          do (cond ((zerop count) (return nil))
                   ((= count 1) (return (cffi:mem-ref buffer :uint8 0)))
                   ((= (errno) +eintr+))
                   (t (setup-error :read-child-status :errno (errno)))))))

(defun wait-for-child (pid)
  "Reap PID and return its raw wait status, retrying across forwarded signals."
  (cffi:with-foreign-object (status :int)
    (loop for result = (%waitpid pid status 0)
          do (cond ((<= 0 result) (return (cffi:mem-ref status :int)))
                   ((= (errno) +eintr+))
                   (t (setup-error :waitpid :errno (errno)))))))

(defun classify-wait-status (pid status)
  (if (exited-p status)
      (make-sandbox-result pid (exit-status status) nil)
      (make-sandbox-result pid nil (termination-signal status))))

(defun supervise-child (resources pid)
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
    (let ((stage (read-child-stage resources)))
      (values (wait-for-child pid) stage))))

(defun run-launch-plan (plan)
  "Enact PLAN: launch its command in the sandbox it describes and supervise it.

Everything PLAN asks for is established before the command exists.  A control
PLAN requests that this build cannot install is an error, not an omission."
  (refuse-unimplemented-controls plan)
  (let ((resources (acquire-launch-resources plan)))
    (unwind-protect
         (progn
           (finish-output *standard-output*)
           (finish-output *error-output*)
           (let ((pid (clone3 +sandbox-clone-flags+))
                 (reaped nil))
             (when (zerop pid)
               (run-child resources))       ; never returns
             (unwind-protect
                  (progn
                    (write-identity-maps pid)
                    (drop-all-capabilities)
                    (verify-no-capabilities)
                    (multiple-value-bind (status stage) (supervise-child resources pid)
                      (setf reaped t)
                      (when stage
                        (error 'child-failure :operation (child-stage-name stage)
                                              :status status))
                      (classify-wait-status pid status)))
               ;; Setup failed with the child still parked on the pipe, or the
               ;; wait was abandoned: it must not be left behind.  Once PID has
               ;; been reaped it is no longer ours to signal.
               (unless reaped
                 (%kill pid +sigkill+)
                 (%waitpid pid (cffi:null-pointer) 0)))))
      (release-launch-resources resources))))

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
