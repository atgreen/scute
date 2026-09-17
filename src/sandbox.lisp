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

;;── The launch plan ────────────────────────────────────────────────────────────
;;
;;; Everything the child touches is allocated here, in the parent, before
;;; clone3.  Slots are untyped on purpose: SBCL stores a foreign pointer in a
;;; typed slot unboxed and would allocate a fresh box on every read, which the
;;; child cannot afford.

(defstruct (launch-plan (:constructor %make-launch-plan))
  command path argv envp envp-count
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
(defconstant +stage-execve+        6)

(defun child-stage-name (stage)
  (case stage
    (#.+stage-pdeathsig+     :child-set-parent-death-signal)
    (#.+stage-sync+          :child-synchronization)
    (#.+stage-clear-ambient+ :child-clear-ambient-capabilities)
    (#.+stage-drop-bounding+ :child-drop-bounding-capabilities)
    (#.+stage-capset+        :child-clear-capabilities)
    (#.+stage-no-new-privs+  :child-set-no-new-privs)
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

(defun resolve-executable (name)
  "Validate NAME as the program to execute.
v0 requires an absolute path; PATH resolution arrives with the landrun exec
stage, which must hand landrun an absolute executable anyway."
  (unless (and (plusp (length name)) (char= #\/ (char name 0)))
    (setup-error :resolve-executable
                 :detail (format nil "~S is not an absolute path" name)))
  name)

(defun compile-launch-plan (command)
  "Compile COMMAND into an immutable plan with every child resource preallocated."
  (unless (and (listp command) command (every #'stringp command))
    (setup-error :compile-launch-plan
                 :detail "command must be a non-empty list of strings"))
  (let ((path (resolve-executable (first command)))
        (environment (sb-ext:posix-environ))
        (last-capability (cap-last-cap)))
    (multiple-value-bind (sync-read sync-write) (make-sync-pipe)
      (multiple-value-bind (status-read status-write) (make-sync-pipe)
        (multiple-value-bind (cap-header cap-data) (make-empty-capability-request)
          (%make-launch-plan
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
           :cap-last last-capability))))))

(defun release-launch-plan (plan)
  "Release every parent-side resource held by PLAN."
  (dolist (fd (list (launch-plan-sync-read plan) (launch-plan-sync-write plan)
                    (launch-plan-status-read plan) (launch-plan-status-write plan)))
    (when (and fd (<= 0 fd)) (%close fd)))
  (cffi:foreign-string-free (launch-plan-path plan))
  (free-foreign-string-vector (launch-plan-argv plan)
                              (length (launch-plan-command plan)))
  (free-foreign-string-vector (launch-plan-envp plan)
                              (launch-plan-envp-count plan))
  (dolist (pointer (list (launch-plan-sync-buffer plan)
                         (launch-plan-status-buffer plan)
                         (launch-plan-cap-header plan)
                         (launch-plan-cap-data plan)))
    (cffi:foreign-free pointer)))

;;── The child ──────────────────────────────────────────────────────────────────

(defun run-child (plan)
  "Become the sandboxed command.  Never returns.

This runs in the process clone3 created, which holds a copy of a Lisp heap no
other thread is maintaining.  It therefore makes foreign calls only: no
allocation, no streams, no conditions, and nothing that could wake the garbage
collector."
  (declare (optimize (speed 3) (safety 0) (debug 0)))
  (let ((status-fd (launch-plan-status-write plan))
        (status-buffer (launch-plan-status-buffer plan)))
    (macrolet ((die (stage exit-code)
                 `(progn
                    (setf (cffi:mem-ref status-buffer :uint8 0) ,stage)
                    (%write status-fd status-buffer 1)
                    (%exit ,exit-code))))
      (%close (launch-plan-sync-write plan))
      ;; Ask the kernel to kill this process if the supervisor dies.  Set
      ;; before the synchronization read, so a supervisor that dies at any
      ;; point either never releases the child or has already armed this.
      (when (minusp (%prctl +pr-set-pdeathsig+ +sigkill+ 0 0 0))
        (die +stage-pdeathsig+ +child-exit-setup-failed+))
      (unless (= 1 (%read (launch-plan-sync-read plan)
                          (launch-plan-sync-buffer plan) 1))
        (die +stage-sync+ +child-exit-sync-failed+))
      (%close (launch-plan-sync-read plan))
      (when (minusp (%prctl +pr-cap-ambient+ +pr-cap-ambient-clear-all+ 0 0 0))
        (die +stage-clear-ambient+ +child-exit-setup-failed+))
      (let ((last-capability (launch-plan-cap-last plan)))
        (declare (type fixnum last-capability))
        (loop for capability of-type fixnum from 0 to last-capability
              do (when (minusp (%prctl +pr-capbset-drop+ capability 0 0 0))
                   (die +stage-drop-bounding+ +child-exit-setup-failed+))))
      (when (minusp (%capset (launch-plan-cap-header plan)
                             (launch-plan-cap-data plan)))
        (die +stage-capset+ +child-exit-setup-failed+))
      (when (minusp (%prctl +pr-set-no-new-privs+ 1 0 0 0))
        (die +stage-no-new-privs+ +child-exit-setup-failed+))
      (%execve (launch-plan-path plan) (launch-plan-argv plan)
               (launch-plan-envp plan))
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

(defun read-child-stage (plan)
  "Wait for the child to reach execve.
Returns NIL once the close-on-exec status pipe reports the exec, or the stage
byte the child wrote just before giving up."
  (let ((fd (launch-plan-status-read plan))
        (buffer (launch-plan-status-buffer plan)))
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

(defun supervise-child (plan pid)
  "Release PID into the sandbox and supervise it until it ends.
Returns its raw wait status, and the stage it failed at if it never reached
the command.  Reaping PID is this function's job alone: nothing above it may
signal a pid that has already been collected."
  (with-forwarded-signals (pid)
    (%close (launch-plan-sync-read plan))
    (setf (launch-plan-sync-read plan) nil)
    (unless (= 1 (%write (launch-plan-sync-write plan)
                         (launch-plan-sync-buffer plan) 1))
      (setup-error :release-child :errno (errno)))
    (%close (launch-plan-sync-write plan))
    (setf (launch-plan-sync-write plan) nil)
    (%close (launch-plan-status-write plan))
    (setf (launch-plan-status-write plan) nil)
    (let ((stage (read-child-stage plan)))
      (values (wait-for-child pid) stage))))

(defun run-namespaced-command (command)
  "Run COMMAND inside fresh user, mount, PID, UTS, and network namespaces.

COMMAND is a list whose first element is an absolute executable path.  The
child becomes PID 1 of its namespace with no capabilities in any set and
no_new_privs set; the parent forwards terminating signals to it and returns a
SANDBOX-RESULT describing how it ended."
  (let ((plan (compile-launch-plan command)))
    (unwind-protect
         (progn
           (finish-output *standard-output*)
           (finish-output *error-output*)
           (let ((pid (clone3 +sandbox-clone-flags+))
                 (reaped nil))
             (when (zerop pid)
               (run-child plan))            ; never returns
             (unwind-protect
                  (progn
                    (write-identity-maps pid)
                    (drop-all-capabilities)
                    (multiple-value-bind (status stage) (supervise-child plan pid)
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
      (release-launch-plan plan))))
