;;; helper.lisp
;;;
;;; SPDX-License-Identifier: MIT
;;;
;;; Copyright (C) 2026 Anthony Green

(in-package #:scute)

;;; A process that runs beside the sandbox, outside it.
;;;
;;; The case this exists for is a credential proxy: the sandbox holds an opaque
;;; token, the proxy holds the real secret and swaps one for the other, and
;;; nothing in the sandbox can reach the network except through it.  Scute
;;; already provides the two halves that make that airtight -- a policy naming
;;; the proxy grants its port and only its port, and the environment filter means
;;; the real credential was never in the sandbox to begin with -- but the operator
;;; had to start the proxy themselves and remember to stop it.
;;;
;;; What it deliberately does not do is take the command from a policy.  A policy
;;; travels with the code being sandboxed; a policy that could start a process on
;;; the host would be a way to run anything at all.  The helper is named on the
;;; command line, where the person running it types it.

(defstruct (helper (:constructor %make-helper (pid command)))
  (pid nil :read-only t)
  (command nil :read-only t))

(defun split-command (text)
  "TEXT split on spaces, which is as much shell as this needs to be."
  (remove "" (uiop:split-string text :separator " ") :test #'string=))

(defun start-helper (text)
  "Start TEXT as a process beside the sandbox, and answer it.

Started with the same clone3 the sandbox uses rather than with run-program,
because the supervisor must stay single-threaded: a thread would prevent it
creating the user namespace the sandbox needs."
  (let* ((command (split-command text))
         (program (resolve-executable (first command)))
         (path (cffi:foreign-string-alloc program))
         (argv (foreign-string-vector command))
         (envp (foreign-string-vector (sb-ext:posix-environ))))
    (finish-output *standard-output*)
    (finish-output *error-output*)
    (let ((pid (clone3 0)))
      (when (zerop pid)
        (%execve path argv envp)
        (%exit 127))
      (%make-helper pid text))))

(defun helper-running-p (helper)
  (cffi:with-foreign-object (status :int)
    (zerop (%waitpid (helper-pid helper) status 1))))   ; WNOHANG

(defun wait-for-port (port seconds)
  "Wait until something accepts connections on PORT, or give up."
  (loop with deadline = (+ (get-internal-real-time)
                           (* seconds internal-time-units-per-second))
        do (handler-case
               (let ((socket (make-instance 'sb-bsd-sockets:inet-socket
                                            :type :stream :protocol :tcp)))
                 (unwind-protect
                      (progn (sb-bsd-sockets:socket-connect socket #(127 0 0 1) port)
                             (return t))
                   (ignore-errors (sb-bsd-sockets:socket-close socket))))
             (error () nil))
           (when (> (get-internal-real-time) deadline) (return nil))
           (sleep 1/50)))

(defun stop-helper (helper)
  "Ask the helper to stop, then insist.
Its work is over when the sandbox's is: leaving a credential proxy listening
after the command that needed it has gone is how a token outlives its purpose."
  (%kill (helper-pid helper) +sigterm+)
  (loop repeat 100                                 ; two seconds, then insist
        while (helper-running-p helper)
        do (sleep 1/50))
  (when (helper-running-p helper)
    (%kill (helper-pid helper) +sigkill+))
  (cffi:with-foreign-object (status :int)
    (%waitpid (helper-pid helper) status 0))
  t)

(defun call-with-helper (text port function)
  "Run FUNCTION with TEXT running beside it, waiting for PORT first."
  (if (null text)
      (funcall function)
      (let ((helper (start-helper text)))
        (unwind-protect
             (progn
               (when (and port (not (wait-for-port port 10)))
                 (setup-error :start-helper
                              :detail (format nil "~S did not answer on port ~D ~
                                                   within ten seconds"
                                              text port)))
               (funcall function))
          (stop-helper helper)))))
