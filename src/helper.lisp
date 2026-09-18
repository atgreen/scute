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
  "TEXT split into arguments the way a shell would, honouring quotes.

Splitting on spaces alone was enough until it was not: a helper wanted an
argument with a space in it, and the only answer was to write a wrapper script.
This understands single quotes, double quotes and backslash escapes, which covers
what anyone would type -- and deliberately nothing else.  There is no variable
expansion, no globbing, no command substitution and no operators: the string is
an argument vector written conveniently, not a shell command, and a policy cannot
reach this at all."
  (let ((arguments '())
        (current (make-string-output-stream))
        (started nil)
        (index 0)
        (length (length text)))
    (flet ((finish ()
             (let ((argument (get-output-stream-string current)))
               (when (or started (plusp (length argument)))
                 (push argument arguments))
               (setf started nil))))
      (loop while (< index length)
            for character = (char text index)
            do (cond ((member character '(#\Space #\Tab #\Newline))
                      (finish)
                      (incf index))
                     ((char= character #\\)
                      ;; The next character, whatever it is, taken literally.
                      (setf started t)
                      (incf index)
                      (when (< index length)
                        (write-char (char text index) current)
                        (incf index)))
                     ((char= character #\')
                      ;; Single quotes are literal to the next single quote,
                      ;; backslashes included, as in every shell.
                      (setf started t)
                      (incf index)
                      (loop while (and (< index length) (char/= (char text index) #\'))
                            do (write-char (char text index) current)
                               (incf index))
                      (when (< index length) (incf index)))
                     ((char= character #\")
                      (setf started t)
                      (incf index)
                      (loop while (and (< index length) (char/= (char text index) #\"))
                            do (if (and (char= (char text index) #\\)
                                        (< (1+ index) length))
                                   (progn (write-char (char text (1+ index)) current)
                                          (incf index 2))
                                   (progn (write-char (char text index) current)
                                          (incf index))))
                      (when (< index length) (incf index)))
                     (t
                      (setf started t)
                      (write-char character current)
                      (incf index))))
      (finish))
    (nreverse arguments)))

(defun start-helper (text)
  "Start TEXT as a process beside the sandbox, and answer it."
  (start-helper-arguments (split-command text) text))

(defun start-helper-arguments (command &optional label)
  "Start COMMAND, an argument vector, as a process beside the sandbox.

Started with the same clone3 the sandbox uses rather than with run-program,
because the supervisor must stay single-threaded: a thread would prevent it
creating the user namespace the sandbox needs."
  (let* ((program (resolve-executable (first command)))
         (path (cffi:foreign-string-alloc program))
         (argv (foreign-string-vector command))
         (envp (foreign-string-vector (sb-ext:posix-environ))))
    (finish-output *standard-output*)
    (finish-output *error-output*)
    (let ((pid (clone3 0)))
      (when (zerop pid)
        (%execve path argv envp)
        (%exit 127))
      (%make-helper pid (or label (format nil "~{~A~^ ~}" command))))))

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
