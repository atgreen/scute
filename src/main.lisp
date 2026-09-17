;;; main.lisp
;;;
;;; SPDX-License-Identifier: MIT
;;;
;;; Copyright (C) 2026 Anthony Green

(in-package #:scute)

(version-string:define-version-parameter +version+ :scute)

;;── Exit status ────────────────────────────────────────────────────────────────

(defun command-exit-status (result)
  "The status Scute exits with to report RESULT, by shell convention: the
command's own code, or 128 plus the signal that killed it."
  (or (sandbox-result-exit-code result)
      (+ 128 (sandbox-result-term-signal result))))

(defun die (status format-control &rest format-arguments)
  "Report a failure on stderr and leave with STATUS."
  (format *error-output* "~&scute: ~?~%" format-control format-arguments)
  (uiop:quit status t))

(defun call-reporting-failures (thunk)
  "Run THUNK, turning Scute's conditions into a message and an exit status.
clingon:run has its own catch-all that prints a condition and exits 1, so a
handler outside it would never see these: the reporting belongs here, where
the exit status can say what kind of failure it was."
  (handler-case (funcall thunk)
    (usage-error (condition)
      (die 64 "~A" condition))                    ; EX_USAGE, as clingon uses
    (child-failure (condition)
      (die (if (eq :child-execve (child-failure-operation condition)) 127 1)
           "~A" condition))
    (scute-error (condition)
      (die 1 "~A" condition))))

(defmacro reporting-failures (&body body)
  `(call-reporting-failures (lambda () ,@body)))

;;── run ────────────────────────────────────────────────────────────────────────

(defparameter +policy-pending-message+
  "Policy enforcement is not implemented yet.  This build installs the process
layer only: fresh user, mount, pid, uts, and network namespaces, every
capability set emptied, and no_new_privs.  The filesystem is NOT restricted,
no resource limits are applied, and no seccomp filter is installed.

Pass --namespaces-only to accept exactly that and run anyway."
  "Said whenever someone asks for enforcement this build cannot provide.  A
sandbox that quietly does less than it was asked for is worse than no sandbox,
because it is believed.")

(defun run-handler (cmd)
  (reporting-failures
   (run-command cmd)))

(defun run-command (cmd)
  (let ((policy (clingon:getopt cmd :policy))
        (namespaces-only (clingon:getopt cmd :namespaces-only))
        (command (clingon:command-arguments cmd)))
    (cond ((and policy namespaces-only)
           (usage-error "--policy and --namespaces-only are exclusive"))
          ((null command)
           (usage-error "no command given; see scute run --help"))
          ((not namespaces-only)
           (usage-error +policy-pending-message+))
          (t
           (uiop:quit (command-exit-status (run-namespaced-command command)) t)))))

(defun make-run-command ()
  (clingon:make-command
   :name "run"
   :description "Run a command inside the sandbox"
   :usage "--namespaces-only -- COMMAND [ARGUMENT ...]"
   :options (list (clingon:make-option
                   :string :long-name "policy" :key :policy
                   :description "Policy file describing the sandbox (not yet implemented)")
                  (clingon:make-option
                   :flag :long-name "namespaces-only" :key :namespaces-only
                   :description "Accept the process layer alone, with no policy enforcement"))
   :handler #'run-handler
   :examples '(("Run a shell with the process layer alone:"
                . "scute run --namespaces-only -- /bin/sh -i"))))

;;── doctor ─────────────────────────────────────────────────────────────────────

(defun doctor-handler (cmd)
  (declare (ignore cmd))
  (reporting-failures
   (uiop:quit (if (print-doctor-report (doctor-report)) 0 1) t)))

(defun make-doctor-command ()
  (clingon:make-command
   :name "doctor"
   :description "Report which sandbox controls this host can enforce"
   :usage ""
   :handler #'doctor-handler))

;;── CLI ────────────────────────────────────────────────────────────────────────

(defun make-app ()
  "Create and return the command-line application."
  (clingon:make-command
   :name    "scute"
   :version +version+
   :description "Run one command inside a deny-by-default Linux sandbox"
   :authors (list "Anthony Green <green@moxielogic.com>")
   :license "MIT"
   :usage "[GLOBAL-OPTIONS] COMMAND [OPTIONS] [ARGUMENTS ...]"
   :sub-commands (list (make-run-command) (make-doctor-command))
   :handler (lambda (cmd)
              (clingon:print-usage-and-exit cmd *standard-output*))))

(defun main ()
  "The main entrypoint."
  (clingon:run (make-app)))
