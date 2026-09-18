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
    (policy-error (condition)
      (die 65 "~A" condition))                    ; EX_DATAERR: the policy is bad
    (child-failure (condition)
      (die (if (eq :child-execve (child-failure-operation condition)) 127 1)
           "~A" condition))
    (scute-error (condition)
      (die 1 "~A" condition))))

(defmacro reporting-failures (&body body)
  `(call-reporting-failures (lambda () ,@body)))

;;── run ────────────────────────────────────────────────────────────────────────

(defparameter +nothing-declared-message+
  "Say what the sandbox allows.  Either name a policy file:

  --policy FILE

or describe the filesystem on the command line:

  --read PATH                 read files and list directories beneath PATH
  --read-execute PATH         the same, plus execute
  --read-write PATH           read, write, create, delete, and rename beneath PATH
  --read-write-execute PATH   the same, plus execute

Nothing outside those paths can be opened.  To run with no filesystem
restriction at all, say so with --namespaces-only."
  "Said when a caller asks for a sandbox without saying what it permits.  An
unrestricted sandbox has to be asked for by name; it is not what forgetting an
argument gets you.")

(defparameter +filesystem-options+
  '((:read . "read") (:read-execute . "read-execute")
    (:read-write . "read-write") (:read-write-execute . "read-write-execute"))
  "The access kinds a caller may name, and the option that names each.")

(defun filesystem-rules (cmd)
  "The (KIND PATH) forms CMD's filesystem options ask for."
  (loop for (kind . nil) in +filesystem-options+
        append (mapcar (lambda (path) (list kind path))
                       (clingon:getopt cmd kind))))

(defun run-handler (cmd)
  (reporting-failures
   (run-command cmd)))

(defun launch-plan-for (cmd command)
  "The plan CMD's options describe, however the caller chose to describe it."
  (let ((policy (clingon:getopt cmd :policy))
        (namespaces-only (clingon:getopt cmd :namespaces-only))
        (rules (filesystem-rules cmd)))
    (cond ((and policy rules)
           (usage-error "--policy already says what the filesystem allows; drop the --read options or the policy"))
          ((and policy namespaces-only)
           (usage-error "--policy and --namespaces-only ask for different things"))
          ((and rules namespaces-only)
           (usage-error "--namespaces-only asks for no filesystem restriction, but filesystem rules were given too"))
          (policy
           (compile-launch-plan (read-sandbox-policy policy) command))
          ((or rules namespaces-only)
           (compile-command-launch-plan command rules))
          (t
           (usage-error +nothing-declared-message+)))))

(defun run-command (cmd)
  (let ((command (clingon:command-arguments cmd)))
    (when (null command)
      (usage-error "no command given; see scute run --help"))
    (let ((plan (launch-plan-for cmd command)))
      (cond ((clingon:getopt cmd :dry-run)
             ;; Print first, then refuse: the plan is what the caller asked to
             ;; see, and a refusal explains itself better beside it.
             (print-launch-plan plan)
             (refuse-unimplemented-controls plan)
             (uiop:quit 0 t))
            (t
             (let ((result (run-launch-plan plan)))
               (when (sandbox-result-oom-killed-p result)
                 (format *error-output*
                         "~&scute: the command was killed by its memory limit~%"))
               (uiop:quit (command-exit-status result) t)))))))

(defun make-run-command ()
  (clingon:make-command
   :name "run"
   :description "Run a command inside the sandbox"
   :usage "[--policy FILE | --read PATH ...] -- COMMAND [ARGUMENT ...]"
   :options (append
             (list (clingon:make-option
                    :string :long-name "policy" :key :policy
                    :description "Policy file describing the sandbox (not yet implemented)"))
             (mapcar (lambda (entry)
                       (destructuring-bind (kind . name) entry
                         (clingon:make-option
                          :list :long-name name :key kind :parameter "PATH"
                          :description (format nil "Grant ~(~A~) access beneath PATH"
                                               (substitute #\Space #\- name)))))
                     +filesystem-options+)
             (list (clingon:make-option
                    :flag :long-name "namespaces-only" :key :namespaces-only
                    :description "Run with no filesystem restriction at all")
                   (clingon:make-option
                    :flag :short-name #\n :long-name "dry-run" :key :dry-run
                    :description "Print the compiled plan and run nothing")))
   :handler #'run-handler
   :examples '(("Run a shell under a policy file:"
                . "scute run --policy scute.policy -- /bin/sh -i")
               ("Show what a policy would do, without running it:"
                . "scute run --policy scute.policy --dry-run -- /bin/sh -i")
               ("Run a shell that can read the system and write only here:"
                . "scute run --read-execute /usr --read /etc --read-write . -- /bin/sh -i")
               ("Run with the process layer alone, filesystem unrestricted:"
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
