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
    (command-not-found (condition)
      (die 127 "~A" condition))                   ; as a shell reports one
    (child-failure (condition)
      ;; A command that exists but could not be run is 126, as in a shell; one
      ;; that vanished between the plan and the exec is 127.
      (die (if (eq :child-execve (child-failure-operation condition))
               (case (child-failure-errno condition)
                 (#.+enoent+ 127)
                 (t 126))
               1)
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
            ((clingon:getopt cmd :explain)
             (multiple-value-bind (result observations)
                 (run-launch-plan plan :observe t)
               (let ((refused (refused-observations observations
                                                    (launch-plan-filesystem plan))))
                 (if refused
                     (report-refusals refused (launch-plan-directory plan)
                                      *error-output*)
                     (format *error-output*
                             "~&scute: the policy allowed everything the command ~
                              reached for~%")))
               (uiop:quit (command-exit-status result) t)))
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
                    :description "Policy file describing the sandbox"))
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
                    :description "Print the compiled plan and run nothing")
                   (clingon:make-option
                    :flag :long-name "explain" :key :explain
                    :description "Say which paths the policy refused, and what would allow them")))
   :handler #'run-handler
   :examples '(("Run a shell under a policy file:"
                . "scute run --policy scute.policy -- sh -i")
               ("Show what a policy would do, without running it:"
                . "scute run --policy scute.policy --dry-run -- sh -i")
               ("Run a shell that can read the system and write only here:"
                . "scute run --read-execute /usr --read /etc --read-write . -- sh -i")
               ("Find out what a policy is refusing:"
                . "scute run --policy scute.policy --explain -- ./build.sh")
               ("Run with the process layer alone, filesystem unrestricted:"
                . "scute run --namespaces-only -- sh -i"))))

(defun report-path-access (rules path stream)
  "Say what RULES allow at PATH.  Answers whether anything is allowed at all."
  (multiple-value-bind (report examined) (path-access-report rules path)
    (let* ((granted (remove nil report :key #'cdr))
           (accesses (mapcar #'car granted))
           ;; One path can draw its accesses from more than one rule, so name
           ;; every rule involved rather than whichever came first.
           (rules-involved (remove-duplicates (mapcar #'cdr granted))))
      (format stream "~&~A~30T~{~(~A~)~^ ~}~:[nothing~;~]" path accesses accesses)
      (when rules-involved
        (format stream "~48T(~{~(~A~) ~A~^, ~})"
                (loop for rule in rules-involved
                      append (list (path-rule-kind rule) (path-rule-path rule)))))
      ;; "via" belongs only where the path itself does not exist and its nearest
      ;; existing ancestor is what governs it.
      (cond ((null examined)
             (format stream "~48T(no part of this path exists)"))
            ((not (probe-file path))
             (format stream " via ~A" examined)))
      (terpri stream)
      (and granted t))))

(defun check-handler (cmd)
  (reporting-failures
   (let ((policy (clingon:getopt cmd :policy))
         (paths (clingon:command-arguments cmd)))
     (unless policy
       (usage-error "scute check needs a policy: --policy FILE"))
     (unless paths
       (usage-error "scute check needs one or more paths to ask about"))
     (let* ((plan (compile-launch-plan (read-sandbox-policy policy) '("/bin/true")))
            (rules (launch-plan-filesystem plan))
            (denied 0))
       (dolist (path paths)
         (unless (report-path-access rules path *standard-output*)
           (incf denied)))
       (uiop:quit (if (plusp denied) 1 0) t)))))

(defun make-check-command ()
  (clingon:make-command
   :name "check"
   :description "Ask a policy what it allows at a path"
   :usage "--policy FILE PATH [PATH ...]"
   :options (list (clingon:make-option
                   :string :long-name "policy" :key :policy
                   :description "Policy file to ask about"))
   :handler #'check-handler
   :examples '(("Will the build be able to write here?"
                . "scute check --policy scute.policy . /usr/bin/gcc /etc/passwd"))))

(defun learn-handler (cmd)
  (reporting-failures
   (let ((command (clingon:command-arguments cmd))
         (output (clingon:getopt cmd :output)))
     (unless command
       (usage-error "scute learn needs a command to watch: learn -- COMMAND ..."))
     (multiple-value-bind (result observations)
         (run-launch-plan (compile-command-launch-plan command '()) :observe t)
       (let ((rules (learned-rules observations (sb-posix:getcwd))))
         (if output
             (with-open-file (stream output :direction :output
                                            :if-exists :supersede
                                            :if-does-not-exist :create)
               (write-learned-policy rules stream :command command)
               (format *error-output* "~&scute: wrote ~A~%" output))
             (write-learned-policy rules *standard-output* :command command)))
       (uiop:quit (command-exit-status result) t)))))

(defun make-learn-command ()
  (clingon:make-command
   :name "learn"
   :description "Watch a command and write the policy it would have needed"
   :usage "[--output FILE] -- COMMAND [ARGUMENT ...]"
   :options (list (clingon:make-option
                   :string :short-name #\o :long-name "output" :key :output
                   :description "Write the policy here instead of to standard output"))
   :handler #'learn-handler
   :examples '(("Find out what a build actually touches:"
                . "scute learn -- make")
               ("Keep the answer:"
                . "scute learn --output scute.policy -- ./run-tests"))))

;;── doctor ─────────────────────────────────────────────────────────────────────

(defun doctor-handler (cmd)
  (reporting-failures
   (let* ((report (doctor-report))
          (ready (if (clingon:getopt cmd :json)
                     (print-doctor-json report)
                     (print-doctor-report report))))
     (uiop:quit (if ready 0 1) t))))

(defun make-doctor-command ()
  (clingon:make-command
   :name "doctor"
   :description "Report which sandbox controls this host can enforce"
   :usage "[--json]"
   :options (list (clingon:make-option
                   :flag :long-name "json" :key :json
                   :description "Report as JSON instead of for a person"))
   :handler #'doctor-handler
   :examples '(("Check whether this host can sandbox at all:" . "scute doctor")
               ("The same, for a script:" . "scute doctor --json"))))

(defun completions-handler (cmd)
  (reporting-failures
   (let ((shell (first (clingon:command-arguments cmd))))
     (unless shell
       (usage-error "which shell? scute completions bash|zsh|fish"))
     (write-completions shell)
     (uiop:quit 0 t))))

(defun make-completions-command ()
  (clingon:make-command
   :name "completions"
   :description "Write shell completions, generated from scute's own commands"
   :usage "bash|zsh|fish"
   :handler #'completions-handler
   :examples '(("Complete scute in this shell, now:"
                . "source <(scute completions bash)")
               ("Install them for everyone:"
                . "scute completions bash > /etc/bash_completion.d/scute"))))

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
   :sub-commands (list (make-run-command) (make-learn-command)
                       (make-check-command) (make-doctor-command)
                       (make-completions-command))
   :handler (lambda (cmd)
              (clingon:print-usage-and-exit cmd *standard-output*))))

(defun main ()
  "The main entrypoint."
  (clingon:run (make-app)))
