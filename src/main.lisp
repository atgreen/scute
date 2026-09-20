;;; main.lisp
;;;
;;; SPDX-License-Identifier: MIT
;;;
;;; Copyright (C) 2026 Anthony Green

(in-package #:scute)

(version-string:define-version-parameter +version+ :scute)

;;── Exit status ────────────────────────────────────────────────────────────────

(defconstant +exit-timed-out+ 124
  "What timeout(1) answers when it has to stop a command, and so does scute.")

(defun command-exit-status (result)
  "The status Scute exits with to report RESULT, by shell convention: the
command's own code, or 128 plus the signal that killed it -- except a command
stopped for taking too long, which is 124 as timeout(1) has it, because the
signal that ended it says nothing about why."
  (cond ((sandbox-result-timed-out result) +exit-timed-out+)
        ((sandbox-result-exit-code result))
        (t (+ 128 (sandbox-result-term-signal result)))))

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
restriction at all, say so with --namespaces-only.

Or have Scute write the policy by watching the command run once:

  scute learn --output scute.policy -- COMMAND"
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

(defmacro with-timeout-from (duration plan-form)
  "PLAN-FORM's plan, with DURATION as its wall-clock limit when one was given."
  `(let ((plan ,plan-form)
         (duration ,duration))
     (if duration
         (plan-with-wall-clock
          plan
          ;; A bad duration on the command line is the caller's mistake, not a
          ;; policy that will not do.
          (handler-case (parse-duration duration nil)
            (policy-error (condition)
              (usage-error (princ-to-string condition)))))
         plan)))

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
           (compile-launch-plan (read-sandbox-policy policy) command
                                :keep (clingon:getopt cmd :keep-env)))
          ((or rules namespaces-only)
           (compile-command-launch-plan command rules nil
                                        (clingon:getopt cmd :keep-env)))
          (t
           (usage-error +nothing-declared-message+)))))

(defun interactive-error-output-p ()
  "Whether somebody is reading stderr, rather than a file or a pipe."
  (plusp (cffi:foreign-funcall "isatty" :int 2 :int)))

(defun offer-explanation (plan result &optional already-explained)
  "Say how to find out which paths a failing command was refused.

A sandboxed command reports its own confusion -- \"Permission denied\", from
somewhere inside a library -- and nothing in that says a sandbox was involved or
that Scute can answer the question.  Someone who does not already know about
--explain has no way to learn it at the moment they need it, and will reasonably
conclude the filesystem is broken.

Only when a person is watching, because a non-zero exit is ordinary in a script
and this would be noise there.  Only when the policy restricts the filesystem, so
there is something --explain could find.  SCUTE_NO_HINTS=1 turns it off."
  (when (and (launch-plan-filesystem plan)
             (not (zerop (command-exit-status result)))
             ;; Not when the failure has already been accounted for.  A command
             ;; refused a credential fails for a reason the broker just printed,
             ;; and following that with "if a path was refused" sends somebody to
             ;; look at the filesystem for a network answer.
             (not already-explained)
             (interactive-error-output-p)
             (not (sb-posix:getenv "SCUTE_NO_HINTS")))
    (format *error-output*
            "~&scute: the command failed.  If a path was refused, this says which:~%~
             ~&       scute run --explain ...~%")))

(defun policy-names-a-command-p (cmd)
  "Whether the policy this invocation names carries a command of its own.

Read here rather than assumed, so that \"no command given\" stays the answer for
a policy that does not name one -- which is most of them."
  (let ((policy (clingon:getopt cmd :policy)))
    ;; Errors are not swallowed here: a policy that cannot be found or parsed
    ;; must say so, rather than becoming "no command given" -- which is what
    ;; somebody sees after mistyping the name of a shipped policy, and which
    ;; sends them looking in the wrong place entirely.
    (and policy (sandbox-policy-command (read-sandbox-policy policy)) t)))

(defun run-command (cmd)
  (let ((command (clingon:command-arguments cmd)))
    (when (and (null command) (not (policy-names-a-command-p cmd)))
      (usage-error "no command given; see scute run --help"))
    ;; Before anything is built: a plan needing a cgroup of Scute's own is
    ;; better re-executed in one than refused with instructions.  This happens
    ;; first so that the plan is compiled by the process that will enact it --
    ;; including whether the proxy can be pinned to its address, which the answer
    ;; to this question changes.
    (let ((preview (launch-plan-for cmd command)))
      (ensure-own-cgroup (launch-plan-limits preview) (launch-plan-proxy preview)))
    (let ((plan (plan-with-proxy-bound-by-address
                 (revised-launch-plan
                 (launch-plan-for cmd command)
                 :wall-clock (let ((duration (clingon:getopt cmd :timeout)))
                               (if duration
                                   (handler-case (parse-duration duration nil)
                                     (policy-error (condition)
                                       (usage-error (princ-to-string condition))))
                                   :keep))
                 :unix-sockets (if (clingon:getopt cmd :allow-unix-sockets)
                                   t
                                   :keep)))))
      ;; A dry run answers before anything is started: no helper, no broker, and
      ;; above all no secret read.  Printing what would happen must not be a way
      ;; to make some of it happen.
      (when (clingon:getopt cmd :dry-run)
        ;; Print first, then refuse: the plan is what the caller asked to see,
        ;; and a refusal explains itself better beside it.
        (print-launch-plan plan)
        (refuse-unimplemented-controls plan)
        (uiop:quit 0 t))
      (call-with-helper
       (clingon:getopt cmd :with)
       (let ((proxy (launch-plan-proxy plan)))
         (and proxy (proxy-url-port proxy nil)))
       (lambda ()
        (call-with-broker
         plan
         (lambda (plan)
      (cond ((launch-plan-audit plan)
             (multiple-value-bind (result observations)
                 (run-launch-plan plan :observe t)
               (let ((events (audit-policy-events (launch-plan-audit plan)))
                     (destination (clingon:getopt cmd :audit)))
                 (flet ((trail (stream)
                          (write-audit-trail observations events stream
                                             :command (launch-plan-command plan))
                          ;; The broker's half of the same run, on the same
                          ;; terms: one JSON object per line, already carrying
                          ;; the task id that ties them together.
                          (when *broker*
                            (dolist (event (broker-events *broker*))
                              (write-line event stream)))))
                   (if destination
                       (with-open-file (stream destination :direction :output
                                                           :if-exists :supersede
                                                           :if-does-not-exist :create)
                         (trail stream))
                       (trail *error-output*))))
               (uiop:quit (command-exit-status result) t)))
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
                              reached for~%"))
                 ;; A report that saw less than it claims is the other way to be
                 ;; wrong, so what was dropped is said out loud.
                 (let ((skipped (observations-skipped observations)))
                   (when (plusp skipped)
                     (format *error-output*
                             "~&scute: ~D path~:P could not be read while watching, ~
                              so this list may be short~%"
                             skipped))))
               (uiop:quit (command-exit-status result) t)))
            (t
             (let ((result (run-launch-plan plan)))
               (when (sandbox-result-oom-killed-p result)
                 (format *error-output*
                         "~&scute: the command was killed by its memory limit~%"))
               (when (sandbox-result-timed-out result)
                 (format *error-output*
                         "~&scute: the command ran past its time limit and was stopped~%"))
               ;; Only when the command failed.  A refusal on the way to a
               ;; success is usually a step rather than a problem: a client that
               ;; waits to be challenged sends nothing, is refused, and then sends
               ;; its credential -- git does exactly that, and reporting the first
               ;; half as a refusal of a run that worked is noise.  The audit trail
               ;; keeps everything either way.
               (let ((explained (and *broker*
                                     (not (zerop (command-exit-status result)))
                                     (report-broker-refusals (broker-events *broker*)))))
                 (offer-explanation plan result explained))
               (uiop:quit (command-exit-status result) t)))))
         :program (clingon:getopt cmd :broker-path)))))))

(defun make-run-command ()
  (clingon:make-command
   :name "run"
   :description "Run a command inside the sandbox"
   :usage "[--policy FILE | --read PATH ...] -- COMMAND [ARGUMENT ...]"
   :options (append
             (list (clingon:make-option
                    :string :long-name "policy" :key :policy :parameter "FILE"
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
                    :string :long-name "broker-path" :key :broker-path
                    :parameter "PATH"
                    :description "Run this credential broker, not the one on PATH")
                   (clingon:make-option
                    :string :long-name "with" :key :with :parameter "COMMAND"
                    :description "Run COMMAND beside the sandbox -- a credential proxy, say")
                   (clingon:make-option
                    :flag :long-name "allow-unix-sockets" :key :allow-unix-sockets
                    :description "Permit sandbox Unix IPC (requires Landlock ABI 9; host paths stay denied)")
                   (clingon:make-option
                    :string :long-name "timeout" :key :timeout :parameter "DURATION"
                    :description "Stop the command if it runs longer than this, e.g. 30s")
                   (clingon:make-option
                    :list :long-name "keep-env" :key :keep-env :parameter "NAME"
                    :description "Also give the command this environment variable")
                   (clingon:make-option
                    :string :long-name "audit" :key :audit :parameter "FILE"
                    :description "Write the audit trail a policy asks for here, not to stderr")
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
               ("Sandbox an agent whose credentials a proxy holds:"
                . "scute run --policy agent.policy --with keyfence -- claude")
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
     (let* ((plan (compile-launch-plan (read-sandbox-policy policy) '("/bin/true")))
            (rules (launch-plan-filesystem plan))
            (denied 0))
       (unless (or paths (launch-plan-credentials plan))
         (usage-error "scute check needs one or more paths to ask about"))
       (dolist (path paths)
         (unless (report-path-access rules path *standard-output*)
           (incf denied)))
       ;; Credentials are as much a part of whether a policy will run as paths
       ;; are, and they fail in a place that is much harder to read: an agent
       ;; getting a 401 from somewhere inside itself.
       (let ((missing (or (report-credentials plan *standard-output*) 0)))
         (uiop:quit (if (plusp (+ denied missing)) 1 0) t))))))

(defun make-check-command ()
  (clingon:make-command
   :name "check"
   :description "Ask a policy what it allows at a path"
   :usage "--policy FILE PATH [PATH ...]"
   :options (list (clingon:make-option
                   :string :long-name "policy" :key :policy :parameter "FILE"
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
     (when (and (clingon:getopt cmd :merge) (null output))
       (usage-error "--merge needs --output FILE, which is what it merges into"))
     (let ((existing (when (and (clingon:getopt cmd :merge) (probe-file output))
                       (read-sandbox-policy output))))
       (multiple-value-bind (result observations)
           (run-launch-plan (revised-launch-plan
                             (compile-command-launch-plan command '())
                             :network (if (clingon:getopt cmd :network) :host :keep))
                            :observe :learn)
         (let ((rules (merge-learned-rules
                       (learned-rules observations (sb-posix:getcwd))
                       existing))
               (*learned-unix-sockets* (observations-unix-sockets observations))
               (*learned-connections*
                 (loop for connection being the hash-keys
                         of (observations-connections observations)
                       collect connection)))
           (if output
               (with-open-file (stream output :direction :output
                                              :if-exists :supersede
                                              :if-does-not-exist :create)
                 (write-learned-policy rules stream :command command :carry existing)
                 (format *error-output* "~&scute: ~:[wrote~;updated~] ~A~%"
                         existing output))
               (write-learned-policy rules *standard-output* :command command)))
         (uiop:quit (command-exit-status result) t))))))

(defun make-learn-command ()
  (clingon:make-command
   :name "learn"
   :description "Watch a command and write the policy it would have needed"
   :usage "[--output FILE] -- COMMAND [ARGUMENT ...]"
   :options (list (clingon:make-option
                   :string :short-name #\o :long-name "output" :key :output :parameter "FILE"
                   :description "Write the policy here instead of to standard output")
                  (clingon:make-option
                   :flag :long-name "network" :key :network
                   :description "Give the command the host's network while watching it")
                  (clingon:make-option
                   :flag :long-name "merge" :key :merge
                   :description "Widen the policy already in --output rather than replacing it"))
   :handler #'learn-handler
   :examples '(("Find out what a build actually touches:"
                . "scute learn -- make")
               ("Keep the answer:"
                . "scute learn --output scute.policy -- ./run-tests")
               ("Teach it a second command:"
                . "scute learn --output scute.policy --merge -- ./run-lint"))))

;;── policies ───────────────────────────────────────────────────────────────────

(defun policies-handler (cmd)
  (declare (ignore cmd))
  (reporting-failures
   (let ((names (available-policies)))
     (if (null names)
         (format t "~&No policies are installed. Looked in:~%~{  ~A~%~}"
                 (policy-search-path))
         ;; Where each one came from, because two directories can hold the same
         ;; name and knowing which one answered is the difference between editing
         ;; a policy and editing a copy of it that nothing reads.
         (dolist (name names)
           (format t "~&~A~24T~A~%" name (locate-policy name))))
     (uiop:quit 0 t))))

(defun make-policies-command ()
  (clingon:make-command
   :name "policies"
   :description "List the policies installed on this host, and where each is"
   :usage ""
   :handler #'policies-handler
   :examples '(("What can be run by name:" . "scute policies")
               ("Run one of them:" . "scute run --policy codex -- \"fix the build\""))))

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

(defun man-handler (cmd)
  (declare (ignore cmd))
  (reporting-failures
   (write-manual-page *standard-output* :version +version+)
   (uiop:quit 0 t)))

(defun make-man-command ()
  (clingon:make-command
   :name "man"
   :description "Write scute's manual page, generated from its own commands"
   :usage ""
   :handler #'man-handler
   :examples '(("Read it now:" . "scute man | man -l -")
               ("Install it:" . "scute man > /usr/share/man/man1/scute.1"))))

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

;;── A policy name as the verb ──────────────────────────────────────────────────
;;;
;;; "scute codex" rather than "scute run --policy codex".  The confinement is the
;;; point of the tool, and asking someone to spell out the mechanism every time is
;;; how the mechanism gets skipped -- the same reason Scute makes its own cgroup
;;; instead of printing the systemd-run line.
;;;
;;; This is a rewriting of the arguments, not a second way to run things: "scute
;;; codex ..." becomes "scute run --policy codex ...", with one code path, one set
;;; of options, and one plan printed by --dry-run.
;;;
;;; A built-in command always wins.  A policy called "doctor" cannot take over
;;; "scute doctor", because a command that means one thing on one machine and
;;; something else on the next is worse than a policy nobody can reach by name.

(defparameter +subcommand-names+
  '("run" "learn" "check" "doctor" "policies" "completions" "man" "help")
  "The verbs Scute has of its own.  A policy may not shadow one.")

(defun policy-verb-arguments (arguments)
  "ARGUMENTS with a leading policy name turned into \"run --policy NAME\".

Answers ARGUMENTS unchanged when the first one is an option, a command Scute
already has, or not the name of an installed policy -- so an unknown verb still
reaches clingon and gets clingon's own error, rather than being reported as a
missing policy."
  (let ((first (first arguments)))
    (if (or (null first)
            (zerop (length first))
            (char= #\- (char first 0))
            (member first +subcommand-names+ :test #'string=)
            (not (policy-name-p first))
            (null (ignore-errors (locate-policy first))))
        arguments
        (list* "run" "--policy" first (rest arguments)))))

;;── CLI ────────────────────────────────────────────────────────────────────────

(defun make-app ()
  "Create and return the command-line application."
  (clingon:make-command
   :name    "scute"
   :version +version+
   :description "Run one command inside a deny-by-default Linux sandbox.
An installed policy can be named directly: \"scute codex\" is \"scute run --policy
codex\", and \"scute policies\" lists what this host has."
   :authors (list "Anthony Green <green@moxielogic.com>")
   :license "MIT"
   :usage "[GLOBAL-OPTIONS] COMMAND|POLICY [OPTIONS] [-- ARGUMENTS ...]"
   :sub-commands (list (make-run-command) (make-learn-command)
                       (make-check-command) (make-doctor-command)
                       (make-policies-command)
                       (make-completions-command) (make-man-command))
   :handler (lambda (cmd)
              (clingon:print-usage-and-exit cmd *standard-output*))))

(defun main ()
  "The main entrypoint."
  ;; Before anything else: a launch drops the capabilities this binary was given,
  ;; and several questions later on are about what it was given rather than what it
  ;; still holds.
  (remember-startup-capabilities)
  (clingon:run (make-app) (policy-verb-arguments (rest sb-ext:*posix-argv*))))
