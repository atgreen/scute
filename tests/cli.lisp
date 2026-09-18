;;; SPDX-License-Identifier: MIT
;;;
;;; The command line, exercised as a user meets it: the built executable, its
;;; exit statuses, and what it says when it refuses.

(in-package #:scute/tests)

(defparameter +scute+ (namestring (merge-pathnames "scute" (uiop:getcwd)))
  "The executable under test.  make test builds it first, so the suite always
tests what ships rather than what happens to be lying around.")

(defun scute-run (arguments &key (input "/dev/null"))
  "Run the scute executable with ARGUMENTS.
Answers its exit status and everything it wrote, so a test can hold both the
status and the message to the same standard."
  (let ((output (scratch-pathname "cli")))
    (unwind-protect
         (let ((status (cffi:foreign-funcall
                        "system" :string
                        (format nil "~A ~A > ~A 2>&1 < ~A" +scute+ arguments
                                output input)
                        :int)))
           (values (ash status -8) (read-file-string output)))
      (delete-scratch output))))

(defun policy-file (text)
  (let ((pathname (scratch-pathname "cli-policy")))
    (with-open-file (stream pathname :direction :output :if-exists :supersede)
      (write-string text stream))
    pathname))

(deftest test-cli-is-built
  "Every test here runs the executable, so say so plainly if it is not there."
  (check (probe-file +scute+)
         "~A does not exist; make test should have built it" +scute+))

(deftest test-help-and-version
  "The first two things anyone types."
  (multiple-value-bind (status said) (scute-run "--help")
    (check (zerop status) "--help exited ~D" status)
    (dolist (expected '("run" "doctor" "deny-by-default"))
      (check (search expected said) "--help does not mention ~S:~%~A" expected said)))
  (multiple-value-bind (status said) (scute-run "--version")
    (check (zerop status) "--version exited ~D" status)
    (check (search "0.1.0" said) "--version said ~S" said))
  (multiple-value-bind (status said) (scute-run "run --help")
    (check (zerop status) "run --help exited ~D" status)
    (dolist (expected '("--policy" "--read-write-execute" "--dry-run"
                        "--namespaces-only"))
      (check (search expected said) "run --help omits ~S" expected))))

(deftest test-usage-errors-are-distinct
  "A caller who asked for something impossible gets EX_USAGE and a reason, not
a stack of Lisp."
  (dolist (case '(("run --namespaces-only" "no command given")
                  ("run -- /bin/true" "Say what the sandbox allows")
                  ("run --namespaces-only --read /usr -- /bin/true"
                   "no filesystem restriction")))
    (destructuring-bind (arguments expected) case
      (multiple-value-bind (status said) (scute-run arguments)
        (check (= 64 status) "~S exited ~D, not 64: ~A" arguments status said)
        (check (search expected said) "~S said ~S, which does not mention ~S"
               arguments said expected)
        (check (not (search "debugger" said))
               "~S leaked a Lisp backtrace:~%~A" arguments said)))))

(deftest test-policy-errors-are-distinct
  "A policy Scute will not accept is a data error, which is a different thing
from a caller misusing the command."
  (let ((missing (scratch-pathname "absent-policy"))
        (bad (policy-file "[filesystem")))
    (unwind-protect
         (progn
           (multiple-value-bind (status said)
               (scute-run (format nil "run --policy ~A -- /bin/true" missing))
             (check (= 65 status) "a missing policy exited ~D: ~A" status said))
           (multiple-value-bind (status said)
               (scute-run (format nil "run --policy ~A -- /bin/true" bad))
             (check (= 65 status) "an unparsable policy exited ~D: ~A" status said)
             (check (search "will not parse" said) "the message was ~S" said)))
      (delete-scratch bad))))

(deftest test-exit-statuses-are-the-commands-own
  "What the command returns is what scute returns, and a command that could not
start says so in the shell's own vocabulary."
  (dolist (code '(0 1 7 42))
    (multiple-value-bind (status)
        (scute-run (format nil "run --namespaces-only -- /bin/sh -c 'exit ~D'" code))
      (check (= code status) "a command exiting ~D gave ~D" code status)))
  (multiple-value-bind (status said)
      (scute-run "run --namespaces-only -- /nonexistent/command")
    (check (= 127 status) "a command that does not exist gave ~D: ~A" status said)
    (check (search "command not found" said) "the message was ~S" said))
  ;; A command that exists but cannot be executed is 126, as in a shell, and the
  ;; child says why rather than only that it failed.
  (let ((unrunnable (scratch-pathname "not-executable")))
    (unwind-protect
         (progn
           (with-open-file (stream unrunnable :direction :output
                                              :if-exists :supersede)
             (write-line "not a program" stream))
           (multiple-value-bind (status said)
               (scute-run (format nil "run --namespaces-only -- ~A" unrunnable))
             (check (= 126 status) "a file that cannot be executed gave ~D: ~A"
                    status said)
             (check (search "Permission denied" said)
                    "the failure did not say why: ~S" said)))
      (delete-scratch unrunnable))))

(deftest test-paths-with-spaces
  "A path with a space in it is a path.  Scute passes argv straight to the
kernel, and this is the test that keeps it that way."
  (let* ((directory (format nil "~A dir" (scratch-pathname "cli space")))
         (policy nil))
    (unwind-protect
         (progn
           (ensure-directories-exist (format nil "~A/" directory))
           (setf policy (policy-file (format nil "[filesystem]~%~
                                                  read-execute = [\"/usr\"]~%~
                                                  read-write = [\"~A\"]~%"
                                            directory)))
           (multiple-value-bind (status said)
               (scute-run (format nil "run --policy '~A' -- /bin/sh -c 'echo hi > \"~A/a file\"'"
                                  policy directory))
             (check (zerop status) "writing to a path with spaces exited ~D: ~A"
                    status said)
             (check (probe-file (format nil "~A/a file" directory))
                    "the file with a space in its name was not written")))
      (ignore-errors (delete-file (format nil "~A/a file" directory)))
      (when policy (delete-scratch policy))
      (ignore-errors (sb-posix:rmdir directory)))))

(deftest test-dry-run-shows-and-does-nothing
  "--dry-run is the reviewer's command: it prints the decision and runs nothing."
  (let* ((witness (scratch-pathname "dry-witness"))
         (policy (policy-file (format nil "[filesystem]~%~
                                           read-execute = [\"/usr\"]~%~
                                           read-write = [\"/tmp\"]~%"))))
    (unwind-protect
         (multiple-value-bind (status said)
             (scute-run (format nil "run --policy ~A --dry-run -- /bin/sh -c 'echo x > ~A'"
                                policy witness))
           (check (zerop status) "--dry-run exited ~D: ~A" status said)
           (dolist (expected '("command" "directory" "filesystem" "read-execute"))
             (check (search expected said) "--dry-run did not report ~S:~%~A"
                    expected said))
           (check (not (probe-file witness))
                  "--dry-run ran the command after all"))
      (delete-scratch policy witness))))

(deftest test-doctor-reads-both-ways
  "doctor answers a person and a script, and its exit status says whether this
host can sandbox at all."
  (multiple-value-bind (status said) (scute-run "doctor")
    (check (zerop status) "doctor exited ~D on a host that sandboxes: ~A" status said)
    (dolist (expected '("user namespaces" "landlock" "libseccomp" "audit"
                        "resource limits"))
      (check (search expected said) "doctor does not report ~S" expected)))
  (multiple-value-bind (status said) (scute-run "doctor --json")
    (check (zerop status) "doctor --json exited ~D" status)
    (check (search "\"ready\": true" said) "doctor --json said ~S" said)
    (dolist (expected '("\"name\": \"landlock\"" "\"mandatory\": true"
                        "\"status\": \"ok\""))
      (check (search expected said) "doctor --json omits ~S:~%~A" expected said))
    ;; Parsed by something that is not us, when there is something to parse with.
    (let ((checker (scratch-pathname "json")))
      (unwind-protect
           (when (zerop (cffi:foreign-funcall
                         "system" :string "command -v python3 >/dev/null 2>&1" :int))
             (with-open-file (stream checker :direction :output :if-exists :supersede)
               (write-string said stream))
             (check (zerop (cffi:foreign-funcall
                            "system" :string
                            (format nil "python3 -m json.tool < ~A > /dev/null 2>&1"
                                    checker)
                            :int))
                    "doctor --json is not valid JSON:~%~A" said))
        (delete-scratch checker)))))

(deftest test-check-answers-what-a-policy-allows
  "check is the command that makes a policy reviewable: it asks the rules what
they permit at a path, launches nothing, and fails if anything is wholly denied."
  (let* ((workspace (scratch-pathname "check-space"))
         (policy nil))
    (unwind-protect
         (progn
           (ensure-directories-exist (format nil "~A/" workspace))
           (setf policy (policy-file (format nil "[filesystem]~%~
                                                  read-execute = [\"/usr\"]~%~
                                                  read = [\"/etc\"]~%~
                                                  read-write = [\"~A\"]~%"
                                            workspace)))
           ;; Everything asked about is allowed something.
           (multiple-value-bind (status said)
               (scute-run (format nil "check --policy ~A /usr/bin/env /etc ~A"
                                  policy workspace))
             (check (zerop status) "check exited ~D where all paths are allowed: ~A"
                    status said)
             (check (search "execute" said) "/usr/bin/env was not reported executable:~%~A" said)
             (check (search "read-execute /usr" said)
                    "the rule granting it was not named:~%~A" said))
           ;; One path allowed nothing: that is a failure, so CI can lean on it.
           (multiple-value-bind (status said)
               (scute-run (format nil "check --policy ~A /var/tmp" policy))
             (check (= 1 status) "a wholly denied path exited ~D: ~A" status said)
             (check (search "nothing" said) "the denial was not reported:~%~A" said))
           ;; A path that does not exist yet is answered by what governs creating it.
           (multiple-value-bind (status said)
               (scute-run (format nil "check --policy ~A ~A/not/there/yet"
                                  policy workspace))
             (check (zerop status) "a path under a writable directory exited ~D: ~A"
                    status said)
             (check (search "via" said)
                    "the answer did not say which directory governs it:~%~A" said))
           ;; A path with no existing ancestor at all still answers.
           (multiple-value-bind (status said)
               (scute-run (format nil "check --policy ~A /nonexistent/deep/path" policy))
             (check (= 1 status) "an unreachable path exited ~D" status)
             (check (search "via /" said)
                    "the answer did not name the directory it reasoned from:~%~A"
                    said))
           ;; check launches nothing: it works even where a sandbox could not run.
           (multiple-value-bind (status)
               (scute-run (format nil "check --policy ~A" policy))
             (check (= 64 status) "check with no paths exited ~D" status))
           (multiple-value-bind (status) (scute-run "check /usr")
             (check (= 64 status) "check with no policy exited ~D" status)))
      (when policy (delete-scratch policy))
      (ignore-errors (sb-posix:rmdir workspace)))))

(deftest test-completions-follow-the-commands
  "Completions are generated from the command tree, so a new command or option
is completable the moment it exists.  This test is what keeps that true."
  (dolist (shell '("bash" "zsh" "fish"))
    (multiple-value-bind (status said) (scute-run (format nil "completions ~A" shell))
      (check (zerop status) "completions ~A exited ~D" shell status)
      (dolist (command '("run" "learn" "check" "doctor"))
        (check (search command said) "~A completions omit ~A" shell command))
      ;; fish spells an option "-l policy", not "--policy", so ask for the
      ;; name and let each shell spell it its own way.
      (dolist (option '("policy" "explain" "dry-run" "namespaces-only"))
        (check (search option said) "~A completions omit ~A" shell option))
      (check (not (search "bash-completions" said))
             "~A completions offer an internal flag" shell)
      ;; Quoting: a description carrying an apostrophe would end the quote it
      ;; sits inside and leave the script unparsable.
      (check (not (search "scute's" said))
             "~A completions carry an unescaped apostrophe" shell)))
  ;; The bash script is a shell script, and bash is the judge of that.
  (let ((script (scratch-pathname "completions")))
    (unwind-protect
         (multiple-value-bind (status said) (scute-run "completions bash")
           (declare (ignore status))
           (with-open-file (stream script :direction :output :if-exists :supersede)
             (write-string said stream))
           (check (zerop (cffi:foreign-funcall
                          "system" :string (format nil "bash -n ~A" script) :int))
                  "the bash completions are not valid bash:~%~A" said)
           ;; And it completes: ask it for the top-level words.
           (let ((answer (scratch-pathname "completed")))
             (unwind-protect
                  (progn
                    (cffi:foreign-funcall
                     "system" :string
                     (format nil "bash -c 'source ~A; COMP_WORDS=(scute \"\"); ~
                                  COMP_CWORD=1; _scute; echo \"${COMPREPLY[@]}\"' > ~A 2>/dev/null"
                             script answer)
                     :int)
                    (let ((completed (read-file-string answer)))
                      (dolist (command '("run" "learn" "check" "doctor"))
                        (check (search command completed)
                               "completing an empty first word did not offer ~A: ~S"
                               command completed))))
               (delete-scratch answer))))
      (delete-scratch script)))
  (multiple-value-bind (status said) (scute-run "completions tcsh")
    (check (= 64 status) "an unknown shell exited ~D" status)
    (check (search "bash" said) "the refusal does not say which shells are known")))

(deftest test-the-manual-page-is-a-manual-page
  "The manual page is generated from the command tree too, and groff is the
judge of whether it is roff."
  (multiple-value-bind (status said) (scute-run "man")
    (check (zerop status) "scute man exited ~D" status)
    (dolist (expected '(".TH SCUTE 1" "NAME" "DESCRIPTION" "EXIT STATUS"
                        "run" "learn" "check" "doctor"))
      (check (search expected said) "the manual page omits ~S" expected))
    (let ((page (scratch-pathname "manual")))
      (unwind-protect
           (progn
             (with-open-file (stream page :direction :output :if-exists :supersede)
               (write-string said stream))
             (if (plusp (cffi:foreign-funcall
                         "system" :string "command -v groff >/dev/null 2>&1" :int))
                 (format *error-output* "~&SKIP: no groff, so the roff is unchecked~%")
                 (check (zerop (cffi:foreign-funcall
                                "system" :string
                                (format nil "groff -man -Tutf8 -ww ~A >/dev/null 2>~A.err ~
                                             && test ! -s ~A.err"
                                        page page page)
                                :int))
                        "groff complained about the manual page")))
        (delete-scratch page (format nil "~A.err" page))))))

(deftest test-the-timeout-flag
  "--timeout is the flag a script reaches for, so it answers 124 the way
timeout(1) does, and a duration it cannot read is the caller's mistake."
  (multiple-value-bind (status said)
      (scute-run "run --namespaces-only --timeout 1s -- /bin/sleep 60")
    (check (= 124 status) "a command stopped for time exited ~D: ~A" status said)
    (check (search "time limit" said) "the message was ~S" said))
  (multiple-value-bind (status said)
      (scute-run "run --namespaces-only --timeout 5s -- /bin/sh -c 'exit 3'")
    (check (= 3 status) "a command that finished in time exited ~D: ~A" status said))
  (multiple-value-bind (status said)
      (scute-run "run --namespaces-only --timeout nonsense -- /bin/true")
    (check (= 64 status) "an unreadable duration exited ~D, not 64: ~A" status said)))

(deftest test-scute-inside-scute-says-so
  "A sandbox refuses the calls a sandbox needs, so scute does not nest.  The
failure has to say that rather than reporting ENOSYS, which reads as though the
kernel were too old."
  (multiple-value-bind (status said)
      (scute-run (format nil "run --namespaces-only -- ~A run --namespaces-only -- /bin/true"
                         +scute+))
    (check (not (zerop status)) "scute nested inside scute, which it cannot do")
    (check (search "inside one" said)
           "the failure did not explain itself:~%~A" said)
    (check (not (search "Function not implemented" said))
           "the failure still reports ENOSYS:~%~A" said)))

(deftest test-no-message-leaks-a-tilde
  "A tilde line-continuation belongs to format, not to the reader: a plain
string keeps the tilde and the newline, and the message reaches the user with
\"~\" in the middle of a sentence.  Three of scute's messages have had this bug,
so the messages are checked rather than trusted."
  (dolist (arguments (list "run -- /bin/true"                 ; nothing declared
                           "run --namespaces-only"            ; no command
                           "run --namespaces-only --read /usr --namespaces-only -- /bin/true"
                           "check /usr"                       ; no policy
                           "completions tcsh"                 ; unknown shell
                           (format nil "run --namespaces-only -- ~A doctor" +scute+)))
    (multiple-value-bind (status said) (scute-run arguments)
      (declare (ignore status))
      (check (not (find #\~ said))
             "the message for ~S carries a tilde, so a continuation was written ~
              in a plain string:~%~A" arguments said))))
