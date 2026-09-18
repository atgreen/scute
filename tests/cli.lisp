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
