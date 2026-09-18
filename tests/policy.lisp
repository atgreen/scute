;;; SPDX-License-Identifier: MIT
;;;
;;; Policies: what Scute will read, what it refuses, and what a policy compiles
;;; into.

(in-package #:scute/tests)

(defparameter +sample-policy+
  "# What this sandbox may reach.
[filesystem]
read-execute = [\"/usr\"]
read = [\"/etc\"]
read-write = [\".\"]

[network]
mode = \"none\"
"
  "The policy the design documents, as a policy file.")

(defun policy-from-string (text)
  "Validate TEXT as a policy, reading it the way a file would be read."
  (call-scute 'validate-sandbox-policy
              (call-scute 'parse-policy-text text)))

(defun policy-refusal (text)
  "The condition validating TEXT signals, or NIL if it was accepted."
  (nth-value 1 (ignore-errors (policy-from-string text))))

(defun refused-p (text)
  (typep (policy-refusal text) 'scute:policy-error))

(defun write-policy (text)
  (let ((pathname (scratch-pathname "policy")))
    (with-open-file (stream pathname :direction :output :if-exists :supersede)
      (write-string text stream))
    pathname))

;;── What a policy means ────────────────────────────────────────────────────────

(deftest test-sample-policy-is-understood
  "The policy the design shows reads as the design says it does."
  (let ((policy (policy-from-string +sample-policy+)))
    (check (eq :none (call-scute 'sandbox-policy-network policy))
           "the network setting was lost")
    (check (null (call-scute 'sandbox-policy-limits policy))
           "limits appeared where the policy asked for none")
    (let ((rules (call-scute 'sandbox-policy-filesystem policy)))
      (check (= 3 (length rules)) "expected three rules, got ~D" (length rules))
      (dolist (expected '((:read-execute "/usr") (:read "/etc") (:read-write ".")))
        (destructuring-bind (kind path) expected
          (check (find-if (lambda (rule)
                            (and (eq kind (call-scute 'filesystem-rule-kind rule))
                                 (string= path (call-scute 'filesystem-rule-path rule))))
                          rules)
                 "no ~(~A~) rule for ~A" kind path))))))

(deftest test-limits-and-audit-are-read
  "Limits and audit events survive validation in Scute's own terms."
  (let* ((policy (policy-from-string "[filesystem]
read-execute = [\"/usr\"]
[limits]
memory = \"2G\"
processes = 256
cpu-percent = 200
[audit]
events = [\"exec\", \"connect\"]"))
         (limits (call-scute 'sandbox-policy-limits policy))
         (audit (call-scute 'sandbox-policy-audit policy)))
    (check (eql (* 2 1024 1024 1024) (call-scute 'resource-limits-memory limits))
           "2G was not read as ~D bytes" (* 2 1024 1024 1024))
    (check (eql 256 (call-scute 'resource-limits-processes limits))
           "processes was not read")
    (check (eql 200 (call-scute 'resource-limits-cpu-percent limits))
           "cpu-percent was not read")
    (check (equal '(:exec :connect) (call-scute 'audit-policy-events audit))
           "audit events were not read")))

(deftest test-memory-sizes
  "A memory limit may be plain digits or carry a K, M, G, or T suffix."
  (dolist (expected '(("512" . 512) ("512K" . 524288) ("4M" . 4194304)
                      ("2G" . 2147483648) ("1T" . 1099511627776)))
    (destructuring-bind (text . bytes) expected
      (let ((policy (policy-from-string
                     (format nil "[filesystem]~%read-execute = [\"/usr\"]~%~
                                  [limits]~%memory = \"~A\"" text))))
        (check (eql bytes (call-scute 'resource-limits-memory
                                      (call-scute 'sandbox-policy-limits policy)))
               "~A was not read as ~D bytes" text bytes)))))

;;── What a policy may not say ──────────────────────────────────────────────────

(deftest test-closed-schema
  "Anything the schema does not name is refused, not ignored.  A policy Scute
half understands is a sandbox the operator half asked for."
  (dolist (case '(("an unknown table"    "[filesystem]
read = [\"/etc\"]
[frobnicate]
x = 1")
                  ("an unknown key"      "[filesystem]
read = [\"/etc\"]
sudo = [\"/\"]")
                  ("an unknown limit"    "[filesystem]
read = [\"/etc\"]
[limits]
swap = \"1G\"")
                  ("an unknown audit key" "[filesystem]
read = [\"/etc\"]
[audit]
programs = [\"mine\"]")
                  ("an unknown event"    "[filesystem]
read = [\"/etc\"]
[audit]
events = [\"everything\"]")
                  ("no filesystem table" "[network]
mode = \"none\"")))
    (destructuring-bind (what text) case
      (check (refused-p text) "~A was accepted" what))))

(deftest test-values-are-type-checked
  "Every value has a shape, and something else in its place is refused."
  (dolist (case '(("a number where paths belong"  "[filesystem]
read = 7")
                  ("an empty path list"           "[filesystem]
read = []")
                  ("an empty path"                "[filesystem]
read = [\"\"]")
                  ("a number where a size belongs" "[filesystem]
read = [\"/etc\"]
[limits]
memory = 2")
                  ("a size that is not one"       "[filesystem]
read = [\"/etc\"]
[limits]
memory = \"2X\"")
                  ("a zero limit"                 "[filesystem]
read = [\"/etc\"]
[limits]
processes = 0")
                  ("a negative limit"             "[filesystem]
read = [\"/etc\"]
[limits]
cpu-percent = -1")
                  ("a network mode v0 lacks"      "[filesystem]
read = [\"/etc\"]
[network]
mode = \"open\"")))
    (destructuring-bind (what text) case
      (check (refused-p text) "~A was accepted" what))))

(deftest test-duplicates-are-refused
  "TOML forbids a duplicate key, and so must Scute.  A parser that keeps the
last value it saw would enforce something the policy's reader never agreed to,
which is why the parser is chosen rather than assumed."
  (check (refused-p "[filesystem]
read = [\"/etc\"]
read = [\"/usr\"]")
         "a duplicate key was accepted")
  (check (refused-p "[limits]
processes = 1
[limits]
memory = \"1G\"")
         "a duplicate table was accepted")
  (check (refused-p "[filesystem]
read = [\"/etc\", \"/etc\"]")
         "the same path listed twice was accepted"))

(deftest test-policy-is-data-only
  "A policy is data.  Nothing in TOML can ask Scute to run anything, and the
size cap keeps a policy the size a person writes."
  (check (refused-p "[filesystem")
         "a policy that does not parse was accepted")
  (let ((huge (with-output-to-string (stream)
                (write-line "[filesystem]" stream)
                (loop repeat 2000
                      do (format stream "# ~A~%" (make-string 70 :initial-element #\x))))))
    (check (typep (policy-refusal huge) 'scute:policy-error)
           "a policy past the size cap was accepted"))
  (let ((nested (with-output-to-string (stream)
                  (write-line "[filesystem]" stream)
                  (format stream "read = ~A/etc~A~%"
                          (make-string 400 :initial-element #\[)
                          (make-string 400 :initial-element #\])))))
    (check (policy-refusal nested) "deeply nested arrays were accepted")))

;;── Compiling a plan ───────────────────────────────────────────────────────────

(deftest test-plan-resolves-and-repeats
  "Compiling a policy resolves every path and yields the same plan every time:
the plan is the decision, and it has to be inspectable before it is enacted."
  (let* ((policy (policy-from-string +sample-policy+))
         (first-plan (call-scute 'compile-launch-plan policy '("/bin/sh" "-c" "true")))
         (second-plan (call-scute 'compile-launch-plan policy '("/bin/sh" "-c" "true"))))
    (check (equalp first-plan second-plan)
           "compiling the same policy twice gave different plans")
    (check (string= (namestring (truename "/bin/sh"))
                    (first (call-scute 'launch-plan-command first-plan)))
           "the command was not resolved to what will run")
    (dolist (rule (call-scute 'launch-plan-filesystem first-plan))
      (let ((path (call-scute 'path-rule-path rule)))
        (check (char= #\/ (char path 0)) "~A is not absolute" path)
        (check (not (find #\~ path)) "~A was not canonical" path)
        (check (or (string= path "/") (char/= #\/ (char path (1- (length path)))))
               "~A keeps a trailing slash" path)))))

(deftest test-relative-paths-stay-put
  "A relative path means what it says from here, and may not climb out."
  (check (typep (nth-value 1 (ignore-errors
                              (call-scute 'compile-launch-plan
                                          (policy-from-string "[filesystem]
read-execute = [\"/usr\"]
read-write = [\"../..\"]")
                                          '("/bin/true"))))
                'scute:policy-error)
         "a relative path escaping the directory was accepted"))

(deftest test-unimplemented-controls-refuse-to-run
  "A plan asking for a control this build lacks is refused before it launches.
Enacting it quietly would hand back a weaker sandbox than the one asked for.
Recording connections is the one left: limits arrived with the cgroup layer and
recording exec and open arrived with the watcher."
  (let* ((policy (policy-from-string "[filesystem]
read-execute = [\"/usr\"]
[audit]
events = [\"connect\"]"))
         (plan (call-scute 'compile-launch-plan policy '("/bin/true")))
         (condition (nth-value 1 (ignore-errors (call-scute 'run-launch-plan plan)))))
    (check (typep condition 'scute:control-not-implemented)
           "a plan asking for what this build lacks ran anyway, got ~S" condition)))

(deftest test-policy-file-drives-the-sandbox
  "The whole path, from a file on disk to a kernel that refuses: this is what
every other test in this file is in service of."
  (let* ((workspace (scratch-pathname "policy-workspace"))
         (pathname nil))
    (unwind-protect
         (progn
           (ensure-directories-exist (format nil "~A/" workspace))
           (setf pathname (write-policy (format nil "[filesystem]~%~
                                                    read-execute = [\"/usr\"]~%~
                                                    read-write = [\"~A\"]~%"
                                                workspace)))
           (let* ((policy (call-scute 'read-sandbox-policy pathname))
                  (plan (call-scute 'compile-launch-plan
                                    policy
                                    (list "/bin/sh" "-c"
                                          (format nil "echo sandboxed > ~A/witness; ~
                                                       cat /etc/hostname > ~A/leak"
                                                  workspace workspace))))
                  (result (call-scute 'run-launch-plan plan)))
             (check (probe-file (format nil "~A/witness" workspace))
                    "the sandbox could not write where the policy allowed")
             (check (zerop (or (with-open-file (stream (format nil "~A/leak" workspace)
                                                       :if-does-not-exist nil)
                                 (and stream (file-length stream)))
                               0))
                    "the sandbox read /etc, which the policy did not allow")
             (check (call-scute 'sandbox-result-exit-code result)
                    "the command did not report an exit code")))
      (ignore-errors (delete-file pathname))
      (dolist (leftover '("witness" "leak"))
        (ignore-errors (delete-file (format nil "~A/~A" workspace leftover))))
      (ignore-errors (sb-posix:rmdir workspace)))))

;;── The environment ────────────────────────────────────────────────────────────

(deftest test-the-environment-is-filtered
  "What a command is given is the short list, not everything the caller had."
  (let ((environment '("PATH=/usr/bin" "HOME=/home/someone" "TERM=xterm"
                       "AWS_SECRET_ACCESS_KEY=hunter2" "GITHUB_TOKEN=ghp_x"
                       "SSH_AUTH_SOCK=/run/user/1000/keyring/ssh"
                       "CARGO_HOME=/home/someone/.cargo")))
    (let ((kept (call-scute 'kept-environment '() environment)))
      (dolist (expected '("PATH=/usr/bin" "HOME=/home/someone" "TERM=xterm"))
        (check (member expected kept :test #'string=)
               "~S was dropped, and things will not run without it" expected))
      (dolist (secret '("AWS_SECRET_ACCESS_KEY=hunter2" "GITHUB_TOKEN=ghp_x"
                        "SSH_AUTH_SOCK=/run/user/1000/keyring/ssh"))
        (check (not (member secret kept :test #'string=))
               "~S crossed into the sandbox" secret)))
    ;; And what a policy or a caller names is kept as well.
    (let ((kept (call-scute 'kept-environment '("CARGO_HOME") environment)))
      (check (member "CARGO_HOME=/home/someone/.cargo" kept :test #'string=)
             "a variable that was asked for was dropped anyway"))))

(deftest test-a-policy-may-keep-a-variable
  "The policy decides, the same way it decides about paths."
  (let ((policy (policy-from-string "[filesystem]
read-execute = [\"/usr\"]
[environment]
keep = [\"CARGO_HOME\", \"RUSTUP_HOME\"]")))
    (check (equal '("CARGO_HOME" "RUSTUP_HOME")
                  (call-scute 'sandbox-policy-environment policy))
           "the policy's environment list was not read: ~S"
           (call-scute 'sandbox-policy-environment policy)))
  (check (refused-p "[filesystem]
read = [\"/etc\"]
[environment]
inherit = true")
         "an unknown key in [environment] was accepted")
  (check (refused-p "[filesystem]
read = [\"/etc\"]
[environment]
keep = [\"NAME=value\"]")
         "something that is not a variable name was accepted"))

(deftest test-secrets-do-not-reach-the-command
  "End to end: a secret in the caller's environment is not in the sandbox's, and
a variable the policy names is."
  (let ((report (scratch-pathname "environment")))
    (unwind-protect
         (progn
           (sb-posix:putenv "SCUTE_TEST_SECRET=hunter2")
           (sb-posix:putenv "SCUTE_TEST_KEPT=wanted")
           (let* ((policy (policy-from-string
                           (format nil "[filesystem]~%~
                                        read-execute = [\"/usr\"]~%~
                                        read-write = [\"/tmp\"]~%~
                                        [environment]~%keep = [\"SCUTE_TEST_KEPT\"]~%")))
                  (plan (call-scute 'compile-launch-plan policy
                                    (list "/bin/sh" "-c"
                                          (format nil "echo \"secret=[$SCUTE_TEST_SECRET] ~
                                                       kept=[$SCUTE_TEST_KEPT] ~
                                                       path=[$PATH]\" > ~A"
                                                  report))))
                  (result (call-scute 'run-launch-plan plan))
                  (said (read-file-string report)))
             (check (eql 0 (call-scute 'sandbox-result-exit-code result))
                    "the command did not finish: ~S" result)
             (check (search "secret=[]" said)
                    "a secret crossed into the sandbox:~%~A" said)
             (check (search "kept=[wanted]" said)
                    "the variable the policy named did not arrive:~%~A" said)
             (check (not (search "path=[]" said))
                    "PATH was dropped, and nothing will run:~%~A" said)))
      (delete-scratch report))))
