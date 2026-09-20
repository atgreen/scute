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

(deftest test-every-control-a-policy-can-ask-for-is-installed
  "Nothing a policy can say is refused as unbuilt any more.

Recording connections was the last of them, and asking for it used to refuse the
launch -- rightly, because enacting a plan quietly without a control it asked for
hands back a weaker sandbox than the one requested.  Now it records connections,
so the refusal has nothing left to refuse, and this test says so rather than
leaving the old assertion to rot."
  (let* ((policy (policy-from-string "[filesystem]
read-execute = [\"/usr\"]
[audit]
events = [\"connect\", \"exec\", \"open\"]"))
         (plan (call-scute 'compile-launch-plan policy '("/bin/true"))))
    (check (null (call-scute 'refuse-unimplemented-controls plan))
           "a policy naming every audit event was refused")))

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

(deftest test-unix-sockets-are-a-policy-decision
  "A policy says whether the command may open a unix-domain socket, and says it
as a boolean."
  (check (not (call-scute 'sandbox-policy-unix-sockets
                          (policy-from-string "[filesystem]
read = [\"/etc\"]")))
         "a policy that says nothing allowed unix sockets")
  (check (not (call-scute 'sandbox-policy-unix-sockets
                          (policy-from-string "[filesystem]
read = [\"/etc\"]
[network]
mode = \"none\"")))
         "a network section that says nothing allowed unix sockets")
  (check (call-scute 'sandbox-policy-unix-sockets
                     (policy-from-string "[filesystem]
read = [\"/etc\"]
[network]
mode = \"none\"
unix-sockets = true"))
         "a policy allowing unix sockets was not read")
  (check (refused-p "[filesystem]
read = [\"/etc\"]
[network]
mode = \"none\"
unix-sockets = \"yes\"")
         "something that is not a boolean was accepted"))

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

(deftest test-a-policy-silent-about-the-network-gets-the-broker
  "Scute's answer to \"how does an agent use a credential it must not hold\" is a
broker, and a broker nothing routes through is a broker nobody uses.  So silence
means the broker: the sandbox may reach exactly one port, and what it can do with
it is what the broker permits.

Silence used to mean no network at all.  The difference matters for a policy
written before this changed, which is why it is asserted here rather than left to
be discovered: a policy that means none now says so."
  (let ((policy (policy-from-string "[filesystem]
read = [\"/etc\"]")))
    (check (eq :host (call-scute 'sandbox-policy-network policy))
           "a policy that says nothing did not get the host's network")
    (check (string= (scute-value '+default-broker-proxy+)
                    (call-scute 'sandbox-policy-proxy policy))
           "it was not pointed at the broker: ~S"
           (call-scute 'sandbox-policy-proxy policy))
    (check (equal (list 10210) (call-scute 'sandbox-policy-connect-tcp policy))
           "the broker's port is not the only one permitted: ~S"
           (call-scute 'sandbox-policy-connect-tcp policy)))
  (check (eq :host (call-scute 'sandbox-policy-network
                               (policy-from-string "[filesystem]
read = [\"/etc\"]
[network]
mode = \"host\"")))
         "a policy asking for the host's network was not read")
  (check (refused-p "[filesystem]
read = [\"/etc\"]
[network]
mode = \"bridged\"")
         "a network mode v0 does not know was accepted")
  ;; And it reaches the kernel: routes exist in one and not the other.
  (flet ((routes (mode)
           (let* ((report (scratch-pathname "routes"))
                  (policy (policy-from-string
                           (format nil "[filesystem]~%read-execute = [\"/usr\"]~%~
                                        read = [\"/proc\"]~%~
                                        read-write = [\"/tmp\"]~%~
                                        [network]~%mode = ~S~%" mode))))
             (unwind-protect
                  (progn
                    (call-scute 'run-launch-plan
                                (call-scute 'compile-launch-plan policy
                                            (list "/bin/sh" "-c"
                                                  (format nil "tail -n +2 /proc/net/route ~
                                                               | wc -l > ~A"
                                                          report))))
                    (parse-integer (read-file-string report) :junk-allowed t))
               (delete-scratch report)))))
    (check (eql 0 (routes "none"))
           "a sandbox with no network had a route")
    (check (plusp (or (routes "host") 0))
           "a sandbox sharing the host's network had no route")))

(defun compile-connect-probe ()
  "Build a program that answers what happened when it tried to connect.
7 means the kernel let it try and nothing was listening; 8 means Landlock
refused it.  Telling those apart is the whole test, and it needs no network."
  (let ((source (format nil "~A.c" (scratch-pathname "connect")))
        (program (scratch-pathname "connect")))
    (with-open-file (stream source :direction :output :if-exists :supersede)
      (write-string "#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
int main(int argc, char **argv) {
  struct sockaddr_in to;
  int s = socket(AF_INET, SOCK_STREAM, 0);
  if (s < 0) return 6;
  to.sin_family = AF_INET;
  to.sin_port = htons((unsigned short)atoi(argv[1]));
  to.sin_addr.s_addr = inet_addr(\"127.0.0.1\");
  if (connect(s, (struct sockaddr *)&to, sizeof to) == 0) return 0;
  if (errno == ECONNREFUSED) return 7;   /* allowed to try */
  if (errno == EACCES || errno == EPERM) return 8;  /* refused by policy */
  return 9;
}
" stream))
    (unwind-protect
         (when (zerop (cffi:foreign-funcall
                       "system" :string
                       (format nil "gcc -o ~A ~A >/dev/null 2>&1" program source)
                       :int))
           program)
      (delete-scratch source))))

(deftest test-a-policy-may-name-the-ports-it-needs
  "Landlock governs ports rather than addresses, which is less than a proxy
offers and a great deal more than nothing: a policy can say TCP 443 and have the
kernel refuse everything else."
  (let ((program (compile-connect-probe)))
    (if (null program)
        (format *error-output* "~&SKIP: no working gcc, so port rules are untested~%")
        (unwind-protect
             (flet ((try (port)
                      (let ((policy (policy-from-string
                                     (format nil "[filesystem]~%~
                                                  read-execute = [\"/\"]~%~
                                                  [network]~%mode = \"host\"~%~
                                                  connect-tcp = [9]~%"))))
                        (call-scute 'sandbox-result-exit-code
                                    (call-scute 'run-launch-plan
                                                (call-scute 'compile-launch-plan policy
                                                            (list program
                                                                  (princ-to-string port))))))))
               (check (eql 7 (try 9))
                      "connecting to the port the policy named was refused by the ~
                       kernel, not by the host")
               (check (eql 8 (try 10))
                      "connecting to a port the policy did not name was allowed"))
          (delete-scratch program)))))

(deftest test-a-proxy-is-the-only-way-out
  "Naming a proxy sets the variables a client reads and grants its port -- and
only its port, so a command that ignores the variables still cannot go around
it.  That is what makes it a proxy rather than a suggestion."
  (let* ((policy (policy-from-string "[filesystem]
read-execute = [\"/usr\"]
[network]
mode = \"host\"
proxy = \"http://127.0.0.1:10210\""))
         (plan (call-scute 'compile-launch-plan policy '("/bin/true"))))
    (check (equal '(10210) (call-scute 'launch-plan-connect-tcp plan))
           "naming a proxy did not restrict connections to its port: ~S"
           (call-scute 'launch-plan-connect-tcp plan))
    (check (find "HTTPS_PROXY=http://127.0.0.1:10210"
                 (call-scute 'launch-plan-environment plan) :test #'string=)
           "the command would never be told about the proxy")
    (check (refused-p "[filesystem]
read = [\"/etc\"]
[network]
mode = \"none\"
connect-tcp = [443]")
           "ports were accepted on a network that is not there")
    (check (refused-p "[filesystem]
read = [\"/etc\"]
[network]
mode = \"host\"
proxy = \"localhost\"")
           "a proxy naming no port was accepted")))

(deftest test-a-policy-can-set-a-variable-not-only-keep-one
  "Keeping passes a variable the caller had; setting gives the sandbox one the
caller need not have.  A policy that only works when the operator remembers to
export something first is not really a policy -- the first time they forget, the
command reads the configuration the sandbox was meant to keep it away from."
  (let* ((policy (policy-from-string "[filesystem]
read = [\"/etc\"]

[environment]
keep = [\"KEPT_ONE\"]

[environment.set]
GH_CONFIG_DIR = \".gh\"
CLAUDE_CONFIG_DIR = \".claude\""))
         (plan (call-scute 'compile-launch-plan policy '("/bin/true")
                           :environment '("KEPT_ONE=from-the-caller"
                                          "GH_CONFIG_DIR=/home/you/.config/gh"
                                          "DROPPED=yes")))
         (environment (call-scute 'launch-plan-environment plan)))
    (check (member "GH_CONFIG_DIR=.gh" environment :test #'string=)
           "the policy's value was not set: ~S" environment)
    (check (member "CLAUDE_CONFIG_DIR=.claude" environment :test #'string=)
           "the second setting is missing")
    ;; Setting wins over what the caller had, or the value would depend on the
    ;; shell the command was started from.
    (check (not (member "GH_CONFIG_DIR=/home/you/.config/gh" environment :test #'string=))
           "the caller's value survived beside the policy's")
    (check (member "KEPT_ONE=from-the-caller" environment :test #'string=)
           "a kept variable was lost")
    (check (not (member "DROPPED=yes" environment :test #'string=))
           "a variable the policy never named was passed")))

(deftest test-a-setting-has-to-be-a-name-and-a-string
  "[environment.set] is a table of NAME = \"value\", and nothing else."
  (flet ((refused-p (text)
           (nth-value 1 (ignore-errors (policy-from-string text)))))
    (check (refused-p "[filesystem]
read = [\"/etc\"]
[environment.set]
\"NOT=A=NAME\" = \"x\"")
           "a name with an equals sign in it was accepted")
    (check (refused-p "[filesystem]
read = [\"/etc\"]
[environment.set]
NUMBER = 7")
           "a non-string value was accepted")
    (check (not (refused-p "[filesystem]
read = [\"/etc\"]
[environment.set]
FINE = \"yes\""))
           "a perfectly good setting was refused")))

;;── Policies that can be shipped ───────────────────────────────────────────────
;;;
;;; A policy installed with Scute has to describe machines it has never seen, and
;;; be runnable by name rather than by path. Three things make that work, and each
;;; of them is a way to go quietly wrong: a path that may be absent, a home
;;; directory that is not the author's, and a command the policy carries itself.

(deftest test-a-path-may-be-declared-optional
  "A leading ? means \"if this host has it\", so one policy fits two machines."
  (let* ((policy (policy-from-string
                  (format nil "[filesystem]~%read = [\"/etc\", \"?/etc/definitely-absent\"]~%")))
         (rules (call-scute 'sandbox-policy-filesystem policy)))
    (check (= 2 (length rules)) "expected both rules to survive validation")
    (destructuring-bind (required optional) rules
      (check (not (call-scute 'filesystem-rule-optional required))
             "an ordinary path was marked optional")
      (check (call-scute 'filesystem-rule-optional optional)
             "a ?-marked path was not marked optional")
      (check (string= "/etc/definitely-absent" (call-scute 'filesystem-rule-path optional))
             "the marker was left in the path: ~S"
             (call-scute 'filesystem-rule-path optional)))))

(deftest test-an-absent-optional-path-is-skipped-and-reported
  "Skipped, and said out loud: a grant that vanishes silently is an afternoon
spent on \"permission denied\" with a policy that looks correct."
  (let* ((pathname (write-policy (format nil "[filesystem]~%~
                                             read-execute = [\"/usr\"]~%~
                                             read = [\"/etc\", \"?/etc/definitely-absent\"]~%")))
         (plan (call-scute 'compile-launch-plan
                           (call-scute 'read-sandbox-policy pathname)
                           '("/bin/true"))))
    (check (notany (lambda (rule)
                     (search "definitely-absent" (call-scute 'path-rule-path rule)))
                   (call-scute 'launch-plan-filesystem plan))
           "an absent path reached the kernel rules")
    (check (member "/etc/definitely-absent" (call-scute 'launch-plan-absent plan)
                   :test #'string=)
           "the plan does not report what it skipped: ~S"
           (call-scute 'launch-plan-absent plan))))

(deftest test-an-absent-path-without-the-marker-is-still-a-refusal
  "A typo in a path is the commonest way to grant nothing while believing
otherwise, so silence is only ever what a policy asked for.

Refused when the plan is compiled rather than when the policy is parsed: whether a
path exists is a fact about this host, and a policy has to be readable on a host
it was not written for."
  (let* ((pathname (write-policy (format nil "[filesystem]~%~
                                             read-execute = [\"/usr\"]~%~
                                             read = [\"/etc/definitely-absent\"]~%")))
         (policy (call-scute 'read-sandbox-policy pathname))
         (refusal (nth-value 1 (ignore-errors
                                (call-scute 'compile-launch-plan policy '("/bin/true"))))))
    (check (typep refusal 'scute:policy-error)
           "an unmarked missing path was accepted")
    (check (search "definitely-absent" (princ-to-string refusal))
           "the refusal does not name the path: ~A" refusal)))

(deftest test-a-home-relative-path-is-expanded
  "/home/green is nobody else's path, so a shipped policy writes ~/."
  (let* ((home (sb-posix:getenv "HOME"))
         (pathname (write-policy (format nil "[filesystem]~%~
                                             read-execute = [\"/usr\"]~%~
                                             read = [\"~~/\"]~%")))
         (plan (call-scute 'compile-launch-plan
                           (call-scute 'read-sandbox-policy pathname)
                           '("/bin/true"))))
    (check (find home (call-scute 'launch-plan-filesystem plan)
                 :key (lambda (rule) (call-scute 'path-rule-path rule))
                 :test #'string=)
           "~~/ did not become ~A: ~S" home
           (mapcar (lambda (rule) (call-scute 'path-rule-path rule))
                   (call-scute 'launch-plan-filesystem plan)))))

(deftest test-a-policy-can-carry-its-own-command
  "The flag that makes an agent work belongs where the policy is read, not in a
README somebody skims."
  (let* ((pathname (write-policy (format nil "[filesystem]~%~
                                             read-execute = [\"/usr\"]~%~
                                             read = [\"/etc\"]~%~
                                             [command]~%~
                                             program = \"echo\"~%~
                                             arguments = [\"first\"]~%")))
         (policy (call-scute 'read-sandbox-policy pathname)))
    (check (equal '("echo" "first") (call-scute 'sandbox-policy-command policy))
           "the command was not read: ~S" (call-scute 'sandbox-policy-command policy))
    ;; What the caller writes after -- are arguments to it, appended.
    (let ((plan (call-scute 'compile-launch-plan policy '("second"))))
      (check (equal '("first" "second") (rest (call-scute 'launch-plan-command plan)))
             "the caller's arguments did not follow the policy's: ~S"
             (call-scute 'launch-plan-command plan))
      (check (search "echo" (first (call-scute 'launch-plan-command plan)))
             "the program was not resolved: ~S"
             (first (call-scute 'launch-plan-command plan))))))

(deftest test-a-command-table-is-checked-like-everything-else
  (check (refused-p (format nil "[filesystem]~%read = [\"/etc\"]~%[command]~%~
                                 arguments = [\"x\"]~%"))
         "a [command] with no program was accepted")
  (check (refused-p (format nil "[filesystem]~%read = [\"/etc\"]~%[command]~%~
                                 program = \"sh\"~%arguments = \"not-a-list\"~%"))
         "arguments that are not a list were accepted")
  (check (refused-p (format nil "[filesystem]~%read = [\"/etc\"]~%[command]~%~
                                 program = \"sh\"~%what = \"else\"~%"))
         "an unknown key in [command] was accepted"))

;;── Finding a policy by name ───────────────────────────────────────────────────

(deftest test-a-name-is-looked-up-on-the-search-path
  "--policy codex, not --policy /usr/share/scute/policies/codex.policy."
  (let* ((directory (scratch-pathname "policies"))
         (installed (merge-pathnames "shipped.policy"
                                     (uiop:ensure-directory-pathname directory))))
    (ensure-directories-exist (uiop:ensure-directory-pathname directory))
    (with-open-file (stream installed :direction :output :if-exists :supersede)
      (format stream "[filesystem]~%read = [\"/etc\"]~%"))
    (sb-posix:setenv "SCUTE_POLICY_PATH" (namestring directory) 1)
    (unwind-protect
         (progn
           (check (string= (namestring installed) (call-scute 'locate-policy "shipped"))
                  "a name on the search path was not found: ~S"
                  (call-scute 'locate-policy "shipped"))
           (check (member "shipped" (call-scute 'available-policies) :test #'string=)
                  "the name is not listed as available")
           ;; A path is never shadowed by an installed policy of the same name.
           (check (string= "./shipped.policy" (call-scute 'locate-policy "./shipped.policy"))
                  "a path was treated as a name")
           (let ((refusal (nth-value 1 (ignore-errors (call-scute 'locate-policy "absent")))))
             (check (typep refusal 'scute:policy-error)
                    "an unknown name was not refused")
             (check (search "shipped" (princ-to-string refusal))
                    "the refusal does not say what is installed: ~A" refusal)))
      (sb-posix:unsetenv "SCUTE_POLICY_PATH"))))

(deftest test-the-shipped-policies-are-valid
  "The policies in this tree are the ones that get installed, so they are held to
the same standard as any other: parsed, checked, and read for the command they
carry. Their paths are not resolved here -- half of them are deliberately absent
on any given machine, which is the point of the optional marker."
  (dolist (pathname (directory (merge-pathnames "policies/*.policy"
                                                (asdf:system-source-directory :scute))))
    (let ((policy (call-scute 'read-sandbox-policy pathname)))
      (check (call-scute 'sandbox-policy-command policy)
             "~A ships without a [command], so it cannot be run by name"
             (file-namestring pathname))
      (check (call-scute 'sandbox-policy-filesystem policy)
             "~A grants no filesystem access at all" (file-namestring pathname)))))

;;── Drop-in directories ────────────────────────────────────────────────────────
;;;
;;; A shipped policy cannot know where this machine keeps its caches, and copying
;;; the whole policy to add one path means an upgrade's improvements never arrive.
;;; NAME.d/*.policy is how someone extends a policy they do not own.

(defun with-policy-directories (function)
  "Run FUNCTION with a search path of two scratch directories, far and near.
Answers their pathnames, so a test can write policies and fragments into them."
  (let* ((far (uiop:ensure-directory-pathname (scratch-pathname "far")))
         (near (uiop:ensure-directory-pathname (scratch-pathname "near"))))
    ;; Emptied first: the scratch names are per-process, so without this a
    ;; fragment written by one test is still there for the next -- which is how
    ;; three of these tests first "failed".
    (dolist (directory (list far near))
      (ignore-errors (uiop:delete-directory-tree directory :validate t))
      (ensure-directories-exist directory))
    ;; Nearest first, as the real search path is ordered.
    (sb-posix:setenv "SCUTE_POLICY_PATH"
                     (format nil "~A:~A" (namestring near) (namestring far)) 1)
    (unwind-protect (funcall function far near)
      (sb-posix:unsetenv "SCUTE_POLICY_PATH"))))

(defun write-into (directory name text)
  (let ((pathname (merge-pathnames name (uiop:ensure-directory-pathname directory))))
    (ensure-directories-exist pathname)
    (with-open-file (stream pathname :direction :output :if-exists :supersede)
      (write-string text stream))
    pathname))

(deftest test-a-drop-in-adds-to-what-a-policy-grants
  "The common case: two more paths, without touching the shipped file."
  (with-policy-directories
    (lambda (far near)
      (declare (ignore near))
      (write-into far "app.policy"
                  (format nil "[filesystem]~%read = [\"/etc\"]~%"))
      (write-into far "app.d/10-more.policy"
                  (format nil "[filesystem]~%read = [\"/usr\"]~%read-write = [\"/tmp\"]~%"))
      (let* ((policy (call-scute 'read-sandbox-policy "app"))
             (paths (mapcar (lambda (rule) (call-scute 'filesystem-rule-path rule))
                            (call-scute 'sandbox-policy-filesystem policy))))
        (dolist (expected '("/etc" "/usr" "/tmp"))
          (check (member expected paths :test #'string=)
                 "~A did not survive the merge: ~S" expected paths))))))

(deftest test-a-drop-in-can-replace-a-scalar-and-add-arguments
  "One rule, everywhere: arrays append, and a scalar is an answer whose last
version wins.  So a drop-in changes which program runs by naming another, and adds
to its arguments rather than restating them -- which is what somebody wanting one
more flag actually wants."
  (with-policy-directories
    (lambda (far near)
      (declare (ignore near))
      (write-into far "app.policy"
                  (format nil "[filesystem]~%read = [\"/etc\"]~%~
                               [network]~%mode = \"none\"~%~
                               [command]~%program = \"sh\"~%arguments = [\"-c\", \"true\"]~%"))
      (write-into far "app.d/50-mine.policy"
                  (format nil "[network]~%mode = \"host\"~%~
                               [command]~%program = \"bash\"~%arguments = [\"--norc\"]~%"))
      (let ((policy (call-scute 'read-sandbox-policy "app")))
        (check (eq :host (call-scute 'sandbox-policy-network policy))
               "the drop-in did not change the network mode")
        (check (equal '("bash" "-c" "true" "--norc")
                      (call-scute 'sandbox-policy-command policy))
               "expected the program replaced and the arguments appended, got ~S"
               (call-scute 'sandbox-policy-command policy))))))

(deftest test-the-nearest-directory-has-the-last-word
  "Yours wins: a fragment in your own configuration outranks one shipped with the
policy, the same way your copy of a policy outranks the installed one."
  (with-policy-directories
    (lambda (far near)
      (write-into far "app.policy" (format nil "[filesystem]~%read = [\"/etc\"]~%~
                                                [limits]~%processes = 8~%"))
      (write-into far "app.d/10-vendor.policy" (format nil "[limits]~%processes = 64~%"))
      (write-into near "app.d/10-mine.policy" (format nil "[limits]~%processes = 256~%"))
      (let ((limits (call-scute 'sandbox-policy-limits
                                (call-scute 'read-sandbox-policy "app"))))
        (check (= 256 (call-scute 'resource-limits-processes limits))
               "expected the nearest fragment to win, got ~D"
               (call-scute 'resource-limits-processes limits))))))

(deftest test-fragments-are-merged-in-filename-order
  "10- before 20-, which is the only reason to number them."
  (with-policy-directories
    (lambda (far near)
      (declare (ignore near))
      (write-into far "app.policy" (format nil "[filesystem]~%read = [\"/etc\"]~%"))
      (write-into far "app.d/20-second.policy" (format nil "[limits]~%processes = 2~%"))
      (write-into far "app.d/10-first.policy" (format nil "[limits]~%processes = 1~%"))
      (let ((limits (call-scute 'sandbox-policy-limits
                                (call-scute 'read-sandbox-policy "app"))))
        (check (= 2 (call-scute 'resource-limits-processes limits))
               "20- did not follow 10-: processes = ~D"
               (call-scute 'resource-limits-processes limits))))))

(deftest test-a-repeated-path-in-a-drop-in-is-harmless
  "A fragment naming a path the policy already grants is ordinary, and must not
become the duplicate that validation refuses inside one file."
  (with-policy-directories
    (lambda (far near)
      (declare (ignore near))
      (write-into far "app.policy" (format nil "[filesystem]~%read = [\"/etc\"]~%"))
      (write-into far "app.d/10-again.policy"
                  (format nil "[filesystem]~%read = [\"/etc\", \"/usr\"]~%"))
      (let* ((policy (call-scute 'read-sandbox-policy "app"))
             (paths (mapcar (lambda (rule) (call-scute 'filesystem-rule-path rule))
                            (call-scute 'sandbox-policy-filesystem policy))))
        (check (= 1 (count "/etc" paths :test #'string=))
               "/etc survived twice: ~S" paths)
        (check (member "/usr" paths :test #'string=)
               "the new path was lost: ~S" paths)))))

(deftest test-every-file-that-contributed-is-named
  "A policy whose meaning comes from files nobody can see is worse than no
drop-ins, so the plan carries them and --dry-run prints them."
  (with-policy-directories
    (lambda (far near)
      (declare (ignore near))
      (let ((base (write-into far "app.policy"
                              (format nil "[filesystem]~%read-execute = [\"/usr\"]~%~
                                           read = [\"/etc\"]~%")))
            (fragment (write-into far "app.d/10-more.policy"
                                  (format nil "[filesystem]~%read-write = [\"/tmp\"]~%"))))
        (let* ((plan (call-scute 'compile-launch-plan
                                 (call-scute 'read-sandbox-policy "app")
                                 '("/bin/true")))
               (sources (call-scute 'launch-plan-sources plan)))
          (check (equal (list (namestring base) (namestring fragment)) sources)
                 "the plan names ~S" sources))))))

(deftest test-an-empty-drop-in-directory-changes-nothing
  (with-policy-directories
    (lambda (far near)
      (declare (ignore near))
      (write-into far "app.policy" (format nil "[filesystem]~%read = [\"/etc\"]~%"))
      (ensure-directories-exist
       (uiop:ensure-directory-pathname (merge-pathnames "app.d" far)))
      (let ((policy (call-scute 'read-sandbox-policy "app")))
        (check (= 1 (length (call-scute 'sandbox-policy-filesystem policy)))
               "an empty directory added rules")))))

;;── The broker is the default network ──────────────────────────────────────────
;;;
;;; Scute's answer to "how does an agent use a credential it must not hold" is a
;;; broker, and a broker nothing routes through is a broker nobody uses. So a
;;; policy that says nothing about the network gets the broker: one reachable port,
;;; and what can be done with it is the broker's to decide.

(deftest test-the-default-network-is-the-broker-and-only-the-broker
  (let ((policy (policy-from-string (format nil "[filesystem]~%read = [\"/etc\"]~%"))))
    (check (equal (list 10210) (call-scute 'sandbox-policy-connect-tcp policy))
           "more than the broker's port was permitted: ~S"
           (call-scute 'sandbox-policy-connect-tcp policy))
    (check (null (call-scute 'sandbox-policy-allow policy))
           "an address allowlist appeared where the policy wrote none")))

(deftest test-a-policy-wanting-no-network-still-gets-none
  "And needs no broker for it: a sandbox with no network cannot talk to one."
  (let ((policy (policy-from-string (format nil "[filesystem]~%read = [\"/etc\"]~%~
                                                 [network]~%mode = \"none\"~%"))))
    (check (eq :none (call-scute 'sandbox-policy-network policy))
           "mode = \"none\" did not survive")
    (check (null (call-scute 'sandbox-policy-proxy policy))
           "a proxy was added to a sandbox with no network")
    (check (null (call-scute 'sandbox-policy-broker policy))
           "a broker was required by a policy that cannot reach one")))

(deftest test-a-broker-is-settled-for-even-without-credentials
  "The broker has to be running for its port to be worth permitting, and its
certificate has to be trusted for TLS through it to work at all -- neither of which
depends on the policy asking it to hold a secret."
  (let ((policy (policy-from-string (format nil "[filesystem]~%read = [\"/etc\"]~%"))))
    (check (call-scute 'sandbox-policy-broker policy)
           "no broker settings for a policy whose egress goes through one")
    (check (null (call-scute 'sandbox-policy-credentials policy))
           "credentials appeared where the policy named none")))

(deftest test-naming-a-proxy-is-enough-to-mean-through-it
  "mode is not required beside a proxy: there is only one thing naming one means."
  (let ((policy (policy-from-string
                 (format nil "[filesystem]~%read = [\"/etc\"]~%~
                              [network]~%proxy = \"http://127.0.0.1:10210\"~%"))))
    (check (eq :host (call-scute 'sandbox-policy-network policy))
           "naming a proxy did not imply a network to proxy")))

(deftest test-a-table-that-names-no-mode-gets-the-default
  "One rule: a mode nobody named is the broker.  So a [network] table saying only
that unix sockets are wanted still gets the default network, rather than being
refused for not repeating something it did not want to decide."
  (let ((policy (policy-from-string
                 (format nil "[filesystem]~%read = [\"/etc\"]~%~
                              [network]~%unix-sockets = true~%"))))
    (check (eq :host (call-scute 'sandbox-policy-network policy))
           "a table without a mode did not get the default network")
    (check (string= (scute-value '+default-broker-proxy+)
                    (call-scute 'sandbox-policy-proxy policy))
           "it was not pointed at the broker: ~S"
           (call-scute 'sandbox-policy-proxy policy))
    (check (call-scute 'sandbox-policy-unix-sockets policy)
           "the one thing the table did say was lost"))
  ;; And a mode that is named means exactly itself: mode = "host" is the host's
  ;; network with no broker in it, which is what many policies already say.
  (let ((policy (policy-from-string
                 (format nil "[filesystem]~%read = [\"/etc\"]~%~
                              [network]~%mode = \"host\"~%connect-tcp = [443]~%"))))
    (check (null (call-scute 'sandbox-policy-proxy policy))
           "a proxy was added to a policy that asked for the host's network")
    (check (equal (list 443) (call-scute 'sandbox-policy-connect-tcp policy))
           "the ports it named were changed: ~S"
           (call-scute 'sandbox-policy-connect-tcp policy))))

(deftest test-the-default-takes-the-strongest-form-the-host-allows
  "Two forms of the same default, and which one you get is a fact about the host.

With CAP_BPF -- which the packages grant -- the kernel rewrites the destination of
every web connection to the broker, so a client that ignores the proxy variables
arrives there anyway and nothing in the sandbox can address anywhere else. Without
it, the broker is named as the proxy and Landlock permits that one port: a client
ignoring the variables reaches nothing, which is weaker and still a sandbox.

Choosing the stronger form where it can be enacted is Scute's own default, not
something a policy asked for -- a policy writing mode = \"proxied\" itself is still
refused where the guard cannot be installed."
  (let ((scute::*implicit-network-mode* nil))
    (check (string= "proxied" (call-scute 'implicit-network-mode t))
           "a host that can attach the guard did not get the kernel redirect")
    (check (string= "host" (call-scute 'implicit-network-mode nil))
           "a host without the capability did not fall back to the port-level form"))
  ;; And the stronger form is a whole policy, not a mode with nothing behind it:
  ;; the web ports have to pass Landlock for the kernel to redirect them at all.
  (let ((scute::*implicit-network-mode* "proxied"))
    (let ((policy (policy-from-string (format nil "[filesystem]~%read = [\"/etc\"]~%"))))
      (check (eq :proxied (call-scute 'sandbox-policy-network policy))
             "the implicit mode was not enacted")
      (check (string= (scute-value '+default-broker-proxy+)
                      (call-scute 'sandbox-policy-proxy policy))
             "redirected to nowhere: ~S" (call-scute 'sandbox-policy-proxy policy))
      (dolist (port '(80 443 53))
        (check (member port (call-scute 'sandbox-policy-connect-tcp policy))
               "port ~D is refused before the kernel could redirect it: ~S"
               port (call-scute 'sandbox-policy-connect-tcp policy))))))

(deftest test-security-absent-optional-grants-fail-closed
  (let* ((text (format nil "[filesystem]~%read = [\"?/scute-missing-optional-393fd9\"]~%[network]~%mode = \"none\"~%"))
         (policy (call-scute 'validate-sandbox-policy (call-scute 'parse-policy-text text)))
         (refusal (nth-value 1 (ignore-errors
                                (call-scute 'compile-launch-plan policy '("/bin/true"))))))
    (check (typep refusal 'scute:policy-error)
           "a policy with no remaining grants disabled filesystem confinement: ~S" refusal))
  (check (null (call-scute 'launch-plan-filesystem
                           (call-scute 'compile-command-launch-plan '("/bin/true") nil)))
         "explicit namespaces-only launches must remain available"))
