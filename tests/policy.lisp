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

(deftest test-the-network-mode-is-the-policys-to-choose
  "A sandbox has no network because it has a network namespace of its own.  A
policy that needs one -- a build that fetches dependencies -- says so, and then
shares the host's."
  (check (eq :none (call-scute 'sandbox-policy-network
                               (policy-from-string "[filesystem]
read = [\"/etc\"]")))
         "a policy that says nothing did not default to no network")
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
