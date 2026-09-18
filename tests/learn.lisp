;;; SPDX-License-Identifier: MIT
;;;
;;; Learning: watching a command to find out what policy it would have needed.

(in-package #:scute/tests)

(defun learn-command (command &optional directory)
  "Watch COMMAND and answer its result and what it reached for."
  (call-scute 'run-launch-plan
              (call-scute 'compile-command-launch-plan command '()
                          (or directory (sb-posix:getcwd)))
              :observe t))

(defun observed-access (observations path)
  "What PATH was reached for, by a path that may have been canonicalized."
  (let ((paths (call-scute 'observations-paths observations))
        (wanted (or (ignore-errors (and (probe-file path) (namestring (truename path))))
                    path)))
    (gethash wanted paths)))

(deftest test-learning-sees-reads-and-writes
  "A watched command's reads and writes are both recorded, against the paths the
kernel would see rather than the ones the program typed."
  (let* ((workspace (scratch-pathname "learn"))
         (written (format nil "~A/written" workspace)))
    (unwind-protect
         (progn
           (ensure-directories-exist (format nil "~A/" workspace))
           (multiple-value-bind (result observations)
               (learn-command (list "/bin/sh" "-c"
                                    (format nil "cat /etc/hostname > ~A" written))
                              workspace)
             (check (eql 0 (call-scute 'sandbox-result-exit-code result))
                    "the watched command did not finish: ~S" result)
             (check (member :read (observed-access observations "/etc/hostname"))
                    "reading /etc/hostname was not seen: ~S"
                    (observed-access observations "/etc/hostname"))
             (check (member :write (observed-access observations written))
                    "writing ~A was not seen: ~S" written
                    (observed-access observations written))
             ;; /bin/sh is a symlink here; what is recorded is what it resolves to.
             (check (member :execute (observed-access observations "/bin/sh"))
                    "executing the command itself was not seen")))
      (ignore-errors (delete-file written))
      (ignore-errors (sb-posix:rmdir workspace)))))

(deftest test-a-learned-policy-runs-the-command
  "The point of the whole exercise: what learning writes down is enough to run
the command again under it.  If this fails, learning is a toy."
  (let* ((workspace (scratch-pathname "learn-roundtrip"))
         (script "cat /etc/hostname > copy; ls > listing; wc -l < listing")
         (policy-file (format nil "~A/scute.policy" workspace)))
    (unwind-protect
         (progn
           (ensure-directories-exist (format nil "~A/" workspace))
           (multiple-value-bind (result observations)
               (learn-command (list "/bin/sh" "-c" script) workspace)
             (check (eql 0 (call-scute 'sandbox-result-exit-code result))
                    "the learning run itself failed: ~S" result)
             (let ((rules (call-scute 'learned-rules observations workspace)))
               (check rules "learning produced no rules at all")
               (with-open-file (stream policy-file :direction :output
                                                   :if-exists :supersede)
                 (call-scute 'write-learned-policy rules stream))
               ;; Now run it again, under the policy that was just written.
               (let* ((policy (call-scute 'read-sandbox-policy policy-file))
                      (plan (call-scute 'compile-launch-plan policy
                                        (list "/bin/sh" "-c" script)
                                        :directory workspace))
                      (again (call-scute 'run-launch-plan plan)))
                 (check (eql 0 (call-scute 'sandbox-result-exit-code again))
                        "the command failed under the policy learned from it: ~S~%~A"
                        again (read-file-string policy-file))))))
      (dolist (name '("copy" "listing" "scute.policy"))
        (ignore-errors (delete-file (format nil "~A/~A" workspace name))))
      (ignore-errors (sb-posix:rmdir workspace)))))

(deftest test-learned-rules-are-few-and-relative
  "A policy nobody would read is no use.  Forty files under /usr become one
rule, and the working directory is named as \".\" so the policy travels with the
project instead of naming somebody's home."
  (let ((workspace (scratch-pathname "learn-shape")))
    (unwind-protect
         (progn
           (ensure-directories-exist (format nil "~A/" workspace))
           (multiple-value-bind (result observations)
               (learn-command (list "/bin/sh" "-c" "ls /usr/bin > here") workspace)
             (declare (ignore result))
             (let* ((rules (call-scute 'learned-rules observations workspace))
                    (paths (loop for (nil . named) in rules append named)))
               (check (member "/usr" paths :test #'string=)
                      "the files under /usr did not become one rule: ~S" paths)
               (check (member "." paths :test #'string=)
                      "the working directory was not named as \".\": ~S" paths)
               (check (notany (lambda (path) (eql 0 (search "/usr/" path))) paths)
                      "a rule named something under /usr as well as /usr: ~S" paths)
               (check (< (length paths) 8)
                      "~D rules is more than anyone will read: ~S"
                      (length paths) paths))))
      (ignore-errors (delete-file (format nil "~A/here" workspace)))
      (ignore-errors (sb-posix:rmdir workspace)))))

(deftest test-learning-observes-without-restricting
  "Learning has to see what a command wants, which means not stopping it: no
filesystem rules are installed during a learning run."
  (multiple-value-bind (result observations)
      (learn-command '("/bin/sh" "-c" "cat /etc/hostname > /dev/null"))
    (declare (ignore observations))
    (check (eql 0 (call-scute 'sandbox-result-exit-code result))
           "a learning run stopped the command it was watching: ~S" result)))

(deftest test-learning-keeps-the-process-layer
  "Watching a command does not relax the rest of the sandbox: the denylist is in
the same filter as the notifications, so a learning run refuses what a real one
would."
  (let ((result (call-scute 'run-launch-plan
                            (call-scute 'compile-command-launch-plan
                                        '("/usr/bin/unshare" "--user" "/bin/true")
                                        '())
                            :observe t)))
    (check (not (eql 0 (call-scute 'sandbox-result-exit-code result)))
           "a learning run allowed a syscall the filter denies: ~S" result)))

;;── Explaining a refusal ───────────────────────────────────────────────────────

(defun explain-run (policy-text command directory)
  "Run COMMAND under POLICY-TEXT, watching, and answer what it was refused."
  (let ((plan (call-scute 'compile-launch-plan
                          (call-scute 'validate-sandbox-policy
                                      (call-scute 'parse-policy-text policy-text))
                          command :directory directory)))
    (multiple-value-bind (result observations)
        (call-scute 'run-launch-plan plan :observe t)
      (values (call-scute 'refused-observations observations
                          (call-scute 'launch-plan-filesystem plan))
              result
              plan))))

(deftest test-explaining-names-what-was-refused
  "A command refused something reports its own confusion; scute says which path
and what access, because a seccomp filter sees the attempt before the security
modules refuse it."
  (let ((workspace (scratch-pathname "explain")))
    (unwind-protect
         (progn
           (ensure-directories-exist (format nil "~A/" workspace))
           (multiple-value-bind (refused result)
               (explain-run "[filesystem]
read-execute = [\"/usr\"]"
                            ;; Separate statements: a redirection that fails
                            ;; stops the command before it can read anything,
                            ;; and then there is nothing to report about the read.
                            '("/bin/sh" "-c" "cat /etc/hostname; echo x > copy")
                            workspace)
             (check (not (eql 0 (call-scute 'sandbox-result-exit-code result)))
                    "the command succeeded under a policy that forbids its work")
             (check (assoc "/etc/hostname" refused :test #'string=)
                    "reading /etc/hostname was not reported as refused: ~S" refused)
             (let ((write (assoc (format nil "~A/copy" workspace) refused
                                 :test #'string=)))
               (check write "writing copy was not reported as refused: ~S" refused)
               (check (member :write (cdr write))
                      "the refusal did not say what was wanted: ~S" write))
             ;; Every refusal names somewhere a rule could actually name.
             (dolist (refusal refused)
               (check (call-scute 'reachable-path-p (car refusal))
                      "~A cannot be named by any rule, so suggesting it would ~
                       produce a policy that will not load" (car refusal)))))
      (ignore-errors (delete-file (format nil "~A/copy" workspace)))
      (ignore-errors (sb-posix:rmdir workspace)))))

(deftest test-a-sufficient-policy-explains-nothing
  "Nothing is reported when nothing was refused.  This is the test that would
have caught rules naming a file -- /dev/tty, /dev/null -- being read as granting
nothing, because the access questions asked for directory-only rights."
  (let ((workspace (scratch-pathname "explain-clean")))
    (unwind-protect
         (progn
           (ensure-directories-exist (format nil "~A/" workspace))
           (multiple-value-bind (refused result)
               (explain-run (format nil "[filesystem]~%~
                                         read-execute = [\"/usr\"]~%~
                                         read = [\"/etc\"]~%~
                                         read-write = [\"~A\", \"/dev/tty\", \"/dev/null\"]~%"
                                    workspace)
                            '("/bin/sh" "-c" "cat /etc/hostname > copy")
                            workspace)
             (check (eql 0 (call-scute 'sandbox-result-exit-code result))
                    "the command failed under a policy that allows its work: ~S"
                    result)
             (check (null refused)
                    "a policy that allowed everything still reported refusals: ~S"
                    refused)))
      (ignore-errors (delete-file (format nil "~A/copy" workspace)))
      (ignore-errors (sb-posix:rmdir workspace)))))

(deftest test-the-suggested-rules-are-the-missing-ones
  "What scute suggests adding is what makes the command work: the refusals fold
into rules the same way a learned policy does, and applying them is enough."
  (let ((workspace (scratch-pathname "explain-fix")))
    (unwind-protect
         (progn
           (ensure-directories-exist (format nil "~A/" workspace))
           (multiple-value-bind (refused) 
               (explain-run "[filesystem]
read-execute = [\"/usr\"]"
                            '("/bin/sh" "-c" "cat /etc/hostname > copy")
                            workspace)
             (let* ((suggested (call-scute 'refusal-rules refused workspace))
                    (text (with-output-to-string (stream)
                            (format stream "[filesystem]~%read-execute = [\"/usr\"]~%")
                            (loop for (kind . paths) in suggested
                                  do (format stream "~(~A~) = [~{~S~^, ~}]~%"
                                             kind paths))))
                    (plan (call-scute 'compile-launch-plan
                                      (call-scute 'validate-sandbox-policy
                                                  (call-scute 'parse-policy-text text))
                                      '("/bin/sh" "-c" "cat /etc/hostname > copy")
                                      :directory workspace))
                    (result (call-scute 'run-launch-plan plan)))
               (check (eql 0 (call-scute 'sandbox-result-exit-code result))
                      "the command still failed after adding what scute ~
                       suggested:~%~A~%result ~S" text result))))
      (ignore-errors (delete-file (format nil "~A/copy" workspace)))
      (ignore-errors (sb-posix:rmdir workspace)))))

;;── The audit trail ────────────────────────────────────────────────────────────

(defun audit-run (policy-text command directory)
  "Run COMMAND under POLICY-TEXT and answer the audit trail it produced."
  (let* ((policy (call-scute 'validate-sandbox-policy
                             (call-scute 'parse-policy-text policy-text)))
         (plan (call-scute 'compile-launch-plan policy command :directory directory)))
    (multiple-value-bind (result observations)
        (call-scute 'run-launch-plan plan :observe t)
      (values (with-output-to-string (stream)
                (call-scute 'write-audit-trail observations
                            (call-scute 'audit-policy-events
                                        (call-scute 'launch-plan-audit plan))
                            stream :command (call-scute 'launch-plan-command plan)))
              result))))

(deftest test-auditing-records-what-happened
  "A policy asking to be audited gets a record per event, one JSON object to a
line, so that reading it needs nothing but the usual tools."
  (let ((workspace (scratch-pathname "audit")))
    (unwind-protect
         (progn
           (ensure-directories-exist (format nil "~A/" workspace))
           (multiple-value-bind (trail result)
               (audit-run (format nil "[filesystem]~%~
                                       read-execute = [\"/usr\"]~%~
                                       read = [\"/etc\"]~%~
                                       read-write = [\"~A\", \"/dev/null\"]~%~
                                       [audit]~%events = [\"exec\", \"open\"]~%"
                                  workspace)
                          '("/bin/sh" "-c" "cat /etc/hostname > copy")
                          workspace)
             (check (eql 0 (call-scute 'sandbox-result-exit-code result))
                    "the audited command did not finish: ~S" result)
             (check (search "\"event\": \"start\"" trail)
                    "the trail does not say what was run:~%~A" trail)
             (check (search "\"event\": \"exec\"" trail)
                    "no exec was recorded:~%~A" trail)
             (check (search "/etc/hostname" trail)
                    "the file the command read was not recorded:~%~A" trail)
             ;; Every line is a JSON object on its own, which is the whole point
             ;; of the format: check the shape without a JSON parser to hand.
             (with-input-from-string (stream trail)
               (loop for line = (read-line stream nil nil)
                     while line
                     do (check (and (char= #\{ (char line 0))
                                    (char= #\} (char line (1- (length line)))))
                               "a trail line is not one object: ~S" line)))))
      (ignore-errors (delete-file (format nil "~A/copy" workspace)))
      (ignore-errors (sb-posix:rmdir workspace)))))

(deftest test-auditing-records-only-what-was-asked
  "A policy asking for exec alone does not get a record of every file opened."
  (let ((workspace (scratch-pathname "audit-narrow")))
    (unwind-protect
         (progn
           (ensure-directories-exist (format nil "~A/" workspace))
           (multiple-value-bind (trail)
               (audit-run (format nil "[filesystem]~%~
                                       read-execute = [\"/usr\"]~%~
                                       read = [\"/etc\"]~%~
                                       read-write = [\"~A\", \"/dev/null\"]~%~
                                       [audit]~%events = [\"exec\"]~%"
                                  workspace)
                          '("/bin/sh" "-c" "cat /etc/hostname > /dev/null")
                          workspace)
             (check (search "\"event\": \"exec\"" trail)
                    "no exec was recorded:~%~A" trail)
             (check (not (search "\"event\": \"open\"" trail))
                    "opens were recorded by a policy that asked only for exec:~%~A"
                    trail)))
      (ignore-errors (sb-posix:rmdir workspace)))))

(deftest test-auditing-connections-is-refused
  "v0 gives a sandbox no network, so a policy asking for connections to be
recorded is refused rather than quietly given a trail with nothing in it."
  (let* ((policy (policy-from-string "[filesystem]
read-execute = [\"/usr\"]
[audit]
events = [\"connect\"]"))
         (plan (call-scute 'compile-launch-plan policy '("/bin/true")))
         (condition (nth-value 1 (ignore-errors (call-scute 'run-launch-plan plan)))))
    (check (typep condition 'scute:control-not-implemented)
           "auditing connections was accepted, got ~S" condition)))

(deftest test-a-learned-policy-always-loads
  "A learned policy must be one scute will accept.  A loader probes for library
variants that are not installed, and a rule naming a missing path is an error,
so those observations are left out however they arrived."
  (let* ((observations (scute::make-observations nil))
         (workspace (scratch-pathname "learn-loads")))
    (unwind-protect
         (progn
           (ensure-directories-exist (format nil "~A/" workspace))
           ;; One real path, one that exists nowhere at all, and a connection --
           ;; which changes the network section and so is where a duplicate key
           ;; would appear.
           (scute::record-observation observations nil "/etc/hostname" :read)
           (scute::record-connection observations (cons #(127 0 0 1) 443))
           (scute::record-observation observations nil
                                      "/no/such/prefix/glibc-hwcaps/x/libc.so.6" :read)
           (let* ((rules (call-scute 'learned-rules observations workspace))
                  (text (with-output-to-string (stream)
                          (let ((scute:*learned-connections*
                                  (loop for c being the hash-keys
                                          of (scute:observations-connections observations)
                                        collect c)))
                            (call-scute 'write-learned-policy rules stream)))))
             (check (not (search "/no/such/prefix" text))
                    "a learned policy named a path that does not exist:~%~A" text)
             (check (search "allow = [\"127.0.0.1:443\"]" text)
                    "the connection was not written as an allowlist entry:~%~A" text)
             ;; And what it wrote is a policy scute accepts.
             (let ((policy (call-scute 'validate-sandbox-policy
                                       (call-scute 'parse-policy-text text))))
               (check (call-scute 'compile-launch-plan policy '("/bin/true")
                                  :directory workspace)
                      "the learned policy would not compile"))))
      (ignore-errors (sb-posix:rmdir workspace)))))
