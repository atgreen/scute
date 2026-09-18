;;; SPDX-License-Identifier: MIT
;;;
;;; Learning: watching a command to find out what policy it would have needed.

(in-package #:scute/tests)

(defun learn-command (command &optional directory)
  "Watch COMMAND and answer its result and what it reached for."
  (call-scute 'run-launch-plan
              (call-scute 'compile-command-launch-plan command '()
                          (or directory (sb-posix:getcwd)))
              :learn t))

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
                            :learn t)))
    (check (not (eql 0 (call-scute 'sandbox-result-exit-code result)))
           "a learning run allowed a syscall the filter denies: ~S" result)))
