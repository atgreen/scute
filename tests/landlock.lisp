;;; SPDX-License-Identifier: MIT
;;;
;;; The filesystem layer: one Landlock ruleset, enforced by the child on itself.

(in-package #:scute/tests)

(defparameter +system-rules+ '((:read-execute "/usr"))
  "Enough to run /bin/sh and its loader on a merged-/usr host, and no more.")

(defun run-with-rules (script rules)
  "Run SCRIPT under RULES and answer the sandbox result."
  (call-scute 'run-namespaced-command
              (list "/bin/sh" "-c" script)
              :filesystem rules))

(defun sandbox-says (script rules)
  "Run SCRIPT under RULES with its output captured, and answer what it wrote."
  (let ((report (scratch-pathname "landlock")))
    (unwind-protect
         (progn
           (delete-scratch report)
           (run-with-rules (format nil "exec > ~A 2>&1~%~A" report script)
                           (append rules (list (list :read-write "/tmp"))))
           (read-file-string report))
      (delete-scratch report))))

(deftest test-filesystem-is-denied-by-default
  "Without a rule for it, a path cannot be opened -- and with one, it can.
Both halves matter: the second is what proves the first is Landlock talking
and not some unrelated failure."
  (let ((denied (sandbox-says "if cat /etc/hostname; then echo ALLOWED; else echo denied; fi"
                              +system-rules+))
        (allowed (sandbox-says "if cat /etc/hostname > /dev/null; then echo ALLOWED; else echo denied; fi"
                               (append +system-rules+
                                       '((:read "/etc") (:read-write "/dev/null"))))))
    (check (search "denied" denied) "/etc was readable without a rule: ~A" denied)
    (check (search "ALLOWED" allowed) "/etc was not readable with a rule: ~A" allowed)))

(deftest test-write-needs-more-than-read
  "A :read rule does not carry the right to write beneath it."
  ;; Not ":" -- a redirection failure on a POSIX special builtin makes a
  ;; non-interactive shell exit, and the else branch never runs.
  (let ((output (sandbox-says
                 "if echo x > /etc/scute-must-not-appear; then echo WROTE; else echo refused; fi"
                 (append +system-rules+ '((:read "/etc"))))))
    (check (search "refused" output) "a :read rule permitted a write: ~A" output)
    (check (not (probe-file "/etc/scute-must-not-appear"))
           "the sandbox created a file outside its rules")))

(deftest test-writable-path-is-writable
  "What a :read-write rule grants actually works, including creating files."
  (let* ((directory (scratch-pathname "workspace"))
         (witness (format nil "~A/written" directory)))
    (unwind-protect
         (progn
           (ensure-directories-exist (format nil "~A/" directory))
           (run-with-rules (format nil "echo sandboxed > ~A" witness)
                           (append +system-rules+ (list (list :read-write directory))))
           (check (probe-file witness) "the sandbox could not write where it was allowed")
           (check (search "sandboxed" (if (probe-file witness)
                                          (read-file-string witness)
                                          ""))
                  "the written file did not hold what the sandbox wrote"))
      (ignore-errors (delete-file witness))
      (ignore-errors (sb-posix:rmdir directory)))))

(deftest test-rules-on-files-not-only-directories
  "A rule may name a single file.  The kernel rejects directory-only rights on
one, so those rights have to be masked out -- /dev/null is the everyday case."
  (let ((output (sandbox-says "if echo discarded > /dev/null; then echo OK; else echo failed; fi"
                              (append +system-rules+ '((:read-write "/dev/null"))))))
    (check (search "OK" output) "a rule on /dev/null did not work: ~A" output)))

(deftest test-unrestricted-without-rules
  "With no rules there is no ruleset and no filesystem restriction.  This is the
control for every test above."
  (let ((result (run-with-rules "cat /etc/hostname > /dev/null" '())))
    (check (eql 0 (call-scute 'sandbox-result-exit-code result))
           "an unrestricted sandbox could not read /etc: ~S" result)))

(deftest test-executable-must-be-permitted
  "Rules that do not allow the command to execute are refused up front, rather
than surfacing as EACCES from execve and reading like a broken command."
  (let ((condition (nth-value 1 (ignore-errors
                                 (run-with-rules "echo hi" '((:read "/etc")))))))
    (check (typep condition 'scute:sandbox-setup-error)
           "a command with no execute rule was allowed to launch, got ~S" condition)
    (check (and (typep condition 'scute:sandbox-setup-error)
                (eq :executable-not-permitted
                    (scute:sandbox-setup-error-operation condition)))
           "the refusal did not name the missing execute access: ~S" condition)))

(deftest test-rule-path-must-exist
  "A rule naming a path that is not there is an error, not a rule to skip."
  (let ((condition (nth-value 1 (ignore-errors
                                 (run-with-rules "true" '((:read "/no/such/path")))))))
    (check (typep condition 'scute:sandbox-setup-error)
           "a nonexistent rule path was accepted, got ~S" condition)))

(deftest test-unknown-access-kind-is-refused
  "Only the four documented access kinds mean anything."
  (let ((condition (nth-value 1 (ignore-errors
                                 (run-with-rules "true" '((:read-only "/usr")))))))
    (check (typep condition 'scute:usage-error)
           "an unknown access kind was accepted, got ~S" condition)))
