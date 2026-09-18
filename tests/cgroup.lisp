;;; SPDX-License-Identifier: MIT
;;;
;;; Resource limits: that they are installed beneath the caller's own delegated
;;; subtree, that they bind, that the kernel's account of them comes back, and
;;; that nothing is left behind.

(in-package #:scute/tests)

(defparameter +needed-controllers+ '("memory" "pids" "cpu"))

(defun controller-enabled-ancestor ()
  "The nearest ancestor of this process's cgroup that already hands out the
controllers a limit needs.  A cgroup created under it can carry limits, which
is what lets these tests arrange a delegated subtree of their own."
  (loop with directory = (call-scute 'discover-cgroup2)
        repeat 8
        do (setf directory (string-right-trim "/" (directory-namestring directory)))
           (when (or (zerop (length directory)) (string= "/sys/fs/cgroup" directory))
             (return nil))
           (when (and (zerop (scute::%access directory scute::+w-ok+))
                      (every (lambda (controller)
                               (member controller (scute::enabled-controllers directory)
                                       :test #'string=))
                             +needed-controllers+))
             (return directory))))

(defun call-in-own-cgroup (function)
  "Run FUNCTION with this process alone in a cgroup of its own.

Cgroup v2 will not let a cgroup hold processes and hand controllers to its
children at the same time, so a Scute sharing a cgroup with anything else
cannot install limits.  These tests borrow a cgroup rather than demanding one:
they make one, step into it, and step back out afterwards."
  (let ((ancestor (controller-enabled-ancestor))
        (home (call-scute 'discover-cgroup2)))
    (if (null ancestor)
        (progn (format *error-output*
                       "~&SKIP: no cgroup here hands out ~{~A~^, ~} to children, ~
                        so limits cannot be exercised~%"
                       +needed-controllers+)
               nil)
        (let ((mine (format nil "~A/scute-test.~D" ancestor (sb-posix:getpid))))
          (unwind-protect
               (progn
                 (ignore-errors (sb-posix:mkdir mine #o755))
                 (scute::write-proc-file (format nil "~A/cgroup.procs" mine)
                                         (format nil "~D" (sb-posix:getpid))
                                         :test-enter-cgroup)
                 (funcall function mine)
                 t)
            (ignore-errors
             (scute::write-proc-file (format nil "~A/cgroup.procs" home)
                                     (format nil "~D" (sb-posix:getpid))
                                     :test-leave-cgroup))
            (ignore-errors (sb-posix:rmdir (format nil "~A/scute.supervisor" mine)))
            (ignore-errors (sb-posix:rmdir mine)))))))

(defmacro with-own-cgroup ((root) &body body)
  `(call-in-own-cgroup (lambda (,root) (declare (ignorable ,root)) ,@body)))

(defun limited-policy (&rest limits)
  "A policy carrying LIMITS, and filesystem rules wide enough that nothing here
is stopped by the wrong layer: these tests need to read their own cgroup, and to
ask for memory they must be able to open /dev/zero."
  (call-scute 'validate-sandbox-policy
              (call-scute 'parse-policy-text
                          (format nil "[filesystem]~%~
                                       read-execute = [\"/usr\"]~%~
                                       read = [\"/proc\", \"/sys\"]~%~
                                       read-write = [\"/dev/zero\", \"/dev/null\", \"/tmp\"]~%~
                                       [limits]~%~{~A~%~}"
                                  limits))))

(defun run-limited (command &rest limits)
  "Run COMMAND under LIMITS."
  (call-scute 'run-launch-plan
              (call-scute 'compile-launch-plan
                          (apply #'limited-policy limits)
                          command)))

(defun sandbox-cgroup-names (root)
  "The sandbox cgroups under ROOT, which is not the supervisor Scute lives in."
  (remove "scute.supervisor"
          (mapcar (lambda (path) (car (last (pathname-directory path))))
                  (directory (format nil "~A/scute.*/" root)))
          :test #'string=))

;;── Limits as asked for ────────────────────────────────────────────────────────

(deftest test-limits-reach-the-kernel
  "What a policy asks for is what the sandbox is given, in the units the kernel
uses, in a cgroup of the sandbox's own."
  (with-own-cgroup (root)
    (let* ((report (scratch-pathname "cgroup"))
           (result (run-limited
                    (list "/bin/sh" "-c"
                          (format nil "cg=/sys/fs/cgroup$(cut -d: -f3 /proc/self/cgroup); ~
                                       { basename $cg; cat $cg/memory.max; ~
                                         cat $cg/pids.max; cat $cg/cpu.max; ~
                                         cat $cg/memory.swap.max; } > ~A"
                                  report))
                    "memory = \"64M\"" "processes = 32" "cpu-percent = 50")))
      (unwind-protect
           (let ((lines (with-open-file (stream report)
                          (loop for line = (read-line stream nil nil)
                                while line collect line))))
             (check (eql 0 (call-scute 'sandbox-result-exit-code result))
                    "the command did not finish: ~S" result)
             (destructuring-bind (&optional name memory pids cpu swap) lines
               (check (and name (eql 0 (search "scute." name)))
                      "the sandbox was not in a cgroup of its own: ~S" name)
               (check (equal "67108864" memory) "memory.max is ~S, not 64M" memory)
               (check (equal "32" pids) "pids.max is ~S" pids)
               (check (equal "50000 100000" cpu) "cpu.max is ~S, not 50%" cpu)
               (check (equal "0" swap)
                      "memory.swap.max is ~S: a memory limit that can be swapped ~
                       around does not mean what it says" swap)))
        (delete-scratch report)))))

(deftest test-memory-limit-binds
  "A command that wants more memory than its limit is killed, and Scute can say
that the limit is what killed it -- which the exit status alone cannot."
  (with-own-cgroup (root)
    (let ((result (run-limited '("/bin/sh" "-c" "dd if=/dev/zero of=/dev/null bs=256M count=1")
                               "memory = \"64M\"")))
      (check (eql 9 (call-scute 'sandbox-result-term-signal result))
             "expected death by SIGKILL, got ~S" result)
      (check (call-scute 'sandbox-result-oom-killed-p result)
             "the memory limit was not recognized as the cause: events ~S"
             (call-scute 'sandbox-result-events result)))))

(deftest test-process-limit-binds
  "A command that wants more processes than its limit is refused them, and the
kernel's count of the refusals comes back with the result."
  (with-own-cgroup (root)
    (let* ((result (run-limited
                    '("/bin/sh" "-c"
                      "i=0; while [ $i -lt 40 ]; do /bin/sleep 0.2 & i=$((i+1)); done; wait")
                    "processes = 4"))
           (events (call-scute 'sandbox-result-events result)))
      (check (plusp (or (cdr (assoc "pids.max" events :test #'string=)) 0))
             "nothing was refused by the process limit: events ~S" events))))

;;── Nothing left behind ────────────────────────────────────────────────────────

(deftest test-cgroup-is-removed-after-a-run
  "The sandbox cgroup is gone when the sandbox is, after success and after a
launch that never got as far as running anything."
  (with-own-cgroup (root)
    (run-limited '("/bin/true") "processes = 16")
    (check (null (sandbox-cgroup-names root))
           "a cgroup survived a normal exit: ~S" (sandbox-cgroup-names root))
    (ignore-errors (run-limited '("/nonexistent/command") "processes = 16"))
    (check (null (sandbox-cgroup-names root))
           "a cgroup survived a failed launch: ~S" (sandbox-cgroup-names root))))

;;── Without delegation ─────────────────────────────────────────────────────────

(deftest test-limits-fail-closed-without-delegation
  "Where limits cannot be installed, asking for them is refused with something
a person can act on -- never enforced in part."
  (multiple-value-bind (installable root explanation) (call-scute 'limits-installable-p)
    (declare (ignore root))
    (if installable
        (format *error-output*
                "~&SKIP: limits are installable here (~A), so refusal cannot be ~
                 exercised~%" explanation)
        (let ((condition (nth-value 1 (ignore-errors
                                       (run-limited '("/bin/true") "processes = 16")))))
          (check (typep condition 'scute:sandbox-setup-error)
                 "limits were accepted where they cannot be installed, got ~S"
                 condition)
          (check (search "systemd-run" (princ-to-string condition))
                 "the refusal does not say how to get a delegated cgroup: ~A"
                 condition)))))
