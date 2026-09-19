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

;;── A limit on time ────────────────────────────────────────────────────────────

(defun run-for-at-most (seconds command)
  "Run COMMAND with a wall-clock limit, and answer the result and the wall time."
  (let* ((plan (call-scute 'plan-with-wall-clock
                           (call-scute 'compile-command-launch-plan command '())
                           seconds))
         (start (get-internal-real-time))
         (result (call-scute 'run-launch-plan plan)))
    (values result (/ (- (get-internal-real-time) start)
                      internal-time-units-per-second))))

(deftest test-a-time-limit-stops-a-command
  "A command that runs past its limit is stopped and reported as such -- and
promptly, because a command that catches nothing will never see the signal it is
being asked to stop by, being PID 1 of its namespace."
  (multiple-value-bind (result elapsed) (run-for-at-most 1 '("/bin/sleep" "60"))
    (check (call-scute 'sandbox-result-timed-out result)
           "the command was not reported as having run out of time: ~S" result)
    (check (eql 9 (call-scute 'sandbox-result-term-signal result))
           "expected it to be killed, got ~S" result)
    (check (< elapsed 3)
           "stopping took ~,1Fs, so a grace period was waited out for a command ~
            that could not receive the signal" elapsed)))

(deftest test-a-time-limit-leaves-a-prompt-command-alone
  "A command that finishes inside its limit keeps its own exit status, and a
command that catches the signal gets the grace period to act on it."
  (multiple-value-bind (result) (run-for-at-most 5 '("/bin/sh" "-c" "exit 3"))
    (check (eql 3 (call-scute 'sandbox-result-exit-code result))
           "a command that finished in time did not keep its status: ~S" result)
    (check (not (call-scute 'sandbox-result-timed-out result))
           "a command that finished in time was reported as timed out"))
  (multiple-value-bind (result elapsed)
      (run-for-at-most 1 '("/bin/sh" "-c"
                           "trap 'exit 9' TERM; i=0; ~
                            while [ $i -lt 300 ]; do sleep 0.1; i=$((i+1)); done"))
    (check (eql 9 (call-scute 'sandbox-result-exit-code result))
           "a command that caught the signal did not choose its own exit: ~S" result)
    (check (call-scute 'sandbox-result-timed-out result)
           "it was still stopped for time, and should say so")
    (check (< elapsed 4) "the trapped stop took ~,1Fs" elapsed)))

(deftest test-a-time-limit-needs-no-cgroup
  "A wall-clock limit is the supervisor's own clock, so asking for one must not
demand a delegated cgroup subtree that nothing would use."
  (let ((plan (call-scute 'plan-with-wall-clock
                          (call-scute 'compile-command-launch-plan '("/bin/true") '())
                          5)))
    (call-scute 'preflight plan)          ; signals if it wants a cgroup
    (check (eql 0 (call-scute 'sandbox-result-exit-code
                              (call-scute 'run-launch-plan plan)))
           "a plan with only a time limit would not run")))

;;; Getting a cgroup without being told to.
;;;
;;; The remedy Scute used to print -- systemd-run --user --scope -p Delegate=yes
;;; -- was something it could run itself, and a tool that needs a wrapper gets
;;; used without the wrapper. These are about when it decides to, which is the
;;; part that can go wrong quietly: too eager and every run spawns a scope, too
;;; shy and a policy silently gets weaker egress than it asked for.

(deftest test-limits-are-a-reason-to-make-a-scope
  "Memory and process caps are cgroup controls, and there is no other way."
  (let ((limits (call-scute 'make-resource-limits :memory (* 64 1024 1024))))
    (check (call-scute 'plan-wants-own-cgroup-p limits nil nil)
           "a memory limit did not ask for a cgroup")))

(deftest test-a-time-limit-is-not-a-reason-to-make-a-scope
  "The supervisor's own timer needs nothing from the kernel's accounting."
  (let ((limits (call-scute 'make-resource-limits :wall-clock 5)))
    (check (not (call-scute 'plan-wants-own-cgroup-p limits nil nil))
           "a wall-clock limit asked for a cgroup it would not use")))

(deftest test-a-proxy-is-a-reason-only-when-the-guard-could-be-attached
  "Pinning a proxy to its address is BPF on a cgroup, so it needs both halves.

Without the capability there is nothing to attach and a scope would buy nothing;
with it, a scope is the difference between port-level and address-level egress,
which is worth making without being asked."
  (check (call-scute 'plan-wants-own-cgroup-p nil "http://127.0.0.1:10210" t)
         "a proxy with the guard available did not ask for a cgroup")
  (check (not (call-scute 'plan-wants-own-cgroup-p nil "http://127.0.0.1:10210" nil))
         "a proxy asked for a cgroup that could not hold a guard anyway")
  (check (not (call-scute 'plan-wants-own-cgroup-p nil nil t))
         "a plan wanting nothing asked for a cgroup"))

(deftest test-a-scope-is-not-made-twice
  "Re-executing inside the scope we just made would be a fork bomb in a unit."
  (sb-posix:setenv scute::+own-scope-marker+ "1" 1)
  (unwind-protect
       (multiple-value-bind (possible reason) (call-scute 'own-scope-possible-p)
         (check (not possible) "a second scope would have been made")
         (check (search "already" reason)
                "the reason does not say it is already in one: ~S" reason))
    (sb-posix:unsetenv scute::+own-scope-marker+)))

(deftest test-a-scope-can-be-refused
  "Someone who would rather be refused than have a scope made for them."
  (sb-posix:setenv scute::+own-scope-opt-out+ "1" 1)
  (unwind-protect
       (multiple-value-bind (possible reason) (call-scute 'own-scope-possible-p)
         (check (not possible) "the opt-out was ignored")
         (check (search scute::+own-scope-opt-out+ reason)
                "the reason does not name the variable: ~S" reason))
    (sb-posix:unsetenv scute::+own-scope-opt-out+)))
