;;; SPDX-License-Identifier: MIT
;;;
;;; The supervisor as a whole: every layer at once, and nothing left behind when
;;; a launch fails.  The other files test one layer each; this one tests that
;;; they assemble.

(in-package #:scute/tests)

(defun count-open-fds ()
  (length (directory "/proc/self/fd/*")))

(defun unreaped-child ()
  "A child of this process waiting to be collected, or NIL.
waitpid over any child answers -1 when there is nothing left, which is what a
supervisor that reaps what it creates should leave behind."
  (let ((pid (scute::%waitpid -1 (cffi:null-pointer) 1))) ; WNOHANG
    (and (plusp pid) pid)))

(deftest test-every-layer-at-once
  "One policy file, one command, every control at once: fresh namespaces, no
capabilities, no_new_privs, a seccomp filter, a Landlock ruleset, and a cgroup
carrying limits.  Each layer has its own tests; this is the one that would
notice them failing to assemble."
  (with-own-cgroup (root)
    (let* ((workspace (scratch-pathname "supervisor"))
           (report (format nil "~A/report" workspace))
           (pathname nil))
      (unwind-protect
           (progn
             (ensure-directories-exist (format nil "~A/" workspace))
             (setf pathname
                   (write-policy
                    (format nil "[filesystem]~%~
                                 read-execute = [\"/usr\"]~%~
                                 read = [\"/proc\", \"/sys\"]~%~
                                 read-write = [\"~A\", \"/dev/null\"]~%~
                                 [network]~%mode = \"none\"~%~
                                 [limits]~%memory = \"256M\"~%processes = 16~%~
                                 cpu-percent = 100~%"
                            workspace)))
             (let* ((plan (call-scute 'compile-launch-plan
                                      (call-scute 'read-sandbox-policy pathname)
                                      (list "/bin/sh" "-c"
                                            (format nil
                                                    "exec > ~A 2>&1~%~
                                                     printf 'pid=%s\\n' \"$$\"~%~
                                                     printf 'routes='; tail -n +2 /proc/net/route | wc -l~%~
                                                     grep -E '^(CapEff|CapBnd|Seccomp|NoNewPrivs):' /proc/self/status~%~
                                                     cg=/sys/fs/cgroup$(cut -d: -f3 /proc/self/cgroup)~%~
                                                     printf 'cgroup=%s\\n' \"$(basename $cg)\"~%~
                                                     printf 'memory=%s pids=%s\\n' \"$(cat $cg/memory.max)\" \"$(cat $cg/pids.max)\"~%~
                                                     echo written > ~A/witness && echo 'wrote=yes'~%~
                                                     if cat /etc/hostname > /dev/null 2>&1; then echo 'etc=readable'; else echo 'etc=denied'; fi~%~
                                                     exit 23"
                                                    report workspace))))
                    (result (call-scute 'run-launch-plan plan))
                    (said (read-file-string report)))
               (check (eql 23 (call-scute 'sandbox-result-exit-code result))
                      "exit status was not preserved: ~S" result)
               (dolist (expected (list "pid=1" "routes=0" "wrote=yes" "etc=denied"
                                       "cgroup=scute."
                                       (format nil "CapEff:~C0000000000000000" #\Tab)
                                       (format nil "CapBnd:~C0000000000000000" #\Tab)
                                       (format nil "Seccomp:~C2" #\Tab)
                                       (format nil "NoNewPrivs:~C1" #\Tab)
                                       "memory=268435456 pids=16"))
                 (check (search expected said)
                        "~S is missing from what the sandbox reported:~%~A"
                        expected said))))
        (ignore-errors (delete-file pathname))
        (dolist (name '("report" "witness"))
          (ignore-errors (delete-file (format nil "~A/~A" workspace name))))
        (ignore-errors (sb-posix:rmdir workspace))))))

(deftest test-nothing-is-left-behind-when-a-launch-fails
  "Every way a launch can fail leaves the supervisor as it was: no descriptors,
no unreaped children, and no cgroup."
  (check (null (unreaped-child)) "a child was already waiting to be reaped")
  (let ((before (count-open-fds)))
    (dolist (attempt (list
                      ;; refused before anything is created
                      (lambda () (call-scute 'run-namespaced-command '("relative/path")))
                      ;; a rule naming something that is not there
                      (lambda () (call-scute 'run-namespaced-command '("/bin/true")
                                             :filesystem '((:read "/no/such/path"))))
                      ;; refused by preflight, where limits cannot be installed
                      (lambda () (run-limited '("/bin/true") "processes = 8"))
                      ;; the child is created, and cannot become the command
                      (lambda () (call-scute 'run-namespaced-command
                                             '("/nonexistent/command")))))
      (ignore-errors (funcall attempt)))
    (check (= before (count-open-fds))
           "descriptors leaked: ~D before, ~D after" before (count-open-fds))
    (check (null (unreaped-child)) "a failed launch left a child unreaped"))
  ;; And the same where a cgroup was created first: the child exists, then fails
  ;; to become the command.
  (with-own-cgroup (root)
    (let ((before (count-open-fds)))
      (ignore-errors (run-limited '("/nonexistent/command") "processes = 8"))
      (check (null (sandbox-cgroup-names root))
             "a cgroup survived a child that could not exec: ~S"
             (sandbox-cgroup-names root))
      (check (= before (count-open-fds))
             "descriptors leaked around a cgroup: ~D before, ~D after"
             before (count-open-fds))
      (check (null (unreaped-child)) "a failed launch left a child unreaped"))))

(deftest test-preflight-gates-the-launch
  "Preflight asks for everything before acquiring anything, and names what is
missing.  A plan this host can carry out passes it."
  (call-scute 'preflight
              (call-scute 'compile-launch-plan
                          (policy-from-string "[filesystem]
read-execute = [\"/usr\"]")
                          '("/bin/true")))                  ; signals if refused
  (check (call-scute 'user-namespaces-available-p)
         "this host cannot create user namespaces, yet the suite has been ~
          creating them")
  (multiple-value-bind (installable) (call-scute 'limits-installable-p)
    (unless installable
      (let ((condition (nth-value 1 (ignore-errors
                                     (call-scute 'preflight
                                                 (call-scute 'compile-launch-plan
                                                             (limited-policy "processes = 8")
                                                             '("/bin/true")))))))
        (check (typep condition 'scute:sandbox-setup-error)
               "preflight passed a plan this host cannot carry out: ~S" condition)
        (check (eq :preflight
                   (scute:sandbox-setup-error-operation condition))
               "the refusal did not come from preflight: ~S" condition)
        (check (search "systemd-run" (princ-to-string condition))
               "the refusal does not say what to do about it: ~A" condition)))))
