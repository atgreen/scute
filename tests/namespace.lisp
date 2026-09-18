;;; SPDX-License-Identifier: MIT
;;;
;;; The kernel boundary: namespaces, capabilities, supervision, exit status.

(in-package #:scute/tests)

(defparameter +namespaces+ '("user" "net" "pid" "mnt" "uts"))

;;── The kernel boundary ────────────────────────────────────────────────────────

(defun namespace-report-script (report)
  (format nil
          "exec > ~A~@
           printf 'pid=%s\\n' \"$$\"~@
           printf 'tasks='; find /proc/self/task -mindepth 1 -maxdepth 1 | wc -l~@
           for ns in ~{~A ~}; do printf '%s=' \"$ns\"; readlink /proc/self/ns/$ns; done~@
           printf 'routes='; tail -n +2 /proc/net/route | wc -l~@
           grep '^Cap' /proc/self/status~@
           exit 37~%"
          report +namespaces+))

(deftest test-namespace-boundary
  "The child is PID 1 of fresh namespaces, single-tasked, unrouted, and
stripped of every capability, and its exit status arrives intact."
  (let ((report (scratch-pathname "namespace")))
    (unwind-protect
         (progn
           (delete-scratch report)
           (let* ((result (call-scute 'run-namespaced-command
                                      (list "/bin/sh" "-c"
                                            (namespace-report-script report))))
                  (contents (read-file-string report)))
             (check (eql 37 (call-scute 'sandbox-result-exit-code result))
                    "expected exit 37, got ~S" result)
             (check (search "pid=1" contents) "command was not PID 1:~%~A" contents)
             (check (search "tasks=1" contents) "command had extra tasks:~%~A" contents)
             (check (search "routes=0" contents) "network namespace has routes:~%~A"
                    contents)
             (dolist (namespace +namespaces+)
               (let ((line (format nil "~A=~A" namespace
                                   (call-scute 'namespace-id namespace))))
                 (check (search (format nil "~A=~A:[" namespace namespace) contents)
                        "no ~A namespace was reported:~%~A" namespace contents)
                 (check (not (search line contents))
                        "~A namespace was shared with the host (~A)" namespace line)))
             (dolist (name '("CapBnd" "CapEff" "CapPrm" "CapInh" "CapAmb"))
               (check (search (format nil "~A:~C0000000000000000" name #\Tab)
                              contents)
                      "~A was not zero:~%~A" name contents))))
      (delete-scratch report))))

(deftest test-standard-streams
  "The command inherits the supervisor's own stdout and stderr."
  (let ((out (scratch-pathname "out"))
        (err (scratch-pathname "err"))
        (saved-out (sb-posix:dup 1))
        (saved-err (sb-posix:dup 2))
        (flags (logior sb-posix:o-wronly sb-posix:o-creat sb-posix:o-trunc))
        (result nil))
    (unwind-protect
         (let ((out-fd (sb-posix:open out flags #o600))
               (err-fd (sb-posix:open err flags #o600)))
           (finish-output *standard-output*)
           (finish-output *error-output*)
           (unwind-protect
                (progn
                  (sb-posix:dup2 out-fd 1)
                  (sb-posix:dup2 err-fd 2)
                  (setf result
                        (call-scute 'run-namespaced-command
                                    (list "/bin/sh" "-c"
                                          "printf 'to stdout\\n'; \
                                           printf 'to stderr\\n' >&2; exit 0"))))
             (sb-posix:dup2 saved-out 1)
             (sb-posix:dup2 saved-err 2)
             (sb-posix:close out-fd)
             (sb-posix:close err-fd)))
      (sb-posix:close saved-out)
      (sb-posix:close saved-err))
    (unwind-protect
         (progn
           (check (eql 0 (call-scute 'sandbox-result-exit-code result))
                  "expected exit 0, got ~S" result)
           (check (search "to stdout" (read-file-string out))
                  "stdout was not preserved")
           (check (search "to stderr" (read-file-string err))
                  "stderr was not preserved"))
      (delete-scratch out err))))

(defun spawn-signaller (ready pid)
  "Send PID SIGTERM once the sandboxed command creates READY.
Waiting on READY removes any race with the supervisor's signal handlers."
  (spawn-shell (format nil "while [ ! -e ~A ]; do sleep 0.05; done; kill -TERM ~D"
                       ready pid)))

(deftest test-signal-forwarding
  "SIGTERM sent to the supervisor reaches the sandboxed command, which is free
to trap it and choose its own exit status.

The guard handler matters: without one, a supervisor that forwarded nothing
would let SIGTERM kill this very process, and SBCL exits 0 for SIGTERM, so the
suite would go green having run no checks at all."
  (let* ((ready (scratch-pathname "ready"))
         (leaked nil)
         (guard (lambda (signal info context)
                  (declare (ignore signal info context))
                  (setf leaked t)))
         (previous (sb-sys:enable-interrupt sb-unix:sigterm guard))
         (result nil))
    (unwind-protect
         (progn
           (delete-scratch ready)
           (spawn-signaller ready (sb-posix:getpid))
           (setf result
                 (call-scute
                  'run-namespaced-command
                  (list "/bin/sh" "-c"
                        (format nil
                                "trap 'exit 42' TERM; : > ~A; ~
                                 i=0; while [ $i -lt 300 ]; do ~
                                   sleep 0.1; i=$((i+1)); done; exit 99"
                                ready))))
           (check (not leaked)
                  "SIGTERM was left with the caller's handler: the supervisor ~
                   installed none")
           (check (eql 42 (call-scute 'sandbox-result-exit-code result))
                  "SIGTERM was not forwarded to the command, got ~S" result)
           (check (null (call-scute 'sandbox-result-term-signal result))
                  "a trapped exit was misreported as a signal death, got ~S" result))
      (sb-sys:enable-interrupt sb-unix:sigterm (or previous :default))
      (delete-scratch ready))))

(defparameter +signal-death-marker+ "99999.5"
  "An argument no other process on the host is plausibly running.")

(deftest test-signal-death
  "A command killed by a signal is reported as a signal death, not an exit.
SIGKILL is the signal to use: it is the one an ancestor namespace can force on
a process that is PID 1 of its own."
  (let ((command (format nil "sleep ~A" +signal-death-marker+)))
    (spawn-shell (format nil "while ! pgrep -x -f '~A' >/dev/null; do sleep 0.05; done; ~
                              pkill -KILL -x -f '~A'"
                         command command))
    (let ((result (call-scute 'run-namespaced-command
                              (list "/bin/sh" "-c" (format nil "exec ~A" command)))))
      (check (eql 9 (call-scute 'sandbox-result-term-signal result))
             "expected death by SIGKILL, got ~S" result)
      (check (null (call-scute 'sandbox-result-exit-code result))
             "a signal death reported an exit code, got ~S" result)
      (check (eql 137 (call-scute 'command-exit-status result))
             "a SIGKILL death should exit 128+9, got ~S"
             (call-scute 'command-exit-status result)))))

(deftest test-orphan-is-killed
  "The sandbox dies with its supervisor: no orphan survives a killed parent."
  (let* ((marker "88888.5")
         (command (format nil "sleep ~A" marker))
         (pidfile (scratch-pathname "runner"))
         (runner (format nil
                         "sbcl --noinform --non-interactive ~
                          --eval '(asdf:load-system :scute)' ~
                          --eval '(scute:run-namespaced-command (list \"/bin/sh\" \"-c\" \"exec ~A\"))' ~
                          & echo $! > ~A"
                         command pidfile)))
    (unwind-protect
         (progn
           (delete-scratch pidfile)
           (spawn-shell runner)
           (check (wait-until (lambda () (probe-file pidfile)) 60)
                  "the supervisor under test never started")
           (check (wait-until (lambda () (process-matching-p command)) 60)
                  "the sandboxed command never started")
           (spawn-shell (format nil "kill -KILL $(cat ~A)" pidfile))
           (check (wait-until (lambda () (not (process-matching-p command))) 60)
                  "the sandbox outlived its killed supervisor")
           (unless (wait-until (lambda () (not (process-matching-p command))) 1)
             (spawn-shell (format nil "pkill -KILL -x -f '~A'" command))))
      (delete-scratch pidfile))))

(deftest test-exit-status-mapping
  "A command's own exit status is what Scute exits with."
  (dolist (code '(0 1 7 42))
    (let ((result (call-scute 'run-namespaced-command
                              (list "/bin/sh" "-c" (format nil "exit ~D" code)))))
      (check (eql code (call-scute 'command-exit-status result))
             "expected exit ~D, got ~S" code result))))

(deftest test-stop-escalates-when-ignored
  "A command that ignores a stop signal is stopped anyway.

The command is PID 1 of its namespace, and a signal from an ancestor namespace
reaches PID 1 only if it has a handler: this one installs an empty trap, so the
forwarded SIGTERM is discarded and nothing but SIGKILL will do."
  (let* ((ready (scratch-pathname "ignores-term"))
         (leaked nil)
         (guard (lambda (signal info context)
                  (declare (ignore signal info context))
                  (setf leaked t)))
         (previous (sb-sys:enable-interrupt sb-unix:sigterm guard))
         (scute:*stop-grace-seconds* 1/5)
         (result nil))
    (unwind-protect
         (progn
           (delete-scratch ready)
           (spawn-signaller ready (sb-posix:getpid))
           (setf result
                 (call-scute 'run-namespaced-command
                             (list "/bin/sh" "-c"
                                   (format nil "trap '' TERM; : > ~A; ~
                                                i=0; while [ $i -lt 300 ]; do ~
                                                  sleep 0.1; i=$((i+1)); done; exit 99"
                                           ready))))
           (check (not leaked)
                  "SIGTERM was left with the caller's handler: the supervisor ~
                   installed none")
           (check (eql 9 (call-scute 'sandbox-result-term-signal result))
                  "a command ignoring SIGTERM was not killed, got ~S" result))
      (sb-sys:enable-interrupt sb-unix:sigterm (or previous :default))
      (delete-scratch ready))))

(deftest test-fail-closed-launch
  "A command Scute cannot resolve is refused before any namespace is created.
It is the caller's mistake rather than the host's, so it reads as one."
  (let ((condition (nth-value 1 (ignore-errors
                                 (call-scute 'run-namespaced-command '("sh"))))))
    (check (typep condition 'scute:usage-error)
           "a relative command was not refused, got ~S" condition)))
