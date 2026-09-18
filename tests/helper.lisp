;;; SPDX-License-Identifier: MIT
;;;
;;; A process running beside the sandbox: started, waited for, and stopped.

(in-package #:scute/tests)

(defparameter +helper-port+ 18642
  "A port nothing else on a developer machine is likely to want.")

(defun write-listener-script (port)
  "A script that listens on PORT until it is killed."
  (let ((path (format nil "~A.sh" (scratch-pathname "listener"))))
    (with-open-file (stream path :direction :output :if-exists :supersede)
      (format stream "#!/bin/sh~%exec /usr/bin/python3 -c \"~
import socket,time~%~
s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)~%~
s.bind(('127.0.0.1',~D));s.listen(5)~%~
time.sleep(120)\"~%" port))
    (sb-posix:chmod path #o755)
    path))

(deftest test-a-helper-is-started-waited-for-and-stopped
  "The case this exists for is a credential proxy: it has to be up before the
sandbox runs and gone after, and neither should be the operator's job."
  (if (plusp (cffi:foreign-funcall "system" :string
                                  "command -v python3 >/dev/null 2>&1" :int))
      (format *error-output* "~&SKIP: no python3 to stand in for a proxy~%")
      (let ((script (write-listener-script +helper-port+))
            (helper nil))
        (unwind-protect
             (progn
               (check (not (call-scute 'wait-for-port +helper-port+ 1/10))
                      "something is already listening on ~D" +helper-port+)
               (setf helper (call-scute 'start-helper script))
               (check (call-scute 'helper-running-p helper) "the helper did not start")
               (check (call-scute 'wait-for-port +helper-port+ 10)
                      "the helper never answered on ~D" +helper-port+)
               (call-scute 'stop-helper helper)
               (setf helper nil)
               (check (not (call-scute 'wait-for-port +helper-port+ 1/2))
                      "the helper is still listening after being stopped"))
          (when helper (ignore-errors (call-scute 'stop-helper helper)))
          (delete-scratch script)))))

(deftest test-the-sandbox-can-reach-its-helper-and-nothing-else
  "The whole point: the command reaches the helper's port because the policy
names it, and cannot reach anything else because the kernel says so."
  (if (plusp (cffi:foreign-funcall "system" :string
                                  "command -v python3 >/dev/null 2>&1" :int))
      (format *error-output* "~&SKIP: no python3 to stand in for a proxy~%")
      (let ((script (write-listener-script (1+ +helper-port+)))
            (helper nil))
        (unwind-protect
             (progn
               (setf helper (call-scute 'start-helper script))
               (check (call-scute 'wait-for-port (1+ +helper-port+) 10)
                      "the helper never came up")
               (let* ((policy (policy-from-string
                               (format nil "[filesystem]~%~
                                            read-execute = [\"/usr\"]~%~
                                            read = [\"/etc\"]~%~
                                            [network]~%mode = \"host\"~%~
                                            proxy = \"http://127.0.0.1:~D\"~%"
                                       (1+ +helper-port+))))
                      (reach (lambda (port)
                               (call-scute 'sandbox-result-exit-code
                                           (call-scute 'run-launch-plan
                                                       (call-scute 'compile-launch-plan
                                                                   policy
                                                                   (list "/usr/bin/bash" "-c"
                                                                         (format nil "exec 3<>/dev/tcp/127.0.0.1/~D" port))))))))
                 (check (eql 0 (funcall reach (1+ +helper-port+)))
                        "the command could not reach the helper the policy names")
                 (check (not (eql 0 (funcall reach 22)))
                        "the command reached a port the policy does not name")))
          (when helper (ignore-errors (call-scute 'stop-helper helper)))
          (delete-scratch script)))))

(deftest test-a-helper-command-can-carry-quoted-arguments
  "--with takes a command line, and a command line has quoting in it.  Splitting
on spaces alone meant anything with a space in an argument needed a wrapper
script; this understands what anyone would type, and nothing more than that."
  (let ((cases
          '(("keyfence" ("keyfence"))
            ("keyfence -api-key-file /run/secrets/api-key"
             ("keyfence" "-api-key-file" "/run/secrets/api-key"))
            ("proxy --label 'my agent'" ("proxy" "--label" "my agent"))
            ("proxy --label \"my agent\"" ("proxy" "--label" "my agent"))
            ("proxy --path /a\\ b" ("proxy" "--path" "/a b"))
            ("  spaced   out  " ("spaced" "out"))
            ("echo ''" ("echo" ""))
            ("say \"it's fine\"" ("say" "it's fine"))
            ("say 'a \"quoted\" word'" ("say" "a \"quoted\" word")))))
    (dolist (case cases)
      (destructuring-bind (text expected) case
        (let ((got (call-scute 'split-command text)))
          (check (equal got expected)
                 "~S split into ~S, expected ~S" text got expected))))))
