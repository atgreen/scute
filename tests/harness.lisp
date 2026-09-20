;;; SPDX-License-Identifier: MIT

(in-package #:scute/tests)

;;; A test names itself with DEFTEST and is run in definition order.  Tests
;;; reach Scute through CALL-SCUTE, by name, so that a suite written before its
;;; subject compiles and says which function is missing.

(defvar *tests* '() "Registered tests, most recently defined first.")
(defvar *failures* 0)
(defvar *ran* 0)

(defmacro deftest (name &body body)
  `(progn
     (defun ,name () ,@body)
     (pushnew ',name *tests*)
     ',name))

(defun check (truth format-control &rest format-arguments)
  (unless truth
    (incf *failures*)
    (format *error-output* "FAIL: ~?~%" format-control format-arguments)))

(defun scute-function (name)
  (let ((symbol (find-symbol (string name) '#:scute)))
    (unless (and symbol (fboundp symbol))
      (error "Scute function ~A is not implemented" name))
    (symbol-function symbol)))

(defun call-scute (name &rest arguments)
  (apply (scute-function name) arguments))

(defun read-file-string (pathname)
  (with-open-file (stream pathname :direction :input)
    (let ((contents (make-string (file-length stream))))
      (subseq contents 0 (read-sequence contents stream)))))

(defun scute-value (name)
  "The value of a Scute variable, as call-scute is for its functions."
  (symbol-value (or (find-symbol (string name) '#:scute)
                    (error "Scute variable ~A is not there" name))))

(defun scratch-pathname (purpose)
  (format nil "/tmp/scute-test-~A-~D" purpose (sb-posix:getpid)))

(defun delete-scratch (&rest pathnames)
  (dolist (pathname pathnames)
    (ignore-errors (delete-file pathname))))

(defun spawn-shell (command)
  "Run COMMAND in a detached /bin/sh.
system(3) keeps helper processes out of SBCL's own process machinery, which
must stay clear of the supervisor's own wait and signal handling."
  (cffi:foreign-funcall "system" :string
                        (format nil "( ~A ) >/dev/null 2>&1 &" command)
                        :int))

(defun wait-until (predicate deciseconds)
  "Poll PREDICATE every tenth of a second until it holds or the budget runs out."
  (loop repeat deciseconds
        thereis (funcall predicate)
        do (sleep 1/10)))

(defun process-matching-p (command)
  "Whether any process on the host is running exactly COMMAND."
  (zerop (cffi:foreign-funcall
          "system" :string (format nil "pgrep -x -f '~A' >/dev/null 2>&1" command)
          :int)))

(defun run-test (name)
  (incf *ran*)
  (handler-case (funcall name)
    (error (condition)
      (incf *failures*)
      (format *error-output* "FAIL: ~A signalled ~A~%" name condition))))

(defparameter +completion-sentinel+ ".test-passed"
  "Written only when the whole suite has run and passed.

make checks for this file rather than trusting an exit status.  SBCL exits 0
when SIGTERM reaches it with the default disposition, so a test that lets a
signal through would otherwise abort the suite and still report success -- and
a suite that can pass without running is worse than no suite.")

(defun call-with-quiet-stdin (function)
  "Run FUNCTION with standard input on /dev/null.

Not tidiness: bash decides it was started by a remote shell daemon when its
standard input is a socket, and then sources ~/.bashrc even non-interactively.
A suite run from a harness whose stdin is a socket would therefore watch a shell
drag in the developer's dotfiles, and what a sandbox needs would depend on who
ran the tests."
  (let ((saved (sb-posix:dup 0))
        (null (sb-posix:open "/dev/null" sb-posix:o-rdonly)))
    (unwind-protect
         (progn (sb-posix:dup2 null 0)
                (funcall function))
      (sb-posix:dup2 saved 0)
      (sb-posix:close null)
      (sb-posix:close saved))))

(defun run-tests ()
  (call-with-quiet-stdin #'run-tests-now))

(defun run-tests-now ()
  (ignore-errors (delete-file +completion-sentinel+))
  (setf *failures* 0 *ran* 0)
  ;; What a policy silent about the network means depends on whether this host
  ;; can attach a BPF guard, which is a property of the machine the suite is run
  ;; on and not of anything being tested.  Pinned, so that the same policy text
  ;; means the same thing on a developer's build and on a packaged one; the tests
  ;; that are about the choice itself bind it themselves.
  (setf (symbol-value (or (find-symbol "*IMPLICIT-NETWORK-MODE*" '#:scute)
                          (error "Scute has no *implicit-network-mode*")))
        "host")
  (mapc #'run-test (reverse *tests*))
  (when (plusp *failures*)
    (error "~D Scute test~:P failed" *failures*))
  (when (zerop *ran*)
    (error "no Scute tests ran at all"))
  (with-open-file (stream +completion-sentinel+ :direction :output
                                                :if-exists :supersede)
    (format stream "~D~%" *ran*))
  (format t "~D Scute test~:P passed.~%" *ran*)
  t)

(defun unix-isolation-available-or-refused-p ()
  "On older kernels, prove the launch fails closed instead of skipping the check."
  (if (>= (or (call-scute 'landlock-abi-version) 0) 9)
      t
      (let ((refusal (nth-value 1 (ignore-errors
                                   (call-scute 'acquire-launch-resources
                                               (call-scute 'compile-command-launch-plan '("/bin/true") nil)
                                               :observe :learn)))))
        (check (and refusal (search "landlock-unix" (string-downcase (princ-to-string refusal))))
               "older kernel did not refuse Unix-enabled learning safely: ~S" refusal)
        nil)))
