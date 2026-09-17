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

(defun run-tests ()
  (setf *failures* 0 *ran* 0)
  (mapc #'run-test (reverse *tests*))
  (when (plusp *failures*)
    (error "~D Scute test~:P failed" *failures*))
  (format t "~D Scute test~:P passed.~%" *ran*)
  t)
