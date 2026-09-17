;;; main.lisp
;;;
;;; SPDX-License-Identifier: MIT
;;;
;;; Copyright (C) 2026 Your Name

(in-package #:scute)

(version-string:define-version-parameter +version+ :scute)

;;── CLI ────────────────────────────────────────────────────────────────────────

(defun make-app ()
  "Create and return the command-line application."
  (let ((n (clingon:make-option :flag :short-name #\n :long-name "dry-run" :key :dry-run
                                :description "Don't really do it.")))
    (clingon:make-command
     :name    "scute"
     :version +version+
     :description "A command-line tool"
     :authors (list "Your Name")
     :license "MIT"
     :usage ""
     :options (list n)
     :handler (lambda (cmd)
                (declare (ignore cmd)))
     :examples '(("Do nothing example:"
                  . "scute")
                 ("Do even less:"
                  . "scute -n")))))

(defun main ()
  "The main entrypoint."
  (handler-case
      (clingon:run (make-app))
    (error (e)
      (format *error-output* "Error: ~A~%" e)
      (uiop:quit 1))))
