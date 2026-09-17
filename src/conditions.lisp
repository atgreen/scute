;;; conditions.lisp
;;;
;;; SPDX-License-Identifier: MIT
;;;
;;; Copyright (C) 2026 Anthony Green

(in-package #:scute)

;;── Conditions ─────────────────────────────────────────────────────────────────
;;
;;; Scute is fail-closed: every control it is asked to install either succeeds
;;; or the launch aborts with one of these conditions.  Nothing degrades
;;; silently into a weaker sandbox.

(defun strerror (errno)
  "A human-readable name for ERRNO.  Lives here because condition reports are
its only caller."
  (cffi:foreign-funcall "strerror" :int errno :string))

(define-condition scute-error (error)
  ()
  (:documentation "Base class for every error Scute reports."))

(define-condition sandbox-setup-error (scute-error)
  ((operation :initarg :operation :reader sandbox-setup-error-operation
              :documentation "A keyword naming the step that failed.")
   (errno     :initarg :errno     :reader sandbox-setup-error-errno
              :initform nil
              :documentation "The errno value, when the step was a syscall.")
   (detail    :initarg :detail    :reader sandbox-setup-error-detail
              :initform nil
              :documentation "A human-readable note, when there is one."))
  (:report
   (lambda (condition stream)
     (format stream "Sandbox setup failed at ~(~A~)~@[: ~A~]~@[ (~A)~]"
             (sandbox-setup-error-operation condition)
             (sandbox-setup-error-detail condition)
             (let ((errno (sandbox-setup-error-errno condition)))
               (and errno (strerror errno))))))
  (:documentation "A mandatory sandbox control could not be established."))

(define-condition child-failure (scute-error)
  ((operation :initarg :operation :reader child-failure-operation)
   (status    :initarg :status    :reader child-failure-status :initform nil))
  (:report
   (lambda (condition stream)
     (format stream "Sandboxed child failed during ~(~A~)~@[ (wait status ~D)~]"
             (child-failure-operation condition)
             (child-failure-status condition))))
  (:documentation "The child died before it could become the requested command."))

(defun setup-error (operation &key errno detail)
  "Signal a SANDBOX-SETUP-ERROR for OPERATION."
  (error 'sandbox-setup-error :operation operation :errno errno :detail detail))
