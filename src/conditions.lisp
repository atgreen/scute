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

(define-condition usage-error (scute-error)
  ((detail :initarg :detail :reader usage-error-detail))
  (:report (lambda (condition stream)
             (write-string (usage-error-detail condition) stream)))
  (:documentation "The command line asked for something Scute cannot do."))

(define-condition policy-error (scute-error)
  ((pathname :initarg :pathname :reader policy-error-pathname :initform nil)
   (detail   :initarg :detail   :reader policy-error-detail))
  (:report
   (lambda (condition stream)
     (format stream "~@[~A: ~]~A"
             (policy-error-pathname condition)
             (policy-error-detail condition))))
  (:documentation "A policy could not be read, or did not say something Scute
recognizes.  Policies are refused whole: Scute does not enforce the half of a
policy it understood."))

(define-condition control-not-implemented (scute-error)
  ((control :initarg :control :reader control-not-implemented-control)
   (detail  :initarg :detail  :reader control-not-implemented-detail
            :initform nil))
  (:report
   (lambda (condition stream)
     (format stream "This build cannot enforce ~A~@[: ~A~]"
             (control-not-implemented-control condition)
             (control-not-implemented-detail condition))))
  (:documentation "The policy asked for a control that exists in the design but
not yet in this build.  Silently skipping it would hand back a sandbox weaker
than the one asked for."))

(define-condition command-not-found (scute-error)
  ((pathname :initarg :pathname :reader command-not-found-pathname))
  (:report
   (lambda (condition stream)
     (format stream "command not found: ~A"
             (command-not-found-pathname condition))))
  (:documentation "The command named does not exist, found before anything was
created rather than as a failed exec."))

(define-condition child-failure (scute-error)
  ((operation :initarg :operation :reader child-failure-operation)
   (status    :initarg :status    :reader child-failure-status :initform nil)
   (errno     :initarg :errno     :reader child-failure-errno :initform nil)
   ;; Said by whoever signals this when the errno alone would mislead.  An exec
   ;; refused with EPERM is the one that does: the file carries capabilities and
   ;; the sandbox has an empty bounding set, which reads as a permission problem
   ;; with the path and is nothing of the sort.
   (detail    :initarg :detail    :reader child-failure-detail :initform nil))
  (:report
   (lambda (condition stream)
     (format stream "the sandboxed child failed during ~(~A~)~@[: ~A~]~@[. ~A~]"
             (child-failure-operation condition)
             (let ((errno (child-failure-errno condition)))
               (and errno (plusp errno) (strerror errno)))
             (child-failure-detail condition))))
  (:documentation "The child died before it could become the requested command.
It reports the stage it failed at and its errno over its status pipe, so the
supervisor can say why rather than only that."))

(defun usage-error (detail)
  "Signal a USAGE-ERROR carrying DETAIL."
  (error 'usage-error :detail detail))

(defun policy-error (detail &optional pathname)
  "Signal a POLICY-ERROR carrying DETAIL."
  (error 'policy-error :detail detail :pathname pathname))

(defun setup-error (operation &key errno detail)
  "Signal a SANDBOX-SETUP-ERROR for OPERATION."
  (error 'sandbox-setup-error :operation operation :errno errno :detail detail))
