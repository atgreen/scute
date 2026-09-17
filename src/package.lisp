;;; package.lisp
;;;
;;; SPDX-License-Identifier: MIT
;;;
;;; Copyright (C) 2026 Anthony Green

(defpackage #:scute
  (:use #:cl)
  (:documentation "A deny-by-default native sandbox for one local command.")
  (:export #:main
           ;; Conditions
           #:scute-error
           #:sandbox-setup-error
           #:sandbox-setup-error-operation
           #:sandbox-setup-error-errno
           #:sandbox-setup-error-detail
           #:usage-error
           #:usage-error-detail
           #:child-failure
           #:child-failure-operation
           ;; The kernel boundary
           #:run-namespaced-command
           #:sandbox-result
           #:sandbox-result-p
           #:sandbox-result-pid
           #:sandbox-result-exit-code
           #:sandbox-result-term-signal
           #:capability-sets
           #:namespace-id
           ;; Host diagnostics
           #:doctor-report
           #:print-doctor-report
           #:probe
           #:probe-name
           #:probe-status
           #:probe-detail
           #:command-exit-status))

(in-package #:scute)
