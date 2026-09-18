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
           #:policy-error
           #:policy-error-detail
           #:policy-error-pathname
           #:control-not-implemented
           #:control-not-implemented-control
           #:child-failure
           #:child-failure-operation
           ;; Policies and plans
           #:read-sandbox-policy
           #:validate-sandbox-policy
           #:sandbox-policy
           #:sandbox-policy-filesystem
           #:sandbox-policy-network
           #:sandbox-policy-limits
           #:sandbox-policy-audit
           #:filesystem-rule
           #:filesystem-rule-kind
           #:filesystem-rule-path
           #:resource-limits
           #:resource-limits-memory
           #:resource-limits-processes
           #:resource-limits-cpu-percent
           #:audit-policy
           #:audit-policy-events
           #:compile-launch-plan
           #:print-launch-plan
           #:launch-plan
           #:launch-plan-command
           #:launch-plan-directory
           #:launch-plan-filesystem
           #:launch-plan-limits
           #:launch-plan-audit
           #:path-rule
           #:path-rule-kind
           #:path-rule-path
           #:run-launch-plan
           ;; The kernel boundary
           #:run-namespaced-command
           #:sandbox-result
           #:sandbox-result-p
           #:sandbox-result-pid
           #:sandbox-result-exit-code
           #:sandbox-result-term-signal
           #:capability-sets
           #:verify-no-capabilities
           #:namespace-id
           ;; The system-call filter
           #:v0-seccomp-filter
           #:seccomp-filter
           #:seccomp-filter-denied
           #:seccomp-filter-unavailable
           #:seccomp-filter-instructions
           #:denied-syscall-names
           ;; Host diagnostics
           #:doctor-report
           #:print-doctor-report
           #:probe
           #:probe-name
           #:probe-status
           #:probe-detail
           #:command-exit-status))

(in-package #:scute)
