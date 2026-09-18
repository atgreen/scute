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
           #:command-not-found
           #:command-not-found-pathname
           #:child-failure
           #:child-failure-operation
           #:child-failure-errno
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
           #:path-access-report
           #:run-launch-plan
           #:preflight
           #:user-namespaces-available-p
           #:*stop-grace-seconds*
           ;; The kernel boundary
           #:run-namespaced-command
           #:sandbox-result
           #:sandbox-result-p
           #:sandbox-result-pid
           #:sandbox-result-exit-code
           #:sandbox-result-term-signal
           #:sandbox-result-events
           #:sandbox-result-oom-killed-p
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
           ;; Resource limits
           #:discover-cgroup2
           #:delegated-root
           #:create-sandbox-cgroup
           #:move-process-to-cgroup
           #:read-cgroup-events
           #:delete-sandbox-cgroup
           #:limits-installable-p
           ;; Learning
           #:learned-rules
           #:write-learned-policy
           #:observations
           #:observations-paths
           #:watched-syscall
           ;; Host diagnostics
           #:doctor-report
           #:print-doctor-report
           #:print-doctor-json
           #:probe
           #:probe-name
           #:probe-status
           #:probe-detail
           #:command-exit-status))

(in-package #:scute)
