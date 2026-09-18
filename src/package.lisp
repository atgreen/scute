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
           #:sandbox-policy-environment
           #:kept-environment
           #:launch-plan-environment
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
           #:call-with-helper
           #:start-helper
           #:stop-helper
           #:helper-pid
           #:helper-running-p
           #:wait-for-port
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
           #:sandbox-result-timed-out
           #:resource-limits-wall-clock
           #:plan-with-wall-clock
           #:revised-launch-plan
           #:launch-plan-unix-sockets
           #:launch-plan-connect-tcp
           #:launch-plan-bind-tcp
           #:sandbox-policy-proxy
           #:launch-plan-proxy
           #:launch-plan-allow
           #:sandbox-policy-allow
           #:endpoint-key
           #:endpoint-host
           #:endpoint-port
           #:endpoint-address
           #:parse-endpoint
           #:proxy-url-host
           #:plan-with-proxy-bound-by-address
           #:proxy-address-bindable-p
           #:compile-egress-guard
           #:egress-guard-available-p
           #:sandbox-policy-connect-tcp
           #:sandbox-policy-bind-tcp
           #:sandbox-policy-unix-sockets
           #:parse-duration
           #:capability-sets
           #:verify-no-capabilities
           #:make-dumpable
           #:catches-signal-p
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
           #:merge-learned-rules
           #:refused-observations
           #:report-refusals
           #:refusal-rules
           #:write-audit-trail
           #:reachable-path-p
           #:observations
           #:observations-paths
           #:observations-unix-sockets
           #:*learned-unix-sockets*
           #:*learned-connections*
           #:observations-connections
           #:watched-syscall
           ;; Credential brokering
           #:credential-request
           #:make-credential-request
           #:credential-request-name
           #:credential-request-secret-file
           #:credential-request-reference
           #:credential-request-destinations
           #:credential-request-variable
           #:credential-request-ttl
           #:broker-settings
           #:make-broker-settings
           #:broker-settings-name
           #:broker-settings-proxy-port
           #:broker-settings-control-port
           #:launch-plan-broker
           #:launch-plan-credentials
           #:call-with-broker
           #:start-broker
           #:stop-broker
           #:mint-token
           #:revoke-tokens
           #:broker-certificate
           #:broker-certificate-path
           #:broker-answering-p
           #:broker-helper
           #:broker-environment
           #:broker-tokens
           #:broker-error
           #:read-secret
           #:plan-with-broker
           #:loopback-request
           #:http-response-status
           #:http-response-body
           #:json-string-field
           #:json-escape
           #:expand-home
           ;; Shell completions
           #:write-completions
           #:command-tree
           #:write-manual-page
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
