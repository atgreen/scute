;;; doctor.lisp
;;;
;;; SPDX-License-Identifier: MIT
;;;
;;; Copyright (C) 2026 Anthony Green

(in-package #:scute)

;;; What this host can and cannot enforce.  Scute refuses to run with a control
;;; missing, so it owes the operator a way to ask why before they try.  Every
;;; probe here only reads, except the user-namespace probe, which launches
;;; /bin/true in a real sandbox: the honest way to answer "can this host do it"
;;; is to do it.

(defstruct (probe (:constructor make-probe (name status detail)))
  "One answered question about the host.  STATUS is :OK, :MISSING, or :INFO."
  (name   nil :read-only t)
  (status nil :read-only t)
  (detail nil :read-only t))

(defun probe-mandatory-p (probe)
  "Whether a missing PROBE stops Scute from running anything at all.
Resource limits and auditing are not here on purpose: Scute sandboxes perfectly
well without either, and a host that cannot provide them should be told what it
would need rather than failed."
  (member (probe-name probe)
          '("user namespaces" "landlock" "cgroup v2" "libseccomp")
          :test #'string=))

;;── Probes ─────────────────────────────────────────────────────────────────────

(defun probe-kernel ()
  (make-probe "kernel" :info (or (read-first-line "/proc/sys/kernel/osrelease")
                                 "unknown")))

(defun probe-capabilities ()
  (make-probe "capabilities" :info
              (format nil "cap_last_cap ~D, this process holds ~{~A~^ ~}"
                      (cap-last-cap)
                      (let ((held (remove-if (lambda (entry)
                                               (or (zerop (cdr entry))
                                                   (string= "CapBnd" (car entry))))
                                             (capability-sets))))
                        (if held
                            (mapcar (lambda (entry)
                                      (format nil "~A=~(~16,'0X~)" (car entry) (cdr entry)))
                                    held)
                            (list "none"))))))

(defun probe-user-namespaces ()
  "Launch /bin/true in a real sandbox.  Nothing else proves this host can."
  (handler-case
      (let ((result (run-namespaced-command '("/bin/true"))))
        (if (eql 0 (sandbox-result-exit-code result))
            (make-probe "user namespaces" :ok
                        "launched /bin/true in fresh user, mount, pid, uts, and net namespaces")
            (make-probe "user namespaces" :missing
                        (format nil "/bin/true ended unexpectedly: ~S" result))))
    (scute-error (condition)
      (make-probe "user namespaces" :missing (princ-to-string condition)))))

(defun probe-landlock ()
  (let ((version (landlock-abi-version)))
    (cond ((null version)
           (make-probe "landlock" :missing
                       "this kernel does not implement landlock_create_ruleset"))
          (t
           (make-probe "landlock" :ok
                       (format nil "ABI version ~D, ~D filesystem access rights handled~@[ (~A)~]"
                               version (logcount (supported-rights version))
                               (cond ((< version 2)
                                      "no REFER: cross-directory rename will fail")
                                     ((< version 3)
                                      "no TRUNCATE: truncation is not governed"))))))))

(defun probe-cgroup-v2 ()
  (handler-case
      (let ((directory (discover-cgroup2)))
        (make-probe "cgroup v2" :ok
                    (format nil "~A is delegated (controllers: ~A)" directory
                            (or (read-first-line
                                 (format nil "~A/cgroup.controllers" directory))
                                "none"))))
    (scute-error (condition)
      (make-probe "cgroup v2" :missing (princ-to-string condition)))))

(defun probe-resource-limits ()
  "Whether a policy asking for limits could be honoured here.  Not mandatory:
Scute sandboxes fine without limits, and refuses clearly when a policy wants
them on a host that cannot give them."
  (multiple-value-bind (installable root explanation) (limits-installable-p)
    (declare (ignore root))
    (cond (installable (make-probe "resource limits" :ok explanation))
          ;; Scute makes a cgroup of its own when a plan needs one, so the state
          ;; this shell happens to be in is not the answer to whether limits work
          ;; here -- and telling somebody to type systemd-run, which Scute now
          ;; types for itself, sends them to fix something that is not broken.
          ((own-scope-possible-p)
           (make-probe "resource limits" :ok
                       (format nil "this shell's cgroup cannot hand controllers ~
                                    to children, so Scute will make a scope of ~
                                    its own")))
          (t
           (multiple-value-bind (possible reason) (own-scope-possible-p)
             (declare (ignore possible))
             (make-probe "resource limits" :info
                         (format nil "~A, and Scute cannot make a scope of its ~
                                      own here (~A). ~A"
                                 explanation reason +delegation-remedy+)))))))

(defun probe-seccomp ()
  "Build the v0 filter to answer this, rather than only looking for the library:
a filter that will not compile here is a launch that will not happen."
  (handler-case
      (let ((filter (v0-seccomp-filter)))
        (make-probe "libseccomp" :ok
                    (format nil "~D syscalls denied in ~D instructions~@[, ~D not on this architecture~]"
                            (length (seccomp-filter-denied filter))
                            (seccomp-filter-instructions filter)
                            (let ((absent (length (seccomp-filter-unavailable filter))))
                              (and (plusp absent) absent)))))
    (scute-error (condition)
      (make-probe "libseccomp" :missing (princ-to-string condition)))))

(defun probe-default-network ()
  "Which form the default network takes here.

Worth reporting on its own: a policy that says nothing about the network is the
common case, and the difference between the two forms is the difference between a
client that cannot reach anywhere else and one that merely fails if it tries."
  (let ((mode (implicit-network-mode)))
    (if (string= "proxied" mode)
        (make-probe "default network" :ok
                    (format nil "through the broker, redirected in the kernel: a ~
                                 client that ignores the proxy variables arrives ~
                                 there anyway"))
        (make-probe "default network" :info
                    (format nil "through the broker, port-level: Landlock permits ~
                                 the broker's port and nothing else, so a client ~
                                 ignoring the proxy variables reaches nothing. For ~
                                 the kernel redirect, install the package or run ~
                                 make egress")))))

(defun probe-egress ()
  "Whether this host can enforce an address-level egress allowlist.
Optional, like limits: a policy that does not ask for one is unaffected."
  (multiple-value-bind (available reason) (egress-guard-available-p)
    (if available
        (make-probe "address egress" :ok "CAP_BPF and CAP_NET_ADMIN are held")
        (make-probe "address egress" :info reason))))

(defparameter +default-broker-control-port+ 10212
  "Where a credential broker answers control requests by its own default.")

(defun probe-broker ()
  "Whether the credential broker is there.

Required rather than optional: a policy that says nothing about the network goes
through the broker, so this is the difference between \"scute bash\" working and
refusing on most policies.  A sandbox asking for no network at all needs no broker,
which is the one case this is not fatal in -- so it is reported as missing rather
than failing, and the refusal at launch says the rest."
  (let ((certificate (probe-file (broker-certificate-path)))
        (installed (ignore-errors (resolve-executable "keyfence"))))
    (cond ((broker-answering-p +default-broker-control-port+)
           (make-probe "credential broker" :ok
                       (format nil "answering on ~D~:[; no CA certificate at ~A~;~]"
                               +default-broker-control-port+
                               certificate (broker-certificate-path))))
          (installed
           (make-probe "credential broker" :info
                       (format nil "installed at ~A but not running, so Scute will ~
                                    start one per run.  Better as a service: ~
                                    systemctl --user enable --now keyfence.socket ~
                                    keyfence-api.socket"
                               installed)))
          (t
           (make-probe "credential broker" :missing
                       (format nil "keyfence is not installed, and the default ~
                                    network goes through it: only policies with ~
                                    [network] mode = \"none\" will run. ~
                                    https://github.com/atgreen/keyfence"))))))

(defun probe-audit ()
  "What the host would offer an audit program, without loading one.
Auditing is optional in the design and absent from this build, so this reports
the kernel side only, and never as a failure."
  (let* ((btf (and (probe-file "/sys/kernel/btf/vmlinux") t))
         (unprivileged (read-first-line "/proc/sys/kernel/unprivileged_bpf_disabled"))
         (held (remove-if (lambda (entry)
                            (or (zerop (cdr entry)) (string= "CapBnd" (car entry))))
                          (capability-sets))))
    (make-probe "audit" :info
                (format nil "not installed by this build; kernel offers ~
                             BTF ~:[absent~;present~], unprivileged BPF ~A, ~
                             and this process holds ~:[no capabilities~;capabilities~]"
                        btf
                        (cond ((null unprivileged) "unreported")
                              ((string= "0" (string-trim " " unprivileged)) "allowed")
                              (t (format nil "disabled (~A)" (string-trim " " unprivileged))))
                        held))))

;;── Machine-readable ───────────────────────────────────────────────────────────

(defun write-json-string (text stream)
  "Write TEXT as a JSON string literal."
  (write-char #\" stream)
  (loop for character across text
        do (case character
             (#\" (write-string "\\\"" stream))
             (#\\ (write-string "\\\\" stream))
             (#\Newline (write-string "\\n" stream))
             (#\Tab (write-string "\\t" stream))
             (#\Return (write-string "\\r" stream))
             (t (if (< (char-code character) 32)
                    (format stream "\\u~4,'0X" (char-code character))
                    (write-char character stream)))))
  (write-char #\" stream))

(defun print-doctor-json (report &optional (stream *standard-output*))
  "Print REPORT as JSON, for something other than a person to read."
  (let ((missing (remove-if-not (lambda (probe)
                                  (and (eq :missing (probe-status probe))
                                       (probe-mandatory-p probe)))
                                report)))
    (format stream "{~%  \"ready\": ~:[false~;true~],~%  \"probes\": [~%"
            (null missing))
    (loop for probe in report
          for remaining = (rest (member probe report))
          do (format stream "    {\"name\": ")
             (write-json-string (probe-name probe) stream)
             (format stream ", \"status\": ")
             (write-json-string (string-downcase (probe-status probe)) stream)
             (format stream ", \"mandatory\": ~:[false~;true~], \"detail\": "
                     (probe-mandatory-p probe))
             (write-json-string (or (probe-detail probe) "") stream)
             (format stream "}~:[~;,~]~%" remaining))
    (format stream "  ]~%}~%")
    (null missing)))

;;── Report ─────────────────────────────────────────────────────────────────────

(defun doctor-report ()
  "Answer every host question Scute cares about, in reporting order."
  (list (probe-kernel)
        (probe-user-namespaces)
        (probe-landlock)
        (probe-cgroup-v2)
        (probe-resource-limits)
        (probe-egress)
        (probe-default-network)
        (probe-seccomp)
        (probe-broker)
        (probe-audit)
        (probe-capabilities)))

(defun print-doctor-report (report &optional (stream *standard-output*))
  "Print REPORT and answer whether every mandatory control is present."
  (let ((width (reduce #'max report :key (lambda (probe)
                                           (length (probe-name probe))))))
    (dolist (probe report)
      (format stream "~&~7A ~VA  ~A~%"
              (ecase (probe-status probe)
                (:ok "ok") (:missing "MISSING") (:info "--"))
              width (probe-name probe) (probe-detail probe))))
  (let ((missing (remove-if-not (lambda (probe)
                                  (and (eq :missing (probe-status probe))
                                       (probe-mandatory-p probe)))
                                report)))
    (when missing
      (format stream "~&~%~D mandatory control~:P missing: ~{~A~^, ~}.~%~
                      Scute will refuse to launch a sandbox on this host.~%"
              (length missing) (mapcar #'probe-name missing)))
    (null missing)))
