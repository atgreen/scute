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
  "Whether a missing PROBE stops Scute from running anything at all."
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
    (make-probe "resource limits" (if installable :ok :info)
                (if installable
                    explanation
                    (format nil "~A; run under a cgroup of its own, e.g. ~
                                 systemd-run --user --scope -p Delegate=yes"
                            explanation)))))

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

;;── Report ─────────────────────────────────────────────────────────────────────

(defun doctor-report ()
  "Answer every host question Scute cares about, in reporting order."
  (list (probe-kernel)
        (probe-user-namespaces)
        (probe-landlock)
        (probe-cgroup-v2)
        (probe-resource-limits)
        (probe-seccomp)
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
