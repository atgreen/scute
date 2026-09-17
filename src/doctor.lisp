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
          '("user namespaces" "landlock" "landrun" "cgroup v2" "libseccomp")
          :test #'string=))

(defun read-first-line (pathname)
  (with-open-file (stream pathname :direction :input :if-does-not-exist nil)
    (and stream (read-line stream nil nil))))

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
    (if version
        (make-probe "landlock" :ok (format nil "ABI version ~D" version))
        (make-probe "landlock" :missing
                    "this kernel does not implement landlock_create_ruleset"))))

(defun split-path (path)
  (when path
    (loop with start = 0
          for colon = (position #\: path :start start)
          collect (subseq path start colon)
          while colon
          do (setf start (1+ colon)))))

(defun probe-landrun ()
  (let ((path (find-if (lambda (directory)
                         (zerop (%access (format nil "~A/landrun" directory) +x-ok+)))
                       (split-path (sb-posix:getenv "PATH")))))
    (if path
        (make-probe "landrun" :ok (format nil "~A/landrun" path))
        (make-probe "landrun" :missing "not found on PATH"))))

(defun own-cgroup ()
  "The caller's cgroup-v2 path, as /proc reports it."
  (let ((line (read-first-line "/proc/self/cgroup")))
    (when (and line (eql 0 (search "0::" line)))
      (subseq line 3))))

(defun probe-cgroup-v2 ()
  (let ((cgroup (own-cgroup)))
    (cond ((null cgroup)
           (make-probe "cgroup v2" :missing "no unified hierarchy in /proc/self/cgroup"))
          ((not (probe-file "/sys/fs/cgroup/cgroup.controllers"))
           (make-probe "cgroup v2" :missing "/sys/fs/cgroup is not a cgroup-v2 mount"))
          (t
           (let ((directory (format nil "/sys/fs/cgroup~A" cgroup)))
             (if (zerop (%access directory +w-ok+))
                 (make-probe "cgroup v2" :ok
                             (format nil "~A is delegated (controllers: ~A)" directory
                                     (or (read-first-line
                                          (format nil "~A/cgroup.controllers" directory))
                                         "none")))
                 (make-probe "cgroup v2" :missing
                             (format nil "~A is not writable: no delegated subtree"
                                     directory))))))))

(defun probe-seccomp ()
  (if (library-loadable-p "libseccomp.so.2")
      (make-probe "libseccomp" :ok
                  (format nil "libseccomp.so.2, kernel actions: ~A"
                          (or (read-first-line "/proc/sys/kernel/seccomp/actions_avail")
                              "unreported")))
      (make-probe "libseccomp" :missing "libseccomp.so.2 could not be loaded")))

;;── Report ─────────────────────────────────────────────────────────────────────

(defun doctor-report ()
  "Answer every host question Scute cares about, in reporting order."
  (list (probe-kernel)
        (probe-user-namespaces)
        (probe-landlock)
        (probe-landrun)
        (probe-cgroup-v2)
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
