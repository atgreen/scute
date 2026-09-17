;;; SPDX-License-Identifier: MIT
;;;
;;; What doctor reports about the host it runs on.

(in-package #:scute/tests)

(defun probe-named (report name)
  (find name report :key (lambda (probe) (call-scute 'probe-name probe))
                    :test #'string=))

(deftest test-doctor-report
  "Doctor answers every question it asks, and reports this host as able to
launch a sandbox -- it just did, to find out."
  (let ((report (call-scute 'doctor-report)))
    (check (every (lambda (probe)
                    (and (call-scute 'probe-name probe)
                         (call-scute 'probe-detail probe)
                         (member (call-scute 'probe-status probe) '(:ok :missing :info))))
                  report)
           "a probe answered nothing: ~S" report)
    (let ((namespaces (probe-named report "user namespaces")))
      (check namespaces "no user namespace probe in the report")
      (check (eq :ok (and namespaces (call-scute 'probe-status namespaces)))
             "this host cannot launch a sandbox: ~S" namespaces))
    (dolist (name '("landlock" "cgroup v2" "libseccomp"))
      (check (probe-named report name) "no ~A probe in the report" name))))

(deftest test-doctor-fails-closed
  "A missing mandatory control makes the report say no."
  (let* ((missing (scute::make-probe "landlock" :missing "pretend this kernel has none"))
         (present (scute::make-probe "kernel" :info "pretend"))
         (verdict nil)
         (output (with-output-to-string (stream)
                   (setf verdict (call-scute 'print-doctor-report
                                             (list present missing) stream)))))
    (check (null verdict) "a missing mandatory control was reported as fine")
    (check (search "landlock" output) "the report did not name the missing control")
    (setf verdict (with-output-to-string (stream)
                    (call-scute 'print-doctor-report (list present) stream)))
    (check (call-scute 'print-doctor-report (list present)
                       (make-broadcast-stream))
           "a report with nothing missing was reported as failing")))
