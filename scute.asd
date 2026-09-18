;;; scute.asd
;;;
;;; SPDX-License-Identifier: MIT
;;;
;;; Copyright (C) 2026 Anthony Green

(asdf:defsystem #:scute
  :description "Run one command inside a deny-by-default Linux sandbox."
  :author      "Anthony Green <anthony@atgreen.org>"
  :license     "MIT"
  :version     "0.1.0"
  :depends-on (:cffi :clingon :clop :version-string :whistler)
  :serial t
  :components ((:file "src/package")
               (:file "src/conditions")
               (:file "src/linux")
               (:file "src/landlock")
               (:file "src/seccomp")
               (:file "src/cgroup")
               (:file "src/learn")
               (:file "src/policy")
               (:file "src/sandbox")
               (:file "src/doctor")
               (:file "src/completions")
               (:file "src/main"))
  :in-order-to ((test-op (test-op "scute/test")))
  :build-operation "program-op"
  :build-pathname "scute"
  :entry-point "scute:main")

;;; Startup latency is paid on every invocation of a tool meant to wrap every
;;; command; disk is paid once.  A compressed core is about 15 MiB and takes
;;; some 215 ms to start; uncompressed it is about 67 MiB and takes some 75 ms,
;;; and the compression level barely moves either number, because the cost is
;;; decompressing the core at all.  So: fast by default, small on request with
;;; SCUTE_COMPRESSION=9 (or any zstd level) for anyone who would rather have
;;; the disk back.
#+sb-core-compression
(defmethod asdf:perform ((o asdf:image-op) (c asdf:system))
  (uiop:dump-image (asdf:output-file o c)
                   :executable t
                   :compression (let ((level (uiop:getenv "SCUTE_COMPRESSION")))
                                  (cond ((or (null level) (string= "" level)) nil)
                                        ((every #'digit-char-p level)
                                         (parse-integer level))
                                        (t t)))))

(asdf:defsystem #:scute/test
  :description "Tests for Scute."
  :depends-on (#:scute)
  :serial t
  :components ((:file "tests/package")
               (:file "tests/harness")
               (:file "tests/namespace")
               (:file "tests/landlock")
               (:file "tests/policy")
               (:file "tests/seccomp")
               (:file "tests/cgroup")
               (:file "tests/supervisor")
               (:file "tests/cli")
               (:file "tests/learn")
               (:file "tests/doctor"))
  :perform (test-op (o c)
             (declare (ignore o c))
             (uiop:symbol-call '#:scute/tests '#:run-tests)))
