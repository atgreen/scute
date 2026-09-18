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
               (:file "src/policy")
               (:file "src/sandbox")
               (:file "src/doctor")
               (:file "src/main"))
  :in-order-to ((test-op (test-op "scute/test")))
  :build-operation "program-op"
  :build-pathname "scute"
  :entry-point "scute:main")

#+sb-core-compression
(defmethod asdf:perform ((o asdf:image-op) (c asdf:system))
  (uiop:dump-image (asdf:output-file o c) :executable t :compression t))

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
               (:file "tests/doctor"))
  :perform (test-op (o c)
             (declare (ignore o c))
             (uiop:symbol-call '#:scute/tests '#:run-tests)))
