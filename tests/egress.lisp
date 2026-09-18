;;; SPDX-License-Identifier: MIT
;;;
;;; Address-level egress: the part of scute that wants a privilege.  Loading a
;;; BPF program needs CAP_BPF, so what can be checked without one is checked
;;; here, and what cannot is refused rather than half-done.

(in-package #:scute/tests)

(deftest test-the-guard-compiles
  "The BPF program is compiled from Lisp by Whistler, with no kernel involved,
so whether it compiles is answerable on any machine."
  (multiple-value-bind (maps progs) (call-scute 'compile-egress-guard)
    (check (equal '("scute_allowed") (mapcar (lambda (m) (getf m :name)) maps))
           "the guard's map is not what was expected: ~S"
           (mapcar (lambda (m) (getf m :name)) maps))
    (let ((program (first progs)))
      (check (string= "scute_egress_guard" (getf program :name))
             "the guard's name changed: ~S" (getf program :name))
      (check (string= "cgroup/connect4" (getf program :section))
             "the guard is attached to the wrong hook: ~S" (getf program :section))
      (check (plusp (length (getf program :insns)))
             "the guard compiled to nothing")
      (check (getf program :relocs)
             "the guard does not reference its map, so it would allow everything"))))

(deftest test-the-key-matches-what-the-kernel-will-see
  "Byte order is where this sort of code goes wrong, and the program cannot be
run here, so the arithmetic is checked against the C library instead: the key
scute builds must equal the address and port as inet_addr and htons render them."
  (dolist (case '(("127.0.0.1" . 443) ("10.11.12.13" . 80) ("172.66.147.243" . 8443)))
    (destructuring-bind (address . port) case
      (let* ((endpoint (call-scute 'parse-endpoint (format nil "~A:~D" address port) nil))
             (from-libc (logior
                         (ash (logand #xffffffff
                                      (cffi:foreign-funcall "inet_addr" :string address
                                                                        :uint32))
                              32)
                         (cffi:foreign-funcall "htons" :uint16 port :uint16))))
        (check (eql from-libc (call-scute 'endpoint-key endpoint))
               "the key for ~A:~D is ~X, but the kernel will see ~X"
               address port (call-scute 'endpoint-key endpoint) from-libc)))))

(deftest test-endpoints-are-resolved-before-anything-runs
  "A policy names hosts; the plan records addresses.  Resolution happens in the
supervisor so that what a sandbox may reach is decided, and visible, before it
is running."
  (let ((endpoint (call-scute 'parse-endpoint "localhost:443" nil)))
    (check (string= "localhost" (call-scute 'endpoint-host endpoint))
           "the host was not kept")
    (check (eql 443 (call-scute 'endpoint-port endpoint)) "the port was not kept")
    (check (= 4 (length (call-scute 'endpoint-address endpoint)))
           "the address is not IPv4: ~S" (call-scute 'endpoint-address endpoint)))
  (dolist (bad '("localhost" "localhost:0" "localhost:99999"
                 "no-such-host.invalid:443"))
    (check (typep (nth-value 1 (ignore-errors (call-scute 'parse-endpoint bad nil)))
                  'scute:policy-error)
           "~S was accepted as an endpoint" bad)))

(deftest test-an-allowlist-is-refused-without-the-privilege
  "A policy asking for address-level egress on a host that cannot provide it is
refused before anything is created, and the refusal says how to provide it."
  (multiple-value-bind (available reason) (call-scute 'egress-guard-available-p)
    (if available
        (format *error-output*
                "~&SKIP: this process holds CAP_BPF, so the refusal cannot be ~
                 exercised~%")
        (let* ((policy (policy-from-string "[filesystem]
read-execute = [\"/usr\"]
[network]
mode = \"host\"
allow = [\"localhost:443\"]"))
               (plan (call-scute 'compile-launch-plan policy '("/bin/true")))
               (condition (nth-value 1 (ignore-errors (call-scute 'preflight plan)))))
          (check (typep condition 'scute:sandbox-setup-error)
                 "a policy needing CAP_BPF was accepted without it: ~S" condition)
          (check (search "setcap" (princ-to-string condition))
                 "the refusal does not say how to grant the privilege: ~A" condition)
          (check (search "CAP_BPF" reason) "the reason does not name what is missing")))))

(deftest test-an-allowlist-needs-a-network
  "Naming places to reach on a sandbox that has no network is a contradiction,
not a no-op."
  (check (refused-p "[filesystem]
read = [\"/etc\"]
[network]
mode = \"none\"
allow = [\"localhost:443\"]")
         "an allowlist was accepted on a network that is not there"))

(defun guard-instructions ()
  "The guard's bytecode, decoded into (opcode dst src offset immediate) tuples."
  (multiple-value-bind (maps progs) (call-scute 'compile-egress-guard)
    (declare (ignore maps))
    (let ((insns (getf (first progs) :insns)))
      (loop for i from 0 below (length insns) by 8
            collect (list (aref insns i)
                          (ldb (byte 4 0) (aref insns (+ i 1)))
                          (ldb (byte 4 4) (aref insns (+ i 1)))
                          (let ((v (logior (aref insns (+ i 2))
                                           (ash (aref insns (+ i 3)) 8))))
                            (if (> v 32767) (- v 65536) v))
                          (logior (aref insns (+ i 4))
                                  (ash (aref insns (+ i 5)) 8)
                                  (ash (aref insns (+ i 6)) 16)
                                  (ash (aref insns (+ i 7)) 24)))))))

(deftest test-the-guard-does-what-it-claims
  "The program cannot be loaded here, so it is read instead.

Three things have to be true of it and none of them need a kernel: it reads the
destination from where struct bpf_sock_addr keeps it, it checks the map lookup
for NULL before dereferencing it -- a verifier rejects a program that does not,
so this is the difference between working and not loading at all -- and a miss
answers 0, which is a refusal.  The first sandbox run on a privileged host
should not be where these are discovered."
  (let ((insns (guard-instructions)))
    ;; struct bpf_sock_addr: user_ip4 at 4, user_port at 24, both network order.
    (check (find-if (lambda (i) (and (= #x61 (first i)) (= 4 (fourth i)))) insns)
           "the guard does not read user_ip4 from offset 4")
    (check (find-if (lambda (i) (and (= #x61 (first i)) (= 24 (fourth i)))) insns)
           "the guard does not read user_port from offset 24")
    ;; The lookup, and the NULL check that must follow it.
    (let ((call (position-if (lambda (i) (and (= #x85 (first i)) (= 1 (fifth i))))
                             insns)))
      (check call "the guard never calls bpf_map_lookup_elem")
      (when call
        (let ((after (subseq insns (1+ call) (min (length insns) (+ call 4)))))
          (check (find-if (lambda (i) (and (member (first i) '(#x15 #x55))
                                           (zerop (fifth i))))
                          after)
                 "nothing compares the lookup result against zero, so the guard ~
                  would dereference NULL on a miss and the verifier would reject ~
                  it:~%~S" after))))
    (check (= #x95 (first (car (last insns))))
           "the guard does not end in exit")))
