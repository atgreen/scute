;;; SPDX-License-Identifier: MIT
;;;
;;; Address-level egress: the part of scute that wants a privilege.  Loading a
;;; BPF program needs CAP_BPF, so what can be checked without one is checked
;;; here, and what cannot is refused rather than half-done.

(in-package #:scute/tests)

(deftest test-ssh-is-redirected-to-the-bastion-only-when-asked
  "Port 22 is refused by a proxied sandbox -- an HTTP proxy cannot speak ssh, and
delivering it there would leave somebody debugging a timeout.  With a bastion to
send it to, the same port is rewritten instead, which is what lets an agent keep
the remote it already has: git@github.com, arriving where the key is.

The program is read here rather than loaded: building it needs no privileges,
and what is being checked is the decision, not the kernel's opinion of it."
  (let* ((proxy (call-scute 'parse-endpoint "127.0.0.1:10210" nil))
         (bastion (call-scute 'parse-endpoint "127.0.0.1:10211" nil))
         (without (format nil "~S" (call-scute 'egress-redirect-forms proxy)))
         (with (format nil "~S" (call-scute 'egress-redirect-forms proxy bastion)))
         ;; 22 and 10211 as connect4 presents them: sixteen bits, byte-swapped.
         (ssh-port (call-scute 'network-port-word 22))
         (bastion-port (call-scute 'network-port-word 10211)))
    (check (not (search (princ-to-string ssh-port) without))
           "a policy with no ssh credential still says something about port 22")
    (check (search (princ-to-string ssh-port) with)
           "the redirect does not mention port 22 even with a bastion to send it to")
    (check (search (princ-to-string bastion-port) with)
           "the redirect never names the bastion's port")
    ;; And it still compiles to a program: forms that read well and will not
    ;; verify are worse than no feature.
    (check (nth-value 1 (call-scute 'compile-egress-redirect proxy bastion))
           "the redirect with a bastion compiled to nothing")))

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

(defun plan-for-proxy-policy (&optional allow)
  (let* ((text (format nil "~
[filesystem]~%read = [\"/etc\"]~%~%[network]~%mode = \"host\"~%~
proxy = \"http://127.0.0.1:10210\"~%~@[allow = [~S]~%~]" allow))
         (policy (call-scute 'validate-sandbox-policy (call-scute 'parse-policy-text text))))
    (call-scute 'compile-launch-plan policy '("/bin/true"))))

(deftest test-a-named-proxy-is-bound-by-address-when-the-kernel-can
  "Landlock filters ports, not addresses, so a policy naming a proxy permits that
port on any host.  Where the BPF guard can be installed, the proxy's own address
is added to what it permits, which is what naming a proxy was meant to say.

Both answers are exercised whatever this host can do: the availability of the
guard is a parameter, so the branch that matters is not the one that happens to
be untestable here."
  (let ((plan (plan-for-proxy-policy)))
    (check (null (call-scute 'launch-plan-allow plan))
           "the policy named no allow entries, so the plan should have had none")
    (let ((allow (call-scute 'launch-plan-allow
                             (call-scute 'plan-with-proxy-bound-by-address plan t))))
      (check (= 1 (length allow))
             "expected the proxy's address to be permitted, got ~D entries" (length allow))
      (when allow
        (check (equal '(127 0 0 1)
                      (coerce (call-scute 'endpoint-address (first allow)) 'list))
               "the address bound was not the proxy's")
        (check (= 10210 (call-scute 'endpoint-port (first allow)))
               "the port bound was not the proxy's")))
    ;; Without the capability there is nothing to install, and refusing would make
    ;; every proxy policy unusable on an ordinary host.
    (check (null (call-scute 'launch-plan-allow
                             (call-scute 'plan-with-proxy-bound-by-address plan nil)))
           "an address guard was added on a host that cannot install one")))

(deftest test-binding-the-proxy-does-not-disturb-an-explicit-allow-list
  "A policy that already names addresses keeps them: the proxy joins the set
rather than replacing it, because the sandbox has to be able to reach it."
  (let* ((plan (plan-for-proxy-policy "127.0.0.1:9999"))
         (allow (call-scute 'launch-plan-allow
                            (call-scute 'plan-with-proxy-bound-by-address plan t))))
    (check (= 1 (length (call-scute 'launch-plan-allow plan)))
           "the policy's own allow entry went missing before binding")
    (check (= 2 (length allow))
           "expected the policy's entry and the proxy's, got ~D" (length allow))
    (check (find 9999 allow :key (lambda (e) (call-scute 'endpoint-port e)))
           "the policy's own allow entry was dropped")
    (check (find 10210 allow :key (lambda (e) (call-scute 'endpoint-port e)))
           "the proxy's address was not added")))

(deftest test-a-proxy-already-named-in-the-allow-list-is-not-added-twice
  "Naming the proxy's address explicitly, as the README suggests, must not leave
the guard with the same rule twice."
  (let ((allow (call-scute 'launch-plan-allow
                           (call-scute 'plan-with-proxy-bound-by-address
                                       (plan-for-proxy-policy "127.0.0.1:10210") t))))
    (check (= 1 (length allow))
           "the proxy's address was added beside an identical entry (~D entries)"
           (length allow))))

(deftest test-binding-the-proxy-needs-a-cgroup-as-well-as-a-capability
  "Granting the binary CAP_BPF is not enough to bind a proxy's address: the guard
attaches to a cgroup, and a host without delegation has none to attach it to.

This is the regression the parameter exists for.  Binding was added whenever the
capabilities were held, so granting them made every proxy policy on an ordinary
host start failing in preflight -- over a control the policy had not asked for.
Narrowing beyond what a policy said is a courtesy, so where it cannot be enacted
the plan is left alone; an allow list the policy wrote itself is still refused."
  (let ((plan (plan-for-proxy-policy)))
    (check (null (call-scute 'launch-plan-allow
                             (call-scute 'plan-with-proxy-bound-by-address plan nil)))
           "a proxy address was bound on a host that cannot install the guard")
    (check (call-scute 'launch-plan-allow
                       (call-scute 'plan-with-proxy-bound-by-address plan t))
           "a proxy address was not bound on a host that can install the guard")
    ;; And what the host can actually do is both halves together, so the
    ;; predicate says so rather than only checking capabilities.
    (multiple-value-bind (capable) (call-scute 'egress-guard-available-p)
      (check (or (not (call-scute 'proxy-address-bindable-p)) capable)
             "bindable without the capability to load the program"))))

(deftest test-the-redirect-program-compiles-and-names-the-proxy
  "A connect4 program may rewrite the destination it was asked about, which is
what makes a proxy unavoidable rather than merely mandatory.  Compiling needs no
privileges, so the program's shape is checked wherever the suite runs."
  (let* ((endpoint (call-scute 'make-endpoint "127.0.0.1" 10210 #(127 0 0 1)))
         (programs (nth-value 1 (call-scute 'compile-egress-redirect endpoint))))
    (check (= 1 (length programs)) "expected one program, got ~D" (length programs))
    (let ((program (first programs)))
      (check (string= "scute_egress_proxied" (getf program :name))
             "the program is called ~S" (getf program :name))
      (check (plusp (length (getf program :insns)))
             "the program has no instructions")
      (check (string= "cgroup/connect4" (getf program :section))
             "attached at ~S, which is not where a destination can be rewritten"
             (getf program :section)))))

(deftest test-the-redirect-uses-the-byte-order-the-kernel-presents
  "Byte order is where this sort of code goes wrong, so the numbers compiled into
the program are pinned: connect4 hands over the address and port in network byte
order, and a little-endian machine reading those bytes as integers sees them
reversed."
  (check (= #x0100007F (call-scute 'endpoint-address-word
                                   (call-scute 'make-endpoint "127.0.0.1" 1 #(127 0 0 1))))
         "127.0.0.1 became ~X" (call-scute 'endpoint-address-word
                                           (call-scute 'make-endpoint "127.0.0.1" 1 #(127 0 0 1))))
  (check (= #xBB01 (call-scute 'network-port-word 443))
         "443 became ~X" (call-scute 'network-port-word 443))
  (check (= #x5000 (call-scute 'network-port-word 80))
         "80 became ~X" (call-scute 'network-port-word 80))
  (check (= #xE227 (call-scute (quote network-port-word) 10210))
         "10210 became ~X" (call-scute 'network-port-word 10210)))

(deftest test-a-proxied-policy-says-what-it-needs-and-refuses-what-it-cannot-mean
  "Proxied sends every web connection to the proxy, so there has to be one -- and
an allow list beside it would be a second answer to the same question."
  (flet ((policy (text) (ignore-errors
                         (call-scute 'validate-sandbox-policy
                                     (call-scute 'parse-policy-text text)))))
    ;; Proxied with no proxy named is the broker, because repeating the same
    ;; address in every policy is a thing to forget rather than a decision.
    (let ((defaulted (policy (format nil "[filesystem]~%read = [\"/etc\"]~%~%~
                                          [network]~%mode = \"proxied\"~%"))))
      (check defaulted "proxied without a proxy was refused")
      (check (string= (scute-value '+default-broker-proxy+)
                      (call-scute 'sandbox-policy-proxy defaulted))
             "proxied did not default to the broker: ~S"
             (call-scute 'sandbox-policy-proxy defaulted)))
    (check (null (policy (format nil "[filesystem]~%read = [\"/etc\"]~%~%~
                                      [network]~%mode = \"proxied\"~%~
                                      proxy = \"http://127.0.0.1:10210\"~%~
                                      allow = [\"api.github.com:443\"]~%")))
           "proxied with an allow list was accepted")
    (let ((good (policy (format nil "[filesystem]~%read = [\"/etc\"]~%~%~
                                     [network]~%mode = \"proxied\"~%~
                                     proxy = \"http://127.0.0.1:10210\"~%"))))
      (check good "a proper proxied policy was refused")
      (when good
        (let ((plan (call-scute 'compile-launch-plan good '("/bin/true"))))
          (check (eq :proxied (call-scute 'launch-plan-network plan))
                 "the mode did not survive into the plan")
          ;; Landlock sees the connect syscall, and the rewrite happens further
          ;; in, so the original ports have to pass here.
          (let ((connect (call-scute 'launch-plan-connect-tcp plan)))
            (dolist (port '(80 443 10210))
              (check (member port connect)
                     "port ~D is not permitted, so the rewrite would never be reached: ~S"
                     port connect))))))))

(deftest test-udp-does-not-escape-a-guarded-sandbox
  "connect4 sees connect(2), and sendto(2) on an unconnected socket never calls
it.  A sandbox whose TCP was fully accounted for could still send datagrams
anywhere -- verified as an actual escape before this existed -- so the same shape
of program answers at sendmsg4, where unconnected UDP does go."
  (let ((programs (nth-value 1 (call-scute 'compile-egress-udp))))
    (check (= 1 (length programs)) "expected one program, got ~D" (length programs))
    (let ((program (first programs)))
      (check (string= "cgroup/sendmsg4" (getf program :section))
             "attached at ~S, which is not where unconnected UDP goes"
             (getf program :section))
      (check (plusp (length (getf program :insns))) "the program has no instructions")))
  ;; Name resolution is the exception, because a client resolves before it
  ;; connects and a failed resolution never reaches the connect being guarded.
  (check (= 53 (scute-value '+resolver-port+)) "the exception is not port 53")
  (check (= #x3500 (call-scute 'network-port-word 53))
         "53 in network order is ~X" (call-scute 'network-port-word 53)))

(deftest test-the-redirect-leaves-name-resolution-alone
  "The redirect refused port 53, so a client could not resolve the name it was
about to connect to -- and nothing ever reached the proxy to be redirected.  It
was invisible while the sandbox also had HTTPS_PROXY set, because then the proxy
did the resolving.

Checked at the level that broke: the program's own text, since the failure was a
missing branch rather than a wrong number."
  (let* ((endpoint (call-scute 'make-endpoint "127.0.0.1" 10210 #(127 0 0 1)))
         (text (format nil "~S" (call-scute 'egress-redirect-forms endpoint))))
    ;; 53 in network byte order, which is what the program compares against.
    (check (search (format nil "~D" (call-scute 'network-port-word 53)) text)
           "the program never mentions the resolver port: ~A" text))
  ;; And Landlock has to permit it, since it sees the connect before the rewrite.
  (let* ((policy (call-scute 'validate-sandbox-policy
                             (call-scute 'parse-policy-text
                                         (format nil "[filesystem]~%read = [\"/etc\"]~%~%~
                                                      [network]~%mode = \"proxied\"~%~
                                                      proxy = \"http://127.0.0.1:10210\"~%"))))
         (plan (call-scute 'compile-launch-plan policy '("/bin/true")))
         (connect (call-scute 'launch-plan-connect-tcp plan)))
    (check (member 53 connect)
           "TCP resolution is refused, so a truncated answer has no fallback: ~S"
           connect)))

;;── What this binary started with ──────────────────────────────────────────────

(deftest test-the-guard-is-judged-by-what-the-binary-started-with
  "Scute drops every capability it holds before a sandboxed child exists, which is
right and destroys the evidence for anyone asking afterwards whether this host
could install a guard.

doctor asked exactly that, one probe after the one that launches /bin/true -- so a
packaged Scute carrying cap_bpf reported itself as a Scute without it, and then
reported the default network as the port-level fallback when the kernel redirect
was available all along."
  (let ((scute::*startup-capabilities*
          ;; CAP_BPF is 39, CAP_NET_ADMIN is 12.
          (list (cons "CapEff" (logior (ash 1 39) (ash 1 12)))
                (cons "CapPrm" (logior (ash 1 39) (ash 1 12))))))
    (check (call-scute 'egress-guard-available-p)
           "a binary that started with the capabilities was judged not to have them")
    (let ((scute::*implicit-network-mode* nil))
      (check (string= "proxied" (call-scute 'implicit-network-mode))
             "the default network ignored the capabilities the binary started with")))
  ;; And a process that never had them is still told so, with the remedy.
  (let ((scute::*startup-capabilities* (list (cons "CapEff" 0) (cons "CapPrm" 0))))
    (multiple-value-bind (available reason) (call-scute 'egress-guard-available-p)
      (check (not available) "a binary with no capabilities claimed the guard")
      (check (search "CAP_BPF" reason) "the reason does not name what is missing"))))
