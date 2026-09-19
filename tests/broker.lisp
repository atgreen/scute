;;; SPDX-License-Identifier: MIT
;;;
;;; Giving a sandbox a credential it cannot read.
;;;
;;; The broker these tests talk to is a few lines of Python standing in for
;;; KeyFence: it answers /health, issues a token for whatever credential it is
;;; sent, and records what it was sent so a test can prove the real secret went
;;; to the broker and the token -- not the secret -- went to the sandbox.

(in-package #:scute/tests)

(defparameter +broker-proxy-port+ 18810)
(defparameter +broker-control-port+ 18812)

(defun write-fake-broker (control-port record)
  "A script answering the control API KeyFence answers, writing what it saw."
  (let ((path (format nil "~A.py" (scratch-pathname "broker"))))
    (with-open-file (stream path :direction :output :if-exists :supersede)
      (dolist (line (list
                     "import json,http.server"
                     "class H(http.server.BaseHTTPRequestHandler):"
                     "    def log_message(self,*a): pass"
                     "    def do_GET(self):"
                     "        self.send_response(200); self.end_headers()"
                     "        if self.path.startswith('/tokens'):"
                     "            self.wfile.write(b'[]')"
                     "        elif self.path.startswith('/credentials'):"
                     "            self.wfile.write(b'{\"credentials\":[]}')"
                     "        else:"
                     "            self.wfile.write(b'{\"status\":\"ok\"}')"
                     "    def do_POST(self):"
                     "        n=int(self.headers['Content-Length'])"
                     "        body=json.loads(self.rfile.read(n))"
                     "        body['authorization']=self.headers.get('Authorization','')"
                     (format nil "        open(~S,'a').write(json.dumps(body)+chr(10))"
                             record)
                     "        self.send_response(200); self.end_headers()"
                     "        held=body.get('credential') or body.get('credential_ref')"
                     "        t={'token':'kf_'+held[::-1]}"
                     "        self.wfile.write(json.dumps(t).encode())"
                     "    def do_DELETE(self):"
                     (format nil "        open(~S,'a').write(json.dumps({'revoked':self.path})+chr(10))"
                             record)
                     "        self.send_response(204); self.end_headers()"
                     (format nil "http.server.HTTPServer(('127.0.0.1',~D),H).serve_forever()"
                             control-port)))
        (write-line line stream)))
    path))

(defun start-fake-broker (record)
  (let ((script (write-fake-broker +broker-control-port+ record)))
    (let ((helper (call-scute 'start-helper-arguments
                              (list "/usr/bin/python3" script))))
      (unless (call-scute 'wait-for-port +broker-control-port+ 10)
        (call-scute 'stop-helper helper)
        (error "the stand-in broker never answered"))
      helper)))

(defun brokered-policy-text ()
  (format nil "~
[filesystem]~%read-execute = [\"/usr\"]~%read = [\"/etc\"]~%~%~
[network]~%mode = \"host\"~%proxy = \"http://127.0.0.1:~D\"~%~%~
[credentials]~%broker = \"keyfence\"~%control-port = ~D~%~%~
[credentials.anthropic]~%secret-file = ~S~%destinations = [\"api.anthropic.com\"]~%~
env = \"ANTHROPIC_API_KEY\"~%"
          +broker-proxy-port+ +broker-control-port+
          (format nil "~A.secret" (scratch-pathname "broker"))))

(deftest test-a-policy-says-which-credential-the-sandbox-never-holds
  "The policy names a secret file and an environment variable.  What the plan
says is that the file is read by Scute and the variable carries a token, and a
dry run has to show both without reading anything."
  (let ((policy (call-scute 'validate-sandbox-policy
                            (call-scute 'parse-policy-text (brokered-policy-text)))))
    (let ((credentials (call-scute 'sandbox-policy-credentials policy))
          (broker (call-scute 'sandbox-policy-broker policy)))
      (check (= 1 (length credentials)) "expected one credential, got ~D"
             (length credentials))
      (let ((request (first credentials)))
        (check (string= "anthropic" (call-scute 'credential-request-name request))
               "the credential lost its name")
        (check (string= "ANTHROPIC_API_KEY"
                        (call-scute 'credential-request-variable request))
               "the token would land in the wrong variable")
        (check (equal '("api.anthropic.com")
                      (call-scute 'credential-request-destinations request))
               "the token would not be locked to the destination the policy named"))
      (check (= +broker-proxy-port+ (call-scute 'broker-settings-proxy-port broker))
             "the broker would not listen where the proxy is")
      (check (= +broker-control-port+ (call-scute 'broker-settings-control-port broker))
             "the control port was not read from the policy"))))

(deftest test-credentials-need-a-proxy-to-be-swapped-behind
  "A swap nothing routes through is not containment.  A policy asking for
credentials without naming a proxy is refused rather than half honoured."
  (let ((text (format nil "~
[filesystem]~%read = [\"/etc\"]~%~%[network]~%mode = \"host\"~%~%~
[credentials]~%broker = \"keyfence\"~%~%[credentials.x]~%~
secret-file = \"/etc/hostname\"~%destinations = [\"example.com\"]~%env = \"X\"~%")))
    (check (nth-value 1 (ignore-errors
                         (call-scute 'validate-sandbox-policy
                                     (call-scute 'parse-policy-text text))))
           "a policy with credentials but no proxy was accepted")))

(deftest test-a-token-reaches-the-sandbox-and-the-secret-does-not
  "The whole point, end to end against a stand-in broker: Scute reads the secret,
the broker gets it, and what the sandbox is handed is the token."
  (if (plusp (cffi:foreign-funcall "system" :string
                                  "command -v python3 >/dev/null 2>&1" :int))
      (format *error-output* "~&SKIP: no python3 to stand in for a broker~%")
      (let* ((record (format nil "~A.jsonl" (scratch-pathname "broker-record")))
             (secret-file (format nil "~A.secret" (scratch-pathname "broker")))
             (secret "sk-ant-not-a-real-key")
             (helper nil))
        (with-open-file (stream secret-file :direction :output :if-exists :supersede)
          (write-line secret stream))
        (sb-posix:chmod secret-file #o600)
        (unwind-protect
             (progn
               (setf helper (start-fake-broker record))
               (let* ((policy (call-scute 'validate-sandbox-policy
                                          (call-scute 'parse-policy-text
                                                      (brokered-policy-text))))
                      (plan (call-scute 'compile-launch-plan policy '("/bin/true")))
                      (seen nil))
                 (call-scute 'call-with-broker plan
                             (lambda (revised) (setf seen revised)))
                 (let ((environment (call-scute 'launch-plan-environment seen)))
                   (check (find (format nil "ANTHROPIC_API_KEY=kf_~A"
                                        (reverse secret))
                                environment :test #'string=)
                          "the sandbox was not given the token")
                   (check (notany (lambda (entry) (search secret entry)) environment)
                          "the real secret reached the sandbox's environment")
                   (check (find-if (lambda (entry)
                                     (and (> (length entry) 14)
                                          (string= "SSL_CERT_FILE=" entry :end2 14)))
                                   environment)
                          "the sandbox was not told which CA to trust"))
                 (let ((sent (with-open-file (stream record) (read-line stream nil ""))))
                   (check (search secret sent)
                          "the broker was never given the real credential")
                   (check (search "api.anthropic.com" sent)
                          "the token was not locked to the policy's destination"))
                 (let ((lines (with-open-file (stream record)
                                (loop for line = (read-line stream nil)
                                      while line collect line))))
                   (check (find-if (lambda (line) (search "revoked" line)) lines)
                          "the token outlived the run that minted it"))))
          (when helper (call-scute 'stop-helper helper))
          (delete-scratch record secret-file)))))

(defun write-healthy-stranger (port)
  "Something that is not a broker, answering 200 on /health as many things do."
  (let ((path (format nil "~A.py" (scratch-pathname "stranger"))))
    (with-open-file (stream path :direction :output :if-exists :supersede)
      (dolist (line (list
                     "import http.server"
                     "class H(http.server.BaseHTTPRequestHandler):"
                     "    def log_message(self,*a): pass"
                     "    def do_GET(self):"
                     "        if self.path.startswith('/health'):"
                     "            self.send_response(200); self.end_headers()"
                     "            self.wfile.write(b'{\"status\":\"ok\"}')"
                     "        else:"
                     "            self.send_error(404)"
                     "    def do_POST(self):"
                     (format nil "        open(~S,'a').write(self.rfile.read(int(self.headers['Content-Length'])).decode())"
                             (format nil "~A.received" (scratch-pathname "stranger")))
                     "        self.send_response(200); self.end_headers()"
                     (format nil "http.server.HTTPServer(('127.0.0.1',~D),H).serve_forever()"
                             port)))
        (write-line line stream)))
    path))

(deftest test-a-secret-is-not-handed-to-whatever-answers-the-port
  "Attaching to a broker means posting the operator's plaintext credential to it,
so health is not enough to go on: plenty of things answer 200.  Something on the
port that cannot answer a broker's control API gets nothing."
  (if (plusp (cffi:foreign-funcall "system" :string
                                  "command -v python3 >/dev/null 2>&1" :int))
      (format *error-output* "~&SKIP: no python3 to stand in for a stranger~%")
      (let* ((received (format nil "~A.received" (scratch-pathname "stranger")))
             (secret-file (format nil "~A.secret" (scratch-pathname "broker")))
             (helper nil))
        (with-open-file (stream secret-file :direction :output :if-exists :supersede)
          (write-line "sk-ant-not-a-real-key" stream))
        (sb-posix:chmod secret-file #o600)
        (unwind-protect
             (progn
               (setf helper (call-scute 'start-helper-arguments
                                        (list "/usr/bin/python3"
                                              (write-healthy-stranger
                                               +broker-control-port+))))
               (check (call-scute 'wait-for-port +broker-control-port+ 10)
                      "the stand-in stranger never answered")
               (let* ((policy (call-scute 'validate-sandbox-policy
                                          (call-scute 'parse-policy-text
                                                      (brokered-policy-text))))
                      (plan (call-scute 'compile-launch-plan policy '("/bin/true")))
                      (ran nil))
                 (check (nth-value 1 (ignore-errors
                                      (call-scute 'call-with-broker plan
                                                  (lambda (revised)
                                                    (declare (ignore revised))
                                                    (setf ran t)))))
                        "Scute attached to something that is not a broker")
                 (check (not ran) "the sandbox ran with a credential nobody brokered")
                 (check (not (probe-file received))
                        "the credential was posted to something that is not a broker")))
          (when helper (call-scute 'stop-helper helper))
          (delete-scratch received secret-file)))))

(defun referencing-policy-text ()
  (format nil "~
[filesystem]~%read-execute = [\"/usr\"]~%read = [\"/etc\"]~%~%~
[network]~%mode = \"host\"~%proxy = \"http://127.0.0.1:~D\"~%~%~
[credentials]~%control-port = ~D~%~%~
[credentials.anthropic]~%ref = \"anthropic\"~%destinations = [\"api.anthropic.com\"]~%~
env = \"ANTHROPIC_API_KEY\"~%"
          +broker-proxy-port+ +broker-control-port+))

(deftest test-a-referenced-credential-is-never-read-by-scute
  "The broker already holds the secret, so Scute names it instead of reading it:
the request carries credential_ref, no file is opened, and no plaintext passes
through this process at all."
  (if (plusp (cffi:foreign-funcall "system" :string
                                  "command -v python3 >/dev/null 2>&1" :int))
      (format *error-output* "~&SKIP: no python3 to stand in for a broker~%")
      (let* ((record (format nil "~A.jsonl" (scratch-pathname "ref-record")))
             (helper nil))
        (unwind-protect
             (progn
               (setf helper (start-fake-broker record))
               (let* ((policy (call-scute 'validate-sandbox-policy
                                          (call-scute 'parse-policy-text
                                                      (referencing-policy-text))))
                      (plan (call-scute 'compile-launch-plan policy '("/bin/true")))
                      (seen nil))
                 (call-scute 'call-with-broker plan (lambda (revised) (setf seen revised)))
                 (let ((sent (with-open-file (stream record) (read-line stream nil ""))))
                   (check (search "credential_ref" sent)
                          "the broker was not asked for a credential by name: ~S" sent)
                   (check (search "anthropic" sent)
                          "the reference did not name the credential")
                   (check (not (search "\"credential\":" sent))
                          "a plaintext credential was sent as well as a reference"))
                 (check (find-if (lambda (entry)
                                   (and (> (length entry) 18)
                                        (string= "ANTHROPIC_API_KEY=" entry :end2 18)))
                                 (call-scute 'launch-plan-environment seen))
                        "the sandbox was not given a token")))
          (when helper (call-scute 'stop-helper helper))
          (delete-scratch record)))))

(deftest test-a-credential-needs-a-secret-file-or-a-ref-and-not-both
  "One or the other: a secret Scute reads, or one the broker already holds."
  (flet ((refused-p (credential-lines)
           (nth-value 1 (ignore-errors
                         (call-scute 'validate-sandbox-policy
                                     (call-scute 'parse-policy-text
                                                 (format nil "~
[filesystem]~%read = [\"/etc\"]~%~%[network]~%mode = \"host\"~%~
proxy = \"http://127.0.0.1:10210\"~%~%[credentials.x]~%~A~
destinations = [\"example.com\"]~%env = \"X\"~%"
                                                         credential-lines)))))))
    (check (refused-p "") "a credential naming neither a secret-file nor a ref was accepted")
    (check (refused-p (format nil "secret-file = \"/etc/hostname\"~%ref = \"x\"~%"))
           "a credential naming both a secret-file and a ref was accepted")
    (check (not (refused-p (format nil "ref = \"x\"~%")))
           "a credential naming only a ref was refused")))

(deftest test-json-string-list-reads-a-flat-array
  "The names out of the broker's answer, without a JSON reader."
  (let ((body "{\"credentials\":[\"anthropic\",\"github\"],\"keyring\":true}"))
    (check (equal '("anthropic" "github")
                  (call-scute 'json-string-list body "credentials"))
           "got ~S" (call-scute 'json-string-list body "credentials")))
  (check (null (call-scute 'json-string-list "{\"credentials\":[]}" "credentials"))
         "an empty array should read as no names")
  (check (null (call-scute 'json-string-list "{\"other\":[\"x\"]}" "credentials"))
         "a missing key should read as no names"))

(deftest test-checking-a-policy-reports-credentials-it-cannot-have
  "Whether a credential can be had is as much a part of whether a policy will run
as whether a path can be read, and it fails in a much harder place to read: an
agent getting a 401 from somewhere inside itself.  A name the broker does not
know is a fault in the policy and counts; a broker that cannot be reached is a
fact about the host and does not."
  (if (plusp (cffi:foreign-funcall "system" :string
                                  "command -v python3 >/dev/null 2>&1" :int))
      (format *error-output* "~&SKIP: no python3 to stand in for a broker~%")
      (let* ((record (format nil "~A.jsonl" (scratch-pathname "check-record")))
             (helper nil))
        (unwind-protect
             (progn
               (setf helper (start-fake-broker record))
               (let* ((policy (call-scute 'validate-sandbox-policy
                                          (call-scute 'parse-policy-text
                                                      (referencing-policy-text))))
                      (plan (call-scute 'compile-launch-plan policy '("/bin/true"))))
                 ;; The stand-in answers /credentials with no names at all, so the
                 ;; reference in the policy is one it does not know.
                 (let ((said (with-output-to-string (stream)
                               (check (plusp (call-scute 'report-credentials plan stream))
                                      "a reference the broker does not know was not counted"))))
                   (check (search "anthropic" said)
                          "the report does not name the credential: ~S" said))))
          (when helper (call-scute 'stop-helper helper))
          (delete-scratch record)))))

(deftest test-json-object-list-splits-without-parsing
  "The broker's events come back as an array of objects, and what is wanted from
each is a field or two.  Splitting has to survive a nested object and a brace
inside a string, which is why it is not a search for the next closing brace."
  (let ((body "{\"entries\":[{\"event\":\"deny\",\"why\":{\"rule\":\"dest\"}},{\"event\":\"allow\",\"note\":\"a } brace\"}]}"))
    (let ((objects (call-scute 'json-object-list body "entries")))
      (check (= 2 (length objects)) "split into ~D objects, expected 2: ~S"
             (length objects) objects)
      (when (= 2 (length objects))
        (check (equal "deny" (call-scute 'json-string-field (first objects) "event"))
               "the first object is not the deny: ~S" (first objects))
        (check (equal "allow" (call-scute 'json-string-field (second objects) "event"))
               "a brace inside a string ended the object early: ~S" (second objects)))))
  (check (null (call-scute 'json-object-list "{\"entries\":[]}" "entries"))
         "an empty array should read as no objects"))

(deftest test-refusals-are-picked-out-of-what-the-broker-recorded
  "A failing command's reason often lives in the broker's log, which the operator
may not think to read.  These are the entries worth repeating back."
  (let* ((events (list "{\"event\":\"issue\",\"token_id\":\"a\"}"
                       "{\"event\":\"allow\",\"destination\":\"api.github.com\"}"
                       "{\"event\":\"deny\",\"destination\":\"api.anthropic.com\",\"deny_reason\":\"token not allowed for destination api.anthropic.com\"}"
                       "{\"event\":\"deny\",\"destination\":\"evil.example\",\"deny_rule\":\"no_token\"}"))
         (refusals (call-scute 'refusals-among events)))
    (check (= 2 (length refusals)) "found ~D refusals, expected 2" (length refusals))
    (check (equal "api.anthropic.com" (car (first refusals)))
           "the first refusal names ~S" (car (first refusals)))
    (check (search "not allowed" (cdr (first refusals)))
           "the reason was lost: ~S" (cdr (first refusals)))
    ;; A deny with only a rule still says something, rather than nothing.
    (check (equal "no_token" (cdr (second refusals)))
           "a deny with no reason fell back to ~S" (cdr (second refusals)))
    (let ((said (with-output-to-string (stream)
                  (call-scute 'report-broker-refusals events stream))))
      (check (search "refused 2 requests" said) "the report says: ~S" said)
      (check (search "api.anthropic.com" said) "the report omits the destination"))))

(deftest test-a-refusal-with-no-token-is-still-reported
  "The refusal a misconfigured sandbox actually produces is 'no keyfence token
found', and that one carries no run id -- there is no token to take one from.
Attributed entries alone would have said nothing about the very case worth
explaining, so unattributed refusals are found by time instead."
  (let ((*trace-output* *trace-output*))
    (check (call-scute 'rfc3339-now) "there is no timestamp to compare against")
    ;; The shape the broker stamps: UTC, to the second, sortable as text.
    (let ((now (call-scute 'rfc3339-now)))
      (check (= 20 (length now)) "~S is not the shape the broker writes" now)
      (check (char= #\Z (char now 19)) "~S is not in UTC" now)
      (check (string<= "2026-01-01T00:00:00Z" now) "~S sorts before 2026" now))))

(deftest test-refusals-are-reported-with-the-run-they-happened-during
  "Both kinds go into one list: what the broker tied to this run, and what it
refused during the run without being able to tie it to anything."
  (let ((events (list "{\"ts\":\"2026-09-18T21:52:51Z\",\"event\":\"deny\",\"destination\":\"api.github.com\",\"deny_reason\":\"no keyfence token found in request headers\"}"
                      "{\"ts\":\"2026-09-18T21:52:52Z\",\"event\":\"allow\",\"destination\":\"api.github.com\",\"task_id\":\"scute-1-A\"}")))
    (let ((said (with-output-to-string (stream)
                  (call-scute 'report-broker-refusals events stream))))
      (check (search "during this run" said)
             "the report claims more than it knows: ~S" said)
      (check (search "no keyfence token found" said)
             "the reason a sandbox most often fails was not reported: ~S" said))))

;;── The broker without a credential to broker ──────────────────────────────────
;;;
;;; The default network sends every connection to the broker, so a run that asks
;;; it to hold nothing still needs it: a port to send traffic to, and the public CA
;;; certificate without which every TLS handshake inside the sandbox fails.
;;;
;;; Neither of those is protected by the control key, and requiring it anyway made
;;; ordinary runs fail wherever this process could not read the key -- a refusal for
;;; the sake of a secret nobody was sending.

(defun write-keyless-broker (port)
  "A broker that answers /ca to anyone and demands a key for its token API, which
is what KeyFence does: a CA certificate is public by definition."
  (let ((path (format nil "~A.py" (scratch-pathname "keyless"))))
    (with-open-file (stream path :direction :output :if-exists :supersede)
      (dolist (line (list
                     "import http.server"
                     "class H(http.server.BaseHTTPRequestHandler):"
                     "    def log_message(self,*a): pass"
                     "    def do_GET(self):"
                     "        if self.path.startswith('/ca'):"
                     "            self.send_response(200)"
                     "            self.send_header('Content-Type','application/x-pem-file')"
                     "            self.end_headers()"
                     "            self.wfile.write(b'-----BEGIN CERTIFICATE-----\\nnot-a-real-ca\\n-----END CERTIFICATE-----\\n')"
                     "        elif self.path.startswith('/health'):"
                     "            self.send_response(200); self.end_headers()"
                     "            self.wfile.write(b'{\"status\":\"ok\"}')"
                     "        else:"
                     "            self.send_error(401)"
                     (format nil "http.server.HTTPServer(('127.0.0.1',~D),H).serve_forever()"
                             port)))
        (write-line line stream)))
    path))

(deftest test-a-run-with-no-credentials-does-not-need-the-control-key
  (if (plusp (cffi:foreign-funcall "system" :string
                                  "command -v python3 >/dev/null 2>&1" :int))
      (format *error-output* "~&SKIP: no python3 to stand in for a broker~%")
      (let ((helper nil))
        (unwind-protect
             (progn
               (setf helper (call-scute 'start-helper-arguments
                                        (list "/usr/bin/python3"
                                              (write-keyless-broker +broker-control-port+))))
               (check (call-scute 'wait-for-port +broker-control-port+ 10)
                      "the stand-in broker never answered")
               ;; A policy with a proxy and no [credentials] table: the default
               ;; network, written out so the test does not depend on the default.
               (let* ((text (format nil "~
[filesystem]~%read-execute = [\"/usr\"]~%read = [\"/etc\"]~%~%~
[network]~%mode = \"host\"~%proxy = \"http://127.0.0.1:~D\"~%"
                                    +broker-proxy-port+))
                      (policy (call-scute 'validate-sandbox-policy
                                          (call-scute 'parse-policy-text text)))
                      (plan (call-scute 'compile-launch-plan policy '("/bin/true")))
                      (given nil))
                 (check (call-scute 'sandbox-policy-broker policy)
                        "a policy whose egress goes through the broker got no broker")
                 (call-scute 'call-with-broker plan
                             (lambda (revised) (setf given revised)))
                 (check given "the run was refused for want of a key it did not need")
                 ;; And the certificate reached the sandbox, which is the whole
                 ;; reason to talk to the broker at all when holding no secret.
                 (check (find-if (lambda (entry)
                                   (and (> (length entry) 14)
                                        (string= "SSL_CERT_FILE=" entry :end2 14)))
                                 (call-scute 'launch-plan-environment given))
                        "the sandbox was given no CA certificate to trust")))
          (when helper (call-scute 'stop-helper helper))))))
