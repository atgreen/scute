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
