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
(defun broker-test-socket ()
  (format nil "~A/control.sock" (scratch-pathname "broker-control")))

(defun prepare-broker-test-socket ()
  (let ((path (broker-test-socket)))
    (ensure-directories-exist path)
    (sb-posix:chmod (directory-namestring path) #o700)
    (delete-scratch path)
    path))

(defun wait-for-broker-test-socket ()
  (wait-until (lambda () (call-scute 'broker-answering-p (broker-test-socket))) 100))

(defun write-fake-broker (control-socket record)
  "A script answering the control API KeyFence answers, writing what it saw."
  (let ((path (format nil "~A.py" (scratch-pathname "broker"))))
    (with-open-file (stream path :direction :output :if-exists :supersede)
      (dolist (line (list
                     "import json,http.server,socketserver"
                     "class H(http.server.BaseHTTPRequestHandler):"
                     "    def log_message(self,*a): pass"
                     "    def do_GET(self):"
                     "        self.send_response(200); self.end_headers()"
                     "        if self.path.startswith('/tokens'):"
                     "            self.wfile.write(b'[]')"
                     "        elif self.path.startswith('/ca'):"
                     "            self.wfile.write(b'-----BEGIN CERTIFICATE-----\\nfixture\\n-----END CERTIFICATE-----\\n')"
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
                     "        held=body.get('credential') or body.get('credential_ref') or body.get('ssh_private_key')"
                     "        t={'token':'kf_'+held[::-1]}"
                     "        self.wfile.write(json.dumps(t).encode())"
                     "    def do_DELETE(self):"
                     (format nil "        open(~S,'a').write(json.dumps({'revoked':self.path})+chr(10))"
                             record)
                     "        self.send_response(204); self.end_headers()"
                     "class Server(socketserver.UnixStreamServer): allow_reuse_address=True"
                     (format nil "Server(~S,H).serve_forever()" control-socket)))
        (write-line line stream)))
    path))

(defun start-fake-broker (record)
  (let ((script (write-fake-broker (prepare-broker-test-socket) record)))
    (let ((helper (call-scute 'start-helper-arguments
                              (list "/usr/bin/python3" script))))
      (unless (wait-for-broker-test-socket)
        (call-scute 'stop-helper helper)
        (error "the stand-in broker never answered"))
      helper)))

(defun brokered-policy-text ()
  (format nil "~
[filesystem]~%read-execute = [\"/usr\"]~%read = [\"/etc\"]~%~%~
[network]~%mode = \"host\"~%proxy = \"http://127.0.0.1:~D\"~%~%~
[credentials]~%broker = \"keyfence\"~%control-socket = ~S~%~%~
[credentials.anthropic]~%secret-file = ~S~%destinations = [\"api.anthropic.com\"]~%~
env = \"ANTHROPIC_API_KEY\"~%"
          +broker-proxy-port+ (broker-test-socket)
          (format nil "~A.secret" (scratch-pathname "broker"))))

(defun ssh-credential-policy-text (key-file)
  "A policy whose credential is an ssh key the broker holds for a forge."
  (format nil "~
[filesystem]~%read-execute = [\"/usr\"]~%read = [\"/etc\"]~%~%~
[network]~%mode = \"proxied\"~%proxy = \"http://127.0.0.1:~D\"~%~%~
[credentials]~%broker = \"keyfence\"~%control-socket = ~S~%~%~
[credentials.forge]~%secret-file = ~S~%ssh-user = \"git\"~%~
destinations = [\"forge.example.com\"]~%"
          +broker-proxy-port+ (broker-test-socket) key-file))

(deftest test-a-control-socket-that-never-answers-is-an-error-not-a-debugger
  "A socket can exist and serve nobody -- systemd holds one open for a service
that is already running, so nothing ever accepts on it -- and Scute used to meet
that with an unhandled deadline and an SBCL debugger prompt, which is the worst
thing a command-line tool can do to somebody.

The catch is that a deadline is not an error: SBCL signals DEADLINE-TIMEOUT as a
plain condition, so the handler that catches everything else lets it past."
  (let* ((directory (scratch-pathname "deaf-broker"))
         (path (format nil "~A/control.sock" directory))
         (socket nil))
    (unwind-protect
         (progn
           (ensure-directories-exist (format nil "~A/" directory))
           ;; Listening and never accepting: the connect succeeds into the
           ;; backlog, the request goes out, and the answer never comes.
           (setf socket (listening-unix-socket path))
           (let ((refusal (nth-value 1 (ignore-errors
                                        (call-scute 'unix-control-request
                                                    path "GET" "/health"
                                                    :seconds 1)))))
             (check refusal "a socket that never answers did not raise anything")
             (check (and refusal (search "did not answer"
                                         (princ-to-string refusal)))
                    "the refusal does not say what happened: ~A" refusal))
           ;; And the question Scute actually asks at startup answers no rather
           ;; than exploding.
           (check (null (call-scute 'broker-answering-p path))
                  "a deaf socket was taken for a working broker"))
      (when socket (ignore-errors (sb-bsd-sockets:socket-close socket)))
      (ignore-errors (delete-file path))
      (ignore-errors (sb-posix:rmdir directory)))))

(deftest test-an-ssh-credential-is-a-key-the-broker-keeps
  "An ssh key is the credential kind with no header to swap, so the broker holds
it and answers the sandbox's ssh itself.  What Scute has to get right is the
request -- the key goes up as an ssh key rather than as something to put in a
header -- and the arrangement around it: the token lands where sshpass reads it,
port 22 is sent to the bastion rather than to the host the command named, and the
plan says so out loud."
  (if (plusp (cffi:foreign-funcall "system" :string
                                  "command -v python3 >/dev/null 2>&1" :int))
      (format *error-output* "~&SKIP: no python3 to stand in for a broker~%")
      (let* ((record (format nil "~A.jsonl" (scratch-pathname "broker-ssh-record")))
             (key-file (format nil "~A.key" (scratch-pathname "broker-ssh")))
             (key "-----BEGIN OPENSSH PRIVATE KEY-----not-a-real-key")
             (helper nil))
        (with-open-file (stream key-file :direction :output :if-exists :supersede)
          (write-line key stream))
        (sb-posix:chmod key-file #o600)
        (unwind-protect
             (progn
               (setf helper (start-fake-broker record))
               (let* ((policy (call-scute 'validate-sandbox-policy
                                          (call-scute 'parse-policy-text
                                                      (ssh-credential-policy-text key-file))))
                      (plan (call-scute 'compile-launch-plan policy '("/bin/true")))
                      (seen nil)
                      (shim-directory nil)
                      (shim-text nil))
                 (check (equal "127.0.0.1:10211" (call-scute 'launch-plan-ssh-proxy plan))
                        "the plan does not send ssh to the bastion: ~S"
                        (call-scute 'launch-plan-ssh-proxy plan))
                 (check (member 22 (call-scute 'launch-plan-connect-tcp plan))
                        "port 22 is not permitted, so the redirect would never ~
                         see the connection: ~S"
                        (call-scute 'launch-plan-connect-tcp plan))
                 ;; Read while the sandbox would be running: the shim exists
                 ;; for exactly as long as the run does.
                 (call-scute 'call-with-broker plan
                             (lambda (revised)
                               (setf seen revised)
                               (let* ((path (find-if (lambda (entry)
                                                       (and (> (length entry) 5)
                                                            (string= "PATH=" entry :end2 5)))
                                                     (call-scute 'launch-plan-environment revised)))
                                      (value (and path (subseq path 5)))
                                      (directory (and value
                                                      (subseq value 0 (position #\: value)))))
                                 (setf shim-directory directory)
                                 (when (and directory
                                            (probe-file (format nil "~A/ssh" directory)))
                                   (setf shim-text
                                         (with-open-file (stream (format nil "~A/ssh" directory))
                                           (let ((text (make-string (file-length stream))))
                                             (subseq text 0 (read-sequence text stream)))))))))
                 (let ((environment (call-scute 'launch-plan-environment seen))
                       (first-on-path shim-directory))
                   ;; The credential is not in the environment at all.  An agent
                   ;; decides what its subprocesses inherit -- codex hands its
                   ;; shells a core set and nothing else -- so a token in a
                   ;; variable reaches the agent and stops there.  What the
                   ;; sandbox gets instead is an ssh of its own, first on PATH,
                   ;; which is the one variable every agent passes down.
                   (check (notany (lambda (entry) (search "kf_" entry)) environment)
                          "the token was in the environment, where an agent may ~
                           filter it away or write it to a log: ~S" environment)
                   (check (notany (lambda (entry) (search "BEGIN OPENSSH" entry))
                                  environment)
                          "the key itself reached the sandbox's environment")
                   (check (and first-on-path (search "scute-ssh-" first-on-path))
                          "the sandbox's own ssh is not first on its PATH: ~S"
                          first-on-path)
                   (check shim-text
                          "nothing was written for the sandbox to run as ssh")
                   (when shim-text
                     (check (search "SSH_ASKPASS" shim-text)
                            "the shim does not answer the bastion's password ~
                             prompt: ~A" shim-text)
                     (check (search "/ssh " shim-text)
                            "the shim does not run a real ssh by an absolute ~
                             path, so it would find itself: ~A" shim-text))
                   ;; And it is taken away again: a token left in the runtime
                   ;; directory outlives the run that minted it.
                   (check (not (probe-file first-on-path))
                          "the shim directory survived the run: ~A" first-on-path))
                 (let ((sent (with-open-file (stream record) (read-line stream nil ""))))
                   (check (search "ssh_private_key" sent)
                          "the key was not offered to the broker as an ssh key: ~A"
                          sent)
                   (check (and (search "ssh_username" sent) (search "\"git\"" sent))
                          "the broker was not told who to log in as: ~A" sent)
                   (check (search "forge.example.com" sent)
                          "the token was not locked to the forge: ~A" sent))))
          (when helper (call-scute 'stop-helper helper))
          (ignore-errors (delete-file key-file))
          (ignore-errors (delete-file record))))))

(deftest test-an-ssh-credential-is-kept-to-one-key-and-one-host
  "Two refusals, both about the broker's side of the arrangement.  A ref names a
credential the broker swaps into a header, which would issue a token the bastion
cannot use.  And the bastion connects to the destination the token names, taking
the first if there are several -- so a second destination is one the sandbox
would never reach, silently."
  (flet ((refusal (text)
           (nth-value 1 (ignore-errors
                         (call-scute 'validate-sandbox-policy
                                     (call-scute 'parse-policy-text text))))))
    (let ((with-ref (refusal (format nil "~
[filesystem]~%read-execute = [\"/usr\"]~%~%~
[credentials.forge]~%ref = \"forge\"~%ssh-user = \"git\"~%~
destinations = [\"forge.example.com\"]~%")))
          (two-hosts (refusal (format nil "~
[filesystem]~%read-execute = [\"/usr\"]~%~%~
[credentials.forge]~%secret-file = \"/etc/hostname\"~%ssh-user = \"git\"~%~
destinations = [\"one.example.com\", \"two.example.com\"]~%"))))
      (check (and with-ref (search "secret-file" (princ-to-string with-ref)))
             "an ssh credential naming a ref was not refused as such: ~A" with-ref)
      (check (and two-hosts (search "one host" (princ-to-string two-hosts)))
             "an ssh credential with two destinations was not refused as such: ~A"
             two-hosts))))

(deftest test-an-ssh-credential-needs-the-redirect
  "Without the kernel redirect, port 22 goes to the host the command named, which
would be handed a password it has never heard of -- and the failure would read as
a bad key rather than a missing capability.  Refused instead, with the remedy."
  (let* ((text (ssh-credential-policy-text "/etc/hostname"))
         (host-mode (let ((in (search "mode = \"proxied\"" text)))
                      (concatenate 'string (subseq text 0 in) "mode = \"host\""
                                   (subseq text (+ in (length "mode = \"proxied\""))))))
         (refusal (nth-value 1 (ignore-errors
                                (call-scute 'compile-launch-plan
                                            (call-scute 'validate-sandbox-policy
                                                        (call-scute 'parse-policy-text
                                                                    host-mode))
                                            '("/bin/true"))))))
    (check refusal "an ssh credential was accepted with no redirect to use")
    (check (search "make egress" (princ-to-string refusal))
           "the refusal does not say how to get the redirect: ~A" refusal)))

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
      (check (equal (broker-test-socket) (call-scute 'broker-settings-control-socket broker))
             "the control socket was not read from the policy"))))

(deftest test-a-broker-that-will-not-start-is-quoted-not-guessed-about
  "A broker that fails writes the reason down -- a port already in use, a
certificate it cannot read -- and that line is the answer.  Scute used to guess
instead, and its guess named the only cause it knew of: a KeyFence too old for
Unix control.  Anyone whose broker failed for any other reason was sent to
upgrade something that was already new enough.

Both halves are checked, because the guess is still the right thing to say when
the broker wrote nothing at all."
  (let* ((directory (scratch-pathname "broker-log"))
         (log (format nil "~A/broker.log" directory)))
    (unwind-protect
         (progn
           (ensure-directories-exist (format nil "~A/" directory))
           (with-open-file (stream log :direction :output :if-exists :supersede)
             (write-line "2026/09/20 17:54:01 proxy listening on 127.0.0.1:10210" stream)
             (write-line "2026/09/20 17:54:01 ssh: listen 127.0.0.1:10211: bind: address already in use"
                         stream)
             (write-line "" stream))
           (let ((complaint (call-scute 'broker-last-words log)))
             (check (equal "ssh: listen 127.0.0.1:10211: bind: address already in use"
                           complaint)
                    "the broker's last words came back as ~S" complaint))
           (with-open-file (stream log :direction :output :if-exists :supersede)
             (declare (ignore stream)))
           (check (null (call-scute 'broker-last-words log))
                  "an empty log answered with something")
           (check (null (call-scute 'broker-last-words
                                    (format nil "~A/no-such-log" directory)))
                  "a log that does not exist answered with something"))
      (ignore-errors (delete-file log))
      (ignore-errors (sb-posix:rmdir directory)))))

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
          (delete-scratch (broker-test-socket))
          (ignore-errors (sb-posix:rmdir (directory-namestring (broker-test-socket))))
          (delete-scratch record secret-file)))))

(defun write-healthy-stranger (socket)
  "Something that is not a broker, answering 200 on /health as many things do."
  (let ((path (format nil "~A.py" (scratch-pathname "stranger"))))
    (with-open-file (stream path :direction :output :if-exists :supersede)
      (dolist (line (list
                     "import http.server,socketserver"
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
                     (format nil "socketserver.UnixStreamServer(~S,H).serve_forever()" socket)))
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
                                               (prepare-broker-test-socket)))))
               (check (wait-for-broker-test-socket)
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
          (delete-scratch (broker-test-socket))
          (ignore-errors (sb-posix:rmdir (directory-namestring (broker-test-socket))))
          (delete-scratch received secret-file)))))

(defun referencing-policy-text ()
  (format nil "~
[filesystem]~%read-execute = [\"/usr\"]~%read = [\"/etc\"]~%~%~
[network]~%mode = \"host\"~%proxy = \"http://127.0.0.1:~D\"~%~%~
[credentials]~%control-socket = ~S~%~%~
[credentials.anthropic]~%ref = \"anthropic\"~%destinations = [\"api.anthropic.com\"]~%~
env = \"ANTHROPIC_API_KEY\"~%"
          +broker-proxy-port+ (broker-test-socket)))

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
          (delete-scratch (broker-test-socket))
          (ignore-errors (sb-posix:rmdir (directory-namestring (broker-test-socket))))
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
          (delete-scratch (broker-test-socket))
          (ignore-errors (sb-posix:rmdir (directory-namestring (broker-test-socket))))
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

(defun write-keyless-broker (socket)
  "A broker that answers /ca to anyone and demands a key for its token API, which
is what KeyFence does: a CA certificate is public by definition."
  (let ((path (format nil "~A.py" (scratch-pathname "keyless"))))
    (with-open-file (stream path :direction :output :if-exists :supersede)
      (dolist (line (list
                     "import http.server,socketserver"
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
                     "            self.send_response(200); self.end_headers()"
                     "            self.wfile.write(b'[]')"
                     (format nil "socketserver.UnixStreamServer(~S,H).serve_forever()" socket)))
        (write-line line stream)))
    path))

(deftest test-a-run-with-no-credentials-does-not-need-the-control-key
  (if (plusp (cffi:foreign-funcall "system" :string
                                  "command -v python3 >/dev/null 2>&1" :int))
      (format *error-output* "~&SKIP: no python3 to stand in for a broker~%")
      (let ((helper nil)
            (scute::*broker-control-socket* (broker-test-socket)))
        (unwind-protect
             (progn
               (setf helper (call-scute 'start-helper-arguments
                                        (list "/usr/bin/python3"
                                              (write-keyless-broker (prepare-broker-test-socket)))))
               (check (wait-for-broker-test-socket)
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
          (when helper (call-scute 'stop-helper helper))
          (delete-scratch (broker-test-socket))
          (ignore-errors (sb-posix:rmdir (directory-namestring (broker-test-socket))))))))

(deftest test-credentials-need-no-proxy-named-now-that-one-is-the-default
  "A policy asking for a credential is already routed through the broker, so
naming its address as well is ceremony.  What cannot work is still refused: a
policy that asks for a credential and then names a network with no broker in it."
  (let ((defaulted (call-scute 'validate-sandbox-policy
                               (call-scute 'parse-policy-text
                                           (format nil "~
[filesystem]~%read = [\"/etc\"]~%~%~
[credentials.anthropic]~%ref = \"anthropic\"~%~
destinations = [\"api.anthropic.com\"]~%env = \"ANTHROPIC_API_KEY\"~%")))))
    (check (string= (scute-value '+default-broker-proxy+)
                    (call-scute 'sandbox-policy-proxy defaulted))
           "a credentialled policy was not routed through the broker: ~S"
           (call-scute 'sandbox-policy-proxy defaulted))
    (check (call-scute 'sandbox-policy-broker defaulted)
           "no broker settings for a policy asking for a credential"))
  (check (typep (nth-value 1 (ignore-errors
                              (call-scute 'validate-sandbox-policy
                                          (call-scute 'parse-policy-text
                                                      (format nil "~
[filesystem]~%read = [\"/etc\"]~%~%~
[network]~%mode = \"host\"~%~%~
[credentials.anthropic]~%ref = \"anthropic\"~%~
destinations = [\"api.anthropic.com\"]~%env = \"ANTHROPIC_API_KEY\"~%")))))
                'scute:policy-error)
         "a credential was accepted beside a network that goes around the broker"))

;;── A credential written where a program will look for it ──────────────────────
;;;
;;; An environment variable is how most programs take a credential, and not all of
;;; them. Codex reads CODEX_HOME/auth.json, decodes the token it finds there, and
;;; refreshes anything it cannot parse -- so an opaque token cannot reach it at
;;; all, and what it is handed has to be shaped like a token with the broker's one
;;; inside it.

(deftest test-a-template-and-a-file-are-a-pair
  (flet ((refused (text)
           (typep (nth-value 1 (ignore-errors
                                (call-scute 'validate-sandbox-policy
                                            (call-scute 'parse-policy-text text))))
                  'scute:policy-error)))
    (check (refused (format nil "~
[filesystem]~%read = [\"/etc\"]~%~%[credentials.x]~%ref = \"x\"~%~
destinations = [\"api.example.test\"]~%file = \"/tmp/x.json\"~%"))
           "a file with no template was accepted")
    (check (refused (format nil "~
[filesystem]~%read = [\"/etc\"]~%~%[credentials.x]~%ref = \"x\"~%~
destinations = [\"api.example.test\"]~%template = \"/tmp/x.tmpl\"~%"))
           "a template with no file was accepted")
    (check (refused (format nil "~
[filesystem]~%read = [\"/etc\"]~%~%[credentials.x]~%ref = \"x\"~%~
destinations = [\"api.example.test\"]~%"))
           "a credential with neither env nor file was accepted")
    (check (refused (format nil "~
[filesystem]~%read = [\"/etc\"]~%~%[credentials.x]~%ref = \"x\"~%~
destinations = [\"api.example.test\"]~%file = \"/tmp/x.json\"~%~
template = \"/tmp/definitely-not-a-template\"~%"))
           "a template that does not exist was accepted")))

(deftest test-a-credential-can-arrive-as-a-file-instead-of-a-variable
  "env is not required when a file is named: the programs this exists for do not
read an environment variable at all."
  (let ((template (scratch-pathname "template")))
    (unwind-protect
         (progn
           (with-open-file (stream template :direction :output :if-exists :supersede)
             (write-string "{\"token\": \"header.payload.${token}\"}" stream))
           (let* ((text (format nil "~
[filesystem]~%read = [\"/etc\"]~%~%[credentials.model]~%ref = \"model\"~%~
destinations = [\"api.example.test\"]~%file = \"~A.out\"~%template = \"~A\"~%"
                                template template))
                  (policy (call-scute 'validate-sandbox-policy
                                      (call-scute 'parse-policy-text text)))
                  (request (first (call-scute 'sandbox-policy-credentials policy))))
             (check (null (call-scute 'credential-request-variable request))
                    "a variable appeared where the policy named none")
             (check (string= (format nil "~A.out" template)
                             (call-scute 'credential-request-file request))
                    "the file was lost")))
      (delete-scratch template))))

(deftest test-the-token-is-rendered-into-the-file-and-nothing-else-is
  (let* ((template (scratch-pathname "render-template"))
         (destination (format nil "~A.json" (scratch-pathname "render-out"))))
    (unwind-protect
         (progn
           (with-open-file (stream template :direction :output :if-exists :supersede)
             (write-string "{\"access_token\": \"head.body.${token}\", \"refresh_token\": \"none\"}"
                           stream))
           (let* ((text (format nil "~
[filesystem]~%read = [\"/etc\"]~%~%[credentials.model]~%ref = \"model\"~%~
destinations = [\"api.example.test\"]~%file = \"~A\"~%template = \"~A\"~%"
                                destination template))
                  (policy (call-scute 'validate-sandbox-policy
                                      (call-scute 'parse-policy-text text)))
                  (request (first (call-scute 'sandbox-policy-credentials policy)))
                  (written (call-scute 'render-credential-file request "kf_written")))
             (let ((contents (read-file-string (call-scute 'rendered-credential-path written))))
               (check (search "head.body.kf_written" contents)
                      "the token is not where the template put it: ~S" contents)
               (check (not (search "${token}" contents))
                      "the placeholder survived: ~S" contents)
               (check (search "\"refresh_token\": \"none\"" contents)
                      "the rest of the template was lost: ~S" contents))
             ;; Nobody else's business, even though what it holds is only a token.
             (check (= #o600 (logand #o777 (sb-posix:stat-mode (sb-posix:stat (call-scute 'rendered-credential-path written)))))
                    "the rendered file is readable by others")
             (call-scute 'remove-credential-files (list written))))
      (delete-scratch template destination))))

(deftest test-a-template-with-nowhere-for-the-token-is-refused
  "Rendering it would hand the sandbox a file that looks right and authenticates
nothing, which is a worse failure than saying so."
  (let* ((template (scratch-pathname "empty-template"))
         (destination (format nil "~A.json" (scratch-pathname "empty-out"))))
    (unwind-protect
         (progn
           (with-open-file (stream template :direction :output :if-exists :supersede)
             (write-string "{\"nothing\": \"here\"}" stream))
           (let* ((text (format nil "~
[filesystem]~%read = [\"/etc\"]~%~%[credentials.model]~%ref = \"model\"~%~
destinations = [\"api.example.test\"]~%file = \"~A\"~%template = \"~A\"~%"
                                destination template))
                  (policy (call-scute 'validate-sandbox-policy
                                      (call-scute 'parse-policy-text text)))
                  (request (first (call-scute 'sandbox-policy-credentials policy)))
                  (refusal (nth-value 1 (ignore-errors
                                         (call-scute 'render-credential-file
                                                     request "kf_unused")))))
             (check refusal "a template with no ${token} in it was rendered anyway")
             (check (not (probe-file destination))
                    "a file was written for a template that could not work")))
      (delete-scratch template destination))))

(deftest test-security-credential-output-never-follows-symlinks
  (let* ((directory (format nil "~A/" (scratch-pathname "safe-render")))
         (template (concatenate 'string directory "template"))
         (victim (concatenate 'string directory "victim"))
         (link (concatenate 'string directory "link")))
    (ensure-directories-exist template)
    (unwind-protect
         (progn
           (with-open-file (out template :direction :output :if-exists :supersede)
             (write-string "changed ${token}" out))
           (with-open-file (out victim :direction :output :if-exists :supersede)
             (write-string "original" out))
           (sb-posix:symlink victim link)
           (dolist (destination (list link victim))
             (let* ((request (call-scute 'make-credential-request "x" nil '("example.test")
                                         nil nil "ref" destination template))
                    (refusal (nth-value 1 (ignore-errors
                                           (call-scute 'render-credential-file request "dummy")))))
               (check refusal "credential output replaced existing path ~A" destination)
               (check (equal "original" (read-file-string victim))
                      "credential output overwrote the host file")))
           (delete-file link)
           (sb-posix:symlink directory link)
           (let* ((destination (concatenate 'string link "/new-file"))
                  (request (call-scute 'make-credential-request "x" nil '("example.test")
                                      nil nil "ref" destination template)))
             (check (nth-value 1 (ignore-errors
                                  (call-scute 'render-credential-file request "dummy")))
                    "credential output followed a symlink ancestor")))
      (delete-scratch link victim template (concatenate 'string directory "new-file"))
      (ignore-errors (sb-posix:rmdir directory)))))

(deftest test-security-control-never-falls-back-to-tcp
  (let* ((name (find-symbol "LOOPBACK-REQUEST" :scute))
         (original (symbol-function name))
         (sent nil)
         (settings (call-scute 'make-broker-settings :keyfence 18810 "/tmp/scute-no-control-393fd9.sock"))
         (broker (call-scute '%make-broker settings nil nil)))
    (unwind-protect
         (progn
           (setf (symbol-function name)
                 (lambda (&rest arguments)
                   (declare (ignore arguments))
                   (setf sent t)
                   (call-scute '%make-http-response 200 "[]")))
           (check (nth-value 1 (ignore-errors
                                (call-scute 'control-request broker "POST" "/tokens"
                                            :body "dummy-secret")))
                  "missing Unix control did not refuse the request")
           (check (not sent) "control secrets were sent over unauthenticated TCP"))
      (setf (symbol-function name) original))))

(deftest test-security-broker-rejects-another-users-peer
  (check (nth-value 1 (ignore-errors
                       (call-scute 'require-broker-peer-uid (1+ (sb-posix:geteuid)))))
         "a different user's broker peer was accepted")
  (check (call-scute 'require-broker-peer-uid (sb-posix:geteuid))
         "our broker peer was refused"))

(deftest test-security-credential-cleanup-keeps-the-pinned-directory
  (let* ((root (format nil "~A/" (scratch-pathname "pinned-cleanup")))
         (parent (concatenate 'string root "original/"))
         (moved (concatenate 'string root "moved/"))
         (destination (concatenate 'string parent "token"))
         (file nil))
    (unwind-protect
         (progn
           (setf file (call-scute 'write-credential-output destination "dummy"))
           (sb-posix:rename parent moved)
           (ensure-directories-exist destination)
           (with-open-file (out destination :direction :output)
             (write-string "replacement" out))
           (call-scute 'remove-credential-files (list file))
           (check (not (probe-file (concatenate 'string moved "token")))
                  "cleanup left the original token behind")
           (check (equal "replacement" (read-file-string destination))
                  "cleanup deleted a replacement directory's file"))
      (when file (call-scute 'remove-credential-files (list file)))
      (delete-scratch destination (concatenate 'string moved "token"))
      (dolist (path (list parent moved root)) (ignore-errors (sb-posix:rmdir path))))))

(deftest test-security-unix-peer-credentials-come-from-the-kernel
  (cffi:with-foreign-object (pair :int 2)
    (check (zerop (cffi:foreign-funcall "socketpair" :int 1 :int 1 :int 0 :pointer pair :int))
           "could not create a local socket pair")
    (let ((socket (make-instance 'sb-bsd-sockets:local-socket :type :stream
                                :descriptor (cffi:mem-aref pair :int 0))))
      (unwind-protect
           (check (call-scute 'authenticate-broker-socket socket)
                  "a kernel-authenticated peer with our uid was refused")
        (sb-bsd-sockets:socket-close socket)
        (sb-posix:close (cffi:mem-aref pair :int 1))))))

(deftest test-security-control-port-policies-require-migration
  (check (typep (nth-value 1 (ignore-errors
                              (call-scute 'validate-sandbox-policy
                                          (call-scute 'parse-policy-text
                                            (format nil "[filesystem]~%read=[\"/etc\"]~%[credentials]~%control-port=10212~%[credentials.x]~%ref=\"x\"~%env=\"X\"~%destinations=[\"example.test\"]~%")))))
                'scute:policy-error)
         "legacy TCP control settings were silently accepted"))

(deftest test-security-credential-read-grant-pins-the-created-file
  (let* ((root (format nil "~A/" (scratch-pathname "pinned-grant")))
         (destination (concatenate 'string root "token"))
         (moved (concatenate 'string root "moved"))
         (victim (concatenate 'string root "victim"))
         (file nil))
    (ensure-directories-exist destination)
    (unwind-protect
         (progn
           (setf file (call-scute 'write-credential-output destination "dummy-token"))
           (sb-posix:rename destination moved)
           (with-open-file (out victim :direction :output) (write-string "host-secret" out))
           (sb-posix:symlink victim destination)
           (check (equal "dummy-token"
                         (read-file-string (call-scute 'rendered-credential-rule-path file)))
                  "replacing token pathname redirected the read grant"))
      (when file (call-scute 'remove-credential-files (list file)))
      (delete-scratch destination moved victim)
      (ignore-errors (sb-posix:rmdir root)))))
