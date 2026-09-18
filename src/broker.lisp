;;; broker.lisp
;;;
;;; SPDX-License-Identifier: MIT
;;;
;;; Copyright (C) 2026 Anthony Green

(in-package #:scute)

;;; Giving a sandbox a credential it cannot read.
;;;
;;; The environment filter already means a sandboxed command carries only the
;;; variables a policy named -- but a command that legitimately needs an API key
;;; still ends up holding one, and anything it runs can read it out of its own
;;; environment and send it anywhere.  A credential broker breaks that: it holds
;;; the real secret, the sandbox holds an opaque token, and the swap happens in
;;; the broker on each request.
;;;
;;; KeyFence is such a broker, and doing this by hand is a hundred lines of
;;; shell: build two container images, create a pod so both sides share
;;; localhost, mint a control API key, POST the real credential to the token
;;; API, read back the token, then launch the agent with HTTPS_PROXY, a CA
;;; bundle and the token in its environment.  Scute already starts processes,
;;; already filters environments, and already decides what the sandbox may
;;; reach, so all of that is work it can do in one command instead.
;;;
;;; The part Scute contributes that a proxy cannot do for itself: HTTPS_PROXY is
;;; a convention.  An agent that ignores it -- or a subprocess that never read
;;; it, or a prompt-injected one that is told not to -- connects straight out
;;; and the broker never sees the request.  Under a policy naming a proxy, the
;;; kernel permits that one port and refuses every other address, so going
;;; around the swap is not a thing the command can choose to do.


;;; The broker is meant to be a service.  KeyFence keeps one certificate
;;; authority and one credential store for as long as it runs, so a broker that
;;; outlives any single sandbox is the arrangement that actually fits: a run
;;; costs no startup, the trust an agent's runtimes are configured with stays
;;; constant, and the process holding the secrets is one systemd can confine --
;;; see releng/keyfence.service.  Scute starts one itself only when there is
;;; none to attach to, which keeps a machine without the service working.

(defstruct (broker (:constructor %make-broker
                       (settings helper control-key certificate)))
  (settings nil :read-only t)
  (helper nil :read-only t)        ; NIL when we attached to one already running
  (control-key nil :read-only t)   ; authorises control API requests
  (certificate nil :read-only t)   ; the CA the sandbox has to trust
  (tokens nil))                    ; minted here, revoked when the run ends

(defparameter +broker-programs+ '((:keyfence . "keyfence"))
  "The brokers Scute knows how to drive, and the program each one is.

A closed set on purpose.  A policy selects a broker by name; it cannot give a
command line.  A policy travels with the code being sandboxed, and one that
could name an arbitrary program to run on the host would be a way to run
anything at all -- so what a policy can do is ask for the broker Scute already
knows, started with arguments Scute writes.")

(defun broker-program (settings)
  (or (cdr (assoc (broker-settings-name settings) +broker-programs+))
      (setup-error :start-broker
                   :detail (format nil "no broker named ~A"
                                   (broker-settings-name settings)))))

;;── Secrets, on the supervisor's side of the boundary ──────────────────────────

(defun random-hex (bytes)
  "BYTES of randomness from the kernel, in hex."
  (with-open-file (stream "/dev/urandom" :element-type '(unsigned-byte 8))
    (with-output-to-string (out)
      (dotimes (index bytes)
        (format out "~2,'0x" (read-byte stream))))))

(defun read-secret (pathname name)
  "The secret in PATHNAME, with the trailing newline an editor leaves removed.

Read here, in the supervisor, and handed to the broker over the loopback
interface.  It is never put in the sandbox's environment, never written into a
command line where /proc would show it, and never passed through a shell."
  (let ((truename (probe-file pathname)))
    (unless truename
      (setup-error :read-secret
                   :detail (format nil "credential ~A: ~A does not exist"
                                   name pathname)))
    (let ((mode (sb-posix:stat-mode (sb-posix:stat truename))))
      (unless (zerop (logand mode #o077))
        (warn "credential ~A: ~A is readable by more than you (mode ~3,'0o)"
              name pathname (logand mode #o777))))
    (let* ((text (with-open-file (stream truename :external-format :utf-8)
                   (let ((buffer (make-string (min (file-length stream) 65536))))
                     (subseq buffer 0 (read-sequence buffer stream)))))
           (secret (string-trim '(#\Space #\Tab #\Newline #\Return) text)))
      (when (zerop (length secret))
        (setup-error :read-secret
                     :detail (format nil "credential ~A: ~A is empty" name pathname)))
      secret)))

;;── Finding one, or failing that starting one ──────────────────────────────────

(defparameter +broker-data-directory+ "~/.keyfence/"
  "Where KeyFence keeps the certificate authority it signs with, and where the
service unit Scute ships puts the control API key.")

(defun broker-certificate-path ()
  "The CA certificate a broker on this machine signs with.

A broker has to terminate TLS to see the header it swaps, so the sandbox must
trust its CA.  That certificate lives in the broker's own data directory rather
than being exported per run, which is the other reason a long-lived broker is
nicer to live with: the trust stays put between runs."
  (expand-home (concatenate 'string +broker-data-directory+ "ca/ca.pem")))

(defun broker-control-key-from-host ()
  "The control API key for a broker already running on this machine.

From the environment when the operator put it there, and otherwise from a file
beside the CA, which is where the shipped service unit writes it.  A broker
started without a key accepts unauthenticated control requests, so finding none
is not an error here -- whether one was needed is the broker's answer to give."
  (or (sb-posix:getenv "KEYFENCE_API_KEY")
      (let ((path (expand-home (concatenate 'string +broker-data-directory+ "api-key"))))
        (when (probe-file path)
          (let ((key (string-trim '(#\Space #\Tab #\Newline #\Return)
                                  (with-open-file (stream path)
                                    (or (read-line stream nil "") "")))))
            (when (plusp (length key)) key))))))

(defun broker-answering-p (port)
  "Whether anything is listening on PORT and calls itself healthy."
  (handler-case (= 200 (http-response-status
                        (loopback-request port "GET" "/health" :seconds 2)))
    (error () nil)))

(defun identify-broker (port key)
  "What is answering on PORT: :BROKER, :UNAUTHORIZED, or NIL for anything else.

Health is not identity.  Attaching means posting the operator's plaintext
credential to whatever is on that port, so it is not enough that something there
answers 200 -- plenty of things would.  A broker is recognised by its control
API: listing tokens is a request only a broker understands, and it answers with
a JSON array.  Anything that does not is left alone, with the secret unsent."
  (handler-case
      (let ((response (loopback-request port "GET" "/tokens" :seconds 2
                                        :headers (when key
                                                   (list (cons "Authorization"
                                                               (format nil "Bearer ~A"
                                                                       key)))))))
        (case (http-response-status response)
          ((200) (let ((body (string-left-trim '(#\Space #\Tab #\Newline #\Return)
                                               (http-response-body response))))
                   (when (and (plusp (length body)) (char= #\[ (char body 0)))
                     :broker)))
          ((401 403) :unauthorized)
          (t nil)))
    (error () nil)))

(defun fetch-broker-certificate (port)
  "Ask the broker for its CA certificate and write it where the sandbox can read.

Better than assuming where the broker keeps its data directory, which is the sort
of thing that goes wrong quietly: the sandbox trusts the wrong CA and the failure
arrives as a TLS error that reads like a network fault.  The certificate is
public -- every agent behind the proxy has to trust it -- so asking for it over
the control API costs nothing.

Answers the path written, or NIL if this broker does not serve one, in which case
the caller falls back to looking where brokers usually put it."
  (handler-case
      (let ((response (loopback-request port "GET" "/ca" :seconds 5)))
        (when (and (= 200 (http-response-status response))
                   (search "BEGIN CERTIFICATE" (http-response-body response)))
          (let* ((directory (format nil "~A/scute-broker-~D/"
                                    (or (sb-posix:getenv "XDG_RUNTIME_DIR") "/tmp")
                                    (sb-posix:getpid)))
                 (path (concatenate 'string directory "ca.pem")))
            (ensure-directories-exist directory)
            (sb-posix:chmod (string-right-trim "/" directory) #o755)
            (with-open-file (stream path :direction :output :if-exists :supersede
                                         :external-format :utf-8)
              (write-string (http-response-body response) stream))
            (sb-posix:chmod path #o644)
            path)))
    (error () nil)))

(defun start-broker (settings &key program (certificate (broker-certificate-path)))
  "Reach the broker SETTINGS names: the one already running, or a new one.

Attaching is the intended path.  Starting one per run works and keeps a machine
without the service usable, but it pays the broker's startup on every sandbox
and leaves credentials in a process nobody is supervising."
  (let ((control (broker-settings-control-port settings)))
    (if (broker-answering-p control)
        (let ((key (broker-control-key-from-host)))
          (ecase (identify-broker control key)
            (:broker (%make-broker settings nil key
                                   (or (fetch-broker-certificate control) certificate)))
            (:unauthorized
             (setup-error
              :start-broker
              :detail (format nil "a credential broker is running on port ~D but ~
                                   will not accept the control key ~:[Scute could ~
                                   not find~;Scute has~].  Put the right one in ~
                                   KEYFENCE_API_KEY or in ~A"
                              control key
                              (expand-home (concatenate 'string
                                                        +broker-data-directory+
                                                        "api-key")))))
            ((nil)
             (setup-error
              :start-broker
              :detail (format nil "something is listening on port ~D, but it does ~
                                   not answer a credential broker's control API.  ~
                                   Scute will not hand a credential to it"
                              control)))))
        (let* ((executable (resolve-executable (or program (broker-program settings))))
               (control-key (random-hex 16))
               (helper (start-helper-arguments
                        (list executable
                              "-proxy" (format nil ":~D"
                                               (broker-settings-proxy-port settings))
                              "-api" (format nil ":~D" control)
                              ;; Generated per run and gone with it.  It is on a
                              ;; command line, so this user's own processes can
                              ;; read it out of /proc -- but never the sandbox,
                              ;; which is permitted the proxy port and no other
                              ;; address at all.
                              "-api-key" control-key))))
          (let ((broker (%make-broker settings helper control-key certificate)))
            (unless (and (wait-for-port control 15) (broker-answering-p control))
              (stop-helper helper)
              (setup-error :start-broker
                           :detail (format nil "~A did not answer on its control ~
                                                port ~D within fifteen seconds"
                                           executable control)))
            ;; Checked on this side too: a port can be taken between our looking
            ;; and our starting, and what answers may not be what we started.
            (unless (eq :broker (identify-broker control control-key))
              (stop-helper helper)
              (setup-error :start-broker
                           :detail (format nil "what is answering on port ~D is ~
                                                not the broker ~A was started to be"
                                           control executable)))
            (let ((served (fetch-broker-certificate control)))
              (if served
                  (%make-broker settings helper control-key served)
                  broker)))))))

(defun stop-broker (broker)
  "Revoke what this run minted, and stop the broker if this run started it.
A broker we attached to is somebody else's process and outlives the sandbox;
its tokens are still ours to revoke."
  (revoke-tokens broker)
  (when (broker-helper broker)
    (stop-helper (broker-helper broker)))
  ;; A certificate fetched for this run goes with it. One found where the broker
  ;; keeps it belongs to the broker, and is left alone.
  (let ((certificate (namestring (broker-certificate broker))))
    (when (search "/scute-broker-" certificate)
      (ignore-errors (delete-file certificate))
      (ignore-errors (sb-posix:rmdir (directory-namestring certificate)))))
  t)

;;── Tokens ─────────────────────────────────────────────────────────────────────

(defun control-request (broker method path &key body (seconds 10))
  "One request to the broker's control API, authorised if we have a key."
  (loopback-request (broker-settings-control-port (broker-settings broker))
                    method path
                    :body body
                    :seconds seconds
                    :headers (let ((key (broker-control-key broker)))
                               (when key
                                 (list (cons "Authorization"
                                             (format nil "Bearer ~A" key)))))))

(defun mint-token (broker request seconds)
  "Swap the credential REQUEST names for a token locked to its destinations.

A request naming a ref never reads a secret at all: the broker already holds it,
Scute says which one, and the plaintext is in one process rather than two."
  (let* ((reference (credential-request-reference request))
         (secret (unless reference
                   (read-secret (credential-request-secret-file request)
                                (credential-request-name request))))
         (body (format nil "{~A:~A,~A:[~{~A~^,~}],~A:~D,~A:~A}"
                       (json-escape (if reference "credential_ref" "credential"))
                       (json-escape (or reference secret))
                       (json-escape "destinations")
                       (mapcar #'json-escape (credential-request-destinations request))
                       (json-escape "ttl_seconds") seconds
                       (json-escape "label")
                       (json-escape (format nil "scute ~A"
                                            (credential-request-name request)))))
         (response (control-request broker "POST" "/tokens" :body body)))
    (unless (member (http-response-status response) '(200 201))
      (broker-error "the broker refused to issue a token for ~A: ~D ~A"
                    (credential-request-name request)
                    (http-response-status response)
                    (string-trim '(#\Newline #\Return)
                                 (http-response-body response))))
    (let ((token (json-string-field (http-response-body response) "token")))
      (unless token
        (broker-error "the broker's answer for ~A carried no token"
                      (credential-request-name request)))
      (push token (broker-tokens broker))
      token)))

(defun revoke-tokens (broker)
  "Revoke every token this run minted.

The run is over, so the tokens are done.  One left alive is a credential still
usable by anyone who recorded it, for as long as its time to live had left --
and on an attached broker that outlives the sandbox, nothing else would ever
come along to clean it up."
  (dolist (token (broker-tokens broker))
    (ignore-errors
     (control-request broker "DELETE" (format nil "/tokens/~A" token) :seconds 2)))
  (setf (broker-tokens broker) nil))

;;── What the sandbox is given instead ──────────────────────────────────────────

(defparameter +certificate-variables+
  '("SSL_CERT_FILE" "REQUESTS_CA_BUNDLE" "CURL_CA_BUNDLE"
    "NODE_EXTRA_CA_CERTS" "GIT_SSL_CAINFO")
  "Where the runtimes an agent is built from look for a certificate authority.

There is no single variable for this -- Python, curl, Node and git each read
their own -- and an agent that shells out crosses several of them in one task.")

(defun broker-environment (broker tokens)
  "The environment entries a brokered run adds to the sandbox's."
  (append (loop for (variable . token) in tokens
                collect (format nil "~A=~A" variable token))
          (let ((certificate (namestring (broker-certificate broker))))
            (loop for variable in +certificate-variables+
                  collect (format nil "~A=~A" variable certificate)))))

(defun plan-with-broker (plan broker tokens)
  "PLAN as the sandbox will see it once the broker is running: the tokens in its
environment, and read access to the one certificate it has to trust.

The certificate, not the directory holding it: the CA's private key sits beside
it, and a sandbox that could read that could sign for anything."
  (revised-launch-plan
   plan
   :environment (append (launch-plan-environment plan)
                        (broker-environment broker tokens))
   :filesystem (append (launch-plan-filesystem plan)
                       (let ((certificate (probe-file (broker-certificate broker))))
                         (unless certificate
                           (setup-error :start-broker
                                        :detail (format nil "the broker's CA ~
                                                             certificate is not at ~A"
                                                        (broker-certificate broker))))
                         (list (make-path-rule :read (namestring certificate) nil))))))

(defun credential-seconds (request plan)
  "How long REQUEST's token should live.

As long as the run when the policy bounds it: a token outliving the command it
was minted for is a credential nobody is watching any more.  An unbounded run
gets an hour."
  (or (credential-request-ttl request)
      (let ((limits (launch-plan-limits plan)))
        (and limits (resource-limits-wall-clock limits)))
      3600))

(defun call-with-broker (plan function &key program)
  "Run FUNCTION on PLAN, with the broker its policy asked for reachable.

Everything happens before the sandbox exists: the broker is found or started,
the secrets are read here in the supervisor, tokens come back, and only then is
the plan the child will run finally settled.  When the command is over the
tokens are revoked."
  (let ((credentials (launch-plan-credentials plan)))
    (if (null credentials)
        (funcall function plan)
        (let ((broker (start-broker (launch-plan-broker plan) :program program)))
          (unwind-protect
               (let ((tokens (mapcar
                              (lambda (request)
                                (cons (credential-request-variable request)
                                      (mint-token broker request
                                                  (credential-seconds request plan))))
                              credentials)))
                 (funcall function (plan-with-broker plan broker tokens)))
            (stop-broker broker))))))
