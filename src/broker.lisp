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

(defparameter *broker* nil
  "The broker serving the run in progress, for a caller that wants to ask it
what happened.

Answered through a special rather than returned, because the caller ends the run
by exiting the process -- so anything to be learned from the broker has to be
asked for while the run is still on the stack, not afterwards.")

(defparameter *run-identity* nil
  "What the broker calls this run, so its events can be told from another's.

A supervisor and a broker each know half of what happened: Scute knows which
command ran and which paths it was refused, the broker knows which credential went
to which destination.  Neither half answers \"what did this run do\" on its own,
and the broker cannot know they belong together unless it is told -- so every
token minted for a run carries the same task id, and every event about those
tokens carries it back.")

(defstruct (broker (:constructor %make-broker (settings certificate)))
  (settings nil :read-only t)
  (certificate nil :read-only t)   ; the CA the sandbox has to trust
  (tokens nil))                    ; minted here, revoked when the run ends

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

(defun broker-answering-p (socket)
  (handler-case (= 200 (http-response-status
                        (unix-control-request socket "GET" "/health" :seconds 2)))
    (error () nil)))

(defun identify-broker (socket)
  "Check API compatibility after the transport authenticated the peer."
  (let ((response (unix-control-request socket "GET" "/tokens" :seconds 2)))
    (unless (= 200 (http-response-status response))
      (broker-error "broker control at ~A refused access; configure --api-allow-uid ~D"
                    socket (sb-posix:geteuid)))
    (let ((body (string-left-trim '(#\Space #\Tab #\Newline #\Return)
                                  (http-response-body response))))
      (unless (and (plusp (length body)) (char= #\[ (char body 0)))
        (broker-error "the authenticated peer at ~A does not answer the broker API" socket)))
    t))

(defun create-broker-runtime-directory ()
  "An exclusively created private directory; a preexisting path is never reused."
  (let ((path (format nil "~A/scute-broker-~A"
                      (string-right-trim "/" (or (sb-posix:getenv "XDG_RUNTIME_DIR") "/tmp"))
                      (random-hex 16))))
    (sb-posix:mkdir path #o700)
    (concatenate 'string path "/")))

(defun fetch-broker-certificate (socket)
  "Ask the broker for its CA certificate and write it where the sandbox can read.

Better than assuming where the broker keeps its data directory, which is the sort
of thing that goes wrong quietly: the sandbox trusts the wrong CA and the failure
arrives as a TLS error that reads like a network fault.  The certificate is
public -- every agent behind the proxy has to trust it -- so asking for it over
the control API costs nothing.

Answers the path written, or NIL if this broker does not serve one, in which case
the caller falls back to looking where brokers usually put it."
  (handler-case
      (let ((response (unix-control-request socket "GET" "/ca" :seconds 5)))
        (when (and (= 200 (http-response-status response))
                   (search "BEGIN CERTIFICATE" (http-response-body response)))
          (let* ((directory (create-broker-runtime-directory))
                 (path (concatenate 'string directory "ca.pem")))
            (ensure-directories-exist directory)
            (sb-posix:chmod (string-right-trim "/" directory) #o755)
            (with-open-file (stream path :direction :output :if-exists :supersede
                                         :external-format :utf-8)
              (write-string (http-response-body response) stream))
            (sb-posix:chmod path #o644)
            path)))
    (error () nil)))

(defparameter +no-broker-remedy+
  "A broker is a service, not something a run brings with it: enable it once and
       every sandbox after that attaches to the same one.

         systemctl --user enable --now keyfence.socket keyfence-control.socket

       \"scute doctor\" says whether this host has one. Where there is no service
       to attach to -- a container, a host without systemd -- start one beside
       the sandbox with --with, which takes the command line the broker needs."
  "Said when no broker is answering and a policy needs one.")

(defun attach-broker (settings &key (certificate (broker-certificate-path)))
  "The broker this host runs, or a refusal naming the way to have one.

Scute never starts a broker.  A process holding credentials is a service with a
lifetime of its own: one already running has the certificate authority the
agent's runtimes already trust, its tokens outlive nothing, it is not a second
listener on ports a service already holds, and it is not a stranger in the
cgroup Scute has to delegate to its child.  Every one of those was a bug while
Scute started one per run.

A host with no service starts one beside the sandbox instead -- --with is for
exactly that, and takes the command line the broker needs."
  (let ((control (broker-settings-control-socket settings)))
    (unless (probe-file control)
      (setup-error :no-broker
                   :detail (format nil "no broker is answering at ~A, and this ~
                                        policy needs one.~%       ~A"
                                   control +no-broker-remedy+)))
    (identify-broker control)
    (%make-broker settings (or (fetch-broker-certificate control) certificate))))

(defun stop-broker (broker)
  "Revoke what this run minted.  The broker is somebody else's process: it was
running before this sandbox and goes on after it, and the tokens are the only
part of it that belonged to the run."
  (revoke-tokens broker)
  ;; A certificate fetched for this run goes with it. One found where the broker
  ;; keeps it belongs to the broker, and is left alone.
  (let ((certificate (namestring (broker-certificate broker))))
    (when (search "/scute-broker-" certificate)
      (ignore-errors (delete-file certificate))
      (ignore-errors (sb-posix:rmdir (directory-namestring certificate)))))
  t)

;;── Tokens ─────────────────────────────────────────────────────────────────────

(defun control-request (broker method path &key body (seconds 10))
  "Authenticate each new connection, including revocation and audit requests."
  (unix-control-request (broker-settings-control-socket (broker-settings broker))
                        method path :body body :seconds seconds))

(defparameter *run-started* nil
  "When this run began, in the form the broker stamps its entries with.

Needed because not every entry can be attributed.  A refusal for a request that
carried no token has no token to take a run id from -- and that is exactly the
refusal a misconfigured sandbox produces, so it is the one most worth reporting.
Time is what is left to go on.")

(defun rfc3339-now ()
  "The current time as the broker writes it: UTC, to the second.

Compared as text, which works because both sides write the same shape and the
same zone, and which avoids parsing a timestamp to answer a question about
ordering."
  (multiple-value-bind (second minute hour day month year)
      (decode-universal-time (get-universal-time) 0)
    (format nil "~4,'0D-~2,'0D-~2,'0DT~2,'0D:~2,'0D:~2,'0DZ"
            year month day hour minute second)))

(defun new-run-identity ()
  "An identity for this run, unique and meaning nothing outside it."
  (format nil "scute-~D-~A" (sb-posix:getpid) (random-hex 6)))

(defun mint-token (broker request seconds)
  "Swap the credential REQUEST names for a token locked to its destinations.

A request naming a ref never reads a secret at all: the broker already holds it,
Scute says which one, and the plaintext is in one process rather than two."
  (let* ((reference (credential-request-reference request))
         (ssh-user (credential-request-ssh-user request))
         ;; Built as a string rather than conditionalised inside the format
         ;; string, for the reason the ssh field below gives.
         (cgroup-field (let ((id (and *sandbox-cgroup* (cgroup-id *sandbox-cgroup*))))
                         (if id
                             (format nil ",~A:~D" (json-escape "cgroup_id") id)
                             "")))
         (secret (unless reference
                   (read-secret (credential-request-secret-file request)
                                (credential-request-name request))))
         ;; An ssh key is not swapped into a header on the way past: the broker
         ;; keeps it, answers the sandbox's ssh itself, and logs in upstream as
         ;; the user named here.  Same request, a different field, and the same
         ;; token comes back.
         ;; Built rather than conditionalised inside the format string: a
         ;; directive that consumes one argument and skips two is how this went
         ;; wrong the first time, silently, for every credential that was not an
         ;; ssh key.
         (ssh-field (if ssh-user
                        (format nil "~A:~A," (json-escape "ssh_username")
                                (json-escape ssh-user))
                        ""))
         (body (format nil "{~A:~A,~A~A:[~{~A~^,~}],~A:~D,~A:~A~@[,~A:~A~]~A}"
                       (json-escape (cond (reference "credential_ref")
                                          (ssh-user "ssh_private_key")
                                          (t "credential")))
                       (json-escape (or reference secret))
                       ssh-field
                       (json-escape "destinations")
                       (mapcar #'json-escape (credential-request-destinations request))
                       (json-escape "ttl_seconds") seconds
                       (json-escape "label")
                       (json-escape (format nil "scute ~A"
                                            (credential-request-name request)))
                       (and *run-identity* (json-escape "task_id"))
                       (and *run-identity* (json-escape *run-identity*))
                       cgroup-field))
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

(defun broker-events (broker &optional (identity *run-identity*))
  "What the broker recorded about this run, as raw JSON lines.

Asked for once the command is over rather than subscribed to while it runs: the
supervisor has a child to watch and a broker that outlives it, and a question
answered afterwards needs neither a thread nor a held connection."
  (when identity
    (handler-case
        (let ((ours (let ((response (control-request
                                     broker "GET"
                                     (format nil "/audit?task_id=~A" identity)
                                     :seconds 5)))
                      (when (= 200 (http-response-status response))
                        (json-object-list (http-response-body response) "entries"))))
              (orphans (unattributed-refusals broker)))
          (append ours orphans))
      (error () nil))))

(defun unattributed-refusals (broker)
  "Refusals during this run that carry no run id.

A request the broker turns away for having no token has no token to take a run id
from, which is precisely the refusal a sandbox misconfigured for credentials
produces.  Those are found by time instead: entries stamped at or after this run
began, with no task of their own.  It is a weaker claim than attribution, and the
report says so."
  (when *run-started*
    (handler-case
        (let ((response (control-request broker "GET" "/audit" :seconds 5)))
          (when (= 200 (http-response-status response))
            (remove-if-not
             (lambda (event)
               (and (null (json-string-field event "task_id"))
                    (equal "deny" (json-string-field event "event"))
                    (let ((stamp (json-string-field event "ts")))
                      (and stamp (string<= *run-started* stamp)))))
             (json-object-list (http-response-body response) "entries"))))
      (error () nil))))

(defun refusals-among (events)
  "The broker's denials, as (DESTINATION . REASON), in the order they happened."
  (loop for event in events
        for what = (json-string-field event "event")
        when (equal what "deny")
          collect (cons (or (json-string-field event "destination") "somewhere")
                        (or (json-string-field event "deny_reason")
                            (json-string-field event "deny_rule")
                            "refused"))))

(defun report-broker-refusals (events &optional (stream *error-output*))
  "Say what the broker refused, which is the half of a failure Scute cannot see.

A command that cannot reach the network fails somewhere inside itself, with a 401
or a timeout, and the reason lives in a service's log the operator may not think
to read.  This is --explain for the part of the sandbox that is not the
filesystem."
  (let ((refusals (refusals-among events)))
    (when refusals
      (format stream "~&scute: the broker refused ~D request~:P during this run:~%"
              (length refusals))
      (let ((seen '()))
        (loop for (destination . reason) in refusals
              for key = (cons destination reason)
              unless (member key seen :test #'equal)
                do (push key seen)
                   (format stream "~&  ~A~30T~A~%" destination reason)))
      ;; Answered, so that a caller can stop offering a second explanation of a
      ;; failure that has just been explained.
      (length refusals))))

(defun registered-credentials (settings)
  "The credential names the broker knows, or NIL if it cannot be asked.

Answers a second value explaining why not, so that a report can say \"the broker
is not running\" rather than \"the credential is missing\" -- two problems that
look identical from here and call for different fixes."
  (let ((control (broker-settings-control-socket settings)))
    (if (not (broker-answering-p control))
        (values nil (format nil "no broker is answering at ~A" control))
        (handler-case
            (let ((response (control-request
                             (%make-broker settings nil)
                             "GET" "/credentials" :seconds 5)))
              (case (http-response-status response)
                ((200) (values (json-string-list (http-response-body response)
                                                 "credentials")
                               nil))
                ((401 403) (values nil "the broker does not authorize this Unix peer"))
                (t (values nil (format nil "the broker answered ~D"
                                       (http-response-status response))))))
          (error (condition) (values nil (princ-to-string condition)))))))

(defun report-credentials (plan &optional (stream *standard-output*))
  "Say whether each credential a policy names can be had, and answer how many
cannot.  What a policy asks of the broker is as much a part of whether it will
run as what it asks of the filesystem, and until now the only way to find out was
to run it and watch an agent fail."
  (let ((credentials (launch-plan-credentials plan)))
    (when credentials
      (multiple-value-bind (registered reason)
          (registered-credentials (launch-plan-broker plan))
        (let ((missing 0))
          (dolist (request credentials)
            (let* ((reference (credential-request-reference request))
                   (state (cond ((null reference)
                                 (if (probe-file (credential-request-secret-file request))
                                     :readable
                                     :absent))
                                (reason :unknown)
                                ((member reference registered :test #'string=) :registered)
                                (t :absent))))
              (unless (eq state :unknown)
                (when (eq state :absent) (incf missing)))
              (format stream "~(~18A~) ~A~@[ (~A)~]~%"
                      (credential-request-name request)
                      (ecase state
                        (:registered "registered with the broker")
                        (:readable "a secret file Scute can read")
                        (:absent (if reference
                                     "NOT registered with the broker"
                                     "secret file missing"))
                        (:unknown "cannot tell"))
                      (ecase state
                        (:registered reference)
                        (:readable (credential-request-secret-file request))
                        (:absent (or reference
                                     (credential-request-secret-file request)))
                        (:unknown reason)))))
          missing)))))

(defun plan-with-broker (plan broker tokens &optional rendered)
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
                           (setup-error :broker-certificate
                                        :detail (format nil "the broker's CA ~
                                                             certificate is not at ~A"
                                                        (broker-certificate broker))))
                         (cons (make-path-rule :read (namestring certificate) nil)
                               ;; And whatever was written for a program that reads
                               ;; its credential from a file rather than from the
                               ;; environment.  Read-only: the sandbox has no reason
                               ;; to rewrite what it was handed.
                               (mapcar (lambda (file)
                                         (make-path-rule :read (rendered-credential-rule-path file) nil))
                                       rendered))))))

;;── A token written where a program will look for it ───────────────────────────
;;;
;;; An environment variable is how most programs take a credential, and not all of
;;; them.  Codex reads CODEX_HOME/auth.json and takes its token from a field there,
;;; having first decoded it and checked the expiry -- so it cannot be handed an
;;; opaque string at all, and has to be handed something shaped like what it
;;; expects with the token inside it.  KeyFence finds a token in the third segment
;;; of a dotted value, which is what makes that work.
;;;
;;; The rendered file is not a secret.  What goes into it is the run's token, which
;;; is worth nothing except through the broker and is revoked when the run ends.
;;; It is still written 0600 and removed afterwards, because a file nobody meant to
;;; keep should not outlive its reason.

(defparameter +token-placeholder+ "${token}"
  "What a template has where the token goes.")

(defstruct rendered-credential path file-fd directory-fd basename)

(defun rendered-credential-rule-path (file)
  "Landlock must grant the created inode, even if its pathname was replaced."
  (format nil "/proc/self/fd/~D" (rendered-credential-file-fd file)))

(defun open-output-directory (destination)
  "Pin DESTINATION's parent, creating missing directories without following links.
Every component is opened relative to the previous descriptor, so renames cannot
redirect later operations through a different pathname."
  (let* ((absolute (if (uiop:absolute-pathname-p destination)
                       destination
                       (concatenate 'string (sb-posix:getcwd) "/" destination)))
         (parts (remove "" (uiop:split-string absolute :separator "/") :test #'string=))
         (fd (%open "/" (logior +o-path+ +o-directory+ +o-cloexec+))))
    (unless (and parts (not (member ".." parts :test #'string=))
                 (not (member "." parts :test #'string=))
                 (not (char= #\/ (char absolute (1- (length absolute))))))
      (when (>= fd 0) (%close fd))
      (setup-error :render-credential-file :detail "output must name a file without . or .. components"))
    (when (minusp fd)
      (setup-error :render-credential-file :errno (errno)))
    (handler-case
        (progn
          (dolist (part (butlast parts))
            (let ((next (cffi:foreign-funcall "openat" :int fd :string part
                          :int (logior +o-path+ +o-directory+ +o-cloexec+ #o400000) :int))) ; O_NOFOLLOW
              (when (and (minusp next) (= (errno) +enoent+))
                (cffi:foreign-funcall "mkdirat" :int fd :string part :unsigned-int #o700 :int)
                (setf next (cffi:foreign-funcall "openat" :int fd :string part
                             :int (logior +o-path+ +o-directory+ +o-cloexec+ #o400000) :int)))
              (when (minusp next)
                (setup-error :render-credential-file :errno (errno) :detail destination))
              (%close fd)
              (setf fd next)))
          (values fd (car (last parts))))
      (error (condition) (%close fd) (error condition)))))

(defun write-credential-output (destination text)
  "Create one new 0600 file, retaining its parent descriptor for safe cleanup."
  (multiple-value-bind (directory basename) (open-output-directory destination)
    (let ((fd nil) (pinned nil) (created nil) (completed nil))
      (unwind-protect
           (progn
             (setf fd (cffi:foreign-funcall "openat" :int directory :string basename
                        :int (logior +o-wronly+ +o-create+ +o-cloexec+ #o200 #o400000)
                        :unsigned-int #o600 :int)) ; O_EXCL | O_NOFOLLOW
             (when (minusp fd)
               (setup-error :render-credential-file :errno (errno)
                            :detail (format nil "~A must be a new file, not an existing file or symlink"
                                            destination)))
             (setf created t
                   pinned (cffi:foreign-funcall "fcntl" :int fd :int 1030 :int 3 :int)) ; F_DUPFD_CLOEXEC
             (when (minusp pinned)
               (setup-error :render-credential-file :errno (errno)))
             (with-open-stream (stream (sb-sys:make-fd-stream fd :output t
                                       :element-type 'character :external-format :utf-8))
               (setf fd nil) ; stream owns it now
               (write-string text stream))
             (setf completed t)
             (make-rendered-credential :path destination :file-fd pinned
                                       :directory-fd directory :basename basename))
        (when (and fd (>= fd 0)) (%close fd))
        (unless completed
          (when (and pinned (>= pinned 0)) (%close pinned))
          (when created
            (cffi:foreign-funcall "unlinkat" :int directory :string basename :int 0 :int))
          (%close directory))))))

(defun render-credential-file (request token)
  "Write REQUEST's file, with TOKEN in place of the placeholder.
Answer the pinned file and parent descriptors for registration and cleanup."
  (let* ((template (credential-request-template request))
         (destination (credential-request-file request))
         (text (handler-case
                   (with-open-file (stream template :direction :input
                                                    :external-format :utf-8)
                     (let ((buffer (make-string (file-length stream))))
                       (subseq buffer 0 (read-sequence buffer stream))))
                 (error (condition)
                   (setup-error :render-credential-file
                                :detail (format nil "template ~A: ~A"
                                                template condition))))))
    (unless (search +token-placeholder+ text)
      (setup-error :render-credential-file
                   :detail (format nil "template ~A has no ~A in it, so the token ~
                                        would not appear in what the sandbox reads"
                                   template +token-placeholder+)))
    (let ((rendered (with-output-to-string (out)
                      (loop with start = 0
                            for found = (search +token-placeholder+ text :start2 start)
                            while found
                            do (write-string text out :start start :end found)
                               (write-string token out)
                               (setf start (+ found (length +token-placeholder+)))
                            finally (write-string text out :start start)))))
      (write-credential-output destination rendered))))

(defun remove-credential-files (files)
  "Unlink relative to the pinned parent, even if a sandbox renamed an ancestor."
  (dolist (file files)
    (let ((fd (rendered-credential-directory-fd file)))
      (when fd
        (unwind-protect
             (cffi:foreign-funcall "unlinkat" :int fd
                                   :string (rendered-credential-basename file) :int 0 :int)
          (%close fd)
          (%close (rendered-credential-file-fd file))
          (setf (rendered-credential-directory-fd file) nil
                (rendered-credential-file-fd file) nil))))))

(defun credential-seconds (request plan)
  "How long REQUEST's token should live.

As long as the run when the policy bounds it: a token outliving the command it
was minted for is a credential nobody is watching any more.  An unbounded run
gets an hour."
  (or (credential-request-ttl request)
      (let ((limits (launch-plan-limits plan)))
        (and limits (resource-limits-wall-clock limits)))
      3600))

(defparameter +ssh-shim+
  "#!/bin/sh
# Written by scute for one run, and removed when it ends.  The sandbox has no
# key: this answers the broker's bastion with a token, which is what the broker
# swaps for the key it holds.
SSH_ASKPASS=~A/askpass
SSH_ASKPASS_REQUIRE=force
export SSH_ASKPASS SSH_ASKPASS_REQUIRE
exec ~A -F none -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \\
     -o PreferredAuthentications=password -o NumberOfPasswordPrompts=1 \"$@\"
"
  "An ssh of the sandbox's own, first on its PATH.

Why a program rather than an environment variable, which is what this started
as: an agent decides what its subprocesses inherit, and codex's default hands
its shells a core set that carries HOME and PATH and nothing else.  A token in
SSHPASS reaches the agent and stops there, so the git the agent runs has no
credential and the push fails for a reason no one can see from inside.

PATH survives, because a shell with no PATH is no use to anybody.  So the
credential travels as a file the shim reads, and the shim is what git finds when
it looks for ssh.  The real ssh is named absolutely here, or the shim would find
itself.

Every option is required by the arrangement rather than chosen: -F none because
/etc belongs to a user this sandbox has no mapping for, so ssh would refuse the
system-wide configuration as owned by nobody; the host checks off because the
sandbox believes it is talking to the upstream and is in fact talking to the
bastion, whose key is its own -- the check that matters happens in the broker,
against its own known_hosts; and password authentication because the token is
the password.")

(defun write-ssh-shim (token)
  "Write the ssh a sandbox with an ssh credential will find on its PATH.
Answers the directory holding it, which the caller grants and later removes."
  (let* ((directory (format nil "~A/scute-ssh-~A"
                            (string-right-trim "/" (or (sb-posix:getenv "XDG_RUNTIME_DIR")
                                                       "/tmp"))
                            (random-hex 16)))
         (real-ssh (or (search-path-for "ssh")
                       (setup-error :write-ssh-shim
                                    :detail "no ssh on PATH for the sandbox's own to run"))))
    (sb-posix:mkdir directory #o700)
    (flet ((write-file (name text mode)
             (let ((path (format nil "~A/~A" directory name)))
               (with-open-file (stream path :direction :output :if-exists :supersede
                                            :external-format :utf-8)
                 (write-string text stream))
               (sb-posix:chmod path mode)
               path)))
      ;; The token in a file of its own, read by the askpass and by nothing else:
      ;; a credential in the environment is a credential in every log the agent
      ;; writes about its own subprocesses.
      (write-file "token" token #o400)
      (write-file "askpass" (format nil "#!/bin/sh~%exec cat ~A/token~%" directory) #o500)
      (write-file "ssh" (format nil +ssh-shim+ directory real-ssh) #o500))
    directory))

(defun remove-ssh-shim (directory)
  "Take the shim and the token in it away, whatever the run did."
  (when directory
    (dolist (name '("token" "askpass" "ssh"))
      (ignore-errors (delete-file (format nil "~A/~A" directory name))))
    (ignore-errors (sb-posix:rmdir directory))))

(defun plan-with-ssh-shim (plan directory)
  "PLAN with DIRECTORY readable, executable, and first on the sandbox's PATH."
  (if (null directory)
      plan
      (revised-launch-plan
       plan
       :filesystem (append (launch-plan-filesystem plan)
                           (list (make-path-rule :read-execute directory t)))
       :environment
       (loop for entry in (launch-plan-environment plan)
             collect (if (and (> (length entry) 5) (string= "PATH=" entry :end2 5))
                         (format nil "PATH=~A:~A" directory (subseq entry 5))
                         entry)))))

(defun call-with-broker (plan function)
  "Run FUNCTION on PLAN, with the broker its policy asked for reachable.

Everything happens before the sandbox exists: the broker is found or started,
the secrets are read here in the supervisor, tokens come back, and only then is
the plan the child will run finally settled.  When the command is over the
tokens are revoked."
  (let ((credentials (launch-plan-credentials plan))
        ;; A plan whose egress goes through the broker needs it running whether or
        ;; not it also needs a secret from it.  Without this, the default network
        ;; would point every connection at a port with nothing behind it, and the
        ;; sandbox would fail its TLS handshakes for want of the broker's
        ;; certificate -- reported by whatever was running as a broken network.
        (brokered (and (launch-plan-proxy plan) (launch-plan-broker plan)))
        ;; What was written for this run, so that it can be removed even when the
        ;; command ends badly.
        (written '())
        (shim-directory nil))
    (if (and (null credentials) (null brokered))
        (funcall function plan)
        (let* ((sandbox-cgroup
                 ;; Made here rather than in run-launch-plan, because a token
                 ;; can only be bound to a cgroup that already exists and
                 ;; minting happens before the child does. run-launch-plan
                 ;; takes this one instead of making a second.
                 (when (plan-needs-sandbox-cgroup-p plan)
                   (create-sandbox-cgroup (or (launch-plan-limits plan)
                                              (make-resource-limits)))))
               (*sandbox-cgroup* sandbox-cgroup)
               (broker (attach-broker (launch-plan-broker plan)))
               (*broker* broker)
               (*run-identity* (new-run-identity))
               (*run-started* (rfc3339-now)))
          (unwind-protect
               (let* ((minted (mapcar
                               (lambda (request)
                                 (cons request
                                       (mint-token broker request
                                                   (credential-seconds request plan))))
                               credentials))
                      ;; A program that reads a variable is given one; a program
                      ;; that reads a file has one written for it.  A credential
                      ;; may ask for both, and some need only the file.
                      (rendered (loop for (request . token) in minted
                                      when (credential-request-file request)
                                        collect (let ((file (render-credential-file request token)))
                                                  (push file written)
                                                  file)))
                      (tokens (loop for (request . token) in minted
                                    for variable = (credential-request-variable request)
                                    when variable collect (cons variable token)))
                      ;; An ssh credential is spent by a program rather than read
                      ;; from a variable, so what the sandbox gets is an ssh of
                      ;; its own, first on its PATH.
                      (shim (loop for (request . token) in minted
                                  when (credential-request-ssh-user request)
                                    return (write-ssh-shim token))))
                 ;; With no credentials there are no tokens, and the certificate is
                 ;; still the point: the sandbox has to trust the broker to speak
                 ;; TLS through it at all.
                 (setf shim-directory shim)
                 (funcall function
                          (plan-with-ssh-shim
                           (plan-with-broker plan broker tokens rendered)
                           shim)))
            (remove-ssh-shim shim-directory)
            (remove-credential-files written)
            (stop-broker broker)
            (when sandbox-cgroup (delete-sandbox-cgroup sandbox-cgroup)))))))
