;;; policy.lisp
;;;
;;; SPDX-License-Identifier: MIT
;;;
;;; Copyright (C) 2026 Anthony Green

(in-package #:scute)

;;; Policies, and the launch plans they compile into.
;;;
;;; A policy usually travels with the code being sandboxed, so reading one is
;;; part of the boundary it describes.  Policies are TOML: a format that cannot
;;; express evaluation at all, that reviewers outside Lisp can read, and that
;;; other tools can generate.  What the parser returns is then checked against a
;;; closed schema, where any table or key the schema does not name is an error
;;; rather than an ignored line.

;;── Reading ────────────────────────────────────────────────────────────────────

(defparameter +policy-size-limit+ 65536
  "Longest policy Scute will read, in characters.  A policy is a declaration a
person wrote; a megabyte of one is an attack, not a configuration.  The cap is
also what bounds the parser's own recursion on pathological nesting.")

(defun parse-policy-text (text &optional pathname)
  "Parse TEXT as TOML, refusing it whole if it will not parse.

Scute parses with clop deliberately.  TOML 1.0 forbids a duplicate key, and a
parser that accepts one quietly keeps the last value it saw -- so a policy
saying `processes = 1` and later `processes = 99999` would enforce something
its reader never agreed to.  clop refuses both duplicate keys and duplicate
table headers; cl-toml does not.  A policy's meaning must not depend on which
parser read it."
  (when (> (length text) +policy-size-limit+)
    (policy-error (format nil "policy is longer than ~D characters"
                          +policy-size-limit+)
                  pathname))
  (handler-case (clop:parse text)
    (policy-error (condition) (error condition))
    ;; Deep nesting can exhaust the parser's stack before the size cap bites.
    ((or error storage-condition) (condition)
      (policy-error (format nil "policy will not parse: ~A" condition)
                    pathname))))

(defun read-sandbox-policy (pathname)
  "Read and validate the policy in PATHNAME."
  (let ((text (handler-case
                  (with-open-file (stream pathname :direction :input
                                                   :external-format :utf-8)
                    (let ((buffer (make-string (min (file-length stream)
                                                    (1+ +policy-size-limit+)))))
                      (subseq buffer 0 (read-sequence buffer stream))))
                (error (condition)
                  (policy-error (format nil "cannot be read: ~A" condition)
                                pathname)))))
    (validate-sandbox-policy (parse-policy-text text pathname) pathname)))

;;── What a policy says ─────────────────────────────────────────────────────────

(defstruct (filesystem-rule (:constructor make-filesystem-rule (kind path)))
  "One access kind and the path a policy declared it for, exactly as written."
  (kind nil :read-only t)
  (path nil :read-only t))

(defstruct (credential-request (:constructor make-credential-request
                                   (name secret-file destinations variable ttl)))
  "One credential the sandbox needs, and what the sandbox is given instead."
  (name nil :read-only t)
  (secret-file nil :read-only t)   ; read by the supervisor, never by the sandbox
  (destinations nil :read-only t)  ; hosts the token is locked to
  (variable nil :read-only t)      ; the environment variable the token lands in
  (ttl nil :read-only t))          ; seconds, or NIL for the run's own limit

(defstruct (broker-settings (:constructor make-broker-settings
                                (name proxy-port control-port)))
  (name nil :read-only t)          ; :keyfence is the only one v0 knows
  (proxy-port nil :read-only t)
  (control-port nil :read-only t))

(defstruct (resource-limits (:constructor make-resource-limits
                                (&key memory processes cpu-percent wall-clock)))
  "The limits a policy asks for.  NIL means the policy did not ask.
WALL-CLOCK is in seconds and is the supervisor's business rather than the
kernel's: cgroups bound what a command may consume, not how long it may take."
  (memory      nil :read-only t)
  (processes   nil :read-only t)
  (cpu-percent nil :read-only t)
  (wall-clock  nil :read-only t))

(defparameter +kept-environment+
  '("PATH" "HOME" "TERM" "LANG" "LC_ALL" "LC_CTYPE" "LC_MESSAGES" "TZ"
    "USER" "LOGNAME")
  "The variables a sandbox is given unless a policy says otherwise.

Everything else is dropped.  A sandbox exists to run code you have reason to
distrust, and the environment it inherits is where the credentials are: an
AWS_SECRET_ACCESS_KEY, a GITHUB_TOKEN, an SSH_AUTH_SOCK naming an agent that
will sign anything asked of it.  A policy that says nothing about the
environment should not be handing those over, and a list short enough to read
is the only kind anyone can check.")

(defstruct (audit-policy (:constructor make-audit-policy (events)))
  "The events a policy asks to be audited."
  (events nil :read-only t))

(defstruct (sandbox-policy (:constructor %make-sandbox-policy))
  "A validated policy: what the operator asked for, in Scute's own terms."
  (filesystem nil :read-only t)
  (network    :none :read-only t)
  (limits     nil :read-only t)
  (audit      nil :read-only t)
  (environment nil :read-only t)     ; extra variables to keep, beyond the default
  (unix-sockets nil :read-only t)    ; may the command open an AF_UNIX socket
  (connect-tcp nil :read-only t)     ; the only ports it may connect to
  (bind-tcp    nil :read-only t)     ; the only ports it may listen on
  (proxy      nil :read-only t)      ; everything outbound goes through this
  (allow      nil :read-only t)      ; the only addresses it may reach
  (broker     nil :read-only t)      ; a credential broker to run beside it
  (credentials nil :read-only t)     ; what that broker is asked to hold
  (pathname   nil :read-only t))

;;── The document Scute expects ─────────────────────────────────────────────────
;;
;;; clop answers nested association lists: a table is a list of (KEY . VALUE)
;;; entries with string keys, an array is a list of values, and a scalar is
;;; itself.  Everything below reads that shape and refuses anything else, so a
;;; policy that says `read = 7` is turned away rather than half understood.

(defun table-entries (value key pathname)
  "VALUE as the entries of a TOML table."
  (unless (and (consp value)
               (every (lambda (entry) (and (consp entry) (stringp (car entry))))
                      value))
    (policy-error (format nil "[~A] must be a table" key) pathname))
  value)

(defun string-array (value key pathname)
  "VALUE as a non-empty TOML array of non-empty strings."
  (let ((values (if (and (consp value) (not (stringp value))) value (list value))))
    (unless (and values
                 (every (lambda (element)
                          (and (stringp element) (plusp (length element))))
                        values))
      (policy-error (format nil "~A must be an array of one or more paths, ~
                                 written as strings"
                            key)
                    pathname))
    (loop for (path . rest) on values
          when (member path rest :test #'string=)
            do (policy-error (format nil "~A lists ~S more than once" key path)
                             pathname))
    values))

(defun scalar-string (value key pathname)
  (unless (stringp value)
    (policy-error (format nil "~A must be a string" key) pathname))
  value)

(defun positive-integer (value key pathname)
  (unless (and (integerp value) (plusp value))
    (policy-error (format nil "~A must be a positive integer, not ~S" value key)
                  pathname))
  value)

(defun check-known-keys (entries known key pathname)
  "Refuse any key KNOWN does not name."
  (dolist (entry entries)
    (unless (member (car entry) known :test #'string=)
      (policy-error (format nil "~A is not part of ~A; expected ~{~A~^, ~}"
                            (car entry) key known)
                    pathname))))

;;── Validation ─────────────────────────────────────────────────────────────────

(defparameter +access-key-names+
  '(("read" . :read) ("read-execute" . :read-execute)
    ("read-write" . :read-write) ("read-write-execute" . :read-write-execute))
  "The filesystem keys a policy may use, and the access kind each names.")

(defun validate-filesystem (value pathname)
  (let ((entries (table-entries value "filesystem" pathname)))
    (check-known-keys entries (mapcar #'car +access-key-names+)
                      "[filesystem]" pathname)
    (loop for (key . paths) in entries
          for kind = (cdr (assoc key +access-key-names+ :test #'string=))
          append (mapcar (lambda (path) (make-filesystem-rule kind path))
                         (string-array paths key pathname)))))

(defun proxy-url-port (url pathname)
  "The TCP port a proxy URL names, defaulting by scheme."
  (let* ((scheme-end (search "://" url))
         (authority (if scheme-end (subseq url (+ scheme-end 3)) url))
         (colon (position #\: authority :from-end t))
         (port (when colon
                 (parse-integer authority :start (1+ colon) :junk-allowed t))))
    (cond (port port)
          ((and scheme-end (string= "https" (subseq url 0 scheme-end))) 443)
          ((and scheme-end (string= "http" (subseq url 0 scheme-end))) 80)
          (t (policy-error
              (format nil "proxy ~S names no port, and its scheme does not imply one"
                      url)
              pathname)))))

(defun validate-network (value pathname)
  "The network section: the mode, and whether unix-domain sockets are allowed.
Answers the mode and that permission."
  (let ((entries (table-entries value "network" pathname)))
    (check-known-keys entries '("mode" "unix-sockets" "connect-tcp" "bind-tcp"
                                "proxy" "allow")
                      "[network]" pathname)
    (let ((mode (scalar-string (cdr (assoc "mode" entries :test #'string=))
                               "mode" pathname))
          (unix (assoc "unix-sockets" entries :test #'string=)))
      (let ((setting (cond ((string= "none" mode) :none)
                           ((string= "host" mode) :host)
                           (t (policy-error
                               (format nil "network mode ~S is not one v0 knows; ~
                                            expected \"none\" or \"host\""
                                       mode)
                               pathname)))))
        (when (and unix (not (member (cdr unix) '(t nil))))
          (policy-error "unix-sockets is true or false" pathname))
        (flet ((ports (key)
                 (let ((named (assoc key entries :test #'string=)))
                   (when named
                     (let ((values (if (listp (cdr named)) (cdr named) (list (cdr named)))))
                       (mapcar (lambda (port)
                                 (unless (and (integerp port) (< 0 port 65536))
                                   (policy-error
                                    (format nil "~A takes TCP port numbers, not ~S"
                                            key port)
                                    pathname))
                                 port)
                               values))))))
          (let* ((proxy (let ((named (assoc "proxy" entries :test #'string=)))
                          (when named
                            (scalar-string (cdr named) "proxy" pathname))))
                 (proxy-port (when proxy (proxy-url-port proxy pathname)))
                 (connect (append (ports "connect-tcp")
                                  ;; A proxy is only a proxy if nothing can go
                                  ;; around it, so naming one grants its port
                                  ;; and, unless the policy says otherwise,
                                  ;; nothing else.
                                  (when proxy-port (list proxy-port))))
                 (bind (ports "bind-tcp")))
            (when (and (eq setting :none) (or connect bind))
              (policy-error "connect-tcp and bind-tcp name ports on a network, ~
                             and mode is \"none\", which is the absence of one"
                            pathname))
            (values setting (and unix (eq t (cdr unix))) connect bind proxy
                    (let ((named (assoc "allow" entries :test #'string=)))
                      (when named
                        (when (eq setting :none)
                          (policy-error "allow names places to reach on a network, ~
                                         and mode is \"none\", which is the ~
                                         absence of one"
                                        pathname))
                        (mapcar (lambda (text) (parse-endpoint text pathname))
                                (string-array (cdr named) "allow" pathname)))))))))))

(defun expand-home (path)
  "PATH with a leading ~/ replaced by the home directory.

A secret lives under a home directory more often than not, and a policy that
had to spell that out could not be shared between two people's machines."
  (if (and (> (length path) 1) (char= #\~ (char path 0)) (char= #\/ (char path 1)))
      (concatenate 'string (or (sb-posix:getenv "HOME") "~") (subseq path 1))
      path))

(defun validate-credential (name value pathname)
  "One [credentials.NAME] table: a secret to hold, and where its token goes."
  (let ((entries (table-entries value (format nil "credentials.~A" name) pathname)))
    (check-known-keys entries '("secret-file" "destinations" "env" "ttl")
                      (format nil "[credentials.~A]" name) pathname)
    (flet ((entry (key) (cdr (assoc key entries :test #'string=))))
      (let ((secret-file (let ((raw (entry "secret-file")))
                           (when raw (scalar-string raw "secret-file" pathname))))
            (variable (let ((raw (entry "env")))
                        (when raw (scalar-string raw "env" pathname))))
            (destinations (let ((raw (entry "destinations")))
                            (when raw (string-array raw "destinations" pathname)))))
        (unless secret-file
          (policy-error (format nil "[credentials.~A] must say which secret-file ~
                                     holds the credential"
                                name)
                        pathname))
        (unless variable
          (policy-error (format nil "[credentials.~A] must say which env variable ~
                                     the sandbox receives its token in"
                                name)
                        pathname))
        (unless destinations
          (policy-error (format nil "[credentials.~A] must name the destinations ~
                                     the token is locked to"
                                name)
                        pathname))
        ;; A token that works anywhere is not containment, it is a second copy
        ;; of the credential with a different name on it.
        (when (member "*" destinations :test #'string=)
          (policy-error (format nil "[credentials.~A] destinations cannot be \"*\"; ~
                                     a token is worth having because it is locked ~
                                     to somewhere"
                                name)
                        pathname))
        (make-credential-request
         name (expand-home secret-file) destinations variable
         (let ((ttl (entry "ttl"))) (when ttl (parse-duration ttl pathname))))))))

(defparameter +default-control-port-offset+ 2
  "How far the broker's control API sits from its proxy port, by its own default
layout: KeyFence proxies on 10210 and answers control requests on 10212.")

(defun validate-credentials (value proxy-port pathname)
  "The [credentials] table: which broker to run, and what it holds for us.
Answers the broker settings and the credentials it will be asked for."
  (let ((entries (table-entries value "credentials" pathname)))
    (let ((scalars (remove-if #'consp entries :key #'cdr))
          (tables (remove-if-not #'consp entries :key #'cdr)))
      (check-known-keys scalars '("broker" "control-port") "[credentials]" pathname)
      (let* ((broker (let ((named (assoc "broker" scalars :test #'string=)))
                       ;; Naming one is optional: there is one broker, and a
                       ;; policy that asks for credentials has already said the
                       ;; interesting part.
                       (if named
                           (scalar-string (cdr named) "broker" pathname)
                           "keyfence")))
             (name (if (string= "keyfence" broker)
                       :keyfence
                       (policy-error
                        (format nil "broker ~S is not one Scute knows; expected ~
                                     \"keyfence\""
                                broker)
                        pathname)))
             (control (or (cdr (assoc "control-port" scalars :test #'string=))
                          (+ proxy-port +default-control-port-offset+))))
        (unless (and (integerp control) (< 0 control 65536))
          (policy-error "control-port is a TCP port number" pathname))
        (when (= control proxy-port)
          (policy-error "the broker's control port cannot be its proxy port: the ~
                         sandbox may reach the proxy, and the control port is ~
                         where credentials are handed over"
                        pathname))
        (unless tables
          (policy-error "[credentials] names a broker but no credentials; add a ~
                         [credentials.NAME] table saying what it should hold"
                        pathname))
        (values (make-broker-settings name proxy-port control)
                (mapcar (lambda (entry)
                          (validate-credential (car entry) (cdr entry) pathname))
                        tables))))))

(defparameter +duration-multipliers+
  '((#\s . 1) (#\m . 60) (#\h . 3600)))

(defun parse-duration (text pathname)
  "Seconds named by TEXT: plain digits, or digits with s, m, or h."
  (unless (and (stringp text) (plusp (length text)))
    (policy-error "a duration is a string, like \"30s\"" pathname))
  (let* ((suffix (assoc (char-downcase (char text (1- (length text))))
                        +duration-multipliers+))
         (digits (if suffix (subseq text 0 (1- (length text))) text))
         (count (handler-case (parse-integer digits)
                  (error ()
                    (policy-error
                     (format nil "~S is not a duration; expected digits with an ~
                                  optional s, m, or h"
                             text)
                     pathname)))))
    (unless (plusp count)
      (policy-error (format nil "~S is not a usable time limit" text) pathname))
    (* count (if suffix (cdr suffix) 1))))

(defparameter +memory-multipliers+
  '((#\K . 1024) (#\M . 1048576) (#\G . 1073741824) (#\T . 1099511627776)))

(defun parse-memory-limit (text pathname)
  "Bytes named by TEXT, which counts them in plain digits or with a K, M, G, or
T suffix."
  (let* ((suffix (assoc (char-upcase (char text (1- (length text))))
                        +memory-multipliers+))
         (digits (if suffix (subseq text 0 (1- (length text))) text))
         (count (handler-case (parse-integer digits)
                  (error ()
                    (policy-error
                     (format nil "memory ~S is not a size; expected digits ~
                                  with an optional K, M, G, or T"
                             text)
                     pathname)))))
    (unless (plusp count)
      (policy-error (format nil "memory ~S is not a usable limit" text) pathname))
    (* count (if suffix (cdr suffix) 1))))

(defun validate-limits (value pathname)
  (let ((entries (table-entries value "limits" pathname)))
    (check-known-keys entries '("memory" "processes" "cpu-percent" "wall-clock")
                      "[limits]" pathname)
    (flet ((entry (key) (assoc key entries :test #'string=)))
      (make-resource-limits
       :memory (let ((memory (entry "memory")))
                 (when memory
                   (parse-memory-limit
                    (scalar-string (cdr memory) "memory" pathname) pathname)))
       :processes (let ((processes (entry "processes")))
                    (when processes
                      (positive-integer (cdr processes) "processes" pathname)))
       :cpu-percent (let ((cpu (entry "cpu-percent")))
                      (when cpu
                        (positive-integer (cdr cpu) "cpu-percent" pathname)))
       :wall-clock (let ((clock (entry "wall-clock")))
                     (when clock
                       (parse-duration (scalar-string (cdr clock) "wall-clock"
                                                      pathname)
                                       pathname)))))))

(defparameter +audit-event-names+
  '(("exec" . :exec) ("open" . :open) ("connect" . :connect))
  "What a policy may ask to have recorded.

exec and open are answered by watching the command through a seccomp
notification, which needs no privileges.  connect is designed but has nothing
to observe while v0 has no network, and is refused rather than accepted
silently.")

(defun validate-audit (value pathname)
  (let ((entries (table-entries value "audit" pathname)))
    (check-known-keys entries '("events") "[audit]" pathname)
    (make-audit-policy
     (mapcar (lambda (event)
               (or (cdr (assoc event +audit-event-names+ :test #'string=))
                   (policy-error
                    (format nil "~S is not an audit event; expected one of ~
                                 ~{~S~^, ~}"
                            event (mapcar #'car +audit-event-names+))
                    pathname)))
             (string-array (cdr (assoc "events" entries :test #'string=))
                           "events" pathname)))))

(defun validate-environment (value pathname)
  "The variables a policy asks to keep, beyond the ones kept anyway."
  (let ((entries (table-entries value "environment" pathname)))
    (check-known-keys entries '("keep") "[environment]" pathname)
    (let ((keep (cdr (assoc "keep" entries :test #'string=))))
      (mapcar (lambda (name)
                (when (find #\= name)
                  (policy-error
                   (format nil "~S is not a variable name" name) pathname))
                name)
              (string-array keep "keep" pathname)))))

(defun kept-environment (extra &optional (environment (sb-ext:posix-environ)))
  "ENVIRONMENT with only the variables scute keeps and EXTRA names."
  (let ((wanted (append +kept-environment+ extra)))
    (remove-if-not (lambda (entry)
                     (let ((equals (position #\= entry)))
                       (and equals
                            (member (subseq entry 0 equals) wanted
                                    :test #'string=))))
                   environment)))

(defun credentials-proxy-port (tables pathname)
  "The port the policy's proxy sits on, which is where the broker must listen.

A brokered run has no port of its own to choose.  The proxy in [network] is
already the one address the sandbox may reach, so that is where the broker has
to be -- and a policy asking for credentials without naming a proxy is asking
for a swap that nothing routes through."
  (let ((network (cdr (assoc "network" tables :test #'string=))))
    (let ((proxy (and network
                      (let ((named (assoc "proxy" (table-entries network "network" pathname)
                                          :test #'string=)))
                        (when named (scalar-string (cdr named) "proxy" pathname))))))
      (unless proxy
        (policy-error "[credentials] needs [network] to name a proxy: the broker ~
                       has to be the one address the sandbox can reach, or the ~
                       command can simply go around it"
                      pathname))
      (proxy-url-port proxy pathname))))

(defun validate-sandbox-policy (document &optional pathname)
  "Check DOCUMENT against the policy schema and answer a SANDBOX-POLICY.
Anything the schema does not name is an error: a policy Scute half understands
is a sandbox the operator half asked for."
  (let ((tables (table-entries document "policy" pathname)))
    (check-known-keys tables '("filesystem" "network" "limits" "audit"
                               "environment" "credentials")
                      "a policy" pathname)
    (flet ((table (name) (cdr (assoc name tables :test #'string=))))
      (let ((filesystem (table "filesystem")))
        (unless filesystem
          (policy-error
           "a policy must have a [filesystem] table saying what the sandbox may reach"
           pathname))
        (%make-sandbox-policy
         :filesystem (validate-filesystem filesystem pathname)
         :network (if (table "network")
                      (validate-network (table "network") pathname)
                      :none)
         :unix-sockets (when (table "network")
                         (nth-value 1 (validate-network (table "network") pathname)))
         :connect-tcp (when (table "network")
                        (nth-value 2 (validate-network (table "network") pathname)))
         :bind-tcp (when (table "network")
                     (nth-value 3 (validate-network (table "network") pathname)))
         :proxy (when (table "network")
                  (nth-value 4 (validate-network (table "network") pathname)))
         :allow (when (table "network")
                  (nth-value 5 (validate-network (table "network") pathname)))
         :limits (when (table "limits")
                   (validate-limits (table "limits") pathname))
         :audit (when (table "audit")
                  (validate-audit (table "audit") pathname))
         :broker (when (table "credentials")
                   (validate-credentials (table "credentials")
                                         (credentials-proxy-port tables pathname)
                                         pathname))
         :credentials (when (table "credentials")
                        (nth-value 1 (validate-credentials
                                      (table "credentials")
                                      (credentials-proxy-port tables pathname)
                                      pathname)))
         :environment (when (table "environment")
                        (validate-environment (table "environment") pathname))
         :pathname pathname)))))

;;── The launch plan ────────────────────────────────────────────────────────────
;;
;;; A launch plan is the decision, resolved and immutable, before any of it is
;;; enacted: canonical paths, the exact command, the environment it will carry.
;;; It holds no kernel resources, so it can be printed for review and compared
;;; for equality, which is how the tests pin down what a policy means.

(defstruct (launch-plan (:constructor %make-launch-plan) (:copier nil))
  "What Scute will do, decided in full before anything is created."
  (command     nil :read-only t)
  (directory   nil :read-only t)
  (environment nil :read-only t)
  (filesystem  nil :read-only t)
  (network     :none :read-only t)
  (unix-sockets nil :read-only t)
  (connect-tcp nil :read-only t)
  (bind-tcp    nil :read-only t)
  (proxy       nil :read-only t)
  (allow       nil :read-only t)
  (limits      nil :read-only t)
  (audit       nil :read-only t)
  (broker      nil :read-only t)
  (credentials nil :read-only t))

(defun canonical-directory (pathname)
  "PATHNAME as a canonical directory name, ending in a slash."
  (let ((truename (probe-file pathname)))
    (unless truename
      (setup-error :resolve-directory
                   :detail (format nil "~A does not exist" pathname)))
    (namestring (uiop:ensure-directory-pathname truename))))

(defun path-directories (&optional (path (sb-posix:getenv "PATH")))
  (when path
    (loop with start = 0
          for colon = (position #\: path :start start)
          collect (let ((entry (subseq path start colon)))
                    (if (plusp (length entry)) entry "."))
          while colon
          do (setf start (1+ colon)))))

(defun search-path-for (name)
  "The first executable called NAME on PATH."
  (loop for directory in (path-directories)
        for candidate = (format nil "~A/~A" (string-right-trim "/" directory) name)
        when (and (probe-file candidate)
                  (zerop (%access candidate +x-ok+)))
          return candidate))

(defun resolve-executable (name &optional (directory (sb-posix:getcwd)))
  "NAME as the canonical path of the program that will run.

A bare name is looked up on PATH once, here, and the plan records what it
resolved to.  The point of the old rule -- that a sandbox whose command is
chosen by searching PATH depends on an environment it inherited -- is kept by
resolving in the supervisor rather than in the child: what will run is decided
before anything is created, and scute run --dry-run shows it."
  (unless (and (stringp name) (plusp (length name)))
    (usage-error "the command is empty"))
  (let* ((located (if (find #\/ name)
                      (merge-pathnames name (uiop:ensure-directory-pathname directory))
                      (search-path-for name)))
         (truename (and located (probe-file located))))
    (unless truename
      (error 'command-not-found :pathname name))
    (namestring truename)))

(defun beneath-directory-p (path directory)
  "Whether PATH is at or beneath DIRECTORY, both canonical."
  (let ((base (string-right-trim "/" directory)))
    (or (string= base (string-right-trim "/" path))
        (and (<= (length base) (length path))
             (string= base path :end2 (length base))
             (char= #\/ (char path (length base)))))))

(defun resolve-rule (rule directory &optional pathname)
  "Resolve RULE against DIRECTORY into the PATH-RULE the kernel will be told.
A relative path means what it says from where Scute was invoked, and may not
climb out of there: a policy that writes \"../..\" is describing somewhere it
was not asked about."
  (let* ((declared (filesystem-rule-path rule))
         (relative (not (char= #\/ (char declared 0))))
         (truename (probe-file (if relative
                                  (merge-pathnames declared directory)
                                  declared))))
    (unless truename
      (policy-error (format nil "~S does not exist" declared) pathname))
    (let ((path (namestring truename)))
      (when (and relative (not (beneath-directory-p path directory)))
        (policy-error
         (format nil "~S resolves to ~A, outside ~A" declared path directory)
         pathname))
      (make-path-rule (filesystem-rule-kind rule)
                      (trim-trailing-slash path)
                      (and (uiop:directory-exists-p truename) t)))))

(defun compile-launch-plan (policy command
                            &key (directory (sb-posix:getcwd))
                                 (environment (sb-ext:posix-environ))
                                 (keep '()))
  "Resolve POLICY and COMMAND into an immutable launch plan.
Paths are canonical, the command is the program that will actually run, and
nothing here touches the kernel."
  (unless (and (listp command) command (every #'stringp command))
    (usage-error "the command must be a non-empty list of strings"))
  (let ((directory (canonical-directory directory)))
    (%make-launch-plan
     :command (cons (resolve-executable (first command) directory) (rest command))
     :directory directory
     ;; Deny-by-default applies to the environment too: what a command is given
     ;; is the short list plus whatever the policy and the caller named.
     :environment (let ((kept (kept-environment
                               (append (sandbox-policy-environment policy) keep)
                               environment))
                        (proxy (sandbox-policy-proxy policy)))
                    ;; A proxy the command cannot be told about is a proxy it
                    ;; will not use, so naming one sets the variables every
                    ;; ordinary client reads.
                    (if proxy
                        (append kept
                                (list (format nil "HTTPS_PROXY=~A" proxy)
                                      (format nil "HTTP_PROXY=~A" proxy)
                                      (format nil "https_proxy=~A" proxy)
                                      (format nil "http_proxy=~A" proxy)))
                        kept))
     :filesystem (mapcar (lambda (rule)
                           (resolve-rule rule directory
                                         (sandbox-policy-pathname policy)))
                         (sandbox-policy-filesystem policy))
     :network (sandbox-policy-network policy)
     :unix-sockets (sandbox-policy-unix-sockets policy)
     :connect-tcp (sandbox-policy-connect-tcp policy)
     :bind-tcp (sandbox-policy-bind-tcp policy)
     :proxy (sandbox-policy-proxy policy)
     :allow (sandbox-policy-allow policy)
     :limits (sandbox-policy-limits policy)
     :audit (sandbox-policy-audit policy)
     :broker (sandbox-policy-broker policy)
     :credentials (sandbox-policy-credentials policy))))

(defun compile-command-launch-plan (command filesystem &optional directory keep)
  "A launch plan for COMMAND with FILESYSTEM given as (KIND PATH) forms.
The path a caller with no policy file takes: the forms are checked exactly as
a policy's would be, so the two routes cannot diverge."
  (let ((policy (%make-sandbox-policy
                 :filesystem
                 (mapcar (lambda (form)
                           (destructuring-bind (kind path) form
                             (unless (member kind +access-kinds+)
                               (usage-error
                                (format nil "~S is not one of ~{~(~A~)~^, ~}"
                                        kind +access-kinds+)))
                             (make-filesystem-rule kind path)))
                         filesystem))))
    (compile-launch-plan policy command
                         :directory (or directory (sb-posix:getcwd))
                         :keep keep)))

(defun revised-launch-plan (plan &key (wall-clock :keep) (unix-sockets :keep)
                                      (network :keep) (environment :keep)
                                      (filesystem :keep))
  "PLAN with what the command line overrode, whatever its policy said.
A plan is immutable, so an override makes another one rather than changing it."
  (let ((limits (launch-plan-limits plan)))
    (%make-launch-plan
     :command (launch-plan-command plan)
     :directory (launch-plan-directory plan)
     :environment (if (eq environment :keep)
                      (launch-plan-environment plan)
                      environment)
     :filesystem (if (eq filesystem :keep)
                     (launch-plan-filesystem plan)
                     filesystem)
     :network (if (eq network :keep) (launch-plan-network plan) network)
     :unix-sockets (if (eq unix-sockets :keep)
                       (launch-plan-unix-sockets plan)
                       unix-sockets)
     :connect-tcp (launch-plan-connect-tcp plan)
     :bind-tcp (launch-plan-bind-tcp plan)
     :proxy (launch-plan-proxy plan)
     :allow (launch-plan-allow plan)
     :audit (launch-plan-audit plan)
     :broker (launch-plan-broker plan)
     :credentials (launch-plan-credentials plan)
     :limits (if (eq wall-clock :keep)
                 limits                       ; including none at all
                 (make-resource-limits
                  :memory (and limits (resource-limits-memory limits))
                  :processes (and limits (resource-limits-processes limits))
                  :cpu-percent (and limits (resource-limits-cpu-percent limits))
                  :wall-clock (if (eq wall-clock :keep)
                                  (and limits (resource-limits-wall-clock limits))
                                  wall-clock))))))

(defun plan-with-wall-clock (plan seconds)
  "PLAN with SECONDS as its wall-clock limit."
  (revised-launch-plan plan :wall-clock seconds))

(defun refuse-unimplemented-controls (plan)
  "Refuse a plan asking for a control this build cannot install.
Enacting such a plan quietly would hand back a weaker sandbox than the one that
was asked for."
  (let ((audit (launch-plan-audit plan)))
    (when (and audit (member :connect (audit-policy-events audit)))
      (error 'control-not-implemented
             :control "auditing connections"
             :detail "the audit trail records paths, and a connection is not ~
                      one; the rest of [audit] works.  Meanwhile `scute learn ~
                      --network` reports what a command connects to"))))

(defun print-launch-plan (plan &optional (stream *standard-output*))
  "Print PLAN as the decision it is, for review before anything runs."
  (format stream "~&command      ~{~S~^ ~}~%" (launch-plan-command plan))
  (format stream "directory    ~A~%" (launch-plan-directory plan))
  (format stream "network      ~(~A~)~:[~;, unix sockets allowed~]~%"
          (case (launch-plan-network plan)
            (:host "the host's, shared")
            (t "none"))
          (launch-plan-unix-sockets plan))
  (let ((proxy (launch-plan-proxy plan)))
    (when proxy (format stream "~13Tthrough ~A~%" proxy)))
  (dolist (endpoint (launch-plan-allow plan))
    (format stream "~13Tallow ~A:~D (~{~D~^.~})~%"
            (endpoint-host endpoint) (endpoint-port endpoint)
            (coerce (endpoint-address endpoint) 'list)))
  (let ((connect (launch-plan-connect-tcp plan))
        (bind (launch-plan-bind-tcp plan)))
    (when (or connect bind)
      (format stream "~13T~@[connect tcp ~{~D~^ ~}~]~@[ bind tcp ~{~D~^ ~}~]~%"
              connect bind)))
  ;; Printed in full, because this is the one place a policy asks Scute to read
  ;; something the sandbox itself could not: whoever reviews the policy should
  ;; see which files that is before any of them is opened.
  (dolist (request (launch-plan-credentials plan))
    (format stream "credential   ~A~%" (credential-request-name request))
    (format stream "~13Tholds ~A~%" (credential-request-secret-file request))
    (format stream "~13Tthe sandbox gets a token in ~A~%"
            (credential-request-variable request))
    (format stream "~13Tusable only at ~{~A~^, ~}~%"
            (credential-request-destinations request)))
  (let ((broker (launch-plan-broker plan)))
    (when broker
      (format stream "broker       ~(~A~), proxy on ~D, control on ~D~%"
              (broker-settings-name broker)
              (broker-settings-proxy-port broker)
              (broker-settings-control-port broker))))
  ;; Names only.  The values are the caller's own, but a plan is the sort of
  ;; thing that ends up in a log.
  (format stream "environment  ~:[nothing~;~:*~{~A~^ ~}~]~%"
          (sort (mapcar (lambda (entry) (subseq entry 0 (position #\= entry)))
                        (launch-plan-environment plan))
                #'string<))
  (if (launch-plan-filesystem plan)
      (dolist (rule (launch-plan-filesystem plan))
        (format stream "filesystem   ~(~18A~) ~A~%"
                (path-rule-kind rule) (path-rule-path rule)))
      (format stream "filesystem   unrestricted~%"))
  (let ((limits (launch-plan-limits plan)))
    (when limits
      (format stream "limits       ~@[memory ~D ~]~@[processes ~D ~]~
                      ~@[cpu-percent ~D ~]~@[wall-clock ~Ds~]~%"
              (resource-limits-memory limits)
              (resource-limits-processes limits)
              (resource-limits-cpu-percent limits)
              (resource-limits-wall-clock limits))))
  (let ((audit (launch-plan-audit plan)))
    (when audit
      (format stream "audit        ~{~(~A~)~^ ~}~%" (audit-policy-events audit))))
  plan)
