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

;;── Finding a policy by name ───────────────────────────────────────────────────
;;;
;;; A policy that only exists on the machine it was written on is a note, not a
;;; tool.  Scute ships policies for the agents people actually run, and a name is
;;; how you reach one: --policy codex, not --policy /usr/share/scute/policies/
;;; codex.policy.
;;;
;;; The search is ordered so that yours wins.  A shipped policy is a starting
;;; point, and the way to change one is to put a policy of the same name in your
;;; own configuration directory, where an upgrade will not touch it.

(defparameter +policy-extension+ ".policy")

(defun policy-search-path ()
  "Where a policy named rather than spelled out is looked for, nearest first.

SCUTE_POLICY_PATH replaces the list, which is what tests use and what somebody
with policies in one shared directory wants."
  (let ((override (sb-posix:getenv "SCUTE_POLICY_PATH")))
    (if (and override (plusp (length override)))
        (remove "" (uiop:split-string override :separator ":") :test #'string=)
        (let ((home (sb-posix:getenv "HOME"))
              (config (sb-posix:getenv "XDG_CONFIG_HOME"))
              (data (sb-posix:getenv "XDG_DATA_HOME")))
          (remove nil
                  (list
                   ;; Yours, first: an edited copy must outrank the shipped one.
                   (cond ((and config (plusp (length config)))
                          (format nil "~A/scute/policies" config))
                         (home (format nil "~A/.config/scute/policies" home)))
                   (cond ((and data (plusp (length data)))
                          (format nil "~A/scute/policies" data))
                         (home (format nil "~A/.local/share/scute/policies" home)))
                   "/usr/local/share/scute/policies"
                   "/usr/share/scute/policies"))))))

(defun policy-name-p (text)
  "Whether TEXT is a name to look up rather than a path to open.

A name has no slash and no extension: \"codex\".  Anything else is a path, so an
existing file is never shadowed by a shipped policy of the same name."
  (and (plusp (length text))
       (not (find #\/ text))
       (not (search +policy-extension+ text))
       (not (probe-file text))))

(defun available-policies ()
  "The policy names on the search path, nearest first, each named once.
What a refusal lists, and what \"scute policies\" prints."
  (let ((seen '()))
    (dolist (directory (policy-search-path) (nreverse seen))
      (dolist (file (ignore-errors
                     (directory (merge-pathnames
                                 (format nil "*~A" +policy-extension+)
                                 (uiop:ensure-directory-pathname directory)))))
        (let ((name (pathname-name file)))
          (unless (member name seen :test #'string=)
            (push name seen)))))))

(defun locate-policy (text)
  "TEXT as a policy file: itself if it is a path, or the nearest match by name."
  (if (not (policy-name-p text))
      text
      (or (loop for directory in (policy-search-path)
                for candidate = (format nil "~A/~A~A" (string-right-trim "/" directory)
                                        text +policy-extension+)
                when (probe-file candidate)
                  return candidate)
          (let ((available (available-policies)))
            (policy-error
             (if available
                 (format nil "no policy named ~S, and no file by that name. ~
                              Installed: ~{~A~^, ~}"
                         text available)
                 (format nil "no policy named ~S, and no file by that name. ~
                              Nothing is installed in ~{~A~^, ~}"
                         text (policy-search-path)))
             nil)))))

;;── Drop-in directories ────────────────────────────────────────────────────────
;;;
;;; codex.d/*.policy, beside codex.policy, merged into it.  A shipped policy
;;; cannot know where this machine keeps its module cache or that this user wants
;;; one more credential in every run, and copying the whole policy to change one
;;; line means an upgrade's improvements never arrive.
;;;
;;; A fragment is not a policy: a file containing nothing but two extra paths is
;;; exactly the case this is for, so fragments are merged before validation rather
;;; than validated one by one.
;;;
;;; One merge rule, so that nobody has to remember two: an array appends, a scalar
;;; is an answer and the last answer wins, and a table is merged key by key.  A
;;; drop-in therefore adds paths, adds arguments, and replaces a mode, a limit or a
;;; program by naming another one.  Fragments are taken in filename order -- 10-
;;; before 20- -- and the search path is walked from its far end, so a fragment in
;;; your own configuration has the last word over one shipped beside the policy.
;;;
;;; This widens what a policy grants, and that is not a hole: whoever can write a
;;; drop-in could copy the policy instead, so it hands them nothing they did not
;;; already have.  The mechanism for an operator constraining somebody else is a
;;; different one, and it can only narrow.

(defun table-document-p (value)
  "Whether VALUE is a TOML table rather than an array or a scalar.

A table is an alist keyed by strings; an array of strings is a list of strings.
Both are lists, so the elements decide."
  (and (consp value)
       (not (stringp value))
       (every (lambda (entry) (and (consp entry) (stringp (car entry)))) value)))

(defun merge-policy-values (base addition)
  "BASE with ADDITION merged in: tables recursively, arrays appended, else last wins."
  (cond ((and (table-document-p base) (table-document-p addition))
         (merge-policy-documents base addition))
        ((and (listp base) (listp addition)
              (not (stringp base)) (not (stringp addition)))
         ;; Appended, minus what is already there: a drop-in repeating a path it
         ;; needs is ordinary, while a policy listing one twice is a typo -- and
         ;; that second case is inside one file, where the validator still sees it.
         (append base (remove-if (lambda (item) (member item base :test #'equal))
                                 addition)))
        (t addition)))

(defun merge-policy-documents (base addition)
  "BASE with every entry of ADDITION merged into it, in BASE's key order."
  (let ((result (copy-alist base)))
    (loop for (key . value) in addition
          for existing = (assoc key result :test #'string=)
          do (if existing
                 (setf (cdr existing) (merge-policy-values (cdr existing) value))
                 (setf result (append result (list (cons key value))))))
    result))

(defun drop-in-directory (pathname)
  "The NAME.d beside the policy file PATHNAME."
  (let* ((path (uiop:parse-native-namestring pathname))
         (stem (pathname-name path)))
    (uiop:ensure-directory-pathname
     (merge-pathnames (format nil "~A.d" stem) path))))

(defun drop-in-files (pathname name)
  "The fragment files that extend the policy at PATHNAME.

Ordered so that the last word belongs to the directory nearest the user: the
search path is walked from its far end, and within a directory the files are taken
in filename order, which is what a 10- and 20- prefix is for."
  (let ((directories (if name
                         (reverse (mapcar (lambda (directory)
                                            (uiop:ensure-directory-pathname
                                             (format nil "~A/~A.d"
                                                     (string-right-trim "/" directory)
                                                     name)))
                                          (policy-search-path)))
                         (list (drop-in-directory pathname)))))
    (loop for directory in directories
          append (sort (mapcar #'namestring
                               (ignore-errors
                                (directory (merge-pathnames
                                            (format nil "*~A" +policy-extension+)
                                            directory))))
                       #'string<))))

(defun read-policy-document (pathname)
  "Parse the policy text in PATHNAME, without validating it."
  (let ((text (handler-case
                  (with-open-file (stream pathname :direction :input
                                                   :external-format :utf-8)
                    (let ((buffer (make-string (min (file-length stream)
                                                    (1+ +policy-size-limit+)))))
                      (subseq buffer 0 (read-sequence buffer stream))))
                (error (condition)
                  (policy-error (format nil "cannot be read: ~A" condition)
                                pathname)))))
    (parse-policy-text text pathname)))

(defun read-sandbox-policy (pathname)
  "Read and validate the policy in PATHNAME, or the policy PATHNAME names."
  (let* ((text (if (stringp pathname) pathname (namestring pathname)))
         (name (and (policy-name-p text) text))
         (base (locate-policy text))
         (fragments (drop-in-files base name))
         (document (reduce (lambda (merged fragment)
                             (merge-policy-documents merged
                                                     (read-policy-document fragment)))
                           fragments
                           :initial-value (read-policy-document base)))
         (sources (cons base fragments)))
    ;; The files that contributed travel with the policy, so that --dry-run can
    ;; name them: a policy whose meaning comes from files nobody can see is worse
    ;; than no drop-ins at all.
    (validate-sandbox-policy document base sources)))

;;── What a policy says ─────────────────────────────────────────────────────────

(defstruct (filesystem-rule (:constructor make-filesystem-rule (kind path &optional optional)))
  "One access kind and the path a policy declared it for, exactly as written.

OPTIONAL is what a leading \"?\" asked for: a path to grant if this host has it.
Kept here rather than in the string so that ~ expansion, the relative-path rules
and the refusal messages all see the path the policy meant."
  (kind nil :read-only t)
  (path nil :read-only t)
  (optional nil :read-only t))

(defstruct (credential-request (:constructor make-credential-request
                                   (name secret-file destinations variable ttl
                                    &optional reference file template)))
  "One credential the sandbox needs, and what the sandbox is given instead."
  (name nil :read-only t)
  (secret-file nil :read-only t)   ; read by the supervisor, never by the sandbox
  (reference nil :read-only t)     ; or held by the broker, read by nobody here
  (destinations nil :read-only t)  ; hosts the token is locked to
  (variable nil :read-only t)      ; the environment variable the token lands in
  (ttl nil :read-only t)           ; seconds, or NIL for the run's own limit
  ;; Some programs do not read an environment variable.  Codex reads
  ;; CODEX_HOME/auth.json and takes its credential out of a field there, and the
  ;; programs that keep a credential in a file are exactly the ones whose
  ;; credentials are most worth brokering -- a file is where a credential
  ;; otherwise sits on disk for ever.
  (file nil :read-only t)          ; where to write the token, inside the sandbox
  (template nil :read-only t))     ; what to write there, with ${token} in it

(defstruct (broker-settings (:constructor make-broker-settings
                                (name proxy-port control-socket)))
  (name nil :read-only t)          ; :keyfence is the only one v0 knows
  (proxy-port nil :read-only t)
  (control-socket nil :read-only t))

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
  (environment-set nil :read-only t) ; variables the policy gives the sandbox
  (unix-sockets nil :read-only t)    ; may the command open an AF_UNIX socket
  (connect-tcp nil :read-only t)     ; the only ports it may connect to
  (bind-tcp    nil :read-only t)     ; the only ports it may listen on
  (proxy      nil :read-only t)      ; everything outbound goes through this
  (allow      nil :read-only t)      ; the only addresses it may reach
  (broker     nil :read-only t)      ; a credential broker to run beside it
  (credentials nil :read-only t)     ; what that broker is asked to hold
  (command    nil :read-only t)      ; the program this policy is for, and its arguments
  (sources    nil :read-only t)      ; every file that contributed, drop-ins included
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

(defun optional-path-p (declared)
  "Whether DECLARED is marked as a path that may be absent, by a leading \"?\".

A policy that ships with Scute has to describe machines it has never seen.
/home/linuxbrew/.linuxbrew holds the agent on one host and does not exist on the
next; ~/.cache/go-build is there once Go has run and not before.  Naming those
unconditionally makes a policy that refuses to start, and leaving them out makes
one that cannot work -- so a policy may say that a path is wanted if it is there.

Marked, never inferred.  An unmarked path that does not exist is still a refusal,
because a typo in a path is the most common way a policy grants nothing where its
author believed it granted something."
  (and (plusp (length declared)) (char= #\? (char declared 0))))

(defun declared-path (declared)
  "DECLARED without any optional marker."
  (if (optional-path-p declared) (subseq declared 1) declared))

(defun validate-filesystem (value pathname)
  (let ((entries (table-entries value "filesystem" pathname)))
    (check-known-keys entries (mapcar #'car +access-key-names+)
                      "[filesystem]" pathname)
    (loop for (key . paths) in entries
          for kind = (cdr (assoc key +access-key-names+ :test #'string=))
          append (mapcar (lambda (path)
                           (make-filesystem-rule kind (declared-path path)
                                                 (optional-path-p path)))
                         (string-array paths key pathname)))))

(defun proxy-url-host (url)
  "The host a proxy URL names, or NIL if it names none."
  (let* ((scheme-end (search "://" url))
         (authority (if scheme-end (subseq url (+ scheme-end 3)) url))
         (slash (position #\/ authority))
         (authority (if slash (subseq authority 0 slash) authority))
         (colon (position #\: authority :from-end t)))
    (let ((host (if colon (subseq authority 0 colon) authority)))
      (when (plusp (length host)) host))))

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

(defparameter +default-broker-proxy+ "http://127.0.0.1:10210"
  "Where KeyFence listens, and so where a sandbox's network goes by default.

Scute's answer to \"how does an agent use a credential it must not hold\" is a
broker, and a broker nothing routes through is a broker nobody uses.  So a policy
that says nothing about the network gets the broker rather than nothing: every
connection goes to it, and what the sandbox may reach is what the broker permits --
with a credential swapped in that the sandbox never saw, and a line in an audit
trail for each request.

Brokered rather than redirected in the kernel.  \"proxied\" is stronger, and needs
CAP_BPF to attach its guard; as a default it would refuse to run at all on a host
where Scute holds no capabilities, which is most of them.  What this default gives
is Landlock permitting exactly one port -- the broker's -- so a client that ignores
the proxy variables reaches nothing rather than reaching the internet.  Where the
capability is there, the proxy is pinned to its address as well, and --dry-run says
which of the two you got.

A policy wanting no network at all still says so, and needs no broker:

    [network]
    mode = \"none\"")

(defvar *implicit-network-mode* nil
  "Overrides the mode a policy silent about the network is read as having.

Bound by the tests, so that what a policy means does not depend on the
capabilities of the machine the suite happens to run on.")

(defun implicit-network-mode (&optional (guard-available (egress-guard-available-p)))
  "Which form the default network takes on this host.

\"proxied\" is the stronger of the two: the kernel rewrites the destination of
every web connection to the broker's address, so a client that ignores the proxy
variables does not fail -- it arrives at the broker anyway, and nothing in the
sandbox can address anywhere else.  It needs CAP_BPF, which the packages grant and
a build from source does not until `make egress'.

Where the capability is absent the default is the port-level form: the host's
network with the broker named as its proxy, and Landlock permitting that one port.
A client ignoring the variables then reaches nothing rather than reaching the
internet, which is weaker and still a sandbox.

Choosing the strongest enactable form is not the silent degradation Scute refuses
elsewhere: this is Scute's own default, not something a policy asked for.  A policy
that writes mode = \"proxied\" itself is still refused, loudly, where the guard
cannot be installed -- and --dry-run names which of the two any run got."
  (or *implicit-network-mode*
      (if guard-available "proxied" "host")))

(defun implicit-network (&optional (mode (implicit-network-mode)))
  "The [network] table a policy that has none is read as having."
  (list (cons "mode" mode) (cons "proxy" +default-broker-proxy+)))

(defun validate-network (value pathname)
  "The network section: the mode, and whether unix-domain sockets are allowed.
Answers the mode and that permission."
  (let ((entries (table-entries value "network" pathname)))
    (check-known-keys entries '("mode" "unix-sockets" "connect-tcp" "bind-tcp"
                                "proxy" "allow")
                      "[network]" pathname)
    (let* ((named-mode (assoc "mode" entries :test #'string=))
           ;; No mode means the default, whatever else the table says: a table
           ;; naming only unix-sockets, or only a proxy, or nothing at all, is a
           ;; policy that did not want to decide this -- and the default is the
           ;; broker.  A mode that is named is taken exactly as written, so
           ;; mode = "host" is still the host's network and no broker.
           (mode (if named-mode
                     (scalar-string (cdr named-mode) "mode" pathname)
                     "host"))
           (unix (assoc "unix-sockets" entries :test #'string=)))
      (let ((setting (cond ((string= "none" mode) :none)
                           ((string= "host" mode) :host)
                           ((string= "proxied" mode) :proxied)
                           (t (policy-error
                               (format nil "network mode ~S is not one Scute knows; ~
                                            expected \"none\", \"host\" or \"proxied\""
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
                                  (when proxy-port (list proxy-port))
                                  ;; Proxied rewrites the destination in the
                                  ;; kernel, and Landlock has already seen the
                                  ;; original by then: it checks the connect
                                  ;; syscall, the rewrite happens further in. So
                                  ;; the web ports have to pass here, and what
                                  ;; constrains where they actually go is the BPF
                                  ;; program.
                                  ;; And 53, because a client resolves a name
                                  ;; before it connects: TCP resolution is rare
                                  ;; but it is what a truncated answer falls back
                                  ;; to, and a sandbox that cannot resolve never
                                  ;; reaches the connect being redirected.
                                  (when (string= "proxied" mode) (list 80 443 53))))
                 (bind (ports "bind-tcp")))
            (when (and (eq setting :none) (or connect bind))
              (policy-error "connect-tcp and bind-tcp name ports on a network, ~
                             and mode is \"none\", which is the absence of one"
                            pathname))
            ;; Proxied means the kernel sends every web connection to the proxy,
            ;; so there has to be one, and it is the egress control: an allow list
            ;; beside it would be two answers to the same question.
            ;; Repeating the broker's address in every policy is a thing to
            ;; forget rather than a decision anybody makes twice, so it is the
            ;; default in the two places one is meant: a mode nobody named, and
            ;; "proxied", which is nothing without a proxy to send traffic to.
            (when (and (null proxy)
                       (or (null named-mode) (eq setting :proxied)))
              (setf proxy +default-broker-proxy+)
              (pushnew (proxy-url-port proxy pathname) connect))
            (when (eq setting :proxied)
              (when (assoc "allow" entries :test #'string=)
                (policy-error "mode \"proxied\" is the egress control: every web ~
                               connection goes to the proxy and nothing else goes ~
                               anywhere, so an allow list would be a second answer ~
                               to the same question"
                              pathname)))
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
had to spell that out could not be shared between two people's machines -- which
goes double for a policy Scute ships: /home/green is nobody else's path."
  (if (and (> (length path) 1) (char= #\~ (char path 0)) (char= #\/ (char path 1)))
      (concatenate 'string (or (sb-posix:getenv "HOME") "~") (subseq path 1))
      path))

(defun validate-credential (name value pathname)
  "One [credentials.NAME] table: a secret to hold, and where its token goes."
  (let ((entries (table-entries value (format nil "credentials.~A" name) pathname)))
    (check-known-keys entries '("secret-file" "ref" "destinations" "env" "ttl"
                                "file" "template")
                      (format nil "[credentials.~A]" name) pathname)
    (flet ((entry (key) (cdr (assoc key entries :test #'string=))))
      (let ((secret-file (let ((raw (entry "secret-file")))
                           (when raw (scalar-string raw "secret-file" pathname))))
            (reference (let ((raw (entry "ref")))
                         (when raw (scalar-string raw "ref" pathname))))
            (variable (let ((raw (entry "env")))
                        (when raw (scalar-string raw "env" pathname))))
            (destinations (let ((raw (entry "destinations")))
                            (when raw (string-array raw "destinations" pathname))))
            (file (let ((raw (entry "file")))
                    (when raw (expand-home (scalar-string raw "file" pathname)))))
            (template (let ((raw (entry "template")))
                        (when raw (expand-home (scalar-string raw "template" pathname))))))
        (when (and secret-file reference)
          (policy-error (format nil "[credentials.~A] gives both secret-file and ~
                                     ref; they are alternatives -- a secret Scute ~
                                     reads, or one the broker already holds"
                                name)
                        pathname))
        (unless (or secret-file reference)
          (policy-error (format nil "[credentials.~A] must say either which ~
                                     secret-file holds the credential, or the ref ~
                                     it is registered with the broker under"
                                name)
                        pathname))
        (when (and (or file template) (not (and file template)))
          (policy-error (format nil "[credentials.~A] gives ~:[template~;file~] ~
                                     without the other; a file needs something to ~
                                     write and a template needs somewhere to go"
                                name file)
                        pathname))
        (unless (or variable file)
          (policy-error (format nil "[credentials.~A] must say where the sandbox ~
                                     receives its token: env, for the programs that ~
                                     read one, or file and template for the ~
                                     programs that read a file"
                                name)
                        pathname))
        (when (and template (not (probe-file template)))
          (policy-error (format nil "[credentials.~A] template ~S does not exist"
                                name template)
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
         name (and secret-file (expand-home secret-file)) destinations variable
         (let ((ttl (entry "ttl"))) (when ttl (parse-duration ttl pathname)))
         reference file template)))))

(defvar *broker-control-socket* nil
  "Optional embedding override for the local broker control socket.")

(defun default-broker-control-socket ()
  (or *broker-control-socket*
      (format nil "~A/keyfence/control.sock"
              (string-right-trim "/"
                (or (sb-posix:getenv "XDG_RUNTIME_DIR")
                    (format nil "/run/user/~D" (sb-posix:geteuid)))))))

(defun validate-credentials (value proxy-port pathname)
  "The [credentials] table: which broker to run, and what it holds for us.
Answers the broker settings and the credentials it will be asked for."
  (let ((entries (table-entries value "credentials" pathname)))
    (let ((scalars (remove-if #'consp entries :key #'cdr))
          (tables (remove-if-not #'consp entries :key #'cdr)))
      (when (assoc "control-port" scalars :test #'string=)
        (policy-error "control-port is no longer safe; use control-socket with a KeyFence Unix control listener"
                      pathname))
      (check-known-keys scalars '("broker" "control-socket") "[credentials]" pathname)
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
             (control (let ((named (assoc "control-socket" scalars :test #'string=)))
                        (if named
                            (expand-home (scalar-string (cdr named) "control-socket" pathname))
                            (default-broker-control-socket)))))
        (unless (uiop:absolute-pathname-p control)
          (policy-error "control-socket must be an absolute pathname" pathname))
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

(defun validate-variable-name (name pathname)
  (unless (and (stringp name) (plusp (length name)))
    (policy-error "an environment variable needs a name" pathname))
  (when (find #\= name)
    (policy-error (format nil "~S is not a variable name" name) pathname))
  name)

(defun validate-environment (value pathname)
  "The [environment] table: variables to keep, and variables to set.

Answers the names to keep and an alist of NAME . VALUE to set.

Keeping and setting are different things, and a policy needs both.  Keep passes a
variable the caller already had; set gives the sandbox one the caller need not
have at all -- which is what a tool's configuration directory is.  Without it, a
policy that only works when the operator remembers to export something first is
not really a policy: the first time they forget, the command reads the
configuration the sandbox was meant to keep it away from, and fails in a way that
looks like a filesystem problem."
  (let ((entries (table-entries value "environment" pathname)))
    (check-known-keys (remove-if #'consp entries :key #'cdr)
                      '("keep") "[environment]" pathname)
    (let ((keep (cdr (assoc "keep" entries :test #'string=)))
          (set (cdr (assoc "set" entries :test #'string=))))
      (values
       (when keep
         (mapcar (lambda (name) (validate-variable-name name pathname))
                 (string-array keep "keep" pathname)))
       (when set
         (mapcar (lambda (entry)
                   (unless (consp entry)
                     (policy-error "[environment.set] is a table of NAME = \"value\""
                                   pathname))
                   (cons (validate-variable-name (car entry) pathname)
                         (scalar-string (cdr entry)
                                        (format nil "[environment.set] ~A" (car entry))
                                        pathname)))
                 (table-entries set "environment.set" pathname)))))))

(defun environment-with-settings (environment settings)
  "ENVIRONMENT with SETTINGS applied, replacing any variable of the same name.

A policy that sets a variable means it, so setting wins over both what the caller
had and what the policy kept.  Anything else would make the value depend on the
shell the command was started from, which is the thing a policy is for avoiding.

A leading ~/ in a value is expanded, as it is in a path: a shipped policy has to
say where a tool's configuration lives without knowing whose home it is in, and a
variable holding a path is how half of them are told.  Only a leading ~/, and
nothing else about the value, because guessing at the rest of somebody's string is
not Scute's business."
  (let ((result (remove-if (lambda (entry)
                             (let ((equals (position #\= entry)))
                               (and equals
                                    (assoc (subseq entry 0 equals) settings
                                           :test #'string=))))
                           environment)))
    (append result
            (loop for (name . value) in settings
                  collect (format nil "~A=~A" name (expand-home value))))))

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
already the one address the sandbox may reach, so that is where the broker has to
be -- and a policy asking for credentials whose traffic goes somewhere else is
asking for a swap that nothing routes through.

Naming it is optional, because the default network is the broker: a policy that
says nothing about the network is already routed through it, and repeating the
address would be ceremony.  What is still refused is a policy that asks for a
credential and then names a network with no proxy in it, which is the one
combination that cannot work."
  (let* ((network (cdr (assoc "network" tables :test #'string=)))
         (entries (and network (table-entries network "network" pathname)))
         (named-mode (and entries (assoc "mode" entries :test #'string=)))
         (proxy (and entries
                     (let ((named (assoc "proxy" entries :test #'string=)))
                       (when named (scalar-string (cdr named) "proxy" pathname))))))
    (unless proxy
      (when (and named-mode (not (string= "proxied" (cdr named-mode))))
        (policy-error "[credentials] needs the network to go through the broker: ~
                       it has to be the one address the sandbox can reach, or the ~
                       command can simply go around it.  Either drop [network] and ~
                       take the default, or name the proxy"
                      pathname))
      (setf proxy +default-broker-proxy+))
    (proxy-url-port proxy pathname)))

(defun validate-command (value pathname)
  "One [command] table: the program a policy is for, and the arguments it needs.

A policy that names its own command is the difference between documentation and a
thing you can run.  Confining codex means knowing that its own sandbox has to be
turned off, and a flag that lives in a README is a flag somebody leaves out --
whereas one written here is read by whoever reviews the policy and passed by
whoever runs it.

The program is resolved when the plan is compiled, not here, so that a policy can
be read and checked on a machine where the program is not installed."
  (let ((entries (table-entries value "command" pathname)))
    (check-known-keys entries '("program" "arguments") "[command]" pathname)
    (let* ((program (let ((named (assoc "program" entries :test #'string=)))
                      (unless named
                        (policy-error "[command] must name a program" pathname))
                      (scalar-string (cdr named) "program" pathname)))
           (arguments (let ((named (assoc "arguments" entries :test #'string=)))
                        (when named
                          (let ((values (cdr named)))
                            (unless (and (listp values) (every #'stringp values))
                              (policy-error "[command] arguments must be a list of strings"
                                            pathname))
                            values)))))
      (when (zerop (length program))
        (policy-error "[command] program cannot be empty" pathname))
      (cons program arguments))))

(defun validate-sandbox-policy (document &optional pathname sources)
  "Check DOCUMENT against the policy schema and answer a SANDBOX-POLICY.
Anything the schema does not name is an error: a policy Scute half understands
is a sandbox the operator half asked for."
  (let ((tables (table-entries document "policy" pathname)))
    (check-known-keys tables '("filesystem" "network" "limits" "audit"
                               "environment" "credentials" "command")
                      "a policy" pathname)
    (flet ((table (name) (cdr (assoc name tables :test #'string=))))
      (let ((filesystem (table "filesystem")))
        (unless filesystem
          (policy-error
           "a policy must have a [filesystem] table saying what the sandbox may reach"
           pathname))
        (%make-sandbox-policy
         :filesystem (validate-filesystem filesystem pathname)
         ;; No [network] table means the broker, not nothing.  Synthesised as a
         ;; table and validated like any other, so there is one code path and the
         ;; default cannot drift from what a policy could write by hand.
         :network (validate-network (or (table "network") (implicit-network))
                                    pathname)
         :unix-sockets (nth-value 1 (validate-network
                             (or (table "network") (implicit-network))
                             pathname))
         :connect-tcp (nth-value 2 (validate-network
                             (or (table "network") (implicit-network))
                             pathname))
         :bind-tcp (nth-value 3 (validate-network
                             (or (table "network") (implicit-network))
                             pathname))
         :proxy (nth-value 4 (validate-network
                             (or (table "network") (implicit-network))
                             pathname))
         :allow (nth-value 5 (validate-network
                             (or (table "network") (implicit-network))
                             pathname))
         :limits (when (table "limits")
                   (validate-limits (table "limits") pathname))
         :audit (when (table "audit")
                  (validate-audit (table "audit") pathname))
         ;; Settings for the broker even when no credential is asked of it: a
         ;; policy whose egress goes through the broker needs it running, and its
         ;; certificate, or the sandbox cannot speak TLS through it at all.  What a
         ;; [credentials] table adds is what it should hold, not whether it runs.
         :broker (if (table "credentials")
                     (validate-credentials (table "credentials")
                                           (credentials-proxy-port tables pathname)
                                           pathname)
                     (let ((proxy (nth-value 4 (validate-network
                                                (or (table "network")
                                                    (implicit-network))
                                                pathname))))
                       (when proxy
                         (let ((port (proxy-url-port proxy pathname)))
                           (make-broker-settings
                            :keyfence port
                            (default-broker-control-socket))))))
         :credentials (when (table "credentials")
                        (nth-value 1 (validate-credentials
                                      (table "credentials")
                                      (credentials-proxy-port tables pathname)
                                      pathname)))
         :environment (when (table "environment")
                        (validate-environment (table "environment") pathname))
         :environment-set (when (table "environment")
                            (nth-value 1 (validate-environment (table "environment")
                                                               pathname)))
         :command (when (table "command")
                    (validate-command (table "command") pathname))
         :sources (or sources (and pathname (list pathname)))
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
  (credentials nil :read-only t)
  (sources     nil :read-only t)     ; the policy files this plan was read from
  ;; Optional paths this host does not have.  Kept so that --dry-run can say
  ;; what a policy asked for and did not get: a grant that quietly vanished is
  ;; how someone spends an afternoon on "permission denied".
  (absent      nil :read-only t))

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
  "Resolve RULE against DIRECTORY into the PATH-RULE the kernel will be told, or
NIL for an optional path that is not here.

A relative path means what it says from where Scute was invoked, and may not
climb out of there: a policy that writes \"../..\" is describing somewhere it
was not asked about."
  (let* ((declared (expand-home (filesystem-rule-path rule)))
         (optional (filesystem-rule-optional rule))
         (relative (not (char= #\/ (char declared 0))))
         (truename (probe-file (if relative
                                  (merge-pathnames declared directory)
                                  declared))))
    (unless truename
      (when optional
        (return-from resolve-rule nil))
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
  ;; A policy may name its own command, and then what the caller wrote after --
  ;; are arguments to it rather than a program of their own.  This is what lets a
  ;; shipped policy be run rather than copied: "scute run --policy codex" knows
  ;; that codex needs its own sandbox turned off, because the policy says so.
  (setf command (append (sandbox-policy-command policy) command))
  (unless (and (listp command) command (every #'stringp command))
    (usage-error "the command must be a non-empty list of strings"))
  (let* ((directory (canonical-directory directory))
         (rules (remove nil
                        (mapcar (lambda (rule)
                                  (resolve-rule rule directory
                                                (sandbox-policy-pathname policy)))
                                (sandbox-policy-filesystem policy)))))
    (when (and (sandbox-policy-filesystem policy) (null rules))
      (policy-error "no filesystem grants remain after resolving optional paths"
                    (sandbox-policy-pathname policy)))
    (%make-launch-plan
     :command (cons (resolve-executable (first command) directory) (rest command))
     :directory directory
     ;; Deny-by-default applies to the environment too: what a command is given
     ;; is the short list plus whatever the policy and the caller named.
     :environment (let ((kept (environment-with-settings
                               (kept-environment
                                (append (sandbox-policy-environment policy) keep)
                                environment)
                               (sandbox-policy-environment-set policy)))
                        (proxy (sandbox-policy-proxy policy)))
                    ;; A proxy the command cannot be told about is a proxy it
                    ;; will not use, so naming one sets the variables every
                    ;; ordinary client reads.
                    ;;
                    ;; Except in proxied mode, where the kernel sends the traffic
                    ;; to the proxy whatever the command believes.  Setting them
                    ;; there would be harmless and dishonest: the redirect is the
                    ;; mechanism, and a mode whose variables do the work in
                    ;; practice is a mode whose mechanism is never exercised until
                    ;; it matters.  A policy that wants them can set them itself.
                    (if (and proxy (not (eq :proxied (sandbox-policy-network policy))))
                        (append kept
                                (list (format nil "HTTPS_PROXY=~A" proxy)
                                      (format nil "HTTP_PROXY=~A" proxy)
                                      (format nil "https_proxy=~A" proxy)
                                      (format nil "http_proxy=~A" proxy)))
                        kept))
     :filesystem rules
     :sources (sandbox-policy-sources policy)
     :absent (loop for rule in (sandbox-policy-filesystem policy)
                   when (and (filesystem-rule-optional rule)
                             (null (resolve-rule rule directory
                                                 (sandbox-policy-pathname policy))))
                     collect (filesystem-rule-path rule))
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
                                      (filesystem :keep) (allow :keep))
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
     :allow (if (eq allow :keep) (launch-plan-allow plan) allow)
     :audit (launch-plan-audit plan)
     :broker (launch-plan-broker plan)
     :credentials (launch-plan-credentials plan)
     :absent (launch-plan-absent plan)
     :sources (launch-plan-sources plan)
     :limits (if (eq wall-clock :keep)
                 limits                       ; including none at all
                 (make-resource-limits
                  :memory (and limits (resource-limits-memory limits))
                  :processes (and limits (resource-limits-processes limits))
                  :cpu-percent (and limits (resource-limits-cpu-percent limits))
                  :wall-clock (if (eq wall-clock :keep)
                                  (and limits (resource-limits-wall-clock limits))
                                  wall-clock))))))

(defun proxy-address-bindable-p ()
  "Whether this host could enact an address rule for a proxy right now.

Both halves are needed: the capabilities to load and attach the guard, and a
cgroup to attach it to.  Asking for one without the other is how granting
capabilities to the binary made working policies start failing -- the rule was
added automatically, and then nothing could install it."
  (and (egress-guard-available-p) (limits-installable-p)))

(defun proxy-endpoint (url)
  "The endpoint a proxy URL names, resolved."
  (parse-endpoint (format nil "~A:~D" (or (proxy-url-host url) "127.0.0.1")
                          (proxy-url-port url nil))
                  nil))

(defun plan-with-proxy-bound-by-address (plan &optional (guard-available
                                                    (proxy-address-bindable-p)))
  "PLAN with its proxy's address permitted, not only its port.

Landlock filters TCP ports and not addresses, so a policy naming a proxy permits
that port -- on any host.  The sandbox cannot reach ordinary HTTPS, but it can
reach a listener on the proxy's port number somewhere else, which is a way out
for anything the command can already read.

The address-level guard closes that, and it is BPF attached to a cgroup, so it
needs both a capability this process may not hold and a cgroup it may not have.
When it has them, the proxy's own address is added to what the guard permits,
which is what the policy meant by naming a proxy.  When it does not, the plan is
left as it was: port-level, which --dry-run and the manual both say plainly.

Narrowing further than a policy asked for is a courtesy, so declining it where it
cannot be enacted is not the silent degradation Scute refuses elsewhere -- an
allow list the policy wrote itself is still refused loudly.  The distinction
matters: without it, granting the binary a capability would break every proxy
policy on a host without cgroup delegation, which is most of them."
  (let ((proxy (launch-plan-proxy plan)))
    (if (or (null proxy) (not guard-available))
        plan
        (let* ((host (proxy-url-host proxy))
               (port (proxy-url-port proxy nil))
               (endpoint (and host port
                              (handler-case
                                  (parse-endpoint (format nil "~A:~D" host port) nil)
                                (policy-error () nil)))))
          (if (null endpoint)
              plan
              (let ((allow (launch-plan-allow plan)))
                (if (find-if (lambda (existing)
                               (and (equalp (endpoint-address existing)
                                            (endpoint-address endpoint))
                                    (= (endpoint-port existing)
                                       (endpoint-port endpoint))))
                             allow)
                    plan
                    (revised-launch-plan plan :allow (append allow (list endpoint))))))))))

(defun plan-with-wall-clock (plan seconds)
  "PLAN with SECONDS as its wall-clock limit."
  (revised-launch-plan plan :wall-clock seconds))

(defun refuse-unimplemented-controls (plan)
  "Refuse a plan asking for a control this build cannot install.

Enacting such a plan quietly would hand back a weaker sandbox than the one that
was asked for, so this is where that refusal belongs.  There is nothing to refuse
at present: every control a policy can ask for is installed.  It is kept as the
one place to put the next one, and as the reason a caller can rely on a plan that
compiles being a plan that runs."
  (declare (ignore plan))
  nil)

(defun print-launch-plan (plan &optional (stream *standard-output*))
  "Print PLAN as the decision it is, for review before anything runs."
  (format stream "~&command      ~{~S~^ ~}~%" (launch-plan-command plan))
  (format stream "directory    ~A~%" (launch-plan-directory plan))
  (format stream "network      ~(~A~)~:[~;, unix sockets allowed~]~%"
          (case (launch-plan-network plan)
            (:host "the host's, shared")
            (:proxied "the host's, with every web connection sent to the proxy")
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
  (let ((sources (launch-plan-sources plan)))
    (when sources
      (format stream "policy       ~A~%" (first sources))
      (dolist (fragment (rest sources))
        (format stream "~13T+ ~A~%" fragment))))
  (dolist (path (launch-plan-absent plan))
    (format stream "absent       ~A (optional; not on this host)~%" path))
  (dolist (request (launch-plan-credentials plan))
    (format stream "credential   ~A~%" (credential-request-name request))
    (if (credential-request-reference request)
        (format stream "~13Tthe broker holds it, registered as ~A~%"
                (credential-request-reference request))
        (format stream "~13Tholds ~A~%" (credential-request-secret-file request)))
    (let ((variable (credential-request-variable request))
          (file (credential-request-file request)))
      (when variable
        (format stream "~13Tthe sandbox gets a token in ~A~%" variable))
      (when file
        ;; Named because it is a file Scute writes into the sandbox's reach, and
        ;; whoever reviews a plan should see every one of those before it exists.
        (format stream "~13Tthe sandbox gets a token written into ~A~%" file)
        (format stream "~13Tfrom the template ~A~%"
                (credential-request-template request))))
    (format stream "~13Tusable only at ~{~A~^, ~}~%"
            (credential-request-destinations request)))
  (let ((broker (launch-plan-broker plan)))
    (when broker
      (format stream "broker       ~(~A~), proxy on ~D, control at ~A~%"
              (broker-settings-name broker)
              (broker-settings-proxy-port broker)
              (broker-settings-control-socket broker))))
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
