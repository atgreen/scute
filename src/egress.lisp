;;; egress.lisp
;;;
;;; SPDX-License-Identifier: MIT
;;;
;;; Copyright (C) 2026 Anthony Green

(in-package #:scute)

;;; Where a sandbox may connect to, by address.
;;;
;;; Landlock governs TCP ports and not addresses, so a policy naming port 443
;;; permits every host on 443.  A BPF program attached to the sandbox's cgroup
;;; sees the destination of each connect(2) before it happens and can refuse it,
;;; which is the difference between "https anywhere" and "https to these".
;;;
;;; This is the one part of Scute that wants a privilege: loading a BPF program
;;; needs CAP_BPF, and attaching one to a cgroup needs CAP_NET_ADMIN.  A policy
;;; that asks for address-level egress on a host that cannot provide it is
;;; refused rather than quietly downgraded to port-level.

(defparameter +egress-capability-remedy+
  "loading a BPF program needs CAP_BPF and attaching one to a cgroup needs CAP_NET_ADMIN.  Grant them to the binary once: sudo setcap cap_bpf,cap_net_admin+ep /path/to/scute"
  "Said whenever a policy asks for address-level egress without the privilege to
provide it.  Note what it does not say: a setuid script.  Linux ignores the
setuid bit on anything with a shebang, so the only things that work are file
capabilities on the binary, a sudo rule, or a service that grants them.")

(defparameter +egress-map-forms+
  '((whistler:defmap scute-allowed
     :type :hash :key-size 8 :value-size 1 :max-entries 4096))
  "One entry per permitted endpoint, keyed by address and port together.")

(defparameter +egress-program-forms+
  '((whistler:defprog scute-egress-guard
     (:type :cgroup-sock-addr :section "cgroup/connect4" :license "GPL")
     ;; The key is the destination exactly as the kernel presents it: the
     ;; address and the port both in network byte order, packed into one word
     ;; so that a single hash lookup answers the question.
     (let* ((key u64 (logior (<< (cast u64 (ctx user-ip4)) 32)
                             (cast u64 (ctx user-port)))))
       (if (= 0 (getmap scute-allowed key)) 0 1))))
  "Answer 1 to let a connection proceed, 0 to refuse it with EPERM.")

(defun compile-egress-guard ()
  "Compile the guard.  Needs no privileges: nothing here touches the kernel."
  (uiop:symbol-call
   '#:whistler/loader '#:compile-bpf-forms
   (mapcar (lambda (form)
             (uiop:symbol-call '#:whistler/loader '#:whistler-intern-form form))
           +egress-map-forms+)
   (mapcar (lambda (form)
             (uiop:symbol-call '#:whistler/loader '#:whistler-intern-form form))
           +egress-program-forms+)))

;;── Endpoints ──────────────────────────────────────────────────────────────────

(defstruct (endpoint (:constructor make-endpoint (host port address)))
  "A place a policy permits connections to, and the address it resolved to."
  (host nil :read-only t)
  (port nil :read-only t)
  (address nil :read-only t))       ; IPv4, as four octets

(defun parse-endpoint (text pathname)
  "TEXT as HOST:PORT, with HOST resolved to an address now rather than later.

Resolution happens here, in the supervisor, for the same reason the command is
resolved here: what the sandbox is allowed to reach should be decided before it
is running, and be visible in the plan."
  (let ((colon (position #\: text :from-end t)))
    (unless colon
      (policy-error (format nil "~S is not host:port" text) pathname))
    (let ((host (subseq text 0 colon))
          (port (parse-integer text :start (1+ colon) :junk-allowed t)))
      (unless (and port (< 0 port 65536))
        (policy-error (format nil "~S names no TCP port" text) pathname))
      (let ((address (handler-case
                         (sb-bsd-sockets:host-ent-address
                          (sb-bsd-sockets:get-host-by-name host))
                       (error ()
                         (policy-error
                          (format nil "~S does not resolve to an address" host)
                          pathname)))))
        (unless (= 4 (length address))
          (policy-error (format nil "~S resolves to no IPv4 address; v0 guards ~
                                     IPv4 connections only"
                                host)
                        pathname))
        (make-endpoint host port address)))))

(defun endpoint-key (endpoint)
  "ENDPOINT as the BPF program will see it.

Byte order is where this sort of code goes wrong, so: the kernel hands
connect4 the address and port in network byte order, and a little-endian
machine reading those bytes as integers sees them reversed.  The key is
therefore built from the octets rather than from any host-order number."
  (let* ((octets (endpoint-address endpoint))
         (port (endpoint-port endpoint))
         (address (logior (ash (aref octets 3) 24)
                          (ash (aref octets 2) 16)
                          (ash (aref octets 1) 8)
                          (aref octets 0)))
         (network-port (logior (ash (logand port #xff) 8) (ash port -8))))
    (logior (ash address 32) network-port)))

;;── Installing it ──────────────────────────────────────────────────────────────

(defun egress-guard-available-p ()
  "Whether this process could load and attach the guard.
Answers a second value saying why not."
  (let ((capabilities (capability-sets)))
    (flet ((held (name bit)
             (let ((set (cdr (assoc name capabilities :test #'string=))))
               (and set (logbitp bit set)))))
      ;; CAP_BPF is 39 and CAP_NET_ADMIN is 12; CAP_SYS_ADMIN (21) implies both.
      (cond ((or (held "CapEff" 21)
                 (and (held "CapEff" 39) (held "CapEff" 12)))
             t)
            (t (values nil +egress-capability-remedy+))))))

(defun detach-egress-guard (attachment)
  "Take the guard off the cgroup.  The cgroup is about to go with it, but an
attachment outliving its sandbox is the sort of thing that accumulates."
  (ignore-errors (uiop:symbol-call '#:whistler/loader '#:detach attachment)))

(defmacro with-narration-captured (stream &body body)
  "Run BODY with everything it prints going to STREAM.

Every stream a library might narrate to, not just the obvious two.  Whistler
writes its progress to *trace-output*, which is easy to forget and shows up as
noise in the middle of somebody's session."
  `(let ((*standard-output* ,stream)
         (*error-output* ,stream)
         (*trace-output* ,stream)
         (*debug-io* (make-two-way-stream (make-concatenated-stream) ,stream)))
     ,@body))

(defun install-egress-guard (cgroup endpoints)
  "Load the guard, allow ENDPOINTS, and attach it to CGROUP.
Answers the attachment, which the supervisor detaches when the sandbox ends."
  (multiple-value-bind (available reason) (egress-guard-available-p)
    (unless available
      (setup-error :egress-guard :detail (format nil "~A" reason))))
  (multiple-value-bind (map-specs prog-specs) (compile-egress-guard)
    ;; The loader narrates what it is doing, which belongs in a debugging
    ;; session and not in the middle of a sandboxed command's output.  Kept,
    ;; though: if the load fails, what it said is the best evidence there is.
    ;;
    ;; All three streams, because it uses all three: binding *standard-output*
    ;; and *error-output* left ";; load-program prog-type=18 ..." going to
    ;; *trace-output*, which is where anything with a ";;" in front of it tends
    ;; to go, and which turned up in the middle of an interactive agent session.
    (let* ((narration (make-string-output-stream))
           (maps (with-narration-captured narration
                   (uiop:symbol-call '#:whistler/loader '#:session-create-maps
                                     map-specs)))
           (progs (handler-case
                      (with-narration-captured narration
                        (uiop:symbol-call '#:whistler/loader '#:session-load-progs
                                          prog-specs maps))
                    (error (condition)
                      (setup-error :load-egress-guard
                                   :detail (format nil "~A~@[; the loader said: ~A~]"
                                                   condition
                                                   (let ((said (get-output-stream-string
                                                                narration)))
                                                     (and (plusp (length said)) said)))))))
           (guard (cdr (first progs)))
           (table (cdr (first maps))))
      (dolist (endpoint endpoints)
        (uiop:symbol-call '#:whistler/loader '#:map-update-int
                          table (endpoint-key endpoint) 1))
      (uiop:symbol-call '#:whistler/loader '#:attach-cgroup
                        (uiop:symbol-call '#:whistler/loader '#:prog-info-fd guard)
                        cgroup
                        (symbol-value (uiop:find-symbol* '#:+bpf-cgroup-inet4-connect+
                                                         '#:whistler/loader))))))
