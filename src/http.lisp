;;; http.lisp
;;;
;;; SPDX-License-Identifier: MIT
;;;
;;; Copyright (C) 2026 Anthony Green

(in-package #:scute)

;;; Just enough HTTP to talk to a credential broker over an authenticated Unix socket.
;;;
;;; Scute has no HTTP client and should not grow one.  What it needs is four
;;; requests to a local process, over a socket whose peer it authenticated: no redirects, no chunked transfer, no TLS, no connection reuse, no
;;; content negotiation.  A general client would bring a dependency that runs
;;; before the sandbox exists, in the process holding the operator's secret.
;;; This is a hundred lines that do only what the broker's control API needs,
;;; and that refuse anything they do not understand rather than guessing.

(define-condition broker-error (scute-error)
  ((detail :initarg :detail :reader broker-error-detail))
  (:report (lambda (condition stream)
             (format stream "~A" (broker-error-detail condition))))
  (:documentation "The credential broker could not be reached or refused us."))

(defun broker-error (format-control &rest arguments)
  (error 'broker-error :detail (apply #'format nil format-control arguments)))

(defstruct (http-response (:constructor %make-http-response (status body)))
  (status 0 :read-only t)
  (body "" :read-only t))

(defun write-request (stream method path body headers)
  (format stream "~A ~A HTTP/1.1~C~C" method path #\Return #\Newline)
  (format stream "Host: 127.0.0.1~C~C" #\Return #\Newline)
  (format stream "Connection: close~C~C" #\Return #\Newline)
  (loop for (name . value) in headers
        do (format stream "~A: ~A~C~C" name value #\Return #\Newline))
  (when body
    (format stream "Content-Type: application/json~C~C" #\Return #\Newline)
    ;; Length in octets, not characters: a secret with a non-ASCII character in
    ;; it would otherwise leave the broker waiting for a body that never ends.
    (format stream "Content-Length: ~D~C~C"
            (length (sb-ext:string-to-octets body :external-format :utf-8))
            #\Return #\Newline))
  (format stream "~C~C" #\Return #\Newline)
  (when body (write-string body stream))
  (finish-output stream))

(defun read-status-code (line)
  "The status out of an HTTP status line, or NIL if that is not what this is."
  (let ((space (position #\Space line)))
    (when (and space (string= "HTTP/1." line :end2 (min 7 (length line))))
      (ignore-errors (parse-integer line :start (1+ space) :junk-allowed t)))))

(defun read-response (stream)
  "Read one response.  Headers are skipped: the body is read to end of stream,
which is what Connection: close makes correct without parsing Content-Length."
  (let* ((status-line (or (read-line stream nil nil)
                          (broker-error "the broker closed the connection ~
                                         without answering")))
         (status (or (read-status-code (string-right-trim '(#\Return) status-line))
                     (broker-error "the broker did not answer with HTTP"))))
    (loop for line = (read-line stream nil nil)
          until (or (null line) (string= "" (string-right-trim '(#\Return) line))))
    (let ((body (with-output-to-string (out)
                  (loop for character = (read-char stream nil nil)
                        while character do (write-char character out)))))
      (%make-http-response status body))))

(defun loopback-request (port method path &key body headers (seconds 10))
  "Make one request to 127.0.0.1:PORT and answer the http-response.

Only the loopback address is ever addressed.  A broker is a process Scute
started beside the sandbox; a request leaving this machine would mean Scute had
been talked into sending a credential somewhere nobody named."
  (let ((socket (make-instance 'sb-bsd-sockets:inet-socket
                               :type :stream :protocol :tcp)))
    (unwind-protect
         (handler-case
             ;; A deadline rather than a socket timeout: it covers the connect,
             ;; the write and the read together, so a broker that accepts the
             ;; connection and then says nothing cannot hold up the sandbox.
             (sb-sys:with-deadline (:seconds seconds)
               (sb-bsd-sockets:socket-connect socket #(127 0 0 1) port)
               (let ((stream (sb-bsd-sockets:socket-make-stream
                              socket :input t :output t :element-type 'character
                              :external-format :utf-8)))
                 (write-request stream method path body headers)
                 (read-response stream)))
           (broker-error (condition) (error condition))
           (sb-sys:deadline-timeout ()
             (broker-error "the broker on 127.0.0.1:~D did not answer within ~
                            ~D second~:P"
                           port seconds))
           (error (condition)
             (broker-error "cannot reach the broker on 127.0.0.1:~D: ~A"
                           port condition)))
      (ignore-errors (sb-bsd-sockets:socket-close socket)))))

(defun require-broker-peer-uid (uid)
  "Only this user's broker may receive credentials."
  (unless (= uid (sb-posix:geteuid))
    (broker-error "refusing broker owned by uid ~D (expected ~D)" uid (sb-posix:geteuid)))
  t)

(defun authenticate-broker-socket (socket)
  "Check the connected peer, not the pathname, before sending any bytes."
  (cffi:with-foreign-objects ((credentials :uint32 3) (size :uint32))
    (setf (cffi:mem-ref size :uint32) 12)
    (unless (and (zerop (cffi:foreign-funcall "getsockopt"
                         :int (sb-bsd-sockets:socket-file-descriptor socket)
                         :int 1 :int 17 ; SOL_SOCKET, SO_PEERCRED
                         :pointer credentials :pointer size :int))
                 (= 12 (cffi:mem-ref size :uint32)))
      (broker-error "cannot authenticate the broker's Unix socket peer"))
    (require-broker-peer-uid (cffi:mem-aref credentials :uint32 1))))

(defun unix-control-request (path method resource &key body (seconds 10))
  "One control request over an authenticated Unix connection. Never uses TCP."
  (unless (and (stringp path) (uiop:absolute-pathname-p path))
    (broker-error "broker control requires an absolute Unix socket path"))
  (let ((socket (make-instance 'sb-bsd-sockets:local-socket :type :stream)))
    (unwind-protect
         (handler-case
             (sb-sys:with-deadline (:seconds seconds)
               (sb-bsd-sockets:socket-connect socket path)
               (authenticate-broker-socket socket)
               (let ((stream (sb-bsd-sockets:socket-make-stream
                               socket :input t :output t :element-type 'character
                               :external-format :utf-8)))
                 (write-request stream method resource body nil)
                 (read-response stream)))
           (broker-error (condition) (error condition))
           (error (condition)
             (broker-error "cannot reach authenticated broker control at ~A: ~A" path condition)))
      (ignore-errors (sb-bsd-sockets:socket-close socket)))))

;;── Just enough JSON ───────────────────────────────────────────────────────────

(defun json-escape (text)
  "TEXT as a JSON string body, quotes and all."
  (with-output-to-string (out)
    (write-char #\" out)
    (loop for character across text
          do (case character
               (#\" (write-string "\\\"" out))
               (#\\ (write-string "\\\\" out))
               (#\Newline (write-string "\\n" out))
               (#\Return (write-string "\\r" out))
               (#\Tab (write-string "\\t" out))
               (t (if (< (char-code character) #x20)
                      (format out "\\u~4,'0x" (char-code character))
                      (write-char character out)))))
    (write-char #\" out)))

(defun json-string-field (body name)
  "The string value of NAME in BODY, or NIL if it has none.

A whole JSON reader is not wanted here: the broker answers with one flat object
and Scute reads one field out of it.  What matters is that this never guesses.
It finds the key as a key -- quoted, followed by a colon -- and reads a proper
JSON string after it, honouring escapes, or answers NIL."
  (let ((key (concatenate 'string "\"" name "\"")))
    (loop with start = 0
          for at = (search key body :start2 start)
          while at
          do (setf start (+ at (length key)))
             (let ((colon (position-if-not
                           (lambda (c) (member c '(#\Space #\Tab #\Newline #\Return)))
                           body :start start)))
               (when (and colon (char= #\: (char body colon)))
                 (let ((quote-at (position-if-not
                                  (lambda (c) (member c '(#\Space #\Tab #\Newline #\Return)))
                                  body :start (1+ colon))))
                   (when (and quote-at (char= #\" (char body quote-at)))
                     (return (read-json-string body (1+ quote-at))))))))))

(defun json-object-list (body name)
  "The objects in the array NAME names, each as its own JSON text.

Splitting rather than parsing: what the caller wants from each object is one or
two string fields, which json-string-field already answers, and a reader for the
whole of JSON is a bigger thing than this needs.  Depth is tracked so that a
nested object does not end its parent early."
  (let* ((key (concatenate 'string "\"" name "\""))
         (at (search key body)))
    (when at
      (let ((open (position #\[ body :start (+ at (length key)))))
        (when open
          (loop with index = (1+ open)
                with objects = '()
                while (< index (length body))
                for character = (char body index)
                do (cond ((char= character #\{)
                          (let ((end (matching-brace body index)))
                            (unless end (return (nreverse objects)))
                            (push (subseq body index (1+ end)) objects)
                            (setf index (1+ end))))
                         ((char= character #\]) (return (nreverse objects)))
                         (t (incf index)))
                finally (return (nreverse objects))))))))

(defun matching-brace (body start)
  "The index of the brace closing the object that opens at START."
  (loop with depth = 0
        with in-string = nil
        for index from start below (length body)
        for character = (char body index)
        do (cond (in-string
                  (cond ((char= character #\\) (incf index))
                        ((char= character #\") (setf in-string nil))))
                 ((char= character #\") (setf in-string t))
                 ((char= character #\{) (incf depth))
                 ((char= character #\}) (decf depth)
                                        (when (zerop depth) (return index))))))

(defun json-string-list (body name)
  "The strings in the array NAME names, which is as much JSON array as is needed
here: one flat list of names, out of an answer that has no others."
  (let* ((key (concatenate 'string "\"" name "\""))
         (at (search key body)))
    (when at
      (let ((open (position #\[ body :start (+ at (length key)))))
        (when open
          (let ((close (position #\] body :start open)))
            (when close
              (loop with index = (1+ open)
                    while (< index close)
                    for quote-at = (position #\" body :start index :end close)
                    while quote-at
                    collect (let ((value (read-json-string body (1+ quote-at))))
                              (setf index (+ quote-at 2 (length value)))
                              value)))))))))

(defun read-json-string (body start)
  "The JSON string beginning at START, which is just past its opening quote."
  (with-output-to-string (out)
    (loop with index = start
          while (< index (length body))
          for character = (char body index)
          do (cond ((char= character #\") (return))
                   ((char= character #\\)
                    (incf index)
                    (when (>= index (length body)) (return))
                    (let ((escaped (char body index)))
                      (case escaped
                        (#\n (write-char #\Newline out))
                        (#\r (write-char #\Return out))
                        (#\t (write-char #\Tab out))
                        (#\u (let ((code (ignore-errors
                                          (parse-integer body :start (1+ index)
                                                              :end (+ index 5)
                                                              :radix 16))))
                               (when code (write-char (code-char code) out))
                               (incf index 4)))
                        (t (write-char escaped out)))
                      (incf index)))
                   (t (write-char character out) (incf index))))))
