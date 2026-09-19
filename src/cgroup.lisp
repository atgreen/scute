;;; cgroup.lisp
;;;
;;; SPDX-License-Identifier: MIT
;;;
;;; Copyright (C) 2026 Anthony Green

(in-package #:scute)

;;; Resource limits, beneath the caller's own delegated cgroup-v2 subtree and
;;; nowhere else.
;;;
;;; Cgroup v2 forbids a cgroup from holding processes and enabling controllers
;;; for its children at the same time, which shapes everything here.  A Scute
;;; sharing its cgroup with a shell and its other children cannot enable
;;; anything for children of it, and says so instead of pretending.  A Scute
;;; alone in a delegated cgroup steps aside into a supervisor cgroup of its own,
;;; leaving the cgroup empty and able to give its children controllers.

(defparameter +cgroup-mount+ "/sys/fs/cgroup")

(defparameter +supervisor-cgroup-name+ "scute.supervisor"
  "Where Scute puts itself so that its own cgroup can hand controllers to
children.  Recognized on a later run, so that the second sandbox in a scope
lands beside the first rather than one level deeper.")

(defparameter +limit-controllers+
  '((:memory . "memory") (:processes . "pids") (:cpu-percent . "cpu"))
  "The controller each kind of limit needs enabled.")

(defparameter +delegation-remedy+
  "Run scute under a cgroup of its own, for example: systemd-run --user --scope -p Delegate=yes scute run ..."
  "What to do about a cgroup that cannot hand controllers to its children.  Said
in one place, so that every refusal carries it.")

(defvar *sandbox-cgroup-counter* 0)

(defun read-first-line (pathname)
  (with-open-file (stream pathname :direction :input :if-does-not-exist nil)
    (and stream (read-line stream nil nil))))

(defun own-cgroup ()
  "The caller's cgroup-v2 path, as /proc reports it."
  (let ((line (read-first-line "/proc/self/cgroup")))
    (when (and line (eql 0 (search "0::" line)))
      (subseq line 3))))

(defun cgroup-directory (path)
  (format nil "~A~A" +cgroup-mount+ (string-right-trim "/" path)))

(defun cgroup-file (directory name)
  (format nil "~A/~A" directory name))

(defun cgroup-processes (directory)
  "The pids in DIRECTORY's cgroup."
  (with-open-file (stream (cgroup-file directory "cgroup.procs")
                          :direction :input :if-does-not-exist nil)
    (when stream
      (loop for line = (read-line stream nil nil)
            while line
            collect (parse-integer line :junk-allowed t)))))

(defun enabled-controllers (directory)
  (let ((line (read-first-line (cgroup-file directory "cgroup.subtree_control"))))
    (if (and line (plusp (length line)))
        (uiop:split-string line :separator " ")
        '())))

(defun discover-cgroup2 ()
  "The caller's own cgroup directory, or a refusal.
Everything Scute creates lives beneath this and nowhere else."
  (let ((path (own-cgroup)))
    (unless path
      (setup-error :discover-cgroup2
                   :detail "no unified hierarchy in /proc/self/cgroup"))
    (unless (probe-file (cgroup-file +cgroup-mount+ "cgroup.controllers"))
      (setup-error :discover-cgroup2
                   :detail (format nil "~A is not a cgroup-v2 mount" +cgroup-mount+)))
    (let ((directory (cgroup-directory path)))
      (unless (zerop (%access directory +w-ok+))
        (setup-error :discover-cgroup2
                     :detail (format nil "~A is not writable: no delegated subtree"
                                     directory)))
      directory)))

(defun delegated-root (&optional (directory (discover-cgroup2)))
  "Where sandbox cgroups belong: the delegated cgroup itself, or its parent when
Scute has already stepped aside into a supervisor cgroup under it."
  (let ((parent (uiop:native-namestring
                 (uiop:pathname-parent-directory-pathname
                  (uiop:ensure-directory-pathname directory)))))
    (if (and (string= +supervisor-cgroup-name+
                      (file-namestring (uiop:parse-native-namestring directory)))
             (zerop (%access parent +w-ok+)))
        (string-right-trim "/" parent)
        directory)))

(defun required-controllers (limits)
  (loop for (kind . controller) in +limit-controllers+
        when (ecase kind
               (:memory (resource-limits-memory limits))
               (:processes (resource-limits-processes limits))
               (:cpu-percent (resource-limits-cpu-percent limits)))
          collect controller))

(defun cgroup-limits-p (limits)
  "Whether LIMITS asks for anything a cgroup is needed for.
A wall-clock limit is the supervisor's own business, and asking for one should
not drag in a delegated subtree that nothing will use."
  (and limits (required-controllers limits) t))

(defun step-aside (root)
  "Move this process into a supervisor cgroup under ROOT, so ROOT can give its
children controllers.  Only ever moves Scute itself."
  (let ((supervisor (cgroup-file root +supervisor-cgroup-name+)))
    (unless (probe-file (uiop:ensure-directory-pathname supervisor))
      (handler-case (sb-posix:mkdir supervisor #o755)
        (sb-posix:syscall-error (condition)
          (setup-error :create-supervisor-cgroup
                       :detail (format nil "~A: ~A" supervisor condition)))))
    (write-proc-file (cgroup-file supervisor "cgroup.procs")
                     (format nil "~D" (sb-posix:getpid))
                     :enter-supervisor-cgroup)
    supervisor))

(defun prepare-delegated-root (root controllers)
  "Make ROOT able to give CONTROLLERS to its children, or explain why it cannot."
  (let ((missing (set-difference controllers (enabled-controllers root)
                                 :test #'string=)))
    (when missing
      (let ((others (remove (sb-posix:getpid) (cgroup-processes root))))
        (when others
          (setup-error
           :delegate-cgroup
           :detail (format nil
                           "~A holds ~D other ~A, so cgroup v2 will not let it ~
                            give controllers (~{~A~^, ~}) to children. ~A"
                           root (length others)
                           (if (= 1 (length others)) "process" "processes")
                           missing +delegation-remedy+)))
        (step-aside root))
      (write-proc-file (cgroup-file root "cgroup.subtree_control")
                       (format nil "~{+~A~^ ~}" missing)
                       :enable-cgroup-controllers))
    root))

(defun cpu-max-setting (percent)
  "PERCENT of one processor, as cpu.max wants it: a quota and a period."
  (let ((period 100000))
    (format nil "~D ~D" (round (* period percent) 100) period)))

(defun create-sandbox-cgroup (limits)
  "Create one cgroup for one sandbox, configured with LIMITS.
Returns its directory.  Nothing outside the caller's delegated subtree is
touched, and nothing is created until every limit is known to be installable."
  (let* ((root (prepare-delegated-root (delegated-root)
                                       (required-controllers limits)))
         (directory (cgroup-file root (format nil "scute.~D.~D" (sb-posix:getpid)
                                              (incf *sandbox-cgroup-counter*)))))
    (handler-case (sb-posix:mkdir directory #o755)
      (sb-posix:syscall-error (condition)
        (setup-error :create-sandbox-cgroup
                     :detail (format nil "~A: ~A" directory condition))))
    (handler-bind ((error (lambda (condition)
                            (declare (ignore condition))
                            (delete-sandbox-cgroup directory))))
      (let ((memory (resource-limits-memory limits))
            (processes (resource-limits-processes limits))
            (cpu (resource-limits-cpu-percent limits)))
        (when memory
          (write-proc-file (cgroup-file directory "memory.max")
                           (format nil "~D" memory) :set-memory-max)
          (cap-swap directory))
        (when processes
          (write-proc-file (cgroup-file directory "pids.max")
                           (format nil "~D" processes) :set-pids-max))
        (when cpu
          (write-proc-file (cgroup-file directory "cpu.max")
                           (cpu-max-setting cpu) :set-cpu-max))))
    directory))

(defun host-swap-p ()
  "Whether this host has swap at all.  /proc/swaps carries a header line and
then one line per swap area."
  (with-open-file (stream "/proc/swaps" :direction :input :if-does-not-exist nil)
    (and stream
         (progn (read-line stream nil nil)            ; the header
                (and (read-line stream nil nil) t)))))

(defun cap-swap (directory)
  "Forbid the sandbox from swapping around its memory limit.

A memory limit should mean what it says.  memory.max bounds memory alone, so a
cgroup with 64M and swap available can hold far more than 64M of pages -- and
on a host with zram, zero-filled pages compress away to almost nothing, so the
limit is invisible.  Setting memory.swap.max to 0 makes the number honest.  If
this kernel cannot account for swap and the host has some, the limit cannot be
made honest and the launch is refused instead."
  (let ((pathname (cgroup-file directory "memory.swap.max")))
    (cond ((probe-file pathname)
           (write-proc-file pathname "0" :set-memory-swap-max))
          ((host-swap-p)
           (setup-error :cap-swap
                        :detail "this kernel does not account for swap per cgroup, ~
                                 and the host has swap, so a memory limit could ~
                                 not be enforced as written")))))

(defun move-process-to-cgroup (pid directory)
  "Place PID in DIRECTORY's cgroup, before it runs anything of its own."
  (write-proc-file (cgroup-file directory "cgroup.procs") (format nil "~D" pid)
                   :enter-sandbox-cgroup))

(defun read-cgroup-events (directory)
  "What the kernel recorded about DIRECTORY's limits: an alist of counts."
  (loop for (file . prefix) in '(("memory.events" . "memory")
                                 ("pids.events" . "pids"))
        append (with-open-file (stream (cgroup-file directory file)
                                       :direction :input :if-does-not-exist nil)
                 (when stream
                   (loop for line = (read-line stream nil nil)
                         while line
                         for space = (position #\Space line)
                         when space
                           collect (cons (format nil "~A.~A" prefix
                                                 (subseq line 0 space))
                                         (or (parse-integer line :start (1+ space)
                                                                 :junk-allowed t)
                                             0)))))))

(defun delete-sandbox-cgroup (directory)
  "Remove DIRECTORY's cgroup once it is empty.
A cgroup can stay busy for a moment after its last process is reaped, so this
gives the kernel a little time before it gives up and says so."
  (loop repeat 10
        do (handler-case (return-from delete-sandbox-cgroup
                           (progn (sb-posix:rmdir directory) t))
             (sb-posix:syscall-error (condition)
               (unless (member (sb-posix:syscall-errno condition)
                               (list sb-posix:ebusy sb-posix:enoent))
                 (warn "scute: cannot remove ~A: ~A" directory condition)
                 (return-from delete-sandbox-cgroup nil))
               (when (= (sb-posix:syscall-errno condition) sb-posix:enoent)
                 (return-from delete-sandbox-cgroup t))))
           (sleep 1/50))
  (warn "scute: cgroup ~A stayed busy and was left behind" directory)
  nil)

(defun limits-installable-p ()
  "Whether this host would let Scute install resource limits right now.
Answers the question doctor asks, without creating anything."
  (handler-case
      (let* ((root (delegated-root))
             (enabled (enabled-controllers root)))
        (if (every (lambda (controller) (member controller enabled :test #'string=))
                   '("memory" "pids" "cpu"))
            (values t root "controllers are already enabled for children")
            (let ((others (remove (sb-posix:getpid) (cgroup-processes root))))
              (if others
                  (values nil root
                          (format nil "~A holds ~D other ~A, so it cannot give ~
                                       controllers to children"
                                  root (length others)
                                  (if (= 1 (length others)) "process" "processes")))
                  (values t root "Scute can step aside and enable them")))))
    (scute-error (condition) (values nil nil (princ-to-string condition)))))

;;── Getting a cgroup of our own ────────────────────────────────────────────────
;;;
;;; The remedy above is a true thing to say and a poor thing to require.  Scute
;;; knows exactly what has to be run -- it prints it -- so anything it can type
;;; for itself, it should: a tool that needs a wrapper to do its job is a tool
;;; that gets used without the wrapper, and then quietly does less.
;;;
;;; What happens instead is that Scute re-executes itself inside a transient
;;; scope of its own, which is the same command the message used to hand over.
;;; The scope inherits the terminal, so an interactive sandbox stays interactive,
;;; and the child's exit status is this process's exit status.

(defparameter +own-scope-marker+ "SCUTE_OWN_SCOPE"
  "Set in the re-executed process, so that it does not do this again.

Recursion here would be a fork bomb wearing a systemd unit, so the marker is
checked before anything else.")

(defparameter +own-scope-opt-out+ "SCUTE_NO_OWN_SCOPE"
  "Set by someone who would rather be refused than have a scope made for them.")

(defun in-own-scope-p ()
  (let ((marker (uiop:getenv +own-scope-marker+)))
    (and marker (plusp (length marker)))))

(defun own-scope-refused-p ()
  (let ((opt-out (uiop:getenv +own-scope-opt-out+)))
    (and opt-out (plusp (length opt-out)))))

(defun systemd-run-program ()
  "Where systemd-run is, or NIL with a reason."
  (let ((path (or (find-if (lambda (candidate) (probe-file candidate))
                           '("/usr/bin/systemd-run" "/bin/systemd-run"))
                  (let ((found (ignore-errors
                                (uiop:run-program '("sh" "-c" "command -v systemd-run")
                                                  :output '(:string :stripped t)
                                                  :ignore-error-status t))))
                    (and found (plusp (length found)) found)))))
    (if path
        (values path nil)
        (values nil "systemd-run is not installed"))))

(defun user-manager-reachable-p ()
  "Whether there is a systemd user manager to ask for a scope.

Without a session bus, systemd-run --user has nothing to talk to, and finding
that out by running it would mean an error message from a program the caller
never invoked."
  (let ((runtime (uiop:getenv "XDG_RUNTIME_DIR")))
    (cond ((or (null runtime) (zerop (length runtime)))
           (values nil "XDG_RUNTIME_DIR is unset, so there is no user session to put a scope in"))
          ((not (probe-file (format nil "~A/systemd/private" (string-right-trim "/" runtime))))
           (values nil "no systemd user manager is running in this session"))
          (t t))))

(defun own-scope-possible-p ()
  "Whether Scute can put itself in a scope, and if not, why not."
  (cond ((in-own-scope-p)
         ;; Already tried: the scope exists and still cannot delegate, which is
         ;; a different problem and needs the honest refusal.
         (values nil "Scute is already running in a scope of its own"))
        ((own-scope-refused-p)
         (values nil (format nil "~A is set" +own-scope-opt-out+)))
        (t
         (multiple-value-bind (manager reason) (user-manager-reachable-p)
           (if manager
               (multiple-value-bind (program why-not) (systemd-run-program)
                 (if program (values t program) (values nil why-not)))
               (values nil reason))))))

(defun own-executable ()
  "This program, as something that can be executed again.

*runtime-pathname* is the binary for a saved executable, which is what Scute
ships as.  argv[0] is the fallback, and is what a development image has."
  (or (ignore-errors
       (let ((runtime (uiop:native-namestring sb-ext:*runtime-pathname*)))
         (and runtime (probe-file runtime) runtime)))
      (first sb-ext:*posix-argv*)))

(defun reexec-in-own-scope (program)
  "Run this same command again, inside a transient delegated scope, and exit with
whatever it exits with.

The scope inherits this process's standard streams and terminal, so nothing about
the sandbox's interactivity changes.  Any failure to start it is answered NIL, so
that the caller can fall back to explaining what it wanted."
  (let ((arguments (append (list "--user" "--scope" "--quiet"
                                 "--property" "Delegate=yes"
                                 "--")
                           (list (own-executable))
                           (rest sb-ext:*posix-argv*))))
    (handler-case
        (let ((process (sb-ext:run-program program arguments
                                           :environment (cons (format nil "~A=1" +own-scope-marker+)
                                                              (sb-ext:posix-environ))
                                           :input t :output t :error t
                                           :wait t)))
          (uiop:quit (or (sb-ext:process-exit-code process) 1) t))
      (error (condition)
        (format *error-output* "scute: could not make a cgroup of its own (~A): ~A~%"
                program condition)
        nil))))

(defun plan-wants-own-cgroup-p (limits proxy &optional (guard-available
                                                       (egress-guard-available-p)))
  "Whether this plan would be enacted better from a cgroup of Scute's own.

Two reasons, and the second is easy to overlook: resource limits cannot be
installed without one, and a proxy cannot be pinned to its address without one
either -- so a run that looked fine would have had port-level egress where
address-level was available.

A wall-clock limit is not a reason: it is the supervisor's own timer, and making a
scope for it would be ceremony for nothing."
  (or (cgroup-limits-p limits)
      (and proxy guard-available t)))

(defun ensure-own-cgroup (limits proxy)
  "Put Scute in a cgroup of its own if this plan needs one and this one will not
do.  Returns, having done nothing, when there is nothing to do."
  (when (and (plan-wants-own-cgroup-p limits proxy)
             (not (limits-installable-p)))
    (multiple-value-bind (possible program) (own-scope-possible-p)
      (when possible
        (reexec-in-own-scope program)))))
