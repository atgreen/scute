;;; SPDX-License-Identifier: MIT
;;;
;;; The filesystem layer: one Landlock ruleset, enforced by the child on itself.

(in-package #:scute/tests)

(defparameter +system-rules+ '((:read-execute "/usr"))
  "Enough to run /bin/sh and its loader on a merged-/usr host, and no more.")

(defun run-with-rules (script rules)
  "Run SCRIPT under RULES and answer the sandbox result."
  (call-scute 'run-namespaced-command
              (list "/bin/sh" "-c" script)
              :filesystem rules))

(defun sandbox-says (script rules)
  "Run SCRIPT under RULES with its output captured, and answer what it wrote."
  (let ((report (scratch-pathname "landlock")))
    (unwind-protect
         (progn
           (delete-scratch report)
           (run-with-rules (format nil "exec > ~A 2>&1~%~A" report script)
                           (append rules (list (list :read-write "/tmp"))))
           (read-file-string report))
      (delete-scratch report))))

(defun listening-unix-socket (path)
  "A listening Unix socket at PATH, in this process, outside any sandbox."
  (ignore-errors (delete-file path))
  (let ((socket (make-instance 'sb-bsd-sockets:local-socket :type :stream)))
    (sb-bsd-sockets:socket-bind socket path)
    (sb-bsd-sockets:socket-listen socket 1)
    socket))

(defun connect-probe (directory)
  "Build a program that connects to a Unix socket and answers 0 or its errno.
Answers its path, or NIL where it could not be built."
  (let ((source (format nil "~A/connect.c" directory))
        (program (format nil "~A/connect" directory)))
    (with-open-file (stream source :direction :output :if-exists :supersede)
      (write-line "#include <sys/socket.h>" stream)
      (write-line "#include <sys/un.h>" stream)
      (write-line "#include <string.h>" stream)
      (write-line "#include <errno.h>" stream)
      (write-line "int main(int argc, char **argv) {" stream)
      (write-line "  struct sockaddr_un a; int s;" stream)
      (write-line "  memset(&a, 0, sizeof a); a.sun_family = AF_UNIX;" stream)
      (write-line "  strncpy(a.sun_path, argv[1], sizeof a.sun_path - 1);" stream)
      (write-line "  s = socket(AF_UNIX, SOCK_STREAM, 0);" stream)
      (write-line "  if (s < 0) return 100 + errno;" stream)
      (write-line "  if (connect(s, (struct sockaddr *)&a, sizeof a) < 0) return errno;" stream)
      (write-line "  return 0;" stream)
      (write-line "}" stream))
    (uiop:run-program (list "gcc" "-O2" "-o" program source) :ignore-error-status t)
    (and (probe-file program) program)))

(deftest test-asking-whether-a-path-is-readable-is-not-reading-it
  "A boundary of the kernel's, documented here because it looks like a bug in
the sandbox.  Landlock governs opening a file and not access(2), so test -r says
a path is readable and reading it is refused a moment later.  Anyone verifying a
policy with a shell test concludes it is wider than it is, and anyone debugging a
refusal concludes the sandbox is inconsistent.

If this test ever fails, the kernel has started governing faccessat and the
README's troubleshooting row about it should go."
  (let ((result (sandbox-says
                 "if test -r /etc/fstab; then echo access-says-yes; fi; ~
                  if cat /etc/fstab > /dev/null 2>&1; then echo read-it; ~
                  else echo read-refused; fi"
                 (list (list :read-execute "/usr")
                       (list :read "/etc/hostname")
                       (list :read "/proc")
                       (list :read-write "/dev/null")))))
    (check (search "access-says-yes" result)
           "test -r no longer answers about a path the policy withholds: ~S" result)
    (check (search "read-refused" result)
           "a path the policy never named was readable: ~S" result)))

(deftest test-a-host-socket-needs-a-connect-rule
  "Every Unix socket already on the host is out of reach, whatever the
filesystem rules say, because the sockets lying around a machine include the
credential broker's own control API -- and a sandbox that could reach that could
ask for the secrets it exists not to hold.

One kind of rule opens one socket: connect, which names the socket itself.  This
is the grant that lets an agent reach a restricted ssh-agent and push to a forge
without the key ever being in the sandbox, so both halves are worth proving --
that a read-write rule over the same directory is not enough, and that connect
is."
  (let* ((directory (scratch-pathname "connect"))
         (path (format nil "~A/socket" directory))
         (socket nil))
    (flet ((run (policy-text probe)
             (call-scute
              'run-launch-plan
              (call-scute 'compile-launch-plan
                          (call-scute 'validate-sandbox-policy
                                      (call-scute 'parse-policy-text policy-text))
                          (list probe path)
                          :directory directory)))
           (policy (extra)
             (format nil "[filesystem]~%read-execute = [\"/usr\"]~%~
                          read-write-execute = [\"~A\"]~%~A~
                          [network]~%mode = \"none\"~%unix-sockets = true~%"
                     directory extra)))
      (unwind-protect
           (progn
             (ensure-directories-exist (format nil "~A/" directory))
             (let ((probe (connect-probe directory)))
               (setf socket (listening-unix-socket path))
               (let ((refused (run (policy "") probe))
                     (allowed (run (policy (format nil "connect = [\"~A\"]~%" path))
                                   probe)))
                 (check (eql 13 (call-scute 'sandbox-result-exit-code refused))
                        "a host socket was reachable under read-write alone, or ~
                         failed for some reason other than EACCES: ~S" refused)
                 (check (eql 0 (call-scute 'sandbox-result-exit-code allowed))
                        "a connect rule did not make the socket reachable: ~S"
                        allowed))))
        (when socket (ignore-errors (sb-bsd-sockets:socket-close socket)))
        (ignore-errors (delete-file path))
        (dolist (name (list "connect.c" "connect"))
          (ignore-errors (delete-file (format nil "~A/~A" directory name))))
        (ignore-errors (sb-posix:rmdir directory))))))

(deftest test-filesystem-is-denied-by-default
  "Without a rule for it, a path cannot be opened -- and with one, it can.
Both halves matter: the second is what proves the first is Landlock talking
and not some unrelated failure."
  (let ((denied (sandbox-says "if cat /etc/hostname; then echo ALLOWED; else echo denied; fi"
                              +system-rules+))
        (allowed (sandbox-says "if cat /etc/hostname > /dev/null; then echo ALLOWED; else echo denied; fi"
                               (append +system-rules+
                                       '((:read "/etc") (:read-write "/dev/null"))))))
    (check (search "denied" denied) "/etc was readable without a rule: ~A" denied)
    (check (search "ALLOWED" allowed) "/etc was not readable with a rule: ~A" allowed)))

(deftest test-write-needs-more-than-read
  "A :read rule does not carry the right to write beneath it."
  ;; Not ":" -- a redirection failure on a POSIX special builtin makes a
  ;; non-interactive shell exit, and the else branch never runs.
  (let ((output (sandbox-says
                 "if echo x > /etc/scute-must-not-appear; then echo WROTE; else echo refused; fi"
                 (append +system-rules+ '((:read "/etc"))))))
    (check (search "refused" output) "a :read rule permitted a write: ~A" output)
    (check (not (probe-file "/etc/scute-must-not-appear"))
           "the sandbox created a file outside its rules")))

(deftest test-writable-path-is-writable
  "What a :read-write rule grants actually works, including creating files."
  (let* ((directory (scratch-pathname "workspace"))
         (witness (format nil "~A/written" directory)))
    (unwind-protect
         (progn
           (ensure-directories-exist (format nil "~A/" directory))
           (run-with-rules (format nil "echo sandboxed > ~A" witness)
                           (append +system-rules+ (list (list :read-write directory))))
           (check (probe-file witness) "the sandbox could not write where it was allowed")
           (check (search "sandboxed" (if (probe-file witness)
                                          (read-file-string witness)
                                          ""))
                  "the written file did not hold what the sandbox wrote"))
      (ignore-errors (delete-file witness))
      (ignore-errors (sb-posix:rmdir directory)))))

(deftest test-rules-on-files-not-only-directories
  "A rule may name a single file.  The kernel rejects directory-only rights on
one, so those rights have to be masked out -- /dev/null is the everyday case."
  (let ((output (sandbox-says "if echo discarded > /dev/null; then echo OK; else echo failed; fi"
                              (append +system-rules+ '((:read-write "/dev/null"))))))
    (check (search "OK" output) "a rule on /dev/null did not work: ~A" output)))

(deftest test-unrestricted-without-rules
  "With no rules there is no ruleset and no filesystem restriction.  This is the
control for every test above."
  (let ((result (run-with-rules "cat /etc/hostname > /dev/null" '())))
    (check (eql 0 (call-scute 'sandbox-result-exit-code result))
           "an unrestricted sandbox could not read /etc: ~S" result)))

(deftest test-executable-must-be-permitted
  "Rules that do not allow the command to execute are refused up front, rather
than surfacing as EACCES from execve and reading like a broken command."
  (let ((condition (nth-value 1 (ignore-errors
                                 (run-with-rules "echo hi" '((:read "/etc")))))))
    (check (typep condition 'scute:sandbox-setup-error)
           "a command with no execute rule was allowed to launch, got ~S" condition)
    (check (and (typep condition 'scute:sandbox-setup-error)
                (eq :executable-not-permitted
                    (scute:sandbox-setup-error-operation condition)))
           "the refusal did not name the missing execute access: ~S" condition)))

(deftest test-rule-path-must-exist
  "A rule naming a path that is not there is an error, not a rule to skip.
The fault is in the declaration, so it is reported as one."
  (let ((condition (nth-value 1 (ignore-errors
                                 (run-with-rules "true" '((:read "/no/such/path")))))))
    (check (typep condition 'scute:policy-error)
           "a nonexistent rule path was accepted, got ~S" condition)))

(deftest test-unknown-access-kind-is-refused
  "Only the four documented access kinds mean anything."
  (let ((condition (nth-value 1 (ignore-errors
                                 (run-with-rules "true" '((:read-only "/usr")))))))
    (check (typep condition 'scute:usage-error)
           "an unknown access kind was accepted, got ~S" condition)))

(deftest test-a-rule-on-the-root
  "A policy may name the root.  Trimming its trailing slash would leave an empty
path the kernel cannot open, so the root is the one path that keeps its slash."
  (let ((result (call-scute 'run-namespaced-command
                            '("/bin/sh" "-c" "cat /etc/hostname > /dev/null")
                            :filesystem '((:read-write-execute "/")))))
    (check (eql 0 (call-scute 'sandbox-result-exit-code result))
           "a sandbox granted the whole filesystem could not read /etc: ~S" result)))

(deftest test-security-unix-isolation-is-independent-of-filesystem-grants
  ;; Even namespaces-only and learning must isolate the same-uid control socket.
  (unless (unix-isolation-available-or-refused-p)
    (return-from test-security-unix-isolation-is-independent-of-filesystem-grants nil))
  (let ((ruleset (call-scute 'compile-filesystem-ruleset nil "/bin/true"
                             :isolate-unix t)))
    (unwind-protect
         (check (and ruleset (>= ruleset 0)) "Unix isolation was omitted with no filesystem grants")
      (when ruleset (sb-posix:close ruleset))))
  (dolist (kind '(:read :read-execute :read-write :read-write-execute))
    (check (zerop (logand (ash 1 16) (call-scute 'kind-rights kind 9)))
           "a broad filesystem grant exposes preexisting Unix sockets")))

(deftest test-unix-pathname-isolation-denies-host-and-allows-sandbox-ipc
  "Exercise RESOLVE_UNIX against real pathname sockets in a disposable process."
  (unless (unix-isolation-available-or-refused-p)
    (return-from test-unix-pathname-isolation-denies-host-and-allows-sandbox-ipc nil))
  (let* ((base (scratch-pathname "unix-domain"))
         (source (concatenate 'string base ".c"))
         (program (concatenate 'string base ".bin"))
         (host (concatenate 'string base ".host"))
         (local (concatenate 'string base ".local"))
         (ruleset (call-scute 'compile-filesystem-ruleset nil "/bin/true" :isolate-unix t)))
    (unwind-protect
         (progn
           (with-open-file (out source :direction :output :if-exists :supersede)
             (write-string "#define _GNU_SOURCE
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
static int listener(char *path) {
  int fd=socket(AF_UNIX,SOCK_STREAM,0);
  struct sockaddr_un a={.sun_family=AF_UNIX};
  strncpy(a.sun_path,path,sizeof(a.sun_path)-1);
  if(fd<0 || bind(fd,(void*)&a,sizeof(a)) || listen(fd,1)) return -1;
  return fd;
}
static int connection(char *path) {
  int fd=socket(AF_UNIX,SOCK_STREAM,0), result, saved;
  struct sockaddr_un a={.sun_family=AF_UNIX};
  strncpy(a.sun_path,path,sizeof(a.sun_path)-1);
  if(fd<0) return -1;
  result=connect(fd,(void*)&a,sizeof(a)); saved=errno; close(fd); errno=saved;
  return result;
}
int main(int argc,char **argv) {
  if(argc!=4) return 10;
  int host=listener(argv[2]); if(host<0) return 11;
  if(prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0) || syscall(446,atoi(argv[1]),0)) return 12;
  close(atoi(argv[1]));
  if(connection(argv[2])==0 || errno!=EACCES) return 13;
  int local=listener(argv[3]); if(local<0) return 14;
  if(connection(argv[3])) return 15;
  close(local); close(host); return 0;
}
" out))
           (check (zerop (cffi:foreign-funcall "system" :string
                           (format nil "gcc -Wall -Wextra -o ~A ~A" program source) :int))
                  "could not compile the Unix isolation probe")
           ;; The only inherited extra descriptor is the ruleset under test.
           (sb-posix:fcntl ruleset sb-posix:f-setfd 0)
           (let ((status (cffi:foreign-funcall "system" :string
                           (format nil "~A ~D ~A ~A" program ruleset host local) :int)))
             (check (zerop status)
                    "Unix isolation probe status ~D (11=host socket unavailable, 13=host access, 15=internal IPC denied)"
                    status)))
      (sb-posix:close ruleset)
      (delete-scratch source program host local))))

(deftest test-security-old-landlock-refuses-unix-isolation
  (loop for abi from 1 below 9
        do (check (nth-value 1 (ignore-errors (call-scute 'require-unix-isolation abi)))
                  "ABI ~D was accepted for host Unix socket isolation" abi))
  (call-scute 'require-unix-isolation 9))
