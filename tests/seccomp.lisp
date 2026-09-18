;;; SPDX-License-Identifier: MIT
;;;
;;; The system-call filter: that it is built, that it is installed, and that it
;;; refuses what it claims to refuse.

(in-package #:scute/tests)

(defparameter +unrestricted+ '()
  "No filesystem rules, so the filter is the only thing that can refuse.")

(deftest test-filter-denies-what-it-claims
  "The filter is built from a declared list, and every name on it is either
denied or absent from this architecture -- never quietly dropped."
  (let* ((filter (call-scute 'v0-seccomp-filter))
         (denied (call-scute 'seccomp-filter-denied filter))
         (unavailable (call-scute 'seccomp-filter-unavailable filter))
         (declared (call-scute 'denied-syscall-names)))
    (check (plusp (call-scute 'seccomp-filter-instructions filter))
           "the filter compiled to no instructions")
    (dolist (name declared)
      (check (or (member name denied :test #'string=)
                 (member name unavailable :test #'string=))
             "~A is neither denied nor accounted for as absent" name))
    ;; The groups the design names, pinned so an edit cannot drop one silently.
    (dolist (name '("keyctl" "add_key" "bpf" "perf_event_open" "ptrace"
                    "unshare" "setns" "mount" "pivot_root"
                    "open_by_handle_at" "name_to_handle_at"
                    "userfaultfd" "io_uring_setup" "init_module" "kexec_load"
                    "clock_settime" "quotactl"))
      (check (member name denied :test #'string=)
             "~A is no longer denied" name))))

(deftest test-filter-is-installed-in-the-child
  "The child runs under a seccomp filter, with no_new_privs set so that no exec
can win back a privilege."
  (let ((status (sandbox-says "grep -E '^(Seccomp|Seccomp_filters|NoNewPrivs):' /proc/self/status"
                              (append +system-rules+ '((:read "/proc"))))))
    (check (search (format nil "Seccomp:~C2" #\Tab) status)
           "the child is not in seccomp filter mode:~%~A" status)
    (check (search (format nil "Seccomp_filters:~C1" #\Tab) status)
           "the child carries no filter:~%~A" status)
    (check (search (format nil "NoNewPrivs:~C1" #\Tab) status)
           "no_new_privs was not set:~%~A" status)))

(deftest test-denied-syscall-is-refused
  "A denied call fails for the sandboxed command.

unshare is the one to test with, because creating a user namespace needs no
capability at all: before the filter existed this very command exited 0, so a
refusal here is the filter's work and nothing else's."
  (let ((denied (call-scute 'run-namespaced-command
                            '("/usr/bin/unshare" "--user" "/bin/true")
                            :filesystem +unrestricted+))
        (allowed (call-scute 'run-namespaced-command
                             '("/usr/bin/unshare" "--version")
                             :filesystem +unrestricted+)))
    (check (not (eql 0 (call-scute 'sandbox-result-exit-code denied)))
           "a nested user namespace was allowed: ~S" denied)
    (check (eql 0 (call-scute 'sandbox-result-exit-code allowed))
           "the same binary could not even run: ~S -- the refusal above may not ~
            be the filter's" allowed)))

(deftest test-ordinary-work-still-runs
  "The filter is a denylist, and ordinary software must not notice it.  Compiling
a C program exercises far more of the system-call surface than a shell does."
  (let ((directory (scratch-pathname "seccomp-build")))
    (unwind-protect
         (progn
           (ensure-directories-exist (format nil "~A/" directory))
           (with-open-file (stream (format nil "~A/hello.c" directory)
                                   :direction :output :if-exists :supersede)
             (write-line "int main(void){return 7;}" stream))
           (let ((result (call-scute
                          'run-namespaced-command
                          (list "/bin/sh" "-c"
                                (format nil "cd ~A && gcc -O2 -o hello hello.c && ./hello"
                                        directory))
                          :filesystem +unrestricted+)))
             (check (eql 7 (call-scute 'sandbox-result-exit-code result))
                    "compiling and running a C program under the filter gave ~S"
                    result)))
      (dolist (name '("hello.c" "hello"))
        (ignore-errors (delete-file (format nil "~A/~A" directory name))))
      (ignore-errors (sb-posix:rmdir directory)))))

(deftest test-supervisor-holds-no-capabilities
  "By the time a command exists, the supervisor has dropped everything it could
pass on, and has checked rather than assumed."
  (call-scute 'run-namespaced-command '("/bin/true") :filesystem +unrestricted+)
  (call-scute 'verify-no-capabilities)          ; signals if anything is left
  (dolist (entry (call-scute 'capability-sets))
    (when (member (car entry) '("CapEff" "CapPrm" "CapInh" "CapAmb") :test #'string=)
      (check (zerop (cdr entry))
             "the supervisor still holds ~A = ~(~16,'0X~)" (car entry) (cdr entry)))))

(deftest test-nested-user-namespaces-are-refused
  "A command cannot put itself in a new user namespace, by any of the three
routes.  This matters more than the rest of the denylist: a nested user
namespace hands its creator a full capability set inside itself, which is where
a great many kernel exploits begin."
  (let ((filter (call-scute 'v0-seccomp-filter)))
    (dolist (name '("clone(CLONE_NEWUSER)" "clone3" "unshare"))
      (check (member name (call-scute 'seccomp-filter-denied filter) :test #'string=)
             "~A is not among what the filter denies" name)))
  ;; unshare, which needs no capability and worked before the filter existed.
  (let ((result (call-scute 'run-namespaced-command
                            '("/usr/bin/unshare" "--user" "/bin/true")
                            :filesystem +unrestricted+)))
    (check (not (eql 0 (call-scute 'sandbox-result-exit-code result)))
           "unshare --user was allowed: ~S" result))
  ;; And clone itself, which seccomp can only refuse by reading its flags.
  ;; The suffix matters: gcc will not compile a file it cannot recognize, and
  ;; scratch-pathname ends its names with a pid.
  (let ((source (format nil "~A.c" (scratch-pathname "nested")))
        (program (scratch-pathname "nested")))
    (unwind-protect
         (progn
           (with-open-file (stream source :direction :output :if-exists :supersede)
             (write-string "#define _GNU_SOURCE
#include <sched.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <signal.h>
int main(void) {
  long p = syscall(SYS_clone, (unsigned long)(CLONE_NEWUSER | SIGCHLD), 0L, 0L, 0L, 0L);
  if (p < 0) return 7;          /* refused */
  if (p == 0) _exit(0);
  return 0;                     /* a namespace was created */
}
" stream))
           (if (plusp (cffi:foreign-funcall
                       "system" :string
                       (format nil "gcc -o ~A ~A >/dev/null 2>&1" program source)
                       :int))
               (format *error-output*
                       "~&SKIP: no working gcc, so the clone route is untested~%")
               (let ((result (call-scute 'run-namespaced-command (list program)
                                         :filesystem +unrestricted+)))
                 (check (eql 7 (call-scute 'sandbox-result-exit-code result))
                        "clone(CLONE_NEWUSER) was not refused inside the sandbox: ~S"
                        result))))
      (delete-scratch source program))))
