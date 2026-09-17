# Scute

Scute runs one local command inside a deny-by-default Linux sandbox.

```sh
scute run --policy scute.policy -- command ...
```

It is a native sandbox, not a container or a virtual machine. There is one
executable and no privileged daemon: a parent process establishes every
requested control, drops all of its own capabilities, and only then releases
the child that becomes the command. Scute shares the host kernel and does not
claim to contain kernel exploits.

Nothing degrades quietly. A host missing Landlock, user namespaces, cgroup
delegation, libseccomp, or any other control the policy asks for gets an error
before the command runs, never a weaker sandbox than the one it asked for.

## Status

Scute is v0 and unfinished. The kernel boundary works: `run-namespaced-command`
launches a command as PID 1 of fresh user, mount, PID, UTS, and network
namespaces, with every capability set empty and `no_new_privs` set, and
supervises it to completion. The command line above is the destination, not
today's behaviour — policy reading, the Landlock exec stage, cgroup limits,
seccomp, auditing, and the `run` command itself are still to come, so the
`scute` binary does nothing useful yet.

`docs/design.md` is the architecture. The task graph lives in
[beads](https://github.com/steveyegge/beads); `bd ready` shows what is
claimable.

## Policy

Policies are data-only Common Lisp forms, read with `*read-eval*` bound to
`nil` and validated before anything privileged happens.

```lisp
(sandbox
  (filesystem
    (read "/usr" "/bin" "/lib" "/lib64" "/etc")
    (read-write "."))
  (network none)
  (limits
    (memory "2G")
    (processes 256)
    (cpu-percent 200))
  (audit exec connect))
```

## Building

Scute needs SBCL and [ocicl](https://github.com/ocicl/ocicl) for its
dependencies, which `ocicl.csv` pins.

```sh
ocicl install
make          # builds ./scute
make test     # runs the test suite
```

Some tests exercise the kernel directly, so they need a Linux host with
unprivileged user namespaces enabled.

## Author and License

`scute` was written by Anthony Green and is distributed under the terms of the
MIT license.
