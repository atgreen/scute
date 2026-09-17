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
before the command runs, never a weaker sandbox than the one it asked for. The
kernel is addressed directly — `clone3`, `landlock_create_ruleset`, `capset`,
`prctl` — with no helper binary to install, trust, or keep in step.

## Status

Scute is v0 and unfinished, but it runs. Two layers are in place — the process
layer (fresh user, mount, PID, UTS, and network namespaces; every capability
set emptied; `no_new_privs`; the sandbox dies with its supervisor) and the
filesystem layer, one Landlock ruleset the child enforces on itself just before
it execs. Policy files work, and so does describing the filesystem directly on
the command line:

```sh
scute run --read-execute /usr --read /etc --read-write . -- /bin/sh -c 'ls; echo hi > note'
```

Nothing outside those paths can be opened — including, note, `/proc` and
`/dev/null`, which most programs expect; grant them explicitly when a command
needs them. To run with no filesystem restriction at all, say so:

```sh
scute run --namespaces-only -- COMMAND
```

`scute doctor` reports what the host can enforce and exits non-zero if
something mandatory is absent.

A policy may already ask for resource limits or auditing, and Scute will refuse
to launch rather than pretend: those controls are designed but not built, and
silently skipping one would hand back a weaker sandbox than the policy asked
for.

Still to come: cgroup-v2 resource limits, the seccomp filter, and optional eBPF
auditing. `docs/design.md` is the architecture. The task graph
lives in [beads](https://github.com/steveyegge/beads); `bd ready` shows what is
claimable.

## Policy

A policy is a TOML document, validated whole before anything privileged
happens. Anything the schema does not name -- an unknown table, an unknown key,
a value of the wrong shape -- is an error rather than a line quietly ignored.

```toml
[filesystem]
read-execute = ["/usr"]
read = ["/etc"]
read-write = ["."]

[network]
mode = "none"
```

```sh
scute run --policy scute.policy -- /bin/sh -i
scute run --policy scute.policy --dry-run -- /bin/sh -i   # show, run nothing
```

`--dry-run` prints the compiled plan: canonical paths, the command that will
actually run, and the directory it runs in. Reviewing that is cheaper than
reasoning about what a policy implies.

## Building

Scute needs SBCL and [ocicl](https://github.com/ocicl/ocicl) for its
dependencies, which `ocicl.csv` pins.

```sh
ocicl install
make          # builds ./scute
make test     # runs the test suite
```

Some tests exercise the kernel directly, so they need a Linux host with
unprivileged user namespaces and Landlock enabled.

## Author and License

`scute` was written by Anthony Green and is distributed under the terms of the
MIT license.
