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

Scute is v0 and unfinished, but it runs. Three layers are in place — the process
layer (fresh user, mount, PID, UTS, and network namespaces; every capability set
emptied; `no_new_privs`; the sandbox dies with its supervisor), the filesystem
layer (one Landlock ruleset the child enforces on itself just before it execs),
and a seccomp filter denying the system calls a confined command has no business
making. Policy files work, and so does describing the filesystem directly on
the command line:

```sh
scute run --read-execute /usr --read /etc --read-write . -- /bin/sh -c 'ls; echo hi > note'
```

Nothing outside those paths can be opened — including, note, `/proc` and
`/dev/null`, which most programs expect; grant them explicitly when a command
needs them. The distinction between `--read-write` and `--read-write-execute`
is real: a directory granted the first can hold a binary you just compiled, but
running it needs the second. To run with no filesystem restriction at all, say so:

```sh
scute run --namespaces-only -- COMMAND
```

`scute doctor` reports what the host can enforce and exits non-zero if something
mandatory is absent. `scute doctor --json` says the same thing to a script.

Exit statuses are the shell's, so scripts can read them:

| status | meaning |
|---|---|
| the command's own | the command ran and ended by itself |
| 128 + signal | a signal ended the command (137 = killed, often a memory limit) |
| 64 | the command line asked for something impossible |
| 65 | the policy is not one Scute will accept |
| 126 | the command exists but could not be executed |
| 127 | the command does not exist |
| 1 | a control this host could not establish |

Resource limits work where the kernel will allow them:

```toml
[limits]
memory = "2G"          # and no swapping around it
processes = 256
cpu-percent = 200      # two processors' worth
```

Cgroup v2 will not let a cgroup hold processes and give controllers to its
children at the same time, so limits need Scute to have a cgroup of its own —
`systemd-run --user --scope -p Delegate=yes scute run ...`, or a service with
`Delegate=yes`. Where that is not the case, asking for limits is refused with
the remedy in the message rather than quietly ignored. `scute doctor` says which
you have.

A policy may still ask for auditing, which is designed but not built; Scute
refuses to launch rather than hand back a weaker sandbox than the policy asked
for. That is the last of v0 still outstanding. `docs/design.md` is the architecture. The task graph
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

And when the question is "will my build be able to write there?", ask:

```sh
$ scute check --policy scute.policy . /usr/bin/gcc /etc/passwd /var/tmp/out
.                             read write        (read-write /home/you/project)
/usr/bin/gcc                  read execute      (read-execute /usr)
/etc/passwd                   read              (read /etc)
/var/tmp/out                  nothing           via /var/tmp
```

`check` is pure arithmetic over the policy — it launches nothing — and exits
non-zero if any path is wholly denied, so it belongs in CI next to the policy
it guards. A path that does not exist yet is answered by the nearest directory
that does, because that is what governs creating it.

## Building

Scute needs SBCL and [ocicl](https://github.com/ocicl/ocicl) for its
dependencies, which `ocicl.csv` pins.

```sh
ocicl install
make          # builds ./scute
make test     # builds it, then runs the suite against it
```

`make` leaves the core uncompressed, which starts in around 75 ms rather than
around 215 ms, at the cost of a larger file on disk. A tool you wrap around
every command should not make you wait for it. Build with
`SCUTE_COMPRESSION=9 make` for roughly a quarter of the size and the slower
start.

Some tests exercise the kernel directly, so they need a Linux host with
unprivileged user namespaces and Landlock enabled.

## Author and License

`scute` was written by Anthony Green and is distributed under the terms of the
MIT license.
