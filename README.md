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

`scute learn` writes the policy for you by watching a command run; see below.

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

## Quickstart

```sh
$ cd ~/project
$ cat > scute.policy <<'EOF'
[filesystem]
read-execute = ["/usr"]
read = ["/etc", "/proc"]
read-write = [".", "/dev/null"]

[network]
mode = "none"
EOF

$ scute run --policy scute.policy -- sh -c 'echo hello > note && cat note'
hello

$ scute run --policy scute.policy -- sh -c 'cat ~/.ssh/id_rsa'
cat: /home/you/.ssh/id_rsa: Permission denied

$ scute run --policy scute.policy -- curl -sS https://example.com
curl: (6) Could not resolve host: example.com
```

The write landed because the policy allows this directory. The key was refused
because nothing in the policy names it. The network is gone because the sandbox
has a network namespace of its own with nothing in it — not a proxy, not a
filter, no route at all — and because unix-domain sockets are refused as well,
which is less obvious and mattered more: a namespace does not stop a command
connecting to `systemd-resolved`, the system D-Bus or an `ssh-agent` by their
socket paths, and Landlock does not govern `connect`. `socketpair` still works,
so a program can talk to itself.

Don't want to write that file yourself? `scute learn` will.

## What this protects against, and what it does not

Scute confines a command to the filesystem, the resources, and the system calls
a policy names. It is a **native sandbox**: one process tree on your own kernel,
not a container and not a virtual machine.

Scute needs no privileges of its own: it is not setuid, carries no file
capabilities, and expects no root. Everything it installs, an ordinary user may
install for their own processes.

It is meant for code you have reason to distrust but still want to run — a build
script from a repository you just cloned, a dependency's install hook, an agent
acting on your behalf. Within a sandbox, a command cannot read files the policy
does not name, cannot write outside what it was given, cannot reach the network,
cannot regain a capability, cannot put itself in a fresh user namespace, and
cannot exceed the memory, process, or CPU limits it was given.

It does **not** contain an attack on the kernel itself. Every layer here —
Landlock, seccomp, namespaces, cgroups — is enforced by the kernel you are
already running, so a kernel bug reachable from the calls the policy still
permits is outside what Scute can promise. If your threat model includes kernel
exploits, you want a virtual machine, and you want it as well as this rather
than instead of it.

Three more limits worth knowing. A sandboxed command shares your kernel's
clocks, load and other side channels, so it can observe more than it can touch.
A consequence of refusing unix-domain sockets is that a command which wants to
create its own — a language server, a test harness talking to a helper — cannot;
say so if that bites and it can become something a policy asks for.
`scute learn` sees one run, not every path a program might take. And a policy is
only as good as its narrowest rule: `read-write = ["/"]` is a policy, and it
protects nothing.

## Learning a policy

Writing a least-privilege policy by hand is the main cost of using any sandbox:
you guess, the command fails somewhere deep inside a library, you guess again.
Scute will do the guessing by running the command once and writing down what it
actually reached for.

```sh
$ scute learn -- /bin/sh -c 'cat /etc/hostname > copy; ls > listing'
# Learned by watching /bin/sh -c cat /etc/hostname > copy; ls > listing run once.
# A starting point, not a finished policy: one run sees one path through
# the program.  Narrow it, then check it with scute check.

[filesystem]
read = ["/etc"]
read-execute = ["/usr"]
read-write = [".", "/dev/tty"]

[network]
mode = "none"
```

`scute learn --output scute.policy -- make` keeps the answer. The command then
runs under it:

```sh
scute run --policy scute.policy -- make
```

It works by seccomp user notification: the kernel parks the command on each
path-taking syscall and hands a description to scute, which reads the path,
records it, and lets the call continue. No privilege, no ptrace, no cooperation
from the command. Nothing is restricted during a learning run — that is the
point — but the rest of the sandbox still applies, because the notifications and
the denylist live in the same filter.

Two honest caveats. One run sees one path through a program: a build that
downloads on a cold cache and not on a warm one will teach you the warm case.
And the mechanism is sound for *watching* but not for *deciding* — a path can
change between the notification and the syscall — which is exactly why learning
writes a draft for you to read rather than enforcing what it saw.

## When a policy is wrong

A sandboxed command that is refused something reports its own confusion —
`Permission denied`, from somewhere deep inside a library — and leaves you
guessing which line a policy is missing. Ask instead:

```sh
$ scute run --policy scute.policy --explain -- ./build.sh
/usr/bin/bash: line 1: copy: Permission denied
scute: the command was refused 3 paths:
  /dev/tty                                      write
  /etc/ld.so.cache                              read
  /home/you/project/copy                        write

Adding this to the policy would allow them:

[filesystem]
read = ["/etc"]
read-write = [".", "/dev/tty"]
```

A seccomp filter runs at syscall entry, before the security modules decide
anything, so scute sees the attempt Landlock went on to refuse. `--explain`
enforces the policy exactly as usual — it only watches as well, at the cost of
a round trip per path, which is why it is a flag rather than the default.

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

Every table and key it may contain:

| Table | Key | Value | Meaning |
|---|---|---|---|
| `[filesystem]` | `read` | array of paths | read files, list directories |
| | `read-execute` | array of paths | the same, and execute |
| | `read-write` | array of paths | read, write, create, delete, rename |
| | `read-write-execute` | array of paths | the same, and execute |
| `[network]` | `mode` | `"none"` | the only mode v0 knows |
| `[limits]` | `memory` | size, e.g. `"2G"` | and no swapping around it |
| | `processes` | integer | `pids.max` |
| | `cpu-percent` | integer | 100 is one processor |
| `[audit]` | `events` | `["exec", "connect"]` | designed; this build refuses rather than pretends |

A relative path means what it says from where scute was invoked and may not
climb out of it. Anything the schema does not name — an unknown table, an
unknown key, a value of the wrong shape, a duplicate key — is an error, and the
policy is refused whole rather than enforced in part.

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

## When something will not run

| What you see | What it usually means |
|---|---|
| `Permission denied` from the command | The policy is missing a path. Re-run with `--explain` and it will tell you which, and the lines to add. |
| `/dev/null: Permission denied` | Landlock grants nothing implicitly. Name `/dev/null`, and usually `/proc`, in the policy. |
| A binary you just built will not run | A directory granted `read-write` can hold it; running it needs `read-write-execute`. |
| `This build cannot enforce resource limits` | Cgroup v2 will not let a cgroup holding processes give controllers to its children. Run scute in a cgroup of its own: `systemd-run --user --scope -p Delegate=yes scute run ...` |
| `command not found` for something on your `PATH` | The command must be an absolute path: a sandbox whose command is chosen by searching `PATH` depends on the environment it inherited. |
| `scute doctor` exits non-zero | It names the missing control. Landlock needs Linux 5.13 or newer, and unprivileged user namespaces must be enabled. |

## Completions

```sh
source <(scute completions bash)     # or zsh, or fish
```

They are generated from scute's own command tree rather than maintained beside
it, so an option is completable the moment it exists. `make completions` writes
all three into `completions/`, and the packages install them.

## Author and License

`scute` was written by Anthony Green and is distributed under the terms of the
MIT license.
