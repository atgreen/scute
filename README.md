# Scute

Run one command inside a deny-by-default Linux sandbox.

```sh
scute run --policy scute.policy -- command ...
```

Scute confines a single command to the files, the network, the resources and the
system calls a policy names. It is a native sandbox — one process tree on your
own kernel, no container, no virtual machine, no daemon, and no root. A build
script from a repository you just cloned, a dependency's install hook, an agent
acting on your behalf: things you have reason to run and reason to distrust.

![scute](docs/demo.gif)

Nothing degrades quietly. A host missing anything the policy asks for —
Landlock, user namespaces, cgroup delegation, libseccomp — gets an error before
the command runs, never a weaker sandbox than the one it asked for.

**Contents** — [Install](#install) · [Quickstart](#quickstart) ·
[Writing a policy](#writing-a-policy) · [Policy reference](#policy-reference) ·
[Commands](#commands) · [Network](#network) ·
[Credentials](#credentials-the-sandbox-cannot-read) ·
[Environment](#environment) · [Limits](#limits-and-timeouts) ·
[Auditing](#auditing) · [When something will not run](#when-something-will-not-run) ·
[What it protects](#what-it-protects-and-what-it-does-not) ·
[What it costs](#what-it-costs) · [How it compares](#how-it-compares) ·
[Building](#building-from-source) · [Status](#status)

## Install

Scute is not published yet, so build it. It needs SBCL and
[ocicl](https://github.com/ocicl/ocicl), which `ocicl.csv` pins.

```sh
ocicl install
make                 # builds ./scute
sudo install -m 755 scute /usr/local/bin/      # optional
```

RPM and Debian packaging live in `releng/` for when there is somewhere to
publish them.

Then check the host can enforce what you will ask of it:

```sh
scute doctor
```

It names anything missing and exits non-zero if a mandatory control is absent.
Landlock needs Linux 5.13 or newer, and unprivileged user namespaces must be
enabled.

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
has a network namespace of its own with nothing in it — no route, no proxy, no
filter — and because unix-domain sockets are refused too, so a command cannot
reach `systemd-resolved` or the system bus by their socket paths either.

Two things surprise people first:

- **Nothing is implicit.** `/proc` and `/dev/null` are not granted unless you
  name them, and most programs expect both.
- **`read-write` does not imply execute.** A directory granted `read-write` can
  hold a binary you just compiled; running it needs `read-write-execute`.

You can skip the policy file and say it on the command line:

```sh
scute run --read-execute /usr --read /etc --read-write . -- ./build.sh
scute run --namespaces-only -- ./build.sh          # no filesystem restriction
```

## Writing a policy

Don't write it by hand. Run the command once and let scute write down what it
actually reached for:

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

```sh
scute learn --output scute.policy -- make     # keep it
scute learn --network -- ./deploy.sh          # also record what it connects to
scute run --policy scute.policy -- make       # then run under it
```

Nothing is restricted during a learning run — that is the point. It needs no
privileges and no cooperation from the command.

Two caveats. One run sees one path through a program: a build that downloads on
a cold cache and not on a warm one teaches you the warm case. And learning
writes a draft for you to read, not a policy to trust unread — narrow it, then
check it.

### Check it before you rely on it

```sh
$ scute check --policy scute.policy . /usr/bin/gcc /etc/passwd /var/tmp/out
.                             read write        (read-write /home/you/project)
/usr/bin/gcc                  read execute      (read-execute /usr)
/etc/passwd                   read              (read /etc)
/var/tmp/out                  nothing           via /var/tmp
```

`check` launches nothing and exits non-zero if any path is wholly denied, so it
belongs in CI beside the policy it guards. A path that does not exist yet is
answered by the nearest directory that does, because that is what governs
creating it.

`scute run --dry-run` prints the compiled plan instead of running it: canonical
paths, the command that will actually run, the directory it runs in, and the
names of the environment variables it will carry.

### When a policy is wrong

A refused command reports its own confusion — `Permission denied`, from
somewhere deep inside a library. Ask scute instead:

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

`--explain` enforces the policy exactly as usual; it only watches as well, at
the cost of a round trip per path, which is why it is a flag and not the
default.

## Policy reference

A policy is a TOML document, validated whole before anything happens. An unknown
table, an unknown key, a value of the wrong shape or a duplicate key is an error
— the policy is refused entire, never enforced in part.

| Table | Key | Value | Meaning |
|---|---|---|---|
| `[filesystem]` | `read` | array of paths | read files, list directories |
| | `read-execute` | array of paths | the same, and execute |
| | `read-write` | array of paths | read, write, create, delete, rename |
| | `read-write-execute` | array of paths | the same, and execute |
| `[network]` | `mode` | `"none"` or `"host"` | no network at all, or the host's, shared |
| | `connect-tcp` | array of ports | the only TCP ports the command may connect to |
| | `bind-tcp` | array of ports | the only TCP ports it may listen on |
| | `proxy` | URL | set the proxy variables, and permit only its port |
| | `allow` | array of `host:port` | the only addresses it may reach ([needs a privilege](#an-address-allowlist)) |
| | `unix-sockets` | `true` / `false` | may the command open an AF_UNIX socket (default `false`) |
| `[credentials.NAME]` | `secret-file` | path | a secret scute reads and the sandbox never sees |
| | `destinations` | array of hosts | where the token it is swapped for is worth anything |
| | `env` | variable name | where the sandbox finds its token |
| | `ttl` | duration | how long the token lives (default: the run) |
| `[limits]` | `memory` | size, e.g. `"2G"` | and no swapping around it |
| | `processes` | integer | `pids.max` |
| | `cpu-percent` | integer | 100 is one processor |
| | `wall-clock` | duration, e.g. `"30s"` | stop the command if it runs longer |
| `[audit]` | `events` | `["exec", "open"]` | what to record |
| `[environment]` | `keep` | array of names | variables to pass, beyond the default list |

A relative path means what it says from where scute was invoked, and may not
climb out of it.

## Commands

| | |
|---|---|
| `scute run --policy FILE -- COMMAND` | run COMMAND under a policy |
| `scute learn -- COMMAND` | run it unrestricted and write the policy it needed |
| `scute check --policy FILE PATH ...` | what the policy permits at each path |
| `scute doctor` | what this host can enforce (`--json` for scripts) |
| `scute completions bash` | shell completions (`zsh`, `fish`) |
| `scute man` | the manual page |

Useful flags to `run`:

| | |
|---|---|
| `--dry-run` | print the plan, run nothing |
| `--explain` | also report every path the policy refused |
| `--timeout 5m` | wall-clock limit, whatever the policy said |
| `--keep-env NAME` | pass one more environment variable |
| `--audit FILE` | write the audit trail here rather than to stderr |
| `--allow-unix-sockets` | permit AF_UNIX sockets |
| `--namespaces-only` | no filesystem restriction at all |
| `--with COMMAND` | run COMMAND beside the sandbox while it runs |
| `--broker-path PATH` | use this credential broker, not the one on `PATH` |

Exit statuses are the shell's, so scripts can read them:

| status | meaning |
|---|---|
| the command's own | the command ran and ended by itself |
| 128 + signal | a signal ended the command (137 = killed, often a memory limit) |
| 124 | stopped for running past its time limit, as `timeout(1)` has it |
| 64 | the command line asked for something impossible |
| 65 | the policy is not one scute will accept |
| 126 | the command exists but could not be executed |
| 127 | the command does not exist |
| 1 | a control this host could not establish |

## Network

`mode = "none"` is the default and gives the command no network at all. When it
needs one — a build fetching dependencies — there are four widths, narrowest
last:

```toml
[network]
mode = "host"                        # the host's network, shared
```

```toml
[network]
mode = "host"
connect-tcp = [443]                  # these ports only, kernel-enforced
```

```toml
[network]
mode = "host"
proxy = "http://127.0.0.1:10210"     # this proxy, and nothing else
```

```toml
[network]
mode = "host"
allow = ["api.github.com:443"]       # these addresses only
```

A port is not an address: `connect-tcp = [443]` means any host on 443. Naming a
`proxy` sets `HTTPS_PROXY` and its friends for the command **and** permits TCP
to that port alone, so a command that ignores the variables still cannot reach
anything else. It is a proxy rather than a suggestion.

`unix-sockets` is separate from all of this, because a network namespace does
not stop a command reaching `systemd-resolved`, the system bus or an
`ssh-agent` by socket path. It is refused by default and it is all or nothing:
Landlock cannot scope a socket path, so there is no way to permit the agent and
not the bus.

### An address allowlist

Everything else here works as an ordinary user. `allow` does not: it loads a BPF
program (`CAP_BPF`) and attaches it to the sandbox's cgroup (`CAP_NET_ADMIN`).

```sh
make egress        # builds, then grants -- one sudo setcap
```

For a package, `setcap cap_bpf,cap_net_admin+ep /usr/bin/scute` in `%post`, or a
systemd unit with `AmbientCapabilities=CAP_BPF CAP_NET_ADMIN`. A policy asking
for `allow` without the privilege is refused, not quietly downgraded to
port-level; `scute doctor` says which you have.

Three things to know:

- **Every rebuild loses it.** Capabilities live on the inode. Re-run `make
  egress` after `make`.
- **`strace` suppresses it.** ptrace prevents privilege elevation, so a policy
  needing `allow` fails only when traced — which looks like a scute bug and is
  not.
- **`CAP_BPF` is close to root.** A cap-bearing binary everyone may execute
  gives it to all of them. `chmod 750` and a group, or keep it to development
  and CI hosts.

The sandboxed command still runs with every capability set empty. Scute installs
the guard before dropping its own, and the tests check the result.

## Credentials the sandbox cannot read

Dropping secrets from the environment stops a command reading what it was never
given. It does nothing for the key the command legitimately needs: an agent that
calls an API holds that API's key, and so does everything it runs.

[KeyFence](https://github.com/atgreen/keyfence) is a credential broker — an
HTTPS proxy that holds the real secret and swaps it in on each request, so the
agent holds only an opaque `kf_` token locked to one destination. Scute drives
it:

```toml
[network]
mode = "host"
proxy = "http://127.0.0.1:10210"       # the broker: the only port it may reach

[credentials.anthropic]
secret-file = "~/.secrets/anthropic"   # read by scute, never by the sandbox
destinations = ["api.anthropic.com"]   # where the token is worth anything
env = "ANTHROPIC_API_KEY"              # where the sandbox finds its token
```

```sh
scute run --policy agent.policy -- claude
```

Scute reads the secret, mints a destination-locked token, hands the sandbox that
token and the CA certificate its runtimes must trust, runs the command, and
revokes the token afterwards. The command's environment holds
`ANTHROPIC_API_KEY=kf_dc8b83…` and nothing else of yours.

The reason to run the broker under scute is that `HTTPS_PROXY` is only a
convention. An agent that ignores it, a subprocess that never read it, or a
prompt-injected one told to avoid it connects straight out, and a proxy never
sees the request. Here the kernel refuses that: ordinary HTTPS is gone, because
naming a proxy permits its port and no other. Nor can the command mint tokens of
its own — the broker's control port is not the proxy port, so it is refused like
anything else:

```console
$ scute run --policy agent.policy -- bash -c 'exec 3<>/dev/tcp/127.0.0.1/10212'
bash: /dev/tcp/127.0.0.1/10212: Permission denied
```

Be precise about what that buys, though, because Landlock filters ports and not
addresses: the sandbox may still reach *some other host* on the proxy's port
number. It cannot reach 443, so it cannot talk to the API it holds a token for,
and the token is worthless anywhere but its destination in any case — but a
listener on port 10210 elsewhere is a path out for data the command can already
read. Close it by naming the address, which is enforced by the BPF guard rather
than by Landlock:

```toml
[network]
mode = "host"
proxy = "http://127.0.0.1:10210"
allow = ["127.0.0.1:10210"]          # the address too, not just the port
```

That needs [the one privilege](#an-address-allowlist). Without it, a policy gets
port-level egress and should be read as such.

`scute run --dry-run` prints which file a policy would read before it reads it,
and `scute doctor` says whether a broker is there to attach to. Attaching means
handing a broker your plaintext credential, so scute checks what is on the port
first: a broker is recognised by answering its own control API, not by returning
200 to a health check, which plenty of things would. Anything else there is an
error and the secret stays unread.

### Run the broker as a service

Scute attaches to a broker already running, and starts one per run only when
there is none. A service is better: no startup per run, one certificate
authority that stays put, and systemd confining the process that holds your
secrets.

```sh
sudo dnf install keyfence                                    # ships the units
systemctl --user enable --now keyfence.socket keyfence-api.socket
```

Those are socket units, so systemd holds the ports and starts the broker on the
first connection: enabled costs nothing until something wants a credential
swapped. KeyFence's units listen on loopback only, generate a control API key on
first start where scute looks for it, and run the broker with `NoNewPrivileges`,
`ProtectSystem=strict`, an empty capability bounding set and a system call filter
— the process holding the real credentials should be able to do less than the
agent it protects, not more.

`releng/keyfence.service` here is the same unit without the socket activation,
for a broker you built rather than installed.

### Anything else beside the sandbox

`--with` starts any command beside the sandbox, waits for the port the policy's
proxy names to answer, and stops it when the sandbox is done:

```sh
scute run --policy agent.policy --with keyfence -- claude
```

The command comes from the command line and never from a policy: a policy
travels with the code being sandboxed, and one that could start a host process
would be a way to run anything at all. (`--with` splits on spaces, so anything
needing quotes belongs in a small script.) A `[credentials]` policy is the
exception that proves the rule — it cannot name a program, only ask for the one
broker scute knows how to drive.

## Environment

A sandbox that confines the filesystem and hands over `AWS_SECRET_ACCESS_KEY`
has not confined much. Scute passes a short list and drops the rest:

```
HOME  LANG  LC_ALL  LC_CTYPE  LC_MESSAGES  LOGNAME  PATH  TERM  TZ  USER
```

Anything else is named:

```toml
[environment]
keep = ["CARGO_HOME", "RUSTUP_HOME"]
```

```sh
scute run --policy scute.policy --keep-env CARGO_HOME -- cargo build
```

This is where a sandbox stricter than you expect bites first: a tool wanting
`JAVA_HOME` or `SSH_AUTH_SOCK` will not find it until you say so. That is the
trade, and `SSH_AUTH_SOCK` in particular names an agent that will sign anything
asked of it.

## Limits and timeouts

```toml
[limits]
memory = "2G"          # and no swapping around it
processes = 256
cpu-percent = 200      # two processors' worth
wall-clock = "5m"      # or --timeout 5m
```

A command stopped for running too long exits **124**. It is sent `SIGTERM` and
given five seconds, unless it has no handler for `SIGTERM` — being PID 1 of its
namespace it would never see it — in which case it is killed immediately.

A wall-clock limit needs nothing of the host. The rest are cgroup v2, which will
not let a cgroup hold processes and give controllers to its children at the same
time, so they need scute to have a cgroup of its own:

```sh
systemd-run --user --scope -p Delegate=yes scute run --policy scute.policy -- make
```

Where that is not the case, asking for limits is refused with the remedy in the
message rather than quietly ignored.

## Auditing

```toml
[audit]
events = ["exec", "open"]
```

```sh
$ scute run --policy scute.policy --audit trail.jsonl -- ./build.sh
$ head -3 trail.jsonl
{"event": "start", "command": ["/usr/bin/bash", "-c", "./build.sh"]}
{"event": "exec", "access": "execute", "path": "/usr/bin/bash"}
{"event": "open", "access": "read", "path": "/etc/ld.so.cache"}
```

One JSON object per line. Without `--audit` it goes to stderr. It costs a round
trip per event, which is why a policy has to ask for it.

## When something will not run

| What you see | What it usually means |
|---|---|
| `Permission denied` from the command | The policy is missing a path. Re-run with `--explain` and it names them, with the lines to add. |
| `/dev/null: Permission denied` | Nothing is granted implicitly. Name `/dev/null`, and usually `/proc`. |
| A binary you just built will not run | `read-write` can hold it; running it needs `read-write-execute`. |
| `This build cannot enforce resource limits` | Scute needs a cgroup of its own: `systemd-run --user --scope -p Delegate=yes scute run ...` |
| `unix_listener: socket: Operation not permitted` | Something wants a unix-domain socket — often a shell's startup files starting an `ssh-agent`. `--allow-unix-sockets`, or `[network] unix-sockets = true`. |
| A learned policy is full of your dotfiles | bash sources `~/.bashrc` non-interactively when stdin is a socket, as under CI. Learn with `< /dev/null`, or `bash --norc`. |
| A tool cannot find its home or cache | The environment is filtered. `--keep-env JAVA_HOME`, or `[environment] keep = [...]`. |
| `command not found` for something on your `PATH` | The command must be an absolute path: a sandbox whose command is found by searching `PATH` depends on the environment it inherited. |
| A policy needing `allow` fails only under `strace` | ptrace suppresses file capabilities. Not a scute bug. |
| `cannot start a sandbox from inside one` | Exactly that: a sandbox refuses the syscalls a sandbox needs. Run it from outside. |
| `scute doctor` exits non-zero | It names the missing control. Landlock needs Linux 5.13 or newer, and unprivileged user namespaces must be enabled. |

## What it protects, and what it does not

Within a sandbox, a command cannot read files the policy does not name, cannot
write outside what it was given, cannot reach the network beyond what it was
allowed, cannot regain a capability, cannot put itself in a fresh user
namespace, and cannot exceed the memory, process or CPU limits it was given.

Scute needs no privileges of its own for any of that: it is not setuid, carries
no file capabilities, and expects no root. Everything it installs, an ordinary
user may install for their own processes.

It does **not** contain an attack on the kernel itself. Every layer here —
Landlock, seccomp, namespaces, cgroups — is enforced by the kernel you are
already running, so a kernel bug reachable from the calls a policy still permits
is outside what scute can promise. If your threat model includes kernel
exploits, you want a virtual machine, and you want it as well as this rather
than instead of it.

Three more limits worth knowing. A sandboxed command shares your kernel's
clocks and load, so it can observe more than it can touch. A command that wants
to create its own unix-domain socket — a language server, a test harness talking
to a helper — cannot, unless you allow sockets wholesale. And a policy is only
as good as its narrowest rule: `read-write = ["/"]` is a policy, and it protects
nothing.

## What it costs

Best of three passes of 25 runs each on one developer machine, so read them as
proportions rather than promises:

| | |
|---|---|
| `/bin/true`, no sandbox | 0.9 ms |
| `scute --version` — starting up, sandboxing nothing | 21.3 ms |
| `scute run --namespaces-only -- /bin/true` | 22.2 ms |
| `scute run --policy scute.policy -- /bin/true` | 24.3 ms |
| the same with `--explain` | 32.2 ms |

The sandbox is the cheap part: about a millisecond for the process layer, two or
three more to read a policy and install a Landlock ruleset. What you pay for is
scute starting at all, which is one Lisp image loading.

## How it compares

The other way to sandbox an agent is a platform: a container or a MicroVM, a
proxy in front of it, and the arrangement to manage. NVIDIA's
[OpenShell](https://github.com/NVIDIA/OpenShell) is that shape of tool, with a
gateway and a Kubernetes path. Scute is the other bet, and the difference is not
size — it is where the boundary sits.

|                           | Scute                                 | Container or MicroVM platform             |
| ------------------------- | ------------------------------------- | ----------------------------------------- |
| What is confined          | the process, by the kernel            | an image, by the runtime                  |
| Filesystem the agent sees | yours, minus what the policy withheld | one you assembled, entirely               |
| To start                  | `scute run --policy p -- cmd`         | build an image, start a daemon            |
| Startup cost              | about 20 ms                           | image build, then seconds                 |
| Needs root or a daemon    | no                                    | usually both                              |
| Egress control            | port and address, unbypassable        | HTTP verbs and hosts, via a proxy         |
| Writing the policy        | `scute learn` watches a real run      | by hand, then rebuild to test             |
| If it is misconfigured    | the command fails at the syscall      | the agent quietly has more than you meant |

A container boundary confines an *image*: whether the agent can read `~/.ssh` is
answered by what you copied in, and everything you did copy in is available to
whatever runs inside. Scute's boundary is the *process*, on the files you already
have — nothing copied, nothing built, the command running against your real
working tree while the kernel refuses every path the policy did not name. You
can narrow a container with bind mounts, but then the question is what you
remembered to leave out, and you find out after an image build rather than at the
first syscall. It is also why `learn` works: it watches the same process, on the
same paths, that will later run under the policy it writes.

What a proxy platform has that scute does not is HTTP-layer egress policy — it
can tell `GET` from `POST`. Scute stops at the port, but it stops there
unbypassably, so you can put any proxy you like in front of a sandboxed agent,
including one that does understand verbs, and know the agent cannot route around
it.

## Building from source

```sh
ocicl install
make          # builds ./scute
make test     # builds it, then runs the suite
make check    # the suite, then the smoke test
```

`make` leaves the image uncompressed, which starts in around 20 ms rather than
around 160 ms at the cost of a larger file; `SCUTE_COMPRESSION=9 make` trades
back. Some tests exercise the kernel directly, so they need a Linux host with
unprivileged user namespaces and Landlock.

Shell completions and the manual page are generated from scute's own command
tree, so a new option appears in both the moment it exists:

```sh
source <(scute completions bash)     # or zsh, or fish
scute man | man -l -
make completions man                 # write them out; the packages install them
```

## Status

Scute is v0 and runs. The process, filesystem, seccomp, limit, network,
credential and audit-trail machinery described above all work. One piece of the
design is not built: `[audit]` cannot yet record `"connect"` events, and a policy
asking for one is refused rather than handed a weaker sandbox than it asked for.

`docs/design.md` is the architecture and the reasoning behind it. The task graph
lives in [beads](https://github.com/steveyegge/beads); `bd ready` shows what is
claimable.

## Author and License

`scute` was written by Anthony Green and is distributed under the terms of the
MIT license.
