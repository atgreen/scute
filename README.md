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
sudo make install    # /usr/local: the binary, man page, completions, policies
```

`make install PREFIX=~/.local` installs into your own home instead, policies
included, with no root involved. RPM and Debian packaging live in `releng/`.

It also needs [KeyFence](https://github.com/atgreen/keyfence), which holds the
credentials a sandbox must not: a policy that says nothing about the network is
routed through it. Run it as a service, which is where credentials belong:

```sh
systemctl --user enable --now keyfence.socket keyfence-api.socket
```

A policy with `[network] mode = "none"` needs no broker, and is the one
configuration that works without one.

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

## Running an agent by name

Scute ships policies for the agents people actually run, and installs them where
it looks for them — so the policy name is the command:

```sh
scute codex               # codex, confined to this directory
scute claude              # claude code, with its key held by the broker
scute bash                # a shell in this directory and nowhere else

scute codex -- "work through the ready beads"    # arguments go to the agent
scute policies            # what this host has, and which file each came from
```

`scute codex` is exactly `scute run --policy codex` — one code path, one set of
options, one plan from `--dry-run`. A built-in command always wins, so a policy
named `doctor` cannot take over `scute doctor`.

Each shipped policy carries the command it is for, including the flag that makes it
work. Codex wraps every command it runs in bubblewrap, which cannot nest inside
Scute's namespaces and fails claiming your kernel forbids user namespaces; the
policy passes `--dangerously-bypass-approvals-and-sandbox`, because Scute is the
sandbox and the inner one is redundant and broken. A flag like that belongs where
the policy is reviewed, not in a README somebody skims.

Policies are looked for in, nearest first:

| Directory | For |
|---|---|
| `~/.config/scute/policies` | yours, and an upgrade will not touch it |
| `~/.local/share/scute/policies` | `make install PREFIX=~/.local` |
| `/usr/local/share/scute/policies` | `make install` |
| `/usr/share/scute/policies` | the package |

`SCUTE_POLICY_PATH` replaces the list. A path is never shadowed by a name:
`--policy ./mine.policy` is that file.

### Extending a policy you do not own

A policy Scute ships cannot know that your skills are symlinked into another
repository, or that you want one more credential in every run. Rather than copying
it — and never seeing an improvement again — put fragments in `NAME.d`:

```sh
mkdir -p ~/.config/scute/policies/codex.d
cat > ~/.config/scute/policies/codex.d/10-skills.policy <<'EOF'
# ~/.codex/skills/* are symlinks into my repositories, and Landlock resolves a
# symlink to its target, so the target has to be granted too.
[filesystem]
read = ["?~/git/hackinator", "?~/git/testinator"]
EOF
```

A fragment is not a whole policy: two extra paths is the point of it. One rule
covers the merge — **an array appends, a scalar's last value wins, a table merges
key by key** — so a fragment adds paths, adds arguments, and replaces a mode, a
limit or a program by naming another. Fragments are read in filename order, and
your own directory has the last word over one shipped beside the policy.

Every file that contributed is named by `--dry-run`:

```
policy       /usr/share/scute/policies/codex.policy
             + /home/green/.config/scute/policies/codex.d/10-skills.policy
```

This widens what a policy grants, and that is not a hole: anyone who can write a
drop-in could copy the whole policy instead. (The operator-side mechanism, which
can only narrow, is a different one.)

### Paths a policy is not sure about

A shipped policy has to describe machines it has never seen, so a `?` before a path
means *if this host has it*:

```toml
read-execute = ["/usr", "?/home/linuxbrew/.linuxbrew", "?~/.local/bin"]
```

An unmarked path that does not exist is still refused — a typo in a path is the
commonest way to grant nothing while believing otherwise. What was skipped is
printed, never silent:

```
absent       ~/.nvm (optional; not on this host)
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

`check` also answers for credentials, which fail in a much harder place to read —
an agent getting a 401 from somewhere inside itself:

```console
$ scute check --policy agent.policy .
.                             read write        (read-write /home/you/project)
anthropic          registered with the broker (anthropic)
github             NOT registered with the broker (githbu)
```

A name the broker does not know is a fault in the policy and exits non-zero. A
broker that cannot be reached at all says `cannot tell` and does not, because
that is a fact about this host rather than a mistake in the policy.

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

`--explain` enforces the policy exactly as usual; it only watches as well, at the
cost of a round trip per path. That is why it is a flag rather than the default:
on a command touching 189,000 paths it took 1.57s against 0.19s, while for a small
one the difference is invisible. When a command fails and someone is watching,
scute says that `--explain` would answer why; in a script it stays quiet, and
`SCUTE_NO_HINTS=1` silences it everywhere.

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
| `[network]` | `mode` | `"none"`, `"host"` or `"proxied"` | no network, the host's, or the host's with every web connection sent to the proxy. Omit the table, or the key, and it is the host's through KeyFence |
| | `connect-tcp` | array of ports | the only TCP ports the command may connect to |
| | `bind-tcp` | array of ports | the only TCP ports it may listen on |
| | `proxy` | URL | set the proxy variables, and permit only its port (default: KeyFence on 10210, when `mode` is not named or is `"proxied"`) |
| | `allow` | array of `host:port` | the only addresses it may reach ([needs a privilege](#an-address-allowlist)) |
| | `unix-sockets` | `true` / `false` | may the command open an AF_UNIX socket (default `false`) |
| `[credentials.NAME]` | `ref` | name | a credential the broker holds, named rather than read |
| | `secret-file` | path | or a secret scute reads and the sandbox never sees |
| | `destinations` | array of hosts | where the token it is swapped for is worth anything |
| | `env` | variable name | where the sandbox finds its token |
| | `ttl` | duration | how long the token lives (default: the run) |
| `[limits]` | `memory` | size, e.g. `"2G"` | and no swapping around it |
| | `processes` | integer | `pids.max` |
| | `cpu-percent` | integer | 100 is one processor |
| | `wall-clock` | duration, e.g. `"30s"` | stop the command if it runs longer |
| `[audit]` | `events` | `["exec", "open", "connect"]` | what to record |
| `[environment]` | `keep` | array of names | variables to pass, beyond the default list |
| `[environment.set]` | any name | string | give the sandbox this value, whatever the caller had |

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

**A policy that says nothing about the network goes through KeyFence.** That is the
default, and it is the answer to the question Scute exists for: an agent that needs
a credential should never hold one. What the sandbox can do with that connection is
the broker's to decide: a request with no token is refused, a request with one gets
the real credential swapped in on the way past, and every one of them is a line in
an audit trail.

The default has two forms, and which one you get is a fact about the host:

| | How it holds | Needs |
|---|---|---|
| **Kernel redirect** | the destination of every web connection is rewritten to the broker, so a client that ignores the proxy variables arrives there anyway | `CAP_BPF`, which the packages grant |
| **Port-level** | Landlock permits the broker's port and nothing else, so a client that ignores the proxy variables reaches nothing | nothing |

`scute doctor` says which, and so does `--dry-run` for a given run. The packaged
binary carries `cap_bpf,cap_net_admin`, so the kernel redirect is the ordinary case;
a build from source gets the port-level form until `make egress`.

That capability is on a binary many people will have installed, so to be exact
about it: Scute loads one BPF program, which it compiled itself from forms in its
own source, attaches it to a cgroup it created, and then **drops every capability
it holds — `CapEff`, `CapPrm`, `CapInh` and `CapAmb`, verified empty — before the
sandboxed child exists at all.** The child never has them. `setcap -r` on the
binary declines the whole thing and leaves a Scute that still sandboxes.

Choosing the stronger form where it can be enacted is Scute's own default, not
something a policy asked for. A policy that writes `mode = "proxied"` itself is
still refused, loudly, on a host where the guard cannot be installed.

So this policy has network, and the sandbox has no way around the broker:

```toml
[filesystem]
read-execute = ["/usr"]
read = ["/etc", "/proc"]
read-write = ["."]
```

```
$ scute run --policy that.policy -- curl -s -o /dev/null -w '%{http_code}\n' https://api.github.com/
401
```

That 401 is KeyFence refusing a request it holds no credential for, and saying so
in the trail. Name a credential and the same request works, without the key ever
being inside the sandbox — see [Credentials](#credentials-the-sandbox-cannot-read).

KeyFence is therefore a **requirement**, not a companion: the package depends on
it, `scute doctor` reports it as missing rather than absent, and a run that needs a
broker it cannot find refuses with the line that installs one. A sandbox is spawned
one per run if no service is listening, which works and is worse — credentials
belong in a process somebody supervises:

```sh
systemctl --user enable --now keyfence.socket keyfence-api.socket
```

A run that asks the broker to hold nothing needs no control key: what it wants is a
port and the public CA certificate, and neither is a secret.

### No network at all

`mode = "none"` is the other end, and needs no broker — a sandbox with no network
cannot talk to one:

```toml
[network]
mode = "none"
```

That is what `scute bash` uses: a shell that cannot send what it read.

### The widths in between

When a policy wants the host's network rather than the broker's, it says so, and
there are four widths, narrowest last:

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

```toml
[network]
mode = "proxied"
proxy = "http://127.0.0.1:10210"     # every web connection goes here
```

A port is not an address: `connect-tcp = [443]` means any host on 443. Naming a
`proxy` sets `HTTPS_PROXY` and its friends for the command **and** permits TCP
to that port alone, so a command that ignores the variables still cannot reach
anything else. It is a proxy rather than a suggestion.

`mode = "proxied"` is the strongest of the four, and the only one that does not
depend on the command cooperating. It deliberately does **not** set `HTTPS_PROXY`
either: the kernel sends the traffic to the proxy whatever the command believes,
and setting the variables as well would mean the redirect was never the thing
being exercised. A policy that wants them can add them with `[environment.set]`. The others let a command reach the proxy;
this one *sends* it there — a BPF program on the sandbox's cgroup rewrites the
destination of every connection to port 80 or 443, and refuses anything else. A
tool that ignores `HTTPS_PROXY` gets proxied anyway instead of failing, so a
credential swap applies to code that never heard of a proxy.

Where the connection was going is not lost: the client still believes it is
talking to the original host, so it sends that host's name in the TLS handshake,
and the proxy reads it there. Cleartext HTTP has no handshake, so the `Host`
header answers instead. TLS to a bare IP address has neither and is refused.

Verified end to end, with no proxy variables in the sandbox at all:

```console
$ scute run --policy proxied.policy -- curl -s http://httpbin.org/bearer \
    -H "Authorization: Bearer $DEMO_TOKEN"
{ "authenticated": true, "token": "the-real-secret" }
```

The service received the real credential; the sandbox only ever had `kf_…`; and
nothing told curl a proxy existed.

Only 80 and 443 are redirected — sending SSH or a database connection to an HTTP
proxy would break it, and refusing is clearer than mangling. Port 53 is left alone
because a client resolves a name before it connects, and a sandbox that cannot
resolve never reaches the connect being redirected.

This needs [the one privilege](#an-address-allowlist) and a cgroup of its own, as
the address allowlist does.

**UDP.** Either guard accounts for `connect(2)`, and `sendto(2)` on an
unconnected socket never calls it — so until recently a sandbox whose TCP was
fully controlled could still send datagrams anywhere, which was an exfiltration
channel and is now closed by a second program at `sendmsg4`. Name resolution is
the exception, because a client resolves a name before it connects and a failed
resolution never reaches the connect being guarded. So a guarded sandbox can
still talk to a nameserver on port 53, and a nameserver is a channel; narrowing
that to the resolvers in `/etc/resolv.conf` would close most of what is left and
is not done yet.

QUIC is refused as a side effect, since it is UDP on 443. Clients fall back to
TCP, which is what you want here — an HTTP proxy cannot terminate QUIC.

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
ref = "anthropic"                      # the broker holds it; scute never sees it
destinations = ["api.anthropic.com"]   # where the token is worth anything
env = "ANTHROPIC_API_KEY"              # where the sandbox finds its token
```

```sh
scute run --policy agent.policy -- claude
```

`ref` names a credential registered with the broker:

```sh
gh auth token | keyfence credential add github     # into the OS keyring
keyfence credential list                           # what the broker can see
```
Scute asks for a token *by name*, so the plaintext lives in one process instead
of two, and rotating it is replacing that file.

Where nothing is registered, `secret-file` has scute read it and hand it over
instead:

```toml
[credentials.anthropic]
secret-file = "~/.secrets/anthropic"   # read by scute, never by the sandbox
```

One or the other, never both.

Scute mints a destination-locked token, hands the sandbox that token and the CA
certificate its runtimes must trust, runs the command, and revokes the token
afterwards. The command's environment holds
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

How tightly that is enforced depends on one privilege. Landlock filters TCP
ports, not addresses, so port-level enforcement alone leaves the sandbox able to
reach *some other host* on the proxy's port number — it cannot reach 443, and the
token is worthless anywhere but its destination, but a listener on port 10210
elsewhere is a path out for data the command can already read.

Where the [address-level guard](#an-address-allowlist) can be installed — which
needs both the capability and a cgroup of its own — scute closes that itself:
naming a proxy binds the proxy's **address**, not just its port, without your
having to say it twice. `--dry-run` shows which you got —

```console
network      the host's, shared
             through http://127.0.0.1:10210
             allow 127.0.0.1:10210 (127.0.0.1)      # address-level
             connect tcp 10210                      # port-level
```

— and where either is absent the `allow` line is missing, which is the honest
report: port-level egress, and a policy to read as such. Automatic narrowing is a
courtesy, so it is skipped rather than refused where it cannot be enacted; an
`allow` list you wrote yourself is still refused loudly.

The cgroup half scute arranges for itself: a plan that would be enacted better
from a cgroup of its own re-executes in a transient delegated scope, so
`scute run` is the whole command whether or not a policy asks for something a
cgroup is needed for.

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
would be a way to run anything at all. (`--with` takes a command line with quoting,
so an argument with a space in it needs no wrapper script — but it is an argument
vector written conveniently, not a shell: no expansion, no globbing, no
operators.) A `[credentials]` policy is the exception that proves the rule — it cannot name a program, only ask for the one
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

A policy can also **set** a variable, which is different from keeping one: keep
passes a value the caller already had, set gives the sandbox one the caller need
not have at all.

```toml
[environment.set]
GH_CONFIG_DIR = ".gh"                # not ~/.config/gh, which holds a token
CLAUDE_CONFIG_DIR = ".claude"
```

Setting wins over both the caller's value and `keep`, so what the command sees
does not depend on the shell it was started from. That matters more than it
sounds: a policy that works only when you remember to export something is not
really a policy, and the first time you forget, the tool reads the configuration
the sandbox was meant to keep it away from.

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

A wall-clock limit needs nothing of the host: it is scute's own timer. The rest
are cgroup v2, which will not let a cgroup hold processes and give controllers to
its children at the same time — a shell's cgroup holds the shell, so scute
cannot install limits in it.

Nothing to type: scute re-executes itself in a transient delegated scope
(`systemd-run --user --scope -p Delegate=yes`) when a plan needs one, inheriting
your terminal and exiting with whatever the command exits with. `SCUTE_NO_OWN_SCOPE=1`
turns that off, and then asking for limits is refused with the remedy in the
message rather than quietly ignored — as it is on a host with no systemd user
manager to ask.

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
{"event": "connect", "address": "1.1.1.1", "port": 53}
```

One JSON object per line. Without `--audit` it goes to stderr. It costs a round
trip per event, which is why a policy has to ask for it.

With a credential broker, its half of the same run lands in the same trail:

```json
{"event": "connect", "address": "127.0.0.1", "port": 10210}
{"event": "issue", "token_id": "e30756…", "task_id": "scute-2368978-1D8E2F", "label": "scute github"}
{"event": "allow", "token_id": "e30756…", "task_id": "scute-2368978-1D8E2F", "destination": "api.github.com", "method": "GET", "path": "/user"}
```

Scute knows which command ran and which paths it was refused; the broker knows
which credential went where. Every token minted for a run carries the same task
id, so the two halves join: one trail says which run used which credential
capability at which destination, with no token or secret value in it.

And when a command fails, what the broker refused is reported beside it — the
half of a failure the sandbox cannot see:

```console
$ scute run --policy agent.policy -- ./deploy.sh
curl: (22) The requested URL returned error: 401
scute: the broker refused 1 request:
  api.anthropic.com           token not allowed for destination api.anthropic.com
```

## When something will not run

| What you see | What it usually means |
|---|---|
| `Permission denied` from the command | The policy is missing a path. Re-run with `--explain` and it names them, with the lines to add — scute says so itself when a command fails and you are watching. |
| `/dev/null: Permission denied` | Nothing is granted implicitly. Name `/dev/null`, and usually `/proc`. |
| A binary you just built will not run | `read-write` can hold it; running it needs `read-write-execute`. |
| `cannot give controllers to children` | Scute needs a cgroup of its own and normally makes one. This means it could not: no systemd user manager in the session, or `SCUTE_NO_OWN_SCOPE=1`. Run it under `systemd-run --user --scope -p Delegate=yes scute run ...`. |
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

A smaller one, for anyone embedding this rather than running it: supervising a
sandbox installs handlers for the signals it forwards, and restores them to the
default afterwards rather than to whatever was there before. SBCL does not report
what a handler replaced, so there is nothing to put back. It does not affect
`scute` the command, whose signal handlers are its own.

Granting `/proc` grants more than it looks like. The sandbox gets a fresh PID
namespace, but not a fresh `/proc`: it sees the host's, so `read = ["/proc"]`
lets it read every process's command line. Environments are safe — the user
namespace maps your uid elsewhere, so `/proc/PID/environ` is refused — but a
secret passed as a command-line argument anywhere on the machine is legible to a
sandbox that has `/proc`. That is one reason to keep secrets out of argv.

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

Scute is v0 and runs. Everything described above works, and nothing a policy can
ask for is refused as unbuilt — `[audit]` records `"connect"` events as of this
version, which was the last piece outstanding.

`docs/design.md` is the architecture and the reasoning behind it. The task graph
lives in [beads](https://github.com/steveyegge/beads); `bd ready` shows what is
claimable.

## Author and License

`scute` was written by Anthony Green and is distributed under the terms of the
MIT license.
