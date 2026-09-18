# Scute v0 design

## Goal

Scute runs one local command inside a deny-by-default Linux sandbox:

```text
scute run --policy scute.policy -- command ...
```

It is a native sandbox, not a container or virtual machine. It shares the host
kernel and does not claim to contain kernel exploits.

## Trust boundary

There is one Scute executable and no privileged daemon. The executable remains
single-threaded while privileged setup is possible. Its long-lived parent
supervises a child that becomes the sandboxed command.

The parent performs all setup requiring host capabilities, builds the Landlock
ruleset, attaches optional Whistler programs, permanently clears its effective,
permitted, inheritable, ambient, and bounding capability sets, and only then
releases the synchronized child. The child clears its own capabilities, sets
`no_new_privs`, installs seccomp, enforces the ruleset on itself with
`landlock_restrict_self`, and execs the requested command.

Landlock is spoken to the kernel directly: `landlock_create_ruleset`,
`landlock_add_rule`, and `landlock_restrict_self`. Scute does not shell out to
`landrun` or to any other helper. The split follows the same line as the rest
of the launch: the parent resolves paths and builds the ruleset, because that
needs Lisp, and the child spends one syscall enforcing it.

The policy and command line are parsed and normalized before any capability is
made effective. Scute never applies file capabilities to sandbox children.

## Startup sequence

1. Parse the policy as TOML and validate it against a closed schema.
2. Resolve paths and the command into an immutable launch plan.
3. Probe every requested kernel and runtime feature, reporting all that are
   missing rather than the first: any missing mandatory control aborts the
   launch before anything has been created.
4. Create a cgroup below the caller's delegated cgroup-v2 subtree.
5. Load and attach requested fixed Whistler audit programs.
6. Build the enforcement programs: one Landlock ruleset, handling every
   filesystem access right the kernel's reported ABI defines and carrying one
   `PATH_BENEATH` rule per declared path; and the seccomp filter, exported as a
   BPF program. Refuse any path that does not exist, and any command no rule
   permits to execute.
7. Create a PID-1 child in user, mount, PID, UTS, and network namespaces with
   `clone3`; it waits on a preallocated synchronization pipe without using Lisp
   runtime services.
8. Write the child's UID/GID maps and move it into the cgroup.
9. Permanently drop and verify every host capability in the parent.
10. Release the child only after every parent-side control is active.
11. In the child, arm `PR_SET_PDEATHSIG`, clear capabilities, set
    `no_new_privs`, and install seccomp.
12. Enforce the ruleset with `landlock_restrict_self`, which requires
    `no_new_privs`, and `execve` the command.
13. Forward signals, consume audit events, decode wait status, and unwind every
    cgroup, BPF, pipe, and process resource in reverse acquisition order.

No agent instruction executes until all requested controls report success.

## Policy

Policies are TOML documents. Unknown tables and keys, duplicate keys, values of
the wrong type, invalid limits, empty commands, and relative paths climbing out
of the directory Scute was invoked from are errors.

```toml
[filesystem]
read = ["/usr", "/bin", "/lib", "/lib64", "/etc"]
read-write = ["."]

[network]
mode = "none"

[limits]
memory = "2G"
processes = 256
cpu-percent = 200

[audit]
events = ["exec", "connect"]
```

Every section lives in a table, including the one-key ones. TOML requires bare
top-level keys to precede the first table header, and a policy whose meaning
depends on the order its lines happen to be in is a policy waiting to be
misread.

### Why TOML, and what the reader owes

A policy usually travels with the code being sandboxed: cloning a repository and
running `scute run --policy ./scute.policy` means the file defining the boundary
arrives from the same place as the thing being confined. TOML cannot express
evaluation at all, so a whole class of question -- what could this file persuade
Scute to do? -- does not arise. It is also legible to reviewers who do not read
Lisp, and writable by tools that do not run it. The cost is real and accepted
deliberately: parsing TOML brings esrap, local-time, cl-unicode and their
dependencies, and about two megabytes of binary.

Because the parser is part of the boundary, which parser matters. TOML 1.0
forbids a duplicate key, and a parser that accepts one keeps whichever value it
saw last: a policy saying `processes = 1` on one line and `processes = 99999` on
another would then enforce something no reviewer agreed to. Scute parses with
clop, which refuses duplicate keys and duplicate table headers. cl-toml accepts
both silently, which is precisely why it is not used. A policy's meaning must
not depend on which parser read it.

Beyond the parser, the reader must:

- read no more than a capped number of characters, which also bounds the
  parser's own recursion on pathological nesting;
- refuse any table or key the schema does not name, rather than ignoring it;
- check the type of every value, so that `read = 7` is turned away rather than
  half understood; and
- refuse a policy whole when any part of it is wrong, never enforcing the part
  it understood.

Validation is where a policy acquires meaning, and a launch plan is where that
meaning becomes fixed: paths canonical, command resolved, nothing yet created.
A plan holds no kernel resources, so it can be printed for review -- `scute run
--policy FILE --dry-run` does exactly that -- and compared for equality, which
is how the tests pin down what a policy means.

Filesystem permissions distinguish read, read-and-execute, read-write, and
read-write-execute access. Network access is disabled in v0. Landlock setup is
fail-closed: rights are masked to the ABI the kernel reports, and a policy
asking for a right that ABI cannot express aborts the launch rather than
quietly granting less.

Cave established an important constraint, and Scute now satisfies it by
construction rather than by requirement: filesystem and network permissions
must be installed as one ruleset. Stacking two can implicitly deny
`LANDLOCK_ACCESS_FS_REFER` and turn allowed cross-directory rename or link
operations into `EXDEV` failures. Scute builds a single ruleset and enforces it
once, so there is no second ruleset to stack with.

Two kernel details shape rule compilation. Rights that only make sense for a
directory -- reading a directory, creating or removing entries, and `REFER` --
are rejected with `EINVAL` when offered for a regular file or a device node, so
a rule naming a file keeps only the file rights. And `LANDLOCK_ACCESS_FS_REFER`
must be granted wherever a rename or link may land, which is why read-write
access includes it.

## Enforcement layers

- **Filesystem:** one Landlock allowlist, built by the parent and enforced by
  the child on itself immediately before `execve`.
- **Process:** user, PID, mount, UTS, and network namespaces; `no_new_privs`;
  zero capabilities; and a denylist seccomp filter installed after setup.
- **Network:** an isolated network namespace with no external route in v0.
- **Resources:** `memory.max`, `pids.max`, `cpu.max`, and `memory.swap.max`
  beneath a delegated cgroup-v2 subtree.
- **Audit:** optional, fixed Whistler programs attached to the sandbox cgroup at
  startup. Policies cannot inject BPF. Existing map and ring-buffer descriptors
  remain readable after capability removal.

Scute never silently weakens a requested control. A host without Landlock,
user namespaces, cgroup delegation for requested limits, libseccomp, required
capabilities, or requested BPF support receives a pre-execution error.

### Limits, and the cgroup that carries them

A sandbox with limits gets a cgroup of its own beneath the caller's delegated
subtree, created before the child exists and removed when it is gone. Cgroup v2
shapes this more than the design would have chosen: a cgroup may hold processes
or hand controllers to its children, never both. A Scute sharing its cgroup with
a shell and that shell's other children therefore cannot install limits at all,
and says so with the remedy in the message rather than enforcing part of what
was asked. A Scute alone in a delegated cgroup steps aside into a supervisor
cgroup of its own, leaving its cgroup empty and able to give its children
controllers. That supervisor is recognized on a later run, so a second sandbox
lands beside the first rather than one level deeper.

A memory limit also sets `memory.swap.max` to zero. `memory.max` bounds memory
alone, so a cgroup limited to 64M on a host with swap can hold far more than 64M
of pages -- and on a host with zram, zero-filled pages compress away to almost
nothing, which makes the limit invisible rather than merely loose. If a kernel
cannot account for swap per cgroup and the host has swap, the limit cannot be
made to mean what it says, and the launch is refused.

The kernel's account of a sandbox comes back with the result, because an exit
status cannot distinguish a command killed for exceeding its memory from one
killed from outside. `memory.events` and `pids.events` are read before the
cgroup is removed, so `scute run` can say that a memory limit is what ended a
command.

### Learning a policy

Beyond v0's scope as first written, and the feature that makes the rest usable:
`scute learn` runs a command once and writes the policy that would have allowed
what it did.

The mechanism is seccomp user notification. A filter whose action for the
path-taking syscalls is `SCMP_ACT_NOTIFY` makes the kernel park the child and
offer a description of the call to whoever holds the listener descriptor. The
listener is created by the child, because `seccomp(2)` returns it to the caller
that installs the filter, and it must not stay there: a command able to answer
its own notifications could wave anything through. So the child hands the
descriptor up and waits; the supervisor takes it with `pidfd_getfd`, releases
the child, reads each path out of the child's memory with `process_vm_readv`,
records it, and answers `SECCOMP_USER_NOTIF_FLAG_CONTINUE`. Closing the listener
on the way out matters: a process parked on a notification nobody will answer
waits for ever.

This observes; it does not enforce. `CONTINUE` is unsound as a security decision
because a path can change between the notification and the syscall. For learning
-- where the product is a draft a person reads -- that is the right trade, and it
is why learning writes a policy rather than enforcing what it saw.

What is recorded is canonicalized, so `/lib64/libc.so.6` and its `/usr/lib64`
target are one entry rather than two. Rules are then folded: paths under one of
a handful of anchors -- `/usr`, `/etc`, `/proc` and their like -- become the
anchor, because nobody reads a rule per file under `/usr`; paths under the
working directory become `"."`, so a learned policy travels with its project;
and anything else is named exactly, a directory as itself and a file as itself.
`/proc` must be an anchor rather than exact: `/proc/self/status` canonicalizes to
a pid that will not exist next time.

### Explaining a refusal

The same machinery answers a different question. A command refused something
reports whatever its libraries make of `EACCES`, which is rarely the path and
never the rule. Because a seccomp filter runs at syscall entry, before the
security modules decide anything, an attempt Landlock goes on to refuse is still
seen; `scute run --explain` enforces the policy exactly as usual and watches as
well, then says which of the paths the command reached for its own rules would
not have allowed, and folds those into the lines that would allow them.

Paths that exist nowhere are dropped rather than reported: a dynamic loader
probes for library variants that are not installed, and those attempts fail for
want of a file rather than for want of a rule. Suggesting them would also
produce a policy that will not load, since a rule naming a missing path is an
error.

### Stopping a sandbox

`pid_namespaces(7)` delivers a signal from an ancestor namespace to PID 1 only
when PID 1 has installed a handler for it; `SIGKILL` and `SIGSTOP` are the
exceptions. A command that installs no handler therefore never sees a forwarded
`SIGTERM`, and a supervisor that only forwarded would wait for a command that
was never told to stop.

Scute forwards the signal, waits a grace period of five seconds, and then sends
`SIGKILL`, which cannot be ignored or discarded. A command that traps the signal
and acts within the grace period decides its own exit status. A second stop
signal does not start the wait again.

### What the filter denies, and what it cannot

The seccomp filter follows the same split as Landlock. The parent builds it with
libseccomp, where a mistake is an error before anything is created, and exports
it as a BPF program; the child installs it with one `seccomp(2)` call and never
touches libseccomp, so nothing between `clone3` and `execve` allocates. It is
installed before `landlock_restrict_self`, which it permits, and both come after
`no_new_privs`, which each requires.

It is a denylist. A sandboxed command is ordinary software doing ordinary work,
and an allowlist of everything a C library might call is a maintenance burden
that fails closed on the wrong things. What v0 denies is the surface a confined
command has no business touching: kernel modules and machine control, the kernel
keyring, BPF and tracing, namespace and mount changes after setup, opening files
by handle, `userfaultfd` and `io_uring`, setting the clock, and machine-wide
state such as quotas and NUMA placement. Denied calls answer `EPERM`. Most of
them also need a capability the sandbox does not have; they are denied anyway,
because a syscall that cannot be reached is a syscall whose bugs cannot be
reached either.

A nested user namespace is closed by all three of its routes, because it
deserves more than defence in depth: a process that creates one holds a full
capability set inside it, which is where a great many kernel exploits begin.
`unshare` is refused outright. `clone` takes its flags in a register, so the
filter reads them and refuses only a clone asking for `CLONE_NEWUSER`, leaving
every ordinary fork alone. `clone3` takes its flags in a struct that seccomp
cannot read, so it is refused whole -- with `ENOSYS` rather than `EPERM`,
because that is the answer a C library is looking for when it decides whether to
fall back to `clone`, where the flags are visible again.

One right is deliberately left ungoverned in v0: `LANDLOCK_ACCESS_FS_IOCTL_DEV`
(ABI 5). Handling it without granting it breaks `tcsetattr` on a terminal, and
an interactive shell nobody can run is not a useful sandbox. Device `ioctl` is
therefore out of v0's scope, stated here rather than discovered later.

## Module map

- `src/conditions.lisp` defines stable setup, policy, enforcement, and child
  failure conditions.
- `src/policy.lisp` owns policy structures, TOML reading, schema validation,
  and immutable launch-plan compilation.
- `src/linux.lisp` contains the small CFFI surface for `clone3`, namespace and
  process synchronization, capabilities, `prctl`, and wait-status handling.
- `src/landlock.lisp` reports the kernel's Landlock ABI, compiles declared
  paths into one ruleset, and enforces it on the calling thread.
- `src/cgroup.lisp` discovers the delegated subtree, creates and configures one
  sandbox cgroup, moves the child, classifies resource events, and cleans up.
- `src/seccomp.lisp` binds the minimal libseccomp API, builds the v0 filter in
  the parent, and exports it as the BPF program the child installs.
- `src/audit.lisp` defines fixed Whistler programs and decodes their events.
- `src/learn.lisp` builds the notifying filter, watches a child through the
  listener, and folds what it saw into a policy.
- `src/sandbox.lisp` holds the preflight check and then orders acquisition, fork
  synchronization, supervision, signal forwarding and enforcement, result
  classification, and cleanup.
- `src/main.lisp` exposes only the `run` and read-only `doctor` CLI commands,
  reports failures on stderr with the shell's exit statuses -- 64 for a caller's
  mistake, 65 for a policy Scute will not accept, 126 and 127 as a shell uses
  them, 128 plus the signal that ended a command -- and answers `doctor --json`
  for anything that is not a person.
- `tests/` contains unit fixtures plus opt-in kernel and capability integration
  tests; `make check` runs the applicable matrix and reports explicit skips for
  optional audit privileges only.

LispIndex was checked for reusable system-programming libraries. CFFI is the
appropriate narrow dependency; Osicat and the listed process libraries do not
cover Landlock, namespaces, capabilities, seccomp, or cgroups. Whistler remains
the eBPF compiler and loader. Ordinary subprocess work stays on UIOP. Scute has
no runtime dependency outside libc and, when limits or auditing are requested,
the kernel facilities themselves.

## Deferred scope

The following are not part of v0: device `ioctl` restriction, live policy
changes, network allowlists or an HTTP proxy, credential brokerage, persistent
named sandboxes, a gateway, a TUI, remote access, non-Linux support, arbitrary
user-supplied BPF, or BPF-based enforcement.

The authoritative implementation plan is the dependency graph under beads epic
`scute-do3`; this document records architecture rather than task status.
