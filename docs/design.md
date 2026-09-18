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
3. Probe every requested kernel and runtime feature; any missing mandatory
   control aborts the launch.
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
- **Resources:** `memory.max`, `pids.max`, and `cpu.max` beneath a delegated
  cgroup-v2 subtree.
- **Audit:** optional, fixed Whistler programs attached to the sandbox cgroup at
  startup. Policies cannot inject BPF. Existing map and ring-buffer descriptors
  remain readable after capability removal.

Scute never silently weakens a requested control. A host without Landlock,
user namespaces, cgroup delegation for requested limits, libseccomp, required
capabilities, or requested BPF support receives a pre-execution error.

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

One limit is stated here rather than left to be discovered. Denying `unshare`
does not prevent a program from creating a nested user namespace: `clone` and
`clone3` can do the same, and seccomp cannot read the struct `clone3` takes its
flags from. The denial is defence in depth, not a boundary.

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
- `src/sandbox.lisp` orders acquisition, fork synchronization, supervision,
  signal forwarding, result classification, and cleanup.
- `src/main.lisp` exposes only the `run` and read-only `doctor` CLI commands.
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
