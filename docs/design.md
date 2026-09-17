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

The parent performs all setup requiring host capabilities, attaches optional
Whistler programs, permanently clears its effective, permitted, inheritable,
ambient, and bounding capability sets, and only then releases the synchronized
child. The child creates its namespaces, clears its own capabilities, sets
`no_new_privs`, installs seccomp, and invokes `landrun`. `landrun` installs one
combined Landlock ruleset and replaces itself with the requested command.

The policy and command line are parsed and normalized before any capability is
made effective. Scute never applies file capabilities to sandbox children.

## Startup sequence

1. Read the policy with `*read-eval*` bound to `nil` and validate its schema.
2. Resolve paths and the command into an immutable launch plan.
3. Probe every requested kernel and runtime feature; any missing mandatory
   control aborts the launch.
4. Create a cgroup below the caller's delegated cgroup-v2 subtree.
5. Load and attach requested fixed Whistler audit programs.
6. Create a PID-1 child in user, mount, PID, UTS, and network namespaces with
   `clone3`; it waits on a preallocated synchronization pipe without using Lisp
   runtime services.
7. Write the child's UID/GID maps and move it into the cgroup.
8. Permanently drop and verify every host capability in the parent.
9. Release the child only after every parent-side control is active.
10. In the child, clear capabilities, set `no_new_privs`, and install seccomp.
11. Execute `landrun` with one combined filesystem/network ruleset; `landrun`
    replaces itself with the command.
12. Forward signals, consume audit events, decode wait status, and unwind every
    cgroup, BPF, pipe, and process resource in reverse acquisition order.

No agent instruction executes until all requested controls report success.

## Policy

Policies are data-only Common Lisp forms. Unknown forms, duplicate fields,
read-time evaluation, invalid limits, empty commands, and paths escaping their
declared base are errors.

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

Filesystem permissions distinguish read, read-and-execute, read-write, and
read-write-execute access. Network access is disabled in v0. Landlock setup is
fail-closed: Scute does not use `landrun --best-effort`.

Cave established an important constraint that Scute preserves: filesystem and
network permissions must be installed as one Landlock ruleset. Stacking the two
can implicitly deny `LANDLOCK_ACCESS_FS_REFER` and turn allowed cross-directory
rename or link operations into `EXDEV` failures. Scute requires a compatible
`landrun` carrying that behavior and always passes an absolute executable.

## Enforcement layers

- **Filesystem:** one Landlock allowlist installed by the ephemeral `landrun`
  exec-stage.
- **Process:** user, PID, mount, UTS, and network namespaces; `no_new_privs`;
  zero capabilities; and a denylist seccomp filter applied after setup.
- **Network:** an isolated network namespace with no external route in v0.
- **Resources:** `memory.max`, `pids.max`, and `cpu.max` beneath a delegated
  cgroup-v2 subtree.
- **Audit:** optional, fixed Whistler programs attached to the sandbox cgroup at
  startup. Policies cannot inject BPF. Existing map and ring-buffer descriptors
  remain readable after capability removal.

Scute never silently weakens a requested control. A host without Landlock,
user namespaces, cgroup delegation for requested limits, libseccomp, required
capabilities, or requested BPF support receives a pre-execution error.

## Module map

- `src/conditions.lisp` defines stable setup, policy, enforcement, and child
  failure conditions.
- `src/policy.lisp` owns policy structures, safe reading, validation, and
  immutable launch-plan compilation.
- `src/linux.lisp` contains the small CFFI surface for `clone3`, namespace and
  process synchronization, capabilities, `prctl`, and wait-status handling.
- `src/landlock.lisp` probes `landrun`, resolves executables, and compiles one
  ruleset invocation.
- `src/cgroup.lisp` discovers the delegated subtree, creates and configures one
  sandbox cgroup, moves the child, classifies resource events, and cleans up.
- `src/seccomp.lisp` binds the minimal libseccomp API and installs the v0
  post-setup filter.
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
the eBPF compiler and loader. Ordinary subprocess work stays on UIOP.

## Deferred scope

The following are not part of v0: live policy changes, network allowlists or an
HTTP proxy, credential brokerage, persistent named sandboxes, a gateway, a TUI,
remote access, non-Linux support, arbitrary user-supplied BPF, or BPF-based
enforcement.

The authoritative implementation plan is the dependency graph under beads epic
`scute-do3`; this document records architecture rather than task status.
