# Changelog

All notable changes to Scute are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

A release takes its notes from the entry here that matches its version, so an
entry is part of releasing rather than a courtesy afterwards.

## [Unreleased]

### Security

- Refuse filesystem policies whose optional grants all disappear.
- Deny IPv6 sockets in proxy and address-guarded runs, including observation.
- Preserve Unix socket denials during audit and explanation.
- Create credential output exclusively without following symlink components;
  pin file descriptors for Landlock grants and directory descriptors for cleanup.
- Authenticate every broker control connection over Unix with `SO_PEERCRED`;
  remove bearer-key discovery and TCP control fallback.

### Changed

- Broker control requires a recent KeyFence with Unix control support. Enable
  `keyfence-control.socket`; replace `control-port` with `control-socket`.
- Unix-enabled and learning runs require Landlock ABI 9. Preexisting host
  pathname sockets remain inaccessible even with broad filesystem grants;
  sockets created inside the sandbox remain usable.
- Credential output destinations must not already exist.

## [0.1.0] - 2026-09-19

### Added

- Run one local command inside a deny-by-default sandbox built from Landlock,
  seccomp, user namespaces and cgroup v2 — native, one process tree on your own
  kernel, with no container, no virtual machine, no daemon and no root. A host
  that cannot provide a control the policy asked for gets an error before the
  command runs, never a weaker sandbox than the one it asked for.
- Keep credentials out of the sandbox. A policy that says nothing about the
  network is routed through [KeyFence](https://github.com/atgreen/keyfence),
  which holds the real secrets and swaps them in on the way past, so the command
  carries opaque tokens that are worth nothing anywhere else.
- Rewrite the destination of every outbound connection with an eBPF program
  attached to the sandbox's cgroup, so a client that ignores the proxy variables
  reaches the broker anyway, and Landlock permits no other port to leave by.
  Where the guard cannot be attached, the port-level fallback stands in and says
  which one is in force.
- Ship policies for the agents people actually run — `scute codex`,
  `scute claude`, `scute bash` — installed where `--policy NAME` looks, and
  outranked by a copy of your own in `~/.config/scute/policies`.
- Write a policy from a run rather than from guesswork: `scute learn` records
  what a command touched and emits a policy that permits it.
- Say what will happen and why it did not: `--dry-run` prints the plan without
  running anything, `--explain` names what was refused and the rule that would
  have allowed it, `scute check` answers whether a path is permitted, and
  `scute doctor` reports what this host can enforce.
- Bound what a command consumes — memory, processes, CPU, and a wall clock that
  stops it — and record what it did with `--audit`.
- Package it: an RPM with the capabilities the kernel redirect needs, a Debian
  build, shell completions, a manual page and an SPDX SBOM.
