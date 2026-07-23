---
id: spec-minvmd-gvproxy-pidfd
title: "minvmd: signal gvproxy switch via pidfd to close the independent-crash recycled-PID window"
kind: spec
status: shipped
tracking-issue: 550
supersedes:
---

# minvmd: signal gvproxy switch via pidfd to close the independent-crash recycled-PID window

## Context

`GvproxySwitch` (`crates/minvmd/src/net.rs`) supervises the gvproxy child
process and tears it down by delivering signals via `signal_child(pid, …)`,
which calls `libc::kill(pid, signal)`. The `stopping: Arc<AtomicBool>` guards
the intentional teardown paths (`stop()`, `GvproxySwitch::Drop`) so the
supervision task classifies the resulting child exit as orderly rather than
unexpected.

The guard does **not** cover an independent gvproxy crash. When gvproxy exits
on its own, `supervise_switch` reaps the child but nothing sets `stopping`. A
subsequent teardown path (e.g. the last `PtaskAttachment` dropping, or a
delayed `stop()` call) evaluates `!stopping.swap(true)` as `true` and sends
SIGTERM to `self.pid`. Between the supervisor's reap and that signal, the OS
may have recycled the PID, causing the signal to land on an unrelated process.

`signal_child` silences `ESRCH`, correctly hiding "process already gone",
but does nothing for the recycle case where the PID now resolves to a live,
unrelated process. The window is documented in-code but not closed
(informed by #550).

## Introduction/Overview

Replace raw-PID `kill(2)` with `pidfd_send_signal(2)` (Linux ≥ 5.1). A pidfd
refers to the exact process instance opened at spawn; after the process exits,
`pidfd_send_signal` always returns `ESRCH`; it never resolves to a recycled
PID. This closes the recycle hazard structurally without altering the
supervision-task coordination logic.

## Goals

- G1: All gvproxy signal deliveries use a `pidfd` rather than a bare PID.
- G2: A `pidfd_send_signal` call against a reaped gvproxy child returns `ESRCH`
  and never delivers a signal to an unrelated process.
- G3: Existing teardown tests remain green.

## User Stories

- As minvmd, when gvproxy crashes independently, any subsequent teardown path
  delivers no signal to a recycled PID.

## Demoable Units of Work

### Unit 1 - Replace raw-PID signalling with pidfd in GvproxySwitch

**R1.1** `GvproxySwitch::supervise()` calls `pidfd_open(pid, 0)` immediately
after extracting the child PID (before spawning the supervision task) and stores
the resulting `OwnedFd` as a new field `pidfd: OwnedFd` on `GvproxySwitch`.
(Linux-only; bounded by the existing `#[cfg(target_os = "linux")]` guards or a
new one at field level.)

**R1.2** A new `signal_pidfd(pidfd, signal, signal_name)` helper replaces
`signal_child` on all teardown paths. It calls `pidfd_send_signal(2)` (via
`libc::pidfd_send_signal` or `libc::syscall(libc::SYS_pidfd_send_signal, …)` if
the bound is absent from the libc version in use). `ESRCH` from a reaped child
is silenced identically to the existing `signal_child` behaviour; unexpected
errors (`EPERM`, `EINVAL`) are logged via `tracing::warn!`.

**R1.3** `stop()` and `GvproxySwitch::Drop` signal via `signal_pidfd`. The
`stopping` atomic and its acquire/release ordering are unchanged, they continue
to classify exits as intentional vs. unexpected in `supervise_switch`.

**R1.4** A new test `pidfd_signal_to_reaped_child_returns_esrch` spawns a
short-lived child, opens its pidfd immediately, awaits the child's reap, then
calls `pidfd_send_signal` and asserts the return is `ESRCH`, confirming the
pidfd path never resolves to a recycled process after the child exits. Existing
tests `stop_terminates_supervised_child` and
`drop_sigkills_supervised_child_without_blocking` stay green.

Fast-path: no cross-cutting design; the implementation plan is in the tracking issue comment (ADR 0012).

## Non-Goals

- Porting to macOS or other non-Linux platforms. pidfd is Linux-only; minvmd's
  gvproxy switch is already gated `#[cfg(target_os = "linux")]`.
- Altering the `stopping` atomic coordination or supervision-task classification
  logic. pidfd closes the recycle hazard; the supervision semantics are
  unchanged.
- Kernel version fallback. minvmd targets Linux ≥ 5.3 (libkrun requirement);
  `pidfd_open` (≥ 5.3) and `pidfd_send_signal` (≥ 5.1) are available on all
  supported kernels.

## Security Considerations

This fix closes a signal-delivery race that could send SIGTERM or SIGKILL to an
unrelated process whose PID was recycled after gvproxy exited unexpectedly. The
pidfd approach binds the signal to the exact process instance, making the race
structurally impossible.

## Open Questions

None. The pidfd approach is unambiguous given the Linux-only target and the
existing kernel version floor.

## Verification

**Proof artifact 1 (Test):**
`cargo test -p minvmd net::tests::pidfd_signal_to_reaped_child_returns_esrch`
passes. This test does not exist on the base branch and fails (test not found)
before the PR lands.

**Proof artifact 2 (File):**
`grep -q 'pidfd' crates/minvmd/src/net.rs`, fails on the base branch (the
string is absent), passes after the PR lands.
