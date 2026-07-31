---
title: minvmd daemon
description: "Ops reference for the minvmd VM daemon: boots and supervises the Linux microVM that hosts minimald."
---

# `minvmd` - VM daemon

`minvmd` is the host daemon that brings up a Linux microVM via libkrun
(macOS/HVF or Linux/KVM) and supervises the
[minimald](./cli-minimald.md) instance running inside it. On macOS it is
the only session backend; on Linux it is selected with `min --provider local-minvmd`
(see [min](./cli-min.md)).

Generated from `--help` at `3a05252c`.

## Global flags

| Flag | Description |
|------|-------------|
| `--minimal-state-dir <PATH>` | Override the state dir base (default: `$XDG_STATE_HOME/minimal`). Runtime files live under `<dir>/providers/local-minvmd0/` |

## Commands

Two commands bring the VM up. `run` (alias `start`) is the
lifecycle-managed supervisor: it drives the daemon's state transitions and
supports `--detach` for background operation, so it is the usual entry
point. `boot` is a lower-level bring-up that skips lifecycle state, used
mainly for diagnostics.

### `boot`

```
minvmd boot [--foreground]
```

Boots the microVM and waits until the guest is up. `--foreground` stays
in the foreground until the VMM child exits.

### `run` (alias: `start`)

```
minvmd run [--detach] [--timeout <SECONDS>]
```

Starts the microVM supervisor (foreground by default).

| Flag | Description |
|------|-------------|
| `--detach` | Spawn the supervisor in the background and return once the host UDS is accepting connections |
| `--timeout <SECONDS>` | Timeout in seconds to wait for the host UDS when using `--detach` (default: `8`) |

### `status`

```
minvmd status [--json]
```

Prints daemon status. Exit code: `0` if running, `1` if stopped, `2` on
lock contention. `--json` prints status as a JSON object.

### `config show`

```
minvmd config show [--json]
```

Prints the effective per-VM configuration and each value's source.
`--json` prints it as a JSON object.

### `config set`

```
minvmd config set [--vcpus <N>] [--ram-mib <N>]
                  [--maintenance-at <HH:MM>]
                  [--maintenance-older-than-secs <N>]
```

Validates and persists configuration, applied on the next boot.

| Flag | Description | Default |
|------|-------------|---------|
| `--vcpus <N>` | Number of virtual CPUs | 2 |
| `--ram-mib <N>` | Guest RAM in MiB | 2048 (x86_64) / 4096 |
| `--maintenance-at <HH:MM>` | Time of day, UTC, the guest runs maintenance | `03:00` |
| `--maintenance-older-than-secs <N>` | Seconds a cache entry may go unused before a sweep may delete it | 1209600 (14 d) |

Each value resolves as `env override ?? persisted config ?? default`; the
environment variables are `MINVMD_VM_VCPUS`, `MINVMD_VM_RAM_MIB`,
`MINVMD_MAINTENANCE_AT`, and `MINVMD_MAINTENANCE_OLDER_THAN_SECS`.

`--maintenance-at` must be a fixed-width 24-hour `HH:MM`. It is passed to the
guest on the kernel command line, which the kernel splits on whitespace, so a
malformed value is rejected here rather than silently dropped at the next boot.

## Guest maintenance

The **guest** owns the maintenance schedule. `minvmd` only configures it: the
time of day and the retention are handed over on the kernel command line at
boot, and the in-VM `minimald` runs its own daily timer from them.

Each run is two ordered steps:

1. **Sweep** — delete cache entries unused for longer than
   `maintenance-older-than-secs`.
2. **Trim** — `fstrim` the state volume, so the blocks the sweep freed are
   returned to the host's backing raw image.

Both are needed. The state volume is mounted without `discard`, so deleting
files inside the guest frees ext4 blocks but leaves the host image at its
high-water mark; the trim is what shrinks it. Each run logs what it reclaimed
(`guest maintenance reclaimed state`), so a run that reclaimed nothing is
distinguishable from one that never happened.

The schedule is UTC, because a microVM rootfs carries no timezone database for
the guest to resolve local time against.

Scheduling in the guest is only sound because the guest clock is kept correct:
it advances only while the VM is scheduled, so a sleeping host would otherwise
leave it hours behind, and `minvmd`'s timekeep bridge pushes the host wall clock
in every minute and immediately after a suspend. The guest waits in short slices
against the wall clock rather than one long sleep, so a suspend moves the target
instead of slipping the schedule. A clock that jumps forward over several missed
occurrences runs once and resumes the daily cadence, rather than firing a
backlog.

A sweep never deletes a cache entry that any session depends on: the protected
set is the union of the packages every session's project references. If that set
cannot be computed for even one session, the sweep deletes nothing — but the
trim still runs, since discarding already-free blocks cannot evict anything. The
skip is reported in the run's log line.

Leaked build sandboxes are **not** reclaimed. A build keeps its sandbox
directory until it succeeds, so a failed or interrupted one leaves the directory
behind; reclaiming those needs a dependable "is the owning process still alive"
signal, which the current `-<pid>` directory suffix does not provide inside the
VM (it records the creating process, which there is the daemon itself, pid 1).

### `stop`

```
minvmd stop
```

Stops the running daemon gracefully.

### `completions`

```
minvmd completions <SHELL>
```

Generates a shell tab-completion script. Supported shells include `bash`, `zsh`,
`elvish`, `fish`, `powershell`.

