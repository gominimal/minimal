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
                  [--maintenance-interval-secs <N>]
                  [--maintenance-older-than-secs <N>]
```

Validates and persists configuration, applied on the next boot.

| Flag | Description | Default |
|------|-------------|---------|
| `--vcpus <N>` | Number of virtual CPUs | 2 |
| `--ram-mib <N>` | Guest RAM in MiB | 2048 (x86_64) / 4096 |
| `--maintenance-interval-secs <N>` | Seconds between guest maintenance cycles; `0` disables the timer | 21600 (6 h) |
| `--maintenance-older-than-secs <N>` | Seconds a cache entry may go unused before a sweep may delete it | 1209600 (14 d) |

Each value resolves as `env override ?? persisted config ?? default`; the
environment variables are `MINVMD_VM_VCPUS`, `MINVMD_VM_RAM_MIB`,
`MINVMD_MAINTENANCE_INTERVAL_SECS`, and
`MINVMD_MAINTENANCE_OLDER_THAN_SECS`.

`config set` refuses a retention shorter than the interval: it would make
every artifact built between two cycles eligible at the next one, sweeping
away exactly what is being actively rebuilt.

## Guest maintenance

While a VM is up, the supervisor drives the in-VM `minimald` through a
maintenance cycle every `maintenance-interval-secs`:

1. **Sweep** — delete cache entries unused for longer than
   `maintenance-older-than-secs`, plus sandbox, task, and temp directories
   whose owning process is gone.
2. **Trim** — `fstrim` the state volume, so the blocks the sweep freed are
   returned to the host's backing raw image.

Both steps are needed. The state volume is mounted without `discard`, so
deleting files inside the guest frees ext4 blocks but leaves the host image
at its high-water mark; the trim is what shrinks it. Each cycle logs what it
reclaimed (`guest maintenance reclaimed state`), so a run that reclaimed
nothing is distinguishable from one that never happened.

The cycle is skipped, and retried on the next tick, when:

- a build or task is in flight in the guest — `FITRIM` takes ext4
  block-group locks, and maintenance has no deadline while a build does;
- the host is running on battery.

A sweep never deletes a cache entry that any live session depends on: the
protected set is the union of the packages every live session's project
references. If that set cannot be computed for even one session, the cycle
deletes nothing at all.

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
`elvish`, `fish`.

