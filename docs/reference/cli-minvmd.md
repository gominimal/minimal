---
title: minvmd daemon
description: Ops reference for the minvmd VM daemon — boots and supervises the Linux microVM that hosts minimald.
---

# `minvmd` — VM daemon

`minvmd` is the host daemon that brings up a Linux microVM via libkrun
(macOS/HVF or Linux/KVM) and supervises the
[minimald](./cli-minimald.md) instance running inside it. On macOS it is
the only session backend; on Linux it is selected with `min --minvmd`
(see [min](./cli-min.md)).

Generated from `--help` at `e5ce5fb8`.

## Global flags

| Flag | Description |
|------|-------------|
| `--minimal-state-dir <PATH>` | Override the state dir base (default: `$XDG_STATE_HOME/minimal`). Runtime files live under `<dir>/providers/local-0/` |

## Commands

### `boot`

```
minvmd boot [--foreground]
```

Boots the microVM and waits until the guest is up. `--foreground` stays
in the foreground until the VMM child exits.

### `run`

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

Prints the effective per-VM resource configuration and each value's
source. `--json` prints it as a JSON object.

### `config set`

```
minvmd config set [--vcpus <N>] [--ram-mib <N>]
```

Validates and persists resource parameters, applied on the next boot.

| Flag | Description |
|------|-------------|
| `--vcpus <N>` | Number of virtual CPUs |
| `--ram-mib <N>` | Guest RAM in MiB |

### `stop`

```
minvmd stop
```

Stops the running daemon gracefully.

### `completions`

```
minvmd completions <SHELL>
```

Generates a shell tab-completion script. Supported shells: `bash`, `zsh`,
`elvish`, `fish`.

## Known issues

- [#823](https://github.com/gominimal/minimal/issues/823) —
  `minvmd run --timeout` is silently ignored without `--detach`.
