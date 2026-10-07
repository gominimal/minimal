---
title: minvmd daemon
description: "Ops reference for the minvmd VM daemon: boots and supervises the Linux microVM that hosts minimald."
---

# `minvmd` - VM daemon

`minvmd` is the host daemon that brings up a Linux microVM via libkrun
(macOS/HVF or Linux/KVM) and supervises the
[minimald](./cli-minimald.md) instance running inside it. On macOS it is
the only session backend. On Linux, select it with `min --provider local-minvmd`
(see [min](./cli-min.md)).

Generated from `--help` at `3a05252c`.

## Global flags

| Flag | Description |
|------|-------------|
| `--minimal-state-dir <PATH>` | Override the state dir base (default: `$XDG_STATE_HOME/minimal`). Runtime files live under `<dir>/providers/local-minvmd0/` |

## Commands

`run` and `boot` bring the VM up. `run` (alias `start`) is the
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

The VM's hostname proxy takes port `7654` when no other process or VM holds it, and a free port otherwise. To pin the port, set `MINVMD_NODE_PROXY_PORT` for `minvmd run` or for the `min` command that starts it. If another process holds a pinned port, the start fails.

To keep the allow-all egress default for a box that declares no `egress` section, set `MINVMD_EGRESS_DENY_ALL_OPT_OUT=1` for `minvmd run` or for the `min` command that starts it. This is the VM counterpart of `minimald run --egress-deny-all-opt-out`. Only `1`, `true`, `yes`, or `on` opt out, in any letter case. Any other value, or leaving it unset, applies this build's egress default. That default is deny-all for own-IP boxes once it is in force. The guest reads the setting once at boot.

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

Checks and persists resource parameters, applied on the next boot.

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

Generates a shell tab-completion script. Supported shells include `bash`, `zsh`,
`elvish`, `fish`, `powershell`.

