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

When no DNS service is installed and no other VM's answerer is running, `minvmd` answers box names itself on UDP `127.0.0.1:7656`. To use another port, for example when a native `minimald` on the same host uses `7656`, set `MINVMD_ZONE_ANSWERER_PORT` to a port from 1 to 65535 for `minvmd run` or for the `min` command that starts it. This is the VM counterpart of `minimald run --zone-answerer-port`. A value that is not a port, `0` included, fails the start. The pin moves only the answerer this VM hosts itself: an installed DNS service keeps its own port, and a VM that finds the service or another VM's answerer running still answers its box names through it. `min ls` and the session start print the port of the answerer that holds this VM's box names: the pin when this VM answers them itself, and `7656` when the DNS service does. When another VM's answerer holds them, this VM prints its own pin, which can differ from the port that answers. All VMs of one user share one answerer, whatever their pins: the first VM that starts with no DNS service installed answers box names, and the others send their names to it. When `min finalize-install` installs the DNS service, it points the resolver at `7656`. Under a pin, `minvmd` keeps both the pin and `7656` for box names: the VM's hostname proxy, a guest port mirrored to the host, and a host exposure never use either one. `minvmd` reads the variable only when it starts.

An own-IP box that declares no `egress` section gets the deny-all egress default: it reaches no external address. To keep the earlier allow-all default for such boxes, set `MINVMD_EGRESS_DENY_ALL_OPT_OUT=1`. This is the VM counterpart of `minimald run --egress-deny-all-opt-out`. Only `1`, `true`, `yes`, or `on` opt out, in any letter case. Any other value, or leaving it unset, keeps the deny-all default.

`minvmd` reads the variable only when it starts, and hands it to the guest at boot. Set it in the environment of the process that starts `minvmd`: `minvmd run`, or the first `min` command that starts the VM for you. Setting it for a later `min` command against a running VM changes nothing. To apply a change, stop `minvmd` (`minvmd stop`) and start it again with the new environment.

`minvmd` closes `host.min.internal` at every port that the `[host-exposures]` table does not open. The table is in the client `config.toml`, `$XDG_CONFIG_HOME/minimal/config.toml` or `~/.config/minimal/config.toml`. Give each exposure a name and an inline table, such as `postgres = { proto = "tcp", port = 5432 }`. `proto` is `tcp` or `udp`, and `tcp` is the default. `port` runs from 1 to 65535. A box in the default host-address network mode then reaches the host at those ports and no other, and the box's egress rules still apply inside an exposure. A deny-all box reaches no exposure. An own-address box gets a refusal at every port, whatever the table says. This is a current limit: the design lets an own-address box reach an exposure when its `egress.allow_dns_hosts` names `host.min.internal` or its `egress.allow_subnets` lists a range that covers that address. [#2990](https://github.com/gominimal/minimal/issues/2990) tracks that change. `minvmd` reads the table again within a second of a change. An added entry opens its port, and a removed entry closes it and refuses the later traffic of its open connections, with no restart. `minvmd` skips an entry in any other form. It also refuses an entry at a port that Minimal itself uses: the hostname proxy's port, the box-name answerer's port, the Box Egress Proxy's port, or a port where the VM's own registry or cache traffic reaches the host. When Minimal starts to use the port of an entry later, `minvmd` closes that entry from then on. The daemon log names each skipped, refused or closed entry, and the Minimal listener that holds its port. `minvmd` no longer reads `MINVMD_HOST_EXPOSURE_PORTS`. When the variable is set, `minvmd` logs a warning and ignores its value.

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

