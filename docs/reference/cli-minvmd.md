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

An own-IP box that declares no `egress` section gets the deny-all egress default: it reaches no external address. To keep the earlier allow-all default for such boxes, set `MINVMD_EGRESS_DENY_ALL_OPT_OUT=1`. This is the VM counterpart of `minimald run --egress-deny-all-opt-out`. Only `1`, `true`, `yes`, or `on` opt out, in any letter case. Any other value, or leaving it unset, keeps the deny-all default.

`minvmd` reads the variable only when it starts, and hands it to the guest at boot. Set it in the environment of the process that starts `minvmd`: `minvmd run`, or the first `min` command that starts the VM for you. Setting it for a later `min` command against a running VM changes nothing. To apply a change, stop `minvmd` (`minvmd stop`) and start it again with the new environment.

Minimal's own downloads in the VM come from the package registry and the package cache. The registry holds the package source repository. `minvmd` lets this traffic reach only the hosts of the node-plane baseline. By default, the baseline admits `github.com` for the registry and `cache.minimal.dev` for the cache. To change which hosts the baseline admits, set `MINVMD_BASELINE_REGISTRY` or `MINVMD_BASELINE_CACHE` to a comma-separated list of host names and IPv4 subnets, such as `pkgs.example.com,203.0.113.0/24`. Neither variable changes where Minimal downloads from. The list replaces the default host, so name the default host again to keep it, or `minvmd` drops the downloads that still go there. An empty value lets that download reach no host. Write one IPv4 address as a `/32` subnet. `minvmd` skips a term that is not a host name or an IPv4 subnet, and logs a warning that names the term. For a host name, the baseline admits TCP port 443 at the addresses that the name resolved to, and no other port. A host name alone does not admit a private address (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) that it resolved to: `minvmd` drops the connection and logs it under `egress-infrastructure-destination`. To reach such a host, list its subnet beside the name. A subnet in the baseline that covers the address admits it, and admits every port there. A subnet admits every port, except at the addresses that follow. `minvmd` refuses link-local (`169.254.0.0/16`) and loopback (`127.0.0.0/8`) addresses whatever the baseline names, and logs the drop under `egress-infrastructure-destination`. It also refuses `100.64.0.0/10` outside the VM's own block of box addresses, under the same rule. At `host.min.internal`, a subnet that covers the address opens TCP port 443 and the host exposures, and no other port. `minvmd` logs a drop at another port under `host-alias`. The address of the Box Egress Proxy stays closed whatever the baseline names, and `minvmd` logs the drop under `egress-uncredentialed-proxy-destination`. `minvmd` drops a connection that the baseline does not admit, without a reset. It logs the drop under `egress-node-plane-unpinned`. The log is in the `logs` directory of the state dir, `~/.local/state/minimal/logs/` by default. The file name is `minvmd.log` with the date appended, such as `minvmd.log.2026-11-18`. `minvmd` reads both variables when it starts, the same way it reads `MINVMD_EGRESS_DENY_ALL_OPT_OUT`. For an own-IP box, `min session policy` shows the baseline below the rules of the box. It reads the variables from the environment of that `min` command. The baseline never applies to the traffic of a box. The egress rules of the box decide what its processes reach, and where its packages download their sources from.

`minvmd` closes `host.min.internal` at every port that the `[host-exposures]` table does not open. The table is in the client `config.toml`, `$XDG_CONFIG_HOME/minimal/config.toml` or `~/.config/minimal/config.toml`. Give each exposure a name and an inline table, such as `postgres = { proto = "tcp", port = 5432 }`. `proto` is `tcp` or `udp`, and `tcp` is the default. `port` runs from 1 to 65535. A box in the `host_ip` mode, the default, then reaches the host at those ports and no other. The egress rules of the box still apply inside an exposure. A deny-all box reaches no exposure. An own-address box gets a refusal at every port, whatever the table says. This is a current limit. The design lets an own-address box reach an exposure in two cases: its `egress.allow_dns_hosts` names `host.min.internal`, or its `egress.allow_subnets` lists a range that covers that address. [#2990](https://github.com/gominimal/minimal/issues/2990) tracks that change. `minvmd` reads the table again within a second of a change. When you add an entry, its port opens. When you remove one, its port closes and `minvmd` refuses the later traffic of its open connections. Neither change needs a restart. `minvmd` skips an entry in any other form. It also refuses an entry at a port that Minimal itself uses. Those are the ports of the hostname proxy, of the resolver for box names and of the Box Egress Proxy. Each port where the registry or cache traffic of the VM reaches the host counts as well, for TCP only. An entry for UDP at that port still opens. When Minimal starts to use the port of an entry later, `minvmd` closes that entry from then on. The daemon log names each skipped, refused or closed entry, and the Minimal listener that holds its port. `minvmd` no longer reads `MINVMD_HOST_EXPOSURE_PORTS`. When you set the variable, `minvmd` logs a warning and ignores its value.

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

