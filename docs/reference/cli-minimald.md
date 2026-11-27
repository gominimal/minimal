---
title: minimald daemon
description: "Ops reference for the minimald host daemon, which serves sandboxed boxes to the min CLI over SSH on a Unix domain socket."
---

# `minimald` - host daemon

`minimald` is the Minimal host daemon. It creates and supervises the
sandboxed boxes that the [min CLI](./cli-min.md) connects to. It speaks SSH
over a Unix domain socket, or over vsock when it runs inside the `minvmd`
microVM. You do not usually run it by hand. On Linux, `min` starts a native
daemon when it needs one, and [minvmd](./cli-minvmd.md) runs the daemon
inside the microVM.

## Global flags

| Flag | Short | Description |
|------|-------|-------------|
| `--minimal-state-dir <PATH>` | | The directory for state. The default is `$XDG_STATE_HOME/minimal` when `XDG_STATE_HOME` is an absolute path. Otherwise it is `minimal` in the platform state directory, else `~/.local/state/minimal` |
| `--minimal-cache-dir <PATH>` | | The directory for cached artifacts. The default is the platform cache directory, such as `$XDG_CACHE_HOME/minimal` |

## Commands

### `run`

```
minimald run [OPTIONS]
```

Runs the minimald server in the foreground.

| Flag | Description |
|------|-------------|
| `--instance-num <N>` | The instance number of this daemon. It sets the client paths under `<minimal_state_dir>/providers/local-minimald<N>`, where the SSH socket is `ssh.sock`. Default: `0` |
| `--vsock` | Serve the SSH socket over vsock, not a Unix domain socket. The vsock port is the default port base plus `--instance-num` |
| `--hostname-proxy-port <PORT>` | The port for the host-side hostname proxy, which clients set `HTTP(S)_PROXY` to. With the flag unset, the daemon tries 7654. When 7654 is busy, it asks the OS for a free port and reports that port to clients. `min ls` prints it, and a second daemon on the host gets a port of its own. When a port that you set is busy, the daemon does not start the proxy on another port |
| `--zone-answerer-port <PORT>` | The UDP port for `*.min.internal` that the daemon holds as the single-operator interim. The default is 7656. The interim runs only while the host has no `minzoned` answerer service installed. With the service installed, the daemon sends its box names to the service and does not hold the port. When the port is busy, the daemon reports an error and does not move to another port |
| `--detach` | Start minimald in a new session (`setsid`) and return when clients can connect to the SSH socket. After 14 seconds without that, it exits with an error. `min` uses it to start a native daemon on Linux. The daemon refuses `--detach` with `--vsock` |
| `--gvproxy-bin <PATH>` | The path to the gvproxy ("gvisor-tap-vsock") binary for own-address networking. The default is the installed binary: the user-local `bin/gvproxy-min` that the installer writes, else the system install path. Set it to a local build to use own-address boxes without an install |
| `--egress-deny-all-opt-out` | Keep allow-all egress for a box that declares no `egress` section. Without the flag, an own-address box with no egress declaration cannot reach any external address, and the `EGRESS` column of `min ls` shows `deny-all (default)`. A box that declares its own egress section keeps it either way. The daemon reads the flag when it starts, so restart the daemon to change it |

`MINIMALD_EGRESS_DENY_ALL_OPT_OUT` in the daemon's environment has the same
effect as `--egress-deny-all-opt-out`. The values `1`, `true`, `yes` and
`on` opt out, in any letter case. A daemon that `min` starts does not get flags,
but it gets the environment of the shell that started it. Export the
variable to keep the opt-out each time `min` starts the daemon. The VM
counterpart is `MINVMD_EGRESS_DENY_ALL_OPT_OUT`, as [minvmd](./cli-minvmd.md)
describes.

A host can block unprivileged user namespaces. On such a host the daemon
refuses to create a box. `MINIMALD_USERNS_GATE=off` in the daemon's
environment turns that check off, and the daemon logs a warning that it
skipped the check.

#### Listener log lines

When the hostname proxy comes up, the daemon logs a line with
`component=dns-proxy` and `status=serving`. The line names the port and a
`port_source` field:

- `configured`: `--hostname-proxy-port` set the port.
- `default`: the default port was free.
- `selected`: the OS chose the port. The default was busy, the host
  refused a publish of the port, or the configured port was `0`.

When the daemon runs the interim answerer, it logs a line with
`component=zone-answerer` and `status=serving`. The line names the `port`,
the `listener` address and the `channel` path.

`min ls` prints a `HOSTNAME PROXY` line with the proxy's port. It also
prints a `DNS SERVICE` line, marked `(UDP)`, for the answerer that serves
the box names of this daemon. That is the port of the `minzoned` service,
or the interim's port. It is the port for the host's resolver, not a value
for `HTTP(S)_PROXY`.

### `completions`

```
minimald completions <SHELL>
```

Prints a shell tab-completion script for `minimald`. The shells are `bash`,
`zsh`, `elvish`, `fish` and `powershell`. To load it in bash, run
`source <(minimald completions bash)`.

## Known issues

- `minimald` accepts the hidden `--stdlib-dir` flag but does not use it.
