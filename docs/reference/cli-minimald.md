---
title: minimald daemon
description: "Ops reference for the minimald host daemon: serves sandboxed sessions to the min CLI over SSH-on-UDS."
---

# `minimald` - host daemon

`minimald` is the Minimal host daemon. It creates and supervises the
sandboxed sessions that the [min CLI](./cli-min.md) connects to, speaking
SSH over a Unix domain socket (or vsock when hosted inside the `minvmd`
microVM). End users normally never run it by hand: `min` auto-starts a
native daemon on Linux, and [minvmd](./cli-minvmd.md) supervises it
inside the microVM.

Generated from `--help` at `3a05252c`.

## Global flags

| Flag | Short | Description |
|------|-------|-------------|
| `--minimal-state-dir <PATH>` | | Override the directory where state is stored (default: `$XDG_STATE_HOME/minimal`) |
| `--minimal-cache-dir <PATH>` | | Override the directory where artifacts are cached (default: `$XDG_CACHE_HOME/minimal`) |

## Commands

### `run`

```
minimald run [OPTIONS]
```

Runs the minimald server in the foreground.

| Flag | Description |
|------|-------------|
| `--instance-num <N>` | Instance number for this minimald; determines client-relevant paths under `<minimal_state_dir>/providers/local-minimald<N>`. The SSH socket is accessible as `ssh.sock`. Default: `0` |
| `--vsock` | Host the SSH socket over vsock instead of UDS; the vsock port is the default port base plus `instance_num` |
| `--hostname-proxy-port <PORT>` | Port the host-side hostname proxy must listen on, when this deployment pins one — the port clients point `HTTP(S)_PROXY` at, whose documented default is 7654. Unset (the default) tries that default first and only when it is busy asks the OS for a free port, which the daemon reports wherever a client needs it: `min ls` prints it, and a second daemon on the same machine gets its own port instead of silently losing hostname routing. A pinned port that is busy stays a hard failure. |
| `--zone-answerer-port <PORT>` | Port the box-zone answerer must listen on (UDP), when this deployment pins one — the port the host's resolver is pointed at to answer `*.min.internal`, whose documented default is 7656. Unset (the default) gives it the same try-the-default-then-select treatment `--hostname-proxy-port` documents. |
| `--detach` | Daemonize: spawn minimald in a new session (setsid) and return once the SSH socket accepts connections, or an 8s timeout elapses. Used by the `min` CLI to auto-start a native daemon on Linux |
| `--gvproxy-bin <PATH>` | Path to the gvproxy ("gvisor-tap-vsock") binary used for networking. Defaults to the installed location: the user-local `bin/gvproxy-min` the installer stamps, else the system install path. |

### `completions`

```
minimald completions <SHELL>
```

Generates a shell tab-completion script for `minimald`. Supported shells include
`bash`, `zsh`, `elvish`, `fish`, `powershell`. Usage:
`source <(minimald completions bash)`.

## Known issues

- `minimald` accepts but ignores the hidden `--stdlib-dir` flag.
