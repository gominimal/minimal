---
title: minimald daemon
description: Ops reference for the minimald host daemon — serves sandboxed sessions to the min CLI over SSH-on-UDS.
---

# `minimald` — host daemon

`minimald` is the Minimal host daemon. It creates and supervises the
sandboxed sessions that the [min CLI](./cli-min.md) connects to, speaking
SSH over a Unix domain socket (or vsock when hosted inside the `minvmd`
microVM). End users normally never run it by hand: `min` auto-starts a
native daemon on Linux, and [minvmd](./cli-minvmd.md) supervises it
inside the microVM.

Generated from `--help` at `e5ce5fb8`.

## Global flags

| Flag | Short | Description |
|------|-------|-------------|
| `--minimal-state-dir <PATH>` | | Override the directory where state is stored (default: `$XDG_STATE_DIR/minimal`) |
| `--minimal-cache-dir <PATH>` | | Override the directory where artifacts are cached (default: `$XDG_CACHE_DIR/minimal`) |
| `--num-parallel-builds <N>` | `-n` | Configure the number of parallel builds (currently accepted but ignored — see [Known issues](#known-issues)) |

## Commands

### `run`

```
minimald run [OPTIONS]
```

Runs the minimald server in the foreground.

| Flag | Description |
|------|-------------|
| `--instance-num <N>` | Instance number for this minimald; determines client-relevant paths under `<minimal_state_dir>/providers/local-<N>`. The SSH socket is accessible as `ssh.sock`. Default: `0` |
| `--vsock` | Host the SSH socket over vsock instead of UDS; the vsock port is the default port base plus `instance_num` |
| `--detach` | Daemonize: spawn minimald in a new session (setsid) and return once the SSH socket accepts connections, or an 8s timeout elapses. Used by the `min` CLI to auto-start a native daemon on Linux |
| `--gvproxy-bin <PATH>` | Path to the gvproxy ("gvisor-tap-vsock") binary backing the per-host own-IP switch. Defaults to the fixed system install path; point it at a local build to run own-IP networking without a system install |

### `completions`

```
minimald completions <SHELL>
```

Generates a shell tab-completion script for `minimald`. Supported shells:
`bash`, `zsh`, `elvish`, `fish`. Usage:
`source <(minimald completions bash)`.

## Known issues

- [#820](https://github.com/gominimal/minimal/issues/820) — `minimald`
  accepts but ignores `-n`/`--num-parallel-builds` and `--stdlib-dir`.
