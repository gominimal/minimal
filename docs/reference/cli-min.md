---
title: min CLI
description: Reference for the min session CLI: create, attach to, and manage sandboxed development sessions, plus the git-remote-min helper.
---

# `min` - session CLI

`min` is the Minimal session CLI. It talks to the `minimald` daemon (see
[minimald](./cli-minimald.md)) to create, attach to, and manage sandboxed
development sessions. Most commands start the daemon automatically when it
isn't running (`bug` is the exception): natively on Linux, or inside the
[`minvmd`](./cli-minvmd.md) microVM host daemon on macOS (and on Linux
under `--minvmd`).

Generated from `--help` at `60e19f60`.

## Global flags

These apply to every subcommand.

| Flag | Short | Description |
|------|-------|-------------|
| `--repo-dir <PATH>` | `-C` | Use the given directory as the repository root, instead of the current working directory |
| `--minimal-dir <PATH>` | | Override the base directory used for operations (default: `~/.cache/minimal`) |
| `--config-dir <PATH>` | | Override the user config directory; everything under `<config_dir>/minimal/` (`config.toml`, `loadouts/`, ...) resolves relative to it. Defaults to `$XDG_CONFIG_HOME` on Linux (or `$HOME/.config`); macOS also uses `$HOME/.config` |
| `--minvmd` | | Linux: run `minimald` inside the `minvmd` microVM instead of natively on the host (the default). No effect on macOS, where `minvmd` is the only backend |

## Commands

### `ls`

```
min ls [--raw] [--json]
```

Lists sessions. `--raw` prints raw session IDs one per line for piping
into scripts; `--json` prints the full session list as pretty-printed
JSON. When the daemon reports a shared resource pool, the table is headed
by a `RESOURCE POOL:` line (CPU cores, memory, and the number of sessions
sharing them); `--raw` omits it.

### `activate`

```
min activate [OPTIONS] [PATH]
```

Activates (creates) a new session for the project at `PATH` (defaults to
the current directory).

| Flag | Short | Description |
|------|-------|-------------|
| `--name <NAME>` | `-n` | Optional session name |
| `--sync <MODE>` | | How to load project files into the session: `tarball` (default: stream a tarball of your project and unpack it) or `none` (do not populate the worktree) |
| `--network <MODE>` | | Network mode: `no-net`, `host-net` (default), or `own-ip` |
| `--ingress <EXT:INT[/PROTO]>` | | Static ingress port mapping (`PROTO` = `tcp`\|`udp`, default `tcp`). Repeatable. Requires `--network own-ip` |
| `--loadout <NAME>` | | Apply the named loadout from `<config>/minimal/loadouts/<NAME>.toml`. Repeatable; if given, config-file `default_loadouts` are ignored |
| `--no-loadouts` | | Apply no loadouts at all (also skips the config's `default_loadouts`). Conflicts with `--loadout` |
| `--no-prompt` | | Fail instead of prompting when the daemon surfaces items user policy can't auto-decide; implied when stdin/stderr isn't a TTY |
| `--attach` | | Automatically attach after creation |

### `attach`

```
min attach [-c <COMMAND>] <SESSION>
```

Attaches to an existing session, identified by UUID or session name.
`-c/--command` execs a command in the session context non-interactively
instead of opening an interactive shell.

### `destroy`

```
min destroy [--all] [-f|--force] [SESSION]
```

Destroys (terminates) a session. `--all` destroys all sessions;
`-f/--force` skips the confirmation when destroying all sessions.

### `stop`

```
min stop [-f|--force]
```

Shuts down the `minimald` daemon. `--force` shuts down even if active
sessions exist.

### `loadout list` (alias: `ls`)

```
min loadout list [--dir <DIR>]
```

Lists loadouts from the user's config directory. `--dir` overrides the
loadouts directory (default: `<config>/minimal/loadouts`, e.g.
`~/.config/minimal/loadouts` on Linux).

### `dirs`

```
min dirs
```

Prints important directories and file paths for debugging.

### `bug`

```
min bug [-o <OUTPUT>]
```

Collects a diagnostic bundle (logs, state, config) to send to the minimal
dev team. Writes `minimal-diag-<timestamp>.tar.zst` to the current
directory; `-o/--output` overrides the path. The archive contains host
system facts, log tails, redacted config, and state listings, plus a
`manifest.json` recording any collector that failed or timed out; a
broken install still yields a valid archive that explains what is
missing.

Diagnosing a wedged system must not change it: `bug` mutates no state and
never starts a daemon; it works even when none is running.

Secret-shaped values (env vars, tokens) are redacted before they enter
the archive: only a small allowlist of env names (`RUST_LOG`, `HOME`,
`SHELL`, `TERM`, `PATH`, and the `XDG_*` / `MINIMAL_*` / `MINVMD_*` /
`MINIMALD_*` prefixes) has values captured verbatim (a sensitive-shaped
name always loses to the allowlist), and every other env var is reported
by name only. Session and project file contents are never included, only
name/size listings. Review the archive before sharing.

### `rename`

```
min rename <SESSION> <NEW_NAME>
```

Renames an existing session.

### `init`, `add`, `update`

```
min init [-y|--yes]
min add <--runtime|--build|--task <TASK>> <PACKAGES>...
min update
```

Project-configuration conveniences mirroring the corresponding `mip`
commands: initialize minimal configuration from your source tree, add a
tool or dependency, and refresh local checkouts of upstream packages and
the standard library. See the [mip reference](./cli-mip.md) for details.

### `version`

```
min version
```

Prints CLI and daemon version information.

### `completions`

```
min completions <SHELL>
```

Generates a shell tab-completion script. Supported shells: `bash`, `zsh`,
`elvish`, `fish`. Usage: `source <(min completions bash)`.

## `git push min://` - the git remote helper

Installs of `min` lay down a `bin/git-remote-min` symlink pointing at the
`min` binary. The binary dispatches on `argv[0]`: when invoked with the
basename `git-remote-min` (which is how git invokes remote helpers for
`min://` URLs), it speaks the
[gitremote-helpers](https://git-scm.com/docs/gitremote-helpers) line
protocol on stdio instead of the normal CLI.

This lets you add a session's workspace as a git remote and push to or
fetch from it directly:

```
git remote add session min://<session>
git push session
```

Only the `connect` capability is implemented: on `connect`, the helper
opens an exec channel to `minimald` over its Unix domain socket (the same
transport the rest of the CLI uses) and bridges git's pack-protocol
conversation across it; no external `ssh` or `socat` involved. Only the
two pack services (`git-upload-pack`, `git-receive-pack`) are accepted.
If the daemon is not running, the helper starts it, using default global
flags (git invokes helpers without any of `min`'s own flags).
