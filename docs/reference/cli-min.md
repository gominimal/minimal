---
title: min CLI
description: "Reference for the min session CLI: create, attach to, and manage sandboxed development sessions, plus the git-remote-min helper."
---

# `min` - session CLI

`min` is the Minimal session CLI. It talks to the `minimald` daemon (see
[minimald](./cli-minimald.md)) to create, attach to, and manage sandboxed
development sessions. Most commands start the daemon automatically when it
isn't running (`bug`, `stop`, and `version` are the exceptions): natively on
Linux, or inside the [`minvmd`](./cli-minvmd.md) microVM host daemon on macOS
(and on Linux under `--provider local-minvmd`). Running bare `min` with no
subcommand resolves a session for the current directory (activating one if
needed) and attaches to it.

Commands are spelled `min <noun> <verb>`, and every noun accepts its singular
and plural form (`session`/`sessions`, `provider`/`providers`,
`loadout`/`loadouts`). Bare `min` and a handful of bare verbs (`ls`, `stop`,
`init`, `add`, `update`) survive at the top level as deliberate ergonomic
exceptions, called out as such below; see
[the CLI convention](./cli.md#command-naming-convention) for the rule and the
full list of exceptions.

Generated from `--help` at `cb29f065`.

## Global flags

These apply to every subcommand.

| Flag | Short | Description |
|------|-------|-------------|
| `--repo-dir <PATH>` | `-C` | Use the given directory as the repository root, instead of the current working directory |
| `--minimal-dir <PATH>` | | Override the base directory used for operations (default: `~/.cache/minimal`) |
| `--config-dir <PATH>` | | Override the user config directory; everything under `<config_dir>/minimal/` (`config.toml`, `loadouts/`, ...) resolves relative to it. Defaults to `$XDG_CONFIG_HOME` on Linux (or `$HOME/.config`); macOS also uses `$HOME/.config` |
| `--provider <PROVIDER>` | | Daemon backend that hosts sessions: `local-minimald` (Linux default, `minimald` natively on the host) or `local-minvmd` (`minimald` inside the `minvmd` microVM). No effect on macOS, where `minvmd` is the only backend |
| `--no-input` | | Skip interactive prompts that need a terminal (such as the session picker); ambiguous choices error with a list of candidates instead. Implied when stdin/stdout is not a terminal |

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

A deliberate exception to the `min <noun> <verb>` convention: `ls` is the
highest-traffic command in the CLI and keeps its bare top-level form.

### `session activate`

```
min session activate [OPTIONS] [PATH]
```

Activates (creates) a new session for the project at `PATH` (defaults to
the current directory).

| Flag | Short | Description |
|------|-------|-------------|
| `--name <NAME>` | `-n` | Optional session name |
| `--sync <MODE>` | | How to load project files into the session: `tarball` (default: stream a tarball of your project and unpack it) or `none` (do not populate the worktree) |
| `--loadout <NAME>` | | Apply the named loadout from `<config>/minimal/loadouts/<NAME>.toml`. Repeatable; if given, config-file `default_loadouts` are ignored |
| `--no-loadouts` | | Apply no loadouts at all (also skips the config's `default_loadouts`). Conflicts with `--loadout` |
| `--no-prompt` | | Fail instead of prompting when the daemon surfaces items user policy can't auto-decide; implied when stdin/stderr isn't a TTY |
| `--attach` | | Automatically attach after creation |

### `session attach`

```
min session attach [-c <COMMAND>] [SESSION]
```

Attaches to an existing session, identified by UUID or session name. When
`SESSION` is omitted, `min session attach` resolves a session from the current
working directory (or the only existing session) and opens an interactive
picker if the choice is ambiguous (`--no-input` errors instead).
`-c/--command` execs a command in the session context non-interactively
instead of opening an interactive shell; the daemon accepts only
`min run <task name>` invocations on this channel, not arbitrary commands.

### `session destroy`

```
min session destroy [--all] [-f|--force] [SESSION]
```

Destroys (terminates) a session. `--all` destroys all sessions;
`-f/--force` skips the confirmation when destroying all sessions.

### `session rename`

```
min session rename <SESSION> <NEW_NAME>
```

Renames an existing session.

### `stop`

```
min stop [-f|--force]
```

Shuts down the `minimald` daemon. `--force` shuts down even if active
sessions exist. This stops the daemon backend that hosts sessions, and the
sessions themselves survive it (contrast
[`session destroy`](#session-destroy), which removes one session and leaves the
daemon running).

`stop` stays bare at the top level — a deliberate exception to the
`min <noun> <verb>` convention: it acts on the daemon, not on any session.

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

These three are deliberate exceptions to the `min <noun> <verb>` convention:
they are passthroughs to the `mip` commands of the same name, and keeping the
spelling identical across the two CLIs is worth more than the hierarchy.

### `version`

```
min version
```

Prints CLI and daemon version information.

### `completions`

```
min completions <SHELL>
```

Generates a shell tab-completion script. Supported shells include `bash`, `zsh`,
`elvish`, `fish`. Usage: `source <(min completions bash)`.

What it emits is a short *registration* shim, not a completion table: it teaches
the shell to ask `min` itself what to offer. That indirection is what makes
session arguments completable — `min session attach <TAB>` lists live session
names, and `min session attach 019<TAB>` lists session IDs, neither of which
exists at the time a static script would be written. Every argument documented
as "UUID or session name" completes this way: `session attach`,
`session destroy`, `session rename`, `session policy`, and `ssh-forward`.

Session completion is best-effort by design. It never starts a daemon — with
none running there is nothing to list, and booting a VM on a keystroke would be
a poor trade — and it gives up rather than make you wait if the daemon does not
answer promptly. In both cases the shell simply offers nothing.

To see the candidates without a shell in the loop, or to check completion
against a non-default backend:

```
min complete-session-str [<prefix>]              # value<TAB>description per line
min --provider local-minvmd complete-session-str # honours global args
```

The in-process completer cannot see global args (clap hands a value completer
only the word being typed), so it always resolves the default backend; this
hidden command is the way to check any other.

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
