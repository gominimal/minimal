---
title: min CLI
description: "Reference for the min session CLI: create, attach to, and manage sandboxed development sessions, plus the git-remote-min helper."
---

# `min` - session CLI

`min` is the Minimal session CLI. It talks to the `minimald` daemon (see
[minimald](./cli-minimald.md)) to create, attach to, and manage sandboxed
development sessions. Most commands start the daemon automatically when it
isn't running, with `bug`, `stop`, and `version` being the exceptions. The 
daemon starts natively on Linux (and under `--provider local-minvmd`) or 
inside the [`minvmd`](./cli-minvmd.md) microVM host daemon on macOS. 
Running bare `min` with no subcommand routes you into a session when stdin
and stdout are both a terminal: it follows the smart-resolution rules of
`min session attach` with no argument (cwd match → attach, only session →
attach, ambiguity → picker), and when no sessions exist it creates one from
the current directory and attaches. Without a terminal it instead prints a
read-only state report on stderr and exits successfully. Use `min --help` to print this
help.

Commands are spelled `min <noun> <verb>`, and every noun accepts its singular
and plural form (`session`/`sessions`, `loadout`/`loadouts`). A handful of
bare verbs (`ls`, `stop`,
`init`, `add`, `update`) survive at the top level as deliberate ergonomic
exceptions, called out as such below; see
[the CLI convention](./cli.md#command-naming-convention) for the rule and the
full list of exceptions.

## Global flags

These apply to every subcommand.

| Flag | Short | Description |
|------|-------|-------------|
| `--repo-dir <PATH>` | `-C` | Use the given directory as the repository root, instead of the current working directory |
| `--minimal-dir <PATH>` | | Override the base directory for minimal's state; the session store, provider instances, and other on-disk state live under `<minimal_dir>/`. Defaults to `$XDG_STATE_HOME/minimal` on Linux (or `$HOME/.local/state/minimal`); macOS also uses `$HOME/.local/state/minimal` |
| `--config-dir <PATH>` | | Override the user config directory; everything under `<config_dir>/minimal/` (`config.toml`, `loadouts/`, ...) resolves relative to it. Defaults to `$XDG_CONFIG_HOME` on Linux (or `$HOME/.config`); macOS also uses `$HOME/.config` |
| `--provider <PROVIDER>` | | Daemon backend that hosts sessions: `local-minimald` (Linux default, `minimald` natively on the host) or `local-minvmd` (`minimald` inside the `minvmd` microVM). No effect on macOS, where `minvmd` is the only backend |
| `--no-input` | | Skip interactive prompts that need a terminal (such as the session picker); ambiguous choices error with a list of candidates instead. Implied when stdin/stdout is not a terminal |

## Commands

### `session list` (aliases: `min ls`, `min session ls`)

```
min session list [--raw] [--json]
```

Lists sessions. `--raw` prints raw session IDs one per line for piping
into scripts; `--json` prints the full session list as pretty-printed
JSON. When the daemon reports a shared resource pool, the table is headed
by a `RESOURCE POOL:` line (CPU cores, memory, and the number of sessions
sharing them); `--raw` omits it.

`min ls` is the same command kept bare at the top level — a deliberate
exception to the `min <noun> <verb>` convention, since it is the
highest-traffic command in the CLI; `min session ls` is the noun-level alias.
All three spellings take the same flags and produce identical output.

### `dash`

```text
min dash
```

Opens a full-screen TUI for browsing, inspecting, and managing sessions
across every running provider on the host (native minimald and the minvmd
microVM). The left pane lists sessions grouped by provider; the right pane
stacks the focused session's Info, networking Policy, and a read-only live
Preview of its terminal screen (no attach, no PTY resize). Requires a
terminal.

Keys: `↑`/`↓` (or `k`/`j`) move, `/` fuzzy-filters by name, ID, and
project path, `enter` attaches to the focused session (suspend TUI → ssh →
resume on `ctrl-]` then `d` detach) or collapses a provider group, `d` destroys
(with confirmation — also cancels an in-flight create/upload), `r`
renames, `n` creates a session through the full activate flow (project
upload, loadout compose, finalize), `q` quits. The cursor's last position
is restored on the next launch from `<state>/dash-state.json`; TUI
diagnostics go to `<state>/dash.log`.

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
| `--no-hooks` | | Run none of the session's [lifecycle hooks](./loadouts.md#lifecycle_hooks---scripts-at-session-transition-points), from either the loadouts or the project's `minimal.toml`. Recorded on the session, so it applies to the later attach, detach, and destroy transitions too |
| `--no-prompt` | | Fail instead of prompting when the daemon surfaces items user policy can't auto-decide; implied when stdin/stderr isn't a TTY |
| `--attach` | | Automatically attach after creation |

When `PATH` has no `minimal.toml`, activation still succeeds and the session
comes up with a default environment. On an interactive terminal `min` first
offers to scaffold a `minimal.toml`; accepting writes one into `PATH`, while
declining leaves your directory untouched. When prompts are skipped
(`--no-input`, or a non-terminal stdin) `min` prints a notice and continues
without writing anything to `PATH` — the daemon fabricates a default config
inside the session's own workspace instead. `--loadout` is resolved before any
of this, so an unknown loadout name errors even in a directory with no config.

### `session attach`

```
min session attach [SESSION]
```

Attaches to an existing session, identified by UUID or session name. When
`SESSION` is omitted, `min session attach` resolves a session from the current
working directory (or the only existing session) and opens an interactive
picker if the choice is ambiguous (`--no-input` errors instead).

### `session exec`

```
min session exec <SESSION> <COMMAND>...
```

Runs a command in an existing session, non-interactively, relaying its
stdout, stderr and exit code.

How `COMMAND` is read depends on how many arguments you give it:

- **One argument is a shell command**, run by the session's shell with its
  pipes, globs and `$VAR` intact — the `ssh host '<cmd>'` form.

  ```
  min session exec web 'echo $PWD'
  ```

- **Several arguments are an argv**, carried as data. No shell reassembles
  them, so a word keeps its spaces and its metacharacters stay literal.

  ```
  min session exec web sh -c 'echo A B C'
  ```

The argv form matters because ssh has no argv on the wire — it joins its
trailing arguments with single spaces and the far side reshells the result.
Passing words through one by one would let the session's shell re-split them,
which is how `sh -c 'echo A B C'` once lost its first word to `sh`'s `$0`.

Nothing about a command's *text* routes it: a command is the session's however
it happens to start, so the session's own `min` binary is reachable here. The
daemon's own operations are named explicitly instead — see `session run`.

#### Backgrounding a command

`session exec` returns when `COMMAND` itself exits, and relays output up to
that point. A process the command backgrounds keeps running in the session,
but what it writes *after* the command has exited is not yours to rely on: a
short drain catches whatever was already in flight, and past that its output
is read and discarded. Nothing it writes is ever lost to a broken pipe — the
process is not killed — but you will not see it.

```
min session exec web 'sleep 20 & echo STARTED'   # returns immediately
```

So background a long-running process with its output redirected somewhere you
can retrieve it, rather than expecting it on the wire:

```
min session exec web 'nohup ./server >server.log 2>&1 &'
min session exec web 'tail -n 50 server.log'
```

`nohup ... >/dev/null 2>&1 &` is the fully detached form: it hands the process
its own stdout and stderr and drops the ones it inherited, so nothing about it
depends on the exec channel at all. The same applies to `session run` and
`task run`, which relay over the same channel.

### `session run`

```
min session run <SESSION> <TASK>
```

Runs a task declared in the session project's `minimal.toml`, in that session,
relaying its output and exit code.

This is the session-scoped counterpart to
[`min task run <task>`](../guide/tasks.md), which composes a task session of
its own. Use `session run` when you want the task to run against a session you
already have.

Because the task is named as a task rather than inferred from a command string,
a task may share a name with a daemon subcommand or with a program on the
session's `PATH`.

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

### `session policy`

```
min session policy <SESSION>
```

Prints the effective networking policy for `SESSION` (a UUID or session
name) as JSON — an object with `egress` and `ingress` fields, each null
when unset. Resolved from the daemon.

### `session hooks`

```
min session hooks <SESSION> [--json]
```

Lists the [lifecycle hooks](./loadouts.md#lifecycle_hooks---scripts-at-session-transition-points)
composed into `SESSION` (a UUID or session name), one row per script, with
the transition it runs on, whether it is inline or external, its timeout, and
the loadout or project that declared it.

This shows what will actually run, not what was asked for: the daemon answers
from the session's composition, which holds only the hooks that survived your
[user policy](./user-policy.md). A session activated with `--no-hooks`, or one
whose project you never allow-listed, lists nothing.

Rows are in setup order — the project first, then loadouts in the order they
were applied; teardown runs the reverse. Inline bodies are collapsed to their
first line; `--json` emits the full records.

Answered from the persisted composition, so it works after a daemon restart
and for a session nobody is attached to.

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

Because sessions are interactive, the bundle also records the terminal
`bug` itself ran on (`host/terminal.json`): whether stdin, stdout, and
stderr are ttys — the same condition `attach` gates on, so a run under a
pipe or CI is distinguishable from a real terminal — and, for each that
is, its device and its `TIOCGWINSZ` geometry (rows, columns, and the
`xpixel`/`ypixel` size emulators report), which is what makes a garbled
TUI or wrong wrapping diagnosable.

The bundle is scoped to a project, so it can be attributed to one. Every
other collector describes a machine, and a machine hosts many projects:
two bundles taken on one host from two checkouts otherwise read
identically. `manifest.json` therefore opens with the project's name,
root, and which config file defines it (`minimal.toml` or
`.minimal/minimal.toml`), repeated in `project/project.json` along with
the directory `bug` was actually run from. Run outside a project, the
manifest records that as a finding with its reason rather than falling
silent.

Only the project's identity is recorded there — its name, its root, its
config file's relative path, and where `bug` ran from. No configuration
*values*; the redacted config is collected separately, under the
allowlist policy below.

Diagnosing a wedged system must not change it: `bug` mutates no state and
never starts a daemon; it works even when none are running.

Secret-shaped values (env vars, tokens) are redacted before they enter
the archive: only a small allowlist of env names (`RUST_LOG`, `HOME`,
`SHELL`, `TERM`, `TERM_PROGRAM`, `TERM_PROGRAM_VERSION`, `COLORTERM`,
`PATH`, and the `XDG_*` / `MINIMAL_*` / `MINVMD_*` / `MINIMALD_*`
prefixes) have values captured verbatim (a sensitive-shaped
name always loses to the allowlist), and every other env var is reported
by name only. Session and project file contents are never included, only
name/size listings. Review the archive before sharing.

### `init`, `add`, `update`

```
min init [-y|--yes]
min add <--session|--runtime|--build|--task <TASK>> <PACKAGES>...
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

### `completions` (alias: `completion`)

```
min completions print <SHELL>
min completions install [<SHELL>...]
```

`print` writes a shell tab-completion script to stdout. Supported shells
include `bash`, `zsh`, `elvish`, `fish`, `powershell`. Usage:
`source <(min completions print bash)`.

`install` writes that script into the shell's completion directory instead,
for the three shells with a conventional per-user completion path. With no
`SHELL` argument it installs for all three.

| Shell | Path |
|-------|------|
| `bash` | `$XDG_DATA_HOME/bash-completion/completions/min` (default `~/.local/share/...`) |
| `zsh` | `$XDG_DATA_HOME/zsh/completions/_min` (default `~/.local/share/...`) |
| `fish` | `$XDG_CONFIG_HOME/fish/completions/min.fish` (default `~/.config/...`) |

Each file is written atomically — a temporary sibling, then a rename — so a
half-written completion file never reaches a shell.

`install` prints every path it wrote to stdout, one per line. That is a
contract rather than a convenience: `scripts/install.sh` feeds exactly those
paths into its install record so `uninstall` can remove them, and derives no
paths of its own. The bookkeeping therefore has one implementation, reachable
by everyone rather than only by users who installed via `curl | sh`.

A completion directory that exists but is not writable — these are shared,
user-owned locations that can pre-exist root-owned — produces a warning on
stderr, not a failure: the other shells still install and the exit status is
still 0. For `zsh`, a stale `compinit` dump is dropped after a (re)install,
since it can otherwise keep trusting its cached contents after the completion
file underneath has changed.

What it emits is a short *registration* shim, not a completion table: it teaches
the shell to ask `min` itself what to offer. That indirection is what makes
session arguments completable — `min session attach <TAB>` lists live session
names, and `min session attach 019<TAB>` lists session IDs, neither of which
exists at the time a static script would be written. Every argument documented
as "UUID or session name" completes this way: `session attach`,
`session exec`, `session run`, `session destroy`, `session rename`, and
`session policy`.

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
