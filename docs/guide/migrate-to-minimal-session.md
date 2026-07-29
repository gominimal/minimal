---
description: Migration to the new architecture after v0.5.0 release for Linux and macOS.
---

# Minimal Sessions Migration Guide

If you're on a release **older than v0.5.0**, you'll need to update your configuration to use the new Sessions architecture. Check your version with `minimal --version` or `min --version`.

## Upgrading from v0.4.1 or earlier

> **Note:** `tasks` are not supported by v0.5.0. If you rely on `tasks` for non-interactive, job-like workflows, keep `minimal` (<=v0.4.1) installed for tasks, and install `min` (v0.5.0) alongside it for sessions.

The Minimal command is becoming `min`, which won't conflict with the legacy `minimal` command. `minimal` will keep working for the foreseeable future, but its installer will no longer be available after v0.5.0 ships.

To install `min`, see [install](./install.md). If you no longer need `minimal`, uninstall it with:
```shell
./.minimal/shim/uninstall.sh
```

### Linux: use `mip` in place of `minimal`

To keep ephemeral build systems on Linux working, the `min` installer also installs `mip` (Minimal-In-Process), which is functionally identical to `minimal`. Update any scripts using `minimal` to use `mip` instead — see [cli-mip](../reference/cli-mip.md) for full docs.

| Old | New |
|---|---|
| `minimal run` | `mip run` |
| `minimal update` | `mip update` |
| `minimal add` | `mip add` |
| `minimal status` | `mip status` |
| `minimal build` | `mip build` |
| `minimal test` | `mip test` |
| `minimal materialize` | `mip materialize` |
| `minimal package` | `mip package` |
| `minimal cache` | `mip cache` |
| `minimal check` | `mip check` |
| `minimal dep` | `mip dep` |
| `minimal completions` | `mip completions` |
| `minimal help` | `mip help` |

The in-VM command `min add` is unchanged.

## Changes to `minimal.toml`

Prior to v0.5.0, `minimal.toml` had five sections: `upstream`, `harness`, `defaults`, `outputs`, and `tasks`.

| Section | Status |
|---|---|
| `[upstream]` | Unchanged |
| `[harness]` | Renamed to [`[stack]`](../concepts/stacks.md); functionality unchanged |
| `[defaults]` | `profiles` deprecated — see [Profiles](#profiles) |
| `[outputs]` | Unchanged |
| `[tasks]` | Interactive tasks (bash, shell, interactive agent sessions) moved to [`[session]`](#session-new); non-interactive tasks (test, build) aren't supported in v0.5.0 |

### `[session]` (new)

`session` is a new concept in v0.5.0 for interactive environments — shell, bash, and interactive agent entry points. Migrate any task using `shell`, `bash`, or an interactive agent entry point to a session definition; see [the session configuration reference](../reference/minimal-dot-toml.md#session---what-every-contributors-session-gets-session) for how.

Unlike `tasks`, which supported multiple definitions each invoked with `minimal run <task>`, a project has only one `session`:

```shell
min activate          # creates a session, prints its ID
min attach <session ID>  # enters an existing session
min activate --attach    # creates and enters a session in one step
```

## Profiles

Profiles have been deprecated:

- `profile.env_vars` → `session.vars`
- `profile.packages` → `session.packages`

See [the session configuration reference](../reference/minimal-dot-toml.md#session---what-every-contributors-session-gets-session) for how to define a session.
