---
title: Sandbox operations
description: In-sandbox min helper commands — add packages, search, check configuration, and run tasks from within a sandbox.
---

# `min` commands

`min` helper commands are available within all task sandboxes. Task sandboxes
(and therefore these commands) are Linux-only.

> **Naming note**: the in-sandbox `min` helper is a different tool from the
> [`min` session CLI](./cli-min.md) that happens to share its name. Inside a
> task sandbox, `min` always refers to the helper documented here; the session
> CLI is not available there.

## Commands

### `add [FLAG] <PACKAGES...>` {#add}

Installs tools & dependencies into the running sandbox. With no flag, packages
are installed for the current sandbox session only — `minimal.toml` is not
modified. With a flag, the named packages are also recorded as a build,
runtime, or task dependency in `minimal.toml`.

| Flag | Description |
|------|-------------|
| `--session` | Install for this sandbox session only, without editing `minimal.toml` (the default when no flag is given) |
| `--runtime` | Also add packages to `stack.runtime_packages` |
| `--build` | Also add packages to `stack.build_packages` |
| `--task` | Also add packages to the current task's `packages` list |

`min add` is the in-sandbox equivalent of the [`mip add`](./cli-mip.md#add) command.

### `search <TERM>`

Searches for and lists packages related to the search term.

### `check [<OPTIONS>] [FILTER_NAMES...]`

Validates minimal configuration including packages, stacks, and profiles.

| Flag | Description |
|------|-------------|
| `--fix` | Attempt to fix any issues |
| `--packages` | Check packages defined in the codebase |
| `--stacks` | Check stacks defined in the codebase |
| `--profiles` | Check profiles defined in the codebase |

If no type flags are specified, all types are checked by default.

If filter names are specified, any package, stack, or profile matching a specified name is checked.

`min check` is the in-sandbox equivalent of the [`mip check`](./cli-mip.md#check)
command, with a reduced flag set (no `--skip-checkers`, and no short flag
aliases).

### `run <TASK_NAME> [<ARGS>...]`

Runs the specified task in a new Minimal sandbox. Interactive tasks are not supported.

`min run` is the in-sandbox equivalent of the [`mip run`](./cli-mip.md#run) command.

### `build`, `test`

Shorthands for `min run build` and `min run test` respectively.

### `patched-pkg <PACKAGE>`

Builds the named package in a clean room using potentially-stale dependencies
(the already-cached builds of its dependencies, without rebuilding them first),
and commits the result to the local cache. Useful for quickly iterating on a
single package's build.
