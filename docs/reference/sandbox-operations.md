---
description: In-sandbox min helper commands — add packages, search, check configuration, and run tasks from within a sandbox.
---

# `min` commands

`min` helper commands are available within all task sandboxes.

## Commands

### `add <PACKAGES...>` {#add}

Installs tools & dependencies into the running sandbox. If flags are provided, the named packages
are also configured as a build, runtime, or task dependency in `minimal.toml`.

| Flag | Description |
|------|-------------|
| `--runtime` | Add packages to `harness.runtime_packages` |
| `--build` | Add packages to `harness.build_packages` |
| `--task <TASK_NAME>` | Add packages to `tasks.<TASK_NAME>.packages` |

`min add` is the in-sandbox equivalent of the [`mip add`](./cli-mip.md#add) command.

### `search <TERM>`

Searches for and lists packages related to the search term.

### `check [<OPTIONS>] [FILTER_NAMES...]`

Validates minimal configuration including packages, harnesses, and profiles.

| Flag | Short | Description |
|------|-------|-------------|
| `--fix` | `-f` | Attempt to fix any issues |
| `--skip-checkers <NAMES>` | `-s` | Comma-delimited checker names to skip |
| `--packages` | | Check packages defined in the codebase |
| `--harnesses` | | Check harnesses defined in the codebase |
| `--profiles` | | Check profiles defined in the codebase |

If no type flags are specified, all types are checked by default.

If filter names are specified, any package, harness, or profile matching a specified name is checked.

`min check` is the in-sandbox equivalent of the [`mip check`](./cli-mip.md#check) command.

### `run <TASK_NAME> [<ARGS>...]`

Runs the specified task in a new Minimal sandbox. Interactive tasks are not supported.

`min run` is the in-sandbox equivalent of the [`mip run`](./cli-mip.md#run) command.
