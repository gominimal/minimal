---
title: mip CLI
description: "Reference for mip, the package and build CLI that runs without the daemon on Linux, with its flags and commands."
---

# `mip` - package/build CLI

`mip` (short for "Minimal in-process") is the Minimal package and build
CLI. It reads a project's [`minimal.toml`](./minimal-dot-toml.md) and builds
packages in clean rooms. It also runs [tasks](./tasks.md) in sandboxes and
keeps the content-addressed local cache. It works without the daemon.

> **Advanced tool.** `mip` is for Linux only, and for advanced users who
> drive the package and build engine directly. For most work, use the
> [`min` session CLI](./cli-min.md).

## Global flags

These flags apply to every subcommand.

| Flag | Short | Description |
|------|-------|-------------|
| `--repo-dir <PATH>` | `-C` | Use this directory as the repository root. Without it, `mip` searches up from the current directory |
| `--minimal-dir <PATH>` | | The state directory. The default is `$XDG_STATE_HOME/minimal` when `XDG_STATE_HOME` is an absolute path, else `minimal` in the platform state directory, else `~/.local/state/minimal` |
| `--no-cache` | | Do not use the binary artifacts in the local cache. `mip` builds again each package that no remote cache has |
| `--no-fetch` | | Do not fetch binary artifacts from the internet |
| `--offline` | | Use only what is in the local cache for sources, VCS checkouts and artifacts. On a cache miss, `mip` exits with an error and does not use the network. `--offline` includes the remote-cache part of `--no-fetch`. It does not change `--no-cache` or `--rebuild` |
| `--num-parallel-builds <N>` | `-n` | The number of builds that run in parallel |

## Commands

### `run` {#run}

Runs a task. *(Linux only)*

```
mip run [OPTIONS] <task_name> [task_args]...
mip run [OPTIONS] --upstream <upstream> --task-spec <task_spec> [task_args]...
```

| Argument / flag | Description |
|-----------------|-------------|
| `<task_name>` | The name of a task in `minimal.toml` |
| `[task_args]...` | More arguments for the task, parsed by the task's `args` schema |
| `--upstream <JSON>` | The upstream link, as JSON. Use it with `--task-spec`, in place of `<task_name>`. It needs no `minimal.toml` |
| `--task-spec <JSON>` | A task, as JSON. Use it with `--upstream` |

`mip run --upstream ... --task-spec ...` refuses to run unless
`MINIMAL_SCIENCE_MODE=yeppers` is in the environment.

A task that `mip run <task_name>` runs has its `[patches]` checked against
your [`user_policy.toml`](./user-policy.md) first.

### `update`

```
mip update
```

Updates the project's `[upstream]` link and each sideload to the head of
its tracking branch, and writes the new `locked_commit` values to
`minimal.toml`. The command prints each change. It then downloads the
packages that the project can reach and that are in a remote cache but
not in the local cache.

The command changes `minimal.toml` in your working tree. Do not run it
only to fetch artifacts.

### `add` {#add}

```
mip add <--runtime|--build|--task <TASK>> <PACKAGES>...
```

Adds packages to `minimal.toml`. Give exactly one of these flags:

| Flag | Description |
|------|-------------|
| `--runtime` | Add the packages as runtime dependencies, which your program needs wherever it runs |
| `--build` | Add the packages as build dependencies, which your program needs to build |
| `--task <TASK>` | Add the packages to the package list of the task `<TASK>` |

### `init`

```
mip init [-y|--yes]
```

Writes a Minimal configuration for your source tree, from what it detects
there. With `--yes`, it writes the configuration and does not ask you first.

### `status`

```
mip status
```

Shows the status of Minimal in this codebase.

### `materialize` {#materialize}

```
mip materialize --output <OUTPUT> [--arch <ARCH>] <OUTPUT_NAME>
```

Writes an output that an
[`[outputs.<name>]`](./minimal-dot-toml.md#outputs) section of
`minimal.toml` declares.

| Flag | Short | Description |
|------|-------|-------------|
| `--output <PATH>` | `-o` | **(required)** The output file to write |
| `--arch <ARCH>` | | The architecture to build the output for, such as `amd64` or `arm64`. It takes precedence over the `arch` field in `minimal.toml` and the host default |

The output type `oci-image` writes a Linux OCI image archive of the
configured packages. You can load it with `docker load` or push it to a
registry.

### `package` (aliases: `pkg`, `packages`)

Package operations. It takes the subcommand `package build` or
`package dep`.

#### `package build`

```
mip package build [OPTIONS] [PACKAGES]...
```

Builds the packages in a clean room. The builds go into the local cache.

| Flag | Short | Description |
|------|-------|-------------|
| `--verbose` | `-v` | Print the build's stdout and stderr |
| `--rebuild` | | Build the packages again, even when the cache already has them |

#### `package dep`

```
mip package dep [OPTIONS] [PACKAGES]...
```

Prints the dependency graph as Graphviz source, or as Mermaid with
`--output-format mermaid`. To draw it, run
`mip package dep --input-deps-depth=0 | dot -Tpng > deps.png`.

A `<BOOL>` flag with no value means `true`: `--needs` is `--needs=true`.

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--excludes <PKGS>` | `-e` | | Packages to leave out of the graph and not follow, comma-separated. `--exclude` is the same flag |
| `--build-spec-deps <BOOL>` | | `true` | Include build spec `build_deps` (does not affect runtime deps) |
| `--source-deps <BOOL>` | | `false` | Include source code `build_deps` |
| `--local-deps <BOOL>` | | `false` | Include local (`build.sh`) input deps |
| `--needs <BOOL>` | | `false` | Include "Needs" nodes and edges |
| `--provides <BOOL>` | | `false` | Include "Provides" edges and "Needs" nodes |
| `--bootstrap <BOOL>` | | `false` | Include replace-on-cycle/prebuilts/bootstrap |
| `--subtrees-only <BOOL>` | | `false` | Require non-zero subtree deps for runtime/input deps |
| `--input-deps-depth <N>` | | `-1` | How many levels of input dependencies the graph follows (`-1` = all) |
| `--runtime-deps-depth <N>` | | `-1` | How many levels of runtime dependencies the graph follows (`-1` = all) |
| `--prune-edgeless <BOOL>` | | `false` | Discard graph nodes with no edges |
| `--output-format <FMT>` | | `dot` | Output format: `dot` or `mermaid` |

### `cache clean`

```
mip cache clean [--older-than <DURATION>]
```

Removes old entries from the local cache. It deletes a cached build
artifact when its last recorded use and last write are both older than
the cutoff. It also deletes each artifact with neither time recorded. It
always keeps the packages that the current project's tasks and stack need.
It also removes the sandbox, task and temporary build directories whose
process is no longer running.

`--older-than` takes a whole number of days, hours or minutes, such as
`30d`, `12h` or `45m`. The default is `14d`.

### `cache notices`

```
mip cache notices <source_sha256>
```

Prints, as JSON, the upstream attribution files (`NOTICE`, `COPYRIGHT`,
`COPYING`) that `mip` recorded the last time it extracted the source archive
with this sha256. Use the sha256 that the build spec declares.

| Argument | Description |
|----------|-------------|
| `<source_sha256>` | The archive's sha256, as declared in the build spec |

With no notices recorded for the sha256, the command fails with
`no notices recorded for <sha256>; extract the source first`.

### `check` {#check}

```
mip check [OPTIONS] [FILTER_NAMES]...
```

Checks the Minimal configuration: packages and stacks.

| Flag | Short | Description |
|------|-------|-------------|
| `--fix` | `-f` | Try to fix each issue that it finds |
| `--packages` | | Check packages defined in the codebase |
| `--stacks` | | Check stacks defined in the codebase |
| `--skip-checkers <NAMES>` | `-s` | The checkers to skip, by name, comma-separated. `--skip` is the same flag |

With no type flag, `mip check` checks packages and stacks. With filter
names, it checks each package or stack whose name matches one of them.

### `completions`

```
mip completions <SHELL>
```

Prints a shell tab-completion script for `mip`. The shells are `bash`,
`zsh`, `elvish`, `fish` and `powershell`. To load it in bash, run
`source <(mip completions bash)`.

## Environment variables

| Variable | Description |
|----------|-------------|
| `RUST_LOG` | The log filter. The default is `info` |

## Hidden commands

With `MINIMAL_SCIENCE_MODE` in the environment, `mip --help` shows more
commands. They are experimental and unsupported, and this page does not
document them. `mip package patched-build` refuses to run unless
`MINIMAL_SCIENCE_MODE=yeppers`.
