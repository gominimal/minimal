---
title: mip CLI
description: "Reference for the mip package/build CLI: build packages, run tasks, materialize outputs, and manage the local cache."
---

# `mip` - package/build CLI

`mip` (short for "Minimal in-process") is the Minimal package/build CLI. It
reads a project's [`minimal.toml`](./minimal-dot-toml.md), builds packages in
clean rooms, runs [tasks](./tasks.md) in sandboxes, and manages the
content-addressed local cache.

> **Advanced tool.** `mip` is Linux-only and aimed at advanced users driving
> the package/build plane directly. Most workflows are better served by the
> [`min` session CLI](./cli-min.md).

Generated from `--help` at `d9f20165`.

## Global flags

These apply to every subcommand.

| Flag | Short | Description |
|------|-------|-------------|
| `--repo-dir <PATH>` | `-C` | Use the given directory as the repository root instead of searching from the current working directory |
| `--minimal-dir <PATH>` | | Override the base directory used for operations (default: `~/.cache/minimal`) |
| `--no-cache` | | Ignore locally-available binary artifacts (results in rebuilds unless present in a remote cache) |
| `--no-fetch` | | Do not fetch binary artifacts from the internet |
| `--offline` | | Use only what's already in the local cache for sources, VCS checkouts, and the remote artifact cache; fail with a clear error on cache miss instead of attempting any network call. Implies the remote-artifact-cache half of `--no-fetch`; orthogonal to `--no-cache`/`--rebuild` |
| `--num-parallel-builds <N>` | `-n` | Configure the number of parallel builds |

## Commands

### `run` {#run}

Runs a task, such as one specified in `minimal.toml`. *(Linux only)*

```
mip run [OPTIONS] <task_name> [task_args]...
mip run [OPTIONS] --upstream <upstream> --task-spec <task_spec> [task_args]...
```

| Argument / flag | Description |
|-----------------|-------------|
| `<task_name>` | Name of the task to run (from `minimal.toml`) |
| `[task_args]...` | Additional arguments to pass to the task |
| `--upstream <JSON>` | JSON stanza specifying the software supply chain; must be used with `--task-spec` |
| `--task-spec <JSON>` | JSON stanza specifying a task inline; must be used with `--upstream` |

### `shell`, `build`, `test`

```
mip shell
mip build
mip test
```

Shorthands for `mip run shell`, `mip run build`, and `mip run test`
respectively. `shell` launches a development shell. *(Linux only)*

### `update`

```
mip update
```

Refreshes local checkouts of upstream packages and the standard library.

### `add` {#add}

```
mip add <--runtime|--build|--task <TASK>> <PACKAGES>...
```

Add a new tool or dependency. Exactly one placement flag is required:

| Flag | Description |
|------|-------------|
| `--runtime` | Add as a runtime dependency: your program needs this package anywhere it runs |
| `--build` | Add as a build dependency: your program needs this package to build |
| `--task <TASK>` | Add to a task's package list |

### `init`

```
mip init [-y|--yes]
```

Automatically initialize minimal configuration based on your source tree.
`--yes` skips confirmation and writes configuration based on
auto-detection.

### `status`

```
mip status
```

Shows the status of Minimal in this codebase.

### `materialize` {#materialize}

```
mip materialize --output <OUTPUT> [--arch <ARCH>] <OUTPUT_NAME>
```

Materializes an output specified in an
[`[outputs.<name>]`](./minimal-dot-toml.md#outputs) section of
`minimal.toml`.

| Flag | Short | Description |
|------|-------|-------------|
| `--output <PATH>` | `-o` | **(required)** The output file to write |
| `--arch <ARCH>` | | Override the architecture used when building the output (e.g. `amd64`, `arm64`); takes precedence over the `arch` field in `minimal.toml` and the host default |

Supported output types include `oci-image`, a Linux OCI image archive
containing the configured packages, suitable for `docker load` or pushing
to a registry.

### `package` (alias: `pkg`)

```
mip package [OPTIONS] [PACKAGES]...
```

Builds the specified package(s) in a clean room, making them available in
the local cache.

| Flag | Short | Description |
|------|-------|-------------|
| `--verbose` | `-v` | Log stdout/stderr during the build |
| `--rebuild` | | Always build the specified packages, even if they are already available |

### `cache clean`

```
mip cache clean [--older-than <DURATION>]
```

Removes stale entries from the local cache: cached build artifacts whose
last recorded use is older than the cutoff, or that have no recorded use
at all. Packages needed by the current project's tasks and stack are
always kept. Also removes sandbox, task, and temporary build directories
whose owning process is no longer running.

`--older-than` takes a whole number of days, hours, or minutes (e.g.
`30d`, `12h`, `45m`); the default is `14d`.

### `check` {#check}

```
mip check [OPTIONS] [FILTER_NAMES]...
```

Validates minimal configuration including packages, stacks, and profiles.

| Flag | Short | Description |
|------|-------|-------------|
| `--fix` | `-f` | Attempt to fix any issues |
| `--packages` | | Check packages defined in the codebase |
| `--stacks` | | Check stacks defined in the codebase |
| `--profiles` | | Check profiles defined in the codebase |
| `--skip-checkers <NAMES>` | `-s` | Checker names to skip, comma-separated |

If no type flags are specified, all types are checked. If filter names
are given, any package, stack, or profile matching a name is checked.

### `dep`

```
mip dep [OPTIONS] [PACKAGES]...
```

Generates Graphviz source code of the dependency graph, e.g.
`mip dep --input-deps-depth=0 | dot -Tpng > deps.png`.

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--excludes <PKGS>` | `-e` | | Packages left out of the graph and not traversed |
| `--build-spec-deps <BOOL>` | | `true` | Include build spec `build_deps` (does not affect runtime deps) |
| `--source-deps <BOOL>` | | `false` | Include source code `build_deps` |
| `--local-deps <BOOL>` | | `false` | Include local (`build.sh`) input deps |
| `--needs <BOOL>` | | `false` | Include "Needs" nodes and edges |
| `--provides <BOOL>` | | `false` | Include "Provides" edges and "Needs" nodes |
| `--bootstrap <BOOL>` | | `false` | Include replace-on-cycle/prebuilts/bootstrap |
| `--subtrees-only <BOOL>` | | `false` | Require non-zero subtree deps for runtime/input deps |
| `--input-deps-depth <N>` | | `-1` | How deeply input dependencies are followed (`-1` = all) |
| `--runtime-deps-depth <N>` | | `-1` | How deeply runtime dependencies are followed (`-1` = all) |
| `--prune-edgeless <BOOL>` | | `false` | Discard graph nodes with no edges |
| `--output-format <FMT>` | | `dot` | Output format: `dot` or `mermaid` |

### `completions`

```
mip completions <SHELL>
```

Generates a shell tab-completion script for `mip`. Supported shells:
`bash`, `zsh`, `elvish`, `fish`. Usage: `source <(mip completions bash)`.

## Environment variables

| Variable | Description |
|----------|-------------|
| `RUST_LOG` | Controls logging level (default: `info`) |

## Hidden commands

Additional unsupported/internal commands are hidden behind the
`MINIMAL_SCIENCE_MODE` environment variable. They are experimental, carry
no stability or consistency guarantees, and are not documented here.
