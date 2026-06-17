---
description: Complete CLI reference for all Minimal commands (run, build, test, shell, add, init, update, check, package, dep) and global flags.
---

# Minimal CLI Reference

## Global Flags

| Flag | Short | Description |
|------|-------|-------------|
| `--repo-dir <PATH>` | `-C` | Use the given directory as the repository root instead of searching from cwd |
| `--minimal-dir <PATH>` | | Override the base directory used for operations (default: `~/.cache/minimal`) |
| `--no-cache` | | Ignore locally-available binary artifacts (forces rebuilds unless present in remote cache) |
| `--no-fetch` | | Do not fetch binary artifacts from the internet |
| `--offline` | | Use only what's already in the local cache; fail on any network call. Useful for builds in network-isolated environments. |
| `--num-parallel-builds <N>` | `-n` | Configure the number of parallel builds |

## Commands

### `run <TASK_NAME> [<args>]` {#run}

Runs a task specified in [`minimal.toml`](/reference/tasks). *(Linux only)*

### `shell`

Launches a development shell. Shorthand for `minimal run shell`.

### `build`

Runs the build task. Shorthand for `minimal run build`.

### `test`

Runs the test task. Shorthand for `minimal run test`.

### `update`

Refreshes local checkouts of upstream packages and the standard library.

### `add <PACKAGES...>` {#add}

Add a new tool or dependency. Requires exactly one of:

| Flag | Description |
|------|-------------|
| `--runtime` | Add as a runtime dependency |
| `--build` | Add as a build dependency |
| `--task <TASK_NAME>` | Add to a task's package list |

### `init`

Automatically initialize Minimal configuration based on your source tree.

| Flag | Short | Description |
|------|-------|-------------|
| `--yes` | `-y` | Skip confirmation, write configuration based on auto-detection |

### `status`

Shows the status of Minimal in this codebase.

### `package <PACKAGES...>` (alias: `pkg`)

Builds specified package(s) in a clean room, making them available in the local cache. If no packages are specified, Minimal will build packages from local origin.

| Flag | Short | Description |
|------|-------|-------------|
| `--verbose` | `-v` | Log stdout/stderr during the build |

### `materialize <OUTPUT_NAME>` {#materialize}

Materializes an output defined in an [`[outputs.<name>]`](/reference/minimal-dot-toml#outputs) section of `minimal.toml`.

| Flag | Short | Description |
|------|-------|-------------|
| `--output <PATH>` | `-o` | **(required)** The output file to write |
| `--arch <ARCH>` | | Target architecture for OCI images (e.g. `amd64`, `arm64`). Overrides the `arch` field in `minimal.toml` and the host default |

Supported output types:

- `oci-image` — a Linux OCI image archive containing the configured packages, suitable for `docker load` or pushing to a registry.

See [`[outputs.*]`](/reference/minimal-dot-toml#outputs) for the full configuration schema.

### `check [FILTER_NAMES...]` {#check}

Validates Minimal's configuration including packages, stacks, and profiles.

| Flag | Short | Description |
|------|-------|-------------|
| `--fix` | `-f` | Attempt to fix any issues |
| `--skip-checkers <NAMES>` | `-s` | Comma-delimited checker names to skip |
| `--packages` | | Check packages defined in the codebase |
| `--stacks` | | Check stacks defined in the codebase |
| `--profiles` | | Check profiles defined in the codebase |

If no type flags are specified, all types are checked by default.

If filter names are specified, any package, stack, or profile matching a specified name is checked.

### `dep [PACKAGES...]`

Generates a dependency graph visualization.

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--excludes <PKGS>` | `-e` | | Comma-delimited packages to exclude |
| `--build-spec-deps` | | `true` | Include build spec "build_deps" |
| `--source-deps` | | `false` | Include source code "build_deps" |
| `--local-deps` | | `false` | Include local (build.sh) "input" deps |
| `--hostpath-deps` | | `false` | Include host path "build_deps" |
| `--needs` | | `false` | Include "Needs" nodes and edges |
| `--provides` | | `false` | Include "Provides" edges and "Needs" nodes |
| `--bootstrap` | | `false` | Include replace-on-cycle/prebuilts/bootstrap |
| `--subtrees-only` | | `false` | Require non-zero subtree deps for runtime/input deps |
| `--input-deps-depth <N>` | | `-1` | How deeply input dependencies are followed (-1 = all) |
| `--runtime-deps-depth <N>` | | `-1` | How deeply runtime dependencies are followed (-1 = all) |
| `--prune-edgeless` | | `false` | Discard graph nodes with no edges |
| `--output-format <FMT>` | | `dot` | Output format: `dot` or `mermaid` |

### `cache clean`

Remove cache entries that haven't been used recently.

| Flag | Default | Description |
|------|---------|-------------|
| `--older-than <DURATION>` | `14d` | Duration string (e.g. `7d`, `24h`, `30m`) |

### `completions <SHELL>`

Generate shell completion script. Supported shells: `bash`, `zsh`, `elvish`, `fish`.

Usage: `source <(minimal completions bash)`

## Environment Variables

| Variable | Description |
|----------|-------------|
| `RUST_LOG` | Controls logging level (default: `info`) |
