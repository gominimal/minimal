---
title: Sandbox operations
description: "In-sandbox min helper commands: add packages, search, check configuration, and run tasks from within a sandbox."
---

# `min` commands

`min` helper commands are available within task sandboxes (Linux-only) and
inside [sessions](./cli-min.md), which install the same helper as
`/usr/bin/min`.

> **Naming note**: the in-sandbox `min` helper is a different tool from the
> [`min` session CLI](./cli-min.md) that happens to share its name. Inside a
> task sandbox, `min` always refers to the helper documented here. The session
> CLI is not available there.

## Commands

### `add [FLAG] <PACKAGES...>` {#add}

Installs tools & dependencies into the running sandbox. The default differs
by sandbox type. In a **session**, `min add <pkg>` with no flag defaults to
`--session`: it installs the package live and records it in the `[session]`
`packages` list of the project's `minimal.toml`. In a **task sandbox**, no
flag installs for the current sandbox only and leaves `minimal.toml`
unchanged. With a flag, `min add` records the packages as a session, runtime,
or build dependency in `minimal.toml`.

| Flag | Description |
|------|-------------|
| `--session` | Also add packages to the `[session]` `packages` list in `minimal.toml` |
| `--runtime` | Also add packages to `stack.runtime_packages` |
| `--build` | Also add packages to `stack.build_packages` |

`min add` is the in-sandbox counterpart of [`mip add`](./cli-mip.md#add). The flag surfaces differ: `mip add` requires one of `--runtime`, `--build`, or `--task <TASK>`.

`min package add` is the canonical noun-verb spelling. `min add` is an accepted alias.

### `search <TERM>`

Searches for and lists packages related to the search term.

`min package search` is the canonical noun-verb spelling. `min search` is an accepted alias.

### `check [<OPTIONS>] [FILTER_NAMES...]`

Checks the minimal configuration, including packages & stacks.

| Flag | Description |
|------|-------------|
| `--fix` | Attempt to fix any issues |
| `--packages` | Check packages defined in the codebase |
| `--stacks` | Check stacks defined in the codebase |

With no type flag, `min check` checks all types.

With filter names, `min check` checks each package or stack whose name matches one of them.

`min check` is the in-sandbox equivalent of the [`mip check`](./cli-mip.md#check)
command, with a reduced flag set (no `--skip-checkers`, and no short flag
aliases).

### `run <TASK_NAME> [<ARGS>...]`

Runs the specified task in a new Minimal sandbox. Interactive tasks are not supported.

`min run` is the in-sandbox equivalent of the [`mip run`](./cli-mip.md#run) command.

`min task run` is the canonical noun-verb spelling. The bare `min run` is a legacy alias.

### `net expose <PORT>`

Sessions only: publishes `<PORT>` at the box's published address, so the
host can reach it. Minimal decides the request against the
[`--dynamic-ingress`](./cli-min.md#session-activate) stance set at activation.
`allow` publishes a port inside `--dynamic-range` and refuses any other.
`ask` prompts the terminal attached to the session. With nobody attached,
Minimal refuses the request at once. An unset or `deny` stance refuses it.

The stances apply only to a `--network own_ip` box. On a `host_ip` box (the
default), the port does not need exposing: the box shares the host's network
and already answers at `<box>.min.internal:<PORT>`. Minimal refuses the
request from a `--network none` box. A deny or an unanswered `ask` names its
way forward, such as re-activating with the flags or the host-side
[`min net forward`](./cli-min.md#net-forward). Runtime publishes appear in
[`min session policy`](./cli-min.md#session-policy).

### `package build <PACKAGES...>`

Builds the packages in a clean room. The builds become available in the local
cache.

### `package patched-build <PACKAGE>`

Builds the package in a clean room with potentially-stale dependencies: the
already-cached builds of its dependencies, without rebuilding them first. It
commits the result to the local cache. Useful for quickly iterating on a
single package's build.

### `materialize [--arch <arch>] -o <out-file> <output-name>`

Materializes an output specified in an
[`[outputs.<name>]`](./minimal-dot-toml.md#outputs) section of
`minimal.toml`.

| Flag | Short | Description |
|------|-------|-------------|
| `--output <PATH>` | `-o` | **(required)** The output file to write |
| `--arch <ARCH>` | | Override the architecture used when building the output (such as `amd64` or `arm64`). It takes precedence over the `arch` field in `minimal.toml` and the host default |
