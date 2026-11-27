---
title: Sandbox operations
description: "Commands of the min helper inside a box or a mip run sandbox, for packages, configuration checks, tasks, builds, outputs and ports."
---

# `min` commands

Inside a sandbox, `/usr/bin/min` is a helper, not the
[`min` session CLI](./cli-min.md) that you run on the host. The session CLI
is not available inside a sandbox. The helper comes in these forms:

- **The box helper**, in every box that `minimald` hosts: session boxes and
  the boxes of `min task run`.
- **The `mip run` helper**, in the sandbox of a task that
  [`mip run`](./cli-mip.md#run) runs, on Linux only. It has fewer commands.

In a box, run `min --help` to print the helper's commands, and add `--help`
to a command to print its usage. The `mip run` helper has no `--help`. Run
`min` there with no arguments: it prints its commands on stderr and exits 1.

| Command | Box helper | `mip run` helper |
|---------|------------|------------------|
| [`add`](#add) | Yes | Yes, with `--task` |
| [`package search`](#search) | Yes | Yes |
| [`check`](#check) | Yes | Yes |
| [`task run`](#run) | Yes | Yes |
| [`package build`](#package-build) | Yes | No |
| [`package patched-build`](#package-patched-build) | Yes | Yes |
| [`materialize`](#materialize) | Yes | No |
| [`net expose`](#net-expose) | Yes | No |

`min pkg` is an alias of `min package` in both helpers.

## Commands

### `add [FLAG] <PACKAGES...>` {#add}

Installs packages into the running sandbox. Whether `min add` also records
them in `minimal.toml` depends on the flag and on the helper, as the table
and the list below say. `min package add` is the same
command.

| Flag | Description |
|------|-------------|
| `--session` | In a box, also add the packages to the `packages` list of `[defaults.session]`. In a `mip run` sandbox, install them without a record |
| `--runtime` | Also add the packages to `stack.runtime_packages` |
| `--build` | Also add the packages to `stack.build_packages` |
| `--task` | `mip run` helper only. Also add the packages to the packages of the task that is running |

With no flag, the two helpers do different things:

- In a box, `min add <pkg>` is `min add --session <pkg>`. It installs the
  package and records it in the `packages` list of `[defaults.session]` in
  the box's `minimal.toml`. A top-level `[session]` table from an older
  `minimal.toml` moves under `[defaults]` when `min add` writes the file.
- In a `mip run` sandbox, `min add <pkg>` installs the package for this
  sandbox only and leaves `minimal.toml` unchanged. It prints a line that
  says so.

A package that sets environment variables prints an `export` line. Run it
to apply the variables in your current shell.

`min add` is the in-sandbox counterpart of [`mip add`](./cli-mip.md#add).
The flags differ: `mip add` requires one of `--runtime`, `--build`, or
`--task <TASK>`.

### `package search <TERM>` {#search}

Lists up to eight packages whose names are closest to the search term.
`min search` is the same command.

### `check [<OPTIONS>] [FILTER_NAMES...]` {#check}

Checks the Minimal configuration: packages and stacks.

| Flag | Description |
|------|-------------|
| `--fix` | Try to fix each issue that it finds |
| `--packages` | Check packages defined in the codebase |
| `--stacks` | Check stacks defined in the codebase |

With no type flag, `min check` checks packages and stacks.

With filter names, `min check` checks each package or stack whose name
matches one of them.

`min check` is the in-sandbox equivalent of [`mip check`](./cli-mip.md#check),
with fewer flags. It has no `--skip-checkers` and no short flags.

### `task run <TASK_NAME> [<ARGS>...]` {#run}

Runs the task in a new sandbox and passes it the arguments. `min run` is the
same command.

You cannot run an interactive task from inside a sandbox. The helper refuses
it with `cannot run interactive tasks from within an environment`. Run it
from the host instead.

In a box, a task that sets [`inherit_cwd = true`](./tasks.md) starts in the
current directory when that directory is under `/workbench`. When the
directory is outside `/workbench`, the helper prints a line that says so,
and the task starts in `/workbench`. Any other task starts in `/workbench`.

From the shell that runs `min task run`, the task gets only the variables
that it declares with [`{ inherit = true }`](./tasks.md#env_vars). The
shell's other variables do not reach the task, and a declared variable that
the shell does not set makes Minimal refuse the run.

When the helper's stdin is a pipe or a file, the task reads that stdin.
The helper exits with the task's exit code. When the connection closes
before the task reports its exit code, the helper prints an error and exits
125. Ctrl-C ends the helper with 130, and the helper does not print an
error.

`min task run` is the in-sandbox equivalent of [`mip run`](./cli-mip.md#run).

### `package build <PACKAGES...>` {#package-build}

Box helper only. Builds the packages in a clean room. The builds go into the
local cache. The `mip run` helper refuses the command.

A build that you ask for inside a box runs in a build box. Its reach depends
on where the package comes from. A box that does not admit the network
refuses a project package that needs the network. See
[build boxes](./build-specs.md#build-boxes).

### `package patched-build <PACKAGE>` {#package-patched-build}

Builds the package in a clean room against the cached builds of its
dependencies. It does not rebuild those dependencies first. Use it to
iterate quickly on the build of one package.

It writes the result to the local cache, apart from the builds that a
normal build or install uses. A later patched build of a package that
depends on it uses it.

### `materialize [--arch <arch>] -o <out-file> <output-name>` {#materialize}

Box helper only. Writes an output that an
[`[outputs.<name>]`](./minimal-dot-toml.md#outputs) section of
`minimal.toml` declares. A relative `--output` path is relative to the
current directory.

| Flag | Short | Description |
|------|-------|-------------|
| `--output <PATH>` | `-o` | **(required)** The output file to write |
| `--arch <ARCH>` | | The architecture to build the output for, such as `amd64` or `arm64`. It takes precedence over the `arch` field in `minimal.toml` and the host default |

### `net expose <PORT>` {#net-expose}

Box helper only. Publishes `<PORT>` at the box's published address, so that
the host can reach it. Minimal decides the request against the stance that
`network.dynamic_ingress` sets in the box's entry, or that
`--dynamic-ingress` sets when the box starts, as
[`min session start`](./cli-min.md#session-start) describes.

- `allow` publishes a port inside `--dynamic-range` and refuses any other.
- `ask` puts the request to the terminal attached to the box. With no
  terminal attached, Minimal refuses the request at once.
- `deny`, or no stance, refuses the request.

Under `allow`, Minimal also publishes a port inside `--dynamic-range` when a
process in the box listens on it. A `min net expose` of that port succeeds.
It names the address that the port answers at and publishes nothing more.
That publication ends when the process stops listening on the port.

The stances apply only to a `--network own_ip` box. On a `host_ip` box (the
default), you do not need to expose the port. The box shares the host's
network and already answers at `<box>.min.internal:<PORT>`. Minimal refuses
the request from a `--network none` box. A refusal, or an `ask` that nobody
answers, names the next step. That step can be to start the box again with
the flags, or to run [`min net forward`](./cli-min.md#net-forward) on the
host.

`min net expose --public <PORT>` asks to publish the port outside the host.
Minimal refuses it on every host, with
`public exposure is not available on this host. Nothing was published.`
