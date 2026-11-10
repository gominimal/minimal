---
title: minimal.toml
description: "Schema reference for the minimal.toml configuration file: upstream, stack, defaults, tasks, and outputs sections."
---

# `minimal.toml`

The `minimal.toml` file defines the configuration for Minimal in a codebase.

This file must be present at the base of the repository (i.e. `./minimal.toml`), or
in a `.minimal` directory at the base of the repository.

Unless [`-C`](./cli-mip.md#global-flags) is specified, the [mip CLI](./cli-mip.md) searches the directory tree backwards from
the current directory till a `minimal.toml` file is found. This behavior allows minimal to be invoked in project directories.

## Example

```toml
[upstream]
repo = "https://github.com/gominimal/pkgs"
branch = "main"
locked_commit = "d39aaaa581f983d6b3ba5eaaf383485a602f37f0"

[stack]
use = "pnpm"
build_packages = ["railway"]

[defaults.task]
state_key = "dev"

[defaults.session]
packages = ["base", "git", "nano"]

[tasks.dev]
exec = "pnpm run dev"

[tasks.preview]
env_vars.PORT = "8080"
bash = "pnpm run build && pnpm run start"

[tasks.deploy]
packages = ["railway"]
exec = "railway up"
```

## Schema

### `[upstream]` - Where software comes from {#upstream}

The `[upstream]` section defines the precise source of packages & stacks. This represents the
preceding link in the [software supply chain](../concepts/software-supply-chain.md).

```toml
[upstream]
repo = "<git URL>"
branch = "<branch>"
locked_commit = "<commit hash>"
```

`locked_commit` is automatically updated when [`mip update`](./cli-mip.md) is
run: it re-resolves `branch` to its current HEAD and rewrites the
`locked_commit` of the upstream (and of every sideload) in `minimal.toml` in
place; expect a diff on these fields after running it.

#### `[[upstream.sideload]]` - Additional software sideloaded into your supply chain {#sideload}

Sideload entries let you load in additional packages or stacks from a separate repository, but those packages
are built using the version of packages from your upstream.

Each sideload entry is loaded in order from the specified repository, and follows the same schema as `[upstream]` (the canonical table name is `sideloads`; `sideload` is an accepted alias):

```toml
[[upstream.sideload]]
repo = "<git URL>"
branch = "<branch>"
locked_commit = "<commit hash>" # Updated via `mip update`
```

Sideload repositories have the same layout as an upstream: that is having a `minimal.toml` file, and `packages/` / `stacks/`
directories as needed.

### `[stack]` - How to build code in your repo {#stack}

```toml
[stack]
use = "<stack name>"
build_packages = ["<additional build package>"]     # optional
runtime_packages = ["<additional runtime package>"] # optional
```

The `[stack]` section configures the [stack](../concepts/stacks.md) to use for building code, if any.
See [stack specs](./stack-specs.md) for how stacks themselves are defined.

`use` is an accepted alias for the canonical `name` key, and both parse.
`[harness]`, the name of this section before v0.5.0, is no longer accepted:
a file that still uses it fails to load, naming the rename, so rename the
section to `[stack]`.

The environment variables and packages configured on a stack are inherited on all tasks in this repository.

`build_packages` and `runtime_packages` are optional fields that allow you to declare
additional package dependencies for build time or run time respectively.



### `[defaults]` - Settings for every entry {#defaults}

`[defaults]` holds settings that apply to every [entry](#entries). A table
under it that has the name of a type, such as `[defaults.session]` or
`[defaults.task]`, applies only to the entries of that type. When the same
key is set in more than one place, the lists combine, and the more specific
place sets every other value: the entry over `[defaults.<type>]`, and
`[defaults.<type>]` over `[defaults]`.

```toml
[defaults.task]
state_key = "<state key>"  # optional
```

When set, `defaults.task.state_key` sets a state key on all tasks that do not
set `state_key`.

`[defaults.session]` is described [below](#session).



### `[defaults.session]` - What every contributor's session gets {#session}

Contributes to [sessions](../concepts/sessions.md) activated
on this project (`min session activate`). It carries the same primitives as a
[loadout](./loadouts.md) (packages, vars, patches, lifecycle hooks), scoped to
the project rather than the developer: where a loadout says "what this
developer wants everywhere", the session block says "what every session
working on this codebase needs". There is at most one per `minimal.toml`, and
it has no name or description.

```toml
[defaults.session]
# Toolchain every contributor's session gets.
packages = ["rustc", "cargo", "postgresql-client"]

# Config that lives in the repo, patched into the session's home.
patches = [
    { dest = ".cargo/config.toml", source = "config/cargo.toml" },
    { dest = ".psqlrc",            source = "config/psqlrc" },
]

[defaults.session.vars]
# Applies uniformly to every developer's session.
RUST_LOG         = "info"
CARGO_TERM_COLOR = "always"
# Inherit from the developer's environment if set, else the default.
DATABASE_URL     = { inherit = true, default = "postgres://localhost/dev" }
# Inherit with no fallback: a developer who has not set this cannot
# activate a session on this project.
GITHUB_TOKEN     = { inherit = true }

# Declared to warm the compile cache when a session comes up.
[[defaults.session.lifecycle_hooks]]
on_activate = { type = "inline", value = "cargo check --workspace >/dev/null 2>&1 || true" }
```

- **`packages`**: Packages brought into every session on this project,
  alongside whatever the developer's loadouts contribute.
- **`vars`**: Environment variables. A string sets a fixed value;
  `{ inherit = true }` passes the developer's own value through. Here that
  inheritance is **required**: if the developer's environment does not have
  the variable set, activation fails rather than proceeding without it.

  ```console
  $ min session activate
  error: Composition gating failed: could not resolve pending var
  `GITHUB_TOKEN`: environment variable not found
  ```

  Adding `default = "..."` supplies a fallback and makes the variable
  optional again. A loadout spells the bare form the same way but treats it
  as optional — see
  [Where `{ inherit = true }` differs](#inherit-divergence).

  One name is read specially: setting `SHELL` to a supported, installed
  shell makes the session's attach shell that shell instead of bash. See
  [`SHELL` — Which shell an attach starts](./loadouts.md#session-shell) for
  the supported shells and the fallback behavior.
- **`patches`**: `{ source, dest }` rows copying files into the session.
  `dest` is relative to the session user's home directory; `source` resolves
  on the host, typically inside the repo. The one expansion a loadout has
  and a project does not is `$LOADOUT_ROOT`, which names a loadout's own
  directory; referencing it here fails the activation.
- **`lifecycle_hooks`**: Scripts declared for session transition points
  (`on_activate`, `on_destroy`, `on_attach`, `on_detach`), run inside the
  session under POSIX `sh` — or under whatever a leading shebang names, for
  a hook you would rather write in fish or Python. A project's hooks require
  the developer to allow-list the project in their
  [user policy](./user-policy.md) before they will run — a hook is arbitrary
  code, so the developer must opt in.
- **`hooks_on_resume`**: Set `hooks_on_resume = true` to run the
  `on_activate` hooks again each time a stopped or exited session resumes.
  They run before the `on_attach` hooks of the attach that resumes it. If an
  `on_activate` hook fails, the session does not resume and stays stopped or
  exited. The error names the hook's source and its exit status. Without the
  key, a resume runs only the `on_attach` hooks.

The field shapes and composition semantics (conflicts, policy gating) are the
same as loadouts; see the [loadout reference](./loadouts.md) for the exact
rules. Variable *resolution* is the exception: a bare `{ inherit = true }`
that the host has not set fails activation here, where a loadout drops it
with a warning, so the loadout page's rule for that one case does not carry
over.

#### Where `{ inherit = true }` differs {#inherit-divergence}

Three surfaces accept `{ inherit = true }`, spelled identically on each.
They agree that a variable the host *has* set is passed through, and they
disagree about everything else:

| Surface | Host variable unset | `default = "..."` |
|---|---|---|
| This file's `[defaults.session.vars]` (and `[[defaults.session.vars_lenient]]`) | Activation fails: `could not resolve pending var <NAME>` | Supported; the default is used |
| A loadout's [`[vars]`](./loadouts.md#vars) and [`[[vars_lenient]]`](./loadouts.md#vars_lenient) | Dropped, with a warning on the terminal; activation continues | Supported; the default is used |
| A task's [`env_vars`](./tasks.md#env_vars) | The run fails before the session is built | Rejected when the file is parsed — a task's `inherit` takes no `default` |

Two things narrow the task row. An `echo` task never builds an environment,
so it never reads — or fails over — an `env_vars` declaration. And
`min run <task>` from inside a session resolves `inherit` against the
daemon's environment rather than your shell; `min session run` resolves it
against your shell, as `min task run` does. Both are covered in
[Tasks](./tasks.md#env_vars).



### `[tasks.*]` - Run tasks, scripts, & dev tooling {#tasks}

See: [tasks](./tasks.md).

A task cannot set `interactive = true`. A file with such a task fails to load
with exit code 3, and the error names the `[sessions.<name>]` entry to
declare instead. Interactive work belongs in a session.

A task entry takes `hooks_on_resume = true` too, with the same meaning as
[the `[defaults.session]` key](#session). Only a box with a terminal
resumes, so the key changes nothing for a task that runs without one.

### Entry tables {#entries}

An entry is a named table that a box is created from. `[boxes.<name>]` is
the general form, and its `type` key names the entry's type. Each of these
tables is a shorter way to write `[boxes.<name>]` with its `type` set:

| Table | Same as |
|---|---|
| `[sessions.<name>]` | `[boxes.<name>]` with `type = "session"` |
| `[tasks.<name>]` | `[boxes.<name>]` with `type = "task"` |
| `[agents.<name>]` | `[boxes.<name>]` with `type = "agent"` |
| `[services.<name>]` | `[boxes.<name>]` with `type = "service"` |

An entry name is 1 to 63 lowercase letters, digits, or hyphens, and does not
start or end with a hyphen. Each name is used once in the file, whichever
table declares it, and `self` cannot name an entry. A file that breaks one
of these rules fails to load with exit code 3.

An entry writes its settings as flat keys, such as `timeout`, `pty_enabled`,
`on_oom`, and the `[machine]` table. `packages`, `patches`, `vars`, and
`lifecycle_hooks` mean the same in an entry as in
[`[defaults.session]`](#session).

#### `timeout` - How long a box runs {#timeout}

`timeout` sets how long a box can run. Set it in `[defaults.session]`, in
the legacy `[session]` table, or in a task's `[tasks.<name>]` table:

```toml
[defaults.session]
timeout = "8h"

[tasks.lint]
exec = ["cargo", "clippy"]
timeout = 90
```

The value is one of these forms:

- A whole number of seconds, such as `90`.
- A string of a whole number followed by `s`, `m` or `h`, such as `"30s"`,
  `"5m"` or `"1h"`.

A timeout of zero, in any unit, means no timeout. Any other value fails the
load with exit code 3, and the error names the key and the entry.

The clock starts each time the box's first process starts, so a resumed
box gets its full timeout again. When a session or a task box runs past its
timeout, every process in the box gets SIGTERM, including processes that
`min box exec` started. Processes that still run after a grace period of 10
seconds get SIGKILL. The box then ends as `exited` with the reason
`timeout`, and keeps its files and its record until you remove it. A box
that you stop before its timeout ends as `stopped`.

A `min task run` whose task runs past its timeout exits with code 124. It
prints a line on stderr that says the task ran past its timeout. A task
that exits with code 124 by itself gets no such line.



### `[outputs.*]` - Artifacts produced by `mip materialize` {#outputs}

Each `[outputs.<name>]` section defines an artifact that can be produced with
[`mip materialize <name> -o <path>`](./cli-mip.md#materialize).

```toml
[outputs.<name>]
type = "<output type>"          # optional; defaults to "oci-image"
packages = ["<package>", ...]   # optional; defaults to ["base"] when empty
arch = "<arch>"                 # optional; e.g. "amd64", "arm64"
path = "<path>"                 # raw-file only; required there, invalid for oci-image
entrypoint = "<cmd>"            # oci-image only; string or list of strings
cmd = ["<arg>", ...]            # oci-image only; string or list of strings
vars = { KEY = "value" }        # oci-image only; alias: `env_vars`
```

#### Output types

| `type` | Description |
|--------|-------------|
| `oci-image` | A Linux OCI image archive built from `packages`. Compatible with `docker load` and OCI-compatible registries. |
| `raw-file` | A single file extracted from `packages` at the given `path`. Useful for pulling one artifact (a kernel image, a rootfs image, …) out of a package's file tree. |

#### Fields

- **`type`**: The output kind, either `oci-image` or `raw-file`. Defaults to `oci-image` when omitted.
- **`packages`**: Packages to include in the materialized output. When omitted or empty, defaults to `["base"]`.
- **`arch`**: Target architecture for OCI images. Common values: `amd64`, `arm64`. The CLI flag [`--arch`](./cli-mip.md#materialize) overrides this; if neither is set, the host architecture is used.
- **`path`**: _(`raw-file` only)_ Path, relative to the package file tree, of the single file to extract. Required for `raw-file` outputs; supplying it on an `oci-image` output is an error.
- **`entrypoint`**: _(`oci-image` only)_ OCI image entrypoint. May be a string (`"/app/server"`) or a list (`["/bin/sh", "-c"]`).
- **`cmd`**: _(`oci-image` only)_ OCI image default command. Same string-or-list shape as `entrypoint`.
- **`vars`** (alias: `env_vars`): _(`oci-image` only)_ Environment variables baked into the image as a `KEY = "value"` table.

Setting an `oci-image`-only field (`entrypoint`, `cmd`, `vars`) on a `raw-file` output, or setting `path` on an `oci-image` output, is rejected when the `minimal.toml` is parsed.

#### Examples

A minimal OCI image of just the `base` packages, useful for ad-hoc shells:

```toml
[outputs.base-image]
type = "oci-image"
```

```sh
mip materialize base-image -o ./base.tar
```

A server image with extra packages, an entrypoint, and an env var:

```toml
[outputs.app]
type = "oci-image"
arch = "arm64"
packages = ["base", "openssl"]
entrypoint = "/app/server"
vars = { PORT = "8080" }
```

```sh
mip materialize app -o ./app.tar
```

Override the architecture at the command line:

```sh
mip materialize app --arch amd64 -o ./app-amd64.tar
```

A `raw-file` output extracts a single file from a package. Here the kernel
`Image` is pulled out of the `virtio-kernel-raw` package:

```toml
[outputs.virtio-kernel]
type = "raw-file"
packages = ["virtio-kernel-raw"]
path = "usr/share/virtio-linux/Image"
```

```sh
mip materialize virtio-kernel -o ./Image
```

### `[args]` - Repo-wide parameters {#args}

Declares named parameters available to tasks across the repository, using the
same `{type, help, default}` shape as per-task [`args`](./tasks.md). Every
parameter in `[args]` must declare a `default`.

Each parameter acts as a defaulted arg on every task: a command reads it as
`%{name}`, and `--name <value>` overrides it for one run. A task that
declares an arg of the same name uses its own arg instead.

```toml
[args]
greeting = { type = "string", default = "hi" }

[tasks.hello]
bash = "echo %{greeting}"  # `hi`, or `bye` with `--greeting bye`
```

### `[cache]` - Artifact cache behavior {#cache}

```toml
[cache]
index_source = "auto"  # optional: "auto" (default), "pinned", or "root"
fetch_retries = 2      # optional: retry count for remote fetches
```

### `[stdlib]` - Standard library requirements {#stdlib}

```toml
[stdlib]
minimum_version = "<version>"  # optional; alias: min_version
```

Refuses to operate when the upstream's standard library is older than the
declared minimum.

### Legacy tables {#legacy}

Release 0.8 still reads three older spellings, each as its new place. Each
time Minimal reads one, it prints a hint that names the change to make.
Release 0.9.0 and later refuse each of them with exit code 3 and the same
hint.

| Older spelling | Write instead |
|---|---|
| `[session]` | [`[defaults.session]`](#session) |
| `state_key` and `profile` under `[defaults]` | the same keys under [`[defaults.task]`](#defaults) |
| `[params]` | [`[args]`](#args) |

`profile` is deprecated. A task's own `args` key is not a legacy spelling,
and it keeps its meaning.
