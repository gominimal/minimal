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

[defaults]
state_key = "dev"

[session]
packages = ["base", "git", "nano"]

[tasks.dev]
exec = "pnpm run dev"

[tasks.preview]
env_vars.PORT = "8080"
bash = "pnpm run build && pnpm run start"

[tasks.deploy]
packages = ["railway"]
exec = "railway up"

[tasks.shell]
interactive = true
packages = ["base", "git", "nano"]
exec = "bash -l"
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

`use` is an accepted alias for the canonical `name` key; both parse. `[harness]`
is accepted as a deprecated alias for `[stack]`, pending removal after
July 2026; prefer `[stack]` in new configs.

The environment variables and packages configured on a stack are inherited on all tasks in this repository.

`build_packages` and `runtime_packages` are optional fields that allow you to declare
additional package dependencies for build time or run time respectively.



### `[defaults]` - Settings for all tasks {#defaults}

```toml
[defaults]
state_key = "<state key>"  # optional
```

When set, `defaults.state_key` will set a state key on all tasks which do not set `state_key`.



### `[session]` - What every contributor's session gets {#session}

Contributes to [sessions](../concepts/sessions.md) activated
on this project (`min session activate`). It carries the same primitives as a
[loadout](./loadouts.md) (packages, vars, patches, lifecycle hooks), scoped to
the project rather than the developer: where a loadout says "what this
developer wants everywhere", the session block says "what every session
working on this codebase needs". There is at most one per `minimal.toml`, and
it has no name or description.

```toml
[session]
# Toolchain every contributor's session gets.
packages = ["rustc", "cargo", "postgresql-client"]

# Config that lives in the repo, patched into the session's home.
patches = [
    { dest = ".cargo/config.toml", source = "config/cargo.toml" },
    { dest = ".psqlrc",            source = "config/psqlrc" },
]

[session.vars]
# Applies uniformly to every developer's session.
RUST_LOG         = "info"
CARGO_TERM_COLOR = "always"
# Inherit from the developer's environment if set, else the default.
DATABASE_URL     = { inherit = true, default = "postgres://localhost/dev" }

# Declared to warm the compile cache when a session comes up.
[[session.lifecycle_hooks]]
on_activate = { type = "inline", value = "cargo check --workspace >/dev/null 2>&1 || true" }
```

- **`packages`**: Packages brought into every session on this project,
  alongside whatever the developer's loadouts contribute.
- **`vars`**: Environment variables. A string sets a fixed value;
  `{ inherit = true }` passes the developer's own value through (add
  `default = "..."` for a fallback when it is unset).
- **`patches`**: `{ source, dest }` rows copying files into the session.
  `dest` is relative to the session user's home directory; `source` resolves
  on the host, typically inside the repo.
- **`lifecycle_hooks`**: Scripts declared for session transition points
  (`on_activate`, `on_destroy`, `on_attach`, `on_detach`), run inside the
  session under POSIX `sh` — or under whatever a leading shebang names, for
  a hook you would rather write in fish or Python. A project's hooks require
  the developer to allow-list the project in their
  [user policy](./user-policy.md) before they will run — a hook is arbitrary
  code, so the developer must opt in.

The field shapes and composition semantics (conflicts, policy gating) are the
same as loadouts; see the [loadout reference](./loadouts.md) for the exact
rules.



### `[tasks.*]` - Run tasks, scripts, & dev tooling {#tasks}

See: [tasks](./tasks.md).



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

### `[params]` - Repo-wide parameters {#params}

Declares named parameters available to tasks across the repository, using the
same `{type, help, default}` shape as per-task [`args`](./tasks.md). Every
`[params]` entry must declare a `default`.

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
