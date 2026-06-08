---
description: Schema reference for the minimal.toml configuration file — upstream, harness, defaults, tasks, and outputs sections.
---

# `minimal.toml`

The `minimal.toml` file defines the configuration for Minimal in a codebase.

This file must be present at the base of the repository (i.e. `./minimal.toml`), or
in a `.minimal` directory at the base of the repository.

Unless [`-C`](/reference/cli#global-flags) is specified, the [Minimal CLI](/reference/cli) searches the directory tree backwards from
the current directory till a `minimal.toml` file is found. This behavior allows minimal to be invoked in project directories.

## Example

```toml
[upstream]
repo = "https://github.com/gominimal/pkgs"
branch = "main"
locked_commit = "d39aaaa581f983d6b3ba5eaaf383485a602f37f0"

[harness]
use = "pnpm"
build_packages = ["railway"]

[defaults]
state_key = "dev"

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

The `[upstream]` section defines the precise source of packages, harnesses, and profiles. This represents the
preceding link in the [software supply chain](/concepts/software-supply-chain).

```toml
[upstream]
repo = "<git URL>"
branch = "<branch>"
locked_commit = "<commit hash>"
```

`locked_commit` is automatically updated when `minimal update` is run.

#### `[[upstream.sideload]]` - Additional software sideloaded into your supply chain {#sideload}

Sideload entries let you load in additional packages, harnesses, and profiles from a separate repository, but those packages
are built using the version of packages from your upstream.

Each sideload entry is loaded in order from the specified repository, and follows the same schema as `[upstream]`:

```toml
[[upstream.sideload]]
repo = "<git URL>"
branch = "<branch>"
locked_commit = "<commit hash>" # Updated via `minimal update`
```

Sideload repositories have the same layout as an upstream: that is having a `minimal.toml` file, and `packages/` / `harnesses/` / `profiles/`
directories as needed.

### `[harness]` - How to build code in your repo {#harness}

```toml
[harness]
use = "<harness name>"
build_packages = ["<additional build package>"]     # optional
runtime_packages = ["<additional runtime package>"] # optional
```

The `[harness]` section configures the [harness](/concepts/harnesses) to use for building code, if any.

The environment variables and packages configured on a harness are inherited on all tasks in this repository.

`build_packages` and `runtime_packages` are optional fields that allow you to declare
additional package dependencies for build time or run time respectively.



### `[defaults]` - Settings for all tasks {#defaults}

```toml
[defaults]
profile = "<profile name>" # optional
state_key = "<state key>"  # optional
```

When set, `defaults.profile` will set a [profile](/concepts/profiles) on all tasks which do not set a profile.

When set, `defaults.state_key` will set a state key on all tasks which do not set `state_key`.



### `[tasks.*]` - Run tasks, scripts, & dev tooling {#tasks}

See: [tasks](/reference/tasks).



### `[outputs.*]` - Artifacts produced by `minimal materialize` {#outputs}

Each `[outputs.<name>]` section defines an artifact that can be produced with
[`minimal materialize <name> -o <path>`](/reference/cli#materialize).

```toml
[outputs.<name>]
type = "<output type>"          # required; alias: `ty`
packages = ["<package>", ...]   # optional; defaults to ["base"] when empty
arch = "<arch>"                 # optional; e.g. "amd64", "arm64"
entrypoint = "<cmd>"            # optional; string or list of strings
cmd = ["<arg>", ...]            # optional; string or list of strings
vars = { KEY = "value" }        # optional; alias: `env_vars`
```

#### Output types

| `type` | Description |
|--------|-------------|
| `oci-image` | A Linux OCI image archive built from `packages`. Compatible with `docker load` and OCI-compatible registries. |

#### Fields

- **`type`** (alias: `ty`) — The output kind. Currently only `oci-image` is supported.
- **`packages`** — Packages to include in the materialized output. When omitted or empty, defaults to `["base"]`.
- **`arch`** — Target architecture for OCI images. Common values: `amd64`, `arm64`. The CLI flag [`--arch`](/reference/cli#materialize) overrides this; if neither is set, the host architecture is used.
- **`entrypoint`** — OCI image entrypoint. May be a string (`"/app/server"`) or a list (`["/bin/sh", "-c"]`).
- **`cmd`** — OCI image default command. Same string-or-list shape as `entrypoint`.
- **`vars`** (alias: `env_vars`) — Environment variables baked into the image as a `KEY = "value"` table.

#### Examples

A minimal OCI image of just the `base` packages, useful for ad-hoc shells:

```toml
[outputs.base-image]
type = "oci-image"
```

```sh
minimal materialize base-image -o ./base.tar
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
minimal materialize app -o ./app.tar
```

Override the architecture at the command line:

```sh
minimal materialize app --arch amd64 -o ./app-amd64.tar
```
