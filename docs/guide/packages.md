---
description: Add build, runtime, session, and task-specific package dependencies using the min and mip CLIs or minimal.toml.
---

# Packages

Minimal makes it easy to add tools and dependencies to your project. Where a package lives depends on when you need it: building your code, running it, developing interactively, or inside a specific task.

## Build and runtime dependencies

Build and runtime dependencies belong to your build plane and are managed with `min add`:

```shell
# Add as a build dependency (needed to compile your code)
$ min add --build protobuf

# Add as a runtime dependency (needed wherever your code runs)
$ min add --runtime openssl
```

Each command updates your `minimal.toml` automatically.

**Build dependencies** are packages needed during compilation but not at runtime. They are declared in the `[stack]` section:

```toml
[stack]
use = "rust"
build_packages = ["protobuf", "perl"]
```

**Runtime dependencies** are packages that must be present wherever the built software runs:

```toml
[stack]
use = "rust"
runtime_packages = ["openssl"]
```

## Session tools

Tools you want available while developing interactively go in the project's `[session]` block, not the build plane. Every contributor's [dev session](./dev-shell.md) picks them up:

```toml
[session]
packages = ["git", "ripgrep", "jq"]
```

To add a tool to a running session without editing config, run `min add <package>` from inside the session shell.

## Task-specific packages

Packages can also be scoped to individual [tasks](../reference/tasks.md), where they are only available when that task runs. Add them with `min add --task <name>`:

```shell
$ min add --task lint ruff
```

```toml
[tasks.lint]
packages = ["python", "ruff"]
exec = "ruff check ."
```

## Available packages

The [Minimal Public Package Registry](https://github.com/gominimal/pkgs/tree/main/packages) contains hundreds of packages including compilers, interpreters, build tools, and common CLI utilities.
