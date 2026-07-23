---
description: Add build, runtime, and task-specific package dependencies using mip add or minimal.toml.
---

# Packages

Minimal makes it easy to add tools and dependencies to your project using the `mip add` command.

## Adding a package

Every package needs a destination, which controls where it should be available. There are three options:

```shell
# Add to a specific task
$ mip add --task shell ripgrep jq

# Add as a build dependency (needed to compile your code)
$ mip add --build protobuf-compiler

# Add as a runtime dependency (needed wherever your code runs)
$ mip add --runtime openssl
```

Each command updates your `minimal.toml` automatically.

## Build vs runtime dependencies

**Build dependencies** are packages needed during compilation but not at runtime. These are declared in the `[stack]` section:

```toml
[stack]
use = "rust"
build_packages = ["protobuf-compiler", "perl"]
```

**Runtime dependencies** are packages that must be present wherever the built software runs:

```toml
[stack]
use = "rust"
runtime_packages = ["openssl"]
```

## Task-specific packages

Packages can also be added to individual [tasks](../reference/tasks.md). These are only available when that task runs:

```toml
[tasks.shell]
packages = ["base", "git", "curl"]
exec = "bash -l"

[tasks.lint]
packages = ["python", "ruff"]
exec = "ruff check ."
```

## Available packages

The [Minimal Public Package Registry](https://github.com/gominimal/pkgs/tree/main/packages) contains 150+ packages including compilers, interpreters, build tools, and common CLI utilities.
