---
description: Initialize a project with mip init (auto-detects language) and pin dependencies with mip update.
---

# Initialize a project

## Run `mip init`

Minimal can auto-detect most languages and produce an initial `minimal.toml` to get you started. Supported languages and build systems include Go, Rust, pnpm, npm, Bun, Deno, Python (uv/pip), Gradle, Make, Meson, CMake, and Zig.

Drop into your project directory in a shell, and run:

```shell
$ mip init
```

### Alternative: Manual setup

Create the below `minimal.toml` file in the root of your repository, picking the variant that matches your toolchain.

For a **pnpm** project:

```toml
[upstream] # The software supply chain
repo = "https://github.com/gominimal/pkgs"
branch = "main"

[stack] # Wires Minimal to build a pnpm project
use = "pnpm"

[tasks.shell]
packages = ["base"]
exec = "bash -l"
```

For a **Go** project:

```toml
[upstream] # The software supply chain
repo = "https://github.com/gominimal/pkgs"
branch = "main"

[stack] # Wires Minimal to build a go binary
use = "go"

[tasks.shell]
packages = ["base"]
exec = "bash -l"
```

For a **Rust** project:

```toml
[upstream] # The software supply chain
repo = "https://github.com/gominimal/pkgs"
branch = "main"

[stack] # Wires Minimal to build a rust workspace
use = "rust"

[tasks.shell]
packages = ["base"]
exec = "bash -l"
```

## Run `mip update`

Run `mip update` to fetch the necessary tools and packages from the minimal public registry.

```shell
$ mip update
Upstream https://github.com/gominimal/pkgs:main updated from <unpinned> to 9d36aa3d0fec09658fe3bbc676beeae49a89c53d
$
```
