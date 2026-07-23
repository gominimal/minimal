---
description: Stacks wire Minimal to build codebases with specific languages and tools. Covers available stacks, usage, and how to define custom ones.
---

# Stacks

Stacks wire Minimal to operate a codebase with specific tools and commands. When you name a stack
in your [`minimal.toml`](../reference/minimal-dot-toml.md) file, build-plane commands like `mip build` just work. Additionally, your [tasks](../reference/tasks.md) inherit these familiar tools and semantics automatically.

Learn more about stacks in [the reference section](../reference/stack-specs.md).

## Available stacks

The [Minimal Public Package Registry](https://github.com/gominimal/pkgs) ships stacks for most common languages and build systems:

| Stack | Detected by | Build command |
|---------|-------------|---------------|
| `go` | `go.mod` + `go.sum` | `go build` |
| `rust` | `Cargo.toml` | `cargo build --release` |
| `pnpm` | `pnpm-lock.yaml` | `pnpm install && pnpm build` |
| `npm` | `package-lock.json` | `npm ci && npm run build` |
| `bun` | `bun.lock` | `bun install && bun run build` |
| `deno` | `deno.json` | `deno compile` |
| `uv` | `uv.lock`, `pyproject.toml` | `uv sync && uv build` |
| `pip` | `requirements.txt`, `setup.py` | `pip3 install --target ./build .` |
| `gradle` | `build.gradle` | `gradle build -x test` |
| `make` | `Makefile` | `./configure && make` |
| `meson` | `meson.build` | `meson setup && ninja` |
| `cmake` | `CMakeLists.txt` | `cmake && make` |
| `zig` | `build.zig` | `zig build -Doptimize=ReleaseSafe` |

## Using a stack

Stacks are declared in the [`[stack]` section](../reference/minimal-dot-toml.md#stack) of your `minimal.toml` file.

```toml
[stack]
use = "<stack name>"
```

Any stack defined in your codebase (or defined in any layer in your [software supply chain](./software-supply-chain.md)) can be used.

When a stack is defined, any [task](../reference/tasks.md) will inherit the packages, default tasks, and other wiring
declared in the stack.

### Declaring additional dependencies

It's quite common for a specific codebase to need additional dependencies, either during the build (build packages) or
on any system the built software runs (runtime packages). Both can be declared in your `minimal.toml`:

```toml
[stack]
use = "..."
build_packages = ["perl"]
runtime_packages = ["openssl"]
```

Dependencies can also be added automatically using the [`mip add`](../reference/cli-mip.md) command.

### Automatic initialization

Minimal will auto-detect the stack to use for most languages and package managers. To have the Minimal CLI detect an appropriate stack
and pre-fill your codebase's [`minimal.toml`](../reference/minimal-dot-toml.md) file, run `mip init` in the root directory.
