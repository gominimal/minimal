---
description: Run builds and tests in sandboxed environments using stacks. Covers extra dependencies, test commands, and build state persistence.
---

# Building

Minimal builds your code reproducibly inside a sandbox, using a [stack](../concepts/stacks.md) to wire up the right tools and build commands for your language or build system.

A build is a **one-shot** command that runs in its own fresh sandbox and exits, driven by the `mip` CLI (Linux-only; on macOS, work inside a [dev session](./dev-shell.md) instead). That is different from an interactive dev session, which is a long-lived environment you attach to with `min` for interactive development.

## Running a build

```shell
$ mip run build
```

The stack configured in your `minimal.toml` determines what happens. For example, a Rust stack runs `cargo build --release`, while a pnpm stack runs roughly `pnpm install && pnpm build`.

## How stacks work

When you declare a stack, it provides:

- **Build packages**: compilers, build tools, and other dependencies needed during compilation
- **Runtime packages**: libraries needed wherever the built software runs
- **Build commands**: the default commands executed by `mip run build`
- **Environment variables**: compiler flags, paths, and other configuration

```toml
[stack]
use = "go"
```

With just this configuration, `mip run build` will run `go build` with the Go compiler and all necessary toolchain packages available in the sandbox.

## Adding extra dependencies

Most projects need additional dependencies beyond what the stack provides. Declare them in the `[stack]` section:

```toml
[stack]
use = "rust"
build_packages = ["protobuf", "perl"]
runtime_packages = ["openssl"]
```

Or add them with the CLI:

```shell
$ min add --build protobuf
$ min add --runtime openssl
```

## Running tests

Similarly to `mip run build`, you can run your test suite with:

```shell
$ mip run test
```

This runs the `test` task from your `minimal.toml`; define one with `[tasks.test]`. Stacks only ship a default `build` task.

## Persisting build state

By default, each task invocation starts from a clean state. To cache build artifacts across runs (like `node_modules` or `target/`), set a `state_key`:

```toml
[defaults]
state_key = "dev"
```

Tasks sharing the same `state_key` share cached state, so your builds do not start from scratch every time.
