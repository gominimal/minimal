---
description: How Minimal isolates all builds and tasks from the host system using hermetic sandboxes.
---

# Sandboxing

Sandboxing is essential to ensure all builds and tasks are insulated from the machine they run in. **In Minimal, all tasks and builds run in a sandbox**.


## Package builds

Minimal packages encapsulate all tooling and software, so it's essential they are compiled in a hermetically-sealed environment to provide a strong
foundation to the rest of the ecosystem. As such, package builds take place in a cleanroom sandbox that shares nothing with the host machine.

Specifically, the cleanroom sandbox wires:

 - Files representing the build inputs and runtime dependencies of the package
 - Working directories `/build`, `/tmp`, and an empty `/state`.
 - The source of the package being built
 - Network connectivity (when called-for by a dependency)

At the completion of the build, artifacts are gathered based on the outputs specified in the packages' build-spec, and
are cached for later consumption when needed by a task or another package build.

By default, Minimal is configured to fetch completed builds from our binary cache, to avoid a slow process building everything locally the first time it is needed.
You can force the CLI to build artifacts locally using a combination of the `--no-fetch` and `--no-cache` flags.


## The task sandbox

When a task is invoked, its configuration is used to setup and launch a task sandbox. This sandbox wires:

 - Files representing the packages requested and their runtime dependencies. The packages requested for a task includes
   any that are explicitly defined on the task, and those defined by the repository stack (if set).
 - The repository's files and directories, from the repository root downward, but not above it.
 - A `/state` directory, which can be shared between tasks & task invocations by specifying a task `state_key`. Packages managers
   are typically wired to cache source downloads and intermediate build artifacts in this directory.
 - Pinhole filesystem mappings, as declared by packages. For instance, the `claude-code` package wires the `~/.claude` directory into task sandboxes so claude-code
   can maintain state and access its API key.
 - Network connectivity when necessary.
