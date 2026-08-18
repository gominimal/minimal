---
description: How Minimal isolates all builds and tasks from the host system using hermetic sandboxes.
---

# Sandboxing

Sandboxing is essential to make sure all builds and tasks are insulated from the machine they run in. **In Minimal, all tasks and builds run in a sandbox**.


## Package builds

Minimal packages encapsulate all tooling and software, so it's essential they are compiled in a hermetically-sealed environment that gives the rest of the ecosystem a strong
foundation. As such, package builds take place in a cleanroom sandbox that shares nothing with the host machine, aside from network access when a dependency calls for it.

Specifically, the cleanroom sandbox wires:

 - Files representing the build inputs and runtime dependencies of the package
 - Working directories `/build`, `/tmp`, and an empty `/state`.
 - The source of the package being built
 - Network connectivity (when called-for by a dependency)

At the completion of the build, artifacts are gathered based on the outputs specified in the packages' build-spec, and
are cached for later consumption when needed by a task or another package build.

By default, Minimal is configured to fetch completed builds from our binary cache, to avoid a slow process building everything locally the first time it is needed.
You can force builds to run locally with the build CLI's `--no-fetch` and `--no-cache` flags.


## The task sandbox

When a task is invoked, its configuration is used to setup and launch a task sandbox. This sandbox wires:

 - Files representing the packages requested and their runtime dependencies. The packages requested for a task includes
   any that are explicitly defined on the task, and those defined by the repository stack (if set).
 - The repository's files and directories, from the repository root downward, but not above it.
 - A `/state` directory, which can be shared between tasks and task invocations by specifying a task `state_key`. Package managers
   are typically wired to cache source downloads and intermediate build artifacts in this directory.
 - Pinhole filesystem mappings, as declared by packages.
 - Network connectivity when necessary.

## The session sandbox

A [session](./sessions.md) is hosted in a sandbox of its own: the one you drop
into when you attach a shell. Its contents are the union of the project's
`[session]` packages, the packages the repository's `[stack]` declares, and
whatever your applied [loadouts](./loadouts.md) contribute. The session
sandbox's working directory is the session's workspace, seeded with a copy of
your project files at activation.
