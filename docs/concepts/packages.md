---
description: Packages are reproducible, dependency-aware units of software in Minimal. Covers usage, definition, caching, and hermetic builds.
---

# Minimal packages

Packages are the core of software production in Minimal. Packages are reproducible, maintainable, and dependency-aware building blocks designed for environment parity across the software development lifecycle (SDLC).

Structurally, a package is the union of its declarative build specification and the resulting binary artifacts. A metaphor for Minimal's packages would be a recipe (the build specification) and the meal that's cooked from it (the resulting artifacts). This relationship is cemented by a [layer of metadata](#definition) that defines the package's dependencies, architecture, and provenance. In our metaphor, these would be the optional modifications made to tailor the dish so it's more to your liking. By binding the "recipe" to the "result," Minimal makes sure that you have complete control over every dish you make, verifying that every component of your environment is transparent, verifiable, and maintainable at scale.

## Using packages {#using}

A Minimal package is available anywhere it is called for:

 - A package declared on a [task](../reference/tasks.md) will always be installed in the environment the task runs.
 - A package declared as an input to a [build spec](../reference/build-specs.md) will always be present in the build sandbox.
 - A package declared on a [stack](./stacks.md) will always be present in the tasks and builds that use the stack.
 - A package declared on a [session](./sessions.md) will always be present in that session.


## Defining packages {#definition}

Packages are defined in a [build spec](../reference/build-specs.md) file located at `packages/<package name>/build.ncl`. The `packages/` directory
is always adjacent to the [`minimal.toml`](../reference/minimal-dot-toml.md) file at the base of the layer, but can be omitted if the layer does not
define any packages.

The package definition captures a variety of useful information:

 - The build-time and runtime dependencies of the package, defined in terms of other packages
 - How to build the package from source-code: including build commands, where to fetch the source, and what outputs compose the package
 - Runtime semantics, such as state directories or environment variables that need to be configured at runtime
 - Metadata, such as the current version of the software, the software license, and the authoritative source of releases.

## Caching {#caching}

Built packages are cached against their _spec hash_: a cryptographic hash of the metadata of the package, including the recipe for
building the package (and the recipes for building all its transitive dependencies). Using these hashes as the storage key makes sure
that the exact package described in your repository or [software supply chain](./software-supply-chain.md) is used anywhere it is
requested, as well as providing a reliable key for fetching packages remotely.

When Minimal needs a package, it first checks the local cache. If the package is not present locally, Minimal fetches it from the remote binary cache. If the remote fetch is disabled or the package is unavailable there, Minimal builds it locally.

## Package builds

All Minimal package builds take place in a hermetic, isolated environment to prevent interference or non-reproducibility from the machine running the build.

## Sideloading additional packages

Sometimes you may want to use packages defined in a separate repository, but still use the toolchains and software versions defined by your [`[upstream]`](../reference/minimal-dot-toml.md#upstream).

Sideloads allow you to do this: each sideload specified in your `minimal.toml` brings in additional packages from other repositories, while building those packages
using the version of packages defined by your [`[upstream]`](../reference/minimal-dot-toml.md#upstream). See the [`sideloading schema`](../reference/minimal-dot-toml.md#sideload) for additional information.
