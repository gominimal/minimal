---
description: Layered, composable model for declarative software dependencies, from public registries to organization-internal packages.
---

# The Minimal software supply chain

To enable declarative, reproducible, and understandable software in Minimal, all software exists within a layered model
we refer to as the _software supply chain_.

The lowest layer of the software supply chain is your codebase, within which you invoke commands in the Minimal CLI. Each layer
depends on configuration and software in the layer above it, which is itself a codebase. Each codebase links to the layer above it
via the `[upstream]` section in the [`minimal.toml`](../reference/minimal-dot-toml.md) file:

```toml
[upstream]
repo = "<git remote URL>"
branch = "<git branch>"
locked_commit = "<git commit hash the repo is currently pinned to>"
```

These all form the software supply chain.

The most common upstream is our public packages registry:

```toml
[upstream] # Source of software & tooling
repo = "https://github.com/gominimal/pkgs"
branch = "main"
# locked_commit is filled in when you run `min update`
```

For more information, check out the [minimal.toml page](../reference/minimal-dot-toml.md) in the References section.

## Software is configuration

Software in any real environment is more complicated than binaries copied to disk, and these nuances are the basis of how Minimal operates. By building security into the way that products are created, Minimal makes software secure by default and removes pressure from the engineering staff.

A piece of software is encapsulated in a [package](./packages.md), defined at any layer of the software supply chain and usable
by packages at that layer or below. Packages themselves are defined by build specifications: config-as-code that describes the detailed
semantics of what the software needs to function as well as an exact, reproducible description of how to build the software.

Dependencies of packages are references to other packages, an approach that enables Minimal to build exact production and development environments
from simple, composable descriptions of individual packages.

For readers familiar with Nix/Nixpkgs, package build-specs are similar to Nix derivations.

## Everything is (composable) configuration

In addition to declaring packages, each software supply chain layer also declares [stacks](./stacks.md). Each layer inherits the definitions from the layers above it and adds its own on top; defining the same name twice is an error. Your codebase can use packages from the public registry while defining its own stacks, and an organization's internal registry can add private packages on top of the public one.

This composability means you can:

- **Use the public registry as-is** for standard open-source tooling
- **Add an internal layer** with organization-specific packages, stacks, or policies
- **Define project-local packages** for software unique to your codebase
