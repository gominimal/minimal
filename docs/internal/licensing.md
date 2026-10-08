---
title: Licensing stance
description: Internal record of the project's license posture, LGPL exceptions, and redistribution obligations.
---

> This is internal documentation. It is not published to the docs site.

# Licensing stance

Minimal uses the Apache-2.0 license. The workspace `Cargo.toml` declares
it once, and every crate inherits it through `license.workspace = true`.
The license text is in `LICENSE` at the repo root. The redistribution
attributions are in `NOTICE`. The Contributor License Agreement covers
inbound contributions (see `CONTRIBUTING.md` and `legal/`). `cargo deny`
enforces the dependency license policy in `deny.toml`, which points back
at this document for the exceptions that follow.

## LGPL exceptions in deny.toml

### malachite family: document-and-accept

The crates `malachite`, `malachite-base`, `malachite-float`,
`malachite-nz`, and `malachite-q` use the LGPL-3.0-only license, and our
binaries link them statically. They arrive transitively through the
`nickel-lang-core` git dependency. We do not depend on them directly.

Stance: document and accept. LGPL-3.0 §4(d)(0) requires two conveyances
in a form suitable for relinking. The first is the Minimal Corresponding
Source, which is the LGPL library source. The second is the
Corresponding Application Code, which is everything else needed to
relink. Both must use one of the GPLv3 §6 conveyance methods.

**Source-conveyance mechanism.** We rely on GPLv3 §6(d) and give a
network location from which to download the Corresponding Source.
crates.io publishes the malachite crates at the pinned versions that
`Cargo.lock` records. `Cargo.lock` itself records only registry URLs and
checksums. It does not convey the sources. The actual conveyance depends
on crates.io staying available and keeping those versions.

**Relinking form.** This repository holds the Corresponding Application
Code and is public. Anyone can rebuild the binaries with a modified
malachite if they override the dependency in `Cargo.toml`. The
statically linked binary format does not prevent relinking, because
users have the complete application source.

**Risk acknowledgment.** The §6(d) conveyance fails if the pinned
malachite versions disappear from crates.io. Some distribution channels,
such as air-gapped environments or long-term archival, need stronger
guarantees. Those channels need the malachite sources vendored under
`vendor/`, or a §6(b) written offer valid for three years. Neither is in
place. The current stance is acceptable for our distribution model, in
which the binaries are source-available and anyone can rebuild them on
demand.

### hakoniwa: linking exception, Linux-only

`hakoniwa` uses LGPL-3.0-only WITH LGPL-3.0-linking-exception, so static
linking is expressly permitted without LGPL relink obligations. Its
footprint is Linux-only. `sandbox2` and `minimald` use it, and it no
longer reaches macOS builds since #721 decoupled `mctx` from it.

## Redistributed third-party code in release artifacts

The release artifacts redistribute two Apache-2.0 components, pinned in
`vendor/`:

- libkrun v1.19.6 (`vendor/libkrun/libkrun.lock`), built from source
  with the patches in `vendor/libkrun/patches/` applied,
  https://github.com/containers/libkrun. The macOS (darwin/arm64)
  release distributes it as `libkrun.1.dylib`. The Linux (amd64, arm64)
  release links it statically into the `minvmd` binary
  (`scripts/build-libkrun-linux.sh`).
- gvproxy v0.8.9 from gvisor-tap-vsock
  (`vendor/gvproxy/gvproxy.lock`), in the macOS (darwin/arm64) release
  artifacts, https://github.com/containers/gvisor-tap-vsock

Apache-2.0 redistribution requires us to keep the license and notices.
The root `NOTICE` file attributes both components.
