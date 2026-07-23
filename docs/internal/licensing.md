---
title: Licensing stance
description: Internal record of the project's license posture, LGPL exceptions, and redistribution obligations.
---

> This is internal documentation. It is not published to the docs site.

# Licensing stance

Minimal is licensed under Apache-2.0 (declared once in the workspace
`Cargo.toml` and inherited by every crate via
`license.workspace = true`). The license text lives at the repo root
(`LICENSE`); redistribution attributions live in `NOTICE`. Inbound
contributions are governed by the Contributor License Agreement (see
`CONTRIBUTING.md` and `legal/`). Dependency license policy is enforced
by `cargo deny` against `deny.toml`, which points back at this document
for the exceptions explained below.

## LGPL exceptions in deny.toml

### malachite family: document-and-accept

Five crates (`malachite`, `malachite-base`, `malachite-float`,
`malachite-nz`, `malachite-q`) are licensed LGPL-3.0-only and are
statically linked into our binaries. They are pulled in transitively via
the `nickel-lang-core` git dependency; we do not depend on them
directly.

Stance: document and accept. LGPL-3.0 §4(d)(0) requires conveying both
the Minimal Corresponding Source (the LGPL library source) and the
Corresponding Application Code (everything else needed to relink) in a
form suitable for relinking, via one of the GPLv3 §6 conveyance methods.

**Source-conveyance mechanism:** We rely on GPLv3 §6(d), providing a
network location from which to download the Corresponding Source. The
malachite crates are published on crates.io at pinned versions recorded
in `Cargo.lock`. Note that `Cargo.lock` itself only records registry
URLs and checksums; it does not convey the sources. The actual
conveyance depends on crates.io remaining available and retaining those
versions.

**Relinking form:** This repository (Corresponding Application Code) is
public, and anyone can rebuild the binaries with a modified malachite by
editing `Cargo.toml` to override the dependency. The statically linked
binary format does not impede relinking because users have the complete
application source.

**Risk acknowledgment:** If crates.io were to remove the pinned
malachite versions, the §6(d) conveyance would fail. For distribution
channels requiring stronger guarantees (e.g., air-gapped environments or
long-term archival), vendoring malachite sources under `vendor/` or
providing a §6(b) written offer valid for three years would be required.
Neither is currently implemented; the current stance is acceptable for
our distribution model (source-available binaries rebuilt on demand).

### hakoniwa: linking exception, Linux-only

`hakoniwa` ships under LGPL-3.0-only WITH LGPL-3.0-linking-exception,
so static linking is expressly permitted without LGPL relink
obligations. Its footprint is Linux-only: it is used by `sandbox2` and
`minimald`, and no longer reaches macOS builds since `mctx` was
decoupled from it in #721.

## nickel-lang git dependencies and crates.io

`nickel-lang-core` (and its sibling crates) are consumed as git
dependencies pinned to a rev recorded in `Cargo.lock`. crates.io only
accepts packages whose dependencies are themselves published registry
versions, so a workspace crate carrying these git deps could not be
published there as-is.

That is fine: the workspace sets `package.publish = false` and its
crates are not intended for crates.io. Publishing would only become a
prerequisite if that changed, and would require released nickel-lang
versions first.

## Redistributed binaries in darwin release artifacts

The macOS (darwin/arm64) release artifacts redistribute two prebuilt
Apache-2.0 components, pinned in `vendor/`:

- libkrun v1.19.4 (`vendor/libkrun/libkrun.lock`), shipped as
  `libkrun.1.dylib`, https://github.com/containers/libkrun
- gvproxy v0.8.9 from gvisor-tap-vsock
  (`vendor/gvproxy/gvproxy.lock`),
  https://github.com/containers/gvisor-tap-vsock

Apache-2.0 redistribution requires retaining the license and notices;
both are attributed in the root `NOTICE` file.
