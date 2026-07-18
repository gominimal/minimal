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

Five crates — `malachite`, `malachite-base`, `malachite-float`,
`malachite-nz`, `malachite-q` — are licensed LGPL-3.0-only and are
statically linked into our binaries. They are pulled in transitively via
the `nickel-lang-core` git dependency; we do not depend on them
directly.

Stance: document and accept. LGPL-3.0 §4 (via GPL-3.0 §6) requires that
users can relink the covered work against a modified version of the
library. The complete corresponding source is public (this repository
plus the pinned crate sources recorded in `Cargo.lock`), and anyone can
rebuild the binaries with a modified malachite, which satisfies the
relinking requirement for our current distribution model. Revisit this
stance if distribution terms change (for example, restricted-source or
object-only distribution).

### hakoniwa: linking exception, Linux-only

`hakoniwa` ships under LGPL-3.0-only WITH LGPL-3.0-linking-exception,
so static linking is expressly permitted without LGPL relink
obligations. Its footprint is Linux-only: it is used by `sandbox2` and
`minimald`, and no longer reaches macOS builds since `mctx` was
decoupled from it in #721.

## nickel-lang git dependencies block crates.io publishing

`nickel-lang-core` (and its sibling crates) are consumed as git
dependencies pinned to a rev recorded in `Cargo.lock`. crates.io
rejects packages whose dependencies are not themselves published
registry versions, so any future publishing of workspace crates to
crates.io is blocked until we move to released nickel-lang versions.
The workspace currently sets `package.publish = false`, so this is a
latent constraint, not an active problem.

## Redistributed binaries in darwin release artifacts

The macOS (darwin/arm64) release artifacts redistribute two prebuilt
Apache-2.0 components, pinned in `vendor/`:

- libkrun v1.19.4 (`vendor/libkrun/libkrun.lock`), shipped as
  `libkrun.1.dylib` — https://github.com/containers/libkrun
- gvproxy v0.8.9 from gvisor-tap-vsock
  (`vendor/gvproxy/gvproxy.lock`) —
  https://github.com/containers/gvisor-tap-vsock

Apache-2.0 redistribution requires retaining the license and notices;
both are attributed in the root `NOTICE` file.
