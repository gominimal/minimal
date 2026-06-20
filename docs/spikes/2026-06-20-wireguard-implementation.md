---
id: 486
title: "WireGuard implementation choice — wireguard-go vs boringtun for Unit 4"
status: partial
date: 2026-06-20
authors:
  - gominimal-aw-bot[bot]
budget_hours: 2
actual_hours: 1.5
related:
  - "issue #478 (spec-networking tracking issue)"
  - "issue #486 (this spike)"
  - "docs/specs/03-spec-networking/03-spec-networking.md (R4.1, R4.7)"
  - "docs/specs/03-spec-networking/networking-with-diagrams.md"
tags:
  - wireguard
  - networking
  - unit-4
  - build-chain
---

# Question

For Unit 4's WireGuard mesh (R4.1), should `minimald` embed wireguard-go (via
cgo, requiring a Go toolchain — already needed for gvproxy source build) or
boringtun (pure Rust, no additional toolchain dependency)? Which is more
production-ready for the subnet-router model minimald requires?

# Hypothesis

wireguard-go is the safe choice (Tailscale's production reference implementation,
actively maintained) and has reduced marginal CI cost since gvproxy's source build
already requires Go. boringtun is a viable pure-Rust alternative but has narrower
production adoption at the subnet-router level.

# Method

1. Reviewed wireguard-go project metadata: commit activity, production users,
   integration patterns for non-Go consumers, and subnet-router deployment record.
2. Reviewed boringtun project metadata: crates.io releases, commit activity,
   production users, and Cargo feature-gating suitability.
3. Compared the integration cost of each approach for a Rust daemon:
   cgo shared-library vs pure-Rust Cargo dependency.
4. Evaluated the "reduced marginal CI cost" claim against the actual complexity
   cgo adds even when a Go toolchain is present.
5. Assessed how both implementations map to minimald's v1 subnet-router
   requirements (manual key exchange, AllowedIPs-based route advertisement for
   the gvproxy switch subnet, feature-flagged per R4.7).
6. Cross-checked findings against the spec's existing building-block analysis
   in `docs/specs/03-spec-networking/networking-with-diagrams.md`.

# Findings

## 1. Production maturity comparison for the subnet-router model

### wireguard-go

- **Source:** `golang.zx2c4.com/wireguard` — the canonical Go implementation,
  authored by WireGuard's creator Jason A. Donenfeld. The `github.com/WireGuard/
  wireguard-go` repository shows continuous commit activity with multiple commits
  per month and is the upstream reference for third-party integrations.
- **Tailscale deployment:** Tailscale operates a derivative stack
  (`github.com/tailscale/wireguard-go`) in production across millions of devices.
  Their subnet-router feature — where a peer advertises a local subnet (e.g.
  `192.168.1.0/24`) to the rest of the mesh via AllowedIPs — is central to their
  product and is the exact model minimald requires. This is the strongest
  evidence of production maturity for the subnet-router pattern.
- **Integration into non-Go binaries:** wireguard-go is a Go program. Embedding
  it in a Rust binary requires one of two paths:
  - **Subprocess:** Run the `wireguard-go` binary as a child process; communicate
    via its JSON configuration socket. minimald manages the lifecycle alongside
    gvproxy. Simple from a Rust perspective but adds a second supervised process.
  - **cgo shared library:** Build wireguard-go with
    `go build -buildmode=c-shared -o libwireguard.so`. This embeds the Go runtime
    in the `.so`. Rust calls it via C FFI. **Critical obstacle:** wireguard-go
    exposes no stable C API. A Go wrapper must be authored to define C-exported
    symbols, then built as the shared library. No such wrapper exists in the
    upstream project; it would need to be written and maintained by minimald.
  - The spec's R4.1 description "compiled to a shared library via cgo" refers to
    path B; this doc's primary finding is that path B's complexity is
    substantially higher than the hypothesis assumed.

### boringtun

- **Source:** `boringtun` crate on crates.io (Cloudflare), version 0.7.1 (May
  2026; preceded by 0.7.0 in January 2026 with critical security updates, and
  0.6.0 in July 2023). GitHub: `github.com/cloudflare/boringtun`. Development
  pace had an ~18-month gap between 0.6.0 and 0.7.0, but resumed actively in
  early 2026 with security-focused releases; the WireGuard protocol is stable
  (RFC equivalent), so implementation-level churn risk is low.
- **Production use:** Cloudflare WARP (their consumer VPN product) and Mullvad
  VPN both use boringtun in production, proving it handles sustained real-world
  traffic. Neither deploys at Tailscale's device count, but both are at a
  scale that validates the implementation.
- **Subnet-router model:** The subnet-router pattern (advertising a local subnet
  via AllowedIPs on WireGuard peers) is a WireGuard protocol-level feature, not
  an implementation-specific feature. Both wireguard-go and boringtun support it
  identically: set `AllowedIPs = 100.64.0.0/16` (the gvproxy switch subnet) on
  remote peers. The implementation-level difference between the two is nil for
  this use case. Tailscale's "battle-tested subnet-router" advantage lies in
  their coordination and ACL layer — not in wireguard-go itself — which minimald
  does not need in v1 (manual key exchange per R4.1).
- **Rust integration:** `cargo add boringtun` in the workspace `Cargo.toml`.
  The `Tunn` struct wraps a WireGuard tunnel with a standard read/write
  interface. No C FFI, no subprocess, no second runtime.

## 2. CI build-chain impact

### Go toolchain requirement analysis

The spec notes in Technical Considerations:

> **gvproxy binary**: building from source is preferred for reproducibility.

This is the premise for the "reduced marginal CI cost" claim: if Go is already
in CI for gvproxy, wireguard-go costs nothing extra. The premise is directionally
correct, but carries a critical nuance:

- **Go for pure-Go builds (gvproxy):** Requires only the Go toolchain and
  standard library. `CGO_ENABLED=0` is typical for Go CLI binaries like gvproxy.
  This is simple and cross-compilation is handled natively by Go's `GOARCH`/`GOOS`.
- **Go for cgo builds (wireguard-go shared library):** Requires `CGO_ENABLED=1`,
  a C compiler (`gcc`/`clang`) on the host, and the corresponding
  cross-compilation C compiler for every target architecture. Cross-compiling a
  cgo shared library to `linux/arm64` from a `linux/amd64` host requires an
  `aarch64-linux-gnu-gcc` toolchain — a separate installation step not needed
  for gvproxy. This is a materially different CI surface than the Go used for
  gvproxy.

**Conclusion on CI cost:**
- wireguard-go via subprocess: CI cost = Go toolchain already present. Minimal.
  But adds process management code in minimald.
- wireguard-go via cgo: CI cost = Go toolchain + C cross-compiler per target.
  Notably higher than gvproxy's pure-Go build, and raises cross-compilation risk.
- boringtun: CI cost = zero beyond current Rust toolchain. `cargo build --target
  aarch64-unknown-linux-musl` works without additional tooling.

### Feature-flag conditional compilation (R4.7)

R4.7 requires WireGuard code to be conditionally compiled behind a feature flag
with no impact on binary size or startup time when unconfigured.

- **boringtun:** A standard Cargo feature gate (`[features] wg = ["boringtun"]`)
  and `#[cfg(feature = "wg")]` guards make this native. The dependency is only
  compiled and linked when the feature is enabled. This is idiomatic Rust.
- **wireguard-go via cgo:** A cgo dependency cannot be gated with a Cargo feature
  flag in the same way. The `.so` either exists and is linked or is absent and
  the build fails. Conditional compilation across a cgo boundary requires either
  a stub `.so` for the non-WireGuard build, a `build.rs` that detects the flag
  and changes link behavior, or structuring wireguard-go as a subprocess that is
  just not spawned when unconfigured. Each adds non-trivial complexity.
- **wireguard-go via subprocess:** The subprocess path can be feature-gated
  naturally (`#[cfg(feature = "wg")]` around the spawn/manage code), but the
  binary still needs to know the wireguard-go executable is available at runtime.
  Distributing and versioning the subprocess binary adds its own complexity.

## 3. Recommendation

**boringtun is the recommended choice for minimald v1.**

The hypothesis is partially supported — wireguard-go is more battle-tested at
Tailscale's scale, and Go toolchain presence does reduce the raw toolchain
footprint for cgo. However, the hypothesis underestimates two factors:

1. **The cgo shared-library path is non-trivial even with Go present.** No
   stable C API exists for wireguard-go; minimald would own a custom Go wrapper.
   cgo cross-compilation adds C compiler dependencies absent from the gvproxy
   pure-Go build. The Go runtime embedded in a `.so` introduces two memory
   managers and non-trivial signal handling between the Rust and Go runtimes.

2. **The subnet-router model at v1 requires only WireGuard protocol AllowedIPs
   routing, not Tailscale's coordination layer.** boringtun's production record
   (Cloudflare WARP, Mullvad VPN) is sufficient for this use case. The
   Tailscale-scale production advantage is specific to their coordination and
   ACL infrastructure, not to wireguard-go as a WireGuard implementation.

boringtun's integration advantages for a Rust project:

| Dimension | wireguard-go (cgo) | wireguard-go (subprocess) | boringtun |
|---|---|---|---|
| Integration complexity | High — Go wrapper + FFI | Medium — process lifecycle | Low — Cargo dependency |
| R4.7 feature flag | Hard — cgo link-time | Medium — spawn-time gate | Easy — Cargo feature |
| Cross-compilation | High — C cross-compiler | Medium — separate binary | Low — Rust toolchain |
| Process count | Same (in-proc) | +1 (alongside gvproxy) | Same (in-proc) |
| Production subnet-router | Tailscale-scale | Tailscale-scale | Cloudflare/Mullvad-scale |
| Maintenance risk | Low | Low | Low–Medium (gap resolved in 2026) |

If boringtun's maintenance pace declines materially or the v1 manual-key-exchange
model is replaced with Tailscale-style coordination, revisiting wireguard-go via
subprocess (not via cgo) is the recommended escalation path.

# Conclusion

**Status: partial.**

The hypothesis holds for the production maturity claim: wireguard-go, via
Tailscale's derivative, is more extensively battle-tested for the subnet-router
model than boringtun. This is confirmed.

The "reduced marginal CI cost" claim is partially confirmed (Go toolchain is
already present for gvproxy), but the cgo path adds a C compiler requirement
and cross-compilation complexity that the hypothesis does not account for.

The practical recommendation departs from the hypothesis: **boringtun is the
right choice for minimald v1** given its clean Cargo feature-flag support
(R4.7), zero additional build-chain dependencies, and sufficient production
maturity for the AllowedIPs-based subnet-router pattern minimald requires.
The spec's existing preference for wireguard-go (in the context section and the
networking-with-diagrams building-block analysis) should be revised to specify
boringtun, with a follow-up spike if v2 subnet-router requirements exceed
boringtun's capability.

The subprocess path for wireguard-go is noted as a viable middle ground but
adds a second supervised process alongside gvproxy without providing the cgo
approach's in-process integration benefit.

# Action items

1. **Spec amendment (R4.1):** Update R4.1 in `docs/specs/03-spec-networking/
   03-spec-networking.md` to specify boringtun as the chosen WireGuard
   implementation; remove the cgo-via-shared-library option. The parenthetical
   "wireguard-go (compiled to a shared library via cgo)" should become
   "boringtun (pure-Rust WireGuard, `boringtun` crate)."
2. **Full wireguard-go reference sweep (daemon and CLI):** boringtun applies
   to both `minimald` (daemon) and the `minimal` CLI (also pure Rust), so all
   wireguard-go references in the networking spec must be updated together to
   avoid internal inconsistency. Six locations need amendment:
   - `03-spec-networking.md` context paragraph (line 26): "wireguard-go (Tailscale
     userspace netstack)" → "boringtun (pure-Rust WireGuard)"
   - `03-spec-networking.md` R4.3 (line 318): "with wireguard-go bundled so no
     system WireGuard package is required" → "with boringtun bundled so no
     system WireGuard package is required"
   - `networking-with-diagrams.md` building-block B6 label (line 437):
     "wireguard-go / Tailscale userspace netstack" → "boringtun (pure-Rust
     WireGuard)"
   - `networking-with-diagrams.md` UC2 diagram, `WG` node (line 287):
     "wireguard-go peer (bundled in minimal CLI or system WG client)" →
     "boringtun peer (bundled in minimal CLI or system WG client)"
   - `networking-with-diagrams.md` deployment-model diagram, `LapWG` node
     (line 503): "wireguard-go peer (bundled in minimal CLI)" → "boringtun peer
     (bundled in minimal CLI)"
   - `networking-with-diagrams.md` Option A prose (lines 585–588): "Each
     minimald is a wireguard-go peer" → "Each minimald is a boringtun peer";
     "wireguard-go is bundled" → "boringtun is bundled"
3. **Workspace dependency pin:** When Unit 4 implementation begins, pin
   `boringtun` in `[workspace.dependencies]` with `features = []` and add it to
   `minimald/Cargo.toml` behind the `wg` feature flag.
4. **Risk register entry:** Note that boringtun exhibited an ~18-month release
   gap (0.6.0 July 2023 → 0.7.0 January 2026) before resuming active
   maintenance with security-focused releases in early 2026. Flag this cadence
   pattern as a known risk in Unit 4 task descriptions; retain the checkpoint
   to re-evaluate if no version is released within 18 months of the prior
   release.
5. **Follow-up spike (if needed):** If v2 requirements add Tailscale-style
   peer coordination or the boringtun crate shows signs of abandonment, open a
   follow-up spike comparing wireguard-go subprocess integration with the then-
   current state of the boringtun ecosystem.

# Artifacts

## Source repositories inspected

- `golang.zx2c4.com/wireguard` (wireguard-go): canonical Go WireGuard
  implementation. Active commit history as of spike date. No C-exported API in
  upstream; all integrations call the library from Go code.
- `github.com/tailscale/wireguard-go`: Tailscale fork, derives from upstream
  wireguard-go with Tailscale-specific extensions (netstack, subnet-router
  coordination). Production scale: millions of Tailscale nodes.
- `github.com/cloudflare/boringtun` (`boringtun` crate, v0.7.1 as of June
  2026): Cloudflare's pure-Rust WireGuard implementation. Production use
  confirmed in Cloudflare WARP and Mullvad VPN. Actively maintained as of
  spike date (0.7.0 January 2026 with critical security updates, 0.7.1 May
  2026).

## Spec documents reviewed

- `docs/specs/03-spec-networking/03-spec-networking.md`: R4.1 (WireGuard
  implementation choice), R4.7 (feature flag requirement), Technical
  Considerations (gvproxy binary, WireGuard in Rust).
- `docs/specs/03-spec-networking/networking-with-diagrams.md`: Building-block
  diagram B6 ("wireguard-go / Tailscale userspace netstack").

## cgo cross-compilation evidence

Go's own documentation on `buildmode=c-shared` states:
> "Build the listed main package, plus all packages it imports, into a C shared
> library. The only callable symbols will be those functions exported using a
> cgo `//export` comment."

Since wireguard-go exports no symbols via `//export`, a custom Go shim must be
written. `CGO_ENABLED=1` and a host C compiler are required; for cross-
compilation each target architecture requires a matching C cross-compiler
toolchain. This is documented in the Go `cmd/cgo` man page and is separate from
the Go-for-Go cross-compilation used to build gvproxy.
