# Spikes

Time-boxed investigations that answer a specific technical question before
implementation work commits to an approach. Files are named
`YYYY-MM-DD-<kebab-topic>.md` and carry frontmatter with the question's
status: `proved`, `disproved`, or `partial` (answered in part within the
budget).

Like specs, spikes are working artifacts: excluded from the docs site but
publicly visible in the repository.

## Index

| Date | Spike | Question | Outcome |
|---|---|---|---|
| 2026-06-20 | [WireGuard implementation choice](2026-06-20-wireguard-implementation.md) | Embed wireguard-go (Go toolchain, cgo or subprocess) or boringtun (pure Rust) for the networking mesh's subnet-router model? | partial — wireguard-go is the production-proven subnet-router stack (Tailscale-scale) but exposes no stable C API, so embedding means a supervised subprocess or a custom cgo shim; boringtun is pure Rust and production-proven (WARP, Mullvad) but its subnet-router fit was not fully established in budget. |
| 2026-06-21 | [gvproxy switch attachment](2026-06-21-gvproxy-attachment.md) | What are the exact gvproxy v0.8.9 invocation flags and the tap-fd attachment handshake for multiple netns clients on native Linux? | proved — one gvproxy with a repeatable `-listen` control socket; clients POST to `/connect` (HTTP hijack) then relay ethernet frames with 16-bit little-endian length framing; subnet/leases are YAML-`-config`-only (no `-subnet` flag); ports map via the `/services/forwarder` API. |
