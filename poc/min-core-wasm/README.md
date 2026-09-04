# min-core wasm probe

Milestones 1 and 1b of gominimal/inbox#606, as a standalone crate: the `min
session attach` handshake on top of russh, and beneath it a userspace
WireGuard tunnel with its own TCP/IP stack so the tab is a mesh node — built
for `wasm32-unknown-unknown` with a wasm-bindgen head, plus the same code
running natively under test.

Not part of the `minimal` workspace on purpose (own `[workspace]` table): the
point is to see what a dependency-minimal core costs, and `Cargo.lock` here is
that number.

## What is proven

- `src/attach.rs`: `auth_none` → `env MINIMAL_SESSION_ID` → `pty-req` →
  `shell`, then data / window-change / exit on the channel — the exact sequence
  `crates/minimald/src/connection.rs` accepts. Transport is any
  `AsyncRead + AsyncWrite + Send`.
- `tests/roundtrip.rs`: that sequence against an in-process russh server that
  enforces minimald's preconditions, over a `tokio::io::duplex` pipe:
  attach banner, echo, resize, exit status, close; and the refusal path.
- `src/web.rs`: a browser `WebSocket` as the SSH stream (`SendWrapper` for
  russh's `Send` bounds), and `attach()` / `MinAttach{write,resize,close}`
  exported to JS. Compiles; not yet run in a browser.
- `js/min-socket.mjs`: the WebSocket-shaped adapter `TerminalPane.astro`'s
  `connect()` would use instead of `new WebSocket(url)`.

## Stage 1b: the tab as a WireGuard node

- `src/wg.rs`: boringtun's `Tunn` (the same crate `minimald` embeds under
  `networking-wg`) plus smoltcp, behind the russh transport. `WgStack::new`
  takes a `DatagramPipe` (two queues, one WireGuard datagram per item) and
  returns a driver future the host spawns; `connect(port)` / `listen(port)`
  give a `WgTcpStream` that is `AsyncRead + AsyncWrite + Send`, so russh
  neither knows nor cares that the bytes cross a tunnel.
- `src/rt.rs`: the only runtime services the network layer needs, clock and
  sleep, tokio natively and `Date.now` + `setTimeout` in a browser.
- `vendor/boringtun` + `patches/`: boringtun 0.7.1 compiles and *runs* on wasm
  with one patch: its sleep-aware clock has unix and windows backends only, and
  its TAI64N handshake stamp calls `std::time::SystemTime::now()`, which panics
  on `wasm32-unknown-unknown`; both go through `web-time` now. Upstreamable.
- `tests/wg_roundtrip.rs`: two in-process nodes cross-connected by datagram
  queues; the daemon node listens on TCP/22 inside the tunnel with the
  fake-minimald server, the tab node connects and runs the attach. Handshake,
  banner, echo, resize, a 20 KB payload, exit status, close.
- `tests/wg_over_ws.rs` + `examples/wg-peer.rs`: the same through a real
  loopback WebSocket, one datagram per binary frame. `wg-peer` is the native
  stand-in for "minimald with a WireGuard-over-WebSocket ingress" that a
  browser can dial; it prints the JSON peer config the page passes to
  `attach_wg`.
- `attach_wg(...)` in `src/web.rs` and `minMeshSocket` in `js/min-socket.mjs`:
  the browser head for the mesh path.
- `js/headless-check.mjs`: drives the *built bundle* from Node (>= 22, global
  `WebSocket`) against `wg-peer` exactly as the browser adapter would — the
  handshake, banner, echo, resize, a 20 KB paste, exit — and prints timings.
  `MIN_CORE_TRACE=1` logs every WebSocket frame. This is what catches
  wasm-only failures (`SystemTime::now()` panics, dropped-closure traps)
  before a browser does.

Run the stand-in and point the page at it, or the headless check:

    cargo run --example wg-peer -- 127.0.0.1:7691 /tmp/peer.json
    node js/headless-check.mjs /tmp/peer.json      # needs dist/ (see Building)
    # in the page: minMeshSocket({ peer: <the printed JSON>, sessionId, cols, rows })

Caveats: interop is proven boringtun-to-boringtun (also what `minimald`
embeds), not against wireguard-go or the kernel module; there is no relay —
`wg-peer` terminates the WebSocket itself, the "daemon is reachable" case; a
WebSocket that dies is not yet surfaced to the SSH layer, so the session hangs
until a keepalive notices. None of it has run in a browser yet.

## Building

Native (tests):

    cargo test

wasm, in a sandbox whose toolchain has no wasm32 std (this one): bootstrap
std from `rust-src`. `RUSTC_BOOTSTRAP=1` is the stopgap for `-Zbuild-std`
on the pinned stable toolchain; the real fix is a catalog package carrying
the target's `rust-std` (see the webapp issue).

    RUSTC_BOOTSTRAP=1 CC_wasm32_unknown_unknown=clang \
      cargo build --release --target wasm32-unknown-unknown -Zbuild-std=std,panic_abort
    wasm-bindgen --target web --out-dir pkg target/wasm32-unknown-unknown/release/min_core.wasm
    wasm-opt -Os -g -o pkg/min_core_bg.opt.wasm pkg/min_core_bg.wasm   # -g keeps the name section for attributable traps

`.cargo/config.toml` points the target at `wasm-ld` (no `rust-lld` in this
sysroot) and sets `--cfg getrandom_backend="wasm_js"` for the getrandom 0.4
line that ssh-key's p256 pulls in. `ring` needs `clang` for its C sources.

## Wiring into webapp#735

1. Relay: a `--relay <uds>` mode in `scripts/terminal-poc-server.ts` that
   pipes WebSocket binary frames <-> the minimald socket, byte for byte. Same
   shape as `min proxy --socket` (`crates/minimal/src/lib.rs`), which is what
   the CLI's `ssh` uses as ProxyCommand today.
2. Page: in `TerminalPane.astro` `connect()`, behind a query flag,
   `const socket = await minSocket({ relayUrl, sessionId, cols, rows })`
   in place of `new WebSocket(url)`. Nothing else on the page changes.
3. The session id is a real minimald session uuid (`min session list`).

## Findings worth carrying back to #606

- russh 0.63.1 builds for the browser target with `ring` + `flate2` and no
  patch. The only extras a consumer needs: `SendWrapper` around JS handles,
  `getrandom_backend="wasm_js"`, and `clang` for ring.
- Leave `client::Config` keepalive/inactivity at `None` on wasm: russh drives
  them with `tokio::time`, which has no driver in a browser. Do not call
  `Handle::disconnect` there either (it uses `tokio::time::timeout`).
- `russh::server` compiles natively only; the client half is what the core needs.

## Numbers (2026-09-03, rust 1.97.1, russh 0.63.1, wasm-bindgen 0.2.127, binaryen 124)

SSH-only module (Stage 0):

| Artifact | raw | gzip -9 |
|---|---|---|
| `min_core.wasm` from cargo (`opt-level = "s"`, lto, panic=abort, build-std) | 2,188,098 B | 530,788 B |
| after `wasm-bindgen --target web` | 1,871,025 B | 436,660 B |
| after `wasm-opt -Os` | 909,229 B | 355,877 B |
| `min_core.js` glue | 26,705 B | 5,840 B |

Reference point from webapp#735: ghostty-web is 636,327 B raw / 184,359 B gzip.
Obvious diet candidates, untried: drop `flate2` (compression is negotiable),
and see whether `ssh-key`'s p256/p384/p521 can be left out when minimald only
ever presents ed25519.

With the WireGuard + smoltcp layer (Stage 1b), same pipeline:

| Artifact | raw | gzip -9 |
|---|---|---|
| after `wasm-bindgen --target web` | 2,167,797 B | 548,885 B |
| after `wasm-opt -Os` | 1,092,803 B | 446,597 B |
| `min_core.js` glue | 31,492 B | 6,676 B |

The network layer costs 183 KB raw / 91 KB gzip on top of the SSH-only module.

Headless run of the built bundle in Node 24 against `wg-peer` on loopback
(2026-09-04): instantiate 17 ms; WebSocket open → attach banner 95 ms
(WireGuard handshake + TCP + SSH kex + auth + env/pty/shell); keystroke round
trip 0.8 ms; 20 KB paste echoed in 43 ms.
