# min-core wasm probe

Milestone 1 of gominimal/inbox#606, as a standalone crate: the `min session
attach` handshake on top of russh, built for `wasm32-unknown-unknown` with a
wasm-bindgen head, plus the same code running natively under test.

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
    wasm-opt -Os -o pkg/min_core_bg.opt.wasm pkg/min_core_bg.wasm   # optional

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
