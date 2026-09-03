# Handoff: the browser side of the min-core POC (Stage 1)

For the gominimal/webapp agent. Goal: run the wasm `min` client in a real
browser, as a WireGuard mesh node, inside the existing `/terminal-poc` page,
against the native daemon stand-in — and report what happens. No credential
work yet; that is Stage 2 and needs core changes first.

## Read first

- The plan: `plans/browser-min-client-direction.plan.md` on gominimal/minimal
  branch `feat/min-core-wasm-poc` (PR #1350), sections "Stage 1" and "Decisions
  taken on 2026-09-03". The Open Questions log there is the decision record.
- Findings so far: gominimal/inbox#606, the last three comments.
- The page you are changing: gominimal/webapp#735 (`/terminal-poc`,
  `src/pages/terminal-poc/_components/TerminalPane.astro`). Its `connect()`
  (about lines 252–307) is the whole transport seam.

## What you get from the minimal branch

All under `poc/min-core-wasm/`:

- `dist/` — the built wasm bundle: `min_core.js` (ES module, wasm-bindgen
  `--target web`), `min_core_bg.wasm` (1.09 MB raw / 447 KB gzip after
  wasm-opt), the `.d.ts` files, and `SHA256SUMS`. Vendor these; do not try to
  build the wasm in your sandbox (the toolchain packages are gominimal/webapp#755).
- `js/min-socket.mjs` — `minMeshSocket({ peer, sessionId, cols, rows, term })`
  returns a WebSocket-shaped object (`onopen`, `onmessage`, `onclose`, `onerror`,
  `send`, `close`, `readyState`) speaking the page's existing frame protocol:
  binary frames are PTY bytes, text frames are the JSON control messages
  (`{t:"attached",…}`, `{t:"exit",code}`), and `send()` accepts the page's
  `{t:"input",d}` / `{t:"resize",cols,rows}` JSON. It calls `attach_wg` from
  `dist/min_core.js`; adjust its import path to wherever you vendor the bundle.
- `examples/wg-peer.rs` — the daemon stand-in. It terminates the WebSocket,
  runs WireGuard (boringtun, the same crate `minimald` embeds) and a TCP stack,
  and serves a fake `minimald` SSH server on TCP/22 inside the tunnel that
  echoes input, reports resizes, and exits on `exit`. It prints the JSON peer
  config the page needs.

## The wasm API, if you bypass the adapter

```ts
attach_wg(wsUrl, privateKeyB64, peerPublicKeyB64, localIp, peerIp, prefixLen, sshPort,
          sessionId, term, cols, rows,
          onData: (bytes: Uint8Array) => void,
          onClose: (exitCode: number | undefined) => void): Promise<MinAttach>
MinAttach.write(data: Uint8Array): Promise<void>
MinAttach.resize(cols: number, rows: number): Promise<void>
MinAttach.close(): Promise<void>
```

`attach(...)` (no `_wg`) is the plain-WebSocket variant from Stage 0; ignore it
for this work.

## Steps

1. Run the stand-in. In a checkout of the minimal branch, inside
   `poc/min-core-wasm`: `cargo run --example wg-peer -- 127.0.0.1:7691`. Needs
   Rust (`min add --session rust`) and `ssh-keygen` on PATH (the `openssh`
   package) for the throwaway host key. It prints a JSON object with `wsUrl`,
   `privateKey`, `peerPublicKey`, `localIp`, `peerIp`, `prefixLen`, `sshPort`.
   Keys are fresh per start.
2. Vendor `dist/` into the webapp so the four files sit next to each other and
   are served with `application/wasm` for the module (Astro dev does this;
   verify prod build output). Load with `await init()` from the JS glue.
3. In `TerminalPane.astro` `connect()`, behind a query flag (`?transport=mesh`),
   replace `new WebSocket(url)` with `await minMeshSocket({ peer, sessionId,
   cols: term.cols, rows: term.rows })`. Take `peer` from a `?peer=` query
   parameter carrying the base64url-encoded JSON from step 1 (reload-safe), or
   a dev-only text field. `sessionId` can be any slug; the stand-in does not
   validate it. Leave the non-mesh path exactly as it is.
4. Keep every prod-unreachability mechanism #735 has. The mesh path adds no
   backend and must not depend on `scripts/terminal-poc-server.ts`.
5. On the terminal route only: a strict CSP (`script-src 'self'
   'wasm-unsafe-eval'` at minimum — WebAssembly compilation needs
   `'wasm-unsafe-eval'`), SRI on `min_core.js`, and no third-party scripts.
   This is the interview decision "separate origin, no third-party scripts";
   the separate origin itself is v1 work, not this step.

## Exit criteria

- An interactive session in ghostty over the tunnel: the banner
  `attached <sessionId> <cols>x<rows>` appears, typing echoes back with the
  `echo ` prefix, a window resize produces `resize CxR` from the stand-in.
- Typing `exit` ends the session with exit code 7 and the page reports it
  through the existing `{t:"exit"}` handling.
- A reload reconnects (new tunnel; the stand-in keeps no session state).
- No console errors, no CSP violations, the wasm served as `application/wasm`.

## What to measure and report (a comment on gominimal/inbox#606)

- wasm fetch + instantiate time, cold and cached; total bytes over the wire.
- Time from WebSocket open to the attach banner (WireGuard handshake + TCP +
  SSH handshake, end to end).
- Keystroke round trip and throughput on a large paste (tens of KB).
- Tab backgrounded then foregrounded, desktop and mobile emulation, and a real
  phone if one is available: does the tunnel survive, does typing resume.
- Kill `wg-peer` mid-session: expected today is a hung terminal (known gap,
  core fix pending); report how long until anything is noticed.
- Browser matrix: Chrome, Firefox, Safari; anything that fails to instantiate.
- Memory of the tab with the tunnel up.

## Known gaps — do not work around them in the webapp

- A dead WebSocket is not yet surfaced to the SSH layer (core fix coming).
- Authentication is `auth_none` and the host key is not verified: Stage 2.
- The stand-in is not `minimald`; the real daemon ingress is Stage 3.
- WireGuard interop is boringtun-to-boringtun only.

## Do not

- Add any server component to the mesh path (no proxy, no bridge, no relay).
- Modify anything in gominimal/minimal; file findings and requests on #606.
- Persist keys or peer config anywhere but the URL or an in-memory field.
