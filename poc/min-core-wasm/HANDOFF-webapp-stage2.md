# Handoff: the browser side of the min-core POC (Stage 2, tab-held credential)

For the gominimal/webapp agent, after Stage 1. Goal: the tab authenticates to
the daemon stand-in with a Gatehouse-shaped SSH certificate on a key the tab
cannot export, verifies the daemon's host certificate against Host CA anchors
fetched from the issuer, and every refusal case is visible as a refusal. All
against `wg-peer --auth stub`; nothing here is Gatehouse.

## Read first

- `plans/browser-min-client-direction.plan.md`, "Stage 2" and decisions 15–17
  (in-memory tokens, separate origin, pinned bundle).
- inbox#606 for the Stage 1 numbers and this stage's results as they land.
- `HANDOFF-webapp.md` (Stage 1) for the page seam and the run steps; this
  document only adds to it.

## What you get from the minimal branch (`poc/min-core-wasm/`)

- `dist/` — rebuilt bundle. New exports: `attach_mesh`, `ssh_public_key_from_ed25519_raw`,
  `dpop_jkt_ed25519`, `pkce_verifier`, `pkce_challenge`, `dpop_proof`. Sizes
  with the `name` section kept: see `dist/README.md`. `attach_wg` still exists
  for the Stage 1 page; `attach_mesh` supersedes it.
- `js/min-socket.mjs` — `minMeshSocketWithAuth({ peer, sessionId, cols, rows, auth })`,
  the same WebSocket-shaped object as before.
- `examples/wg-peer.rs --auth stub` — the stand-in in certificate mode: it
  refuses `auth_none`, decides certificates with the core's
  `verify_user_cert`, presents a host certificate, and serves the stub's HTTP
  API on the same port with CORS. Its printed peer config gains an `auth`
  block: `issuerUrl`, `username`, `expectedHostPrincipal`, `hostCa`.
- `js/headless-auth-check.mjs` — does everything below from Node against the
  stub and passes. If the browser diverges, the difference is the browser.

## The stub's HTTP API (`issuerUrl`, same host and port as the WebSocket)

Every route sends `Access-Control-Allow-Origin: *`, allows the headers
`content-type, authorization, dpop`, and answers `OPTIONS` with 204. JSON in
and out. This is the shape of Gatehouse's routes with the paths shortened
(`/v1/ssh/certify` → `/certify`, etc.).

| Route | Request | Response |
|---|---|---|
| `GET /ssh/ca` | — | `{ user_ca: [line], host_ca: [line], known_hosts, host_principal, trust_domain, rogue_ca_for_tests: [line] }` — fetch the anchors from **here**, never from the webapp origin (decision 17 / §2.2 provenance) |
| `POST /certify` | `{ public_key: "ssh-ed25519 AAAA…", profile: "exchange", ttl?: ≤900, username?: "dev", case?: <see below> }`; send `Authorization: DPoP <token>` and `DPoP: <proof>` headers (the stub only checks presence on `/token`) | `{ certificate: "ssh-ed25519-cert-v01@openssh.com AAAA…", serial, key_id, valid_after, valid_before, profile, username, case }` — a 15-minute cert with §5.3 `key_id` JSON and extensions |
| `POST /token` | any JSON; **requires a `DPoP` header** | `{ access_token, token_type: "DPoP", expires_in: 900, refresh_token, scope: "box:ssh" }` (no-op) |
| `POST /mesh/bind` | `{ network, wg_pub }` | `{ binding, network, wg_pub, exp }` (no-op) |
| `GET /decisions` | — | `[{ at, user, serial, key_id, result }]`, `result` is `"accepted"` or a refusal code — use it to show *why* an attach was refused |

`case` values for `/certify`, each minting a certificate that fails one
check: `other-key`, `rogue-ca`, `host-type`, `unknown-critical`, `revoked`,
`expired`, `not-yet-valid`, `tampered` (`valid` or absent = a good one).

## The JS contract

```ts
// One JSON config; everything from the Stage 1 peer config, plus:
attach_mesh(configJson: string, sign: ((bytes: Uint8Array) => Promise<Uint8Array>) | null,
            onData: (bytes: Uint8Array) => void,
            onClose: (exitCode: number | undefined) => void): Promise<MinAttach>
// config = { wsUrl, privateKey, peerPublicKey, localIp, peerIp, prefixLen?, sshPort?,
//            sessionId, term?, cols, rows,
//            auth?: { username: "dev",                 // the box-login principal
//                     certificate: <line from /certify>,
//                     hostCa: <host_ca array from /ssh/ca>,
//                     expectedHostPrincipal: <peer.auth.expectedHostPrincipal> } }
ssh_public_key_from_ed25519_raw(raw: Uint8Array): string   // "ssh-ed25519 AAAA…" for exportKey("raw", publicKey)
dpop_jkt_ed25519(rawPublic: Uint8Array): string            // RFC 7638 thumbprint, the dpop_jkt value
pkce_verifier(): string; pkce_challenge(verifier: string): string
dpop_proof(rawPublic, htm, htu, nonce | null, accessToken | null, sign): Promise<string>  // EdDSA JWS
```

The signer contract: `sign` receives the exact bytes to sign and must resolve
to the **raw 64-byte Ed25519 signature** — `new Uint8Array(await
crypto.subtle.sign("Ed25519", privateKey, bytes))`. The core wraps it in the
SSH `Signature{algorithm, blob}` encoding for auth and in the JWS for DPoP;
the page never encodes anything.

Errors: `attach_mesh` **rejects its promise** (no socket object exists yet)
with a message that names the stage:

- `host rejected: … (principal_mismatch | unknown_ca | …)` — the host's
  certificate failed the policy; nothing was authenticated.
- `authentication rejected by daemon` — SSH `USERAUTH_FAILURE`, which
  carries no reason; `GET /decisions` has the daemon's code when the
  certificate reached its decision (`rogue-ca`, `host-type`,
  `unknown-critical`, `revoked`), and no entry when russh refused it before
  that (`expired`, `not-yet-valid`, `tampered`, `other-key`).
- `signing: …` — the sign callback threw or returned the wrong shape.

A tunnel that dies after attach still comes through `onClose` with no exit
code, as in Stage 1.

## Steps

1. Run `cargo run --example wg-peer -- 127.0.0.1:7691 /tmp/peer.json --auth stub`.
2. Generate the key once per page session, non-extractable:
   `crypto.subtle.generateKey({ name: "Ed25519" }, false, ["sign", "verify"])`;
   check `exportKey` on the private half throws (the Stage 2 exit criterion).
3. `GET ${issuerUrl}/ssh/ca` for the anchors; `POST ${issuerUrl}/certify` with
   `ssh_public_key_from_ed25519_raw(exportKey("raw", publicKey))`.
4. `minMeshSocketWithAuth({ peer, sessionId, cols, rows, auth: { username, certificate, hostCa, expectedHostPrincipal, sign } })`
   behind the same `?transport=mesh` flag; the page's handler wiring is unchanged.
5. Login flow against the stub, with the core's helpers: PKCE pair, DPoP
   proof for `POST /token` (the stub 400s without the header), then
   `POST /mesh/bind`. Tokens stay in memory (decision 15).
6. Keep tokens, keys and certificates out of storage; keep the route's CSP.

## Exit criteria

- With a good certificate: banner, echo, resize, typed `exit` → exit 7.
- The private key is non-extractable (`exportKey` throws) and the page
  never sees or stores the certificate beyond memory.
- Each of the eight `case` certificates is refused by `attach_mesh`, and
  `/decisions` shows the expected code for the four that reach the daemon.
- A wrong `expectedHostPrincipal` and the `rogue_ca_for_tests` anchor are
  refused with `host rejected: …`; `auth: undefined` against the stub is
  refused with `authentication rejected by daemon`.
- `/token` and `/mesh/bind` round-trip with a `dpop_proof` the browser can
  verify with `crypto.subtle.verify`.

## Measure and report (inbox#606)

- Time from WebSocket open to the attach banner in certificate mode versus
  Stage 1's `auth_none` (the extra is host-cert verification and one
  signature round trip through WebCrypto).
- Certify latency and total bytes for the login flow.
- What the page shows for each refusal, and whether `/decisions` is enough to
  explain it to a user.
- Browser matrix for WebCrypto Ed25519: Chrome, Firefox, Safari, and a phone.

## Do not

- Fall back to `auth_none` on a refusal.
- Fetch the anchors from the webapp origin, or let the page hold a CA
  private key: the stub mints and signs; the page only signs with its own key.
- Persist the key, the certificate or the tokens.
