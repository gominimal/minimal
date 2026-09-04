// Headless Stage 2 check of the built bundle from Node (>= 22): what the page
// does in certificate mode, against `wg-peer --auth stub`.
//
//   cargo run --example wg-peer -- 127.0.0.1:7691 /tmp/peer.json --auth stub
//   node js/headless-auth-check.mjs /tmp/peer.json
//
// 1. a non-extractable WebCrypto Ed25519 key; exportKey("raw") on the public
//    half; the core formats it as an OpenSSH key line
// 2. GET /ssh/ca (anchors), POST /certify (15-min exchange cert)
// 3. attach_mesh with the auth block and a sign callback over crypto.subtle
// 4. banner, echo, resize, exit 7
// 5. every refusal case: attach_mesh must reject, and the daemon's decision
//    (GET /decisions) must name the code for the cases that reach it
// 6. host policy: wrong principal / rogue Host CA / auth_none all rejected
// 7. PKCE + DPoP helpers round-trip through the stub's /token and /mesh/bind
// Exit code 0 on success; prints a JSON summary.

import { readFileSync } from "node:fs";

const DIST = new URL(process.env.MIN_CORE_DIST ?? "../dist/", import.meta.url);
const core = await import(new URL("min_core.js", DIST));
const { default: init, attach_mesh, ssh_public_key_from_ed25519_raw, dpop_jkt_ed25519, pkce_verifier, pkce_challenge, dpop_proof } = core;
await init({ module_or_path: readFileSync(new URL("min_core_bg.wasm", DIST)) });

const peer = JSON.parse(readFileSync(process.argv[2] ?? "/tmp/peer.json", "utf8"));
if (!peer.auth) throw new Error("peer config has no auth block: run wg-peer with --auth stub");
const issuer = peer.auth.issuerUrl;
const enc = new TextEncoder();
const dec = new TextDecoder();

// 1. key
const keyPair = await crypto.subtle.generateKey({ name: "Ed25519" }, false, ["sign", "verify"]);
let exportThrows = false;
try { await crypto.subtle.exportKey("raw", keyPair.privateKey); } catch { exportThrows = true; }
try { await crypto.subtle.exportKey("pkcs8", keyPair.privateKey); exportThrows = false; } catch { /* still throws */ }
const rawPub = new Uint8Array(await crypto.subtle.exportKey("raw", keyPair.publicKey));
const sshPub = ssh_public_key_from_ed25519_raw(rawPub);
const sign = async (bytes) => new Uint8Array(await crypto.subtle.sign("Ed25519", keyPair.privateKey, bytes));

// 2. anchors + certify
const ca = await (await fetch(`${issuer}/ssh/ca`)).json();
const certify = async (extra = {}) => {
  const r = await fetch(`${issuer}/certify`, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: "DPoP stub-access-token", dpop: "stub" },
    body: JSON.stringify({ public_key: sshPub, profile: "exchange", ttl: 900, ...extra }),
  });
  const j = await r.json();
  if (!r.ok) throw new Error(`certify ${JSON.stringify(extra)}: ${r.status} ${JSON.stringify(j)}`);
  return j;
};
const minted = await certify();

// 3. attach with the certificate
const cfg = (overrides = {}) => JSON.stringify({
  ...peer, auth: undefined,
  sessionId: "sess-auth", term: "xterm-256color", cols: 100, rows: 30,
  auth: { username: peer.auth.username, certificate: minted.certificate, hostCa: ca.host_ca, expectedHostPrincipal: peer.auth.expectedHostPrincipal },
  ...overrides,
});
let buf = "";
const waiters = [];
const check = () => { for (let i = waiters.length - 1; i >= 0; i--) { const [n, res] = waiters[i]; if (buf.includes(n)) { waiters.splice(i, 1); res(); } } };
const expect = (needle, ms = 10000) => new Promise((res, rej) => { waiters.push([needle, res]); check(); setTimeout(() => rej(new Error(`timeout waiting for ${JSON.stringify(needle)}; got ${JSON.stringify(buf)}`)), ms).unref(); });
let closedWith = null;
const closed = new Promise((res) => { globalThis.__close = (c) => { closedWith = c; res(c); }; });
const t0 = performance.now();
const att = await attach_mesh(cfg(), sign, (b) => { buf += dec.decode(b); check(); }, (c) => globalThis.__close(c));
const tAttach = performance.now() - t0;
await expect("attached sess-auth 100x30");
await att.write(enc.encode("ping\n"));
await expect("echo ping\n");
await att.resize(120, 40);
await expect("resize 120x40");
for (const ch of "exit\r") await att.write(enc.encode(ch));
const code = await Promise.race([closed, new Promise((_, rej) => setTimeout(() => rej(new Error("no close")), 10000).unref())]);
if (code !== 7) throw new Error(`expected exit 7, got ${code}`);
const decisionsAfterValid = await (await fetch(`${issuer}/decisions`)).json();
const accepted = decisionsAfterValid.find((d) => d.serial === minted.serial);
if (!accepted || accepted.result !== "accepted") throw new Error(`daemon did not record acceptance: ${JSON.stringify(decisionsAfterValid)}`);

// 5. refusal cases
const refusals = {};
const cases = { "rogue-ca": "unknown_ca", "host-type": "wrong_cert_type", "unknown-critical": "unknown_critical_option", revoked: "cert_revoked", expired: null, "not-yet-valid": null, tampered: null, "other-key": null };
for (const [c, expectedCode] of Object.entries(cases)) {
  const bad = await certify({ case: c });
  let message = null;
  try {
    await attach_mesh(cfg({ auth: { username: peer.auth.username, certificate: bad.certificate, hostCa: ca.host_ca, expectedHostPrincipal: peer.auth.expectedHostPrincipal } }), sign, () => {}, () => {});
  } catch (e) { message = String(e?.message ?? e); }
  if (message === null) throw new Error(`case ${c} was accepted`);
  const decisions = await (await fetch(`${issuer}/decisions`)).json();
  const d = decisions.find((x) => x.serial === bad.serial);
  if (expectedCode && (!d || d.result !== expectedCode)) throw new Error(`case ${c}: daemon decision ${JSON.stringify(d)} != ${expectedCode}`);
  if (!expectedCode && d) throw new Error(`case ${c}: unexpectedly reached the daemon's decision: ${JSON.stringify(d)}`);
  refusals[c] = { rejected: message, daemonDecision: d?.result ?? "(refused before the decision)" };
}

// 6. host policy + auth_none
const hostPolicy = {};
for (const [name, auth] of Object.entries({
  wrongPrincipal: { username: peer.auth.username, certificate: minted.certificate, hostCa: ca.host_ca, expectedHostPrincipal: "10.90.0.9" },
  rogueHostCa: { username: peer.auth.username, certificate: minted.certificate, hostCa: ca.rogue_ca_for_tests, expectedHostPrincipal: peer.auth.expectedHostPrincipal },
  authNone: undefined,
})) {
  let message = null;
  try { await attach_mesh(cfg({ auth }), auth ? sign : null, () => {}, () => {}); } catch (e) { message = String(e?.message ?? e); }
  if (message === null) throw new Error(`${name} was accepted`);
  hostPolicy[name] = message;
}

// 7. PKCE + DPoP against the stub
const verifier = pkce_verifier();
const challenge = pkce_challenge(verifier);
const jkt = dpop_jkt_ed25519(rawPub);
const proof = await dpop_proof(rawPub, "POST", `${issuer}/token`, null, null, sign);
const [h, p, s] = proof.split(".");
const header = JSON.parse(Buffer.from(h, "base64url").toString());
const claims = JSON.parse(Buffer.from(p, "base64url").toString());
const proofOk = header.typ === "dpop+jwt" && header.alg === "EdDSA" && header.jwk.kty === "OKP" && claims.htm === "POST" && claims.htu === `${issuer}/token` && s.length > 0
  && await crypto.subtle.verify("Ed25519", keyPair.publicKey, Buffer.from(s, "base64url"), enc.encode(`${h}.${p}`));
const token = await (await fetch(`${issuer}/token`, { method: "POST", headers: { "content-type": "application/json", dpop: proof }, body: JSON.stringify({ grant_type: "authorization_code", code: "stub", code_verifier: verifier, dpop_jkt: jkt }) })).json();
const bind = await (await fetch(`${issuer}/mesh/bind`, { method: "POST", headers: { "content-type": "application/json", authorization: `DPoP ${token.access_token}`, dpop: proof }, body: JSON.stringify({ network: "stub", wg_pub: peer.peerPublicKey }) })).json();

console.log(JSON.stringify({
  ok: true,
  key: { nonExtractable: exportThrows, sshPublicKey: sshPub.slice(0, 30) + "…" },
  certify: { serial: minted.serial, ttlSeconds: minted.valid_before - minted.valid_after, keyId: minted.key_id },
  attachMs: +tAttach.toFixed(1),
  exitCode: code,
  refusals,
  hostPolicy,
  dpop: { pkceChallenge: challenge.slice(0, 12) + "…", jkt, proofVerifies: proofOk, token: token.token_type, bind: bind.binding },
  node: process.version,
}, null, 2));
process.exit(0);
