// Headless smoke test of the built bundle: drives `attach_wg` from Node
// (>= 22, for the global WebSocket) against a running `wg-peer`, exactly as
// the browser adapter would, and checks the attach banner, echo, resize and
// exit. Usage:
//
//   cargo run --example wg-peer -- 127.0.0.1:7691 /tmp/peer.json   # in one shell
//   node js/headless-check.mjs /tmp/peer.json                       # in another
//
// Exit code 0 on success. Prints timings the browser report also wants.

import { readFileSync } from "node:fs";
// MIN_CORE_DIST overrides where the bundle is loaded from (default ../dist/).
const DIST = new URL(process.env.MIN_CORE_DIST ?? "../dist/", import.meta.url);
const { default: init, attach_wg } = await import(new URL("min_core.js", DIST));

// Frame trace (set MIN_CORE_TRACE=1): every WebSocket event and send, so a
// stalled handshake shows where it stalls.
if (process.env.MIN_CORE_TRACE) {
  const Orig = globalThis.WebSocket;
  const t = () => (performance.now() | 0) + "ms";
  globalThis.WebSocket = class extends Orig {
    constructor(...args) {
      super(...args);
      this.addEventListener("open", () => console.error(t(), "ws open"));
      this.addEventListener("message", (e) => console.error(t(), "ws recv", e.data?.byteLength ?? typeof e.data, e.data?.constructor?.name));
      this.addEventListener("close", (e) => console.error(t(), "ws close", e.code, e.reason));
      this.addEventListener("error", () => console.error(t(), "ws error"));
    }
    send(d) {
      console.error(t(), "ws send", d?.byteLength ?? d?.length, d?.constructor?.name);
      return super.send(d);
    }
  };
}

const peer = JSON.parse(readFileSync(process.argv[2] ?? "/tmp/peer.json", "utf8"));
const t0 = performance.now();
await init({ module_or_path: readFileSync(new URL("min_core_bg.wasm", DIST)) });
const tInit = performance.now() - t0;

let buf = "";
let closedWith = null;
const waiters = [];
const check = () => {
  for (let i = waiters.length - 1; i >= 0; i--) {
    const [needle, resolve] = waiters[i];
    if (buf.includes(needle)) {
      waiters.splice(i, 1);
      resolve();
    }
  }
};
const expect = (needle, ms = 10000) =>
  new Promise((resolve, reject) => {
    waiters.push([needle, resolve]);
    check();
    setTimeout(() => reject(new Error(`timeout waiting for ${JSON.stringify(needle)}; got ${JSON.stringify(buf)}`)), ms).unref();
  });
const closed = new Promise((resolve) => {
  globalThis.__onClose = (code) => {
    closedWith = code;
    resolve(code);
  };
});

const t1 = performance.now();
const att = await attach_wg(
  peer.wsUrl, peer.privateKey, peer.peerPublicKey, peer.localIp, peer.peerIp,
  peer.prefixLen ?? 24, peer.sshPort ?? 22,
  "sess-headless", "xterm-256color", 100, 30,
  (bytes) => { buf += new TextDecoder().decode(bytes); check(); },
  (code) => globalThis.__onClose(code),
);
const tAttach = performance.now() - t1;
await expect("attached sess-headless 100x30");
const tBanner = performance.now() - t1;

const t2 = performance.now();
await att.write(new TextEncoder().encode("ping\n"));
await expect("echo ping\n");
const rtt = performance.now() - t2;

await att.resize(132, 40);
await expect("resize 132x40");

const big = "x".repeat(20000) + "\n";
const t3 = performance.now();
await att.write(new TextEncoder().encode(big));
const xs = () => (buf.match(/x/g) ?? []).length;
const tBigDeadline = performance.now() + 15000;
while (xs() < 20000) {
  if (performance.now() > tBigDeadline) throw new Error(`paste incomplete: ${xs()} of 20000 bytes echoed`);
  await new Promise((r) => setTimeout(r, 20));
}
const tBig = performance.now() - t3;

await att.write(new TextEncoder().encode("exit\n"));
const code = await Promise.race([closed, new Promise((_, rej) => setTimeout(() => rej(new Error("no close")), 10000).unref())]);

console.log(JSON.stringify({
  ok: code === 7,
  exitCode: code,
  timingsMs: { instantiate: +tInit.toFixed(1), attachResolved: +tAttach.toFixed(1), wsOpenToBanner: +tBanner.toFixed(1), keystrokeRtt: +rtt.toFixed(1), paste20kb: +tBig.toFixed(1) },
  node: process.version,
}, null, 2));
process.exit(code === 7 ? 0 : 1);
