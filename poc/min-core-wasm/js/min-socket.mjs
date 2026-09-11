// WebSocket-shaped adapters over the wasm exports, so TerminalPane.astro's
// `connect()` can swap `new WebSocket(url)` for `await minSocket(...)` /
// `await minMeshSocket(...)` and keep its handler wiring as-is.
//
// Frame mapping, mirroring src/lib/terminal-poc/protocol.ts:
//   - PTY bytes arrive as binary frames (ArrayBuffer) -> onmessage
//   - {t:"attached", ...} / {t:"exit", code} arrive as text frames -> onmessage
//   - send(JSON {t:"input"|"resize"}) is decoded here and turned into
//     write()/resize() calls on the attachment.
//
// Ordering: the caller assigns `onopen`/`onmessage` only after the awaited
// call returns, so messages that arrive before that are queued and flushed
// when `onmessage` is assigned, and `onopen` fires on a macrotask.

import init, { attach, attach_wg } from "./min_core.js";

function makeSocket() {
  const encoder = new TextEncoder();
  let attachment = null;
  let onmessage = null;
  const queue = [];
  const sock = {
    readyState: 0, // CONNECTING
    binaryType: "arraybuffer",
    onopen: null,
    onclose: null,
    onerror: null,
    send(payload) {
      if (typeof payload !== "string" || !attachment) return; // the page only sends text frames
      let msg;
      try {
        msg = JSON.parse(payload);
      } catch {
        return;
      }
      if (msg.t === "input") void attachment.write(encoder.encode(msg.d));
      else if (msg.t === "resize") void attachment.resize(msg.cols, msg.rows);
    },
    close() {
      void attachment?.close();
    },
  };
  Object.defineProperty(sock, "onmessage", {
    get: () => onmessage,
    set(fn) {
      onmessage = fn;
      if (fn) while (queue.length) fn(queue.shift());
    },
  });
  const emit = (data) => (onmessage ? onmessage({ data }) : queue.push({ data }));
  const onData = (bytes) => emit(bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength));
  const onClose = (code) => {
    sock.readyState = 3; // CLOSED
    if (code !== undefined) emit(JSON.stringify({ t: "exit", code }));
    sock.onclose?.({ code: 1000, reason: "" });
  };
  const opened = (att, attached) => {
    attachment = att;
    sock.readyState = 1; // OPEN
    emit(JSON.stringify({ t: "attached", ...attached }));
    setTimeout(() => sock.onopen?.({}), 0); // after the caller has assigned handlers
    return sock;
  };
  return { sock, onData, onClose, opened };
}

// Plain path (Stage 0): a WebSocket relay to the daemon socket.
export async function minSocket({ relayUrl, sessionId, cols, rows, term = "xterm-256color" }) {
  await init();
  const { onData, onClose, opened } = makeSocket();
  const att = await attach(relayUrl, sessionId, term, cols, rows, onData, onClose);
  // What the byte-ring backend used to announce; the daemon's session info
  // RPC is where host/ip/startedAt come from once wired.
  return opened(att, { cols, rows, replayedBytes: 0, resumed: true, host: "", ip: null, startedAt: Date.now() });
}

// Mesh path (Stage 1b): the tab is a WireGuard node. `peer` is the JSON
// `wg-peer` (later: the daemon / Gatehouse) prints: wsUrl, privateKey,
// peerPublicKey, localIp, peerIp, prefixLen, sshPort.
export async function minMeshSocket({ peer, sessionId, cols, rows, term = "xterm-256color" }) {
  await init();
  const { onData, onClose, opened } = makeSocket();
  const att = await attach_wg(
    peer.wsUrl, peer.privateKey, peer.peerPublicKey, peer.localIp, peer.peerIp,
    peer.prefixLen ?? 24, peer.sshPort ?? 22,
    sessionId, term, cols, rows, onData, onClose,
  );
  return opened(att, { cols, rows, replayedBytes: 0, resumed: true, host: peer.peerIp, ip: peer.peerIp, startedAt: Date.now() });
}

// Stage 2: the same socket shape with `attach_mesh` and an optional `auth`
// block. `peer` is what wg-peer prints (with its `auth` sub-object when run
// with `--auth stub`), `cert` the OpenSSH certificate line from `/certify`,
// `hostCa` the `host_ca` array from `/ssh/ca`, and `sign` the page's
// `(bytes: Uint8Array) => Promise<Uint8Array>` over its WebCrypto key.
export async function minMeshSocketWithAuth({ peer, sessionId, cols, rows, term = "xterm-256color", auth }) {
  const { attach_mesh } = await import("./min_core.js");
  await init();
  const { onData, onClose, opened } = makeSocket();
  const config = {
    wsUrl: peer.wsUrl, privateKey: peer.privateKey, peerPublicKey: peer.peerPublicKey,
    localIp: peer.localIp, peerIp: peer.peerIp, prefixLen: peer.prefixLen ?? 24, sshPort: peer.sshPort ?? 22,
    sessionId, term, cols, rows,
    auth: auth
      ? { username: auth.username, certificate: auth.certificate, hostCa: auth.hostCa, expectedHostPrincipal: auth.expectedHostPrincipal }
      : undefined,
  };
  const att = await attach_mesh(JSON.stringify(config), auth?.sign ?? null, onData, onClose);
  return opened(att, { cols, rows, replayedBytes: 0, resumed: true, host: peer.peerIp, ip: peer.peerIp, startedAt: Date.now() });
}
