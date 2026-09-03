// WebSocket-shaped adapter over the wasm `attach` export, so
// `TerminalPane.astro`'s `connect()` can swap `new WebSocket(url)` for
// `await minSocket(...)` and keep its onopen/onmessage/onclose/send/close
// handling as-is. Untested in a browser yet: written against the wasm-bindgen
// surface in src/web.rs and the page's usage in webapp#735.
//
// Frame mapping, mirroring src/lib/terminal-poc/protocol.ts:
//   - PTY bytes arrive as binary frames (ArrayBuffer) -> onmessage
//   - {t:"attached", ...} / {t:"exit", code} arrive as text frames -> onmessage
//   - send(JSON {t:"input"|"resize"}) is decoded here and turned into
//     write()/resize() calls on the attachment.

import init, { attach } from "./min_core.js";

export async function minSocket({ relayUrl, sessionId, cols, rows, term = "xterm-256color" }) {
  await init();
  const encoder = new TextEncoder();
  const sock = {
    readyState: 0, // CONNECTING
    binaryType: "arraybuffer",
    onopen: null,
    onmessage: null,
    onclose: null,
    onerror: null,
    send(payload) {
      if (typeof payload !== "string") return; // the page only sends text frames
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
      void attachment.close();
    },
  };
  const emit = (data) => sock.onmessage?.({ data });
  const attachment = await attach(
    relayUrl,
    sessionId,
    term,
    cols,
    rows,
    (bytes) => emit(bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength)),
    (code) => {
      sock.readyState = 3; // CLOSED
      if (code !== undefined) emit(JSON.stringify({ t: "exit", code }));
      sock.onclose?.({ code: 1000, reason: "" });
    },
  );
  sock.readyState = 1; // OPEN
  sock.onopen?.({});
  // What the byte-ring backend used to announce; the daemon's session
  // info RPC is where host/ip/startedAt come from once wired.
  emit(JSON.stringify({ t: "attached", cols, rows, replayedBytes: 0, resumed: true, host: "", ip: null, startedAt: Date.now() }));
  return sock;
}
