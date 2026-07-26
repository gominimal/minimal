---
id: "TBD"
title: "S2: russh-over-WSS byte bridge handshake (Worker/DO → getTcpPort → minimald)"
status: in-progress
date: 2026-07-25
budget_hours: 8
actual_hours: 1
progress: "transport-swap half CODE-VERIFIED against tree (russh generic-stream bound + single-swap seam + two-consumer trust split); live handshake + PTY-latency gate still pending a CF deploy"
related:
  - "plan: /home/.claude/plans/look-at-the-lessons-silly-stallman.md (Phase 0, S2; decision: transport = tunnel russh over WSS)"
  - "sibling: norrietaylor/minimal-sessions docs/specs/01-wire-protocol.md, docs/specs/09-ssh-ingress.md"
  - "crates/minimal/src/client.rs:157 (Client::connect — russh over UnixStream today)"
  - "crates/minimald/src/connection.rs:160,296 (is_local / Auth gate)"
tags:
  - cloudflare
  - remote-provider
  - transport
  - russh
  - websocket
  - de-risk
---

# Question

Can the existing russh transport ride a WebSocket tunnel through a Cloudflare
Worker/DO to an in-container `minimald`, with **no change to the wire/RPC/exec
layer**? Concretely:

1. Does a full russh handshake complete over a WS-framed duplex
   `AsyncRead + AsyncWrite` piped `client → Worker → DO → getTcpPort(22).connect()`?
2. Does one `minimald-rpc` oneshot RPC round-trip succeed over it?
3. Does one interactive exec/PTY channel open and stream both directions?
4. What is the added interactive-PTY latency vs the local UDS path?

# Hypothesis

Yes. russh drives any `AsyncRead + AsyncWrite`; `minimald-rpc` carries no
transport deps; the exec channel is transport-agnostic. Only the client's
`connect()` stream construction changes (UnixStream → WS-framed duplex). This
mirrors the existing "minvmd is a UDS↔vsock bridge" indirection with a
"Worker/DO is a WSS↔TCP bridge" one. Latency is dominated by edge RTT, not framing.

# Method

1. Stand up a minimal Worker + Durable Object that: accepts a client WSS,
   `getTcpPort(22).connect()`s the container, and pipes bytes both ways (no
   parsing).
2. Run `minimald` in a CF Container bound to a TCP port (Listener with
   `is_local=false`, see S-trust follow-on — but for S2, auth can stay permissive
   in a throwaway build to isolate the transport question).
3. Client side: wrap the WS as a duplex stream and hand it to
   `russh::client::connect_stream` unchanged; drive a handshake + one oneshot RPC
   + one exec channel.
4. Measure: handshake time, RPC round-trip, and PTY keystroke-echo latency
   (p50/p95) over the tunnel vs a local UDS baseline.

# Gate

**PASS** ⇒ handshake + RPC + exec all succeed AND PTY latency is within an
acceptable interactive budget (record the number) ⇒ transport shape (russh-over-WSS)
confirmed; unblocks P2. **FAIL** ⇒ if russh cannot complete over the framed WS
(e.g. message-boundary or half-close semantics break it), reconsider shape B
(the sibling's SPEC-01 JSON-over-WSS wire) — a much larger client rewrite.

# Findings

## Code-level pre-verification (2026-07-25, local — no deploy)

The transport-swap half of the hypothesis is **CONFIRMED against this tree** short
of the live handshake and latency number. Evidence:

- **russh's stream bound is fully generic.** `russh::client::connect_stream`
  (russh 0.62.3, `Cargo.lock`) is
  `connect_stream<H, R>(config, stream: R, handler) where R: AsyncRead + AsyncWrite
  + Unpin + Send + 'static` (docs.rs, verified verbatim). A `tokio::net::UnixStream`
  satisfies it today; a WS-framed duplex satisfies it identically. Nothing in the
  bound is UDS-specific.
- **The in-process client is a pure stream swap.** `Client::connect`
  (`crates/minimal/src/client.rs:157`) hardcodes `UnixStream::connect(sock_path)`
  (line 162) purely to *produce* the `stream` it hands to `connect_stream` (line
  189). Swapping that one construction for a WSS-tunneled duplex is the entire
  transport change; the handshake/auth/channel code below it is untouched.
- **`minimald-rpc` and the exec channel carry no transport deps** — confirmed in
  prior tree review; the RPC/exec layer rides russh channels, not the raw fd.
- **No consumer bypasses the russh Handle by reaching for the raw fd** — grep of
  the crate finds the only raw-socket uses are UDS *connect/bind* points, never a
  `russh::Channel` sidestep, with one deliberate exception (next bullet).

## Refinement the stub missed: there are TWO transport consumers, with DIFFERENT trust surfaces

`cmd_proxy` (`crates/minimal/src/lib.rs:730`) does **not** use russh at all. It
`UnixStream::into_split()`s and `tokio::io::copy`s raw bytes between our stdio and
the socket (lines 743–757) — it is an SSH `ProxyCommand` shim, where the user's
**external** `ssh`/`git` binary speaks the SSH protocol end-to-end and our process
only shuffles bytes. Consequence for P2's trust model:

| Consumer | SSH endpoint | Who verifies host key / presents credential |
|---|---|---|
| `Client::connect` (RPC, interactive attach) | our in-process russh | **us** — `MinimalClientHandler` (`client.rs:133-142`, `authenticate_none` line 194) |
| `cmd_proxy` (`min`-as-`ProxyCommand`) | the user's own `ssh`/`git` | **the user's** `known_hosts` + keys, outside our Rust |

Both are stream-swappable (hypothesis holds for both), but the plan's "give remote
endpoints a real `russh::client::Handler`" framing covers only the first. The
`cmd_proxy` path's remote trust is the user's ssh client config, so P2 must either
(a) document that the `ProxyCommand` path inherits the user's ssh trust chain, or
(b) surface a provider-scoped `known_hosts`/key the spawned ssh is pointed at.
Either way it is a **second, distinct** conversion, exactly as the plan's "convert
the second transport consumer in lockstep" line warned — but the *reason* is a
trust-surface split, not just a second call site.

## Live-gated remainder (still TBD — requires deploy)

Handshake/RPC/exec success **through a real Worker→DO→`getTcpPort`** bridge, and the
interactive-PTY latency table (tunnel vs UDS, p50/p95). These cannot be produced
from the local sandbox and are the actual PASS/FAIL gate.

# Conclusion

Transport shape (russh-over-WSS) is **code-level confirmed**: the change is a pure
`AsyncRead+AsyncWrite` stream swap in `Client::connect`, wire/RPC/exec untouched, no
fd-level bypass. Two consumers need converting, not one, and they split on trust
surface (in-process russh vs external-ssh `ProxyCommand`). The transport-boundary
risk that could have forced shape B (the sibling's JSON-over-WSS rewrite) is
**retired**; only the live latency budget remains to be measured.

# Action items

- [ ] P2: implement the real `russh::client::Handler` for the in-process path
      (host-key verify vs per-provider `known_hosts`; real client credential).
- [ ] P2: decide and document the `cmd_proxy`/`ProxyCommand` trust story
      (inherit user ssh trust vs provider-scoped `known_hosts`) — track as a
      distinct sub-task, not folded into the Handler work.
- [ ] Live: stand up the throwaway Worker/DO bridge and record the handshake +
      RPC + exec + PTY-latency table (the remaining gate).

# Residual Risks / Live Trial Needed

- Requires live Worker + DO + Container deploy.
- The DO sits in the byte path ⇒ billable-hot and each outbound connection keeps
  the DO alive ~15 min; S2 measures raw feasibility/latency, not the
  keepalive/reconnect-with-state design (that is P4).
- Trust model (host-key verification + client credential + `is_local=false`) is
  deliberately deferred to P2 to isolate the transport question — do NOT ship the
  permissive S2 build.

# Artifacts

_TBD — Worker/DO scaffold, client duplex-stream shim, latency capture._
