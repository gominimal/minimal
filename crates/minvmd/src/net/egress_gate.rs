//! The host-side egress gate (NET-081): per-box, source-addressed egress
//! rules applied **outside the VM**, by the host, before the switch sees a
//! frame.
//!
//! On a VM-backed host the guest's per-tap shuttle relays raw Ethernet frames
//! over the vsock bridge [`crate::vm`] registers. Before this module that
//! bridge pointed straight at gvproxy's switch socket, so the first host-side
//! thing a frame met was the switch itself — a pure L2 datapath that forwards
//! by destination and believes whatever source address a frame carries. The
//! in-guest relay already applies the shared frame verdict, but it runs
//! **inside** the escape boundary: a process that breaks out of a box into the
//! VM controls the daemon that applies it. NET-081 moves the decision outside
//! — the shuttle's vsock port is pointed at the gate's socket instead
//! ([`crate::net::shuttle::resolve_gate_sock`]), and the gate sits between the
//! guest and the switch, deciding every frame against the host-side table of
//! published namespaces ([`crate::box_registry`], NET-138) before anything is
//! written on to the switch.
//!
//! ```text
//!  guest                        libkrun                          host
//!  ┌────────┐   AF_VSOCK   ┌──────────┐    UDS      ┌─────────────┐   UDS   ┌─────────┐
//!  │ shuttle│── CID 2 ───▶ │ vsock    │───────────▶│ egress gate │───────▶│ gvproxy │
//!  └────────┘   raw L2     │ bridge   │  gate sock  │  (NET-081)  │ switch │  (NAT)  │
//!                          └──────────┘             └─────────────┘  sock  └─────────┘
//! ```
//!
//! The gate is not a second TCP/IP stack. It parses nothing above the
//! Ethernet header, and that only to summarize a frame for the shared verdict
//! (`sessions::core::egress` — the same pure decision the in-guest relay
//! applies, made here where nothing inside the VM can change it). It forwards
//! the gvproxy upgrade head verbatim, then relays both ways: guest → switch
//! through the verdict, per source address; switch → guest untouched, since
//! ingress policy is the *target* box's and is decided in the guest — NET-081
//! is an egress requirement.
//!
//! The socket is not the shuttle's alone. gvproxy's switch socket is one
//! listener carrying two protocols, and the guest daemon uses both over the
//! bridged vsock port: the shuttle's `/connect` upgrade, and the plain
//! HTTP/1.1 control verbs (`/services/forwarder/expose`,
//! `/services/forwarder/unexpose`, `/services/dns/add`) it drives its
//! publishes and its zone with — request/response, framed by
//! `Content-Length`, never a frame on the wire. The gate reads the first
//! request head either way, classifies it by its request line's target
//! against an allow-list, and refuses anything else **before forwarding** —
//! because gvproxy hijacks on more than the connect path (`/tunnel` dials
//! an address inside the virtual network and relays bytes), so a head the
//! gate has not classified is a reach, not plumbing. What is classified is
//! relayed by what the head asked for — frames through the verdict, control
//! bytes untouched — and a control connection carries exactly **one**
//! request: the head plus exactly its `Content-Length` body bytes, the
//! daemon's own client's shape, after which the first further guest byte
//! tears the connection down without being written on. gvproxy hijacks a
//! hijacking request however late in the connection's life it arrives, so
//! there being no second request to read is what keeps the gate the only
//! way a frame ever reaches the switch.
//!
//! Fail-closed is the posture. A frame whose source address no published
//! namespace holds never leaves the VM (NET-081's failure case); a frame a
//! published box did not declare is dropped where it stands, silently — a
//! drop is not a reset (NET-062) — with one rate-limited warn line per source
//! address per rule, so a diagnostic bundle's daemon log tail carries what
//! the host is dropping and why without a flood's noise. The table those
//! lines are keyed in is bounded, because the source address a frame is keyed
//! by is the frame's own bytes: a guest flooding distinct spoofed addresses
//! cannot turn the throttling into host-memory growth.

use std::collections::HashMap;
use std::io;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use sessions::core::egress::{self, DropReason, FrameFamily, FrameSummary, FrameVerdict};
use switch::DEFAULT_MTU;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, ReadBuf};
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{UnixListener, UnixStream};
use tokio::task::{JoinHandle, JoinSet};

use crate::box_registry::BoxTable;

/// The HTTP request that upgrades a control-socket connection into a raw
/// frame stream. The guest shuttle writes this head before its first frame;
/// gvproxy hijacks the connection and writes no response. The gate forwards
/// it verbatim — the upgrade is the guest's, and what gvproxy accepts is
/// gvproxy's word.
const CONNECT_REQUEST: &[u8] = b"POST /connect HTTP/1.0\r\nHost: localhost\r\n\r\n";

/// The request path that turns a connection into a raw frame stream. The
/// switch socket is one listener with two protocols on it — the HTTP
/// request/response verbs the guest daemon drives, and the upgrade that
/// hijacks the connection into the shuttle's length-framed L2 stream — and
/// gvproxy hijacks on this path, whatever the method and however late in the
/// connection's life the request arrives
/// (`crates/minimald/src/net/policy.rs` for the verbs,
/// `crates/minimald/src/net/switch.rs` for the upgrade). It is the one
/// hijacking path the gate relays, and it relays it only as a first request:
/// on a frame connection the frames behind it go through the verdict, and on
/// a control connection there is no second request to hide one in.
///
/// The path is the whole of the classification, read off the head's request
/// line: a first request for it is a frame stream, a first request for a verb
/// in [`CONTROL_VERBS`] is a control exchange, and any other first request is
/// refused before forwarding ([`GuestSpeak::of_head`]).
const CONNECT_PATH: &[u8] = b"/connect";

/// The control verbs the gate relays: the guest daemon's own plumbing — the
/// publish and unpublish of a declared ingress port, and the zone-add that
/// gives a box its `*.min.internal` name — and nothing else. gvproxy's switch
/// socket carries other verbs on the same listener, its forwarder listings
/// and its lease, CAM and stats reads among them, and one more hijacking
/// verb beside the connect path: `/tunnel?ip=&port=`, which dials an address
/// inside the virtual network and relays bytes — host-originated TCP to any
/// switch address, with no rule consulted and no frame ever through the
/// gate. None of it is a box's declared traffic, so none of it is forwarded.
/// The list is the daemon's own verbs verbatim, matched exactly on the
/// request line's target: the daemon never speaks another, so a head naming
/// something else is not the daemon, and the guest daemon is the only
/// speaker the gate owes anything to here.
const CONTROL_VERBS: [&[u8]; 3] = [
    b"/services/forwarder/expose",
    b"/services/forwarder/unexpose",
    b"/services/dns/add",
];

/// How much of a control connection's body one read of the splice takes.
/// Control bodies are a few hundred bytes of JSON; the size sets only how
/// many writes the body is relayed in, never what is admitted — the count the
/// gate relays is the head's `Content-Length`, exactly.
const CONTROL_READ: usize = 4 * 1024;

/// Where the upgrade head ends and the frames begin.
const HEAD_END: &[u8] = b"\r\n\r\n";

/// Bound on the bytes read looking for the first request head's end. The heads
/// the gate sees — the shuttle's upgrade and the daemon's control verbs — are
/// a few dozen constant bytes, so a guest still talking past this without
/// ending one is malformed or hostile, and is refused rather than buffered.
const MAX_HEAD: usize = 4 * 1024;

/// Bound on the gate's half of the handshake: dialing the switch it fronts,
/// reading the upgrade head off the guest, and forwarding it. A healthy
/// shuttle writes the head the moment it connects, so one still unfinished
/// this far in is a peer that is wedged, silent, or hostile — and the peer
/// the head comes from lives **inside** the escape boundary this gate exists
/// for, so the host does not wait on it. Bounding the handshake is what
/// releases the host switch connection the dial opened and the relay task
/// holding it, instead of letting a silent guest keep both for the gate's
/// lifetime — the same fail-fast the native relay's `VSOCK_CONNECT_TIMEOUT`
/// gives the connect + `/connect` upgrade from the guest's side
/// (`crates/minimald/src/net/switch.rs`).
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

/// Largest Ethernet frame the gate relays: MTU + 14-byte header + 4-byte
/// 802.1Q VLAN tag — the same bound the in-guest relay reads to, so the two
/// halves of the path agree on what a frame may weigh.
const fn max_frame() -> usize {
    DEFAULT_MTU as usize + 14 + 4
}

/// One drop warning per source address per rule per interval — the cadence the
/// daemon's policy warnings use, so a host's log speaks with one voice.
const DROP_WARN_MIN_INTERVAL: Duration = Duration::from_secs(60);

/// How many distinct `(source, rule)` pairs the limiter keeps a window for —
/// the gate's memory bound on its drop lines. The source address a dropped
/// frame is keyed by is the frame's own bytes, read off the wire, and the
/// guest chooses those: flooding the shuttle with frames from ever-different
/// spoofed addresses would otherwise grow host memory one entry per frame,
/// an amplification against the very path the gate exists to protect. Past
/// the cap, a pair the table holds no window for shares one line per rule
/// ([`DropKey::Overflow`]), so a flood costs at most one line per rule per
/// interval and no memory at all.
///
/// The cap sits far past any honest host's need: the pairs that exist
/// legitimately are the published boxes' few addresses under a closed
/// handful of rules, while more distinct sources dropping within one
/// interval than this is a spoofed flood by shape. Stale windows are pruned
/// before the fallback is taken, so a flood that has ended restores
/// per-source lines within one interval.
const DROP_WARN_MAX_TRACKED_PAIRS: usize = 1024;

/// The rule name for NET-081's failure case: a frame whose source address no
/// published namespace holds. Its own rule, not the lease check's, because
/// the host table has no lease to name — the address simply is not one the
/// host published.
const UNKNOWN_SOURCE_RULE: &str = "egress-unknown-source";

/// The rule name for a request head the gate refuses to relay. Two shapes
/// share it: a request-target outside the gate's allow-list — gvproxy's
/// switch socket carries other verbs there, the `/tunnel` hijack among them —
/// and a control head whose body the gate cannot frame, chunked or split
/// across two disagreeing `Content-Length`s. Neither is the daemon's own
/// client's shape, so the head is refused before anything of it is written
/// on, and the refusal is rate-limited like a frame drop: a guest can attempt
/// it on a fresh connection as cheaply as it can send a frame.
const UNDECLARED_VERB_RULE: &str = "egress-undeclared-verb";

/// The rule name for a control connection spoken past the one request it was
/// allowed — the one reach a control exchange could otherwise buy, since
/// gvproxy hijacks a hijacking request however late in the connection's life
/// it arrives. The gate reads no second request at all: the first byte past
/// the body is refused unread and the connection comes down. Emitted at the
/// same cadence as the frame drops: a guest can attempt it on a fresh
/// connection as cheaply as it can send a frame, and the refusal must not
/// become the flood the frame drops are rate-limited against.
const CONTROL_UPGRADE_RULE: &str = "egress-control-upgrade";

/// What the guest's first request head says it came for: gvproxy's switch
/// socket speaks two protocols on one listener, and the head's request line
/// is where they part ways — or does not, which is itself an answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GuestSpeak {
    /// The connect upgrade: a hijacked connection carrying length-framed
    /// Ethernet frames — the traffic NET-081 exists to gate.
    Frames,
    /// One control request: plain HTTP/1.1 request/response, framed by
    /// `Content-Length`, never a frame on the wire. The body is the only
    /// thing the gate relays past the head, and the only thing a control
    /// connection may say after the head at all.
    Control {
        /// The request's body length in bytes, read from the head's
        /// `Content-Length`: exactly this many bytes are relayed, and the
        /// first one after them is refused.
        body: usize,
    },
}

/// A first request head the gate refuses to relay, and what the refusal line
/// names: `target` is the first line's request-target — or the line's own
/// start, when the line never reached one — so the log can say what was
/// refused, even when it is the guest daemon's own verb with a framing the
/// gate cannot follow.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RefusedHead {
    /// The request-target the refusal names, truncated to
    /// [`MAX_NAMED_TARGET`].
    target: Vec<u8>,
}

/// How much of a refused request's first line the refusal line names: the
/// verbs the gate relays are under thirty bytes, so anything past this is not
/// one of them, and a rate-limited warning is no place to echo a hostile
/// head.
const MAX_NAMED_TARGET: usize = 64;

impl RefusedHead {
    /// Refuses `what` — a request-target, or the line that never reached one.
    fn new(what: &[u8]) -> Self {
        Self {
            target: what.iter().copied().take(MAX_NAMED_TARGET).collect(),
        }
    }
}

impl GuestSpeak {
    /// Classifies a first request head by its request line's target against
    /// the gate's allow-list: [`CONNECT_PATH`] is the frame stream, a verb in
    /// [`CONTROL_VERBS`] is one control request, and anything else — a target
    /// gvproxy can do more with than the gate has classified, a line the gate
    /// cannot read a target from, or a control head with no single numeric
    /// `Content-Length` to relay a body by — is refused **before forwarding**,
    /// because a head the gate has not classified is a reach, not plumbing.
    ///
    /// The target is matched on its path alone: gvproxy hijacks the connect
    /// path whatever the method and whatever the query, so neither is read —
    /// but nothing else about the target is forgiven either. An absolute-form
    /// target, a path with anything before or after the connect path, and a
    /// first line that is not `METHOD SP target SP version` are all refused:
    /// the gate never writes on a head it has not classified, so gvproxy
    /// never holds bytes it can reinterpret.
    fn of_head(head: &[u8]) -> Result<Self, RefusedHead> {
        // The request line is the head's first line, CRLF-framed as the head
        // itself is (the head ends where it does because it carries
        // [`HEAD_END`]), so reading it by LF loses the framing CR, not the
        // line.
        let line = strip_cr(head.split(|&b| b == b'\n').next().unwrap_or(&[]));
        // `METHOD SP request-target SP HTTP-version`: three tokens. The
        // split always yields the first, so the method is stepped over
        // unread — gvproxy ignores it on the connect path, and the daemon's
        // verbs are the target's to name.
        let mut words = line.split(|&b| b == b' ');
        words.next();
        let Some(target) = words.next() else {
            return Err(RefusedHead::new(line));
        };
        if words.next().is_none() || words.next().is_some() {
            // No version, or a fourth word: not a request line the gate can
            // read a target from.
            return Err(RefusedHead::new(line));
        }
        // The query is not part of what gvproxy routes by; the path is.
        let path = target.split(|&b| b == b'?').next().unwrap_or(target);
        if path == CONNECT_PATH {
            return Ok(Self::Frames);
        }
        if !CONTROL_VERBS.contains(&path) {
            return Err(RefusedHead::new(target));
        }
        // A control request is `Content-Length`-framed and the gate relays
        // exactly that many body bytes, so the head must frame one body it
        // can read the end of. The daemon's client always sends one count;
        // a head that frames its body any other way — chunked, or in two
        // disagreeing counts — is not a request the gate can relay exactly.
        match framed_body(head) {
            Some(body) => Ok(Self::Control { body }),
            None => Err(RefusedHead::new(target)),
        }
    }
}

/// The body byte count the head frames its request by, or nothing when the
/// gate cannot frame it: the `Content-Length` the daemon's client sends on
/// every control request (`post_json`, `crates/minimald/src/net/policy.rs`),
/// with an absent count reading as no body the way HTTP itself reads it. A
/// `Transfer-Encoding`, a count that is not one plain decimal number, and two
/// counts that disagree are each a request whose end the gate cannot pin,
/// and each is refused rather than guessed at: the count decides where the
/// request ends and where the bytes the gate must never write on begin.
fn framed_body(head: &[u8]) -> Option<usize> {
    let mut found: Option<usize> = None;
    for line in head.split(|&b| b == b'\n').skip(1) {
        let line = strip_cr(line);
        if line.is_empty() {
            // The head's terminator: the headers are done.
            break;
        }
        let Some(colon) = line.iter().position(|&b| b == b':') else {
            // Not a header the gate reads; gvproxy's own parse of the head
            // decides what it means, and the head was already classified by
            // its target.
            continue;
        };
        let (name, rest) = line.split_at(colon);
        if name.eq_ignore_ascii_case(b"Transfer-Encoding") {
            // Chunked framing is the smuggling shape: the gate relays by a
            // byte count, so a request that will not say one is refused.
            return None;
        }
        if !name.eq_ignore_ascii_case(b"Content-Length") {
            continue;
        }
        let value = rest.strip_prefix(b":")?;
        let count = std::str::from_utf8(value.trim_ascii())
            .ok()?
            .parse::<usize>()
            .ok()?;
        if found.replace(count).is_some() {
            // Two `Content-Length` headers is a smuggling shape, not
            // plumbing: the gate refuses rather than pick one.
            return None;
        }
    }
    // No count named is HTTP's own reading of no body, not a malformed head.
    found.or(Some(0))
}

/// A head line's bytes without the CR its CRLF framing left on it: the gate
/// reads the head's lines by LF, which keeps the framing.
fn strip_cr(line: &[u8]) -> &[u8] {
    match line.split_last() {
        Some((&b'\r', rest)) => rest,
        _ => line,
    }
}

/// How a control connection's guest → switch leg ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ControlEnd {
    /// The guest's side is done — it closed the connection, or errored —
    /// having said nothing past its one request's body.
    GuestClosed,
    /// The guest spoke past its one request's body. The bytes are refused
    /// unread — the gate parses no second request, because gvproxy hijacks a
    /// hijacking request however late in the connection's life it arrives
    /// and the only safe number of further bytes to relay is none.
    SpokePastRequest,
}

/// A running host-side egress gate: the accept loop on the gate socket, plus
/// one relay task per live guest connection, all on the tokio runtime the
/// gate was started on. Dropping the handle stops them — the gate lives and
/// dies with the switch runtime it was started on ([`crate::net`]).
#[derive(Debug)]
#[must_use = "dropping the handle stops the gate and every live relay"]
pub struct EgressGate {
    /// The accept loop; aborting it drops its [`JoinSet`], which aborts every
    /// live relay with it.
    accept: JoinHandle<()>,
}

impl EgressGate {
    /// Binds `gate_sock` and starts deciding every frame the guest's shuttle
    /// sends, against `table`, relaying the admitted ones to the switch
    /// listening on `switch_sock`. Must be called within a tokio runtime.
    ///
    /// The gate socket is the path [`crate::vm`] points the shuttle's vsock
    /// port at; a stale socket file from a previous run must be removed by the
    /// caller first, or the bind fails.
    ///
    /// # Errors
    ///
    /// Returns the I/O error if the gate socket cannot be bound.
    pub fn spawn(gate_sock: PathBuf, switch_sock: PathBuf, table: BoxTable) -> io::Result<Self> {
        let listener = UnixListener::bind(&gate_sock)?;
        tracing::info!(
            gate_socket = %gate_sock.display(),
            switch_socket = %switch_sock.display(),
            "host-side egress gate listening",
        );
        // One limiter for the whole gate: a guest that reconnects must not
        // reset the rate window its drops are counted in.
        let limiter = Arc::new(DropLimiter::new());
        Ok(Self {
            accept: tokio::spawn(accept_loop(listener, switch_sock, table, limiter)),
        })
    }
}

impl Drop for EgressGate {
    fn drop(&mut self) {
        // A gate that is gone must not keep deciding frames. Aborting the
        // accept loop drops its JoinSet, which aborts every live relay.
        self.accept.abort();
    }
}

/// Accepts guest connections on the bound listener and gives each one a relay
/// task, held in a [`JoinSet`] this loop owns: aborting the loop — what the
/// [`EgressGate`] handle's `Drop` does — aborts every relay with it.
async fn accept_loop(
    listener: UnixListener,
    switch_sock: PathBuf,
    table: BoxTable,
    limiter: Arc<DropLimiter>,
) {
    let mut relays = JoinSet::new();
    loop {
        match listener.accept().await {
            Ok((guest, _)) => {
                relays.spawn(serve_connection(
                    guest,
                    switch_sock.clone(),
                    table.clone(),
                    Arc::clone(&limiter),
                    HANDSHAKE_TIMEOUT,
                ));
                // Reap the finished so a long-lived gate accumulates no
                // handles for connections long gone.
                while relays.try_join_next().is_some() {}
            }
            Err(error) => {
                // Fail closed, and say so: a gate that cannot accept cannot be
                // bypassed — the guest's connect fails and its relay reports
                // no egress, the same posture as a host gvproxy that never
                // came up.
                tracing::warn!(%error, "egress gate accept failed; the gate has stopped");
                return;
            }
        }
    }
}

/// Serves one guest connection end to end: dial the switch this gate fronts,
/// classify the request head the guest wrote, forward the head if — and only
/// if — the gate relays what it asks for, then relay by what that head asked
/// for: frames through the verdict, control bytes untouched, for as long as
/// the connection lives, until the guest or the switch goes away.
///
/// `handshake_timeout` bounds everything up to and including the forwarded
/// head, and, on a control connection, the drain of the answer that follows
/// the request's end. It is a parameter only so a test can shrink it; every
/// caller outside this module's tests reaches a connection through
/// [`accept_loop`], which passes [`HANDSHAKE_TIMEOUT`].
async fn serve_connection(
    mut guest: UnixStream,
    switch_sock: PathBuf,
    table: BoxTable,
    limiter: Arc<DropLimiter>,
    handshake_timeout: Duration,
) {
    // The handshake is bounded front to back: the guest is the untrusted side
    // here, so a peer that connects and then sends nothing — or a head it
    // never ends — is refused within the bound and the host switch connection
    // the dial opened comes down with it, rather than either being held for
    // the gate's lifetime.
    let handshake = async {
        // Fail closed before anything else: with no switch to relay into
        // there is no egress either way, but the guest gets a closed
        // connection rather than a silent one.
        let mut switch = match UnixStream::connect(&switch_sock).await {
            Ok(switch) => switch,
            Err(error) => {
                tracing::warn!(
                    %error,
                    switch_socket = %switch_sock.display(),
                    "egress gate could not reach the switch; refusing the guest connection"
                );
                return Err(());
            }
        };
        let (head, carry) = match read_request_head(&mut guest).await {
            Ok(pair) => pair,
            Err(error) => {
                tracing::warn!(
                    %error,
                    "egress gate could not read the request head from the guest"
                );
                return Err(());
            }
        };
        // The head is classified before a byte of it is written on: a target
        // the gate has not classified — the `/tunnel` hijack, a listing, a
        // shape the gate cannot frame — never reaches the switch at all.
        let speak = match GuestSpeak::of_head(&head) {
            Ok(speak) => speak,
            Err(refused) => {
                refuse_head(&limiter, &refused);
                return Err(());
            }
        };
        if let Err(error) = switch.write_all(&head).await {
            tracing::warn!(%error, "egress gate could not forward the request head");
            return Err(());
        }
        Ok((switch, carry, speak))
    };
    let (switch, carry, speak) = match tokio::time::timeout(handshake_timeout, handshake).await {
        Ok(Ok(triple)) => triple,
        // Whichever step failed has already said why; the connection is
        // refused either way.
        Ok(Err(())) => return,
        Err(_) => {
            tracing::warn!(
                handshake_timeout = ?handshake_timeout,
                "egress gate handshake timed out; refusing the guest connection"
            );
            return;
        }
    };
    let (switch_rx, switch_tx) = switch.into_split();
    let (guest_rx, guest_tx) = guest.into_split();
    match speak {
        GuestSpeak::Frames => {
            relay_frames(
                Prefixed::new(carry, guest_rx),
                switch_tx,
                switch_rx,
                guest_tx,
                table,
                limiter,
            )
            .await;
        }
        GuestSpeak::Control { body } => {
            relay_control(
                Prefixed::new(carry, guest_rx),
                switch_tx,
                switch_rx,
                guest_tx,
                body,
                limiter,
                handshake_timeout,
            )
            .await;
        }
    }
}

/// Refuses a first request head, at the frame drops' cadence: a guest can
/// attempt an off-list request on a fresh connection as cheaply as it can
/// send a frame, so the refusal must not become a flood. Nothing of the head
/// is written on — gvproxy never sees the request — and the connection's
/// halves come down with the return.
fn refuse_head(limiter: &DropLimiter, refused: &RefusedHead) {
    if limiter.should_warn_at(None, UNDECLARED_VERB_RULE, Instant::now()) != WarnDecision::Silent {
        tracing::warn!(
            rule_matched = UNDECLARED_VERB_RULE,
            request_target = %String::from_utf8_lossy(&refused.target),
            "refused a request head the egress gate does not relay",
        );
    }
}

/// guest ↔ switch on an upgraded connection: egress (guest → switch) through
/// the frame verdict, per source address; ingress (switch → guest) untouched
/// and un-parsed — the gate's job is the egress direction, and what a box may
/// receive is the target's ingress policy, decided in the guest where its
/// declarations are enforced.
async fn relay_frames(
    guest: Prefixed<OwnedReadHalf>,
    switch_tx: OwnedWriteHalf,
    switch_rx: OwnedReadHalf,
    guest_tx: OwnedWriteHalf,
    table: BoxTable,
    limiter: Arc<DropLimiter>,
) {
    let mut ingress = tokio::spawn(copy_switch_to_guest(switch_rx, guest_tx));
    let egress = relay_guest_to_switch(guest, switch_tx, table, limiter);
    tokio::pin!(egress);
    // The two legs race, because neither can see the other's end. The egress
    // leg blocks on the guest, which has no reason to speak while it is idle,
    // so it has no way to learn the switch hung up this one connection's end
    // — the per-connection close a switch makes without the process exit the
    // supervisor catches — and would otherwise hold the relay task, the gate's
    // dial, and the switch write half open until the guest's next frame came
    // and failed to write. The ingress leg ending is the only thing on this
    // side that knows, so whichever leg ends first takes the relay down with
    // it.
    tokio::select! {
        result = &mut egress => match result {
            // The guest closed its side: the shuttle reconnects per boot and
            // drops the connection at teardown.
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {}
            Err(error) => {
                tracing::warn!(%error, "egress gate relay ended on an error");
            }
        },
        result = &mut ingress => match result {
            // The switch closed its side of the connection while the guest was
            // still on it: the guest's egress is down, so say so — the guest
            // has nothing else to tell it why — before the relay comes off.
            Ok(Ok(())) => tracing::warn!(
                "the switch closed its side of the connection; the egress gate \
                 relay is down for it"
            ),
            Ok(Err(error)) if error.kind() == io::ErrorKind::UnexpectedEof => {}
            Ok(Err(error)) => {
                tracing::warn!(%error, "egress gate ingress leg ended on an error");
            }
            Err(error) => {
                tracing::warn!(%error, "egress gate ingress leg ended");
            }
        },
    }
    // The leg that lost the race is torn down with the relay, not left to
    // hold what the guest or the switch end of it was holding.
    ingress.abort();
}

/// One control request on a connection: the head is already forwarded, the
/// gate relays its `Content-Length` body — `body` bytes — verbatim, and
/// nothing past it. The daemon's own client speaks one request per
/// connection and closes from its side once the answer is read (`post_json`,
/// `crates/minimald/src/net/policy.rs`), so one request is all the gate ever
/// relays, and the first guest byte past the body is refused unread rather
/// than parsed: gvproxy hijacks a hijacking request however late in a
/// connection's life it arrives, and there being no second request to read
/// is what leaves nothing for an upgrade to hide in.
///
/// The legs race, because neither can see the other's end. The request leg
/// blocks on the guest, which has no reason to speak while it is idle waiting
/// for the response, so it has no way to learn the switch hung up this one
/// connection's end — the per-connection close a keep-alive control channel
/// makes without the process exit the supervisor catches, the same close
/// [`relay_frames`] races its legs for — and would otherwise hold the relay
/// task, the gate's dial, and both socket halves open until the guest next
/// spoke. The response leg ending is the only thing on this side that knows,
/// so whichever leg ends first takes the relay down with it.
///
/// Whichever way the request leg ends, the exchange's answer is still owed:
/// the switch's side is half-closed, so gvproxy sees the request's end and
/// answers the one request it was given — refused or not, the guest made a
/// request the gate relayed, and dropping its answer in flight would punish
/// nothing but the guest's own daemon — and the response is drained before
/// the relay comes off, bounded by `drain_timeout` — the same bound the
/// handshake reads under — so a switch that will neither answer nor die holds
/// no gate task and no socket past it.
async fn relay_control(
    guest: Prefixed<OwnedReadHalf>,
    switch: OwnedWriteHalf,
    switch_rx: OwnedReadHalf,
    guest_tx: OwnedWriteHalf,
    body: usize,
    limiter: Arc<DropLimiter>,
    drain_timeout: Duration,
) {
    let mut response = tokio::spawn(copy_switch_to_guest(switch_rx, guest_tx));
    let splice = splice_control(guest, switch, body);
    tokio::pin!(splice);
    tokio::select! {
        (end, mut switch) = &mut splice => match end {
            ControlEnd::GuestClosed => {
                finish_control(&mut response, &mut switch, drain_timeout).await;
            }
            ControlEnd::SpokePastRequest => {
                // Refused, at the frame drops' cadence: a guest can attempt
                // this on a fresh connection as cheaply as it can send a
                // frame, and the refusal must not become the flood.
                if limiter.should_warn_at(None, CONTROL_UPGRADE_RULE, Instant::now())
                    != WarnDecision::Silent
                {
                    tracing::warn!(
                        rule_matched = CONTROL_UPGRADE_RULE,
                        "a control connection was spoken past its one request; \
                         the egress gate tore it down",
                    );
                }
                // The answer to the request that *was* relayed is still
                // drained: half-close the switch's side and let gvproxy
                // finish, rather than aborting the response leg and dropping
                // an answer mid-flight.
                finish_control(&mut response, &mut switch, drain_timeout).await;
            }
        },
        result = &mut response => match result {
            // The switch closed its side of the connection while the guest was
            // still on it: no answer is coming, so the relay — and the dial and
            // both socket halves it holds — comes down now, with a line saying
            // which leg ended, rather than waiting on an idle guest.
            Ok(Ok(())) => tracing::warn!(
                "the switch closed its side of the control connection; the \
                 egress gate relay is down for it"
            ),
            Ok(Err(error)) => {
                tracing::warn!(%error, "egress gate control response leg ended on an error");
            }
            Err(error) => {
                tracing::warn!(%error, "egress gate control response leg ended");
            }
        },
    }
}

/// Ends a control connection whose request leg finished: half-close the
/// switch's side, so gvproxy sees the request's end and answers the one
/// request it was given, then drain the answer to the guest, bounded by
/// `drain_timeout`. The bound is what releases the gate's task and the socket
/// halves it holds when a switch will neither answer nor die: the daemon is
/// unaffected either way, but the gate must not outlive the connection on a
/// switch that is not going to speak again.
async fn finish_control(
    response: &mut JoinHandle<io::Result<()>>,
    switch: &mut OwnedWriteHalf,
    drain_timeout: Duration,
) {
    if let Err(error) = switch.shutdown().await {
        tracing::warn!(
            %error,
            "egress gate could not close the switch's side of a control connection"
        );
    }
    match tokio::time::timeout(drain_timeout, &mut *response).await {
        Ok(Ok(Ok(()))) => {}
        Ok(Ok(Err(error))) => {
            tracing::warn!(%error, "egress gate control response leg ended on an error");
        }
        Ok(Err(error)) => {
            tracing::warn!(%error, "egress gate control response leg ended");
        }
        Err(_) => {
            // The switch took the request and said nothing back for the
            // whole bound: stop waiting on it, so the relay — and the dial
            // and both socket halves it holds — comes down now.
            response.abort();
            tracing::warn!(
                drain_timeout = ?drain_timeout,
                "gvproxy did not answer a control request within the bound; \
                 the egress gate relay is down for it"
            );
        }
    }
}

/// Relays a control connection's request to the switch verbatim: exactly
/// `body` bytes — the head's `Content-Length` — however many reads they
/// arrive in, and then the leg's end. A guest that closes or errors is done
/// speaking ([`ControlEnd::GuestClosed`]); a guest that says anything more
/// has spoken past its one request ([`ControlEnd::SpokePastRequest`]), and
/// those bytes are refused **unread**: the gate parses no second request,
/// because gvproxy hijacks a hijacking request however late in the
/// connection's life it arrives, and the only safe number of further bytes
/// to relay is none. The switch half comes back out beside the leg's end, so
/// its caller can half-close the switch's side once the request is spoken —
/// the half is the splice's to write on, not its caller's to hold while the
/// splice runs.
///
/// The body is never parsed, and not only because it is the guest daemon's
/// own plumbing — a `Content-Length`-framed JSON blob, and a control exchange
/// the gate mangled would leave the daemon's publishes failing and its zone
/// never coming up — but because its content is not the gate's to read: the
/// zone-add carries the session's name, and a session name may legally hold
/// the bytes of the connect path (`fix/connection-leak`), so relaying by
/// framing rather than by content is what keeps a legitimate body legitimate.
#[expect(
    clippy::indexing_slicing,
    reason = "every slice is bounded by the `want` the loop computed and the `n` a read reported"
)]
async fn splice_control(
    mut guest: Prefixed<OwnedReadHalf>,
    mut switch: OwnedWriteHalf,
    body: usize,
) -> (ControlEnd, OwnedWriteHalf) {
    let mut remaining = body;
    let mut chunk = vec![0u8; CONTROL_READ];
    while remaining > 0 {
        // One read takes at most what the body still owes, so no read ever
        // holds a byte of what follows it: that is not the gate's to relay.
        let want = remaining.min(chunk.len());
        let n = match guest.read(&mut chunk[..want]).await {
            // The guest's side is done mid-body; nothing is held back, so
            // there is nothing left to flush.
            Ok(0) => return (ControlEnd::GuestClosed, switch),
            Ok(n) => n,
            Err(error) => {
                tracing::warn!(%error, "egress gate control leg ended on an error");
                return (ControlEnd::GuestClosed, switch);
            }
        };
        if let Err(error) = switch.write_all(&chunk[..n]).await {
            tracing::warn!(%error, "egress gate control leg ended on an error");
            return (ControlEnd::GuestClosed, switch);
        }
        remaining -= n;
    }
    // The body is spoken. One request per connection: the next byte —
    // whatever it is, and the gate does not read what it would be — ends
    // the leg as spoken-past, and is never written on.
    let mut probe = [0u8; 1];
    match guest.read(&mut probe).await {
        Ok(0) => (ControlEnd::GuestClosed, switch),
        Ok(_) => (ControlEnd::SpokePastRequest, switch),
        Err(error) => {
            tracing::warn!(%error, "egress gate control leg ended on an error");
            (ControlEnd::GuestClosed, switch)
        }
    }
}

/// switch → guest, untouched. The gate applies no ingress policy and parses
/// nothing on this leg — bytes flow as they came, frames included.
async fn copy_switch_to_guest(
    mut switch: OwnedReadHalf,
    mut guest: OwnedWriteHalf,
) -> io::Result<()> {
    tokio::io::copy(&mut switch, &mut guest).await.map(|_| ())
}

/// guest → switch: read one length-framed Ethernet frame, decide it against
/// the host-side table ([`gate_verdict`]), and write the frame on only when
/// it is admitted. A dropped frame is simply not written on — nothing is sent
/// back toward the guest either; a drop is not a reset (NET-062) — and its
/// class says so once per source address per rule per interval, so a flood
/// inside the VM produces a steady, readable account of what the host is
/// dropping rather than a log flood.
#[expect(
    clippy::indexing_slicing,
    reason = "every `frame[..n]` is bounded by the `n > frame.len()` rejection above"
)]
async fn relay_guest_to_switch(
    mut guest: Prefixed<OwnedReadHalf>,
    mut switch: OwnedWriteHalf,
    table: BoxTable,
    limiter: Arc<DropLimiter>,
) -> io::Result<()> {
    let mut len_buf = [0u8; 2];
    let mut frame = vec![0u8; max_frame()];
    loop {
        match guest.read_exact(&mut len_buf).await {
            // The count is the buffer's length by construction; only the
            // error half carries information.
            Ok(_) => {}
            // A clean close of the guest ends the relay without error.
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e),
        }
        let n = u16::from_le_bytes(len_buf) as usize;
        if n == 0 {
            // A zero-length claim carries no frame to decide; skip the claim
            // rather than read past it.
            continue;
        }
        // Trust nothing the guest claims about length: a frame past the
        // MTU-derived maximum would overrun the buffer and points at a
        // malformed or hostile peer, so refuse it rather than size an
        // allocation to it. The connection comes down — the gate fails
        // closed, never forward.
        if n > frame.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("guest frame length {n} exceeds max {}", frame.len()),
            ));
        }
        guest.read_exact(&mut frame[..n]).await?;
        let summary = egress::summarize(&frame[..n]);
        match gate_verdict(&summary, &table) {
            Ok(()) => {
                // One combined write keeps the length prefix and the frame
                // together even if the switch closes between two writes.
                let mut framed = Vec::with_capacity(2 + n);
                framed.extend_from_slice(&(n as u16).to_le_bytes());
                framed.extend_from_slice(&frame[..n]);
                switch.write_all(&framed).await?;
            }
            Err(dropped) => {
                limiter.emit(summary.source(), dropped.rule());
            }
        }
    }
}

/// The gate's admit-or-drop decision for one frame summary against the
/// host-side table (NET-081): pure — a function of the summary and the table,
/// nothing else — and deliberately separate from the relay loop that applies
/// it, the same discipline the shared verdict keeps.
///
/// The frame's source address is the whole of the routing: the published
/// namespace that holds it supplies the rules its frames are decided by, and
/// an address no namespace holds drops the frame outright, before any rule is
/// consulted — the host table is the authority on which addresses exist at
/// all, so a made-up or stolen one is refused, not matched. Families that
/// carry no readable source address (IPv6, undeclared ethertypes, truncated
/// frames) never reach the table: the shared verdict's own family drops
/// decide them, under any rules, fail-closed.
fn gate_verdict(summary: &FrameSummary, table: &BoxTable) -> Result<(), GateDrop> {
    let Some(src) = summary.source() else {
        return Err(GateDrop::Verdict(family_drop(summary.family())));
    };
    // NET-081's failure case: an address no published namespace holds never
    // leaves the VM.
    let Some(record) = table.by_source(src) else {
        return Err(GateDrop::UnknownSource { src });
    };
    // The shared verdict, unchanged, against the namespace's own compiled
    // rules — the same decision the in-guest relay makes, now made outside
    // where nothing inside can change it.
    match egress::verdict(summary, record.egress()) {
        FrameVerdict::Admit => Ok(()),
        FrameVerdict::Drop(reason) => Err(GateDrop::Verdict(reason)),
    }
}

/// Why the gate dropped a frame: the shared verdict's reason, or the one class
/// the host table adds — a source address no published namespace holds
/// (NET-081's failure case).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GateDrop {
    /// The shared frame verdict dropped it: the namespace's own rules, its
    /// lease check, or its family.
    Verdict(DropReason),
    /// The frame's source address belongs to no published namespace.
    UnknownSource {
        /// The source address no namespace holds.
        src: [u8; 4],
    },
}

impl GateDrop {
    /// The rule that dropped the frame: the rate-limit key and the warning's
    /// `rule_matched` field.
    fn rule(&self) -> &'static str {
        match self {
            Self::Verdict(reason) => reason.rule(),
            Self::UnknownSource { .. } => UNKNOWN_SOURCE_RULE,
        }
    }
}

/// The shared verdict's family drop for a frame that carries no readable
/// source: the families decided without rules, and the fail-closed answer for
/// an arm the summarizer's contract makes unreachable (an ARP or IPv4 frame
/// always carries a source, so one without is truncated).
fn family_drop(family: FrameFamily) -> DropReason {
    match family {
        FrameFamily::Ipv6 => DropReason::Ipv6,
        FrameFamily::UndeclaredFamily(ethertype) => DropReason::UndeclaredFamily(ethertype),
        FrameFamily::Truncated | FrameFamily::Arp | FrameFamily::Ipv4 => DropReason::Truncated,
    }
}

/// The rate-limit key: a dropped frame's source address under the rule that
/// dropped it — `None` for a frame with no readable source — or, past
/// [`DROP_WARN_MAX_TRACKED_PAIRS`], the rule alone.
#[derive(Debug, Hash, PartialEq, Eq)]
enum DropKey {
    /// One source address under one rule: the two things the drop line names.
    Source(Option<[u8; 4]>, &'static str),
    /// The rule's shared window, which every pair the table held no room for
    /// is folded into.
    Overflow(&'static str),
}

/// What the limiter decided for one dropped frame: whether a warning fires,
/// and which window it fires under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WarnDecision {
    /// The pair's own window fired: emit the line naming its source.
    Named,
    /// The pair table is full of live windows, so the rule's shared window
    /// fired instead: emit the flood line, naming no source.
    Overflow,
    /// A window fired inside the interval: emit nothing.
    Silent,
}

/// The gate's rate limiter: one drop warning per source address per rule per
/// [`DROP_WARN_MIN_INTERVAL`], keyed by the two things the drop line names.
/// Keyed per source and per rule both, so one address's flood neither silences
/// another's single drop nor merges two rules into one line.
///
/// The window table is bounded at [`DROP_WARN_MAX_TRACKED_PAIRS`] — the
/// source address it keys by is the frame's own bytes, chosen by the guest,
/// and the guest is the side this gate exists to contain — so the throttling
/// cannot be turned into host-memory growth.
#[derive(Debug, Default)]
struct DropLimiter {
    last: Mutex<HashMap<DropKey, Instant>>,
}

impl DropLimiter {
    /// A fresh limiter that has never emitted for any source or rule.
    fn new() -> Self {
        Self::default()
    }

    /// Whether the drop of `src` under `rule` warns at `now`, and which
    /// window the warning comes under, recording `now` in that window when
    /// one fires. Split from [`emit`](Self::emit) so the rate-limit decision
    /// is testable without a clock or a `tracing` subscriber.
    fn should_warn_at(
        &self,
        src: Option<[u8; 4]>,
        rule: &'static str,
        now: Instant,
    ) -> WarnDecision {
        let mut last = self
            .last
            .lock()
            .expect("the limiter's lock is held only across this lookup, never across a panic");
        let key = DropKey::Source(src, rule);
        if let Some(prev) = last.get(&key)
            && now.duration_since(*prev) < DROP_WARN_MIN_INTERVAL
        {
            return WarnDecision::Silent;
        }
        if last.len() >= DROP_WARN_MAX_TRACKED_PAIRS {
            // The table is at its bound. Drop the windows that have gone
            // stale — their pairs would fire afresh on re-insertion anyway —
            // before folding this one into a shared line: a flood that has
            // ended must not leave honest sources unnamed forever after.
            last.retain(|_, at| now.duration_since(*at) < DROP_WARN_MIN_INTERVAL);
        }
        if last.len() < DROP_WARN_MAX_TRACKED_PAIRS {
            last.insert(key, now);
            return WarnDecision::Named;
        }
        // Still full: every window is live, so more distinct sources are
        // dropping within this interval than the table holds — a spoofed
        // flood by shape. One shared window per rule, so the flood costs no
        // memory and at most one line per rule per interval.
        match last.get(&DropKey::Overflow(rule)) {
            Some(prev) if now.duration_since(*prev) < DROP_WARN_MIN_INTERVAL => {
                WarnDecision::Silent
            }
            _ => {
                last.insert(DropKey::Overflow(rule), now);
                WarnDecision::Overflow
            }
        }
    }

    /// Emits the drop warning for one dropped frame if the rate limit allows:
    /// the source address the frame carried — `none` when the frame carried
    /// none to read, as for an IPv6 or truncated drop — and the rule that
    /// dropped it, the two fields NET-081's observability asks for; or, when
    /// more distinct sources are dropping than the table keeps windows for,
    /// one line per rule naming the flood instead. Returns whether a line
    /// was written.
    fn emit(&self, src: Option<[u8; 4]>, rule: &'static str) -> bool {
        match self.should_warn_at(src, rule, Instant::now()) {
            WarnDecision::Silent => false,
            WarnDecision::Named => {
                let source =
                    src.map_or_else(|| "none".to_string(), |src| Ipv4Addr::from(src).to_string());
                tracing::warn!(
                    source = %source,
                    rule_matched = rule,
                    "dropped a frame leaving the VM at the host-side egress gate",
                );
                true
            }
            WarnDecision::Overflow => {
                tracing::warn!(
                    rule_matched = rule,
                    "dropped frames from more distinct source addresses than the gate \
                     keeps a window per source for; one line per rule covers the rest",
                );
                true
            }
        }
    }
}

/// Reads the head of the guest's first request — through the first
/// [`HEAD_END`] — returning it and any bytes read past it: one `read` can
/// carry the head and what follows it together, and those bytes belong to
/// whichever protocol the head names — the upgrade's first frames, or a
/// control request's body — so the relay must not lose them.
///
/// The head is read for both protocols the switch socket speaks, not only the
/// upgrade: what it asks for is what picks the relay ([`GuestSpeak`]) — and
/// decides whether the gate forwards it at all.
///
/// # Errors
///
/// Returns the I/O error if the guest closes before the head ends, or
/// [`io::ErrorKind::InvalidData`] when the head exceeds [`MAX_HEAD`] without
/// ending — a guest that never ends its first request is refused, not
/// buffered.
async fn read_request_head(guest: &mut UnixStream) -> io::Result<(Vec<u8>, Vec<u8>)> {
    let mut head = Vec::with_capacity(CONNECT_REQUEST.len());
    loop {
        let n = guest.read_buf(&mut head).await?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "guest closed the connection before the switch upgrade head ended",
            ));
        }
        if let Some(end) = find_subslice(&head, HEAD_END) {
            let carry = head.split_off(end + HEAD_END.len());
            return Ok((head, carry));
        }
        if head.len() > MAX_HEAD {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("switch upgrade head exceeded {MAX_HEAD} bytes without ending"),
            ));
        }
    }
}

/// Where `needle` first appears in `hay`, if it does: a small `windows` scan,
/// run once per connection over a head the protocol keeps at a few dozen
/// bytes.
fn find_subslice(hay: &[u8], needle: &[u8]) -> Option<usize> {
    // An empty needle has no position, and `windows` takes a non-zero size.
    if needle.is_empty() {
        return None;
    }
    hay.windows(needle.len())
        .position(|window| window == needle)
}

/// A reader that yields `carry` first, then the wrapped stream: the bytes a
/// single `read` returned past the end of the first request head — the start of
/// the frame stream on an upgraded connection, or of the request's body on a
/// control one — replayed before the socket is read, so nothing is lost to the
/// head's read.
struct Prefixed<R> {
    carry: Vec<u8>,
    pos: usize,
    inner: R,
}

impl<R> Prefixed<R> {
    fn new(carry: Vec<u8>, inner: R) -> Self {
        Self {
            carry,
            pos: 0,
            inner,
        }
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for Prefixed<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.pos < this.carry.len() {
            let n = (this.carry.len() - this.pos).min(buf.remaining());
            #[expect(
                clippy::indexing_slicing,
                reason = "n is the smaller of the carry's remainder and the buffer's spare capacity"
            )]
            buf.put_slice(&this.carry[this.pos..this.pos + n]);
            this.pos += n;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

/// The stand-in guest + switch harness the NET-081 and NET-138 proof tests
/// share: one gate over a stand-in switch, with a "guest" end to write frames
/// from and the switch's accepted end to read only what the gate let through.
#[cfg(test)]
pub(crate) mod test_support {
    use std::io;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use tempfile::TempDir;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{UnixListener, UnixStream};
    use tracing_subscriber::fmt::MakeWriter;

    use super::{CONNECT_REQUEST, EgressGate};
    use crate::box_registry::BoxRegistry;

    /// How long the harness waits for a frame or a log line before calling
    /// the test failed: far past any healthy gate decision on a local socket,
    /// short of nextest's slow-timeout.
    pub(crate) const DEADLINE: Duration = Duration::from_secs(5);
    /// How long the switch end must then stay silent for a test to call a
    /// frame dropped: the gate decides in order, so bytes arriving after this
    /// mean something did slip through.
    pub(crate) const QUIET: Duration = Duration::from_millis(150);

    /// A `MakeWriter` accumulating everything written into a shared buffer,
    /// so a test can assert on the drop lines the gate emits.
    #[derive(Clone, Default)]
    pub(crate) struct CaptureWriter(pub(crate) Arc<Mutex<Vec<u8>>>);

    impl CaptureWriter {
        /// The captured log so far.
        pub(crate) fn contents(&self) -> String {
            let captured = self
                .0
                .lock()
                .expect("the capture's lock is held only across this read")
                .clone();
            String::from_utf8(captured).expect("tracing writes UTF-8")
        }
    }

    impl io::Write for CaptureWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0
                .lock()
                .expect("the capture's lock is held only across this append")
                .extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl MakeWriter<'_> for CaptureWriter {
        type Writer = CaptureWriter;
        fn make_writer(&self) -> Self::Writer {
            self.clone()
        }
    }

    /// One gate over a stand-in switch. `guest` is the end that plays the
    /// guest shuttle — frames written here are decided by the gate;
    /// `switch` is the stand-in switch's accepted end, which reads only what
    /// the gate admitted; `log` captures what the gate has said; `table` is
    /// the gate's own view of the registry.
    pub(crate) struct GateHarness {
        /// The gate under test. Declared first so it drops first, before the
        /// sockets' directory below it goes away. Underscore-named: it is
        /// held for its lifetime, never read.
        pub(crate) _gate: EgressGate,
        /// The guest-shuttle stand-in.
        pub(crate) guest: UnixStream,
        /// The switch stand-in: reads only what the gate admitted.
        pub(crate) switch: UnixStream,
        /// The captured `tracing` output of this test's thread.
        pub(crate) log: CaptureWriter,
        /// The gate's own view of the registry: the read-only lookup surface.
        pub(crate) table: crate::box_registry::BoxTable,
        /// Keeps the sockets' directory alive for the gate's lifetime.
        /// Underscore-named: held for its `Drop`, never read.
        pub(crate) _dir: TempDir,
        /// Keeps the thread-local `tracing` capture installed for the gate's
        /// lifetime. Underscore-named: held for its `Drop`, never read.
        pub(crate) _guard: tracing::subscriber::DefaultGuard,
    }

    /// Brings up one gate over a stand-in switch with the guest's connection
    /// accepted and the gate's dial of the switch taken off the accept queue,
    /// but the upgrade head not yet spoken: the harness every test that drives
    /// the handshake itself builds on. [`gate_over`] and [`gate_over_with`]
    /// complete the handshake before returning; a test that refuses a guest
    /// **mid**-handshake — a head that never ends — starts here instead,
    /// because no head is ever forwarded for the switch end to read back.
    ///
    /// The guest's connect plays libkrun's vsock bridge dialing the gate's
    /// socket, so what the guest writes next meets a gate already holding the
    /// switch connection it will relay into.
    pub(crate) async fn gate_connected(registry: BoxRegistry) -> GateHarness {
        let dir = TempDir::new().expect("a tempdir is creatable");
        let switch_sock = dir.path().join("gvproxy-switch.sock");
        let gate_sock = dir.path().join("gvproxy-gate.sock");
        // The stand-in switch: a listener the gate's connection task dials.
        let listener = UnixListener::bind(&switch_sock).expect("binding the stand-in switch");

        // Capture this thread's tracing output before the gate starts, so its
        // drop lines are assertable. The gate runs on this test's
        // current-thread runtime, so the thread-local default applies to its
        // tasks too.
        let log = CaptureWriter::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(log.clone())
            .with_ansi(false)
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);

        let gate = EgressGate::spawn(gate_sock.clone(), switch_sock.clone(), registry.table())
            .expect("spawning the egress gate");

        // The guest's connect: the shuttle's vsock connection, arrived…
        let guest = UnixStream::connect(&gate_sock)
            .await
            .expect("connecting the guest end");
        // …and the gate's dial of the switch it fronts, accepted before the
        // guest speaks, so what it writes next is decided by a gate whose
        // switch connection is already up.
        let (switch, _) = listener.accept().await.expect("accepting the gate's dial");

        GateHarness {
            _gate: gate,
            guest,
            switch,
            log,
            table: registry.table(),
            _dir: dir,
            _guard,
        }
    }

    /// Brings up one gate over a stand-in switch, deciding by `registry`'s
    /// table, with the guest sending the plain upgrade head first.
    pub(crate) async fn gate_over(registry: BoxRegistry) -> GateHarness {
        gate_over_with(registry, CONNECT_REQUEST.to_vec()).await
    }

    /// [`gate_over`] with the guest's first write supplied by the caller, so a
    /// test can pipeline frames behind the upgrade head in a single write and
    /// exercise the gate's carry-over of the bytes its head-read read past the
    /// head's end.
    ///
    /// The forwarded head is read back off the switch end and asserted
    /// verbatim, so every harness built this way proves the upgrade passes
    /// through untouched before the frame stream begins.
    pub(crate) async fn gate_over_with(registry: BoxRegistry, first_write: Vec<u8>) -> GateHarness {
        let mut harness = gate_connected(registry).await;
        // The guest's first write — the upgrade head, alone or with frames
        // pipelined behind it.
        harness
            .guest
            .write_all(&first_write)
            .await
            .expect("writing the guest's first bytes");
        // The upgrade head, forwarded verbatim and read back off the switch
        // end, so the frame stream begins at a known point.
        let mut head = vec![0u8; CONNECT_REQUEST.len()];
        harness
            .switch
            .read_exact(&mut head)
            .await
            .expect("reading the forwarded head");
        assert_eq!(
            head, CONNECT_REQUEST,
            "the gate forwards the switch upgrade head verbatim"
        );
        harness
    }

    /// Brings up one gate and has the guest speak a control request: gvproxy's
    /// switch socket carries the daemon's HTTP verbs on the same vsock port as
    /// the shuttle's upgrade, so a control exchange is the other half of what
    /// the gate must relay. The head is read back off the switch end and
    /// asserted verbatim — the gate forwards it before it knows what it asks
    /// for — and the body the request carried, pipelined behind the head in
    /// the same write as the guest's own client sends it, is left for the test
    /// to read, so the whole exchange is observable end to end.
    pub(crate) async fn gate_over_control(registry: BoxRegistry, request: Vec<u8>) -> GateHarness {
        let mut harness = gate_connected(registry).await;
        let head_len = super::find_subslice(&request, super::HEAD_END)
            .map(|at| at + super::HEAD_END.len())
            .expect("the control request's head ends");
        harness
            .guest
            .write_all(&request)
            .await
            .expect("writing the control request");
        let mut head = vec![0u8; head_len];
        read_within(&mut harness.switch, &mut head).await;
        assert_eq!(
            head,
            request[..head_len],
            "the gate forwards a control request's head verbatim"
        );
        harness
    }

    /// Writes one length-framed frame from the guest end.
    pub(crate) async fn send_frame(guest: &mut UnixStream, frame: &[u8]) {
        let mut framed = Vec::with_capacity(2 + frame.len());
        framed.extend_from_slice(&(frame.len() as u16).to_le_bytes());
        framed.extend_from_slice(frame);
        guest
            .write_all(&framed)
            .await
            .expect("writing the framed frame");
    }

    /// Reads one length-framed frame from the switch end within [`DEADLINE`],
    /// failing the test when the timeout passes first.
    pub(crate) async fn expect_frame(switch: &mut UnixStream) -> Vec<u8> {
        let mut len_buf = [0u8; 2];
        read_within(switch, &mut len_buf).await;
        let n = u16::from_le_bytes(len_buf) as usize;
        assert!(n > 0, "a zero-length frame claim is not a frame");
        let mut frame = vec![0u8; n];
        read_within(switch, &mut frame).await;
        frame
    }

    /// Reads exactly `buf` from `stream` within [`DEADLINE`], failing the
    /// test when the timeout passes first.
    pub(crate) async fn read_within(stream: &mut UnixStream, buf: &mut [u8]) {
        match tokio::time::timeout(DEADLINE, stream.read_exact(buf)).await {
            Ok(read) => {
                read.expect("reading the stream");
            }
            Err(_) => panic!("expected the bytes to arrive within {DEADLINE:?}, got none"),
        }
    }

    /// Polls the captured log until it contains `needle`, failing with the
    /// log's contents once [`DEADLINE`] passes.
    pub(crate) async fn wait_for_log(log: &CaptureWriter, needle: &str) {
        let deadline = tokio::time::Instant::now() + DEADLINE;
        loop {
            let logged = log.contents();
            if logged.contains(needle) {
                return;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "expected {needle:?} in the captured log within {DEADLINE:?}, got: {logged}"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// After a marker frame has proved the gate decided everything before it,
    /// asserts nothing else arrived at the switch: a frame the gate dropped is
    /// not merely late, it is absent.
    pub(crate) async fn expect_silence(switch: &mut UnixStream) {
        let mut buf = [0u8; 1];
        match tokio::time::timeout(QUIET, switch.read(&mut buf)).await {
            Ok(Ok(0)) => panic!("the switch end closed; the gate's relay is down"),
            Ok(Ok(n)) => panic!(
                "{n} byte(s) arrived at the switch after the marker: a dropped frame slipped through"
            ),
            Ok(Err(e)) => panic!("reading the switch end failed: {e}"),
            // Quiet for the window: nothing else was written on.
            Err(_) => {}
        }
    }

    /// Asserts the guest's side of a refused connection is down — that no
    /// further byte will ever arrive on it — without insisting on which
    /// signal the teardown left behind. A well-behaved guest, one that sent
    /// only what its request declared, reads clean EOF; a guest whose bytes
    /// the gate refused to read finds the socket reset, the OS's report that
    /// its data was discarded. Both mean the gate closed its side, and
    /// neither leaves a further byte for the guest to read.
    pub(crate) async fn expect_teardown(guest: &mut UnixStream) {
        let mut probe = [0u8; 1];
        match tokio::time::timeout(DEADLINE, guest.read(&mut probe)).await {
            Ok(Ok(0)) => {}
            Ok(Ok(n)) => panic!("the gate left {n} byte(s) for a refused guest to read"),
            Ok(Err(e)) if e.kind() == io::ErrorKind::ConnectionReset => {}
            Ok(Err(e)) => panic!("reading the guest end failed: {e}"),
            Err(_) => panic!("the gate left the refused connection hanging"),
        }
    }

    /// An Ethernet II frame carrying an IPv4 `proto` packet from `src` to
    /// `dst`:`port` — the shape the shared verdict reads: a 14-byte Ethernet
    /// header, the fixed 20-byte IPv4 header (TTL 64, the protocol byte, a
    /// zeroed checksum — neither is read), and 4 bytes of L4 ports. `6` is
    /// TCP, `17` UDP.
    pub(crate) fn ipv4_frame(src: [u8; 4], proto: u8, dst: [u8; 4], port: u16) -> Vec<u8> {
        let mut frame = Vec::with_capacity(14 + 24);
        frame.extend_from_slice(&[0x52, 0x54, 0x00, 0x00, 0x00, 0x01]); // dst MAC
        frame.extend_from_slice(&[0x52, 0x54, 0x00, 0x00, 0x00, 0x02]); // src MAC
        frame.extend_from_slice(&0x0800u16.to_be_bytes()); // EtherType: IPv4
        frame.extend_from_slice(&[0x45, 0, 0, 0]); // version 4, IHL 5, TOS, length (unchecked)
        frame.extend_from_slice(&[0; 4]); // id, flags+offset: 0
        frame.push(64); // TTL
        frame.push(proto); // protocol
        frame.extend_from_slice(&[0; 2]); // checksum (unchecked)
        frame.extend_from_slice(&src);
        frame.extend_from_slice(&dst);
        frame.extend_from_slice(&40000u16.to_be_bytes()); // source port
        frame.extend_from_slice(&port.to_be_bytes()); // destination port
        frame
    }

    /// An Ethernet II ARP frame announcing `spa` as its sender protocol
    /// address — the address an ARP frame's source is read from.
    pub(crate) fn arp_frame(spa: [u8; 4]) -> Vec<u8> {
        let mut frame = Vec::with_capacity(14 + 28);
        frame.extend_from_slice(&[0x52, 0x54, 0x00, 0x00, 0x00, 0x01]); // dst MAC
        frame.extend_from_slice(&[0x52, 0x54, 0x00, 0x00, 0x00, 0x02]); // src MAC
        frame.extend_from_slice(&0x0806u16.to_be_bytes()); // EtherType: ARP
        frame.extend_from_slice(&1u16.to_be_bytes()); // htype: Ethernet
        frame.extend_from_slice(&0x0800u16.to_be_bytes()); // ptype: IPv4
        frame.push(6); // hlen
        frame.push(4); // plen
        frame.extend_from_slice(&1u16.to_be_bytes()); // oper: request
        frame.extend_from_slice(&[0x52, 0x54, 0x00, 0x40, 0x00, 0x09]); // sender MAC
        frame.extend_from_slice(&spa); // sender protocol address
        frame.extend_from_slice(&[0; 6]); // target MAC
        frame.extend_from_slice(&[100, 64, 0, 1]); // target protocol address
        frame
    }

    /// An Ethernet II frame carrying an IPv6 payload — the family no v1
    /// admission path exists for, dropped as a family under any rules.
    pub(crate) fn ipv6_frame() -> Vec<u8> {
        let mut frame = Vec::with_capacity(14 + 40);
        frame.extend_from_slice(&[0x52, 0x54, 0x00, 0x00, 0x00, 0x01]); // dst MAC
        frame.extend_from_slice(&[0x52, 0x54, 0x00, 0x00, 0x00, 0x02]); // src MAC
        frame.extend_from_slice(&0x86DDu16.to_be_bytes()); // EtherType: IPv6
        frame.extend_from_slice(&[0; 40]);
        frame
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use sessions::EgressPolicy;
    use sessions::core::egress::{DropReason, FrameFamily, FrameVerdict};
    use switch::SwitchSubnet;
    use tempfile::TempDir;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{UnixListener, UnixStream};

    use super::test_support::{
        CaptureWriter, DEADLINE, arp_frame, expect_frame, expect_silence, expect_teardown,
        gate_connected, gate_over, gate_over_control, gate_over_with, ipv4_frame, ipv6_frame,
        read_within, send_frame, wait_for_log,
    };
    use super::{
        CONNECT_REQUEST, CONTROL_VERBS, DROP_WARN_MAX_TRACKED_PAIRS, DROP_WARN_MIN_INTERVAL,
        DropLimiter, EgressGate, GateDrop, GuestSpeak, HANDSHAKE_TIMEOUT, MAX_HEAD,
        MAX_NAMED_TARGET, WarnDecision, gate_verdict, max_frame, serve_connection,
    };
    use crate::box_registry::{BoxRegistration, BoxRegistry};

    /// The default switch subnet, the plan every registry below is built for.
    const SUBNET: SwitchSubnet = switch::DEFAULT_SUBNET;

    /// The lease of the one published box below: the one source its frames
    /// may carry.
    const LEASE: [u8; 4] = [100, 64, 0, 9];

    /// A box that may reach `10.0.0.0/8` over TCP and nothing else — the
    /// declaration the host-side rules below are compiled from.
    fn tcp_lan_box(registry: &BoxRegistry, lease: [u8; 4]) {
        registry.register(
            BoxRegistration::new("web", Ipv4Addr::from(lease), Ipv4Addr::LOCALHOST)
                .with_admitted_ports([8080])
                .with_egress_policy(EgressPolicy {
                    allow_protocols: Some(vec![sessions::IpProto::Tcp]),
                    allow_subnets: Some(vec!["10.0.0.0/8".to_string()]),
                    allow_dns_hosts: None,
                    deny_subnets: None,
                }),
        );
    }

    /// NET-081: on a VM-backed host a box's rules are applied **outside** the
    /// VM, by the host, before the switch sees anything. A frame the box
    /// declared arrives at the switch exactly as it was sent; a frame it did
    /// not declare never does — the gate drops it where it stands — and the
    /// drop says so, rate-limited, naming the source address and the rule.
    #[tokio::test]
    async fn host_side_rules_applied_outside_vm() {
        let registry = BoxRegistry::new(SUBNET);
        tcp_lan_box(&registry, LEASE);
        let mut h = gate_over(registry).await;

        // Declared: TCP to the allowed subnet reaches the switch, untouched —
        // the same frame, byte for byte, that left the guest.
        let declared = ipv4_frame(LEASE, 6, [10, 1, 2, 3], 80);
        send_frame(&mut h.guest, &declared).await;
        let seen = expect_frame(&mut h.switch).await;
        assert_eq!(
            seen, declared,
            "a declared frame reaches the switch as it was sent"
        );

        // Undeclared: TCP to an address outside the allowed subnet is dropped
        // before the switch. The marker sent after it proves the drop — the
        // gate decides in order, so a marker that arrives means everything
        // before it was decided, and this frame did not pass.
        let undeclared = ipv4_frame(LEASE, 6, [203, 0, 113, 7], 443);
        let marker = ipv4_frame(LEASE, 6, [10, 9, 9, 9], 80);
        send_frame(&mut h.guest, &undeclared).await;
        send_frame(&mut h.guest, &marker).await;
        let seen = expect_frame(&mut h.switch).await;
        assert_eq!(
            seen, marker,
            "the undeclared frame never reached the switch; the marker did"
        );
        expect_silence(&mut h.switch).await;

        // The drop says so, naming the source address and the rule — the line
        // a diagnostic bundle's daemon log tail carries.
        wait_for_log(&h.log, "egress-undeclared-subnet").await;
        let logged = h.log.contents();
        assert!(
            logged.contains("source=100.64.0.9"),
            "the drop line carries the source address, got: {logged}"
        );
        assert!(
            logged.contains("rule_matched=\"egress-undeclared-subnet\""),
            "the drop line carries the rule, got: {logged}"
        );

        // And only once: a second drop of the same class, decided for the same
        // box, adds no second line inside the interval.
        let second = ipv4_frame(LEASE, 6, [203, 0, 113, 8], 443);
        send_frame(&mut h.guest, &second).await;
        send_frame(&mut h.guest, &marker).await;
        let seen = expect_frame(&mut h.switch).await;
        assert_eq!(
            seen, marker,
            "the marker still arrives; the drop is not a reset"
        );
        expect_silence(&mut h.switch).await;
        assert_eq!(
            h.log.contents().matches("egress-undeclared-subnet").count(),
            1,
            "one drop line per source address per rule per interval, got: {}",
            h.log.contents()
        );
    }

    /// NET-081's failure case: a frame whose source address belongs to no box
    /// never leaves the VM. The host table is the authority on which
    /// addresses exist — a made-up address, a namespace the host withdrew,
    /// and an ARP announcing an unpublished address are all refused before any
    /// rule is consulted, whatever the frame carries; the one published box's
    /// frames still pass; and the drops name their addresses and rules.
    #[tokio::test]
    async fn unknown_source_default_deny() {
        let registry = BoxRegistry::new(SUBNET);
        tcp_lan_box(&registry, LEASE);
        // A namespace that was published and then withdrawn: its address is
        // held by no row any more, and its frames are an unknown source's.
        let withdrawn = [100, 64, 0, 10];
        let retired = registry.register(BoxRegistration::new(
            "gone",
            Ipv4Addr::from(withdrawn),
            Ipv4Addr::LOCALHOST,
        ));
        assert!(registry.withdraw(retired.switch_addr()).is_some());
        let mut h = gate_over(registry).await;

        // Four frames no namespace holds the source of: a made-up address, a
        // withdrawn namespace's, an ARP announcing a made-up address —
        // address resolution is no way to smuggle one past the table — and
        // an IPv6 frame, the family with no source to read and no admission
        // path either. The marker after them is the one published box's, so
        // its arrival proves all four were decided and none passed.
        let stranger = [100, 64, 0, 99];
        let unknown = ipv4_frame(stranger, 6, [10, 1, 2, 3], 80);
        let from_retired = ipv4_frame(withdrawn, 6, [10, 1, 2, 3], 80);
        let foreign_arp = arp_frame(stranger);
        let v6 = ipv6_frame();
        let marker = ipv4_frame(LEASE, 6, [10, 1, 2, 3], 80);
        for frame in [&unknown, &from_retired, &foreign_arp, &v6] {
            send_frame(&mut h.guest, frame).await;
        }
        send_frame(&mut h.guest, &marker).await;
        let seen = expect_frame(&mut h.switch).await;
        assert_eq!(
            seen, marker,
            "no frame from an unpublished source reached the switch"
        );
        expect_silence(&mut h.switch).await;

        // The drops are named: the unknown sources under NET-081's own rule —
        // one line per address, so the stranger's two frames share one line —
        // and the IPv6 family under its own, with no source to name.
        wait_for_log(&h.log, "egress-unknown-source").await;
        wait_for_log(&h.log, "egress-ipv6").await;
        let logged = h.log.contents();
        for src in [stranger, withdrawn] {
            assert!(
                logged.contains(&format!("source={}", Ipv4Addr::from(src))),
                "a drop line names the source address {src:?}, got: {logged}"
            );
        }
        assert!(
            logged.contains("source=none"),
            "the family drop names no source rather than inventing one, got: {logged}"
        );
        assert_eq!(
            logged.matches("egress-unknown-source").count(),
            2,
            "three unknown-source frames make two lines (the stranger's two share one), got: {logged}"
        );
        assert_eq!(
            logged.matches("egress-ipv6").count(),
            1,
            "the family drop has its own line, got: {logged}"
        );

        // And the frame that did pass is the published box's own — the table
        // routes a held source to its rules, and holds only what the host
        // published.
        assert!(
            h.table.by_source(LEASE).is_some(),
            "the one published box is still held"
        );
    }

    /// The relay's framing and head handling: the upgrade head is forwarded
    /// verbatim (asserted by every harness), and the frames a guest writes
    /// past it in the same `read` — pipelined behind the head, as a fast
    /// shuttle can — are relayed as frames, not lost to the head's read.
    #[tokio::test]
    async fn frames_pipelined_behind_the_upgrade_head_are_relayed() {
        let registry = BoxRegistry::new(SUBNET);
        registry.register(BoxRegistration::new(
            "web",
            Ipv4Addr::from(LEASE),
            Ipv4Addr::LOCALHOST,
        ));
        // The head plus two frames in one write, both declared; the harness
        // has read the forwarded head back off the switch end already.
        let first = ipv4_frame(LEASE, 6, [10, 1, 2, 3], 80);
        let second = ipv4_frame(LEASE, 17, [100, 64, 0, 1], 53);
        let mut pipelined = CONNECT_REQUEST.to_vec();
        for frame in [&first, &second] {
            pipelined.extend_from_slice(&(frame.len() as u16).to_le_bytes());
            pipelined.extend_from_slice(frame);
        }
        let mut h = gate_over_with(registry, pipelined).await;

        let seen = expect_frame(&mut h.switch).await;
        assert_eq!(seen, first, "the first pipelined frame arrived");
        let seen = expect_frame(&mut h.switch).await;
        assert_eq!(seen, second, "and the second after it");
    }

    /// The vsock port this gate sits on carries gvproxy's control verbs too,
    /// not only the shuttle's upgrade: the guest daemon drives its publishes and
    /// its DNS zone over the same bridged socket, speaking plain HTTP/1.1 with a
    /// `Content-Length` body and no frame ever on the wire. Those exchanges must
    /// pass through untouched — head, body and response — or the daemon's zone
    /// never comes up and every publish reads as a malformed status line, the
    /// shape the macOS and KVM lanes were red on.
    #[tokio::test]
    async fn control_requests_are_spliced_verbatim() {
        let registry = BoxRegistry::new(SUBNET);
        tcp_lan_box(&registry, LEASE);
        // The request the guest's own control client writes: head and body in
        // one write, framed by `Content-Length`, the way `post_json` builds it.
        let body = br#"{"name":"min.internal.","records":[{"name":"web","ip":"100.64.0.9"}]}"#;
        let mut request = b"POST /services/dns/add HTTP/1.1\r\nHost: localhost\r\n\
                           Content-Type: application/json\r\n"
            .to_vec();
        request.extend_from_slice(format!("Content-Length: {}\r\n\r\n", body.len()).as_bytes());
        request.extend_from_slice(body);
        let mut h = gate_over_control(registry, request).await;

        // The head arrived (the harness read it back verbatim); the body must
        // arrive after it exactly as the guest wrote it — not read as a frame
        // length, not gated, not reordered.
        let mut seen_body = vec![0u8; body.len()];
        read_within(&mut h.switch, &mut seen_body).await;
        assert_eq!(
            seen_body, body,
            "the control body reaches gvproxy exactly as the guest sent it"
        );

        // And the response comes back the same way, so the guest's exchange
        // completes as though the gate were not there.
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        h.switch
            .write_all(response)
            .await
            .expect("writing gvproxy's response");
        let mut seen = vec![0u8; response.len()];
        read_within(&mut h.guest, &mut seen).await;
        assert_eq!(
            seen, response,
            "the control response reaches the guest verbatim"
        );

        // Nothing was gated, so nothing was dropped: a control exchange is the
        // daemon's own plumbing, not a box's traffic, and the gate has no
        // verdict to report on it.
        assert!(
            !h.log.contents().contains("dropped"),
            "a control exchange passes through ungated, got: {}",
            h.log.contents()
        );
    }

    /// A control body's bytes are never scanned for the connect path: the
    /// zone-add request carries the session's name, and a session name may
    /// legally hold those bytes (`fix/connection-leak`), so a relay that
    /// grepped the stream for them would tear a perfectly legitimate control
    /// exchange down. The gate relays the body by its `Content-Length`
    /// instead — the request is framed before any of it is read — so a body
    /// carrying the path verbatim is spliced verbatim, answered, and never
    /// refused.
    #[tokio::test]
    async fn a_body_carrying_the_connect_path_passes_verbatim() {
        let registry = BoxRegistry::new(SUBNET);
        tcp_lan_box(&registry, LEASE);
        // The request the guest's own control client writes, with a session
        // named after a branch — the legitimate body a content watch would
        // have torn this exchange down over.
        let body =
            br#"{"name":"fix/connection-leak","records":[{"name":"web","ip":"100.64.0.9"}]}"#;
        let mut request = b"POST /services/dns/add HTTP/1.1\r\nHost: localhost\r\n\
                           Content-Type: application/json\r\n"
            .to_vec();
        request.extend_from_slice(format!("Content-Length: {}\r\n\r\n", body.len()).as_bytes());
        request.extend_from_slice(body);
        let mut h = gate_over_control(registry, request).await;

        // The body arrives exactly as written, connect path and all: the
        // path is what a request *line* says, and this connection's one
        // request line was already spoken.
        let mut seen_body = vec![0u8; body.len()];
        read_within(&mut h.switch, &mut seen_body).await;
        assert_eq!(
            seen_body, body,
            "a body carrying the connect path reaches gvproxy exactly as the guest sent it"
        );

        // And the exchange completes as though the gate were not there.
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        h.switch
            .write_all(response)
            .await
            .expect("writing gvproxy's response");
        let mut seen = vec![0u8; response.len()];
        read_within(&mut h.guest, &mut seen).await;
        assert_eq!(
            seen, response,
            "the control response reaches the guest verbatim"
        );

        // Nothing was refused and nothing was gated: the body was never read
        // as anything but the request its head had already framed.
        let logged = h.log.contents();
        assert!(
            !logged.contains("egress-control-upgrade"),
            "a body carrying the connect path was refused as an upgrade, got: {logged}"
        );
        assert!(
            !logged.contains("dropped"),
            "a control exchange passes through ungated, got: {logged}"
        );
    }

    /// A control connection carries exactly one request, and the first guest
    /// byte past that request's `Content-Length` body tears the connection
    /// down without being written on. gvproxy hijacks a hijacking request
    /// however late in the connection's life it arrives, so a guest that has
    /// spoken a control verb and then writes a second request on the same
    /// connection — with frames from a source no box holds pipelined behind
    /// it — is one hijack from the ungated egress NET-081 exists to prevent.
    /// Nothing reaches the switch, both sides come down after the answer the
    /// gate owes the request it did relay, and the refusal says so under its
    /// own rule.
    #[tokio::test]
    async fn a_second_request_after_the_body_is_refused() {
        let registry = BoxRegistry::new(SUBNET);
        tcp_lan_box(&registry, LEASE);
        // One ordinary control exchange, answered, so the connection is live
        // as control traffic and the guest is still on it — the state a
        // smuggled second request arrives in, however long the guest waits.
        let request =
            b"POST /services/dns/add HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n"
                .to_vec();
        let answer: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        let mut h = gate_over_control(registry, request).await;

        // The second request: a whole control head the gate never reads as
        // one, because this connection's one request is already spoken. With
        // a frame from a source no box holds pipelined behind it, for the
        // ungated egress the hijack would buy.
        let second =
            b"POST /services/forwarder/expose HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\n\r\n";
        h.guest
            .write_all(second)
            .await
            .expect("writing the smuggled second request");
        let frame = ipv4_frame([100, 64, 0, 99], 6, [10, 1, 2, 3], 80);
        send_frame(&mut h.guest, &frame).await;

        // Refused unread, and said so at the gate's own cadence — before the
        // switch end below closes, so the refusal is what ended the relay.
        wait_for_log(&h.log, "spoken past its one request").await;
        // Not one byte of the second request — and none of the frame behind
        // it — reached the switch: its end sees the half-close that ends the
        // exchange, and nothing before it.
        let mut probe = [0u8; 1];
        match tokio::time::timeout(DEADLINE, h.switch.read(&mut probe)).await {
            Ok(Ok(0)) => {}
            Ok(Ok(n)) => panic!("{n} byte(s) of the smuggled request reached the switch"),
            Ok(Err(e)) => panic!("reading the switch end failed: {e}"),
            Err(_) => panic!("the gate left the switch side hanging"),
        }
        // The request that *was* relayed is still owed its answer: answer it
        // and close the switch end, so the drain of the answer completes.
        h.switch
            .write_all(answer)
            .await
            .expect("answering the control request");
        h.switch
            .shutdown()
            .await
            .expect("closing the stand-in switch's end");
        // Not one byte of the second request — and none of the frame behind
        // it — reached the switch: its end sees the half-close that ends the
        // exchange, and nothing before it.
        let mut probe = [0u8; 1];
        match tokio::time::timeout(DEADLINE, h.switch.read(&mut probe)).await {
            Ok(Ok(0)) => {}
            Ok(Ok(n)) => panic!("{n} byte(s) of the smuggled request reached the switch"),
            Ok(Err(e)) => panic!("reading the switch end failed: {e}"),
            Err(_) => panic!("the gate left the switch side hanging"),
        }
        // And the guest's side comes down with it — after the answer to the
        // request it legitimately made, which the gate owes it, and with no
        // byte of the stream it tried to steal behind it.
        let mut answered = vec![0u8; answer.len()];
        read_within(&mut h.guest, &mut answered).await;
        assert_eq!(
            answered, answer,
            "the refused guest got the answer it was owed, and only that"
        );
        // The connection is down with no further byte for the guest — a
        // smuggler's unread bytes were discarded, so its side reads the
        // teardown as a reset rather than a clean end.
        expect_teardown(&mut h.guest).await;
        // The refusal is its own class, not a frame drop: no frame was ever
        // parsed, so no source address was read and no box's rule fired.
        let logged = h.log.contents();
        assert!(
            logged.contains("rule_matched=\"egress-control-upgrade\""),
            "the refusal names its own class, got: {logged}"
        );
        assert!(
            !logged.contains("egress-unknown-source"),
            "no frame behind the refused request was parsed or dropped, got: {logged}"
        );
    }

    /// The same refusal when the smuggled request shares one write with the
    /// request it trails — head, body, a second request and a frame, all
    /// pipelined the way a fast guest puts them on the wire. The body is
    /// relayed by its `Content-Length` alone, so no read ever takes a byte of
    /// what follows it, whatever write the bytes arrived in: the last body
    /// byte is the gate's to relay and the one after it is not.
    #[tokio::test]
    async fn a_request_pipelined_behind_the_body_is_refused() {
        let registry = BoxRegistry::new(SUBNET);
        tcp_lan_box(&registry, LEASE);
        // A real request with a real body, so the count the gate relays is a
        // `Content-Length` it read out of the head, not the empty body of a
        // hand-built one.
        let body = br#"{"name":"web"}"#;
        let mut request = b"POST /services/dns/add HTTP/1.1\r\nHost: localhost\r\n".to_vec();
        request.extend_from_slice(format!("Content-Length: {}\r\n\r\n", body.len()).as_bytes());
        request.extend_from_slice(body);
        // Pipelined behind it in the same write: a whole second request, and
        // a frame from a source no box holds.
        request.extend_from_slice(
            b"POST /services/forwarder/expose HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\n\r\n",
        );
        let frame = ipv4_frame([100, 64, 0, 99], 6, [10, 1, 2, 3], 80);
        request.extend_from_slice(&(frame.len() as u16).to_le_bytes());
        request.extend_from_slice(&frame);
        let mut h = gate_over_control(registry, request).await;

        // The body arrives — the request it belongs to was relayed, and the
        // gate owes it an answer — and not one byte more.
        let mut seen_body = vec![0u8; body.len()];
        read_within(&mut h.switch, &mut seen_body).await;
        assert_eq!(
            seen_body, body,
            "the one request the head declared arrived whole, and alone"
        );
        // The smuggled request was refused unread: the gate relays exactly
        // what the `Content-Length` declared and no byte past it.
        wait_for_log(&h.log, "spoken past its one request").await;
        let mut probe = [0u8; 1];
        match tokio::time::timeout(DEADLINE, h.switch.read(&mut probe)).await {
            Ok(Ok(0)) => {}
            Ok(Ok(n)) => panic!("{n} byte(s) of the pipelined request reached the switch"),
            Ok(Err(e)) => panic!("reading the switch end failed: {e}"),
            Err(_) => panic!("the gate left the switch side hanging"),
        }
        // The request that *was* relayed is still owed its answer: answer it
        // and close the switch end, so the drain of the answer completes.
        let answer: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        h.switch
            .write_all(answer)
            .await
            .expect("answering the control request");
        h.switch
            .shutdown()
            .await
            .expect("closing the stand-in switch's end");
        // The guest got the answer it was owed for the request it did make,
        // then the connection came down — with no byte of the smuggled
        // request or the frame behind it for anyone to read.
        let mut answered = vec![0u8; answer.len()];
        read_within(&mut h.guest, &mut answered).await;
        assert_eq!(
            answered, answer,
            "the refused guest got the answer it was owed"
        );
        // And the connection came down — with no byte of the smuggled request
        // or the frame behind it for anyone to read; the smuggler's own
        // unread bytes were discarded with the teardown.
        expect_teardown(&mut h.guest).await;
        let logged = h.log.contents();
        assert!(
            logged.contains("rule_matched=\"egress-control-upgrade\""),
            "the refusal names its own class, got: {logged}"
        );
        assert!(
            !logged.contains("egress-unknown-source"),
            "no frame behind the refused request was parsed or dropped, got: {logged}"
        );
    }

    /// The first head picks the relay, and the choice is deliberately narrow:
    /// the frame stream is exactly the connect path, because gvproxy hijacks
    /// on the path alone, whatever the method or query; the control relay is
    /// exactly the three verbs the daemon's own client speaks, each with one
    /// `Content-Length`-framed body; and everything else — the `/tunnel`
    /// hijack, the verbs the gate does not relay, a target it has never
    /// classified, a head too malformed to frame — is refused **before
    /// forwarding**. The two ways to be wrong fail differently, and only one
    /// of them widens reach: reading an upgrade as control would splice it to
    /// the switch ungated, while reading a control request as frames fails
    /// closed at its first length claim.
    #[test]
    fn the_first_head_picks_the_relay() {
        // The frame stream: the connect path, however it is asked for.
        assert_eq!(GuestSpeak::of_head(CONNECT_REQUEST), Ok(GuestSpeak::Frames));
        assert_eq!(
            GuestSpeak::of_head(b"GET /connect HTTP/1.1\r\nHost: localhost\r\n\r\n"),
            Ok(GuestSpeak::Frames),
            "gvproxy hijacks on the path alone, not on the method"
        );
        assert_eq!(
            GuestSpeak::of_head(b"POST /connect?guest=1 HTTP/1.1\r\n\r\n"),
            Ok(GuestSpeak::Frames),
            "a query on the path is still the path"
        );

        // The control verbs: one request each, with the body its head
        // declares. An absent count is HTTP's own no-body, not a refusal —
        // the frame relay takes over from wherever the body ends.
        for verb in CONTROL_VERBS {
            let verb = String::from_utf8_lossy(verb);
            let head =
                format!("POST {verb} HTTP/1.1\r\nHost: localhost\r\nContent-Length: 2\r\n\r\n{{}}");
            assert_eq!(
                GuestSpeak::of_head(head.as_bytes()),
                Ok(GuestSpeak::Control { body: 2 }),
                "{verb} is the control relay",
            );
        }
        assert_eq!(
            GuestSpeak::of_head(b"POST /services/dns/add HTTP/1.1\r\nHost: localhost\r\n\r\n"),
            Ok(GuestSpeak::Control { body: 0 }),
            "a control request with no Content-Length has no body to relay"
        );

        // Everything else is refused, and the refusal names what was asked
        // for — the bytes a diagnostic reads off the line.
        let refused = |head: &[u8]| GuestSpeak::of_head(head).unwrap_err().target;
        // The other hijacking verb gvproxy serves on this socket: it dials an
        // address inside the virtual network and relays bytes, so it is not
        // the gate's to splice.
        assert_eq!(
            refused(b"TUNNEL /tunnel?ip=100.64.0.9&port=22 HTTP/1.1\r\n\r\n"),
            b"/tunnel?ip=100.64.0.9&port=22",
            "the tunnel hijack is refused, not spliced ungated"
        );
        // A verb the daemon never speaks — the listing gvproxy serves the
        // host, not the guest.
        assert_eq!(
            refused(b"GET /services/forwarder/all HTTP/1.1\r\n\r\n"),
            b"/services/forwarder/all",
            "a verb the daemon does not speak is refused"
        );
        // A target one byte past the connect path is not it.
        assert_eq!(
            refused(b"POST /connectx HTTP/1.1\r\n\r\n"),
            b"/connectx",
            "an exact path is an exact match: /connectx is not /connect"
        );
        // The absolute form is not the origin form the gate relays.
        assert_eq!(
            refused(b"GET http://localhost/connect HTTP/1.1\r\n\r\n"),
            b"http://localhost/connect",
            "an absolute-form target is not the connect path"
        );
        // A body the gate cannot frame the end of: chunked, or two counts
        // disagreeing.
        assert_eq!(
            refused(
                b"POST /services/dns/add HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n"
            ),
            b"/services/dns/add",
            "a chunked control request is refused: the gate relays by a byte count"
        );
        assert_eq!(
            refused(
                b"POST /services/dns/add HTTP/1.1\r\nContent-Length: 2\r\nContent-Length: 4\r\n\r\n"
            ),
            b"/services/dns/add",
            "a split body count is the smuggling shape, and is refused"
        );
        assert_eq!(
            refused(b"POST /services/dns/add HTTP/1.1\r\nContent-Length: 0x2\r\n\r\n"),
            b"/services/dns/add",
            "a body count that is not a plain decimal number is refused"
        );
        // And a head too malformed to read a request line from, which names
        // nothing rather than guess at bytes.
        assert_eq!(
            refused(b"\r\nHost: localhost\r\n\r\n"),
            b"",
            "a head with no request line is refused, naming nothing"
        );
        // The refusal is a warn line, so it does not echo a hostile head back:
        // a target past the naming bound is named to the bound and no further.
        let long = vec![b'x'; MAX_HEAD];
        let mut shouted = b"GET /".to_vec();
        shouted.extend_from_slice(&long);
        shouted.extend_from_slice(b" HTTP/1.1\r\n\r\n");
        let named = GuestSpeak::of_head(&shouted).unwrap_err().target;
        assert!(
            named.len() <= MAX_NAMED_TARGET,
            "a refused head names at most a bounded prefix of its target, got {} bytes",
            named.len()
        );

        // What the gate classifies by is the request line's target — not the
        // bytes anywhere else in the head, and not the body's content: a
        // control verb whose header block carries the connect path is still
        // the control request its own line says it is.
        assert_eq!(
            GuestSpeak::of_head(
                b"POST /services/dns/add HTTP/1.1\r\nHost: fix/connection-leak\r\nContent-Length: 0\r\n\r\n"
            ),
            Ok(GuestSpeak::Control { body: 0 }),
            "the connect path in a header does not make a control request an upgrade"
        );
    }

    /// A request head the gate has not classified is refused before it is
    /// forwarded, because gvproxy's switch socket serves more than the
    /// shuttle's upgrade and the daemon's three verbs: `/tunnel` dials an
    /// address inside the virtual network and relays bytes to it, and what a
    /// hijacked request may do is nothing the reach rules get a say in. The
    /// hijack arriving as a first head — the way the guest's own client
    /// arrives — is refused unread: gvproxy never holds the request, both
    /// ends come down, and the refusal names the target under its own rule.
    #[tokio::test]
    async fn a_request_outside_the_allow_list_is_refused_before_forwarding() {
        let registry = BoxRegistry::new(SUBNET);
        tcp_lan_box(&registry, LEASE);
        let head = b"TUNNEL /tunnel?ip=100.64.0.9&port=22 HTTP/1.1\r\n\r\n";
        let mut h = gate_connected(registry).await;
        h.guest
            .write_all(head)
            .await
            .expect("writing the tunnel hijack");

        // Refused before forwarding, and said so at the frame drops' cadence:
        // the refusal names the target — the bytes a diagnostic reads off the
        // line — under the head's own rule.
        wait_for_log(&h.log, "egress-undeclared-verb").await;
        let logged = h.log.contents();
        assert!(
            logged.contains("rule_matched=\"egress-undeclared-verb\""),
            "the refusal names its own class, got: {logged}"
        );
        assert!(
            logged.contains("request_target=/tunnel?ip=100.64.0.9&port=22"),
            "the refusal names the target it refused, got: {logged}"
        );
        // Nothing of it reached the switch — the head was never written on,
        // so gvproxy never held a request to hijack — and its end comes down
        // rather than hanging.
        let mut probe = [0u8; 1];
        match tokio::time::timeout(DEADLINE, h.switch.read(&mut probe)).await {
            Ok(Ok(0)) => {}
            Ok(Ok(n)) => panic!("{n} byte(s) of a refused head reached the switch"),
            Ok(Err(e)) => panic!("reading the switch end failed: {e}"),
            Err(_) => panic!("the gate left the switch side hanging"),
        }
        // And the guest's side comes down with it, not left hanging.
        match tokio::time::timeout(DEADLINE, h.guest.read(&mut probe)).await {
            Ok(Ok(0)) => {}
            Ok(Ok(n)) => panic!("the gate left {n} byte(s) for a refused guest to read"),
            Ok(Err(e)) => panic!("reading the guest end failed: {e}"),
            Err(_) => panic!("the gate left the refused connection hanging"),
        }
    }

    /// Refused heads are rate-limited the way frame drops are, and across
    /// connections: a guest that connects fresh for every attempt — exactly as
    /// cheap as sending a frame — must not buy a warn line each time. The
    /// window is keyed by the rule alone, because a refused head names no
    /// source address, so two connections refused in the same interval make
    /// one line, not two.
    #[tokio::test]
    async fn refused_request_heads_share_one_rate_window_across_connections() {
        let registry = BoxRegistry::new(SUBNET);
        tcp_lan_box(&registry, LEASE);
        let dir = TempDir::new().expect("a tempdir is creatable");
        let switch_sock = dir.path().join("gvproxy-switch.sock");
        let gate_sock = dir.path().join("gvproxy-gate.sock");
        let listener = UnixListener::bind(&switch_sock).expect("binding the stand-in switch");

        let log = CaptureWriter::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(log.clone())
            .with_ansi(false)
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);
        let _gate = EgressGate::spawn(gate_sock.clone(), switch_sock.clone(), registry.table())
            .expect("spawning the egress gate");

        // Two connections, each refused on its head — the guest's own
        // client's shape: connect, speak a head the gate does not relay, and
        // take the teardown.
        let head = b"GET /services/forwarder/all HTTP/1.1\r\n\r\n";
        for _ in 0..2 {
            let mut guest = UnixStream::connect(&gate_sock)
                .await
                .expect("connecting the guest end");
            let (mut switch, _) = listener.accept().await.expect("accepting the gate's dial");
            guest
                .write_all(head)
                .await
                .expect("writing the refused head");
            let mut probe = [0u8; 1];
            match tokio::time::timeout(DEADLINE, switch.read(&mut probe)).await {
                Ok(Ok(0)) => {}
                Ok(Ok(n)) => panic!("{n} byte(s) of a refused head reached the switch"),
                Ok(Err(e)) => panic!("reading the switch end failed: {e}"),
                Err(_) => panic!("the gate left the switch side hanging"),
            }
            match tokio::time::timeout(DEADLINE, guest.read(&mut probe)).await {
                Ok(Ok(0)) => {}
                Ok(Ok(n)) => panic!("the gate left {n} byte(s) for a refused guest to read"),
                Ok(Err(e)) => panic!("reading the guest end failed: {e}"),
                Err(_) => panic!("the gate left the refused connection hanging"),
            }
        }

        // One warn line for the pair, not one per connection.
        wait_for_log(&log, "egress-undeclared-verb").await;
        assert_eq!(
            log.contents().matches("egress-undeclared-verb").count(),
            1,
            "two refused connections inside one interval make one line, got: {}",
            log.contents()
        );
    }

    /// A guest that never ends an upgrade head is refused, not buffered, and
    /// nothing of it ever reaches the switch. The head read is bounded at
    /// [`MAX_HEAD`] bytes, so a peer that talks past the bound without ever
    /// writing the head's end — a peer that is speaking, not silent, so the
    /// handshake timeout is not what catches it — is failed closed on at the
    /// bound itself.
    #[tokio::test]
    async fn a_head_that_never_ends_refuses_the_connection() {
        // No namespace needs publishing: a peer refused at the head is refused
        // before any frame is read, whatever the table holds.
        let registry = BoxRegistry::new(SUBNET);
        // The guest's first write is the noise itself — no head is spoken, so
        // the bytes the head reader sees have no end to find.
        let mut h = gate_connected(registry).await;

        // `MAX_HEAD + 1` bytes with no `\r\n\r\n` anywhere in them.
        let noise = vec![b'x'; MAX_HEAD + 1];
        h.guest
            .write_all(&noise)
            .await
            .expect("writing the endless head");

        // Refused on the head's own bound: the log names the over-long head,
        // so the byte-count check is what refused the connection, not the
        // handshake timeout waiting out a silent peer.
        wait_for_log(&h.log, &format!("exceeded {MAX_HEAD} bytes without ending")).await;
        // The gate must close the guest's side rather than leave it hanging…
        let mut probe = [0u8; 1];
        let refused = tokio::time::timeout(DEADLINE, h.guest.read_exact(&mut probe))
            .await
            .expect("the gate refuses within the deadline")
            .is_err();
        assert!(refused, "the guest connection is closed, not left hanging");
        // …and tear the switch side down with it: the stand-in switch reads
        // EOF, not an endless head.
        let mut probe = [0u8; 1];
        match tokio::time::timeout(DEADLINE, h.switch.read(&mut probe)).await {
            Ok(Ok(0)) => {}
            Ok(Ok(n)) => panic!("{n} byte(s) of an endless head reached the switch"),
            Ok(Err(e)) => panic!("reading the switch end failed: {e}"),
            Err(_) => panic!("the gate left the switch side hanging"),
        }
    }

    /// A frame the guest claims is past the largest frame the gate relays is
    /// refused, not sized to: the length prefix is the guest's own bytes, so a
    /// claim past the MTU-derived maximum is a malformed or hostile peer's,
    /// and the connection comes down rather than the gate either allocating
    /// to the claim or forwarding what it carried.
    #[tokio::test]
    async fn a_frame_claimed_past_the_maximum_is_refused() {
        let registry = BoxRegistry::new(SUBNET);
        tcp_lan_box(&registry, LEASE);
        let mut h = gate_over(registry).await;

        // A two-byte prefix claiming a frame past `max_frame()`, with no body
        // behind it: the claim alone is the refusal.
        assert!(
            usize::from(u16::MAX) > max_frame(),
            "the claim must be past the largest frame the gate relays"
        );
        h.guest
            .write_all(&u16::MAX.to_le_bytes())
            .await
            .expect("writing the oversized claim");

        // The refusal says so: the relay ended on the claim's length, and…
        wait_for_log(&h.log, &format!("exceeds max {}", max_frame())).await;
        // …the gate closes the guest's side rather than leave it hanging.
        let mut probe = [0u8; 1];
        let refused = tokio::time::timeout(DEADLINE, h.guest.read_exact(&mut probe))
            .await
            .expect("the gate refuses within the deadline")
            .is_err();
        assert!(refused, "the guest connection is closed, not left hanging");
        // The switch side comes down with it, and nothing arrived there past
        // the forwarded head: the claim was never read into a frame.
        let mut probe = [0u8; 1];
        match tokio::time::timeout(DEADLINE, h.switch.read(&mut probe)).await {
            Ok(Ok(0)) => {}
            Ok(Ok(n)) => panic!("{n} byte(s) arrived at the switch past the head"),
            Ok(Err(e)) => panic!("reading the switch end failed: {e}"),
            Err(_) => panic!("the gate left the switch side hanging"),
        }
    }

    /// The relay ends when either leg ends, not only when the guest goes away:
    /// a switch that closes this one connection's end — without the whole
    /// gvproxy process exiting behind it, which the supervisor catches and
    /// tears the gate down for — must not leave the egress leg waiting on a
    /// guest that is idle and has nothing more to send. The ingress leg's
    /// completion is raced against the egress leg, so the relay, the gate's
    /// dial, and the switch write half come down at once, with a line saying
    /// which leg ended, instead of lingering until the guest's next frame.
    #[tokio::test]
    async fn a_switch_that_hangs_up_takes_the_relay_down_with_it() {
        let registry = BoxRegistry::new(SUBNET);
        tcp_lan_box(&registry, LEASE);
        let mut h = gate_over(registry).await;

        // The switch hangs up while the guest is on the connection and idle:
        // no frame is in flight, so nothing but this close can end the relay.
        h.switch
            .shutdown()
            .await
            .expect("closing the stand-in switch's end");

        // The gate says which leg ended — the line a bundle's daemon log tail
        // carries for a box whose egress went dark with the guest still there.
        wait_for_log(&h.log, "the switch closed its side of the connection").await;
        // And the guest's side comes down with the relay, promptly, rather
        // than hanging on until its next frame finds nowhere to write.
        let mut probe = [0u8; 1];
        match tokio::time::timeout(DEADLINE, h.guest.read(&mut probe)).await {
            Ok(Ok(0)) => {}
            Ok(Ok(n)) => panic!("the gate left {n} byte(s) for a hung-up-on guest to read"),
            Ok(Err(e)) => panic!("reading the guest end failed: {e}"),
            Err(_) => panic!("a hung-up switch left the relay up past {DEADLINE:?}"),
        }
    }

    /// The control relay comes down with a switch that hangs up on an idle
    /// control connection — the same per-connection close the frame relay
    /// races its legs for. gvproxy closes this one connection's end while the
    /// guest is still on it, idle, waiting for the answer to the request it
    /// already spoke: a keep-alive control channel's normal event, not a
    /// process exit the supervisor catches. A relay that watched only its
    /// request leg would never learn of it and hold the splice, the gate's
    /// dial and both socket halves open until the guest next spoke or closed.
    #[tokio::test]
    async fn a_switch_that_hangs_up_takes_the_control_relay_down_with_it() {
        let registry = BoxRegistry::new(SUBNET);
        tcp_lan_box(&registry, LEASE);
        // One live control exchange, so the connection really is relaying
        // control traffic and the guest is on it, idle, waiting.
        let request =
            b"POST /services/dns/add HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n"
                .to_vec();
        let mut h = gate_over_control(registry, request).await;

        // The switch hangs up while the guest is idle: no request is in
        // flight, so nothing but this close can end the exchange.
        h.switch
            .shutdown()
            .await
            .expect("closing the stand-in switch's end");

        // The gate says which leg ended — the line a bundle's daemon log tail
        // carries for a control connection the host closed under an idle guest.
        wait_for_log(
            &h.log,
            "the switch closed its side of the control connection",
        )
        .await;
        // And the guest's side comes down with the relay, promptly, rather than
        // hanging on until a guest with nothing more to say speaks again.
        let mut probe = [0u8; 1];
        match tokio::time::timeout(DEADLINE, h.guest.read(&mut probe)).await {
            Ok(Ok(0)) => {}
            Ok(Ok(n)) => panic!("the gate left {n} byte(s) for a hung-up-on guest to read"),
            Ok(Err(e)) => panic!("reading the guest end failed: {e}"),
            Err(_) => panic!("a hung-up switch left the control relay up past {DEADLINE:?}"),
        }
    }

    /// A switch that takes a control request and then says nothing — neither
    /// answering nor closing, the shape a wedged gvproxy would wear —
    /// releases the relay at the drain bound, the same bound the handshake
    /// reads under. The drain after the guest's request ends is bounded
    /// because it is the only thing left holding the relay, the gate's dial
    /// and both socket halves: without the bound they would hang on a switch
    /// that is never going to speak again, for as long as the gate lives.
    #[tokio::test]
    async fn a_switch_that_never_answers_releases_the_control_relay_at_the_drain_bound() {
        // The bound shrunk from [`HANDSHAKE_TIMEOUT`] — the one every real
        // connection reads and drains under — so the release is watched in
        // milliseconds rather than five seconds.
        let bound = Duration::from_millis(200);
        assert!(
            bound < HANDSHAKE_TIMEOUT,
            "the release must be watched in less time than the real bound allows"
        );
        let registry = BoxRegistry::new(SUBNET);
        tcp_lan_box(&registry, LEASE);
        let table = registry.table();
        let dir = TempDir::new().expect("a tempdir is creatable");
        let switch_sock = dir.path().join("gvproxy-switch.sock");
        let listener = UnixListener::bind(&switch_sock).expect("binding the stand-in switch");

        let log = CaptureWriter::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(log.clone())
            .with_ansi(false)
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);

        let (mut guest, gate_end) = UnixStream::pair().expect("pairing the guest's socket");
        tokio::spawn(serve_connection(
            gate_end,
            switch_sock.clone(),
            table,
            Arc::new(DropLimiter::new()),
            bound,
        ));
        // One control request, spoken whole, answered by nothing.
        let request =
            b"POST /services/dns/add HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n";
        guest
            .write_all(request)
            .await
            .expect("writing the control request");
        // The gate's dial is accepted and the request arrives at the switch…
        let (mut switch, _) = listener.accept().await.expect("accepting the gate's dial");
        let mut seen = vec![0u8; request.len()];
        read_within(&mut switch, &mut seen).await;
        assert_eq!(seen, request, "the one request reached the switch");
        // …and the guest ends its side of it — the daemon's own client does
        // the same once its answer is read — which is the state whose drain
        // is the bounded one.
        guest.shutdown().await.expect("closing the guest's end");

        // The drain gives the switch its bound, then gives up on it with a
        // line naming the bound it waited out.
        wait_for_log(&log, "did not answer a control request within the bound").await;
        let logged = log.contents();
        assert!(
            logged.contains(&format!("drain_timeout={bound:?}")),
            "the release names the bound it waited out, got: {logged}"
        );
        // And the guest's side comes down with the relay, promptly, rather
        // than hanging on until the switch might have spoken.
        let mut probe = [0u8; 1];
        match tokio::time::timeout(DEADLINE, guest.read(&mut probe)).await {
            Ok(Ok(0)) => {}
            Ok(Ok(n)) => panic!("the gate left {n} byte(s) for a drained guest to read"),
            Ok(Err(e)) => panic!("reading the guest end failed: {e}"),
            Err(_) => panic!("a switch that never answered held the relay past {DEADLINE:?}"),
        }
    }

    /// The peer the gate's handshake reads from lives inside the escape
    /// boundary NET-081 exists for, so the handshake is bounded: a guest that
    /// connects and then stays silent — saying nothing at all, or starting a
    /// head it never ends — is refused within the bound, and the host switch
    /// connection the gate's dial opened comes down with it, with nothing of
    /// the guest ever written on. Without the bound a silent guest would hold
    /// a host switch connection and a relay task for the gate's lifetime.
    #[tokio::test]
    async fn a_silent_guest_is_refused_within_the_handshake_bound() {
        // The bound shrunk from [`HANDSHAKE_TIMEOUT`] — the one `accept_loop`
        // passes every real connection — so the refusal is watched in
        // milliseconds rather than five seconds.
        let bound = Duration::from_millis(200);
        assert!(
            bound < HANDSHAKE_TIMEOUT,
            "the refusal must be watched in less time than the real bound allows"
        );
        let registry = BoxRegistry::new(SUBNET);
        tcp_lan_box(&registry, LEASE);
        let table = registry.table();
        let dir = TempDir::new().expect("a tempdir is creatable");
        let switch_sock = dir.path().join("gvproxy-switch.sock");
        // The stand-in switch: a listener the gate's handshake dials.
        let listener = UnixListener::bind(&switch_sock).expect("binding the stand-in switch");

        // The two shapes of a silent peer: a guest that says nothing at all,
        // and one that starts a head and never ends it. Both are refused the
        // same way.
        for first_write in [Vec::new(), b"POST /connec".to_vec()] {
            let (mut guest, gate_end) = UnixStream::pair().expect("pairing the guest's socket");
            tokio::spawn(serve_connection(
                gate_end,
                switch_sock.clone(),
                table.clone(),
                Arc::new(DropLimiter::new()),
                bound,
            ));
            if !first_write.is_empty() {
                guest
                    .write_all(&first_write)
                    .await
                    .expect("writing the never-ended head");
            }
            // The gate dials the switch first, so a silent guest is holding a
            // live host switch connection at this point — the thing the bound
            // exists to release.
            let (mut switch, _) = listener.accept().await.expect("accepting the gate's dial");

            // The switch side comes down within the deadline, and nothing of
            // the guest was written on before it did.
            let mut probe = [0u8; 1];
            match tokio::time::timeout(DEADLINE, switch.read(&mut probe)).await {
                Ok(Ok(0)) => {}
                Ok(Ok(n)) => panic!("{n} byte(s) of a silent guest reached the switch"),
                Ok(Err(e)) => panic!("reading the switch end failed: {e}"),
                Err(_) => panic!("a silent guest held the switch connection past {DEADLINE:?}"),
            }
            // And the guest's side is closed too, not left hanging.
            match tokio::time::timeout(DEADLINE, guest.read(&mut probe)).await {
                Ok(Ok(0)) => {}
                Ok(Ok(n)) => panic!("the gate left {n} byte(s) for a silent guest to read"),
                Ok(Err(e)) => panic!("reading the guest end failed: {e}"),
                Err(_) => panic!("the gate left the silent guest's connection hanging"),
            }
        }
    }

    /// The pure decision, apart from the relay: the families that carry no
    /// readable source never reach the table — the shared verdict's own
    /// family drops decide them, whatever the rows hold — and a source no row
    /// holds is refused before any rule is consulted, while a held source is
    /// decided by its namespace's own rules, the shared verdict unchanged.
    #[test]
    fn gate_verdict_decides_by_source_and_rules() {
        let registry = BoxRegistry::new(SUBNET);
        tcp_lan_box(&registry, LEASE);
        let table = registry.table();
        let summarize = sessions::core::egress::summarize;

        // A held source is decided by its rules: the same frame that the
        // relay test watches pass and drop, decided here with no sockets.
        let declared = summarize(&ipv4_frame(LEASE, 6, [10, 1, 2, 3], 80));
        assert!(matches!(gate_verdict(&declared, &table), Ok(())));
        let rules = table
            .by_source(LEASE)
            .expect("the published box's row is held")
            .egress()
            .clone();
        assert!(
            matches!(
                sessions::core::egress::verdict(&declared, &rules),
                FrameVerdict::Admit
            ),
            "the shared verdict admits what the gate admits"
        );
        let undeclared = summarize(&ipv4_frame(LEASE, 6, [203, 0, 113, 7], 443));
        assert_eq!(
            gate_verdict(&undeclared, &table),
            Err(GateDrop::Verdict(DropReason::UndeclaredSubnet {
                dst: [203, 0, 113, 7],
                proto: 6,
            }))
        );

        // A source no row holds is refused with the table's own class, before
        // any rule: even an ARP announcing it — in-guest, ARP is a declared
        // path for every box — and whatever destination the frame carries.
        let unknown = summarize(&ipv4_frame([100, 64, 0, 99], 6, [10, 1, 2, 3], 80));
        assert_eq!(
            gate_verdict(&unknown, &table),
            Err(GateDrop::UnknownSource {
                src: [100, 64, 0, 99]
            })
        );
        let foreign_arp = summarize(&arp_frame([100, 64, 0, 99]));
        assert_eq!(
            gate_verdict(&foreign_arp, &table),
            Err(GateDrop::UnknownSource {
                src: [100, 64, 0, 99]
            })
        );

        // Families with no readable source are the shared verdict's own drops,
        // under any table — an empty one included.
        let empty = BoxRegistry::new(SUBNET).table();
        assert!(empty.is_empty());
        let v6 = summarize(&ipv6_frame());
        assert_eq!(
            gate_verdict(&v6, &empty),
            Err(GateDrop::Verdict(DropReason::Ipv6))
        );
        let truncated = summarize(&[0u8; 13]);
        assert_eq!(
            gate_verdict(&truncated, &table),
            Err(GateDrop::Verdict(DropReason::Truncated))
        );
        // The summaries agree with the families the frames were built as.
        assert_eq!(v6.family(), FrameFamily::Ipv6);
        assert_eq!(truncated.family(), FrameFamily::Truncated);
    }

    /// One drop line per source address per rule per interval: the first
    /// emission fires, a repeat within the interval does not, a different
    /// source or a different rule keeps its own line, and the interval
    /// elapsing fires again. A frame with no readable source is a key of its
    /// own, so the family drops share no window with a box's.
    #[test]
    fn drop_limiter_rate_limits_per_source_and_rule() {
        let limiter = DropLimiter::new();
        let t0 = Instant::now();
        let src = [100, 64, 0, 9];

        assert_eq!(
            limiter.should_warn_at(Some(src), "egress-undeclared-subnet", t0),
            WarnDecision::Named
        );
        assert_eq!(
            limiter.should_warn_at(
                Some(src),
                "egress-undeclared-subnet",
                t0 + Duration::from_millis(10)
            ),
            WarnDecision::Silent
        );
        // A different source under the same rule keeps its own line…
        assert_eq!(
            limiter.should_warn_at(Some([100, 64, 0, 10]), "egress-undeclared-subnet", t0),
            WarnDecision::Named
        );
        // …and the same source under a different rule keeps its own.
        assert_eq!(
            limiter.should_warn_at(Some(src), "egress-foreign-source", t0),
            WarnDecision::Named
        );
        // A sourceless frame is a key of its own, and so are two family rules
        // between themselves.
        assert_eq!(
            limiter.should_warn_at(None, "egress-ipv6", t0),
            WarnDecision::Named
        );
        assert_eq!(
            limiter.should_warn_at(None, "egress-undeclared-ethertype", t0),
            WarnDecision::Named
        );
        assert_eq!(
            limiter.should_warn_at(None, "egress-ipv6", t0 + Duration::from_millis(10)),
            WarnDecision::Silent
        );
        // Once the interval has elapsed, the line fires again.
        assert_eq!(
            limiter.should_warn_at(
                Some(src),
                "egress-undeclared-subnet",
                t0 + DROP_WARN_MIN_INTERVAL
            ),
            WarnDecision::Named
        );
    }

    /// The limiter's window table is bounded, because the source address it
    /// keys by is the dropped frame's own bytes and a hostile guest chooses
    /// those: flooding distinct spoofed addresses must not grow host memory
    /// one entry per frame. Past the cap a new pair shares one line per rule,
    /// a pair the table already holds keeps its own window, and stale
    /// windows make room again — so the fold is a flood's shape, not a
    /// permanent state.
    #[test]
    fn drop_limiter_bounds_its_source_table() {
        let limiter = DropLimiter::new();
        let t0 = Instant::now();
        let rule = "egress-unknown-source";
        // A source address per index: distinct bytes, so distinct keys.
        let source = |i: usize| u32::try_from(i).expect("an index fits a u32").to_be_bytes();

        // Fill the table to its cap, one window per distinct pair.
        for i in 0..DROP_WARN_MAX_TRACKED_PAIRS {
            assert_eq!(
                limiter.should_warn_at(Some(source(i)), rule, t0),
                WarnDecision::Named,
                "pair {i} takes a window of its own while the table has room"
            );
        }
        // At the cap, a pair the table holds no window for no longer gets
        // one: it falls to the rule's shared line…
        assert_eq!(
            limiter.should_warn_at(Some(source(DROP_WARN_MAX_TRACKED_PAIRS)), rule, t0),
            WarnDecision::Overflow,
            "past the cap a new pair folds into the rule's shared line"
        );
        // …and so does every distinct source after it, at the shared line's
        // own cadence — no window per frame.
        assert_eq!(
            limiter.should_warn_at(Some(source(DROP_WARN_MAX_TRACKED_PAIRS + 1)), rule, t0),
            WarnDecision::Silent,
            "the rule's shared line is rate-limited like any other"
        );
        let windows = || {
            limiter
                .last
                .lock()
                .expect("the limiter's lock is held only across this read")
                .len()
        };
        assert!(
            windows() <= DROP_WARN_MAX_TRACKED_PAIRS + 1,
            "a flood of distinct sources added no window per frame: {} windows",
            windows()
        );
        // A pair the table already holds keeps its own window, full or not.
        assert_eq!(
            limiter.should_warn_at(Some(source(0)), rule, t0 + Duration::from_millis(10)),
            WarnDecision::Silent,
            "a held pair is still rate-limited by its own window"
        );
        // Once every window has gone stale, the flood is over by shape: the
        // prune frees the table and an honest source is named per line again.
        assert_eq!(
            limiter.should_warn_at(
                Some(source(DROP_WARN_MAX_TRACKED_PAIRS + 2)),
                rule,
                t0 + DROP_WARN_MIN_INTERVAL
            ),
            WarnDecision::Named,
            "stale windows make room; a new source gets its own line again"
        );
        assert_eq!(windows(), 1, "the stale windows were pruned, not kept");
    }
}
