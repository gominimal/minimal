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

/// Where the upgrade head ends and the frames begin.
const HEAD_END: &[u8] = b"\r\n\r\n";

/// Bound on the bytes read looking for the upgrade head's end. The real head
/// is a few dozen constant bytes, so a guest still talking past this without
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
/// forward the upgrade head the guest wrote verbatim, then relay frames both
/// ways for as long as the guest stays connected — egress through the
/// verdict, ingress untouched.
///
/// `handshake_timeout` bounds everything up to and including the forwarded
/// head. It is a parameter only so a test can shrink it; every caller outside
/// this module's tests reaches a connection through [`accept_loop`], which
/// passes [`HANDSHAKE_TIMEOUT`].
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
        let (head, carry) = match read_connect_head(&mut guest).await {
            Ok(pair) => pair,
            Err(error) => {
                tracing::warn!(
                    %error,
                    "egress gate could not read the switch upgrade head from the guest"
                );
                return Err(());
            }
        };
        if let Err(error) = switch.write_all(&head).await {
            tracing::warn!(%error, "egress gate could not forward the switch upgrade head");
            return Err(());
        }
        Ok((switch, carry))
    };
    let (switch, carry) = match tokio::time::timeout(handshake_timeout, handshake).await {
        Ok(Ok(pair)) => pair,
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
    // Ingress (switch → guest), untouched and un-parsed. The gate's job is
    // the egress direction; what a box may receive is the target's ingress
    // policy, decided in the guest where its declarations are enforced.
    // Aborted when the egress leg ends, which is the guest going away.
    let ingress = tokio::spawn(copy_switch_to_guest(switch_rx, guest_tx));
    let egress =
        relay_guest_to_switch(Prefixed::new(carry, guest_rx), switch_tx, table, limiter).await;
    ingress.abort();
    match egress {
        // The guest closed its side: the shuttle reconnects per boot and
        // drops the connection at teardown.
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {}
        Err(error) => {
            tracing::warn!(%error, "egress gate relay ended on an error");
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

/// Reads the gvproxy upgrade head from the guest — through the first
/// [`HEAD_END`] — returning it and any bytes read past it: one `read` can
/// carry the head and the first frames together, and those bytes are frames,
/// not head, so the relay must not lose them.
///
/// # Errors
///
/// Returns the I/O error if the guest closes before the head ends, or
/// [`io::ErrorKind::InvalidData`] when the head exceeds [`MAX_HEAD`] without
/// ending — a guest that never upgrades is refused, not buffered.
async fn read_connect_head(guest: &mut UnixStream) -> io::Result<(Vec<u8>, Vec<u8>)> {
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
/// single `read` returned past the end of the upgrade head — the start of the
/// frame stream — replayed before the socket is read, so no frame is lost to
/// the head's read.
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
    /// The guest's connect plays libkrun's vsock bridge dialing the gate's
    /// socket; the forwarded head is read back off the switch end and asserted
    /// verbatim, so every harness proves the upgrade passes through untouched
    /// before the frame stream begins.
    pub(crate) async fn gate_over_with(registry: BoxRegistry, first_write: Vec<u8>) -> GateHarness {
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
        let mut guest = UnixStream::connect(&gate_sock)
            .await
            .expect("connecting the guest end");
        // …and the gate's dial of the switch it fronts.
        let (mut switch, _) = listener.accept().await.expect("accepting the gate's dial");
        // The guest's first write — the upgrade head, alone or with frames
        // pipelined behind it.
        guest
            .write_all(&first_write)
            .await
            .expect("writing the guest's first bytes");
        // The upgrade head, forwarded verbatim and read back off the switch
        // end, so the frame stream begins at a known point.
        let mut head = vec![0u8; CONNECT_REQUEST.len()];
        switch
            .read_exact(&mut head)
            .await
            .expect("reading the forwarded head");
        assert_eq!(
            head, CONNECT_REQUEST,
            "the gate forwards the switch upgrade head verbatim"
        );

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
    async fn read_within(stream: &mut UnixStream, buf: &mut [u8]) {
        match tokio::time::timeout(DEADLINE, stream.read_exact(buf)).await {
            Ok(read) => {
                read.expect("reading the frame body");
            }
            Err(_) => panic!("expected a frame at the switch within {DEADLINE:?}, got none"),
        }
    }

    /// Polls the captured log until it contains `needle`, failing with the
    /// log's contents once [`DEADLINE`] passes.
    pub(crate) async fn wait_for_log(harness: &GateHarness, needle: &str) {
        let deadline = tokio::time::Instant::now() + DEADLINE;
        loop {
            let logged = harness.log.contents();
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
        DEADLINE, arp_frame, expect_frame, expect_silence, gate_over, gate_over_with, ipv4_frame,
        ipv6_frame, send_frame, wait_for_log,
    };
    use super::{
        CONNECT_REQUEST, DROP_WARN_MAX_TRACKED_PAIRS, DROP_WARN_MIN_INTERVAL, DropLimiter,
        GateDrop, HANDSHAKE_TIMEOUT, MAX_HEAD, WarnDecision, gate_verdict, serve_connection,
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
        wait_for_log(&h, "egress-undeclared-subnet").await;
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
        wait_for_log(&h, "egress-unknown-source").await;
        wait_for_log(&h, "egress-ipv6").await;
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

    /// A guest that never ends an upgrade head is refused, not buffered, and
    /// nothing of it ever reaches the switch: the gate fails closed on a peer
    /// that will not speak the protocol.
    #[tokio::test]
    async fn a_head_that_never_ends_refuses_the_connection() {
        let registry = BoxRegistry::new(SUBNET);
        let mut h = gate_over(registry).await;

        // `MAX_HEAD + 1` bytes with no `\r\n\r\n` anywhere in them.
        let noise = vec![b'x'; MAX_HEAD + 1];
        h.guest
            .write_all(&noise)
            .await
            .expect("writing the endless head");
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
