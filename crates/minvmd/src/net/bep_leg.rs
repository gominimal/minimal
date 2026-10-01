//! The Box Egress Proxy's host-side delivery leg (NET-132).
//!
//! A box reaches the node-local Box Egress Proxy at the switch's host-gateway
//! address for it — [`SwitchSubnet::box_egress_proxy_address`], a second
//! virtual IP of the gateway the switch answers ARP for, so a box can route
//! to it. That address is deliberately kept out of the `nat` loopback
//! translation: the translation rewrites every box to one source, and the
//! proxy's listener must see each box by its own switch address — one source
//! for every box and every host process is exactly what NET-132 keeps off
//! the proxy, and the proxy's refusals (a connection that is not a box
//! attachment is refused at the listener) rest on the source.
//!
//! gvproxy terminates the traffic it receives, which is where a box's source
//! is lost — so the egress gate hands every TCP frame addressed to the
//! proxy's address to this leg *before* the switch sees it, and this leg
//! terminates the box's TCP itself and delivers the connection to the
//! proxy's listener with the box's switch address carried on it. The leg
//! speaks the switch's own wire format on both of its faces, so the gate's
//! handoff is a re-plumbing, not a translation:
//!
//! * **toward the gate** — the socket beside the switch socket
//!   ([`bep_sock_beside`]), length-framed Ethernet frames both ways, the
//!   framing gvproxy speaks. The gate dials it once per relaying connection
//!   and diverts the frames it admits whose destination is the proxy's
//!   address; frames the leg sends back are copied verbatim to the guest, so
//!   the box's TCP sees only ever the gateway.
//! * **toward the proxy** — a plain TCP dial of the proxy's listener, with a
//!   PROXY protocol v1 header (`PROXY TCP4 <src> <dst> <sport> <dport>`)
//!   ahead of the box's stream: the source a TCP socket cannot present
//!   unprivileged (binding a non-local source fails the route lookup), the
//!   listener reads off the wire. Until the proxy lands, a stub listener
//!   ([`run_stub_listener`]) stands in: it consumes the header and answers
//!   one line naming the source the connection was presented from — the line
//!   the e2e proof and [`host_process_never_arrives_from_a_box_address`]
//!   read.
//!
//! The TCP the leg terminates is the minimum a box's connection needs, and
//! no more. The path behind it is the vsock→gate→leg hop, which loses no
//! frame and reorders nothing, so there are no retransmission timers and no
//! reassembly: in-order segments are consumed as they arrive, a
//! retransmitted one is re-acknowledged rather than rewritten, and an
//! out-of-order one is dropped for the box to resend (the box's own stack
//! retransmits; nothing here buffers for it). Window updates are honoured on
//! the leg's own sending side, so a slow box reader holds the leg's sends
//! rather than a queue of frames it cannot take. A flow ends the way its two
//! ends do: the box's FIN half-closes the listener's leg, the listener's EOF
//! half-closes the box's, and either side's RST tears the flow down. When
//! the gate's relaying connection goes away — the tap is gone, the guest
//! shut down — every flow on it is dropped with its upstream socket, which
//! is what keeps a dead box from holding listener connections open.
//!
//! Per connection delivered, the leg logs one debug line carrying the box's
//! switch address and the listener — the record a diagnostic bundle's daemon
//! log tail reads back.

use std::collections::HashMap;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream, UnixListener, UnixStream};
use tokio::sync::{Notify, mpsc};
use tokio::task::JoinHandle;

use switch::SwitchSubnet;

/// The largest frame the leg accepts from, and sends to, the gate: the gate's
/// own bound ([`crate::net::egress_gate`]'s MTU-derived maximum), so a
/// diverted frame fits whatever the gate already carries.
const MAX_FRAME: usize = 1518;

/// The largest TCP segment the leg sends to the box in one frame: Ethernet
/// and IPv4 and TCP headers under the MTU, with room to spare, so a segment
/// is never fragmented and never a frame the gate's bound refuses.
const MAX_SEGMENT: usize = 1400;

/// The IPv4 protocol number for TCP.
const IPPROTO_TCP: u8 = 6;

/// TCP flags, the ones the leg sends and reads. Crate-visible so a test can
/// shape the traffic the leg and the gate's divert are driven with.
pub(crate) const TCP_FIN: u8 = 0x01;
pub(crate) const TCP_SYN: u8 = 0x02;
pub(crate) const TCP_RST: u8 = 0x04;
pub(crate) const TCP_PSH: u8 = 0x08;
pub(crate) const TCP_ACK: u8 = 0x10;

/// The window the leg advertises toward the box: everything it reads is
/// written on to the listener as it arrives, so nothing is held that would
/// need a smaller one.
const ADVERTISED_WINDOW: u16 = 0xFFFF;

/// How long the leg waits for the listener's socket to accept the delivered
/// connection before resetting the box's connection: the listener is a local
/// dial, so this bounds a wedged listener rather than a network.
const DELIVERY_TIMEOUT: Duration = Duration::from_secs(5);

/// The most flows one gate connection may hold: a box that opens connections
/// without bound must not pin listener sockets without one. A SYN past the
/// bound is reset, not dropped, so the box's connect fails cleanly.
const MAX_FLOWS_PER_PIPE: usize = 256;

/// The address the shipped leg binds its stub listener on and delivers to —
/// the proxy's listener address until the proxy lands and takes it over. It
/// must avoid every port the e2e lanes and the shipped proxies hold:
/// `:7654` is the hostname router's and `:7655` the retired mTLS listener's
/// (whose absence an e2e case asserts).
pub(crate) const DEFAULT_BEP_DELIVERY_ADDR: SocketAddr =
    SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::LOCALHOST), 18654);

/// The handoff socket's name beside the switch socket: distinct from every
/// other socket the daemon owns, in the same parent directory
/// ([`crate::sock::prepare_socket_dir`] made it mode 0700).
const BEP_SOCK_FILE: &str = "gvproxy-bep.sock";

/// The handoff socket's path beside a given switch socket (same parent
/// directory). Pure — derived only from `switch_sock`, no env — so it is
/// unit-testable and the runtime can derive it from the switch socket it
/// already holds.
#[must_use]
pub(crate) fn bep_sock_beside(switch_sock: &Path) -> PathBuf {
    switch_sock
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(BEP_SOCK_FILE)
}

/// What the egress gate needs to hand frames to this leg: the proxy's gateway
/// address to divert frames by, and the handoff socket to dial per relaying
/// connection. The gate drops what it cannot deliver — a frame addressed to
/// the proxy's address never reaches the switch, so the proxy's listener is
/// never fed a source the leg did not carry.
#[derive(Debug, Clone)]
pub(crate) struct BepDivert {
    /// The proxy's address on the switch
    /// ([`SwitchSubnet::box_egress_proxy_address`]).
    pub(crate) address: Ipv4Addr,
    /// The handoff socket to dial per relaying connection
    /// ([`bep_sock_beside`]).
    pub(crate) handoff_sock: PathBuf,
}

/// A running delivery leg: the handoff socket it accepted gate connections
/// on, and the stub listener standing in for the proxy's. Dropping it stops
/// both, dropping every flow with its gate connection.
#[must_use = "dropping BepLeg stops the delivery leg and the stub listener"]
pub(crate) struct BepLeg {
    worker: Option<std::thread::JoinHandle<()>>,
    stop_tx: Option<tokio::sync::oneshot::Sender<()>>,
    handoff_sock: PathBuf,
}

impl BepLeg {
    /// Binds the leg's handoff socket at `handoff_sock` and runs its two
    /// loops — the stub listener on `stub` (a caller-bound listener, so a
    /// test chooses the port) and the handoff listener — on a dedicated
    /// runtime thread, delivering to `delivery`. `bep_address` is the proxy's
    /// address on the switch; frames addressed elsewhere are dropped rather
    /// than terminated, so the leg terminates only what was diverted to it.
    ///
    /// A stale socket file at `handoff_sock` must be removed by the caller
    /// first (the same discipline the switch and gate sockets get), or the
    /// bind fails.
    ///
    /// # Errors
    ///
    /// Returns the I/O error when the handoff socket cannot be bound, or
    /// when the leg's runtime thread cannot be started.
    pub(crate) fn bind(
        handoff_sock: PathBuf,
        stub: std::net::TcpListener,
        delivery: SocketAddr,
        bep_address: Ipv4Addr,
    ) -> io::Result<Self> {
        let listener = UnixListener::bind(&handoff_sock)?;
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel::<io::Result<()>>();
        let worker = std::thread::Builder::new()
            .name("bep-leg".into())
            .spawn(move || {
                let runtime = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(runtime) => runtime,
                    Err(error) => {
                        let _ = ready_tx.send(Err(error));
                        return;
                    }
                };
                let stub = match tokio::net::TcpListener::from_std(stub) {
                    Ok(stub) => stub,
                    Err(error) => {
                        let _ = ready_tx.send(Err(error));
                        return;
                    }
                };
                if ready_tx.send(Ok(())).is_err() {
                    // The caller is gone before the leg could report ready:
                    // nothing to serve, and the drop below stops the leg.
                    return;
                }
                runtime.block_on(async move {
                    tokio::select! {
                        _ = stop_rx => {}
                        ended = run_leg(listener, stub, delivery, bep_address) => {
                            // A loop that ended on its own — a listener that
                            // failed for good — ends the leg with it.
                            tracing::warn!(?ended, "the box egress proxy's leg ended");
                        }
                    }
                });
            })?;
        // Ready, or the error that failed the leg's own binds.
        match ready_rx.recv() {
            Ok(Ok(())) => {}
            Ok(Err(error)) => return Err(error),
            Err(_) => {
                // The thread died before reporting anything: join it and
                // surface nothing beyond the fact.
                let _ = worker.join();
                return Err(io::Error::other(
                    "the box egress proxy's leg ended before it reported ready",
                ));
            }
        }
        Ok(Self {
            worker: Some(worker),
            stop_tx: Some(stop_tx),
            handoff_sock,
        })
    }

    /// Binds the shipped leg beside the switch socket `switch_sock` sits on:
    /// the handoff socket [`bep_sock_beside`] names, the stub listener on
    /// [`DEFAULT_BEP_DELIVERY_ADDR`], and delivery to that same address —
    /// the stand-in configuration that runs until the proxy lands — and the
    /// proxy's address `subnet` carves for it.
    ///
    /// # Errors
    ///
    /// Returns the I/O error when the handoff socket or the stub listener
    /// cannot be bound.
    pub(crate) fn bind_beside(switch_sock: &Path, subnet: SwitchSubnet) -> io::Result<Self> {
        let stub = std::net::TcpListener::bind(DEFAULT_BEP_DELIVERY_ADDR)?;
        Self::bind(
            bep_sock_beside(switch_sock),
            stub,
            DEFAULT_BEP_DELIVERY_ADDR,
            subnet.box_egress_proxy_address(),
        )
    }

    /// The handoff socket the leg accepted gate connections on.
    pub(crate) fn handoff_sock(&self) -> &Path {
        &self.handoff_sock
    }
}

impl Drop for BepLeg {
    fn drop(&mut self) {
        if let Some(stop_tx) = self.stop_tx.take() {
            // A caller already gone leaves the send failed and the leg to
            // stop with the process.
            let _ = stop_tx.send(());
        }
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

/// The leg's two loops, as one spawnable unit: accepts gate connections on
/// the handoff listener and stands in for the proxy on the stub listener,
/// until either ends — which, for a listener that failed for good, is the
/// leg's own end. Tests spawn this on their own runtime, which is what puts
/// the leg's log lines under their thread-local capture.
async fn run_leg(
    listener: UnixListener,
    stub: TcpListener,
    delivery: SocketAddr,
    bep_address: Ipv4Addr,
) {
    let stub_task = tokio::spawn(run_stub_listener(stub));
    let handoff_task = tokio::spawn(run_handoff(listener, delivery, bep_address));
    tokio::select! {
        ended = stub_task => {
            tracing::warn!(?ended, "the box egress proxy's stub listener ended");
        }
        ended = handoff_task => {
            tracing::warn!(?ended, "the box egress proxy's handoff listener ended");
        }
    }
}

/// Accepts gate connections on the leg's handoff socket, one relay per
/// connection: the gate dials once per relaying connection, so everything on
/// one socket belongs to one guest relay, and a flow's frames never cross
/// guests. When the connection ends, every flow on it is dropped with its
/// upstream socket.
async fn run_handoff(listener: UnixListener, delivery: SocketAddr, bep_address: Ipv4Addr) {
    loop {
        let (sock, _peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(error) => {
                tracing::warn!(%error, "the box egress proxy's handoff accept failed");
                continue;
            }
        };
        tokio::spawn(serve_handoff(sock, delivery, bep_address));
    }
}

/// Serves one gate connection end to end: the framed frames the gate diverts
/// in, the response frames the leg sends back, and the flows in between.
/// Owned per connection, so a box's TCP state lives exactly as long as the
/// relay that carries it.
#[expect(
    clippy::indexing_slicing,
    reason = "every `frame[..n]` is bounded by the `n > MAX_FRAME` rejection above it"
)]
async fn serve_handoff(sock: UnixStream, delivery: SocketAddr, bep_address: Ipv4Addr) {
    let (mut reader, writer) = sock.into_split();
    // Every outbound frame — the flow state machine's and the upstream
    // tasks' — goes through one channel to one writer, so no two tasks ever
    // interleave a length prefix with a frame.
    let (frame_tx, mut frame_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let writer_task = tokio::spawn(async move {
        let mut writer = writer;
        while let Some(frame) = frame_rx.recv().await {
            if writer.write_all(&frame).await.is_err() {
                // The gate is gone; every flow on this pipe is torn down
                // with it below.
                return;
            }
        }
    });
    let mut flows: HashMap<FlowKey, FlowHandle> = HashMap::new();
    let mut len_buf = [0u8; 2];
    let mut frame = vec![0u8; MAX_FRAME];
    loop {
        if reader.read_exact(&mut len_buf).await.is_err() {
            break;
        }
        let n = u16::from_le_bytes(len_buf) as usize;
        // A frame the leg cannot read whole ends the pipe: the gate never
        // sends one, so this is a broken peer, not traffic.
        if n == 0 || n > MAX_FRAME || reader.read_exact(&mut frame[..n]).await.is_err() {
            break;
        }
        match parse_frame(&frame[..n]) {
            Some(segment) => {
                if segment.dst_ip != bep_address {
                    // The gate diverts only frames for the proxy's address;
                    // anything else here is a peer to stop trusting. The
                    // frame is dropped, not answered.
                    tracing::debug!(
                        destination = %segment.dst_ip,
                        "the box egress proxy's leg read a frame addressed elsewhere"
                    );
                    continue;
                }
                handle_segment(segment, &mut flows, &frame_tx, delivery).await;
            }
            None => {
                tracing::debug!(
                    n,
                    "the box egress proxy's leg read a frame it does not terminate"
                );
                continue;
            }
        }
    }
    // The pipe is over: drop every flow, which closes every upstream socket
    // and aborts every upstream task, and end the writer.
    for (_, flow) in flows.drain() {
        flow.teardown();
    }
    drop(frame_tx);
    let _ = writer_task.await;
}

/// A box's connection to the proxy, keyed by the addresses it came from and
/// the port it asked for: the key the box's own TCP conversation lives under,
/// and the key a retransmitted segment resolves to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct FlowKey {
    src: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
}

/// The wire facts of one flow that never change: who sent the frames and who
/// they were addressed to, read off the SYN that opened the flow.
#[derive(Debug, Clone, Copy)]
struct FlowAddrs {
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
}

/// The sequencing state of one flow, shared between the segment loop that
/// reads the box's frames and the upstream task that reads the listener's
/// answers back. The arithmetic is absolute sequence numbers with wrapping
/// comparison, the same convention TCP's own sequence space uses.
#[derive(Debug)]
struct FlowShared {
    /// The leg's initial sequence number for this flow.
    isn: u32,
    /// The next byte the leg expects from the box: the SYN's sequence + 1 to
    /// start with, advanced by every byte and FIN consumed.
    rcv_nxt: u32,
    /// The next sequence number the leg sends to the box.
    snd_nxt: u32,
    /// The lowest sequence number the box has not acknowledged.
    snd_una: u32,
    /// The box's latest advertised receive window, in bytes.
    peer_window: u32,
    /// The box half-closed: it sent a FIN, and nothing further will come.
    peer_fin: bool,
    /// The listener half-closed: its read side returned EOF.
    upstream_eof: bool,
    /// The leg sent its FIN, at `fin_seq`, after both sides closed.
    fin_sent: bool,
    fin_seq: u32,
    /// The flow is done: the upstream task exits when it sees this.
    closed: bool,
}

impl FlowShared {
    /// Whether everything the leg sent — the FIN included, when it sent one —
    /// is acknowledged and both sides have closed: the point a finished flow
    /// can be dropped without leaving the box's TCP waiting for an answer it
    /// will never get.
    fn fully_acked(&self) -> bool {
        self.fin_sent && self.peer_fin && self.snd_una == self.snd_nxt
    }
}

/// One live flow: its sequencing state, the upstream half the segment loop
/// writes the box's bytes to, and the upstream task reading the listener's
/// answers back.
struct FlowHandle {
    addrs: FlowAddrs,
    shared: Arc<Mutex<FlowShared>>,
    /// Woken when the box's window opens or an ACK lands, so the upstream
    /// task re-reads what it may now send.
    notify: Arc<Notify>,
    upstream_write: OwnedWriteHalf,
    upstream_task: JoinHandle<()>,
}

impl FlowHandle {
    /// Tears the flow down: marks it closed so the upstream task exits,
    /// closes the upstream write half, and aborts the task — the listener's
    /// connection ends with the flow, whichever side ended first.
    fn teardown(self) {
        if let Ok(mut shared) = self.shared.lock() {
            shared.closed = true;
        }
        self.notify.notify_one();
        self.upstream_task.abort();
        // `upstream_write` drops here, closing the box→listener direction.
    }
}

/// An ISN the leg hands each new flow: a process-wide counter, unique enough
/// within a box's conversation that a lingering flow's numbers cannot be
/// mistaken for a new flow's. The box's sequence space is its own and never
/// compared against this one.
static ISN_COUNTER: AtomicU32 = AtomicU32::new(0x1f00_0000);

/// Handles one segment the gate diverted in, against the pipe's flows. The
/// pipe's only mutating reader, so flows are decided and advanced one
/// segment at a time — the ordering the path behind the gate guarantees.
async fn handle_segment(
    segment: Segment<'_>,
    flows: &mut HashMap<FlowKey, FlowHandle>,
    frame_tx: &mpsc::UnboundedSender<Vec<u8>>,
    delivery: SocketAddr,
) {
    let key = FlowKey {
        src: segment.src_ip,
        src_port: segment.src_port,
        dst_port: segment.dst_port,
    };

    // A new connection, or a retransmitted SYN for one the leg is still
    // opening: the retransmission waits for the first dial, because the
    // SYN-ACK that follows it answers the box's retransmissions too.
    if segment.flags & TCP_SYN != 0 && segment.flags & TCP_ACK == 0 {
        if flows.contains_key(&key) {
            return;
        }
        if flows.len() >= MAX_FLOWS_PER_PIPE {
            let _ = frame_tx.send(reset_for(&segment));
            return;
        }
        let shared = Arc::new(Mutex::new(FlowShared {
            isn: ISN_COUNTER.fetch_add(1, Ordering::Relaxed),
            rcv_nxt: segment.seq.wrapping_add(1),
            snd_nxt: 0,
            snd_una: 0,
            peer_window: u32::from(segment.window),
            peer_fin: false,
            upstream_eof: false,
            fin_sent: false,
            fin_seq: 0,
            closed: false,
        }));
        let notify = Arc::new(Notify::new());
        let addrs = reply_addrs(&segment);
        // Open the listener's side before anything is sent back: the box's
        // SYN-ACK follows the dial, so a listener that refuses resets the
        // box's connection instead of hanging it.
        let upstream =
            match tokio::time::timeout(DELIVERY_TIMEOUT, TcpStream::connect(delivery)).await {
                Ok(Ok(upstream)) => upstream,
                Ok(Err(error)) => {
                    tracing::warn!(
                        %error,
                        listener = %delivery,
                        source = %segment.src_ip,
                        "the box egress proxy's listener refused the delivered connection"
                    );
                    let _ = frame_tx.send(reset_for(&segment));
                    return;
                }
                Err(_) => {
                    // The dial hung past the bound: a wedged listener, not a
                    // network. Same posture, with no error to name.
                    tracing::warn!(
                        listener = %delivery,
                        dial_timeout = ?DELIVERY_TIMEOUT,
                        source = %segment.src_ip,
                        "the box egress proxy's listener did not answer the delivered \
                         connection's dial"
                    );
                    let _ = frame_tx.send(reset_for(&segment));
                    return;
                }
            };
        let (upstream_read, mut upstream_write) = upstream.into_split();
        // The PROXY v1 header is the box's identity on the listener's leg:
        // written before any byte of the box's stream, read by the listener
        // and never by the box.
        let header = format!(
            "PROXY TCP4 {} {} {} {}\r\n",
            segment.src_ip, segment.dst_ip, segment.src_port, segment.dst_port
        );
        if let Err(error) = upstream_write.write_all(header.as_bytes()).await {
            tracing::warn!(
                %error,
                listener = %delivery,
                "the box egress proxy's listener closed before the delivered \
                 connection could be introduced"
            );
            let _ = frame_tx.send(reset_for(&segment));
            return;
        }
        // One debug line per delivered connection: the box's switch address
        // and the listener, the record a diagnostic bundle's daemon log tail
        // reads back.
        tracing::debug!(
            source = %segment.src_ip,
            source_port = segment.src_port,
            listener = %delivery,
            "delivered a box's connection to the box egress proxy listener \
             from the box's own switch address"
        );
        let isn = {
            let mut s = shared.lock().unwrap();
            s.snd_nxt = s.isn.wrapping_add(1);
            s.snd_una = s.isn;
            s.isn
        };
        let upstream_task = tokio::spawn(pump_upstream(
            upstream_read,
            Arc::clone(&shared),
            Arc::clone(&notify),
            frame_tx.clone(),
            addrs,
        ));
        flows.insert(
            key,
            FlowHandle {
                addrs,
                shared,
                notify,
                upstream_write,
                upstream_task,
            },
        );
        // SYN-ACK: the leg's ISN, the box's SYN acknowledged.
        let _ = frame_tx.send(build_frame(
            &addrs,
            isn,
            segment.seq.wrapping_add(1),
            TCP_SYN | TCP_ACK,
            ADVERTISED_WINDOW,
            &[],
        ));
        return;
    }

    // An existing flow, taken out of the map for the length of this segment
    // and put back when it survives: the ownership shape that lets the
    // teardown paths below take the handle without fighting the map's borrow.
    let Some(mut flow) = flows.remove(&key) else {
        // A segment for a flow the leg does not hold — an ACK or FIN arriving
        // after the flow was torn down, or traffic for a connection the leg
        // reset at its listener's refusal. Reset rather than leave the box's
        // TCP waiting for an answer it will never get.
        let _ = frame_tx.send(reset_for(&segment));
        return;
    };

    if segment.flags & TCP_RST != 0 {
        // The box tore its side down: the flow goes with it, upstream
        // included.
        flow.teardown();
        return;
    }

    // The box's ACK advances what it has received of the leg's sends, and
    // every segment carries the window the leg may now fill.
    {
        let mut s = flow.shared.lock().unwrap();
        if segment.ack.wrapping_sub(s.snd_una) < 0x8000_0000 {
            s.snd_una = segment.ack;
        }
        s.peer_window = u32::from(segment.window);
    }
    flow.notify.notify_one();
    {
        let s = flow.shared.lock().unwrap();
        if s.fully_acked() {
            drop(s);
            flow.teardown();
            return;
        }
    }

    // The box's data: consumed in order, written on to the listener, and
    // acknowledged — a retransmitted segment is acknowledged without a
    // second write, and an out-of-order one is dropped for the box to
    // resend (the path behind the gate loses no frame; only a box that
    // reorders its own sends can produce one).
    let (in_order, overlap) = {
        let s = flow.shared.lock().unwrap();
        if segment.seq == s.rcv_nxt {
            (segment.payload.len(), 0usize)
        } else {
            // An old or future sequence. An old one that extends past what
            // was already consumed is a retransmission carrying a new tail:
            // take the tail. Anything else waits for the segment it lacks.
            let past = s.rcv_nxt.wrapping_sub(segment.seq);
            if past < 0x8000_0000 && (past as usize) < segment.payload.len() {
                (segment.payload.len() - past as usize, past as usize)
            } else {
                (0, 0)
            }
        }
    };
    if in_order > 0 {
        let data = &segment.payload[overlap..overlap + in_order];
        if flow.upstream_write.write_all(data).await.is_err() {
            // The listener's side is gone mid-stream: the box's connection
            // is reset, the flow with it.
            let (snd_nxt, rcv_nxt) = {
                let s = flow.shared.lock().unwrap();
                (s.snd_nxt, s.rcv_nxt)
            };
            let _ = frame_tx.send(build_frame(
                &flow.addrs,
                snd_nxt,
                rcv_nxt,
                TCP_RST | TCP_ACK,
                0,
                &[],
            ));
            flow.teardown();
            return;
        }
    }

    // The box's FIN, when this segment carries it and the leg has consumed
    // everything before it: the listener's leg is half-closed with it, so
    // the listener sees EOF rather than a held-open socket. A FIN whose
    // slot was already consumed is a retransmission, answered with the ACK
    // below and nothing more.
    let fin = segment.flags & TCP_FIN != 0;
    let fin_at = segment.seq.wrapping_add(segment.payload.len() as u32);
    let fin_now = fin && {
        let s = flow.shared.lock().unwrap();
        s.rcv_nxt == fin_at
    };
    if fin_now {
        let _ = flow.upstream_write.shutdown().await;
    }
    // The leg's own FIN, when both sides have closed now and it has not gone
    // out yet: the upstream task sees EOF and sends it when the box's FIN
    // came first, and this is the path when the two closes arrived together.
    let leg_fin = {
        let mut s = flow.shared.lock().unwrap();
        if in_order > 0 {
            s.rcv_nxt = s.rcv_nxt.wrapping_add(in_order as u32);
        }
        if fin_now {
            s.peer_fin = true;
            if s.upstream_eof && !s.fin_sent {
                s.fin_seq = s.snd_nxt;
                s.snd_nxt = s.snd_nxt.wrapping_add(1);
                s.fin_sent = true;
                Some((s.fin_seq, s.rcv_nxt))
            } else {
                None
            }
        } else {
            None
        }
    };
    if let Some((fin_seq, rcv_nxt)) = leg_fin {
        let _ = frame_tx.send(build_frame(
            &flow.addrs,
            fin_seq,
            rcv_nxt,
            TCP_ACK | TCP_FIN,
            ADVERTISED_WINDOW,
            &[],
        ));
    }
    // ACK — always, so a retransmission is answered and the box's window
    // never stalls on an ACK the leg withheld.
    let (snd_nxt, rcv_nxt) = {
        let s = flow.shared.lock().unwrap();
        (s.snd_nxt, s.rcv_nxt)
    };
    let _ = frame_tx.send(build_frame(
        &flow.addrs,
        snd_nxt,
        rcv_nxt,
        TCP_ACK,
        ADVERTISED_WINDOW,
        &[],
    ));
    {
        let s = flow.shared.lock().unwrap();
        if s.fully_acked() {
            drop(s);
            flow.teardown();
            return;
        }
    }
    flows.insert(key, flow);
}

/// The addressing a reply to one segment needs: the segment's own addresses,
/// turned around, so the reply reads to the box's stack as coming from the
/// address the box sent to — the proxy's address on the switch.
#[must_use]
fn reply_addrs(segment: &Segment<'_>) -> FlowAddrs {
    FlowAddrs {
        src_mac: segment.dst_mac,
        dst_mac: segment.src_mac,
        src_ip: segment.dst_ip,
        dst_ip: segment.src_ip,
        src_port: segment.dst_port,
        dst_port: segment.src_port,
    }
}

/// The RST a segment earns when the leg has no flow for it — the standard
/// abort form: the segment's ACK as the sequence, the segment's sequence
/// advanced by its payload as the acknowledgement.
#[must_use]
fn reset_for(segment: &Segment<'_>) -> Vec<u8> {
    build_frame(
        &reply_addrs(segment),
        segment.ack,
        segment.seq.wrapping_add(segment.payload.len() as u32),
        TCP_RST | TCP_ACK,
        0,
        &[],
    )
}

/// Reads the listener's answers back to the box: what the window allows is
/// sent, and what it does not is waited for — a slow box reader holds the
/// leg's sends rather than a queue of frames it cannot take. EOF half-closes
/// the leg's side, which is what lets a finished listener end the box's
/// connection cleanly.
async fn pump_upstream(
    mut upstream: OwnedReadHalf,
    shared: Arc<Mutex<FlowShared>>,
    notify: Arc<Notify>,
    frame_tx: mpsc::UnboundedSender<Vec<u8>>,
    addrs: FlowAddrs,
) {
    let mut buf = vec![0u8; MAX_SEGMENT];
    loop {
        let free = {
            let s = match shared.lock() {
                Ok(s) => s,
                Err(_) => return,
            };
            if s.closed {
                return;
            }
            let in_flight = s.snd_nxt.wrapping_sub(s.snd_una);
            s.peer_window.saturating_sub(in_flight)
        };
        if free == 0 {
            // Wait for the box's ACK to open the window back up.
            notify.notified().await;
            continue;
        }
        let want = (free as usize).min(MAX_SEGMENT);
        match upstream.read(&mut buf[..want]).await {
            Ok(0) => {
                // The listener half-closed: the leg's FIN follows, once both
                // sides have closed — if the box already sent its FIN, send
                // now; otherwise mark it and let the box's FIN trigger it
                // (the segment loop sends it then).
                let frame = {
                    let mut s = shared.lock().unwrap();
                    s.upstream_eof = true;
                    if s.peer_fin && !s.fin_sent {
                        s.fin_seq = s.snd_nxt;
                        s.snd_nxt = s.snd_nxt.wrapping_add(1);
                        s.fin_sent = true;
                        Some(build_frame(
                            &addrs,
                            s.fin_seq,
                            s.rcv_nxt,
                            TCP_ACK | TCP_FIN,
                            ADVERTISED_WINDOW,
                            &[],
                        ))
                    } else {
                        None
                    }
                };
                if let Some(frame) = frame {
                    let _ = frame_tx.send(frame);
                }
                return;
            }
            Ok(n) => {
                let frame = {
                    let mut s = shared.lock().unwrap();
                    if s.closed {
                        return;
                    }
                    let frame = build_frame(
                        &addrs,
                        s.snd_nxt,
                        s.rcv_nxt,
                        TCP_ACK,
                        ADVERTISED_WINDOW,
                        &buf[..n],
                    );
                    s.snd_nxt = s.snd_nxt.wrapping_add(n as u32);
                    frame
                };
                if frame_tx.send(frame).is_err() {
                    return;
                }
            }
            Err(_) => return,
        }
    }
}

/// One segment the leg parsed out of a diverted frame: the addressing the
/// replies need and the TCP header the state machine decides on. The payload
/// borrows the frame it was read from.
struct Segment<'a> {
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    window: u16,
    flags: u8,
    payload: &'a [u8],
}

/// Parses one Ethernet/IPv4/TCP frame into a [`Segment`]: bounds-checked
/// throughout, so a truncated or malformed frame is `None` rather than a
/// panic, and only a well-formed IPv4 TCP frame is returned.
#[must_use]
#[expect(
    clippy::indexing_slicing,
    reason = "every slice is bounded by the length checks immediately above it"
)]
fn parse_frame(frame: &[u8]) -> Option<Segment<'_>> {
    if frame.len() < 14 || u16::from_be_bytes([frame[12], frame[13]]) != 0x0800 {
        return None;
    }
    let ip = &frame[14..];
    if ip.len() < 20 {
        return None;
    }
    let ihl = usize::from(ip[0] & 0x0f) * 4;
    if ihl < 20 || ip.len() < ihl {
        return None;
    }
    if ip[9] != IPPROTO_TCP {
        return None;
    }
    let tcp = &ip[ihl..];
    if tcp.len() < 20 {
        return None;
    }
    let data_offset = usize::from(tcp[12] >> 4) * 4;
    if data_offset < 20 || tcp.len() < data_offset {
        return None;
    }
    Some(Segment {
        src_mac: [frame[6], frame[7], frame[8], frame[9], frame[10], frame[11]],
        dst_mac: [frame[0], frame[1], frame[2], frame[3], frame[4], frame[5]],
        src_ip: Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]),
        dst_ip: Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19]),
        src_port: u16::from_be_bytes([tcp[0], tcp[1]]),
        dst_port: u16::from_be_bytes([tcp[2], tcp[3]]),
        seq: u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]),
        ack: u32::from_be_bytes([tcp[8], tcp[9], tcp[10], tcp[11]]),
        window: u16::from_be_bytes([tcp[14], tcp[15]]),
        flags: tcp[13],
        payload: &tcp[data_offset..],
    })
}

/// Builds one Ethernet/IPv4/TCP frame for `addrs`, with checksums: the
/// framing the gate copies verbatim to the guest, and the box's TCP consumes.
#[must_use]
#[expect(
    clippy::indexing_slicing,
    reason = "the checksum write indexes fixed offsets in headers this function itself sized"
)]
fn build_frame(
    addrs: &FlowAddrs,
    seq: u32,
    ack: u32,
    flags: u8,
    window: u16,
    payload: &[u8],
) -> Vec<u8> {
    let tcp_len = 20 + payload.len();
    let mut tcp = Vec::with_capacity(tcp_len);
    tcp.extend_from_slice(&addrs.src_port.to_be_bytes());
    tcp.extend_from_slice(&addrs.dst_port.to_be_bytes());
    tcp.extend_from_slice(&seq.to_be_bytes());
    tcp.extend_from_slice(&ack.to_be_bytes());
    tcp.push(0x50); // data offset 20 (5 words << 4), reserved 0, no options
    tcp.push(flags);
    tcp.extend_from_slice(&window.to_be_bytes());
    tcp.extend_from_slice(&0u16.to_be_bytes()); // checksum, filled below
    tcp.extend_from_slice(&0u16.to_be_bytes()); // urgent pointer
    tcp.extend_from_slice(payload);
    let checksum = tcp_checksum(&addrs.src_ip, &addrs.dst_ip, &tcp);
    let checksum_bytes = checksum.to_be_bytes();
    tcp[16] = checksum_bytes[0];
    tcp[17] = checksum_bytes[1];

    let total_len = (20 + tcp_len) as u16;
    let mut ip = Vec::with_capacity(20);
    ip.push(0x45); // version 4, IHL 20
    ip.push(0x00); // DSCP/ECN
    ip.extend_from_slice(&total_len.to_be_bytes());
    ip.extend_from_slice(&0u16.to_be_bytes()); // identification
    ip.extend_from_slice(&0u16.to_be_bytes()); // flags/fragment offset
    ip.push(64); // TTL
    ip.push(IPPROTO_TCP);
    ip.extend_from_slice(&0u16.to_be_bytes()); // header checksum, below
    ip.extend_from_slice(&addrs.src_ip.octets());
    ip.extend_from_slice(&addrs.dst_ip.octets());
    let ip_checksum = ones_complement_sum(&ip).to_be_bytes();
    ip[10] = ip_checksum[0];
    ip[11] = ip_checksum[1];

    let mut frame = Vec::with_capacity(14 + ip.len());
    frame.extend_from_slice(&addrs.dst_mac);
    frame.extend_from_slice(&addrs.src_mac);
    frame.extend_from_slice(&0x0800u16.to_be_bytes());
    frame.extend_from_slice(&ip);
    frame
}

/// The ones-complement checksum over `bytes`, as IPv4 and TCP define it:
/// pairs of bytes summed into a ones-complement accumulator, the carry
/// folded back in, and the result complemented. An odd length pads a zero
/// byte on the right.
#[must_use]
fn ones_complement_sum(bytes: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut chunks = bytes.chunks_exact(2);
    for pair in &mut chunks {
        sum += u32::from(u16::from_be_bytes([pair[0], pair[1]]));
    }
    if let Some(last) = chunks.remainder().first() {
        sum += u32::from(u16::from_be_bytes([*last, 0]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// The TCP checksum: the ones-complement sum over the pseudo-header (source,
/// destination, protocol, TCP length) and the TCP segment, as the box's
/// stack checks it.
#[must_use]
fn tcp_checksum(src: &Ipv4Addr, dst: &Ipv4Addr, tcp: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(12 + tcp.len() + usize::from(!tcp.len().is_multiple_of(2)));
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.push(0);
    pseudo.push(IPPROTO_TCP);
    pseudo.extend_from_slice(&(tcp.len() as u16).to_be_bytes());
    pseudo.extend_from_slice(tcp);
    if !tcp.len().is_multiple_of(2) {
        pseudo.push(0);
    }
    ones_complement_sum(&pseudo)
}

/// The stub listener standing in for the proxy's: it consumes the PROXY v1
/// header the leg wrote, answers one line naming the source the connection
/// was presented from, and echoes whatever follows. A connection with no
/// header — a process that dialled the listener directly — is presented from
/// its own peer address, never from a box's address. The stub reads the
/// header from the connection's first read; the leg writes it whole before
/// any byte of the stream, so that holds for the leg's deliveries, and a
/// connection that dribbles a header across reads is simply presented from
/// its own peer — the stand-in's answer, never a source it invented.
async fn run_stub_listener(listener: TcpListener) {
    loop {
        let (mut sock, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(error) => {
                tracing::warn!(%error, "the box egress proxy's stub listener accept failed");
                continue;
            }
        };
        tokio::spawn(async move {
            // The header is at most one line; anything that is not a PROXY
            // header within the first read presents the connection from its
            // own peer.
            let mut buf = [0u8; 128];
            let presented = match sock.read(&mut buf).await {
                Ok(0) | Err(_) => return,
                Ok(n) => match proxy_v1_header(&buf[..n]) {
                    Some((source, consumed)) => {
                        // Whatever followed the header in the same read is
                        // the box's stream: echoed back like any other byte.
                        let _ = sock.write_all(&buf[consumed..n]).await;
                        source
                    }
                    None => {
                        let _ = sock.write_all(&buf[..n]).await;
                        peer.ip().to_string()
                    }
                },
            };
            if sock
                .write_all(format!("source {presented}\n").as_bytes())
                .await
                .is_err()
            {
                return;
            }
            // Echo the rest verbatim, so a probe reads what it sent.
            loop {
                match sock.read(&mut buf).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => {
                        if sock.write_all(&buf[..n]).await.is_err() {
                            return;
                        }
                    }
                }
            }
        });
    }
}

/// The source address a PROXY v1 header presents, with the header's length:
/// when `buf` opens with one well-formed `PROXY TCP4` line, the header's
/// source field and the bytes through its CRLF; otherwise nothing, and the
/// connection is presented from its own peer.
#[must_use]
fn proxy_v1_header(buf: &[u8]) -> Option<(String, usize)> {
    let text = std::str::from_utf8(buf).ok()?;
    let end = text.find("\r\n")?;
    let line = &text[..end];
    let mut fields = line.split(' ');
    if fields.next()? != "PROXY" || fields.next()? != "TCP4" {
        return None;
    }
    let src = fields.next()?;
    let dst = fields.next()?;
    let sport: u16 = fields.next()?.parse().ok()?;
    let dport: u16 = fields.next()?.parse().ok()?;
    if fields.next().is_some() {
        return None;
    }
    if src.parse::<Ipv4Addr>().is_err() || dst.parse::<Ipv4Addr>().is_err() {
        return None;
    }
    if sport == 0 || dport == 0 {
        return None;
    }
    Some((src.to_string(), end + 2))
}

#[cfg(test)]
pub(crate) mod test_frames {
    //! The wire frames the leg's and the gate's tests drive with:
    //! crate-internal and compiled only under `cfg(test)`, so only tests can
    //! make traffic shaped like a box's.

    /// A box's MAC on the switch, arbitrary but stable across a test.
    pub(crate) const BOX_MAC: [u8; 6] = [0x52, 0x54, 0x00, 0x40, 0x00, 0x05];
    /// The gateway's MAC, arbitrary but stable across a test.
    pub(crate) const GATEWAY_MAC: [u8; 6] = [0x52, 0x54, 0x00, 0x40, 0x00, 0x01];

    pub(crate) use super::{TCP_ACK, TCP_FIN, TCP_PSH, TCP_RST, TCP_SYN};

    /// One Ethernet/IPv4/TCP frame from a box's lease toward `dst`, the shape
    /// the gate diverts and the leg terminates.
    #[must_use]
    #[expect(
        clippy::too_many_arguments,
        reason = "a test frame's fields are the segment's header, one each"
    )]
    pub(crate) fn tcp_frame(
        src_ip: std::net::Ipv4Addr,
        dst_ip: std::net::Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        seq: u32,
        ack: u32,
        flags: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        super::build_frame(
            &super::FlowAddrs {
                src_mac: BOX_MAC,
                dst_mac: GATEWAY_MAC,
                src_ip,
                dst_ip,
                src_port,
                dst_port,
            },
            seq,
            ack,
            flags,
            0xFFFF,
            payload,
        )
    }

    /// What a frame the tests read back says: the fields the leg's and the
    /// gate's tests assert on, parsed out of the frame's own headers.
    #[derive(Debug, PartialEq, Eq)]
    pub(crate) struct ReadBack {
        pub(crate) src_ip: std::net::Ipv4Addr,
        pub(crate) dst_ip: std::net::Ipv4Addr,
        pub(crate) src_port: u16,
        pub(crate) dst_port: u16,
        pub(crate) seq: u32,
        pub(crate) ack: u32,
        pub(crate) window: u16,
        pub(crate) flags: u8,
        pub(crate) payload: Vec<u8>,
    }

    /// Parses one frame into a [`ReadBack`], or nothing when the frame is not
    /// a well-formed Ethernet/IPv4/TCP frame — which, for a frame a test
    /// reads back, is the test's own failure to say.
    #[must_use]
    pub(crate) fn read_back(frame: &[u8]) -> Option<ReadBack> {
        super::parse_frame(frame).map(|segment| ReadBack {
            src_ip: segment.src_ip,
            dst_ip: segment.dst_ip,
            src_port: segment.src_port,
            dst_port: segment.dst_port,
            seq: segment.seq,
            ack: segment.ack,
            window: segment.window,
            flags: segment.flags,
            payload: segment.payload.to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::time::Duration;

    use switch::SwitchSubnet;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpStream, UnixStream};

    use super::test_frames::{
        BOX_MAC, GATEWAY_MAC, TCP_ACK, TCP_FIN, TCP_PSH, TCP_RST, TCP_SYN, tcp_frame,
    };
    use super::*;

    const DEADLINE: Duration = Duration::from_secs(5);

    /// The leg under test: a handoff socket in a temp dir, a stub listener on
    /// an ephemeral port, delivery to that same listener, and the leg's loops
    /// spawned on this test's own runtime — which is what puts the leg's log
    /// lines under a thread-local capture.
    struct LegHarness {
        _dir: tempfile::TempDir,
        _leg_task: tokio::task::JoinHandle<()>,
        delivery: SocketAddr,
        handoff: PathBuf,
    }

    impl LegHarness {
        /// Binds the leg's sockets and spawns its loops.
        ///
        /// # Panics
        ///
        /// Panics when a socket cannot be bound — nothing here contends for
        /// them but the test itself.
        async fn bind() -> Self {
            let dir = tempfile::tempdir().expect("a tempdir is creatable");
            let handoff = dir.path().join("gvproxy-bep.sock");
            let subnet = SwitchSubnet::default();
            let stub =
                std::net::TcpListener::bind(("127.0.0.1", 0)).expect("binding the stub listener");
            let delivery = stub.local_addr().expect("the stub listener's address");
            let listener = UnixListener::bind(&handoff).expect("binding the handoff socket");
            let stub = TcpListener::from_std(stub).expect("the stub listener async");
            let leg_task = tokio::spawn(run_leg(
                listener,
                stub,
                delivery,
                subnet.box_egress_proxy_address(),
            ));
            Self {
                _dir: dir,
                _leg_task: leg_task,
                delivery,
                handoff,
            }
        }
    }

    /// Dials the leg's handoff socket as the gate would, and returns the
    /// connection.
    async fn connect_handoff(harness: &LegHarness) -> UnixStream {
        match tokio::time::timeout(DEADLINE, UnixStream::connect(&harness.handoff)).await {
            Ok(Ok(sock)) => sock,
            _ => panic!("the leg's handoff socket is listening"),
        }
    }

    /// Writes one framed frame to the handoff socket, as the gate does.
    async fn send_frame(sock: &mut UnixStream, frame: &[u8]) {
        let mut framed = Vec::with_capacity(2 + frame.len());
        framed.extend_from_slice(&(frame.len() as u16).to_le_bytes());
        framed.extend_from_slice(frame);
        sock.write_all(&framed)
            .await
            .expect("writing a framed frame");
    }

    /// Reads one framed frame from the handoff socket, as the gate does.
    async fn expect_frame(sock: &mut UnixStream) -> Vec<u8> {
        let mut len_buf = [0u8; 2];
        read_within(sock, &mut len_buf).await;
        let n = u16::from_le_bytes(len_buf) as usize;
        assert!(n > 0, "a zero-length frame claim is not a frame");
        let mut frame = vec![0u8; n];
        read_within(sock, &mut frame).await;
        frame
    }

    /// Reads exactly `buf` from `stream` within [`DEADLINE`], failing the
    /// test when the timeout passes first.
    async fn read_within(stream: &mut UnixStream, buf: &mut [u8]) {
        match tokio::time::timeout(DEADLINE, stream.read_exact(buf)).await {
            Ok(read) => {
                read.expect("reading the stream");
            }
            Err(_) => panic!("expected the bytes to arrive within {DEADLINE:?}, got none"),
        }
    }

    /// The parse of one frame, for the tests' assertions on the leg's replies.
    fn read_segment(frame: &[u8]) -> Segment<'_> {
        parse_frame(frame).expect("the leg sent a well-formed TCP frame")
    }

    /// The addressing of a box's connection to the proxy's address, on the
    /// default subnet: the box's lease as the source, the proxy's address as
    /// the destination.
    fn box_addrs(src: Ipv4Addr, dst_port: u16) -> (Ipv4Addr, FlowAddrs) {
        let subnet = SwitchSubnet::default();
        let proxy = subnet.box_egress_proxy_address();
        let addrs = FlowAddrs {
            src_mac: BOX_MAC,
            dst_mac: GATEWAY_MAC,
            src_ip: src,
            dst_ip: proxy,
            src_port: 44444,
            dst_port,
        };
        (proxy, addrs)
    }

    /// A process outside every box — the test's own socket — dials the
    /// proxy's listener directly, the way a host process does: no leg, no
    /// PROXY header, no box in the picture. What the listener presents must
    /// be the dial's own source, never a box's switch address.
    #[tokio::test]
    async fn host_process_never_arrives_from_a_box_address() {
        let harness = LegHarness::bind().await;
        let subnet = SwitchSubnet::default();
        let lease = Ipv4Addr::from(subnet.first_ptask());
        let mut probe = TcpStream::connect(harness.delivery)
            .await
            .expect("the stub listener accepts a host process's dial");
        probe
            .write_all(b"probe\n")
            .await
            .expect("writing the probe");
        let mut answer = String::new();
        match tokio::time::timeout(DEADLINE, probe.read_to_string(&mut answer)).await {
            Ok(read) => {
                read.expect("reading the stub's answer");
            }
            Err(_) => panic!("the stub answers the probe within {DEADLINE:?}"),
        }
        let presented = answer
            .lines()
            .find_map(|line| line.strip_prefix("source "))
            .unwrap_or_else(|| panic!("the stub's answer names the source: {answer}"));
        let presented: Ipv4Addr = presented
            .parse()
            .unwrap_or_else(|_| panic!("the stub's answer carries an address: {answer}"));
        // No box's address: not a lease, not the daemon's, not the host
        // alias's, not the proxy's own — the dial's own loopback address.
        assert_ne!(presented, lease);
        assert_ne!(presented, subnet.daemon_ip());
        assert_ne!(presented, subnet.host_alias());
        assert_ne!(presented, subnet.box_egress_proxy_address());
        assert_ne!(presented, subnet.gateway());
        assert_eq!(presented, Ipv4Addr::LOCALHOST);
    }

    /// The leg's whole path, driven the way the gate drives it: a SYN from a
    /// box's lease to the proxy's address, diverted in over the handoff
    /// socket; the handshake, the data, and the listener's answer all read
    /// back off the handoff socket — and the listener's answer names the
    /// box's lease, the source the leg carried in-band.
    #[tokio::test]
    async fn delivered_connection_arrives_from_the_boxs_switch_address() {
        let harness = LegHarness::bind().await;
        let subnet = SwitchSubnet::default();
        let lease = Ipv4Addr::from(subnet.first_ptask());
        let (_proxy, addrs) = box_addrs(lease, 80);
        let mut gate = connect_handoff(&harness).await;

        // SYN → the dial runs, the PROXY header is written, and the SYN-ACK
        // comes back with the leg's ISN.
        send_frame(
            &mut gate,
            &tcp_frame(
                addrs.src_ip,
                addrs.dst_ip,
                addrs.src_port,
                addrs.dst_port,
                1000,
                0,
                TCP_SYN,
                &[],
            ),
        )
        .await;
        let frame = expect_frame(&mut gate).await;
        let synack = read_segment(&frame);
        assert_eq!(synack.flags & TCP_SYN, TCP_SYN, "the leg answers the SYN");
        assert_eq!(
            synack.flags & TCP_ACK,
            TCP_ACK,
            "the SYN-ACK acknowledges it"
        );
        assert_eq!(synack.ack, 1001, "the SYN is acknowledged");
        let isn = synack.seq;
        assert_ne!(isn, 0, "the leg's ISN is its own");

        // The box's ACK of the SYN-ACK, then its data.
        send_frame(
            &mut gate,
            &tcp_frame(
                addrs.src_ip,
                addrs.dst_ip,
                addrs.src_port,
                addrs.dst_port,
                1001,
                isn.wrapping_add(1),
                TCP_ACK,
                &[],
            ),
        )
        .await;
        send_frame(
            &mut gate,
            &tcp_frame(
                addrs.src_ip,
                addrs.dst_ip,
                addrs.src_port,
                addrs.dst_port,
                1001,
                isn.wrapping_add(1),
                TCP_ACK | TCP_PSH,
                b"ping\n",
            ),
        )
        .await;

        // The leg answers the data with an ACK, and the stub's answer and its
        // echo of the data come back as data segments. The ACK races the
        // stub's answer, so the frames are sorted rather than ordered: one
        // ACK of the data, then the answer and the echo in the order the
        // stub wrote them.
        let mut acked = false;
        let mut answer: Option<Vec<u8>> = None;
        let mut echo: Option<Vec<u8>> = None;
        for _ in 0..3 {
            let frame = expect_frame(&mut gate).await;
            let seg = read_segment(&frame);
            if answer.is_none() && !seg.payload.is_empty() {
                answer = Some(seg.payload.to_vec());
            } else if echo.is_none() && !seg.payload.is_empty() {
                echo = Some(seg.payload.to_vec());
            } else {
                assert!(!acked, "more frames than the three the leg owes");
                assert_eq!(
                    seg.ack, 1006,
                    "the leg acknowledges the box's five data bytes"
                );
                acked = true;
            }
        }
        assert_eq!(
            answer.expect("the stub's answer arrived"),
            format!("source {lease}\n").as_bytes(),
            "the listener saw the connection from the box's own switch address"
        );
        assert_eq!(echo.expect("the stub's echo arrived"), b"ping\n");

        // The box half-closes; the leg's FIN comes back; the box acknowledges
        // it and the flow is gone.
        send_frame(
            &mut gate,
            &tcp_frame(
                addrs.src_ip,
                addrs.dst_ip,
                addrs.src_port,
                addrs.dst_port,
                1006,
                isn.wrapping_add(26),
                TCP_ACK | TCP_FIN,
                &[],
            ),
        )
        .await;
        let mut fin_seq = 0;
        let mut saw_ack = false;
        for _ in 0..2 {
            let frame = expect_frame(&mut gate).await;
            let seg = read_segment(&frame);
            if seg.flags & TCP_FIN != 0 {
                assert_eq!(seg.ack, 1007, "the FIN acknowledges the box's FIN");
                fin_seq = seg.seq;
            } else {
                assert_eq!(
                    seg.ack, 1007,
                    "the leg acknowledges the box's FIN as it arrives"
                );
                saw_ack = true;
            }
        }
        assert!(saw_ack, "the box's FIN is acknowledged");
        assert_ne!(fin_seq, 0, "the leg's FIN went out once both sides closed");
        // The box's ACK of the leg's FIN: the flow must be dropped, so the
        // next frame from the box — a stray ACK — is reset, not answered with
        // a duplicate ACK from a flow that should be gone.
        send_frame(
            &mut gate,
            &tcp_frame(
                addrs.src_ip,
                addrs.dst_ip,
                addrs.src_port,
                addrs.dst_port,
                1007,
                fin_seq.wrapping_add(1),
                TCP_ACK,
                &[],
            ),
        )
        .await;
        let frame = expect_frame(&mut gate).await;
        let reset = read_segment(&frame);
        assert_eq!(
            reset.flags & TCP_RST,
            TCP_RST,
            "a segment for a dropped flow is reset"
        );
    }

    /// A retransmitted segment is acknowledged again, not rewritten: the
    /// stub's echo stays the data it echoed once, and the box's sequence
    /// accounting stays what one write would have left it.
    #[tokio::test]
    async fn a_retransmitted_segment_is_answered_not_rewritten() {
        let harness = LegHarness::bind().await;
        let subnet = SwitchSubnet::default();
        let lease = Ipv4Addr::from(subnet.first_ptask());
        let (_proxy, addrs) = box_addrs(lease, 80);
        let mut gate = connect_handoff(&harness).await;

        send_frame(
            &mut gate,
            &tcp_frame(
                addrs.src_ip,
                addrs.dst_ip,
                addrs.src_port,
                addrs.dst_port,
                1000,
                0,
                TCP_SYN,
                &[],
            ),
        )
        .await;
        let frame = expect_frame(&mut gate).await;
        let synack = read_segment(&frame);
        let isn = synack.seq;
        send_frame(
            &mut gate,
            &tcp_frame(
                addrs.src_ip,
                addrs.dst_ip,
                addrs.src_port,
                addrs.dst_port,
                1001,
                isn.wrapping_add(1),
                TCP_ACK,
                &[],
            ),
        )
        .await;
        // The same five bytes, twice: the second is the box's
        // retransmission, and the leg must not write it on again.
        for _ in 0..2 {
            send_frame(
                &mut gate,
                &tcp_frame(
                    addrs.src_ip,
                    addrs.dst_ip,
                    addrs.src_port,
                    addrs.dst_port,
                    1001,
                    isn.wrapping_add(1),
                    TCP_ACK | TCP_PSH,
                    b"ping\n",
                ),
            )
            .await;
        }
        // The leg answers each segment with an ACK, and the stub's answer
        // and its echo of the one write come back as data. The echo must
        // name the data once — the retransmission was acknowledged, not
        // delivered again.
        let mut answer: Option<Vec<u8>> = None;
        for _ in 0..8 {
            let frame = expect_frame(&mut gate).await;
            let seg = read_segment(&frame);
            if !seg.payload.is_empty() {
                answer = Some(seg.payload.to_vec());
                break;
            }
        }
        assert_eq!(
            answer.expect("the stub's answer arrived"),
            format!("source {lease}\n").as_bytes()
        );
        // The echo of the data, once, after the answer.
        let mut echo: Option<Vec<u8>> = None;
        for _ in 0..8 {
            let frame = expect_frame(&mut gate).await;
            let seg = read_segment(&frame);
            if !seg.payload.is_empty() {
                echo = Some(seg.payload.to_vec());
                break;
            }
        }
        assert_eq!(echo.expect("the stub's echo arrived"), b"ping\n");
    }

    /// Per connection delivered, the leg logs one debug line carrying the
    /// box's switch address, its port, and the listener — the record the
    /// diagnostic bundle's daemon log tail reads back.
    #[tokio::test]
    async fn the_delivered_line_names_the_boxs_address_and_the_listener() {
        // The capture is installed before the leg's loops are spawned, so
        // their lines land in it: the loops run on this test's runtime.
        let capture = Capture::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(capture.clone())
            .with_ansi(false)
            .with_max_level(tracing::level_filters::LevelFilter::DEBUG)
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);

        let harness = LegHarness::bind().await;
        let subnet = SwitchSubnet::default();
        let lease = Ipv4Addr::from(subnet.first_ptask());
        let (_proxy, addrs) = box_addrs(lease, 18654);
        let mut gate = connect_handoff(&harness).await;
        send_frame(
            &mut gate,
            &tcp_frame(
                addrs.src_ip,
                addrs.dst_ip,
                addrs.src_port,
                addrs.dst_port,
                1000,
                0,
                TCP_SYN,
                &[],
            ),
        )
        .await;
        let _synack = expect_frame(&mut gate).await;

        wait_for_log(&capture, "delivered a box's connection").await;
        let logged = capture.contents();
        assert!(
            logged.contains(&format!("source={lease}")),
            "the delivered line names the box's switch address: {logged}"
        );
        assert!(
            logged.contains(&format!("source_port={}", addrs.src_port)),
            "the delivered line names the box's source port: {logged}"
        );
        assert!(
            logged.contains(&format!("listener={}", harness.delivery)),
            "the delivered line names the listener: {logged}"
        );
    }

    /// The leg's delivery going nowhere resets the box's connection: its
    /// connect fails instead of hanging on a listener that will never speak.
    #[tokio::test]
    async fn a_refused_listener_resets_the_boxs_connection() {
        let dir = tempfile::tempdir().expect("a tempdir is creatable");
        let handoff = dir.path().join("gvproxy-bep.sock");
        // A listener that accepts and immediately closes: a delivery that
        // cannot be introduced.
        let dead =
            std::net::TcpListener::bind(("127.0.0.1", 0)).expect("binding the dead listener");
        let dead_port = dead.local_addr().expect("the dead listener's port").port();
        let _dead_guard = std::thread::spawn(move || {
            let (sock, _) = dead.accept().expect("the leg's delivery arrives");
            drop(sock);
        });
        let subnet = SwitchSubnet::default();
        let stub =
            std::net::TcpListener::bind(("127.0.0.1", 0)).expect("binding the stub listener");
        let listener = UnixListener::bind(&handoff).expect("binding the handoff socket");
        let stub = TcpListener::from_std(stub).expect("the stub listener async");
        let leg_task = tokio::spawn(run_leg(
            listener,
            stub,
            SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::LOCALHOST), dead_port),
            subnet.box_egress_proxy_address(),
        ));
        let (_proxy, addrs) = box_addrs(Ipv4Addr::from(subnet.first_ptask()), 80);
        let mut gate = match tokio::time::timeout(DEADLINE, UnixStream::connect(&handoff)).await {
            Ok(Ok(sock)) => sock,
            _ => panic!("the leg's handoff socket is listening"),
        };
        send_frame(
            &mut gate,
            &tcp_frame(
                addrs.src_ip,
                addrs.dst_ip,
                addrs.src_port,
                addrs.dst_port,
                1000,
                0,
                TCP_SYN,
                &[],
            ),
        )
        .await;
        let frame = expect_frame(&mut gate).await;
        let reset = read_segment(&frame);
        assert_eq!(
            reset.flags & TCP_RST,
            TCP_RST,
            "the box's connection is reset"
        );
        leg_task.abort();
    }

    /// A PROXY v1 header parses to its source and its length; anything else
    /// at the head of a connection presents the connection from its own peer.
    #[test]
    fn proxy_v1_header_parses_and_rejects_the_rest() {
        let (source, consumed) =
            proxy_v1_header(b"PROXY TCP4 100.64.0.5 100.64.255.252 44444 80\r\nrest of the stream")
                .expect("a well-formed header parses");
        assert_eq!(source, "100.64.0.5");
        assert_eq!(consumed, 47);
        assert_eq!(proxy_v1_header(b"GET / HTTP/1.1\r\n"), None);
        assert_eq!(proxy_v1_header(b"PROXY TCP6 ::1 ::2 1 2\r\n"), None);
        assert_eq!(
            proxy_v1_header(b"PROXY TCP4 not-an-ip 1.2.3.4 1 2\r\n"),
            None
        );
        assert_eq!(
            proxy_v1_header(b"PROXY TCP4 1.2.3.4 5.6.7.8 0 80\r\n"),
            None
        );
        assert_eq!(
            proxy_v1_header(b"PROXY TCP4 1.2.3.4 5.6.7.8 1 2 extra\r\n"),
            None
        );
        assert_eq!(proxy_v1_header(b"PROXY TCP4 1.2.3.4 5.6.7.8 1 2"), None);
    }

    /// The frames the leg builds carry checksums the box's stack would
    /// accept: parsed back, each header's ones-complement sum — checksum
    /// field included — is zero.
    #[test]
    fn frames_the_leg_builds_carry_checksums_the_box_would_accept() {
        let subnet = SwitchSubnet::default();
        let proxy = subnet.box_egress_proxy_address();
        let addrs = FlowAddrs {
            src_mac: GATEWAY_MAC,
            dst_mac: BOX_MAC,
            src_ip: proxy,
            dst_ip: Ipv4Addr::new(100, 64, 0, 9),
            src_port: 8080,
            dst_port: 44444,
        };
        for payload in [&b"hello box\n"[..], &b"m"[..], &b""[..]] {
            let frame = build_frame(&addrs, 42, 7, TCP_ACK | TCP_PSH, 0xFFFF, payload);
            let segment = parse_frame(&frame).expect("the built frame parses back");
            assert_eq!(segment.payload, payload);
            assert_eq!(segment.src_ip, addrs.src_ip);
            assert_eq!(segment.dst_ip, addrs.dst_ip);
            assert_eq!(segment.src_port, addrs.src_port);
            assert_eq!(segment.dst_port, addrs.dst_port);
            assert_eq!(segment.flags, TCP_ACK | TCP_PSH);
            let ihl = usize::from(frame[14] & 0x0f) * 4;
            let ip = &frame[14..14 + ihl];
            assert_eq!(ones_complement_sum(ip), 0, "the IPv4 checksum verifies");
            let tcp = &frame[14 + ihl..];
            let mut pseudo =
                Vec::with_capacity(12 + tcp.len() + usize::from(!tcp.len().is_multiple_of(2)));
            pseudo.extend_from_slice(&addrs.src_ip.octets());
            pseudo.extend_from_slice(&addrs.dst_ip.octets());
            pseudo.push(0);
            pseudo.push(IPPROTO_TCP);
            pseudo.extend_from_slice(&(tcp.len() as u16).to_be_bytes());
            pseudo.extend_from_slice(tcp);
            if !tcp.len().is_multiple_of(2) {
                pseudo.push(0);
            }
            assert_eq!(ones_complement_sum(&pseudo), 0, "the TCP checksum verifies");
        }
    }

    /// The `tracing` capture the leg's own tests assert through: a mutex'd
    /// buffer every line lands in, whatever thread or task wrote it.
    #[derive(Clone, Default)]
    struct Capture(Arc<Mutex<Vec<u8>>>);

    impl Capture {
        fn contents(&self) -> String {
            String::from_utf8_lossy(&self.0.lock().expect("the capture's lock")).into_owned()
        }
    }

    impl io::Write for Capture {
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

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Capture {
        type Writer = Capture;
        fn make_writer(&self) -> Self::Writer {
            self.clone()
        }
    }

    /// Polls the captured log until it contains `needle`, failing with the
    /// log's contents once [`DEADLINE`] passes.
    async fn wait_for_log(capture: &Capture, needle: &str) {
        let deadline = tokio::time::Instant::now() + DEADLINE;
        loop {
            let logged = capture.contents();
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
}
