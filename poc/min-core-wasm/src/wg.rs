//! Userspace WireGuard + TCP/IP beneath the SSH transport: the tab is a mesh
//! node, and SSH opens a TCP socket inside the tunnel.
//!
//! boringtun's `Tunn` does the noise protocol (the same crate `minimald`
//! embeds under `networking-wg`, `crates/minimald/src/net/wg.rs`); smoltcp
//! is the TCP/IP stack; the only I/O this module asks of its host is a pair
//! of datagram queues — a WebSocket in a browser, an in-memory pair in tests,
//! a UDP socket natively — and the clock and sleep in [`crate::rt`].
//!
//! Shape: [`WgStack`] is a handle around one `Tunn` + one smoltcp
//! `Interface`; a driver future (returned by [`WgStack::new`], spawned by the
//! caller on whatever executor it has) pumps datagrams, timers and the
//! interface; [`WgTcpStream`] is a TCP socket in that stack exposed as
//! `AsyncRead + AsyncWrite + Send`, which is exactly what russh wants.

use std::collections::VecDeque;
use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use smoltcp::iface::{Config, Interface, PollResult, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp;
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{Notify, mpsc};

use crate::rt;

/// Inner packet MTU: the conventional WireGuard figure (1500 - 80).
pub const MTU: usize = 1420;
/// Scratch buffer for encapsulation/decapsulation; boringtun wants 32 bytes
/// of headroom over the largest packet, and handshake messages are small.
const SCRATCH: usize = MTU + 128;
/// How often boringtun's timers are serviced when nothing else is happening.
const TIMER_TICK: Duration = Duration::from_millis(250);
const TCP_BUFFER: usize = 64 * 1024;

#[derive(Clone, Debug)]
pub struct WgConfig {
    /// This node's static private key (32 bytes, clamped by x25519-dalek).
    pub private_key: [u8; 32],
    pub peer_public_key: [u8; 32],
    /// This node's tunnel address and the prefix it shares with the peer.
    pub local_ip: Ipv4Addr,
    pub prefix_len: u8,
    /// The peer's tunnel address (where the SSH server lives).
    pub peer_ip: Ipv4Addr,
    pub persistent_keepalive_secs: Option<u16>,
    /// Send a handshake initiation immediately (the client side).
    pub initiate: bool,
}

/// The host's datagram endpoints. Each `Vec<u8>` is one WireGuard datagram.
pub struct DatagramPipe {
    pub to_network: mpsc::Sender<Vec<u8>>,
    pub from_network: mpsc::Receiver<Vec<u8>>,
}

impl DatagramPipe {
    /// Two cross-connected pipes: what one sends, the other receives.
    pub fn pair(capacity: usize) -> (DatagramPipe, DatagramPipe) {
        let (a_tx, a_rx) = mpsc::channel(capacity);
        let (b_tx, b_rx) = mpsc::channel(capacity);
        (
            DatagramPipe {
                to_network: a_tx,
                from_network: b_rx,
            },
            DatagramPipe {
                to_network: b_tx,
                from_network: a_rx,
            },
        )
    }
}

/// smoltcp device over two queues of raw IP packets.
#[derive(Default)]
struct IpDevice {
    rx: VecDeque<Vec<u8>>,
    tx: VecDeque<Vec<u8>>,
}

struct IpRx(Vec<u8>);
struct IpTx<'a>(&'a mut VecDeque<Vec<u8>>);

impl RxToken for IpRx {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}

impl TxToken for IpTx<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut packet = vec![0u8; len];
        let r = f(&mut packet);
        self.0.push_back(packet);
        r
    }
}

impl Device for IpDevice {
    type RxToken<'a>
        = IpRx
    where
        Self: 'a;
    type TxToken<'a>
        = IpTx<'a>
    where
        Self: 'a;

    fn receive(&mut self, _ts: SmolInstant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let packet = self.rx.pop_front()?;
        Some((IpRx(packet), IpTx(&mut self.tx)))
    }

    fn transmit(&mut self, _ts: SmolInstant) -> Option<Self::TxToken<'_>> {
        Some(IpTx(&mut self.tx))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = MTU;
        caps
    }
}

struct Stack {
    tunn: Tunn,
    iface: Interface,
    device: IpDevice,
    sockets: SocketSet<'static>,
    to_network: mpsc::Sender<Vec<u8>>,
    peer_ip: Ipv4Addr,
    next_port: u16,
    /// The datagram source is gone; nothing will arrive again.
    dead: bool,
    /// Handshake completed at least once (a `WriteToTunnel` or a data
    /// encapsulation succeeded after a handshake response).
    handshaken: bool,
}

impl Stack {
    fn send(&self, datagram: &[u8]) {
        // Datagram semantics: if the host queue is full, drop like UDP would.
        let _ = self.to_network.try_send(datagram.to_vec());
    }

    /// One inbound WireGuard datagram: decapsulate, answer handshakes, queue
    /// inner packets for the interface. Same idiom as `minimald`'s pump.
    fn handle_datagram(&mut self, datagram: &[u8], buf: &mut [u8]) {
        let mut result = self.tunn.decapsulate(None, datagram, buf);
        loop {
            match result {
                TunnResult::Done => break,
                TunnResult::Err(e) => {
                    log::debug!("wireguard decapsulate: {e:?}");
                    break;
                }
                TunnResult::WriteToNetwork(out) => {
                    let out = out.to_vec();
                    self.send(&out);
                    result = self.tunn.decapsulate(None, &[], buf);
                }
                TunnResult::WriteToTunnelV4(packet, _src) => {
                    self.handshaken = true;
                    self.device.rx.push_back(packet.to_vec());
                    break;
                }
                TunnResult::WriteToTunnelV6(..) => break,
            }
        }
    }

    /// Service timers and the interface until quiescent; return how long the
    /// driver may sleep before it must run again.
    fn service(&mut self, buf: &mut [u8]) -> Duration {
        if let TunnResult::WriteToNetwork(out) = self.tunn.update_timers(buf) {
            let out = out.to_vec();
            self.send(&out);
        }
        let now = SmolInstant::from_millis(rt::now_ms());
        loop {
            let changed = self.iface.poll(now, &mut self.device, &mut self.sockets);
            while let Some(packet) = self.device.tx.pop_front() {
                match self.tunn.encapsulate(&packet, buf) {
                    TunnResult::WriteToNetwork(out) => {
                        let out = out.to_vec();
                        self.send(&out);
                    }
                    TunnResult::Done => {}
                    TunnResult::Err(e) => log::debug!("wireguard encapsulate: {e:?}"),
                    _ => {}
                }
            }
            if changed == PollResult::None && self.device.rx.is_empty() {
                break;
            }
        }
        self.iface
            .poll_delay(now, &self.sockets)
            .map(|d| Duration::from_micros(d.total_micros()))
            .unwrap_or(TIMER_TICK)
            .min(TIMER_TICK)
    }
}

/// Handle to one WireGuard tunnel with its own TCP/IP stack.
#[derive(Clone)]
pub struct WgStack {
    inner: Arc<Mutex<Stack>>,
    kick: Arc<Notify>,
}

impl WgStack {
    /// Build the stack. The returned future is the driver: spawn it on the
    /// host executor (`tokio::spawn` natively, `spawn_local` in a browser)
    /// and it runs until the pipe's network side goes away.
    pub fn new(cfg: WgConfig, pipe: DatagramPipe) -> (WgStack, impl Future<Output = ()>) {
        let tunn = Tunn::new(
            StaticSecret::from(cfg.private_key),
            PublicKey::from(cfg.peer_public_key),
            None,
            cfg.persistent_keepalive_secs,
            0,
            None,
        );
        let mut device = IpDevice::default();
        let mut iface = Interface::new(
            Config::new(HardwareAddress::Ip),
            &mut device,
            SmolInstant::from_millis(rt::now_ms()),
        );
        iface.update_ip_addrs(|addrs| {
            addrs
                .push(IpCidr::new(IpAddress::Ipv4(cfg.local_ip), cfg.prefix_len))
                .expect("one address");
        });
        let mut stack = Stack {
            tunn,
            iface,
            device,
            sockets: SocketSet::new(Vec::new()),
            to_network: pipe.to_network,
            peer_ip: cfg.peer_ip,
            next_port: 49152,
            dead: false,
            handshaken: false,
        };
        let mut buf = vec![0u8; SCRATCH];
        if cfg.initiate
            && let TunnResult::WriteToNetwork(out) =
                stack.tunn.format_handshake_initiation(&mut buf, false)
        {
            let out = out.to_vec();
            stack.send(&out);
        }
        let inner = Arc::new(Mutex::new(stack));
        let kick = Arc::new(Notify::new());
        let driver = drive(inner.clone(), kick.clone(), pipe.from_network);
        (WgStack { inner, kick }, driver)
    }

    /// Open a TCP connection to the peer's tunnel address on `port`. The
    /// stream resolves reads/writes once the handshake and the TCP connect
    /// complete; before that they are pending, not failed.
    pub fn connect(&self, port: u16) -> WgTcpStream {
        let mut s = self.inner.lock().unwrap();
        let mut sock = new_socket();
        let local_port = s.next_port;
        s.next_port = s.next_port.wrapping_add(1).max(49152);
        let peer = IpAddress::Ipv4(s.peer_ip);
        sock.connect(s.iface.context(), (peer, port), local_port)
            .expect("fresh socket connects");
        let handle = s.sockets.add(sock);
        drop(s);
        self.kick.notify_one();
        WgTcpStream {
            stack: self.clone(),
            handle,
        }
    }

    /// Accept one TCP connection on `port` at this node's tunnel address.
    pub fn listen(&self, port: u16) -> WgTcpStream {
        let mut s = self.inner.lock().unwrap();
        let mut sock = new_socket();
        sock.listen(port).expect("fresh socket listens");
        let handle = s.sockets.add(sock);
        drop(s);
        self.kick.notify_one();
        WgTcpStream {
            stack: self.clone(),
            handle,
        }
    }

    /// Whether the datagram source has gone away (the tunnel is dead).
    pub fn is_dead(&self) -> bool {
        self.inner.lock().unwrap().dead
    }

    /// Whether a WireGuard handshake has completed with the peer.
    pub fn handshaken(&self) -> bool {
        self.inner.lock().unwrap().handshaken
    }

    pub fn local_ip(&self) -> IpAddr {
        let s = self.inner.lock().unwrap();
        s.iface.ipv4_addr().map(IpAddr::V4).expect("configured")
    }
}

fn new_socket() -> tcp::Socket<'static> {
    let mut sock = tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0u8; TCP_BUFFER]),
        tcp::SocketBuffer::new(vec![0u8; TCP_BUFFER]),
    );
    // Interactive SSH: never hold a keystroke back waiting for the previous
    // segment's ACK (what OpenSSH's TCP_NODELAY does for interactive sessions).
    sock.set_nagle_enabled(false);
    sock
}

async fn drive(inner: Arc<Mutex<Stack>>, kick: Arc<Notify>, mut from_network: mpsc::Receiver<Vec<u8>>) {
    let mut buf = vec![0u8; SCRATCH];
    loop {
        let delay = inner.lock().unwrap().service(&mut buf);
        tokio::select! {
            datagram = from_network.recv() => match datagram {
                Some(d) => inner.lock().unwrap().handle_datagram(&d, &mut buf),
                None => break,
            },
            _ = kick.notified() => {}
            _ = rt::sleep(delay) => {}
        }
    }
    // The network side is gone (the WebSocket closed, the UDP socket died):
    // no packet will ever arrive again, so every TCP socket in this stack is
    // dead. Abort them, which wakes their registered wakers, so the SSH layer
    // sees EOF / broken pipe now instead of waiting for a TCP timeout.
    let mut s = inner.lock().unwrap();
    s.dead = true;
    for (_, socket) in s.sockets.iter_mut() {
        let smoltcp::socket::Socket::Tcp(tcp) = socket;
        tcp.abort();
    }
}

/// A TCP socket inside the tunnel, as an async byte stream.
pub struct WgTcpStream {
    stack: WgStack,
    handle: SocketHandle,
}

fn connecting(state: tcp::State) -> bool {
    matches!(
        state,
        tcp::State::Listen | tcp::State::SynSent | tcp::State::SynReceived
    )
}

impl AsyncRead for WgTcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut s = self.stack.inner.lock().unwrap();
        let dead = s.dead;
        let sock = s.sockets.get_mut::<tcp::Socket>(self.handle);
        if sock.can_recv() {
            let n = sock
                .recv_slice(buf.initialize_unfilled())
                .map_err(|e| io::Error::other(format!("tcp recv: {e}")))?;
            buf.advance(n);
            drop(s);
            self.stack.kick.notify_one();
            return Poll::Ready(Ok(()));
        }
        if dead || (!connecting(sock.state()) && !sock.may_recv()) {
            return Poll::Ready(Ok(())); // EOF: the peer closed, the connection or the tunnel is gone
        }
        sock.register_recv_waker(cx.waker());
        Poll::Pending
    }
}

impl AsyncWrite for WgTcpStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        let mut s = self.stack.inner.lock().unwrap();
        let dead = s.dead;
        let sock = s.sockets.get_mut::<tcp::Socket>(self.handle);
        if dead {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "tunnel closed")));
        }
        if sock.can_send() {
            let n = sock
                .send_slice(data)
                .map_err(|e| io::Error::other(format!("tcp send: {e}")))?;
            drop(s);
            self.stack.kick.notify_one();
            return Poll::Ready(Ok(n));
        }
        if !connecting(sock.state()) && !sock.may_send() {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "tcp closed")));
        }
        sock.register_send_waker(cx.waker());
        Poll::Pending
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.stack.kick.notify_one();
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut s = self.stack.inner.lock().unwrap();
        s.sockets.get_mut::<tcp::Socket>(self.handle).close();
        drop(s);
        self.stack.kick.notify_one();
        Poll::Ready(Ok(()))
    }
}

impl Drop for WgTcpStream {
    fn drop(&mut self) {
        if let Ok(mut s) = self.stack.inner.lock() {
            s.sockets.get_mut::<tcp::Socket>(self.handle).close();
        }
        self.stack.kick.notify_one();
    }
}
