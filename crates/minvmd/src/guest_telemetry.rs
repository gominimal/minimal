//! The guest telemetry door (spec 25 TEL-034,
//! `docs/specs/25-spec-telemetry/guest-vsock.md`): the host-side end of
//! the vsock port the guest daemon ships its telemetry records over.
//!
//! The `run` supervisor binds [`GUEST_TELEMETRY_SOCK_FILE`] beside the
//! control socket and hands its path to the VMM child in
//! [`GUEST_TELEMETRY_SOCK_ENV`]; the child registers it for
//! [`VSOCK_TELEMETRY_PORT`] (guest to host), the same way the READY marker
//! and the guest report door are wired. Each connection libkrun bridges in
//! is the guest's pid-1 daemon: the port exists only for this VM, the
//! socket is owner-only, and inside the guest no box can open an `AF_VSOCK`
//! socket. That last claim is `sandbox2`'s, not this crate's: no
//! socket-family seal admits the family (`sandbox2::tests::no_seal_admits_af_vsock`),
//! and each seal's filter refuses `socket(AF_VSOCK)` with `EAFNOSUPPORT`
//! (`sandbox2::tests::every_seal_refuses_a_vsock_socket`). A change to the
//! seals that admits `AF_VSOCK` opens this door to box code.
//!
//! What arrives is data, never identity: frames of one OTLP-JSON line each
//! (a 4-byte big-endian length, then the line), at most [`MAX_FRAME_BYTES`]
//! long, and at most [`GUEST_BYTES_PER_SEC`] a second with a
//! [`GUEST_BURST_BYTES`] burst for the VM, across reconnects ([`ByteBudget`]),
//! each accepted line charged the larger of its frame and the line the host
//! spools for it.
//! A line is accepted only when a strict JSON parse (`serde_json`: no
//! comments, no trailing commas, no duplicate top-level key) reads one
//! object whose one key is `resourceSpans` or `resourceLogs`, holding an
//! array of exactly one resource entry ([`accept_line`]). Every resource in
//! it is stamped by this process ([`stamp`]): every `minimal.*` attribute
//! the guest wrote, at any level (resource, scope, span, span event and
//! link, log record), is dropped and `minimal.forwarded_by` and
//! `minimal.vm` go first in the resource, so a receiver can tell a guest's
//! records from the host's by what the host says, not what the guest says. The line is then
//! serialized again from the parsed, stamped value, and only that text
//! leaves the door: appended to this process's spool, so `min bug` and the
//! lab see the guest's records beside the host's, and, as one request built
//! from the parsed entries of a batch ([`request_body`]), sent by the
//! forwarder thread to the host's endpoint for the signal under the host's
//! switches (`mlog::otel::forward_request`): off means dropped, on means
//! sent with the headers that endpoint gets. The collector so reads what
//! this parser read, never the guest's bytes. The guest never names an
//! endpoint, and nothing the guest sent is ever logged here: lengths,
//! counts and error kinds only. When the VMM child exits, the
//! supervisor drains the door ([`drain_at_exit`], bounded by
//! [`DRAIN_AT_EXIT`]) so the guest's last batch reaches the endpoint too.

use std::fmt;
use std::io::{self, Read};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TrySendError, sync_channel};
use std::time::{Duration, Instant};

use mlog::otel::{Forwarded, Signal};
use serde_json::{Map, Value};

/// The vsock port the guest daemon connects out to (CID 2) with its
/// telemetry: beside the READY marker's 7350, the host time updates' 7351
/// and the report door's 7352.
pub const VSOCK_TELEMETRY_PORT: u32 = 7353;

/// The host socket the door is bound at, beside the control socket.
pub const GUEST_TELEMETRY_SOCK_FILE: &str = "guest-telemetry.sock";

/// The env the supervisor hands the VMM child the door's path in; the
/// child registers [`VSOCK_TELEMETRY_PORT`] against it when set.
pub const GUEST_TELEMETRY_SOCK_ENV: &str = "MINVMD_GUEST_TELEMETRY_SOCK";

/// A frame longer than this closes the connection: a spool line is a few
/// hundred bytes, and a record bigger than a spool segment is not one. The
/// guest's sender drops a longer record rather than send it (the bound is
/// shared, `mlog::otel::FORWARD_MAX_FRAME_BYTES`).
pub const MAX_FRAME_BYTES: usize = mlog::otel::FORWARD_MAX_FRAME_BYTES;

/// The guest's share of this host's spool and endpoint: bytes a VM may
/// cost per second, sustained, where a line costs the larger of its frame
/// and the stamped line the host spools for it ([`read_frames`]). The
/// frames past it are refused and counted (they stay in the guest's own
/// spool). Foreign lines have no spool of their own: they share the host
/// spool's 50 MiB bound and its pruning order with the host's records
/// (`mlog::otel::spool_foreign_line`), so this rate is what keeps a guest
/// that floods from pushing the CLI's and this daemon's own records out of
/// the spool. The arithmetic: a VM writes at most its 4 MiB burst plus
/// 64 KiB a second into the spool, so one VM at the limit takes
/// (50 - 4) MiB / 64 KiB/s = 736 s, about 12 minutes, to write a spool's
/// worth. The budget is per VM and the spool is shared by every VM on the
/// host, so N VMs flooding at once take (50 - 4N) x 16 / N seconds: 336 s
/// for two, 136 s for four, and thirteen bursts alone exceed the bound. A
/// guest at full tilt records a few hundred spans a second of a few hundred
/// bytes each; this bounds a guest that floods, not one that works.
pub const GUEST_BYTES_PER_SEC: u64 = 64 * 1024;
/// The burst [`GUEST_BYTES_PER_SEC`] allows: the guest sender's own queue
/// bound in bytes, so a guest that comes back with a full queue (TEL-046)
/// is not refused for it.
pub const GUEST_BURST_BYTES: u64 = 4 * 1024 * 1024;

/// A batch goes to the forwarder at this many lines, or this many bytes,
/// or after [`FLUSH_IDLE`] with nothing new.
pub const BATCH_LINES: usize = 64;
/// See [`BATCH_LINES`].
pub const BATCH_BYTES: usize = 256 * 1024;
/// See [`BATCH_LINES`].
pub const FLUSH_IDLE: Duration = Duration::from_secs(1);

/// Batches waiting for the forwarder thread. A host endpoint that hangs
/// costs `EXPORT_TIMEOUT` per batch there; with this many waiting the door
/// drops the next batch (the lines are in the spool) and keeps reading, so
/// the guest's connection never stalls on the host's collector.
pub const FORWARD_QUEUE_BATCHES: usize = 16;

/// The resource attribute naming the forwarder: `minvmd`.
pub const FORWARDED_BY_ATTR: &str = "minimal.forwarded_by";
/// The resource attribute naming the VM the record came from.
pub const VM_ATTR: &str = "minimal.vm";

/// Lines accepted (stamped, spooled, and batched for the forward).
static ACCEPTED: AtomicU64 = AtomicU64::new(0);
/// Frames refused: not UTF-8, not one OTLP-JSON request, or over the VM's
/// byte budget.
static REFUSED: AtomicU64 = AtomicU64::new(0);
/// Lines forwarded to the host's endpoint.
static FORWARDED: AtomicU64 = AtomicU64::new(0);
/// Lines a failed forward lost (spooled still).
static FAILED: AtomicU64 = AtomicU64::new(0);
/// Lines dropped at the forwarder queue, with the forwarder stuck.
static QUEUE_DROPPED: AtomicU64 = AtomicU64::new(0);
/// A forward failure has been logged (once per process).
static WARNED: AtomicBool = AtomicBool::new(false);
/// Connections served so far (the guest reconnects after a bad frame).
static CONNECTIONS: AtomicU64 = AtomicU64::new(0);
/// What the door still owes the host's endpoint, for [`drain_at_exit`].
static PENDING: Pending = Pending::new();

/// How long the supervisor waits at exit for the door to hand the guest's
/// last records to the host's endpoint ([`drain_at_exit`]). The VM is gone
/// by then, so this only delays the supervisor's own exit; a collector
/// that hangs costs at most this, and the lines stay in the spool.
pub const DRAIN_AT_EXIT: Duration = Duration::from_secs(2);

/// The door's outstanding work: guest connections still being read, and
/// lines queued for the forwarder that it has not finished with (sent,
/// failed, or switched off). Lines dropped at a full queue are never
/// queued, so they are not owed.
#[derive(Debug, Default)]
pub(crate) struct Pending {
    open: AtomicU64,
    queued: AtomicU64,
    settled: AtomicU64,
}

impl Pending {
    pub(crate) const fn new() -> Self {
        Self {
            open: AtomicU64::new(0),
            queued: AtomicU64::new(0),
            settled: AtomicU64::new(0),
        }
    }

    fn opened(&self) {
        self.open.fetch_add(1, Ordering::SeqCst);
    }

    fn closed(&self) {
        self.open.fetch_sub(1, Ordering::SeqCst);
    }

    fn queued(&self, n: u64) {
        self.queued.fetch_add(n, Ordering::SeqCst);
    }

    fn settled(&self, n: u64) {
        self.settled.fetch_add(n, Ordering::SeqCst);
    }

    /// No connection is being read and every queued line is settled.
    fn is_drained(&self) -> bool {
        self.open.load(Ordering::SeqCst) == 0
            && self.settled.load(Ordering::SeqCst) >= self.queued.load(Ordering::SeqCst)
    }

    /// Wait up to `timeout` for [`Pending::is_drained`]; whether it was.
    pub(crate) fn wait_drained(&self, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        loop {
            if self.is_drained() {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

/// At the supervisor's exit, after the VMM child is gone: wait up to
/// `timeout` for the door to read the guest's connection to its end (the
/// VMM's exit closes it) and for the forwarder to hand every queued batch
/// to the host's endpoint, so a collector gets the guest's last records
/// (its shutdown), not only the spool. Logs the door's counts either way.
/// Returns whether it drained.
pub fn drain_at_exit(timeout: Duration) -> bool {
    let drained = PENDING.wait_drained(timeout);
    if drained {
        report_counts("supervisor exit");
    } else {
        tracing::warn!(
            timeout_ms = u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX),
            "guest telemetry door: records still owed to the host's endpoint at exit; \
             they stay in the host spool"
        );
        report_counts("supervisor exit, not drained");
    }
    drained
}

/// Refusals between two periodic count lines, and the most time between
/// them: the counts are the one thing the log says about refused frames.
const REPORT_EVERY_REFUSALS: u64 = 1000;
/// See [`REPORT_EVERY_REFUSALS`].
const REPORT_EVERY: Duration = Duration::from_secs(60);

/// One info line with the door's counters, never a guest byte: on every
/// close, and periodically while refusals come in.
fn report_counts(why: &'static str) {
    tracing::info!(
        why,
        connections = CONNECTIONS.load(Ordering::Relaxed),
        accepted = ACCEPTED.load(Ordering::Relaxed),
        refused = REFUSED.load(Ordering::Relaxed),
        forwarded = FORWARDED.load(Ordering::Relaxed),
        forward_failed = FAILED.load(Ordering::Relaxed),
        queue_dropped = QUEUE_DROPPED.load(Ordering::Relaxed),
        "guest telemetry door counts"
    );
}

/// Count one refused frame, with a count line every
/// [`REPORT_EVERY_REFUSALS`].
fn refuse() {
    let n = REFUSED.fetch_add(1, Ordering::Relaxed) + 1;
    if n.is_multiple_of(REPORT_EVERY_REFUSALS) {
        report_counts("refusals");
    }
}

/// Bind the guest telemetry door at [`GUEST_TELEMETRY_SOCK_FILE`] beside
/// `control_sock_path` and serve it on a dedicated thread, answering the
/// bound path so the caller hands the VMM child the same socket it
/// registers [`VSOCK_TELEMETRY_PORT`] for. The bind runs the control
/// socket's posture (path length, 0700 owned parent, stale socket removed,
/// 0600) on the calling thread, so a failure surfaces to the supervisor's
/// own startup handling. A second thread forwards the batches.
pub fn spawn_guest_telemetry_door(control_sock_path: &Path) -> io::Result<PathBuf> {
    let sock_path = control_sock_path.with_file_name(GUEST_TELEMETRY_SOCK_FILE);
    crate::sock::check_uds_path_len(&sock_path)?;
    crate::sock::prepare_socket_dir(&sock_path)?;
    if let Some(parent) = sock_path.parent() {
        crate::sock::restrict_owned_dir(parent)?;
        crate::sock::verify_provider_dir_ownership(parent)?;
    }
    crate::sock::remove_stale_socket(&sock_path)?;
    let listener = UnixListener::bind(&sock_path)?;
    crate::sock::enforce_socket_permissions(&sock_path)?;
    let (tx, rx) = sync_channel::<(Signal, Vec<Value>)>(FORWARD_QUEUE_BATCHES);
    std::thread::Builder::new()
        .name("minvmd-guest-forward".to_string())
        .spawn(move || forward_loop(rx))?;
    tracing::info!(
        sock = %sock_path.display(),
        vsock_port = VSOCK_TELEMETRY_PORT,
        "bound the guest telemetry door; the in-VM daemon's records reach the host's \
         exporter and spool over the vsock bridge"
    );
    let vm = crate::state::vm_name().to_owned();
    std::thread::Builder::new()
        .name("minvmd-guest-telemetry".to_string())
        .spawn(move || accept_loop(listener, &vm, &tx))
        .map(|_| sock_path)
}

/// Accept and serve one guest connection at a time until the daemon exits.
/// The peer check is the control socket's: a uid other than this process's
/// is refused (the socket is 0600, so this only backs the mode up). One
/// [`ByteBudget`] serves every connection: this supervisor runs one VM, so
/// the budget is the VM's, and a guest that reconnects keeps what it spent.
fn accept_loop(listener: UnixListener, vm: &str, forward: &SyncSender<(Signal, Vec<Value>)>) {
    let mut budget = ByteBudget::guest();
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                if crate::control::peer_uid(&stream)
                    .and_then(crate::control::check_peer_uid)
                    .is_err()
                {
                    continue;
                }
                serve_connection(stream, vm, &mut budget, forward);
            }
            Err(error) => tracing::debug!(%error, "guest telemetry door accept failed"),
        }
    }
}

/// Serve one connection: frames in, spool and batches out, until the guest
/// closes or a frame is malformed. A read that waits [`FLUSH_IDLE`] flushes
/// what is batched.
fn serve_connection(
    mut stream: UnixStream,
    vm: &str,
    budget: &mut ByteBudget,
    forward: &SyncSender<(Signal, Vec<Value>)>,
) {
    if let Err(error) = stream.set_read_timeout(Some(FLUSH_IDLE)) {
        tracing::debug!(%error, "guest telemetry door: no read timeout; batches flush on close");
    }
    CONNECTIONS.fetch_add(1, Ordering::Relaxed);
    PENDING.opened();
    let mut batches = Batches::default();
    let result = read_frames(
        &mut stream,
        vm,
        budget,
        &mut batches,
        &mut |signal, lines| {
            enqueue(forward, signal, lines);
        },
    );
    // `read_frames` has queued what it batched before returning.
    PENDING.closed();
    match result {
        Ok(()) => report_counts("closed by the guest"),
        // The error names a length or an I/O error kind, never guest bytes;
        // the guest reconnects after its retry interval (TEL-046).
        Err(error) => {
            tracing::warn!(
                %error,
                "guest telemetry connection ended on a bad frame; the guest reconnects"
            );
            report_counts("closed on a bad frame");
        }
    }
}

/// Hand a batch to the forwarder thread, or drop it (counted) when
/// [`FORWARD_QUEUE_BATCHES`] are already waiting: the door keeps reading
/// whatever the host's collector does.
fn enqueue(forward: &SyncSender<(Signal, Vec<Value>)>, signal: Signal, lines: Vec<Value>) {
    let n = lines.len() as u64;
    // Counted owed before the send, so the forwarder can never settle a
    // batch the drain has not seen queued.
    PENDING.queued(n);
    match forward.try_send((signal, lines)) {
        Ok(()) => {}
        Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => {
            PENDING.settled(n);
            QUEUE_DROPPED.fetch_add(n, Ordering::Relaxed);
        }
    }
}

/// The forwarder thread: one batch at a time to the host's endpoint, each
/// settled for [`drain_at_exit`] once `forward` is done with it.
fn forward_loop(rx: Receiver<(Signal, Vec<Value>)>) {
    while let Ok((signal, lines)) = rx.recv() {
        let n = lines.len() as u64;
        forward(signal, lines);
        PENDING.settled(n);
    }
}

/// Read frames from `r` until it ends: each frame is charged to `budget`,
/// and each accepted line ([`accept_line`]) is stamped with this host's
/// provenance ([`stamp`]), serialized again, spooled, and pushed into
/// `batches`, which hands full batches to `flush`. A read that times out
/// flushes everything batched and carries on, keeping any part of a frame
/// already read (a timeout inside the 4-byte length or the line never
/// shifts the framing); the end of the stream, and an error, flush and
/// return. A frame over [`MAX_FRAME_BYTES`], or an empty one, is the error
/// that ends the connection; a frame that is not one OTLP-JSON request, or
/// one past the VM's byte budget, is refused and counted, and the next one
/// is read. The budget is charged the frame before the parse and, for a
/// line that is accepted, what its spooled form (the stamped line and its
/// newline) is longer than the frame, so an accepted line costs the larger
/// of the two; a line refused at that second charge has paid its frame.
pub(crate) fn read_frames<R: Read>(
    r: &mut R,
    vm: &str,
    budget: &mut ByteBudget,
    batches: &mut Batches,
    flush: &mut impl FnMut(Signal, Vec<Value>),
) -> io::Result<()> {
    let mut last_report = (Instant::now(), REFUSED.load(Ordering::Relaxed));
    loop {
        let mut len = [0u8; 4];
        let header = fill(r, &mut len, &mut || {
            idle(batches, flush, &mut last_report);
        });
        match header {
            Ok(Filled::Full) => {}
            Ok(Filled::End) => {
                batches.flush_all(flush);
                return Ok(());
            }
            Ok(Filled::Cut) => {
                batches.flush_all(flush);
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "the stream ended inside a frame's length",
                ));
            }
            Err(e) => {
                batches.flush_all(flush);
                return Err(e);
            }
        }
        let n = u32::from_be_bytes(len) as usize;
        if n == 0 || n > MAX_FRAME_BYTES {
            batches.flush_all(flush);
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("a frame of {n} bytes (the bound is {MAX_FRAME_BYTES})"),
            ));
        }
        let mut buf = vec![0u8; n];
        let body = fill(r, &mut buf, &mut || {
            idle(batches, flush, &mut last_report);
        });
        match body {
            Ok(Filled::Full) => {}
            Ok(Filled::End | Filled::Cut) => {
                batches.flush_all(flush);
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "the stream ended inside a frame",
                ));
            }
            Err(e) => {
                batches.flush_all(flush);
                return Err(e);
            }
        }
        // Charged before the parse: a guest that floods with garbage spends
        // its budget the same as one that floods with records.
        if !budget.admit(Instant::now(), n + len.len()) {
            refuse();
            continue;
        }
        let Ok(line) = String::from_utf8(buf) else {
            refuse();
            continue;
        };
        let Some((signal, mut resources)) = accept_line(&line) else {
            refuse();
            continue;
        };
        stamp(&mut resources, vm);
        let Some(text) = request_body(signal, resources.clone()) else {
            refuse();
            continue;
        };
        // Charged again for what the host writes: the stamp and the
        // re-serialization make a short record's spooled line longer than
        // its frame, and the spool is what the budget shares out.
        let extra = spooled_bytes(&text).saturating_sub(n + len.len());
        if extra > 0 && !budget.admit(Instant::now(), extra) {
            refuse();
            continue;
        }
        ACCEPTED.fetch_add(1, Ordering::Relaxed);
        mlog::otel::spool_foreign_line(&text);
        batches.push(signal, resources, text.len(), flush);
    }
}

/// The bytes `text` takes in the host spool: the line and its newline.
fn spooled_bytes(text: &str) -> usize {
    text.len() + 1
}

/// While a read waits: flush what is batched, and log the counts now and
/// then while refusals come in.
fn idle(
    batches: &mut Batches,
    flush: &mut impl FnMut(Signal, Vec<Value>),
    last_report: &mut (Instant, u64),
) {
    batches.flush_all(flush);
    let refused = REFUSED.load(Ordering::Relaxed);
    if refused != last_report.1 && last_report.0.elapsed() >= REPORT_EVERY {
        report_counts("periodic");
        *last_report = (Instant::now(), refused);
    }
}

/// How [`fill`] ended.
#[derive(Debug, PartialEq, Eq)]
enum Filled {
    /// The buffer is full.
    Full,
    /// The stream ended before the first byte.
    End,
    /// The stream ended part-way through.
    Cut,
}

/// Fill `buf` from `r`. A read that times out (the stream's read timeout,
/// [`FLUSH_IDLE`]) calls `idle` and reads on into the same buffer, so the
/// bytes already read are kept: `read_exact` would lose them, and the next
/// read would take the rest of a length as the start of one.
fn fill<R: Read>(r: &mut R, buf: &mut [u8], idle: &mut impl FnMut()) -> io::Result<Filled> {
    let mut got = 0;
    loop {
        let Some(rest) = buf.get_mut(got..) else {
            return Ok(Filled::Full);
        };
        if rest.is_empty() {
            return Ok(Filled::Full);
        }
        match r.read(rest) {
            Ok(0) if got == 0 => return Ok(Filled::End),
            Ok(0) => return Ok(Filled::Cut),
            Ok(k) => got += k,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                idle();
            }
            Err(e) => return Err(e),
        }
    }
}

/// The VM's byte budget: a bucket of [`GUEST_BURST_BYTES`] that refills at
/// [`GUEST_BYTES_PER_SEC`]. A frame is admitted when the bucket holds its
/// bytes (the line and its 4-byte length), and refused otherwise; an
/// accepted line is then charged whatever its spooled form adds
/// ([`read_frames`]). The door keeps one for the VM's life, so a reconnect
/// does not refill it, and one per VM, so the host spool's share grows
/// with the number of VMs.
#[derive(Debug)]
pub(crate) struct ByteBudget {
    per_sec: f64,
    burst: f64,
    left: f64,
    last: Option<Instant>,
}

impl ByteBudget {
    /// A budget of `burst` bytes refilled at `per_sec` bytes a second; it
    /// starts full.
    pub(crate) fn new(per_sec: u64, burst: u64) -> Self {
        Self {
            per_sec: per_sec as f64,
            burst: burst as f64,
            left: burst as f64,
            last: None,
        }
    }

    /// The guest's: [`GUEST_BYTES_PER_SEC`] and [`GUEST_BURST_BYTES`].
    pub(crate) fn guest() -> Self {
        Self::new(GUEST_BYTES_PER_SEC, GUEST_BURST_BYTES)
    }

    /// Whether a frame of `bytes` fits at `now`; it is charged when it does.
    pub(crate) fn admit(&mut self, now: Instant, bytes: usize) -> bool {
        if let Some(last) = self.last {
            let refill = now.saturating_duration_since(last).as_secs_f64() * self.per_sec;
            self.left = (self.left + refill).min(self.burst);
        }
        self.last = Some(now);
        let cost = bytes as f64;
        if self.left < cost {
            return false;
        }
        self.left -= cost;
        true
    }
}

/// The top-level object of a request line, read strictly: exactly one key,
/// with its value. A second key is an error even when it repeats the first
/// (`{"resourceSpans":[..],"resourceSpans":[..]}`), which a map would
/// otherwise take silently, last one winning.
struct OneKey(String, Value);

impl<'de> serde::Deserialize<'de> for OneKey {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Visit;
        impl<'de> serde::de::Visitor<'de> for Visit {
            type Value = OneKey;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("an object with exactly one key")
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<OneKey, A::Error> {
                use serde::de::Error as _;
                let Some((key, value)) = map.next_entry::<String, Value>()? else {
                    return Err(A::Error::custom("an empty object"));
                };
                if map.next_key::<serde::de::IgnoredAny>()?.is_some() {
                    return Err(A::Error::custom("more than one key"));
                }
                Ok(OneKey(key, value))
            }
        }
        d.deserialize_map(Visit)
    }
}

/// The signal and the one resource entry of `line`, when the line is
/// exactly one OTLP-JSON request: strict JSON (`serde_json`, so no
/// comments, trailing commas or other leniencies), one object with one key,
/// `resourceSpans` or `resourceLogs`, whose value is an array of exactly
/// one entry. A spool line is one record, so one resource; a line with two
/// is not one the guest's spool wrote. Anything else is `None`, so what the
/// host spools and forwards is only what a spool writer writes.
pub(crate) fn accept_line(line: &str) -> Option<(Signal, Vec<Value>)> {
    let OneKey(key, value) = serde_json::from_str(line).ok()?;
    let signal = [Signal::Traces, Signal::Logs]
        .into_iter()
        .find(|s| s.key() == key)?;
    let Value::Array(resources) = value else {
        return None;
    };
    (resources.len() == 1).then_some((signal, resources))
}

/// One resource attribute with a string value, in OTLP-JSON.
fn string_attr(key: &str, value: &str) -> Value {
    let mut v = Map::new();
    v.insert("stringValue".to_owned(), Value::String(value.to_owned()));
    let mut a = Map::new();
    a.insert("key".to_owned(), Value::String(key.to_owned()));
    a.insert("value".to_owned(), Value::Object(v));
    Value::Object(a)
}

/// Stamp every resource entry in `resources` with this host's provenance:
/// any `minimal.*` attribute the guest put anywhere in the entry is dropped
/// (that namespace is the host's to state): in the resource, and in each
/// scope, span, span event, span link and log record
/// ([`drop_minimal_below_the_resource`]). Then `minimal.forwarded_by=minvmd`
/// and `minimal.vm=<vm>` go first in the resource. An entry with no resource gets one; an entry
/// or a resource that is not an object, or attributes that are not an
/// array, are replaced by ones that are, so no entry leaves unstamped. The
/// values are this host's, never the guest's, and `vm` is reduced to a boot
/// token (letters, digits, `-` and `_`).
pub(crate) fn stamp(resources: &mut [Value], vm: &str) {
    let vm: String = vm
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .collect();
    for entry in resources {
        if !entry.is_object() {
            *entry = Value::Object(Map::new());
        }
        let Some(entry) = entry.as_object_mut() else {
            continue;
        };
        drop_minimal_below_the_resource(entry);
        let resource = entry
            .entry("resource")
            .or_insert_with(|| Value::Object(Map::new()));
        if !resource.is_object() {
            *resource = Value::Object(Map::new());
        }
        let Some(resource) = resource.as_object_mut() else {
            continue;
        };
        let attrs = resource
            .entry("attributes")
            .or_insert_with(|| Value::Array(Vec::new()));
        if !attrs.is_array() {
            *attrs = Value::Array(Vec::new());
        }
        let Some(attrs) = attrs.as_array_mut() else {
            continue;
        };
        attrs.retain(|a| !is_minimal_attr(a));
        attrs.splice(
            0..0,
            [
                string_attr(FORWARDED_BY_ATTR, "minvmd"),
                string_attr(VM_ATTR, &vm),
            ],
        );
    }
}

/// Whether `attr` (`{"key": k, ...}`) is in the host's `minimal.*` namespace.
fn is_minimal_attr(attr: &Value) -> bool {
    attr.get("key")
        .and_then(Value::as_str)
        .is_some_and(|k| k.starts_with("minimal."))
}

/// Drop every `minimal.*` attribute from `attrs`, when it is an array.
fn drop_minimal_attrs(attrs: Option<&mut Value>) {
    if let Some(Value::Array(attrs)) = attrs {
        attrs.retain(|a| !is_minimal_attr(a));
    }
}

/// Drop the guest's `minimal.*` attributes below the resource of one
/// resource entry: each scope's (`scopeSpans[].scope`, `scopeLogs[].scope`),
/// each span's with its events and links, and each log record's. A part
/// that is missing or of the wrong shape is left as it is: nothing there
/// can be read as an attribute.
fn drop_minimal_below_the_resource(entry: &mut Map<String, Value>) {
    for (scopes, items) in [("scopeSpans", "spans"), ("scopeLogs", "logRecords")] {
        let Some(Value::Array(scopes)) = entry.get_mut(scopes) else {
            continue;
        };
        for scope in scopes {
            drop_minimal_attrs(scope.get_mut("scope").and_then(|s| s.get_mut("attributes")));
            let Some(Value::Array(items)) = scope.get_mut(items) else {
                continue;
            };
            for item in items {
                drop_minimal_attrs(item.get_mut("attributes"));
                for nested in ["events", "links"] {
                    if let Some(Value::Array(nested)) = item.get_mut(nested) {
                        for n in nested {
                            drop_minimal_attrs(n.get_mut("attributes"));
                        }
                    }
                }
            }
        }
    }
}

/// One OTLP/JSON request for `signal` holding `resources`, serialized from
/// the parsed values: what the host spools for one line, and what it sends
/// for a batch. `None` only when serialization fails.
pub(crate) fn request_body(signal: Signal, resources: Vec<Value>) -> Option<String> {
    let mut request = Map::new();
    request.insert(signal.key().to_owned(), Value::Array(resources));
    serde_json::to_string(&Value::Object(request)).ok()
}

/// The accepted, stamped resource entries batched per signal, one per
/// line, not yet forwarded.
#[derive(Debug, Default)]
pub(crate) struct Batches {
    traces: Batch,
    logs: Batch,
}

#[derive(Debug, Default)]
struct Batch {
    lines: Vec<Value>,
    bytes: usize,
}

impl Batches {
    fn batch(&mut self, signal: Signal) -> &mut Batch {
        match signal {
            Signal::Traces => &mut self.traces,
            Signal::Logs => &mut self.logs,
        }
    }

    /// Add a line's resource entries (`bytes` long as serialized) to its
    /// signal's batch, handing the batch to `flush` when it reaches
    /// [`BATCH_LINES`] or [`BATCH_BYTES`].
    fn push(
        &mut self,
        signal: Signal,
        resources: Vec<Value>,
        bytes: usize,
        flush: &mut impl FnMut(Signal, Vec<Value>),
    ) {
        let b = self.batch(signal);
        b.bytes += bytes;
        b.lines.extend(resources);
        if b.lines.len() >= BATCH_LINES || b.bytes >= BATCH_BYTES {
            let lines = std::mem::take(&mut b.lines);
            b.bytes = 0;
            flush(signal, lines);
        }
    }

    /// Hand every non-empty batch to `flush`.
    fn flush_all(&mut self, flush: &mut impl FnMut(Signal, Vec<Value>)) {
        for signal in [Signal::Traces, Signal::Logs] {
            let b = self.batch(signal);
            if b.lines.is_empty() {
                continue;
            }
            let lines = std::mem::take(&mut b.lines);
            b.bytes = 0;
            flush(signal, lines);
        }
    }
}

/// Forward one batch under the host's switches as one request serialized
/// from the parsed, stamped entries ([`request_body`]), counting the outcome
/// and warning once per process on a failure (the lines are in the spool
/// either way). The warning carries the error's text from this host's
/// client and the line count, never a line.
fn forward(signal: Signal, lines: Vec<Value>) {
    let n = lines.len() as u64;
    let records = lines.len();
    let result = match request_body(signal, lines) {
        Some(body) => mlog::otel::forward_request(signal, body, records),
        None => Err("the batch did not serialize".to_owned()),
    };
    match result {
        Ok(Forwarded::Sent(sent)) => {
            FORWARDED.fetch_add(sent as u64, Ordering::Relaxed);
        }
        Ok(Forwarded::Off) => {}
        Err(error) => {
            FAILED.fetch_add(n, Ordering::Relaxed);
            if !WARNED.swap(true, Ordering::Relaxed) {
                tracing::warn!(
                    signal = ?signal,
                    lines = n,
                    error = %error,
                    "guest telemetry: forwarding to the host's endpoint failed; the guest's \
                     records stay in the host spool (logged once per process)"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::io::Cursor;

    fn frame(line: &str) -> Vec<u8> {
        let mut v = (line.len() as u32).to_be_bytes().to_vec();
        v.extend_from_slice(line.as_bytes());
        v
    }

    const SPAN: &str = "{\"resourceSpans\":[{\"resource\":{\"attributes\":[]},\"scopeSpans\":[]}]}";
    const LOG: &str = "{\"resourceLogs\":[{\"resource\":{\"attributes\":[]},\"scopeLogs\":[]}]}";

    /// A budget no test frame reaches.
    fn unbounded() -> ByteBudget {
        ByteBudget::new(u64::MAX, u64::MAX)
    }

    /// `line` as the door admits it: parsed, stamped as VM `default`.
    fn stamped(line: &str) -> Vec<Value> {
        let (_, mut r) = accept_line(line).unwrap();
        stamp(&mut r, "default");
        r
    }

    /// The resource attributes of a stamped entry, as (key, string value).
    fn attrs(entry: &Value) -> Vec<(String, String)> {
        entry["resource"]["attributes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| {
                (
                    a["key"].as_str().unwrap().to_owned(),
                    a["value"]["stringValue"]
                        .as_str()
                        .unwrap_or_default()
                        .to_owned(),
                )
            })
            .collect()
    }

    fn stamp_pairs(vm: &str) -> Vec<(String, String)> {
        vec![
            (FORWARDED_BY_ATTR.to_owned(), "minvmd".to_owned()),
            (VM_ATTR.to_owned(), vm.to_owned()),
        ]
    }

    /// Strict JSON, one object, one key, one resource entry: everything
    /// else is refused, the leniencies `serde_json_lenient` would take
    /// included, and a duplicate top-level key, and an array of two.
    #[test]
    fn only_one_otlp_request_per_line_is_accepted() {
        assert_eq!(accept_line(SPAN).map(|(s, _)| s), Some(Signal::Traces));
        assert_eq!(accept_line(LOG).map(|(s, _)| s), Some(Signal::Logs));
        for bad in [
            "",
            "{}",
            "[]",
            "{\"resourceSpans\":[]}",
            "{\"resourceSpans\":[{}]}{\"resourceSpans\":[{}]}",
            "{\"resourceSpans\":{}}",
            "{\"resourceSpans\":[{}],\"x\":1}",
            "{\"resourceMetrics\":[{}]}",
            "{\"resourceSpans\":[}",
            // Two resources in one line: the second would skip a stamp
            // that looked only at the first.
            "{\"resourceSpans\":[{\"resource\":{}},{\"resource\":{}}]}",
            // The same key twice: a map keeps the last one silently.
            "{\"resourceSpans\":[{}],\"resourceSpans\":[{}]}",
            // What a lenient parser takes and a collector may not.
            "{\"resourceSpans\":[{},]}",
            "{\"resourceSpans\":[{\"resource\":{},}]}",
            "{\"resourceSpans\":[{}]} // a comment",
            "/* a comment */{\"resourceSpans\":[{}]}",
        ] {
            assert!(accept_line(bad).is_none(), "{bad:?}");
        }
    }

    /// The host's provenance goes first in the resource; whatever
    /// `minimal.*` the guest wrote there is gone, so there is one
    /// `minimal.vm` and it is the host's; an entry with no resource gets
    /// one; the VM name is reduced to boot-token characters.
    #[test]
    fn a_forwarded_line_is_stamped_with_the_hosts_provenance() {
        assert_eq!(attrs(&stamped(SPAN)[0]), stamp_pairs("default"));

        let forged = "{\"resourceLogs\":[{\"resource\":{\"attributes\":[\
            {\"key\":\"a\",\"value\":{\"stringValue\":\"b\"}},\
            {\"key\":\"minimal.vm\",\"value\":{\"stringValue\":\"other-vm\"}},\
            {\"key\":\"minimal.forwarded_by\",\"value\":{\"stringValue\":\"me\"}}]},\
            \"scopeLogs\":[]}]}";
        let mut want = stamp_pairs("default");
        want.push(("a".to_owned(), "b".to_owned()));
        assert_eq!(attrs(&stamped(forged)[0]), want);

        assert_eq!(
            attrs(&stamped("{\"resourceSpans\":[{\"x\":1}]}")[0]),
            stamp_pairs("default"),
            "an entry with no resource is stamped all the same"
        );
        assert_eq!(
            attrs(&stamped("{\"resourceSpans\":[{\"resource\":{\"attributes\":7}}]}")[0]),
            stamp_pairs("default"),
            "attributes that are not an array are replaced"
        );

        // Every entry is stamped, not the first only.
        let mut two = vec![
            serde_json::from_str::<Value>("{\"resource\":{\"attributes\":[]}}").unwrap(),
            serde_json::from_str::<Value>(
                "{\"resource\":{\"attributes\":[{\"key\":\"minimal.vm\",\"value\":{\"stringValue\":\"x\"}}]}}",
            )
            .unwrap(),
        ];
        stamp(&mut two, "vm 1\"}");
        for entry in &two {
            assert_eq!(attrs(entry), stamp_pairs("vm1"), "the VM name is a token");
        }
    }

    /// What leaves the door is serialized from the parsed value: a batch of
    /// lines with escapes and non-ASCII text is one strict-JSON request with
    /// every entry stamped.
    #[test]
    fn a_batch_is_one_strict_json_request_serialized_from_the_parsed_lines() {
        let tricky = "{\"resourceSpans\":[{\"resource\":{\"attributes\":[\
            {\"key\":\"q\",\"value\":{\"stringValue\":\"a \\\"quote\\\", a \\\\ and \\u00e9\"}}]},\
            \"scopeSpans\":[]}]}";
        let mut batch = Vec::new();
        for line in [SPAN, tricky, SPAN] {
            batch.extend(stamped(line));
        }
        let body = request_body(Signal::Traces, batch).unwrap();
        let parsed: Value = serde_json::from_str(&body).expect("strict JSON");
        let entries = parsed["resourceSpans"].as_array().unwrap();
        assert_eq!(entries.len(), 3);
        for entry in entries {
            assert_eq!(attrs(entry)[..2], stamp_pairs("default")[..]);
        }
        assert_eq!(
            attrs(&entries[1])[2],
            ("q".to_owned(), "a \"quote\", a \\ and \u{e9}".to_owned())
        );
        assert_eq!(
            mlog::otel::classify_line(&body),
            Some(Signal::Traces),
            "the request shape the forward checks"
        );
    }

    #[test]
    fn frames_are_batched_per_signal_and_flushed_at_the_end() {
        let mut bytes = Vec::new();
        bytes.extend(frame(SPAN));
        bytes.extend(frame("not a request"));
        bytes.extend(frame(LOG));
        bytes.extend(frame(SPAN));
        let mut flushed = Vec::new();
        let mut batches = Batches::default();
        read_frames(
            &mut Cursor::new(bytes),
            "default",
            &mut unbounded(),
            &mut batches,
            &mut |s, l| {
                flushed.push((s, l));
            },
        )
        .unwrap();
        let mut spans = stamped(SPAN);
        spans.extend(stamped(SPAN));
        assert_eq!(
            flushed,
            vec![(Signal::Traces, spans), (Signal::Logs, stamped(LOG))]
        );
    }

    #[test]
    fn a_full_batch_goes_out_before_the_end() {
        let mut bytes = Vec::new();
        for _ in 0..(BATCH_LINES + 1) {
            bytes.extend(frame(SPAN));
        }
        let mut sizes = Vec::new();
        let mut batches = Batches::default();
        read_frames(
            &mut Cursor::new(bytes),
            "default",
            &mut unbounded(),
            &mut batches,
            &mut |_, l| {
                sizes.push(l.len());
            },
        )
        .unwrap();
        assert_eq!(sizes, vec![BATCH_LINES, 1]);
    }

    #[test]
    fn an_oversized_or_empty_frame_ends_the_connection_after_a_flush() {
        for len in [0u32, (MAX_FRAME_BYTES as u32) + 1] {
            let mut bytes = frame(SPAN);
            bytes.extend(len.to_be_bytes());
            bytes.extend(b"x");
            let mut flushed = 0;
            let mut batches = Batches::default();
            let err = read_frames(
                &mut Cursor::new(bytes),
                "default",
                &mut unbounded(),
                &mut batches,
                &mut |_, l| {
                    flushed += l.len();
                },
            )
            .unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidData, "{len}");
            assert_eq!(flushed, 1, "the line before the bad frame was flushed");
        }
    }

    #[test]
    fn a_stream_cut_mid_frame_keeps_what_came_before() {
        for cut in [2, 10] {
            let mut bytes = frame(SPAN);
            bytes.extend(frame(LOG)[..cut].to_vec());
            let mut flushed = Vec::new();
            let mut batches = Batches::default();
            let err = read_frames(
                &mut Cursor::new(bytes),
                "default",
                &mut unbounded(),
                &mut batches,
                &mut |s, l| {
                    flushed.push((s, l.len()));
                },
            )
            .unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof, "cut at {cut}");
            assert_eq!(flushed, vec![(Signal::Traces, 1)]);
        }
    }

    /// A reader that hands out scripted chunks, and a read timeout between
    /// them where the script says so.
    struct Script(VecDeque<Option<Vec<u8>>>);

    impl Read for Script {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            match self.0.pop_front() {
                None => Ok(0),
                Some(None) => Err(io::Error::from(io::ErrorKind::WouldBlock)),
                Some(Some(mut chunk)) => {
                    let n = chunk.len().min(buf.len());
                    buf[..n].copy_from_slice(&chunk[..n]);
                    if n < chunk.len() {
                        self.0.push_front(Some(chunk.split_off(n)));
                    }
                    Ok(n)
                }
            }
        }
    }

    /// A read timeout part-way through a frame's 4-byte length, or its
    /// line, keeps the bytes already read: the frame after it is read
    /// whole, not shifted, and the timeout flushed what was batched.
    #[test]
    fn a_read_timeout_inside_a_frame_keeps_the_framing() {
        let second = frame(LOG);
        for split in [2, 4 + 10] {
            let (head, tail) = second.split_at(split);
            let mut script = Script(VecDeque::from([
                Some(frame(SPAN)),
                Some(head.to_vec()),
                None,
                Some(tail.to_vec()),
                Some(frame(SPAN)),
            ]));
            let mut flushed = Vec::new();
            let mut batches = Batches::default();
            read_frames(
                &mut script,
                "default",
                &mut unbounded(),
                &mut batches,
                &mut |s, l| {
                    flushed.push((s, l.len()));
                },
            )
            .unwrap();
            assert_eq!(
                flushed,
                vec![(Signal::Traces, 1), (Signal::Traces, 1), (Signal::Logs, 1)],
                "split at {split}: the timeout flushed the first span, and both \
                 later frames were read whole"
            );
        }
    }

    /// The byte budget: a burst, then refusals until it refills at its
    /// rate, never past the burst.
    #[test]
    fn the_byte_budget_admits_a_burst_then_its_rate() {
        let mut b = ByteBudget::new(1000, 4000);
        let t0 = Instant::now();
        assert!(b.admit(t0, 3000));
        assert!(b.admit(t0, 1000));
        assert!(!b.admit(t0, 1), "the burst is spent");
        assert!(!b.admit(t0 + Duration::from_millis(500), 600));
        assert!(b.admit(t0 + Duration::from_millis(1100), 600));
        assert!(
            !b.admit(t0 + Duration::from_secs(3600), 4001),
            "an idle hour refills to the burst, not past it"
        );
        assert!(b.admit(t0 + Duration::from_secs(3600), 4000));
    }

    /// A guest that floods and reconnects gets no fresh budget: the budget
    /// is the VM's, so the second connection's frames are charged against
    /// what the first spent.
    #[test]
    fn a_reconnect_does_not_reset_the_byte_budget() {
        // What an accepted line costs: its spooled form, which is longer
        // than its frame. Three lines' worth, and no refill within the test.
        let cost = spooled_bytes(&request_body(Signal::Traces, stamped(SPAN)).unwrap()) as u64;
        let mut budget = ByteBudget::new(0, 3 * cost);
        let mut accepted = 0;
        for _connection in 0..2 {
            let mut bytes = Vec::new();
            bytes.extend(frame(SPAN));
            bytes.extend(frame(SPAN));
            let mut batches = Batches::default();
            read_frames(
                &mut Cursor::new(bytes),
                "default",
                &mut budget,
                &mut batches,
                &mut |_, l| {
                    accepted += l.len();
                },
            )
            .unwrap();
        }
        assert_eq!(accepted, 3, "four lines sent, three lines' budget");
    }

    /// The guest's share of the host spool, measured on the line the host
    /// writes. A stamped line is longer than its frame (two stamp
    /// attributes, serialized again), so the door charges an accepted line
    /// the larger of the two: a budget of exactly three spooled lines admits
    /// three, where charging frames alone admitted more. So the spool gains
    /// at most the budget's bytes, and the arithmetic in
    /// [`GUEST_BYTES_PER_SEC`]'s doc (and `mlog::otel::spool_foreign_line`'s)
    /// holds: past the burst, one VM at the limit takes 736 s to write a
    /// spool's worth, and N VMs, each with its own budget, share one spool.
    #[test]
    fn the_guest_budget_is_a_small_share_of_the_host_spool() {
        // The host spool's bound (`mlog`'s `spool::MAX_BYTES`).
        const SPOOL_BYTES: u64 = 50 * 1024 * 1024;
        const RECORD: &str = "{\"resourceSpans\":[{\"resource\":{\"attributes\":[\
            {\"key\":\"service.name\",\"value\":{\"stringValue\":\"minimald\"}}]},\
            \"scopeSpans\":[{\"scope\":{\"name\":\"minimald\"},\"spans\":[{\
            \"traceId\":\"0af7651916cd43dd8448eb211c80319c\",\"spanId\":\"b7ad6b7169203331\",\
            \"name\":\"exec\",\"kind\":1,\"startTimeUnixNano\":\"1700000000000000000\",\
            \"endTimeUnixNano\":\"1700000000100000000\",\"attributes\":[\
            {\"key\":\"session_id\",\"value\":{\"stringValue\":\"6f1c1f9e-5a1b-4c2d-8e3f-000000000001\"}}],\
            \"status\":{}}]}]}]}";
        for line in [SPAN, LOG, RECORD] {
            let (signal, mut resources) = accept_line(line).unwrap();
            stamp(&mut resources, "default");
            let framed = frame(line).len();
            let spooled = spooled_bytes(&request_body(signal, resources).unwrap());
            assert!(
                spooled > framed,
                "a stamped line is longer than its frame: {framed} -> {spooled} bytes"
            );
            let mut budget = ByteBudget::new(0, 3 * spooled as u64);
            let mut accepted = 0;
            let bytes: Vec<u8> = (0..8).flat_map(|_| frame(line)).collect();
            read_frames(
                &mut Cursor::new(bytes),
                "default",
                &mut budget,
                &mut Batches::default(),
                &mut |_, l| accepted += l.len(),
            )
            .unwrap();
            assert_eq!(
                accepted, 3,
                "three spooled lines' budget admits three lines \
                 ({framed}-byte frames, {spooled}-byte spooled lines)"
            );
        }
        // The short record nearly doubles: charging its frame alone would
        // let a guest put about twice its budget into the spool.
        let short = spooled_bytes(&request_body(Signal::Traces, stamped(SPAN)).unwrap());
        assert!(short * 10 > frame(SPAN).len() * 18, "{short}");

        let fill_secs =
            |vms: u64| (SPOOL_BYTES - vms * GUEST_BURST_BYTES) / (vms * GUEST_BYTES_PER_SEC);
        assert_eq!(fill_secs(1), 736, "one VM: more than ten minutes");
        assert_eq!(fill_secs(2), 336, "the budget is per VM, the spool shared");
        assert_eq!(fill_secs(4), 136);
        const {
            // Thirteen VMs' bursts alone exceed the spool.
            assert!(13 * GUEST_BURST_BYTES > SPOOL_BYTES);
            // A frame at the bound fits a full budget.
            assert!(GUEST_BURST_BYTES >= MAX_FRAME_BYTES as u64 + 4);
        }
    }

    /// The guest's `minimal.*` attributes go at every
    /// level, not only the resource: a scope, span, span event, span link or
    /// log record that claims `minimal.vm` or `minimal.forwarded_by` loses
    /// the claim, and every other attribute stays. The host's stamp is the
    /// only `minimal.*` left in a forwarded line.
    #[test]
    fn a_guests_minimal_attributes_are_dropped_at_every_level() {
        let forged = |key: &str| {
            format!(
                "[{{\"key\":\"{key}\",\"value\":{{\"stringValue\":\"forged\"}}}},\
                 {{\"key\":\"keep\",\"value\":{{\"stringValue\":\"kept\"}}}}]"
            )
        };
        let (vm, by) = (forged("minimal.vm"), forged("minimal.forwarded_by"));
        let spans = format!(
            "{{\"resourceSpans\":[{{\"resource\":{{\"attributes\":{vm}}},\
             \"scopeSpans\":[{{\"scope\":{{\"name\":\"s\",\"attributes\":{by}}},\
             \"spans\":[{{\"name\":\"x\",\"attributes\":{vm},\
             \"events\":[{{\"name\":\"e\",\"attributes\":{by}}}],\
             \"links\":[{{\"traceId\":\"t\",\"attributes\":{vm}}}]}}]}}]}}]}}"
        );
        let logs = format!(
            "{{\"resourceLogs\":[{{\"resource\":{{}},\
             \"scopeLogs\":[{{\"scope\":{{\"attributes\":{vm}}},\
             \"logRecords\":[{{\"body\":{{\"stringValue\":\"b\"}},\"attributes\":{by}}}]}}]}}]}}"
        );
        for line in [spans, logs] {
            let (signal, mut stamped) = accept_line(&line).unwrap();
            stamp(&mut stamped, "default");
            let text = request_body(signal, stamped.clone()).unwrap();
            assert!(!text.contains("forged"), "{text}");
            assert_eq!(
                text.matches("minimal.").count(),
                2,
                "the stamp only: {text}"
            );
            assert_eq!(
                text.matches("\"kept\"").count(),
                line.matches("\"kept\"").count(),
                "every other attribute stays: {text}"
            );
            assert_eq!(attrs(&stamped[0])[..2], stamp_pairs("default")[..]);
        }
        // A part of the wrong shape is left as it is.
        let odd = "{\"resourceSpans\":[{\"scopeSpans\":[7,{\"scope\":3,\"spans\":\"x\"}]}]}";
        let (_, mut r) = accept_line(odd).unwrap();
        stamp(&mut r, "default");
        assert_eq!(r[0]["scopeSpans"][0], 7);
        assert_eq!(r[0]["scopeSpans"][1]["spans"], "x");
    }

    /// The exit drain waits for the open connection to end and for every
    /// queued line to be settled by the forwarder, and no longer.
    #[test]
    fn the_exit_drain_waits_for_the_connection_and_the_forwarder() {
        let p = Pending::new();
        assert!(p.wait_drained(Duration::ZERO), "an idle door is drained");
        p.opened();
        p.queued(5);
        assert!(
            !p.wait_drained(Duration::from_millis(50)),
            "a connection is open"
        );
        p.closed();
        assert!(
            !p.wait_drained(Duration::from_millis(50)),
            "5 lines are owed"
        );
        std::thread::scope(|s| {
            s.spawn(|| {
                std::thread::sleep(Duration::from_millis(100));
                p.settled(5);
            });
            let start = Instant::now();
            assert!(p.wait_drained(Duration::from_secs(5)));
            assert!(start.elapsed() < Duration::from_secs(2));
        });
    }

    /// A forwarder that never finishes (a hung collector) bounds the exit
    /// drain at its timeout.
    #[test]
    fn the_exit_drain_gives_up_at_its_bound() {
        let p = Pending::new();
        p.queued(1);
        let start = Instant::now();
        assert!(!p.wait_drained(Duration::from_millis(200)));
        let waited = start.elapsed();
        assert!(waited >= Duration::from_millis(200) && waited < Duration::from_secs(2));
    }

    /// A forwarder that hangs (a host collector that never answers) never
    /// stops the door reading: with the batch queue full the next batch is
    /// dropped and counted, and the stream is read to its end.
    #[test]
    fn a_stuck_forwarder_never_stops_the_reader() {
        let (tx, rx) = sync_channel::<(Signal, Vec<Value>)>(1);
        // Nobody reads `rx`: the first batch fills the queue, the rest drop.
        let mut bytes = Vec::new();
        for _ in 0..(3 * BATCH_LINES) {
            bytes.extend(frame(SPAN));
        }
        let before = QUEUE_DROPPED.load(Ordering::Relaxed);
        let mut batches = Batches::default();
        let start = Instant::now();
        read_frames(
            &mut Cursor::new(bytes),
            "default",
            &mut unbounded(),
            &mut batches,
            &mut |s, l| {
                enqueue(&tx, s, l);
            },
        )
        .unwrap();
        assert!(
            start.elapsed() < Duration::from_secs(1),
            "the reader did not block"
        );
        assert_eq!(
            QUEUE_DROPPED.load(Ordering::Relaxed) - before,
            2 * BATCH_LINES as u64
        );
        assert_eq!(rx.try_recv().map(|(_, l)| l.len()), Ok(BATCH_LINES));
    }
}
