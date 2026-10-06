//! The guest daemon's vsock sender for its telemetry (spec 25 TEL-034,
//! `docs/specs/25-spec-telemetry/guest-vsock.md`): inside a microVM the
//! daemon has no network for telemetry, so the records `mlog` queues for
//! forwarding (each one the spool's OTLP-JSON line) go to the VM host over
//! AF_VSOCK, to the port `MINIMAL_OTEL_FORWARD=vsock:<port>` names on the
//! host (CID 2), where `minvmd` receives them and exports them under the
//! host's switches.
//!
//! One dedicated thread owns the connection. It connects when the first
//! record arrives, writes each burst of queued records as length-delimited
//! frames (a 4-byte big-endian length, then the line), and reconnects after
//! [`RETRY_EVERY`] when a write fails or the host is not there. Nothing on
//! the daemon's request paths waits on it: the queue between `mlog` and
//! this thread is bounded, and while the host is away the records are
//! dropped and counted, not held. The spool is written before any of this
//! and is never affected (TEL-014, TEL-015).

use std::io::{self, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::Receiver;
use std::time::{Duration, Instant};

/// How long the sender waits after a failed connect or write before it
/// tries the host again (TEL-046).
pub const RETRY_EVERY: Duration = Duration::from_secs(5);

/// A write that blocks this long is a host that stopped reading: the
/// connection is dropped and made again, rather than the thread held.
const WRITE_TIMEOUT: Duration = Duration::from_secs(5);

/// Records written at most per frame burst: one `write_all` each.
const BURST_LINES: usize = 64;

/// Lines taken off the queue so far (sent or dropped here).
static TAKEN: AtomicU64 = AtomicU64::new(0);
/// Lines written to the host so far.
static SENT: AtomicU64 = AtomicU64::new(0);
/// Lines dropped here, with no connection to write them on, or too long
/// (or empty) for the host to take as a frame.
static DROPPED: AtomicU64 = AtomicU64::new(0);
/// Of [`DROPPED`], the lines no frame could carry: longer than
/// `mlog::otel::FORWARD_MAX_FRAME_BYTES`, or empty.
static UNFRAMEABLE: AtomicU64 = AtomicU64::new(0);
/// Connections made so far (one, plus one per reconnect).
static CONNECTS: AtomicU64 = AtomicU64::new(0);

/// Start the sender, once, after `mlog::otel::init`: a no-op when that
/// init forwards nothing (no `MINIMAL_OTEL_FORWARD`, telemetry off, or a
/// destination it refused), or when the sender already runs.
pub fn start() {
    let Some(rx) = mlog::otel::take_forward_receiver() else {
        return;
    };
    let Some(mlog::otel::ForwardDestination::Vsock { port }) =
        std::env::var(mlog::otel::FORWARD_ENV)
            .ok()
            .and_then(|v| mlog::otel::ForwardDestination::parse(&v))
    else {
        return;
    };
    let spawned = std::thread::Builder::new()
        .name("otel-forward".into())
        .spawn(move || run(rx, move || connect_vsock(port), RETRY_EVERY));
    match spawned {
        Ok(_) => tracing::info!(port, "telemetry forward: sending records to the VM host"),
        Err(error) => tracing::warn!(
            %error,
            "telemetry forward: cannot start the sender thread; records are not forwarded"
        ),
    }
}

/// Wait up to `timeout` for the sender to settle every record queued so
/// far (written to the host, or dropped and counted): the daemon's last
/// spans (its shutdown) are written to the host before the VM goes down.
/// Settled, not taken: the sender counts a burst taken before its write,
/// so a drain on the taken count returns while the last burst is still
/// being written, and the `reboot(2)` after it cuts that write.
/// Returns whether the queue drained.
pub fn drain(timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        let queued = mlog::otel::forward_queued();
        if settled() >= queued {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// Lines the sender is done with: written to the host, or dropped.
fn settled() -> u64 {
    SENT.load(Ordering::Relaxed) + DROPPED.load(Ordering::Relaxed)
}

/// Lines written to the host so far.
pub fn sent() -> u64 {
    SENT.load(Ordering::Relaxed)
}

/// Lines this sender dropped: for want of a connection, or because no
/// frame could carry them. The queue's own drops (a full queue) are
/// `mlog::otel::forward_dropped`.
pub fn dropped() -> u64 {
    DROPPED.load(Ordering::Relaxed)
}

/// A connection to the host's receiver at `port`, with a write timeout.
fn connect_vsock(port: u32) -> io::Result<Box<dyn Write + Send>> {
    let stream = vsock::VsockStream::connect_with_cid_port(libc::VMADDR_CID_HOST, port)?;
    stream.set_write_timeout(Some(WRITE_TIMEOUT))?;
    Ok(Box::new(stream))
}

/// The sender's loop: for every burst of queued lines, connect when there
/// is no connection and the last attempt is `retry` ago, write the burst
/// as frames, and on a failed write drop the connection. Returns when the
/// queue's writers are gone. `connect` is the one I/O choice, so the loop
/// is tested over a socket pair.
pub(crate) fn run(
    rx: Receiver<String>,
    mut connect: impl FnMut() -> io::Result<Box<dyn Write + Send>>,
    retry: Duration,
) {
    let mut conn: Option<Box<dyn Write + Send>> = None;
    let mut next_try = Instant::now();
    let mut warned = false;
    while let Ok(first) = rx.recv() {
        let mut burst = vec![first];
        while burst.len() < BURST_LINES
            && let Ok(more) = rx.try_recv()
        {
            burst.push(more);
        }
        let n = burst.len() as u64;
        TAKEN.fetch_add(n, Ordering::Relaxed);
        if conn.is_none() && Instant::now() >= next_try {
            match connect() {
                Ok(c) => {
                    conn = Some(c);
                    warned = false;
                    let connects = CONNECTS.fetch_add(1, Ordering::Relaxed) + 1;
                    tracing::info!(
                        connects,
                        dropped = DROPPED.load(Ordering::Relaxed),
                        sent = SENT.load(Ordering::Relaxed),
                        "telemetry forward: connected to the VM host"
                    );
                }
                Err(error) => {
                    next_try = Instant::now() + retry;
                    if !warned {
                        warned = true;
                        tracing::warn!(
                            %error,
                            "telemetry forward: cannot reach the VM host; records are dropped \
                             until it answers (retried every {} s)",
                            retry.as_secs()
                        );
                    }
                }
            }
        }
        match conn.as_mut() {
            Some(w) => match write_frames(w, &burst) {
                Ok(skipped) => {
                    let skipped = skipped as u64;
                    SENT.fetch_add(n - skipped, Ordering::Relaxed);
                    if skipped > 0 {
                        DROPPED.fetch_add(skipped, Ordering::Relaxed);
                        let before = UNFRAMEABLE.fetch_add(skipped, Ordering::Relaxed);
                        if before == 0 {
                            tracing::warn!(
                                max_bytes = mlog::otel::FORWARD_MAX_FRAME_BYTES,
                                "telemetry forward: a record too long for one frame was dropped \
                                 (it stays in the guest's spool; later ones are counted only)"
                            );
                        }
                    }
                }
                Err(error) => {
                    conn = None;
                    next_try = Instant::now() + retry;
                    DROPPED.fetch_add(n, Ordering::Relaxed);
                    tracing::warn!(
                        %error,
                        connects = CONNECTS.load(Ordering::Relaxed),
                        dropped = DROPPED.load(Ordering::Relaxed),
                        "telemetry forward: the VM host connection failed; reconnecting in {} s",
                        retry.as_secs()
                    );
                }
            },
            None => {
                DROPPED.fetch_add(n, Ordering::Relaxed);
            }
        }
    }
}

/// Write `lines` as frames: each a 4-byte big-endian length, then the line
/// without a trailing newline. One write for the burst. A line the host
/// would refuse as a frame (longer than `mlog::otel::FORWARD_MAX_FRAME_BYTES`,
/// or empty) is left out rather than sent: the host ends the connection on
/// such a frame, which would cost the burst and a [`RETRY_EVERY`] of
/// records. Returns how many lines were left out.
pub(crate) fn write_frames(w: &mut impl Write, lines: &[String]) -> io::Result<usize> {
    let mut buf = Vec::with_capacity(lines.iter().map(|l| l.len() + 4).sum());
    let mut skipped = 0;
    for line in lines {
        let line = line.trim_end_matches(['\n', '\r']);
        let len = match u32::try_from(line.len()) {
            Ok(len) if !line.is_empty() && line.len() <= mlog::otel::FORWARD_MAX_FRAME_BYTES => len,
            _ => {
                skipped += 1;
                continue;
            }
        };
        buf.extend_from_slice(&len.to_be_bytes());
        buf.extend_from_slice(line.as_bytes());
    }
    if !buf.is_empty() {
        w.write_all(&buf)?;
        w.flush()?;
    }
    Ok(skipped)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read as _;
    use std::os::unix::net::UnixStream;
    use std::sync::mpsc::sync_channel;

    /// The frames a reader parses out of `bytes`.
    fn frames(mut bytes: &[u8]) -> Vec<String> {
        let mut out = Vec::new();
        while !bytes.is_empty() {
            let (len, rest) = bytes.split_at(4);
            let n = u32::from_be_bytes(len.try_into().unwrap()) as usize;
            let (line, rest) = rest.split_at(n);
            out.push(String::from_utf8(line.to_vec()).unwrap());
            bytes = rest;
        }
        out
    }

    #[test]
    fn frames_are_length_prefixed_lines_without_the_newline() {
        let mut buf = Vec::new();
        let skipped = write_frames(
            &mut buf,
            &["{\"a\":1}\n".to_string(), "{\"b\":2}".to_string()],
        )
        .unwrap();
        assert_eq!(skipped, 0);
        assert_eq!(buf[..4], 7u32.to_be_bytes());
        assert_eq!(frames(&buf), vec!["{\"a\":1}", "{\"b\":2}"]);
    }

    /// A record no frame can carry (over the host's frame bound, or empty)
    /// is left out and counted, and the records around it still go: the
    /// host would end the connection on that frame.
    #[test]
    fn a_record_over_the_frame_bound_is_dropped_not_sent() {
        let max = mlog::otel::FORWARD_MAX_FRAME_BYTES;
        let at_bound = "x".repeat(max);
        let mut buf = Vec::new();
        let skipped = write_frames(
            &mut buf,
            &[
                "{\"a\":1}".to_string(),
                "y".repeat(max + 1),
                String::new(),
                "\n".to_string(),
                at_bound.clone(),
                "{\"b\":2}".to_string(),
            ],
        )
        .unwrap();
        assert_eq!(skipped, 3);
        assert_eq!(
            frames(&buf),
            vec!["{\"a\":1}".to_string(), at_bound, "{\"b\":2}".to_string()]
        );

        // A burst of nothing but such records writes nothing at all.
        let mut buf = Vec::new();
        assert_eq!(write_frames(&mut buf, &["z".repeat(max + 1)]).unwrap(), 1);
        assert!(buf.is_empty());
    }

    /// With the host away the sender drops and counts; once a connect
    /// succeeds the later records arrive as frames; a failed write drops the
    /// connection and the burst, and the next record reconnects.
    #[test]
    fn the_sender_drops_while_the_host_is_away_and_reconnects() {
        let (tx, rx) = sync_channel::<String>(16);
        let (mut host, guest) = UnixStream::pair().unwrap();
        let (mut host2, guest2) = UnixStream::pair().unwrap();
        let ends = std::sync::Mutex::new(vec![Some(guest2), Some(guest)]);
        let attempts = std::sync::atomic::AtomicUsize::new(0);
        let (sent_before, dropped_before) = (sent(), dropped());
        std::thread::scope(|s| {
            s.spawn(|| {
                run(
                    rx,
                    || {
                        let n = attempts.fetch_add(1, Ordering::Relaxed);
                        // The first attempt fails; the next ones hand out the
                        // pairs' guest ends in order.
                        if n == 0 {
                            return Err(io::Error::other("no host"));
                        }
                        let end = ends.lock().unwrap().pop().flatten();
                        end.map(|e| Box::new(e) as Box<dyn Write + Send>)
                            .ok_or_else(|| io::Error::other("no more ends"))
                    },
                    Duration::ZERO,
                );
            });
            tx.send("lost".into()).unwrap();
            // Let the sender take the record with no host.
            while TAKEN.load(Ordering::Relaxed) == 0 {
                std::thread::sleep(Duration::from_millis(5));
            }
            tx.send("one".into()).unwrap();
            let mut buf = [0u8; 7];
            host.read_exact(&mut buf).unwrap();
            assert_eq!(frames(&buf), vec!["one"]);
            // The host closes: the next write fails, that burst is dropped,
            // and the one after it goes out on the fresh connection.
            drop(host);
            tx.send("two".into()).unwrap();
            while dropped() - dropped_before < 2 {
                std::thread::sleep(Duration::from_millis(5));
            }
            tx.send("three".into()).unwrap();
            let mut buf = [0u8; 9];
            host2.read_exact(&mut buf).unwrap();
            assert_eq!(frames(&buf), vec!["three"]);
            drop(tx);
        });
        assert_eq!(sent() - sent_before, 2);
        assert_eq!(dropped() - dropped_before, 2);
    }
}
