//! The guest daemon's forward path (spec 25 TEL-034): inside a microVM the
//! daemon has no network for telemetry, so each finished span and log record
//! is handed, as the spool's OTLP-JSON line, to a sender the daemon runs
//! (`minimald::guest`), which ships it to the VM host over vsock. The host's
//! `minvmd` receives the lines and exports them under the host's switches
//! ([`super::forward_request`]). `MINIMAL_OTEL_FORWARD=vsock:<port>` on the
//! boot line turns the path on; no OTLP exporter is built beside it.
//!
//! Bounded and lossy by design: the queue holds at most [`QUEUE_LINES`]
//! lines, a full queue drops the newest record and counts it, and nothing on
//! the daemon's request paths waits on the host. The spool is written by its
//! own processors first and is never affected (TEL-014, TEL-015).

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TrySendError, sync_channel};
use std::sync::{Arc, Mutex, OnceLock};

use opentelemetry::InstrumentationScope;
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::error::OTelSdkResult;
use opentelemetry_sdk::logs::{LogProcessor, SdkLogRecord};
use opentelemetry_sdk::trace::{SpanData, SpanProcessor};

use super::spool::{log_line, resource_json, span_line};

/// The variable that turns the forward path on: `vsock:<port>`.
pub const FORWARD_ENV: &str = "MINIMAL_OTEL_FORWARD";

/// Lines the queue holds before it drops. At ~1 KiB a line that is about
/// a megabyte of records in flight while the host is slow.
pub const QUEUE_LINES: usize = 1024;

/// The longest line one frame carries, on both ends of the channel: the
/// host's receiver (`minvmd::guest_telemetry`) ends a connection on a longer
/// frame, so the guest's sender (`minimald::telemetry_forward`) drops and
/// counts a longer record instead of sending it. A spool line is a few
/// hundred bytes; a record this big is not one worth a reconnect.
pub const MAX_FRAME_BYTES: usize = 1 << 20;

/// Where `MINIMAL_OTEL_FORWARD` sends the records.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Destination {
    /// The VM host, over AF_VSOCK, at this port on CID 2.
    Vsock {
        /// The port the host's receiver is wired at.
        port: u32,
    },
}

impl Destination {
    /// The destination `value` spells (`vsock:<port>`, the port a decimal
    /// `u32` other than 0 and the kernel's "any" value), or `None`.
    pub fn parse(value: &str) -> Option<Self> {
        let port = value.strip_prefix("vsock:")?;
        if port.is_empty() || port.starts_with('0') || !port.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let port: u32 = port.parse().ok()?;
        (port != u32::MAX).then_some(Self::Vsock { port })
    }
}

impl fmt::Display for Destination {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Vsock { port } => write!(f, "vsock:{port}"),
        }
    }
}

/// The bounded queue between the processors and the daemon's sender.
#[derive(Debug)]
pub(crate) struct Queue {
    tx: SyncSender<String>,
    queued: AtomicU64,
    dropped: AtomicU64,
}

impl Queue {
    /// Queue `line`, or drop it and count the drop when the queue is full
    /// or nobody reads it any more.
    fn push(&self, line: String) {
        match self.tx.try_send(line) {
            Ok(()) => {
                self.queued.fetch_add(1, Ordering::Relaxed);
            }
            Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

/// This process's queue, once [`install`] made one; `None` after an `init`
/// that forwards nothing.
static QUEUE: OnceLock<Option<Arc<Queue>>> = OnceLock::new();

/// The reading end, held until the daemon's sender takes it.
static RECEIVER: Mutex<Option<Receiver<String>>> = Mutex::new(None);

/// Make this process's queue (once). The processors write into it; the
/// daemon takes the reading end with [`take_receiver`].
pub(crate) fn install() -> Arc<Queue> {
    let q = QUEUE.get_or_init(|| {
        let (tx, rx) = sync_channel(QUEUE_LINES);
        if let Ok(mut slot) = RECEIVER.lock() {
            *slot = Some(rx);
        }
        Some(Arc::new(Queue {
            tx,
            queued: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
        }))
    });
    // `install` is the one writer and always stores `Some`; a `None` here
    // means `mark_absent` ran first, which `init` never does after an
    // install. Either way a fresh queue nobody reads is a safe answer.
    q.clone().unwrap_or_else(|| {
        let (tx, _rx) = sync_channel(QUEUE_LINES);
        Arc::new(Queue {
            tx,
            queued: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
        })
    })
}

/// Record that this process forwards nothing, so [`take_receiver`] answers
/// `None` at once.
pub(crate) fn mark_absent() {
    #[expect(
        clippy::let_underscore_must_use,
        reason = "a queue installed first stays installed, which is the intent"
    )]
    let _ = QUEUE.set(None);
}

/// The reading end of the forward queue, once per process: `Some` for the
/// first caller after an `init` that forwards, `None` otherwise. The caller
/// owns the delivery from here (the vsock sender in `minimald::guest`).
pub fn take_receiver() -> Option<Receiver<String>> {
    RECEIVER.lock().ok().and_then(|mut slot| slot.take())
}

/// Records accepted into the queue so far; with the sender's own count of
/// what it took, a shutdown can wait for the queue to drain.
pub fn queued() -> u64 {
    QUEUE
        .get()
        .and_then(Option::as_ref)
        .map_or(0, |q| q.queued.load(Ordering::Relaxed))
}

/// Records dropped at the queue so far (full, or no reader).
pub fn dropped() -> u64 {
    QUEUE
        .get()
        .and_then(Option::as_ref)
        .map_or(0, |q| q.dropped.load(Ordering::Relaxed))
}

/// Queues each finished, sampled span as its OTLP-JSON line.
#[derive(Debug)]
pub(crate) struct ForwardSpans {
    queue: Arc<Queue>,
    resource: String,
}

impl ForwardSpans {
    pub(crate) fn new(queue: Arc<Queue>) -> Self {
        Self {
            queue,
            resource: resource_json(&Resource::builder_empty().build()),
        }
    }
}

impl SpanProcessor for ForwardSpans {
    fn on_start(&self, _span: &mut opentelemetry_sdk::trace::Span, _cx: &opentelemetry::Context) {}

    fn on_end(&self, span: SpanData) {
        if span.span_context.is_sampled() {
            self.queue.push(span_line(&self.resource, &span));
        }
    }

    fn force_flush(&self) -> OTelSdkResult {
        Ok(())
    }

    fn shutdown_with_timeout(&self, _timeout: std::time::Duration) -> OTelSdkResult {
        Ok(())
    }

    fn set_resource(&mut self, resource: &Resource) {
        self.resource = resource_json(resource);
    }
}

/// Queues each exported log record as its OTLP-JSON line.
#[derive(Debug)]
pub(crate) struct ForwardLogs {
    queue: Arc<Queue>,
    resource: String,
}

impl ForwardLogs {
    pub(crate) fn new(queue: Arc<Queue>) -> Self {
        Self {
            queue,
            resource: resource_json(&Resource::builder_empty().build()),
        }
    }
}

impl LogProcessor for ForwardLogs {
    fn emit(&self, record: &mut SdkLogRecord, scope: &InstrumentationScope) {
        self.queue.push(log_line(&self.resource, record, scope));
    }

    fn force_flush(&self) -> OTelSdkResult {
        Ok(())
    }

    fn shutdown_with_timeout(&self, _timeout: std::time::Duration) -> OTelSdkResult {
        Ok(())
    }

    fn set_resource(&mut self, resource: &Resource) {
        self.resource = resource_json(resource);
    }
}

/// The OTLP request a forwarded line is: which signal, by its one top-level
/// key. The spool writes exactly these two shapes ([`span_line`],
/// [`log_line`]), so a reader that classifies by prefix and suffix reads
/// what the writer wrote and nothing else.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Signal {
    /// An `ExportTraceServiceRequest`.
    Traces,
    /// An `ExportLogsServiceRequest`.
    Logs,
}

impl Signal {
    /// The request's top-level key.
    pub const fn key(self) -> &'static str {
        match self {
            Self::Traces => "resourceSpans",
            Self::Logs => "resourceLogs",
        }
    }

    /// The switches' name for the signal.
    pub(crate) const fn switch_name(self) -> &'static str {
        match self {
            Self::Traces => "TRACES",
            Self::Logs => "LOGS",
        }
    }
}

/// The signal `line` is a request for, by the shape the spool writes
/// (`{"<key>":[` ... `]}`), or `None` for anything else. Shape only: the
/// receiver runs a strict JSON parse before this.
pub fn classify_line(line: &str) -> Option<Signal> {
    [Signal::Traces, Signal::Logs]
        .into_iter()
        .find(|s| strip_request(line, *s).is_some())
}

/// The elements of `line`'s top-level array, as text, when `line` has the
/// spool's shape for `signal`.
fn strip_request(line: &str, signal: Signal) -> Option<&str> {
    let line = line.trim_end_matches(['\n', '\r']);
    let inner = line
        .strip_prefix("{\"")?
        .strip_prefix(signal.key())?
        .strip_prefix("\":[")?
        .strip_suffix("]}")?;
    Some(inner)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_destination_is_a_vsock_port() {
        assert_eq!(
            Destination::parse("vsock:7353"),
            Some(Destination::Vsock { port: 7353 })
        );
        for bad in [
            "",
            "vsock:",
            "vsock:0",
            "vsock:07353",
            "vsock:x",
            "tcp:1",
            "vsock:4294967295",
        ] {
            assert_eq!(Destination::parse(bad), None, "{bad:?}");
        }
        assert_eq!(Destination::Vsock { port: 7353 }.to_string(), "vsock:7353");
    }

    #[test]
    fn a_line_is_classified_by_the_spools_shape() {
        assert_eq!(
            classify_line("{\"resourceSpans\":[{\"resource\":{}}]}\n"),
            Some(Signal::Traces)
        );
        assert_eq!(
            classify_line("{\"resourceLogs\":[{\"resource\":{}}]}"),
            Some(Signal::Logs)
        );
        for other in [
            "",
            "{}",
            "{\"resourceMetrics\":[]}",
            "[{\"resourceSpans\":[]}]",
            "{\"resourceSpans\":[]} ",
            " {\"resourceSpans\":[]}",
        ] {
            assert_eq!(classify_line(other), None, "{other:?}");
        }
    }

    #[test]
    fn a_full_queue_drops_the_newest_and_counts() {
        let (tx, rx) = sync_channel(2);
        let q = Queue {
            tx,
            queued: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
        };
        q.push("a".into());
        q.push("b".into());
        q.push("c".into());
        assert_eq!(q.dropped.load(Ordering::Relaxed), 1);
        assert_eq!(q.queued.load(Ordering::Relaxed), 2);
        assert_eq!(rx.recv().unwrap(), "a");
        assert_eq!(rx.recv().unwrap(), "b");
        assert_eq!(rx.try_recv().ok(), None);
        drop(rx);
        q.push("d".into());
        assert_eq!(
            q.dropped.load(Ordering::Relaxed),
            2,
            "no reader counts as dropped"
        );
    }
}
