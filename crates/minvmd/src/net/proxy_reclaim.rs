//! The hostname proxy's preferred port, taken back while the VM runs
//! (NET-150, NET-151), and a held port published once it frees (NET-021).
//!
//! A start that found the preferred proxy port held hands the guest a
//! substitute, and the proxy serves there. This module watches the preferred
//! port for the rest of the VM's life. When the port passes the same bind and
//! loopback checks the start's assignment uses, the watcher takes the port's
//! reservation and asks the host switch to publish `127.0.0.1:<preferred>` to
//! the guest proxy's own port. The substitute keeps serving, so a browser
//! pointed at either port reaches the proxy, and the VM does not restart.
//!
//! A start that found no port to serve on at all starts the VM with its
//! proxy down. The held-port watcher ([`spawn_held_port_watcher`]) retries
//! that port with backoff and publishes it with the same checks, so the
//! proxy serves once the port frees, and the VM does not restart.
//!
//! The assignment's own log line lives here too ([`log_proxy_port_assignment`]):
//! the line that says the proxy is on a substitute port, and the line that
//! says the watcher took the preferred port back, are one story in one log.

// Only the libkrun boot loop starts the watcher; every other target
// compiles it for the tests alone.
#![cfg_attr(not(minvmd_libkrun), allow(dead_code))]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// How often the watcher probes the preferred port. A probe is two binds and
/// one loopback connect, so it costs the host nothing it would notice, and a
/// person who frees the port waits at most this long.
#[cfg_attr(not(minvmd_libkrun), allow(dead_code))]
pub(crate) const RECLAIM_PROBE_INTERVAL: Duration = Duration::from_secs(5);

/// One hostname-proxy port assignment, as its log line reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AssignmentLine {
    /// The port the assignment preferred: the default, or the operator's pin.
    pub(crate) preferred: u16,
    /// The port handed to the guest.
    pub(crate) port: u16,
    /// Whether the port came from the operator's pin.
    pub(crate) configured: bool,
    /// Which check refused the preferred port, when one did.
    pub(crate) skip_reason: Option<&'static str>,
    /// The process that holds the preferred port, when the host can name it.
    pub(crate) port_holder: Option<String>,
}

/// The hostname proxy's assignment line (NET-151). A start that landed on the
/// preferred port logs at info. A start that skipped it logs at warn, with the
/// check that refused the port and the process that holds it, because the
/// proxy then serves on a port nobody configured a browser for.
pub(crate) fn log_proxy_port_assignment(line: &AssignmentLine) {
    let holder = line.port_holder.as_deref().unwrap_or("");
    match line.skip_reason {
        Some(skip_reason) => tracing::warn!(
            preferred = line.preferred,
            skip_reason,
            port_holder = %holder,
            port = line.port,
            configured = line.configured,
            "hostname proxy serving on a substitute port"
        ),
        None => tracing::info!(
            surface = "hostname proxy",
            preferred = line.preferred,
            handed = line.port,
            configured = line.configured,
            "assigned the node port"
        ),
    }
}

/// What one reclaim attempt found ([`reclaim_once`]).
#[derive(Debug)]
pub(crate) enum ReclaimAttempt<R> {
    /// The preferred port did not pass the checks: something still holds it.
    Held,
    /// The switch now publishes the preferred port. The reservation is the
    /// caller's to hold for the VM's life.
    Reclaimed(R),
    /// The checks passed but the switch did not publish the port. The
    /// reservation is dropped again, so the next attempt starts clean.
    PublishFailed(String),
}

/// One reclaim attempt: `take` runs the assignment's checks on `preferred`
/// and takes its reservation when they pass, and `publish` asks the switch to
/// forward `127.0.0.1:<preferred>` to the guest proxy at `substitute`.
pub(crate) fn reclaim_once<R>(
    preferred: u16,
    substitute: u16,
    take: &mut dyn FnMut(u16) -> Option<R>,
    publish: &mut dyn FnMut(u16, u16) -> Result<(), String>,
) -> ReclaimAttempt<R> {
    let Some(reservation) = take(preferred) else {
        return ReclaimAttempt::Held;
    };
    match publish(preferred, substitute) {
        Ok(()) => ReclaimAttempt::Reclaimed(reservation),
        Err(why) => ReclaimAttempt::PublishFailed(why),
    }
}

/// The running watcher. Dropping it stops the watcher and releases the
/// preferred port's reservation when the watcher took one.
pub(crate) struct ReclaimWatcher<R> {
    stop: Arc<AtomicBool>,
    held: Arc<Mutex<Option<R>>>,
}

impl<R> ReclaimWatcher<R> {
    /// Whether the watcher took the preferred port back.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn reclaimed(&self) -> bool {
        self.held
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_some()
    }
}

impl<R> Drop for ReclaimWatcher<R> {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
    }
}

/// Gates the watcher's `take` on the proxy's publish state: while
/// `status` records a down cause, `take` is not called and the probe reads
/// as held. An unconfirmed publish holds the watcher until the guest's late
/// report confirms it, and a late port-held report stops every publish to a
/// guest proxy that is not serving.
pub(crate) fn take_while_serving<R>(
    status: crate::control::ProxyPublishStatus,
    mut take: impl FnMut(u16) -> Option<R> + Send + 'static,
) -> impl FnMut(u16) -> Option<R> + Send + 'static {
    move |port| {
        if status.down().is_some() {
            None
        } else {
            take(port)
        }
    }
}

/// Starts the watcher on its own thread. Every `interval` it makes one
/// [`reclaim_once`] attempt. On success it calls `reclaimed` with the
/// preferred port, logs the reclaim line, holds the reservation, and stops.
/// A publish the switch refused is logged at warn once, then at debug, and
/// tried again on the next probe.
pub(crate) fn spawn_reclaim_watcher<R: Send + 'static>(
    preferred: u16,
    substitute: u16,
    interval: Duration,
    mut take: impl FnMut(u16) -> Option<R> + Send + 'static,
    mut publish: impl FnMut(u16, u16) -> Result<(), String> + Send + 'static,
    reclaimed: impl FnOnce(u16) + Send + 'static,
) -> ReclaimWatcher<R> {
    let stop = Arc::new(AtomicBool::new(false));
    let held = Arc::new(Mutex::new(None));
    let watcher = ReclaimWatcher {
        stop: Arc::clone(&stop),
        held: Arc::clone(&held),
    };
    let vm_scope = crate::telemetry::vm_task("proxy.port.reclaim");
    std::thread::spawn(move || {
        let _vm_scope = vm_scope.entered();
        let mut warned = false;
        while !stop.load(Ordering::Acquire) {
            std::thread::sleep(interval);
            if stop.load(Ordering::Acquire) {
                return;
            }
            match reclaim_once(preferred, substitute, &mut take, &mut publish) {
                ReclaimAttempt::Held => {}
                ReclaimAttempt::Reclaimed(reservation) => {
                    *held
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(reservation);
                    reclaimed(preferred);
                    tracing::info!(
                        preferred,
                        substitute,
                        "hostname proxy reclaimed its preferred port"
                    );
                    return;
                }
                ReclaimAttempt::PublishFailed(why) if !warned => {
                    warned = true;
                    tracing::warn!(
                        preferred,
                        substitute,
                        error = %why,
                        "the preferred hostname proxy port is free but the switch did not \
                         publish it; trying again"
                    );
                }
                ReclaimAttempt::PublishFailed(why) => {
                    tracing::debug!(preferred, substitute, error = %why, "reclaim publish failed");
                }
            }
        }
    });
    watcher
}

/// The held-port watcher's retry schedule (NET-021): the first retry waits
/// `initial`, each later one doubles the wait, and no wait passes `max`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct HeldPortBackoff {
    pub(crate) initial: Duration,
    pub(crate) max: Duration,
}

impl Default for HeldPortBackoff {
    /// One second first, then up to 30 s: a person who frees the port waits
    /// at most half a minute, and a port held all day costs two probes a
    /// minute.
    fn default() -> Self {
        Self {
            initial: Duration::from_secs(1),
            max: Duration::from_secs(30),
        }
    }
}

impl HeldPortBackoff {
    /// The wait before retry `attempt`, counted from zero.
    pub(crate) fn delay(&self, attempt: u32) -> Duration {
        self.initial
            .saturating_mul(2u32.saturating_pow(attempt.min(16)))
            .min(self.max)
    }
}

/// Records that the proxy serves on `port` after a start that left it down
/// (NET-022): the port goes on the served list, and the down cause goes, so
/// `min ls` stops naming it. The status cell clears only an unconfirmed
/// cause ([`crate::control::ProxyPublishStatus::confirm`]), so the held
/// cause is first replaced by an unconfirmed one on the same port. That
/// is true for the instant between the two calls: the switch publishes the
/// port, and nothing has confirmed it yet.
pub(crate) fn mark_serving(status: &crate::control::ProxyPublishStatus, port: u16) {
    status.set_serving(port);
    status.set_unconfirmed(port);
    status.confirm(port);
}

/// Starts the held-port watcher on its own thread (NET-021). The VM started
/// with its proxy down because another program held `port`. The watcher
/// retries the port on the `backoff` schedule. Each retry is one
/// [`reclaim_once`] attempt that publishes `127.0.0.1:<port>` to the guest
/// proxy's own `port`. Each retry that fails logs one debug line. On
/// success the watcher holds the reservation, calls `recovered` with the
/// port, logs one info line with the time it waited, and stops.
pub(crate) fn spawn_held_port_watcher<R: Send + 'static>(
    port: u16,
    backoff: HeldPortBackoff,
    mut take: impl FnMut(u16) -> Option<R> + Send + 'static,
    mut publish: impl FnMut(u16, u16) -> Result<(), String> + Send + 'static,
    recovered: impl FnOnce(u16) + Send + 'static,
) -> ReclaimWatcher<R> {
    let stop = Arc::new(AtomicBool::new(false));
    let held = Arc::new(Mutex::new(None));
    let watcher = ReclaimWatcher {
        stop: Arc::clone(&stop),
        held: Arc::clone(&held),
    };
    let vm_scope = crate::telemetry::vm_task("proxy.port.held");
    std::thread::spawn(move || {
        let _vm_scope = vm_scope.entered();
        let started = std::time::Instant::now();
        let mut attempt: u32 = 0;
        while !stop.load(Ordering::Acquire) {
            std::thread::sleep(backoff.delay(attempt));
            if stop.load(Ordering::Acquire) {
                return;
            }
            attempt = attempt.saturating_add(1);
            let failure = match reclaim_once(port, port, &mut take, &mut publish) {
                ReclaimAttempt::Reclaimed(reservation) => {
                    *held
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(reservation);
                    recovered(port);
                    tracing::info!(
                        port,
                        attempts = attempt,
                        waited_secs = started.elapsed().as_secs(),
                        "the hostname proxy is serving after its port freed"
                    );
                    return;
                }
                ReclaimAttempt::Held => "the port is still held".to_string(),
                ReclaimAttempt::PublishFailed(why) => why,
            };
            tracing::debug!(
                port,
                attempt,
                error = %failure,
                next_retry = ?backoff.delay(attempt),
                "the hostname proxy's port is not published yet; retrying"
            );
        }
    });
    watcher
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A log buffer for one test's subscriber.
    #[derive(Clone, Default)]
    struct Buf(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for Buf {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Buf {
        type Writer = Self;
        fn make_writer(&'a self) -> Self {
            self.clone()
        }
    }

    fn logged(level: tracing::Level, f: impl FnOnce()) -> String {
        let buf = Buf::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(buf.clone())
            .with_ansi(false)
            .with_max_level(level)
            .finish();
        tracing::subscriber::with_default(subscriber, f);
        let bytes = buf
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        String::from_utf8(bytes).expect("the log is UTF-8")
    }

    // NET-151: a start that skipped the preferred port warns, naming the
    // port it skipped, why, who holds it, and the port it serves on.
    #[test]
    fn proxy_substitute_port_logs_warning() {
        let log = logged(tracing::Level::WARN, || {
            log_proxy_port_assignment(&AssignmentLine {
                preferred: 7654,
                port: 65264,
                configured: false,
                skip_reason: Some("bind refused"),
                port_holder: Some("pid 4242 (python3)".to_string()),
            });
        });
        assert!(log.contains("WARN"), "{log}");
        assert!(
            log.contains("hostname proxy serving on a substitute port"),
            "{log}"
        );
        assert!(log.contains("preferred=7654"), "{log}");
        assert!(log.contains("skip_reason=\"bind refused\""), "{log}");
        assert!(log.contains("port_holder=pid 4242 (python3)"), "{log}");
        assert!(log.contains("port=65264"), "{log}");

        // A start on the preferred port says nothing at warn.
        let quiet = logged(tracing::Level::WARN, || {
            log_proxy_port_assignment(&AssignmentLine {
                preferred: 7654,
                port: 7654,
                configured: false,
                skip_reason: None,
                port_holder: None,
            });
        });
        assert!(quiet.is_empty(), "{quiet}");
    }

    /// A stand-in switch: answers every forwarder request with HTTP 200 and
    /// hands each request's text to the test.
    fn fake_switch(sock: &std::path::Path) -> std::sync::mpsc::Receiver<String> {
        fake_switch_answering(sock, 200, "")
    }

    /// A stand-in switch that answers every forwarder request with `status`
    /// and `body`, and hands each request's text to the test.
    fn fake_switch_answering(
        sock: &std::path::Path,
        status: u16,
        body: &'static str,
    ) -> std::sync::mpsc::Receiver<String> {
        use std::io::{Read as _, Write as _};
        let listener = std::os::unix::net::UnixListener::bind(sock).expect("bind the fake switch");
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { return };
                let mut request = Vec::new();
                let mut chunk = [0u8; 1024];
                // The request is one write: head and body. Read until the
                // body the head announces is in.
                loop {
                    let n = stream.read(&mut chunk).unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    request.extend_from_slice(chunk.get(..n).unwrap_or_default());
                    let text = String::from_utf8_lossy(&request);
                    if let Some((head, body)) = text.split_once("\r\n\r\n") {
                        let length = head
                            .lines()
                            .find_map(|line| line.strip_prefix("Content-Length: "))
                            .and_then(|value| value.trim().parse::<usize>().ok())
                            .unwrap_or(0);
                        if body.len() >= length {
                            break;
                        }
                    }
                }
                let answer = format!(
                    "HTTP/1.1 {status} Answer\r\nContent-Length: {}\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(answer.as_bytes());
                let _ = tx.send(String::from_utf8_lossy(&request).into_owned());
            }
        });
        rx
    }

    // NET-150: while another process holds the preferred port the watcher
    // publishes nothing. Once the port is free it takes the reservation,
    // asks the switch to publish the preferred port to the guest proxy's
    // port, and the control socket's served ports list both, preferred first.
    #[test]
    fn proxy_reclaims_preferred_port_when_free() {
        let dir = tempfile::tempdir().expect("tempdir");
        let ports_dir = dir.path().join("ports");
        std::fs::create_dir(&ports_dir).expect("ports dir");
        let switch_sock = dir.path().join("switch.sock");
        let requests = fake_switch(&switch_sock);

        // The other process on the preferred port.
        let holder =
            std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).expect("bind holder");
        let preferred = holder.local_addr().expect("holder addr").port();
        let substitute = 65264;
        let node = std::net::Ipv4Addr::new(192, 168, 127, 2);

        let runtime = tokio::runtime::Runtime::new().expect("a runtime");
        let _entered = runtime.enter();
        let registry = crate::box_registry::BoxRegistry::new(switch::DEFAULT_SUBNET);
        let ledger = crate::net::egress_gate::TestMirrorLedger::attach(
            &registry.table(),
            switch_sock.clone(),
        );

        let status = crate::control::ProxyPublishStatus::new();
        status.set_serving(substitute);
        let recorded = status.clone();
        let watcher = spawn_reclaim_watcher(
            preferred,
            substitute,
            Duration::from_millis(50),
            crate::cmd::run::proxy_reclaim_check(ports_dir.clone()),
            crate::cmd::run::proxy_reclaim_publisher(switch_sock.clone(), node, registry.table()),
            move |port| recorded.add_preferred(port),
        );

        // Held: several probes pass and the switch hears nothing.
        assert!(
            requests.recv_timeout(Duration::from_millis(400)).is_err(),
            "the watcher published a port another process holds"
        );
        assert!(!watcher.reclaimed());
        assert_eq!(status.serving_ports(), vec![substitute]);

        // Free the port: the next probe takes it back.
        drop(holder);
        let expose = requests
            .recv_timeout(Duration::from_secs(10))
            .expect("the watcher asks the switch to publish the preferred port");
        assert!(
            expose.starts_with("POST /services/forwarder/expose HTTP/1.1\r\n"),
            "{expose}"
        );
        assert!(
            expose.ends_with(&format!(
                r#"{{"local":"127.0.0.1:{preferred}","remote":"{node}:{substitute}","protocol":"tcp"}}"#
            )),
            "{expose}"
        );
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while !watcher.reclaimed() && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(watcher.reclaimed());
        assert_eq!(status.serving_ports(), vec![preferred, substitute]);
        // The forward is noted in the egress gate's ledger, so the gate
        // tracks its connections and admits the replies on them.
        assert_eq!(
            ledger.dials(std::net::Ipv4Addr::LOCALHOST, preferred),
            Some(node)
        );
        // The watcher holds the preferred port's reservation: a second
        // supervisor's check skips it.
        assert!(crate::cmd::run::proxy_reclaim_check(ports_dir.clone())(preferred).is_none());
        // One expose, never a second.
        assert!(requests.recv_timeout(Duration::from_millis(200)).is_err());
        drop(watcher);
    }

    // NET-150: a `proxy already running` answer to an expose the ledger did
    // not already hold means another forward holds the listener. The watcher
    // does not count that port as the proxy's, and the ledger keeps no note.
    #[test]
    fn proxy_reclaims_preferred_port_when_free_not_on_a_listener_held_elsewhere() {
        let dir = tempfile::tempdir().expect("tempdir");
        let ports_dir = dir.path().join("ports");
        std::fs::create_dir(&ports_dir).expect("ports dir");
        let switch_sock = dir.path().join("switch.sock");
        let requests = fake_switch_answering(&switch_sock, 500, "proxy already running\n");

        let runtime = tokio::runtime::Runtime::new().expect("a runtime");
        let _entered = runtime.enter();
        let registry = crate::box_registry::BoxRegistry::new(switch::DEFAULT_SUBNET);
        let ledger = crate::net::egress_gate::TestMirrorLedger::attach(
            &registry.table(),
            switch_sock.clone(),
        );

        // A free port: the check takes it on the first probe.
        let preferred = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .expect("bind a free port")
            .local_addr()
            .expect("free addr")
            .port();
        let substitute = 65264;
        let node = std::net::Ipv4Addr::new(192, 168, 127, 2);
        let status = crate::control::ProxyPublishStatus::new();
        status.set_serving(substitute);
        let recorded = status.clone();
        let watcher = spawn_reclaim_watcher(
            preferred,
            substitute,
            Duration::from_millis(50),
            crate::cmd::run::proxy_reclaim_check(ports_dir.clone()),
            crate::cmd::run::proxy_reclaim_publisher(switch_sock.clone(), node, registry.table()),
            move |port| recorded.add_preferred(port),
        );

        requests
            .recv_timeout(Duration::from_secs(10))
            .expect("the watcher asks the switch to publish the preferred port");
        // Let a few more attempts fail the same way.
        std::thread::sleep(Duration::from_millis(300));
        assert!(!watcher.reclaimed());
        assert_eq!(status.serving_ports(), vec![substitute]);
        assert_eq!(
            ledger.dials(std::net::Ipv4Addr::LOCALHOST, preferred),
            None,
            "a failed expose leaves no note in the ledger"
        );
        drop(watcher);
    }

    /// A proxy whose publish is unconfirmed, or held after the start, has no
    /// serving ports to report, and the watcher does not take the preferred
    /// port for it.
    #[test]
    fn proxy_reclaims_preferred_port_when_free_only_while_serving() {
        let status = crate::control::ProxyPublishStatus::new();
        status.set_serving(65264);
        let counter = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let seen = std::sync::Arc::clone(&counter);
        let mut take = take_while_serving(status.clone(), move |_port: u16| {
            seen.fetch_add(1, Ordering::SeqCst);
            Some(())
        });

        status.set_unconfirmed(65264);
        assert!(status.serving_ports().is_empty());
        assert!(take(7654).is_none());

        status.confirm(65264);
        assert_eq!(status.serving_ports(), vec![65264]);
        assert!(take(7654).is_some());

        status.set_down(
            65264,
            minimald_rpc::ProxyDownCause::PortHeldAfterStart { holder: None },
        );
        assert!(status.serving_ports().is_empty());
        assert!(take(7654).is_none());
        // Only the probe after the confirm reached `take`.
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    // NET-021: the held-port watcher waits 1 s first, doubles the wait, and
    // never waits past 30 s.
    #[test]
    fn held_port_backoff_doubles_from_one_second_to_thirty() {
        let backoff = HeldPortBackoff::default();
        let waits: Vec<u64> = (0..8).map(|n| backoff.delay(n).as_secs()).collect();
        assert_eq!(waits, vec![1, 2, 4, 8, 16, 30, 30, 30]);
        assert_eq!(backoff.delay(u32::MAX), Duration::from_secs(30));
    }

    // NET-021, NET-022: a VM that started with its proxy down on a held
    // port publishes nothing while the port stays held. Once the holder
    // exits, the watcher takes the reservation, asks the switch to publish
    // `127.0.0.1:<port>` to the guest proxy's own port, and clears the
    // down cause, so the status read reports the port as serving.
    #[test]
    fn proxy_publishes_once_the_held_port_frees() {
        let dir = tempfile::tempdir().expect("tempdir");
        let ports_dir = dir.path().join("ports");
        std::fs::create_dir(&ports_dir).expect("ports dir");
        let switch_sock = dir.path().join("switch.sock");
        let requests = fake_switch(&switch_sock);

        let holder =
            std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).expect("bind holder");
        let port = holder.local_addr().expect("holder addr").port();
        let node = std::net::Ipv4Addr::new(192, 168, 127, 2);

        let runtime = tokio::runtime::Runtime::new().expect("a runtime");
        let _entered = runtime.enter();
        let registry = crate::box_registry::BoxRegistry::new(switch::DEFAULT_SUBNET);
        let ledger = crate::net::egress_gate::TestMirrorLedger::attach(
            &registry.table(),
            switch_sock.clone(),
        );

        let status = crate::control::ProxyPublishStatus::new();
        status.set_down(
            port,
            minimald_rpc::ProxyDownCause::PortHeldAfterStart {
                holder: Some("pid 4242 (python3)".to_string()),
            },
        );
        let recorded = status.clone();
        {
            let watcher = spawn_held_port_watcher(
                port,
                HeldPortBackoff {
                    initial: Duration::from_millis(20),
                    max: Duration::from_millis(50),
                },
                crate::cmd::run::proxy_reclaim_check(ports_dir.clone()),
                crate::cmd::run::proxy_reclaim_publisher(
                    switch_sock.clone(),
                    node,
                    registry.table(),
                ),
                move |port| mark_serving(&recorded, port),
            );

            // Held: several retries pass and the switch hears nothing.
            assert!(
                requests.recv_timeout(Duration::from_millis(400)).is_err(),
                "the watcher published a port another process holds"
            );
            assert!(!watcher.reclaimed());
            assert!(
                status.down().is_some(),
                "the cause stays while the port is held"
            );
            assert!(status.serving_ports().is_empty());

            // Free the port: the next retry publishes it.
            drop(holder);
            let expose = requests
                .recv_timeout(Duration::from_secs(10))
                .expect("the watcher asks the switch to publish the freed port");
            assert!(
                expose.ends_with(&format!(
                    r#"{{"local":"127.0.0.1:{port}","remote":"{node}:{port}","protocol":"tcp"}}"#
                )),
                "{expose}"
            );
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            while status.down().is_some() && std::time::Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(10));
            }
            assert!(watcher.reclaimed());
            assert_eq!(status.down(), None, "the recovery clears the cause");
            assert_eq!(status.serving_ports(), vec![port]);
            assert_eq!(
                ledger.dials(std::net::Ipv4Addr::LOCALHOST, port),
                Some(node)
            );
            assert!(requests.recv_timeout(Duration::from_millis(200)).is_err());
            drop(watcher);
        }
    }

    #[test]
    fn a_refused_publish_drops_the_reservation_and_retries() {
        let mut taken = 0;
        let mut take = |_port: u16| {
            taken += 1;
            Some(())
        };
        let mut publish = |_: u16, _: u16| Err("address already in use".to_string());
        assert!(matches!(
            reclaim_once(7654, 65264, &mut take, &mut publish),
            ReclaimAttempt::PublishFailed(_)
        ));
        let mut held = |_port: u16| None::<()>;
        let mut never =
            |_: u16, _: u16| -> Result<(), String> { panic!("a held port is never published") };
        assert!(matches!(
            reclaim_once(7654, 65264, &mut held, &mut never),
            ReclaimAttempt::Held
        ));
        assert_eq!(taken, 1);
    }
}
