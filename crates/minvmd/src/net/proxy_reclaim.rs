//! The hostname proxy's preferred port, taken back while the VM runs
//! (NET-150, NET-151).
//!
//! A start that found the preferred proxy port held hands the guest a
//! substitute, and the proxy serves there. This module watches the preferred
//! port for the rest of the VM's life. When the port passes the same bind and
//! loopback checks the start's assignment uses, the watcher takes the port's
//! reservation and asks the host switch to publish `127.0.0.1:<preferred>` to
//! the guest proxy's own port. The substitute keeps serving, so a browser
//! pointed at either port reaches the proxy, and the VM does not restart.
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
                let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
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

        let status = crate::control::ProxyPublishStatus::new();
        status.set_serving(substitute);
        let recorded = status.clone();
        let watcher = spawn_reclaim_watcher(
            preferred,
            substitute,
            Duration::from_millis(50),
            crate::cmd::run::proxy_reclaim_check(ports_dir.clone()),
            crate::cmd::run::proxy_reclaim_publisher(switch_sock.clone(), node),
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
        // The watcher holds the preferred port's reservation: a second
        // supervisor's check skips it.
        assert!(crate::cmd::run::proxy_reclaim_check(ports_dir.clone())(preferred).is_none());
        // One expose, never a second.
        assert!(requests.recv_timeout(Duration::from_millis(200)).is_err());
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
