//! Blocking oneshot-RPC client for the in-VM minimald over the bridge UDS.
//!
//! `minvmd`'s command paths are synchronous, so this wraps a short-lived
//! current-thread tokio runtime around the same russh flow as the async
//! client in `crates/minimal/src/client.rs`. The two cannot be shared:
//! `minimal` depends on `minvmd`, so importing its client here would be a
//! dependency cycle (dedup would move the client below both — out of scope).

use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context as _;
use minimald_rpc::OneshotSshRpc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Largest oneshot-RPC response body accepted from the in-VM daemon.
///
/// Every response on this path is a small JSON status object; the cap exists
/// so a wedged or hostile guest cannot make the host buffer without bound.
/// Generous by two orders of magnitude against the real payloads, so it can
/// only ever fire on something pathological.
const MAX_RESPONSE_BYTES: u64 = 8 * 1024 * 1024;

/// russh client handler that accepts any host key. The daemon generates a
/// fresh host key on every boot and the connection is a local UDS (the
/// libkrun vsock bridge), so TOFU trust is acceptable. russh 0.63 widened the
/// callback to `PublicKeyOrCertificate`; both variants are accepted on that
/// same rationale — the guest daemon never presents a host certificate, and
/// nothing here is verified either way.
struct AnyHostKey;

impl russh::client::Handler for AnyHostKey {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _key: &russh::keys::PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

/// Issue a single oneshot RPC to the in-VM minimald over the UDS at
/// `uds_path`, with two independent deadlines: `connect_timeout` covers
/// connect + SSH handshake + auth (short — libkrun accepts the UDS connect
/// even when the guest is wedged, so only a completed handshake proves a
/// live daemon), and `rpc_timeout` covers the request/response exchange
/// (long — the handler may do real work, e.g. draining sessions, before it
/// answers). `rpc_deadline`, when set, also ends the exchange at that
/// instant: it is measured once the connect has finished, so a connect that
/// returns early hands the time it did not use to the RPC.
pub(crate) fn call_oneshot_blocking<R: OneshotSshRpc>(
    uds_path: &Path,
    request: R::Request<'_>,
    connect_timeout: Duration,
    rpc_timeout: Duration,
    rpc_deadline: Option<Instant>,
) -> anyhow::Result<R::Response> {
    // Read before the runtime: its tasks start with no current span.
    let traceparent = crate::telemetry::traceparent();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("building RPC client runtime")?;
    rt.block_on(async {
        let mut handle = tokio::time::timeout(connect_timeout, connect(uds_path))
            .await
            .map_err(|_| {
                anyhow::anyhow!(
                    "no live minimald behind {} after {connect_timeout:?}",
                    uds_path.display()
                )
            })??;
        let rpc_timeout = rpc_deadline.map_or(rpc_timeout, |deadline| {
            rpc_timeout.min(deadline.saturating_duration_since(Instant::now()))
        });
        tokio::time::timeout(
            rpc_timeout,
            call_oneshot::<R>(&mut handle, request, traceparent.as_deref()),
        )
        .await
        // `Elapsed` says only "deadline has elapsed"; the deadline itself is
        // `rpc_timeout`, so the message names that and not the error.
        .map_err(|_elapsed| anyhow::anyhow!("RPC {} timed out after {rpc_timeout:?}", R::NAME))?
    })
}

/// Ask the in-VM minimald to shut down: drain sessions and quiesce the state
/// volume (R2.3). `force: true` because the caller is tearing the VM down
/// regardless — a refused non-force shutdown would only trade a clean drain
/// for an unclean SIGTERM. The bounds are [`call_oneshot_blocking`]'s.
#[tracing::instrument(name = "guest.shutdown", skip_all, fields(otel.status_code = tracing::field::Empty))]
pub(crate) fn shutdown_guest(
    uds_path: &Path,
    connect_timeout: Duration,
    rpc_timeout: Duration,
    rpc_deadline: Option<Instant>,
) -> anyhow::Result<minimald_rpc::ShutdownResponse> {
    // A clean stop that fails (a wedged guest, the bridge down, the RPC
    // timed out) exports its span with an error status (TEL-035), as
    // `vm.boot` does; the caller goes on to SIGTERM, and the trace says so.
    let span = tracing::Span::current();
    let failed = crate::telemetry::ErrorUnlessOk::new(&span);
    let answer = call_oneshot_blocking::<minimald_rpc::Shutdown>(
        uds_path,
        minimald_rpc::ShutdownRequest { force: true },
        connect_timeout,
        rpc_timeout,
        rpc_deadline,
    );
    if answer.is_ok() {
        failed.ok();
    }
    answer
}

async fn connect(uds_path: &Path) -> anyhow::Result<russh::client::Handle<AnyHostKey>> {
    let stream = tokio::net::UnixStream::connect(uds_path)
        .await
        .with_context(|| format!("connect to minimald at {}", uds_path.display()))?;

    let config = Arc::new(russh::client::Config::default());
    let mut handle = russh::client::connect_stream(config, stream, AnyHostKey)
        .await
        .context("ssh connect")?;

    let auth = handle
        .authenticate_none("minvmd")
        .await
        .context("authenticate")?;
    if !auth.success() {
        anyhow::bail!("authentication rejected by daemon");
    }
    Ok(handle)
}

async fn call_oneshot<R: OneshotSshRpc>(
    handle: &mut russh::client::Handle<AnyHostKey>,
    request: R::Request<'_>,
    traceparent: Option<&str>,
) -> anyhow::Result<R::Response> {
    let channel = handle
        .channel_open_session()
        .await
        .with_context(|| format!("open channel for {}", R::NAME))?;
    // The same `TRACEPARENT` channel env the CLI's RPCs carry, so the guest
    // daemon's `rpc` span is a child of this call's span. Best effort and
    // reply-less, as there: a daemon ignores env names it does not know.
    if let Some(tp) = traceparent {
        #[expect(
            clippy::let_underscore_must_use,
            reason = "best effort: a telemetry failure is a silent no-op (spec 25 principle 8)"
        )]
        let _ = channel
            .set_env(false, minimald_rpc::trace::TRACEPARENT_ENV, tp)
            .await;
    }
    channel
        .request_subsystem(false, R::NAME)
        .await
        .with_context(|| format!("request subsystem {}", R::NAME))?;

    let body = serde_json_lenient::to_vec(&request).context("serialize request")?;
    let mut rpc = channel.into_stream();
    rpc.write_all(&body).await.context("write request")?;
    rpc.shutdown().await.context("shutdown write half")?;

    // Bound the response. These are small JSON status objects, but the peer is
    // the in-VM daemon across the vsock bridge: an unbounded `read_to_end`
    // lets a wedged or hostile guest make the host buffer without limit.
    // `take` the cap plus one byte so hitting the cap is distinguishable from
    // a response that merely fills it. (Mirrors `MAX_REQUEST_BYTES` in
    // `minimald::diag`, which bounds the same shape of read in the other
    // direction.)
    let mut resp_buf = Vec::with_capacity(256);
    (&mut rpc)
        .take(MAX_RESPONSE_BYTES + 1)
        .read_to_end(&mut resp_buf)
        .await
        .context("read response")?;
    if resp_buf.len() as u64 > MAX_RESPONSE_BYTES {
        anyhow::bail!(
            "{} response too large: over {MAX_RESPONSE_BYTES} bytes",
            R::NAME
        );
    }

    serde_json_lenient::from_slice(&resp_buf)
        .with_context(|| format!("decode response for {}", R::NAME))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shutdown_guest_errors_fast_on_absent_socket() {
        let tmp = tempfile::tempdir().unwrap();
        let missing = tmp.path().join("no-such.sock");
        let started = std::time::Instant::now();
        let err = shutdown_guest(
            &missing,
            Duration::from_secs(5),
            Duration::from_secs(60),
            None,
        )
        .unwrap_err();
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "must fail on connect, not wait out the timeout"
        );
        assert!(
            err.to_string().contains("connect to minimald"),
            "got: {err:#}"
        );
    }

    /// `guest.shutdown` is open before the guest is dialed: the span is the
    /// host's and starts on entry, so the guest's `rpc` span for the
    /// Shutdown it carries starts after it. A guest `rpc` that a trace shows
    /// starting before its `guest.shutdown` parent does so on the guest's
    /// clock, which follows the host's only to within the timekeep step
    /// threshold (spec 25 TEL-034); it is not an ordering slip on this side.
    /// A clean stop that fails exports `guest.shutdown` with an error status
    /// (TEL-035): the span is not left Unset for a shutdown that did not happen.
    #[test]
    fn a_failed_guest_shutdown_marks_its_span_error() {
        use std::sync::{Arc, Mutex};
        use tracing_subscriber::layer::SubscriberExt as _;

        #[derive(Clone, Default)]
        struct Status(Arc<Mutex<Option<String>>>);
        struct Grab<'a>(&'a Mutex<Option<String>>);
        impl tracing::field::Visit for Grab<'_> {
            fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                if field.name() == "otel.status_code" {
                    *self.0.lock().unwrap() = Some(value.to_owned());
                }
            }
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                if field.name() == "otel.status_code" {
                    *self.0.lock().unwrap() =
                        Some(format!("{value:?}").trim_matches('"').to_owned());
                }
            }
        }
        impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Status {
            fn on_record(
                &self,
                _id: &tracing::span::Id,
                values: &tracing::span::Record<'_>,
                _ctx: tracing_subscriber::layer::Context<'_, S>,
            ) {
                values.record(&mut Grab(&self.0));
            }
        }

        let status = Status::default();
        let _guard =
            tracing::subscriber::set_default(tracing_subscriber::registry().with(status.clone()));
        let missing =
            std::env::temp_dir().join(format!("minvmd-no-such-{}.sock", std::process::id()));
        shutdown_guest(
            &missing,
            Duration::from_millis(200),
            Duration::from_millis(200),
            None,
        )
        .unwrap_err();
        assert_eq!(status.0.lock().unwrap().as_deref(), Some("ERROR"));
    }

    #[test]
    fn guest_shutdown_opens_before_the_guest_is_dialed() {
        use std::sync::{Arc, Mutex};
        use std::time::Instant;
        use tracing_subscriber::layer::SubscriberExt as _;

        /// The instant the first `guest.shutdown` span was opened.
        #[derive(Clone, Default)]
        struct Opened(Arc<Mutex<Option<Instant>>>);

        impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Opened {
            fn on_new_span(
                &self,
                attrs: &tracing::span::Attributes<'_>,
                _id: &tracing::span::Id,
                _ctx: tracing_subscriber::layer::Context<'_, S>,
            ) {
                if attrs.metadata().name() == "guest.shutdown" {
                    self.0.lock().unwrap().get_or_insert_with(Instant::now);
                }
            }
        }

        let opened = Opened::default();
        let _guard =
            tracing::subscriber::set_default(tracing_subscriber::registry().with(opened.clone()));
        let tmp = tempfile::tempdir().unwrap();
        let sock = tmp.path().join("guest.sock");
        let listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();
        // The stand-in guest notes when it is dialed and hangs up, so the
        // call fails at the handshake.
        let dialed = std::thread::spawn(move || {
            let (_conn, _) = listener.accept().unwrap();
            Instant::now()
        });
        let _failed = shutdown_guest(&sock, Duration::from_secs(5), Duration::from_secs(5), None)
            .unwrap_err();
        let dialed = dialed.join().unwrap();
        let opened = opened.0.lock().unwrap().expect("guest.shutdown was opened");
        assert!(
            opened < dialed,
            "guest.shutdown must open before the guest is dialed"
        );
    }

    /// A socket that accepts but never speaks SSH (a wedged guest behind
    /// libkrun's always-accepting bridge) must fail within the connect
    /// deadline, not the (much longer) RPC deadline.
    #[test]
    fn shutdown_guest_fails_within_connect_deadline_on_mute_listener() {
        let tmp = tempfile::tempdir().unwrap();
        let sock = tmp.path().join("mute.sock");
        let _listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();

        let started = std::time::Instant::now();
        let err = shutdown_guest(
            &sock,
            Duration::from_millis(300),
            Duration::from_secs(60),
            None,
        )
        .unwrap_err();
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "must give up at the connect deadline, not the RPC deadline"
        );
        assert!(err.to_string().contains("no live minimald"), "got: {err:#}");
    }

    /// A guest that answers the handshake at once but is still draining
    /// when the deadline comes: the RPC must run until `rpc_deadline`, not
    /// stop at whatever `rpc_timeout` a caller split from the same budget.
    #[test]
    fn shutdown_guest_rpc_runs_to_its_deadline_after_a_fast_connect() {
        let tmp = tempfile::tempdir().unwrap();
        let sock = tmp.path().join("stalling.sock");
        test_support::spawn_stalling_guest(&sock);

        let started = Instant::now();
        let deadline = started + Duration::from_secs(3);
        let err = shutdown_guest(
            &sock,
            Duration::from_millis(1500),
            Duration::from_secs(60),
            Some(deadline),
        )
        .unwrap_err();
        assert!(err.to_string().contains("timed out"), "got: {err:#}");
        assert!(
            Instant::now() >= deadline,
            "the RPC gave up {:?} before its deadline",
            deadline.saturating_duration_since(Instant::now())
        );
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "the RPC overran its deadline: {:?}",
            started.elapsed()
        );
    }
}

/// Test doubles for the in-VM daemon's side of the bridge UDS.
#[cfg(test)]
pub(crate) mod test_support {
    use std::path::Path;
    use std::sync::Arc;

    use russh::keys::{Algorithm, PrivateKey, key::safe_rng};

    /// A guest daemon that completes the SSH handshake and accepts the
    /// RPC's channel and subsystem, then never answers: a live guest still
    /// draining its sessions.
    struct StallingGuest;

    impl russh::server::Handler for StallingGuest {
        type Error = russh::Error;

        async fn auth_none(&mut self, _user: &str) -> Result<russh::server::Auth, Self::Error> {
            Ok(russh::server::Auth::Accept)
        }

        async fn channel_open_session(
            &mut self,
            _channel: russh::Channel<russh::server::Msg>,
            reply: russh::server::ChannelOpenHandle,
            _session: &mut russh::server::Session,
        ) -> Result<(), Self::Error> {
            reply.accept().await;
            Ok(())
        }

        async fn subsystem_request(
            &mut self,
            channel: russh::ChannelId,
            _name: &str,
            session: &mut russh::server::Session,
        ) -> Result<(), Self::Error> {
            session.channel_success(channel)
        }
    }

    /// Serve a [`StallingGuest`] on a UDS bound at `sock`, on a thread
    /// that lives as long as the test process.
    pub(crate) fn spawn_stalling_guest(sock: &Path) {
        let listener = std::os::unix::net::UnixListener::bind(sock).expect("bind guest socket");
        listener
            .set_nonblocking(true)
            .expect("nonblocking listener");
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("guest runtime");
            rt.block_on(async move {
                let listener =
                    tokio::net::UnixListener::from_std(listener).expect("tokio listener");
                let key =
                    PrivateKey::random(&mut safe_rng(), Algorithm::Ed25519).expect("host key");
                let config = Arc::new(russh::server::Config {
                    keys: vec![key],
                    ..Default::default()
                });
                while let Ok((stream, _)) = listener.accept().await {
                    let config = config.clone();
                    tokio::spawn(async move {
                        if let Ok(session) =
                            russh::server::run_stream(config, stream, StallingGuest).await
                        {
                            // The session ends when the client hangs up;
                            // how it ended does not matter to the test.
                            drop(session.await);
                        }
                    });
                }
            });
        });
    }
}
