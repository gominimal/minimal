use super::*;

/// Bidirectionally pipe stdio to a daemon UDS socket.
///
/// Intended for use as an SSH `ProxyCommand`: ssh writes to our stdin and
/// reads from our stdout, while we bridge both directions to the UDS.
pub async fn cmd_proxy(global: &GlobalArgs, args: ProxyArgs) -> Result<(), anyhow::Error> {
    let socket_path = match args.socket {
        Some(socket_path) => socket_path,
        None => {
            ensure_daemon(global)?;
            client::resolve_socket_path(global.minimal_dir.as_deref(), global.use_minvmd())
                .context("Failed to resolve daemon socket path")?
                .to_str()
                .unwrap()
                .to_string()
        }
    };

    let stream = connect_with_retry(&socket_path).await?;

    proxy_bridge(stream, tokio::io::stdin(), tokio::io::stdout()).await
}

/// Connect to the daemon UDS, retrying a bounded number of times when the
/// connect is refused.
///
/// A burst of concurrent connects to the daemon socket can overflow the
/// daemon's accept backlog, so a single refused connect must not fail the
/// proxy outright. A full backlog surfaces as `ConnectionRefused` on macOS
/// and as `WouldBlock` (`EAGAIN` from the non-blocking connect) on Linux, so
/// both are retried. A `NotFound` (no socket file) fails immediately: it
/// usually means the daemon is not running, but it also covers the short
/// unlink-then-bind window of a daemon re-binding its socket, which this
/// helper does not retry.
async fn connect_with_retry(socket_path: &str) -> Result<tokio::net::UnixStream, anyhow::Error> {
    let mut last_err = None;
    for _ in 0..client::CONNECT_RETRIES {
        match tokio::net::UnixStream::connect(socket_path).await {
            Ok(stream) => return Ok(stream),
            Err(err)
                if matches!(
                    err.kind(),
                    std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::WouldBlock
                ) =>
            {
                last_err = Some(err);
                tokio::time::sleep(client::CONNECT_RETRY_DELAY).await;
            }
            Err(err) => {
                return Err(err).with_context(|| format!("connect to {}", socket_path));
            }
        }
    }
    Err(last_err.expect("CONNECT_RETRIES > 0, so at least one attempt ran and failed"))
        .with_context(|| format!("connect to {}", socket_path))
}

/// Bridge proxy stdio to the daemon socket until either side closes.
///
/// The socket half (`from_sock`) reaching EOF means the daemon has torn the
/// socket down; returning then — instead of waiting on stdin, which the
/// driving `ssh` holds open indefinitely — is what keeps the proxy from
/// lingering against a dead socket. When stdin closes first, its write half
/// is shut down and any remaining daemon output is drained before exit.
pub(crate) async fn proxy_bridge<I, O>(
    stream: tokio::net::UnixStream,
    mut stdin: I,
    mut stdout: O,
) -> Result<(), anyhow::Error>
where
    I: tokio::io::AsyncRead + Unpin,
    O: tokio::io::AsyncWrite + Unpin,
{
    let (mut rx, mut tx) = stream.into_split();

    let to_sock = async {
        match tokio::io::copy(&mut stdin, &mut tx).await {
            // The daemon closed its end, so there is no write half left to
            // shut down: macOS fails that shutdown with ENOTCONN.
            Err(err) if err.kind() == std::io::ErrorKind::BrokenPipe => {
                tracing::debug!(error = %err, "stdin→daemon copy ended: daemon stopped reading");
                Ok(())
            }
            res => {
                res?;
                tx.shutdown().await
            }
        }
    };
    let from_sock = async { ignore_broken_pipe(tokio::io::copy(&mut rx, &mut stdout).await) };
    tokio::pin!(from_sock);

    tokio::select! {
        res = &mut from_sock => {
            res.context("proxy")?;
        }
        res = to_sock => {
            res.context("proxy")?;
            from_sock.await.context("proxy")?;
        }
    }
    Ok(())
}

/// Treat a `BrokenPipe` from the socket-to-stdout copy as normal termination.
///
/// The reader on the downstream side may close the pipe before the copy
/// finishes (for example `yes | ssh host 'cmd'`, where `cmd` never reads
/// stdin): the peer tears the stream down and `tokio::io::copy` reports
/// `BrokenPipe`. That is not a proxy failure, so it is mapped to a
/// successful zero-byte copy instead of surfacing `error: proxy: Broken
/// pipe (os error 32)`.
fn ignore_broken_pipe(result: std::io::Result<u64>) -> std::io::Result<u64> {
    match result {
        Err(err) if err.kind() == std::io::ErrorKind::BrokenPipe => {
            tracing::debug!(error = %err, "daemon→stdout copy ended: downstream reader closed");
            Ok(0)
        }
        other => other,
    }
}

/// The local mesh-enrolment record path. `--minimal-dir` still wins for
/// the historical "everything lives under the state dir" workflow;
/// otherwise falls through to the loadout-subsystem's config dir
/// so `--config-dir` moves the mesh enrolment along with everything
/// else.
///
/// Not gated behind `remote-access`: it is a pure path helper the `min bug`
/// diagnostic bundle captures regardless of whether the mesh commands are
/// compiled in.
pub fn mesh_enrolment_path(global: &GlobalArgs) -> PathBuf {
    let base = match &global.minimal_dir {
        Some(dir) => dir.clone(),
        None => config::resolve_minimal_config_dir(global),
    };
    base.join("mesh-enrolment")
}

/// Show this minimald's WireGuard mesh status (R4.6): own public key, the
/// switch subnets it advertises, and each peer's last handshake.
#[cfg(feature = "remote-access")]
pub async fn cmd_mesh_status(global: &GlobalArgs) -> Result<(), anyhow::Error> {
    ensure_daemon(global)?;

    let mut client = connect_daemon(global).await?;

    use minimald_rpc::GetMeshStatus;
    let resp = client
        .oneshot_rpc::<GetMeshStatus>(())
        .await
        .context("GetMeshStatus RPC failed")?;

    if !resp.configured {
        println!("No WireGuard mesh is configured on this minimald.");
        return Ok(());
    }

    println!(
        "public key:  {}",
        resp.own_public_key.as_deref().unwrap_or("-")
    );
    if resp.advertised_subnets.is_empty() {
        println!("advertised:  (none)");
    } else {
        println!("advertised:  {}", resp.advertised_subnets.join(", "));
    }

    if resp.peers.is_empty() {
        println!("peers:       (none)");
        return Ok(());
    }

    println!("peers:");
    println!("  {:<20}  {:<46}  LAST HANDSHAKE", "NAME", "PUBLIC KEY");
    for p in &resp.peers {
        let handshake = match p.last_handshake_secs {
            Some(secs) => format!("{secs}s ago"),
            None => "never".to_string(),
        };
        println!("  {:<20}  {:<46}  {handshake}", p.name, p.public_key);
    }

    Ok(())
}

/// Record this machine's enrolment into a remote minimald's mesh (R4.3, v1
/// manual key exchange) and print the steps to complete the key swap.
#[cfg(feature = "remote-access")]
pub fn cmd_mesh_join(global: &GlobalArgs, args: MeshJoinArgs) -> Result<(), anyhow::Error> {
    // Validate the endpoint at the point of entry so a typo never lands a bad
    // enrolment on disk for a later consumer to choke on. The CLI contract is
    // `host:port`; require a non-empty host and a parseable u16 port.
    let Some((host, port)) = args.address.rsplit_once(':') else {
        bail!("mesh join address must be host:port, e.g. mesh.example.com:51820")
    };
    if host.is_empty() || port.parse::<u16>().map(|p| p == 0).unwrap_or(true) {
        bail!("mesh join address must include a non-empty host and a valid non-zero port");
    }

    let path = mesh_enrolment_path(global);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    std::fs::write(&path, format!("{}\n", args.address))
        .with_context(|| format!("writing {}", path.display()))?;

    println!(
        "Recorded mesh enrolment for {} at {}.",
        args.address,
        path.display()
    );
    println!();
    println!("v1 uses manual key exchange. To complete the join:");
    println!("  1. Run `min mesh status` on the remote host to read its public key.");
    println!("  2. Add this machine's WireGuard public key to the remote minimald's peers.");
    println!("  3. Add the remote's public key and endpoint to this machine's mesh config.");
    Ok(())
}

/// Drop this machine's local mesh enrolment (R4.3). Remote peer entries are
/// removed on the remote host (manual v1).
#[cfg(feature = "remote-access")]
pub fn cmd_mesh_leave(global: &GlobalArgs) -> Result<(), anyhow::Error> {
    let path = mesh_enrolment_path(global);
    match std::fs::remove_file(&path) {
        Ok(()) => {
            println!(
                "Left the mesh; removed local enrolment at {}.",
                path.display()
            );
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            println!("No local mesh enrolment to remove.");
            Ok(())
        }
        Err(e) => Err(e).with_context(|| format!("removing {}", path.display())),
    }
}

/// Print that there is nothing to mint.
///
/// `min login` once called the daemon's certificate-issuing RPC and wrote
/// the key and CA to the config directory; that surface is retired, so the
/// verb now writes nothing and asks the daemon for nothing — it does not
/// spawn one. It stays as the home of the sign-in that replaces it.
///
/// The notice goes to the caller's writer rather than to stdout directly,
/// so the test can capture it and hold the verb to what it actually emits.
pub async fn cmd_login<W: std::io::Write>(
    _global: &GlobalArgs,
    _args: LoginArgs,
    out: &mut W,
) -> Result<(), anyhow::Error> {
    writeln!(out, "{}", login_nothing_to_mint_line()).context("writing the login notice")?;
    Ok(())
}

/// The one line `min login` prints. A person who runs the verb out of habit
/// is owed the reason it is now a no-op, not a silent exit.
pub(crate) fn login_nothing_to_mint_line() -> &'static str {
    "Nothing to mint: the HTTPS reverse proxy is retired, so no client certificate is issued and no key is written."
}

// ---------------------------------------------------------------------------
// Build-system commands (local, no daemon).
//
// These mirror the legacy `minimal` binary's `init`, `add`, and `update`
// subcommands. They operate directly against the local package graph,
// VCS checkouts, and `minimal.toml` — they do not go through minimald.
// -----------------------------------------------------------------------

/// Draw the client's activity spinner on stderr for `args.seconds`
/// (or until Ctrl-C), then clear it. Ticks the byte counter as it
/// runs so the `{bytes}` / `{bytes_per_sec}` placeholders in the
/// spinner template look alive instead of stuck at zero — makes it
/// easier to eyeball the animation next to realistic template
/// content.
pub async fn cmd_spin(_global: &GlobalArgs, args: SpinArgs) -> Result<(), anyhow::Error> {
    use std::time::Duration;
    let bar = client::add_spinner_bar("Spinner demo");
    let deadline = tokio::time::sleep(Duration::from_secs(args.seconds));
    tokio::pin!(deadline);
    // ~80 KB/s of fake throughput. Below indicatif's rate-average
    // window smoothing so the reported `{bytes_per_sec}` stays
    // legible instead of dancing every tick.
    let mut fake_throughput = tokio::time::interval(Duration::from_millis(50));
    // Registered once, outside the loop, for the same reason as `net forward`:
    // a fresh `ctrl_c()` per iteration can drop a SIGINT between arms.
    let ctrl_c = tokio::signal::ctrl_c();
    tokio::pin!(ctrl_c);
    loop {
        tokio::select! {
            _ = &mut ctrl_c => break,
            _ = &mut deadline => break,
            _ = fake_throughput.tick() => bar.inc(4096),
        }
    }
    bar.finish_and_clear();
    Ok(())
}

/// Print CLI and daemon version information.
///
/// Always shows the CLI version. If the daemon is reachable, also shows
/// the daemon version and stdlib version. Unlike other commands, this does
/// not autospawn the daemon — it is a lightweight diagnostic that should
/// report versions without starting a VM.
///
/// The output goes to the caller's writer rather than to stdout directly,
/// so a reader that has gone away (e.g. `min version | head -1`) surfaces
/// as a broken-pipe error instead of a `println!` panic.
pub async fn cmd_version<W: std::io::Write>(
    global: &GlobalArgs,
    out: &mut W,
) -> Result<(), anyhow::Error> {
    writeln!(out, "Client: minimal {}", version::LONG_VERSION)?;

    let sock = match client::resolve_socket_path(global.minimal_dir.as_deref(), global.use_minvmd())
    {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Server: (daemon unreachable: {e})");
            return Ok(());
        }
    };

    // Deliberately not version-gated: reporting the two versions is how an
    // operator sees a skew at all, so this must answer on a skewed pair rather
    // than refuse — and the gate's own check is this very RPC.
    let mut client = match client::Client::connect(&sock).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Server: (daemon unreachable: {e})");
            return Ok(());
        }
    };

    use minimald_rpc::GetVersion;
    let resp = match client.oneshot_rpc::<GetVersion>(()).await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Server: (daemon unreachable: {e})");
            return Ok(());
        }
    };

    writeln!(out, "Server: minimald {}", resp.long_version)?;
    writeln!(out, "Stdlib: {}", resp.stdlib_version)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A refused connect is retried: a listener that comes up after the first
    /// attempt is still reached, so a burst of concurrent proxies that
    /// overflows the daemon's accept backlog does not fail spuriously.
    #[tokio::test]
    async fn connect_with_retry_reaches_a_late_listener() {
        let dir = tempfile::tempdir().expect("a temp dir for the socket");
        let sock = dir.path().join("daemon.sock");
        let sock_path = sock.to_str().unwrap().to_string();

        // A stale socket file: the listener died and left its path behind, so
        // connects are refused until a new listener takes the path.
        let stale = std::os::unix::net::UnixListener::bind(&sock).expect("stale bind");
        drop(stale);

        // A listener comes up after the first refused attempt, exercising the
        // retry path.
        let bind_sock = sock.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(150)).await;
            std::fs::remove_file(&bind_sock).expect("remove the stale socket");
            let _listener = tokio::net::UnixListener::bind(&bind_sock).expect("late bind");
            // Hold the listener open until the connect lands.
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        });

        let stream = connect_with_retry(&sock_path)
            .await
            .expect("a late-bound listener must be reached by retry");
        drop(stream);
    }

    /// A missing socket path fails immediately: `NotFound` is not retried, so
    /// a proxy against a daemon that is not running does not hang for the
    /// full retry window.
    #[tokio::test]
    async fn connect_with_retry_fails_fast_on_missing_socket() {
        let dir = tempfile::tempdir().expect("a temp dir for the socket");
        let sock_path = dir.path().join("no-daemon.sock");
        let sock_path = sock_path.to_str().unwrap().to_string();

        let started = std::time::Instant::now();
        let err = connect_with_retry(&sock_path)
            .await
            .expect_err("a missing socket must fail");
        let elapsed = started.elapsed();

        assert!(
            err.to_string().contains(&sock_path),
            "the error must name the socket path: {err}"
        );
        assert!(
            elapsed < std::time::Duration::from_secs(1),
            "a missing socket must not be retried ({elapsed:?})"
        );
    }

    /// A would-block connect is retried: on Linux a full accept backlog makes
    /// the non-blocking connect fail with `EAGAIN` (`WouldBlock`), and a
    /// listener that drains its backlog after the first attempt is still
    /// reached.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn connect_with_retry_retries_a_would_block_on_a_full_backlog() {
        let dir = tempfile::tempdir().expect("a temp dir for the socket");
        let sock = dir.path().join("daemon.sock");
        let sock_path = sock.to_str().unwrap().to_string();

        let listener = std::os::unix::net::UnixListener::bind(&sock).expect("bind");
        // Shrink the accept backlog so a couple of connects fill it.
        nix::sys::socket::listen(
            &listener,
            nix::sys::socket::Backlog::new(0).expect("a zero backlog"),
        )
        .expect("shrink the backlog");

        // Fill the backlog until a connect would block.
        let mut held = Vec::new();
        loop {
            match tokio::net::UnixStream::connect(&sock).await {
                Ok(stream) => {
                    held.push(stream);
                    assert!(held.len() < 64, "the backlog never filled");
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(err) => panic!("unexpected connect error filling the backlog: {err}"),
            }
        }

        // Drain the backlog after the first retried attempt, then accept the
        // retried connect too.
        let pending = held.len() + 1;
        let acceptor = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(150));
            (0..pending)
                .map(|_| listener.accept().expect("accept").0)
                .collect::<Vec<_>>()
        });

        let stream = connect_with_retry(&sock_path)
            .await
            .expect("a would-block connect must be reached by retry");
        drop(stream);
        drop(held);
        acceptor.join().expect("the acceptor thread");
    }

    /// A downstream writer that fails every write with the given error kind.
    struct FailingWriter(std::io::ErrorKind);

    impl tokio::io::AsyncWrite for FailingWriter {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            _buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            std::task::Poll::Ready(Err(std::io::Error::from(self.0)))
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    /// Write a couple of bytes down the daemon side and then shut it down, so
    /// the bridge's socket-to-stdout copy has something to deliver.
    fn writing_daemon(mut stream: tokio::net::UnixStream) {
        tokio::spawn(async move {
            stream
                .write_all(b"hello")
                .await
                .expect("daemon writes its greeting");
            stream.shutdown().await.expect("daemon shuts down");
        });
    }

    /// A minimal DEBUG-and-up subscriber for the tests that assert on the
    /// bridge's swallowed-pipe lines. `enabled` filters to DEBUG so only the
    /// lines under test reach the log, and `event` records each line's
    /// message.
    #[derive(Clone, Default)]
    struct DebugLog(std::sync::Arc<std::sync::Mutex<Vec<String>>>);

    /// Records an event's `message` field — the swallowed-pipe line's text.
    struct MessageField<'a>(&'a mut String);

    impl tracing::field::Visit for MessageField<'_> {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            if field.name() == "message" {
                use std::fmt::Write as _;
                let _ = write!(self.0, "{value:?}");
            }
        }
    }

    impl DebugLog {
        /// The lines said so far, in order.
        fn lines(&self) -> Vec<String> {
            self.0.lock().expect("the test owns the log").clone()
        }
    }

    impl tracing::Subscriber for DebugLog {
        fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
            *metadata.level() <= tracing::Level::DEBUG
        }

        fn event(&self, event: &tracing::Event<'_>) {
            let mut line = String::new();
            event.record(&mut MessageField(&mut line));
            self.0.lock().expect("the test owns the log").push(line);
        }

        // The bridge emits no span, so the span half of the trait is inert: a
        // single id that nothing records into and nothing enters.
        fn new_span(&self, _span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }

        fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}

        fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}

        fn enter(&self, _span: &tracing::span::Id) {}

        fn exit(&self, _span: &tracing::span::Id) {}
    }

    /// Capture every DEBUG line the current thread emits while the guard
    /// lives. The current-thread test runtime drives the bridge on the test's
    /// own thread, so the thread-local default subscriber sees its lines.
    fn capture_debug_lines() -> (DebugLog, tracing::subscriber::DefaultGuard) {
        let log = DebugLog::default();
        let guard = tracing::subscriber::set_default(log.clone());
        (log, guard)
    }

    /// When the downstream reader closes early (BrokenPipe), the bridge treats
    /// it as normal termination rather than surfacing `error: proxy: Broken
    /// pipe (os error 32)`. The swallow is still visible as a DEBUG line
    /// naming the side whose pipe broke.
    #[tokio::test]
    async fn proxy_bridge_exits_quietly_on_broken_pipe() {
        let (bridge, daemon) = tokio::net::UnixStream::pair().expect("socket pair");
        writing_daemon(daemon);
        let stdout = FailingWriter(std::io::ErrorKind::BrokenPipe);

        let (log, _guard) = capture_debug_lines();
        proxy_bridge(bridge, &[][..], stdout)
            .await
            .expect("a broken pipe downstream is not a proxy failure");
        assert!(
            log.lines()
                .iter()
                .any(|line| line.contains("daemon→stdout")),
            "the swallowed pipe must be logged naming its side, got {:?}",
            log.lines()
        );
    }

    /// Any error other than BrokenPipe is still surfaced with the `proxy`
    /// context intact.
    #[tokio::test]
    async fn proxy_bridge_reports_non_broken_pipe_errors() {
        let (bridge, daemon) = tokio::net::UnixStream::pair().expect("socket pair");
        writing_daemon(daemon);
        let stdout = FailingWriter(std::io::ErrorKind::Other);

        let err = proxy_bridge(bridge, &[][..], stdout)
            .await
            .expect_err("a non-broken-pipe write failure must surface");
        assert!(
            format!("{err:#}").contains("proxy"),
            "the error must carry the proxy context: {err:#}"
        );
    }

    /// When the daemon stops reading first, the stdin-to-socket copy hits
    /// `BrokenPipe`. The bridge treats that as normal termination — logged as
    /// a DEBUG line naming the stdin→daemon side — and still drains the
    /// daemon's remaining output to stdout instead of failing or truncating
    /// it. Linux only: there a write to a peer that shut down its read side
    /// fails with `EPIPE` at once.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn proxy_bridge_drains_daemon_output_after_stdin_broken_pipe() {
        let (bridge, daemon) = std::os::unix::net::UnixStream::pair().expect("socket pair");
        daemon
            .shutdown(std::net::Shutdown::Read)
            .expect("daemon stops reading");
        for s in [&bridge, &daemon] {
            s.set_nonblocking(true).expect("non-blocking");
        }
        let bridge = tokio::net::UnixStream::from_std(bridge).expect("bridge stream");
        let mut daemon = tokio::net::UnixStream::from_std(daemon).expect("daemon stream");

        // Hold the daemon's write side open until well after the bridge's
        // first write has failed, so the socket-to-stdout copy cannot finish
        // first and the BrokenPipe arm is the one that runs.
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            daemon
                .write_all(b"hello")
                .await
                .expect("daemon writes its reply");
        });

        let mut stdout = Vec::new();
        let (log, _guard) = capture_debug_lines();
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            proxy_bridge(bridge, tokio::io::repeat(b'x'), &mut stdout),
        )
        .await
        .expect("the bridge must not hang after a broken pipe")
        .expect("a broken pipe towards the daemon is not a proxy failure");
        assert_eq!(stdout, b"hello", "the daemon's output must be drained");
        assert!(
            log.lines().iter().any(|line| line.contains("stdin→daemon")),
            "the swallowed pipe must be logged naming its side, got {:?}",
            log.lines()
        );
    }
}
