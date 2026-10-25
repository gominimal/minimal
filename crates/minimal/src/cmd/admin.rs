use super::*;

/// Bidirectionally pipe stdio to a daemon UDS socket.
///
/// Intended for use as an SSH `ProxyCommand`: ssh writes to our stdin and
/// reads from our stdout, while we bridge both directions to the UDS.
/// Without an explicit socket path, ensures the selected daemon is running
/// and resolves its socket. An owner PID or lock enables the lifetime watch
/// described by [`owner_gone`]; detecting owner loss closes the socket and
/// returns successfully.
///
/// # Errors
///
/// Propagates daemon startup, socket resolution, connection, and bridge I/O
/// errors. Broken-pipe errors during copying are treated as normal termination.
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

    proxy_while_owner_lives(
        stream,
        tokio::io::stdin(),
        tokio::io::stdout(),
        args.owner,
        args.owner_lock,
    )
    .await
}

/// Bridges stdio to the daemon, watching for owner loss when `owner` or
/// `lock` is supplied (see [`owner_gone`]). With neither, waits only for
/// [`proxy_bridge`], which drains daemon output after stdin closes.
/// Detecting owner loss cancels the bridge and returns `Ok(())`, closing
/// the daemon socket without waiting for pending output.
///
/// # Errors
///
/// Propagates bridge copy and socket shutdown errors if the bridge finishes
/// first; broken-pipe copy errors are treated as normal termination.
async fn proxy_while_owner_lives<I, O>(
    stream: tokio::net::UnixStream,
    stdin: I,
    stdout: O,
    owner: Option<u32>,
    lock: Option<PathBuf>,
) -> Result<(), anyhow::Error>
where
    I: tokio::io::AsyncRead + Unpin,
    O: tokio::io::AsyncWrite + Unpin,
{
    let bridge = proxy_bridge(stream, stdin, stdout);
    match (owner, lock) {
        (None, None) => bridge.await,
        (owner, lock) => tokio::select! {
            res = bridge => res,
            () = owner_gone(owner, lock) => {
                tracing::debug!(?owner, "the proxy's owner is gone; closing the daemon connection");
                Ok(())
            }
        },
    }
}

/// How often the proxy looks for its owner.
const OWNER_POLL: std::time::Duration = std::time::Duration::from_millis(250);

/// Resolves once the `min` process this proxy serves is gone.
///
/// ssh is that process's child and this proxy is ssh's. A `min session exec`
/// that dies without a chance to take ssh down (SIGKILL, an OOM kill; the
/// catchable signals are handled in the exec path) leaves both running with
/// the daemon's socket open, and the daemon, which learns of a lost client
/// only from its connection closing, keeps the command running — a silent
/// `sleep` outlived its killed client indefinitely (lab scenario 732).
/// Polled, since the owner is a grandparent this process cannot wait on.
///
/// The lock is the watch: the owner holds an exclusive `flock` on `lock`
/// for its life, and the kernel releases it when the process's descriptors
/// close at exit — before any reaping, so a SIGKILLed owner its parent has
/// not waited on reads as gone too. The path is unique to that one process
/// (pid and start time), so a recycled pid names a different file. The pid
/// is the fallback where no lock was handed (an older `min`): gone when
/// `kill(pid, 0)` finds nothing or, on Linux, when the process is a zombie
/// (`EPERM` is alive). A pid that does not fit a `pid_t` names no process
/// and reads as gone.
///
/// Checks immediately, then every 250 ms. When `lock` is supplied, ignores
/// the PID and resolves if the file cannot be opened for any reason or its
/// lock can be acquired; lock-acquisition errors keep the watch running.
/// With no lock and no usable PID, resolves immediately. Filesystem and
/// process-probe errors are handled by the watch and do not reach callers.
async fn owner_gone(pid: Option<u32>, lock: Option<PathBuf>) {
    let pid = pid.and_then(|pid| i32::try_from(pid).ok().map(nix::unistd::Pid::from_raw));
    loop {
        if let Some(path) = &lock
            && owner_lock_is_free(path)
        {
            return;
        }
        if lock.is_none()
            && let Some(pid) = pid
            && pid_gone(pid)
        {
            return;
        }
        if lock.is_none() && pid.is_none() {
            // A pid that fit no `pid_t` and no lock: nothing to watch.
            return;
        }
        tokio::time::sleep(OWNER_POLL).await;
    }
}

/// Whether a pid no longer names a live process: nothing answers to it, or
/// (Linux) it is a zombie, exited and not yet reaped by its parent.
/// Signal-probe errors other than `ESRCH` do not establish process loss;
/// an unreadable or unrecognized Linux proc status is also inconclusive.
fn pid_gone(pid: nix::unistd::Pid) -> bool {
    if matches!(
        nix::sys::signal::kill(pid, None),
        Err(nix::errno::Errno::ESRCH)
    ) {
        return true;
    }
    #[cfg(target_os = "linux")]
    if let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) {
        // The state follows the parenthesised command name, which may itself
        // contain `)`: split on the last one.
        if let Some((_, rest)) = stat.rsplit_once(')')
            && rest.trim_start().starts_with('Z')
        {
            return true;
        }
    }
    false
}

/// Returns `true` if the owner's lock file is gone (the owner unlinked it on
/// its way out) or its exclusive `flock` can be acquired. Any other error,
/// opening the file (`EACCES`, `EMFILE`) or taking the lock, returns `false`:
/// a watch that cannot tell keeps watching, rather than ending a live attach
/// over a transient fault of its own.
///
/// On acquiring the lock, attempts to unlink its file while still holding
/// the lock, then releases it. An unlink failure does not change the result.
fn owner_lock_is_free(path: &std::path::Path) -> bool {
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return true,
        Err(err) => {
            tracing::debug!(error = %err, path = %path.display(), "the proxy's owner lock could not be opened; still watching");
            return false;
        }
    };
    match nix::fcntl::Flock::lock(file, nix::fcntl::FlockArg::LockExclusiveNonblock) {
        Ok(lock) => {
            let removed = std::fs::remove_file(path);
            drop(lock);
            tracing::debug!(?removed, path = %path.display(), "the proxy's owner lock was free");
            true
        }
        Err(_) => false,
    }
}

#[cfg(test)]
mod owner_watch_tests {
    use super::{owner_gone, proxy_while_owner_lives};
    use std::time::Duration;
    use tokio::io::AsyncReadExt as _;

    /// A SIGKILLed owner its parent has not reaped is a zombie, which
    /// `kill(pid, 0)` still answers for: the pid watch reads it as gone
    /// anyway. The child is reaped only after the assertion.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn a_zombie_owner_reads_as_gone() {
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("sleep spawns");
        let pid = child.id();
        child.kill().expect("sleep is killable");
        tokio::time::timeout(Duration::from_secs(2), owner_gone(Some(pid), None))
            .await
            .expect("an unreaped (zombie) owner should read as gone");
        child.wait().expect("sleep is reaped");
    }

    /// The path the fix relies on end to end: while the owner holds its
    /// lock the proxy bridges, and once the lock is released the proxy
    /// returns and the daemon side of the socket reads EOF.
    #[tokio::test]
    async fn the_daemon_reads_eof_once_the_owner_is_gone() {
        let dir = tempfile::tempdir().expect("a temp dir");
        let path = dir.path().join("proxy-owner-eof.lock");
        let file = std::fs::File::create(&path).expect("the lock file is created");
        let held = nix::fcntl::Flock::lock(file, nix::fcntl::FlockArg::LockExclusiveNonblock)
            .unwrap_or_else(|(_, errno)| panic!("taking the lock: {errno}"));
        let (proxy_side, mut daemon_side) = tokio::net::UnixStream::pair().expect("a socket pair");
        // stdin that stays open (ssh holds it open for the proxy's life)
        let (_stdin_writer, stdin) = tokio::io::duplex(64);
        let proxy = tokio::spawn(proxy_while_owner_lives(
            proxy_side,
            stdin,
            tokio::io::sink(),
            None,
            Some(path.clone()),
        ));
        tokio::time::sleep(Duration::from_millis(600)).await;
        assert!(
            !proxy.is_finished(),
            "the proxy ended while its owner lived"
        );
        drop(held);
        tokio::time::timeout(Duration::from_secs(2), proxy)
            .await
            .expect("the proxy did not end after its owner was gone")
            .expect("the proxy task should not panic")
            .expect("the proxy should end cleanly");
        let mut buf = [0u8; 8];
        let n = tokio::time::timeout(Duration::from_secs(2), daemon_side.read(&mut buf))
            .await
            .expect("the daemon side should see the close")
            .expect("reading the daemon side");
        assert_eq!(n, 0, "the daemon side should read EOF");
    }

    /// The pid fallback holds while the owner lives and resolves once it is
    /// gone.
    #[tokio::test]
    async fn the_watch_resolves_when_the_owner_dies() {
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("sleep spawns");
        let pid = child.id();
        assert!(
            tokio::time::timeout(Duration::from_millis(600), owner_gone(Some(pid), None))
                .await
                .is_err(),
            "the watch resolved while the owner was alive"
        );
        child.kill().expect("sleep is killable");
        child.wait().expect("sleep is reaped");
        tokio::time::timeout(Duration::from_secs(2), owner_gone(Some(pid), None))
            .await
            .expect("the watch did not resolve after the owner died");
    }

    /// The lock watch holds while the owner holds its lock and resolves
    /// once the lock is released — what the kernel does for a process that
    /// ends any way at all, SIGKILL included. The pid handed beside it is a
    /// live one (this process), so only the lock can end the watch.
    #[tokio::test]
    async fn the_watch_resolves_when_the_owner_lock_is_released() {
        let dir = tempfile::tempdir().expect("a temp dir");
        let path = dir.path().join("proxy-owner-test.lock");
        let file = std::fs::File::create(&path).expect("the lock file is created");
        let held = nix::fcntl::Flock::lock(file, nix::fcntl::FlockArg::LockExclusiveNonblock)
            .unwrap_or_else(|(_, errno)| panic!("taking the lock: {errno}"));
        let me = std::process::id();
        assert!(
            tokio::time::timeout(
                Duration::from_millis(600),
                owner_gone(Some(me), Some(path.clone()))
            )
            .await
            .is_err(),
            "the watch resolved while the lock was held"
        );
        drop(held);
        tokio::time::timeout(
            Duration::from_secs(2),
            owner_gone(Some(me), Some(path.clone())),
        )
        .await
        .expect("the watch did not resolve after the lock was released");
        assert!(!path.exists(), "the freed lock file is removed");
    }
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
#[cfg(debug_assertions)]
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

    /// A shared buffer the DEBUG capture subscriber renders into.
    #[derive(Clone, Default)]
    struct DebugLog(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for DebugLog {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0
                .lock()
                .expect("the test owns the log")
                .extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl DebugLog {
        /// Everything rendered so far.
        fn text(&self) -> String {
            String::from_utf8_lossy(&self.0.lock().expect("the test owns the log")).into_owned()
        }
    }

    /// Capture every DEBUG line the current thread emits while the guard
    /// lives. The current-thread test runtime drives the bridge on the test's
    /// own thread, so the thread-local default subscriber sees its lines; no
    /// global subscriber is installed.
    fn capture_debug_lines() -> (DebugLog, tracing::subscriber::DefaultGuard) {
        let log = DebugLog::default();
        let writer = log.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_writer(move || writer.clone())
            .with_ansi(false)
            .finish();
        let guard = tracing::subscriber::set_default(subscriber);
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
            log.text().contains("daemon→stdout"),
            "the swallowed pipe must be logged naming its side, got {:?}",
            log.text()
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
            log.text().contains("stdin→daemon"),
            "the swallowed pipe must be logged naming its side, got {:?}",
            log.text()
        );
    }
}
