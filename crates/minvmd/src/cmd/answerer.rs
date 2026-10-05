//! The `min-answerer` program: the one the privileged step copies to a
//! root-owned path and installs as the host's box-zone answerer service,
//! and the handover's client verbs the same step runs as root.
//!
//! The service manager runs it as the operator's uid, never root — the uid
//! its unit names — and hands it both of the answerer's sockets, held by the
//! manager the whole time: the listener at the hook port on the host loopback
//! and the channel socket node daemons publish their rows over. Socket
//! activation is how they arrive, launchd's on macOS and systemd's
//! `LISTEN_FDS` on Linux, and each socket is classified by what it *is* — a
//! datagram socket on an internet address is the listener, a stream socket on
//! a unix address is the channel — so the order a unit lists them in never
//! matters and a socket this service has no use for is closed, not served.
//!
//! Serving never ends from the inside: the stop flag handed to the serving
//! loops is never set, because the manager's stop of the service is the
//! process's — SIGTERM's default is the whole stop, and the rows a restart
//! holds nothing of are republished by the nodes unprompted
//! ([`crate::net::answerer`]).

use std::net::UdpSocket;
use std::os::fd::{AsFd, AsRawFd as _, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixListener;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use anyhow::{Context as _, Result, bail};

use crate::net::answerer;

/// The name of the answerer's listener socket as the service manager's unit
/// names it: the socket at the hook port on the host loopback. launchd
/// hands its sockets over by this name (`launch_activate_socket`), so the
/// CLI's privileged step must name the plist's entry exactly this — one
/// definition, so the question and the answer cannot drift apart. systemd
/// hands unnamed fds, and the socket is found by what it is.
pub const LISTENER_SOCKET_NAME: &str = "Listener";

/// The name of the answerer's channel socket as the service manager's unit
/// names it: the unix stream socket node daemons publish their rows over
/// (see [`LISTENER_SOCKET_NAME`]).
pub const CHANNEL_SOCKET_NAME: &str = "Channel";

/// The most sockets a unit hands one service: past this, `LISTEN_FDS` is not
/// a unit's — it is a hostile environment, and no service allocates for it.
#[cfg(any(test, not(target_os = "macos")))]
const HANDED_SOCKET_LIMIT: usize = 1024;

/// The answerer service, as the unit runs it.
///
/// `--protocol-version` never serves: it prints the channel protocol version
/// this copy speaks — the one fact the CLI's hook probe compares with the
/// daemon's own, re-surfacing the privileged step on a mismatch so an
/// upgrade re-runs it and the installed copy is never left speaking a wire
/// the daemon no longer understands.
///
/// Without it, this is the service: receive the manager's sockets, serve the
/// zone from them, for as long as the manager keeps the process running.
pub fn run(protocol_version: bool) -> Result<()> {
    if protocol_version {
        println!("{}", answerer::CHANNEL_PROTOCOL_VERSION);
        return Ok(());
    }
    let (listener, channel) = activated_sockets().context(
        "the answerer service starts only by socket activation, its two sockets \
         held by the service manager",
    )?;
    // The uid the channel's gate serves is the running uid — the operator,
    // the one the unit's User= names. The gate refuses every other uid
    // before a byte of its payload is read, so only this operator's own
    // daemons can publish rows to the machine's one answerer.
    //
    // SAFETY: geteuid only reads the process's own uid.
    let expected_uid = unsafe { libc::geteuid() };
    // The stop flag is never set: the manager's stop of the service is the
    // process's, and SIGTERM's default is the whole stop.
    answerer::serve_service(
        listener,
        channel,
        expected_uid,
        Arc::new(AtomicBool::new(false)),
    );
    Ok(())
}

/// How long the release verb waits for the hook port to be free once every
/// daemon it asked has answered: a released daemon frees the port before
/// it answers, so the wait only has to outlast a slow close — a port still
/// held past it is another process's, a collision.
const PORT_FREE_WAIT: std::time::Duration = std::time::Duration::from_secs(2);

/// How long the release verbs wait for one daemon's answer.
const CONTROL_REPLY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(12);

/// The handover's release verb (NET-122's privileged step, as root): asks
/// each VM host daemon whose control socket is in `controls` to release its
/// interim answerer, then waits up to [`PORT_FREE_WAIT`] for the hook port
/// to be free. A control socket that is absent or that nothing listens
/// behind is a daemon that is not running — skipped. A port still held
/// after the wait is a collision: another process holds the hook port (a
/// VM host daemon of another state dir included), and the error names it.
///
/// # Errors
///
/// When a daemon refuses the request, or the port is still held.
pub fn release(controls: &[std::path::PathBuf], port: u16) -> Result<()> {
    for control in controls {
        if let Some(reply) = ask(control, &minimald_rpc::BoxControlRequest::ReleaseAnswerer)? {
            eprintln!("min-answerer: {}: {reply}", control.display());
        }
    }
    let deadline = std::time::Instant::now() + PORT_FREE_WAIT;
    loop {
        if UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, port)).is_ok() {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            bail!(
                "the hook port 127.0.0.1:{port} is still held {} s after the release: \
                 another process holds it (a collision — a VM host daemon of another \
                 state dir, a native minimald, or a foreign process), so the answerer \
                 service cannot take it",
                PORT_FREE_WAIT.as_secs()
            );
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

/// The handover's release-cancel verb: asks each daemon in `controls` to
/// re-bind its interim answerer at once. Best-effort per daemon — a cancel
/// is the failure path's own step, and one daemon that cannot answer must
/// not keep the others from re-binding.
pub fn release_cancel(controls: &[std::path::PathBuf]) {
    for control in controls {
        match ask(
            control,
            &minimald_rpc::BoxControlRequest::ReleaseAnswererCancel,
        ) {
            Ok(Some(reply)) => eprintln!("min-answerer: {}: {reply}", control.display()),
            Ok(None) => {}
            Err(error) => eprintln!("min-answerer: {}: {error:#}", control.display()),
        }
    }
}

/// One request over one daemon's control socket: `None` when no daemon is
/// there (the socket is absent, or nothing listens behind it), else the
/// daemon's answer as a sentence.
fn ask(
    control: &std::path::Path,
    request: &minimald_rpc::BoxControlRequest,
) -> Result<Option<String>> {
    use std::io::{BufRead as _, Write as _};
    let mut stream = match std::os::unix::net::UnixStream::connect(control) {
        Ok(stream) => stream,
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
            ) =>
        {
            return Ok(None);
        }
        Err(error) => {
            return Err(error).with_context(|| format!("connecting to {}", control.display()));
        }
    };
    stream.set_read_timeout(Some(CONTROL_REPLY_TIMEOUT))?;
    let mut line = serde_json_lenient::to_string(request).context("encoding the request")?;
    line.push('\n');
    stream.write_all(line.as_bytes())?;
    let mut reply = String::new();
    std::io::BufReader::new(&stream)
        .read_line(&mut reply)
        .with_context(|| format!("reading {}'s answer", control.display()))?;
    match serde_json_lenient::from_str::<minimald_rpc::BoxControlReply>(reply.trim()) {
        Ok(minimald_rpc::BoxControlReply::AnswererRelease { acted, detail }) => {
            Ok(Some(if acted {
                detail
            } else {
                format!("nothing to do: {detail}")
            }))
        }
        Ok(minimald_rpc::BoxControlReply::Error { error }) => {
            bail!("{} refused the request: {error}", control.display())
        }
        Ok(other) => bail!("{} answered {other:?}", control.display()),
        Err(error) => bail!(
            "{} answered nothing this verb understands ({error}); the daemon may predate \
             the handover",
            control.display()
        ),
    }
}

/// The answerer's two sockets, received from the service manager and
/// classified by what they are: the datagram listener at the hook port and
/// the unix stream channel. Both must arrive; a socket that is neither is
/// closed, and the error when one is missing names which.
fn activated_sockets() -> Result<(UdpSocket, UnixListener)> {
    let mut listener = None;
    let mut channel = None;
    for fd in handed_over()? {
        mark_cloexec(fd.as_fd())?;
        match socket_kind(fd.as_fd())? {
            SocketKind::Datagram => listener = Some(fd),
            SocketKind::UnixStream => channel = Some(fd),
            // Dropped here, which closes it: a socket the unit hands that
            // this service has no use for is not served, and it is not left
            // open in a process whose children would inherit it either.
            SocketKind::Other => {}
        }
    }
    match (listener, channel) {
        (Some(listener), Some(channel)) => {
            Ok((UdpSocket::from(listener), UnixListener::from(channel)))
        }
        (None, _) => bail!(
            "the unit hands the answerer no datagram listener at the hook port; \
             its socket must ListenDatagram= the host loopback"
        ),
        (Some(_), None) => bail!(
            "the unit hands the answerer no unix stream channel socket; its \
             socket must ListenStream= the channel's path"
        ),
    }
}

/// The sockets the service manager hands the answerer over, by platform:
/// launchd hands them by name, systemd as `LISTEN_FDS` fds from 3.
#[cfg(target_os = "macos")]
fn handed_over() -> Result<Vec<OwnedFd>> {
    Ok(vec![
        activate(LISTENER_SOCKET_NAME)?,
        activate(CHANNEL_SOCKET_NAME)?,
    ])
}

/// See the macOS arm ([`handed_over`]).
#[cfg(not(target_os = "macos"))]
fn handed_over() -> Result<Vec<OwnedFd>> {
    let count = activated_count(
        std::env::var("LISTEN_FDS").ok().as_deref(),
        std::env::var("LISTEN_PID").ok().as_deref(),
        std::process::id(),
    )?;
    let mut fds = Vec::with_capacity(count);
    for offset in 0..count {
        // The fd number is 3 (the first a manager may hand over, past the
        // std streams) plus the offset, and a count this side of
        // [`HANDED_SOCKET_LIMIT`] fits an fd number without wrapping.
        let fd = 3 + i32::try_from(offset)
            .map_err(|_| anyhow::anyhow!("the manager handed more fds than a process can hold"))?;
        // SAFETY: the manager hands the fd over for this service to own;
        // from this take on, the OwnedFd owns and closes it.
        fds.push(unsafe { OwnedFd::from_raw_fd(fd) });
    }
    Ok(fds)
}

/// One socket launchd handed the answerer, by the name the plist's `Sockets`
/// entry gives it — the API launchd's activation rests on, and the one
/// libSystem exports for it.
#[cfg(target_os = "macos")]
fn activate(name: &str) -> Result<OwnedFd> {
    // launch_activate_socket hands launchd's named socket over: it writes
    // the array of fds it allocated into `fds` and the array's length into
    // `count`, and the caller frees the array with free(3).
    unsafe extern "C" {
        fn launch_activate_socket(
            name: *const libc::c_char,
            fds: *mut *mut libc::c_int,
            count: *mut usize,
        ) -> libc::c_int;
    }
    let cname = std::ffi::CString::new(name).context("the socket name is a plain word")?;
    let mut fds: *mut libc::c_int = std::ptr::null_mut();
    let mut count = 0usize;
    // SAFETY: launch_activate_socket writes the array's pointer into `fds`
    // and its length into `count`, both ours to read after the call; the
    // name pointer is live for the call's life.
    let rc = unsafe { launch_activate_socket(cname.as_ptr(), &mut fds, &mut count) };
    if rc != 0 {
        bail!(
            "launchd did not hand the answerer its {name} socket (launch_activate_socket \
             said {rc}); the plist's Sockets entry must activate this service"
        );
    }
    if fds.is_null() || count == 0 {
        bail!("launchd handed the answerer no {name} socket");
    }
    // SAFETY: the array launch_activate_socket returned holds `count` fds;
    // the first is taken (the OwnedFd owns and closes it), the rest are
    // closed, and the array itself is freed — the API's one contract is a
    // free(3) array.
    let fd = unsafe { OwnedFd::from_raw_fd(*fds) };
    unsafe {
        for extra in 1..count {
            libc::close(*fds.add(extra));
        }
        libc::free(fds.cast());
    }
    Ok(fd)
}

/// The number of sockets the manager hands the answerer over, from
/// `LISTEN_FDS`, checked against `LISTEN_PID` (which the manager sets to
/// exactly this process — a stale activation from a re-exec'd parent is
/// refused rather than served). Pure over its arguments, so every arm is
/// testable without touching the process's environment, which no test may
/// race with another.
#[cfg(any(test, not(target_os = "macos")))]
fn activated_count(
    listen_fds: Option<&str>,
    listen_pid: Option<&str>,
    our_pid: u32,
) -> Result<usize> {
    let Some(count) = listen_fds else {
        bail!(
            "the service manager did not hand the answerer its sockets (LISTEN_FDS \
             is unset): this service starts only by socket activation"
        );
    };
    let count: usize = count
        .trim()
        .parse()
        .with_context(|| format!("LISTEN_FDS ({count}) is not a socket count"))?;
    if let Some(pid) = listen_pid
        && pid.trim() != our_pid.to_string()
    {
        bail!(
            "LISTEN_PID ({pid}) is not this process ({our_pid}); the activation is \
             not the answerer's"
        );
    }
    if count > HANDED_SOCKET_LIMIT {
        bail!("LISTEN_FDS ({count}) is past any unit's socket count; refusing it");
    }
    if count < 2 {
        bail!(
            "the unit hands the answerer {count} socket(s); it needs its two — the \
             listener at the hook port and the channel"
        );
    }
    Ok(count)
}

/// What one activated socket is, by the two facts the kernel answers about
/// it: its type and its address family.
#[derive(Debug, PartialEq, Eq)]
enum SocketKind {
    /// A datagram socket on an internet address: the listener at the hook
    /// port on the host loopback.
    Datagram,
    /// A stream socket on a unix address: the channel node daemons publish
    /// their rows over.
    UnixStream,
    /// Anything else — a socket the unit hands that this service has no use
    /// for.
    Other,
}

/// Classifies one socket by what it is: `SO_TYPE` for the listener's
/// datagram against the channel's stream, and the address family for the
/// host loopback against a unix path. The classification is the whole reason
/// the order a unit lists its sockets in never matters.
fn socket_kind(fd: BorrowedFd<'_>) -> std::io::Result<SocketKind> {
    let mut ty: libc::c_int = 0;
    let mut ty_len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: getsockopt writes one int into `ty`, whose size is passed
    // alongside it; the fd is borrowed for the call's life.
    let rc = unsafe {
        libc::getsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            std::ptr::addr_of_mut!(ty).cast(),
            &mut ty_len,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: sockaddr_storage is plain old data; zeroed is a valid value,
    // and getsockname writes at most the size passed alongside it into the
    // fd's own address.
    let mut addr: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut addr_len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    // SAFETY: as above; the fd is borrowed for the call's life.
    let rc = unsafe {
        libc::getsockname(
            fd.as_raw_fd(),
            std::ptr::addr_of_mut!(addr).cast(),
            &mut addr_len,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(match (ty, i32::from(addr.ss_family)) {
        (libc::SOCK_DGRAM, libc::AF_INET) => SocketKind::Datagram,
        (libc::SOCK_STREAM, libc::AF_UNIX) => SocketKind::UnixStream,
        _ => SocketKind::Other,
    })
}

/// Marks the manager's socket close-on-exec: the fds arrive without the flag
/// (the manager wants them inherited by exactly this service), and nothing
/// this service runs may carry the answerer's sockets into a child.
fn mark_cloexec(fd: BorrowedFd<'_>) -> std::io::Result<()> {
    // SAFETY: fcntl on the fd borrowed for the call's life; F_GETFD reads
    // the descriptor's flags, F_SETFD writes them — never the socket's.
    let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: as above; the new flags are the old ones plus CLOEXEC.
    let rc = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, flags | libc::FD_CLOEXEC) };
    if rc < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A socket without `LISTEN_FDS` is not an activation: the service
    /// starts only by socket activation, and the error says so.
    #[test]
    fn activation_refuses_without_listen_fds() {
        let error = activated_count(None, None, 1234).expect_err("no LISTEN_FDS is refused");
        assert!(
            error.to_string().contains("LISTEN_FDS"),
            "the error names the missing fact: {error}"
        );
        assert!(
            error.to_string().contains("socket activation"),
            "the error says the service starts only by activation: {error}"
        );
    }

    /// The count is what it says it is, and `LISTEN_PID` matching this
    /// process is what makes the activation this service's.
    #[test]
    fn activation_reads_the_count_and_the_pid() {
        assert_eq!(
            activated_count(Some("2"), None, 1234).expect("two sockets is a unit's"),
            2,
            "the count is read from LISTEN_FDS"
        );
        assert_eq!(
            activated_count(Some(" 2\n"), Some("1234"), 1234)
                .expect("the service's own pid is accepted"),
            2,
            "the count and pid are read as trimmed numbers"
        );
    }

    /// A `LISTEN_FDS` that is not a number is refused, naming the value.
    #[test]
    fn activation_refuses_a_count_that_is_not_one() {
        let error = activated_count(Some("two"), None, 1234).expect_err("a non-number is refused");
        assert!(
            error.to_string().contains("LISTEN_FDS"),
            "the error names the variable: {error}"
        );
        assert!(
            error.to_string().contains("two"),
            "the error names the value: {error}"
        );
    }

    /// A `LISTEN_PID` naming another process is not this service's
    /// activation: a stale one from a re-exec'd parent is refused, not
    /// served.
    #[test]
    fn activation_refuses_a_foreign_pid() {
        let error =
            activated_count(Some("2"), Some("4321"), 1234).expect_err("a foreign pid is refused");
        assert!(
            error.to_string().contains("LISTEN_PID"),
            "the error names the stale fact: {error}"
        );
    }

    /// Fewer than the two sockets the answerer needs is refused — the count
    /// is checked before a single fd is taken for it — and a hostile count is
    /// refused rather than allocated for.
    #[test]
    fn activation_bounds_the_count() {
        let short = activated_count(Some("1"), None, 1234).expect_err("one socket is refused");
        assert!(
            short.to_string().contains("needs its two"),
            "the error names what is missing: {short}"
        );
        let huge = activated_count(Some(&(HANDED_SOCKET_LIMIT + 1).to_string()), None, 1234)
            .expect_err("an implausible count is refused");
        assert!(
            huge.to_string().contains("past any unit's"),
            "the error refuses the implausible count: {huge}"
        );
    }

    /// The listener's shape is a datagram socket on an internet address —
    /// classified from a real one.
    #[test]
    fn the_listener_socket_classifies_as_the_datagram() {
        let socket = UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .expect("the listener binds the host loopback");
        // SAFETY: the fd is the socket's own and stays valid for the
        // borrow's life.
        let fd = unsafe { BorrowedFd::borrow_raw(socket.as_raw_fd()) };
        assert_eq!(
            socket_kind(fd).expect("the kernel answers for its own socket"),
            SocketKind::Datagram,
            "a datagram socket on the host loopback is the listener"
        );
    }

    /// The channel's shape is a stream socket on a unix address — classified
    /// from a real one.
    #[test]
    fn the_channel_socket_classifies_as_the_unix_stream() {
        let dir = tempfile::TempDir::new().expect("a temp dir for the channel socket");
        let listener = UnixListener::bind(dir.path().join("channel.sock"))
            .expect("the channel binds its path");
        // SAFETY: the fd is the listener's own and stays valid for the
        // borrow's life.
        let fd = unsafe { BorrowedFd::borrow_raw(listener.as_raw_fd()) };
        assert_eq!(
            socket_kind(fd).expect("the kernel answers for its own socket"),
            SocketKind::UnixStream,
            "a stream socket on a unix address is the channel"
        );
    }

    /// A socket that is neither the listener's shape nor the channel's — a
    /// stream socket on an internet address, the shape a misrendered unit's
    /// `ListenStream=` on the hook port would hand over — is neither, and is
    /// closed rather than served.
    #[test]
    fn a_foreign_socket_classifies_as_other() {
        let tcp = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .expect("the foreign socket binds the host loopback");
        // SAFETY: the fd is the listener's own and stays valid for the
        // borrow's life.
        let fd = unsafe { BorrowedFd::borrow_raw(tcp.as_raw_fd()) };
        assert_eq!(
            socket_kind(fd).expect("the kernel answers for its own socket"),
            SocketKind::Other,
            "a stream socket on an internet address is neither the answerer's listener \
             nor its channel"
        );
    }
}
