//! The proxy's listener: the acceptor for the switch peer's deliveries
//! (BEP-026).
//!
//! A box reaches the proxy through the switch. The switch's peer
//! (`switch::bep_host`) accepts the box's TCP connection on the leg's
//! address, then dials this listener's unix socket, once per flow. The dial
//! writes the per-boot token ([`TOKEN_LEN`] bytes) and then one fixed
//! delivery header ([`DELIVERY_HEADER_LEN`] bytes) ahead of any byte of the
//! box's flow. The header layout is the one `switch::bep_host::DeliveryHeader`
//! documents, and this module reads it byte for byte:
//!
//! - byte 0: the wire version, [`DELIVERY_HEADER_VERSION`]
//! - bytes 1..17: the box id, filled from the box's attachment
//! - bytes 17..21 and 21..23: the box's switch address and source port
//! - bytes 23..27 and 27..29: the destination address and port
//!
//! The listener admits a connection only when it proves each of these, in
//! order. Any other connection is refused at the listener, sealed value or
//! not (BEP-026). The proxy is a credential proxy for boxes, never a general
//! egress proxy for the host.
//!
//! 1. The peer's uid is this process's uid. The socket is mode `0600` in a
//!    `0700` directory, so this is the kernel's answer for who connected.
//! 2. The connection presents this boot's token. A host shell that finds the
//!    socket's path does not know the token, so it reaches the listener but
//!    is never a box's connection.
//! 3. The header's version is [`DELIVERY_HEADER_VERSION`].
//! 4. The box id is not all zero, and the [`Attachments`] hold it for the
//!    header's source.
//!
//! A refused connection is closed without one byte of answer, and one warn
//! line records the reason and the peer.

use std::fmt;
use std::io;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::net::{UnixListener, UnixStream};

/// The per-boot token's length in bytes: `switch::bep_host::TOKEN_LEN`.
pub const TOKEN_LEN: usize = 32;

/// The delivery header's wire version: `switch::bep_host::DELIVERY_HEADER_VERSION`.
pub const DELIVERY_HEADER_VERSION: u8 = 1;

/// The delivery header's length in bytes: `switch::bep_host::DELIVERY_HEADER_LEN`.
pub const DELIVERY_HEADER_LEN: usize = 1 + 16 + 4 + 2 + 4 + 2;

/// How long a connection has to present its token and header. A peer that
/// stalls before the head is refused, so it holds no task.
pub const PRESENT_TIMEOUT: Duration = Duration::from_secs(5);

/// A box's id as the delivery carries it: 16 opaque bytes. The all-zero id
/// names no box.
pub type BoxId = [u8; 16];

/// The box id in its one text form: 32 lowercase hex digits, the form every
/// audit record's `subject` and `min box audit` use.
#[must_use]
pub fn box_id_text(id: &BoxId) -> String {
    use fmt::Write as _;
    let mut out = String::with_capacity(32);
    for byte in id {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// One connection the listener admitted: the box it is for, and the flow's
/// two endpoints as the box's connection gave them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Delivery {
    /// The box the connection belongs to.
    pub box_id: BoxId,
    /// The box's switch address and source port.
    pub source: SocketAddrV4,
    /// The address and port the box connected to.
    pub destination: SocketAddrV4,
}

impl Delivery {
    /// Parses the fixed header. `None` when the version is not
    /// [`DELIVERY_HEADER_VERSION`].
    #[must_use]
    pub fn parse(head: &[u8; DELIVERY_HEADER_LEN]) -> Option<Self> {
        if head[0] != DELIVERY_HEADER_VERSION {
            return None;
        }
        let mut box_id = [0u8; 16];
        box_id.copy_from_slice(&head[1..17]);
        let endpoint = |at: usize| {
            SocketAddrV4::new(
                Ipv4Addr::new(head[at], head[at + 1], head[at + 2], head[at + 3]),
                u16::from_be_bytes([head[at + 4], head[at + 5]]),
            )
        };
        Some(Self {
            box_id,
            source: endpoint(17),
            destination: endpoint(23),
        })
    }

    /// The header bytes for this delivery, as the switch peer writes them.
    #[must_use]
    pub fn emit(&self) -> [u8; DELIVERY_HEADER_LEN] {
        let mut head = [0u8; DELIVERY_HEADER_LEN];
        head[0] = DELIVERY_HEADER_VERSION;
        head[1..17].copy_from_slice(&self.box_id);
        head[17..21].copy_from_slice(&self.source.ip().octets());
        head[21..23].copy_from_slice(&self.source.port().to_be_bytes());
        head[23..27].copy_from_slice(&self.destination.ip().octets());
        head[27..29].copy_from_slice(&self.destination.port().to_be_bytes());
        head
    }

    /// The box id as text, [`box_id_text`].
    #[must_use]
    pub fn box_id_text(&self) -> String {
        box_id_text(&self.box_id)
    }
}

/// Why the listener refused a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The kernel did not give the peer's credentials.
    Credentials,
    /// The peer runs as another user.
    Uid,
    /// The connection closed before its token and header were complete.
    Short,
    /// The connection did not present its token and header in time.
    Timeout,
    /// The token is not this boot's.
    Token,
    /// The header's version is not one this listener reads.
    Version,
    /// The header carries the all-zero box id.
    ZeroBoxId,
    /// No attachment holds the header's box id for its source.
    NoAttachment,
}

impl Refusal {
    /// The reason word the warn line carries.
    #[must_use]
    pub fn reason(self) -> &'static str {
        match self {
            Self::Credentials => "peer_credentials_unavailable",
            Self::Uid => "peer_uid",
            Self::Short => "short_presentation",
            Self::Timeout => "presentation_timeout",
            Self::Token => "token_mismatch",
            Self::Version => "header_version",
            Self::ZeroBoxId => "zero_box_id",
            Self::NoAttachment => "no_attachment",
        }
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.reason())
    }
}

/// The host's attachments: which box a switch source address belongs to.
pub trait Attachments: Send + Sync {
    /// Whether the attachment for `source` holds `box_id`.
    fn holds(&self, source: Ipv4Addr, box_id: &BoxId) -> bool;
}

/// The attachments as the switch peer read them. The peer fills the box id
/// from the source's attachment before each dial, and delivers no flow for a
/// source that holds none. The token proves the dial came from the peer, so
/// this source admits every id the peer wrote.
#[derive(Debug, Clone, Copy, Default)]
pub struct PeerAttested;

impl Attachments for PeerAttested {
    fn holds(&self, _source: Ipv4Addr, _box_id: &BoxId) -> bool {
        true
    }
}

impl<F: Fn(Ipv4Addr, &BoxId) -> bool + Send + Sync> Attachments for F {
    fn holds(&self, source: Ipv4Addr, box_id: &BoxId) -> bool {
        self(source, box_id)
    }
}

/// Whether `presented` is `expected`, in time that does not depend on where
/// the two first differ. The token is a shared secret.
fn token_matches(presented: &[u8; TOKEN_LEN], expected: &[u8; TOKEN_LEN]) -> bool {
    presented
        .iter()
        .zip(expected)
        .fold(0u8, |diff, (a, b)| diff | (a ^ b))
        == 0
}

/// This process's effective uid.
fn own_uid() -> u32 {
    // SAFETY: geteuid reads the caller's effective uid. It has no side
    // effects and cannot fail.
    unsafe { libc::geteuid() }
}

/// The listener on its unix socket.
pub struct Listener {
    inner: UnixListener,
    path: PathBuf,
    token: [u8; TOKEN_LEN],
    attachments: Arc<dyn Attachments>,
}

impl fmt::Debug for Listener {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Listener")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl Listener {
    /// Binds the listener at `path`, with mode `0600` and a parent
    /// directory of mode `0700`. A socket file left at `path` by an earlier
    /// run is removed first.
    ///
    /// # Errors
    ///
    /// The I/O error of the directory, the bind or the mode change.
    pub fn bind(
        path: &Path,
        token: [u8; TOKEN_LEN],
        attachments: Arc<dyn Attachments>,
    ) -> io::Result<Self> {
        let inner = bind_owner_only(path)?;
        Ok(Self {
            inner,
            path: path.to_owned(),
            token,
            attachments,
        })
    }

    /// The socket's path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Accepts connections until the listener fails. Each admitted
    /// connection goes to `handler` on a task of its own. The stream's next
    /// byte is the first byte of the box's flow.
    ///
    /// # Errors
    ///
    /// The accept's I/O error.
    pub async fn run<H, F>(self, handler: H) -> io::Result<()>
    where
        H: Fn(Delivery, UnixStream) -> F + Send + Sync + 'static,
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        let handler = Arc::new(handler);
        let token = self.token;
        loop {
            let stream = accept(&self.inner, "proxy listener").await?;
            let attachments = Arc::clone(&self.attachments);
            let handler = Arc::clone(&handler);
            tokio::spawn(async move {
                let mut stream = stream;
                let (uid, pid) = match stream.peer_cred() {
                    Ok(cred) => (Some(cred.uid()), cred.pid()),
                    Err(_) => (None, None),
                };
                let presented = tokio::time::timeout(
                    PRESENT_TIMEOUT,
                    present(&mut stream, uid, &token, attachments.as_ref()),
                )
                .await
                .unwrap_or(Err(Refusal::Timeout));
                match presented {
                    Ok(delivery) => handler(delivery, stream).await,
                    Err(refusal) => {
                        tracing::warn!(
                            reason = refusal.reason(),
                            peer_uid = uid,
                            peer_pid = pid,
                            "refused a connection at the proxy listener, because it is not a box's connection"
                        );
                    }
                }
            });
        }
    }
}

/// Reads and checks one connection's presentation: the uid the kernel gave
/// for the peer, then the token, then the header.
///
/// # Errors
///
/// The [`Refusal`] for the first check that failed.
pub async fn present(
    stream: &mut UnixStream,
    peer_uid: Option<u32>,
    token: &[u8; TOKEN_LEN],
    attachments: &dyn Attachments,
) -> Result<Delivery, Refusal> {
    match peer_uid {
        None => return Err(Refusal::Credentials),
        Some(uid) if uid != own_uid() => return Err(Refusal::Uid),
        Some(_) => {}
    }
    let mut presented = [0u8; TOKEN_LEN];
    stream
        .read_exact(&mut presented)
        .await
        .map_err(|_| Refusal::Short)?;
    if !token_matches(&presented, token) {
        return Err(Refusal::Token);
    }
    let mut head = [0u8; DELIVERY_HEADER_LEN];
    stream
        .read_exact(&mut head)
        .await
        .map_err(|_| Refusal::Short)?;
    let delivery = Delivery::parse(&head).ok_or(Refusal::Version)?;
    if delivery.box_id == [0u8; 16] {
        return Err(Refusal::ZeroBoxId);
    }
    if !attachments.holds(*delivery.source.ip(), &delivery.box_id) {
        return Err(Refusal::NoAttachment);
    }
    Ok(delivery)
}

/// Binds a unix socket at `path` that only this user can reach: the parent
/// directory gets mode `0700` when this call creates it, and the socket
/// gets mode `0600`. A stale socket at `path` is removed first. A socket
/// is stale when a connect to it is refused. A socket that takes the
/// connect belongs to a running process, and the bind fails.
///
/// The socket is bound in a staging directory of mode `0700` beside `path`,
/// given mode `0600`, and then renamed to `path`. So no other user can
/// connect while the socket still has the umask's mode, even when the
/// parent directory is wider than `0700`.
///
/// # Errors
///
/// [`io::ErrorKind::AddrInUse`] when the socket at `path` is not stale.
/// Otherwise the I/O error of the directory, the removal, the bind, the
/// mode change or the rename.
pub fn bind_owner_only(path: &Path) -> io::Result<UnixListener> {
    use std::os::unix::fs::{DirBuilderExt, FileTypeExt, PermissionsExt};
    use std::sync::atomic::{AtomicU64, Ordering};
    static STAGING: AtomicU64 = AtomicU64::new(0);

    let parent = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    if !parent.exists() {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)?;
    }
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_socket() => {
            // A socket that still takes connections belongs to a running
            // process. Only a socket that refuses them is stale.
            match std::os::unix::net::UnixStream::connect(path) {
                Ok(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::AddrInUse,
                        format!("{} is in use by another process", path.display()),
                    ));
                }
                Err(err)
                    if matches!(
                        err.kind(),
                        io::ErrorKind::ConnectionRefused | io::ErrorKind::NotFound
                    ) =>
                {
                    match std::fs::remove_file(path) {
                        Err(err) if err.kind() != io::ErrorKind::NotFound => return Err(err),
                        _ => {}
                    }
                }
                Err(err) => {
                    return Err(io::Error::new(
                        io::ErrorKind::AddrInUse,
                        format!("{} is not stale: {err}", path.display()),
                    ));
                }
            }
        }
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("{} exists and is not a socket", path.display()),
            ));
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => return Err(err),
    }
    let staging = parent.join(format!(
        ".bep-bind-{}-{}",
        std::process::id(),
        STAGING.fetch_add(1, Ordering::Relaxed)
    ));
    // A staging directory left by a process that had this pid is stale.
    match std::fs::symlink_metadata(&staging) {
        Ok(meta) if meta.is_dir() => std::fs::remove_dir_all(&staging)?,
        Ok(_) => std::fs::remove_file(&staging)?,
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => return Err(err),
    }
    std::fs::DirBuilder::new().mode(0o700).create(&staging)?;
    let staged = staging.join("s");
    let bound = UnixListener::bind(&staged).and_then(|listener| {
        std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o600))?;
        std::fs::rename(&staged, path)?;
        Ok(listener)
    });
    let _ = std::fs::remove_file(&staged);
    let _ = std::fs::remove_dir(&staging);
    bound
}

/// How long an accept loop waits after a transient accept error.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);

/// Accepts the next connection on `listener`. A transient error, such as a
/// full descriptor table or a connection that the peer aborted, is logged
/// with `socket` and retried after [`ACCEPT_BACKOFF`]. It does not end the
/// accept loop.
///
/// # Errors
///
/// An accept error that is not transient.
pub(crate) async fn accept(listener: &UnixListener, socket: &str) -> io::Result<UnixStream> {
    loop {
        match listener.accept().await {
            Ok((stream, _)) => return Ok(stream),
            Err(err) if transient(&err) => {
                tracing::warn!(socket, error = %err, "an accept failed, retrying");
                tokio::time::sleep(ACCEPT_BACKOFF).await;
            }
            Err(err) => return Err(err),
        }
    }
}

/// Whether an accept error passes: an aborted or reset connection, an
/// interrupt, or a short supply of descriptors or memory.
fn transient(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::Interrupted
            | io::ErrorKind::WouldBlock
            | io::ErrorKind::OutOfMemory
    ) || matches!(
        err.raw_os_error(),
        Some(libc::EMFILE | libc::ENFILE | libc::ENOBUFS | libc::ENOMEM | libc::EPROTO)
    )
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use tokio::io::AsyncWriteExt;

    use super::*;

    const TOKEN: [u8; TOKEN_LEN] = [0x5a; TOKEN_LEN];

    fn delivery() -> Delivery {
        Delivery {
            box_id: [0x42; 16],
            source: SocketAddrV4::new(Ipv4Addr::new(10, 0, 2, 7), 40_000),
            destination: SocketAddrV4::new(Ipv4Addr::new(10, 0, 2, 3), 8118),
        }
    }

    /// A listener whose handler counts the connections it admits, and
    /// echoes `admitted` to each.
    async fn counting_listener(
        dir: &Path,
        attachments: Arc<dyn Attachments>,
    ) -> (PathBuf, Arc<AtomicUsize>) {
        let path = dir.join("bep/listener.sock");
        let listener = Listener::bind(&path, TOKEN, attachments).unwrap();
        let admitted = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&admitted);
        tokio::spawn(listener.run(move |_delivery, mut stream| {
            let count = Arc::clone(&count);
            async move {
                count.fetch_add(1, Ordering::SeqCst);
                let _ = stream.write_all(b"admitted").await;
            }
        }));
        (path, admitted)
    }

    /// What the listener answers to `bytes`: everything it wrote before it
    /// closed the connection.
    async fn answer(path: &Path, bytes: &[u8]) -> Vec<u8> {
        let mut stream = UnixStream::connect(path).await.unwrap();
        stream.write_all(bytes).await.unwrap();
        stream.shutdown().await.unwrap();
        let mut out = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut out)).await;
        out
    }

    fn presentation(token: &[u8; TOKEN_LEN], delivery: &Delivery) -> Vec<u8> {
        let mut bytes = token.to_vec();
        bytes.extend_from_slice(&delivery.emit());
        bytes
    }

    // BEP-026: a host shell can reach the socket, but it is not a box's
    // connection, so the listener refuses it before any HTTP, sealed value
    // or not. A box's delivery through the switch peer is admitted.
    #[tokio::test]
    async fn host_shell_connection_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let (path, admitted) = counting_listener(dir.path(), Arc::new(PeerAttested)).await;

        // A host shell speaks HTTP to the socket directly, with a sealed value.
        let shell = answer(
            &path,
            b"CONNECT api.github.com:443 HTTP/1.1\r\nHost: api.github.com:443\r\n\
              Proxy-Authorization: Bearer sealed.v1.AAAA\r\n\r\n",
        )
        .await;
        assert!(shell.is_empty(), "the shell got an answer: {shell:?}");

        // A guess at the token is refused too, also with a well-formed header.
        let guessed = answer(&path, &presentation(&[0u8; TOKEN_LEN], &delivery())).await;
        assert!(guessed.is_empty());

        // The right token with an unknown header version is refused.
        let mut wrong_version = presentation(&TOKEN, &delivery());
        wrong_version[TOKEN_LEN] = DELIVERY_HEADER_VERSION + 1;
        assert!(answer(&path, &wrong_version).await.is_empty());

        // The all-zero box id names no box.
        let mut zero = delivery();
        zero.box_id = [0; 16];
        assert!(answer(&path, &presentation(&TOKEN, &zero)).await.is_empty());
        assert_eq!(admitted.load(Ordering::SeqCst), 0);

        // The switch peer's delivery is a box's connection.
        let peer = answer(&path, &presentation(&TOKEN, &delivery())).await;
        assert_eq!(peer, b"admitted");
        assert_eq!(admitted.load(Ordering::SeqCst), 1);

        // The socket is the owner's alone.
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        let dir_mode = std::fs::metadata(path.parent().unwrap())
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(dir_mode & 0o777, 0o700);
    }

    #[tokio::test]
    async fn a_box_id_no_attachment_holds_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let holds = |source: Ipv4Addr, id: &BoxId| {
            source == Ipv4Addr::new(10, 0, 2, 7) && *id == [0x42; 16]
        };
        let (path, admitted) = counting_listener(dir.path(), Arc::new(holds)).await;
        let mut other = delivery();
        other.box_id = [0x43; 16];
        assert!(
            answer(&path, &presentation(&TOKEN, &other))
                .await
                .is_empty()
        );
        assert_eq!(admitted.load(Ordering::SeqCst), 0);
        assert_eq!(
            answer(&path, &presentation(&TOKEN, &delivery())).await,
            b"admitted"
        );
    }

    // A second bind at the path of a live socket fails, and the first
    // listener keeps the path. A socket nobody listens on is stale.
    #[tokio::test]
    async fn second_bind_at_a_live_socket_is_addr_in_use() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bep/listener.sock");
        let first = bind_owner_only(&path).unwrap();
        let err = bind_owner_only(&path).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AddrInUse, "{err}");
        assert!(UnixStream::connect(&path).await.is_ok());
        drop(first);
        drop(bind_owner_only(&path).unwrap());
    }

    #[test]
    fn header_round_trips_and_box_id_is_hex() {
        let d = delivery();
        assert_eq!(Delivery::parse(&d.emit()), Some(d));
        assert_eq!(d.box_id_text(), "42".repeat(16));
    }
}
