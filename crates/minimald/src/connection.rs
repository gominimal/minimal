use russh::{
    Channel as RuChannel, ChannelId,
    server::{ChannelOpenHandle, Config as RuConfig, Msg, RunningSession, Session},
};
use sessions::SessionId;
use std::{
    collections::BTreeMap,
    pin::Pin,
    sync::{Arc, LazyLock},
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
    sync::{Mutex, MutexGuard},
};

use crate::{
    ChannelConfig, RequestedPty, exec,
    rpc::{self},
    server::ServerStateHandle,
    sessions::SessionKeyPredicate,
    sftp,
};

static PROTOCOL_TRACE_ENABLED: LazyLock<bool> =
    LazyLock::new(|| std::env::var("PROTOCOL_TRACE").as_deref() == Ok("1"));

macro_rules! protocol_trace {
    ($($arg:tt)*) => {
        if *PROTOCOL_TRACE_ENABLED {
            tracing::info!($($arg)*);
        }
    };
}

/// The auth state of the SSH connection.
#[derive(Debug, Default, PartialEq, Eq)]
pub enum Auth {
    #[default]
    Pending,
    Local,
}

/// Represents the state variants of an SSH channel within a connection.
#[derive(Debug)]
pub enum ChannelInner {
    /// A channel has been created but not yet minted into a specific variant,
    /// namely an exec variant, shell, or subsystem variant.
    Pending(RuChannel<Msg>, ChannelConfig),
    /// The pending channel was finalized, and the channel handle was taken
    /// to be used for writing bytes from a different async context.
    Taken,
}

/// Represents the state of an SSH channel within a connection.
#[derive(Debug)]
pub struct Channel {
    pub id: ChannelId,
    pub inner: ChannelInner,
    closed: bool,
}

impl Channel {
    /// Mints a new session state object. Expected to be called from the russh
    /// handler code for a connection.
    fn new_session(id: ChannelId, c: RuChannel<Msg>) -> Self {
        Channel {
            id,
            inner: ChannelInner::Pending(
                c,
                ChannelConfig {
                    env_vars: BTreeMap::new(),
                    pty: None,
                },
            ),
            closed: false,
        }
    }

    /// Called when the client wants to close this channel.
    fn handle_channel_close(&mut self) {
        self.closed = true;
    }

    /// Consumes a pending session, returning its state and leaving [`ChannelInner::Taken`] in its place.
    pub fn take(&mut self) -> Option<(RuChannel<Msg>, ChannelConfig)> {
        match std::mem::replace(&mut self.inner, ChannelInner::Taken) {
            ChannelInner::Pending(c, p) => Some((c, p)),
            other => {
                self.inner = other;
                None
            }
        }
    }

    /// Returns a mutable reference to the state of the channel under construction, if
    /// the channel has not already been launched and/or closed.
    pub fn pending_config_mut(&mut self) -> Option<&mut ChannelConfig> {
        if let ChannelInner::Pending(_, p) = &mut self.inner {
            Some(p)
        } else {
            None
        }
    }
}

/// Represents the SSH connection. Lives for the
/// lifetime of the connection.
#[derive(Debug)]
pub struct Connection {
    /// The current authentication state of this connection.
    pub auth: Auth,
    /// The username given via SSH. Not populated till the client
    /// authenticates the connection.
    pub ssh_username: Option<String>,

    /// State specific to an SSH channel.
    channels: BTreeMap<ChannelId, Channel>,

    /// Session ids created via `CreateSession` over this connection.
    /// When the connection closes, any of these still left in an
    /// unfinalized state — `Pending` (never got a `SubmitVerdict`) or
    /// `Materializing` (never got a `FinalizeSession`) — are reaped, so
    /// a client that dropped mid-activation (e.g. Ctrl-C at the
    /// composition-gating prompt) doesn't strand a half-built session
    /// that holds its name hostage. Finalized (`Active`) sessions are
    /// long-lived and outlive the connection, so they are never reaped
    /// here.
    created_sessions: Vec<SessionId>,

    serv: ServerStateHandle,
}

impl Connection {
    /// Drives a new SSH connection over an arbitrary byte stream.
    ///
    /// The russh stack is transport-agnostic, so this accepts any
    /// async stream: a [`UnixStream`] for the native UDS daemon or a
    /// vsock stream for the in-VM (pid-1) guest. `is_local` marks the
    /// peer as pre-authenticated ([`Auth::Local`]); both the UDS and the
    /// host-mediated vsock transports are equally trusted.
    pub(crate) async fn from_stream<S>(
        s: S,
        c: Arc<RuConfig>,
        serv: ServerStateHandle,
        is_local: bool,
    ) -> Result<(ConnectionHandle, RunningSession<ConnectionHandler>), ConnectionError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let h = ConnectionHandle(Arc::new(Mutex::new(Self {
            auth: if is_local { Auth::Local } else { Auth::Pending },
            ssh_username: None,
            channels: BTreeMap::new(),
            created_sessions: Vec::new(),
            serv,
        })));

        // A handshake failure (e.g. a client that connects then drops) must not
        // propagate as a panic: in the guest, minimald is pid-1, so a panic here
        // kills init and takes down the whole VM. Surface the error so the accept
        // loop can drop the connection and keep serving.
        let session = russh::server::run_stream(c, s, ConnectionHandler(h.clone())).await?;
        Ok((h, session))
    }

    pub(crate) fn pending_config_mut(&mut self, id: ChannelId) -> Option<&mut ChannelConfig> {
        let c = self.channels.get_mut(&id)?;
        if c.closed {
            tracing::warn!("Client tried to update config on an already-closed channel {id}");
            return None;
        }
        c.pending_config_mut()
    }

    pub fn take(&mut self, id: ChannelId) -> Option<(RuChannel<Msg>, ChannelConfig)> {
        let c = self.channels.get_mut(&id)?;
        if c.closed {
            tracing::warn!("Client tried to take an already-closed channel {id}");
            return None;
        }
        c.take()
    }

    fn handle_channel_close(&mut self, id: ChannelId) -> Result<(), ConnectionError> {
        match self.channels.remove(&id) {
            None => tracing::warn!("request to close channel {id} which does not exist"),
            Some(mut c) => {
                c.handle_channel_close();
            }
        };
        Ok(())
    }
}

/// A thread-safe handle to the connection.
#[derive(Clone, Debug)]
pub struct ConnectionHandle(Arc<Mutex<Connection>>);

impl ConnectionHandle {
    pub fn lock(&self) -> impl Future<Output = MutexGuard<'_, Connection>> {
        self.0.lock()
    }

    /// Record a session created via `CreateSession` over this connection,
    /// so an unfinalized one can be reaped when the connection closes.
    pub async fn record_created_session(&self, id: SessionId) {
        self.0.lock().await.created_sessions.push(id);
    }

    /// Drain and return the ids of every session created over this
    /// connection. Called once at connection teardown to decide which
    /// half-built sessions to reap.
    pub async fn take_created_sessions(&self) -> Vec<SessionId> {
        std::mem::take(&mut self.0.lock().await.created_sessions)
    }
}

/// An error when handling the SSH connection.
#[derive(Debug, thiserror::Error)]
pub enum ConnectionError {
    /// A protocol error.
    #[error("Protocol error: {0}")]
    Protocol(#[from] russh::Error),
    /// An internal error.
    #[error("Internal error: {0}")]
    Internal(String),

    /// Failed to (de)serialize a JSON-encoded RPC message.
    #[error("Serialization error: {0}")]
    Json(#[from] serde_json_lenient::Error),

    /// An operation was attempted after the session was launched
    /// (i.e. setting env vars after exec), which is both non-sensical and
    /// heavily implied by RFC 4254 to be invalid.
    #[error("Protocol error: Attempted channel configuration after initialization")]
    SetupAfterInitiation,
}

/// A [`russh::server::Handler`] for a [`Connection`].
///
/// IMPORTANT: Handler methods must be fast to avoid blocking the
/// task which is servicing the socket. Handlers should reconfigure
/// state, spawn an async task for any potentially long-running task,
/// and return.
///
/// NOTE: channel_eof left at default impl, implementing channel_eof prevents propagation
/// to channel handle. Similarly, don't implement data().
pub struct ConnectionHandler(ConnectionHandle);

impl russh::server::Handler for ConnectionHandler {
    type Error = ConnectionError;

    async fn auth_none(&mut self, user: &str) -> Result<russh::server::Auth, Self::Error> {
        let mut s = self.0.lock().await;
        if s.auth == Auth::Local {
            s.ssh_username = Some(user.to_string());
            Ok(russh::server::Auth::Accept)
        } else {
            Ok(russh::server::Auth::reject())
        }
    }

    async fn channel_open_session(
        &mut self,
        c: RuChannel<Msg>,
        reply: ChannelOpenHandle,
        _: &mut Session,
    ) -> Result<(), Self::Error> {
        let mut s = self.0.lock().await;
        if s.auth != Auth::Local {
            reply
                .reject(russh::ChannelOpenFailure::AdministrativelyProhibited)
                .await; // indicate failure
            return Ok(());
        }

        protocol_trace!("Minting session channel with id {}", c.id());
        s.channels.insert(c.id(), Channel::new_session(c.id(), c));

        reply.accept().await; // indicate success
        Ok(())
    }

    async fn env_request(
        &mut self,
        id: ChannelId,
        var_name: &str,
        var_value: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        protocol_trace!("Got env_request on channel {id}: {var_name}={var_value}");

        match self.0.lock().await.pending_config_mut(id) {
            Some(p) => {
                session.channel_success(id)?;
                p.env_vars
                    .insert(var_name.to_string(), var_value.to_string());
            }
            None => session.channel_failure(id)?,
        }
        Ok(())
    }

    async fn pty_request(
        &mut self,
        id: ChannelId,
        term: &str,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        modes: &[(russh::Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        protocol_trace!(
            "Got pty_request on channel {id}: term={term} sz=({col_width}, {row_height}) p_sz=({pix_width}, {pix_height}) modes={:?}",
            modes,
        );

        match self.0.lock().await.pending_config_mut(id) {
            Some(p) => {
                session.channel_success(id)?;
                p.pty = Some(RequestedPty {
                    char_sizes: (col_width, row_height),
                    pixel_sizes: (pix_width, pix_height),
                    term: term.to_string(),
                    modes: modes.to_vec(),
                });
            }
            None => session.channel_failure(id)?,
        }
        Ok(())
    }

    async fn exec_request(
        &mut self,
        id: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        protocol_trace!(
            "Got exec_request on channel {id}: {:?}",
            String::from_utf8(data.to_vec())
        );
        let c = self.0.clone();
        let s = c.0.lock().await.serv.clone();
        exec::handle_exec(data, s, c, id, session).await
    }

    async fn shell_request(
        &mut self,
        id: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        protocol_trace!("Got shell_request on channel {id}");

        let conn = self.0.clone();
        let serv = conn.0.lock().await.serv.clone();
        let mut conn_lock = conn.lock().await;
        let Some((channel, config)) = conn_lock.take(id) else {
            session.channel_failure(id)?;
            return Ok(());
        };
        let conn_username = conn_lock.ssh_username.clone().expect("already authed");
        drop(conn_lock);
        if config.pty.is_none() {
            tracing::warn!("channel {id}: pty not requested for shell session",);
            session.channel_failure(id)?;
            return Ok(());
        }

        let Some(session_id_str) = config.env_vars.get(crate::MINIMAL_SESSION_ID_ENV) else {
            tracing::warn!("shell request rejected on channel {id}: missing MINIMAL_SESSION_ID",);
            session.channel_failure(id)?;
            return Ok(());
        };
        let Ok(session_id) = SessionId::parse_str(session_id_str) else {
            tracing::warn!(
                value = %session_id_str,
                "shell request rejected on channel {id}: not a uuid",
            );
            session.channel_failure(id)?;
            return Ok(());
        };

        let mngr = serv.sessions_manager().await;
        let session_handle = match mngr.get_session(SessionKeyPredicate::Id(session_id)).await {
            Ok(Some(h)) => h,
            Ok(None) => {
                tracing::warn!(%session_id, "shell request rejected: unknown session");
                session.channel_failure(id)?;
                return Ok(());
            }
            Err(e) => {
                tracing::warn!(%session_id, error = %e, "shell request rejected: lookup failed");
                session.channel_failure(id)?;
                return Ok(());
            }
        };

        session.channel_success(id)?;
        let hnd = session.handle();
        tokio::spawn(async move {
            if let Err(e) = session_handle.attach(conn_username, channel, config).await {
                let _ = hnd
                    .data(id, format!("Error attaching to session: {e}\r\n"))
                    .await;
                let _ = hnd.close(id).await;
            }
        });
        Ok(())
    }

    async fn subsystem_request(
        &mut self,
        id: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        protocol_trace!("Got subsystem_request on channel {id}: subsystem={name}");

        if name.starts_with(minimald_rpc::RPC_SUBSYSTEM_PREFIX) {
            let c = self.0.clone();
            let s = c.0.lock().await.serv.clone();
            rpc::handle_ssh_rpc(s, c, name, id, session).await?;
        } else if name == sftp::SUBSYSTEM_NAME {
            let c = self.0.clone();
            let s = c.0.lock().await.serv.clone();
            sftp::handle_sftp_subsystem(s, c, id, session).await?;
        } else {
            session.channel_failure(id)?;
        }

        Ok(())
    }

    async fn channel_close(&mut self, id: ChannelId, _: &mut Session) -> Result<(), Self::Error> {
        protocol_trace!("Got channel_close on channel {id}");
        self.0.0.lock().await.handle_channel_close(id)
    }

    /// SSH `LocalForward` / `direct-tcpip` handler (R4.9).
    ///
    /// When an authenticated client runs `ssh -L local:remote_host:remote_port`,
    /// OpenSSH opens a `direct-tcpip` channel requesting a TCP connection from
    /// the server side to `(host_to_connect, port_to_connect)`. This handler
    /// accepts the request, connects to the target, and relays bytes
    /// bidirectionally between the SSH channel and the upstream TCP connection.
    ///
    /// Only authenticated (local) connections may forward ports; unauthenticated
    /// connections are rejected by returning `false`.
    ///
    /// The connection attempt times out after 10 seconds; a failure rejects the
    /// channel so the SSH client receives a clean error rather than hanging.
    ///
    /// Served in every build: the `ssh-forward` feature gate is retired
    /// (NET-110), so a release build forwards ports too.
    async fn channel_open_direct_tcpip(
        &mut self,
        channel: RuChannel<Msg>,
        host_to_connect: &str,
        port_to_connect: u32,
        originator_address: &str,
        originator_port: u32,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        protocol_trace!(
            "Got channel_open_direct_tcpip: {host_to_connect}:{port_to_connect} \
             from {originator_address}:{originator_port}"
        );

        let (is_local, username, serv) = {
            let state = self.0.lock().await;
            (
                state.auth == Auth::Local,
                state.ssh_username.clone(),
                state.serv.clone(),
            )
        };

        if !is_local {
            reply
                .reject(russh::ChannelOpenFailure::AdministrativelyProhibited)
                .await;
            return Ok(());
        }

        // Validate the session identified by the SSH username (R4.9). The client
        // passes the session UUID as `-l <uuid>` so the server can confirm the
        // session exists before accepting the forward. Fail closed: a missing
        // or non-UUID username is rejected so direct-tcpip cannot be used
        // without a valid session context.
        let Some(uname) = username.as_deref() else {
            tracing::warn!("direct-tcpip rejected: no SSH username");
            reply
                .reject(russh::ChannelOpenFailure::AdministrativelyProhibited)
                .await;
            return Ok(());
        };
        let Ok(session_id) = SessionId::parse_str(uname) else {
            tracing::warn!(value = %uname, "direct-tcpip rejected: username not a session UUID");
            reply
                .reject(russh::ChannelOpenFailure::AdministrativelyProhibited)
                .await;
            return Ok(());
        };
        let mngr = serv.sessions_manager().await;
        let session = match mngr.get_session(SessionKeyPredicate::Id(session_id)).await {
            Ok(Some(session)) => session,
            Ok(None) => {
                tracing::warn!(
                    %session_id,
                    "direct-tcpip rejected: session not found"
                );
                reply
                    .reject(russh::ChannelOpenFailure::AdministrativelyProhibited)
                    .await;
                return Ok(());
            }
            Err(e) => {
                tracing::warn!(
                    %session_id,
                    error = %e,
                    "direct-tcpip rejected: session lookup failed"
                );
                reply
                    .reject(russh::ChannelOpenFailure::AdministrativelyProhibited)
                    .await;
                return Ok(());
            }
        };

        let host = host_to_connect.to_string();
        let port = match u16::try_from(port_to_connect) {
            Ok(p) => p,
            Err(_) => {
                tracing::warn!(port = port_to_connect, "direct-tcpip: port out of range");
                reply.reject(russh::ChannelOpenFailure::ConnectFailed).await;
                return Ok(());
            }
        };

        // Where the dial runs: a `host_ip` box shares the daemon's network
        // namespace, so the daemon can open the socket itself, but a box with
        // its own netns (`none`, `own_ip`) has a loopback of its own — a dial
        // from the daemon would reach the daemon, not the box — so there the
        // dial runs inside the box's namespaces.
        let site = match session.record().await {
            Ok(record) => dial_site(record.network),
            Err(e) => {
                tracing::warn!(
                    %session_id,
                    error = %e,
                    "direct-tcpip rejected: session record unreadable"
                );
                reply
                    .reject(russh::ChannelOpenFailure::AdministrativelyProhibited)
                    .await;
                return Ok(());
            }
        };

        // Bring the box-side half of the relay up before accepting the
        // channel, so a shared-netns dial can still refuse with `ConnectFailed`
        // rather than leaving an open-but-dead channel. The in-box dial cannot
        // be observed from here — the in-box process connects after the accept
        // — so it is accepted with the spawn, and a box port that refuses
        // surfaces as the relay ending at once: the client sees the connection
        // close, which is what a refused dial looks like.
        enum Upstream {
            Shared(TcpStream),
            InBox(ChildStdio),
        }
        let upstream = match site {
            DialSite::Shared => match tokio::time::timeout(
                Duration::from_secs(10),
                TcpStream::connect((host.as_str(), port)),
            )
            .await
            {
                Ok(Ok(s)) => Ok(Upstream::Shared(s)),
                Ok(Err(error)) => {
                    tracing::warn!(
                        %host,
                        port,
                        %error,
                        "direct-tcpip: could not connect to target"
                    );
                    Err(russh::ChannelOpenFailure::ConnectFailed)
                }
                Err(_) => {
                    tracing::warn!(
                        %host,
                        port,
                        "direct-tcpip: connection to target timed out"
                    );
                    Err(russh::ChannelOpenFailure::ConnectFailed)
                }
            },
            DialSite::InBox => dial_in_box(&session, uname, &host, port)
                .await
                .map(Upstream::InBox),
        };
        let upstream = match upstream {
            Ok(upstream) => upstream,
            Err(failure) => {
                reply.reject(failure).await;
                return Ok(());
            }
        };

        reply.accept().await;

        // One info line per served channel open (NET-110): the daemon log —
        // and the diagnostics bundle's tail of it — names every direct-tcpip
        // channel that relays, with the session it forwarded for and the box
        // port it reached, and where the dial ran.
        tracing::info!(
            session_id = %session_id,
            host = %host,
            port,
            dial = ?site,
            "direct-tcpip channel open: relaying bytes to the box port"
        );

        // Relay bytes bidirectionally: SSH channel ↔ upstream. The relay is
        // the session's to abort at teardown, so a session that goes away
        // takes its forwards down with it.
        let relay = match upstream {
            Upstream::Shared(socket) => tokio::spawn(relay_streams(channel.into_stream(), socket)),
            Upstream::InBox(child) => tokio::spawn(relay_streams(channel.into_stream(), child)),
        };
        session.track_forward(relay.abort_handle()).await;

        Ok(())
    }
}

/// Where a direct-tcpip dial must run, decided by the session's network mode.
#[derive(Debug, PartialEq, Eq)]
enum DialSite {
    /// The box shares the daemon's network namespace (`host_ip`): the daemon
    /// opens the socket itself.
    Shared,
    /// The box has a network namespace of its own (`none`, `own_ip`), whose
    /// `127.0.0.1` is not the daemon's: the dial runs inside the box's
    /// namespaces.
    InBox,
}

fn dial_site(network: sessions::NetworkMode) -> DialSite {
    match network {
        sessions::NetworkMode::HostNet => DialSite::Shared,
        // The modes this daemon knows, and any a newer config carries:
        // `127.0.0.1` always means inside the box, and dialing there from
        // the box is the one reading that holds for every isolated mode.
        sessions::NetworkMode::NoNet | sessions::NetworkMode::OwnIp | _ => DialSite::InBox,
    }
}

/// Dials `host:port` from inside the box's namespaces, returning the relay's
/// box-side half on success and the SSH open failure to reject the channel
/// with otherwise.
///
/// The box's namespaces are reached the one sanctioned way — a command run
/// in-session, which is the nsenter injection joining every namespace the
/// box unshared, netns included — and the dial itself is a `socat` relaying
/// the box port onto its stdio. `socat` is a baseline package, so every box
/// has it.
///
/// `session` is the session the channel is being opened for; `conn_username`
/// is its SSH username (the session's UUID), passed to `ensure_host` the way
/// the exec path does.
async fn dial_in_box(
    session: &crate::session::SessionHandle,
    conn_username: &str,
    host: &str,
    port: u16,
) -> Result<ChildStdio, russh::ChannelOpenFailure> {
    let host_handle = match session.ensure_host(conn_username.to_string()).await {
        Ok(host_handle) => host_handle,
        Err(e) => {
            tracing::warn!(
                host,
                port,
                error = %e,
                "direct-tcpip: could not bring the box up to dial from"
            );
            return Err(russh::ChannelOpenFailure::AdministrativelyProhibited);
        }
    };
    let mut command = match host_handle
        .command_in_session(
            "socat",
            [
                "-".to_string(),
                format!("TCP:{host}:{port},connect-timeout=10"),
            ],
        )
        .await
    {
        Ok(command) => command,
        Err(e) => {
            tracing::warn!(
                host,
                port,
                error = %e,
                "direct-tcpip: could not build the in-box dial"
            );
            return Err(russh::ChannelOpenFailure::ConnectFailed);
        }
    };
    use std::process::Stdio;
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let child = match tokio::process::Command::from(command)
        .kill_on_drop(true)
        .spawn()
    {
        Ok(child) => child,
        Err(e) => {
            tracing::warn!(
                host,
                port,
                error = %e,
                "direct-tcpip: could not start the in-box dial"
            );
            return Err(russh::ChannelOpenFailure::ConnectFailed);
        }
    };
    Ok(ChildStdio::new(child))
}

/// The box-side half of an in-box dial: the piped stdio of the injected
/// relay process. Reads are the bytes the box port sent back; writes are the
/// bytes being forwarded to it.
///
/// The child is held — boxed, so this stays `Unpin` for [`relay_streams`] —
/// because its drop is the kill: `kill_on_drop` on the injection shim, whose
/// PDEATHSIG takes the in-box program with it. Never read on purpose.
struct ChildStdio {
    stdin: tokio::process::ChildStdin,
    stdout: tokio::process::ChildStdout,
    _child: Pin<Box<tokio::process::Child>>,
}

impl ChildStdio {
    fn new(mut child: tokio::process::Child) -> Self {
        let stdin = child.stdin.take().expect("stdin was piped");
        let stdout = child.stdout.take().expect("stdout was piped");
        Self {
            stdin,
            stdout,
            _child: Box::pin(child),
        }
    }
}

impl AsyncRead for ChildStdio {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stdout).poll_read(cx, buf)
    }
}

impl AsyncWrite for ChildStdio {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.stdin).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stdin).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stdin).poll_shutdown(cx)
    }
}

/// Relay bytes bidirectionally between two async streams, logging any relay error.
async fn relay_streams<A, B>(mut a: A, mut b: B)
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    if let Err(e) = tokio::io::copy_bidirectional(&mut a, &mut b).await {
        tracing::debug!(error = %e, "direct-tcpip relay ended with error");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn relay_streams_forwards_bytes_bidirectionally() {
        let (mut client, relay_client) = tokio::io::duplex(4096);
        let (mut server, relay_server) = tokio::io::duplex(4096);

        tokio::spawn(relay_streams(relay_client, relay_server));

        client.write_all(b"hello").await.unwrap();
        let mut buf = [0u8; 5];
        server.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello");

        server.write_all(b"world").await.unwrap();
        let mut buf2 = [0u8; 5];
        client.read_exact(&mut buf2).await.unwrap();
        assert_eq!(&buf2, b"world");
    }

    /// A `direct-tcpip` channel to a box port relays bytes in the default,
    /// featureless build — the configuration a release build ships — because
    /// nothing about the handler is behind a feature anymore (NET-110). The
    /// open logs one info line naming the session it forwarded for and the
    /// port it reached.
    #[tokio::test]
    async fn direct_tcpip_served_in_release() {
        use russh::keys::PublicKeyOrCertificate;
        use tokio::net::{TcpListener, UnixStream};

        use crate::test_harness::{TestServer, captured_log, create_session_req};

        // Install the capture subscriber before the open happens: the global
        // subscriber must already exist when the info line is emitted.
        let log = captured_log();

        // The box port: a loopback listener echoing whatever it receives.
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 64];
            loop {
                match sock.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => sock.write_all(&buf[..n]).await.unwrap(),
                }
            }
        });

        // The session the forward is scoped to: the SSH username carries its
        // UUID, exactly as `ssh -l <uuid> -L ...` does.
        let server = TestServer::new().await;
        let req = create_session_req("direct-tcpip", "/tmp");
        let session_id = server
            .state
            .sessions_manager()
            .await
            .create_session(req.config, None)
            .await
            .unwrap();

        // `TestClient` keeps its russh handle private and this test needs the
        // raw `channel_open_direct_tcpip`, so drive both halves of the
        // connection the way `TestServer::connect` does.
        struct ForwardHandler;
        impl russh::client::Handler for ForwardHandler {
            type Error = russh::Error;
            async fn check_server_key(
                &mut self,
                _key: &PublicKeyOrCertificate,
            ) -> Result<bool, Self::Error> {
                Ok(true)
            }
        }

        let host_key = server.state.host_key().await.unwrap();
        let russh_config = Arc::new(russh::server::Config {
            keys: vec![host_key],
            auth_rejection_time_initial: Some(Duration::ZERO),
            nodelay: true,
            ..Default::default()
        });
        let (server_side, client_side) = UnixStream::pair().unwrap();
        let server_setup = {
            let state = server.state.clone();
            let russh_config = russh_config.clone();
            async move {
                let (_conn, session_fut) =
                    Connection::from_stream(server_side, russh_config, state, true)
                        .await
                        .expect("handshake over the in-memory pair");
                tokio::spawn(session_fut);
            }
        };
        let client_setup = russh::client::connect_stream(
            Arc::new(russh::client::Config::default()),
            client_side,
            ForwardHandler,
        );
        let (_, handle) = tokio::join!(server_setup, client_setup);
        let mut handle = handle.unwrap();
        let auth = handle
            .authenticate_none(&session_id.to_string())
            .await
            .unwrap();
        assert!(auth.success(), "auth_none should succeed on local UDS");

        // The point of the test: the channel opens in a build with no
        // features, and bytes relay through it to the box port and back.
        let channel = handle
            .channel_open_direct_tcpip("127.0.0.1", port.into(), "127.0.0.1", 0)
            .await
            .expect("direct-tcpip must open in the default (release) build");
        let mut channel = channel.into_stream();
        channel.write_all(b"ping").await.unwrap();
        let mut echoed = [0u8; 4];
        channel.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"ping", "the box port must echo the relayed bytes");

        // Observability (NET-110): the open's info line names the session and
        // the box port it reached.
        let logged = log.contents();
        let line = logged
            .lines()
            .find(|l| l.contains("direct-tcpip channel open"))
            .unwrap_or_else(|| {
                panic!("expected a direct-tcpip channel-open info line, got: {logged}")
            });
        assert!(
            line.contains(&format!("session_id={session_id}")),
            "the open line must name the session, got: {line}"
        );
        assert!(
            line.contains(&format!("port={port}")),
            "the open line must name the box port, got: {line}"
        );
    }

    /// A session with a network namespace of its own (`none`) dials its box
    /// port from inside the box: `127.0.0.1` in the box is not the daemon's
    /// loopback, so the dial goes out through the one sanctioned door into
    /// the box's namespaces — a command run in-session — and comes back as
    /// the relay's box-side stdio. In this harness the in-session command is
    /// the host-side stand-in (MockLauncher builds it host-side under
    /// `cfg(test)`); what the test pins is the path the production dial takes:
    /// the session's host is minted, the relay program is `socat` (a baseline
    /// package, so every box has it), and the channel relays through it. The
    /// open line then records where the dial ran, and destroying the session
    /// aborts the forward with it (NET-105's daemon half).
    #[tokio::test]
    async fn direct_tcpip_dials_inside_box_netns() {
        use russh::keys::PublicKeyOrCertificate;
        use tokio::net::{TcpListener, UnixStream};

        use crate::test_harness::{TestServer, captured_log, create_session_req, unwrap_ready};

        // Install the capture subscriber before the open happens: the global
        // subscriber must already exist when the info line is emitted.
        let log = captured_log();

        // The box port: a loopback listener echoing whatever it receives.
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 64];
            loop {
                match sock.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => sock.write_all(&buf[..n]).await.unwrap(),
                }
            }
        });

        let server = TestServer::new().await;

        // An `Active` session with its own netns. The create flow is inlined
        // because the request must carry `none` — the harness's builders
        // default to the shared-netns mode the release test covers.
        let mut req = create_session_req("direct-tcpip-netns", "/tmp");
        req.config.network = sessions::NetworkMode::NoNet;
        use minimald_rpc::{
            ConfigureLoadout, ConfigureLoadoutRequest, CreateSession, Errorable, FinalizeSession,
            FinalizeSessionRequest,
        };
        let mut client = server.connect().await;
        let session_id = match client.call::<CreateSession>(&req).await {
            Errorable::Ok(r) => r.id,
            Errorable::Err { error } => panic!("CreateSession failed: {error}"),
        };
        unwrap_ready(
            client
                .call::<ConfigureLoadout>(&ConfigureLoadoutRequest {
                    session_id,
                    contribution: Default::default(),
                })
                .await
                .unwrap(),
        );
        match client
            .call::<FinalizeSession>(&FinalizeSessionRequest { session_id })
            .await
        {
            Errorable::Ok(_) => {}
            Errorable::Err { error } => panic!("FinalizeSession failed: {error}"),
        }

        // `TestClient` keeps its russh handle private and this test needs the
        // raw `channel_open_direct_tcpip`, so drive both halves of the
        // connection the way `TestServer::connect` does.
        struct ForwardHandler;
        impl russh::client::Handler for ForwardHandler {
            type Error = russh::Error;
            async fn check_server_key(
                &mut self,
                _key: &PublicKeyOrCertificate,
            ) -> Result<bool, Self::Error> {
                Ok(true)
            }
        }

        let host_key = server.state.host_key().await.unwrap();
        let russh_config = Arc::new(russh::server::Config {
            keys: vec![host_key],
            auth_rejection_time_initial: Some(Duration::ZERO),
            nodelay: true,
            ..Default::default()
        });
        let (server_side, client_side) = UnixStream::pair().unwrap();
        let server_setup = {
            let state = server.state.clone();
            let russh_config = russh_config.clone();
            async move {
                let (_conn, session_fut) =
                    Connection::from_stream(server_side, russh_config, state, true)
                        .await
                        .expect("handshake over the in-memory pair");
                tokio::spawn(session_fut);
            }
        };
        let client_setup = russh::client::connect_stream(
            Arc::new(russh::client::Config::default()),
            client_side,
            ForwardHandler,
        );
        let (_, handle) = tokio::join!(server_setup, client_setup);
        let mut handle = handle.unwrap();
        let auth = handle
            .authenticate_none(&session_id.to_string())
            .await
            .unwrap();
        assert!(auth.success(), "auth_none should succeed on local UDS");

        // The point of the test: the channel dials through the box's
        // namespaces, and bytes relay through it to the box port and back.
        let channel = handle
            .channel_open_direct_tcpip("127.0.0.1", port.into(), "127.0.0.1", 0)
            .await
            .expect("the in-box dial must open the channel");
        let mut channel = channel.into_stream();
        channel.write_all(b"ping").await.unwrap();
        let mut echoed = [0u8; 4];
        channel.read_exact(&mut echoed).await.unwrap();
        assert_eq!(
            &echoed, b"ping",
            "the box port must echo the relayed bytes through the in-box dial"
        );

        // Observability: the open's info line names the session, the box
        // port, and where the dial ran.
        let logged = log.contents();
        let line = logged
            .lines()
            .find(|l| l.contains("direct-tcpip channel open"))
            .unwrap_or_else(|| {
                panic!("expected a direct-tcpip channel-open info line, got: {logged}")
            });
        assert!(
            line.contains(&format!("session_id={session_id}")),
            "the open line must name the session, got: {line}"
        );
        assert!(
            line.contains(&format!("port={port}")),
            "the open line must name the box port, got: {line}"
        );
        assert!(
            line.contains("dial=InBox"),
            "the open line must record the dial as in-box, got: {line}"
        );

        // NET-105's daemon half: teardown aborts the session's forwards, so
        // the channel the forward was relaying ends with the session.
        let mngr = server.state.sessions_manager().await;
        let session = mngr
            .get_session(SessionKeyPredicate::Id(session_id))
            .await
            .unwrap()
            .expect("the session exists until destroyed");
        session.destroy().await.unwrap();
        let mut end = [0u8; 1];
        let n = tokio::time::timeout(Duration::from_secs(5), channel.read(&mut end))
            .await
            .expect("the channel must close with the session")
            .expect("read on the channel after teardown");
        assert_eq!(n, 0, "the forward's channel must see EOF, not more bytes");
    }
}
