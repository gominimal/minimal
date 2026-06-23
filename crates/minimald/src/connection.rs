use russh::{
    Channel as RuChannel, ChannelId,
    server::{Config as RuConfig, Msg, RunningSession, Session},
};
use sessions::SessionId;
use std::{
    collections::BTreeMap,
    fmt,
    sync::{Arc, LazyLock},
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
#[allow(dead_code)]
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
#[allow(dead_code)]
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
#[allow(dead_code)]
pub struct Connection {
    /// The current authentication state of this connection.
    pub auth: Auth,
    /// The username given via SSH. Not populated till the client
    /// authenticates the connection.
    pub ssh_username: Option<String>,

    /// State specific to an SSH channel.
    channels: BTreeMap<ChannelId, Channel>,

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
}

/// An error when handling the SSH connection.
#[derive(Debug)]
#[allow(dead_code)]
pub enum ConnectionError {
    /// A protocol error.
    Protocol(russh::Error),
    /// An internal error.
    Internal(String),

    /// Failed to (de)serialize a JSON-encoded RPC message.
    Json(serde_json::Error),

    /// An operation was attempted after the session was launched
    /// (i.e. setting env vars after exec), which is both non-sensical and
    /// heavily implied by RFC 4254 to be invalid.
    SetupAfterInitiation,
}

impl From<russh::Error> for ConnectionError {
    fn from(value: russh::Error) -> Self {
        ConnectionError::Protocol(value)
    }
}

impl From<serde_json::Error> for ConnectionError {
    fn from(value: serde_json::Error) -> Self {
        ConnectionError::Json(value)
    }
}

impl fmt::Display for ConnectionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectionError::Protocol(e) => write!(f, "Protocol error: {}", e),
            ConnectionError::Internal(e) => write!(f, "Internal error: {}", e),
            ConnectionError::Json(e) => write!(f, "Serialization error: {}", e),
            ConnectionError::SetupAfterInitiation => write!(
                f,
                "Protocol error: Attempted channel configuration after initialization",
            ),
        }
    }
}

impl std::error::Error for ConnectionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ConnectionError::Protocol(e) => Some(e),
            ConnectionError::Json(e) => Some(e),
            ConnectionError::Internal(_) => None,
            ConnectionError::SetupAfterInitiation => None,
        }
    }
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
        _: &mut Session,
    ) -> Result<bool, Self::Error> {
        let mut s = self.0.lock().await;
        if s.auth != Auth::Local {
            return Ok(false); // indicate failure
        }

        protocol_trace!("Minting session channel with id {}", c.id());
        s.channels.insert(c.id(), Channel::new_session(c.id(), c));

        Ok(true) // indicate success
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
    async fn channel_open_direct_tcpip(
        &mut self,
        channel: RuChannel<Msg>,
        host_to_connect: &str,
        port_to_connect: u32,
        originator_address: &str,
        originator_port: u32,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        protocol_trace!(
            "Got channel_open_direct_tcpip: {host_to_connect}:{port_to_connect} \
             from {originator_address}:{originator_port}"
        );

        if self.0.lock().await.auth != Auth::Local {
            return Ok(false);
        }

        let host = host_to_connect.to_string();
        let port = match u16::try_from(port_to_connect) {
            Ok(p) => p,
            Err(_) => {
                tracing::warn!(port = port_to_connect, "direct-tcpip: port out of range");
                return Ok(false);
            }
        };

        // Connect to the target before accepting the channel. If the target is
        // unreachable within the grace period, reject rather than leaving the
        // client with an open-but-dead channel.
        let upstream = match tokio::time::timeout(
            Duration::from_secs(10),
            TcpStream::connect((host.as_str(), port)),
        )
        .await
        {
            Ok(Ok(s)) => s,
            Ok(Err(error)) => {
                tracing::warn!(
                    %host,
                    port,
                    %error,
                    "direct-tcpip: could not connect to target"
                );
                return Ok(false);
            }
            Err(_) => {
                tracing::warn!(
                    %host,
                    port,
                    "direct-tcpip: connection to target timed out"
                );
                return Ok(false);
            }
        };

        // Relay bytes bidirectionally: SSH channel ↔ upstream TCP.
        tokio::spawn(async move {
            let mut stream = channel.into_stream();
            let mut up = upstream;
            if let Err(e) = tokio::io::copy_bidirectional(&mut stream, &mut up).await {
                tracing::debug!(error = %e, "direct-tcpip relay ended with error");
            }
        });

        Ok(true)
    }
}
