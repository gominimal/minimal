use russh::{
    Channel as RuChannel, ChannelId,
    server::{ChannelOpenHandle, Config as RuConfig, Msg, RunningSession, Session},
};
use sessions::SessionId;
use std::time::Duration;
use std::{
    collections::BTreeMap,
    sync::{Arc, LazyLock},
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

    /// SSH `LocalForward` / `direct-tcpip` handler.
    ///
    /// When an authenticated client opens a local forward, OpenSSH (and
    /// `min net forward`) opens a `direct-tcpip` channel requesting a TCP
    /// connection from the server side to `(host_to_connect, port_to_connect)`.
    /// This handler accepts the request, connects to the target, and relays
    /// bytes bidirectionally between the SSH channel and the upstream TCP
    /// connection.
    ///
    /// Served in every build: a forward is how a port inside a box is reached
    /// from the host, so a release daemon that rejected the channel would leave
    /// the client with no path to it at all.
    ///
    /// Only authenticated (local) connections may forward ports; an
    /// unauthenticated one is rejected. Every open is logged once with the
    /// session it is scoped to, the target port, and how it ended, so a forward
    /// that never carries bytes can be told from one that was refused.
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
            tracing::warn!("direct-tcpip rejected: connection is not authenticated");
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
        match mngr.get_session(SessionKeyPredicate::Id(session_id)).await {
            Ok(Some(_)) => {}
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
        }

        let host = host_to_connect.to_string();
        let port = match u16::try_from(port_to_connect) {
            Ok(p) => p,
            Err(_) => {
                tracing::warn!(port = port_to_connect, "direct-tcpip: port out of range");
                reply.reject(russh::ChannelOpenFailure::ConnectFailed).await;
                return Ok(());
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
                reply.reject(russh::ChannelOpenFailure::ConnectFailed).await;
                return Ok(());
            }
            Err(_) => {
                tracing::warn!(
                    %host,
                    port,
                    "direct-tcpip: connection to target timed out"
                );
                reply.reject(russh::ChannelOpenFailure::ConnectFailed).await;
                return Ok(());
            }
        };

        reply.accept().await;

        // One record per accepted open, naming the session and the target port:
        // this is the only trace a forward leaves, and a forward that relays no
        // bytes is otherwise indistinguishable from one that never opened.
        tracing::info!(
            %session_id,
            %host,
            port,
            outcome = "accepted",
            "direct-tcpip channel open"
        );

        // Relay bytes bidirectionally: SSH channel ↔ upstream TCP.
        tokio::spawn(relay_streams(channel.into_stream(), upstream));

        Ok(())
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

    /// NET-110: a `direct-tcpip` channel is served by a daemon built with no
    /// extra features — the shape a release binary has.
    ///
    /// The handler used to sit behind an off-by-default `ssh-forward` feature,
    /// so a shipped daemon rejected every forward and there was nothing for a
    /// local forward to relay over. This drives a real forward end to end: a
    /// listener stands in for a server inside the box, and the bytes go out
    /// over the SSH channel and come back.
    #[tokio::test]
    async fn direct_tcpip_served_in_release() {
        use crate::test_harness::{TestServer, create_configured_session};
        use tokio::net::TcpListener;

        // The target "inside the box": answers what it is sent, uppercased.
        let backend = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let port = u32::from(backend.local_addr().unwrap().port());
        tokio::spawn(async move {
            let (mut sock, _) = backend.accept().await.unwrap();
            let mut received = [0u8; 5];
            sock.read_exact(&mut received).await.unwrap();
            sock.write_all(&received.to_ascii_uppercase())
                .await
                .unwrap();
        });

        let server = TestServer::new().await;
        let mut client = server.connect().await;
        let session_id = create_configured_session(&mut client, "forward-test", "/tmp").await;

        // A forward names its session in the SSH username, which is what the
        // handler's auth gate reads.
        let mut forwarder = server.connect_as(&session_id.to_string()).await;
        let channel = forwarder
            .open_direct_tcpip("127.0.0.1", port)
            .await
            .expect("a build with no extra features must serve direct-tcpip");

        let mut stream = channel.into_stream();
        stream.write_all(b"hello").await.unwrap();
        let mut relayed = [0u8; 5];
        stream.read_exact(&mut relayed).await.unwrap();
        assert_eq!(&relayed, b"HELLO", "the forward relayed nothing back");

        // Serving the channel is not serving it to anyone: a forward naming no
        // live session is still refused.
        let mut stranger = server.connect_as(&SessionId::nil().to_string()).await;
        assert!(
            stranger.open_direct_tcpip("127.0.0.1", port).await.is_err(),
            "a forward naming no live session must be rejected"
        );
    }

    /// NET-104's daemon half: `min net forward` holds one connection open and
    /// opens a channel per connection its local listener accepts, so the
    /// daemon has to relay each one on its own — half-close included, which is
    /// what a request read to EOF and answered depends on.
    #[tokio::test]
    async fn direct_tcpip_relays_for_net_forward() {
        use crate::test_harness::{TestServer, create_configured_session};
        use tokio::net::TcpListener;

        // The server "inside the box": reads a whole request up to EOF, then
        // answers it uppercased and closes, as a request/response server does.
        let backend = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let port = u32::from(backend.local_addr().unwrap().port());
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = backend.accept().await {
                tokio::spawn(async move {
                    let mut request = Vec::new();
                    sock.read_to_end(&mut request).await.unwrap();
                    sock.write_all(&request.to_ascii_uppercase()).await.unwrap();
                    sock.shutdown().await.unwrap();
                });
            }
        });

        let server = TestServer::new().await;
        let mut client = server.connect().await;
        let session_id = create_configured_session(&mut client, "net-forward", "/tmp").await;

        // One connection, authenticated as the session the forward speaks for,
        // carrying a channel per forwarded connection.
        let mut forwarder = server.connect_as(&session_id.to_string()).await;
        for request in ["first", "second"] {
            let channel = forwarder
                .open_direct_tcpip("127.0.0.1", port)
                .await
                .expect("the daemon must serve a channel per forwarded connection");
            let mut stream = channel.into_stream();
            stream.write_all(request.as_bytes()).await.unwrap();
            // The half-close the box's server reads to; without it relayed,
            // the read below never returns.
            stream.shutdown().await.unwrap();
            let mut answer = Vec::new();
            stream.read_to_end(&mut answer).await.unwrap();
            assert_eq!(
                answer,
                request.to_ascii_uppercase().into_bytes(),
                "the forward relayed back {:?} for {request:?}",
                String::from_utf8_lossy(&answer)
            );
        }
    }
}
