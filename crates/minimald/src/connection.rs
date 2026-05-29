use russh::{
    Channel as RuChannel, ChannelId,
    server::{Config as RuConfig, Msg, RunningSession, Session},
};
use std::{
    collections::BTreeMap,
    fmt,
    sync::{Arc, LazyLock},
};
use tokio::{
    net::UnixStream,
    sync::{Mutex, MutexGuard},
};

use crate::{
    ChannelConfig, RequestedPty,
    rpc::{self},
    server::ServerStateHandle,
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
    pub(crate) async fn from_socket(
        s: UnixStream,
        c: Arc<RuConfig>,
        serv: ServerStateHandle,
        was_local_uds: bool,
    ) -> (ConnectionHandle, RunningSession<ConnectionHandler>) {
        let h = ConnectionHandle(Arc::new(Mutex::new(Self {
            auth: if was_local_uds {
                Auth::Local
            } else {
                Auth::Pending
            },
            ssh_username: None,
            channels: BTreeMap::new(),
            serv,
        })));

        (
            h.clone(),
            russh::server::run_stream(c, s, ConnectionHandler(h))
                .await
                .unwrap(),
        )
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
#[derive(Clone)]
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
            ConnectionError::Json(e) => write!(f, "Serialization error: {}", e),
            ConnectionError::SetupAfterInitiation => write!(
                f,
                "Protocol error: Attempted channel configuration after initialization",
            ),
        }
    }
}

impl std::error::Error for ConnectionError {}

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
        session.channel_failure(id)?; // TODO: handle exec request
        Ok(())
    }

    async fn shell_request(
        &mut self,
        id: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        protocol_trace!("Got shell_request on channel {id}");
        session.channel_failure(id)?; // TODO: handle shell request
        Ok(())
    }

    async fn subsystem_request(
        &mut self,
        id: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        protocol_trace!("Got subsystem_request on channel {id}: subsystem={name}");

        if name.starts_with(rpc::RPC_SUBSYSTEM_PREFIX) {
            let c = self.0.clone();
            let s = c.0.lock().await.serv.clone();
            rpc::handle_ssh_rpc(s, c, name, id, session).await?;
        } else {
            session.channel_failure(id)?;
        }

        Ok(())
    }

    async fn channel_close(&mut self, id: ChannelId, _: &mut Session) -> Result<(), Self::Error> {
        protocol_trace!("Got channel_close on channel {id}");
        self.0.0.lock().await.handle_channel_close(id)
    }
}
