use russh::server::{Config as RuConfig, RunningSession};
pub use std::sync::{Arc, Mutex};
use tokio::net::UnixStream;

/// The auth state of the SSH connection.
#[derive(Debug, Default, PartialEq, Eq)]
pub enum Auth {
    #[default]
    Pending,
    Local,
}

/// Represents the SSH connection. Lives for the
/// lifetime of the connection.
#[derive(Debug, Default)]
#[allow(dead_code)]
pub struct Connection {
    pub auth: Auth,

    /// The username given via SSH. Not populated till the client
    /// authenticates the connection.
    pub ssh_username: Option<String>,
}

impl Connection {
    pub(crate) async fn from_socket(
        s: UnixStream,
        c: Arc<RuConfig>,
        was_local_uds: bool,
    ) -> (ConnectionHandle, RunningSession<ConnectionHandler>) {
        let h = ConnectionHandle(Arc::new(Mutex::new(Self {
            auth: if was_local_uds {
                Auth::Local
            } else {
                Auth::Pending
            },
            ..Default::default()
        })));

        (
            h.clone(),
            russh::server::run_stream(c, s, ConnectionHandler(h))
                .await
                .unwrap(),
        )
    }
}

/// A thread-safe handle to the connection.
#[derive(Clone)]
pub struct ConnectionHandle(Arc<Mutex<Connection>>);

/// An error when handling the SSH connection.
#[derive(Debug)]
#[allow(dead_code)]
pub enum ConnectionError {
    Protocol(russh::Error),
}

impl From<russh::Error> for ConnectionError {
    fn from(value: russh::Error) -> Self {
        ConnectionError::Protocol(value)
    }
}

/// A [`russh::server::Handler`] for a [`Connection`].
pub struct ConnectionHandler(ConnectionHandle);

impl russh::server::Handler for ConnectionHandler {
    type Error = ConnectionError;

    async fn auth_none(&mut self, user: &str) -> Result<russh::server::Auth, Self::Error> {
        let mut s = self.0.0.lock().unwrap();
        if s.auth == Auth::Local {
            s.ssh_username = Some(user.to_string());
            Ok(russh::server::Auth::Accept)
        } else {
            Ok(russh::server::Auth::reject())
        }
    }
}
