use russh::keys::key::safe_rng;
use russh::keys::{PrivateKey, ssh_key::Error as KeyError};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::UnixListener;
use tokio::task::JoinSet;

use crate::connection::Connection;

/// The host private key for the SSH server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostKey {
    /// Randomly-generated when needed.
    Ephemeral,
    /// An OpenSSH-formatted PEM private key.
    Raw(String),
    /// A path to an OpenSSH-formatted PEM private key.
    Path(PathBuf),
}

/// Global Configuration for the minimald server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub host_key: HostKey,
    pub minimal_dir: PathBuf,
}

impl Config {
    /// Returns the SSH host key to use.
    pub fn host_key(&self) -> Result<PrivateKey, KeyError> {
        match &self.host_key {
            HostKey::Ephemeral => {
                let key = PrivateKey::random(&mut safe_rng(), russh::keys::Algorithm::Ed25519)?;
                Ok(key)
            }
            HostKey::Path(path) => Ok(PrivateKey::read_openssh_file(path)?),
            HostKey::Raw(r) => Ok(PrivateKey::from_openssh(r.as_bytes())?),
        }
    }
}

/// A listening minimald server.
#[derive(Debug)]
pub struct Server {
    config: Config,
    listener: UnixListener,
}

impl Server {
    /// Launches minimald, listening for connections on the given UDS socket.
    pub async fn run_on_uds(config: Config, listener: UnixListener) -> Result<(), std::io::Error> {
        Server { config, listener }.run().await
    }

    async fn run(self) -> Result<(), std::io::Error> {
        let russh_config = Arc::new(russh::server::Config {
            keys: vec![self.config.host_key().unwrap()],
            auth_rejection_time_initial: Some(std::time::Duration::ZERO),
            ..Default::default()
        });

        let mut session_set = JoinSet::new();
        loop {
            let (socket, _) = self.listener.accept().await?;
            let (_conn_hnd, session_fut) =
                Connection::from_socket(socket, russh_config.clone(), true).await;
            session_set.spawn(session_fut);
        }
    }
}
