use russh::{Channel as RuChannel, server::Msg};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::connection::ConnectionError;

pub const RPC_SUBSYSTEM_PREFIX: &str = "minimald-v1-";

/// Describes a minimal-specific RPC method sent over ssh.
///
/// Oneshot RPCs are not streaming.
pub(crate) trait OneshotSshRpc {
    /// The subsystem name used to call for this RPC.
    const NAME: &'static str;
    /// The type schema of the request.
    type Request<'a>: Deserialize<'a>;
    /// The type schema of the response.
    type Response: Serialize;

    async fn handle<F>(&self, c: RuChannel<Msg>, handler: F) -> Result<(), ConnectionError>
    where
        F: for<'a> FnOnce(Self::Request<'a>) -> Result<Self::Response, ConnectionError>,
    {
        let mut stream = c.into_stream();

        let mut buf = Vec::with_capacity(1024);
        stream
            .read_to_end(&mut buf)
            .await
            .map_err(russh::Error::from)?;

        let request: Self::Request<'_> = serde_json::from_slice(&buf)?;
        let response = handler(request)?;
        let response_bytes = serde_json::to_vec(&response)?;

        stream
            .write_all(&response_bytes)
            .await
            .map_err(russh::Error::from)?;
        stream.flush().await.map_err(russh::Error::from)?;
        stream.shutdown().await.map_err(russh::Error::from)?;
        Ok(())
    }
}

/// An RPC to get the version of minimald.
pub struct GetVersion;

/// The response to the [`GetVersion`] RPC.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetVersionResponse {
    pub version: String,
    pub long_version: String,
    pub stdlib_version: String,
}

impl OneshotSshRpc for GetVersion {
    const NAME: &'static str = constcat::concat!(RPC_SUBSYSTEM_PREFIX, "GetVersion");
    type Request<'a> = ();
    type Response = GetVersionResponse;
}
