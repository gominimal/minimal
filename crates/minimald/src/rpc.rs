use russh::{
    Channel as RuChannel, ChannelId,
    server::{Msg, Session},
};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::connection::{ConnectionError, ConnectionHandle};

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

    /// Helper to deserialize the request and serialize the response
    /// down the given SSH channel, calling the provided handler function
    /// to compute the response.
    async fn handle_channel<F>(&self, c: RuChannel<Msg>, handler: F) -> Result<(), ConnectionError>
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

impl GetVersion {
    pub async fn handle(self, c: RuChannel<Msg>) -> Result<(), ConnectionError> {
        self.handle_channel(c, |_req| {
            Ok(GetVersionResponse {
                version: env!("CARGO_PKG_VERSION").to_string(),
                long_version: env!("LONG_VERSION").to_string(),
                stdlib_version: stdlib::VERSION.to_string(),
            })
        })
        .await
    }
}

/// Handles an RPC going over an SSH subsystem channel.
///
/// This method takes ownership of the ssh channel, including
/// reading and writing the request/response respectively, as well
/// as indicating if the subsystem request was successful (RPC known)
/// or not (RPC not known, channel request fails).
///
/// The caller should not hold any locks, neither to the Connection nor
/// the Server.
pub async fn handle_ssh_rpc(
    c: ConnectionHandle,
    name: &str,
    id: ChannelId,
    session: &mut Session,
) -> Result<(), ConnectionError> {
    // Take the channel from connection state if its a known RPC.
    let channel = match name {
        GetVersion::NAME => {
            let mut conn_lock = c.lock().await;
            let c_hnd = match conn_lock.take(id) {
                None => {
                    session.channel_failure(id)?;
                    return Ok(());
                }
                Some((channel, _p)) => channel,
            };
            drop(conn_lock);
            session.channel_success(id)?;
            Some(c_hnd)
        }
        _ => {
            session.channel_failure(id)?;
            None
        }
    };
    let channel = match channel {
        Some(c) => c,
        None => return Ok(()),
    };

    // Handle the named RPC.
    match name {
        GetVersion::NAME => tokio::task::spawn(GetVersion.handle(channel)),
        _ => unreachable!(),
    };

    Ok(())
}
