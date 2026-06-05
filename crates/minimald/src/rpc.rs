use russh::{
    Channel as RuChannel, ChannelId,
    server::{Msg, Session},
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sessions::SessionId;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::task::spawn;

use crate::{
    connection::{ConnectionError, ConnectionHandle},
    server::ServerStateHandle,
};

pub const RPC_SUBSYSTEM_PREFIX: &str = "minimald-v1-";

/// Describes a minimal-specific RPC method sent over ssh.
///
/// Oneshot RPCs are not streaming.
pub(crate) trait OneshotSshRpc {
    /// The subsystem name used to call for this RPC.
    const NAME: &'static str;
    /// The type schema of the request.
    ///
    /// Bound on `Serialize` exists so that clients (including the test
    /// harness) can encode requests through the same type the handler
    /// decodes them with.
    type Request<'a>: Deserialize<'a> + Serialize;
    /// The type schema of the response.
    ///
    /// Bound on `DeserializeOwned` exists for symmetry with `Request`:
    /// clients decode the same type the handler emitted.
    type Response: Serialize + DeserializeOwned;

    /// Helper to deserialize the request and serialize the response
    /// down the given SSH channel, calling the provided async handler
    /// function to compute the response.
    async fn handle_channel<F>(&self, c: RuChannel<Msg>, handler: F) -> Result<(), ConnectionError>
    where
        F: for<'a> AsyncFnOnce(Self::Request<'a>) -> Result<Self::Response, ConnectionError>,
    {
        let mut stream = c.into_stream();

        let mut buf = Vec::with_capacity(1024);
        stream
            .read_to_end(&mut buf)
            .await
            .map_err(russh::Error::from)?;

        let request: Self::Request<'_> = serde_json::from_slice(&buf)?;
        let response = handler(request).await?;
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
    pub async fn handle(self, c: RuChannel<Msg>) {
        let res = self
            .handle_channel(c, async |_req| {
                Ok(GetVersionResponse {
                    version: env!("CARGO_PKG_VERSION").to_string(),
                    long_version: env!("LONG_VERSION").to_string(),
                    stdlib_version: stdlib::VERSION.to_string(),
                })
            })
            .await;
        if let Err(e) = res {
            tracing::warn!("RPC handler for {} failed: {}", Self::NAME, e);
        }
    }
}

/// An RPC to list sessions managed by this minimald.
pub struct ListSessions;

/// An entry in the ListSessions response.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ListSessionsEntry {
    pub id: SessionId,
    pub name: Option<String>,
}

/// The response to the [`ListSessions`] RPC.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListSessionsResponse {
    pub sessions: Vec<ListSessionsEntry>,
}

impl OneshotSshRpc for ListSessions {
    const NAME: &'static str = constcat::concat!(RPC_SUBSYSTEM_PREFIX, "ListSessions");
    type Request<'a> = ();
    type Response = ListSessionsResponse;
}

impl ListSessions {
    pub async fn handle(self, s: ServerStateHandle, c: RuChannel<Msg>) {
        let res = self
            .handle_channel(c, async |_req| {
                let mngr = s.sessions_manager().await;
                Ok(ListSessionsResponse {
                    sessions: mngr
                        .list()
                        .await
                        .map_err(|e| ConnectionError::Internal(e.to_string()))?
                        .into_iter()
                        .map(|i| ListSessionsEntry {
                            id: i.id,
                            name: i.name,
                        })
                        .collect(),
                })
            })
            .await;
        if let Err(e) = res {
            tracing::warn!("RPC handler for {} failed: {}", Self::NAME, e);
        }
    }
}

/// An RPC to read the session record for a session corresponding to the request.
pub struct GetSessionRecord;

/// The request for a [`GetSessionRecord`] RPC.
///
/// Serialized examples:
///
///  * `{"name": "my-session"}`
///  * `{"id": "<some-uuid>"}`
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GetSessionRecordRequest {
    Name(String),
    Id(SessionId),
}

/// The response for a [`GetSessionRecord`] RPC.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetSessionRecordResponse {
    pub record: Option<sessions::Record>,
}

impl OneshotSshRpc for GetSessionRecord {
    const NAME: &'static str = constcat::concat!(RPC_SUBSYSTEM_PREFIX, "GetSessionRecord");
    type Request<'a> = GetSessionRecordRequest;
    type Response = GetSessionRecordResponse;
}

impl GetSessionRecord {
    pub async fn handle(self, s: ServerStateHandle, c: RuChannel<Msg>) {
        use crate::sessions::SessionKeyPredicate;
        let res = self
            .handle_channel(c, async |req| {
                let mngr = s.sessions_manager().await;
                Ok(GetSessionRecordResponse {
                    record: mngr
                        .get_record(match req {
                            GetSessionRecordRequest::Id(id) => SessionKeyPredicate::Id(id),
                            GetSessionRecordRequest::Name(name) => SessionKeyPredicate::Name(name),
                        })
                        .await
                        .map_err(|e| ConnectionError::Internal(e.to_string()))?,
                })
            })
            .await;
        if let Err(e) = res {
            tracing::warn!("RPC handler for {} failed: {}", Self::NAME, e);
        }
    }
}

/// An RPC to create a new session based on the given record.
pub struct CreateSession;

/// The request for a [`CreateSession`] RPC.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateSessionRequest {
    pub record: sessions::Record,
}

/// The response for a [`CreateSession`] RPC.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateSessionResponse {
    pub id: SessionId,
}

impl OneshotSshRpc for CreateSession {
    const NAME: &'static str = constcat::concat!(RPC_SUBSYSTEM_PREFIX, "CreateSession");
    type Request<'a> = CreateSessionRequest;
    type Response = CreateSessionResponse;
}

impl CreateSession {
    pub async fn handle(self, s: ServerStateHandle, c: RuChannel<Msg>) {
        let res = self
            .handle_channel(c, async |req| {
                let mngr = s.sessions_manager().await;
                Ok(CreateSessionResponse {
                    id: mngr
                        .create_session(req.record)
                        .await
                        .map_err(|e| ConnectionError::Internal(e.to_string()))?,
                })
            })
            .await;
        if let Err(e) = res {
            tracing::warn!("RPC handler for {} failed: {}", Self::NAME, e);
        }
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
    s: ServerStateHandle,
    c: ConnectionHandle,
    name: &str,
    id: ChannelId,
    session: &mut Session,
) -> Result<(), ConnectionError> {
    // Take the channel from connection state if its a known RPC.
    let channel = match name {
        GetVersion::NAME | ListSessions::NAME | GetSessionRecord::NAME | CreateSession::NAME => {
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
        GetVersion::NAME => spawn(GetVersion.handle(channel)),
        ListSessions::NAME => spawn(ListSessions.handle(s, channel)),
        GetSessionRecord::NAME => spawn(GetSessionRecord.handle(s, channel)),
        CreateSession::NAME => spawn(CreateSession.handle(s, channel)),
        _ => unreachable!(),
    };

    Ok(())
}

#[cfg(test)]
mod tests {
    use paths::HostAbsPath;

    use super::*;
    use crate::test_harness::TestServer;

    #[tokio::test]
    async fn get_version_returns_compiled_in_versions() {
        let server = TestServer::new().await;
        let mut client = server.connect().await;

        let resp = client.call::<GetVersion>(&()).await;

        assert_eq!(resp.version, env!("CARGO_PKG_VERSION"));
        assert_eq!(resp.long_version, env!("LONG_VERSION"));
        assert_eq!(resp.stdlib_version, stdlib::VERSION);
    }

    #[tokio::test]
    async fn list_sessions_is_empty_on_a_fresh_state_dir() {
        let server = TestServer::new().await;
        let mut client = server.connect().await;

        let resp = client.call::<ListSessions>(&()).await;

        assert!(
            resp.sessions.is_empty(),
            "fresh tempdir should yield no sessions, got {:?}",
            resp.sessions,
        );
    }

    #[tokio::test]
    async fn get_session_record_returns_none_for_unknown_name() {
        let server = TestServer::new().await;
        let mut client = server.connect().await;

        let resp = client
            .call::<GetSessionRecord>(&GetSessionRecordRequest::Name("does-not-exist".to_string()))
            .await;

        assert!(resp.record.is_none());
    }

    #[tokio::test]
    async fn get_session_record_returns_none_for_unknown_id() {
        let server = TestServer::new().await;
        let mut client = server.connect().await;

        let resp = client
            .call::<GetSessionRecord>(&GetSessionRecordRequest::Id(SessionId::nil()))
            .await;

        assert!(resp.record.is_none());
    }

    #[tokio::test]
    async fn one_server_serves_multiple_back_to_back_clients() {
        // Each connect() spawns its own server-side task; this proves
        // the harness reuses a single ServerStateHandle across them.
        let server = TestServer::new().await;

        for _ in 0..3 {
            let mut client = server.connect().await;
            let resp = client.call::<GetVersion>(&()).await;
            assert_eq!(resp.version, env!("CARGO_PKG_VERSION"));
        }
    }

    #[tokio::test]
    async fn create_session_shows_in_get_and_list() {
        let server = TestServer::new().await;
        let mut client = server.connect().await;

        let create_session = client
            .call::<CreateSession>(&CreateSessionRequest {
                record: sessions::Record {
                    id: SessionId::nil(),
                    name: Some("my session".to_string()),
                    username: None,
                    project_path: HostAbsPath::try_new("/uwu").unwrap(),
                    attrs: Default::default(),
                },
            })
            .await;

        assert!(create_session.id != SessionId::nil());

        let get_session = client
            .call::<GetSessionRecord>(&GetSessionRecordRequest::Id(create_session.id))
            .await;
        assert_eq!(get_session.record.as_ref().unwrap().id, create_session.id);
        assert_eq!(
            get_session.record.as_ref().unwrap().name,
            Some("my session".to_string())
        );
        assert_eq!(
            get_session.record.as_ref().unwrap().project_path,
            HostAbsPath::try_new("/uwu").unwrap()
        );

        let list_sessions = client.call::<ListSessions>(&()).await;
        assert_eq!(
            list_sessions.sessions,
            vec![ListSessionsEntry {
                id: create_session.id,
                name: Some("my session".to_string()),
            }]
        );
    }
}
