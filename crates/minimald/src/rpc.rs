use minimald_rpc::{
    CreateSession, CreateSessionResponse, Errorable, GetSessionRecord, GetSessionRecordRequest,
    GetSessionRecordResponse, GetVersion, GetVersionResponse, ListSessions, ListSessionsEntry,
    ListSessionsResponse, OneshotSshRpc,
};
use russh::{
    Channel as RuChannel, ChannelId,
    server::{Msg, Session},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::task::spawn;

use crate::{
    connection::{ConnectionError, ConnectionHandle},
    server::ServerStateHandle,
};

/// Server-side serving glue for [`OneshotSshRpc`]s.
///
/// The wire contract (names, request/response schemas) lives in the
/// `minimald-rpc` crate so clients can share it; this extension trait keeps
/// the transport-bound half — reading the request and writing the response
/// over an SSH channel — local to the server, where `russh` and
/// [`ConnectionError`] are available.
trait ServeOneshot: OneshotSshRpc {
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

impl<T: OneshotSshRpc> ServeOneshot for T {}

async fn serve_get_version(c: RuChannel<Msg>) {
    let res = GetVersion
        .handle_channel(c, async |_req| {
            Ok(GetVersionResponse {
                version: env!("CARGO_PKG_VERSION").to_string(),
                long_version: env!("LONG_VERSION").to_string(),
                stdlib_version: stdlib::VERSION.to_string(),
            })
        })
        .await;
    if let Err(e) = res {
        tracing::warn!("RPC handler for {} failed: {}", GetVersion::NAME, e);
    }
}

async fn serve_list_sessions(s: ServerStateHandle, c: RuChannel<Msg>) {
    let res = ListSessions
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
                        attrs: i.attrs.map(|a| minimald_rpc::RunningSessionAttrs {
                            last_stdout: a.stdout_last.map(|i| i.into()),
                            last_stdin: a.stdin_last.map(|i| i.into()),
                            title: a.title.map(|(value, set_at)| minimald_rpc::Title {
                                value,
                                updated_at: set_at.into(),
                            }),
                            visual_bell: a.visual_bell.1.map(|t| minimald_rpc::Bell {
                                count: a.visual_bell.0,
                                last: t.into(),
                            }),
                            audible_bell: a.audible_bell.1.map(|t| minimald_rpc::Bell {
                                count: a.audible_bell.0,
                                last: t.into(),
                            }),
                        }),
                    })
                    .collect(),
            })
        })
        .await;
    if let Err(e) = res {
        tracing::warn!("RPC handler for {} failed: {}", ListSessions::NAME, e);
    }
}

async fn serve_get_session_record(s: ServerStateHandle, c: RuChannel<Msg>) {
    use crate::sessions::SessionKeyPredicate;
    let res = GetSessionRecord
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
        tracing::warn!("RPC handler for {} failed: {}", GetSessionRecord::NAME, e);
    }
}

async fn serve_create_session(s: ServerStateHandle, c: RuChannel<Msg>) {
    let res = CreateSession
        .handle_channel(c, async |req| {
            let mngr = s.sessions_manager().await;

            Ok(match mngr.create_session(req.record).await {
                Ok(id) => Errorable::Ok(CreateSessionResponse { id }),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Errorable::Err {
                    error: "A session with that name already exists".to_string(),
                },
                Err(e) => return Err(ConnectionError::Internal(e.to_string())),
            })
        })
        .await;
    if let Err(e) = res {
        tracing::warn!("RPC handler for {} failed: {}", CreateSession::NAME, e);
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
        GetVersion::NAME => spawn(serve_get_version(channel)),
        ListSessions::NAME => spawn(serve_list_sessions(s, channel)),
        GetSessionRecord::NAME => spawn(serve_get_session_record(s, channel)),
        CreateSession::NAME => spawn(serve_create_session(s, channel)),
        _ => unreachable!(),
    };

    Ok(())
}

#[cfg(test)]
mod tests {
    use minimald_rpc::CreateSessionRequest;
    use paths::HostAbsPath;
    use sessions::SessionId;

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
            .await
            .unwrap();

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
                attrs: None,
            }]
        );
    }

    #[tokio::test]
    async fn create_session_errors_if_name_not_unique() {
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
            .await
            .unwrap();

        assert!(create_session.id != SessionId::nil());

        assert_eq!(
            client
                .call::<CreateSession>(&CreateSessionRequest {
                    record: sessions::Record {
                        id: SessionId::nil(),
                        name: Some("my session".to_string()),
                        username: None,
                        project_path: HostAbsPath::try_new("/uwu").unwrap(),
                        attrs: Default::default(),
                    },
                })
                .await,
            Errorable::Err {
                error: "A session with that name already exists".to_string()
            }
        );
    }
}
