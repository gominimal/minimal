use minimald_rpc::{
    CreateSession, CreateSessionResponse, Errorable, GetSessionRecord, GetSessionRecordRequest,
    GetSessionRecordResponse, GetVersion, GetVersionResponse, ListSessions, ListSessionsEntry,
    ListSessionsResponse, OneshotSshRpc, RPC_SUBSYSTEM_PREFIX, RenameSession,
    RenameSessionResponse,
};
use russh::{
    Channel as RuChannel, ChannelId,
    server::{Msg, Session},
};
use sessions::SessionId;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::task::spawn;

use crate::{
    ChannelConfig,
    connection::{ConnectionError, ConnectionHandle},
    server::ServerStateHandle,
    sessions::SessionKeyPredicate,
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

async fn serve_rename_session(s: ServerStateHandle, c: RuChannel<Msg>) {
    let res = RenameSession
        .handle_channel(c, async |req| {
            let res = s
                .sessions_manager()
                .await
                .rename_session(req.id, req.new_name)
                .await;
            match res {
                Ok(()) => Ok(Errorable::Ok(RenameSessionResponse)),
                Err(e) => Ok(Errorable::Err {
                    error: e.to_string(),
                }),
            }
        })
        .await;
    if let Err(e) = res {
        tracing::warn!("RPC handler for {} failed: {}", RenameSession::NAME, e);
    }
}

pub(crate) const STREAM_WORKSPACE_FILES: &str =
    constcat::concat!(RPC_SUBSYSTEM_PREFIX, "WorkspaceFilesTarZst");

async fn serve_stream_workspace_files(
    s: ServerStateHandle,
    config: ChannelConfig,
    mut c: RuChannel<Msg>,
) {
    if let Err(msg) = unpack_workspace_files(&s, &config, &mut c).await {
        let _ = c.extended_data_bytes(1, msg).await;
    }
    let _ = c.close().await;
}

/// Unpacks the zstd-compressed tarball streamed over `c` into the
/// workspace directory of the session named by the channel environment.
///
/// On failure, returns the human-readable message to relay back to the
/// client over the channel's extended-data stream.
async fn unpack_workspace_files(
    s: &ServerStateHandle,
    config: &ChannelConfig,
    c: &mut RuChannel<Msg>,
) -> Result<(), String> {
    let session_id_str = config
        .env_vars
        .get(crate::MINIMAL_SESSION_ID_ENV)
        .ok_or("missing env-var MINIMAL_SESSION_ID")?;
    let session_id =
        SessionId::parse_str(session_id_str).map_err(|e| format!("parsing session UUID: {e}"))?;

    let mngr = s.sessions_manager().await;
    let session_handle = mngr
        .get_session(SessionKeyPredicate::Id(session_id))
        .await
        .map_err(|e| format!("session UUID lookup failed: {e}"))?
        .ok_or("unknown session UUID")?;
    let workspace_path = session_handle.workspace_path().await;

    let reader = async_compression::tokio::bufread::ZstdDecoder::new(tokio::io::BufReader::new(
        c.make_reader(),
    ));
    async_tar::Archive::new(reader)
        .unpack(workspace_path.as_utf8_path())
        .await
        .map_err(|e| format!("unpack failed: {e}"))?;

    Ok(())
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
    let res = match name {
        GetVersion::NAME
        | ListSessions::NAME
        | GetSessionRecord::NAME
        | CreateSession::NAME
        | RenameSession::NAME
        | STREAM_WORKSPACE_FILES => {
            let mut conn_lock = c.lock().await;
            let c_hnd = match conn_lock.take(id) {
                None => {
                    session.channel_failure(id)?;
                    return Ok(());
                }
                Some((channel, config)) => (channel, config),
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
    let (channel, config) = match res {
        Some((channel, config)) => (channel, config),
        None => return Ok(()),
    };

    // Handle the named RPC.
    match name {
        GetVersion::NAME => spawn(serve_get_version(channel)),
        ListSessions::NAME => spawn(serve_list_sessions(s, channel)),
        GetSessionRecord::NAME => spawn(serve_get_session_record(s, channel)),
        CreateSession::NAME => spawn(serve_create_session(s, channel)),
        RenameSession::NAME => spawn(serve_rename_session(s, channel)),
        STREAM_WORKSPACE_FILES => spawn(serve_stream_workspace_files(s, config, channel)),
        _ => unreachable!(),
    };

    Ok(())
}

#[cfg(test)]
mod tests {
    use minimald_rpc::{CreateSession, CreateSessionRequest, RenameSessionRequest};
    use paths::HostAbsPath;
    use sessions::SessionId;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;
    use crate::MINIMAL_SESSION_ID_ENV;
    use crate::sessions::SessionKeyPredicate;
    use crate::test_harness::{TestClient, TestServer};

    /// Serializes `(path, contents)` entries into a tar archive and
    /// zstd-compresses it, producing exactly the wire format that
    /// [`serve_stream_workspace_files`] decodes.
    async fn tar_zst(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut tar = async_tar::Builder::new(Vec::new());
        for (path, contents) in entries {
            let mut header = async_tar::Header::new_gnu();
            header.set_size(contents.len() as u64);
            header.set_mode(0o644);
            tar.append_data(&mut header, path, *contents).await.unwrap();
        }
        let tar_bytes = tar.into_inner().await.unwrap();

        let mut encoder = async_compression::tokio::write::ZstdEncoder::new(Vec::new());
        encoder.write_all(&tar_bytes).await.unwrap();
        encoder.shutdown().await.unwrap();
        encoder.into_inner()
    }

    /// Creates a session through the public RPC and returns its id.
    async fn fresh_session(client: &mut TestClient) -> SessionId {
        client
            .call::<CreateSession>(&CreateSessionRequest {
                record: sessions::Record {
                    id: SessionId::nil(),
                    name: Some("stream-test".to_string()),
                    username: None,
                    project_path: HostAbsPath::try_new("/tmp").unwrap(),
                    attrs: Default::default(),
                },
            })
            .await
            .unwrap()
            .id
    }

    #[tokio::test]
    async fn stream_workspace_files_unpacks_tarball_into_workspace() {
        let server = TestServer::new().await;
        let mut client = server.connect().await;
        let session_id = fresh_session(&mut client).await;

        let payload = tar_zst(&[
            ("hello.txt", b"hello world\n"),
            ("dir/nested.txt", b"nested contents"),
        ])
        .await;

        let channel = client
            .open_subsystem(
                STREAM_WORKSPACE_FILES,
                &[(MINIMAL_SESSION_ID_ENV, &session_id.to_string())],
            )
            .await;
        let mut stream = channel.into_stream();
        stream.write_all(&payload).await.unwrap();
        // Half-close so the server's decoder sees EOF; then read to the
        // server's channel close so the unpack has completed on-disk
        // before we assert.
        stream.shutdown().await.unwrap();
        let mut trailing = Vec::new();
        stream.read_to_end(&mut trailing).await.unwrap();

        let mngr = server.state.sessions_manager().await;
        let handle = mngr
            .get_session(SessionKeyPredicate::Id(session_id))
            .await
            .unwrap()
            .expect("freshly-created session should be retrievable");
        let workspace = handle.workspace_path().await;

        assert_eq!(
            tokio::fs::read(workspace.as_utf8_path().join("hello.txt"))
                .await
                .unwrap(),
            b"hello world\n",
        );
        assert_eq!(
            tokio::fs::read(workspace.as_utf8_path().join("dir/nested.txt"))
                .await
                .unwrap(),
            b"nested contents",
        );
    }

    #[tokio::test]
    async fn stream_workspace_files_rejects_unknown_session() {
        use russh::ChannelMsg;

        let server = TestServer::new().await;
        let mut client = server.connect().await;

        // A well-formed but unknown session id: the handler should report
        // an error on stderr (ssh extended data) rather than unpacking.
        let mut channel = client
            .open_subsystem(
                STREAM_WORKSPACE_FILES,
                &[(MINIMAL_SESSION_ID_ENV, &SessionId::nil().to_string())],
            )
            .await;
        channel.eof().await.unwrap();

        let mut stderr = Vec::new();
        while let Some(msg) = channel.wait().await {
            if let ChannelMsg::ExtendedData { data, ext: 1 } = msg {
                stderr.extend_from_slice(&data);
            }
        }

        assert!(
            String::from_utf8_lossy(&stderr).contains("unknown session"),
            "expected an unknown-session error on stderr, got {:?}",
            String::from_utf8_lossy(&stderr),
        );
    }

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

    #[tokio::test]
    async fn rename_session_propagates_into_the_running_session() {
        let server = TestServer::new().await;
        let mut client = server.connect().await;
        let session_id = fresh_session(&mut client).await;

        // Bring the session up before renaming, so the rename has to reach the
        // live actor's in-memory record rather than only touching disk.
        let mngr = server.state.sessions_manager().await;
        let handle = mngr
            .get_session(SessionKeyPredicate::Id(session_id))
            .await
            .unwrap()
            .expect("freshly-created session should be retrievable");

        let resp = client
            .call::<RenameSession>(&RenameSessionRequest {
                id: session_id,
                new_name: "renamed".to_string(),
            })
            .await;
        assert_eq!(resp, Errorable::Ok(RenameSessionResponse));

        // The record held by the running session reflects the new name...
        let record = handle.record().await;
        assert_eq!(record.name.as_deref(), Some("renamed"));
        // ...while its id is untouched by the rename.
        assert_eq!(record.id, session_id);

        // The rename is reflected by GetRecord...
        let get_session = client
            .call::<GetSessionRecord>(&GetSessionRecordRequest::Id(record.id))
            .await;
        assert_eq!(
            get_session.record.as_ref().unwrap().name,
            Some("renamed".to_string())
        );
    }

    #[tokio::test]
    async fn rename_session_errors_for_unknown_id() {
        let server = TestServer::new().await;
        let mut client = server.connect().await;

        let resp = client
            .call::<RenameSession>(&RenameSessionRequest {
                id: SessionId::nil(),
                new_name: "renamed".to_string(),
            })
            .await;

        assert!(
            matches!(resp, Errorable::Err { error } if error.contains("no session with ID")),
            "expected an unknown-id error",
        );
    }
}
