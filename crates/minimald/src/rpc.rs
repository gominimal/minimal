#[cfg(feature = "networking-proxy")]
use minimald_rpc::IssueClientCertResponse;
use minimald_rpc::{
    AbortSession, AbortSessionResponse, CreateSession, DestroySession, DestroySessionResponse,
    Errorable, GetMeshStatus, GetSessionPolicy, GetSessionPolicyRequest, GetSessionRecord,
    GetSessionRecordRequest, GetSessionRecordResponse, GetVersion, GetVersionResponse,
    IssueClientCert, IssueClientCertRequest, ListSessions, ListSessionsEntry, ListSessionsResponse,
    OneshotSshRpc, RPC_SUBSYSTEM_PREFIX, RenameSession, RenameSessionResponse, Shutdown,
    ShutdownRequest, ShutdownResponse, SubmitVerdict,
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

/// `CreateSession`: allocates the session's record and brings its actor
/// up, replying with the assigned id. The loadout is composed separately,
/// by the `ConfigureLoadout` that follows.
async fn serve_create_session(
    s: ServerStateHandle,
    c: RuChannel<Msg>,
    ssh_username: Option<String>,
) {
    let res = CreateSession
        .handle_channel(c, async |req| {
            let mngr = s.sessions_manager().await;

            Ok(match mngr.create_session(req.config, ssh_username).await {
                Ok(id) => Errorable::Ok(minimald_rpc::CreateSessionResponse { id }),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Errorable::Err {
                    error: "A session with that name already exists".to_string(),
                },
                // R2.1: a policy/network-mode mismatch is rejected at
                // declaration time and surfaced as a clean typed error rather
                // than a transport failure.
                Err(e) if e.kind() == std::io::ErrorKind::InvalidInput => Errorable::Err {
                    error: e.to_string(),
                },
                Err(e) => return Err(ConnectionError::Internal(e.to_string())),
            })
        })
        .await;
    if let Err(e) = res {
        tracing::warn!("RPC handler for {} failed: {}", CreateSession::NAME, e);
    }
}

/// `ConfigureLoadout`: composes a created session's loadout from the
/// project config in its workspace plus the client's contribution.
/// Resolves the session's live actor and routes the contribution to it;
/// the actor composes and either promotes its record `Pending → Active`
/// (`Ready`) or parks awaiting a verdict (`Pending`).
///
/// A compose failure leaves the session alive and unconfigured, so it
/// surfaces as an `Errorable::Err` the client can act on (fix the project
/// and retry, or abort) rather than a transport failure. An unknown id —
/// including an actor that died between resolve and delivery — is a
/// `NotFound`-flavoured `Errorable::Err`.
async fn serve_configure_loadout(s: ServerStateHandle, c: RuChannel<Msg>) {
    let res = minimald_rpc::ConfigureLoadout
        .handle_channel(c, async |req: minimald_rpc::ConfigureLoadoutRequest| {
            let mngr = s.sessions_manager().await;
            let handle = mngr
                .get_session(SessionKeyPredicate::Id(req.session_id))
                .await
                .map_err(|e| ConnectionError::Internal(e.to_string()))?;
            let Some(h) = handle else {
                return Ok(Errorable::Err {
                    error: format!("no session with ID `{}`", req.session_id.as_ref()),
                });
            };
            Ok(match h.configure_loadout(req.contribution).await {
                Ok(None) => Errorable::Ok(minimald_rpc::ConfigureLoadoutResponse::Ready),
                Ok(Some(response)) => {
                    Errorable::Ok(minimald_rpc::ConfigureLoadoutResponse::Pending { response })
                }
                Err(e) => Errorable::Err {
                    error: e.to_string(),
                },
            })
        })
        .await;
    if let Err(e) = res {
        tracing::warn!(
            "RPC handler for {} failed: {}",
            minimald_rpc::ConfigureLoadout::NAME,
            e
        );
    }
}

/// `SubmitVerdict`: the client's per-item decisions for a `Pending`
/// session. Resolves the session's live actor and routes the verdict
/// to it; the actor runs `resume_from_verdict` and promotes its
/// record `Pending → Active`. Replies with `Errorable::Ok(SessionStep)`
/// where the `SessionStep` is `Active { id }` on success or
/// `Fault { error }` for a structured failure. A verdict for an id
/// with no live session — including an actor that died between
/// resolve and delivery — maps to `Fault { UnknownSessionId }` here;
/// other `io::Error`s bubble up as `ConnectionError::Internal`.
async fn serve_submit_verdict(s: ServerStateHandle, c: RuChannel<Msg>) {
    let res = SubmitVerdict
        .handle_channel(
            c,
            async |req: sessions::wire::request::ContributionVerdict| {
                let mngr = s.sessions_manager().await;
                let unknown = || {
                    Errorable::Ok(sessions::wire::request::SessionStep::Fault {
                        error: sessions::wire::errors::WireError::UnknownSessionId,
                    })
                };
                let handle = mngr
                    .get_session(SessionKeyPredicate::Id(req.session_id))
                    .await
                    .map_err(|e| ConnectionError::Internal(e.to_string()))?;
                match handle {
                    None => Ok(unknown()),
                    Some(h) => match h.submit_verdict(req).await {
                        Ok(step) => Ok(Errorable::Ok(step)),
                        Err(e) if e.kind() == std::io::ErrorKind::NotConnected => Ok(unknown()),
                        Err(e) => Err(ConnectionError::Internal(e.to_string())),
                    },
                }
            },
        )
        .await;
    if let Err(e) = res {
        tracing::warn!("RPC handler for {} failed: {}", SubmitVerdict::NAME, e);
    }
}

/// `RenameSession`: resolves the session's actor (spinning it up from
/// disk if needed) and lets it persist the new name and relink its
/// PTask hostname. A name collision surfaces as the store's
/// `AlreadyExists` in the `Errorable::Err` text.
async fn serve_rename_session(s: ServerStateHandle, c: RuChannel<Msg>) {
    let res = RenameSession
        .handle_channel(c, async |req| {
            let res = async {
                match s
                    .sessions_manager()
                    .await
                    .get_session(SessionKeyPredicate::Id(req.id))
                    .await?
                {
                    None => Err(std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        format!("no session with ID `{}`", req.id.as_ref()),
                    )),
                    Some(h) => h.rename(req.new_name).await,
                }
            }
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

async fn serve_destroy_session(s: ServerStateHandle, c: RuChannel<Msg>) {
    let res = DestroySession
        .handle_channel(c, async |req| {
            let res = s.sessions_manager().await.delete_session(req.id).await;
            match res {
                Ok(()) => Ok(Errorable::Ok(DestroySessionResponse)),
                Err(e) => Ok(Errorable::Err {
                    error: e.to_string(),
                }),
            }
        })
        .await;
    if let Err(e) = res {
        tracing::warn!("RPC handler for {} failed: {}", DestroySession::NAME, e);
    }
}

async fn serve_shutdown(s: ServerStateHandle, c: RuChannel<Msg>) {
    let res = Shutdown
        .handle_channel(c, async |req: ShutdownRequest| {
            let mngr = s.sessions_manager().await;
            Ok(match mngr.shutdown(req.force).await {
                Ok(()) => {
                    // R2.1/R2.2: with the sessions drained, quiesce the state
                    // volume (syncfs + detach) before acknowledging, so a
                    // caller-driven VMM teardown right after the ack leaves a
                    // clean ext4 journal. Best-effort with a bounded wait; the
                    // journal replay backstop covers every failure arm.
                    quiesce_state_volume_if_mounted(&s).await;
                    // Manager is down; tell the accept loop to stop and drain
                    // so the process can exit. Firing before the response is
                    // written is safe: the drain waits out the grace period,
                    // so this reply still flushes to the client.
                    s.trigger_shutdown().await;
                    ShutdownResponse::ShuttingDown
                }
                Err(()) => ShutdownResponse::SessionsLive,
            })
        })
        .await;
    if let Err(e) = res {
        tracing::warn!("RPC handler for {} failed: {}", Shutdown::NAME, e);
    }
}

/// Quiesce the guest state volume during shutdown (R2.2). No-op unless the
/// boot path actually mounted the data volume at the state dir — a native
/// daemon's host directory, or a microVM running without a volume, must
/// never be synced-and-unmounted out from under the host. `syncfs` is
/// blocking, so it runs on the blocking pool with a 10 s ceiling; the
/// handler proceeds regardless of the outcome. Note the ceiling's residual
/// risk: a timed-out `syncfs` keeps running detached while the handler acks,
/// so a very large dirty set can still be mid-flush when the caller tears
/// the VM down — bounded, as ever, by the ext4 journal replay backstop.
#[cfg(target_os = "linux")]
async fn quiesce_state_volume_if_mounted(s: &ServerStateHandle) {
    const QUIESCE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

    if !s.state_volume_mounted().await {
        return;
    }
    let mountpoint = s.minimal_state_dir().await;
    let quiesce = tokio::task::spawn_blocking(move || {
        crate::guest::quiesce_state_volume(mountpoint.as_utf8_path().as_str())
    });
    match tokio::time::timeout(QUIESCE_TIMEOUT, quiesce).await {
        Ok(Ok(Ok(()))) => tracing::info!("state volume quiesced for shutdown"),
        Ok(Ok(Err(e))) => {
            tracing::warn!(error = %e, "state volume quiesce failed; ext4 journal replay will recover")
        }
        Ok(Err(join)) => tracing::warn!(error = %join, "state volume quiesce task panicked"),
        Err(_) => tracing::warn!("state volume quiesce timed out after 10s; proceeding"),
    }
}

#[cfg(not(target_os = "linux"))]
async fn quiesce_state_volume_if_mounted(_s: &ServerStateHandle) {}

/// `AbortSession`: routes to the session actor, whose state machine
/// deletes a `Draft` session's record and stops, or refuses an
/// `Active` session with `InvalidInput` (use `DestroySession`).
/// Unknown ids are `NotFound`.
async fn serve_abort_session(s: ServerStateHandle, c: RuChannel<Msg>) {
    let res = AbortSession
        .handle_channel(c, async |req| {
            let res = async {
                match s
                    .sessions_manager()
                    .await
                    .get_session(SessionKeyPredicate::Id(req.id))
                    .await?
                {
                    None => Err(std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        format!("no session with ID `{}`", req.id.as_ref()),
                    )),
                    Some(h) => h.abort().await,
                }
            }
            .await;
            match res {
                Ok(()) => Ok(Errorable::Ok(AbortSessionResponse)),
                Err(e) => Ok(Errorable::Err {
                    error: e.to_string(),
                }),
            }
        })
        .await;
    if let Err(e) = res {
        tracing::warn!("RPC handler for {} failed: {}", AbortSession::NAME, e);
    }
}

async fn serve_get_session_policy(s: ServerStateHandle, c: RuChannel<Msg>) {
    let res = GetSessionPolicy
        .handle_channel(c, async |req| {
            let mngr = s.sessions_manager().await;
            let predicate = match req {
                GetSessionPolicyRequest::Id(id) => SessionKeyPredicate::Id(id),
                GetSessionPolicyRequest::Name(name) => SessionKeyPredicate::Name(name),
            };
            let record = mngr
                .get_record(predicate)
                .await
                .map_err(|e| ConnectionError::Internal(e.to_string()))?;
            match record {
                None => Ok(Errorable::Err {
                    error: "no session found".to_string(),
                }),
                // R2.6: return the policy configured at launch from the live
                // session record, not a hardcoded default.
                Some(record) => Ok(Errorable::Ok(record.policy)),
            }
        })
        .await;
    if let Err(e) = res {
        tracing::warn!("RPC handler for {} failed: {}", GetSessionPolicy::NAME, e);
    }
}

/// Signs a fresh client certificate for the `minimal login` flow and returns
/// the cert PEM, key PEM, and CA cert PEM so the client can authenticate to
/// the HTTPS reverse proxy. Only compiled when the `networking-proxy` feature
/// is enabled.
#[cfg(feature = "networking-proxy")]
async fn serve_issue_client_cert(s: ServerStateHandle, c: RuChannel<Msg>) {
    let res = IssueClientCert
        .handle_channel(c, async |req: IssueClientCertRequest| {
            let ca = s.cert_authority().await;
            match ca.sign_client_cert(&req.subject_cn) {
                Ok((cert_pem, key_pem)) => Ok(Errorable::Ok(IssueClientCertResponse {
                    cert_pem,
                    key_pem,
                    ca_cert_pem: ca.ca_cert_pem.clone(),
                })),
                Err(e) => Ok(Errorable::Err {
                    error: e.to_string(),
                }),
            }
        })
        .await;
    if let Err(e) = res {
        tracing::warn!("RPC handler for {} failed: {}", IssueClientCert::NAME, e);
    }
}

/// Replies to an `IssueClientCert` request with a readable error when the
/// `networking-proxy` feature is compiled out, so the client sees "feature not
/// enabled" instead of an opaque EOF/channel-close on the response stream.
#[cfg(not(feature = "networking-proxy"))]
async fn serve_issue_client_cert_unavailable(c: RuChannel<Msg>) {
    let res = IssueClientCert
        .handle_channel(c, async |_req: IssueClientCertRequest| {
            Ok(Errorable::Err {
                error: "minimald was built without the networking-proxy feature; \
                        client certificate issuance is unavailable"
                    .to_string(),
            })
        })
        .await;
    if let Err(e) = res {
        tracing::warn!("RPC handler for {} failed: {}", IssueClientCert::NAME, e);
    }
}

async fn serve_get_mesh_status(s: ServerStateHandle, c: RuChannel<Msg>) {
    let res = GetMeshStatus
        .handle_channel(c, async |_req| Ok(s.mesh_status().await))
        .await;
    if let Err(e) = res {
        tracing::warn!("RPC handler for {} failed: {}", GetMeshStatus::NAME, e);
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
    let paths = session_handle
        .paths()
        .await
        .map_err(|e| format!("session is gone: {e}"))?;

    let reader = async_compression::tokio::bufread::ZstdDecoder::new(tokio::io::BufReader::new(
        c.make_reader(),
    ));
    async_tar::Archive::new(reader)
        .unpack(paths.working.as_utf8_path())
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
    // `ssh_username` is read out under the same lock so `serve_*`
    // handlers that need the authenticated user (CreateSession) don't
    // have to re-lock.
    let res = match name {
        GetVersion::NAME
        | ListSessions::NAME
        | GetSessionRecord::NAME
        | CreateSession::NAME
        | minimald_rpc::ConfigureLoadout::NAME
        | SubmitVerdict::NAME
        | RenameSession::NAME
        | DestroySession::NAME
        | Shutdown::NAME
        | AbortSession::NAME
        | GetSessionPolicy::NAME
        | GetMeshStatus::NAME
        | STREAM_WORKSPACE_FILES
        | minimald_rpc::DIAG_BUNDLE_SUBSYSTEM
        | IssueClientCert::NAME => {
            let mut conn_lock = c.lock().await;
            let c_hnd = match conn_lock.take(id) {
                None => {
                    session.channel_failure(id)?;
                    return Ok(());
                }
                Some((channel, config)) => (channel, config),
            };
            let ssh_username = conn_lock.ssh_username.clone();
            drop(conn_lock);
            session.channel_success(id)?;
            Some((c_hnd, ssh_username))
        }
        _ => {
            session.channel_failure(id)?;
            None
        }
    };
    let ((channel, config), ssh_username) = match res {
        Some(v) => v,
        None => return Ok(()),
    };

    // Handle the named RPC (fire-and-forget; join handles are discarded).
    match name {
        GetVersion::NAME => drop(spawn(serve_get_version(channel))),
        ListSessions::NAME => drop(spawn(serve_list_sessions(s, channel))),
        GetSessionRecord::NAME => drop(spawn(serve_get_session_record(s, channel))),
        CreateSession::NAME => drop(spawn(serve_create_session(s, channel, ssh_username))),
        minimald_rpc::ConfigureLoadout::NAME => drop(spawn(serve_configure_loadout(s, channel))),
        SubmitVerdict::NAME => drop(spawn(serve_submit_verdict(s, channel))),
        RenameSession::NAME => drop(spawn(serve_rename_session(s, channel))),
        DestroySession::NAME => drop(spawn(serve_destroy_session(s, channel))),
        Shutdown::NAME => drop(spawn(serve_shutdown(s, channel))),
        AbortSession::NAME => drop(spawn(serve_abort_session(s, channel))),
        GetSessionPolicy::NAME => drop(spawn(serve_get_session_policy(s, channel))),
        GetMeshStatus::NAME => drop(spawn(serve_get_mesh_status(s, channel))),
        STREAM_WORKSPACE_FILES => drop(spawn(serve_stream_workspace_files(s, config, channel))),
        minimald_rpc::DIAG_BUNDLE_SUBSYSTEM => drop(spawn(crate::diag::serve_stream_diag_bundle(
            s, config, channel,
        ))),
        IssueClientCert::NAME => {
            #[cfg(feature = "networking-proxy")]
            drop(spawn(serve_issue_client_cert(s, channel)));
            #[cfg(not(feature = "networking-proxy"))]
            {
                tracing::warn!(
                    "IssueClientCert RPC called but the networking-proxy \
                     feature is not enabled; replying with an error"
                );
                drop(s);
                drop(spawn(serve_issue_client_cert_unavailable(channel)));
            }
        }
        _ => unreachable!(),
    };

    Ok(())
}

#[cfg(test)]
mod tests {
    use minimald_rpc::{
        CreateSession, CreateSessionRequest, DestroySessionRequest, EgressPolicy, GetSessionPolicy,
        GetSessionPolicyRequest, RenameSessionRequest, SessionPolicy, Shutdown, ShutdownRequest,
        ShutdownResponse,
    };
    use paths::HostAbsPath;
    use sessions::{NetworkMode, SessionId};
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

    use crate::test_harness::create_session_req as req;

    /// Creates a session through the public RPCs and returns its id, ready
    /// to attach.
    async fn fresh_session(client: &mut TestClient) -> SessionId {
        crate::test_harness::create_configured_session(client, "stream-test", "/tmp").await
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
        let paths = handle.paths().await.unwrap();

        assert_eq!(
            tokio::fs::read(paths.working.as_utf8_path().join("hello.txt"))
                .await
                .unwrap(),
            b"hello world\n",
        );
        assert_eq!(
            tokio::fs::read(paths.working.as_utf8_path().join("dir/nested.txt"))
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

        let id = client
            .call::<CreateSession>(&req("my session", "/uwu"))
            .await
            .unwrap()
            .id;
        assert!(id != SessionId::nil());

        let get_session = client
            .call::<GetSessionRecord>(&GetSessionRecordRequest::Id(id))
            .await;
        assert_eq!(get_session.record.as_ref().unwrap().id, id);
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
                id,
                name: Some("my session".to_string()),
                attrs: None,
            }]
        );
    }

    #[tokio::test]
    async fn get_session_policy_returns_the_policy_configured_at_launch() {
        // R2.6: GetSessionPolicy reads the live per-session policy from the
        // record, not a hardcoded default. Create an `OwnIp` session carrying an
        // explicit egress policy, then read it back over the RPC.
        let server = TestServer::new().await;
        let mut client = server.connect().await;

        let egress = EgressPolicy {
            allow_subnets: Some(vec!["10.0.0.0/8".to_string()]),
            allow_dns_hosts: None,
            allow_protocols: None,
        };
        let created_id = client
            .call::<CreateSession>(&CreateSessionRequest {
                config: minimald_rpc::SessionConfig {
                    name: Some("policy-session".to_string()),
                    project_path: HostAbsPath::try_new("/uwu").unwrap(),
                    network: NetworkMode::OwnIp,
                    policy: SessionPolicy::new(Some(egress.clone()), None),
                    attrs: Default::default(),
                },
            })
            .await
            .unwrap()
            .id;

        let policy = client
            .call::<GetSessionPolicy>(&GetSessionPolicyRequest::Id(created_id))
            .await
            .unwrap();
        assert_eq!(policy.egress, Some(egress));
        // The configured ingress was `None`, and the read reflects that rather
        // than the old hardcoded `Some(IngressPolicy::default())`.
        assert_eq!(policy.ingress, None);
    }

    #[tokio::test]
    async fn create_session_errors_if_name_not_unique() {
        let server = TestServer::new().await;
        let mut client = server.connect().await;

        let id = client
            .call::<CreateSession>(&req("my session", "/uwu"))
            .await
            .unwrap()
            .id;
        assert!(id != SessionId::nil());

        assert_eq!(
            client
                .call::<CreateSession>(&req("my session", "/uwu"))
                .await,
            Errorable::Err {
                error: "A session with that name already exists".to_string()
            }
        );
    }

    #[tokio::test]
    async fn create_session_rejects_policy_incompatible_with_network_mode() {
        let server = TestServer::new().await;
        let mut client = server.connect().await;

        // R2.1: an egress policy on a non-`OwnIp` PTask is rejected at
        // declaration time, so the invalid session is never stored.
        let egress = EgressPolicy {
            allow_subnets: Some(vec!["10.0.0.0/8".to_string()]),
            allow_dns_hosts: None,
            allow_protocols: None,
        };
        let resp = client
            .call::<CreateSession>(&CreateSessionRequest {
                config: minimald_rpc::SessionConfig {
                    name: Some("bad-policy".to_string()),
                    project_path: HostAbsPath::try_new("/uwu").unwrap(),
                    network: NetworkMode::HostNet,
                    policy: SessionPolicy::new(Some(egress), None),
                    attrs: Default::default(),
                },
            })
            .await;
        assert_eq!(
            resp,
            Errorable::Err {
                error: "egress policy is only valid for an own-IP PTask, not HostNet".to_string()
            }
        );

        // The rejected session left nothing behind in the store.
        let mngr = server.state.sessions_manager().await;
        assert!(mngr.list().await.unwrap().is_empty());
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
        let record = handle.record().await.unwrap();
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

    /// A verdict for an id with no live session is a terminal, structured
    /// `Fault::UnknownSessionId` on the wire — not a transport error. This
    /// mapping lives in `serve_submit_verdict` now that verdicts route to
    /// per-session actors.
    #[tokio::test]
    async fn submit_verdict_unknown_id_returns_unknown_session_id() {
        let server = TestServer::new().await;
        let mut client = server.connect().await;

        let resp = client
            .call::<minimald_rpc::SubmitVerdict>(&sessions::wire::request::ContributionVerdict {
                session_id: SessionId::nil(),
                vars: vec![],
                patches: vec![],
            })
            .await;
        match resp {
            Errorable::Ok(sessions::wire::request::SessionStep::Fault {
                error: sessions::wire::errors::WireError::UnknownSessionId,
            }) => {}
            other => panic!("expected Fault::UnknownSessionId, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn destroy_session_removes_it_from_get_and_list() {
        let server = TestServer::new().await;
        let mut client = server.connect().await;
        let session_id = fresh_session(&mut client).await;

        let resp = client
            .call::<DestroySession>(&DestroySessionRequest { id: session_id })
            .await;
        assert_eq!(resp, Errorable::Ok(DestroySessionResponse));

        // The record is gone: it no longer resolves by id...
        let get_session = client
            .call::<GetSessionRecord>(&GetSessionRecordRequest::Id(session_id))
            .await;
        assert!(get_session.record.is_none());

        // ...and it's dropped from the listing.
        let list_sessions = client.call::<ListSessions>(&()).await;
        assert!(
            list_sessions.sessions.is_empty(),
            "destroyed session should not be listed, got {:?}",
            list_sessions.sessions,
        );
    }

    #[tokio::test]
    async fn destroy_session_errors_for_unknown_id() {
        let server = TestServer::new().await;
        let mut client = server.connect().await;

        let resp = client
            .call::<DestroySession>(&DestroySessionRequest {
                id: SessionId::nil(),
            })
            .await;

        assert!(
            matches!(resp, Errorable::Err { error } if error.contains("no session with ID")),
            "expected an unknown-id error",
        );
    }

    #[tokio::test]
    async fn shutdown_reports_shutting_down_when_no_sessions_are_live() {
        let server = TestServer::new().await;
        let mut client = server.connect().await;

        let resp = client
            .call::<Shutdown>(&ShutdownRequest { force: false })
            .await;
        assert_eq!(resp, ShutdownResponse::ShuttingDown);
    }

    #[tokio::test]
    async fn shutdown_rejects_further_session_work_once_shut_down() {
        let server = TestServer::new().await;
        let mut client = server.connect().await;

        let resp = client
            .call::<Shutdown>(&ShutdownRequest { force: false })
            .await;
        assert_eq!(resp, ShutdownResponse::ShuttingDown);

        // After shutdown the manager refuses to bring sessions up, so even a
        // lookup for a well-formed id is rejected rather than answered.
        let mngr = server.state.sessions_manager().await;
        assert!(
            mngr.get_session(SessionKeyPredicate::Id(SessionId::nil()))
                .await
                .is_err(),
            "manager should reject session work while shutting down",
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn shutdown_without_force_refuses_while_a_session_is_live() {
        let server = TestServer::new().await;
        let mut client = server.connect().await;
        let session_id = fresh_session(&mut client).await;

        // A session is only "busy" once it hosts a live shell (an idle actor
        // no longer blocks an unforced shutdown). Open one and drive an echo
        // round trip so the host is provably up before the shutdown request.
        let mut channel = client.open_shell(session_id).await;
        channel.data_bytes(b"hello\n".to_vec()).await.unwrap();
        let mut stdout = Vec::new();
        loop {
            match channel.wait().await {
                Some(russh::ChannelMsg::Data { data }) => {
                    stdout.extend_from_slice(&data);
                    if String::from_utf8_lossy(&stdout).contains("got:hello") {
                        break;
                    }
                }
                Some(_) => {}
                None => panic!("channel closed before the echo arrived"),
            }
        }

        let resp = client
            .call::<Shutdown>(&ShutdownRequest { force: false })
            .await;
        assert_eq!(resp, ShutdownResponse::SessionsLive);

        // The refusal left the daemon fully operational: the live session is
        // still reachable and no shutdown flag was latched.
        let mngr = server.state.sessions_manager().await;
        assert!(
            mngr.get_session(SessionKeyPredicate::Id(session_id))
                .await
                .unwrap()
                .is_some(),
            "an unforced, refused shutdown must not tear down live sessions",
        );
    }

    #[tokio::test]
    async fn shutdown_with_force_tears_down_live_sessions() {
        let server = TestServer::new().await;
        let mut client = server.connect().await;
        let session_id = fresh_session(&mut client).await;

        let mngr = server.state.sessions_manager().await;
        mngr.get_session(SessionKeyPredicate::Id(session_id))
            .await
            .unwrap()
            .expect("freshly-created session should be retrievable");

        // `force` overrides the live-session guard: the daemon shuts down...
        let resp = client
            .call::<Shutdown>(&ShutdownRequest { force: true })
            .await;
        assert_eq!(resp, ShutdownResponse::ShuttingDown);

        // ...and, being in shutdown, refuses to hand out sessions afterwards.
        assert!(
            mngr.get_session(SessionKeyPredicate::Id(session_id))
                .await
                .is_err(),
            "a forced shutdown should leave the manager rejecting session work",
        );
    }

    #[tokio::test]
    async fn get_mesh_status_is_unconfigured_by_default() {
        // Without a mesh installed, the RPC answers cleanly with `configured =
        // false` rather than erroring (this is also the answer a daemon built
        // without the `networking-wg` feature gives).
        let server = TestServer::new().await;
        let mut client = server.connect().await;

        let resp = client.call::<minimald_rpc::GetMeshStatus>(&()).await;

        assert!(!resp.configured);
        assert!(resp.own_public_key.is_none());
        assert!(resp.peers.is_empty());
    }

    #[cfg(feature = "networking-wg")]
    #[tokio::test]
    async fn get_mesh_status_reports_own_key_and_peers() {
        use crate::net::wg::{Keypair, MeshConfig, PeerConfig};

        let server = TestServer::new().await;

        // Stand up a real mesh peer with one configured peer and install it.
        let remote = Keypair::generate();
        let cfg = MeshConfig {
            keypair: Keypair::generate(),
            listen_port: 0, // ephemeral; no traffic is sent in this test
            advertised_subnets: vec!["100.64.0.0/16".parse().unwrap()],
            peers: vec![PeerConfig {
                name: "remote".to_string(),
                public_key: remote.public(),
                endpoint: None,
                allowed_ips: vec!["100.65.0.0/16".parse().unwrap()],
            }],
        };
        let (sink_tx, _sink_rx) = tokio::sync::mpsc::channel(1);
        let mesh = std::sync::Arc::new(crate::net::wg::start(cfg, sink_tx).await.unwrap());
        let own_pub = mesh.own_public_key().to_base64();
        server.state.set_mesh(mesh).await;

        let mut client = server.connect().await;
        let resp = client.call::<minimald_rpc::GetMeshStatus>(&()).await;

        assert!(resp.configured);
        assert_eq!(resp.own_public_key.as_deref(), Some(own_pub.as_str()));
        assert_eq!(resp.advertised_subnets, vec!["100.64.0.0/16".to_string()]);
        assert_eq!(resp.peers.len(), 1);
        assert_eq!(resp.peers[0].name, "remote");
        assert_eq!(resp.peers[0].public_key, remote.public().to_base64());
        // Keep the sink alive until the assertions complete.
        drop(_sink_rx);
    }
}
