use futures::StreamExt as _;
#[cfg(feature = "networking-proxy")]
use minimald_rpc::IssueClientCertResponse;
use minimald_rpc::{
    AbortSession, AbortSessionResponse, CleanCacheRequest, CleanCacheUpdate, CreateSession,
    DestroySession, DestroySessionResponse, Errorable, FinalizeSession, FinalizeSessionResponse,
    GetMeshStatus, GetSessionPolicy, GetSessionPolicyRequest, GetSessionRecord,
    GetSessionRecordRequest, GetSessionRecordResponse, GetSessionScreen, GetVersion,
    GetVersionResponse, IssueClientCert, IssueClientCertRequest, ListSessions, ListSessionsEntry,
    ListSessionsResponse, OneshotSshRpc, RPC_SUBSYSTEM_PREFIX, RenameSession,
    RenameSessionResponse, ResourcePool, SessionDelta, SessionDeltaRequest, SessionDeltaResponse,
    Shutdown, ShutdownRequest, ShutdownResponse, SubmitVerdict,
};
use russh::{
    Channel as RuChannel, ChannelId,
    server::{Msg, Session},
};
use sessions::SessionId;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, ReadBuf};
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
    ///
    /// On a handler error the message is written to SSH extended data
    /// (stream 1) before the channel is closed, so the client sees a
    /// legible error instead of an opaque EOF (#901).
    async fn handle_channel<F>(
        &self,
        mut c: RuChannel<Msg>,
        handler: F,
    ) -> Result<(), ConnectionError>
    where
        F: for<'a> AsyncFnOnce(Self::Request<'a>) -> Result<Self::Response, ConnectionError>,
    {
        // Read the request by draining Data messages until Eof or the
        // channel closes. Using wait() directly (rather than into_stream)
        // so the channel remains available for extended_data_bytes() and
        // close() on the error path (#901).
        let mut buf = Vec::with_capacity(1024);
        while let Some(msg) = c.wait().await {
            match msg {
                russh::ChannelMsg::Data { data } => buf.extend_from_slice(&data),
                russh::ChannelMsg::Eof | russh::ChannelMsg::Close => break,
                _ => {}
            }
        }

        // All error paths — JSON parse, handler, serialization — are funneled
        // through the same match so the client always sees a legible message
        // on extended data instead of an opaque EOF (#901).
        let result: Result<Vec<u8>, ConnectionError> = async {
            let request: Self::Request<'_> = serde_json_lenient::from_slice(&buf)?;
            let response = handler(request).await?;
            Ok(serde_json_lenient::to_vec(&response)?)
        }
        .await;

        match result {
            Ok(response_bytes) => {
                c.data_bytes(response_bytes).await?;
                c.eof().await?;
                c.close().await?;
                Ok(())
            }
            Err(e) => {
                let _ = c.extended_data_bytes(1, e.to_string()).await;
                let _ = c.close().await;
                Err(e)
            }
        }
    }
}

impl<T: OneshotSshRpc> ServeOneshot for T {}

async fn serve_get_version(c: RuChannel<Msg>) -> Result<(), ConnectionError> {
    GetVersion
        .handle_channel(c, async |_req| {
            Ok(GetVersionResponse {
                version: version::VERSION.to_string(),
                long_version: version::LONG_VERSION.to_string(),
                stdlib_version: stdlib::VERSION.to_string(),
            })
        })
        .await
}

async fn serve_list_sessions(
    s: ServerStateHandle,
    c: RuChannel<Msg>,
) -> Result<(), ConnectionError> {
    ListSessions
        .handle_channel(c, async |_req| {
            let resource_pool = tokio::task::spawn_blocking(detect_resource_pool)
                .await
                .map_err(|e| ConnectionError::Internal(e.to_string()))?;
            let mngr = s.sessions_manager().await;
            Ok(ListSessionsResponse {
                resource_pool,
                sessions: mngr
                    .list()
                    .await
                    .map_err(|e| ConnectionError::Internal(e.to_string()))?
                    .into_iter()
                    .map(|i| ListSessionsEntry {
                        id: i.id,
                        name: i.name,
                        project_path: Some(i.project_path),
                        status: i.status,
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
        .await
}

fn detect_resource_pool() -> Option<ResourcePool> {
    let cpu_cores = std::thread::available_parallelism()
        .ok()?
        .get()
        .try_into()
        .ok()?;
    let mut system = sysinfo::System::new();
    system.refresh_memory();
    let memory_bytes = system.total_memory();

    (memory_bytes > 0).then_some(ResourcePool {
        cpu_cores,
        memory_bytes,
    })
}

async fn serve_get_session_record(
    s: ServerStateHandle,
    c: RuChannel<Msg>,
) -> Result<(), ConnectionError> {
    use crate::sessions::SessionKeyPredicate;
    GetSessionRecord
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
        .await
}

/// Stand-in for `session_name` on the lifecycle records when the session
/// carries no user-assigned name. `SessionConfig::name` is `None` for an
/// anonymous session, and an absent field reads like a logging bug.
const ANONYMOUS_SESSION: &str = "<anonymous>";

/// `CreateSession`: allocates the session's record and brings its actor
/// up, replying with the assigned id. The loadout is composed separately,
/// by the `ConfigureLoadout` that follows.
async fn serve_create_session(
    s: ServerStateHandle,
    conn: ConnectionHandle,
    c: RuChannel<Msg>,
    ssh_username: Option<String>,
) -> Result<(), ConnectionError> {
    CreateSession
        .handle_channel(c, async |req| {
            let mngr = s.sessions_manager().await;
            // Read the name off the config before it is handed to the
            // manager: the success record below needs it, and the reply
            // carries only the assigned id.
            let session_name = req.config.name.clone();

            Ok(match mngr.create_session(req.config, ssh_username).await {
                Ok(id) => {
                    // Tag the session to this connection so it is reaped if
                    // the client drops before finalizing it (e.g. Ctrl-C at
                    // the gating prompt) — see [`ConnectionHandle`] and the
                    // teardown reap in `server.rs`.
                    conn.record_created_session(id).await;
                    tracing::info!(
                        session_id = %id,
                        session_name = session_name.as_deref().unwrap_or(ANONYMOUS_SESSION),
                        "session created"
                    );
                    Errorable::Ok(minimald_rpc::CreateSessionResponse { id })
                }
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
        .await
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
///
/// The actor refuses a re-`ConfigureLoadout` when it already holds a
/// pending contribution awaiting `SubmitVerdict`; the client has to
/// `AbortSession` and create a new session to retry. Without that guard
/// a second call would clobber the stashed `PendingComposeState` and
/// invalidate every `PendingId` the first caller received.
async fn serve_configure_loadout(
    s: ServerStateHandle,
    c: RuChannel<Msg>,
) -> Result<(), ConnectionError> {
    minimald_rpc::ConfigureLoadout
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
                Ok(None) => Errorable::Ok(minimald_rpc::ConfigureLoadoutResponse::Materialized),
                Ok(Some(response)) => {
                    Errorable::Ok(minimald_rpc::ConfigureLoadoutResponse::Pending { response })
                }
                Err(e) => Errorable::Err {
                    error: e.to_string(),
                },
            })
        })
        .await
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
async fn serve_submit_verdict(
    s: ServerStateHandle,
    c: RuChannel<Msg>,
) -> Result<(), ConnectionError> {
    SubmitVerdict
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
        .await
}

/// `FinalizeSession`: promotes a `Materializing` session to
/// `Active`. Gated on the patches-ready marker being present
/// under `<workspace>/patches/`; a missing marker (client crashed
/// mid-upload, or skipped the patches upload entirely) surfaces
/// as `Errorable::Err`. Idempotent on already-Active sessions.
async fn serve_finalize_session(
    s: ServerStateHandle,
    c: RuChannel<Msg>,
) -> Result<(), ConnectionError> {
    FinalizeSession
        .handle_channel(c, async |req| {
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
            Ok(match h.finalize().await {
                Ok(activate_hooks) => Errorable::Ok(FinalizeSessionResponse { activate_hooks }),
                Err(e) => Errorable::Err {
                    error: e.to_string(),
                },
            })
        })
        .await
}

/// `RenameSession`: resolves the session's actor (spinning it up from
/// disk if needed) and lets it persist the new name and relink its
/// PTask hostname. A name collision surfaces as the store's
/// `AlreadyExists` in the `Errorable::Err` text.
async fn serve_rename_session(
    s: ServerStateHandle,
    c: RuChannel<Msg>,
) -> Result<(), ConnectionError> {
    RenameSession
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
        .await
}

async fn serve_destroy_session(
    s: ServerStateHandle,
    c: RuChannel<Msg>,
) -> Result<(), ConnectionError> {
    DestroySession
        .handle_channel(c, async |req| {
            let mngr = s.sessions_manager().await;
            // Resolve the name before the delete — the request carries only
            // the id, and once the record is gone there is nothing left to
            // resolve it against. Purely for the record below, so a failed
            // lookup degrades to the anonymous stand-in rather than failing
            // a destroy that would otherwise succeed.
            let session_name = mngr
                .get_record(SessionKeyPredicate::Id(req.id))
                .await
                .ok()
                .flatten()
                .and_then(|record| record.name);
            match mngr.delete_session(req.id).await {
                Ok(()) => {
                    tracing::info!(
                        session_id = %req.id,
                        session_name = session_name.as_deref().unwrap_or(ANONYMOUS_SESSION),
                        "session destroyed"
                    );
                    Ok(Errorable::Ok(DestroySessionResponse))
                }
                Err(e) => Ok(Errorable::Err {
                    error: e.to_string(),
                }),
            }
        })
        .await
}

async fn serve_shutdown(s: ServerStateHandle, c: RuChannel<Msg>) -> Result<(), ConnectionError> {
    Shutdown
        .handle_channel(c, async |req: ShutdownRequest| {
            let mngr = s.sessions_manager().await;
            Ok(match mngr.shutdown(req.force).await {
                Ok(()) => {
                    // Close the file log first (both the native daemon and the
                    // microVM): it flushes buffered records, and in the
                    // microVM its write-open fd under the mountpoint would
                    // otherwise defeat the clean unmount below. Records still
                    // reach the console. A no-op for a foreground run.
                    s.release_log().await;
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
        .await
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
    // The file log was already released by the shutdown handler, so its fd no
    // longer holds the mountpoint busy.
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
async fn serve_abort_session(
    s: ServerStateHandle,
    c: RuChannel<Msg>,
) -> Result<(), ConnectionError> {
    AbortSession
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
        .await
}

async fn serve_get_session_policy(
    s: ServerStateHandle,
    c: RuChannel<Msg>,
) -> Result<(), ConnectionError> {
    GetSessionPolicy
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
        .await
}

/// `GetSessionHooks`: the lifecycle hooks composed into a session, each
/// with the loadout or project that declared it.
///
/// Read from the persisted composition snapshot, so it answers for a
/// session with no running host and survives a daemon restart. A session
/// whose snapshot is missing (activated before snapshots existed, or
/// reaped mid-write) reports an empty list rather than failing: "no
/// hooks recorded" is the honest answer, and there is nothing to run.
async fn serve_get_session_hooks(
    s: ServerStateHandle,
    c: RuChannel<Msg>,
) -> Result<(), ConnectionError> {
    minimald_rpc::GetSessionHooks
        .handle_channel(c, async |req| {
            let mngr = s.sessions_manager().await;
            let predicate = match req {
                minimald_rpc::GetSessionHooksRequest::Id(id) => SessionKeyPredicate::Id(id),
                minimald_rpc::GetSessionHooksRequest::Name(name) => SessionKeyPredicate::Name(name),
            };
            // The record first, only to tell "no such session" from "a
            // session with nothing recorded" — both of which the
            // composition read answers with `None`.
            if mngr
                .get_record(predicate.clone())
                .await
                .map_err(|e| ConnectionError::Internal(e.to_string()))?
                .is_none()
            {
                return Ok(Errorable::Err {
                    error: "no session found".to_string(),
                });
            }
            // Read-only: `get_composition` goes to the store rather than
            // the actor, so listing a stopped session's hooks does not
            // start it. Reporting on a session is not a reason to run one.
            let composition = mngr
                .get_composition(predicate)
                .await
                .map_err(|e| ConnectionError::Internal(e.to_string()))?;
            let hooks = composition
                .map(|c| {
                    c.lifecycle_hooks()
                        .iter()
                        .cloned()
                        .map(Into::into)
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            Ok(Errorable::Ok(hooks))
        })
        .await
}

/// `SessionDelta`: the session workspace's at-risk report — VCS-exact
/// (uncommitted files, unpushed commits) when the tree is a git repository,
/// the changed-since-activation rows otherwise. Best-effort by contract: an
/// unknown session, a session without a running host, and a failed
/// computation all answer `Unavailable` rather than an error — the client's
/// destroy confirm renders with or without the listing.
async fn serve_session_delta(
    s: ServerStateHandle,
    c: RuChannel<Msg>,
) -> Result<(), ConnectionError> {
    SessionDelta
        .handle_channel(c, async |req: SessionDeltaRequest| {
            let predicate = SessionKeyPredicate::Id(req.id);
            Ok(
                match s.sessions_manager().await.get_session(predicate).await {
                    Ok(Some(h)) => h.workspace_at_risk().await,
                    Ok(None) | Err(_) => SessionDeltaResponse::Unavailable,
                },
            )
        })
        .await
}

/// `GetSessionScreen` (`min dash` Preview section): a read-only snapshot of the
/// session's terminal screen. Unlike attach, this mints nothing and resizes
/// nothing — a session with no live host answers with an error the TUI
/// renders as "session not active".
async fn serve_get_session_screen(
    s: ServerStateHandle,
    c: RuChannel<Msg>,
) -> Result<(), ConnectionError> {
    GetSessionScreen
        .handle_channel(c, async |id| {
            let mngr = s.sessions_manager().await;
            let snapshot = mngr
                .get_screen(SessionKeyPredicate::Id(id))
                .await
                .map_err(|e| ConnectionError::Internal(e.to_string()))?;
            Ok(match snapshot {
                Some(snap) => Errorable::Ok(snap),
                None => Errorable::Err {
                    error: "session is not active".to_string(),
                },
            })
        })
        .await
}

/// Signs a fresh client certificate for the `minimal login` flow and returns
/// the cert PEM, key PEM, and CA cert PEM so the client can authenticate to
/// the HTTPS reverse proxy. Only compiled when the `networking-proxy` feature
/// is enabled.
#[cfg(feature = "networking-proxy")]
async fn serve_issue_client_cert(
    s: ServerStateHandle,
    c: RuChannel<Msg>,
) -> Result<(), ConnectionError> {
    IssueClientCert
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
        .await
}

/// Replies to an `IssueClientCert` request with a readable error when the
/// `networking-proxy` feature is compiled out, so the client sees "feature not
/// enabled" instead of an opaque EOF/channel-close on the response stream.
#[cfg(not(feature = "networking-proxy"))]
async fn serve_issue_client_cert_unavailable(c: RuChannel<Msg>) -> Result<(), ConnectionError> {
    IssueClientCert
        .handle_channel(c, async |_req: IssueClientCertRequest| {
            Ok(Errorable::Err {
                error: "minimald was built without the networking-proxy feature; \
                        client certificate issuance is unavailable"
                    .to_string(),
            })
        })
        .await
}

async fn serve_get_mesh_status(
    s: ServerStateHandle,
    c: RuChannel<Msg>,
) -> Result<(), ConnectionError> {
    GetMeshStatus
        .handle_channel(c, async |_req| Ok(s.mesh_status().await))
        .await
}

/// Serves [`CLEAN_CACHE_SUBSYSTEM`]: runs a cache clean and streams its
/// progress back as newline-delimited [`CleanCacheUpdate`]s.
///
/// The split between the two error surfaces is the wire contract: anything that
/// goes wrong before the clean starts leaves the payload stream empty and says
/// why on extended data, so a client that read no lines knows to look there.
/// Once the clean is running, its own failure is a terminal `Failed` line. (A
/// channel that breaks mid-stream also lands on the extended-data arm, where
/// the write is best-effort — by then the client is already gone.)
async fn serve_clean_cache(
    s: ServerStateHandle,
    mut c: RuChannel<Msg>,
) -> Result<(), ConnectionError> {
    match clean_cache_stream(&s, &mut c).await {
        Ok(()) => {
            c.eof().await?;
            c.close().await?;
            Ok(())
        }
        Err(e) => {
            let _ = c.extended_data_bytes(1, e.to_string()).await;
            let _ = c.close().await;
            Err(e)
        }
    }
}

/// Reads the request, then runs the clean, writing each event out as it
/// happens. The `Err` arm is for failures that precede the clean; a clean that
/// runs reports its own outcome on the payload stream.
async fn clean_cache_stream(
    s: &ServerStateHandle,
    c: &mut RuChannel<Msg>,
) -> Result<(), ConnectionError> {
    let req: CleanCacheRequest = read_channel_request(c).await?;
    let older_than = match req.older_than_secs {
        0 => None,
        secs => Some(std::time::Duration::from_secs(secs)),
    };
    // Every clean goes through the one actor. No actor means no daemon
    // housekeeping to ask (a state built outside `Server::run`), and a clean
    // started here instead would be exactly the unsynchronized second cleaner
    // the actor exists to prevent.
    let maintenance = s.maintenance().await.ok_or_else(|| {
        ConnectionError::Internal("daemon housekeeping is not running".to_string())
    })?;

    let (events, mut rx) = futures::channel::mpsc::unbounded();
    let clean = maintenance.clean_now(older_than, Some(events));
    let mut clean = std::pin::pin!(clean);

    // Drain events as they arrive, until the clean itself resolves. Once the
    // sender is dropped `rx` yields `None`, which disables that branch for the
    // rest of this `select!` — the clean's own branch is irrefutable and never
    // disabled, so the loop parks on it rather than spinning.
    let report = loop {
        tokio::select! {
            Some(event) = rx.next() => write_update(c, &removed(event)).await?,
            report = &mut clean => break report,
        }
    };
    // The clean is done, so its sender is dropped: whatever is still queued is
    // the tail, and the loop below ends on its own.
    while let Some(event) = rx.next().await {
        write_update(c, &removed(event)).await?;
    }

    let terminal = match report {
        Ok(report) => CleanCacheUpdate::Done {
            entries: report.entries,
            dirs: report.dirs,
        },
        Err(e) => CleanCacheUpdate::Failed {
            error: e.to_string(),
        },
    };
    write_update(c, &terminal).await
}

/// The wire form of one reclaimed thing. `render` is the daemon's own
/// rendering, so the RPC and the daemon log say the same words.
fn removed(event: op::CleanEvent) -> CleanCacheUpdate {
    CleanCacheUpdate::Removed {
        detail: event.render(),
    }
}

/// Writes one newline-delimited JSON update.
async fn write_update(
    c: &mut RuChannel<Msg>,
    update: &CleanCacheUpdate,
) -> Result<(), ConnectionError> {
    let mut line = serde_json_lenient::to_vec(update)?;
    line.push(b'\n');
    c.data_bytes(line).await?;
    Ok(())
}

/// Reads a JSON request body off `c`, draining until the client half-closes.
/// The streaming handlers' equivalent of what
/// [`ServeOneshot::handle_channel`] does inline.
async fn read_channel_request<T: serde::de::DeserializeOwned>(
    c: &mut RuChannel<Msg>,
) -> Result<T, ConnectionError> {
    let mut buf = Vec::with_capacity(1024);
    while let Some(msg) = c.wait().await {
        match msg {
            russh::ChannelMsg::Data { data } => buf.extend_from_slice(&data),
            russh::ChannelMsg::Eof | russh::ChannelMsg::Close => break,
            _ => {}
        }
    }
    Ok(serde_json_lenient::from_slice(&buf)?)
}

pub(crate) const STREAM_WORKSPACE_FILES: &str =
    constcat::concat!(RPC_SUBSYSTEM_PREFIX, "WorkspaceFilesTarZst");

pub(crate) const STREAM_WORKSPACE_PATCHES: &str =
    constcat::concat!(RPC_SUBSYSTEM_PREFIX, "WorkspacePatchesTarZst");

/// Marker file the patches unpacker drops after a successful
/// atomic swap. `FinalizeSession` checks for its presence before
/// promoting a session from `Materializing` to `Active`, so a
/// client-side crash between upload and finalize can't leave the
/// session `Active` without patches on disk. See the "why the
/// marker exists" note in `finalize_session_handler`.
pub(crate) const PATCHES_READY_MARKER: &str = ".patches_ready";

pub(crate) const STREAM_WORKSPACE_HOOK_SCRIPTS: &str =
    constcat::concat!(RPC_SUBSYSTEM_PREFIX, "WorkspaceHookScriptsTarZst");

/// Marker file the hook-script unpacker drops after a successful
/// atomic swap. `FinalizeSession` requires it before promoting a
/// session whose composition declares external hook scripts, so a
/// client that skipped the upload can't leave an `Active` session
/// whose hooks reference files that were never staged.
pub(crate) const HOOKS_READY_MARKER: &str = ".hooks_ready";

/// Per-entry size cap on incoming hook scripts. A lifecycle hook is a
/// shell script; a megabyte is already far past anything reasonable,
/// and the cap exists to stop a forged tar header from driving
/// `Vec::with_capacity` into an allocation failure, not to constrain
/// legitimate use.
const MAX_HOOK_SCRIPT_BYTES: u64 = 1024 * 1024;

/// Per-entry size cap on incoming patch archives. Legitimate patch files are
/// dotfiles (KB to a few MB); this ceiling is generous but bounded so a peer
/// forging a tar header can't push `Vec::with_capacity` into an allocation
/// error (panic → task abort) or trigger the allocator's OOM handler
/// (aborts the whole daemon).
const MAX_PATCH_ENTRY_BYTES: u64 = 1024 * 1024 * 1024;

/// Total bytes held in memory across every in-flight patch write in a single
/// `WorkspacePatchesTarZst` unpack. The per-entry cap alone isn't a memory
/// bound — the concurrency knob multiplies through it, so on a many-core
/// host without this the ceiling would be tens of GiB. Fixed at 1 GiB
/// regardless of core count: legitimate patch payloads are small dotfile
/// trees; the ceiling exists as an adversarial-input backstop, not as a
/// throughput knob.
const MAX_UNPACK_INFLIGHT_BYTES: usize = 1024 * 1024 * 1024;

/// Tallies the bytes pulled through an [`AsyncRead`] into a shared counter.
///
/// The counter is shared rather than returned because the reader is
/// swallowed by the decompressor and then by the tar unpacker: when the
/// transfer dies mid-stream those layers surface an error and drop the
/// reader, and the tally is the only surviving evidence of how far the
/// upload got.
struct CountingReader<R> {
    inner: R,
    count: Arc<AtomicU64>,
}

impl<R: AsyncRead + Unpin> AsyncRead for CountingReader<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let polled = Pin::new(&mut self.inner).poll_read(cx, buf);
        // Only a successful read grows `filled`; a pending or failed poll
        // leaves it untouched, so the delta is exactly what this poll
        // delivered regardless of which arm we are in.
        let read = buf.filled().len().saturating_sub(before);
        self.count.fetch_add(read as u64, Ordering::Relaxed);
        polled
    }
}

async fn serve_stream_workspace_files(
    s: ServerStateHandle,
    config: ChannelConfig,
    mut c: RuChannel<Msg>,
) -> Result<(), ConnectionError> {
    // Shared with the counting reader so the tally outlives the unpack on
    // both arms. Bytes-at-failure is the number that separates "the upload
    // never started" from "the upload died three-quarters of the way in".
    let received = Arc::new(AtomicU64::new(0));
    let unpacked = unpack_workspace_files(&s, &config, &mut c, &received).await;
    // Compressed bytes off the wire, not the unpacked tree: it is the
    // figure a client-side upload size can be compared against directly.
    let bytes_received = received.load(Ordering::Relaxed);

    let outcome = match unpacked {
        Ok(()) => {
            tracing::info!(bytes_received, "workspace upload complete");
            Ok(())
        }
        Err(msg) => {
            tracing::warn!(bytes_received, error = %msg, "workspace upload failed");
            let _ = c.extended_data_bytes(1, msg.clone()).await;
            Err(ConnectionError::Internal(msg))
        }
    };
    let _ = c.close().await;
    outcome
}

async fn serve_stream_workspace_patches(
    s: ServerStateHandle,
    config: ChannelConfig,
    mut c: RuChannel<Msg>,
) -> Result<(), ConnectionError> {
    let outcome = match unpack_workspace_patches(&s, &config, &mut c).await {
        Ok(()) => Ok(()),
        Err(msg) => {
            let _ = c.extended_data_bytes(1, msg.clone()).await;
            Err(ConnectionError::Internal(msg))
        }
    };
    let _ = c.close().await;
    outcome
}

/// Look up the session for an upload channel: pulls the session id
/// out of the channel env, resolves the live actor via the manager,
/// and returns its paths. Shared by both `WorkspaceFilesTarZst` and
/// `WorkspacePatchesTarZst`.
async fn upload_session_paths(
    s: &ServerStateHandle,
    config: &ChannelConfig,
) -> Result<crate::session::SessionPaths, String> {
    Ok(upload_session_handle(s, config).await?.1)
}

/// Same lookup as [`upload_session_paths`] but returns the session
/// handle too, so callers that need per-session serialization can
/// grab a lock without a second manager round-trip.
async fn upload_session_handle(
    s: &ServerStateHandle,
    config: &ChannelConfig,
) -> Result<(crate::session::SessionHandle, crate::session::SessionPaths), String> {
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
    Ok((session_handle, paths))
}

/// Unpacks the zstd-compressed tarball streamed over `c` into the
/// workspace directory of the session named by the channel environment,
/// tallying the wire bytes it consumes into `received`.
///
/// On failure, returns the human-readable message to relay back to the
/// client over the channel's extended-data stream.
async fn unpack_workspace_files(
    s: &ServerStateHandle,
    config: &ChannelConfig,
    c: &mut RuChannel<Msg>,
    received: &Arc<AtomicU64>,
) -> Result<(), String> {
    let paths = upload_session_paths(s, config).await?;
    // Emitted once the upload has a destination and before a single byte is
    // pulled, so a transfer that wedges mid-stream still leaves a record
    // saying which session it was for. Its pair is the complete/failed
    // record in the caller.
    tracing::info!("workspace upload started");

    let reader = async_compression::tokio::bufread::ZstdDecoder::new(tokio::io::BufReader::new(
        CountingReader {
            inner: c.make_reader(),
            count: Arc::clone(received),
        },
    ));
    async_tar::Archive::new(reader)
        .unpack(paths.working.as_utf8_path())
        .await
        .map_err(|e| format!("unpack failed: {e}"))?;

    Ok(())
}

/// Runs one dispatched RPC to completion, bracketing it with the pair of
/// records that let a reader reconstruct what the daemon did on a
/// connection from the log alone.
///
/// Start-and-finish rather than finish-only. Finish-only halves the volume
/// but cannot distinguish an RPC still in flight from one that was never
/// dispatched, and "started, never finished" is precisely the shape of a
/// hang — the case this logging exists to catch. Both records are emitted
/// inside the caller's `rpc` span, so each carries `rpc`, `trace_id` and
/// `span_id` from that span plus `conn`/`transport` from the enclosing
/// connection span, without repeating any of them as event fields.
async fn served(fut: impl Future<Output = Result<(), ConnectionError>>) {
    tracing::info!("rpc dispatched");
    let started = std::time::Instant::now();
    let outcome = fut.await;
    let duration_ms = started.elapsed().as_millis() as u64;
    match outcome {
        Ok(()) => tracing::info!(outcome = "ok", duration_ms, "rpc served"),
        Err(e) => tracing::warn!(outcome = "err", duration_ms, error = %e, "rpc failed"),
    }
}

/// What distinguishes one tar-upload stream from another.
///
/// Everything else about unpacking — validation, staging, the atomic
/// swap, the marker — is identical across streams and lives in
/// [`unpack_tar_zst_into`]. Adding a stream means describing it here,
/// not writing a second unpacker: the entry guards are security
/// checks, and a second copy is a second place for a fix to miss.
struct UnpackTarget {
    /// Live directory the staged tree is swapped into.
    dir: std::path::PathBuf,
    /// Marker filename dropped after a successful swap. Preconditions
    /// in `FinalizeSession` read it, so it is written last.
    marker: &'static str,
    /// Ceiling on a single entry's *declared* size. Guards against a
    /// forged header driving `Vec::with_capacity` into an allocation
    /// failure, not against legitimate volume.
    max_entry_bytes: u64,
    /// Serializes the swap against another upload on the same stream
    /// and session.
    lock: Arc<tokio::sync::Mutex<()>>,
    /// Noun for error messages — "patch", "hook script".
    label: &'static str,
}

/// Unpack a zstd-compressed tarball streamed over `c` into
/// `target.dir`.
///
/// The unpack is **atomic**: entries land in a per-upload staging dir
/// first, then swap into place once the stream ends cleanly. A
/// mid-stream failure leaves the staging tree behind (removed on the
/// next run) but never pollutes the live directory.
///
/// Every entry is validated before a byte reaches disk. The client
/// already rejects absolute and `..` paths at the wire-schema level,
/// but the client is untrusted, so the same checks run again here —
/// a peer writing raw tar bytes bypasses every client-side layer.
///
/// On success, drops `target.marker` under `target.dir`. The write
/// order matters: the marker only appears once every entry is on disk,
/// which is what lets `FinalizeSession` treat its presence as proof
/// the upload completed.
#[tracing::instrument(level = "debug", skip_all, fields(stream = target.label))]
async fn unpack_tar_zst_into(target: UnpackTarget, c: &mut RuChannel<Msg>) -> Result<(), String> {
    use std::path::Path as StdPath;

    let UnpackTarget {
        dir,
        marker,
        max_entry_bytes,
        lock,
        label,
    } = target;

    // Per-upload unique staging path so two concurrent uploads for
    // the same session never share a staging tree. The nanosecond
    // clock is fine as a discriminator — the swap lock below
    // serializes the install, so we don't need a strong guarantee
    // against collisions, only against name reuse across the two
    // in-flight tasks.
    let staging_dir = {
        let mut d = dir.clone();
        let suffix = format!(
            ".upload.{}.tmp",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0),
        );
        let name = d
            .file_name()
            .map(|n| {
                let mut n = n.to_os_string();
                n.push(&suffix);
                n
            })
            .unwrap_or_else(|| format!("upload{suffix}").into());
        d.set_file_name(name);
        d
    };

    // Fresh directory. `remove_dir_all` first is defensive against
    // an earlier `SystemTime` collision — extremely unlikely, but
    // cheap to guard against.
    let _ = tokio::fs::remove_dir_all(&staging_dir).await;
    tokio::fs::create_dir_all(&staging_dir)
        .await
        .map_err(|e| format!("creating {label} staging dir: {e}"))?;

    // Zstd decode + tar walk + per-entry unpack. Tar itself is a
    // stream format so decoding entries is sequential, but writing
    // the entry bodies to disk is where the cost actually is (a
    // serial loop over `fs::write` capped at ~190 MB/s per entry).
    // We buffer each body in memory and hand the write off to a
    // spawned task, so up to N files land on disk in parallel. The
    // concurrency cap keeps memory bounded (bodies live only until
    // the write completes) and prevents saturating the runtime's
    // blocking pool.
    let reader = async_compression::tokio::bufread::ZstdDecoder::new(tokio::io::BufReader::new(
        c.make_reader(),
    ));
    let archive = async_tar::Archive::new(reader);
    // Manual iteration so we can reject `..` per-entry before any
    // bytes hit disk. `Archive::unpack` walks entries itself but
    // has no per-entry validation hook.
    use futures::StreamExt as _;
    use tokio::io::AsyncReadExt as _;
    let mut entries = archive
        .entries()
        .map_err(|e| format!("reading {label} tar entries: {e}"))?;
    let write_concurrency = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);
    // Byte-budget semaphore: each in-flight body reserves permits
    // proportional to its size, and can't reserve if the total
    // in-flight bytes would exceed `MAX_UNPACK_INFLIGHT_BYTES`. This
    // is *the* backpressure — reserved *before* the body read, so a
    // slow disk pumps back into the tar decoder (into the pipe,
    // into the SSH channel) instead of into RAM. The concurrency
    // count guard below is a secondary limit to keep the blocking
    // pool from getting saturated by many small entries. `Arc`ed so
    // the spawned write tasks own their permits.
    let byte_budget = Arc::new(tokio::sync::Semaphore::new(MAX_UNPACK_INFLIGHT_BYTES));
    // `JoinSet` (not `FuturesUnordered<JoinHandle>`) so we can
    // `abort_all` in-flight writes on any error return. Dropping a
    // `JoinHandle` only detaches the task — writes queued when we
    // fail would otherwise keep running under `staging_dir`,
    // racing the next upload's `remove_dir_all` at the top of this
    // function and burning blocking-pool slots for results nobody
    // reads.
    let mut inflight: tokio::task::JoinSet<Result<(), String>> = tokio::task::JoinSet::new();
    let loop_result: Result<(), String> = async {
        while let Some(entry) = entries.next().await {
            let mut entry = entry.map_err(|e| format!("reading {label} tar entry: {e}"))?;
            let entry_path = entry
                .path()
                .map_err(|e| format!("decoding entry path: {e}"))?
                .into_owned();
            if !safe_relative_path(&entry_path) {
                return Err(format!(
                    "{label} archive entry rejected: `{}` contains an absolute path or a \
                     `..` component",
                    entry_path.display()
                ));
            }
            // Reject an entry that would clobber the ready marker.
            // Marker + uploaded file would otherwise race, and for
            // patches `materialize_patches_into_home` would silently
            // copy the emptied marker into the sandbox home, zeroing
            // whatever the user had there.
            if entry_path == StdPath::new(marker) {
                return Err(format!(
                    "{label} archive entry rejected: `{}` collides with the daemon's \
                     ready-marker filename",
                    entry_path.display()
                ));
            }
            // Only regular files are unpacked. The client's uploader
            // (`TarZstArchive::add_file`) only ever emits
            // `EntryType::Regular` — symlink sources are read through
            // (their target's bytes get archived as a regular file,
            // dropping the link relation on purpose) and directory
            // sources fan out into per-file Regular entries. Every
            // other entry type is out of scope: we do not create
            // directories, symlinks, hardlinks, or device nodes from
            // an uploaded archive. Blindly running `tokio::fs::write`
            // for any of those would silently land an empty file at
            // that path — a directory entry would then break
            // `create_dir_all(parent)` for its children, and a
            // symlink entry would drop the link target on the floor.
            // Fail loudly instead.
            let entry_type = entry.header().entry_type();
            if !matches!(
                entry_type,
                async_tar::EntryType::Regular | async_tar::EntryType::Continuous
            ) {
                return Err(format!(
                    "{label} archive entry rejected: `{}` is {entry_type:?}; only regular \
                     files are supported",
                    entry_path.display(),
                ));
            }
            let entry_size = entry.header().size().unwrap_or(0);
            // Per-entry cap: refuses forged headers that would push
            // `Vec::with_capacity` into an allocation panic or OOM
            // (allocator abort → whole daemon down) before we ever
            // reserve budget.
            if entry_size > max_entry_bytes {
                return Err(format!(
                    "{label} archive entry rejected: `{}` declares {entry_size} bytes, \
                     exceeds the {max_entry_bytes}-byte per-entry cap",
                    entry_path.display()
                ));
            }

            // Concurrency backpressure: bound the number of writes
            // in flight before we spawn the next one. Kept alongside
            // the byte budget below so a batch of tiny entries can't
            // saturate the blocking pool.
            while inflight.len() >= write_concurrency {
                match inflight.join_next().await {
                    Some(Ok(Ok(()))) => {}
                    Some(Ok(Err(e))) => return Err(e),
                    Some(Err(join_err)) => {
                        return Err(format!("write task panicked: {join_err}"));
                    }
                    None => break,
                }
            }

            // Byte-budget backpressure: reserve permits equal to
            // the entry size *before* the body read, so a stalled
            // fs::write can't let bodies pile up in RAM ahead of
            // it. Zero-byte entries take one permit — semaphores
            // can't acquire zero, but the practical peak is still
            // dominated by real-body permits.
            let permit_bytes = std::cmp::max(entry_size as usize, 1);
            let permit = Arc::clone(&byte_budget)
                .acquire_many_owned(permit_bytes as u32)
                .await
                .map_err(|e| format!("byte-budget semaphore closed: {e}"))?;

            let mut body = Vec::with_capacity(entry_size as usize);
            entry
                .read_to_end(&mut body)
                .await
                .map_err(|e| format!("reading body of `{}`: {e}", entry_path.display()))?;

            let dest = staging_dir.join(&entry_path);
            let path_display = entry_path.display().to_string();
            inflight.spawn(async move {
                if let Some(parent) = dest.parent() {
                    tokio::fs::create_dir_all(parent)
                        .await
                        .map_err(|e| format!("creating parent dir for `{path_display}`: {e}"))?;
                }
                tokio::fs::write(&dest, &body)
                    .await
                    .map_err(|e| format!("writing `{path_display}`: {e}"))?;
                // Explicit drop keeps the permit alive across the
                // fs::write so the byte budget only frees up after
                // the buffer is genuinely gone.
                drop(body);
                drop(permit);
                Ok::<_, String>(())
            });
        }
        // Drain any tasks still in flight.
        while let Some(res) = inflight.join_next().await {
            match res {
                Ok(Ok(())) => {}
                Ok(Err(e)) => return Err(e),
                Err(join_err) if join_err.is_cancelled() => {}
                Err(join_err) => return Err(format!("write task panicked: {join_err}")),
            }
        }
        Ok(())
    }
    .await;

    if loop_result.is_err() {
        // Cancel and drain every straggler write before returning.
        // `abort_all` only marks tasks; the drain awaits each
        // cancellation so no fs::write outlives this function and
        // races the next upload's `remove_dir_all`.
        inflight.abort_all();
        while inflight.join_next().await.is_some() {}
    }
    loop_result?;

    // Serialize the swap + marker-write against any other in-flight
    // upload on this stream for this session. Two concurrent uploads
    // would otherwise race on the live dir — one's `RENAME_EXCHANGE`
    // could observe an unexpected mid-swap state, or the marker could
    // get written pointing at the wrong upload's contents. The staging
    // phase above ran without the lock (all writes went to a per-upload
    // unique dir), so we only pay the serialization cost across the
    // seconds-of-work install step, not the minutes-of-work unpack.
    let _swap_guard = lock.lock_owned().await;

    // Install the new tree. Two shapes depending on whether a
    // prior tree exists:
    //
    // 1. **Prior tree present** — `renameat2(RENAME_EXCHANGE)` swaps
    //    the staging tree and the live tree atomically. At every
    //    instant an on-disk lookup sees exactly one of the two
    //    trees, and each carries a valid marker (the old one from
    //    the prior successful unpack, the new one written below).
    //    A `FinalizeSession` racing the swap can't observe a gap
    //    where the dir doesn't exist or where the marker is absent,
    //    only "old contents + old marker" or "new contents + new
    //    marker." We swap the trees first (contents on disk), then
    //    delete the old contents that ended up under `staging_dir`
    //    after the swap, then write the new marker over the old one.
    // 2. **First install** — no prior tree, so `RENAME_EXCHANGE`
    //    fails with `ENOENT`. Plain `rename` is atomic in this
    //    case (nothing to displace), so we fall through to it.
    //
    // Go through `common::renameat2` (a direct `renameat2(2)`
    // syscall wrapper) rather than `nix::fcntl::renameat2`: nix
    // gates that wrapper behind `target_env = "gnu"`, but `minimald`
    // is also cross-compiled for static musl (the guest initramfs),
    // where the nix item is configured out.
    let swap_result = tokio::task::spawn_blocking({
        let staging_dir = staging_dir.clone();
        let dir = dir.clone();
        move || {
            common::renameat2::renameat2_cwd(&staging_dir, &dir, common::renameat2::RENAME_EXCHANGE)
        }
    })
    .await
    .map_err(|e| format!("atomic-swap task panicked: {e}"))?;
    match swap_result {
        Ok(()) => {
            // `staging_dir` now holds the previous tree
            // (post-exchange). Drop it — a partial cleanup here is
            // fine; the next unpack's leading `remove_dir_all`
            // covers it.
            let _ = tokio::fs::remove_dir_all(&staging_dir).await;
        }
        Err(e) if e.raw_os_error() == Some(libc::ENOENT) => {
            // No prior tree — the `RENAME_EXCHANGE` requires both
            // sides to exist. Plain rename is atomic when the
            // destination doesn't exist yet.
            tokio::fs::rename(&staging_dir, &dir)
                .await
                .map_err(|e| format!("swapping {label} dir into place: {e}"))?;
        }
        Err(e) => {
            return Err(format!("atomic-swap of {label} dir failed: {e}"));
        }
    }

    // Marker last, so the newly-swapped contents can never coexist
    // with a stale marker. If we crash between the swap and this
    // write, the next upload's swap replaces the whole tree and
    // rewrites the marker — FinalizeSession is what fails safe, not
    // this handler.
    let marker_path = dir.join(StdPath::new(marker));
    tokio::fs::write(&marker_path, b"")
        .await
        .map_err(|e| format!("writing {label}-ready marker: {e}"))?;

    Ok(())
}

/// Unpacks the composition-patches tarball streamed over `c` into
/// `<workspace>/patches/`, keyed by each patch's sandbox-home-relative
/// destination. See [`unpack_tar_zst_into`] for the mechanics.
async fn unpack_workspace_patches(
    s: &ServerStateHandle,
    config: &ChannelConfig,
    c: &mut RuChannel<Msg>,
) -> Result<(), String> {
    let (session_handle, paths) = upload_session_handle(s, config).await?;
    let lock = session_handle
        .patches_upload_lock()
        .await
        .map_err(|e| format!("session is gone: {e}"))?;
    unpack_tar_zst_into(
        UnpackTarget {
            dir: paths.patches.as_utf8_path().as_std_path().to_path_buf(),
            marker: PATCHES_READY_MARKER,
            max_entry_bytes: MAX_PATCH_ENTRY_BYTES,
            lock,
            label: "patch",
        },
        c,
    )
    .await
}

/// Unpacks the external-hook-scripts tarball streamed over `c` into
/// `<workspace>/hooks/`.
///
/// Entry paths are the staged paths
/// [`staged_script_path`](sessions::core::lifecyclehook::staged_script_path)
/// produced on the client; the daemon re-derives the same paths from
/// the composition when it goes looking for a script, so nothing here
/// needs a manifest.
async fn unpack_workspace_hook_scripts(
    s: &ServerStateHandle,
    config: &ChannelConfig,
    c: &mut RuChannel<Msg>,
) -> Result<(), String> {
    let (session_handle, paths) = upload_session_handle(s, config).await?;
    let lock = session_handle
        .hook_scripts_upload_lock()
        .await
        .map_err(|e| format!("session is gone: {e}"))?;
    unpack_tar_zst_into(
        UnpackTarget {
            dir: paths.hooks.as_utf8_path().as_std_path().to_path_buf(),
            marker: HOOKS_READY_MARKER,
            max_entry_bytes: MAX_HOOK_SCRIPT_BYTES,
            lock,
            label: "hook script",
        },
        c,
    )
    .await
}
async fn serve_stream_workspace_hook_scripts(
    s: ServerStateHandle,
    config: ChannelConfig,
    mut c: RuChannel<Msg>,
) -> Result<(), ConnectionError> {
    let outcome = match unpack_workspace_hook_scripts(&s, &config, &mut c).await {
        Ok(()) => Ok(()),
        Err(msg) => {
            let _ = c.extended_data_bytes(1, msg.clone()).await;
            Err(ConnectionError::Internal(msg))
        }
    };
    let _ = c.close().await;
    outcome
}

/// Returns true if `p` is a relative path with no `..` components.
/// Enforced on every wire-supplied archive entry name.
fn safe_relative_path(p: &std::path::Path) -> bool {
    if p.is_absolute() {
        return false;
    }
    !p.components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
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
        | FinalizeSession::NAME
        | RenameSession::NAME
        | DestroySession::NAME
        | Shutdown::NAME
        | AbortSession::NAME
        | GetSessionPolicy::NAME
        | minimald_rpc::GetSessionHooks::NAME
        | SessionDelta::NAME
        | GetSessionScreen::NAME
        | GetMeshStatus::NAME
        | STREAM_WORKSPACE_FILES
        | STREAM_WORKSPACE_PATCHES
        | STREAM_WORKSPACE_HOOK_SCRIPTS
        | minimald_rpc::DIAG_BUNDLE_SUBSYSTEM
        | minimald_rpc::CLEAN_CACHE_SUBSYSTEM
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

    // Adopt the client's propagated trace context into this dispatch's span:
    // same trace id, fresh span id, the client's span as parent. Absent or
    // malformed values mint fresh — propagation is a diagnostic aid and must
    // never fail a request. Every record the handler emits carries the ids,
    // so one trace_id grep joins the CLI's log with this daemon's.
    use minimald_rpc::trace::{TRACEPARENT_ENV, TraceContext};
    use tracing::Instrument as _;
    let client_ctx = config
        .env_vars
        .get(TRACEPARENT_ENV)
        .and_then(|v| TraceContext::parse_traceparent(v));
    let ctx = client_ctx
        .as_ref()
        .map(TraceContext::child)
        .unwrap_or_else(TraceContext::mint);
    let span = tracing::info_span!(
        "rpc",
        rpc = name,
        trace_id = %ctx.trace_id_hex(),
        span_id = %ctx.span_id_hex(),
        parent_span_id = tracing::field::Empty,
    );
    if let Some(client_ctx) = &client_ctx {
        span.record(
            "parent_span_id",
            tracing::field::display(client_ctx.span_id_hex()),
        );
    }

    // Handle the named RPC (fire-and-forget; join handles are discarded).
    // `served` brackets each handler with its dispatch/outcome records —
    // the span alone emits nothing, so without them the ids minted above
    // never reach the log.
    macro_rules! serve {
        ($fut:expr) => {
            drop(spawn(served($fut).instrument(span.clone())))
        };
    }
    match name {
        GetVersion::NAME => serve!(serve_get_version(channel)),
        ListSessions::NAME => serve!(serve_list_sessions(s, channel)),
        GetSessionRecord::NAME => serve!(serve_get_session_record(s, channel)),
        CreateSession::NAME => serve!(serve_create_session(s, c.clone(), channel, ssh_username)),
        minimald_rpc::ConfigureLoadout::NAME => serve!(serve_configure_loadout(s, channel)),
        SubmitVerdict::NAME => serve!(serve_submit_verdict(s, channel)),
        FinalizeSession::NAME => serve!(serve_finalize_session(s, channel)),
        RenameSession::NAME => serve!(serve_rename_session(s, channel)),
        DestroySession::NAME => serve!(serve_destroy_session(s, channel)),
        Shutdown::NAME => serve!(serve_shutdown(s, channel)),
        AbortSession::NAME => serve!(serve_abort_session(s, channel)),
        GetSessionPolicy::NAME => serve!(serve_get_session_policy(s, channel)),
        minimald_rpc::GetSessionHooks::NAME => serve!(serve_get_session_hooks(s, channel)),
        SessionDelta::NAME => serve!(serve_session_delta(s, channel)),
        GetSessionScreen::NAME => serve!(serve_get_session_screen(s, channel)),
        GetMeshStatus::NAME => serve!(serve_get_mesh_status(s, channel)),
        STREAM_WORKSPACE_FILES => serve!(serve_stream_workspace_files(s, config, channel)),
        STREAM_WORKSPACE_PATCHES => serve!(serve_stream_workspace_patches(s, config, channel)),
        STREAM_WORKSPACE_HOOK_SCRIPTS => {
            serve!(serve_stream_workspace_hook_scripts(s, config, channel))
        }
        minimald_rpc::DIAG_BUNDLE_SUBSYSTEM => {
            serve!(crate::diag::serve_stream_diag_bundle(s, config, channel))
        }
        minimald_rpc::CLEAN_CACHE_SUBSYSTEM => serve!(serve_clean_cache(s, channel)),
        IssueClientCert::NAME => {
            #[cfg(feature = "networking-proxy")]
            serve!(serve_issue_client_cert(s, channel));
            #[cfg(not(feature = "networking-proxy"))]
            {
                tracing::warn!(
                    "IssueClientCert RPC called but the networking-proxy \
                     feature is not enabled; replying with an error"
                );
                drop(s);
                serve!(serve_issue_client_cert_unavailable(channel));
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

    /// Drives the `CleanCache` subsystem to completion, returning every update
    /// it streamed back in order.
    async fn clean_cache(client: &mut TestClient, req: CleanCacheRequest) -> Vec<CleanCacheUpdate> {
        let channel = client
            .open_subsystem(minimald_rpc::CLEAN_CACHE_SUBSYSTEM, &[])
            .await;
        let mut stream = channel.into_stream();
        stream
            .write_all(&serde_json_lenient::to_vec(&req).unwrap())
            .await
            .unwrap();
        // Half-close: the handler reads the request until the client is done.
        stream.shutdown().await.unwrap();

        let mut body = Vec::new();
        stream.read_to_end(&mut body).await.unwrap();
        String::from_utf8(body)
            .unwrap()
            .lines()
            .map(|line| serde_json_lenient::from_str(line).expect("each line is an update"))
            .collect()
    }

    /// The clean runs through the daemon's actor and reports back: a line per
    /// thing reclaimed, then exactly one terminal `Done` carrying the totals.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn clean_cache_streams_progress_then_a_terminal_done() {
        use lcache::{EntryMeta, FileSystem, MetaInner};
        use std::io::Write as _;

        let server = TestServer::new().await;
        let mut client = server.connect().await;

        // Two cold entries — nothing has read them, and no session needs them.
        let cache = server.state.daemon_context().await.local_cache();
        for byte in [1u8, 2] {
            let w = cache
                .write_dir(&common::SpecHash::from_bytes([byte; 32]))
                .unwrap();
            w.open_write("f").unwrap().write_all(b"x").unwrap();
            w.finalize(EntryMeta {
                inner: MetaInner::Spec(format!("pkg-{byte}")),
                fetched: false,
                ..Default::default()
            })
            .unwrap();
        }

        // `older_than_secs` of 1 rather than the daemon default, so entries
        // written a moment ago are in scope.
        let updates = clean_cache(
            &mut client,
            CleanCacheRequest::default().with_older_than_secs(1),
        )
        .await;

        let (terminal, progress) = updates.split_last().expect("at least a terminal update");
        assert_eq!(
            *terminal,
            CleanCacheUpdate::Done {
                entries: 2,
                dirs: 0
            }
        );
        assert_eq!(
            progress.len(),
            2,
            "one line per reclaimed entry: {progress:?}"
        );
        assert!(
            progress.iter().all(|u| matches!(u, CleanCacheUpdate::Removed { detail } if detail.starts_with("Deleting package pkg-"))),
            "progress should name what went: {progress:?}",
        );
        assert_eq!(cache.iter_entries().count(), 0);
    }

    /// An empty cache still terminates the stream properly — a client can
    /// always read to a terminal update.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn clean_cache_with_nothing_to_do_still_terminates() {
        let server = TestServer::new().await;
        let mut client = server.connect().await;

        let updates = clean_cache(&mut client, CleanCacheRequest::default()).await;

        assert_eq!(
            updates,
            vec![CleanCacheUpdate::Done {
                entries: 0,
                dirs: 0
            }]
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

    /// The upload's `bytes_received` field is only worth logging if it is
    /// exact, so pull a payload through in many small polls and check the
    /// tally accumulates across them rather than recording the last read.
    #[tokio::test]
    async fn counting_reader_tallies_every_byte_pulled_through() {
        let payload: Vec<u8> = (0..8192u32).map(|i| i as u8).collect();
        let count = Arc::new(AtomicU64::new(0));
        let mut sunk = Vec::new();

        let read = tokio::io::copy(
            &mut CountingReader {
                inner: payload.as_slice(),
                count: Arc::clone(&count),
            },
            &mut sunk,
        )
        .await
        .unwrap();

        assert_eq!(sunk, payload);
        assert_eq!(read, payload.len() as u64);
        assert_eq!(count.load(Ordering::Relaxed), payload.len() as u64);
    }

    /// `WorkspacePatchesTarZst` unpacks each entry under
    /// `<workspace>/patches/<archive-path>` and drops the ready
    /// marker on success. Guards the write ordering
    /// (staging-dir → atomic rename → marker) that FinalizeSession
    /// depends on.
    #[tokio::test]
    async fn stream_workspace_patches_unpacks_and_writes_marker() {
        let server = TestServer::new().await;
        let mut client = server.connect().await;
        let session_id = fresh_session(&mut client).await;

        let payload = tar_zst(&[
            (".config/helix/config.toml", b"theme = 'nord'\n"),
            (".config/other.toml", b"key = 'value'\n"),
        ])
        .await;

        let channel = client
            .open_subsystem(
                STREAM_WORKSPACE_PATCHES,
                &[(MINIMAL_SESSION_ID_ENV, &session_id.to_string())],
            )
            .await;
        let mut stream = channel.into_stream();
        stream.write_all(&payload).await.unwrap();
        stream.shutdown().await.unwrap();
        let mut trailing = Vec::new();
        stream.read_to_end(&mut trailing).await.unwrap();

        let mngr = server.state.sessions_manager().await;
        let handle = mngr
            .get_session(SessionKeyPredicate::Id(session_id))
            .await
            .unwrap()
            .expect("session should be retrievable");
        let paths = handle.paths().await.unwrap();
        let patches = paths.patches.as_utf8_path();

        assert_eq!(
            tokio::fs::read(patches.join(".config/helix/config.toml"))
                .await
                .unwrap(),
            b"theme = 'nord'\n",
        );
        assert_eq!(
            tokio::fs::read(patches.join(".config/other.toml"))
                .await
                .unwrap(),
            b"key = 'value'\n",
        );
        assert!(
            tokio::fs::try_exists(patches.join(PATCHES_READY_MARKER))
                .await
                .unwrap(),
            "patches-ready marker must be written on successful unpack",
        );
    }

    /// Build a tar+zstd archive with full control over each entry's
    /// type and declared size, so tests can produce the malformed
    /// shapes a hostile peer would hand-craft — `tar_zst` can only
    /// build well-formed regular-file entries.
    ///
    /// `declared_size` overrides the header's size field without
    /// changing the body, which is how the forged-header case is
    /// reproduced.
    async fn tar_zst_raw(entries: &[(&str, &[u8], async_tar::EntryType, Option<u64>)]) -> Vec<u8> {
        let mut tar = async_tar::Builder::new(Vec::new());
        for (path, contents, entry_type, declared_size) in entries {
            let mut header = async_tar::Header::new_gnu();
            header.set_size(declared_size.unwrap_or(contents.len() as u64));
            header.set_mode(0o644);
            header.set_entry_type(*entry_type);
            tar.append_data(&mut header, path, *contents).await.unwrap();
        }
        let tar_bytes = tar.into_inner().await.unwrap();
        let mut encoder = async_compression::tokio::write::ZstdEncoder::new(Vec::new());
        encoder.write_all(&tar_bytes).await.unwrap();
        encoder.shutdown().await.unwrap();
        encoder.into_inner()
    }

    /// Build a tar+zstd archive whose entry name is written straight
    /// into the header's raw name field, bypassing the path validation
    /// `Builder::append_data` performs.
    ///
    /// This is the only way to produce the archive shape the daemon's
    /// traversal guard exists for: `async_tar`'s builder refuses to
    /// *construct* a `..` entry, so a well-behaved client cannot make
    /// one — but a hostile peer writing tar bytes by hand can, and that
    /// is the case the guard has to catch.
    async fn tar_zst_forged_name(name: &[u8], contents: &[u8]) -> Vec<u8> {
        let mut header = async_tar::Header::new_gnu();
        header.set_size(contents.len() as u64);
        header.set_mode(0o644);
        header.set_entry_type(async_tar::EntryType::Regular);
        // Raw name write: `set_path` would reject or normalize this.
        {
            let gnu = header.as_gnu_mut().expect("new_gnu produces a GNU header");
            gnu.name[..name.len()].copy_from_slice(name);
        }
        header.set_cksum();

        let mut tar = async_tar::Builder::new(Vec::new());
        tar.append(&header, contents).await.unwrap();
        let tar_bytes = tar.into_inner().await.unwrap();

        let mut encoder = async_compression::tokio::write::ZstdEncoder::new(Vec::new());
        encoder.write_all(&tar_bytes).await.unwrap();
        encoder.shutdown().await.unwrap();
        encoder.into_inner()
    }

    /// Push `payload` through `subsystem` for `session_id` and return
    /// whatever the daemon relayed on stderr — empty on success. Keeps
    /// the channel (rather than `into_stream`) so extended data stays
    /// readable, which is how a rejection is signalled.
    async fn upload_and_collect_stderr(
        client: &mut TestClient,
        subsystem: &str,
        session_id: SessionId,
        payload: &[u8],
    ) -> String {
        use russh::ChannelMsg;
        let mut channel = client
            .open_subsystem(
                subsystem,
                &[(MINIMAL_SESSION_ID_ENV, &session_id.to_string())],
            )
            .await;
        channel.data(payload).await.unwrap();
        channel.eof().await.unwrap();
        let mut stderr = Vec::new();
        while let Some(msg) = channel.wait().await {
            if let ChannelMsg::ExtendedData { data, ext: 1 } = msg {
                stderr.extend_from_slice(&data);
            }
        }
        String::from_utf8_lossy(&stderr).into_owned()
    }

    /// Resolve a session's staged-patches and staged-hooks dirs.
    async fn staged_dirs(
        server: &TestServer,
        session_id: SessionId,
    ) -> (camino::Utf8PathBuf, camino::Utf8PathBuf) {
        let mngr = server.state.sessions_manager().await;
        let handle = mngr
            .get_session(SessionKeyPredicate::Id(session_id))
            .await
            .unwrap()
            .expect("session should be retrievable");
        let paths = handle.paths().await.unwrap();
        (
            paths.patches.as_utf8_path().to_owned(),
            paths.hooks.as_utf8_path().to_owned(),
        )
    }

    /// A `..` entry is refused end-to-end, not merely by the
    /// `safe_relative_path` unit above: the guard has to actually be
    /// wired into the unpack loop, before any byte reaches disk.
    #[tokio::test]
    async fn stream_workspace_patches_rejects_traversal_end_to_end() {
        let server = TestServer::new().await;
        let mut client = server.connect().await;
        let session_id = fresh_session(&mut client).await;

        let payload = tar_zst_forged_name(b"../escape.toml", b"pwned\n").await;
        let stderr =
            upload_and_collect_stderr(&mut client, STREAM_WORKSPACE_PATCHES, session_id, &payload)
                .await;

        assert!(
            stderr.contains("`..`") || stderr.contains("absolute path"),
            "expected a traversal rejection, got: {stderr:?}",
        );
        let (patches, _) = staged_dirs(&server, session_id).await;
        assert!(
            !tokio::fs::try_exists(patches.join(PATCHES_READY_MARKER))
                .await
                .unwrap_or(false),
            "a rejected upload must not leave a ready marker",
        );
    }

    /// An entry named exactly like the ready marker is refused: it
    /// would otherwise be copied into the sandbox home by
    /// `materialize_patches_into_home`, zeroing whatever the user had
    /// at that path.
    #[tokio::test]
    async fn stream_workspace_patches_rejects_marker_collision() {
        let server = TestServer::new().await;
        let mut client = server.connect().await;
        let session_id = fresh_session(&mut client).await;

        let payload = tar_zst(&[(PATCHES_READY_MARKER, b"")]).await;
        let stderr =
            upload_and_collect_stderr(&mut client, STREAM_WORKSPACE_PATCHES, session_id, &payload)
                .await;

        assert!(
            stderr.contains("ready-marker"),
            "expected a marker-collision rejection, got: {stderr:?}",
        );
    }

    /// Only regular files are unpacked. A directory entry would
    /// otherwise be written as an empty *file*, which then breaks
    /// `create_dir_all` for anything nested beneath it.
    #[tokio::test]
    async fn stream_workspace_patches_rejects_non_regular_entry() {
        let server = TestServer::new().await;
        let mut client = server.connect().await;
        let session_id = fresh_session(&mut client).await;

        let payload = tar_zst_raw(&[("adir", b"", async_tar::EntryType::Directory, None)]).await;
        let stderr =
            upload_and_collect_stderr(&mut client, STREAM_WORKSPACE_PATCHES, session_id, &payload)
                .await;

        assert!(
            stderr.contains("only regular files"),
            "expected a non-regular-entry rejection, got: {stderr:?}",
        );
    }

    /// A forged header declaring more bytes than the per-entry cap is
    /// refused on the header alone, before the body is read — the
    /// check that stops `Vec::with_capacity` being driven into an
    /// allocation failure.
    #[tokio::test]
    async fn stream_workspace_patches_rejects_oversize_declared_entry() {
        let server = TestServer::new().await;
        let mut client = server.connect().await;
        let session_id = fresh_session(&mut client).await;

        let payload = tar_zst_raw(&[(
            "big.toml",
            b"small body",
            async_tar::EntryType::Regular,
            Some(MAX_PATCH_ENTRY_BYTES + 1),
        )])
        .await;
        let stderr =
            upload_and_collect_stderr(&mut client, STREAM_WORKSPACE_PATCHES, session_id, &payload)
                .await;

        assert!(
            stderr.contains("per-entry cap"),
            "expected an oversize rejection, got: {stderr:?}",
        );
    }

    /// A second upload replaces the first tree wholesale rather than
    /// merging into it, and the marker survives. Exercises both swap
    /// branches: the first upload takes the plain-rename path (no
    /// prior tree), the second takes `RENAME_EXCHANGE`.
    #[tokio::test]
    async fn stream_workspace_patches_second_upload_replaces_the_tree() {
        let server = TestServer::new().await;
        let mut client = server.connect().await;
        let session_id = fresh_session(&mut client).await;

        let first = tar_zst(&[("only-in-first.toml", b"a\n")]).await;
        assert_eq!(
            upload_and_collect_stderr(&mut client, STREAM_WORKSPACE_PATCHES, session_id, &first)
                .await,
            "",
        );
        let second = tar_zst(&[("only-in-second.toml", b"b\n")]).await;
        assert_eq!(
            upload_and_collect_stderr(&mut client, STREAM_WORKSPACE_PATCHES, session_id, &second)
                .await,
            "",
        );

        let (patches, _) = staged_dirs(&server, session_id).await;
        assert!(
            tokio::fs::try_exists(patches.join("only-in-second.toml"))
                .await
                .unwrap(),
            "the second upload's contents must be present",
        );
        assert!(
            !tokio::fs::try_exists(patches.join("only-in-first.toml"))
                .await
                .unwrap(),
            "the first upload's contents must be gone, not merged",
        );
        assert!(
            tokio::fs::try_exists(patches.join(PATCHES_READY_MARKER))
                .await
                .unwrap(),
            "the marker must survive the swap",
        );
    }

    // -- hook scripts ---------------------------------------------------

    /// The hook-script stream unpacks under `<workspace>/hooks/` at the
    /// staged path the client derived, and drops its own ready marker.
    #[tokio::test]
    async fn stream_workspace_hook_scripts_unpacks_and_writes_marker() {
        let server = TestServer::new().await;
        let mut client = server.connect().await;
        let session_id = fresh_session(&mut client).await;

        let payload = tar_zst(&[
            ("loadout/dev/activate.sh", b"echo hi\n"),
            ("project/scripts/setup.sh", b"echo setup\n"),
        ])
        .await;
        let stderr = upload_and_collect_stderr(
            &mut client,
            STREAM_WORKSPACE_HOOK_SCRIPTS,
            session_id,
            &payload,
        )
        .await;
        assert_eq!(stderr, "", "upload should succeed");

        let (_, hooks) = staged_dirs(&server, session_id).await;
        assert_eq!(
            tokio::fs::read(hooks.join("loadout/dev/activate.sh"))
                .await
                .unwrap(),
            b"echo hi\n",
        );
        assert_eq!(
            tokio::fs::read(hooks.join("project/scripts/setup.sh"))
                .await
                .unwrap(),
            b"echo setup\n",
        );
        assert!(
            tokio::fs::try_exists(hooks.join(HOOKS_READY_MARKER))
                .await
                .unwrap(),
            "hooks-ready marker must be written on successful unpack",
        );
    }

    /// The hook-script stream enforces the same entry guards as the
    /// patch stream. Parameterized over the malformed shapes so the two
    /// paths can't drift in what they refuse.
    #[tokio::test]
    async fn stream_workspace_hook_scripts_rejects_malformed_entries() {
        let server = TestServer::new().await;
        let mut client = server.connect().await;
        let session_id = fresh_session(&mut client).await;

        let cases: Vec<(&str, Vec<u8>)> = vec![
            (
                "`..`",
                tar_zst_forged_name(b"../escape.sh", b"pwned\n").await,
            ),
            ("ready-marker", tar_zst(&[(HOOKS_READY_MARKER, b"")]).await),
            (
                "only regular files",
                tar_zst_raw(&[("adir", b"", async_tar::EntryType::Directory, None)]).await,
            ),
            (
                "per-entry cap",
                tar_zst_raw(&[(
                    "big.sh",
                    b"small",
                    async_tar::EntryType::Regular,
                    Some(MAX_HOOK_SCRIPT_BYTES + 1),
                )])
                .await,
            ),
        ];
        for (needle, payload) in cases {
            let stderr = upload_and_collect_stderr(
                &mut client,
                STREAM_WORKSPACE_HOOK_SCRIPTS,
                session_id,
                &payload,
            )
            .await;
            assert!(
                stderr.contains(needle),
                "expected a rejection mentioning {needle:?}, got: {stderr:?}",
            );
        }

        let (_, hooks) = staged_dirs(&server, session_id).await;
        assert!(
            !tokio::fs::try_exists(hooks.join(HOOKS_READY_MARKER))
                .await
                .unwrap_or(false),
            "no rejected upload may leave a ready marker",
        );
    }

    /// Unit test on the daemon-side traversal guard — the piece
    /// covering a malicious peer that hand-crafts a raw tar with
    /// `..` entries (the client's own `async_tar` builder refuses
    /// to construct one, and `SandboxRelPath::try_new` already
    /// rejects them at the wire-schema level, so this is a
    /// defense-in-depth check for the "hand-crafted bytes"
    /// scenario the earlier layers don't cover).
    #[test]
    fn safe_relative_path_rejects_absolute_and_traversal() {
        use std::path::Path as StdPath;
        // Absolute — must reject.
        assert!(!super::safe_relative_path(StdPath::new("/etc/foo")));
        // `..` at any position — must reject.
        assert!(!super::safe_relative_path(StdPath::new("../evil")));
        assert!(!super::safe_relative_path(StdPath::new("a/../b")));
        assert!(!super::safe_relative_path(StdPath::new("a/b/..")));
        // Ordinary relative paths — must accept.
        assert!(super::safe_relative_path(StdPath::new("a")));
        assert!(super::safe_relative_path(StdPath::new("a/b/c")));
        assert!(super::safe_relative_path(StdPath::new(
            ".config/helix/config.toml"
        )));
    }

    /// When the daemon fails to parse a request (or the handler errors),
    /// the error message must reach the client on extended data instead
    /// of the client seeing an opaque EOF on the response stream (#901).
    #[tokio::test]
    async fn oneshot_rpc_surfaces_handler_errors_as_extended_data() {
        use russh::ChannelMsg;

        let server = TestServer::new().await;
        let mut client = server.connect().await;

        // Send invalid JSON to a known subsystem: handle_channel will fail
        // at serde_json_lenient::from_slice, which now writes the error to extended
        // data before closing the channel.
        let mut channel = client.open_subsystem(GetVersion::NAME, &[]).await;
        channel
            .data_bytes(b"not valid json".to_vec())
            .await
            .unwrap();
        channel.eof().await.unwrap();

        let mut err_buf = Vec::new();
        let mut data_buf = Vec::new();
        while let Some(msg) = channel.wait().await {
            match msg {
                ChannelMsg::ExtendedData { data, ext: 1 } => err_buf.extend_from_slice(&data),
                ChannelMsg::Data { data } => data_buf.extend_from_slice(&data),
                _ => {}
            }
        }

        assert!(
            !err_buf.is_empty(),
            "expected an error on extended data, got data={:?}, err=empty",
            String::from_utf8_lossy(&data_buf),
        );
        assert!(
            data_buf.is_empty(),
            "expected no response data on error, got {:?}",
            String::from_utf8_lossy(&data_buf),
        );
    }

    #[tokio::test]
    async fn get_version_returns_compiled_in_versions() {
        let server = TestServer::new().await;
        let mut client = server.connect().await;

        let resp = client.call::<GetVersion>(&()).await;

        assert_eq!(resp.version, version::VERSION);
        assert_eq!(resp.long_version, version::LONG_VERSION);
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
            assert_eq!(resp.version, version::VERSION);
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
        assert!(list_sessions.resource_pool.is_some());
        assert_eq!(
            list_sessions.sessions,
            vec![ListSessionsEntry {
                id,
                name: Some("my session".to_string()),
                project_path: Some(HostAbsPath::try_new("/uwu").unwrap()),
                // A freshly-created session that hasn't been configured yet
                // sits in `Pending` until `ConfigureLoadout` promotes it.
                status: sessions::SessionStatus::Pending,
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
                    hooks_enabled: true,
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
    async fn get_session_screen_snapshots_the_live_terminal() {
        let server = TestServer::new().await;
        let mut client = server.connect().await;
        let session_id = fresh_session(&mut client).await;

        // Before anything attaches there is no host: the RPC answers with a
        // soft error instead of minting one.
        let inactive = client.call::<GetSessionScreen>(&session_id).await;
        assert!(
            matches!(&inactive, Errorable::Err { error } if error.contains("not active")),
            "expected a not-active error, got {inactive:?}",
        );

        // Attach a shell (the mock launcher runs an echo program), then write
        // a line the program echoes back prefixed with `got:`.
        let shell = client.open_shell(session_id).await;
        shell.data_bytes(&b"hello-screen\n"[..]).await.unwrap();

        // The echo round-trips through the pty asynchronously; poll the RPC
        // until the parser has seen it.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let snapshot = loop {
            let resp = client.call::<GetSessionScreen>(&session_id).await;
            match resp {
                Errorable::Ok(snap) => {
                    let text: String = snap
                        .lines
                        .iter()
                        .map(|row| row.cells.iter().map(|c| c.ch).collect::<String>())
                        .collect::<Vec<_>>()
                        .join("\n");
                    if text.contains("got:hello-screen") {
                        break snap;
                    }
                }
                Errorable::Err { .. } => {}
            }
            assert!(
                std::time::Instant::now() < deadline,
                "timed out waiting for the echo to reach the screen snapshot",
            );
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        };
        assert_eq!((snapshot.rows, snapshot.cols), (24, 80));
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
                    hooks_enabled: true,
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
                lifecycle_hooks: vec![],
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
