//! Provider discovery and TUI-specific RPC calls, built on the shared
//! [`minimal_client`] transport.
//!
//! A "provider" is a reachable daemon socket: the host `minimald` and the
//! `minvmd` microVM backend serve independent sockets, and both can be up
//! at once on Linux. On macOS only the VM path exists.

use std::path::Path;

use anyhow::Context as _;
use minimal_client::Client;
use minimald_rpc::{
    CreateSession, CreateSessionRequest, DestroySession, DestroySessionRequest, Errorable,
    GetSessionPolicy, GetSessionPolicyRequest, GetSessionRecord, GetSessionRecordRequest,
    GetVersion, ListSessions, RenameSession, RenameSessionRequest, SessionConfig,
};
use sessions::{NetworkMode, SessionId, SessionPolicy};

/// A reachable daemon the TUI lists sessions from.
pub struct Provider {
    /// Sidebar group label (`host` / `vm`).
    pub label: &'static str,
    /// The daemon's SSH socket, retained for attach and for background
    /// tasks that need their own connection.
    pub sock: std::path::PathBuf,
    pub client: Client,
}

impl std::fmt::Debug for Provider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Provider")
            .field("label", &self.label)
            .finish()
    }
}

/// The data one refresh pulls from a provider.
#[derive(Debug, Clone)]
pub struct ProviderData {
    pub label: String,
    pub version: String,
    pub sessions: Vec<minimald_rpc::ListSessionsEntry>,
}

/// Probe both known socket paths and connect to each reachable daemon.
/// Sockets that don't exist are skipped without a connect attempt, so
/// discovery never pays the connect-retry delay for a down provider.
pub async fn discover(minimal_dir: Option<&Path>) -> Vec<Provider> {
    let mut providers = Vec::new();
    for (label, use_minvmd) in [("host", false), ("vm", true)] {
        let Ok(sock) = minimal_client::resolve_socket_path(minimal_dir, use_minvmd) else {
            continue;
        };
        if !sock.exists() {
            continue;
        }
        match Client::connect(&sock).await {
            Ok(client) => providers.push(Provider {
                label,
                sock,
                client,
            }),
            Err(e) => {
                tracing::warn!(provider = label, error = %e, "socket present but daemon unreachable");
            }
        }
    }
    providers
}

/// Re-fetch the version string and session list for one provider.
pub async fn refresh(provider: &mut Provider) -> Result<ProviderData, anyhow::Error> {
    let version = provider
        .client
        .oneshot_rpc::<GetVersion>(())
        .await
        .context("GetVersion RPC failed")?;
    let sessions = provider
        .client
        .oneshot_rpc::<ListSessions>(())
        .await
        .context("ListSessions RPC failed")?
        .sessions;
    Ok(ProviderData {
        label: provider.label.to_string(),
        version: version.version,
        sessions,
    })
}

/// The record + networking policy behind the detail pane, fetched with one
/// RPC each per focus change.
pub async fn fetch_detail(
    provider: &mut Provider,
    id: SessionId,
) -> Result<(Option<sessions::Record>, Option<SessionPolicy>), anyhow::Error> {
    let record = provider
        .client
        .oneshot_rpc::<GetSessionRecord>(GetSessionRecordRequest::Id(id))
        .await
        .context("GetSessionRecord RPC failed")?
        .record;
    let policy = provider
        .client
        .oneshot_rpc::<GetSessionPolicy>(GetSessionPolicyRequest::Id(id))
        .await
        .context("GetSessionPolicy RPC failed")?
        .ok();
    Ok((record, policy))
}

/// Snapshot the session's live terminal screen. `Ok(None)` when the session
/// has no running host (the daemon answers "session is not active").
pub async fn fetch_screen(
    provider: &mut Provider,
    id: SessionId,
) -> Result<Option<minimald_rpc::ScreenSnapshot>, anyhow::Error> {
    let resp = provider
        .client
        .oneshot_rpc::<minimald_rpc::GetSessionScreen>(minimald_rpc::GetSessionScreenRequest::Id(
            id,
        ))
        .await
        .context("GetSessionScreen RPC failed")?;
    Ok(resp.ok())
}

pub async fn destroy(provider: &mut Provider, id: SessionId) -> Result<(), anyhow::Error> {
    match provider
        .client
        .oneshot_rpc::<DestroySession>(DestroySessionRequest { id })
        .await
        .context("DestroySession RPC failed")?
    {
        Errorable::Ok(_) => Ok(()),
        Errorable::Err { error } => Err(anyhow::anyhow!(error)),
    }
}

pub async fn rename(
    provider: &mut Provider,
    id: SessionId,
    new_name: &str,
) -> Result<(), anyhow::Error> {
    match provider
        .client
        .oneshot_rpc::<RenameSession>(RenameSessionRequest {
            id,
            new_name: new_name.to_string(),
        })
        .await
        .context("RenameSession RPC failed")?
    {
        Errorable::Ok(_) => Ok(()),
        Errorable::Err { error } => Err(anyhow::anyhow!(error)),
    }
}

/// The full activate flow behind the create form: create the record, upload
/// the project tree, compose the (empty) loadout, and finalize — so the new
/// session comes up `Active`, attachable, and restart-persistent rather than
/// dying as an unresumable `Pending` stub on the next daemon restart.
///
/// Connects its own client so it can run as a background task without
/// borrowing the provider's connection. A `ConfigureLoadout` that comes back
/// `Pending` (items needing interactive policy gating) aborts the session
/// and tells the user to run `min session activate` instead — the TUI has
/// no gating wizard yet.
pub async fn activate(
    sock: &Path,
    name: Option<String>,
    project_path: paths::HostAbsPath,
    network: NetworkMode,
) -> Result<SessionId, anyhow::Error> {
    let mut client = Client::connect(sock).await?;
    let id = match client
        .oneshot_rpc::<CreateSession>(CreateSessionRequest {
            config: SessionConfig {
                name,
                project_path: project_path.clone(),
                network,
                policy: SessionPolicy::default(),
                attrs: Default::default(),
            },
        })
        .await
        .context("CreateSession RPC failed")?
    {
        Errorable::Ok(resp) => resp.id,
        Errorable::Err { error } => return Err(anyhow::anyhow!(error)),
    };

    let flow = async {
        client
            .upload_workspace_files_quiet(id, project_path.as_utf8_path().as_std_path())
            .await
            .context("uploading project files")?;
        let configured = client
            .oneshot_rpc::<minimald_rpc::ConfigureLoadout>(minimald_rpc::ConfigureLoadoutRequest {
                session_id: id,
                contribution: Default::default(),
            })
            .await
            .context("ConfigureLoadout RPC failed")?;
        match configured {
            Errorable::Ok(minimald_rpc::ConfigureLoadoutResponse::Materialized) => {}
            Errorable::Ok(minimald_rpc::ConfigureLoadoutResponse::Pending { .. }) => {
                anyhow::bail!(
                    "this project needs interactive policy gating; \
                     create it with `min session activate` instead"
                );
            }
            Errorable::Err { error } => anyhow::bail!("{error}"),
        }
        match client
            .oneshot_rpc::<minimald_rpc::FinalizeSession>(minimald_rpc::FinalizeSessionRequest {
                session_id: id,
            })
            .await
            .context("FinalizeSession RPC failed")?
        {
            Errorable::Ok(_) => Ok(()),
            Errorable::Err { error } => anyhow::bail!("{error}"),
        }
    }
    .await;

    // A failed flow must not orphan the record: a `Pending` stub would hold
    // its name and be reaped at the next daemon restart anyway.
    if let Err(e) = flow {
        let _ = client
            .oneshot_rpc::<minimald_rpc::AbortSession>(minimald_rpc::AbortSessionRequest { id })
            .await;
        return Err(e);
    }
    Ok(id)
}
