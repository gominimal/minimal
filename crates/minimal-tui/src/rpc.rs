//! Daemon-facing RPC for the TUI: provider discovery, refresh, and the
//! session actions, all over the [`minimal_client`] transport.
//!
//! A "provider" is a reachable daemon socket: the host `minimald` and the
//! `minvmd` microVM backend serve independent sockets, and both can be up
//! at once on Linux. On macOS only the VM path exists.

use std::path::{Path, PathBuf};

use anyhow::Context as _;
use minimal_client::Client;
use minimald_rpc::{
    CreateSession, CreateSessionRequest, DestroySession, DestroySessionRequest, Errorable,
    GetSessionPolicy, GetSessionPolicyRequest, GetSessionRecord, GetSessionRecordRequest,
    GetVersion, ListSessions, OneshotSshRpc, RenameSession, RenameSessionRequest, SessionConfig,
};
use sessions::{NetworkMode, SessionId, SessionPolicy};

/// Deadline for the UI-loop RPCs. The draw loop awaits these inline, so a
/// wedged-but-connected daemon (a suspended microVM behind libkrun's
/// always-accepting bridge) must fail fast enough that the TUI stays
/// responsive; the client transport's own, much longer deadline is the
/// backstop for the CLI and background tasks.
const RPC_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Per-attempt deadline when (re)connecting a provider mid-run. Connect
/// retries absorb ~2s on their own; anything longer is a wedged acceptor
/// and the next rediscovery pass will try again.
const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(4);

/// The canonical providers in probe order: label plus whether to resolve
/// the microVM backend's socket.
const PROBES: &[(&str, bool)] = &[("host", false), ("vm", true)];

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

/// The probe list as `(label, socket)` candidates. Two probes can resolve
/// to one socket — on macOS both provider kinds map to the minvmd state
/// dir — so dedupe by path and keep the later (more specific) label;
/// otherwise one daemon would be discovered twice and list every session
/// twice.
fn probe_candidates(minimal_dir: Option<&Path>) -> Vec<(&'static str, PathBuf)> {
    let mut candidates: Vec<(&'static str, PathBuf)> = Vec::new();
    for &(label, use_minvmd) in PROBES {
        let Ok(sock) = minimal_client::resolve_socket_path(minimal_dir, use_minvmd) else {
            continue;
        };
        if let Some(existing) = candidates.iter_mut().find(|(_, s)| *s == sock) {
            existing.0 = label;
            continue;
        }
        candidates.push((label, sock));
    }
    candidates
}

/// Probe both known socket paths and connect to each reachable daemon.
/// Sockets that don't exist are skipped without a connect attempt, so
/// discovery never pays the connect-retry delay for a down provider.
pub async fn discover(minimal_dir: Option<&Path>) -> Vec<Provider> {
    let mut providers = Vec::new();
    for (label, sock) in probe_candidates(minimal_dir) {
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

/// Connect to any canonical provider not already served, so a daemon that
/// (re)appears mid-run joins the dashboard. Each attempt is bounded by
/// [`CONNECT_TIMEOUT`] so a wedged acceptor can't stall the UI loop.
pub async fn connect_missing(providers: &mut Vec<Provider>, minimal_dir: Option<&Path>) {
    for (label, sock) in probe_candidates(minimal_dir) {
        if providers.iter().any(|p| p.label == label || p.sock == sock) {
            continue;
        }
        if !sock.exists() {
            continue;
        }
        match tokio::time::timeout(CONNECT_TIMEOUT, Client::connect(&sock)).await {
            Ok(Ok(client)) => {
                tracing::info!(provider = label, "provider connected");
                providers.push(Provider {
                    label,
                    sock,
                    client,
                });
            }
            Ok(Err(e)) => {
                tracing::debug!(provider = label, error = %e, "provider reconnect failed");
            }
            Err(_) => {
                tracing::debug!(provider = label, "provider reconnect timed out");
            }
        }
    }
}

/// A oneshot RPC bounded by [`RPC_TIMEOUT`]: the UI loop awaits these
/// inline, so an unresponsive daemon must fail the call rather than the
/// whole TUI.
async fn timed<R: OneshotSshRpc>(
    client: &mut Client,
    request: R::Request<'_>,
) -> Result<R::Response, anyhow::Error>
where
    R::Response: serde::de::DeserializeOwned,
{
    tokio::time::timeout(RPC_TIMEOUT, client.oneshot_rpc::<R>(request))
        .await
        .map_err(|_| anyhow::anyhow!("{} RPC timed out after {RPC_TIMEOUT:?}", R::NAME))?
}

/// Re-fetch the version string and session list for one provider.
pub async fn refresh(provider: &mut Provider) -> Result<ProviderData, anyhow::Error> {
    let version = timed::<GetVersion>(&mut provider.client, ())
        .await
        .context("GetVersion RPC failed")?;
    let sessions = timed::<ListSessions>(&mut provider.client, ())
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
    let record = timed::<GetSessionRecord>(&mut provider.client, GetSessionRecordRequest::Id(id))
        .await
        .context("GetSessionRecord RPC failed")?
        .record;
    let policy = timed::<GetSessionPolicy>(&mut provider.client, GetSessionPolicyRequest::Id(id))
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
    let resp = timed::<minimald_rpc::GetSessionScreen>(&mut provider.client, id)
        .await
        .context("GetSessionScreen RPC failed")?;
    Ok(resp.ok())
}

pub async fn destroy(provider: &mut Provider, id: SessionId) -> Result<(), anyhow::Error> {
    match timed::<DestroySession>(&mut provider.client, DestroySessionRequest { id })
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
    match timed::<RenameSession>(
        &mut provider.client,
        RenameSessionRequest {
            id,
            new_name: new_name.to_string(),
        },
    )
    .await
    .context("RenameSession RPC failed")?
    {
        Errorable::Ok(_) => Ok(()),
        Errorable::Err { error } => Err(anyhow::anyhow!(error)),
    }
}

/// The full activate flow behind the create form: create the record, upload
/// the project tree, compose the loadout contribution the CLI composed at
/// startup, and finalize — so the new session comes up `Active`,
/// attachable, and restart-persistent rather than dying as an unresumable
/// `Pending` stub on the next daemon restart.
///
/// Connects its own client so it can run as a background task without
/// borrowing the provider's connection. A `ConfigureLoadout` that comes back
/// `Pending` (items needing interactive policy gating) aborts the session
/// and tells the user to run `min session activate` instead — the TUI has
/// no gating wizard yet.
///
/// The upload root is resolved like the CLI's: walk up from the form's path
/// to the nearest `minimal.toml` repo root, and refuse the upload when that
/// root isn't a VCS checkout — the CLI asks for confirmation there (#770),
/// and a TUI form pre-filled with the current directory must not stream a
/// home directory to the daemon on three Enters.
///
/// Loadout hooks that name an external script are dropped on the way — see
/// [`without_external_hook_scripts`].
pub async fn activate(
    sock: &Path,
    name: Option<String>,
    project_path: paths::HostAbsPath,
    network: NetworkMode,
    contribution: sessions::wire::request::WireContribution,
) -> Result<SessionId, anyhow::Error> {
    let mut client = Client::connect(sock).await?;
    let id = match client
        .oneshot_rpc::<CreateSession>(CreateSessionRequest {
            config: SessionConfig {
                name,
                project_path: project_path.clone(),
                network,
                policy: SessionPolicy::default(),
                // Same default as an activate with no flags: the dashboard
                // has no `--no-hooks` of its own, and a session created here
                // is attachable later like any other.
                hooks_enabled: true,
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
        // The upload-root walk and VCS-root stat are blocking filesystem
        // traversals; run them off the async worker so a stalled mount
        // can't stall the runtime.
        let dir = project_path.as_utf8_path().to_path_buf();
        let (upload_root, is_repo) = tokio::task::spawn_blocking(move || {
            let root = resolve_upload_root(&dir)?;
            let repo = minimal_client::file_upload::is_vcs_root(root.as_std_path());
            Ok::<_, anyhow::Error>((root, repo))
        })
        .await
        .context("resolving the upload root")??;
        if !is_repo {
            anyhow::bail!(
                "refusing to upload '{upload_root}': not a repository root (no .git, .hg, or .jj). \
                 Run `min session activate` to upload a non-repo directory with confirmation"
            );
        }
        client
            .upload_workspace_files_quiet(id, upload_root.as_std_path())
            .await
            .context("uploading project files")?;
        // Drop hooks whose scripts live in a file. The dashboard has no
        // hook-script upload — that staging lives in the `minimal` crate,
        // which sits above this one — and the daemon refuses to finalize a
        // session whose composition names a staged script that never
        // arrived. Sending them would fail every dashboard activation for a
        // user whose loadout happens to use an external hook. Inline hooks
        // carry their body in the composition and are kept.
        let contribution = without_external_hook_scripts(contribution);
        let configured = client
            .oneshot_rpc::<minimald_rpc::ConfigureLoadout>(minimald_rpc::ConfigureLoadoutRequest {
                session_id: id,
                contribution,
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

/// Resolves the directory whose tree should be uploaded as the session
/// workspace, walking up from `dir` to the nearest `minimal.toml` and using
/// its repo root. Falls back to `dir` itself when no mfile is found. Any
/// other mfile error (malformed TOML, I/O) propagates: a broken config in
/// an ancestor should fail loudly rather than silently uploading a subdir
/// with no config. Mirrors the CLI's `resolve_upload_root`.
fn resolve_upload_root(dir: &camino::Utf8Path) -> Result<camino::Utf8PathBuf, anyhow::Error> {
    match mfile::File::from_dir_recursive(dir.as_std_path()) {
        Ok(f) => match f.repo_path() {
            Some(root) => Ok(camino::Utf8PathBuf::from_path_buf(root.to_path_buf())
                .unwrap_or_else(|_| dir.to_path_buf())),
            None => Ok(dir.to_path_buf()),
        },
        Err(mfile::Error::NotFound) => Ok(dir.to_path_buf()),
        Err(e) => Err(anyhow::anyhow!(
            "found a broken {name} while walking up from {dir}: {e}",
            name = mfile::MFILE_NAME,
        )),
    }
}

/// Strip hooks whose scripts are files rather than inline bodies.
///
/// The daemon gates `FinalizeSession` on a marker the hook-script upload
/// writes, and the dashboard has no such upload — the staging that produces
/// it lives in the `minimal` crate, above this one. A composition naming a
/// script that never arrives cannot finalize, so a user whose loadout uses
/// an external hook could not create a session from the dashboard at all.
///
/// Dropping is the conservative half of that trade: an inline hook still
/// runs, and an external one silently does not rather than failing the
/// activation. A hook left with no scripts at all is removed entirely,
/// since an empty one is not constructible.
fn without_external_hook_scripts(
    mut contribution: sessions::wire::request::WireContribution,
) -> sessions::wire::request::WireContribution {
    use sessions::wire::primitives::WireHookScript;
    let is_inline =
        |s: &Option<WireHookScript>| !matches!(s, Some(WireHookScript::External { .. }));
    for ph in &mut contribution.lifecycle_hooks {
        let h = &mut ph.hook;
        for slot in [
            &mut h.on_activate,
            &mut h.on_destroy,
            &mut h.on_attach,
            &mut h.on_detach,
        ] {
            if !is_inline(slot) {
                *slot = None;
            }
        }
    }
    contribution.lifecycle_hooks.retain(|ph| {
        let h = &ph.hook;
        h.on_activate.is_some()
            || h.on_destroy.is_some()
            || h.on_attach.is_some()
            || h.on_detach.is_some()
    });
    contribution
}
#[cfg(test)]
mod tests {
    use super::*;

    /// With no mfile anywhere up the tree, `resolve_upload_root` returns the
    /// input unchanged.
    #[test]
    fn resolve_upload_root_returns_input_when_no_mfile() {
        let dir = tempfile::tempdir().unwrap();
        let path = camino::Utf8PathBuf::from_path_buf(dir.path().join("sub")).unwrap();
        assert_eq!(resolve_upload_root(&path).unwrap(), path);
    }

    /// `resolve_upload_root` walks up to the nearest mfile and returns its
    /// repo root (root layout: `minimal.toml` at the repo root).
    #[test]
    fn resolve_upload_root_walks_up_to_mfile_root_layout() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(mfile::MFILE_NAME),
            "[upstream]\nrepo = \"https://github.com/gominimal/pkgs\"\n",
        )
        .unwrap();
        let root = camino::Utf8PathBuf::from_path_buf(dir.path().to_path_buf()).unwrap();
        let subdir = root.join("crates").join("foo");
        std::fs::create_dir_all(&subdir).unwrap();
        assert_eq!(resolve_upload_root(&subdir).unwrap(), root);
    }

    /// Dot-minimal layout: `minimal.toml` lives in `.minimal/`, and the repo
    /// root is its parent.
    #[test]
    fn resolve_upload_root_walks_up_to_mfile_dot_minimal_layout() {
        let dir = tempfile::tempdir().unwrap();
        let mfile_dir = dir.path().join(".minimal");
        std::fs::create_dir(&mfile_dir).unwrap();
        std::fs::write(
            mfile_dir.join(mfile::MFILE_NAME),
            "[upstream]\nrepo = \"https://github.com/gominimal/pkgs\"\n",
        )
        .unwrap();
        let root = camino::Utf8PathBuf::from_path_buf(dir.path().to_path_buf()).unwrap();
        let subdir = root.join("crates").join("foo");
        std::fs::create_dir_all(&subdir).unwrap();
        assert_eq!(resolve_upload_root(&subdir).unwrap(), root);
    }

    /// A malformed mfile up the tree fails loudly instead of falling back.
    #[test]
    fn resolve_upload_root_errors_on_malformed_mfile() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(mfile::MFILE_NAME), "not valid toml = =").unwrap();
        let path = camino::Utf8PathBuf::from_path_buf(dir.path().to_path_buf()).unwrap();
        assert!(resolve_upload_root(&path).is_err());
    }
}
