//! Daemon-facing RPC for the TUI: provider discovery, refresh, and the
//! session actions, all over the [`minimal_client`] transport.
//!
//! A "provider" is a reachable daemon socket: the host `minimald`'s own, plus
//! one per VM on the `minvmd` microVM backend — the default VM's and every
//! named VM's, each under its own state dir. On Linux all of them can be up
//! at once; on macOS only the VM side exists.

use std::path::{Path, PathBuf};

use anyhow::Context as _;
use minimal_client::Client;
use minimald_rpc::{
    CreateSession, CreateSessionRequest, DestroySession, DestroySessionRequest, Errorable,
    GetEffectiveSessionPolicy, GetEffectiveSessionPolicyRequest, GetSessionRecord,
    GetSessionRecordRequest, GetVersion, ListSessions, OneshotSshRpc, RenameSession,
    RenameSessionRequest, SessionConfig,
};
use sessions::{EffectiveSessionPolicy, NetworkMode, SessionId, SessionPolicy};

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

/// The provider kinds in probe order: `false` resolves the host `minimald`'s
/// own socket, `true` the microVM backend's — which is one socket *per VM*
/// (see [`probe_candidates`]), not one.
const PROBES: &[bool] = &[false, true];

/// The sidebar group label the host `minimald`'s provider carries.
const HOST_LABEL: &str = "host";

/// The sidebar group label the default VM's provider carries. A named VM's
/// group carries the VM's own name; the default VM keeps this one because
/// it is the identity every saved dashboard state has ever recorded
/// ([`state::DashState`]) and the one `provider_rank` orders first among VMs.
const DEFAULT_VM_LABEL: &str = "vm";

/// The sidebar label a VM's provider group carries: the VM's own name, so
/// two VMs show as two groups an operator can tell apart. The default VM
/// keeps its historic label (see [`DEFAULT_VM_LABEL`]).
///
/// A VM whose own name *is* one of the two reserved labels — `host` and
/// `vm` are both valid VM names — would take the identity of the provider
/// that label already belongs to: the dashboard keys its refresh, attach,
/// and saved state by label alone, and [`connect_missing`] skips any
/// candidate whose label a connected provider carries, so the VM's boxes
/// would never reach the provider list. Such a name is escaped into the
/// VM side's own namespace (`vm:host`, `vm:vm`), which no VM name can
/// spell — [`paths::validate_vm_name`] admits no colon — so no two
/// providers ever share a label.
fn vm_label(vm: &str) -> String {
    if vm == paths::DEFAULT_VM_NAME {
        DEFAULT_VM_LABEL.to_string()
    } else if vm == HOST_LABEL || vm == DEFAULT_VM_LABEL {
        format!("{DEFAULT_VM_LABEL}:{vm}")
    } else {
        vm.to_string()
    }
}

/// A reachable daemon the TUI lists sessions from.
pub struct Provider {
    /// Sidebar group label: `host` for the host daemon, `vm` for the default
    /// VM, a named VM's own name for each of those — except a name that
    /// would collide with one of those two identities, which is namespaced
    /// (see [`vm_label`]).
    pub label: String,
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

/// The probe list as `(label, socket)` candidates, in probe order. The host
/// `minimald`'s socket is one probe; the microVM backend's is one per VM —
/// the default VM's plus every named VM's own directory (NET-052), so a
/// dashboard on a two-VM host shows both VMs' boxes under their own groups.
/// Two probes can resolve to one socket — on macOS the host kind maps to the
/// minvmd state dir — so dedupe by path and keep the later (more specific)
/// label; otherwise one daemon would be discovered twice and list every
/// session twice.
fn probe_candidates(minimal_dir: Option<&Path>) -> Vec<(String, PathBuf)> {
    let mut candidates: Vec<(String, PathBuf)> = Vec::new();
    for &vm_side in PROBES {
        if !vm_side {
            let Ok(sock) = minimal_client::resolve_socket_path(minimal_dir, false) else {
                continue;
            };
            push_candidate(&mut candidates, HOST_LABEL.to_string(), sock);
            continue;
        }
        let Ok(vms) = minimal_client::enumerate_vm_sockets(minimal_dir, true) else {
            continue;
        };
        for vm in vms {
            push_candidate(&mut candidates, vm_label(&vm.vm), vm.sock);
        }
    }
    candidates
}

/// One candidate, deduped by socket path: two probes can resolve to one
/// socket — on macOS the host kind maps to the minvmd state dir — so keep the
/// later (more specific) label and never list one daemon twice.
fn push_candidate(candidates: &mut Vec<(String, PathBuf)>, label: String, sock: PathBuf) {
    if let Some(existing) = candidates.iter_mut().find(|(_, s)| *s == sock) {
        existing.0 = label;
        return;
    }
    candidates.push((label, sock));
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
        // Deliberately not version-gated: the dashboard is read-only until the
        // user acts, it renders each provider's version in the sidebar, and a
        // skewed daemon is precisely when an operator needs to see (and be able
        // to destroy) the sessions on it. The one multi-step mutation the TUI
        // drives, `activate`, gates on its own connection instead.
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
        // Deliberately not version-gated, for the same reason as `discover`:
        // a provider that reappears mid-run must still be listable.
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
    let mut sessions = timed::<ListSessions>(&mut provider.client, ())
        .await
        .context("ListSessions RPC failed")?
        .sessions;
    // The daemon cannot probe git (on macOS it runs in the minvmd guest),
    // so fill each session's git context host-side before rendering.
    minimal_client::fill_git_info(&mut sessions).await;
    Ok(ProviderData {
        label: provider.label.clone(),
        version: version.version,
        sessions,
    })
}

/// The record + networking policy behind the detail pane, fetched with one
/// RPC each per focus change. The policy is the *effective* one — the same
/// answer `GetSessionPolicy` serves, with the egress half resolved to what
/// the gate enforces — so the pane's `(default)` mark can show when the
/// deny-all a session is held to is the rollout's default, not its own
/// declaration (what `min session policy` renders).
///
/// A failed policy lookup does not cost the pane its record: it comes back
/// as the policy's `Err`, for the pane to name. A daemon that predates
/// `GetEffectiveSessionPolicy` refuses the subsystem, and that is the case
/// this keeps visible.
pub async fn fetch_detail(
    provider: &mut Provider,
    id: SessionId,
) -> Result<
    (
        Option<sessions::Record>,
        Result<EffectiveSessionPolicy, String>,
    ),
    anyhow::Error,
> {
    let record = timed::<GetSessionRecord>(&mut provider.client, GetSessionRecordRequest::Id(id))
        .await
        .context("GetSessionRecord RPC failed")?
        .record;
    let policy = match timed::<GetEffectiveSessionPolicy>(
        &mut provider.client,
        GetEffectiveSessionPolicyRequest::Id(id),
    )
    .await
    .context("GetEffectiveSessionPolicy RPC failed")
    {
        Ok(Errorable::Ok(policy)) => Ok(policy),
        Ok(Errorable::Err { error }) => Err(error),
        Err(e) => Err(format!("{e:#}")),
    };
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

/// Whether a session holds its name in the VM host's zone in place of a
/// row: a `host_ip` box shares the node's own row, so `min session
/// activate` and [`activate`] hold its name (NODATA) instead of
/// registering one.
fn holds_name(record: &sessions::Record) -> bool {
    record.network == NetworkMode::HostNet && record.box_addresses.is_none()
}

/// Holds or releases a name on the VM host daemon beside `sock`, off the
/// async workers: the control exchange is a blocking socket call.
async fn hold_box_name(sock: &Path, name: &str, id: SessionId, hold: bool) {
    let (sock, name) = (sock.to_path_buf(), name.to_string());
    if let Err(error) = tokio::task::spawn_blocking(move || {
        minimal_client::attach::hold_box_name_beside(&sock, &name, Some(id), hold);
    })
    .await
    {
        tracing::warn!(%error, "the box name hold's thread failed");
    }
}

/// Withdraws a box's host row (T66) on the VM host daemon beside `sock`,
/// off the async workers: the control exchange is a blocking socket call.
/// The pair comes off the session record, which carries no box id, so the
/// pair is the withdrawal's proof.
async fn withdraw_box_row(sock: &Path, name: &str, addresses: sessions::BoxAddresses) {
    let (sock, name) = (sock.to_path_buf(), name.to_string());
    if let Err(error) = tokio::task::spawn_blocking(move || {
        minimal_client::attach::withdraw_box_row_beside(&sock, &name, addresses, None);
    })
    .await
    {
        tracing::warn!(%error, "the box row withdrawal's thread failed");
    }
}

/// The session's record, best-effort: `None` when it cannot be read.
pub async fn record_of(provider: &mut Provider, id: SessionId) -> Option<sessions::Record> {
    timed::<GetSessionRecord>(&mut provider.client, GetSessionRecordRequest::Id(id))
        .await
        .ok()
        .and_then(|resp| resp.record)
}

/// What an attach from the dashboard settles before it starts, from the
/// session's `record` as [`record_of`] read it: the box's host row is
/// asked back on the VM host daemon beside `sock` first (NET-138), as `min
/// session attach` asks — the box's host may have ended and stayed down past
/// the daemon's detach grace, and the in-VM daemon relaunches it only while
/// its row stands. Returns the pair the row was registered with: an attach
/// that ends in the shell-exit prompt's Delete leaves no record to read it
/// from, and [`release_held_name_after_attach`] still owes the row's
/// withdrawal. `None` when the record cannot be read or holds no row.
///
/// # Errors
///
/// The VM host daemon cannot be reached (#1790): the attach does not go
/// ahead, and the status line shows the message `min session attach`
/// fails with. A daemon that answers late or refuses the resume is a warn
/// line, and the attach goes on (NET-138), as `min session attach` does.
pub async fn prepare_attach(
    sock: &Path,
    record: Option<sessions::Record>,
) -> anyhow::Result<Option<sessions::BoxAddresses>> {
    minimal_client::box_registration::resume_box_row(sock, record.as_ref()).await?;
    Ok(record.and_then(|record| record.box_addresses))
}

/// Settles what destroyed session `id` held on the VM host daemon beside
/// `sock`, as `min session destroy` settles it: the row an own-address box
/// registered is withdrawn with the pair off its record, and a `host_ip`
/// box's zone hold is released. A session that held neither owes nothing.
async fn settle_destroyed_box(sock: &Path, id: SessionId, record: &sessions::Record) {
    let Some(name) = record.name.as_deref() else {
        return;
    };
    if let Some(addresses) = record.box_addresses {
        withdraw_box_row(sock, name, addresses).await;
    } else if holds_name(record) {
        hold_box_name(sock, name, id, false).await;
    }
}

/// Destroys the session, then withdraws the row its box registered or
/// releases the zone hold a `host_ip` box's name kept, as `min session
/// destroy` does.
pub async fn destroy(provider: &mut Provider, id: SessionId) -> Result<(), anyhow::Error> {
    let record = record_of(provider, id).await;
    match timed::<DestroySession>(&mut provider.client, DestroySessionRequest { id })
        .await
        .context("DestroySession RPC failed")?
    {
        Errorable::Ok(_) => {
            if let Some(record) = record {
                settle_destroyed_box(&provider.sock, id, &record).await;
            }
            Ok(())
        }
        Errorable::Err { error } => Err(anyhow::anyhow!(error)),
    }
}

/// Renames the session; a `host_ip` box's zone hold moves with the name, as
/// `min session rename` moves it.
pub async fn rename(
    provider: &mut Provider,
    id: SessionId,
    new_name: &str,
) -> Result<(), anyhow::Error> {
    let record = record_of(provider, id).await;
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
        Errorable::Ok(_) => {
            if let Some(record) = record.filter(holds_name) {
                if let Some(old_name) = record.name.as_deref() {
                    hold_box_name(&provider.sock, old_name, id, false).await;
                }
                hold_box_name(&provider.sock, new_name, id, true).await;
            }
            Ok(())
        }
        Errorable::Err { error } => Err(anyhow::anyhow!(error)),
    }
}

/// Settles what session `id` held once an attach from the dashboard has
/// ended with the session gone: the shell-exit prompt's Delete destroys the
/// session daemon-side, past [`destroy`]. The row its box registered is
/// withdrawn with `box_addresses`, the pair [`prepare_attach`] read
/// before the attach; with none, the name's zone hold is released. A lookup
/// that fails settles nothing; a session still there keeps its row and its
/// hold, and the release names the session, so a newer session under
/// `name` keeps its own.
pub async fn release_held_name_after_attach(
    provider: &mut Provider,
    id: SessionId,
    name: &str,
    box_addresses: Option<sessions::BoxAddresses>,
) {
    let lookup =
        timed::<GetSessionRecord>(&mut provider.client, GetSessionRecordRequest::Id(id)).await;
    if let Ok(resp) = lookup
        && resp.record.is_none()
    {
        match box_addresses {
            Some(addresses) => withdraw_box_row(&provider.sock, name, addresses).await,
            None => hold_box_name(&provider.sock, name, id, false).await,
        }
    }
}

/// The full activate flow behind the create form: create the record, upload
/// the project tree, compose the loadout contribution the CLI composed at
/// startup, upload the composition's patch files, and finalize — so the new
/// session comes up `Active`, attachable, and restart-persistent rather than
/// dying as an unresumable `Pending` stub on the next daemon restart.
///
/// Connects its own client so it can run as a background task without
/// borrowing the provider's connection. A `ConfigureLoadout` that comes back
/// `Pending` (items needing interactive policy gating) aborts the session
/// and tells the user to run `min session activate` instead — the TUI has
/// no gating wizard yet.
///
/// An own-address box on a VM-backed host registers its host row before the
/// create, holds the registration's lease until the session is active, and
/// withdraws the row on any failure after it exists — the registration
/// `min session activate` makes, through the same client library
/// ([`create_registering`]).
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
) -> Result<Activated, anyhow::Error> {
    let mut client = Client::connect(sock).await?;
    // The dashboard's own copy of the create/upload/configure/finalize
    // sequence, so it needs the same gate `min session activate` gets: on a
    // skewed pair `FinalizeSession` fails after the record exists, and the
    // abort below then destroys the session the user just created (#1251).
    // The gate is the `must_match_version` on the create below and the version
    // the reply echoes back — not a `GetVersion` ahead of them. Activation is
    // the one path where an extra round trip is felt, and the create can carry
    // the check for free.
    let config = SessionConfig {
        name,
        project_path: project_path.clone(),
        network,
        policy: SessionPolicy::default(),
        // An own-address box on a VM-backed host is handed its addresses by
        // the registration [`create_registering`] makes first.
        task_addresses: Vec::new(),
        box_id: None,
        box_addresses: None,
        // Same default as an activate with no flags: the dashboard
        // has no `--no-hooks` of its own, and a session created here
        // is attachable later like any other.
        hooks_enabled: true,
        attrs: Default::default(),
    };
    let undeclared_own_ip = config.network == NetworkMode::OwnIp && config.policy.egress.is_none();
    let (created, mut row) = create_registering(sock, config, &mut client, |client, config| {
        Box::pin(async move {
            client
                .oneshot_rpc::<CreateSession>(CreateSessionRequest {
                    config,
                    // A daemon of another build refuses this before it
                    // allocates anything; `None` under the skew override,
                    // which is how an operator still gets through.
                    must_match_version: minimal_client::version_assertion(),
                })
                .await
                .context("CreateSession RPC failed")
        })
    })
    .await?;
    // A daemon that predates the field ignored the assertion and echoes no
    // version; that silence is itself the skew. Refuse now — before the
    // upload and the finalize — leaving an unfinalized record the daemon
    // reaps when this connection drops, and withdrawing the row its
    // registration bought.
    if let Err(error) = minimal_client::ensure_version_reported(created.daemon_version.as_deref()) {
        row.withdraw().await;
        return Err(error);
    }
    let id = created.id;
    let egress_deny_all_default = undeclared_own_ip && deny_all_default_binds(&created);

    // The registration's lease is held across the flow and committed only
    // once the session is active: until then a dashboard that dies leaves
    // the VM host daemon to withdraw the row on the lease's close.
    let lease = row.take_lease();
    let flow = minimal_client::box_registration::finalize_holding_lease(lease, async {
        // The upload-root walk and VCS-root stat are blocking filesystem
        // traversals; run them off the async worker so a stalled mount
        // can't stall the runtime.
        let dir = project_path.as_utf8_path().to_path_buf();
        let (upload_root, is_repo) = tokio::task::spawn_blocking(move || {
            let root = crate::resolve_upload_root(&dir)?;
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
        // Collect the upload pairs before the contribution moves into the
        // ConfigureLoadout RPC, through the collection `min session
        // activate` uses: they land in the final composition of a
        // `Materialized` response (the only one the dashboard accepts), so
        // the client is authoritative for them.
        let mut patches = minimal_client::contribution_patch_uploads(&contribution);
        minimal_client::dedup_patch_uploads(&mut patches);
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
        // The composition's patches must arrive between `ConfigureLoadout`
        // and `FinalizeSession`: the daemon's finalize gate refuses a
        // composition whose patch upload never completed. An empty list is
        // a no-op. Quiet: the dashboard owns the screen, and a progress bar
        // would corrupt it.
        client
            .upload_patches_quiet(id, &patches)
            .await
            .context("uploading composition patches")?;
        match client
            .oneshot_rpc::<minimald_rpc::FinalizeSession>(minimald_rpc::FinalizeSessionRequest {
                session_id: id,
                // The dashboard's status line does not render the yielded
                // ports, so it does not ask for them.
                report_shared_port_collisions: false,
            })
            .await
            .context("FinalizeSession RPC failed")?
        {
            Errorable::Ok(ok) => Ok(ok.package_check_skipped),
            Errorable::Err { error } => anyhow::bail!("{error}"),
        }
    })
    .await;

    // A failed flow must not orphan the record: a `Pending` stub would hold
    // its name and be reaped at the next daemon restart anyway.
    match flow {
        Ok(package_check_skipped) => {
            // The session is active: a `host_ip` box holds its name in the
            // zone (NODATA) the way `min session activate` holds it, read
            // off the record so an autogen name is the one held.
            if let Ok(resp) = client
                .oneshot_rpc::<GetSessionRecord>(GetSessionRecordRequest::Id(id))
                .await
                && let Some(record) = resp.record.filter(holds_name)
                && let Some(name) = record.name.as_deref()
            {
                hold_box_name(sock, name, id, true).await;
            }
            Ok(Activated {
                id,
                package_check_skipped,
                egress_deny_all_default,
            })
        }
        Err(e) => {
            let _ = client
                .oneshot_rpc::<minimald_rpc::AbortSession>(minimald_rpc::AbortSessionRequest { id })
                .await;
            row.withdraw().await;
            Err(e)
        }
    }
}

/// The host row an own-address box's dashboard create registered with the
/// VM host daemon (T66): its creator owes it a withdrawal on every failure
/// after it exists, by the id the registration handed back, so a late
/// withdrawal never removes a newer box. Empty for a box that registered
/// nothing — a native host, a `host_ip` or `none` box.
struct BoxRow {
    control_sock: Option<PathBuf>,
    name: Option<String>,
    registration: Option<minimal_client::box_registration::RegisteredWithVmHost>,
}

impl BoxRow {
    /// Withdraws the row, best-effort, as `min session activate` withdraws
    /// it when its activation fails; nothing for a box that registered none.
    async fn withdraw(&self) {
        minimal_client::box_registration::withdraw_box_row(
            self.control_sock.clone(),
            self.name.as_deref(),
            self.registration
                .as_ref()
                .map(|registration| registration.addresses),
            self.registration
                .as_ref()
                .and_then(|registration| registration.box_id),
        )
        .await;
    }

    /// The registration's lease, to hold across the flow that makes the
    /// session active.
    fn take_lease(&mut self) -> Option<minimal_client::box_registration::BoxLease> {
        self.registration
            .as_mut()
            .and_then(|registration| registration.lease.take())
    }
}

/// One `CreateSession` exchange, as [`create_registering`] sends it.
type CreateFuture<'c> = std::pin::Pin<
    Box<
        dyn std::future::Future<
                Output = anyhow::Result<Errorable<minimald_rpc::CreateSessionResponse>>,
            > + Send
            + 'c,
    >,
>;

/// The dashboard's `CreateSession` with an own-address box's registration
/// around it, as `min session activate` makes them (T66): on a VM-backed
/// host — `sock` in a VM host's provider dir, with its control socket
/// beside it ([`vm_host_control_sock`](minimal_client::box_registration::vm_host_control_sock)) — the
/// box registers first, through the client library the CLI registers
/// through, and the create carries the addresses the registration handed
/// back, since the in-VM daemon refuses an own-address box with none. A
/// box the form left unnamed is named first the way the CLI names one,
/// because the row is registered under the name, and an autogen name that
/// collides with a live row or session is re-minted within the CLI's
/// budget. Every failure after the row exists withdraws it, with its id.
/// On a native host, or for a box that is not own-address, this is the
/// plain create it always was. `create` sends the create request on
/// `client`.
async fn create_registering<C: Send>(
    sock: &Path,
    mut config: SessionConfig,
    client: &mut C,
    mut create: impl for<'c> FnMut(&'c mut C, SessionConfig) -> CreateFuture<'c>,
) -> anyhow::Result<(minimald_rpc::CreateSessionResponse, BoxRow)> {
    use minimal_client::box_registration::{
        control_sock_beside, register_box_beside_reminting_autogen, vm_host_control_sock,
    };
    use minimal_client::session_name::{autogen_session_name, random_hex4, should_retry_autogen};
    let control_sock = control_sock_beside(sock);
    let registers = config.network == NetworkMode::OwnIp && vm_host_control_sock(sock).is_some();
    let project_dir = config.project_path.as_utf8_path().to_path_buf();
    let mint = || autogen_session_name(&project_dir, &random_hex4());
    let autogen = registers && config.name.is_none();
    if autogen {
        config.name = Some(mint());
    }
    let mut attempts = 0u32;
    let mut row = BoxRow {
        control_sock,
        name: None,
        registration: None,
    };
    loop {
        if let Some(name) = config.name.as_mut() {
            row.registration = register_box_beside_reminting_autogen(
                sock,
                config.network,
                name,
                &config.policy,
                autogen,
                &mut attempts,
                &mint,
            )
            .await?;
        }
        row.name.clone_from(&config.name);
        config.box_addresses = row
            .registration
            .as_ref()
            .map(|registration| registration.addresses);
        config.task_addresses = row
            .registration
            .as_ref()
            .map(|registration| registration.task_addresses.clone())
            .unwrap_or_default();
        config.box_id = row
            .registration
            .as_ref()
            .and_then(|registration| registration.box_id);
        let error = match create(client, config.clone()).await {
            Ok(Errorable::Ok(created)) => return Ok((created, row)),
            Ok(Errorable::Err { error }) => error,
            // A transport failure abandons the create and the row its
            // registration bought: no session holds the pair.
            Err(error) => {
                row.withdraw().await;
                return Err(error);
            }
        };
        // The row the attempt bought is left behind with it: its creator
        // withdraws it, and a retry re-registers under the re-minted name.
        row.withdraw().await;
        if !should_retry_autogen(autogen, attempts, &error) {
            return Err(anyhow::anyhow!(error));
        }
        attempts += 1;
        row.registration = None;
        config.name = Some(mint());
    }
}

/// A session the dashboard created and activated.
#[derive(Debug)]
pub struct Activated {
    pub id: SessionId,
    /// The daemon's package check stepped aside at finalize, so unknown
    /// package names surface at first exec; the status line says so.
    pub package_check_skipped: bool,
    /// The box is own-address with no egress section, on a daemon that
    /// has not opted out, so the deny-all default binds it (NET-074): it
    /// reaches nothing outside itself, and the status line says so, as
    /// `min session activate` prints its one-line note.
    pub egress_deny_all_default: bool,
}

/// Whether the deny-all egress default binds an own-address box with no
/// egress section that `created` answered the create of (NET-074): the
/// build's phase has it in force, and the daemon, the side that knows,
/// did not report its opt-out (NET-077) — the check `min session
/// activate` makes before its note.
fn deny_all_default_binds(created: &minimald_rpc::CreateSessionResponse) -> bool {
    match sessions::EGRESS_DEFAULT_PHASE {
        sessions::EgressDefaultPhase::Announced => false,
        sessions::EgressDefaultPhase::InForce => created.deny_all_opt_out != Some(true),
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

    /// A stand-in VM host daemon on the control socket `control_sock`
    /// beside a dashboard's ssh socket: it answers one connection per reply
    /// in `replies`, in order — one request line in, the reply line out —
    /// and hands back the request lines it read. Each connection is held
    /// open until the last one is answered, as a registration's lease is.
    fn fake_vm_host(
        control_sock: &Path,
        replies: Vec<minimald_rpc::BoxControlReply>,
    ) -> std::thread::JoinHandle<Vec<String>> {
        use std::io::{BufRead as _, Write as _};
        let listener = std::os::unix::net::UnixListener::bind(control_sock).unwrap();
        std::thread::spawn(move || {
            let mut held = Vec::new();
            let mut lines = Vec::new();
            for reply in replies {
                let (stream, _) = listener.accept().unwrap();
                let mut reader = std::io::BufReader::new(stream);
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                let mut reply = serde_json_lenient::to_string(&reply).unwrap();
                reply.push('\n');
                reader.get_mut().write_all(reply.as_bytes()).unwrap();
                lines.push(line);
                held.push(reader);
            }
            lines
        })
    }

    /// A VM host's provider dir inside `dir` — the dir a dashboard's ssh
    /// socket and the VM host daemon's control socket share.
    fn vm_provider_dir(dir: &tempfile::TempDir) -> std::path::PathBuf {
        let provider = dir.path().join("providers").join("local-minvmd0");
        std::fs::create_dir_all(&provider).unwrap();
        provider
    }

    /// NET-074 from the dashboard: the deny-all default binds a bare
    /// own-address box unless the daemon reports its opt-out (NET-077); a
    /// daemon that predates the field is read as not opted out, as the CLI
    /// reads it.
    #[test]
    fn deny_all_default_binds_unless_the_daemon_opted_out() {
        let mut reply = created();
        assert!(
            deny_all_default_binds(&reply),
            "no field: the default binds"
        );
        reply.deny_all_opt_out = Some(false);
        assert!(deny_all_default_binds(&reply));
        reply.deny_all_opt_out = Some(true);
        assert!(!deny_all_default_binds(&reply), "an opted-out daemon");
    }

    /// The dashboard's create config for an own-address box in `dir`.
    fn own_ip_config(dir: &Path, name: Option<&str>) -> SessionConfig {
        SessionConfig {
            name: name.map(str::to_string),
            project_path: paths::HostAbsPath::try_new(
                camino::Utf8PathBuf::from_path_buf(dir.join("web-app")).unwrap(),
            )
            .unwrap(),
            network: NetworkMode::OwnIp,
            policy: SessionPolicy::default(),
            task_addresses: Vec::new(),
            box_id: None,
            box_addresses: None,
            hooks_enabled: true,
            attrs: Default::default(),
        }
    }

    fn created() -> minimald_rpc::CreateSessionResponse {
        serde_json_lenient::from_str(r#"{"id":"00000000-0000-0000-0000-000000000000"}"#)
            .expect("a create reply")
    }

    /// T66 from the dashboard: an own-address create on a VM-backed host
    /// registers the box first, through the client library the CLI
    /// registers through — under a name minted the CLI's way, since the form
    /// left it unnamed and the row is registered under the name — and the
    /// create carries the addresses the registration handed back, never
    /// none (the in-VM daemon refuses an own-address box with none).
    #[tokio::test]
    async fn tui_own_ip_create_registers_and_hands_addresses() {
        let dir = tempfile::TempDir::new().unwrap();
        let provider = vm_provider_dir(&dir);
        let ssh_sock = provider.join("ssh.sock");
        let box_id = minimald_rpc::BoxId::from_bytes([7; 16]);
        let handed = minimald_rpc::RegisteredBox {
            switch_address: std::net::Ipv4Addr::new(100, 64, 0, 2),
            loopback_address: std::net::Ipv4Addr::new(127, 0, 64, 0),
            box_id,
            task_addresses: Vec::new(),
        };
        let server = fake_vm_host(
            &provider.join(minimal_client::attach::VM_HOST_CONTROL_SOCK_FILE),
            vec![minimald_rpc::BoxControlReply::Registered(handed.clone())],
        );
        let mut sent = Vec::new();
        let (_, row) = create_registering(
            &ssh_sock,
            own_ip_config(dir.path(), None),
            &mut sent,
            |sent, config| {
                sent.push(config);
                Box::pin(async { Ok(Errorable::Ok(created())) })
            },
        )
        .await
        .expect("the registered box is created");
        let lines = server.join().unwrap();

        assert_eq!(lines.len(), 1, "one registration, one request");
        let request: minimald_rpc::BoxControlRequest =
            serde_json_lenient::from_str(lines[0].trim()).expect("the request is the wire type");
        let minimald_rpc::BoxControlRequest::Register(request) = request else {
            panic!("a registration is carried by the register verb");
        };
        assert!(request.hold, "the create holds its registration as a lease");
        assert!(
            request.name.starts_with("web-app-"),
            "an unnamed box is registered under the CLI's autogen name: {}",
            request.name
        );

        let [config] = sent.as_slice() else {
            panic!("one create, got {}", sent.len());
        };
        assert_eq!(
            config.name.as_deref(),
            Some(request.name.as_str()),
            "the create names the session the row was registered under"
        );
        assert_eq!(
            config.box_addresses,
            Some(sessions::BoxAddresses {
                switch_address: handed.switch_address,
                loopback_address: handed.loopback_address,
            }),
            "the create carries the handed addresses"
        );
        let registration = row.registration.as_ref().expect("the row is the create's");
        assert_eq!(registration.box_id, Some(box_id));
        assert!(
            registration.lease.is_some(),
            "the lease is held for the flow"
        );
    }

    /// NET-138 from the dashboard: an own-address create asks the host for
    /// the box's task addresses with its registration, and the create
    /// carries the ones handed back, so the in-VM daemon draws nothing for a
    /// task run either.
    #[tokio::test]
    async fn tui_activation_registers_task_slots_for_own_ip_box() {
        let dir = tempfile::TempDir::new().unwrap();
        let provider = vm_provider_dir(&dir);
        let ssh_sock = provider.join("ssh.sock");
        let task_addresses = vec![
            std::net::Ipv4Addr::new(100, 64, 0, 3),
            std::net::Ipv4Addr::new(100, 64, 0, 4),
        ];
        let server = fake_vm_host(
            &provider.join(minimal_client::attach::VM_HOST_CONTROL_SOCK_FILE),
            vec![minimald_rpc::BoxControlReply::Registered(
                minimald_rpc::RegisteredBox {
                    switch_address: std::net::Ipv4Addr::new(100, 64, 0, 2),
                    loopback_address: std::net::Ipv4Addr::new(127, 0, 64, 0),
                    box_id: minimald_rpc::BoxId::from_bytes([7; 16]),
                    task_addresses: task_addresses.clone(),
                },
            )],
        );
        let mut sent = Vec::new();
        create_registering(
            &ssh_sock,
            own_ip_config(dir.path(), Some("web")),
            &mut sent,
            |sent, config| {
                sent.push(config);
                Box::pin(async { Ok(Errorable::Ok(created())) })
            },
        )
        .await
        .expect("the registered box is created");
        let lines = server.join().unwrap();
        let request: minimald_rpc::BoxControlRequest =
            serde_json_lenient::from_str(lines[0].trim()).expect("the request is the wire type");
        let minimald_rpc::BoxControlRequest::Register(request) = request else {
            panic!("a registration is carried by the register verb");
        };
        assert_eq!(
            request.task_slots,
            minimald_rpc::TASK_SLOTS_PER_BOX,
            "the registration asks for the box's task addresses"
        );
        let [config] = sent.as_slice() else {
            panic!("one create, got {}", sent.len());
        };
        assert_eq!(
            config.task_addresses, task_addresses,
            "the create carries the task addresses the host handed"
        );
    }

    /// A dashboard create that fails after its box registered withdraws the
    /// row — its creator presenting the name, the pair and the id the
    /// registration handed back — and surfaces the create's own error, not
    /// a raw transport one.
    #[tokio::test]
    async fn tui_own_ip_create_failure_withdraws_the_row() {
        let dir = tempfile::TempDir::new().unwrap();
        let provider = vm_provider_dir(&dir);
        let ssh_sock = provider.join("ssh.sock");
        let box_id = minimald_rpc::BoxId::from_bytes([9; 16]);
        let addresses = sessions::BoxAddresses {
            switch_address: std::net::Ipv4Addr::new(100, 64, 0, 3),
            loopback_address: std::net::Ipv4Addr::new(127, 0, 64, 1),
        };
        let server = fake_vm_host(
            &provider.join(minimal_client::attach::VM_HOST_CONTROL_SOCK_FILE),
            vec![
                minimald_rpc::BoxControlReply::Registered(minimald_rpc::RegisteredBox {
                    switch_address: addresses.switch_address,
                    loopback_address: addresses.loopback_address,
                    box_id,
                    task_addresses: Vec::new(),
                }),
                minimald_rpc::BoxControlReply::Addresses(addresses),
            ],
        );
        let failed = create_registering(
            &ssh_sock,
            own_ip_config(dir.path(), Some("web")),
            &mut (),
            |(), _config| {
                Box::pin(async {
                    Ok(Errorable::Err {
                        error: "the project path is not a directory".to_string(),
                    })
                })
            },
        )
        .await;
        let error = match failed {
            Ok(_) => panic!("the refused create is the dashboard's error"),
            Err(error) => format!("{error:#}"),
        };
        assert_eq!(error, "the project path is not a directory");
        let lines = server.join().unwrap();

        assert_eq!(lines.len(), 2, "a registration, then its withdrawal");
        let request: minimald_rpc::BoxControlRequest =
            serde_json_lenient::from_str(lines[1].trim()).expect("the request is the wire type");
        let minimald_rpc::BoxControlRequest::Withdraw(request) = request else {
            panic!("the abandoned row goes by the withdraw verb");
        };
        assert_eq!(request.name, "web");
        assert_eq!(request.switch_address, addresses.switch_address);
        assert_eq!(request.loopback_address, addresses.loopback_address);
        assert_eq!(
            request.box_id,
            Some(box_id),
            "the withdrawal names the id the registration handed back"
        );
    }

    /// A registration the VM host daemon refuses ends the dashboard's create
    /// before any create is sent, with the registration's cause in words.
    #[tokio::test]
    async fn tui_own_ip_create_refused_registration_creates_nothing() {
        let dir = tempfile::TempDir::new().unwrap();
        let provider = vm_provider_dir(&dir);
        let ssh_sock = provider.join("ssh.sock");
        let server = fake_vm_host(
            &provider.join(minimal_client::attach::VM_HOST_CONTROL_SOCK_FILE),
            vec![minimald_rpc::BoxControlReply::Error {
                error: "the switch's address plan is exhausted".to_string(),
            }],
        );
        let failed = create_registering(
            &ssh_sock,
            own_ip_config(dir.path(), Some("web")),
            &mut (),
            |(), _config| -> CreateFuture<'_> {
                panic!("no create is sent for a box that did not register")
            },
        )
        .await;
        let error = match failed {
            Ok(_) => panic!("the refused registration is the dashboard's error"),
            Err(error) => format!("{error:#}"),
        };
        assert!(
            error.starts_with("registering the box with the VM host daemon failed")
                && error.contains("address plan is exhausted"),
            "the refusal surfaces with its reason: {error}"
        );
        assert_eq!(server.join().unwrap().len(), 1);
    }

    /// On a native host an own-address create is the plain create it always
    /// was: nothing registers, the name stays as the form gave it, and the
    /// create carries no addresses — even though native minimald's answerer
    /// door sits beside its ssh socket under the VM host's control socket
    /// name, which a registration must never be sent to.
    #[tokio::test]
    async fn tui_own_ip_create_on_a_native_host_registers_nothing() {
        let dir = tempfile::TempDir::new().unwrap();
        let provider = dir.path().join("providers").join("local-minimald0");
        std::fs::create_dir_all(&provider).unwrap();
        let _answerer_door = std::os::unix::net::UnixListener::bind(
            provider.join(minimal_client::attach::VM_HOST_CONTROL_SOCK_FILE),
        )
        .unwrap();
        let mut sent = Vec::new();
        let (_, row) = create_registering(
            &provider.join("ssh.sock"),
            own_ip_config(dir.path(), None),
            &mut sent,
            |sent, config| {
                sent.push(config);
                Box::pin(async { Ok(Errorable::Ok(created())) })
            },
        )
        .await
        .expect("the native create goes ahead");
        assert!(row.registration.is_none());
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].name, None);
        assert_eq!(sent[0].box_addresses, None);
    }

    /// NET-138 from the dashboard: an attach asks the VM host daemon for
    /// the box's row back before it starts, as `min session attach` does —
    /// one resume line naming the box and the pair off its record — and
    /// still hands back the pair the after-attach withdrawal needs.
    #[tokio::test]
    async fn tui_attach_resumes_the_box_first() {
        let dir = tempfile::TempDir::new().unwrap();
        let ssh_sock = dir.path().join("ssh.sock");
        let addresses = sessions::BoxAddresses {
            switch_address: std::net::Ipv4Addr::new(100, 64, 0, 4),
            loopback_address: std::net::Ipv4Addr::new(127, 0, 64, 2),
        };
        let server = fake_vm_host(
            &dir.path()
                .join(minimal_client::attach::VM_HOST_CONTROL_SOCK_FILE),
            vec![minimald_rpc::BoxControlReply::Registered(
                minimald_rpc::RegisteredBox {
                    switch_address: addresses.switch_address,
                    loopback_address: addresses.loopback_address,
                    box_id: minimald_rpc::BoxId::from_bytes([3; 16]),
                    task_addresses: Vec::new(),
                },
            )],
        );
        let mut record = own_ip_record(Some(addresses));
        record.name = Some("web".to_string());
        let pair = prepare_attach(&ssh_sock, Some(record))
            .await
            .expect("the VM host answers the resume");
        assert_eq!(pair, Some(addresses), "the attach keeps the pair it read");
        let lines = server.join().unwrap();
        assert_eq!(lines.len(), 1, "one resume before the attach");
        let request: minimald_rpc::BoxControlRequest =
            serde_json_lenient::from_str(lines[0].trim()).expect("the request is the wire type");
        let minimald_rpc::BoxControlRequest::ResumeBox(request) = request else {
            panic!("the row is asked back by the resume verb");
        };
        assert_eq!(request.name, "web");
        assert_eq!(request.switch_address, addresses.switch_address);
        assert_eq!(request.loopback_address, addresses.loopback_address);
    }

    /// An own-address record holding `box_addresses`.
    fn own_ip_record(box_addresses: Option<sessions::BoxAddresses>) -> sessions::Record {
        sessions::Record {
            id: SessionId::nil(),
            name: None,
            username: None,
            project_path: paths::HostAbsPath::try_new("/p").unwrap(),
            network: NetworkMode::OwnIp,
            policy: SessionPolicy {
                egress: None,
                ingress: None,
                credentialed_upstream: None,
            },
            status: sessions::SessionStatus::default(),
            hooks_enabled: true,
            box_addresses,
            task_addresses: Vec::new(),
            host_ip_enforcement: None,
            box_id: None,
            host_row_bound: false,
            attrs: Default::default(),
        }
    }

    /// T66's dashboard destroy: a destroyed own-address box's row is
    /// withdrawn on the control socket beside the daemon's ssh socket — one
    /// withdraw line naming the box and the pair off its record, with no
    /// box id, which the record does not carry.
    #[tokio::test]
    async fn tui_destroy_withdraws_box_row() {
        use std::io::{BufRead as _, Write as _};
        let dir = tempfile::TempDir::new().unwrap();
        let ssh_sock = dir.path().join("ssh.sock");
        let listener = std::os::unix::net::UnixListener::bind(
            dir.path()
                .join(minimal_client::attach::VM_HOST_CONTROL_SOCK_FILE),
        )
        .unwrap();
        let handed = sessions::BoxAddresses {
            switch_address: std::net::Ipv4Addr::new(100, 64, 0, 2),
            loopback_address: std::net::Ipv4Addr::new(127, 0, 64, 0),
        };
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut reader = std::io::BufReader::new(stream);
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            reader
                .get_mut()
                .write_all(
                    b"{\"switch_address\":\"100.64.0.2\",\"loopback_address\":\"127.0.64.0\"}\n",
                )
                .unwrap();
            line
        });
        let record = sessions::Record {
            id: SessionId::nil(),
            name: Some("web".to_string()),
            username: None,
            project_path: paths::HostAbsPath::try_new("/p").unwrap(),
            network: NetworkMode::OwnIp,
            policy: SessionPolicy {
                egress: None,
                ingress: None,
                credentialed_upstream: None,
            },
            status: sessions::SessionStatus::default(),
            hooks_enabled: true,
            task_addresses: Vec::new(),
            box_addresses: Some(handed),
            host_ip_enforcement: None,
            box_id: None,
            host_row_bound: false,
            attrs: Default::default(),
        };
        settle_destroyed_box(&ssh_sock, record.id, &record).await;
        let line = server.join().unwrap();
        let request: minimald_rpc::BoxControlRequest =
            serde_json_lenient::from_str(line.trim()).expect("the request is the wire type");
        let minimald_rpc::BoxControlRequest::Withdraw(request) = request else {
            panic!("a destroyed box's row goes by the withdraw verb");
        };
        assert_eq!(request.name, "web");
        assert_eq!(request.switch_address, handed.switch_address);
        assert_eq!(request.loopback_address, handed.loopback_address);
        assert_eq!(request.box_id, None, "the record carries no box id");
    }

    /// NET-057's TUI half: the probe list covers every VM — the default one
    /// under its historic `vm` label, every named VM under its own name and
    /// socket — beside the host daemon's probe. And no socket is ever probed
    /// twice: on macOS the host kind resolves the minvmd state dir, where it
    /// collapses into the default VM's entry and keeps the more specific
    /// label, so a daemon would never list its sessions in two groups.
    #[test]
    fn probes_every_named_vm() {
        let dir = tempfile::tempdir().unwrap();
        let provider = dir.path().join("providers/local-minvmd0");
        for vm in ["alpha", "beta"] {
            std::fs::create_dir_all(provider.join(vm)).unwrap();
        }
        let candidates = probe_candidates(Some(dir.path()));
        let label_at = |sock: &std::path::Path| -> Option<String> {
            candidates
                .iter()
                .find(|(_, s)| s == sock)
                .map(|(label, _)| label.clone())
        };
        assert_eq!(
            label_at(&provider.join("ssh.sock")).as_deref(),
            Some("vm"),
            "the default VM is probed under its historic label: {candidates:?}"
        );
        for vm in ["alpha", "beta"] {
            assert_eq!(
                label_at(&provider.join(vm).join("ssh.sock")).as_deref(),
                Some(vm),
                "{vm} has a state dir, so its socket is probed: {candidates:?}"
            );
        }
        let unique: std::collections::HashSet<_> =
            candidates.iter().map(|(_, s)| s.clone()).collect();
        assert_eq!(
            candidates.len(),
            unique.len(),
            "one socket must never be probed twice: {candidates:?}"
        );
    }

    /// A VM named `host` or `vm` — both valid per
    /// [`paths::validate_vm_name`] — must not take the identity of the
    /// group those labels already belong to: the dashboard keys its
    /// refresh, attach, and saved state by label alone, and
    /// [`connect_missing`] skips any candidate whose label a connected
    /// provider carries, so a verbatim label would keep the VM's boxes
    /// from ever reaching the provider list once the host daemon (or the
    /// default VM) is connected. The escape is the VM side's namespace,
    /// which no VM name can spell, so both keep their own candidate and
    /// every candidate keeps a label no other candidate carries.
    #[test]
    fn vms_named_for_the_reserved_labels_keep_their_own_candidates() {
        let dir = tempfile::tempdir().unwrap();
        let provider = dir.path().join("providers/local-minvmd0");
        for vm in ["host", "vm"] {
            std::fs::create_dir_all(provider.join(vm)).unwrap();
        }
        let candidates = probe_candidates(Some(dir.path()));
        let label_at = |sock: &std::path::Path| -> Option<String> {
            candidates
                .iter()
                .find(|(_, s)| s == sock)
                .map(|(label, _)| label.clone())
        };
        assert_eq!(
            label_at(&provider.join("ssh.sock")).as_deref(),
            Some("vm"),
            "the default VM keeps its own historic label: {candidates:?}"
        );
        assert_eq!(
            label_at(&provider.join("host").join("ssh.sock")).as_deref(),
            Some("vm:host"),
            "a VM named `host` must not take the host daemon's label: {candidates:?}"
        );
        assert_eq!(
            label_at(&provider.join("vm").join("ssh.sock")).as_deref(),
            Some("vm:vm"),
            "a VM named `vm` must not take the default VM's label: {candidates:?}"
        );
        let unique_labels: std::collections::HashSet<_> =
            candidates.iter().map(|(label, _)| label.clone()).collect();
        assert_eq!(
            candidates.len(),
            unique_labels.len(),
            "every candidate keeps a label no other candidate carries — the \
             label is the identity `connect_missing` and the dashboard resolve \
             providers by: {candidates:?}"
        );
    }
}

#[cfg(test)]
mod version_gate_tests {
    /// The dashboard opens three daemon connections, and #1251's gate reached
    /// none of them. Only `activate` runs a multi-step mutation, so only it is
    /// gated; the two discovery connections stay open on purpose and must say
    /// so, since a reader who finds an ungated connect has no other way to tell
    /// an audited decision from an oversight.
    ///
    /// Asserted as an inventory rather than a count, so adding, removing, or
    /// reclassifying a connection fails here and forces the same judgement.
    #[test]
    fn only_the_activation_path_is_version_gated() {
        assert_eq!(
            connect_site_inventory(),
            [
                "activate = gated",
                "connect_missing = ungated (explained)",
                "discover = ungated (explained)",
            ]
        );
    }

    /// The dashboard's activation must not spend a round trip on the version
    /// either. Its gate is the assertion on the `CreateSession` it was already
    /// sending plus the build the reply echoes back — never a `GetVersion`
    /// ahead of them.
    ///
    /// `refresh` still calls `GetVersion`, and must: the sidebar renders each
    /// provider's build. That is a display fetch on the idle loop, not a gate
    /// on the create path.
    #[test]
    fn the_dashboard_activation_makes_no_version_round_trip() {
        let body = function_code("activate").expect("rpc.rs no longer defines activate");
        for round_trip in ["GetVersion", "ensure_version_match"] {
            assert!(
                !body.contains(round_trip),
                "activate reintroduced a version round trip ({round_trip})"
            );
        }
        assert!(
            body.contains("must_match_version"),
            "activate no longer asserts its build on the create"
        );
        assert!(
            body.contains("ensure_version_reported"),
            "activate no longer checks the build the create echoed back"
        );
        assert!(
            function_code("refresh").is_some_and(|f| f.contains("GetVersion")),
            "the sidebar still needs each provider's version"
        );
    }

    /// Every free-function declaration in this file, as `(line index, name)`.
    fn fn_decls(lines: &[&str]) -> Vec<(usize, String)> {
        lines
            .iter()
            .enumerate()
            .filter_map(|(i, l)| {
                let t = l.trim_start();
                let t = t.strip_prefix("pub ").unwrap_or(t);
                let t = t.strip_prefix("async ").unwrap_or(t);
                t.strip_prefix("fn ")
                    .map(|rest| (i, rest.split(['(', '<']).next().unwrap_or("").to_string()))
            })
            .collect()
    }

    /// The named function's code, comments dropped — the rationale prose names
    /// the very mechanisms the scanners look for.
    fn function_code(name: &str) -> Option<String> {
        let src = include_str!("rpc.rs");
        let lines: Vec<&str> = src.lines().collect();
        let decls = fn_decls(&lines);
        let at = decls.iter().position(|(_, n)| n == name)?;
        let to = decls.get(at + 1).map_or(lines.len(), |(d, _)| *d);
        Some(
            lines[decls[at].0..to]
                .iter()
                .filter(|l| !l.trim_start().starts_with("//"))
                .copied()
                .collect::<Vec<_>>()
                .join("\n"),
        )
    }

    /// Attributes every direct `Client` connection in this file to the
    /// function that opens it, and reports how it is classified: gated by the
    /// assertion it carries on its own first RPC, or deliberately ungated with
    /// a comment saying why. An unclassified connection fails the test.
    fn connect_site_inventory() -> Vec<String> {
        // Concatenated so this scanner does not match itself.
        const NEEDLE: &str = concat!("Client", "::connect(");
        let src = include_str!("rpc.rs");
        let lines: Vec<&str> = src.lines().collect();
        let decls = fn_decls(&lines);

        let mut sites = Vec::new();
        for (i, line) in lines.iter().enumerate() {
            if !line.contains(NEEDLE) {
                continue;
            }
            let (start, name) = decls
                .iter()
                .rev()
                .find(|(d, _)| *d < i)
                .cloned()
                .unwrap_or((0, "<top level>".to_string()));
            let end = decls
                .iter()
                .find(|(d, _)| *d > start)
                .map_or(lines.len(), |(d, _)| *d);
            let body = &lines[start..end];
            let gated = body.iter().any(|l| {
                l.contains("must_match_version")
                    || l.contains("ensure_version_reported")
                    || l.contains("ensure_version_match")
            });
            let explained = body.iter().any(|l| l.contains("not version-gated"));
            let label = match (gated, explained) {
                (true, _) => "gated",
                (false, true) => "ungated (explained)",
                (false, false) => panic!("unclassified daemon connection in {name}"),
            };
            sites.push(format!("{name} = {label}"));
        }
        sites.sort();
        sites
    }
}
