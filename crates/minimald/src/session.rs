use crate::channel_progress::ChannelProgress;
use crate::session_sop::{
    BuildUpdate, CheckOpts, CheckUpdate, MaterializeOpts, MaterializeUpdate, SideOp,
};

use crate::sessions::{SessionControl, WeakManagerHandle, composables};
use crate::store::SessionRecordHandle;
use crate::{
    ChannelConfig,
    session_host::{self, HostAttrs, WinSize},
};
use mctx::ConfigBuilder;
use ot::OpTracker;
use paths::DaemonAbsPath;
use russh::{Channel, server::Msg};
use sessions::wire::request::ContributionResponse;
use sessions::{
    Record, SessionStatus,
    core::compose::Composition,
    daemon::composer::{ComposeOutcome, PendingComposeState, resume_from_verdict},
    store::{DiskSession, SessionObject},
    wire::request::{ContributionVerdict, SessionStep, WireContribution},
};
use std::fmt::{self};
use std::ops::ControlFlow;
use std::sync::Arc;
#[cfg(target_os = "linux")]
use std::sync::RwLock;
use tokio::sync::mpsc::WeakSender;
use tokio::sync::{Mutex, mpsc, oneshot};
use tokio::task::JoinHandle;

/// Copy every `composition.patches()` entry from the staged
/// `<workspace>/patches/<dest>` into the session's home dir at
/// the same relative path. Called once by [`Session::finalize`]
/// when the session goes `Active`; subsequent attaches see the
/// populated home without re-copying.
///
/// Parent dirs are created as needed. A missing staged patch
/// surfaces as an `io::Error` — the FinalizeSession precondition
/// checked the patches-ready marker, so a missing file at this
/// point is a bug (the marker was written but the file it should
/// have gated on didn't land).
async fn materialize_patches_into_home(
    patches_dir: &DaemonAbsPath,
    home_dir: &DaemonAbsPath,
    composition: &Composition,
) -> Result<(), std::io::Error> {
    for sp in composition.patches() {
        let dest = sp.patch().destination().as_utf8_path();
        let src = patches_dir.as_utf8_path().join(dest);
        let target = home_dir.as_utf8_path().join(dest);
        if let Some(parent) = target.parent() {
            tokio::fs::create_dir_all(parent.as_std_path()).await?;
        }
        tokio::fs::copy(src.as_std_path(), target.as_std_path())
            .await
            .map_err(|e| {
                std::io::Error::new(
                    e.kind(),
                    format!(
                        "materializing patch {} → {}: {e}",
                        src.as_str(),
                        target.as_str()
                    ),
                )
            })?;
    }
    Ok(())
}

/// Load the persisted composition snapshot for an `Active` session
/// brought up from disk after a daemon restart. Returns `None` (with
/// a warning log) when the sidecar is missing or corrupt. The
/// launcher then falls back to its baseline set, preserving the
/// "attach still works" property at the cost of the lost loadout
/// contributions. This is the loud-fallback path: the operator sees
/// the warning instead of a silent drop.
async fn load_composition(record: &SessionRecordHandle) -> Option<Arc<Composition>> {
    match record.load_composition().await {
        Ok(Some(comp)) => Some(Arc::new(comp)),
        Ok(None) => {
            tracing::warn!(
                session_id = %record.id(),
                "no composition snapshot for Active session; falling back to baseline",
            );
            None
        }
        Err(e) => {
            tracing::warn!(
                session_id = %record.id(),
                error = %e,
                "failed to load composition snapshot; falling back to baseline",
            );
            None
        }
    }
}

/// The name a session's PTask hostname is registered under, doubling as the
/// session host's display name: the session's assigned name, or the project
/// directory's basename when unnamed.
pub(crate) fn registry_name(record: &Record) -> String {
    match &record.name {
        Some(s) => s.clone(),
        None => record
            .project_path
            .file_name()
            .map(|s| s.to_string())
            .unwrap_or_else(|| "session".to_string()),
    }
}

/// The server-side `AcceptEnv` allowlist: locale and timezone vars a client is
/// permitted to forward from its shell into the session (OpenSSH's default
/// `AcceptEnv LANG LC_*`, plus `TZ`). Everything else the client set on the
/// channel — e.g. `MINIMAL_SESSION_ID`, `TRACEPARENT` — is control plumbing and
/// must not leak into the shell environment, so it is filtered out here.
fn inherited_session_env(
    channel_env: &std::collections::BTreeMap<String, String>,
) -> Vec<(String, String)> {
    channel_env
        .iter()
        .filter(|(k, _)| k.as_str() == "LANG" || k.as_str() == "TZ" || k.starts_with("LC_"))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

/// An error that occurred when attaching to a running session/its-shell.
#[derive(Debug)]
pub enum AttachError {
    SpawnFailed(std::io::Error),
    NoPty,
    ContextCreationFailed(String),
    /// The session's networking policy is incompatible with its network mode
    /// (R2.1): e.g. an egress section on a non-`OwnIp` PTask.
    InvalidPolicy(sessions::PolicyError),
    /// Configuring the loadout of an as-yet-unconfigured session, on the way
    /// into the attach, failed.
    LoadoutFailed(std::io::Error),
    /// The session isn't attachable yet. Either its composition is
    /// still awaiting the client's contribution verdict
    /// (`SubmitVerdict` hasn't landed), or its composition
    /// finalized but the session is `Materializing` — the
    /// client still owes a patches upload + `FinalizeSession`
    /// before a shell can be minted.
    SessionPending,
}

impl std::error::Error for AttachError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            AttachError::InvalidPolicy(e) => Some(e),
            AttachError::LoadoutFailed(e) => Some(e),
            _ => None,
        }
    }
}

impl fmt::Display for AttachError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AttachError::ContextCreationFailed(e) => {
                write!(f, "init of minimal context: {e}")
            }
            AttachError::NoPty => write!(f, "SSH channel did not configure a PTY"),
            AttachError::SpawnFailed(e) => write!(f, "session spawn: {e}"),
            AttachError::InvalidPolicy(e) => write!(f, "invalid session policy: {e}"),
            AttachError::LoadoutFailed(e) => write!(f, "configuring session loadout: {e}"),
            AttachError::SessionPending => write!(
                f,
                "session isn't attachable yet (still awaiting either \
                 SubmitVerdict or FinalizeSession)"
            ),
        }
    }
}

/// The paths on the daemon relevant to a session's internals.
#[derive(Debug)]
pub struct SessionPaths {
    pub working: DaemonAbsPath,
    pub cache: DaemonAbsPath,
    pub home: DaemonAbsPath,
    /// Where the daemon stages client-uploaded composition patches
    /// (`WorkspacePatchesTarZst` unpacks under this dir, keyed by
    /// the patch's sandbox-home-relative destination). Directory
    /// may not exist yet — it's created on the first successful
    /// upload.
    pub patches: DaemonAbsPath,
}

/// Everything a [`Session`] actor needs at spawn time. Every session actor
/// is spawned through [`Session::run`] with one of these, whether it is
/// backed by a freshly allocated record (the `CreateSession` path) or an
/// existing one being brought up from disk (the `GetSession` path); what the
/// session *is* comes from its record, not from the spawn site.
pub(crate) struct SessionConfig {
    pub minimal_state_dir: DaemonAbsPath,
    pub minimal_cache_dir: DaemonAbsPath,
    pub daemon_ctx: Arc<mctx::DaemonContext>,

    /// Handle to this session's record.
    pub record: SessionRecordHandle,
    /// Handle to the session manager, powers operations initiated within the session.
    pub manager: WeakManagerHandle,

    pub net_switch: Arc<Mutex<crate::net::SwitchClient>>,
    /// The daemon's shared PTask hostname registry; the actor registers its
    /// route on spawn, relinks on rename, and withdraws on stop/destroy.
    #[cfg(target_os = "linux")]
    pub hostnames: Arc<RwLock<crate::net::dns::HostnameRegistry>>,
}

/// Lifecycle-dependent state of a session actor: the multi-step create flow
/// as a state machine. Session-lifetime state (record snapshot, dirs,
/// tracker, handles) lives on [`Session`] itself.
#[derive(Debug)]
enum SessionInner {
    /// Session allocated but is accumulating configuration / not yet started.
    Draft {
        /// Daemon-side resume state for [`resume_from_verdict`], stashed by a
        /// [`ComposeOutcome::Pending`] loadout. `None` before the loadout is
        /// configured at all, and for an actor spawned from a `Pending`
        /// record — the state is in-memory only, so it died with whichever
        /// actor produced it. Either way there is nothing to resume, and
        /// `SubmitVerdict` faults.
        pending: Option<Box<PendingComposeState>>,
    },
    /// Composition finalized (record status `Active`), or spawned from an
    /// on-disk `Active` record.
    Active {
        /// The finalized [`Composition`] this session was created with.
        /// `None` only when the sidecar is missing or corrupt on a
        /// session brought up from disk after a daemon restart —
        /// [`load_composition`] logs a warning and the launcher
        /// falls back to its baseline set in that case.
        ///
        /// The launcher currently consumes only the composition's packages
        /// and vars. Patches (need file-upload plumbing) and lifecycle hooks
        /// (need in-sandbox exec plumbing) are held here but not yet applied.
        composition: Option<Arc<Composition>>,
        /// The running host, if minted, paired with the `JoinHandle` of its
        /// runtime loop so teardown can be awaited on destroy.
        host: Option<(
            session_host::HostHandle,
            JoinHandle<Result<i32, std::io::Error>>,
        )>,
        /// Side operations.
        sops: Vec<SideOp>,
    },
}

/// How a session actor's mainloop ended, deciding whether the actor still
/// needs to notify the manager to drop its `running` entry. Manager-initiated
/// terminations (`Stop`, `Destroy`) already removed the entry on the manager
/// side; actor-initiated ones (`Abort`, a failed verdict resume) must evict
/// themselves after the mailbox closes.
enum Teardown {
    ManagerInitiated,
    SelfInitiated,
}

enum SessionMessage {
    GetPaths(oneshot::Sender<SessionPaths>),
    MakeContext(oneshot::Sender<Result<mctx::Context, String>>),
    Attach(
        oneshot::Sender<Result<(), AttachError>>,
        SessionHandle,
        String,
        Channel<Msg>,
        ChannelConfig,
    ),
    GetHostAttrs(oneshot::Sender<Option<HostAttrs>>),
    /// Compose a `Draft` session's loadout from the project config and the
    /// client's wire contribution. `None` finalizes the session (`Active`);
    /// `Some(response)` parks it in `Draft` awaiting a verdict. Refused with
    /// `AlreadyExists` once `Active`; a compose failure is answered as an
    /// error and leaves the actor `Draft`, ready for another attempt.
    ConfigureLoadout(
        WireContribution,
        oneshot::Sender<Result<Option<ContributionResponse>, std::io::Error>>,
    ),
    /// Resume a `Draft` session with the client's verdict, promoting it to
    /// `Active`. Boxed so the variant doesn't dominate the enum's size.
    /// Answered with a `WrongState` fault on an `Active` or unconfigured
    /// session, and with a composer fault on an unresumable verdict — none
    /// of which are terminal for the actor.
    SubmitVerdict(
        Box<(
            ContributionVerdict,
            oneshot::Sender<Result<SessionStep, std::io::Error>>,
        )>,
    ),
    /// Promote a `Materializing` session to `Active`, gating on the
    /// patches-ready marker under `<workspace>/patches/`. Idempotent
    /// on an already-`Active` session; refused with `InvalidInput`
    /// on `Pending` (configure the loadout first).
    Finalize(oneshot::Sender<Result<(), std::io::Error>>),
    /// Abort a `Draft` session: delete its record and stop the actor.
    /// Refused with `InvalidInput` on an `Active` session (use `Destroy`).
    Abort(oneshot::Sender<Result<(), std::io::Error>>),
    /// Rename the session: persist the new name through the record handle,
    /// refresh the in-memory snapshot, and relink the PTask hostname.
    Rename(String, oneshot::Sender<Result<(), std::io::Error>>),
    /// Whether this session blocks an unforced daemon shutdown: a `Draft`
    /// holding compose state (a client is mid create flow, and stopping
    /// would strand it) or an `Active` with a minted host. A `Draft` that
    /// was merely created isn't busy — nothing is in flight to strand.
    IsBusy(oneshot::Sender<bool>),
    /// Shutdown-stop: kill the host (if any), withdraw the hostname, and stop
    /// the actor — the on-disk record is kept.
    Stop(oneshot::Sender<()>),
    /// Full teardown: like [`Stop`](Self::Stop), but also deletes the on-disk
    /// record.
    Destroy(oneshot::Sender<Result<(), std::io::Error>>),
    GetRecord(oneshot::Sender<Record>),
    /// Hand back an `Arc` clone of this session's patches-upload lock, see
    /// [`Session::patches_upload_lock`].
    GetPatchesUploadLock(oneshot::Sender<Arc<Mutex<()>>>),
    /// Kick off a background package build as a session side-op. Replies with
    /// the receiver end of the build's event stream.
    StartBuild {
        rebuild: bool,
        pkgs: Vec<String>,
        reply: oneshot::Sender<Result<mpsc::Receiver<BuildUpdate>, std::io::Error>>,
    },
    /// Kick off a background check run as a session side-op. Replies with the
    /// receiver end of the run's result stream.
    StartCheck {
        opts: CheckOpts,
        reply: oneshot::Sender<Result<mpsc::Receiver<CheckUpdate>, std::io::Error>>,
    },
    /// Kick off a background materialize run as a session side-op. Replies with
    /// the receiver end of the run's stream.
    StartMaterialize {
        opts: MaterializeOpts,
        reply: oneshot::Sender<Result<mpsc::Receiver<MaterializeUpdate>, std::io::Error>>,
    },
    /// Test-only inspection: an `Arc` clone of the held [`Composition`]
    /// (`None` in `Draft`, or `Active` without one post-restart). Lets tests
    /// assert composition contents without disturbing the lifecycle.
    #[cfg(test)]
    PeekComposition(oneshot::Sender<Option<Arc<Composition>>>),
}

/// Manages one session, from the moment its record is allocated: the create
/// flow (compose → `Draft` → verdict → `Active`) runs as the
/// [`SessionInner`] state machine, and the actor owns its record's writes
/// and deletion, its PTask hostname, its held composition, and its host.
///
/// Follows the actor pattern.
#[derive(Debug)]
pub struct Session {
    receiver: mpsc::Receiver<SessionMessage>,
    minimal_state_dir: DaemonAbsPath,
    minimal_cache_dir: DaemonAbsPath,
    daemon_ctx: Arc<mctx::DaemonContext>,

    /// Store-backed handle to this session's record.
    record: SessionRecordHandle,

    /// The daemon's shared PTask hostname registry (see
    /// [`SessionSeed::hostnames`]). The lock is only ever held for a
    /// synchronous register/deregister, never across an `.await`.
    #[cfg(target_os = "linux")]
    hostnames: Arc<RwLock<crate::net::dns::HostnameRegistry>>,

    /// The daemon-scoped gvproxy switch, injected into each `SandboxLauncher`
    /// this session mints so an `OwnIp` PTask attaches to the one per-host
    /// switch (R1.5). Read only by the production `session_launcher`
    /// (`cfg(not(test))`); the `cfg(test)` mock launcher ignores it, so the
    /// unused-field lint is silenced under test rather than threaded through.
    #[cfg_attr(test, allow(dead_code))]
    net_switch: Arc<Mutex<crate::net::SwitchClient>>,

    /// The root of this session's operation tree - tracks long-running
    /// operations for display.
    tracker: OpTracker,

    /// Session state machine.
    inner: SessionInner,

    /// Serializes `WorkspacePatchesTarZst` uploads for this session: two
    /// concurrent uploads would race on the single `<workspace>/patches/`
    /// tree and step on each other.
    patches_upload_lock: Arc<Mutex<()>>,

    /// A non-owning handle to the [`Manager`](crate::sessions::Manager), used to
    /// build the [`SessionControl`] handed to each [`Binding`] so a shell-exit
    /// "delete" tears this session down through the manager (record removal and
    /// all), and to self-evict from the manager's running map on
    /// actor-initiated termination. Weak by design — see
    /// [`crate::sessions::Manager::weak_self`].
    manager: WeakManagerHandle,

    /// A non-owning handle to this session, handed to the runtime objects
    /// we spawns (e.g. build [`SideOp`]s) so they can reach back into
    /// the session.
    weak_self: WeakSessionHandle,
}

impl Session {
    /// Assembles the actor from its seed, mailbox, and initial state. The
    /// caller decides when to enter [`Self::mainloop`].
    fn assemble(
        seed: SessionConfig,
        receiver: mpsc::Receiver<SessionMessage>,
        inner: SessionInner,
        weak_self: WeakSessionHandle,
    ) -> Self {
        let SessionConfig {
            minimal_state_dir,
            minimal_cache_dir,
            daemon_ctx,
            record,
            net_switch,
            manager,
            #[cfg(target_os = "linux")]
            hostnames,
        } = seed;
        Self {
            receiver,
            record,
            minimal_state_dir,
            minimal_cache_dir,
            daemon_ctx,
            net_switch,
            tracker: OpTracker::new_root(),
            inner,
            patches_upload_lock: Arc::new(Mutex::new(())),
            manager,
            weak_self,
            #[cfg(target_os = "linux")]
            hostnames,
        }
    }

    /// Create the session's backing directories (workspace, home, cache).
    fn create_dirs(object: &DiskSession) -> Result<(), std::io::Error> {
        std::fs::create_dir_all(object.workspace_path())?;
        std::fs::create_dir_all(object.home_path())?;
        std::fs::create_dir_all(object.cache_path())?;
        Ok(())
    }

    /// Launches the actor for a session — the one path onto which every
    /// session actor is spawned. The initial state machine state is derived
    /// from the record alone: an `Active` record comes up ready to attach
    /// with its composition restored from the snapshot sidecar (or, if the
    /// sidecar is missing or corrupt, with a logged warning and no
    /// composition so the launcher falls back to its baseline set), a
    /// `Pending` one as an unconfigured `Draft` awaiting `ConfigureLoadout`.
    pub(crate) async fn run(conf: SessionConfig) -> Result<SessionHandle, std::io::Error> {
        let obj = conf.record.object().await?;
        Self::create_dirs(&obj)?;

        let inner = match obj.record().status {
            SessionStatus::Active => {
                let composition = load_composition(&conf.record).await;
                SessionInner::Active {
                    composition,
                    host: None,
                    sops: vec![],
                }
            }
            SessionStatus::Pending => SessionInner::Draft { pending: None },
            // `Materializing` records are only meaningful across a
            // matching in-memory composition, which is lost on
            // daemon restart. `Manager::init` runs
            // `reap_unresumable_records` at startup to delete these
            // before any actor spawns.
            //
            // If we still see one here — spawn racing the reap,
            // reap's delete failing (permissions, EIO) and being
            // logged-and-skipped, or a future code path adding a
            // spawn that bypasses the reap — refuse to bring the
            // actor up. Every alternative gets a session into a
            // bad shape:
            //
            //   * `SessionInner::Draft { pending: None }` would let
            //     `configure_loadout` accept a fresh contribution
            //     while the on-disk status stays `Materializing`,
            //     drifting the two into inconsistency.
            //   * A stale `.patches_ready` from the prior upload
            //     could then satisfy the *new* composition's
            //     finalize marker check, materializing the wrong
            //     patches into the sandbox home.
            //   * `SessionInner::Active { composition: None }`
            //     would let attach reach a shell against a session
            //     that never actually finished materializing.
            //
            // Fail the spawn instead; the caller sees an error and
            // the operator can destroy the stuck record explicitly.
            SessionStatus::Materializing => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "session record is Materializing but has no in-memory composition \
                     (restart-orphaned actor); destroy the session and re-activate",
                ));
            }
        };

        let (sender, receiver) = mpsc::channel(8);
        // A weak self-handle so the actor can hand its own mailbox to the
        // runtime objects it spawns without a caller threading it in.
        let weak_self = WeakSessionHandle(sender.downgrade());
        let actor = Self::assemble(conf, receiver, inner, weak_self);

        // Register the PTask hostname before the actor goes live, so the
        // route exists by the time the caller can observe the session
        // (R3.1/R3.6). A `Draft` session has nothing to route to yet, so
        // `register_hostname` no-ops until its loadout finalizes.
        #[cfg(target_os = "linux")]
        actor.register_hostname(obj.record());

        tokio::spawn(actor.mainloop());
        Ok(SessionHandle(sender))
    }

    /// Register this session's PTask hostname (R3.1/R3.6). Both HostNet and
    /// OwnIp resolve to loopback: a HostNet PTask's listeners are on host
    /// loopback; an OwnIp PTask is reached through a gvproxy-published
    /// loopback port (#542, the published-loopback model). A NoNet PTask
    /// exposes no services, so it is not registered — and neither is a
    /// `Draft` session, which has nothing to route to until its composition
    /// finalizes.
    #[cfg(target_os = "linux")]
    fn register_hostname(&self, record: &Record) {
        if !self.owns_hostname_route(record) {
            return;
        }
        let name = registry_name(record);
        let mut reg = self
            .hostnames
            .write()
            .expect("hostname registry lock poisoned");
        match record.network {
            sessions::NetworkMode::OwnIp => {
                reg.register_own_ip(record.id, &name);
            }
            sessions::NetworkMode::HostNet => {
                reg.register_host_net(record.id, &name);
            }
            _ => {}
        }
    }

    /// Whether this session currently owns a PTask hostname route: `Active`
    /// with a routable network mode — exactly the condition under which
    /// [`Self::register_hostname`] registered one.
    #[cfg(target_os = "linux")]
    fn owns_hostname_route(&self, record: &Record) -> bool {
        matches!(self.inner, SessionInner::Active { .. })
            && matches!(
                record.network,
                sessions::NetworkMode::HostNet | sessions::NetworkMode::OwnIp
            )
    }

    /// Withdraw this session's PTask hostname (R3.5).
    ///
    /// Gated on [`Self::owns_hostname_route`] rather than relying on the
    /// registry's no-op behavior: the registry is keyed by name alone, so an
    /// ungated deregister from a session that never registered (`Draft`, or
    /// a non-routable mode) could withdraw an *unrelated* session's route
    /// that happens to share the same derived name.
    #[cfg(target_os = "linux")]
    async fn deregister_hostname(&self) {
        let record = self.record.record().await.unwrap();
        if !self.owns_hostname_route(&record) {
            return;
        }
        self.hostnames
            .write()
            .expect("hostname registry lock poisoned")
            .deregister(&registry_name(&record));
    }

    /// The async task which handles interactions with the session.
    ///
    /// On an actor-initiated termination (abort, failed verdict resume) the
    /// mailbox is closed *before* the manager is told to drop its `running`
    /// entry, so a manager concurrently awaiting this actor errors out
    /// instead of deadlocking against a full manager mailbox.
    async fn mainloop(mut self) {
        let mut teardown = Teardown::ManagerInitiated;
        while let Some(msg) = self.receiver.recv().await {
            if let ControlFlow::Break(t) = self.handle_message(msg).await {
                teardown = t;
                break;
            }
        }
        if matches!(teardown, Teardown::SelfInitiated) {
            let session_id = *self.record.id();
            let manager = self.manager.clone();
            // Close the mailbox first (see above), then notify the manager.
            drop(self);
            if let Some(manager) = manager.upgrade() {
                manager.evict(session_id).await;
            }
        }
    }

    /// Handles a specific message recieved by the session.
    ///
    /// Returns [`ControlFlow::Break`] when the session has terminated and
    /// the actor loop should exit.
    async fn handle_message(&mut self, msg: SessionMessage) -> ControlFlow<Teardown> {
        match msg {
            SessionMessage::GetPaths(r) => {
                let _ = r.send(self.paths().await);
            }
            SessionMessage::MakeContext(r) => {
                let _ = r.send(self.context(false).await);
            }
            SessionMessage::Attach(r, session_hnd, conn_username, channel, config) => {
                let _ = r.send(
                    self.attach(session_hnd, conn_username, channel, config)
                        .await,
                );
            }
            SessionMessage::GetHostAttrs(r) => {
                let _ = r.send(match &self.inner {
                    SessionInner::Active {
                        host: Some((h, _)), ..
                    } => h.get_attrs().await.ok(),
                    _ => None,
                });
            }
            SessionMessage::ConfigureLoadout(contribution, r) => {
                let _ = r.send(self.configure_loadout(contribution).await);
            }
            SessionMessage::SubmitVerdict(msg) => {
                let (verdict, r) = *msg;
                let _ = r.send(self.handle_verdict(verdict).await);
            }
            SessionMessage::Finalize(r) => {
                let _ = r.send(self.finalize().await);
            }
            SessionMessage::Abort(r) => match &self.inner {
                // Abort is Draft-only: delete the record, then stop. The
                // record delete happens before the reply so a post-reply
                // store read never sees the aborted session.
                SessionInner::Draft { .. } => {
                    let _ = r.send(self.record.clone().delete().await);
                    return ControlFlow::Break(Teardown::SelfInitiated);
                }
                SessionInner::Active { .. } => {
                    let _ = r.send(Err({
                        match self.record.record().await {
                            Ok(record) => std::io::Error::new(
                                std::io::ErrorKind::InvalidInput,
                                format!(
                                    "cannot abort session `{}`: status is {:?}, expected Pending",
                                    record.id.as_ref(),
                                    record.status,
                                ),
                            ),
                            Err(e) => e,
                        }
                    }));
                }
            },
            SessionMessage::Rename(new_name, r) => {
                let _ = r.send(self.rename(new_name).await);
            }
            SessionMessage::IsBusy(r) => {
                let _ = r.send(match &self.inner {
                    // Awaiting a verdict: a client is mid create flow.
                    SessionInner::Draft { pending } => pending.is_some(),
                    SessionInner::Active { host, .. } => host.is_some(),
                });
            }
            SessionMessage::Stop(r) => {
                self.stop_running(true).await;
                #[cfg(target_os = "linux")]
                self.deregister_hostname().await;
                let _ = r.send(());
                return ControlFlow::Break(Teardown::ManagerInitiated);
            }
            SessionMessage::Destroy(r) => {
                self.stop_running(false).await;
                // Withdraw the hostname before the fallible record delete, so
                // a delete failure leaves a stale on-disk record (repairable
                // on restart) but never a stale routing entry pointing at a
                // destroyed session (R3.5).
                #[cfg(target_os = "linux")]
                self.deregister_hostname().await;
                let _ = r.send(self.record.clone().delete().await);
                return ControlFlow::Break(Teardown::ManagerInitiated);
            }
            SessionMessage::GetPatchesUploadLock(r) => {
                let _ = r.send(Arc::clone(&self.patches_upload_lock));
            }
            SessionMessage::StartBuild {
                rebuild,
                pkgs,
                reply,
            } => {
                let _ = reply.send(self.start_build(rebuild, pkgs).await);
            }
            SessionMessage::StartCheck { opts, reply } => {
                let _ = reply.send(self.start_check(opts).await);
            }
            SessionMessage::StartMaterialize { opts, reply } => {
                let _ = reply.send(self.start_materialize(opts).await);
            }
            SessionMessage::GetRecord(r) => {
                let _ = r.send(self.record.record().await.unwrap());
            }
            #[cfg(test)]
            SessionMessage::PeekComposition(r) => {
                let _ = r.send(match &self.inner {
                    SessionInner::Active { composition, .. } => composition.clone(),
                    SessionInner::Draft { .. } => None,
                });
            }
        }
        ControlFlow::Continue(())
    }

    /// Compose this session's loadout from its project config and the
    /// client's wire contribution, then either finalize it (`Ok(None)`, the
    /// session is now `Active`) or park it in `Draft` holding the resume
    /// state until the client gates the returned items (`Ok(Some(response))`).
    ///
    /// Every failure leaves the actor alive and `Draft`: the caller decides
    /// whether to retry with a different contribution or tear the session
    /// down, so a compose error can't strand a half-built session.
    ///
    /// A re-`ConfigureLoadout` against a session that already holds
    /// `Draft{pending: Some(_)}` is refused with `WouldBlock`: overwriting
    /// the stashed [`PendingComposeState`] would invalidate every
    /// `PendingId` the first caller received (they were valid moments ago,
    /// but a fresh stash starts numbering from 0 again). The client must
    /// `AbortSession` and create a new session to retry rather than
    /// silently strand its outstanding verdict submission.
    async fn configure_loadout(
        &mut self,
        contribution: WireContribution,
    ) -> Result<Option<ContributionResponse>, std::io::Error> {
        match &self.inner {
            SessionInner::Active { .. } => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    "session loadout is already configured",
                ));
            }
            SessionInner::Draft { pending: Some(_) } => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WouldBlock,
                    "session already has a pending contribution awaiting SubmitVerdict; \
                     abort it and create a new session to retry",
                ));
            }
            SessionInner::Draft { pending: None } => {}
        }
        let object = self.record.object().await?;
        let workspace_path = object.workspace_path();

        // Deliberately no scaffold here: composing is not the moment to
        // fabricate a project. `scaffold_default_mfile` resolves the default
        // package repo's branch head over the network, and the default's
        // packages reach the sandbox through the launcher's context (built
        // from the workspace mfile) rather than through the composition —
        // so paying for it here would buy nothing. A bare workspace composes
        // to an empty loadout, and the scaffold lands at context-build time.

        // Phase 1+2: resolve the project and drive the composer. Kept fully
        // synchronous — its non-`Send` intermediaries must not cross an
        // `.await`.
        let outcome = composables::run_compose(&self.daemon_ctx, &workspace_path, contribution)?;

        match outcome {
            // The composition is complete: promote the record
            // `Pending → Active` and hold the composition for the launcher.
            ComposeOutcome::Ready(composition) => {
                // Compose finalized in one shot — the record is now
                // `Materializing`, not yet `Active`. `Active` waits
                // for `FinalizeSession` after the client has
                // uploaded the composition's patches. Hostname
                // registration is deferred to the same transition
                // (a session isn't attachable until then, so
                // publishing the route would let something reach a
                // launcher that can't materialize its patches).
                //
                // Persist the composition snapshot before the record
                // write so a crash at any point leaves either a
                // reaped session (Pending/Materializing records are
                // reaped at startup) or an Active session with its
                // sidecar intact.
                self.record.store_composition(&composition).await?;
                let mut record = object.record().clone();
                record.status = SessionStatus::Materializing;
                self.record.write(record.clone()).await?;
                self.inner = SessionInner::Active {
                    composition: Some(Arc::new(composition)),
                    host: None,
                    sops: vec![],
                };
                Ok(None)
            }
            // The client must gate items before the composition completes.
            // Park in `Draft` with the daemon-side resume state; the record
            // is already `Pending` on disk, so nothing to write.
            ComposeOutcome::Pending {
                mut response,
                state,
            } => {
                // The composer ran before the allocated id was known to it.
                response.session_id = *self.record.id();
                self.inner = SessionInner::Draft {
                    pending: Some(Box::new(state)),
                };
                Ok(Some(response))
            }
        }
    }

    /// Resume a `Draft` session with the client's verdict: finalize the
    /// composition and transition to `Active`.
    ///
    /// Structured refusals — a session that is already `Active` or was never
    /// configured, and a verdict the composer can't apply — come back as a
    /// [`SessionStep::Fault`] and leave the session `Draft` and resumable, so
    /// a client that mis-gated an item can correct it and re-submit rather
    /// than lose the session.
    async fn handle_verdict(
        &mut self,
        verdict: ContributionVerdict,
    ) -> Result<SessionStep, std::io::Error> {
        let wrong_state = |what: &str| {
            Ok(SessionStep::Fault {
                error: sessions::wire::errors::WireError::WrongState {
                    what: what.to_string(),
                },
            })
        };
        let pending = match &self.inner {
            SessionInner::Active { .. } => return wrong_state("expected Pending, found Active"),
            SessionInner::Draft { pending: None } => {
                return wrong_state(
                    "expected Pending, found a session with no composition to resume",
                );
            }
            SessionInner::Draft {
                pending: Some(state),
            } => state,
        };

        // Clone rather than take: `resume_from_verdict` consumes the state,
        // and a rejected verdict has to leave the session resumable.
        let composition = match resume_from_verdict((**pending).clone(), verdict) {
            Ok(c) => c,
            Err(e) => return Ok(SessionStep::Fault { error: e.into() }),
        };

        // Promote the on-disk record `Pending → Materializing`. A
        // write failure leaves both the record and the actor
        // `Draft`, so the client can re-submit the same verdict
        // once the store recovers. `Active` waits for a follow-up
        // `FinalizeSession` after patches upload — see
        // [`Self::finalize`] for the transition and its
        // preconditions.
        //
        // Persist the composition snapshot before the record write
        // (same crash-safety reasoning as the Materialized fast
        // path above).
        self.record.store_composition(&composition).await?;
        let mut record = self.record.record().await?;
        record.status = SessionStatus::Materializing;
        self.record.write(record.clone()).await?;
        self.inner = SessionInner::Active {
            composition: Some(Arc::new(composition)),
            host: None,
            sops: vec![],
        };
        Ok(SessionStep::Materialized { id: record.id })
    }

    /// Finalize a `Materializing` session: verify that the client
    /// has uploaded its composition patches (marker present under
    /// `<workspace>/patches/`), promote the record
    /// `Materializing → Active`, and publish the PTask route so
    /// the session becomes attachable.
    ///
    /// Idempotent: a session already in `Active` (client retried
    /// after a network blip that lost the ack) returns success
    /// without side effects. Refuses `Pending` or `Draft` sessions
    /// with `WrongState`; refuses `Materializing` sessions without
    /// a patches-ready marker with a "patches upload never
    /// finished" fault.
    async fn finalize(&mut self) -> Result<(), std::io::Error> {
        let record = self.record.record().await?;
        match record.status {
            SessionStatus::Active => {
                // Already finalized — retry is a no-op.
                Ok(())
            }
            SessionStatus::Materializing => {
                // Guard against a `Materializing` record whose
                // actor didn't carry compose state through — the
                // only path there is `Session::run` spawning from
                // an on-disk `Materializing` record after a
                // restart survived the reap in `Manager::init`
                // (delete failed, log-and-skip). Without the
                // in-memory composition we can't tell whether the
                // patches were uploaded; `has_patches` below would
                // trivially match `false` and skip the marker
                // check, then `materialize_patches_into_home`
                // would iterate an empty composition and no-op —
                // silently promoting the session to `Active` with
                // an empty home. Fault the finalize so the client
                // sees the problem instead of the user attaching
                // to a broken shell.
                if !matches!(
                    &self.inner,
                    SessionInner::Active {
                        composition: Some(_),
                        ..
                    }
                ) {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "session is Materializing but has no in-memory composition \
                         (restart-orphaned actor); destroy the session and re-activate",
                    ));
                }

                // Precondition: patches marker present on disk. The
                // marker is the last thing the patches unpacker
                // writes, so its presence proves every patch is
                // staged. Without this check a client-side bug
                // that skipped the patches upload would silently
                // yield an Active session with a broken sandbox
                // rootfs.
                //
                // Short-circuit: a composition with no patches has
                // nothing for the client to upload, so the marker
                // isn't required. Callers with empty compositions
                // (internal ones — sftp/exec/session-recovery — and
                // any project with no fs mappings) go straight
                // through here.
                let paths_obj = self.record.object().await?;
                let patches_dir = paths_obj.patches_path();
                let has_patches = matches!(
                    &self.inner,
                    SessionInner::Active {
                        composition: Some(c),
                        ..
                    } if !c.patches().is_empty()
                );
                if has_patches {
                    let marker = patches_dir
                        .as_utf8_path()
                        .join(crate::rpc::PATCHES_READY_MARKER);
                    // Distinguish "marker absent" (client forgot the
                    // upload; retry the upload + FinalizeSession)
                    // from "we couldn't tell" (permissions, filesystem
                    // I/O). Collapsing the latter into the former
                    // sends the operator chasing an upload that
                    // already succeeded when the real fault is a
                    // broken workspace dir.
                    let marker_present = tokio::fs::try_exists(&marker).await.map_err(|e| {
                        std::io::Error::new(
                            e.kind(),
                            format!("checking patches-ready marker at {}: {e}", marker.as_str()),
                        )
                    })?;
                    if !marker_present {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            "patches upload never completed; cannot finalize \
                             (upload patches, then retry FinalizeSession)",
                        ));
                    }
                }

                // Materialize the composition's patches into the
                // session's home dir. Done here — once — rather
                // than on every attach so the sandbox home is
                // populated exactly at the point the session
                // becomes attachable, and subsequent attaches see
                // the same tree without re-copying (which would
                // clobber any in-sandbox modifications the user
                // made in prior attaches). If the composition has
                // no patches, this is a no-op.
                if let SessionInner::Active {
                    composition: Some(comp),
                    ..
                } = &self.inner
                {
                    let home = paths_obj.home_path();
                    materialize_patches_into_home(&patches_dir, &home, comp).await?;
                }

                let mut record = record;
                record.status = SessionStatus::Active;
                self.record.write(record.clone()).await?;
                #[cfg(target_os = "linux")]
                self.register_hostname(&record);
                Ok(())
            }
            SessionStatus::Pending => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "session is Pending; configure the loadout first",
            )),
        }
    }

    /// Kicks off a background package build as a side-op and registers it on
    /// this session, returning the receiver end of its event stream. The build
    /// runs against a fresh workspace-rooted context (rebuilt per call so it
    /// tracks `minimal.toml` edits).
    ///
    /// The returned receiver closes when the build ends.
    async fn start_build(
        &mut self,
        rebuild: bool,
        pkgs: Vec<String>,
    ) -> Result<mpsc::Receiver<BuildUpdate>, std::io::Error> {
        let ctx = self.context(false).await.map_err(std::io::Error::other)?;
        let (sop, rx) = SideOp::spawn_build(self.weak_self.clone(), rebuild, pkgs, ctx, 64).await?;
        match &mut self.inner {
            SessionInner::Active { sops, .. } => sops.push(sop),
            SessionInner::Draft { .. } => {
                sop.shutdown().await;
                unreachable!("`context()` already rejected a `Draft`");
            }
        }
        Ok(rx)
    }

    /// Kicks off a background check run as a side-op and registers it on this
    /// session, returning the receiver end of its result stream. Like
    /// [`start_build`](Self::start_build) it runs against a fresh
    /// workspace-rooted context, so it sees `minimal.toml` edits made since the
    /// session came up.
    ///
    /// The returned receiver closes when the run ends.
    async fn start_check(
        &mut self,
        opts: CheckOpts,
    ) -> Result<mpsc::Receiver<CheckUpdate>, std::io::Error> {
        let ctx = self.context(false).await.map_err(std::io::Error::other)?;
        let (sop, rx) = SideOp::spawn_check(self.weak_self.clone(), opts, ctx, 64).await?;
        match &mut self.inner {
            SessionInner::Active { sops, .. } => sops.push(sop),
            SessionInner::Draft { .. } => {
                sop.shutdown().await;
                unreachable!("`context()` already rejected a `Draft`");
            }
        }
        Ok(rx)
    }

    /// Kicks off a background materialize run as a side-op and registers it on
    /// this session, returning the receiver end of its stream. Like
    /// [`start_build`](Self::start_build) it runs against a fresh
    /// workspace-rooted context, so it sees outputs declared since the session
    /// came up. The receiver closes when the run ends.
    async fn start_materialize(
        &mut self,
        opts: MaterializeOpts,
    ) -> Result<mpsc::Receiver<MaterializeUpdate>, std::io::Error> {
        let ctx = self.context(false).await.map_err(std::io::Error::other)?;
        let (sop, rx) = SideOp::spawn_materialize(self.weak_self.clone(), opts, ctx, 64).await?;
        match &mut self.inner {
            SessionInner::Active { sops, .. } => sops.push(sop),
            SessionInner::Draft { .. } => {
                sop.shutdown().await;
                unreachable!("`context()` already rejected a `Draft`");
            }
        }
        Ok(rx)
    }

    /// Tears down any runtime objects, such as the host or side ops. Shutdown
    /// of these objects is complete once awaited.
    ///
    /// `for_shutdown` is threaded to the host's kill so attached clients get
    /// the daemon-shutdown message (and a terminal reset) rather than a bare
    /// disconnect when the session dies because the daemon is going away.
    async fn stop_running(&mut self, for_shutdown: bool) {
        let inner = match &mut self.inner {
            SessionInner::Active { host, sops, .. } => Some((host.take(), std::mem::take(sops))),
            SessionInner::Draft { .. } => None,
        };
        if let Some((host, mut sops)) = inner {
            for s in sops.drain(..) {
                s.shutdown().await;
            }
            if let Some((host, task)) = host {
                // Signal the process to die, then await the runtime loop so the
                // sandbox files backing its rootfs are released before the caller
                // removes the session's directory tree.
                let _ = host.kill(for_shutdown).await;
                let _ = task.await;
            }
        }
    }

    /// Renames the session: persists the new name through the record handle
    /// (a name collision surfaces as the store's `AlreadyExists`), relinks
    /// the PTask hostname so `<new>.local.min.internal` routes and the old name stops (R3.6).
    async fn rename(&mut self, new_name: String) -> Result<(), std::io::Error> {
        let record = self.record.record().await?;

        // Withdraw the route under the pre-rename name before the record
        // mutates; re-register under the new name afterwards. Both calls
        // gate on this session actually owning a route, so a Draft/NoNet
        // rename never touches the registry.
        #[cfg(target_os = "linux")]
        self.deregister_hostname().await;
        let mut new_record = record.clone();
        new_record.name = Some(new_name);
        let written = self.record.write(new_record.clone()).await;

        // Re-register whichever name stuck (the new one on success, the old
        // one if the write was refused) so a failed rename never strands the
        // session without a route.
        #[cfg(target_os = "linux")]
        self.register_hostname(match &written {
            Ok(_) => &new_record,
            Err(_) => &record,
        });

        written
    }

    async fn attach(
        &mut self,
        session_hnd: SessionHandle,
        conn_username: String,
        channel: Channel<Msg>,
        config: ChannelConfig,
    ) -> Result<(), AttachError> {
        let sz = WinSize::from(match config.pty.as_ref() {
            Some(pty) => pty,
            None => return Err(AttachError::NoPty),
        });

        // Capture the environment this attach contributes to the shell it may
        // mint: the locale/timezone vars the client forwarded (folded as
        // defaults below the composition) and the per-connection facts folded
        // above it. Currently the only connection fact is `TERM`, from the
        // client's PTY request.
        //
        // `SSH_TTY` and `SSH_CONNECTION`/`SSH_CLIENT` are intentionally omitted:
        // the session sandbox has no host `/dev/pts` and the transport is a
        // local Unix socket (no peer IP/port), so any value would name something
        // that doesn't exist in-session and would only mislead audit logs,
        // source-IP checks, or `$SSH_TTY` consumers.
        let attach_env = {
            let inherited = inherited_session_env(&config.env_vars);
            let mut connection = Vec::new();
            if let Some(pty) = config.pty.as_ref()
                && !pty.term.is_empty()
            {
                connection.push(("TERM".to_string(), pty.term.clone()));
            }
            session_host::AttachEnv {
                inherited,
                connection,
            }
        };

        // A session that was created but never had its loadout configured has
        // nothing in flight, so attaching to it shouldn't be an error: set it
        // up now, with an empty contribution, and carry on into the attach.
        // Composition that comes back `Pending` is the one case we can't
        // resolve here — items need a client-side gate — and falls through to
        // the refusal below.
        //
        // The shortcut only works when the composition ends up with
        // no patches. Patches require the client to run the
        // `WorkspacePatchesTarZst` upload + `FinalizeSession`
        // sequence, and this attach path has no way to obtain those
        // files — nothing on the daemon side reaches back to the
        // client to solicit an upload. If we ran `configure_loadout`
        // and it produced patches, the record would be stuck at
        // `Materializing` with no path to `Active` and every
        // subsequent attach would hit the `SessionPending` refusal.
        // So: run the configure, and if patches surfaced, roll the
        // in-memory state back to `Draft { pending: None }` (the
        // record's on-disk `Materializing` status still leaves it
        // reachable for `DestroySession`) and refuse the attach with
        // an actionable error naming the required explicit flow.
        if let SessionInner::Draft { pending: None } = &self.inner {
            self.configure_loadout(WireContribution::default())
                .await
                .map_err(AttachError::LoadoutFailed)?;
            let has_patches = matches!(
                &self.inner,
                SessionInner::Active {
                    composition: Some(c),
                    ..
                } if !c.patches().is_empty()
            );
            if has_patches {
                // Refuse: this attach path can't run the
                // upload + FinalizeSession sequence the composition
                // requires. `finalize`'s per-op guard will refuse
                // any later attempt against this Materializing
                // record, so the operator has to destroy it and
                // re-activate through `min session activate`, which drives
                // the full flow.
                return Err(AttachError::LoadoutFailed(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "composition has patches that can only be uploaded via `min session activate` \
                     (ConfigureLoadout → WorkspacePatchesTarZst → FinalizeSession); \
                     the attach shortcut can't drive that sequence — destroy this session \
                     and re-activate through the CLI",
                )));
            }
            // No patches: finalize inline so the shortcut still
            // yields an attachable session. The marker check inside
            // `finalize` is gated on `!composition.patches().is_empty()`,
            // so an empty composition doesn't need the dir + marker
            // to exist: `finalize` skips the check, `materialize`
            // iterates zero patches, and the record is written as
            // `Active`.
            self.finalize().await.map_err(AttachError::LoadoutFailed)?;
        }

        // Attach is gated on `Active` — a Materializing session has
        // a composition but its patches may not be on disk yet,
        // and materializing without them would produce a broken
        // sandbox rootfs. See [`Session::finalize`] for the
        // transition.
        {
            let record = self
                .record
                .record()
                .await
                .map_err(AttachError::LoadoutFailed)?;
            if record.status != SessionStatus::Active {
                return Err(AttachError::SessionPending);
            }
        }

        let host = match &mut self.inner {
            // Awaiting a verdict: a client is mid create flow, and composing
            // over it here would discard the items it is still gating.
            SessionInner::Draft { .. } => return Err(AttachError::SessionPending),
            SessionInner::Active { host, .. } => host,
        };
        match host {
            None => {
                self.mint_session_host(session_hnd, conn_username, channel, sz, attach_env)
                    .await
            }
            Some((h, _)) => {
                match h.attach(channel, sz).await {
                    Ok(()) => Ok(()),
                    Err((channel, sz)) => {
                        // session host is dead
                        self.mint_session_host(session_hnd, conn_username, channel, sz, attach_env)
                            .await
                    }
                }
            }
        }
    }

    async fn mint_session_host(
        &mut self,
        session_hnd: SessionHandle,
        conn_username: String,
        channel: Channel<Msg>,
        sz: WinSize,
        attach_env: session_host::AttachEnv,
    ) -> Result<(), AttachError> {
        let record = self.record.record().await.unwrap();
        let paths = self.paths().await;
        let name = registry_name(&record);

        // Mint a handle to this session ID in the sessions actor/manager.
        let control = SessionControl::new(self.manager.clone(), record.id);

        // Spawn/setup the session in a closure that reports progress down the terminal.
        let launcher = self
            .session_launcher(session_hnd, &record, attach_env)
            .await?;
        let progress = ChannelProgress::new(channel, self.tracker.clone(), (sz.cols, sz.rows));
        let (channel, spawned) = progress
            .run(Box::pin(session_host::Host::spawn(
                launcher,
                name,
                conn_username,
                paths,
                sz,
                None,
                Some(control),
            )))
            .await;
        let h = spawned.map_err(AttachError::SpawnFailed)?;

        // Wire the channel to the freshly launched host. A failure here means
        // the host died in the window between launch and attach; surface it as
        // a spawn failure rather than leaving a dead, channel-less host.
        h.0.attach(channel, sz).await.map_err(|_| {
            AttachError::SpawnFailed(std::io::Error::other(
                "session host exited before its channel could attach",
            ))
        })?;
        let SessionInner::Active { host, .. } = &mut self.inner else {
            unreachable!("mint_session_host is only reachable from the Active state");
        };
        *host = Some(h);
        Ok(())
    }

    /// The held [`Composition`], if any — `None` in `Draft` or for an actor
    /// spawned from disk after a daemon restart.
    #[cfg_attr(test, allow(dead_code))]
    fn composition(&self) -> Option<Arc<Composition>> {
        match &self.inner {
            SessionInner::Active { composition, .. } => composition.clone(),
            SessionInner::Draft { .. } => None,
        }
    }

    /// Builds the session launcher used to mint a session host: the real
    /// sandboxed shell in production.
    #[cfg(not(test))]
    async fn session_launcher(
        &mut self,
        session: SessionHandle,
        record: &Record,
        attach_env: session_host::AttachEnv,
    ) -> Result<session_host::SandboxLauncher, AttachError> {
        // R2.1: reject a policy that is incompatible with the network mode
        // (e.g. egress on a non-`OwnIp` PTask) before launching the host.
        record
            .validate_policy()
            .map_err(AttachError::InvalidPolicy)?;
        let network_mode = record.network;
        // Only an `OwnIp` PTask attaches to the switch, so ingress forwards are
        // only carried for that mode; `validate_policy` has already rejected
        // ingress configured on any other mode.
        let ingress = record.policy.ingress.clone();
        Ok(session_host::SandboxLauncher {
            ctx: self
                .context(true)
                .await
                .map_err(AttachError::ContextCreationFailed)?,
            attach_env,
            network_mode,
            net_switch: Arc::clone(&self.net_switch),
            ingress,
            composition: self.composition(),
            // A weak handle so in-sandbox `min build` can drive session
            // side-ops without keeping the actor alive past teardown.
            session: session.downgrade(),
        })
    }

    /// Under test, swap in a mock launcher that runs a plain host process wired
    /// to the pty, exercising the session-host runtime without building a real
    /// sandbox (which needs packages unavailable in the unit-test tempdir).
    #[cfg(test)]
    async fn session_launcher(
        &mut self,
        _session: SessionHandle,
        record: &Record,
        _attach_env: session_host::AttachEnv,
    ) -> Result<session_host::MockLauncher, AttachError> {
        // Mirror the production R2.1 gate so test launches reject a
        // policy/network-mode mismatch the same way production does.
        record
            .validate_policy()
            .map_err(AttachError::InvalidPolicy)?;
        Ok(session_host::MockLauncher)
    }

    /// Return this session's workspace-rooted [`mctx::Context`].
    ///
    /// This is NOT cached to enable session execution to change as the
    /// `minimal.toml` file changes.
    ///
    /// Gated on the same lifecycle status as [`Session::attach`]:
    /// the on-disk record must be `Active`. `SessionInner::Active`
    /// alone doesn't distinguish `Materializing` (composition done,
    /// patches not yet uploaded and not yet materialized into the
    /// sandbox home) from `Active` (fully ready). Building a
    /// context and running a task against a `Materializing`
    /// session would execute against an unpopulated home dir —
    /// the exact lifecycle escape the `Materializing` state was
    /// added to prevent.
    async fn context(&mut self, scaffold_if_missing: bool) -> Result<mctx::Context, String> {
        if matches!(&self.inner, SessionInner::Draft { .. }) {
            return Err("session is pending composition".to_string());
        }
        let record = self
            .record
            .record()
            .await
            .map_err(|e| format!("reading session record: {e}"))?;
        if record.status != SessionStatus::Active {
            return Err(format!(
                "session isn't attachable yet (status is {:?}, need Active — \
                 finish the upload + FinalizeSession sequence first)",
                record.status,
            ));
        }

        let ctx = self.build_context(scaffold_if_missing).await?;
        Ok(ctx)
    }

    /// The mctx [`Config`] rooted at this session's workspace, shared by the
    /// scaffold and context-construction paths so both see one session.
    ///
    /// [`Config`]: mctx::Config
    fn workspace_config(&self, wsp: &DaemonAbsPath) -> Result<mctx::Config, String> {
        ConfigBuilder::new()
            .with_repo_dir(wsp.as_utf8_path())
            .with_cache_dir(self.minimal_cache_dir.as_utf8_path())
            .with_state_dir(self.minimal_state_dir.as_utf8_path())
            // Every context this session builds reports into its operation tree.
            // The host-mint path renders that tree onto the SSH channel; the
            // task-exec path (via `MakeContext`) also feeds it, so task builds
            // surface on the same tracker even though only a mint renders it.
            .with_operation_tracker(self.tracker.clone())
            .with_daemon_id(self.daemon_ctx.daemon_id().unwrap()) // always set under minimald
            .build()
            .map_err(|e| mctx::Error::from(e).to_string())
    }

    /// TEMPORARY: write a default shell-stack `minimal.toml` into the
    /// session's workspace if it has none, so [`mctx::Context::new`] can
    /// succeed and the session gets a usable set of packages. A workspace
    /// that already holds an uploaded `minimal.toml` is left alone.
    fn scaffold_mfile_if_missing(&self, wsp: &DaemonAbsPath) -> Result<(), String> {
        if wsp.as_utf8_path().join(mfile::MFILE_NAME).exists() {
            return Ok(());
        }
        match mfile::File::from_dir(wsp.as_utf8_path()) {
            Ok(_) => Ok(()), // it exists
            Err(mfile::Error::NotFound) => {
                let config = self.workspace_config(wsp)?;

                use op::ProjectOp as _;
                let mut env = mctx::ProjectSetup::for_init(config).map_err(|e| e.to_string())?;
                let plan = op::InitProject.run(&mut env).map_err(|e| e.to_string())?;

                std::fs::write(&plan.toml_path, &plan.content).map_err(|e| e.to_string())
            }
            Err(e) => Err(e.to_string()),
        }
    }

    /// Do the actual context construction: run [`mctx::Context::new`] against
    /// a session-rooted [`Config`]. Called at most once per actor lifetime by
    /// [`Self::context`].
    ///
    /// The workspace mfile it parses is either the client's uploaded one or
    /// a default scaffolded here on the way past.
    ///
    /// [`Config`]: mctx::Config
    async fn build_context(&self, scaffold_if_missing: bool) -> Result<mctx::Context, String> {
        let wsp = self.record.object().await.unwrap().workspace_path();
        if scaffold_if_missing {
            self.scaffold_mfile_if_missing(&wsp)?;
        }
        mctx::Context::new(self.workspace_config(&wsp)?).map_err(|e| e.to_string())
    }

    async fn paths(&self) -> SessionPaths {
        let obj = self.record.object().await.unwrap();

        SessionPaths {
            working: obj.workspace_path(),
            cache: obj.cache_path(),
            home: obj.home_path(),
            patches: obj.patches_path(),
        }
    }
}

/// The handle to the session.
#[derive(Debug, Clone)]
pub struct SessionHandle(mpsc::Sender<SessionMessage>);

impl SessionHandle {
    /// Returns a non-owning handle to this session.
    #[must_use]
    pub fn downgrade(&self) -> WeakSessionHandle {
        WeakSessionHandle(self.0.downgrade())
    }

    /// Handle to the per-session patches-upload lock, owned by the session
    /// actor.
    ///
    /// Workspace patches are accumulated in a fixed per-session directory,
    /// so this lock is used to serialize `WorkspacePatchesTarZst` RPCs so
    /// they dont race and stomp each other.
    pub async fn patches_upload_lock(&self) -> Result<Arc<Mutex<()>>, std::io::Error> {
        let (send, recv) = oneshot::channel();
        // Ignore send errors - the recv will also fail.
        let _ = self
            .0
            .send(SessionMessage::GetPatchesUploadLock(send))
            .await;
        recv.await.map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::NotConnected, "session actor is gone")
        })
    }

    /// Kicks off a background package build as a session side-op, returning the
    /// receiver end of the build's event stream. Events flow until the build
    /// finishes (success or cancellation), at which point the channel closes.
    /// A `Draft` session is refused with `InvalidInput`; a dead actor maps to
    /// `NotConnected`.
    pub async fn start_build(
        &self,
        rebuild: bool,
        pkgs: Vec<String>,
    ) -> Result<mpsc::Receiver<BuildUpdate>, std::io::Error> {
        let (reply, recv) = oneshot::channel();
        // Ignore send errors - the recv will also fail.
        let _ = self
            .0
            .send(SessionMessage::StartBuild {
                rebuild,
                pkgs,
                reply,
            })
            .await;
        recv.await.map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::NotConnected, "session actor is gone")
        })?
    }

    /// Kicks off a background check run as a session side-op, returning the
    /// receiver end of the run's result stream. Results flow until the run
    /// finishes (completion, failure, or cancellation), at which point the
    /// channel closes. A `Draft` session is refused with `InvalidInput`; a dead
    /// actor maps to `NotConnected`.
    pub(crate) async fn start_check(
        &self,
        opts: CheckOpts,
    ) -> Result<mpsc::Receiver<CheckUpdate>, std::io::Error> {
        let (reply, recv) = oneshot::channel();
        // Ignore send errors - the recv will also fail.
        let _ = self
            .0
            .send(SessionMessage::StartCheck { opts, reply })
            .await;
        recv.await.map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::NotConnected, "session actor is gone")
        })?
    }

    /// Kicks off a background materialize run as a session side-op, returning
    /// the receiver end of the run's stream. An unknown output name is refused
    /// with `NotFound`; a `Draft` session with `InvalidInput`; a dead actor
    /// maps to `NotConnected`.
    pub async fn start_materialize(
        &self,
        opts: MaterializeOpts,
    ) -> Result<mpsc::Receiver<MaterializeUpdate>, std::io::Error> {
        let (reply, recv) = oneshot::channel();
        // Ignore send errors - the recv will also fail.
        let _ = self
            .0
            .send(SessionMessage::StartMaterialize { opts, reply })
            .await;
        recv.await.map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::NotConnected, "session actor is gone")
        })?
    }

    /// Returns paths on the daemon backing various internals of the session.
    /// A dead actor (self-terminated abort/failed-verdict/create-failure, or
    /// mid-teardown) maps to `NotConnected` — callers race actor death.
    pub async fn paths(&self) -> Result<SessionPaths, std::io::Error> {
        let (send, recv) = oneshot::channel();
        // Ignore send errors - the recv will also fail.
        let _ = self.0.send(SessionMessage::GetPaths(send)).await;
        recv.await.map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::NotConnected, "session actor is gone")
        })
    }
    /// Returns the host attributes of the running session, if any. A dead
    /// actor (self-terminated or mid-teardown) reads as `None` rather than a
    /// panic — the manager polls this while actors come and go.
    pub async fn get_attrs(&self) -> Option<HostAttrs> {
        let (send, recv) = oneshot::channel();
        // Ignore send errors - the recv will also fail.
        let _ = self.0.send(SessionMessage::GetHostAttrs(send)).await;
        recv.await.ok().flatten()
    }

    /// Returns a minimal context initialized on this sessions' worktree.
    pub async fn context(&self) -> Result<mctx::Context, String> {
        let (send, recv) = oneshot::channel();
        // Ignore send errors - the recv will also fail.
        let _ = self.0.send(SessionMessage::MakeContext(send)).await;
        recv.await
            .unwrap_or_else(|_| Err("session actor is gone".to_string()))
    }

    /// Returns the session record currently held by the live session actor
    /// (the in-memory copy, not the on-disk record). Used by the task-exec path
    /// to read the session's network mode, and by tests to assert propagation.
    /// A dead actor maps to `NotConnected`.
    pub(crate) async fn record(&self) -> Result<Record, std::io::Error> {
        let (send, recv) = oneshot::channel();
        // Ignore send errors - the recv will also fail.
        let _ = self.0.send(SessionMessage::GetRecord(send)).await;
        recv.await.map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::NotConnected, "session actor is gone")
        })
    }

    /// Configure the session's loadout from the client's wire contribution:
    /// `Ok(None)` means the composition finalized and the session is now
    /// `Active`; `Ok(Some(response))` means the client must gate the returned
    /// items and come back with a verdict. `AlreadyExists` if the loadout is
    /// already configured; a dead actor maps to `NotConnected`.
    pub(crate) async fn configure_loadout(
        &self,
        contribution: WireContribution,
    ) -> Result<Option<ContributionResponse>, std::io::Error> {
        let (send, recv) = oneshot::channel();
        // Ignore send errors - the recv will also fail.
        let _ = self
            .0
            .send(SessionMessage::ConfigureLoadout(contribution, send))
            .await;
        recv.await.unwrap_or_else(|_| {
            Err(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "session actor is gone",
            ))
        })
    }

    /// Submit the client's contribution verdict against a `Draft` session.
    /// On success the actor promotes its record from `Pending` to
    /// `Materializing` and replies with [`SessionStep::Materialized`]; the
    /// client still has to upload patches and call `FinalizeSession`
    /// before the session becomes attachable. Structured failures
    /// (wrong state, an unresumable verdict) come back as
    /// [`SessionStep::Fault`]. A dead actor maps to `NotConnected`
    /// (the caller reads it as unknown-session).
    pub(crate) async fn submit_verdict(
        &self,
        verdict: ContributionVerdict,
    ) -> Result<SessionStep, std::io::Error> {
        let (send, recv) = oneshot::channel();
        // Ignore send errors - the recv will also fail.
        let _ = self
            .0
            .send(SessionMessage::SubmitVerdict(Box::new((verdict, send))))
            .await;
        recv.await.unwrap_or_else(|_| {
            Err(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "session actor is gone",
            ))
        })
    }

    /// Promote a `Materializing` session to `Active`, gating on the
    /// patches-ready marker having been written by a completed
    /// `WorkspacePatchesTarZst` upload. Idempotent on already-Active
    /// sessions. See [`Session::finalize`] for the state-machine
    /// contract.
    pub(crate) async fn finalize(&self) -> Result<(), std::io::Error> {
        let (send, recv) = oneshot::channel();
        // Ignore send errors - the recv will also fail.
        let _ = self.0.send(SessionMessage::Finalize(send)).await;
        recv.await.unwrap_or_else(|_| {
            Err(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "session actor is gone",
            ))
        })
    }

    /// Abort a `Draft` session: the actor deletes its on-disk record and
    /// stops. `InvalidInput` if the session is `Active` (use destroy);
    /// a dead actor maps to `NotConnected`.
    pub(crate) async fn abort(&self) -> Result<(), std::io::Error> {
        let (send, recv) = oneshot::channel();
        // Ignore send errors - the recv will also fail.
        let _ = self.0.send(SessionMessage::Abort(send)).await;
        recv.await.unwrap_or_else(|_| {
            Err(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "session actor is gone",
            ))
        })
    }

    /// Whether this session blocks an unforced daemon shutdown: awaiting a
    /// contribution verdict mid create flow, or hosting a live shell. A dead
    /// actor is not busy.
    pub(crate) async fn is_busy(&self) -> bool {
        let (send, recv) = oneshot::channel();
        // Ignore send errors - the recv will also fail.
        let _ = self.0.send(SessionMessage::IsBusy(send)).await;
        recv.await.unwrap_or(false)
    }

    /// Test-only peek at the actor's held [`Composition`]. Bumps the
    /// refcount rather than moving it, so the caller can assert on contents
    /// without disturbing the lifecycle.
    #[cfg(test)]
    pub(crate) async fn peek_composition(&self) -> Option<Arc<Composition>> {
        let (send, recv) = oneshot::channel();
        let _ = self.0.send(SessionMessage::PeekComposition(send)).await;
        recv.await.ok().flatten()
    }

    /// Renames the session: the actor persists the new name through its
    /// record handle (name collision → `AlreadyExists`) and relinks its PTask
    /// hostname. A dead actor maps to `NotConnected`.
    pub(crate) async fn rename(&self, new_name: String) -> Result<(), std::io::Error> {
        let (send, recv) = oneshot::channel();
        // Ignore send errors - the recv will also fail.
        let _ = self.0.send(SessionMessage::Rename(new_name, send)).await;
        recv.await.unwrap_or_else(|_| {
            Err(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "session actor is gone",
            ))
        })
    }

    /// Shutdown-stop: kills the host (if any), withdraws the hostname, and
    /// stops the actor — the on-disk record is kept. A dead actor is already
    /// stopped, so send/recv failures read as success.
    pub(crate) async fn stop(&self) {
        let (send, recv) = oneshot::channel();
        // Ignore send errors - the recv will also fail.
        let _ = self.0.send(SessionMessage::Stop(send)).await;
        // If the actor died before acking, it is stopped all the same.
        let _ = recv.await;
    }

    /// Tears down the session: kills its host (if any), waits for teardown,
    /// deletes the on-disk record, and stops the actor. The handle is dead
    /// once this returns. A dead actor reads as `Ok` — whatever terminated it
    /// already ran its teardown.
    pub(crate) async fn destroy(&self) -> Result<(), std::io::Error> {
        let (send, recv) = oneshot::channel();
        // Ignore send errors - the recv will also fail.
        let _ = self.0.send(SessionMessage::Destroy(send)).await;
        recv.await.unwrap_or(Ok(()))
    }

    pub async fn attach(
        &self,
        conn_username: String,
        channel: Channel<Msg>,
        config: ChannelConfig,
    ) -> Result<(), AttachError> {
        let (send, recv) = oneshot::channel();
        // Ignore send errors - the recv will also fail.
        let _ = self
            .0
            .send(SessionMessage::Attach(
                send,
                self.clone(),
                conn_username,
                channel,
                config,
            ))
            .await;
        // A dead session actor (it panicked or was dropped mid-attach) drops the
        // reply sender. Surface that as an attach error rather than panicking the
        // daemon worker — the SSH layer reports it to the client and closes.
        match recv.await {
            Ok(result) => result,
            Err(_) => Err(AttachError::SpawnFailed(std::io::Error::other(
                "session actor terminated before the attach completed",
            ))),
        }
    }
}

/// A non-owning handle to the [`Session`] actor.
#[derive(Debug, Clone)]
pub struct WeakSessionHandle(WeakSender<SessionMessage>);

impl WeakSessionHandle {
    /// Promotes to a strong [`SessionHandle`], or `None` if the session actor
    /// has already shut down (all strong senders dropped).
    #[must_use]
    pub fn upgrade(&self) -> Option<SessionHandle> {
        Some(SessionHandle(self.0.upgrade()?))
    }

    /// A dangling handle whose actor is already gone (`upgrade` always yields
    /// `None`). Test-only: lets fixtures that never exercise the session
    /// round-trip satisfy an `EnvArgs`/`SessionChannel` that now requires a
    /// handle, without standing up a live actor.
    #[cfg(test)]
    pub(crate) fn dangling() -> Self {
        let (tx, _rx) = mpsc::channel::<SessionMessage>(1);
        let weak = tx.downgrade();
        // Drop the only strong sender so `upgrade()` returns `None`.
        drop(tx);
        Self(weak)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use russh::ChannelMsg;
    use sessions::SessionId;

    use minimald_rpc::{GetSessionRecord, GetSessionRecordRequest};

    use crate::test_harness::{TestClient, TestServer, create_configured_session};

    /// The `AcceptEnv` allowlist keeps locale + timezone vars and drops
    /// everything else — critically the control-plane vars, which must never
    /// reach the shell environment.
    #[test]
    fn inherited_session_env_keeps_only_locale_and_tz() {
        let env: std::collections::BTreeMap<String, String> = [
            ("LANG", "en_US.UTF-8"),
            ("LC_CTYPE", "en_US.UTF-8"),
            ("LC_ALL", "C"),
            ("TZ", "America/New_York"),
            ("MINIMAL_SESSION_ID", "00000000-0000-0000-0000-000000000000"),
            ("TRACEPARENT", "00-abc-def-01"),
            ("PATH", "/evil/bin"),
            ("PS1", "# "),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();

        let kept: std::collections::BTreeMap<String, String> =
            super::inherited_session_env(&env).into_iter().collect();

        assert_eq!(kept.get("LANG").map(String::as_str), Some("en_US.UTF-8"));
        assert_eq!(
            kept.get("LC_CTYPE").map(String::as_str),
            Some("en_US.UTF-8")
        );
        assert_eq!(kept.get("LC_ALL").map(String::as_str), Some("C"));
        assert_eq!(kept.get("TZ").map(String::as_str), Some("America/New_York"));
        // Control-plane routing/tracing vars and everything else must be dropped.
        assert!(!kept.contains_key("MINIMAL_SESSION_ID"));
        assert!(!kept.contains_key("TRACEPARENT"));
        assert!(!kept.contains_key("PATH"));
        assert!(!kept.contains_key("PS1"));
        assert_eq!(kept.len(), 4, "only LANG, LC_*, and TZ should survive");
    }

    /// A `LC_`-*prefixed* var is accepted, but a bare `LC` (or one that merely
    /// contains `LC_`) is not — the filter is a prefix match, not a substring.
    #[test]
    fn inherited_session_env_prefix_not_substring() {
        let env: std::collections::BTreeMap<String, String> = [
            ("LC_MESSAGES", "C"),
            ("LC", "nope"),
            ("MYLC_VAR", "nope"),
            ("XLANG", "nope"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();

        let kept: std::collections::BTreeMap<String, String> =
            super::inherited_session_env(&env).into_iter().collect();

        assert_eq!(
            kept.keys().cloned().collect::<Vec<_>>(),
            vec!["LC_MESSAGES"]
        );
    }

    /// Reads the session record for `id`, or `None` once it has been deleted.
    async fn record_exists(client: &mut TestClient, id: SessionId) -> bool {
        client
            .call::<GetSessionRecord>(&GetSessionRecordRequest::Id(id))
            .await
            .record
            .is_some()
    }

    /// Creates a fresh, configured session on the server and returns its id.
    async fn create_session(client: &mut TestClient) -> SessionId {
        create_configured_session(client, "shell-test", "/uwu").await
    }

    /// Attaching to a session whose loadout was never configured must not
    /// blow up: nothing is in flight on a bare `Draft`, so the attach
    /// configures it with an empty contribution on the way in and mints the
    /// shell as usual. Guards the `min session activate` → `min session attach` path against
    /// a caller that never reached the compose step (a compose failure
    /// leaves the actor `Draft` — attach has to still land it live), and
    /// any internal caller that only ever wanted a session to run something
    /// in.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn attach_to_an_unconfigured_session_configures_it_rather_than_failing() {
        use crate::test_harness::create_session_req;
        use minimald_rpc::CreateSession;

        let server = TestServer::new().await;
        let mut client = server.connect().await;
        // Bare `CreateSession` — no `ConfigureLoadout` follow-up. The
        // session stays `Draft`; the attach path is the one that has
        // to notice and configure it on the way in.
        let session_id = client
            .call::<CreateSession>(&create_session_req("bare-session", "/uwu"))
            .await
            .unwrap()
            .id;

        let mut channel = client.open_shell(session_id).await;
        channel.data_bytes(b"hello\n".to_vec()).await.unwrap();
        let mut stdout = Vec::new();
        loop {
            match channel.wait().await {
                Some(ChannelMsg::Data { data }) => {
                    stdout.extend_from_slice(&data);
                    if String::from_utf8_lossy(&stdout).contains("got:hello") {
                        break;
                    }
                }
                Some(_) => {}
                None => {
                    let stdout = String::from_utf8_lossy(&stdout);
                    panic!(
                        "attaching to an unconfigured session should mint a shell; got: {stdout:?}"
                    );
                }
            }
        }

        // The attach finalized the session on its way in.
        assert_eq!(
            server
                .state
                .sessions_manager()
                .await
                .get_record(crate::sessions::SessionKeyPredicate::Id(session_id))
                .await
                .unwrap()
                .expect("the record should exist")
                .status,
            sessions::SessionStatus::Active,
        );
    }

    /// Drives the full SSH path into the session host with the mock launcher:
    /// create a session, request a pty + shell, feed stdin, observe the echoed
    /// stdout, then confirm the host tears down when the process exits.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn shell_round_trips_stdin_to_stdout_then_tears_down() {
        let server = TestServer::new().await;
        let mut client = server.connect().await;
        let session_id = create_session(&mut client).await;

        let mut channel = client.open_shell(session_id).await;

        // Echo round trip: the mock echoes each line back as `got:<line>`.
        // Read until we observe the echo, proving the stdin -> program ->
        // stdout path works while the process is still alive.
        channel.data_bytes(b"hello\n".to_vec()).await.unwrap();
        let mut stdout = Vec::new();
        loop {
            match channel.wait().await {
                Some(ChannelMsg::Data { data }) => {
                    stdout.extend_from_slice(&data);
                    if String::from_utf8_lossy(&stdout).contains("got:hello") {
                        break;
                    }
                }
                Some(_) => {}
                None => {
                    let stdout = String::from_utf8_lossy(&stdout);
                    panic!("channel closed before the echo arrived; stdout: {stdout:?}");
                }
            }
        }

        // Now ask the mock to exit. The shell exiting raises the session-exit
        // prompt (see `session_host`), rendered over the channel; answer it by
        // confirming the first option (Enter -> detach) so teardown proceeds and
        // the channel closes.
        channel
            .data_bytes(format!("{}\n", crate::session_host::MOCK_EXIT_LINE).into_bytes())
            .await
            .unwrap();
        let mut saw_exit_status = false;
        let mut closed = false;
        let mut answered_prompt = false;
        let mut prompt_out = Vec::new();
        while let Ok(msg) = tokio::time::timeout(Duration::from_secs(10), channel.wait()).await {
            match msg {
                Some(ChannelMsg::Data { data }) => {
                    // Wait for the prompt to render, then confirm the first
                    // option. The prompt only appears once the mainloop has
                    // stopped reading the channel, so this keypress reaches the
                    // prompt rather than the (now-defunct) stdin path.
                    prompt_out.extend_from_slice(&data);
                    if !answered_prompt
                        && String::from_utf8_lossy(&prompt_out)
                            .contains(crate::session_host::SHELL_EXIT_PROMPT)
                    {
                        channel.data_bytes(b"\r".to_vec()).await.unwrap();
                        answered_prompt = true;
                    }
                }
                Some(ChannelMsg::ExitStatus { .. }) => saw_exit_status = true,
                Some(_) => {}
                None => {
                    closed = true;
                    break;
                }
            }
        }
        assert!(
            answered_prompt,
            "expected the session-exit prompt to render"
        );
        assert!(closed, "channel should close once the mock process exits");
        assert!(saw_exit_status, "expected an exit status on teardown");

        // Detach leaves the session alive: its record must still resolve.
        assert!(
            record_exists(&mut client, session_id).await,
            "detach must not delete the session record"
        );
    }

    /// The shell-exit prompt leads with the files changed since activation:
    /// write a file into the session's workspace while the shell is live, then
    /// exit it and expect the delta header and the changed-file row above the
    /// prompt. Answered with the default (keep), so the session survives.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn shell_exit_prompt_lists_files_changed_since_activation() {
        let server = TestServer::new().await;
        let mut client = server.connect().await;
        let session_id = create_session(&mut client).await;

        let mut channel = client.open_shell(session_id).await;

        // Prove the shell is live first (mock echoes `got:<line>`); the
        // baseline snapshot is taken before the process launches, so a write
        // from here on is a change.
        channel.data_bytes(b"hello\n".to_vec()).await.unwrap();
        let mut stdout = Vec::new();
        loop {
            match channel.wait().await {
                Some(ChannelMsg::Data { data }) => {
                    stdout.extend_from_slice(&data);
                    if String::from_utf8_lossy(&stdout).contains("got:hello") {
                        break;
                    }
                }
                Some(_) => {}
                None => panic!("channel closed before the echo arrived"),
            }
        }

        // Change the workspace daemon-side, as an in-session shell would.
        let manager = server.state.sessions_manager().await;
        let handle = manager
            .get_session(crate::sessions::SessionKeyPredicate::Id(session_id))
            .await
            .unwrap()
            .expect("session should resolve");
        let paths = handle.paths().await.expect("paths should resolve");
        let scratch = paths
            .working
            .join(&paths::DaemonRelPath::try_new("scratch.txt").unwrap());
        tokio::fs::write(scratch.as_utf8_path(), b"made in session")
            .await
            .unwrap();

        // Exit the shell; the prompt must lead with the delta.
        channel
            .data_bytes(format!("{}\n", crate::session_host::MOCK_EXIT_LINE).into_bytes())
            .await
            .unwrap();
        let mut answered_prompt = false;
        let mut prompt_out = Vec::new();
        while let Ok(msg) = tokio::time::timeout(Duration::from_secs(10), channel.wait()).await {
            match msg {
                Some(ChannelMsg::Data { data }) => {
                    prompt_out.extend_from_slice(&data);
                    if !answered_prompt
                        && String::from_utf8_lossy(&prompt_out)
                            .contains(crate::session_host::SHELL_EXIT_PROMPT)
                    {
                        channel.data_bytes(b"\r".to_vec()).await.unwrap();
                        answered_prompt = true;
                    }
                }
                Some(_) => {}
                None => break,
            }
        }
        let prompt_out = String::from_utf8_lossy(&prompt_out);
        assert!(
            answered_prompt,
            "expected the session-exit prompt to render; got: {prompt_out:?}"
        );
        assert!(
            prompt_out.contains("changed since activation:"),
            "prompt should lead with the delta header; got: {prompt_out:?}"
        );
        assert!(
            prompt_out.contains("A scratch.txt"),
            "prompt should list the added file; got: {prompt_out:?}"
        );

        // Keep (the default) must leave the session intact.
        assert!(
            record_exists(&mut client, session_id).await,
            "keep must not delete the session record"
        );
    }

    /// Selecting "delete" on the shell-exit prompt must tear the connection down
    /// *and* destroy the session (record removed), routed through the manager
    /// via the binding's weak handle.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn terminate_option_deletes_session_and_closes_channel() {
        let server = TestServer::new().await;
        let mut client = server.connect().await;
        let session_id = create_session(&mut client).await;

        let mut channel = client.open_shell(session_id).await;

        // Confirm the shell is live before exiting it (mock echoes `got:<line>`).
        channel.data_bytes(b"hello\n".to_vec()).await.unwrap();
        let mut stdout = Vec::new();
        loop {
            match channel.wait().await {
                Some(ChannelMsg::Data { data }) => {
                    stdout.extend_from_slice(&data);
                    if String::from_utf8_lossy(&stdout).contains("got:hello") {
                        break;
                    }
                }
                Some(_) => {}
                None => panic!("channel closed before the echo arrived"),
            }
        }

        // Exit the shell to raise the prompt, then pick the second option
        // (delete): a down-arrow to move off the default, then Enter.
        channel
            .data_bytes(format!("{}\n", crate::session_host::MOCK_EXIT_LINE).into_bytes())
            .await
            .unwrap();
        let mut closed = false;
        let mut answered_prompt = false;
        let mut prompt_out = Vec::new();
        while let Ok(msg) = tokio::time::timeout(Duration::from_secs(10), channel.wait()).await {
            match msg {
                Some(ChannelMsg::Data { data }) => {
                    prompt_out.extend_from_slice(&data);
                    if !answered_prompt
                        && String::from_utf8_lossy(&prompt_out)
                            .contains(crate::session_host::SHELL_EXIT_PROMPT)
                    {
                        channel.data_bytes(b"\x1b[B\r".to_vec()).await.unwrap();
                        answered_prompt = true;
                    }
                }
                Some(_) => {}
                None => {
                    closed = true;
                    break;
                }
            }
        }

        // Requirement 1: the connection is torn down.
        assert!(
            answered_prompt,
            "expected the session-exit prompt to render"
        );
        assert!(closed, "channel should close after the delete completes");

        // Requirement 2: the session is gone. The binding awaits the destroy
        // before closing the channel, so the record is already removed by the
        // time we observe the close.
        assert!(
            !record_exists(&mut client, session_id).await,
            "delete must remove the session record"
        );
    }

    /// A second shell request to the same session takes over the running host:
    /// the new channel is flushed the current terminal state (so it sees the
    /// earlier `hello` output), and the original channel is disconnected.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn second_shell_takes_over_session_and_closes_the_first() {
        let server = TestServer::new().await;
        let mut client = server.connect().await;
        let session_id = create_session(&mut client).await;

        // First attachment: drive an echo so the host's terminal state holds
        // `got:hello`, confirming it before we take the session over.
        let mut first = client.open_shell(session_id).await;
        first.data_bytes(b"hello\n".to_vec()).await.unwrap();
        let mut first_out = Vec::new();
        loop {
            match first.wait().await {
                Some(ChannelMsg::Data { data }) => {
                    first_out.extend_from_slice(&data);
                    if String::from_utf8_lossy(&first_out).contains("got:hello") {
                        break;
                    }
                }
                Some(_) => {}
                None => {
                    let first_out = String::from_utf8_lossy(&first_out);
                    panic!("first channel closed before the echo arrived; got: {first_out:?}");
                }
            }
        }

        // Second attachment to the same session takes over.
        let mut second = client.open_shell(session_id).await;

        // The takeover flushes the current terminal state to the new channel,
        // so the earlier `got:hello` shows up in what it's sent on attach. The
        // session stays live (no teardown), so read with a timeout rather than
        // draining to close.
        let mut flushed = Vec::new();
        while let Ok(Some(msg)) = tokio::time::timeout(Duration::from_secs(5), second.wait()).await
        {
            if let ChannelMsg::Data { data } = msg {
                flushed.extend_from_slice(&data);
                if String::from_utf8_lossy(&flushed).contains("got:hello") {
                    break;
                }
            }
        }
        let flushed = String::from_utf8_lossy(&flushed);
        assert!(
            flushed.contains("got:hello"),
            "takeover should flush prior terminal state to the new channel, got: {flushed:?}",
        );

        // The original channel should have been disconnected by the takeover.
        let mut first_closed = false;
        while let Ok(msg) = tokio::time::timeout(Duration::from_secs(5), first.wait()).await {
            if msg.is_none() {
                first_closed = true;
                break;
            }
        }
        assert!(
            first_closed,
            "first channel should be closed once the session is taken over",
        );
    }

    /// The ctrl-w detach chord (a single `0x17` byte) detaches the current
    /// channel — sending a detach notice down it before it closes — without
    /// tearing the session down, so a later channel resumes it (the earlier
    /// `got:hello` is flushed on reattach).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ctrl_w_detaches_channel_then_session_resumes_on_reattach() {
        let server = TestServer::new().await;
        let mut client = server.connect().await;
        let session_id = create_session(&mut client).await;

        // First attachment: drive an echo so the terminal state holds
        // `got:hello` before we detach.
        let mut first = client.open_shell(session_id).await;
        first.data_bytes(b"hello\n".to_vec()).await.unwrap();
        let mut first_out = Vec::new();
        loop {
            match first.wait().await {
                Some(ChannelMsg::Data { data }) => {
                    first_out.extend_from_slice(&data);
                    if String::from_utf8_lossy(&first_out).contains("got:hello") {
                        break;
                    }
                }
                Some(_) => {}
                None => {
                    let first_out = String::from_utf8_lossy(&first_out);
                    panic!("first channel closed before the echo arrived; got: {first_out:?}");
                }
            }
        }

        // Send the detach chord. The host writes a detach notice down the
        // channel and then closes it.
        first.data_bytes(vec![0x17]).await.unwrap();
        let mut detach_out = Vec::new();
        let mut first_closed = false;
        while let Ok(msg) = tokio::time::timeout(Duration::from_secs(5), first.wait()).await {
            match msg {
                Some(ChannelMsg::Data { data }) => detach_out.extend_from_slice(&data),
                Some(_) => {}
                None => {
                    first_closed = true;
                    break;
                }
            }
        }
        let detach_out = String::from_utf8_lossy(&detach_out);
        assert!(
            detach_out.contains("Detaching due to ctrl-w."),
            "expected a detach notice on the channel before it closed, got: {detach_out:?}",
        );
        assert!(first_closed, "channel should close after the detach chord");

        // Reattach: a second channel resumes the same (still-live) session, so
        // the earlier `got:hello` is flushed to it on connect.
        let mut second = client.open_shell(session_id).await;
        let mut flushed = Vec::new();
        while let Ok(Some(msg)) = tokio::time::timeout(Duration::from_secs(5), second.wait()).await
        {
            if let ChannelMsg::Data { data } = msg {
                flushed.extend_from_slice(&data);
                if String::from_utf8_lossy(&flushed).contains("got:hello") {
                    break;
                }
            }
        }
        let flushed = String::from_utf8_lossy(&flushed);
        assert!(
            flushed.contains("got:hello"),
            "reattaching should flush prior terminal state, got: {flushed:?}",
        );
    }

    /// A session's composition persists across a daemon restart: the
    /// sidecar written at composition-assembly time is read back when
    /// the actor is respawned from disk, so the launcher sees the same
    /// packages and vars instead of falling back to the baseline set.
    /// This is the core fix for issue #849 — "session composition state
    /// is in-memory only: daemon restart drops loadout packages/vars
    /// for existing sessions."
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn composition_survives_actor_restart() {
        let server = TestServer::new().await;
        let mut client = server.connect().await;
        let session_id = create_session(&mut client).await;

        // The actor was spawned during `create_configured_session`
        // and holds the composition in memory. Verify it's present.
        let manager = server.state.sessions_manager().await;
        let handle = manager
            .get_session(crate::sessions::SessionKeyPredicate::Id(session_id))
            .await
            .unwrap()
            .expect("session should resolve while actor is running");
        assert!(
            handle.peek_composition().await.is_some(),
            "freshly configured session should hold its composition in memory"
        );

        // Stop the actor and evict it from the running map so the
        // next `get_session` spawns a fresh actor from the on-disk
        // record — simulating a daemon restart.
        handle.stop().await;
        manager.evict(session_id).await;

        // Re-resolve: spawns a new actor from disk. The composition
        // should be restored from the sidecar, not None.
        let handle = manager
            .get_session(crate::sessions::SessionKeyPredicate::Id(session_id))
            .await
            .unwrap()
            .expect("session should resolve after eviction");
        assert!(
            handle.peek_composition().await.is_some(),
            "re-spawned session should have its composition restored from \
             the sidecar, not fall back to baseline"
        );
    }

    /// When the sidecar is missing (e.g. a session that predated the
    /// sidecar, or a corrupt filesystem), the actor still spawns — but
    /// with no composition, so the launcher falls back to its baseline
    /// set. The operator sees a warning log rather than a silent drop.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn missing_sidecar_falls_back_to_baseline() {
        let server = TestServer::new().await;
        let mut client = server.connect().await;
        let session_id = create_session(&mut client).await;

        let manager = server.state.sessions_manager().await;
        let handle = manager
            .get_session(crate::sessions::SessionKeyPredicate::Id(session_id))
            .await
            .unwrap()
            .expect("session should resolve");

        // Delete the sidecar to simulate a pre-sidecar session or a
        // corrupt filesystem. The composition sidecar lives at
        // `<session-root>/composition.json`, a sibling of `record.json`;
        // derive it from the workspace path (`<root>/tree`).
        let paths = handle.paths().await.expect("paths should resolve");
        let composition_file = paths
            .working
            .parent()
            .expect("workspace path has a parent")
            .join(&paths::DaemonRelPath::try_new("composition.json").unwrap());
        tokio::fs::remove_file(composition_file.as_utf8_path())
            .await
            .expect("sidecar should exist to delete");

        handle.stop().await;
        manager.evict(session_id).await;

        // Re-resolve: spawns from disk with no sidecar. The
        // composition should be None — loud fallback to baseline.
        let handle = manager
            .get_session(crate::sessions::SessionKeyPredicate::Id(session_id))
            .await
            .unwrap()
            .expect("session should resolve after eviction");
        assert!(
            handle.peek_composition().await.is_none(),
            "session with a missing sidecar should fall back to baseline \
             (composition None), not hold a stale composition"
        );
    }
}
