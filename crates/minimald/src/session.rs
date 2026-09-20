use crate::channel_progress::ChannelProgress;
use crate::session_sop::{
    BuildUpdate, CheckOpts, CheckUpdate, MaterializeOpts, MaterializeUpdate, SideOp,
};

use crate::sessions::{SessionControl, WeakManagerHandle, composables};
use crate::store::SessionRecordHandle;
use crate::{
    ChannelConfig,
    session_delta::{self, DeltaSource},
    session_host::{self, HostAttrs, WinSize},
};
use common::SpecHash;
use mctx::ConfigBuilder;
use ot::OpTracker;
use paths::DaemonAbsPath;
use russh::{Channel, server::Msg};
use sessions::keys::SessionKeys;
use sessions::wire::request::ContributionResponse;
use sessions::{
    Record, SessionStatus,
    core::compose::Composition,
    daemon::composer::{ComposeOutcome, PendingComposeState, resume_from_verdict},
    store::{DiskSession, SessionObject},
    wire::request::{ContributionVerdict, SessionStep, WireContribution},
};
use std::collections::HashSet;
use std::fmt::{self};
use std::ops::ControlFlow;
use std::sync::Arc;
#[cfg(target_os = "linux")]
use std::sync::RwLock;
use tokio::sync::mpsc::WeakSender;
use tokio::sync::{Mutex, mpsc, oneshot};
use tokio::task::JoinHandle;

mod helpers;

pub(crate) use helpers::*;

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
    /// Where the daemon stages client-uploaded external lifecycle-hook
    /// scripts (`WorkspaceHookScriptsTarZst` unpacks under this dir,
    /// keyed by the script's staged path). Like `patches`, it may not
    /// exist yet — a session whose hooks are all inline never uploads
    /// anything here.
    pub hooks: DaemonAbsPath,
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
    /// The host's published-box table, the zone the answerer serves; the
    /// actor publishes its box at finalize and withdraws it at destroy.
    #[cfg(target_os = "linux")]
    pub published: Arc<RwLock<crate::net::publish::PublishTable>>,
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
        host: Option<LaunchedHost>,
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

/// A launched host: its handle, paired with the `JoinHandle` of its runtime
/// loop so teardown can be awaited on destroy.
type LaunchedHost = (
    session_host::HostHandle,
    JoinHandle<Result<i32, std::io::Error>>,
);

/// Where in the session lifecycle a host launch is happening, which decides
/// whether the launch has to wait for an `Active` record.
///
/// Only [`Session::finalize`]'s launch is `Activating`. Every other
/// launch happens after the session is attachable and keeps the status gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LaunchPhase {
    /// A launch against a session that is already `Active`: an attach, or an
    /// exec's [`Session::ensure_host`]. Both check the record's status
    /// themselves before getting here; the gate in [`Session::context`] is
    /// their backstop.
    Attached,
    /// The pre-activation launch inside [`Session::finalize`]. It runs while
    /// the record is still `Materializing` by construction — promoting to
    /// `Active` is what finalize does *after* the activation hooks this host
    /// exists to run — so it cannot take the `Active` gate without
    /// deadlocking against itself.
    Activating,
}

/// How long *all* of a teardown transition's hooks get, together.
///
/// A hook's own timeout is capped at
/// [`MAX_HOOK_TIMEOUT`](sessions::core::lifecyclehook::MAX_HOOK_TIMEOUT)
/// to keep one from holding a session open, but nothing bounds how many
/// hooks a composition may carry — so without a total, N of them at the
/// cap would hold a destroy for N×5 minutes and defeat the point. This
/// is that total. Wide enough that an honest teardown never meets it;
/// the hooks are a courtesy, and the destroy is the contract.
const TEARDOWN_HOOK_BUDGET: std::time::Duration = std::time::Duration::from_secs(120);

/// How long a teardown transition will wait for the sandbox it needs to
/// run its hooks in.
///
/// Nothing else about a host launch is time-bounded, because every other
/// caller is a user waiting on their own attach. A teardown is not: the
/// hooks are a courtesy and the destroy is the contract, so the launch
/// gets a deadline and the session is torn down either way. Generous
/// enough to cover a cold cache on a loaded box — this is a backstop
/// against a wedge, not a performance budget.
const HOOK_LAUNCH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// This session's workspace baseline for the shell-exit prompt's change
/// detection, established once before the first host launches and reused
/// across every host teardown and rebuild. Re-arming the baseline at each
/// launch would re-snapshot an already-modified workspace when a "keep
/// filesystem" exit is followed by a reattach, so the next exit would detect
/// no changes and drop the save-then-delete option.
enum WorkspaceBaseline {
    /// No host has launched yet; the baseline is armed on the first launch.
    Unarmed,
    /// Armed once at first launch and reused for the session's lifetime. Holds
    /// the arm result verbatim — including the `None` of a walk that timed out
    /// — so a rebuild never re-snapshots against a dirty tree.
    Armed(Option<Arc<DeltaSource>>),
}

// Opaque so `Session`'s derived `Debug` need not dump the whole baseline
// snapshot: only whether the baseline is armed and present is informative.
impl fmt::Debug for WorkspaceBaseline {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unarmed => f.write_str("Unarmed"),
            Self::Armed(delta) => write!(f, "Armed(present: {})", delta.is_some()),
        }
    }
}

/// Deadline for a read-only probe of a session's host — the terminal
/// attributes and the screen snapshot.
///
/// Spawning those probes off the session actor (see
/// [`Session::handle_message`]) keeps the *actor* responsive, but says
/// nothing about the spawned task: against a host that never answers, an
/// unbounded probe outlives every caller that gave up on it. Nor does it
/// stay parked in the same place:
/// [`HOST_MAILBOX_CAPACITY`](crate::session_host::HOST_MAILBOX_CAPACITY)
/// messages in, a wedged host's mailbox is full and the probe blocks in
/// `send` rather than `recv` — still forever, and still one stranded task
/// per poll. `min dash` polls the focused session's screen on every refresh
/// tick, which makes that leak unbounded in the one case the bound exists
/// for.
///
/// So the probe is bounded here too, not only at its callers: a task that
/// cannot answer within the deadline ends, and the caller reads the same
/// `None` a session with no running host already reports.
///
/// [`crate::sessions::Manager`] bounds these probes again on its own
/// mainloop. That is not redundant — this deadline covers a wedged *host*,
/// and the manager's covers a wedged *session actor*, which can be parked in
/// an inline `EnsureHost`, `Attach`, or `ConfigureLoadout` and never reach
/// the spawn at all.
pub(crate) const HOST_PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

/// Awaits a host probe under [`HOST_PROBE_TIMEOUT`], collapsing both a
/// missed deadline and a dead host to `None`.
pub(crate) async fn probe_host<T>(
    probe: impl std::future::Future<Output = Result<T, ()>>,
) -> Option<T> {
    tokio::time::timeout(HOST_PROBE_TIMEOUT, probe)
        .await
        .ok()?
        .ok()
}

/// The PTY size a host minted with nothing attached starts at. A client that
/// attaches later resizes it; until then only an unattached shell sees it.
const UNATTACHED_WIN_SIZE: WinSize = WinSize {
    rows: 24,
    cols: 80,
    xpixel: 0,
    ypixel: 0,
};

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
    /// Hand back this session's host, minting one — with no channel bound to
    /// it — if the session has none running. Used by the exec path, which runs
    /// a command inside the session's sandbox and so needs the sandbox up, but
    /// has no terminal to attach and nothing to render progress to.
    EnsureHost(
        oneshot::Sender<Result<session_host::HostHandle, AttachError>>,
        SessionHandle,
        String,
    ),
    /// The workspace's at-risk report (what a destroy would lose), served
    /// to the `SessionDelta` RPC for the destroy confirm. `Unavailable`
    /// without a running host, or when the host cannot compute it.
    GetWorkspaceDelta(oneshot::Sender<minimald_rpc::SessionDeltaResponse>),
    /// Snapshot the running host's terminal screen for a read-only preview
    /// (`min dash`'s `GetSessionScreen`). `None` when no host is running.
    GetHostScreen(oneshot::Sender<Option<minimald_rpc::ScreenSnapshot>>),
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
    Finalize(oneshot::Sender<Result<Vec<minimald_rpc::RanHook>, std::io::Error>>),
    /// Run this session's `on_detach` hooks, sent by a binding that has
    /// left a session which outlives it. Answered when they have run (or
    /// been skipped), so a departing binding can await them.
    RunDetachHooks(oneshot::Sender<()>),
    /// Abort a `Draft` session: delete its record and stop the actor.
    /// Refused with `InvalidInput` on an `Active` session (use `Destroy`).
    Abort(oneshot::Sender<Result<(), std::io::Error>>),
    /// Rename the session: persist the new name through the record handle,
    /// refresh the in-memory snapshot, and relink the PTask hostname.
    Rename(String, oneshot::Sender<Result<(), std::io::Error>>),
    /// Publish one of this box's ports at runtime, decided against its
    /// `dynamic_ingress` setting (NET-043, NET-044, NET-047). Answered with
    /// the daemon's decision; the error is the store's, for a record that
    /// could not be read or written.
    Expose(
        u16,
        sessions::IpProto,
        oneshot::Sender<Result<minimald_rpc::ExposeResponse, std::io::Error>>,
    ),
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
    /// The daemon's shared gvproxy switch, reached through the session because
    /// that is the handle the task path holds.
    GetNetSwitch(oneshot::Sender<Arc<Mutex<crate::net::SwitchClient>>>),
    /// Hand back the session's composition, if it has one. Sourced from
    /// the persisted snapshot: `Session::run` loads it at spawn, so this
    /// answers for an actor brought up from disk after a restart.
    GetComposition(oneshot::Sender<Option<Arc<Composition>>>),
    /// Hand back an `Arc` clone of this session's patches-upload lock, see
    /// [`Session::patches_upload_lock`].
    GetPatchesUploadLock(oneshot::Sender<Arc<Mutex<()>>>),
    /// Hand back an `Arc` clone of this session's hook-scripts-upload lock,
    /// see [`Session::hook_scripts_upload_lock`].
    GetHookScriptsUploadLock(oneshot::Sender<Arc<Mutex<()>>>),
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

    /// The host's published-box table (see [`SessionSeed::published`]): where
    /// this box's name answers, from finalize to destroy. Held for a
    /// synchronous publish/withdraw only, never across an `.await`.
    #[cfg(target_os = "linux")]
    published: Arc<RwLock<crate::net::publish::PublishTable>>,

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

    /// Workspace baseline for the shell-exit prompt, armed once and reused
    /// across host rebuilds so a reattach after a "keep filesystem" exit still
    /// reports the changes made before that exit. See [`WorkspaceBaseline`].
    workspace_baseline: WorkspaceBaseline,

    /// Serializes `WorkspacePatchesTarZst` uploads for this session: two
    /// concurrent uploads would race on the single `<workspace>/patches/`
    /// tree and step on each other.
    patches_upload_lock: Arc<Mutex<()>>,

    /// The same, for `WorkspaceHookScriptsTarZst` uploads and the
    /// `<workspace>/hooks/` tree. A separate lock from the patches one:
    /// the two uploads target different trees and run back-to-back, so
    /// sharing a lock would serialize them against each other for no
    /// reason.
    hook_scripts_upload_lock: Arc<Mutex<()>>,

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

    /// What brought the currently held host up, which decides whether an
    /// interactive attach may respawn it. See [`HostOrigin`].
    host_origin: HostOrigin,
}

/// Why a session host was launched.
///
/// The sandbox and the interactive shell are one spawn — the shell *is* the
/// sandbox's session leader — so a launch that only wanted the sandbox still
/// creates the shell a user may later attach to, and that shell's `environ`
/// is fixed for its lifetime. This records which case a live host is in, so
/// an attach can tell "the shell was made for a terminal" from "the shell was
/// made for a hook, and no terminal has ever described itself to it".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HostOrigin {
    /// Minted by an attach, from a client with a PTY. Its environment already
    /// describes a terminal.
    Interactive,
    /// Minted by [`Session::launch_host_for_hooks`] to run lifecycle hooks.
    /// Nothing of the user's runs in it: activation hooks have completed by
    /// the time an attach can arrive, so the shell is safe to replace.
    Hooks,
    /// Minted by [`Session::ensure_host`] to serve an exec. The command is
    /// live inside that sandbox, so replacing the shell would kill it — this
    /// one is never respawned, and the attaching terminal's facts reach it
    /// through the per-attach environment instead.
    Exec,
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
            #[cfg(target_os = "linux")]
            published,
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
            workspace_baseline: WorkspaceBaseline::Unarmed,
            patches_upload_lock: Arc::new(Mutex::new(())),
            hook_scripts_upload_lock: Arc::new(Mutex::new(())),
            manager,
            weak_self,
            // No host yet; the first launch sets this. `Interactive` is the
            // conservative default — it is the one value that never licenses
            // a respawn.
            host_origin: HostOrigin::Interactive,
            #[cfg(target_os = "linux")]
            hostnames,
            #[cfg(target_os = "linux")]
            published,
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
        actor.register_hostname(obj.record()).await;

        tokio::spawn(actor.mainloop());
        Ok(SessionHandle(sender))
    }

    /// Register this session's PTask hostname (R3.1/R3.6) and publish its
    /// box (NET-010, NET-011, NET-129). Both HostNet and OwnIp route to
    /// loopback through the proxy: a HostNet PTask's listeners are on host
    /// loopback; an OwnIp PTask is reached through a gvproxy-published
    /// loopback port (#542, the published-loopback model). A NoNet PTask
    /// exposes no services, so it is not routed — but it is published like
    /// any box, at a loopback address of its own, so its name answers. A
    /// `Draft` session is neither routed nor published: it has nothing to
    /// answer for until its composition finalizes.
    #[cfg(target_os = "linux")]
    async fn register_hostname(&self, record: &Record) {
        self.publish_box(record).await;
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

    /// Whether this session is published in the box zone: `Active`, in any
    /// network mode — exactly the condition under which [`Self::publish_box`]
    /// published it.
    #[cfg(target_os = "linux")]
    fn is_published(&self) -> bool {
        matches!(self.inner, SessionInner::Active { .. })
    }

    /// Publish this session's box in the host's zone: an own-address or
    /// `none` box at a loopback address of its own, a host-address box at the
    /// node's address, at the box's own port numbers (NET-010, NET-129). A
    /// `Draft` session publishes nothing. An exhausted reserved range is
    /// logged and the box goes unpublished; the session itself still runs.
    ///
    /// The address is leased, the box's declared ports are bound on it, and
    /// only then is the name registered (NET-121), so the name never answers
    /// ahead of the ports it promises. A declared port whose forwarder cannot
    /// bind is reported with its reason and nothing is substituted for it:
    /// no other port, no other address, and no name.
    ///
    /// NET-123: the reserved local range is bind-probed before the box is
    /// published. While it is absent the box goes to the `127.0.0.1` interim,
    /// whatever its mode, and the session start's advisory has already said
    /// so; with the range present the mode's own publication applies.
    #[cfg(target_os = "linux")]
    async fn publish_box(&self, record: &Record) {
        use crate::net::answerer::{interim_address, probe_reserved_range};
        use crate::net::publish::Forwarders;

        if !self.is_published() {
            return;
        }
        let name = registry_name(record);
        let probe = probe_reserved_range();
        let lease = {
            let mut table = self.published.write().expect("publish table lock poisoned");
            match interim_address(&probe) {
                Some(interim) => {
                    tracing::info!(
                        session_id = %record.id,
                        %interim,
                        range = ?probe,
                        "reserved range absent; publishing the box at the interim address"
                    );
                    table.lease_interim(interim)
                }
                None => match table.lease(record.network) {
                    Ok(lease) => lease,
                    Err(error) => {
                        tracing::error!(
                            session_id = %record.id,
                            %error,
                            "could not publish the box; its name will not resolve natively"
                        );
                        return;
                    }
                },
            }
        };
        let declared = declared_ports(record, lease.kind());
        match Forwarders::bind(lease.address(), &declared).await {
            Ok(forwarders) => {
                self.published
                    .write()
                    .expect("publish table lock poisoned")
                    .register(record.id, &name, lease, forwarders);
            }
            Err(failure) => {
                tracing::error!(
                    session_id = %record.id,
                    hostname = %name,
                    port = failure.port,
                    address = %failure.address,
                    error = %failure.error,
                    "a declared port's forwarder could not bind; the box is not published \
                     and no substitute address is published for the port"
                );
                self.published
                    .write()
                    .expect("publish table lock poisoned")
                    .release(lease);
            }
        }
    }

    /// Publish `port` of this box at runtime, as `min net expose` asks: the
    /// request is decided against the box's `dynamic_ingress` setting and an
    /// allow binds the port at the box's published address and records the
    /// mapping in its policy (NET-043, NET-044, NET-047). The actor serves
    /// it because the record write goes through its handle, like a rename.
    #[cfg(target_os = "linux")]
    async fn expose(
        &self,
        port: u16,
        proto: sessions::IpProto,
    ) -> Result<minimald_rpc::ExposeResponse, std::io::Error> {
        crate::net::dynamic_ingress::expose(
            &self.record,
            &self.published,
            &self.net_switch,
            port,
            proto,
        )
        .await
    }

    /// Without the box zone there is no address to publish a port at.
    #[cfg(not(target_os = "linux"))]
    async fn expose(
        &self,
        _port: u16,
        _proto: sessions::IpProto,
    ) -> Result<minimald_rpc::ExposeResponse, std::io::Error> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "dynamic ingress needs the box zone, which this host does not serve",
        ))
    }

    /// Withdraw this session's box from the host's zone (NET-012), releasing
    /// its own address if it held one. Gated like [`Self::deregister_hostname`]:
    /// the table is keyed by name alone, so an ungated withdraw from a `Draft`
    /// session could take down an unrelated box under the same derived name.
    ///
    /// The forwarders the box held for its declared ports are unbound here and
    /// awaited before returning (NET-121), so a rename — a withdraw followed
    /// by a publish that leases the address just released — never binds its new
    /// forwarders against the old ones.
    #[cfg(target_os = "linux")]
    async fn withdraw_box(&self) {
        let record = self.record.record().await.unwrap();
        if !self.is_published() {
            return;
        }
        let withdrawn = self
            .published
            .write()
            .expect("publish table lock poisoned")
            .withdraw(&registry_name(&record));
        if let Some(withdrawn) = withdrawn {
            withdrawn.finished().await;
        }
    }

    /// Record whether this session's box is running, for the zone: a
    /// shared-address box answers its name only while it runs (NET-128).
    #[cfg(target_os = "linux")]
    async fn mark_running(&self, running: bool) {
        if !self.is_published() {
            return;
        }
        let Ok(record) = self.record.record().await else {
            return;
        };
        self.published
            .write()
            .expect("publish table lock poisoned")
            .set_running(&registry_name(&record), running);
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
        self.withdraw_box().await;
        let record = self.record.record().await.unwrap();
        if !self.owns_hostname_route(&record) {
            return;
        }
        let name = registry_name(&record);
        self.hostnames
            .write()
            .expect("hostname registry lock poisoned")
            .deregister(&name);
        // The box is gone, so what it declared goes with its route: a name that
        // no longer resolves declares no port and attributes no caller
        // (NET-069, NET-070).
        self.net_switch
            .lock()
            .await
            .admissions()
            .write()
            .expect("box declarations lock poisoned")
            .withdraw(&name);
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
            SessionMessage::EnsureHost(r, session_hnd, conn_username) => {
                let _ = r.send(self.ensure_host(session_hnd, conn_username).await);
            }
            SessionMessage::GetHostAttrs(r) => match &self.inner {
                SessionInner::Active {
                    host: Some((h, _)), ..
                } => {
                    // Forwarded off-actor for the same reason as
                    // `GetWorkspaceDelta`: the host loop can be mid-attach or
                    // mid-teardown, and awaiting it from here parks this
                    // actor — which the manager awaits in turn, from its own
                    // mainloop, where a park costs every session RPC.
                    //
                    // Bounded *inside* the task: dropping the caller's
                    // receiver does not cancel a spawned future, so an
                    // unbounded probe would strand one task per poll against
                    // a host that never answers.
                    let h = h.clone();
                    tokio::spawn(async move {
                        let _ = r.send(probe_host(h.get_attrs()).await);
                    });
                }
                _ => {
                    let _ = r.send(None);
                }
            },
            SessionMessage::GetWorkspaceDelta(r) => match &self.inner {
                SessionInner::Active {
                    host: Some((h, _)), ..
                } => {
                    // Forwarded off-actor: the host answers via bounded git
                    // commands / a workspace re-walk that can take seconds,
                    // and this actor must stay responsive while they run.
                    let h = h.clone();
                    tokio::spawn(async move {
                        let _ = r.send(h.at_risk().await);
                    });
                }
                _ => {
                    let _ = r.send(minimald_rpc::SessionDeltaResponse::Unavailable);
                }
            },
            SessionMessage::GetHostScreen(r) => match &self.inner {
                SessionInner::Active {
                    host: Some((h, _)), ..
                } => {
                    // Off-actor and bounded for the same reasons as
                    // `GetHostAttrs`.
                    let h = h.clone();
                    tokio::spawn(async move {
                        let _ = r.send(probe_host(h.get_screen()).await);
                    });
                }
                _ => {
                    let _ = r.send(None);
                }
            },
            SessionMessage::ConfigureLoadout(contribution, r) => {
                // Honour what the user chose at `min session activate`.
                let hooks_enabled = match self.record.record().await {
                    Ok(rec) => rec.hooks_enabled,
                    // Unreadable record: compose without hooks. Failing
                    // closed is the only safe default for a domain whose
                    // approval grants code execution.
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            "reading hooks_enabled failed; composing without lifecycle hooks",
                        );
                        false
                    }
                };
                let _ = r.send(self.configure_loadout(contribution, hooks_enabled).await);
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
            SessionMessage::Expose(port, proto, r) => {
                let _ = r.send(self.expose(port, proto).await);
            }
            SessionMessage::IsBusy(r) => {
                let _ = r.send(match &self.inner {
                    // Awaiting a verdict: a client is mid create flow.
                    SessionInner::Draft { pending } => pending.is_some(),
                    // A *live* host, not merely a held one: the slot outlives
                    // the process (see `launch_host_for_hooks`), so a session
                    // whose shell has exited still holds a handle to a host
                    // that runs nothing — and nothing is what an unforced
                    // shutdown would interrupt there.
                    SessionInner::Active { host, .. } => {
                        host.as_ref().is_some_and(|(h, _)| h.is_alive())
                    }
                });
            }
            SessionMessage::Stop(r) => {
                self.stop_running(true).await;
                #[cfg(target_os = "linux")]
                self.deregister_hostname().await;
                let _ = r.send(());
                return ControlFlow::Break(Teardown::ManagerInitiated);
            }
            SessionMessage::RunDetachHooks(r) => {
                self.run_hooks_headless(crate::hooks::HookEvent::Detach)
                    .await;
                let _ = r.send(());
            }
            SessionMessage::Destroy(r) => {
                // Before `stop_running`: a destroy hook runs *inside* the
                // session, so the sandbox it joins has to still exist — or
                // be minted, which is what this does when the session's
                // shell has already gone. Failures are logged, never
                // propagated: a session must stay destroyable whatever its
                // hooks do.
                self.run_hooks_headless(crate::hooks::HookEvent::Destroy)
                    .await;
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
            SessionMessage::GetHookScriptsUploadLock(r) => {
                let _ = r.send(Arc::clone(&self.hook_scripts_upload_lock));
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
            SessionMessage::GetComposition(r) => {
                let _ = r.send(self.composition());
            }
            SessionMessage::GetRecord(r) => {
                let _ = r.send(self.record.record().await.unwrap());
            }
            SessionMessage::GetNetSwitch(r) => {
                let _ = r.send(Arc::clone(&self.net_switch));
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
    /// `hooks_enabled` is passed rather than read from the record
    /// because the two callers disagree: the `ConfigureLoadout` RPC
    /// honours what the user chose at activation, while the attach
    /// shortcut always composes with hooks off (see its call site).
    async fn configure_loadout(
        &mut self,
        contribution: WireContribution,
        hooks_enabled: bool,
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

        // Scaffold before composing, not after: the launcher's package set is
        // its baseline unioned with the composition's packages (see the note
        // on `SessionInner::Active::composition`), so a default written any
        // later never reaches the sandbox. Propagated, not logged — an
        // activation that hands back a session id must hand back a usable
        // session, and a box with no blueprint can't run anything.
        //
        // Fenced: the scaffold resolves the default package repo over the
        // network and runs inline on the session actor, so an unfenced call
        // would pin a worker for the whole fetch. Flavor-guarded because
        // `block_in_place` panics on a current-thread runtime.
        let scaffold = || self.scaffold_mfile_if_missing(&workspace_path);
        match tokio::runtime::Handle::current().runtime_flavor() {
            tokio::runtime::RuntimeFlavor::MultiThread => tokio::task::block_in_place(scaffold),
            _ => scaffold(),
        }
        .map_err(|e| std::io::Error::other(format!("scaffolding a default mfile: {e}")))?;

        // Phase 1+2: resolve the project and drive the composer. Kept fully
        // synchronous — its non-`Send` intermediaries must not cross an
        // `.await`.
        // A session activated with `--no-hooks` drops the project's
        // hooks here, the same way the client already dropped its
        // loadouts' before sending. Both ends honour the flag, so the
        // composition — and the snapshot persisted from it — records
        // that the session has no hooks at all, rather than carrying
        // hooks that every later transition has to remember to skip.
        let outcome = composables::run_compose(
            &self.daemon_ctx,
            &workspace_path,
            &self.record.record().await?.project_path,
            contribution,
            hooks_enabled,
        )?;

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
    async fn finalize(&mut self) -> Result<Vec<minimald_rpc::RanHook>, std::io::Error> {
        let record = self.record.record().await?;
        match record.status {
            SessionStatus::Active => {
                // Already finalized — retry is a no-op, and its hooks ran
                // on the finalize that did the work.
                Ok(Vec::new())
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

                // Same precondition for hook scripts that arrive by
                // upload. Without it, a client that skipped that upload
                // would produce an `Active` session whose hooks name
                // files that were never staged — and the first symptom
                // would be an activation hook failing at some later
                // point, far from the cause. Which hooks those are is
                // narrower than "any external script": see
                // [`composition_needs_staged_scripts`].
                let needs_staged_scripts = matches!(
                    &self.inner,
                    SessionInner::Active {
                        composition: Some(c),
                        ..
                    } if composition_needs_staged_scripts(c)
                );
                if needs_staged_scripts {
                    let marker = paths_obj
                        .hooks_path()
                        .as_utf8_path()
                        .join(crate::rpc::HOOKS_READY_MARKER);
                    let marker_present = tokio::fs::try_exists(&marker).await.map_err(|e| {
                        std::io::Error::new(
                            e.kind(),
                            format!("checking hooks-ready marker at {}: {e}", marker.as_str()),
                        )
                    })?;
                    if !marker_present {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            "hook-script upload never completed; cannot finalize \
                             (upload hook scripts, then retry FinalizeSession)",
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

                // Activate hooks run here — after the patches are in the
                // sandbox home, before the session becomes attachable —
                // so setup work and its failures land at
                // `min session activate` rather than at some later
                // attach.
                //
                // A hook runs *inside* the session, which means a shell
                // has to exist for its namespaces to be joined. Nothing
                // launches one this early, so this does, and keeps it:
                // the next attach reuses it, and whatever the hooks put
                // in `/tmp` survives into the session instead of dying
                // with a throwaway sandbox. Gated on there actually
                // being activate hooks, so a session without them pays
                // nothing and comes up exactly as before.
                let mut ran: Vec<minimald_rpc::RanHook> = Vec::new();
                if self.has_hooks_for(crate::hooks::HookEvent::Activate) {
                    self.launch_host_for_hooks(LaunchPhase::Activating).await?;
                    let outcomes = run_session_hooks(
                        &self.inner,
                        &self.record,
                        crate::hooks::HookEvent::Activate,
                    )
                    .await;
                    // Unlike every other transition, an activate failure
                    // aborts: a development environment whose setup
                    // script failed is not the environment the user
                    // asked for, and handing back a quietly-wrong
                    // session is worse than refusing.
                    if let Some(failed) = outcomes.iter().find(|o| o.failed()) {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            format!(
                                "activation hook from {} failed ({:?}); the session was not \
                                 activated{}",
                                failed.declared_by,
                                failed.status,
                                if failed.output.is_empty() {
                                    String::new()
                                } else {
                                    format!(":\n{}", failed.output)
                                },
                            ),
                        ));
                    }
                    // Nothing failed, so every outcome here is a hook that
                    // ran. Reported back so the client can say what it did
                    // — an activate hook is headless, and without this the
                    // only trace is the daemon log.
                    ran.extend(outcomes.iter().map(|o| minimald_rpc::RanHook {
                        declared_by: o.declared_by.clone(),
                        description: o.description.clone(),
                        output: o.output.clone(),
                    }));
                }

                let mut record = record;
                record.status = SessionStatus::Active;
                self.record.write(record.clone()).await?;
                #[cfg(target_os = "linux")]
                self.register_hostname(&record).await;
                Ok(ran)
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

    /// Kills `host` and stops its runtime loop `task`, bounded so a wedged
    /// host cannot park the caller. Both the kill and the wait for the loop to
    /// act on it are bounded: `HostHandle::kill`'s `send_timeout` only bounds
    /// the wait for mailbox *capacity*, so a loop parked mid-`step()` (mailbox
    /// nearly empty) queues the kill yet never processes it, and awaiting that
    /// loop unbounded would park the caller behind it forever. So a kill that
    /// cannot be queued, or a loop that does not finish within
    /// `HOST_PROBE_TIMEOUT` of accepting it, aborts the loop instead of
    /// waiting on it.
    ///
    /// Aborting drops the loop at its await point, so the awaited `NetGuard`
    /// teardown in `Host::mainloop` is skipped and the wedged host's sandbox
    /// process and network are orphaned rather than reclaimed here;
    /// reclamation is a tracked follow-up.
    async fn kill_and_stop_loop(
        host: &session_host::HostHandle,
        task: &mut JoinHandle<Result<i32, std::io::Error>>,
        for_shutdown: bool,
    ) {
        let killed = host.kill(for_shutdown).await.is_ok();
        if !killed
            || tokio::time::timeout(HOST_PROBE_TIMEOUT, &mut *task)
                .await
                .is_err()
        {
            task.abort();
        }
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
        #[cfg(target_os = "linux")]
        self.mark_running(false).await;
        if let Some((host, mut sops)) = inner {
            for s in sops.drain(..) {
                s.shutdown().await;
            }
            if let Some((host, mut task)) = host {
                // Signal the process to die, then stop its runtime loop so the
                // sandbox files backing its rootfs are released before the
                // caller removes the session's directory tree. The wait is
                // bounded and aborts a wedged loop rather than parking shutdown
                // behind it — see [`Session::kill_and_stop_loop`].
                Self::kill_and_stop_loop(&host, &mut task, for_shutdown).await;
            }
        }
    }

    /// Renames the session: persists the new name through the record handle
    /// (a name collision surfaces as the store's `AlreadyExists`), relinks
    /// the PTask hostname so `<new>.min.internal` routes and the old name stops (R3.6).
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
        })
        .await;
        // A fresh publication starts as not running; carry the live host
        // over so a renamed shared-address box keeps answering.
        #[cfg(target_os = "linux")]
        {
            let running = matches!(
                &self.inner,
                SessionInner::Active { host: Some((h, _)), .. } if h.is_alive()
            );
            self.mark_running(running).await;
        }

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
        // above it — `TERM` from the client's PTY request, and the banner's
        // detach hint derived from the negotiated keys below.
        //
        // `SSH_TTY` and `SSH_CONNECTION`/`SSH_CLIENT` are intentionally omitted:
        // the session sandbox has no host `/dev/pts` and the transport is a
        // local Unix socket (no peer IP/port), so any value would name something
        // that doesn't exist in-session and would only mislead audit logs,
        // source-IP checks, or `$SSH_TTY` consumers.
        // The negotiated session keys: the leader chord and detach/forward
        // subcommand keys the client sent on this channel, re-validated here as
        // a silent safety backstop (a bad chord falls back to the default,
        // never garbling the screen). Per-channel: two clients with different
        // configs on the same session each get their own chord.
        let session_keys = SessionKeys::from_env(&config.env_vars).validated_or_default();

        let attach_env = {
            let inherited = inherited_session_env(&config.env_vars);
            let mut connection = Vec::new();
            match config.pty.as_ref().map(|pty| pty.term.as_str()) {
                Some(term) if !term.is_empty() => {
                    tracing::info!(term, "attach carries a terminal");
                    connection.push(("TERM".to_string(), term.to_string()));
                }
                // The client had nothing to say about its terminal — OpenSSH
                // sends an empty pty-req term string when its own `TERM` is
                // unset. The session keeps whatever the last attach published,
                // which is right (an absent value is not an assertion that
                // there is no terminal) but indistinguishable from "nothing
                // changed" unless it is said out loud. Logged because the
                // silence here has already cost one debugging session: the
                // symptom is a session whose `TERM` never follows the client,
                // and this line is the difference between reading it off and
                // guessing at it.
                _ => tracing::info!(
                    "attach carries no terminal (client sent an empty pty-req term); \
                     keeping the last published TERM"
                ),
            }
            // The orientation banner's detach hint: derived from the negotiated
            // keys so a remapped leader/detach chord advertises itself. Seeded
            // daemon-side (like MINIMAL_SESSION_NAME), never forwarded from the
            // client — the client sends raw key names, the daemon builds the
            // display string. The MOTD template interpolates this with a
            // `${VAR:-fallback}` so an unset var (no negotiation) still renders.
            connection.push((
                "MINIMAL_DETACH_HINT".to_string(),
                format!(
                    "{} then {}",
                    session_keys.leader.as_config_str(),
                    session_keys.detach_key.as_config_str(),
                ),
            ));
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
            // Hooks are forced off on this path regardless of the
            // record. The shortcut composes with no client in the loop,
            // and a project hook needs a client-side policy decision it
            // has no way to obtain — composing with hooks on would
            // return `Pending`, which this path cannot resolve, and
            // every attach to a hook-declaring project would fail.
            // A session that wants its project's hooks has to come up
            // through `min session activate`, where the user is present
            // to answer for them.
            self.configure_loadout(WireContribution::default(), false)
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

        // A host minted to run hooks has an environment that describes no
        // terminal, because there was none — and the shell's `environ` cannot
        // be revised in place. Nothing of the user's is running in it (the
        // activation hooks it was launched for have completed by the time an
        // attach can arrive), so replace it with one minted for the terminal
        // that is actually here. An `Exec`-minted host is deliberately not
        // replaced: a command is live inside that sandbox, and killing it to
        // improve `TERM` is a bad trade. That case rides on the per-attach
        // environment the host republishes instead.
        let respawn_for_terminal =
            self.host_origin == HostOrigin::Hooks && attach_env.declares_terminal();
        if respawn_for_terminal
            && let SessionInner::Active {
                host: slot @ Some(_),
                ..
            } = &mut self.inner
        {
            tracing::info!(
                "replacing the hook-launched session shell with one minted for the attaching terminal"
            );
            let (handle, mut join) = slot.take().expect("matched on Some");
            // Bound the wait for the hook host to wind down, aborting a wedged
            // loop rather than parking the attach behind it. Same bounded
            // kill-and-stop as shutdown; see [`Session::kill_and_stop_loop`].
            Self::kill_and_stop_loop(&handle, &mut join, false).await;
        }

        let host = match &mut self.inner {
            // Awaiting a verdict: a client is mid create flow, and composing
            // over it here would discard the items it is still gating.
            SessionInner::Draft { .. } => return Err(AttachError::SessionPending),
            SessionInner::Active { host, .. } => host,
        };
        match host {
            None => {
                self.mint_session_host(
                    session_hnd,
                    conn_username,
                    channel,
                    sz,
                    attach_env,
                    session_keys,
                )
                .await
            }
            Some((h, _)) => {
                // Every attach carries the connection facts, not just the one
                // that mints the shell: `TERM` describes whichever terminal is
                // on the other end of *this* channel.
                match h
                    .attach(channel, sz, attach_env.connection_env(), session_keys)
                    .await
                {
                    Ok(()) => Ok(()),
                    Err((channel, sz)) => {
                        // The host is gone, or wedged past the attach deadline.
                        self.mint_session_host(
                            session_hnd,
                            conn_username,
                            channel,
                            sz,
                            attach_env,
                            session_keys,
                        )
                        .await
                    }
                }
            }
        }
    }

    /// Launches a host for this session.
    ///
    /// The one path all callers take: [`Self::attach`], which has a client
    /// channel and passes it in as `progress` so the sandbox coming up is
    /// rendered on the client's terminal, [`Self::ensure_host`], which has
    /// no channel at all, and [`Self::launch_host_for_hooks`], which
    /// runs before the session is `Active` (hence `phase`). The channel goes
    /// in and comes back out because progress rendering borrows it for the
    /// duration; storing the result is left to the caller, since attach only
    /// keeps a host it could bind to.
    async fn launch_host(
        &mut self,
        session_hnd: SessionHandle,
        conn_username: String,
        sz: WinSize,
        attach_env: session_host::AttachEnv,
        progress: Option<ChannelProgress>,
        phase: LaunchPhase,
    ) -> Result<(Option<Channel<Msg>>, LaunchedHost), AttachError> {
        let record = self.record.record().await.unwrap();
        let paths = self.paths().await;
        // Kept before the launcher consumes `attach_env`: the launch folds
        // these into the shell's environment, and the host keeps them so it
        // can layer them onto everything it later runs in the session and
        // republish them for the shell to re-read.
        let connection_env = attach_env.connection_env();
        let launcher = self
            .session_launcher(session_hnd, &record, attach_env, phase)
            .await?;
        // Where the shell-exit prompt's save-then-delete lane archives the
        // changed files. Daemon-side and session-independent; created on
        // demand at save time.
        let archives_dir = self
            .minimal_state_dir
            .as_utf8_path()
            .as_std_path()
            .join("archives");
        // Arm the workspace baseline once, before this session's first host
        // launches; a host rebuilt on reattach reuses it rather than
        // re-snapshotting the already-modified workspace. See
        // [`WorkspaceBaseline`].
        let delta = match &self.workspace_baseline {
            WorkspaceBaseline::Armed(delta) => delta.clone(),
            WorkspaceBaseline::Unarmed => {
                let workspace_root = paths.working.as_utf8_path().as_std_path().to_path_buf();
                let delta = self.load_or_arm_baseline(workspace_root).await;
                self.workspace_baseline = WorkspaceBaseline::Armed(delta.clone());
                delta
            }
        };
        let spawn = Box::pin(session_host::Host::spawn(
            launcher,
            session_host::HostParams {
                name: registry_name(&record),
                username: conn_username,
                paths,
                sz,
                channel: None,
                // Mint a handle to this session ID in the sessions actor/manager.
                control: Some(SessionControl::new(self.manager.clone(), record.id)),
                delta,
                archives_dir,
                session_id: record.id,
                // The host runs attach and detach itself: it owns the terminal
                // they write to and the process whose namespaces they join.
                composition: self.composition(),
                connection_env,
            },
        ));

        let (channel, spawned) = match progress {
            Some(progress) => {
                let (channel, spawned) = progress.run(spawn).await;
                (Some(channel), spawned)
            }
            None => (None, spawn.await),
        };
        Ok((channel, spawned.map_err(AttachError::SpawnFailed)?))
    }

    /// Produces this session's arm result for [`WorkspaceBaseline`]: the
    /// persisted sidecar when one is readable — so a daemon restart keeps
    /// the activation-time baseline — and a fresh walk otherwise, persisted
    /// best-effort so the next restart finds it. Every failure degrades to
    /// the fresh walk or to skipping persistence with a warning: change
    /// detection is a courtesy and never blocks a launch.
    async fn load_or_arm_baseline(
        &self,
        workspace_root: std::path::PathBuf,
    ) -> Option<Arc<DeltaSource>> {
        match self.record.load_delta_baseline().await {
            Ok(Some(bytes)) => {
                match session_delta::from_sidecar_bytes(&bytes, workspace_root.clone()) {
                    Ok(delta) => return delta,
                    Err(e) => {
                        tracing::warn!(
                            session_id = %self.record.id(),
                            error = %e,
                            "unreadable delta-baseline sidecar; arming afresh",
                        );
                    }
                }
            }
            Ok(None) => {}
            Err(e) => {
                tracing::warn!(
                    session_id = %self.record.id(),
                    error = %e,
                    "failed to read delta-baseline sidecar; arming afresh",
                );
            }
        }
        let delta = DeltaSource::arm(workspace_root).await;
        // Persist the arm result — a failed arm included, so a restart
        // honors "change detection disabled" instead of re-snapshotting a
        // tree the session may already have modified.
        match session_delta::to_sidecar_bytes(delta.as_ref()) {
            Ok(bytes) => {
                if let Err(e) = self.record.store_delta_baseline(bytes).await {
                    tracing::warn!(
                        session_id = %self.record.id(),
                        error = %e,
                        "failed to persist the delta baseline; a daemon restart will re-arm",
                    );
                }
            }
            Err(e) => {
                tracing::warn!(
                    session_id = %self.record.id(),
                    error = %e,
                    "unserializable delta baseline; a daemon restart will re-arm",
                );
            }
        }
        delta
    }

    /// Hands back this session's host, launching one if none is running.
    ///
    /// Unlike [`Self::attach`] there is no channel: the host is minted with
    /// nothing bound to it, because the caller wants the *sandbox* — to run a
    /// command inside it — not a terminal. A client that attaches later reuses
    /// this host and resizes its PTY, so the placeholder size is only ever what
    /// an unattached session's shell sees.
    ///
    /// Gated on the same `Active` record status as `attach`, without its
    /// draft-session shortcut: composing a loadout is a client-driven flow, and
    /// an exec request is not the place to start one.
    async fn ensure_host(
        &mut self,
        session_hnd: SessionHandle,
        conn_username: String,
    ) -> Result<session_host::HostHandle, AttachError> {
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

        let running = match &self.inner {
            SessionInner::Draft { .. } => return Err(AttachError::SessionPending),
            SessionInner::Active {
                host: Some((h, _)), ..
            } if h.is_alive() => Some(h.clone()),
            SessionInner::Active { .. } => None,
        };
        if let Some(host) = running {
            // Same claim as the launch below, for a host this call did not
            // mint: an exec is about to run in this sandbox, so a later
            // attach must not replace the shell out from under it. Without
            // this, a host minted for lifecycle hooks stays `Hooks` through
            // every exec that reuses it, and the first interactive attach
            // would respawn it — killing a command that is still running.
            self.host_origin = HostOrigin::Exec;
            return Ok(host);
        }

        let (_, launched) = self
            .launch_host(
                session_hnd,
                conn_username,
                UNATTACHED_WIN_SIZE,
                session_host::AttachEnv::default(),
                None,
                LaunchPhase::Attached,
            )
            .await?;

        let host = launched.0.clone();
        let SessionInner::Active { host: slot, .. } = &mut self.inner else {
            unreachable!("ensure_host returns early on a Draft session");
        };
        *slot = Some(launched);
        // Minted for an exec: a command is about to run in this sandbox, so a
        // later attach must not replace it. See [`HostOrigin::Exec`].
        self.host_origin = HostOrigin::Exec;
        #[cfg(target_os = "linux")]
        self.mark_running(true).await;
        Ok(host)
    }

    async fn mint_session_host(
        &mut self,
        session_hnd: SessionHandle,
        conn_username: String,
        channel: Channel<Msg>,
        sz: WinSize,
        attach_env: session_host::AttachEnv,
        session_keys: SessionKeys,
    ) -> Result<(), AttachError> {
        let progress = ChannelProgress::new(channel, self.tracker.clone(), (sz.cols, sz.rows));
        let (channel, launched) = self
            .launch_host(
                session_hnd,
                conn_username,
                sz,
                attach_env,
                Some(progress),
                LaunchPhase::Attached,
            )
            .await?;
        let channel = channel.expect("progress hands back the channel it was given");

        // Wire the channel to the freshly launched host. A failure here means
        // the host died in the window between launch and attach; surface it as
        // a spawn failure rather than leaving a dead, channel-less host — which
        // is why the host is stored only once it is bound.
        //
        // The launch already folded this attach's connection facts into the
        // shell's environment, so nothing new is passed here: the host holds
        // them, and an empty map means "no revision", not "no terminal".
        launched
            .0
            .attach(
                channel,
                sz,
                session_host::ConnectionEnv::new(),
                session_keys,
            )
            .await
            .map_err(|_| {
                AttachError::SpawnFailed(std::io::Error::other(
                    "session host exited before its channel could attach",
                ))
            })?;
        let SessionInner::Active { host, .. } = &mut self.inner else {
            unreachable!("mint_session_host is only reachable from the Active state");
        };
        // A wedged-but-alive host can reach here via attach's re-mint branch
        // (`session_host.rs` `SendTimeoutError::Timeout`): its loop task is
        // still running. Dropping the replaced `(HostHandle, JoinHandle)`
        // would detach that task, leaking the old sandbox process, pty master,
        // and `NetGuard` for the daemon's lifetime — one leak per attach to the
        // same wedged host. Abort the task being replaced, mirroring
        // `stop_running` (a no-op when the old loop had already exited).
        if let Some((_, task)) = host.replace(launched) {
            task.abort();
        }
        // Minted by an attach: its environment describes the terminal that is
        // here, so nothing may replace it out from under that client.
        self.host_origin = HostOrigin::Interactive;
        #[cfg(target_os = "linux")]
        self.mark_running(true).await;
        Ok(())
    }

    /// True when this session's composition declares at least one script for
    /// `event`. Gates the headless host launches ([`Self::finalize`]'s and
    /// [`Self::run_detach_hooks`]'s): without it, a transition would pay for
    /// a sandbox no hook is going to use.
    fn has_hooks_for(&self, event: crate::hooks::HookEvent) -> bool {
        let SessionInner::Active {
            composition: Some(c),
            ..
        } = &self.inner
        else {
            return false;
        };
        c.lifecycle_hooks()
            .iter()
            .any(|ph| event.script_of(ph.hook()).is_some())
    }

    /// Runs this session's hooks for `event` headlessly, minting a host
    /// first when none is running.
    ///
    /// The launch is what makes this reliable. A hook runs *inside* the
    /// session, so it needs a process whose namespaces it can join, and
    /// neither teardown transition is guaranteed one: the host slot outlives
    /// the host process, so a session whose shell has exited still holds a
    /// handle to a host that can no longer run anything, and a session that
    /// was never attached may have no host at all. Minting here — the same
    /// launch [`Self::finalize`] does for activation — covers both, and a
    /// session whose shell is still up (the ctrl-w detach, a destroy from a
    /// second terminal) reuses it rather than starting a second one.
    ///
    /// Best effort, and *bounded*: a teardown that cannot run its hooks
    /// still happens, so every failure is logged, none is propagated, and
    /// nothing here may block indefinitely — see [`HOOK_LAUNCH_TIMEOUT`].
    /// Activation is the exception and keeps its own path in
    /// [`Self::finalize`] — a failed activate hook aborts the activation
    /// rather than being logged past.
    async fn run_hooks_headless(&mut self, event: crate::hooks::HookEvent) {
        if !self.has_hooks_for(event) {
            return;
        }
        // `Attached`, not `Activating`: both transitions only happen once the
        // session is `Active`, so neither has reason to skip the status gate.
        // A session torn down before it activated (an aborted finalize leaves
        // it `Materializing`) is refused here and skips its hooks — teardown
        // for setup that never completed.
        //
        // Timed out rather than simply awaited: this runs on the destroy
        // path, and building a sandbox reaches the filesystem, the package
        // cache, and (for an own-IP session) the network switch. A session
        // must always be destroyable, so a launch that wedges has to cost
        // its hooks rather than the whole teardown.
        match tokio::time::timeout(
            HOOK_LAUNCH_TIMEOUT,
            self.launch_host_for_hooks(LaunchPhase::Attached),
        )
        .await
        {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                tracing::warn!(
                    event = event.as_str(),
                    error = %e,
                    "launching the session to run its hooks failed; skipping them",
                );
                return;
            }
            Err(_elapsed) => {
                tracing::warn!(
                    event = event.as_str(),
                    timeout_secs = HOOK_LAUNCH_TIMEOUT.as_secs(),
                    "launching the session to run its hooks timed out; skipping them",
                );
                return;
            }
        }
        run_session_hooks(&self.inner, &self.record, event).await;
    }

    /// Launch the session host so lifecycle hooks have namespaces to
    /// join, and keep it as the session's host.
    ///
    /// Headless: there is no client channel, no PTY negotiated, and no
    /// forwarded locale — neither the activating RPC nor a departing
    /// binding is an attach. The window size is a placeholder the first
    /// real attach replaces.
    ///
    /// A host that is still *running* (an attach raced the finalize; a
    /// ctrl-w detach left the shell up) is left alone. A dead one is
    /// replaced rather than reused: the slot outlives the process, so a
    /// session whose shell exited still holds a handle to a host that can no
    /// longer run anything — which is exactly the state a detach hook meets
    /// on the shell-exit path. Mirrors [`Self::ensure_host`]'s liveness
    /// check for the same reason.
    async fn launch_host_for_hooks(&mut self, phase: LaunchPhase) -> Result<(), std::io::Error> {
        if matches!(
            &self.inner,
            SessionInner::Active { host: Some((h, _)), .. } if h.is_alive()
        ) {
            return Ok(());
        }
        let session_hnd = self.weak_self.upgrade().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "session actor is shutting down; cannot run lifecycle hooks",
            )
        })?;
        let username = self
            .record
            .record()
            .await?
            .username
            .unwrap_or_else(|| "user".to_string());
        let launched = self
            .launch_host(
                session_hnd,
                username,
                WinSize {
                    rows: 24,
                    cols: 80,
                    xpixel: 0,
                    ypixel: 0,
                },
                session_host::AttachEnv::default(),
                None,
                phase,
            )
            .await
            .map_err(|e| {
                std::io::Error::other(format!("launching the session to run its hooks: {e}"))
            })?
            .1;
        let SessionInner::Active { host, .. } = &mut self.inner else {
            unreachable!("a headless hook launch only reaches here from the Active state");
        };
        *host = Some(launched);
        // Minted for hooks, with no terminal to describe: an interactive
        // attach may replace this shell rather than inherit its blank `TERM`.
        // See [`HostOrigin::Hooks`].
        self.host_origin = HostOrigin::Hooks;
        #[cfg(target_os = "linux")]
        self.mark_running(true).await;
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
        phase: LaunchPhase,
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
        let egress = record.policy.egress.clone();
        Ok(session_host::SandboxLauncher {
            ctx: match phase {
                LaunchPhase::Attached => self.context(true).await,
                // The activation launch runs inside `finalize`, before the
                // record is promoted, so the status gate in `context` would
                // reject it — see [`LaunchPhase::Activating`]. Everything
                // that gate protects has already been established by the
                // time finalize gets here: the session is composed (checked
                // before any of this runs) and its patches are materialized
                // into the home dir.
                LaunchPhase::Activating => self.build_context(true).await,
            }
            .map_err(AttachError::ContextCreationFailed)?,
            attach_env,
            network_mode,
            net_switch: Arc::clone(&self.net_switch),
            ingress,
            published: Arc::clone(&self.published),
            egress,
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
        _phase: LaunchPhase,
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
    ///
    /// The one caller that legitimately runs before the promotion —
    /// [`Session::finalize`]'s activation-hook launch — reaches
    /// [`Self::build_context`] directly instead, via
    /// [`LaunchPhase::Activating`]. It materializes the home dir first, so
    /// it satisfies the invariant this gate protects without being able to
    /// satisfy the gate itself.
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
    ///
    /// Runs from [`Self::configure_loadout`], ahead of the composition that
    /// decides the launcher's packages; [`Self::build_context`] repeats it as
    /// an idempotent backstop for sessions brought up from disk.
    fn scaffold_mfile_if_missing(&self, wsp: &DaemonAbsPath) -> Result<(), String> {
        if wsp.as_utf8_path().join(mfile::MFILE_NAME).exists() {
            return Ok(());
        }
        match mfile::File::from_dir(wsp.as_utf8_path()) {
            Ok(_) => Ok(()), // it exists
            Err(mfile::Error::NotFound) => {
                let (toml_path, content) = self.default_mfile_plan(wsp)?;
                std::fs::write(&toml_path, &content).map_err(|e| e.to_string())
            }
            Err(e) => Err(e.to_string()),
        }
    }

    /// The default `minimal.toml` [`Self::scaffold_mfile_if_missing`] writes:
    /// `op::InitProject` detects the workspace's stack against the default
    /// package repo, whose branch head it resolves over the network.
    #[cfg(not(any(test, feature = "test-support")))]
    fn default_mfile_plan(
        &self,
        wsp: &DaemonAbsPath,
    ) -> Result<(std::path::PathBuf, String), String> {
        let config = self.workspace_config(wsp)?;

        use op::ProjectOp as _;
        let mut env = mctx::ProjectSetup::for_init(config).map_err(|e| e.to_string())?;
        let plan = op::InitProject.run(&mut env).map_err(|e| e.to_string())?;

        Ok((plan.toml_path, plan.content))
    }

    /// Under test, stand in for `op::InitProject`'s network round-trip: tests
    /// run offline, and what they need from the scaffold is that it lands
    /// before the composition — not what stack detection would have picked.
    /// Same two packages `op::InitProject` falls back to when nothing matches.
    #[cfg(any(test, feature = "test-support"))]
    fn default_mfile_plan(
        &self,
        wsp: &DaemonAbsPath,
    ) -> Result<(std::path::PathBuf, String), String> {
        Ok((
            wsp.as_utf8_path()
                .join(mfile::MFILE_NAME)
                .into_std_path_buf(),
            "[session]\npackages = [\"base\", \"vim\"]\n".to_string(),
        ))
    }

    /// Do the actual context construction: run [`mctx::Context::new`] against
    /// a session-rooted [`Config`]. Called at most once per actor lifetime by
    /// [`Self::context`].
    ///
    /// The workspace mfile it parses is either the client's uploaded one or
    /// the default [`Self::configure_loadout`] scaffolded. The scaffold is
    /// repeated here as a backstop — it early-returns when the mfile exists,
    /// so it only fires for a session whose compose predates it.
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
            hooks: obj.hooks_path(),
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

    /// The session's composition, if it has one. See
    /// [`SessionMessage::GetComposition`].
    pub async fn composition(&self) -> Result<Option<Arc<Composition>>, std::io::Error> {
        let (send, recv) = oneshot::channel();
        let _ = self.0.send(SessionMessage::GetComposition(send)).await;
        recv.await.map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::NotConnected, "session actor is gone")
        })
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

    /// Handle to the per-session hook-scripts-upload lock, owned by the
    /// session actor. Serializes `WorkspaceHookScriptsTarZst` RPCs the
    /// same way [`Self::patches_upload_lock`] serializes patch uploads.
    pub async fn hook_scripts_upload_lock(&self) -> Result<Arc<Mutex<()>>, std::io::Error> {
        let (send, recv) = oneshot::channel();
        // Ignore send errors - the recv will also fail.
        let _ = self
            .0
            .send(SessionMessage::GetHookScriptsUploadLock(send))
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

    /// Returns the workspace's at-risk report (what a destroy would lose),
    /// or `Unavailable` when it cannot be computed — no running host, no
    /// baseline, failed bounded computation, or a dead actor. Never an
    /// error: the destroy confirm renders with or without the listing.
    pub async fn workspace_at_risk(&self) -> minimald_rpc::SessionDeltaResponse {
        let (send, recv) = oneshot::channel();
        // Ignore send errors - the recv will also fail.
        let _ = self.0.send(SessionMessage::GetWorkspaceDelta(send)).await;
        recv.await
            .unwrap_or(minimald_rpc::SessionDeltaResponse::Unavailable)
    }
    /// Returns a snapshot of the running session's terminal screen, if any.
    /// Same dead-actor semantics as [`Self::get_attrs`].
    pub async fn get_screen(&self) -> Option<minimald_rpc::ScreenSnapshot> {
        let (send, recv) = oneshot::channel();
        // Ignore send errors - the recv will also fail.
        let _ = self.0.send(SessionMessage::GetHostScreen(send)).await;
        recv.await.ok().flatten()
    }

    /// Runs this session's `on_detach` hooks, awaiting them so a departing
    /// binding doesn't race its own teardown. A dead actor means there is
    /// no session to run them against, which is not an error worth raising
    /// on a path whose whole job is leaving.
    pub async fn run_detach_hooks(&self) {
        let (send, recv) = oneshot::channel();
        // Ignore send errors - the recv will also fail.
        let _ = self.0.send(SessionMessage::RunDetachHooks(send)).await;
        let _ = recv.await;
    }

    /// Returns a minimal context initialized on this sessions' worktree.
    pub async fn context(&self) -> Result<mctx::Context, String> {
        let (send, recv) = oneshot::channel();
        // Ignore send errors - the recv will also fail.
        let _ = self.0.send(SessionMessage::MakeContext(send)).await;
        recv.await
            .unwrap_or_else(|_| Err("session actor is gone".to_string()))
    }

    /// The spec hash of every package this session's project needs: its tasks,
    /// its stack, and its `[session]` block.
    ///
    /// Resolved through this session's own workspace context, so the answer
    /// reflects the `minimal.toml` currently in its worktree. Spec hashes
    /// rather than `BuildSpecRef`s because a ref only means something against
    /// the graph it was resolved in — see [`mctx::Context::needed_packages`].
    ///
    /// Runs off the actor: the resolve is nickel evaluation plus a graph
    /// build, which has no business sitting in the session's mainloop, so it
    /// goes to the blocking pool like every other graph build in the daemon.
    pub async fn needed_packages(&self) -> Result<HashSet<SpecHash>, String> {
        let mut ctx = self.context().await?;
        // `mctx::Error` isn't `Send` (it carries nickel-language types), so it
        // is rendered to a string inside the task.
        tokio::task::spawn_blocking(move || ctx.needed_packages().map_err(|e| e.to_string()))
            .await
            .map_err(|e| format!("resolving needed packages: {e}"))?
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

    /// The daemon's shared gvproxy switch, for the task path's network
    /// provider. A dead actor maps to `NotConnected`.
    pub(crate) async fn net_switch(
        &self,
    ) -> Result<Arc<Mutex<crate::net::SwitchClient>>, std::io::Error> {
        let (send, recv) = oneshot::channel();
        // Ignore send errors - the recv will also fail.
        let _ = self.0.send(SessionMessage::GetNetSwitch(send)).await;
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
    pub(crate) async fn finalize(&self) -> Result<Vec<minimald_rpc::RanHook>, std::io::Error> {
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

    /// Publishes `port` of this box at runtime, decided against its
    /// `dynamic_ingress` setting; see [`SessionMessage::Expose`]. A dead
    /// actor maps to `NotConnected`.
    pub(crate) async fn expose(
        &self,
        port: u16,
        proto: sessions::IpProto,
    ) -> Result<minimald_rpc::ExposeResponse, std::io::Error> {
        let (send, recv) = oneshot::channel();
        // Ignore send errors - the recv will also fail.
        let _ = self.0.send(SessionMessage::Expose(port, proto, send)).await;
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

    /// This session's host, launching one with nothing bound to it if the
    /// session has none running.
    ///
    /// For callers that need the session's *sandbox* rather than its terminal —
    /// an SSH exec request runs its command inside the sandbox, which means the
    /// session process whose namespaces it joins has to exist.
    ///
    /// # Errors
    ///
    /// [`AttachError::SessionPending`] on a session that is not yet `Active`,
    /// and [`AttachError::SpawnFailed`] if the host cannot be launched or the
    /// session actor is gone.
    pub async fn ensure_host(
        &self,
        conn_username: String,
    ) -> Result<session_host::HostHandle, AttachError> {
        let (send, recv) = oneshot::channel();
        // Ignore send errors - the recv will also fail.
        let _ = self
            .0
            .send(SessionMessage::EnsureHost(
                send,
                self.clone(),
                conn_username,
            ))
            .await;
        match recv.await {
            Ok(result) => result,
            Err(_) => Err(AttachError::SpawnFailed(std::io::Error::other(
                "session actor terminated before the host could be launched",
            ))),
        }
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

/// The ports `record`'s ingress declaration names, and how the box answers
/// each at its published address (NET-121).
///
/// A TCP mapping on an address of the box's own is answered by a forwarder
/// minimald binds there, sending what it accepts to the host-side forward the
/// box's switch publishes for the port (`127.0.0.1:<external>`). Every other
/// declared port is published with no forwarder interposed: on a shared
/// address — a host-address box, or the `127.0.0.1` interim — the box's own
/// listeners answer its port numbers, so binding there would take the port
/// from the box itself, and a UDP mapping's datagrams are carried by the
/// switch forward rather than by a connection-oriented forwarder.
#[cfg(target_os = "linux")]
fn declared_ports(
    record: &Record,
    kind: crate::net::publish::AddressKind,
) -> Vec<crate::net::publish::DeclaredPort> {
    use crate::net::publish::{AddressKind, DeclaredPort, PortAnswer};

    record
        .policy
        .ingress
        .as_ref()
        .map(|ingress| {
            ingress
                .port_mappings
                .iter()
                .map(|m| DeclaredPort {
                    port: m.internal_port,
                    answer: match (kind, m.proto) {
                        (AddressKind::Own, sessions::IpProto::Tcp) => {
                            PortAnswer::Forwarded(std::net::SocketAddr::from((
                                std::net::Ipv4Addr::LOCALHOST,
                                m.external_port,
                            )))
                        }
                        _ => PortAnswer::Direct,
                    },
                })
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests;
