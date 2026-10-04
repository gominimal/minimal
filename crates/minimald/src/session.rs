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
    /// The session host is alive but busy (its mailbox stayed full past the
    /// attach deadline). The client should retry.
    SessionBusy,
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
            AttachError::SessionBusy => {
                write!(f, "session host is busy; retry the attach once it drains")
            }
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
    /// The answerer's lease book for this host (NET-010): the durable record
    /// a grant of the reserved local range is arbitrated through. The actor
    /// asks it for this session's box at finalize (NET-010/NET-011) and
    /// returns the address at destroy — through the registry the publish and
    /// the withdrawal bookend. Every ask is a synchronous read-modify-write
    /// under the record's own lock file, so two daemons on one host are
    /// serialized by the record, not by each other.
    #[cfg(target_os = "linux")]
    pub loopback: Arc<crate::net::dns::LoopbackLeaseBook>,
    /// Whether the daemon opted out of the deny-all egress default
    /// (NET-077): the launcher and the task path read it to resolve this
    /// session's effective egress (NET-074), and the start line below logs
    /// it so a diagnostics bundle can name the posture without the daemon's
    /// flags.
    pub deny_all_opt_out: bool,
}

/// The egress *section* the gate compiles for a session: the materialized
/// form of [`sessions::effective_egress`]'s answer — `None` for the shipped
/// allow-all, the deny-all section for an absent declaration under the
/// in-force default (NET-074), and a declaration verbatim. `phase` is the
/// rollout phase to resolve under — the launcher and the task path pass
/// [`sessions::EGRESS_DEFAULT_PHASE`], the phase this build ships, while the
/// tests pass [`sessions::EgressDefaultPhase::InForce`] so the posture the
/// rollout ends at stays proven while the default is only announced
/// (NET-076). `opt_out` is the daemon's deny-all opt-out (NET-077), threaded
/// from the server config.
///
/// Shared by the session launcher (the box's own gate) and the task path
/// ([`crate::exec::task_network`]), so a task runs under the same egress
/// its session does.
pub(crate) fn effective_egress_section(
    policy: &sessions::SessionPolicy,
    network: sessions::NetworkMode,
    phase: sessions::EgressDefaultPhase,
    opt_out: bool,
) -> Option<sessions::EgressPolicy> {
    match sessions::effective_egress(policy.egress.as_ref(), network, phase, opt_out) {
        sessions::EffectiveEgress::DenyAll => Some(sessions::EgressPolicy::deny_all()),
        sessions::EffectiveEgress::AllowAll => None,
        sessions::EffectiveEgress::Declared(section) => Some(section),
    }
}

/// The policy the gate enforces for a session: its declared ingress, and its
/// egress resolved to the section [`effective_egress_section`] names — the
/// deny-all section for an own-address box with no `egress` section once the
/// default is in force (NET-074), the shipped allow-all for everything an
/// opt-out (NET-077) or an earlier phase leaves in place, and a declaration
/// verbatim. `phase` resolves under, exactly as [`effective_egress_section`]
/// documents. The declaration on the record is left untouched: the strict
/// `SessionPolicy` a client reads back stays exactly what the box was
/// launched with.
pub(crate) fn effective_session_policy(
    policy: &sessions::SessionPolicy,
    network: sessions::NetworkMode,
    phase: sessions::EgressDefaultPhase,
    opt_out: bool,
) -> sessions::SessionPolicy {
    sessions::SessionPolicy {
        egress: effective_egress_section(policy, network, phase, opt_out),
        ingress: policy.ingress.clone(),
        // The credentialed-upstream declaration (NET-134) resolves nothing —
        // the lane it opens is decided host-side, by the row the client's
        // registration fills — so it is carried verbatim, like the ingress:
        // the effective policy a box's gate reads keeps the lane the box
        // declared beside it.
        credentialed_upstream: policy.credentialed_upstream.clone(),
    }
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
    /// Whether this daemon opted out of the deny-all egress default
    /// (NET-077), read by the task path so a task resolves its session's
    /// effective egress (NET-074) the same way the launcher does.
    GetDenyAllOptOut(oneshot::Sender<bool>),
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
    /// Register a live direct-tcpip forward relay as belonging to this
    /// session, so teardown takes it down too: a session that goes away
    /// aborts its forwards rather than leaving relays pointing into a box
    /// that no longer exists.
    TrackForward(tokio::task::AbortHandle),
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
    /// Publish `port` for this box at runtime (NET-043): the request a process
    /// inside the box sends with its own `min net expose`, decided against the
    /// box's `dynamic_ingress` setting and — when it allows — bound on the
    /// switch and recorded as a live mapping (NET-044). Answered with the
    /// published mapping, or the typed reason the request was refused.
    ExposeDynamic {
        port: u16,
        reply:
            oneshot::Sender<Result<minimald_rpc::LiveMapping, crate::net::policy::ExposeFailure>>,
    },
    /// The live dynamic-ingress mappings this box published at runtime
    /// (NET-044) — what the `GetLiveIngress` RPC serves. Empty for a box that
    /// published none.
    LiveIngress(oneshot::Sender<Vec<minimald_rpc::LiveMapping>>),
    /// The attached human's answer to a runtime port-publish ask routed to
    /// them (NET-045), sent by the task [`Session::route_ask`] spawned —
    /// never by the actor itself, which must not park on a human. `None`
    /// means nobody was attached to answer, which is the ask's own
    /// fail-closed case rather than an error to report.
    ///
    /// Carries the ask's [`AskId`], not just its port: two asks can share a
    /// port, and an answer that arrived keyed only by that would pop whichever
    /// ask on it parked first — a late fail-closed answer would refuse the
    /// wrong asker while its dialog was still on screen.
    AskAnswered {
        id: AskId,
        port: u16,
        answer: Option<session_host::AskAnswer>,
    },
    /// Test-only inspection: an `Arc` clone of the held [`Composition`]
    /// (`None` in `Draft`, or `Active` without one post-restart). Lets tests
    /// assert composition contents without disturbing the lifecycle.
    #[cfg(test)]
    PeekComposition(oneshot::Sender<Option<Arc<Composition>>>),
    /// Test-only inspection: the ids of the runtime port-publish asks still
    /// parked on a human (NET-045), in route order, paired with their ports.
    /// Lets tests name the asks they answer out of band — the interleaving a
    /// racy hand-off failure can produce in production, reconstructed
    /// deterministically here — without disturbing the lifecycle.
    #[cfg(test)]
    PeekPendingAsks(oneshot::Sender<Vec<(AskId, u16)>>),
}

/// The key an ask parks under (NET-045): minted per request the session
/// routes, never derived from the port — two concurrent requests can share a
/// port. The ask's continuation ([`SessionMessage::AskAnswered`]) carries it
/// back, so an answer reaches the ask it answers even when another ask on the
/// same port is parked ahead of it, and a late fail-closed answer for an ask
/// that already ended does not pop its neighbour instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AskId(u64);

/// One runtime port-publish request this box decided `ask`, parked until the
/// attached human answers the dialog it was routed to (NET-045).
///
/// The caller's reply travels with it because the actor never answers the
/// request itself: it answers from [`Session::resume_ask`] once the human
/// has, or fail-closed from [`Session::stop_running`] when the session is
/// going away and nobody can. Keyed by [`AskId`] — the id the continuation
/// message carries back — so two asks for the same port each reach their own
/// asker however their answers arrive.
#[derive(Debug)]
struct PendingAsk {
    /// The ask's key: the id its continuation carries back.
    id: AskId,
    /// The port the box asked to publish.
    port: u16,
    /// The box's record as it stood when the ask was routed: the publish an
    /// allow ends up running needs the address pair the box's registration
    /// handed it, and it is the same record the decision was made against.
    record: Record,
    /// The box's name, resolved once at route time so the log line and the
    /// audit record (NET-046) name the same box the human's dialog named.
    box_name: String,
    /// The caller's reply, answered by whichever way the ask ended.
    reply: oneshot::Sender<Result<minimald_rpc::LiveMapping, crate::net::policy::ExposeFailure>>,
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

    /// The answerer's lease book for this host ([`SessionConfig::loopback`]):
    /// where the box's own host loopback address comes from at finalize and
    /// where it goes back at destroy. Every ask is a synchronous
    /// read-modify-write under the record's own lock file — never held across
    /// an `.await` — so the session needs no lock of its own around it and
    /// two daemons on one host cannot both be granted one address.
    #[cfg(target_os = "linux")]
    loopback: Arc<crate::net::dns::LoopbackLeaseBook>,

    /// The daemon-scoped gvproxy switch, injected into each `SandboxLauncher`
    /// this session mints so an `OwnIp` PTask attaches to the one per-host
    /// switch (R1.5). Read by the production `session_launcher`
    /// (`cfg(not(test))`), and by the runtime port-publish path, which drives
    /// the switch's forwarder through it (NET-043) in every build; the
    /// `cfg(test)` mock launcher ignores it for launches, so the
    /// unused-field lint is silenced under test rather than threaded through.
    #[cfg_attr(test, allow(dead_code))]
    net_switch: Arc<Mutex<crate::net::SwitchClient>>,

    /// The ports this box published at runtime with its own `min net expose`
    /// (NET-044): one entry per port the box's `dynamic_ingress` allowed and
    /// the switch accepted, held from the publish until the box stops, where
    /// [`Session::stop_running`] unbinds them — or until the spawn they
    /// deliver to ends, whose guard unbinds them beside its declared forwards
    /// (the cell is shared with it through the launch's
    /// [`crate::net::provider::OwnAddressReporter`]). A box that published
    /// none — and one that is not running — holds an empty list.
    live_ingress: crate::net::provider::RuntimeIngress,

    /// The runtime port-publish requests this box decided `ask`, parked until
    /// the attached human answers them (NET-045). Empty for a box with
    /// nothing waiting on a human; drained fail-closed by
    /// [`Session::stop_running`].
    pending_asks: Vec<PendingAsk>,

    /// The counter behind [`AskId`]: the actor mints one id per ask it parks,
    /// so ids are unique within the session and monotonic in route order —
    /// and carry no meaning beyond that.
    next_ask_id: u64,

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

    /// Whether this daemon opted out of the deny-all egress default
    /// (NET-077), threaded from the server config: the launcher resolves
    /// this session's effective egress (NET-074) against it, and the task
    /// path reads it through the handle for the same resolution.
    deny_all_opt_out: bool,

    /// The live direct-tcpip forwards opened for this session: one abort
    /// handle per relay the connection layer spawned. Pruned as relays
    /// finish; every live one is aborted by [`Session::stop_running`], so a
    /// session that goes away takes its forwards down with it (NET-105).
    forwards: Vec<tokio::task::AbortHandle>,
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
            deny_all_opt_out,
            #[cfg(target_os = "linux")]
            hostnames,
            #[cfg(target_os = "linux")]
            loopback,
        } = seed;
        Self {
            receiver,
            record,
            minimal_state_dir,
            minimal_cache_dir,
            daemon_ctx,
            net_switch,
            deny_all_opt_out,
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
            // Forwards are registered as their channels open; a session
            // starts with none.
            forwards: Vec::new(),
            // The same for the ports the box publishes at runtime: nothing is
            // live until a `min net expose` inside it lands (NET-044).
            live_ingress: Default::default(),
            // And for the asks routed to a human: nothing waits until a
            // request decided `ask` lands (NET-045), and the first of those
            // takes the first id.
            pending_asks: Vec::new(),
            next_ask_id: 0,
            #[cfg(target_os = "linux")]
            hostnames,
            #[cfg(target_os = "linux")]
            loopback,
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
        // One line per session start (NET-074/NET-076/NET-077): the rollout
        // phase this build ships, the daemon's opt-out state, and the
        // effective egress they leave this box with. The declaration
        // travels on the record; these three are the facts a reader of a
        // diagnostics bundle's daemon-log tail needs to explain why a box
        // can — or cannot — reach anything, without the daemon's flags or
        // its source at hand.
        {
            let record = obj.record();
            tracing::info!(
                session = %record.id,
                name = ?record.name,
                network = ?record.network,
                egress_default_phase = ?sessions::EGRESS_DEFAULT_PHASE,
                deny_all_opt_out = conf.deny_all_opt_out,
                effective_egress = ?sessions::effective_egress(
                    record.policy.egress.as_ref(),
                    record.network,
                    sessions::EGRESS_DEFAULT_PHASE,
                    conf.deny_all_opt_out,
                ),
                "session starts"
            );
        }
        // A weak self-handle so the actor can hand its own mailbox to the
        // runtime objects it spawns without a caller threading it in.
        let weak_self = WeakSessionHandle(sender.downgrade());
        let actor = Self::assemble(conf, receiver, inner, weak_self);

        // Register the PTask hostname before the actor goes live, so the
        // route exists by the time the caller can observe the session
        // (R3.1/R3.6). A `Draft` session has nothing to route to yet, so
        // `register_hostname` no-ops until its loadout finalizes.
        //
        // Never waiting on the range verdict (NET-123 §7.1): this runs
        // inside the manager's own message handling — the resume an RPC
        // naming the box brings up, the create, and the bring-up a destroy
        // makes to run its hooks — so a wait here would park every other
        // session's operation behind it. A resumed handed box the verdict
        // has not vouched for publishes at the `127.0.0.1` interim at once,
        // and the present landing's sweep moves it to its hand.
        #[cfg(target_os = "linux")]
        actor.register_hostname(obj.record(), false).await;

        tokio::spawn(actor.mainloop());
        Ok(SessionHandle(sender))
    }

    /// Register this session's PTask hostname (R3.1/R3.6). A HostNet PTask's
    /// listeners are on host loopback. An OwnIp PTask routes once the attach
    /// path has reported its lease — at spawn that report has not happened
    /// yet, so this registers nothing and the route appears when the box
    /// attaches (NET-001); on a rename or re-finalize the reported lease is
    /// already on file and the name re-registers against it, carrying the
    /// ports the session's ingress declaration publishes (NET-069) — an empty
    /// set, and so a deny-all gate, when the box declares no ingress: that is
    /// the posture its own relay gate gives a direct connection, and the
    /// proxy's must match on every host form (NET-071). A NoNet
    /// PTask exposes no services, so it is not registered — and neither is a
    /// `Draft` session, which has nothing to route to until its composition
    /// finalizes.
    ///
    /// An `OwnIp` PTask is also recorded as the *caller* a proxied request
    /// from it is checked against (NET-070): its egress declaration, over the
    /// switch its own relay is attached to, is kept until the box's lease
    /// joins onto it, and the rules built there are the ones its own outbound
    /// frames are decided by on the switch
    /// ([`crate::net::switch::compiled_egress`] over the switch's subnet, so
    /// the resolver carve-out matches too, and with the box's lease, so the
    /// verdict's source check does too — NET-084), so a request from the box
    /// through the hostname proxy meets its own declaration — exactly what a
    /// direct connection from it meets (NET-071).
    ///
    /// `wait_for_verdict` is whether a hand the range verdict has not
    /// vouched for may wait for it ([`Self::hand_or_interim`]): only the
    /// box's first finalize does, inside its own actor. Every other
    /// registration — the pre-live one [`Self::run`] makes from the
    /// manager's message handling, a rename — publishes such a hand at the
    /// `127.0.0.1` interim at once, and the present landing moves it.
    #[cfg(target_os = "linux")]
    async fn register_hostname(&self, record: &Record, wait_for_verdict: bool) {
        if !self.owns_hostname_route(record) {
            return;
        }
        let name = registry_name(record);
        // Scoped: the switch lock is dropped before the registry is taken, so
        // no path holds both.
        let subnet = self.net_switch.lock().await.subnet();
        match record.network {
            sessions::NetworkMode::OwnIp => {
                // NET-010/NET-011: finalize publishes the box's declaration
                // at a host loopback address of its own — the one the VM
                // host daemon handed the box's registration (T66), or one an
                // earlier finalize published and the registry kept by the
                // stable session id across a rename, a restart of the actor,
                // or a restart of the daemon — so the name answers from
                // here to destroy, whether or not a client ever attaches
                // (NET-013).
                //
                // A box nobody handed an address — a native launch, whose
                // creator is the daemon itself, or a VM lane whose client
                // spelled no provider to register with — is still owed a
                // publish (NET-040: a fresh install's `--network own_ip
                // --ingress` publishes on the host), so finalize asks the
                // answerer for one: the host-global allocation NET-010
                // names, arbitrated through the answerer's authenticated
                // channel, which no daemon self-assigns beside. The grant is
                // not the daemon choosing an address — the answerer's one
                // lease record chooses it, and the release at destroy hands
                // it back — and it is not a substitute either: it is asked
                // before any forwarder binds, so the binds and the name
                // answer at the one address it granted. A grant withheld for
                // a fault — a spent pool, an unreadable record — publishes
                // nothing and registers no name, and the attach of a box
                // that declared ingress fails with "no published address
                // handed" rather than binding forwards at an address nobody
                // granted; a grant withheld for the host's surface — an
                // absent range, a verdict still walking — publishes the box
                // on the `127.0.0.1` interim (NET-123), so the binds and
                // the name answer at the one address the host can listen
                // on.
                //
                // The address is asked for **before** the registry's write
                // lock, and never underneath it: the ask is a synchronous
                // read-modify-write of the answerer's record under its lock
                // file, and this daemon's registry is what every DNS answer
                // it serves reads — holding one across another daemon's
                // in-flight grant would stall the answers for the length of
                // the stall, and the registry is never held across the
                // record, so the two orders cannot cycle either way. A box
                // that already published one — a rename, a resume — is
                // answered from the registry alone, without asking, so no
                // ask is logged on its account — unless what it published is
                // one of the two publishes that are not the box's own
                // address: the `127.0.0.1` interim, and a reserved-range
                // address a landed verdict has since overruled. Those ask
                // again (the two filters below), so the interim cannot
                // outstay the window that made it and no box holds an
                // address the surface cannot bind; and two paths that both
                // miss and both ask are still safe, the ask idempotent by
                // namespace and answered with the address the first one
                // recorded.
                //
                // A VM-backed box publishes at the address the VM host
                // daemon handed its registration (T66) — the host's slice of
                // the reserved local range, not a grant this daemon's in-guest
                // book could hand out — so the handed address stands in for
                // the lease before the lease is ever asked for, and the
                // attach path's expose requests name exactly it as their
                // `local`. It is never drawn from the pool: the host-side
                // table's row owns it, so neither the grant's info line nor
                // the release at destroy runs for a handed box.
                //
                // The hand still goes through the verdict the host's publish
                // surface holds (NET-123 §7.1): the VM host daemon hands
                // slice addresses without measuring the loopback they bind
                // on — the root fix is the host daemon measuring before it
                // hands (#1818) — and on a host whose surface cannot bind
                // the range the hand names an address no bind will ever
                // hold. [`vouches_for`] is the gate, and only a **landed
                // present** verdict passes it: a pending one has measured
                // nothing, and the hand's own provenance (the host-side
                // row, which a resumed box keeps its address on, NET-013)
                // is a fact about who chose the address, not about the
                // surface it binds on. So a hand the verdict has not
                // vouched for is not published and not refused either —
                // the box's first finalize waits for the verdict to land,
                // bounded by the daemon's one verdict deadline
                // ([`Self::hand_or_interim`]), so the name publishes once
                // at its final address: at the hand when the walk lands
                // present inside the bound, at the interim when it lands
                // absent or never lands — and the present landing's sweep
                // upgrades an interim-standing handed box back to its own
                // hand when the verdict arrives late. Every other
                // registration publishes such a hand at the interim
                // without waiting. The recorded publish reads through the
                // same gate (the first filter above): a hand the landing
                // has since overruled does not survive in the registry
                // either.
                let (already_published, stood_on_interim) = {
                    let reg = self
                        .hostnames
                        .read()
                        .expect("hostname registry lock poisoned");
                    let standing = reg.published_own_address(record.id);
                    let kept = standing
                        // The verdict the book holds gates the recorded
                        // publish exactly as it gates the fresh hand below
                        // (NET-123): a publish that outlived the verdict
                        // that vouched for it — a landing has overruled it
                        // since — names an address the surface cannot bind,
                        // and the record's memory of it must not keep the
                        // box standing there. The ask below answers with
                        // the interim instead.
                        .filter(|address| self.loopback.vouches_for(*address))
                        // The `127.0.0.1` interim is the surface's answer,
                        // never an address the box owns, so a publish
                        // standing on it asks again: the walk's landing is
                        // the moment the ask upgrades to a grant — and a box
                        // the landing misses, because it was stopped across
                        // it, upgrades at this same ask — where a granted
                        // address is the box's own and keeps.
                        .filter(|address| *address != std::net::Ipv4Addr::LOCALHOST);
                    (kept, standing == Some(std::net::Ipv4Addr::LOCALHOST))
                };
                let handed = record
                    .box_addresses
                    .map(|addresses| addresses.loopback_address);
                let published = if already_published.is_some() {
                    already_published
                } else {
                    match handed {
                        // The hand goes through the verdict the host's
                        // publish surface holds (NET-123 §7.1) — under a
                        // verdict that has vouched for it, at the hand;
                        // under one that has not, at the interim, after the
                        // bounded wait a first finalize takes so the name
                        // does not publish twice. Never a grant: a hand is
                        // only ever replaced by `127.0.0.1`.
                        Some(hand) => Some(
                            self.hand_or_interim(
                                record,
                                &name,
                                hand,
                                wait_for_verdict,
                                stood_on_interim,
                            )
                            .await,
                        ),
                        None => self.lease_loopback_address(record, &name),
                    }
                };
                let mut reg = self
                    .hostnames
                    .write()
                    .expect("hostname registry lock poisoned");
                // The verdict re-read under the write lock: a present
                // landing that stored its verdict after the answer above
                // but before this lock may have run its sweep already —
                // which enumerated the registry without this publish — so a
                // handed box headed for the interim takes its hand here
                // instead of standing on the interim until its next
                // registration. The landing stores the verdict before its
                // sweep takes the registry, so either the sweep sees this
                // publish and moves it, or this re-read sees the verdict.
                // The box cannot have been destroyed under it: a destroy
                // runs through this session's own mailbox, after this
                // registration, and the hand is never released to a pool.
                let published = match promote_interim_to_hand(
                    &reg,
                    &self.loopback,
                    record.id,
                    &name,
                    published,
                    handed,
                ) {
                    Some(hand) => {
                        tracing::warn!(
                            session_id = %record.id,
                            session_name = &name,
                            from = %std::net::Ipv4Addr::LOCALHOST,
                            to = %hand,
                            action = "loopback-range-present-box",
                            "the verdict landed present while the box was \
                             registering; it publishes at its own hand, not \
                             the 127.0.0.1 interim"
                        );
                        Some(hand)
                    }
                    None => published,
                };
                reg.register_caller(record.id, &name, &record.policy, subnet);
                let declared = crate::net::switch::declared_request_ports(Some(&record.policy));
                if let Some(hand) = handed {
                    // The hand is the box's own address whether this
                    // publish lands at it or at the interim the wait's
                    // expiry stands it on: recorded so the present landing's
                    // sweep moves a handed box off the interim back to its
                    // own hand, never to a grant drawn from the pool.
                    reg.record_own_hand(record.id, hand);
                }
                if let Some(address) = published {
                    // One warn line per port another box at the same address
                    // also publishes (NET-129): intrinsic to the shared-address
                    // mode, reported — the session-start report — and never
                    // translated.
                    reg.publish_own_address(record.id, &name, address, declared.clone());
                }
                // A box whose grant was withheld registers no name: the
                // registry's own route is built only from a published
                // address, so `register_own_ip` leaves the name absent and
                // the attach path fails the box with the same fact.
                reg.register_own_ip(record.id, &name, declared);
            }
            sessions::NetworkMode::HostNet => {
                let mut reg = self
                    .hostnames
                    .write()
                    .expect("hostname registry lock poisoned");
                reg.register_host_net(record.id, &name);
            }
            _ => {}
        }
        // The cross-record collision report, at the moment the design puts it
        // (NET-010, design §7.1: cross-node collisions are reported at session
        // start, like a port collision) — the same moment the port collision
        // report above fires at, and the half the daemon's own start report
        // cannot cover: a grant another state root's daemon makes after this
        // one booted is one no report this daemon ran at its start will ever
        // see again. Outside the registry's lock, like the lease ask above:
        // the report is a read of the record under its lock file beside a
        // read of the kernel's socket table, and no DNS answer this daemon
        // serves waits behind it.
        if matches!(record.network, sessions::NetworkMode::OwnIp) {
            self.report_unrecorded_publishes();
        }
    }

    /// Resolves a hand to the address the box publishes at (NET-123 §7.1):
    /// the hand itself when the verdict vouches for it, the `127.0.0.1`
    /// interim when it does not — and never anything else. A hand is only
    /// ever replaced by the interim, so no grant is asked for a handed box:
    /// the hand is the host-side table's row, and the attach path's forwards
    /// name it as their `local`.
    ///
    /// With `wait_for_verdict` — the box's first finalize — a verdict still
    /// pending is waited for, bounded by the daemon's one verdict deadline
    /// ([`crate::net::dns::LoopbackLeaseBook::await_vouch_for`]), so the
    /// name publishes **once** at its final address rather than moving
    /// under the clients a live session already has. A verdict that lands
    /// present inside the bound vouches for the hand; one that lands absent,
    /// or a deadline that passes first, answers "not vouched". Without it
    /// the verdict is read as it stands. An unvouched hand publishes the
    /// interim, with the hand→interim move said out loud in one warn line
    /// naming the box and both addresses — once, not again on a
    /// re-registration of a box already standing there
    /// (`stood_on_interim`). The present landing's sweep upgrades a handed
    /// box standing at the interim back to its own hand when the verdict
    /// finally vouches for it
    /// ([`crate::sessions::land_range_verdict`]'s present arm).
    ///
    /// Called outside every registry lock, since the wait is async.
    #[cfg(target_os = "linux")]
    async fn hand_or_interim(
        &self,
        record: &Record,
        name: &str,
        hand: std::net::Ipv4Addr,
        wait_for_verdict: bool,
        stood_on_interim: bool,
    ) -> std::net::Ipv4Addr {
        let vouched = if wait_for_verdict {
            self.loopback.await_vouch_for(hand).await
        } else {
            self.loopback.vouches_for(hand)
        };
        if vouched {
            return hand;
        }
        if !stood_on_interim {
            tracing::warn!(
                session_id = %record.id,
                session_name = name,
                from = %hand,
                to = %std::net::Ipv4Addr::LOCALHOST,
                action = "loopback-hand-to-interim",
                "the hand's range is not vouched for by a landed present \
                 verdict; the box's publish — name and route with it — \
                 moves to the 127.0.0.1 interim, and the present landing \
                 upgrades it to the hand once the verdict vouches"
            );
        }
        std::net::Ipv4Addr::LOCALHOST
    }

    /// One warn line per reserved-range address a live publish holds on this
    /// host that the answerer's record for this daemon's state root does not
    /// name — the cross-record collision report (NET-010), at session start
    /// like a port collision, through the one emitter the daemon's own start
    /// report shares
    /// ([`warn_publish_collision`](crate::net::dns::warn_publish_collision))
    /// so the two read as one report in a diagnostics bundle's log tail.
    ///
    /// A box that publishes on the shared-address interim — a spent pool, an
    /// absent range, an unreadable record — starts too, and still gets the
    /// report: the addresses it names are other roots' grants, not this
    /// box's, and the moment the design asks for is this session's start.
    #[cfg(target_os = "linux")]
    fn report_unrecorded_publishes(&self) {
        for address in self.loopback.unrecorded_publishes() {
            crate::net::dns::warn_publish_collision(address);
        }
    }

    /// Asks the answerer for this box's host loopback address (NET-010) — a
    /// grant of the reserved local range, arbitrated through the host's one
    /// lease record — with the one info line the observability contract asks
    /// for per lease, naming the box and the address (the diagnostics
    /// bundle's log tail carries these beside each release).
    ///
    /// This is the ask a box nobody handed an address takes (NET-040: the
    /// daemon is the creator of its own native boxes, and a VM lane whose
    /// client spelled no provider to register with has no host-side creator
    /// either), and it is not the daemon choosing an address: the answerer's
    /// record is the host-global allocation NET-010 binds, the one
    /// authenticated channel every daemon on the host asks through.
    ///
    /// `None` — with the warn line that says why — for the two answers that
    /// are faults rather than facts about the host's surface: a spent pool
    /// and an unreadable record. The box then publishes nothing and registers
    /// no name, and the attach of a box that declared ingress fails with
    /// "no published address handed" rather than binding forwards at an
    /// address nobody granted — reported, never substituted.
    ///
    /// The two answers that are facts about the surface — the range absent,
    /// the verdict still walking its deferred window — publish the box on the
    /// `127.0.0.1` interim (NET-123's absent arm): the host can listen there
    /// whatever its `lo0` carries, so the box's declared ports are published
    /// and reachable instead of failing at an address the surface cannot
    /// bind. The interim is recorded as the box's own publish — the name
    /// routes at it and the attach binds its forwards at it — but it is the
    /// surface's answer, never an address the box owns, so it cannot outstay
    /// the window that made it: the walk's landing re-points the boxes
    /// standing on it when its verdict lands, and a finalize that finds one
    /// asks again rather than answering from the record. A grant the box
    /// already holds — a resumed session asking again after a restart —
    /// answers with the recorded address once a present verdict has landed,
    /// which is how a box's address stays stable across a daemon restart
    /// (NET-013); inside a restarted daemon's pending window it answers the
    /// interim, and the present landing restores the recorded address — no
    /// reserved-range address publishes under anything but a landed present.
    #[cfg(target_os = "linux")]
    fn lease_loopback_address(&self, record: &Record, name: &str) -> Option<std::net::Ipv4Addr> {
        let namespace = crate::net::dns::LeaseNamespace::Box { session: record.id };
        let granted = self.loopback.grant(namespace);
        match granted {
            crate::net::dns::LoopbackGrant::Granted(address) => {
                tracing::info!(
                    session_id = %record.id,
                    session_name = name,
                    ip = %address,
                    action = "loopback-lease",
                    "leased a host loopback address for the box's published ports"
                );
            }
            crate::net::dns::LoopbackGrant::PoolSpent => {
                tracing::warn!(
                    session_id = %record.id,
                    session_name = name,
                    action = "loopback-pool-spent",
                    "the host's reserved local range is spent; the box's \
                     declared ingress has no address to publish at"
                );
            }
            crate::net::dns::LoopbackGrant::RangePending => {
                tracing::warn!(
                    session_id = %record.id,
                    session_name = name,
                    action = "loopback-range-pending",
                    "the verdict over the reserved local range is still pending; \
                     the box's declared ingress publishes on the 127.0.0.1 interim \
                     until the publish-surface walk lands"
                );
            }
            crate::net::dns::LoopbackGrant::RangeAbsent => {
                tracing::warn!(
                    session_id = %record.id,
                    session_name = name,
                    action = "loopback-range-absent",
                    "the reserved local range is absent on this host's publish \
                     surface; the box's declared ingress publishes on the \
                     127.0.0.1 interim"
                );
            }
            crate::net::dns::LoopbackGrant::RecordUnavailable => {
                tracing::warn!(
                    session_id = %record.id,
                    session_name = name,
                    action = "loopback-record-unavailable",
                    "the answerer's lease record could not be read or written; \
                     the box's declared ingress has no address to publish at"
                );
            }
        }
        granted.publishable_address()
    }

    /// Returns a destroyed box's host loopback address to the host's pool
    /// (NET-010) — the publish's other half, at the same
    /// [`Self::lease_loopback_address`] that named the grant — with the one
    /// info line per release naming the box and the address.
    ///
    /// The answer is the record's, not the registry's: a box that holds a
    /// grant gets exactly that address back — even a box whose publish was
    /// lost to a restart leaves its grant here, so the record never outlives
    /// the session it names. No line at all — and no change — for a
    /// namespace the record does not name. A box whose address was handed
    /// from the host side (T66) never drew from this pool, so its record
    /// names no namespace and this is the no-op half for it.
    #[cfg(target_os = "linux")]
    fn release_loopback_address(&self, record: &Record, name: &str) {
        let namespace = crate::net::dns::LeaseNamespace::Box { session: record.id };
        if let Some(address) = self.loopback.release(namespace) {
            tracing::info!(
                session_id = %record.id,
                session_name = name,
                ip = %address,
                action = "loopback-release",
                "released a destroyed box's host loopback address back into the pool"
            );
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

    /// Withdraw this session's PTask hostname (R3.5), and — when the session
    /// is ending for good — drop its publish and its grant, so neither the
    /// registry nor the answerer's record outlives the box they pointed at:
    /// the address returns to the host's pool (NET-010) and every later
    /// lookup of the name answers NXDOMAIN (NET-012).
    ///
    /// A stop is not that: a stopped box still exists — its session record
    /// survives, and a resume brings the same box back — so `for_good` is
    /// the destroy paths' alone. A stop withdraws the name's route and
    /// keeps both halves of the publish, the registry's row and the
    /// answerer's grant (NET-013: the box's address is its own from
    /// finalize to destroy, and a stopped box that resumes must find the
    /// same address waiting, whether the same daemon or a restarted one
    /// answers — a stop that released the grant would hand the address to
    /// the next box to finalize and leave the resumed one published
    /// somewhere else). Shutdown stops every session the same way, which is
    /// how the grant a restarted daemon re-derives from the answerer's
    /// record is the very one the box held before the restart.
    ///
    /// Gated on [`Self::owns_hostname_route`] rather than relying on the
    /// registry's no-op behavior: the registry is keyed by name alone, so an
    /// ungated deregister from a session that never registered (`Draft`, or
    /// a non-routable mode) could withdraw an *unrelated* session's route
    /// that happens to share the same derived name. A rename withdraws with
    /// the grant and the publish kept: the re-register that follows it routes
    /// at the same box, on the same address (NET-001).
    ///
    /// The registry's lock is never held across the answerer's record — the
    /// same rule the grant path's [`Self::lease_loopback_address`] ask
    /// follows: the release is
    /// a synchronous read-modify-write of the record under its lock file,
    /// and this daemon's registry is what every DNS answer it serves reads,
    /// so no answer waits behind a destroyed box's release. The registry's
    /// rows go first, under the write lock alone, and the release runs after
    /// it is dropped — which is also the safe half of that order: while the
    /// record still names the grant, no other box can be handed the
    /// address, so there is no moment where the registry answers an address
    /// the pool already holds free.
    #[cfg(target_os = "linux")]
    async fn deregister_hostname(&self, for_good: bool) {
        let record = self.record.record().await.unwrap();
        if for_good {
            // NET-010: the destroyed box's publish is withdrawn first, and the
            // grant it held returns to the host's pool — the grant the
            // finalize made, released here so the next box may publish on it.
            // NET-012: the name goes with the publish, so every later lookup
            // answers NXDOMAIN rather than a stale address.
            {
                let mut reg = self
                    .hostnames
                    .write()
                    .expect("hostname registry lock poisoned");
                reg.unpublish_own_address(record.id);
                reg.forget_own_address(record.id);
            }
            self.release_loopback_address(&record, &registry_name(&record));
        }
        if !self.owns_hostname_route(&record) {
            return;
        }
        let mut reg = self
            .hostnames
            .write()
            .expect("hostname registry lock poisoned");
        reg.deregister(&registry_name(&record));
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
                // NET-013: a stop withdraws the name's route — the stopped
                // box is not answering for clients — but keeps the grant and
                // the registry's publish row: the session still exists, a
                // resume brings the same box back, and its address is its
                // own until destroy. Releasing here would let the next box
                // to finalize take the address and leave a resumed box
                // published somewhere else than before it stopped.
                #[cfg(target_os = "linux")]
                self.deregister_hostname(false).await;
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
                // destroyed session (R3.5). The session is ending for good, so
                // its lease fact goes with it.
                #[cfg(target_os = "linux")]
                self.deregister_hostname(true).await;
                let _ = r.send(self.record.clone().delete().await);
                return ControlFlow::Break(Teardown::ManagerInitiated);
            }
            SessionMessage::GetPatchesUploadLock(r) => {
                let _ = r.send(Arc::clone(&self.patches_upload_lock));
            }
            SessionMessage::GetHookScriptsUploadLock(r) => {
                let _ = r.send(Arc::clone(&self.hook_scripts_upload_lock));
            }
            SessionMessage::TrackForward(forward) => {
                // Prune the ones that have finished on their own, so the
                // list holds the live forwards and nothing else.
                self.forwards.retain(|h| !h.is_finished());
                self.forwards.push(forward);
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
            SessionMessage::ExposeDynamic { port, reply } => {
                // Answers the reply itself, or parks it with the ask it
                // routed to the attached human (NET-045) — either way this
                // handler is done with it.
                self.expose_dynamic(port, reply).await;
            }
            SessionMessage::LiveIngress(r) => {
                #[expect(
                    clippy::let_underscore_must_use,
                    reason = "the asker may already be gone; there is nothing to answer then"
                )]
                let _ = r.send(self.live_ingress_snapshot());
            }
            SessionMessage::AskAnswered { id, port, answer } => {
                self.resume_ask(id, port, answer).await;
            }
            SessionMessage::GetRecord(r) => {
                let _ = r.send(self.record.record().await.unwrap());
            }
            SessionMessage::GetNetSwitch(r) => {
                let _ = r.send(Arc::clone(&self.net_switch));
            }
            SessionMessage::GetDenyAllOptOut(r) => {
                #[expect(
                    clippy::let_underscore_must_use,
                    reason = "the asker may already be gone; there is nothing to answer then"
                )]
                let _ = r.send(self.deny_all_opt_out);
            }
            #[cfg(test)]
            SessionMessage::PeekComposition(r) => {
                let _ = r.send(match &self.inner {
                    SessionInner::Active { composition, .. } => composition.clone(),
                    SessionInner::Draft { .. } => None,
                });
            }
            #[cfg(test)]
            SessionMessage::PeekPendingAsks(r) => {
                #[expect(
                    clippy::let_underscore_must_use,
                    reason = "the asker may already be gone; there is nothing to answer then"
                )]
                let _ = r.send(
                    self.pending_asks
                        .iter()
                        .map(|ask| (ask.id, ask.port))
                        .collect(),
                );
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
                // The box's first finalize: the one registration that may
                // wait for the range verdict (NET-123 §7.1).
                #[cfg(target_os = "linux")]
                self.register_hostname(&record, true).await;
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
    /// loop unbounded would park the caller behind it forever.
    ///
    /// When the kill cannot be queued the loop is aborted. When the kill
    /// landed but the loop does not finish within `HOST_PROBE_TIMEOUT`, the
    /// task is detached rather than aborted so the `NetGuard` teardown at the
    /// end of `Host::mainloop` can still run once the loop drains.
    async fn kill_and_stop_loop(
        host: &session_host::HostHandle,
        task: &mut JoinHandle<Result<i32, std::io::Error>>,
        for_shutdown: bool,
    ) {
        let killed = host.kill(for_shutdown).await.is_ok();
        if !killed {
            // The kill could not be queued — the host is wedged past the
            // mailbox-capacity deadline. Abort the loop; the NetGuard
            // teardown in mainloop is skipped, but the host was already
            // unreachable.
            task.abort();
        } else if tokio::time::timeout(HOST_PROBE_TIMEOUT, &mut *task)
            .await
            .is_err()
        {
            // The kill landed but the loop did not finish within the
            // deadline. Detach rather than abort: the task continues
            // running and will run the NetGuard teardown at the end of
            // mainloop once it drains. Dropping the JoinHandle (when the
            // caller's `task` binding goes out of scope) detaches it.
            //
            // worker-iterate: declined CodeRabbit's "keep timed-out hosts
            // owned until cleanup is coordinated" finding. The suggested
            // change — retain the timed-out JoinHandle under supervision and
            // coordinate sandbox/NetGuard teardown before Destroy deletes the
            // session or terminal-triggered replacement mints a second host —
            // is a heavy architectural lift, not a behavior-preserving patch.
            // It would restructure `SessionInner` to hold and later await the
            // detached task and thread teardown coordination through both the
            // Destroy and replacement paths, a change that cannot be validated
            // here (the wedged-host scenario is not reproducible in this
            // environment) and that risks regressing the bounded-caller
            // response (`HOST_PROBE_TIMEOUT`) this function exists to
            // preserve. The detach-on-timeout trade-off is deliberate and
            // documented; full reclamation is a tracked follow-up.
        }
    }

    /// Publishes `port` for this box at runtime (NET-043): the request a
    /// process inside the box sends with its own `min net expose`, decided
    /// against the box's `dynamic_ingress` setting and — when it allows —
    /// bound on the switch and recorded as a live mapping (NET-044), which is
    /// what `min session policy` lists beside the declaration.
    ///
    /// Takes the caller's reply by value because it does not always answer it:
    /// a request the box decided `ask` is routed to the attached human
    /// (NET-045) and parked — with the reply — until they have answered, and
    /// the actor must not park with it, or every probe, read, and shutdown
    /// behind this one would wait on a human. The parked request comes back
    /// through [`SessionMessage::AskAnswered`]. Everything else is finished
    /// here, through [`Self::answer_expose`], which writes the one info line
    /// every request logs and the decision's own audit record (NET-046)
    /// beside it.
    ///
    /// The one path this actor cannot name a box on is a record that does not
    /// read — the box's name lives in it — so that path answers its own typed
    /// failure, and the env channel, which knows the name without the record,
    /// writes the info line that request owes the log.
    async fn expose_dynamic(
        &mut self,
        port: u16,
        reply: oneshot::Sender<
            Result<minimald_rpc::LiveMapping, crate::net::policy::ExposeFailure>,
        >,
    ) {
        use crate::net::policy::ExposeFailure;

        let record = match self.record.record().await {
            Ok(record) => record,
            // The request could not be read back to be decided, so no
            // decision was made and there is nothing to audit (NET-046): the
            // typed failure is the whole answer, and the env channel writes
            // the info line, naming the box from its own copy of the name.
            Err(e) => {
                #[expect(
                    clippy::let_underscore_must_use,
                    reason = "the asker may already be gone; there is nothing to answer then"
                )]
                let _ = reply.send(Err(ExposeFailure::RecordUnreadable { port, source: e }));
                return;
            }
        };
        let box_name = record.name.clone().unwrap_or_else(|| record.id.to_string());
        // The setting the request is evaluated against (NET-043), spelled the
        // way the record carries it: the deny-all default for a box that
        // declared nothing.
        let decision = record
            .policy
            .ingress
            .as_ref()
            .and_then(|ingress| ingress.dynamic_ingress)
            .unwrap_or(sessions::DynamicIngress::Deny);
        // The box's own setting decides first (NET-043), whatever asked: the
        // deny-all default when nothing was declared, the range gate under an
        // `allow`, and an `ask` handed to whoever is attached (NET-045).
        match crate::net::policy::dynamic_ingress_decision(record.policy.ingress.as_ref(), port) {
            Err(crate::net::policy::ExposeRefusal::AskNeedsAnswer) => {
                self.route_ask(record, box_name, port, reply).await;
            }
            decided => {
                // The only decision that passes the gate is the box's own
                // `allow`, so an `Ok` here is one; every other refusal was
                // made with the switch asked nothing (NET-047).
                let outcome = match decided {
                    Ok(_) => self.publish_exposed_port(&record, port).await,
                    Err(refusal) => Err(ExposeFailure::Refused(refusal)),
                };
                self.answer_expose(
                    &box_name,
                    port,
                    decision,
                    crate::audit::DecidedBy::BoxPolicy,
                    outcome,
                    reply,
                )
                .await;
            }
        }
    }

    /// Routes a runtime port-publish request the box decided `ask` to whoever
    /// is attached (NET-045): the host's binding renders the exit prompt's own
    /// dialog, and the human's answer decides the request.
    ///
    /// The ask itself runs off the actor, on a spawned task: the human's
    /// answer is the only bound it has, and parking the actor on it would
    /// hang `min session policy` reads, manager probes, and a daemon shutdown
    /// behind a dialog nobody may be looking at. It comes back as
    /// [`SessionMessage::AskAnswered`], which answers the parked reply.
    ///
    /// Nobody attached is not an error to route — it is the ask's own
    /// fail-closed answer, decided by the daemon, and it goes through the
    /// same continuation ([`Self::resume_ask`]) so every ask ends on the one
    /// path that writes the log line and the audit record (NET-046).
    async fn route_ask(
        &mut self,
        record: Record,
        box_name: String,
        port: u16,
        reply: oneshot::Sender<
            Result<minimald_rpc::LiveMapping, crate::net::policy::ExposeFailure>,
        >,
    ) {
        // The dialog needs a host with somebody attached to render it. No
        // host running means the same thing as nobody attached — there is no
        // human to ask — so it is answered fail-closed right here rather than
        // routed to a continuation that would only come back with the same
        // answer.
        let host = match &self.inner {
            SessionInner::Active {
                host: Some((host, _)),
                ..
            } => host.clone(),
            _ => {
                self.answer_expose(
                    &box_name,
                    port,
                    sessions::DynamicIngress::Ask,
                    crate::audit::DecidedBy::Daemon,
                    Err(crate::net::policy::ExposeFailure::Refused(
                        crate::net::policy::ExposeRefusal::AskNeedsAnswer,
                    )),
                    reply,
                )
                .await;
                return;
            }
        };
        // Minted before the park, not derived from the port: two asks can
        // share a port, and the continuation below keys on this so each
        // answer reaches the ask it answers however their answers arrive.
        let id = AskId(self.next_ask_id);
        self.next_ask_id += 1;
        self.pending_asks.push(PendingAsk {
            id,
            port,
            record,
            box_name,
            reply,
        });
        let weak = self.weak_self.clone();
        tokio::spawn(async move {
            let answer = host.ask_expose(port).await;
            // A session that already went away has already answered its
            // pending asks fail-closed (`stop_running`), so a handle that
            // will not promote is the normal end of a late answer.
            if let Some(handle) = weak.upgrade() {
                handle.ask_answered(id, port, answer).await;
            }
        });
    }

    /// Continues a parked runtime port-publish ask (NET-045) with the attached
    /// human's answer — or its absence, which is the ask's own fail-closed
    /// refusal. The ask is found by its [`AskId`], not its port: two asks can
    /// share a port, and the answer is whatever the task the *ask* routed
    /// came back with. The pending request's reply is answered here and its
    /// decision audited (NET-046), whichever way it went: an allow runs the
    /// publish half against the record the ask was routed with, a deny is the
    /// box's own deny answer in the human's hand, and nobody attached is the
    /// typed nobody-is-attached refusal the request ends with.
    async fn resume_ask(&mut self, id: AskId, port: u16, answer: Option<session_host::AskAnswer>) {
        let Some(position) = self.pending_asks.iter().position(|ask| ask.id == id) else {
            // The ask already ended another way — the session answered it
            // fail-closed on its way down — or the asker went away. Nothing
            // is waiting on this answer, and no decision changes: said at
            // info like the answer it failed to be, because an answer the
            // audit cannot account for is the line that explains the port
            // that did not publish.
            tracing::info!(
                id = id.0,
                port,
                "a runtime port-publish answer arrived with no ask waiting for it"
            );
            return;
        };
        let ask = self.pending_asks.remove(position);
        let outcome = match answer {
            // The human said allow: run the publish half. Everything that can
            // still refuse it runs there — a duplicate publish, a missing
            // address pair, a switch that would not bind — so even an
            // allowed ask can end refused, with the switch asked only now
            // (NET-047).
            Some(session_host::AskAnswer::Allowed) => {
                self.publish_exposed_port(&ask.record, ask.port).await
            }
            // The human said deny — or keyed a cancel (Ctrl-C, `q`, Escape),
            // which means the same thing: the box's own deny answer, now in
            // the human's hand. An input EOF is not this — a client that
            // went away did not answer — so it lands on the `None` below.
            Some(session_host::AskAnswer::Refused) => {
                Err(crate::net::policy::ExposeFailure::Refused(
                    crate::net::policy::ExposeRefusal::DeniedByPolicy,
                ))
            }
            // Nobody was attached to answer (NET-045's unwanted branch) — no
            // binding to render the dialog, or one that ended mid-dialog
            // without the human choosing, its reply sender dropped unsent: a
            // shed, a teardown, the host going away, an input EOF (the
            // client's channel going away with the dialog standing). The
            // typed refusal, decided by the daemon, because there was no
            // human deciding.
            None => Err(crate::net::policy::ExposeFailure::Refused(
                crate::net::policy::ExposeRefusal::AskNeedsAnswer,
            )),
        };
        let decided_by = match answer {
            Some(_) => crate::audit::DecidedBy::AttachedHuman,
            None => crate::audit::DecidedBy::Daemon,
        };
        self.answer_expose(
            &ask.box_name,
            ask.port,
            sessions::DynamicIngress::Ask,
            decided_by,
            outcome,
            ask.reply,
        )
        .await;
    }

    /// Finishes one runtime port-publish request (or one parked ask now
    /// answered): one info line naming the box, the port, the decision the
    /// box's `dynamic_ingress` setting made, who actually decided it, and the
    /// outcome — the line a diagnostics bundle's daemon log tail carries every
    /// request with — and the decision's own audit record (NET-046) written
    /// beside it, then the caller's answer.
    async fn answer_expose(
        &mut self,
        box_name: &str,
        port: u16,
        decision: sessions::DynamicIngress,
        decided_by: crate::audit::DecidedBy,
        outcome: Result<minimald_rpc::LiveMapping, crate::net::policy::ExposeFailure>,
        reply: oneshot::Sender<
            Result<minimald_rpc::LiveMapping, crate::net::policy::ExposeFailure>,
        >,
    ) {
        let (audited, reason) = match &outcome {
            Ok(mapping) => {
                tracing::info!(
                    name = %box_name,
                    port,
                    decision = %decision,
                    decided_by = %decided_by,
                    outcome = "published",
                    local = %mapping.local,
                    "dynamic ingress expose"
                );
                (crate::audit::DecisionOutcome::Published, None)
            }
            Err(crate::net::policy::ExposeFailure::Refused(refusal)) => {
                tracing::info!(
                    name = %box_name,
                    port,
                    decision = %decision,
                    decided_by = %decided_by,
                    outcome = "refused",
                    reason = %refusal,
                    "dynamic ingress expose"
                );
                (
                    crate::audit::DecisionOutcome::Refused,
                    Some(refusal.to_string()),
                )
            }
            Err(crate::net::policy::ExposeFailure::Publish { source, .. }) => {
                tracing::info!(
                    name = %box_name,
                    port,
                    decision = %decision,
                    decided_by = %decided_by,
                    outcome = "publish failed",
                    reason = %source,
                    "dynamic ingress expose"
                );
                (
                    crate::audit::DecisionOutcome::PublishFailed,
                    Some(source.to_string()),
                )
            }
            // Neither reaches this path: the record-read failure is answered
            // in [`Self::expose_dynamic`] before a decision exists, and
            // `ActorGone` is what the asker's handle answers when this actor
            // dropped before replying. Logged and audited all the same, so
            // the one-line-per-request promise holds whatever calls this.
            Err(
                failure @ (crate::net::policy::ExposeFailure::RecordUnreadable { .. }
                | crate::net::policy::ExposeFailure::ActorGone { .. }),
            ) => {
                tracing::info!(
                    name = %box_name,
                    port,
                    decision = %decision,
                    decided_by = %decided_by,
                    outcome = "refused",
                    reason = %failure,
                    "dynamic ingress expose"
                );
                (
                    crate::audit::DecisionOutcome::Refused,
                    Some(failure.to_string()),
                )
            }
        };
        crate::audit::append(
            self.minimal_state_dir.as_utf8_path().as_std_path(),
            &crate::audit::DecisionRecord {
                ts: chrono::Utc::now().to_rfc3339(),
                box_name: box_name.to_string(),
                port,
                decision,
                decided_by,
                outcome: audited,
                reason,
            },
        )
        .await;
        #[expect(
            clippy::let_underscore_must_use,
            reason = "the asker may already be gone; there is nothing to answer then"
        )]
        let _ = reply.send(outcome);
    }

    /// The actor's own answer to "is a box running behind this session": an
    /// `active` session holding a live host. A stopped box's record still
    /// reads `active`, but the actor resurrected for it holds no host — so
    /// this, not the record's status, is what a publish must consult (and
    /// what `IsBusy` consults for the same reason).
    fn has_live_host(&self) -> bool {
        matches!(
            &self.inner,
            SessionInner::Active { host: Some((h, _)), .. } if h.is_alive()
        )
    }

    /// The publish half of a runtime port-publish request (NET-043): the
    /// duplicate check, the address pair the publish needs, and the switch
    /// bind, run once the request is decided — by the box's own `allow` in
    /// [`Session::expose_dynamic`], or by the attached human's answer to an
    /// `ask` in [`Session::resume_ask`]. Everything the box can refuse
    /// without asking the switch runs first, so a refused request is refused
    /// with nothing bound and nothing asked (NET-047). Only then is the
    /// switch asked to bind, and the forwarder is recorded only once it
    /// accepted.
    async fn publish_exposed_port(
        &mut self,
        record: &Record,
        port: u16,
    ) -> Result<minimald_rpc::LiveMapping, crate::net::policy::ExposeFailure> {
        use crate::net::policy::{ExposeFailure, ExposeRefusal, expose_dynamic};

        // The port is published already, live, by this box: a second request
        // for it would double-bind the same address, so it is refused as the
        // duplicate it is.
        if self.live_ingress.publishes(port) {
            return Err(ExposeFailure::Refused(ExposeRefusal::AlreadyPublished(
                port,
            )));
        }

        // A publish needs a box standing behind it. A stopped box's record
        // still reads `active` — Stop keeps the grant, the publish row and
        // the record (NET-013) — but the actor this request reached holds no
        // host, and a forward bound for its lease would name an address
        // nothing answers for. Refused here, before the registry is read or
        // the switch asked anything, so a stopped box asks nothing and
        // holds nothing (NET-047); starting the box again is what fixes it.
        if !self.has_live_host() {
            return Err(ExposeFailure::Refused(ExposeRefusal::NotRunning));
        }

        // The publish rides the address the box's declared ports bind at and
        // its name answers at (NET-010): the hostname registry's published
        // own address, the one source the declared path reads too, through
        // `OwnAddressReporter::published_address`. Never the raw handed
        // loopback address: a hand the loopback verdict has not vouched for
        // publishes at the `127.0.0.1` interim (NET-123 §7.1), and a hand a
        // landed verdict overrules is moved off by the landing's sweep — the
        // registry row is the address that actually binds, so the runtime
        // publish and the declaration answer at the one address a connection
        // reaches. The hand's `switch_address` (T66) — or, for a native
        // host's self-allocated box, the lease its running PTask reported
        // (design §7.1) — is what the forward delivers to, and it is taken
        // from the record and the registry without preference between the
        // two ways a box came by it.
        //
        // The two halves are refused apart, so the box's `min net expose`
        // says which one is missing: nothing published is a capability gap —
        // the daemon has no default of its own to stand in with (NET-010),
        // so the request is refused rather than bound at an address nobody
        // chose for this box — while no lease is a box not attached yet,
        // which starting it fixes.
        let (loopback_address, switch_address) = {
            let registry = self
                .hostnames
                .read()
                .expect("hostname registry lock poisoned");
            let Some(published) = registry.published_own_address(record.id) else {
                return Err(ExposeFailure::Refused(ExposeRefusal::NoPublishedAddress));
            };
            let switch_address = match record.box_addresses {
                Some(addresses) => addresses.switch_address,
                None => {
                    let Some(lease) = registry.own_lease(record.id) else {
                        return Err(ExposeFailure::Refused(ExposeRefusal::NotAttached));
                    };
                    lease
                }
            };
            (published, switch_address)
        };
        // The lease is per-spawn: the registry keeps the last one reported
        // until the box is destroyed, so a spawn that has ended leaves it
        // behind. The runtime cell knows the spawn ended — its guard's
        // teardown detached it — and a forward to the dead lease would
        // deliver wherever the switch hands that address next.
        if self.live_ingress.is_detached() {
            return Err(ExposeFailure::Refused(ExposeRefusal::NotAttached));
        }

        let control = self.switch_control().await;
        let forwarder = match expose_dynamic(
            &control,
            loopback_address,
            switch_address,
            port,
            sessions::IpProto::Tcp,
            None,
        )
        .await
        {
            Ok(forwarder) => forwarder,
            Err(source) => return Err(ExposeFailure::Publish { port, source }),
        };
        // Recorded only now, with the switch's acceptance in hand: a publish
        // that failed leaves nothing in the list (NET-047), so the rows the
        // policy surfaces read never name a port the switch is not holding.
        // The liveness read and the record push are one synchronous step —
        // nothing is awaited between them — so the stopped-box answer and the
        // push cannot disagree, and `stop_running`'s unexpose sweep (which
        // runs in this actor's own turn, over `take_all`) stays complete: a
        // box that went down in the window the bind was in flight has its
        // just-bound forward unbound here instead of recorded, so nothing
        // outlives the lease it delivers to.
        let mapping = minimald_rpc::LiveMapping {
            local: forwarder.local().to_string(),
            internal_port: forwarder.internal_port(),
            proto: sessions::IpProto::Tcp,
            // A fact about the box's relay gate, not about the bind: the
            // serving handler fills it on every read, from the gate's
            // compile set. Stored as `Some(false)` here — never rendered
            // from the stored cell, and never the unknown `None` that a
            // reply from a daemon older than the field decodes as.
            pending: Some(false),
        };
        if !self.has_live_host() {
            crate::net::policy::remove_ingress(&control, &[forwarder]).await;
            return Err(ExposeFailure::Refused(ExposeRefusal::NotRunning));
        }
        if let Err(stale) = self
            .live_ingress
            .record(crate::net::provider::LiveIngressForward {
                forwarder,
                mapping: mapping.clone(),
            })
        {
            crate::net::policy::remove_ingress(&control, &[stale.forwarder]).await;
            return Err(ExposeFailure::Refused(ExposeRefusal::NotAttached));
        }
        Ok(mapping)
    }

    /// The switch's control channel, read off the daemon's shared switch under
    /// a lock held only for the two sync reads — never across the publish it
    /// feeds.
    async fn switch_control(&self) -> crate::net::policy::ControlChannel {
        let switch = self.net_switch.lock().await;
        match switch.transport() {
            crate::net::SwitchTransport::LocalSpawn => {
                crate::net::policy::ControlChannel::Unix(switch.control_socket())
            }
            crate::net::SwitchTransport::HostShuttle { cid, port } => {
                crate::net::policy::ControlChannel::Vsock { cid, port }
            }
        }
    }

    /// The live dynamic-ingress mappings, in publish order — the rows
    /// `min session policy` lists beside the declaration (NET-044).
    fn live_ingress_snapshot(&self) -> Vec<minimald_rpc::LiveMapping> {
        self.live_ingress.snapshot()
    }

    /// Tears down any runtime objects, such as the host or side ops. Shutdown
    /// of these objects is complete once awaited.
    ///
    /// `for_shutdown` is threaded to the host's kill so attached clients get
    /// the daemon-shutdown message (and a terminal reset) rather than a bare
    /// disconnect when the session dies because the daemon is going away.
    async fn stop_running(&mut self, for_shutdown: bool) {
        // The session's forwards relay into its box: a session that is going
        // away takes them with it, rather than leaving live relays pointed at
        // a box that is being torn down. Both teardown paths — `Stop` and
        // `Destroy` — come through here.
        for forward in std::mem::take(&mut self.forwards) {
            forward.abort();
        }

        // The ports the box published at runtime go with it too (NET-044):
        // unbind each forward the switch accepted, so a box that stops leaves
        // no live publish behind. Best-effort, like the declared forwards'
        // teardown — `remove_ingress` logs a failed unexpose and moves on,
        // since there is no caller left to propagate to.
        let forwarders = self.live_ingress.take_all();
        if !forwarders.is_empty() {
            let control = self.switch_control().await;
            crate::net::policy::remove_ingress(&control, &forwarders).await;
        }

        // Runtime port-publish asks still waiting on a human (NET-045) fail
        // closed with the typed nobody-is-attached refusal: a session that is
        // going away has no attached human to answer them, and no caller can
        // be left parked on a reply that will never come. The decision is
        // audited like every other (NET-046) — and a late answer from the
        // task the ask routed through finds no ask left to answer.
        for ask in std::mem::take(&mut self.pending_asks) {
            self.answer_expose(
                &ask.box_name,
                ask.port,
                sessions::DynamicIngress::Ask,
                crate::audit::DecidedBy::Daemon,
                Err(crate::net::policy::ExposeFailure::Refused(
                    crate::net::policy::ExposeRefusal::AskNeedsAnswer,
                )),
                ask.reply,
            )
            .await;
        }

        let inner = match &mut self.inner {
            SessionInner::Active { host, sops, .. } => Some((host.take(), std::mem::take(sops))),
            SessionInner::Draft { .. } => None,
        };
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
    /// the PTask hostname so `<new>.min.internal` routes and the old name
    /// stops (R3.6).
    async fn rename(&mut self, new_name: String) -> Result<(), std::io::Error> {
        let record = self.record.record().await?;

        // Renaming to the name the session already has is an error, not a
        // no-op: `save` deliberately treats same-id same-name as a no-op (a
        // status promotion re-saves an unchanged name), so without this guard
        // a rename-to-self would silently succeed and report a rename that
        // did not happen.
        if record.name.as_deref() == Some(new_name.as_str()) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!("session is already named `{new_name}`"),
            ));
        }

        // Withdraw the route under the pre-rename name before the record
        // mutates; re-register under the new name afterwards. Both calls
        // gate on this session actually owning a route, so a Draft/NoNet
        // rename never touches the registry. The lease fact stays: the
        // re-register routes at the same box (NET-001).
        #[cfg(target_os = "linux")]
        self.deregister_hostname(false).await;
        let mut new_record = record.clone();
        new_record.name = Some(new_name.clone());
        let written = self.record.write(new_record.clone()).await;

        // Re-register whichever name stuck (the new one on success, the old
        // one if the write was refused) so a failed rename never strands the
        // session without a route.
        #[cfg(target_os = "linux")]
        self.register_hostname(
            match &written {
                Ok(_) => &new_record,
                Err(_) => &record,
            },
            false,
        )
        .await;

        // Forward the new name to the running host so the shell's
        // `$MINIMAL_SESSION_NAME` is republished through the per-attach
        // environment channel. Best-effort: the record-side rename has
        // already succeeded, and a dead host drops the message silently.
        if written.is_ok()
            && let SessionInner::Active {
                host: Some((host, _)),
                ..
            } = &self.inner
        {
            host.rename(new_name).await;
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
                    Err(session_host::HostAttachError::Closed(channel, sz)) => {
                        // The host's loop has ended; mint a fresh one from the
                        // channel it handed back.
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
                    Err(session_host::HostAttachError::Timeout) => {
                        // The host is alive but its mailbox stayed full past
                        // the attach deadline. Re-minting here would abort a
                        // busy-but-healthy shell, orphaning its processes and
                        // skipping its NetGuard teardown. Refuse instead: the
                        // client can retry once the host drains.
                        Err(AttachError::SessionBusy)
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
    ///
    /// `for_hooks` says what the launch is *for*, which `phase` cannot say:
    /// the phase records the status-gate posture (an attach and a teardown
    /// hook launch are both `Attached`; finalize's activation launch is
    /// `Activating`), while this flag marks the launches minted only for
    /// lifecycle hooks, whose pty nobody reads. It is the launcher's to
    /// carry, so the launch-scoped decisions downstream (the
    /// unenforced-placement advisory) can tell a session start from a hook
    /// run.
    // Left positional: three call sites, each naming every argument it means,
    // so a struct would be ceremony rather than clarity.
    #[expect(
        clippy::too_many_arguments,
        reason = "three call sites, each naming every argument it means"
    )]
    async fn launch_host(
        &mut self,
        session_hnd: SessionHandle,
        conn_username: String,
        sz: WinSize,
        attach_env: session_host::AttachEnv,
        progress: Option<ChannelProgress>,
        phase: LaunchPhase,
        for_hooks: bool,
    ) -> Result<(Option<Channel<Msg>>, LaunchedHost), AttachError> {
        let record = self.record.record().await.unwrap();
        let paths = self.paths().await;
        // Kept before the launcher consumes `attach_env`: the launch folds
        // these into the shell's environment, and the host keeps them so it
        // can layer them onto everything it later runs in the session and
        // republish them for the shell to re-read.
        let connection_env = attach_env.connection_env();
        let launcher = self
            .session_launcher(session_hnd, &record, attach_env, phase, for_hooks)
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
                // The host owns the box's name-lifecycle half (NET-128): its
                // `mainloop` marks the name running on the way in and stopped
                // on the way out, so a shared-address name answers NODATA while
                // no host is alive to answer it.
                #[cfg(target_os = "linux")]
                name_marker: Some(session_host::NameMarker::new(
                    Arc::clone(&self.hostnames),
                    record.id,
                )),
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
                false,
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
                false,
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
                // This launch exists only so the hooks have namespaces to
                // join — a hook run, not a session start. See
                // [`Session::launch_host`].
                true,
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
        for_hooks: bool,
    ) -> Result<session_host::SandboxLauncher, AttachError> {
        // R2.1: reject a policy that is incompatible with the network mode
        // (e.g. ingress forwards on a non-`OwnIp` PTask) before launching the
        // host.
        record
            .validate_policy()
            .map_err(AttachError::InvalidPolicy)?;
        let network_mode = record.network;
        // Only an `OwnIp` PTask attaches to the switch, so the policy's relay
        // halves — egress verdict and ingress forwards — are only consumed in
        // that mode. `validate_policy` rejects egress rules only on `NoNet`: a
        // host-address box may carry them (NET-120), and such a box never
        // reaches the relay. Only the ingress half is own-address-only, and
        // `validate_policy` has already rejected it on any other mode.
        //
        // NET-074: the gate enforces the *effective* egress — an absent
        // section on an own-address box is the deny-all section once the
        // default is in force, this daemon's opt-out excepted (NET-077) —
        // while the record keeps the declaration untouched for the strict
        // `GetSessionPolicy` reply.
        let policy = effective_session_policy(
            &record.policy,
            record.network,
            sessions::EGRESS_DEFAULT_PHASE,
            self.deny_all_opt_out,
        );
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
            policy,
            // The attach reports the lease through this, so the box's
            // `<name>.min.internal` proxy route exists exactly while the box
            // does (NET-001).
            // It carries the box's runtime-publish cell too, so the spawn's
            // guard unbinds those forwards with its declared ones (NET-044).
            own_address: Some(
                crate::net::provider::OwnAddressReporter::new(
                    Arc::clone(&self.hostnames),
                    record.id,
                )
                .with_runtime_ingress(self.live_ingress.clone()),
            ),
            // The addresses the VM host daemon handed this box's registration
            // (T66), persisted on the record: the `OwnIp` attach reuses the
            // handed switch address instead of drawing one the host-side row
            // would not match — including on a re-attach after a restart,
            // where the record is the only thing that still knows it.
            box_addresses: record.box_addresses,
            composition: self.composition(),
            // A weak handle so in-sandbox `min build` can drive session
            // side-ops without keeping the actor alive past teardown.
            session: session.downgrade(),
            // What this launch is for; see [`Session::launch_host`].
            for_hooks,
            // The classifier tree the privileged step installs natively and
            // the guest's own boot mounts; see the field's doc.
            classifier_root: std::path::PathBuf::from(sandbox2::classifier::TREE_ROOT),
            // The mount table the launch's classifier facts answer over is
            // the daemon's own, read live on every launch; see the field's
            // doc.
            classifier_mountinfo: None,
        })
    }

    /// Under test, swap in a mock launcher that runs a plain host process wired
    /// to the pty, exercising the session-host runtime without building a real
    /// sandbox (which needs packages unavailable in the unit-test tempdir).
    ///
    /// Kept separate from the production launcher: the two return *different*
    /// launcher types (`SandboxLauncher` vs `MockLauncher`), each with its own
    /// `SessionProcess`/`SessionGuard` associated types, and `SessionLauncher`
    /// is not object-safe — merging them would force a boxed/dyn launcher
    /// through the production spawn path.
    #[cfg(test)]
    async fn session_launcher(
        &mut self,
        _session: SessionHandle,
        record: &Record,
        _attach_env: session_host::AttachEnv,
        _phase: LaunchPhase,
        _for_hooks: bool,
    ) -> Result<session_host::MockLauncher, AttachError> {
        // Mirror the production R2.1 gate so test launches reject a
        // policy/network-mode mismatch the same way production does.
        record
            .validate_policy()
            .map_err(AttachError::InvalidPolicy)?;
        Ok(session_host::MockLauncher::default())
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

    /// The default `minimal.toml` [`Self::scaffold_mfile_if_missing`] writes.
    ///
    /// Production: `op::InitProject` detects the workspace's stack against the
    /// default package repo, whose branch head it resolves over the network.
    ///
    /// Under `test`/`test-support`: stand in for that network round-trip. Tests
    /// run offline, and what they need from the scaffold is that it lands before
    /// the composition — not what stack detection would have picked. The two
    /// packages are what `op::InitProject` falls back to when nothing matches.
    fn default_mfile_plan(
        &self,
        wsp: &DaemonAbsPath,
    ) -> Result<(std::path::PathBuf, String), String> {
        #[cfg(any(test, feature = "test-support"))]
        {
            Ok((
                wsp.as_utf8_path()
                    .join(mfile::MFILE_NAME)
                    .into_std_path_buf(),
                "[session]\npackages = [\"base\", \"vim\"]\n".to_string(),
            ))
        }
        #[cfg(not(any(test, feature = "test-support")))]
        {
            let config = self.workspace_config(wsp)?;

            use op::ProjectOp as _;
            let mut env = mctx::ProjectSetup::for_init(config).map_err(|e| e.to_string())?;
            let plan = op::InitProject.run(&mut env).map_err(|e| e.to_string())?;

            Ok((plan.toml_path, plan.content))
        }
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

    /// Publishes `port` for this box at runtime (NET-043) — the request the
    /// in-box `min net expose` sends, decided against the box's
    /// `dynamic_ingress` setting. Answers with the published mapping, or the
    /// typed reason the request was refused. A dead actor is its own typed
    /// failure — `ActorGone`, not `Publish` — because it never reached the
    /// bind: the box that would own the mapping is gone, so no publish was
    /// attempted and none could be reported as failed.
    pub(crate) async fn expose_dynamic(
        &self,
        port: u16,
    ) -> Result<minimald_rpc::LiveMapping, crate::net::policy::ExposeFailure> {
        let (send, recv) = oneshot::channel();
        // Ignore send errors - the recv will also fail.
        #[expect(
            clippy::let_underscore_must_use,
            reason = "the actor may already be gone; the recv below reports that"
        )]
        let _ = self
            .0
            .send(SessionMessage::ExposeDynamic { port, reply: send })
            .await;
        match recv.await {
            Ok(reply) => reply,
            Err(_) => Err(crate::net::policy::ExposeFailure::ActorGone { port }),
        }
    }

    /// Continues a parked runtime port-publish ask (NET-045) with the attached
    /// human's answer, or its absence — sent by the task
    /// [`Session::route_ask`] spawned, never by the actor itself. Keyed by the
    /// ask's [`AskId`] so the answer reaches the ask it answers. Best-effort
    /// by shape: a session that has already stopped has answered its asks
    /// fail-closed, so a message that does not land is the normal end of a
    /// late answer, not a loss.
    pub(crate) async fn ask_answered(
        &self,
        id: AskId,
        port: u16,
        answer: Option<session_host::AskAnswer>,
    ) {
        #[expect(
            clippy::let_underscore_must_use,
            reason = "the session may already be gone; its asks were answered fail-closed then"
        )]
        let _ = self
            .0
            .send(SessionMessage::AskAnswered { id, port, answer })
            .await;
    }

    /// Test-only: the ids of the runtime port-publish asks still parked on a
    /// human (NET-045), in route order, paired with their ports. Lets a test
    /// answer a specific ask through [`Self::ask_answered`] — the same path
    /// the routed task's answer takes — without guessing which park it
    /// reached.
    #[cfg(test)]
    pub(crate) async fn pending_ask_ids(&self) -> Vec<(AskId, u16)> {
        let (send, recv) = oneshot::channel();
        #[expect(
            clippy::let_underscore_must_use,
            reason = "the actor may already be gone; an empty peek is the honest answer then"
        )]
        let _ = self.0.send(SessionMessage::PeekPendingAsks(send)).await;
        // A dead actor has no asks parked, and `Vec`'s default says exactly
        // that — which is also the truth about a session that stopped, since
        // `stop_running` answered them all fail-closed first.
        recv.await.unwrap_or_default()
    }

    /// The live dynamic-ingress mappings this box published at runtime
    /// (NET-044) — the rows `min session policy` lists. Empty for a box that
    /// published none. A dead actor maps to `NotConnected`.
    pub(crate) async fn live_ingress(
        &self,
    ) -> Result<Vec<minimald_rpc::LiveMapping>, std::io::Error> {
        let (send, recv) = oneshot::channel();
        // Ignore send errors - the recv will also fail.
        #[expect(
            clippy::let_underscore_must_use,
            reason = "the actor may already be gone; the recv below reports that"
        )]
        let _ = self.0.send(SessionMessage::LiveIngress(send)).await;
        #[expect(
            clippy::map_err_ignore,
            reason = "a closed oneshot carries no cause beyond the actor being gone"
        )]
        recv.await.map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::NotConnected, "session actor is gone")
        })
    }

    /// Whether this daemon opted out of the deny-all egress default
    /// (NET-077), for the task path's effective-egress resolution. A dead
    /// actor maps to `NotConnected`.
    pub(crate) async fn deny_all_opt_out(&self) -> Result<bool, std::io::Error> {
        let (send, recv) = oneshot::channel();
        // Ignore send errors - the recv will also fail.
        #[expect(
            clippy::let_underscore_must_use,
            reason = "the actor may already be gone; the recv below reports that"
        )]
        let _ = self.0.send(SessionMessage::GetDenyAllOptOut(send)).await;
        #[expect(
            clippy::map_err_ignore,
            reason = "a closed oneshot carries no cause beyond the actor being gone"
        )]
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

    /// Registers a forward relay with the session it forwards for, so the
    /// session aborts it at teardown.
    ///
    /// Best-effort by design: a send error means the session actor is
    /// already gone, in which case the relay is about to learn the same
    /// thing its client does — there is no session to outlive. The
    /// connection layer ignores the outcome.
    pub async fn track_forward(&self, forward: tokio::task::AbortHandle) {
        // Ignore send errors - a session that is gone has nothing left to
        // track, and the forward ends with it.
        let _ = self.0.send(SessionMessage::TrackForward(forward)).await;
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

    /// A handle to a stand-in "actor" that answers each expose request with
    /// the next of `answers`, and drops the reply channel for any request
    /// past them — the dead-actor path no live actor can be made to take on
    /// demand. Test-only: lets the env channel's tests drive the typed
    /// failures [`SessionHandle::expose_dynamic`] hands back, without
    /// standing up a session whose publish genuinely fails. The stand-in
    /// keeps its strong sender alive for the test's runtime, so `upgrade()`
    /// holds; only messages it answers reach a reply.
    #[cfg(test)]
    pub(crate) fn answering(
        answers: Vec<Result<minimald_rpc::LiveMapping, crate::net::policy::ExposeFailure>>,
    ) -> Self {
        let (tx, mut rx) = mpsc::channel::<SessionMessage>(1);
        let weak = tx.downgrade();
        tokio::spawn(async move {
            // Hold the strong sender for the runtime the test lives in:
            // without a live sender the channel closes and the asker's
            // `upgrade()` fails before any answer is reached.
            let _hold = tx;
            let mut answers = answers.into_iter();
            while let Some(message) = rx.recv().await {
                // Past the script, no answer is sent: `reply` drops
                // unanswered, which the asker types as the actor being gone.
                if let SessionMessage::ExposeDynamic { reply, .. } = message
                    && let Some(answer) = answers.next()
                {
                    #[expect(
                        clippy::let_underscore_must_use,
                        reason = "the asker whose request was answered is the env \
                                  channel, which has no use for a send receipt"
                    )]
                    let _ = reply.send(answer);
                }
            }
        });
        Self(weak)
    }
}

/// The write-lock promotion of a registration headed for the interim: the
/// hand to publish instead of `127.0.0.1` when the verdict now vouches for
/// it, or `None` to keep `published` as it stands. Called under the
/// registry's write lock, so the verdict and the name are read together
/// with the publish that follows. Only a publish standing at the interim
/// with a hand behind it moves, and never over a name another session holds.
fn promote_interim_to_hand(
    reg: &crate::net::dns::HostnameRegistry,
    book: &crate::net::dns::LoopbackLeaseBook,
    session_id: sessions::SessionId,
    name: &str,
    published: Option<std::net::Ipv4Addr>,
    handed: Option<std::net::Ipv4Addr>,
) -> Option<std::net::Ipv4Addr> {
    match (published, handed) {
        (Some(std::net::Ipv4Addr::LOCALHOST), Some(hand))
            if book.vouches_for(hand) && !reg.name_held_by_another(session_id, name) =>
        {
            Some(hand)
        }
        _ => None,
    }
}

// `pub(crate)`: the env channel's tests reach the stand-in forwarder and the
// session fixtures this module owns, so a reply's honesty is read against a
// real session's publish rather than a parallel fixture of it; and the
// session-host tests, which host the runtime port-publish ask tests (NET-045)
// and drive them through the session actor's own flow, reuse them too.
#[cfg(test)]
pub(crate) mod tests;
