use crate::box_ops::{
    BuildUpdate, CheckOpts, CheckUpdate, MaterializeOpts, MaterializeUpdate, SideOp,
};
use crate::channel_progress::ChannelProgress;

use crate::box_manager::{BoxControl, WeakBoxManagerHandle, composables};
use crate::store::BoxRecordHandle;
use crate::{
    ChannelConfig,
    box_runtime::{self, HostAttrs, WinSize},
    workspace_delta::{self, DeltaSource},
};
use boxes::keys::SessionKeys;
use boxes::wire::request::ContributionResponse;
use boxes::{
    BoxState, Record,
    core::compose::Composition,
    daemon::composer::{ComposeOutcome, PendingComposeState, resume_from_verdict},
    store::{BoxObject, DiskBox},
    wire::request::{BoxStep, ContributionVerdict, WireContribution},
};
use common::SpecHash;
use mctx::ConfigBuilder;
use ot::OpTracker;
use paths::DaemonAbsPath;
use russh::{Channel, server::Msg};
use std::collections::HashSet;
use std::fmt::{self};
use std::ops::ControlFlow;
use std::sync::Arc;
#[cfg(target_os = "linux")]
use std::sync::RwLock;
use tokio::sync::{Mutex, mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

mod helpers;

/// How many sessions may run their `on_destroy` hooks at once, daemon-wide.
/// A destroy used to run on the session manager's loop, one at a time; off
/// it (inbox#710) nothing else bounds how many sandboxed hook runs a caller
/// that destroys many sessions at once can drive. Past this a destroy waits
/// for a slot, its session still in the manager's tearing-down set.
const DESTROY_HOOK_RUNS_MAX: usize = 4;

/// The slots [`DESTROY_HOOK_RUNS_MAX`] counts.
static DESTROY_HOOK_RUNS: tokio::sync::Semaphore =
    tokio::sync::Semaphore::const_new(DESTROY_HOOK_RUNS_MAX);

// The per-message span names: a file of its own, because the daemon's refusal guard scans the
// string literals of this module's files for RPC names (crates/minimal/src/tests.rs), and span
// names are not refusals. The guard skips kind.rs.
mod kind;

// The actor's concerns, one file each. The actor type, its loop and its
// messages stay here.
mod attach;
// BEP-015: the git credential helper a GitHub grant box carries.
pub(crate) mod bep_git_helper;
mod handle;
mod host;
mod launcher;
mod naming;
mod ports;
mod setup;

pub(crate) use attach::*;
pub(crate) use handle::*;
pub(crate) use helpers::*;
pub(crate) use host::*;
use launcher::*;
pub(crate) use ports::*;
pub(crate) use setup::*;

/// The paths on the daemon relevant to a session's internals.
#[derive(Debug)]
pub struct BoxPaths {
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

/// Everything a [`BoxActor`] actor needs at spawn time. Every session actor
/// is spawned through [`BoxActor::run`] with one of these, whether it is
/// backed by a freshly allocated record (the `CreateSession` path) or an
/// existing one being brought up from disk (the `GetSession` path); what the
/// session *is* comes from its record, not from the spawn site.
pub(crate) struct BoxActorConfig {
    pub minimal_state_dir: DaemonAbsPath,
    pub minimal_cache_dir: DaemonAbsPath,
    pub daemon_ctx: Arc<mctx::DaemonContext>,

    /// Handle to this session's record.
    pub record: BoxRecordHandle,
    /// Handle to the session manager, powers operations initiated within the session.
    pub manager: WeakBoxManagerHandle,

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
    /// The liveness of the connection that created this session over
    /// `CreateSession`, or `None` for a session brought up any other way
    /// (from disk, or by an in-process caller). See `BoxActor::creator`.
    pub creator: Option<std::sync::Weak<()>>,
}

/// Lifecycle-dependent state of a session actor: the multi-step create flow
/// as a state machine. Session-lifetime state (record snapshot, dirs,
/// tracker, handles) lives on [`BoxActor`] itself.
#[derive(Debug)]
enum BoxInner {
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

enum BoxMessage {
    GetPaths(oneshot::Sender<BoxPaths>),
    MakeContext(oneshot::Sender<Result<mctx::Context, String>>),
    Attach(
        oneshot::Sender<Result<(), AttachError>>,
        BoxHandle,
        String,
        Channel<Msg>,
        ChannelConfig,
        /// The attaching connection's liveness, see [`BoxActor::creator`].
        Option<std::sync::Weak<()>>,
    ),
    /// Hand back this session's host, minting one — with no channel bound to
    /// it — if the session has none running. Used by the exec path, which runs
    /// a command inside the session's sandbox and so needs the sandbox up, but
    /// has no terminal to attach and nothing to render progress to.
    EnsureHost(
        oneshot::Sender<Result<box_runtime::HostHandle, AttachError>>,
        BoxHandle,
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
            oneshot::Sender<Result<BoxStep, std::io::Error>>,
        )>,
    ),
    /// Promote a `Materializing` session to `Active`, gating on the
    /// patches-ready marker under `<workspace>/patches/`. Idempotent
    /// on an already-`Active` session; refused with `InvalidInput`
    /// on `Pending` (configure the loadout first).
    Finalize(oneshot::Sender<Result<minimald_rpc::FinalizeSessionResponse, std::io::Error>>),
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
    /// Test-only: park the actor for the duration, holding its mailbox the
    /// way a long inline message does. The sender is answered as the park
    /// begins, so a test knows every earlier message, and the publish that
    /// follows it, is done.
    #[cfg(test)]
    Park(std::time::Duration, oneshot::Sender<()>),
    /// Shutdown-stop: kill the host (if any), withdraw the hostname, and stop
    /// the actor — the on-disk record is kept.
    Stop(oneshot::Sender<()>),
    /// Full teardown: like [`Stop`](Self::Stop), but also deletes the on-disk
    /// record.
    Destroy(oneshot::Sender<Result<Vec<String>, std::io::Error>>),
    /// [`Self::Destroy`] for a session that has not finished activating:
    /// `Ok(None)` and nothing done when the record is `Active`. Decided here,
    /// in mailbox order, so a finalize ahead of it ends first (inbox#690).
    DestroyIfUnfinalized(oneshot::Sender<Result<Option<Vec<String>>, std::io::Error>>),
    GetRecord(oneshot::Sender<Record>),
    /// The daemon's shared gvproxy switch, reached through the session because
    /// that is the handle the task path holds.
    GetNetSwitch(oneshot::Sender<Arc<Mutex<crate::net::SwitchClient>>>),
    /// Whether this daemon opted out of the deny-all egress default
    /// (NET-077), read by the task path so a task resolves its session's
    /// effective egress (NET-074) the same way the launcher does.
    GetDenyAllOptOut(oneshot::Sender<bool>),
    /// Hand back the session's composition, if it has one. Sourced from
    /// the persisted snapshot: `BoxActor::run` loads it at spawn, so this
    /// answers for an actor brought up from disk after a restart.
    GetComposition(oneshot::Sender<Option<Arc<Composition>>>),
    /// Hand back an `Arc` clone of this session's patches-upload lock, see
    /// [`BoxActor::patches_upload_lock`].
    GetPatchesUploadLock(oneshot::Sender<Arc<Mutex<()>>>),
    /// Hand back an `Arc` clone of this session's hook-scripts-upload lock,
    /// see [`BoxActor::hook_scripts_upload_lock`].
    GetHookScriptsUploadLock(oneshot::Sender<Arc<Mutex<()>>>),
    /// Mark one `WorkspaceFilesTarZst` upload into this session as
    /// started (true) or finished (false), see
    /// [`BoxActor::workspace_uploads_in_flight`]. The ack fires once the
    /// actor has applied the change, so a Begin is visible to an attach
    /// before the upload pulls its first byte. It carries whether the
    /// change was applied: a Begin is refused unless the session is still
    /// unconfigured (`Draft { pending: None }`), since an upload comes
    /// before the configure in the create flow. One already composed and
    /// awaiting its verdict is refused too: the upload would change the
    /// tree under a composition already computed. `configure_loadout`
    /// holds the other side, refusing while any upload is in flight.
    SetWorkspaceUploadInFlight(bool, oneshot::Sender<bool>),
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
    /// A shared-address port this box took over while another box held it
    /// (NET-129): bind its forward now if the box is running, so the port
    /// is served without waiting for the box's next attach. Sent by the
    /// sessions manager for each hand-over the name registry makes.
    #[cfg(target_os = "linux")]
    BindHandedPort {
        address: std::net::Ipv4Addr,
        port: u16,
    },
    /// The live dynamic-ingress mappings this box published at runtime
    /// (NET-044), by the surface that published them — what the
    /// `GetLiveIngress` RPC serves. Empty for a box that published none.
    LiveIngress(oneshot::Sender<LiveIngressRows>),
    /// The attached human's answer to a runtime port-publish ask routed to
    /// them (NET-045), sent by the task [`BoxActor::route_ask`] spawned —
    /// never by the actor itself, which must not park on a human.
    /// [`AskEnd::Unanswered`] means nobody was attached to answer, which is
    /// the ask's own fail-closed case rather than an error to report.
    ///
    /// Carries the ask's [`AskId`], not just its port: two asks can share a
    /// port, and an answer that arrived keyed only by that would pop whichever
    /// ask on it parked first — a late fail-closed answer would refuse the
    /// wrong asker while its dialog was still on screen.
    AskAnswered {
        id: AskId,
        port: u16,
        answer: AskEnd,
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
    /// Test-only inspection: clones of the box's shared runtime ingress cell
    /// and publication set, the two a spawn's end reaches without going
    /// through this actor — so a test can end the spawn while the actor is
    /// mid-turn, the way the spawn's guard does in production.
    #[cfg(test)]
    PeekIngressCells(
        oneshot::Sender<(
            crate::net::provider::RuntimeIngress,
            crate::net::listeners::BoxPublications,
        )>,
    ),
    /// Test-only: turn on the finalize package check that test builds leave
    /// off (see [`BoxActor::check_packages_at_finalize`]), bounded by the
    /// carried deadline — [`PACKAGE_CHECK_DEADLINE`] for the production
    /// bound, shorter to exercise the expiry path. Acknowledged once set,
    /// so a finalize sent after the ack sees it.
    #[cfg(test)]
    CheckPackagesAtFinalize(std::time::Duration, oneshot::Sender<()>),
    /// Test-only: drop the compose-time graph names, as an actor restored
    /// from disk lacks them, so the finalize check takes its fallback and
    /// evaluates the graph itself. Acknowledged once dropped.
    #[cfg(test)]
    ForgetComposedGraphNames(oneshot::Sender<()>),
    /// Test-only: acknowledge on the first sender, then hold the actor in
    /// this message until the receiver fires or its sender drops, so a test
    /// can queue messages behind it in a known order.
    #[cfg(test)]
    HoldUntil(oneshot::Sender<()>, oneshot::Receiver<()>),
}

/// Manages one session, from the moment its record is allocated: the create
/// flow (compose → `Draft` → verdict → `Active`) runs as the
/// [`BoxInner`] state machine, and the actor owns its record's writes
/// and deletion, its PTask hostname, its held composition, and its host.
///
/// Follows the actor pattern.
#[derive(Debug)]
pub struct BoxActor {
    receiver: crate::traced::Receiver<BoxMessage>,
    /// The slot this actor's handle reads its host from; see [`HostSlot`].
    host_slot: HostSlot,
    minimal_state_dir: DaemonAbsPath,
    minimal_cache_dir: DaemonAbsPath,
    daemon_ctx: Arc<mctx::DaemonContext>,

    /// Store-backed handle to this session's record.
    record: BoxRecordHandle,

    /// The daemon's shared PTask hostname registry (see
    /// [`SessionSeed::hostnames`]). The lock is only ever held for a
    /// synchronous register/deregister, never across an `.await`.
    #[cfg(target_os = "linux")]
    hostnames: Arc<RwLock<crate::net::dns::HostnameRegistry>>,

    /// The answerer's lease book for this host ([`BoxActorConfig::loopback`]):
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
    /// [`BoxActor::stop_running`] unbinds them — or until the spawn they
    /// deliver to ends, whose guard unbinds them beside its declared forwards
    /// (the cell is shared with it through the launch's
    /// [`crate::net::provider::OwnAddressReporter`]). A box that published
    /// none — and one that is not running — holds an empty list.
    live_ingress: crate::net::provider::RuntimeIngress,

    /// The switch address the VM host daemon admitted this box's runtime
    /// publishes under (T94), kept from the publish so the stop's withdrawal
    /// sweep reports against the row it admitted them in without re-reading
    /// the record — a read that fails there would skip the sweep and leave
    /// the host's row naming ports nothing publishes.
    reported_switch_address: Option<std::net::Ipv4Addr>,

    /// This box's runtime publications, whichever of the two runtime surfaces
    /// made them — the `min net expose` path or the listen watcher the
    /// launch's plan starts — each port with its owner. Built fresh by the
    /// session's launcher for the spawn it is about to run, so a respawn
    /// starts empty and the expose path below reads the same set the box's
    /// watcher does: a port the one published is answered by the other as
    /// published already, and never bound twice.
    publications: crate::net::listeners::BoxPublications,

    /// The runtime port-publish requests this box decided `ask`, parked until
    /// the attached human answers them (NET-045). Empty for a box with
    /// nothing waiting on a human; drained fail-closed by
    /// [`BoxActor::stop_running`].
    pending_asks: Vec<PendingAsk>,

    /// The counter behind [`AskId`]: the actor mints one id per ask it parks,
    /// so ids are unique within the session and monotonic in route order —
    /// and carry no meaning beyond that.
    next_ask_id: u64,

    /// The root of this session's operation tree - tracks long-running
    /// operations for display.
    tracker: OpTracker,

    /// Session state machine.
    inner: BoxInner,

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

    /// How many `WorkspaceFilesTarZst` uploads are currently streaming into
    /// the workspace. A count rather than a flag so one upload finishing
    /// cannot re-admit attaches while another into the same session is
    /// still unpacking. While non-zero, an attach would run its Draft shortcut
    /// (`configure_loadout` with an empty contribution) against a
    /// half-populated tree, scaffolding a default `minimal.toml` that
    /// conflicts with the layout the upload is about to land — so the
    /// attach is refused instead, and the client retries once the upload
    /// completes.
    workspace_uploads_in_flight: usize,

    /// The liveness of the connection that created this session, while it
    /// is still open. That connection owns the activation — upload,
    /// `ConfigureLoadout`, `FinalizeSession` — from `CreateSession` until
    /// the session leaves `Draft`, so an attach from any other connection
    /// that finds the session unconfigured while its creator is live is
    /// refused rather than configured: the Draft shortcut would compose
    /// against a workspace the creator has not finished uploading (or has
    /// uploaded but not yet configured), and the creator's own
    /// `ConfigureLoadout` would then be refused. The creator's own attach
    /// is let through: it knows where its activation stands. This
    /// keeps upgrading after the creator's connection closes, until that
    /// connection's teardown has reaped the sessions it left unfinalized:
    /// the gate holds over a dying creator's `Draft` until the `Draft` is
    /// gone, and only then stops upgrading. So the shortcut is
    /// open to the creator's own connection, and otherwise only for a
    /// session with no live creator: one restored from disk or created
    /// in-process (`None`).
    creator: Option<std::sync::Weak<()>>,

    /// A non-owning handle to the [`BoxManager`](crate::box_manager::BoxManager), used to
    /// build the [`BoxControl`] handed to each [`Binding`] so a shell-exit
    /// "delete" tears this session down through the manager (record removal and
    /// all), and to self-evict from the manager's running map on
    /// actor-initiated termination. Weak by design — see
    /// [`crate::box_manager::BoxManager::weak_self`].
    manager: WeakBoxManagerHandle,

    /// A non-owning handle to this session, handed to the runtime objects
    /// we spawns (e.g. build [`SideOp`]s) so they can reach back into
    /// the session.
    weak_self: WeakBoxHandle,

    /// Cancelled once a destroy of this session proceeds, before the destroy
    /// stops the host. Shared with every [`BoxHandle`], so a command the
    /// destroy ends can tell (see [`BoxHandle::is_destroying`]).
    destroying: CancellationToken,

    /// What brought the currently held host up, which decides whether an
    /// interactive attach may respawn it. See [`HostOrigin`].
    host_origin: HostOrigin,

    /// Whether the host in the slot is the launch that bound this box's
    /// host-side row (NET-138): set by that launch, cleared by every later
    /// one. In memory only, so a restarted actor starts without it — the
    /// restart ended the PTask the row was tied to. See
    /// [`Self::host_row_lost`].
    slot_holds_row: bool,

    /// Whether the last [`Self::host_row_lost`] read found the binding
    /// launch's host gone and the VM host daemon's row still standing, so
    /// the launch that follows rejoins that row. The next attach or exec
    /// launch takes it and marks its host as holding the row; a hook launch,
    /// which reads nothing first, drops it.
    relaunch_row_confirmed: bool,

    /// Whether this daemon opted out of the deny-all egress default
    /// (NET-077), threaded from the server config: the launcher resolves
    /// this session's effective egress (NET-074) against it, and the task
    /// path reads it through the handle for the same resolution.
    deny_all_opt_out: bool,

    /// The live direct-tcpip forwards opened for this session: one abort
    /// handle per relay the connection layer spawned. Pruned as relays
    /// finish; every live one is aborted by [`BoxActor::stop_running`], so a
    /// session that goes away takes its forwards down with it (NET-105).
    forwards: Vec<tokio::task::AbortHandle>,

    /// Whether [`Self::finalize`] resolves the composition's package names
    /// before promoting the record (see [`Self::check_composed_packages`]).
    /// On in every production build. Off by default under
    /// `test`/`test-support`, whose sessions run offline and compose names
    /// (the scaffolded `base`/`vim`, for one) that only an upstream declares;
    /// a test that wants the check turns it on through
    /// [`BoxHandle::check_packages_at_finalize`].
    check_packages_at_finalize: bool,

    /// The bound on [`Self::check_composed_packages`] —
    /// [`PACKAGE_CHECK_DEADLINE`] in every build; the test-only switch
    /// above carries a shorter one to drive the expiry path.
    package_check_deadline: std::time::Duration,

    /// Package names the compose-time graph declared, captured by
    /// [`Self::configure_loadout`] so [`Self::check_composed_packages`]
    /// can judge the composition's names without re-evaluating the
    /// project graph — the most expensive step of a compose. `None`
    /// when compose saw no mfile (or the actor was rebuilt from disk),
    /// where the check falls back to evaluating the graph itself.
    composed_graph_names: Option<HashSet<String>>,
}

impl BoxActor {
    /// Assembles the actor from its seed, mailbox, and initial state. The
    /// caller decides when to enter [`Self::mainloop`].
    fn assemble(
        seed: BoxActorConfig,
        receiver: crate::traced::Receiver<BoxMessage>,
        inner: BoxInner,
        weak_self: WeakBoxHandle,
        destroying: CancellationToken,
    ) -> Self {
        let BoxActorConfig {
            minimal_state_dir,
            minimal_cache_dir,
            daemon_ctx,
            record,
            net_switch,
            manager,
            deny_all_opt_out,
            creator,
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
            workspace_uploads_in_flight: 0,
            creator,
            manager,
            host_slot: Arc::clone(&weak_self.2),
            weak_self,
            destroying,
            // No host yet; the first launch sets this. `Interactive` is the
            // conservative default — it is the one value that never licenses
            // a respawn.
            host_origin: HostOrigin::Interactive,
            // No host yet, so none holds a row.
            slot_holds_row: false,
            relaunch_row_confirmed: false,
            // Forwards are registered as their channels open; a session
            // starts with none.
            forwards: Vec::new(),
            check_packages_at_finalize: !cfg!(any(test, feature = "test-support")),
            package_check_deadline: PACKAGE_CHECK_DEADLINE,
            // Filled by `configure_loadout` from the graph it evaluates;
            // `None` until then (and forever for an actor restored from
            // disk, whose compose predates this process).
            composed_graph_names: None,
            // The same for the ports the box publishes at runtime: nothing is
            // live until a `min net expose` inside it lands (NET-044).
            live_ingress: Default::default(),
            // No runtime publish has been admitted at a VM host yet.
            reported_switch_address: None,
            // And for the publications every runtime surface reads: empty
            // until a launch hands its box one, and then whatever the spawn
            // it launched publishes.
            publications: Default::default(),
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
    fn create_dirs(object: &DiskBox) -> Result<(), std::io::Error> {
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
    pub(crate) async fn run(conf: BoxActorConfig) -> Result<BoxHandle, std::io::Error> {
        let obj = conf.record.object().await?;
        Self::create_dirs(&obj)?;
        // BEP-015: a GitHub grant box carries a git credential helper that
        // answers with its sealed value. Written on every start, so a box
        // from before the helper gets it too. A failed write removes a
        // helper from an earlier start. The box still starts: git then
        // sends no credential for the grant hosts, and a clone fails.
        let home = obj.home_path();
        if let Err(error) = bep_git_helper::install(
            std::path::Path::new(home.as_str()),
            &obj.record().sealed_deliveries,
        ) {
            tracing::warn!(%error, home = %home, "writing the git credential helper");
        }

        let inner = match obj.record().status {
            BoxState::Active => {
                let composition = load_composition(&conf.record).await;
                BoxInner::Active {
                    composition,
                    host: None,
                    sops: vec![],
                }
            }
            BoxState::Pending => BoxInner::Draft { pending: None },
            // `Materializing` records are only meaningful across a
            // matching in-memory composition, which is lost on
            // daemon restart. `BoxManager::init` runs
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
            //   * `BoxInner::Draft { pending: None }` would let
            //     `configure_loadout` accept a fresh contribution
            //     while the on-disk status stays `Materializing`,
            //     drifting the two into inconsistency.
            //   * A stale `.patches_ready` from the prior upload
            //     could then satisfy the *new* composition's
            //     finalize marker check, materializing the wrong
            //     patches into the sandbox home.
            //   * `BoxInner::Active { composition: None }`
            //     would let attach reach a shell against a session
            //     that never actually finished materializing.
            //
            // Fail the spawn instead; the caller sees an error and
            // the operator can destroy the stuck record explicitly.
            BoxState::Materializing => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "session record is Materializing but has no in-memory composition \
                     (restart-orphaned actor); destroy the session and re-activate",
                ));
            }
        };

        let (sender, receiver) = crate::traced::channel(8);
        let destroying = CancellationToken::new();
        // One line per session start (NET-074/NET-076/NET-077): the rollout
        // phase this build ships, the daemon's opt-out state, and the
        // effective egress they leave this box with. The declaration
        // travels on the record; these three are the facts a reader of a
        // diagnostics bundle's daemon-log tail needs to explain why a box
        // can — or cannot — reach anything, without the daemon's flags or
        // its source at hand. The ingress half of the same diagnosis
        // (NET-043): the dynamic stance and the range the record holds,
        // named as the box runs them — an absent stance is the deny the
        // policy module evaluates it as, the same reading `min session
        // policy` prints — so a bundle explains both why a box can reach
        // out and why the outside can reach in.
        {
            let record = obj.record();
            tracing::info!(
                session = %record.id,
                session_name = record.name.as_deref().unwrap_or(crate::rpc::ANONYMOUS_SESSION),
                network = %record.network.word(),
                egress_default_phase = ?boxes::EGRESS_DEFAULT_PHASE,
                deny_all_opt_out = conf.deny_all_opt_out,
                effective_egress = ?boxes::effective_egress(
                    record.policy.egress.as_ref(),
                    record.network,
                    boxes::EGRESS_DEFAULT_PHASE,
                    conf.deny_all_opt_out,
                ),
                dynamic_ingress = %record
                    .policy
                    .ingress
                    .as_ref()
                    .and_then(|ingress| ingress.dynamic_ingress)
                    .unwrap_or(boxes::DynamicIngress::Deny),
                dynamic_allowed_range = ?record
                    .policy
                    .ingress
                    .as_ref()
                    .and_then(|ingress| ingress.dynamic_allowed_range),
                "session starts"
            );
        }
        // A weak self-handle so the actor can hand its own mailbox to the
        // runtime objects it spawns without a caller threading it in.
        let host_slot = HostSlot::default();
        let weak_self = WeakBoxHandle(
            sender.downgrade(),
            destroying.clone(),
            Arc::clone(&host_slot),
        );
        let actor = Self::assemble(conf, receiver, inner, weak_self, destroying.clone());

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

        // The actor outlives the message that brought it up (a create, the
        // resume an RPC naming the box makes): its own root, linked to that
        // request, so the request's span ends with the request.
        let root = tracing::info_span!(
            parent: None,
            "session.actor",
            session_id = %actor.record.id(),
        );
        crate::traced::spawn_detached(root, actor.mainloop());
        Ok(BoxHandle(sender, destroying, host_slot))
    }

    /// Publishes the host this actor holds to the slot its handle reads
    /// ([`HostSlot`]). Called after every message, so between messages, and
    /// for as long as one parks the actor, the slot holds the host the actor
    /// last had, and a listing's probe never waits on this mailbox. Also
    /// called where a host is installed ([`Self::ensure_host`],
    /// [`Self::mint_session_host`], [`Self::launch_host_for_hooks`]), which
    /// is before the message that launched it replies: a caller that awaits
    /// an attach or `ensure_host` and then reads attrs sees the new host.
    pub(super) fn publish_host(&self) {
        let host = match &self.inner {
            BoxInner::Active {
                host: Some((h, _)), ..
            } => Some(AttrsProbe(h.clone())),
            _ => None,
        };
        *self
            .host_slot
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = host;
    }

    /// Tears the session down for good: its `on_destroy` hooks (failures
    /// reported, never obeyed), its host, its hostname, its record. Returns
    /// one line per hook that failed.
    async fn destroy_now(&mut self) -> Result<Vec<String>, std::io::Error> {
        // Before `stop_running`: a destroy hook runs *inside* the
        // session, so the sandbox it joins has to still exist — or
        // be minted, which is what this does when the session's
        // shell has already gone. Failures are reported back to the
        // destroying client, never obeyed: a session must stay
        // destroyable whatever its hooks do.
        //
        // A slot of [`DESTROY_HOOK_RUNS`] is held across the hook run
        // only, and only when there are hooks to run.
        let hook_slot = if self.has_hooks_for(crate::hooks::HookEvent::Destroy) {
            DESTROY_HOOK_RUNS.acquire().await.ok()
        } else {
            None
        };
        let hook_failures: Vec<String> = self
            .run_hooks_headless(crate::hooks::HookEvent::Destroy)
            .await
            .iter()
            .filter(|o| o.failed())
            .map(|o| {
                let mut line = format!("{}: {}", o.declared_by, o.status);
                if !o.output.is_empty() {
                    line.push('\n');
                    line.push_str(&o.output);
                }
                line
            })
            .collect();
        // Cancelled immediately before `stop_running`, which is what
        // ends the session's commands, so a command that ends there
        // can see why. Not before the hooks: they can take seconds,
        // and a command that finishes on its own meanwhile was not
        // stopped by the destroy.
        self.destroying.cancel();
        drop(hook_slot);
        self.stop_running(false).await;
        // Withdraw the hostname before the fallible record delete, so
        // a delete failure leaves a stale on-disk record (repairable
        // on restart) but never a stale routing entry pointing at a
        // destroyed session (R3.5). The session is ending for good, so
        // its lease fact goes with it.
        #[cfg(target_os = "linux")]
        self.deregister_hostname(true).await;
        let deleted = self.record.clone().delete().await;
        deleted.map(|()| hook_failures)
    }

    /// The async task which handles interactions with the session.
    ///
    /// On an actor-initiated termination (abort, failed verdict resume) the
    /// mailbox is closed *before* the manager is told to drop its `running`
    /// entry, so a manager concurrently awaiting this actor errors out
    /// instead of deadlocking against a full manager mailbox.
    async fn mainloop(mut self) {
        let mut teardown = Teardown::ManagerInitiated;
        let _clear_slot = ClearSlotOnExit(Arc::clone(&self.host_slot));
        self.publish_host();
        while let Some((msg, caller)) = self.receiver.recv().await {
            // Opened now, a child of the sender's ids (see
            // `traced::Receiver::recv`), so compose, graph resolution and
            // checkouts nest under the RPC that asked for them.
            let span = tracing::info_span!(
                parent: None,
                "session.message",
                kind = msg.kind(),
                trace_id = tracing::field::Empty,
                span_id = tracing::field::Empty,
                parent_span_id = tracing::field::Empty,
            );
            crate::exec::adopt_trace(&span, caller);
            if let ControlFlow::Break(t) =
                tracing::Instrument::instrument(self.handle_message(msg), span).await
            {
                teardown = t;
                break;
            }
            self.publish_host();
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
    async fn handle_message(&mut self, msg: BoxMessage) -> ControlFlow<Teardown> {
        match msg {
            BoxMessage::GetPaths(r) => {
                let _ = r.send(self.paths().await);
            }
            BoxMessage::MakeContext(r) => {
                let _ = r.send(self.context(false).await);
            }
            BoxMessage::Attach(r, session_hnd, conn_username, channel, config, attacher) => {
                let _ = r.send(
                    self.attach(session_hnd, conn_username, channel, config, attacher)
                        .await,
                );
            }
            BoxMessage::EnsureHost(r, session_hnd, conn_username) => {
                let _ = r.send(self.ensure_host(session_hnd, conn_username).await);
            }
            BoxMessage::GetWorkspaceDelta(r) => match &self.inner {
                BoxInner::Active {
                    host: Some((h, _)), ..
                } => {
                    // Forwarded off-actor: the host answers via bounded git
                    // commands / a workspace re-walk that can take seconds,
                    // and this actor must stay responsive while they run.
                    let h = h.clone();
                    crate::traced::spawn(async move {
                        let _ = r.send(h.at_risk().await);
                    });
                }
                _ => {
                    let _ = r.send(minimald_rpc::SessionDeltaResponse::Unavailable);
                }
            },
            BoxMessage::GetHostScreen(r) => match &self.inner {
                BoxInner::Active {
                    host: Some((h, _)), ..
                } => {
                    // Off-actor and bounded for the same reasons as
                    // `GetWorkspaceDelta`.
                    let h = h.clone();
                    crate::traced::spawn(async move {
                        let _ = r.send(probe_host(h.get_screen()).await);
                    });
                }
                _ => {
                    let _ = r.send(None);
                }
            },
            BoxMessage::ConfigureLoadout(contribution, r) => {
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
            BoxMessage::SubmitVerdict(msg) => {
                let (verdict, r) = *msg;
                let _ = r.send(self.handle_verdict(verdict).await);
            }
            BoxMessage::Finalize(r) => {
                let _ = r.send(self.finalize().await);
            }
            BoxMessage::Abort(r) => match &self.inner {
                // Abort is Draft-only: delete the record, then stop. The
                // record delete happens before the reply so a post-reply
                // store read never sees the aborted session.
                BoxInner::Draft { .. } => {
                    let _ = r.send(self.record.clone().delete().await);
                    return ControlFlow::Break(Teardown::SelfInitiated);
                }
                BoxInner::Active { .. } => {
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
            BoxMessage::Rename(new_name, r) => {
                let _ = r.send(self.rename(new_name).await);
            }
            #[cfg(test)]
            BoxMessage::Park(d, entered) => {
                #[expect(
                    clippy::let_underscore_must_use,
                    reason = "the parker may already be gone; the park still runs"
                )]
                let _ = entered.send(());
                tokio::time::sleep(d).await;
            }
            BoxMessage::IsBusy(r) => {
                let _ = r.send(match &self.inner {
                    // Awaiting a verdict: a client is mid create flow.
                    BoxInner::Draft { pending } => pending.is_some(),
                    // A *live* host, not merely a held one: the slot outlives
                    // the process (see `launch_host_for_hooks`), so a session
                    // whose shell has exited still holds a handle to a host
                    // that runs nothing — and nothing is what an unforced
                    // shutdown would interrupt there.
                    BoxInner::Active { host, .. } => {
                        host.as_ref().is_some_and(|(h, _)| h.is_alive())
                    }
                });
            }
            BoxMessage::Stop(r) => {
                self.stop_running(true).await;
                // NET-013: a stop keeps the grant and the registry's publish
                // row — the session still exists, a resume brings the same
                // box back, and its address is its own until destroy.
                // NET-128: the name stays held but a shared-address box
                // answers NODATA while stopped, so the node's own listener
                // at that port is not spoken for by a dead box. The marker
                // is cleared on resume when the host starts.
                #[cfg(target_os = "linux")]
                {
                    // An unreadable record must not panic the Stop arm, and it
                    // must not fail open either: the box is stopped whether or
                    // not its record reads, and a shared-address name left
                    // answering would let a dead box speak for the node's own
                    // listener. The marker is keyed by the session id, which
                    // the actor holds without the record, so when the network
                    // mode cannot be read the name is marked stopped on the
                    // `Active` half of the route gate alone.
                    let owns_route = match self.record.record().await {
                        Ok(record) => self.owns_hostname_route(&record),
                        Err(e) => {
                            tracing::warn!(
                                session_id = %self.record.id(),
                                error = %e,
                                "reading the session record failed while stopping; \
                                 marking the box's name stopped by its id",
                            );
                            matches!(self.inner, BoxInner::Active { .. })
                        }
                    };
                    if owns_route {
                        self.hostnames
                            .write()
                            .expect("hostname registry lock poisoned")
                            .mark_stopped(*self.record.id());
                    }
                }
                let _ = r.send(());
                return ControlFlow::Break(Teardown::ManagerInitiated);
            }
            BoxMessage::RunDetachHooks(r) => {
                self.run_hooks_headless(crate::hooks::HookEvent::Detach)
                    .await;
                let _ = r.send(());
            }
            BoxMessage::Destroy(r) => {
                let _ = r.send(self.destroy_now().await);
                return ControlFlow::Break(Teardown::ManagerInitiated);
            }
            BoxMessage::DestroyIfUnfinalized(r) => {
                // A record that cannot be read is destroyed, as an
                // unconditional destroy would: keeping is the exception.
                let finished = matches!(
                    self.record.record().await,
                    Ok(record) if record.status == BoxState::Active
                );
                if finished {
                    tracing::info!(
                        session_id = %self.record.id(),
                        "kept a session a cleanup destroy was sent for: it finished activating first"
                    );
                    let _ = r.send(Ok(None));
                } else {
                    let _ = r.send(self.destroy_now().await.map(Some));
                    // The manager did not claim this actor (its entry stays
                    // in `running` for a conditional destroy), so it evicts
                    // itself.
                    return ControlFlow::Break(Teardown::SelfInitiated);
                }
            }
            BoxMessage::GetPatchesUploadLock(r) => {
                let _ = r.send(Arc::clone(&self.patches_upload_lock));
            }
            BoxMessage::GetHookScriptsUploadLock(r) => {
                let _ = r.send(Arc::clone(&self.hook_scripts_upload_lock));
            }
            BoxMessage::SetWorkspaceUploadInFlight(in_flight, r) => {
                let applied = if !in_flight {
                    self.workspace_uploads_in_flight =
                        self.workspace_uploads_in_flight.saturating_sub(1);
                    true
                } else if matches!(self.inner, BoxInner::Draft { pending: None }) {
                    self.workspace_uploads_in_flight += 1;
                    true
                } else {
                    false
                };
                let _ = r.send(applied);
            }
            BoxMessage::TrackForward(forward) => {
                // Prune the ones that have finished on their own, so the
                // list holds the live forwards and nothing else.
                self.forwards.retain(|h| !h.is_finished());
                self.forwards.push(forward);
            }
            BoxMessage::StartBuild {
                rebuild,
                pkgs,
                reply,
            } => {
                let _ = reply.send(self.start_build(rebuild, pkgs).await);
            }
            BoxMessage::StartCheck { opts, reply } => {
                let _ = reply.send(self.start_check(opts).await);
            }
            BoxMessage::StartMaterialize { opts, reply } => {
                let _ = reply.send(self.start_materialize(opts).await);
            }
            BoxMessage::GetComposition(r) => {
                let _ = r.send(self.composition());
            }
            BoxMessage::ExposeDynamic { port, reply } => {
                // Answers the reply itself, or parks it with the ask it
                // routed to the attached human (NET-045) — either way this
                // handler is done with it.
                self.expose_dynamic(port, reply).await;
            }
            #[cfg(target_os = "linux")]
            BoxMessage::BindHandedPort { address, port } => {
                self.bind_handed_port(address, port).await;
            }
            BoxMessage::LiveIngress(r) => {
                #[expect(
                    clippy::let_underscore_must_use,
                    reason = "the asker may already be gone; there is nothing to answer then"
                )]
                let _ = r.send(self.live_ingress_snapshot());
            }
            BoxMessage::AskAnswered { id, port, answer } => {
                self.resume_ask(id, port, answer).await;
            }
            BoxMessage::GetRecord(r) => {
                let _ = r.send(self.record.record().await.unwrap());
            }
            BoxMessage::GetNetSwitch(r) => {
                let _ = r.send(Arc::clone(&self.net_switch));
            }
            BoxMessage::GetDenyAllOptOut(r) => {
                #[expect(
                    clippy::let_underscore_must_use,
                    reason = "the asker may already be gone; there is nothing to answer then"
                )]
                let _ = r.send(self.deny_all_opt_out);
            }
            #[cfg(test)]
            BoxMessage::PeekComposition(r) => {
                let _ = r.send(match &self.inner {
                    BoxInner::Active { composition, .. } => composition.clone(),
                    BoxInner::Draft { .. } => None,
                });
            }
            #[cfg(test)]
            BoxMessage::PeekPendingAsks(r) => {
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
            #[cfg(test)]
            BoxMessage::PeekIngressCells(r) => {
                #[expect(
                    clippy::let_underscore_must_use,
                    reason = "the asker may already be gone; there is nothing to answer then"
                )]
                let _ = r.send((self.live_ingress.clone(), self.publications.clone()));
            }
            #[cfg(test)]
            BoxMessage::CheckPackagesAtFinalize(deadline, r) => {
                self.check_packages_at_finalize = true;
                self.package_check_deadline = deadline;
                #[expect(
                    clippy::let_underscore_must_use,
                    reason = "the asker may already be gone; there is nothing to answer then"
                )]
                let _ = r.send(());
            }
            #[cfg(test)]
            BoxMessage::HoldUntil(entered, release) => {
                #[expect(
                    clippy::let_underscore_must_use,
                    reason = "the holder may already be gone; the hold still ends on its release"
                )]
                let _ = entered.send(());
                #[expect(
                    clippy::let_underscore_must_use,
                    reason = "a dropped release ends the hold as a sent one does"
                )]
                let _ = release.await;
            }
            #[cfg(test)]
            BoxMessage::ForgetComposedGraphNames(r) => {
                self.composed_graph_names = None;
                #[expect(
                    clippy::let_underscore_must_use,
                    reason = "the asker may already be gone; there is nothing to answer then"
                )]
                let _ = r.send(());
            }
        }
        ControlFlow::Continue(())
    }

    async fn paths(&self) -> BoxPaths {
        let obj = self.record.object().await.unwrap();

        BoxPaths {
            working: obj.workspace_path(),
            cache: obj.cache_path(),
            home: obj.home_path(),
            patches: obj.patches_path(),
            hooks: obj.hooks_path(),
        }
    }
}

/// The test seam for what an own-address box's launch found published: the
/// test launcher records, per launch, the address the production attach
/// would bind the box's declared forwards at
/// ([`crate::net::provider::OwnAddressReporter::published_address`]), so a
/// test can prove the publish precedes the launch — the order finalize's
/// activate-hook launch depends on (#2070). Keyed by session id, like the
/// seams below, so tests running beside each other in one process never
/// read each other's launches.
#[cfg(all(test, target_os = "linux"))]
pub(crate) mod launch_publish_seam {
    use std::collections::HashMap;
    use std::net::Ipv4Addr;
    use std::sync::Mutex;

    use boxes::SessionId;

    /// What each launch of one session found published, in launch order.
    type Launches = Vec<Option<Ipv4Addr>>;

    static OBSERVED: Mutex<Option<HashMap<SessionId, Launches>>> = Mutex::new(None);

    /// The launcher's half: one launch of `id` found `published`.
    pub(super) fn observe(id: SessionId, published: Option<Ipv4Addr>) {
        OBSERVED
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get_or_insert_with(HashMap::new)
            .entry(id)
            .or_default()
            .push(published);
    }

    /// What each launch of `id` found published, in launch order; empty
    /// when nothing launched it.
    pub(crate) fn observed(id: SessionId) -> Launches {
        OBSERVED
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .and_then(|observed| observed.get(&id).cloned())
            .unwrap_or_default()
    }
}

/// The test seam for a launch whose outcome cannot be recorded (NET-079):
/// a test names a session whose launch-record write fails, and gets back
/// the flag the session's box's network teardown sets — the observable
/// that the launch killed the box it could not record. Keyed by session
/// id, so tests running beside each other in one process never fail each
/// other's writes.
#[cfg(test)]
pub(crate) mod launch_record_seam {
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    use boxes::SessionId;

    static FAILING: Mutex<Option<HashMap<SessionId, Arc<AtomicBool>>>> = Mutex::new(None);

    /// Makes every launch-record write for `id` fail, and returns the flag
    /// its box's network teardown sets.
    pub(crate) fn fail_writes_for(id: SessionId) -> Arc<AtomicBool> {
        let torn_down = Arc::new(AtomicBool::new(false));
        FAILING
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get_or_insert_with(HashMap::new)
            .insert(id, Arc::clone(&torn_down));
        torn_down
    }

    pub(super) fn write_fails(id: &SessionId) -> bool {
        FAILING
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .is_some_and(|failing| failing.contains_key(id))
    }

    pub(super) fn teardown_guard(id: SessionId) -> Option<Box<dyn sandbox::NetGuard>> {
        let failing = FAILING
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let torn_down = Arc::clone(failing.as_ref()?.get(&id)?);
        Some(Box::new(TeardownFlag(torn_down)))
    }

    struct TeardownFlag(Arc<AtomicBool>);

    impl sandbox::NetGuard for TeardownFlag {
        fn teardown(
            self: Box<Self>,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> {
            self.0.store(true, Ordering::SeqCst);
            Box::pin(async {})
        }
    }
}

/// The test seam for the window between a mint's launch and its attach: a
/// test seeds the failure that lands there for one session id, and the mint
/// applies it to the host it just launched before wiring the channel. The
/// take is once: a failure belongs to the mint that reads it, and a session a
/// test seeded nothing for mints an ordinary host. Keyed by session id, like
/// the launch-record seam, so tests running beside each other in one process
/// never answer each other's mints.
///
/// The seam never fabricates the error itself — it only puts the freshly
/// launched host into the state that produces it, so what the mint's own
/// `attach` call returns, and how that maps onto the refusal the client sees,
/// is exactly what production runs.
#[cfg(test)]
#[expect(
    clippy::disallowed_methods,
    reason = "a test seam: plain tokio tasks are fine here; the traced-spawn rule is for request handling"
)]
pub(crate) mod mint_attach_seam {
    use std::collections::HashMap;
    use std::sync::Mutex;

    use boxes::SessionId;

    use crate::box_runtime::{HOST_MAILBOX_CAPACITY, HostHandle, WedgedMailbox};

    /// The failure a seeded mint must hit: the host's loop ending before the
    /// attach could be delivered, or a wedged loop whose mailbox stays full.
    pub(crate) enum Failure {
        HostDiedBeforeAttach,
        HostWedged,
    }

    static SEEDED: Mutex<Option<HashMap<SessionId, Failure>>> = Mutex::new(None);
    // Held for the daemon's lifetime so a wedged handle's mailbox never
    // drains: an undrained mailbox is what keeps it wedged. Keyed by session
    // id, like SEEDED, so tests running beside each other in one process keep
    // their own stand-in's mailbox.
    static WEDGED_MAILBOXES: Mutex<Option<HashMap<SessionId, WedgedMailbox>>> = Mutex::new(None);

    /// Makes the next mint of `id` hit `failure` between its launch and its
    /// attach.
    pub(crate) fn seed(id: SessionId, failure: Failure) {
        SEEDED
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get_or_insert_with(HashMap::new)
            .insert(id, failure);
    }

    /// Applies the failure seeded for `id`, if any, to the host this mint
    /// just launched. Once: the seeded failure is taken, not borrowed, so a
    /// later mint of the same session mints an ordinary host. Takes the
    /// launched pair and hands it back so the mint's binding needs no
    /// mutation the non-test build would flag as unused.
    pub(crate) async fn apply(
        id: SessionId,
        mut launched: super::LaunchedHost,
    ) -> super::LaunchedHost {
        let seeded = SEEDED
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_mut()
            .and_then(|seeded| seeded.remove(&id));
        match seeded {
            None => {}
            Some(Failure::HostDiedBeforeAttach) => {
                // End the host's loop now, and wait for the end so the host
                // (and its mailbox) is gone before the mint's attach sends:
                // the send finds the channel closed rather than racing a
                // loop that might still drain it.
                launched.1.abort();
                let _ = (&mut launched.1).await;
            }
            Some(Failure::HostWedged) => {
                // End the real host's loop, as above, so nothing of it
                // outlives the swap. Then swap in a wedged stand-in, paired
                // with a task that stays pending like a live wedged loop, so
                // the stored (handle, task) pair describes one host. Fill the
                // stand-in's mailbox to capacity through the production
                // sender, so the mint's own attach send cannot queue and runs
                // out its deadline.
                launched.1.abort();
                let _ = (&mut launched.1).await;
                let (wedged, mailbox) = HostHandle::wedged();
                launched = (wedged, tokio::spawn(std::future::pending()));
                WEDGED_MAILBOXES
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .get_or_insert_with(HashMap::new)
                    .insert(id, mailbox);
                for i in 0..HOST_MAILBOX_CAPACITY {
                    launched.0.rename(format!("mint-attach-seam-{i}")).await;
                }
            }
        }
        launched
    }
}

/// The test seam for a launch that carries a listen plan: a test seeds the
/// facts a real launch gathers for one — the box's lease, its published
/// address (NET-010), the switch's control channel and its ingress gate —
/// and the session's test launcher builds the plan from them for the spawn
/// it is about to run, sharing the box's publication set the way a real
/// launch's plan does. The take is once: a plan belongs to the launch that
/// reads it, and a session a test seeded nothing for launches with no
/// watcher at all, the way a launch that could gather no plan does. Keyed
/// by session id, like the launch-record seam, so tests running beside each
/// other in one process never answer each other's launches.
#[cfg(test)]
pub(crate) mod listen_plan_seam {
    use std::collections::HashMap;
    use std::net::Ipv4Addr;
    use std::sync::{Arc, Mutex};

    use boxes::SessionId;

    use crate::net::listeners::BoxPublications;
    use crate::net::policy::ControlChannel;
    use crate::net::switch::BoxGate;

    /// The facts a test hands the mock launch it seeds.
    pub(crate) struct Seeded {
        /// The box's lease on the switch — where a publication's forward
        /// delivers.
        pub(crate) lease: Ipv4Addr,
        /// The box's published address (NET-010) — where a publication
        /// binds.
        pub(crate) published: Ipv4Addr,
        /// The gvproxy control channel the watcher's forwarder verbs ride.
        pub(crate) control: ControlChannel,
        /// The box's session gate: the permit decision and the admission.
        pub(crate) gate: Arc<BoxGate>,
    }

    static SEEDED: Mutex<Option<HashMap<SessionId, Seeded>>> = Mutex::new(None);

    /// The publication sets the seeded launches handed back, keyed by the
    /// session whose launch built them: the same set the launch's plan
    /// carried and its actor reads, so a test can hold a reservation in it
    /// the way the actor's own publish would.
    static HANDED_BACK: Mutex<Option<HashMap<SessionId, BoxPublications>>> = Mutex::new(None);

    /// Seeds `id`'s next launch with these plan facts, taken by that launch
    /// alone.
    pub(crate) fn seed(id: SessionId, seeded: Seeded) {
        SEEDED
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get_or_insert_with(HashMap::new)
            .insert(id, seeded);
    }

    pub(super) fn take(id: SessionId) -> Option<Seeded> {
        SEEDED
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_mut()
            .and_then(|seeded| seeded.remove(&id))
    }

    /// The launcher's half of the hand-back: a seeded launch records the
    /// publication set it built — the one its plan carries and its session's
    /// actor reads — under the session's id, so [`publications_of`] answers
    /// with the real set the launch is running on, not a parallel fixture
    /// of it.
    pub(super) fn hand_back(id: SessionId, publications: BoxPublications) {
        HANDED_BACK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get_or_insert_with(HashMap::new)
            .insert(id, publications);
    }

    /// The publication set `id`'s last seeded launch is running on — the set
    /// its watcher reads and its actor reserves in, so a test holding a
    /// reservation in it contends with the box's real surfaces over the
    /// real port.
    pub(crate) fn publications_of(id: SessionId) -> Option<BoxPublications> {
        HANDED_BACK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .and_then(|sets| sets.get(&id).cloned())
    }
}

// `pub(crate)`: the env channel's tests reach the stand-in forwarder and the
// session fixtures this module owns, so a reply's honesty is read against a
// real session's publish rather than a parallel fixture of it; and the
// session-host tests, which host the runtime port-publish ask tests (NET-045)
// and drive them through the session actor's own flow, reuse them too.
#[cfg(test)]
pub(crate) mod tests;
