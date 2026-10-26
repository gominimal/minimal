use std::{collections::BTreeMap, io::ErrorKind::NotFound};

use crate::{
    box_actor::{BoxActor, BoxActorConfig, BoxHandle},
    box_runtime::HostAttrs,
    store::{BoxRecordHandle, RecordPredicate, Store, StoreHandle},
};
use boxes::SessionId;
use paths::DaemonAbsPath;
#[cfg(target_os = "linux")]
use std::collections::BTreeSet;
#[cfg(target_os = "linux")]
use std::net::Ipv4Addr;
use std::sync::Arc;
#[cfg(target_os = "linux")]
use std::sync::RwLock;
use tokio::sync::{Mutex, oneshot};
use tokio_util::sync::CancellationToken;

pub(crate) mod composables;
mod handle;
#[cfg(test)]
use composables::{
    ProjectResolution, build_composables, resolve_project_ctx_and_graph, run_compose, run_composer,
};
pub use handle::{BoxControl, BoxManagerHandle, WeakBoxManagerHandle};

/// A short summary of the metadata of a session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoxInfo {
    pub id: SessionId,
    pub name: Option<String>,
    /// The absolute host path the session was built from. Surfaced through
    /// `ListSessions` so a client can match sessions against the current
    /// working directory without a per-session `GetSessionRecord` round-trip.
    pub project_path: paths::HostAbsPath,
    /// The session's lifecycle status, surfaced so a client picker can
    /// render a state glyph.
    pub status: boxes::BoxState,
    pub attrs: Option<HostAttrs>,
}

/// A key you can use to identify a session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BoxKeyPredicate {
    Id(SessionId),
    Name(String),
}

impl From<BoxKeyPredicate> for RecordPredicate {
    fn from(pred: BoxKeyPredicate) -> Self {
        match pred {
            BoxKeyPredicate::Id(id) => RecordPredicate::Id(id),
            BoxKeyPredicate::Name(name) => RecordPredicate::Name(name),
        }
    }
}

/// Transport / internal error when communicating with the sessions actor.
type BoxManagerError = std::io::Error;

/// NET-079's observability, for the create path's half of the refusal: how
/// many creates this daemon has refused because a host-address box's
/// declaration named rules the classifier cannot enforce while the host
/// decided per box. Process-global like the fact it reads — the count is
/// the daemon's, not a session's — and only counted here: a launch
/// refused on the same ground is that launch's own refusal, logged beside
/// the box it refused, never a create this counter saw.
static REFUSED_UNENFORCEABLE_CREATES: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// Reads how many creates this daemon has refused over an unenforceable
/// host-address declaration — the counter's surface, for a diagnostics
/// pass or a test that wants the count itself rather than the log line
/// each refusal also writes.
pub(crate) fn refused_unenforceable_creates() -> u64 {
    REFUSED_UNENFORCEABLE_CREATES.load(std::sync::atomic::Ordering::Relaxed)
}

/// Assemble a [`boxes::Record`] from the out-of-band session
/// config and the SSH-supplied username, then validate its policy.
/// Returns `Err(io::InvalidInput)` if the policy is incompatible
/// with the network mode (R2.1) — so an invalid session is never
/// written to the store. The `id` field is left as `nil`; the store
/// mints the record's box id at `create` time.
///
/// The `CreateSession` handler always persists the record as
/// `Pending`; the session actor's create flow promotes it to
/// `Active` once composition finalizes.
///
/// The daemon stamps the box's type, parent and project root here
/// (BOX-001): `box_type` is the creating verb's, `parent` is `parent`, which
/// the caller derives from the creating connection and never from the
/// request, and `project_root` is the project root the client resolved,
/// or the project path when an older client sends no root.
fn build_record(
    config: minimald_rpc::BoxConfig,
    username: Option<String>,
    status: boxes::BoxState,
    box_type: &str,
    parent: Option<SessionId>,
) -> Result<boxes::Record, std::io::Error> {
    // BEP-007: a delivery's variable is written into the box's environment
    // and into the file its shell sources, so a name that is not a POSIX
    // variable name is refused here and never reaches the store.
    if let Some(delivery) = config.sealed_deliveries.iter().find(|delivery| {
        boxes::core::primitives::StrictVarName::try_new(delivery.variable.as_str()).is_err()
    }) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "the GitHub grant {:?} is not a valid environment variable name",
                delivery.variable
            ),
        ));
    }
    let record = boxes::Record {
        id: SessionId::nil(),
        name: config.name,
        username,
        // The root the client resolved from the project's `minimal.toml`.
        // A client that predates the field sends none: the working path is
        // the best root the daemon has then.
        project_root: Some(
            config
                .project_root
                .unwrap_or_else(|| config.project_path.clone()),
        ),
        project_path: config.project_path,
        network: config.network,
        policy: config.policy,
        // The handed addresses ride the record: the attach path reads the
        // switch address back out of it, so a re-attach — after a restart
        // included — reuses the address the host table still holds instead
        // of drawing a new one the row would not match.
        box_addresses: config.box_addresses,
        // Task runs attach at these, one run per address, so the in-VM
        // daemon draws nothing for a task either (NET-138).
        task_addresses: config.task_addresses,
        status,
        hooks_enabled: config.hooks_enabled,
        // Daemon-owned from its first line: a create holds no launch's
        // outcome to record, and the key a client might assert in `attrs`
        // is stripped above, so only a launch ever writes this field.
        host_ip_enforcement: None,
        // The id the host's row of the box holds, beside its addresses.
        box_id: config.box_id,
        // Daemon-owned as well: only a launch binds the box's host-side row.
        host_row_bound: false,
        bound_ports: std::collections::BTreeSet::new(),
        // BEP-007: the grants' sealed values ride the record, so every host
        // launch of the box, after a daemon restart included, places them.
        sealed_deliveries: config.sealed_deliveries,
        // BEP-011: the proxy's root rides the record beside them, so every
        // host launch of the box, after a daemon restart included, adds it
        // to the box's own trust store.
        root_certificate: config.root_certificate,
        box_type: Some(box_type.to_string()),
        parent,
        attrs: config.attrs,
    };
    record
        .validate_new_policy()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    Ok(record)
}

/// Encapsulates the return channel for messages back from the actor.
#[derive(Debug)]
pub(crate) struct Responder<T>(oneshot::Sender<Result<T, BoxManagerError>>);

impl<T> Responder<T> {
    /// Constructs both ends of the return channel.
    pub(crate) fn channel() -> (Self, oneshot::Receiver<Result<T, BoxManagerError>>) {
        let (send, recv) = oneshot::channel();
        (Self(send), recv)
    }

    /// Awaits the provided future, transmitting its result to the caller.
    pub(crate) async fn handle<F>(self, fut: F)
    where
        F: Future<Output = Result<T, BoxManagerError>>,
    {
        let _ = self.0.send(fut.await);
    }
}

/// CreateSession payload — boxed so it doesn't dominate
/// `ManagerMessage`'s size (the variant carries a full session
/// config; other variants are just a few words).
#[derive(Debug)]
struct CreateSessionMsg {
    config: minimald_rpc::BoxConfig,
    /// Authenticated SSH username, supplied by the RPC handler from
    /// the SSH connection context (never the client).
    username: Option<String>,
    /// The creating connection's liveness, see
    /// [`BoxManagerHandle::create_session_by`].
    creator: Option<std::sync::Weak<()>>,
    responder: Responder<SessionId>,
}

/// A create that carries the box's spec (BOX-068): the create itself and
/// the spec the client sent on its request.
#[derive(Debug)]
struct CreateBoxMsg {
    create: CreateSessionMsg,
    spec: Option<serde_json_lenient::Value>,
}

impl BoxManagerHandle {
    /// [`Self::create_session_by`] for a create request that carries the
    /// box's spec (BOX-068). The manager checks the spec before it files
    /// the record, and writes it beside the record before the box's actor
    /// starts. A create whose spec is refused files nothing.
    pub async fn create_box_with_spec(
        &self,
        config: minimald_rpc::BoxConfig,
        spec: Option<serde_json_lenient::Value>,
        username: Option<String>,
        creator: Option<std::sync::Weak<()>>,
    ) -> Result<SessionId, BoxManagerError> {
        let (send, recv) = Responder::channel();
        // Ignore send errors - the recv will also fail.
        let _ = self
            .sender
            .send(ManagerMessage::CreateBox(Box::new(CreateBoxMsg {
                create: CreateSessionMsg {
                    config,
                    username,
                    creator,
                    responder: send,
                },
                spec,
            })))
            .await;
        recv.await.expect("corresponding sessions manager is dead")
    }
}

/// The bytes the daemon stores for a box's spec (BOX-068): the spec the
/// client sent, serialized with its keys in order. A spec must be a JSON
/// object whose `v` is a whole number, the spec's version.
///
/// # Errors
///
/// `InvalidInput`, naming the problem, for a spec that is not such an
/// object.
fn spec_bytes(spec: &serde_json_lenient::Value) -> Result<Vec<u8>, BoxManagerError> {
    let has_version = spec
        .as_object()
        .and_then(|object| object.get("v"))
        .is_some_and(serde_json_lenient::Value::is_u64);
    if !has_version {
        return Err(BoxManagerError::new(
            std::io::ErrorKind::InvalidInput,
            "The create request carries a box spec without a version. \
             The daemon accepts a spec that is a JSON object with a whole number `v`. \
             No box was created.",
        ));
    }
    serde_json_lenient::to_vec(spec)
        .map_err(|e| BoxManagerError::other(format!("could not serialize the box spec: {e}")))
}

enum ManagerMessage {
    List(Responder<Vec<BoxInfo>>),
    GetRecord(BoxKeyPredicate, Responder<Option<boxes::Record>>),
    GetSession(BoxKeyPredicate, Responder<Option<BoxHandle>>),
    /// Snapshot a running session's terminal screen (`min dash`'s
    /// `GetSessionScreen`). Read-only against the `running` map — unlike
    /// [`GetSession`](Self::GetSession) it never starts an actor, and a
    /// session with no live host answers `None`.
    GetScreen(
        BoxKeyPredicate,
        Responder<Option<minimald_rpc::ScreenSnapshot>>,
    ),
    /// Read a session's persisted composition snapshot. Read-only
    /// against the store — like [`GetRecord`](Self::GetRecord) and
    /// unlike [`GetSession`](Self::GetSession), it never starts an
    /// actor, so inspecting a stopped session leaves it stopped.
    GetComposition(
        BoxKeyPredicate,
        Responder<Option<boxes::core::compose::Composition>>,
    ),
    /// How many session actors are live. Test-only, and the only way
    /// to observe the read-only-ness of [`GetRecord`](Self::GetRecord)
    /// and [`GetComposition`](Self::GetComposition) — "did that query
    /// start an actor?" is otherwise invisible from outside.
    #[cfg(test)]
    RunningCount(Responder<usize>),
    /// The ids of the live session actors, in the order the `running`
    /// map holds them. Test-only: it shows that the holder keeps its boxes
    /// in box id order, which is their creation order.
    #[cfg(test)]
    RunningIds(Responder<Vec<SessionId>>),
    CreateSession(Box<CreateSessionMsg>),
    /// A create that carries the box's spec (BOX-068).
    CreateBox(Box<CreateBoxMsg>),
    /// Destroy a session; with `true`, only if it has not finished
    /// activating (`None` when it was kept).
    DeleteSession(SessionId, bool, Responder<Option<Vec<String>>>),
    Shutdown(bool, Responder<Result<(), ()>>),
    /// Bring up the actor of every `Active` record whose box owns a name,
    /// so a restarted daemon routes the names of the sessions it restored
    /// (see [`BoxManagerHandle::resume_active_sessions`]). Answers with how many
    /// actors it started.
    #[cfg(target_os = "linux")]
    ResumeActive(Responder<usize>),
    /// Fire-and-forget: drop the `running` entry for a session whose actor
    /// terminated on its own (abort, failed verdict resume, create failure).
    /// A no-op for an id already removed; ids are never reused, so a stale
    /// evict can't remove a fresh actor.
    Evict(SessionId),
}

impl ManagerMessage {
    /// The variant's name, for the manager loop's span.
    fn kind(&self) -> &'static str {
        match self {
            Self::List(..) => "List",
            Self::GetRecord(..) => "GetRecord",
            Self::GetSession(..) => "GetSession",
            Self::GetScreen(..) => "GetScreen",
            Self::GetComposition(..) => "GetComposition",
            #[cfg(test)]
            Self::RunningCount(..) => "RunningCount",
            #[cfg(test)]
            Self::RunningIds(..) => "RunningIds",
            Self::CreateSession(..) => "CreateSession",
            // A create with a spec is still the create RPC's message: the
            // span kind stays `CreateSession`, so traces and the trace tests
            // see one kind for every create (BOX-068).
            Self::CreateBox(..) => "CreateSession",
            Self::DeleteSession(..) => "DeleteSession",
            Self::Shutdown(..) => "Shutdown",
            #[cfg(target_os = "linux")]
            Self::ResumeActive(..) => "ResumeActive",
            Self::Evict(..) => "Evict",
        }
    }
}

/// Routes session operations to per-session [`BoxActor`] actors, spawning
/// them as needed: `CreateSession` allocates a record and spawns the actor
/// that owns the create flow, `GetSession` brings a known session's actor up
/// from disk, and `DeleteSession` tears one down. Everything session-
/// specific (compose state, verdicts, rename, attach) lives on the session
/// actor behind its [`BoxHandle`].
///
/// Follows the actor pattern.
#[derive(Debug)]
pub struct BoxManager {
    /// Cancelled once a shutdown proceeds, before any session is stopped.
    /// Shared with every [`BoxManagerHandle`], so a command the shutdown ends
    /// can tell (see [`BoxManagerHandle::is_shutting_down`]).
    in_shutdown: CancellationToken,
    receiver: crate::traced::Receiver<ManagerMessage>,
    /// The live session actors, keyed by box id. A box id is a `UUIDv7`
    /// and orders by its bytes, so the map holds its boxes in the time
    /// order their ids were minted: creation order. The shutdown stops
    /// them in that order.
    running: BTreeMap<SessionId, BoxHandle>,
    /// Sessions whose teardown runs on a task of its own (`DeleteSession`):
    /// out of `running`, their record on disk until the task deletes it. The
    /// resolver reads such a session as gone, so an attach, a listing's
    /// bring-up or a second destroy in that window starts no second actor and
    /// runs no `on_destroy` hook twice. A task removes its id as it ends.
    tearing_down: Arc<std::sync::Mutex<BTreeSet<SessionId>>>,
    /// The teardown tasks, joined by `Shutdown` before the state volume is
    /// quiesced: a hook still running or a record delete still in flight
    /// would otherwise race the unmount.
    teardowns: tokio::task::JoinSet<()>,
    store: StoreHandle,

    /// A weak handle to this manager, which can be duplicated so
    /// that downstream actors (session, session host) have a handle
    /// to do operations on us.
    weak_self: WeakBoxManagerHandle,

    /// Daemon-scoped mctx state (config, stdlib_dir, vcs, cache) cloned
    /// into each session actor, which composes its loadout and builds its
    /// per-session `mctx::Context` on top. Built once at daemon startup by
    /// the caller (which keeps its own handle on it, for the housekeeping
    /// that runs outside any session) and shared here behind an `Arc`.
    daemon_ctx: Arc<mctx::DaemonContext>,

    minimal_state_dir: DaemonAbsPath,
    minimal_cache_dir: DaemonAbsPath,
    /// The daemon-scoped gvproxy switch, handed to each session it starts so an
    /// `OwnIp` PTask attaches to the one per-host switch (R1.4/R1.5/R1.6).
    net_switch: Arc<Mutex<crate::net::SwitchClient>>,

    /// In-memory PTask hostname registry (Unit 3). Shared behind an `Arc<RwLock>`
    /// so the daemon's host-side proxies ([`crate::net::proxy`]) can resolve a
    /// `Host:` header without routing through the actor mainloop, while the
    /// manager still mutates it under `&mut self`. The lock is only ever held for
    /// a synchronous register/deregister/resolve, never across an `.await`.
    /// `HostNet` PTasks register on launch and withdraw on teardown.
    #[cfg(target_os = "linux")]
    hostnames: Arc<RwLock<crate::net::dns::HostnameRegistry>>,

    /// The answerer's lease book for this host (NET-010): the durable record
    /// of which published namespace — a box or the node — holds which granted
    /// address of the reserved local range, one record per host, written
    /// through by every daemon on it. It is the address half of a publish, as
    /// the registry beside it is the name half: a session's own-address box
    /// asks it at finalize and returns its address at destroy, holding it
    /// through its `BoxActorConfig`. Every ask is a synchronous
    /// read-modify-write under the record's own lock file, so two daemons on
    /// one host are serialized by the file system rather than by each other —
    /// no daemon asks another for an address, and none self-assigns (design
    /// §7.1).
    #[cfg(target_os = "linux")]
    loopback: Arc<crate::net::dns::LoopbackLeaseBook>,

    /// Whether this daemon opted out of the deny-all egress default
    /// (NET-077), threaded from the server config into every session actor
    /// so each one resolves its own effective egress (NET-074) the same way
    /// the RPC path does.
    deny_all_opt_out: bool,
}

impl BoxManager {
    /// Launches a sessions manager managing sessions in
    /// the given minimal state dir.
    pub async fn init(
        minimal_state_dir: DaemonAbsPath,
        minimal_cache_dir: DaemonAbsPath,
        daemon_ctx: Arc<mctx::DaemonContext>,
        net_switch: Arc<Mutex<crate::net::SwitchClient>>,
        deny_all_opt_out: bool,
    ) -> Result<BoxManagerHandle, std::io::Error> {
        let store = Store::init(minimal_state_dir.clone()).await?;

        // Reap unresumable on-disk records left over from a prior
        // daemon lifetime. Both `Pending` (compose in flight — the
        // in-memory `PendingComposeState` didn't survive the
        // restart) and `Materializing` (composition ready but
        // patches upload state is lost) are meaningless without
        // in-memory context, so the record can't be brought back
        // to a working state. Delete them here rather than let
        // them linger and confuse `min ls` / hold their names
        // hostage.
        reap_unresumable_records(&store).await?;

        let running = BTreeMap::new();
        let (sender, receiver) = crate::traced::channel(8);
        // Shared so the host-side proxies can resolve `Host:` headers directly;
        // a clone is held by both the actor (which mutates it) and the handle
        // (which hands it to the proxies via `hostnames()`). Whether the
        // daemon sits on the gvproxy switch decides how an own-address box's
        // name routes: straight to its lease on a VM host (the daemon holds a
        // tap on the switch), or through the published-loopback forwarder on a
        // native host (NET-001).
        //
        // The registry mints its names under this daemon instance's host id —
        // the same one the switch carries, seeded from the daemon id — so two
        // daemons on one host mint distinct names and route both sets at the
        // same time (NET-027) instead of the second daemon's registrations
        // overwriting the first's under the shared `local` label.
        //
        // The registry and the lease book are one publish's two halves, built
        // beside each other: the book is the answerer's record of the
        // addresses granted on this host (NET-010's arbitration, design §7.1),
        // the registry the names that answer them. Allocation in the reserved
        // local range is host-global and arbitrated through that record, so
        // this daemon asks it rather than carving the range for itself — and
        // the same record is what a restarted daemon re-derives its live
        // grants from, rather than starting from an empty table: the sweep
        // below frees the grants of boxes whose sessions are gone, and every
        // box that is still live keeps its line for its resumed session to
        // re-register with.
        //
        // A VM daemon asks for one address for its *node* before any box does
        // (NET-129: "one allocated address per VM node") — the address its
        // host-address boxes answer at. A native node's address is the host
        // loopback itself, which it already owns.
        #[cfg(target_os = "linux")]
        let (hostnames, loopback) = {
            // This daemon's start, on the record's own clock: the stamp the
            // sweep's race guard reads. A grant another daemon on this host
            // makes from this moment on — most importantly for a session
            // whose record the liveness snapshot below was read without —
            // is never this sweep's to free, so a stopped host's fresh
            // grants survive this daemon's start rather than being read as
            // dead by a snapshot that predates them.
            let daemon_start = crate::net::dns::unix_now_secs();
            let switch = net_switch.lock().await;
            let transport = switch.transport();
            let on_switch = matches!(transport, crate::net::SwitchTransport::HostShuttle { .. });
            // The daemon-start bind probe (NET-123's obligation): the
            // addresses the book grants are only publishable where the
            // reserved local range binds, so the probe is run once here —
            // over the host the publishes will bind on — and its verdict
            // gates every grant. Which host that is depends on where this
            // daemon's forwarder lives: a native daemon spawns its gvproxy
            // itself, so its own loopback is the publish surface and the
            // local bind probe is the honest one; a daemon on the gvproxy
            // switch is inside a microVM, and its forwarder binds the
            // *host's* loopback — a machine the guest cannot see, and whose
            // verdict its own `lo` would lie about, since the guest carries
            // the whole `127/8` whatever the host carries. So that shape
            // conducts the same whole-range walk through the forwarder
            // itself, over the same shuttle the publishes ride: the bind is
            // the only question that decides whether an address is
            // publishable, and the forwarder is the only thing that can do
            // the binding there. Either arm is the real probe, never the
            // session-start stand-in `rpc.rs`'s tests install: the stand-in
            // is process-global, and a daemon built in one test must not see
            // another test's absent verdict.
            //
            // The two arms are not equally cheap, and only the cheap one is
            // waited on. The local bind probe answers in microseconds, so it
            // is read here, on the way to the book. The forwarder-conducted
            // walk is two request/response rounds per address of the range on
            // one control channel, and a channel that does not answer takes
            // seconds to say so — long enough that awaiting it here would put
            // it on `BoxManager::init`'s critical path, which is the one path
            // `Server::run` waits on before it starts *accepting*: a guest
            // daemon that held its own SSH accept for the host's loopback
            // verdict would make every `minvmd stop` race the probe instead
            // of reaching the daemon behind it. So that arm is spawned here
            // and its verdict applied when it lands
            // (`land_range_verdict`): the book opens on the pending verdict
            // (no box publishes at an address nothing has vouched for; a
            // namespace the record already names keeps its line, and the
            // present landing restores it, NET-013) and the walk, once it
            // has an answer, both un-withholds and hands the node its
            // address, and re-points the publishes the window left
            // standing — a hand the landing overrules moves onto the
            // interim, an interim ask the landing upgrades to a grant or
            // its hand — so no box holds an address the landed
            // verdict contradicts, and the interim never outstays the
            // window that made it.
            let (probe, shuttle) = match transport {
                crate::net::SwitchTransport::HostShuttle { cid, port } => (None, Some((cid, port))),
                _ => (
                    Some(
                        crate::traced::spawn_blocking(crate::net::loopback::probe)
                            .await
                            .unwrap_or_else(|join_error| {
                                tracing::warn!(
                                    error = %join_error,
                                    "the daemon-start loopback probe was lost; \
                                     reading the range absent",
                                );
                                crate::net::loopback::RangeProbe::failed_to_run()
                            }),
                    ),
                    None,
                ),
            };
            if let Some(probe) = probe.as_ref() {
                tracing::info!(
                    surface = probe.surface(),
                    interim = probe.interim(),
                    first_failure = ?probe.first_failure,
                    "daemon-start loopback probe picked the publish surface",
                );
            }
            let present = probe.as_ref().is_some_and(|probe| probe.present());
            // The state the book opens on. Where a probe ran, its answer is
            // the host's: a native daemon's own loopback is its publish
            // surface, so it measures the range itself on the way here. The
            // one arm that leaves `probe` unset — the gvproxy switch above —
            // is the daemon that cannot measure its own, so its book opens
            // pending and the spawned walk below lands the verdict. That a
            // book can be open without one is the whole reason the verdict is
            // a state and not a fact.
            let verdict = match (&probe, present) {
                (None, _) => crate::net::dns::RangeVerdict::Pending,
                (Some(_), true) => crate::net::dns::RangeVerdict::Present,
                (Some(_), false) => crate::net::dns::RangeVerdict::Absent,
            };
            // The answerer's record for this host, under the state root every
            // daemon instance on it shares. Unreadable records withhold
            // grants (never guess an address another namespace may hold);
            // absent ranges grant nothing, the interim's business.
            let book = crate::net::dns::LoopbackLeaseBook::open(&minimal_state_dir, verdict)?;
            let swept = book.release_dead_boxes(&live_session_ids(&store).await?, daemon_start);
            if !swept.is_empty() {
                tracing::info!(
                    addresses = ?swept,
                    "released loopback leases whose sessions are gone from the store",
                );
            }
            // The collision report the record's own arbitration cannot make
            // (NET-010, reported like a port collision): every
            // reserved-range address a live publish holds on this host that
            // this record does not name. That is the shape a second state
            // root produces — its daemon grants an address this root's
            // record already gave out, neither record naming the other's
            // grants, and the collision being on the address means no bind
            // ever fails to tell either daemon. Advisory: a warn per
            // address, the operator's signal to separate the roots or land
            // the host-side arbiter that closes the gap. This is the
            // daemon-start half — over whatever was live before this daemon
            // came up; the session-start half
            // (`BoxActor::report_unrecorded_publishes`) catches the grants a
            // second root makes after it.
            for address in book.unrecorded_publishes() {
                crate::net::dns::warn_publish_collision(address);
            }
            // The node's own address (NET-129): a native node's is the host
            // loopback it already owns, and a VM node's is a grant the range
            // verdict gates — so on a VM node it is the spawned walk's to
            // make, not this block's, and the registry opens on the interim
            // address a withheld grant falls back to (`new`'s own default,
            // named here because it is the interim, not an omission).
            let registry =
                crate::net::dns::HostnameRegistry::new(switch.host_id().to_owned(), on_switch)
                    .with_node_address(Ipv4Addr::LOCALHOST);
            let hostnames: Arc<RwLock<crate::net::dns::HostnameRegistry>> =
                Arc::new(RwLock::new(registry));
            let loopback = Arc::new(book);
            if let Some((cid, port)) = shuttle {
                // Spawned after the sweep above, so the node's grant cannot
                // race the daemon-start liveness pass that frees dead boxes'
                // lines; the book's own flock serializes it against every
                // other ask either way. Holds only `Arc`s, so a daemon that
                // shuts down mid-walk leaves it to land on a closed book —
                // grants then withhold, the shutdown-time answer anyway.
                //
                // The blocking work below — the book's std-Mutex'd flock and
                // the registry's std RwLock, not the awaited walk — is a
                // deliberate choice, not an oversight: it is the same class
                // of ask a session actor's own `lease_loopback_address`
                // makes on the same runtime, and both are bounded by the
                // other holders' critical sections (a small-file
                // read-modify-write, a registry read), so neither parks a
                // worker for an unbounded length. `spawn_blocking` would move
                // the ask but not shorten it, and would add a thread whose
                // whole job is to wait on a lock the actor path already waits
                // on inline.
                //
                // The landing runs on this spawned task — off the manager's
                // mailbox and off every session actor's — so nothing orders
                // it against a destroy, a stop, or a rename. The present
                // arm's apply ([`apply_interim_upgrade`]) therefore re-checks
                // each box under the registry's write lock before it
                // publishes, and releases a grant drawn for a box whose
                // publish is gone.
                let book = Arc::clone(&loopback);
                let registry = Arc::clone(&hostnames);
                crate::traced::spawn(async move {
                    let probe = crate::net::policy::probe_publish_surface(
                        &crate::net::policy::ControlChannel::Vsock { cid, port },
                    )
                    .await;
                    tracing::info!(
                        via = "forwarder",
                        surface = probe.surface(),
                        interim = probe.interim(),
                        first_failure = ?probe.first_failure,
                        "the daemon-start range probe walked the forwarder's loopback \
                         and picked the publish surface",
                    );
                    land_range_verdict(
                        &book,
                        &registry,
                        if probe.present() {
                            crate::net::dns::RangeVerdict::Present
                        } else {
                            crate::net::dns::RangeVerdict::Absent
                        },
                    );
                    if !probe.present() {
                        tracing::warn!(
                            first_failure = ?probe.first_failure,
                            "the reserved local range is absent on the publish surface; \
                             publishing boxes on the 127.0.0.1 interim",
                        );
                        return;
                    }
                    let node = match book.grant(crate::net::dns::LeaseNamespace::Node) {
                        crate::net::dns::LoopbackGrant::Granted(address) => address,
                        crate::net::dns::LoopbackGrant::RecordUnavailable => {
                            // The shutdown shape: a daemon that went down
                            // mid-walk has closed its book, and the grant that
                            // comes back is the closed book's, not a fault on
                            // the host — the manager stops every session
                            // before it closes, so there is nothing left to
                            // publish an interim for either. An unreadable
                            // record lands here too, said at the same level:
                            // neither is a verdict about this host's range.
                            tracing::debug!(
                                grant = ?crate::net::dns::LoopbackGrant::RecordUnavailable,
                                "the node's own loopback address was not granted — \
                                 the book was closed for shutdown, or its record could \
                                 not be read or written",
                            );
                            return;
                        }
                        other => {
                            tracing::warn!(
                                grant = ?other,
                                "the node's own loopback address was not granted; \
                                 publishing host-address boxes on the 127.0.0.1 interim",
                            );
                            return;
                        }
                    };
                    registry
                        .write()
                        .expect("hostname registry lock poisoned")
                        .set_node_address(node);
                });
            }
            (hostnames, loopback)
        };
        let in_shutdown = CancellationToken::new();
        let handle = BoxManagerHandle {
            sender,
            in_shutdown: in_shutdown.clone(),
            #[cfg(target_os = "linux")]
            hostnames: Arc::clone(&hostnames),
            #[cfg(all(test, target_os = "linux"))]
            loopback: Arc::clone(&loopback),
        };
        // A non-owning path back to this actor, handed to each spawned session
        // so its binding can request destruction (see `weak_self`).
        let weak_self = handle.downgrade();
        // NET-129: each shared-address port the registry hands to a new
        // holder is passed to that box's session, which binds the port's
        // forward if the box is running. Off the registry's lock and off
        // the session that made the hand-over, which may be the destroyed
        // holder this manager is still waiting on.
        #[cfg(target_os = "linux")]
        {
            let (sender, mut hand_overs) = tokio::sync::mpsc::unbounded_channel();
            hostnames
                .write()
                .expect("hostname registry lock poisoned")
                .notify_hand_overs(sender);
            let manager = weak_self.clone();
            // Serves hand-overs for the manager's life: a root of its own,
            // like the manager's mainloop below.
            crate::traced::spawn_detached(
                tracing::info_span!(parent: None, "sessions.hand_overs"),
                async move {
                    while let Some(hand_over) = hand_overs.recv().await {
                        let Some(manager) = manager.upgrade() else {
                            return;
                        };
                        let holder = manager
                            .get_session(BoxKeyPredicate::Id(hand_over.holder))
                            .await;
                        if let Ok(Some(holder)) = holder {
                            holder
                                .bind_handed_port(hand_over.address, hand_over.port)
                                .await;
                        }
                    }
                },
            );
        }
        let mngr = Self {
            in_shutdown,
            receiver,
            running,
            tearing_down: Arc::default(),
            teardowns: tokio::task::JoinSet::new(),
            store,
            weak_self,
            daemon_ctx,
            minimal_state_dir,
            minimal_cache_dir,
            net_switch,
            #[cfg(target_os = "linux")]
            hostnames,
            #[cfg(target_os = "linux")]
            loopback,
            deny_all_opt_out,
        };

        // The manager serves every request for the daemon's life: a root of
        // its own, so it never pins whatever span its creator ran in. Each
        // message's span names its sender (see `mainloop`).
        crate::traced::spawn_detached(
            tracing::info_span!(parent: None, "sessions.manager"),
            mngr.mainloop(),
        );
        Ok(handle)
    }
}

/// One box's move off the `127.0.0.1` interim, as the present landing's
/// sweep draws it: the box (`session`, `name`, `ports`) and the address it
/// is to move to — its own hand for a box a creator handed one (`hand`,
/// never a grant drawn from the pool: a hand is only ever replaced by
/// `127.0.0.1`, and the attach path's forwards name the hand as their
/// `local`), a grant the answerer just leased for a box nobody handed an
/// address.
#[cfg(target_os = "linux")]
pub(crate) struct InterimUpgrade {
    /// The session whose box the move re-publishes.
    pub(crate) session: SessionId,
    /// The box name the move re-registers.
    pub(crate) name: String,
    /// The ports the box's declaration publishes.
    pub(crate) ports: BTreeSet<u16>,
    /// The address the box moves to.
    pub(crate) address: Ipv4Addr,
    /// Whether `address` is the box's own hand rather than a grant the
    /// landing drew — the arm that discards a move must not release a hand
    /// it never drew.
    pub(crate) hand: bool,
}

/// Lands a range verdict the way the deferred walk lands it
/// ([`crate::box_manager::BoxManager::init`]'s spawned probe): the state moves
/// first, then the arm that follows it runs over the publishes the old
/// verdict left standing — the one moment a verdict's landing has effects
/// beside the atomic it sets, and the reason the walk cannot simply store
/// its answer.
///
/// An **absent** landing moves every own-address publish standing inside the
/// reserved local range onto the `127.0.0.1` interim (NET-123): the surface
/// cannot bind what those boxes hold, so their attach would fail at it until
/// destroy. The landing is the one moment the daemon holds both facts — the
/// verdict and every publish it contradicts — so it re-publishes each such
/// box at the interim, name and route with it, and the box's attach binds
/// where the surface listens instead of failing until destroy. The arm is
/// a belt behind the pending window's gate: no production path publishes a
/// reserved-range address under anything but a landed present verdict — a
/// hand waits for one or stands at the interim, and a resumed box the
/// record already names is answered with the interim until the present
/// landing restores its recorded address — so a publish this arm finds is
/// one a verdict vouched for and a later landing contradicts.
///
/// A **present** landing moves every own-address publish standing at the
/// interim onto the address it is owed: its own hand for a box a creator
/// handed one, a grant the answerer just leased for a box nobody handed an
/// address. The interim is the ask's own answer for a verdict that had not
/// landed, never an address the box owns, so the landing that replaces the
/// verdict is the moment those asks upgrade — without it the box would
/// stand at `127.0.0.1` until destroy. The move is drawn in two halves
/// ([`draw_interim_upgrades`], [`apply_interim_upgrade`]) because the draw
/// runs outside every registry lock — the ask is a read-modify-write of the
/// answerer's record under its own lock file — and the box can die inside
/// that window: the apply re-checks, under the write lock, that the box
/// still holds its name and still stands at the interim, and a box that
/// does not has nothing published — names are first-writer-owned, so a
/// destroyed box's re-registered name would block the next box that takes
/// it — and, when its publish is gone (the destroyed box), its drawn grant
/// released unpublished.
///
/// The verdict is set **before** either arm runs, so a registration racing
/// the landing reads the landed verdict: its hand is gated by
/// [`crate::net::dns::LoopbackLeaseBook::vouches_for`] — and a hand that
/// meets it unvouched is woken by the landing's broadcast, inside the
/// daemon's one verdict deadline it waits bounded by
/// ([`crate::net::dns::LoopbackLeaseBook::await_vouch_for`]), or re-reads
/// the verdict under the registry's write lock before it publishes — its
/// ask by the verdict's own arm, and each sweep only re-publishes what
/// still stands.
#[cfg(target_os = "linux")]
fn land_range_verdict(
    book: &crate::net::dns::LoopbackLeaseBook,
    registry: &RwLock<crate::net::dns::HostnameRegistry>,
    verdict: crate::net::dns::RangeVerdict,
) {
    book.set_range_verdict(verdict);
    match verdict {
        crate::net::dns::RangeVerdict::Present => {
            for upgrade in draw_interim_upgrades(book, registry) {
                apply_interim_upgrade(book, registry, &upgrade);
            }
        }
        crate::net::dns::RangeVerdict::Absent => {
            // The boxes the window published at reserved-range addresses:
            // the surface cannot bind what they hold, and their attach
            // would fail at it until destroy. One registry lock across the
            // sweep, so no answer reads a half-moved table.
            let mut reg = registry.write().expect("hostname registry lock poisoned");
            for (session, name, from, ports) in reg.own_publishes_in_reserved_range() {
                tracing::warn!(
                    session_id = %session,
                    session_name = &name,
                    from = %from,
                    to = %Ipv4Addr::LOCALHOST,
                    action = "loopback-range-absent-box",
                    "a box's publish stood inside the reserved local range; \
                     the range is absent on the publish surface, so the \
                     publish — name and route with it — moves to the \
                     127.0.0.1 interim",
                );
                reg.publish_own_address(session, &name, Ipv4Addr::LOCALHOST, ports.clone());
                reg.register_own_ip(session, &name, ports);
            }
        }
        // The state a book opens on and the state a test re-opens it in:
        // nothing has been published under it to sweep.
        crate::net::dns::RangeVerdict::Pending => {}
    }
}

/// The present landing's first half: enumerate the boxes standing at the
/// interim under a read lock, then — outside every registry lock — draw the
/// address each is to move to, the hand a creator gave it or a grant the
/// answerer just leased. Split from the apply because the draw's grant is a
/// read-modify-write of the answerer's record under its lock file, and the
/// registry is what every DNS answer this daemon serves reads; the apply
/// re-checks under the write lock what the box is *now*, because the window
/// between the two halves is long enough for a box to die in.
///
/// A grant withheld at the draw leaves the box at the interim — the
/// surface's own answer again, said out loud — and its next finalize
/// re-asks. A hand the (just-landed) present verdict does not vouch for is
/// not moved at all: the same gate the registration path reads.
#[cfg(target_os = "linux")]
pub(crate) fn draw_interim_upgrades(
    book: &crate::net::dns::LoopbackLeaseBook,
    registry: &RwLock<crate::net::dns::HostnameRegistry>,
) -> Vec<InterimUpgrade> {
    let standing = registry
        .read()
        .expect("hostname registry lock poisoned")
        .interim_own_publishes();
    let mut drawn = Vec::new();
    for publish in standing {
        // A box a creator handed an address moves back to it, never to a
        // grant from the pool: the hand is the host-side table's row, the
        // address the attach path's expose requests name, and a hand is
        // only ever replaced by `127.0.0.1` — so the landing's move for it
        // is the return, not a substitution, and a hand the verdict does
        // not vouch for leaves the box where it is, never drawing a grant.
        if let Some(hand) = publish.hand {
            if book.vouches_for(hand) {
                drawn.push(InterimUpgrade {
                    session: publish.session,
                    name: publish.name,
                    ports: publish.ports,
                    address: hand,
                    hand: true,
                });
            }
            continue;
        }
        match book.grant(crate::net::dns::LeaseNamespace::Box {
            session: publish.session,
        }) {
            crate::net::dns::LoopbackGrant::Granted(address) => drawn.push(InterimUpgrade {
                session: publish.session,
                name: publish.name,
                ports: publish.ports,
                address,
                hand: false,
            }),
            // A grant withheld at the draw leaves the box at the interim
            // — the surface's own answer again — and its next finalize
            // re-asks.
            granted => tracing::warn!(
                session_id = %publish.session,
                session_name = &publish.name,
                grant = ?granted,
                action = "loopback-lease-withheld",
                "the verdict landed present but the box's re-ask was \
                 refused; it keeps the 127.0.0.1 interim it stands on"
            ),
        }
    }
    drawn
}

/// The present landing's second half: re-publish one drawn box at the
/// address it was drawn — under the write lock, and only if the box still
/// exists. The draw ran outside every registry lock, so between it and this
/// the box may have been destroyed, its name taken over by a
/// rename or a later session, or its publish moved off the interim by its
/// own next registration; names are first-writer-owned, so any of those
/// means the move publishes nothing. `true` when the move was made, `false`
/// when it was discarded. A discarded box whose publish is gone — the
/// destroyed box — has the drawn grant released back through the
/// answerer's channel, outside the registry's lock the same way the draw
/// took it, so a dead box's landing cannot spend an address the pool would
/// then hold spoken for. One whose publish still stands keeps the grant:
/// the grant is idempotent by namespace, so a box that moved off the
/// interim through its own re-registration stands at the very address the
/// draw recorded, and a renamed one is answered with it at its next
/// registration; releasing it would free an address a live box holds. A
/// stopped box keeps its name, so the move applies to it with its stopped
/// marker intact.
///
/// The re-check is a runtime one, not an ordering argument: the landing
/// runs on the deferred walk's own spawned task
/// ([`crate::box_manager::BoxManager::init`]), never through the manager's
/// mailbox or a session actor's, so a destroy can land anywhere between
/// the draw's enumeration, its grant, and this apply.
#[cfg(target_os = "linux")]
pub(crate) fn apply_interim_upgrade(
    book: &crate::net::dns::LoopbackLeaseBook,
    registry: &RwLock<crate::net::dns::HostnameRegistry>,
    upgrade: &InterimUpgrade,
) -> bool {
    // The re-check, and the move, under the one write lock: no answer reads
    // a half-moved table, and no other registration can slip between the
    // check and the publish.
    let (applied, publish_gone) = {
        let mut reg = registry.write().expect("hostname registry lock poisoned");
        let standing = reg.published_own_address(upgrade.session);
        let box_still_exists = reg.name_held_by(upgrade.session, &upgrade.name)
            && standing == Some(Ipv4Addr::LOCALHOST);
        let applied = if !box_still_exists {
            false
        } else {
            // The move is said out loud, naming the box and both addresses
            // (NET-123 §7.1): the interim was a publishable stand-in, the
            // move is the box taking the address it was owed.
            tracing::warn!(
                session_id = %upgrade.session,
                session_name = &upgrade.name,
                from = %Ipv4Addr::LOCALHOST,
                to = %upgrade.address,
                action = "loopback-range-present-box",
                "the verdict landed present; a box standing on the \
                 127.0.0.1 interim moves to the address it is owed — its \
                 own hand for a handed box, a grant the answerer leased it"
            );
            reg.publish_own_address(
                upgrade.session,
                &upgrade.name,
                upgrade.address,
                upgrade.ports.clone(),
            );
            reg.register_own_ip(upgrade.session, &upgrade.name, upgrade.ports.clone());
            true
        };
        (applied, standing.is_none())
    };
    if applied {
        return true;
    }
    // The discard: publish nothing, and hand the drawn grant back only when
    // the box's publish is gone — the destroyed box. A box still standing
    // somewhere keeps the grant (see the doc above). A hand is never
    // released — it was never drawn from the pool, and the host-side table's
    // row keeps it whatever this daemon does. The release runs outside the
    // registry's lock, the same order the draw's grant took it in; its
    // answer says which call actually took the line, the discard's or a
    // destroy that got there first.
    let released = if upgrade.hand || !publish_gone {
        None
    } else {
        book.release(crate::net::dns::LeaseNamespace::Box {
            session: upgrade.session,
        })
    };
    tracing::warn!(
        session_id = %upgrade.session,
        session_name = &upgrade.name,
        from = %Ipv4Addr::LOCALHOST,
        to = %upgrade.address,
        released = ?released,
        action = "loopback-lease-discarded",
        "the box moved or died inside the landing's window; the publish it \
         stood on is not moved, and the grant drawn for a destroyed box is \
         released unpublished"
    );
    false
}

/// The ids of every session record the store holds: the store's whole live
/// set, not this daemon's. The session store lives under the shared state
/// root, so every daemon instance on the host reads the same set — which is
/// what makes a box's session id a host-global key, and the answerer's
/// start-time sweep ([`crate::net::dns::LoopbackLeaseBook::release_dead_boxes`])
/// a verdict about the *host*, not about which daemon happened to restart:
/// a grant is dead exactly when its session is gone from the store, however
/// many daemons are running.
#[cfg(target_os = "linux")]
async fn live_session_ids(
    store: &crate::store::StoreHandle,
) -> Result<BTreeSet<SessionId>, std::io::Error> {
    let mut live = BTreeSet::new();
    for handle in store.handles().await? {
        live.insert(*handle.id());
    }
    Ok(live)
}

/// Delete on-disk records whose status is unresumable after a
/// daemon restart. See [`BoxManager::init`] for why `Pending` and
/// `Materializing` records fall into this category. A delete
/// failure is logged and skipped — a leftover record wastes a
/// name until it's cleaned up manually but shouldn't block
/// startup.
async fn reap_unresumable_records(store: &crate::store::StoreHandle) -> Result<(), std::io::Error> {
    let handles = store.handles().await?;
    for handle in handles {
        let record = match handle.record().await {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(
                    session_id = %handle.id(),
                    error = %e,
                    "reap: could not read record; skipping",
                );
                continue;
            }
        };
        match record.status {
            boxes::BoxState::Pending | boxes::BoxState::Materializing => {
                let id = *handle.id();
                let status = record.status;
                if let Err(e) = handle.delete().await {
                    tracing::warn!(
                        session_id = %id,
                        error = %e,
                        ?status,
                        "reap: failed to delete unresumable record",
                    );
                } else {
                    tracing::info!(
                        session_id = %id,
                        ?status,
                        "reap: deleted unresumable record left over from a prior daemon lifetime",
                    );
                }
            }
            boxes::BoxState::Active => {}
        }
    }
    Ok(())
}

/// Per-session deadline for the host probes this manager makes — the
/// attributes [`ManagerMessage::List`] reports, and the screen snapshot
/// [`ManagerMessage::GetScreen`] answers with.
///
/// A probe crosses two more actor mailboxes — the session actor, then its
/// host — either of which can legitimately be mid-operation. The manager's
/// mainloop is serial and is the single entry point for *every* session RPC,
/// so it must never wait on one of them without a bound: a session that could
/// not answer once wedged `min ls`, `min session ...` and even `Shutdown`
/// daemon-wide until the daemon was killed. A session that misses the
/// deadline reports no `attrs` / no screen, which is what a session with no
/// running host already reports.
///
/// Aliases the session actor's bound on the same probes rather than picking
/// its own number, so the two hops cannot drift apart.
const HOST_PROBE_TIMEOUT: std::time::Duration = crate::box_actor::HOST_PROBE_TIMEOUT;

impl BoxManager {
    /// The async task which handles interactions with the
    /// manager.
    async fn mainloop(mut self) {
        while let Some((msg, caller)) = self.receiver.recv().await {
            // One span per message, opened now and a child of the sender's
            // ids (see `traced::Receiver::recv`): a message that holds the
            // loop (an inline await on a busy actor) shows as a long span
            // here, and every caller queued behind it waits for its end.
            let span = tracing::info_span!(
                parent: None,
                "sessions.manager.message",
                kind = msg.kind(),
                queued_behind = self.receiver.len(),
                trace_id = tracing::field::Empty,
                span_id = tracing::field::Empty,
                parent_span_id = tracing::field::Empty,
            );
            crate::exec::adopt_trace(&span, caller);
            tracing::Instrument::instrument(self.handle_message(msg), span).await;
        }
    }

    /// Resolves the predicate to a live session actor, spawning one from the
    /// on-disk record if the session is known but not running. Shared by
    /// every manager operation that needs a session actor.
    ///
    /// The store is consulted *before* the running map so a session mid-
    /// self-teardown (its actor deleted the record but hasn't been evicted
    /// yet) resolves to `None` rather than a dying handle. Record status
    /// doesn't gate resolution: the actor's state machine decides which
    /// operations are valid, including for a `Pending` record brought up
    /// without its (in-memory only, so long-gone) compose state — such a
    /// session resolves to an unconfigured `Draft` that can be re-configured
    /// or aborted, rather than to an unreachable record.
    async fn resolve_session(
        &mut self,
        pred: BoxKeyPredicate,
    ) -> Result<Option<BoxHandle>, BoxManagerError> {
        if self.in_shutdown.is_cancelled() {
            return Err(BoxManagerError::new(
                std::io::ErrorKind::ConnectionRefused,
                minimald_rpc::SHUTDOWN_REFUSAL,
            ));
        }
        let Some(handle) = self.store.find(pred.into()).await? else {
            return Ok(None);
        };
        let session_id = *handle.id();
        // Being torn down: the record outlives the actor by the length of
        // its teardown task, and a session in that window is gone, not idle.
        // Checked before `running`: a cleanup destroy leaves its actor there
        // while the actor decides (it may keep the session), and a handle
        // given out meanwhile would queue behind that destroy, against a
        // session the system may have ended by the time it is served.
        if self
            .tearing_down
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains(&session_id)
        {
            return Ok(None);
        }
        if let Some(h) = self.running.get(&session_id) {
            return Ok(Some(h.clone()));
        }
        // Not running, start it! The find above is an await, so a teardown
        // can delete the record and leave the tearing-down set before the
        // check that follows it; the actor then fails to read a record that
        // is gone, and that is "no such session" to the caller, not an error.
        let h = match BoxActor::run(self.session_config(handle)).await {
            Ok(h) => h,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        self.running.insert(session_id, h.clone());
        Ok(Some(h))
    }

    /// Whether the session that answers to `name` is in the tearing-down
    /// set: `None` when no record answers to it any more (a teardown that
    /// ended since the caller's collision). A store error reads as
    /// `Some(false)`: the caller then reports the plain collision it
    /// already had.
    async fn name_is_being_destroyed(&self, name: &str) -> Option<bool> {
        match self
            .store
            .find(RecordPredicate::Name(name.to_string()))
            .await
        {
            Ok(Some(handle)) => Some(
                self.tearing_down
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .contains(handle.id()),
            ),
            Ok(None) => None,
            Err(_) => Some(false),
        }
    }

    /// Starts the actor of every `Active` record whose box owns a name
    /// (`HostNet`, `OwnIp`) and has no actor yet. A session's name is
    /// registered when its actor starts ([`BoxActor::run`]), and a restarted
    /// daemon otherwise starts an actor only when an RPC first names the
    /// session, so until then the name of a session `min ls` lists as active
    /// answers NXDOMAIN and the proxy has no route for it.
    ///
    /// A resumed box with an own address its VM handed it
    /// (`record.box_addresses`) also gets its host launched, detached from
    /// this resume and unattached to any client: the host's launch is what
    /// attaches the box's shuttle, whose lease announcement — a gratuitous
    /// ARP from the box's address, the one frame an idle box sends — marks
    /// the box's host-side row carried (minvmd's `BoxTable::carry`), and
    /// the attach binds its declared ingress forwards — so the box's
    /// published name keeps answering and its ingress binds without waiting
    /// for a client's first exec or attach.
    /// The row a reloaded host registry reinstated awaits this first frame
    /// under its resume bound, which the VM's cold boot must fit inside.
    ///
    /// Resuming through [`BoxActor::run`] keeps one registration path, with
    /// its collision rules and its rule never to wait on the range verdict.
    /// It is idempotent: a session already in `running` is skipped, and a
    /// later RPC that names a resumed session finds its actor there rather
    /// than registering it again.
    ///
    /// A record whose box name is already routed for another session is not
    /// resumed: [`crate::net::dns::HostnameRegistry`] lets the later
    /// registration take the route over, and a restart must not move a name
    /// from one session to another. The check keys on the session id, not
    /// the name — two restored sessions can share one registry name
    /// outright (two unnamed sessions whose project directories share a
    /// basename), the pair the store's name-uniqueness check never sees, as
    /// well as fold to one hostname. That record keeps the lazy path.
    /// A record that cannot be read, or whose actor fails to start, is
    /// logged and skipped, so one bad record costs only its own name.
    #[cfg(target_os = "linux")]
    async fn resume_active_sessions(&mut self) -> Result<usize, BoxManagerError> {
        if self.in_shutdown.is_cancelled() {
            return Ok(0);
        }
        let mut resumed = 0;
        // Oldest session first (the id is a UUIDv7): each resumed box
        // publishes as its actor starts, and a shared-address port goes to
        // the first box publishing it, so this order gives the port to the
        // box created earliest — the box a live hand-over elects (NET-129)
        // — unless a later box bound it before the restart, which takes it
        // back at its own publish (`restore_bound_ports`). The store lists
        // its keys by a random suffix of the id.
        let mut handles = self.store.handles().await?;
        handles.sort_by_key(|handle| *handle.id());
        for handle in handles {
            let session_id = *handle.id();
            // Running, or being torn down (its record outlives its actor by
            // the teardown task's length): either way not one to bring up.
            if self.running.contains_key(&session_id)
                || self
                    .tearing_down
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .contains(&session_id)
            {
                continue;
            }
            let record = match handle.record().await {
                Ok(record) => record,
                Err(error) => {
                    tracing::warn!(
                        session_id = %session_id,
                        %error,
                        "resume: could not read the session record; its name stays \
                         unregistered until an RPC names the session",
                    );
                    continue;
                }
            };
            if !matches!(record.status, boxes::BoxState::Active)
                || !matches!(
                    record.network,
                    boxes::NetworkMode::HostNet | boxes::NetworkMode::OwnIp
                )
            {
                continue;
            }
            let name = crate::box_actor::registry_name(&record);
            if let Some(owner) = self
                .hostnames
                .read()
                .expect("hostname registry lock poisoned")
                .hostname_held_by_another(session_id, &name)
            {
                tracing::warn!(
                    session_id = %session_id,
                    session_name = &name,
                    owner,
                    action = "hostname-collision",
                    "resume: the box name is already routed for another session; \
                     not resuming this one, so the restart does not move the name",
                );
                continue;
            }
            match BoxActor::run(self.session_config(handle)).await {
                Ok(session) => {
                    // An own-address box's host is what carries its shuttle,
                    // and with the shuttle the row's first frame — the lease
                    // announcement its attach sends (`net::switch`), the frame
                    // that stands the reloaded row and binds the declared
                    // ingress. Launched detached from this resume and never
                    // attached to a client, so the next attach or exec finds
                    // it and reuses it, as an exec-minted host is reused.
                    if matches!(record.network, boxes::NetworkMode::OwnIp)
                        && record.box_addresses.is_some()
                    {
                        let session = session.clone();
                        let username = record.username.clone().unwrap_or_else(|| "user".into());
                        crate::traced::spawn_detached(
                            tracing::info_span!(
                                parent: None,
                                "resume_own_ip_host",
                                session_id = %session_id
                            ),
                            async move {
                                if let Err(error) = session.ensure_host(username).await {
                                    tracing::warn!(
                                        %error,
                                        "resume: could not launch the own-address \
                                         box's host; its ingress binds at its \
                                         first exec or attach",
                                    );
                                }
                            },
                        );
                    }
                    self.running.insert(session_id, session);
                    resumed += 1;
                }
                Err(error) => tracing::warn!(
                    session_id = %session_id,
                    session_name = &name,
                    %error,
                    "resume: could not start the session's actor; its name stays \
                     unregistered until an RPC names the session",
                ),
            }
        }
        if resumed > 0 {
            tracing::info!(resumed, "resumed active sessions so their names route");
        }
        Ok(resumed)
    }

    /// The spawn-time config for a session actor backing `record`. The one
    /// place the daemon-scoped dependencies are gathered, so the create and
    /// bring-up-from-disk paths can't hand their actors different worlds.
    fn session_config(&self, record: BoxRecordHandle) -> BoxActorConfig {
        BoxActorConfig {
            minimal_state_dir: self.minimal_state_dir.clone(),
            minimal_cache_dir: self.minimal_cache_dir.clone(),
            daemon_ctx: Arc::clone(&self.daemon_ctx),
            record,
            net_switch: Arc::clone(&self.net_switch),
            manager: self.weak_self.clone(),
            deny_all_opt_out: self.deny_all_opt_out,
            creator: None,
            #[cfg(target_os = "linux")]
            hostnames: Arc::clone(&self.hostnames),
            #[cfg(target_os = "linux")]
            loopback: Arc::clone(&self.loopback),
        }
    }

    /// Allocate a session's record and bring its actor up as `Draft`.
    /// Compose is *not* driven from here: the client's `cmd_activate` runs
    /// its own workspace upload (`WorkspaceFilesTarZst`) after the
    /// returned id, then sends a separate `ConfigureLoadout` RPC that the
    /// actor handles to compose the loadout and promote itself to
    /// `Active`. That split is load-bearing — the compose reads the
    /// project mfile off the daemon-side workspace, which is only
    /// populated once the upload has landed.
    ///
    /// If the actor can't be spawned the record is rolled back — the caller
    /// never received an id, so nothing else could ever reach the session to
    /// abort it, and a `Pending` record left parked would hold its name
    /// hostage.
    #[tracing::instrument(
        level = "info",
        name = "box.create",
        skip_all,
        fields(
            box_id = tracing::field::Empty,
            box_type = tracing::field::Empty,
            parent = tracing::field::Empty,
            spec_bytes = tracing::field::Empty,
        )
    )]
    async fn create_session(
        &mut self,
        config: minimald_rpc::BoxConfig,
        spec: Option<serde_json_lenient::Value>,
        username: Option<String>,
        creator: Option<std::sync::Weak<()>>,
    ) -> Result<SessionId, BoxManagerError> {
        if self.in_shutdown.is_cancelled() {
            return Err(BoxManagerError::new(
                std::io::ErrorKind::ConnectionRefused,
                minimald_rpc::SHUTDOWN_REFUSAL,
            ));
        }
        // NET-079: a host that decides per box refuses a host-address
        // declaration naming rules its classifier cannot enforce — a denied
        // range, a narrowing allow list — and refuses it here, before
        // anything is allocated: no record, no id, no name held, no actor
        // spawned. The host's state is the daemon's one node fact, read
        // exactly as the create response reads it — a create is not a place
        // that decides a box, so it re-probes nothing itself — and the
        // same `can_decide_per_box` the launch that follows re-reads for
        // its own gate; a host that cannot decide per box answers `false`
        // and the create falls through to the exception whole — the box is
        // created, runs unenforced and is recorded as such, never refused
        // on this ground. Own-address boxes are untouched here: their
        // declarations are enforced on the address the box holds, so the
        // gate is the host-address mode's alone.
        if let Some(rules) = crate::net::classifier::refuses_unenforceable_declaration(
            config.network,
            crate::box_runtime::host_ip_enforcement_fact().can_decide_per_box(),
            config.policy.egress.as_ref(),
        ) {
            let refusal = crate::net::classifier::unenforceable_declaration_refusal(&rules);
            REFUSED_UNENFORCEABLE_CREATES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            tracing::info!(
                session_name = config.name.as_deref().unwrap_or(crate::rpc::ANONYMOUS_SESSION),
                network_mode = %config.network.word(),
                host_ip_enforcement = %minimald_rpc::HostIpEnforcement::PerBox.machine_str(),
                refused_unenforceable_creates = refused_unenforceable_creates(),
                refusal = %refusal,
                "refused a create whose host-address declaration names rules \
                 this host's classifier cannot enforce"
            );
            return Err(refusal);
        }
        // BOX-068: the spec is checked before the record exists, so a
        // refused spec leaves no record, id or name behind.
        let spec = match spec.as_ref().map(spec_bytes).transpose() {
            Ok(spec) => spec,
            Err(refusal) => {
                tracing::info!(
                    session_name = config.name.as_deref().unwrap_or(crate::rpc::ANONYMOUS_SESSION),
                    refusal = %refusal,
                    "refused the box spec on a create"
                );
                return Err(refusal);
            }
        };
        if let Some(bytes) = &spec {
            tracing::Span::current().record("spec_bytes", bytes.len());
        }
        // Allocate the record up front: `store.create` assigns the id and
        // catches a name collision (`AlreadyExists`) before any actor exists.
        // On a VM guest the box id is the one the VM host handed in
        // `config.box_id`, and the in-VM store still mints the record key
        // (https://github.com/gominimal/minimal/issues/2397 files the
        // record under the handed id). Elsewhere the
        // record key is the box id.
        let handed_box_id = config.box_id;
        // BOX-001, BOX-140: no caller reaches this daemon from inside a box
        // (a host with no nesting carries no per-box caller identity), so
        // every box created here has no parent. A parent comes from the
        // creating connection once one can carry that identity, never from
        // the request body.
        let parent = None;
        // BOX-001: the type is the creating verb's. A client that predates
        // the field sends none, which reads as the session verb.
        let box_type = match config.creating_verb {
            minimald_rpc::CreatingVerb::Session => boxes::SESSION_BOX_TYPE,
            minimald_rpc::CreatingVerb::Task => boxes::TASK_BOX_TYPE,
        };
        let record = build_record(config, username, boxes::BoxState::Pending, box_type, parent)?;
        tracing::Span::current().record("box_type", box_type);
        let project_root = record.project_root.clone();
        let name = record.name.clone();
        let retry = record.clone();
        let handle = match self.store.create(record).await {
            Ok(handle) => handle,
            // The name may be held by a session whose destroy is still
            // running (its record outlives its actor by the length of the
            // teardown task, a stalled clone's connect timeout at worst):
            // say so, rather than report a plain collision the user cannot
            // see in `min ls`, where that session is no longer listed.
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                // The teardown runs beside this mainloop, so it can end
                // between the collision and the re-read: a record gone by
                // then was a session destroyed meanwhile, and the name is
                // free now, so take it. Once: a second collision is a
                // session created meanwhile, which is a plain collision.
                let Some(name) = name else { return Err(e) };
                match self.name_is_being_destroyed(&name).await {
                    Some(true) => {
                        return Err(BoxManagerError::new(
                            std::io::ErrorKind::AlreadyExists,
                            format!(
                                "a session named `{name}` is still being destroyed; run \
                                 `min session activate --name {name}` again once it is gone"
                            ),
                        ));
                    }
                    None => self.store.create(retry).await?,
                    Some(false) => return Err(e),
                }
            }
            Err(e) => return Err(e),
        };
        let session_id = *handle.id();
        let box_id = handed_box_id.unwrap_or(session_id);
        let parent_field = parent.map_or_else(|| "none".to_string(), |p: SessionId| p.to_string());
        let span = tracing::Span::current();
        span.record("box_id", tracing::field::display(box_id));
        span.record("parent", parent_field.as_str());
        tracing::info!(
            session_id = %session_id,
            box_id = %box_id,
            box_type = %box_type,
            parent = %parent_field,
            project_root = ?project_root.as_ref().map(paths::HostAbsPath::as_str),
            "filed the box record"
        );

        // BOX-068: the spec is written beside the record before the actor
        // starts. A spec that cannot be written takes the record with it:
        // the caller never received the id, so nothing else could reach it.
        if let Some(bytes) = &spec {
            let stored = match handle.object().await {
                Ok(object) => object.store_spec(bytes).map(|()| object.spec_path()),
                Err(e) => Err(e),
            };
            match stored {
                Ok(path) => tracing::info!(
                    session_id = %session_id,
                    spec_bytes = bytes.len(),
                    spec_path = %path.as_str(),
                    "stored the box spec"
                ),
                Err(e) => {
                    tracing::warn!(
                        session_id = %session_id,
                        error = %e,
                        "could not store the box spec; deleting the record"
                    );
                    if let Err(del_err) = handle.delete().await
                        && del_err.kind() != NotFound
                    {
                        tracing::warn!(
                            session_id = %session_id,
                            error = %del_err,
                            "failed to delete the session record after the spec \
                             was not stored; it will linger until it is deleted explicitly",
                        );
                    }
                    return Err(e);
                }
            }
        }

        let mut seed = self.session_config(handle.clone());
        seed.creator = creator;
        match BoxActor::run(seed).await {
            Ok(session) => {
                self.running.insert(session_id, session);
                Ok(session_id)
            }
            // The actor never started, so no one else will delete the
            // record. Best-effort: the spawn error is what the client needs
            // to see, and a leftover `Pending` record is inert — no actor
            // holds it, so it only costs a name until it is deleted.
            Err(e) => {
                if let Err(del_err) = handle.delete().await
                    && del_err.kind() != NotFound
                {
                    tracing::warn!(
                        session_id = %session_id,
                        error = %del_err,
                        "failed to delete the session record after a create \
                         failure; it will linger until it is deleted explicitly",
                    );
                }
                Err(e)
            }
        }
    }

    /// Handles a specific message recieved by the manager.
    async fn handle_message(&mut self, msg: ManagerMessage) {
        match msg {
            // Lists all sessions.
            ManagerMessage::List(r) => {
                let running = &self.running;
                let store = &self.store;
                // A session being torn down is gone here as it is to the
                // resolver: its record outlives its actor only by the length
                // of the teardown task.
                let tearing_down = self
                    .tearing_down
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .clone();
                r.handle(async move {
                    let mut records = Vec::with_capacity(32);
                    for handle in store.handles().await? {
                        if tearing_down.contains(handle.id()) {
                            continue;
                        }
                        records.push(handle.record().await?);
                    }
                    // The attrs probes run in parallel and each under
                    // `HOST_PROBE_TIMEOUT`, so one unresponsive session
                    // costs its own `attrs` rather than the mainloop.
                    // Serially they would also cost N deadlines instead of
                    // one, which the mainloop pays on behalf of every
                    // queued RPC.
                    let out =
                        futures::future::join_all(records.into_iter().map(|record| async move {
                            let attrs = match running.get(&record.id) {
                                Some(h) => tokio::time::timeout(HOST_PROBE_TIMEOUT, h.get_attrs())
                                    .await
                                    .unwrap_or(None),
                                None => None,
                            };
                            BoxInfo {
                                id: record.id,
                                name: record.name.clone(),
                                project_path: record.project_path.clone(),
                                status: record.status,
                                attrs,
                            }
                        }))
                        .await;
                    Ok(out)
                })
                .await;
            }
            // Gets the record for a specific session.
            ManagerMessage::GetRecord(pred, r) => {
                let tearing_down = self
                    .tearing_down
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .clone();
                r.handle(async {
                    Ok::<_, BoxManagerError>(match self.store.find(pred.into()).await? {
                        // Gone, as to the listing and the resolver.
                        Some(handle) if tearing_down.contains(handle.id()) => None,
                        Some(handle) => Some(handle.record().await?),
                        None => None,
                    })
                })
                .await;
            }
            #[cfg(target_os = "linux")]
            ManagerMessage::ResumeActive(r) => {
                r.handle(self.resume_active_sessions()).await;
            }
            #[cfg(test)]
            ManagerMessage::RunningCount(r) => {
                let n = self.running.len();
                r.handle(async move { Ok::<_, BoxManagerError>(n) }).await;
            }
            #[cfg(test)]
            ManagerMessage::RunningIds(r) => {
                let ids: Vec<SessionId> = self.running.keys().copied().collect();
                r.handle(async move { Ok::<_, BoxManagerError>(ids) }).await;
            }
            ManagerMessage::GetComposition(pred, r) => {
                let tearing_down = self
                    .tearing_down
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .clone();
                r.handle(async {
                    Ok::<_, BoxManagerError>(match self.store.find(pred.into()).await? {
                        // Gone, as to `GetRecord`: one answer per session
                        // across the read RPCs during its teardown.
                        Some(handle) if tearing_down.contains(handle.id()) => None,
                        Some(handle) => handle.load_composition().await?,
                        None => None,
                    })
                })
                .await;
            }
            // Get the session actor for the predicate, starting it
            // if the session is known but not running.
            ManagerMessage::GetSession(pred, r) => {
                r.handle(self.resolve_session(pred)).await;
            }
            // Snapshot a running session's screen without starting its
            // actor. A name resolves through the store to its id, then the
            // `running` map answers only for live actors.
            ManagerMessage::GetScreen(pred, r) => {
                // Resolving the predicate to a live actor stays on the
                // mainloop: the store's handlers are all synchronous, so
                // that hop cannot park. The probe does not stay — it
                // crosses the session actor and then its host, either of
                // which can be mid-attach or mid-teardown, and this loop
                // is the single entry point for every session RPC.
                //
                // `min dash` polls this for the focused session on every
                // refresh tick, so leaving it inline meant one wedged host
                // froze `List`, `GetRecord`, `CreateSession` and `Shutdown`
                // daemon-wide — the same failure `List` was just fixed for,
                // reached through `GetSessionScreen` instead.
                let resolved = async {
                    let id = match pred {
                        BoxKeyPredicate::Id(id) => id,
                        BoxKeyPredicate::Name(name) => {
                            match self.store.find(RecordPredicate::Name(name)).await? {
                                Some(handle) => handle.record().await?.id,
                                None => return Ok(None),
                            }
                        }
                    };
                    Ok::<_, BoxManagerError>(self.running.get(&id).cloned())
                }
                .await;
                match resolved {
                    // Spawned *and* bounded: spawning alone would only move
                    // the hang off this loop and onto a task nothing reaps,
                    // leaving the client on an unanswered oneshot.
                    Ok(Some(h)) => {
                        crate::traced::spawn(async move {
                            r.handle(async move {
                                Ok(tokio::time::timeout(HOST_PROBE_TIMEOUT, h.get_screen())
                                    .await
                                    .unwrap_or(None))
                            })
                            .await;
                        });
                    }
                    // Unknown session, or known but not running: answered
                    // here, since neither touches a host.
                    other => r.handle(async move { other.map(|_| None) }).await,
                }
            }
            // Create a session: allocate the record (as `Pending`) and spawn
            // the session actor. Composing the loadout and promoting the
            // record still belong to the actor; the RPC handler drives that
            // step inline against the freshly-spawned actor, so the client
            // sees the composition outcome in the same `CreateSession`
            // response rather than a separate round-trip.
            ManagerMessage::CreateSession(msg) => {
                let CreateSessionMsg {
                    config,
                    username,
                    creator,
                    responder,
                } = *msg;
                let created = self.create_session(config, None, username, creator).await;
                responder.handle(async move { created }).await;
            }
            ManagerMessage::CreateBox(msg) => {
                let CreateBoxMsg {
                    create:
                        CreateSessionMsg {
                            config,
                            username,
                            creator,
                            responder,
                        },
                    spec,
                } = *msg;
                let created = self.create_session(config, spec, username, creator).await;
                responder.handle(async move { created }).await;
            }
            // Deletes a session: tears down its running host and actor (if
            // any), then removes its on-disk record.
            //
            // The mainloop resolves the record and claims the actor; the
            // teardown itself runs on a task of its own. Awaiting the actor
            // here held every queued caller behind it: the reap of a session
            // whose client gave up on `min session activate` while the
            // actor was inside a stalled package-graph clone parked `min ls`
            // for the rest of the clone's connect timeout (70 s in the lab,
            // 710d).
            ManagerMessage::DeleteSession(id, only_if_unfinalized, r) => {
                if self.in_shutdown.is_cancelled() {
                    r.handle(async {
                        Err(BoxManagerError::new(
                            std::io::ErrorKind::ConnectionRefused,
                            minimald_rpc::SHUTDOWN_REFUSAL,
                        ))
                    })
                    .await;
                    return;
                }
                let handle = match self.store.find(RecordPredicate::Id(id)).await {
                    Ok(Some(handle)) => handle,
                    Ok(None) => {
                        r.handle(async {
                            Err(std::io::Error::new(
                                NotFound,
                                format!(
                                    "{} `{}`",
                                    minimald_rpc::UNKNOWN_SESSION_ID_LEAD,
                                    id.as_ref()
                                ),
                            ))
                        })
                        .await;
                        return;
                    }
                    Err(e) => {
                        r.handle(async { Err(e) }).await;
                        return;
                    }
                };
                // A destroy only for an unfinished session (inbox#690) goes
                // to a live actor unclaimed: the actor decides, after any
                // finalize ahead of it in its mailbox, and evicts itself if
                // it destroys. An idle session has no finalize in flight, so
                // its record answers: a finished one is kept, an unfinished
                // one takes the unconditional path below.
                if only_if_unfinalized {
                    let busy = self
                        .tearing_down
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .contains(&id);
                    if busy {
                        r.handle(async {
                            Err(std::io::Error::new(
                                std::io::ErrorKind::ResourceBusy,
                                format!(
                                    "a destroy of session `{}` is already in flight; if the \
                                     session is still listed once it ends, destroy it again",
                                    id.as_ref()
                                ),
                            ))
                        })
                        .await;
                        return;
                    }
                    if let Some(hnd) = self.running.get(&id).cloned() {
                        // In the tearing-down set until the actor answers, as
                        // an unconditional destroy is for its whole teardown:
                        // a second destroy is refused rather than queued
                        // behind this one (where it would destroy a session
                        // this one reports kept), a listing skips the
                        // session rather than reading a record the actor may
                        // be deleting, and a resolve finds nothing (the actor
                        // stays in `running`, unclaimed, since the session
                        // may be kept; the set is what hides it). A kept
                        // session leaves the set with the answer, and is
                        // listed and resolved again.
                        let tearing_down = Arc::clone(&self.tearing_down);
                        let handle = handle.clone();
                        tearing_down
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .insert(id);
                        let span = tracing::Span::current();
                        self.teardowns.spawn(tracing::Instrument::instrument(
                            async move {
                                let release = TearingDown {
                                    set: tearing_down,
                                    id,
                                };
                                let answer: Result<Option<Vec<String>>, BoxManagerError> = async {
                                    let answer = hnd.destroy_if_unfinalized().await?;
                                    // Belt-and-braces, as on the unconditional
                                    // path: a dead actor (self-terminated, not
                                    // yet evicted) reads as destroyed above,
                                    // and may have died without deleting its
                                    // record. Only a destroyed answer removes
                                    // a leftover: a kept session's record is
                                    // the session. `NotFound` is the normal,
                                    // already-deleted case.
                                    if answer.is_some()
                                        && let Err(e) = handle.delete().await
                                        && e.kind() != NotFound
                                    {
                                        return Err(e);
                                    }
                                    Ok(answer)
                                }
                                .await;
                                // Out of the set before the answer goes out: a
                                // caller that reads the record or the listing on
                                // the reply must not find a kept session still
                                // hidden behind the set.
                                drop(release);
                                r.handle(async { answer }).await;
                            },
                            span,
                        ));
                        while let Some(joined) = self.teardowns.try_join_next() {
                            log_teardown_join(joined);
                        }
                        return;
                    }
                    match handle.record().await {
                        Ok(record) if record.status == boxes::BoxState::Active => {
                            r.handle(async { Ok(None) }).await;
                            return;
                        }
                        Ok(_) => {}
                        Err(e) => {
                            r.handle(async { Err(e) }).await;
                            return;
                        }
                    }
                }
                // One teardown per session: a second destroy that lands
                // while the first runs is refused rather than brought up
                // as a fresh actor whose hooks would run again.
                let tearing_down = Arc::clone(&self.tearing_down);
                let first = tearing_down
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .insert(id);
                if !first {
                    r.handle(async {
                        Err(std::io::Error::new(
                            std::io::ErrorKind::ResourceBusy,
                            format!(
                                "a destroy of session `{}` is already in flight; if the \
                                 session is still listed once it ends, destroy it again",
                                id.as_ref()
                            ),
                        ))
                    })
                    .await;
                    return;
                }
                // Teardown belongs to the actor, so an idle session gets
                // one brought up rather than having its record deleted
                // out from under it. That used to be a fair shortcut —
                // "nothing to undo" — but a session's `on_destroy` hooks
                // now run on this path, and skipping the actor skipped
                // them silently for any session whose actor had been
                // reaped (every session, after a daemon restart).
                //
                // Claimed here, brought up and torn down on a task of its
                // own: the mainloop awaits neither the actor's start (a
                // record and composition read) nor its destroy (hooks), so
                // a listing served meanwhile neither waits nor probes it.
                // The caller gets the outcome when the task ends.
                let claimed = self.running.remove(&id);
                let seed = match claimed {
                    Some(_) => None,
                    None => Some(self.session_config(handle.clone())),
                };
                let in_shutdown = self.in_shutdown.clone();
                let span = tracing::Span::current();
                self.teardowns.spawn(tracing::Instrument::instrument(
                    async move {
                        // Out of the set as this task ends, whatever its outcome.
                        let _release = TearingDown {
                            set: tearing_down,
                            id,
                        };
                        r.handle(async {
                            // A shutdown that began after this destroy was
                            // accepted: an idle session is not brought up
                            // now (a fresh actor and sandbox while shutdown
                            // waits on this task). The destroy is refused, as
                            // one that arrived during shutdown is above, and
                            // the record stays for the next start.
                            if seed.is_some() && in_shutdown.is_cancelled() {
                                return Err(BoxManagerError::new(
                                    std::io::ErrorKind::ConnectionRefused,
                                    minimald_rpc::SHUTDOWN_REFUSAL,
                                ));
                            }
                            let actor = match (claimed, seed) {
                                (Some(hnd), _) => Some(hnd),
                                (None, Some(seed)) => match BoxActor::run(seed).await {
                                    // The check above ran before the bring-up;
                                    // a shutdown that began during it stops the
                                    // fresh actor as it stops a live one, and
                                    // the destroy is refused before its hooks
                                    // would mint a sandbox.
                                    Ok(hnd) if in_shutdown.is_cancelled() => {
                                        hnd.stop().await;
                                        return Err(BoxManagerError::new(
                                            std::io::ErrorKind::ConnectionRefused,
                                            minimald_rpc::SHUTDOWN_REFUSAL,
                                        ));
                                    }
                                    Ok(hnd) => Some(hnd),
                                    // A record the actor refuses to come up on — a
                                    // restart-orphaned `Materializing` one is the
                                    // known case — must still be destroyable, so
                                    // fall through to deleting it directly. A
                                    // session that cannot be torn down is worse
                                    // than one torn down without its hooks.
                                    Err(e) => {
                                        tracing::warn!(
                                            session_id = %id,
                                            error = %e,
                                            "could not start the session to run its destroy hooks; \
                                             removing its record without them",
                                        );
                                        None
                                    }
                                },
                                // A claimed actor comes with no seed; the
                                // match above covers every pair that occurs.
                                (None, None) => None,
                            };
                            match actor {
                                Some(hnd) => {
                                    let hook_failures = hnd.destroy().await?;
                                    // Belt-and-braces: a dead actor (self-terminated
                                    // but not yet evicted) reads as `Ok` above, and
                                    // may have died *without* deleting its record
                                    // (its own delete failed). Remove any leftover;
                                    // `NotFound` is the normal already-deleted case.
                                    if let Err(e) = handle.delete().await
                                        && e.kind() != NotFound
                                    {
                                        return Err(e);
                                    }
                                    Ok(Some(hook_failures))
                                }
                                None => {
                                    handle.delete().await?;
                                    Ok(Some(Vec::new()))
                                }
                            }
                        })
                        .await;
                    },
                    span,
                ));
                // Finished tasks leave the set on their own; their join
                // handles leave it here, so the set holds only the live ones.
                while let Some(joined) = self.teardowns.try_join_next() {
                    log_teardown_join(joined);
                }
            }
            ManagerMessage::Shutdown(force, r) => {
                r.handle(async {
                    // Busy sessions (a `Draft` awaiting its verdict, or a
                    // live host) block an unforced shutdown. Idle actors
                    // don't: every created session now has one, so mere
                    // existence can't be the guard or a create-and-
                    // disconnect client would wedge unforced shutdowns
                    // forever.
                    if !force {
                        for hnd in self.running.values() {
                            if hnd.is_busy().await {
                                return Ok(Err(()));
                            }
                        }
                    }

                    self.in_shutdown.cancel();
                    // Stop live sessions. Each actor kills its host and
                    // withdraws its own PTask hostname (R3.5) on the way
                    // down; records — and, with them, the loopback grants
                    // their boxes would resume at — are kept, since shutdown
                    // is not deletion.
                    for hnd in self.running.values() {
                        hnd.stop().await;
                    }
                    self.running.clear();
                    // Teardowns in flight (`DeleteSession` runs them on tasks
                    // of their own) end before the volume is quiesced: a hook
                    // mid-run or a record delete mid-write would otherwise
                    // race the unmount. The wait is as long as the slowest
                    // of them: a claimed actor reaches its `Destroy` only
                    // after the message it is in, so one inside a stalled
                    // package-graph clone holds shutdown for that clone's
                    // connect timeout (minutes on a dropped route), as the
                    // inline destroy used to; its hooks' timeouts come after.
                    // So does a wait for a hook slot: a destroy with hooks
                    // first takes one of the actor's `DESTROY_HOOK_RUNS`, so
                    // with every slot held it waits behind those runs, each
                    // bounded by its own hooks' timeouts. That wait is the
                    // price of the cap, and it ends: no slot is held past
                    // its run.
                    while let Some(joined) = self.teardowns.join_next().await {
                        log_teardown_join(joined);
                    }
                    // Release the cache's held-open alog fd: it lives on the
                    // state volume, and a surviving write-open fd there makes
                    // the post-drain quiesce (R2.1 syncfs + unmount) fail
                    // EBUSY, leaving the ext4 journal dirty on clean stops.
                    self.daemon_ctx.release_cache_read_tracker();
                    #[cfg(target_os = "linux")]
                    // And the answerer's lease book's lock-file fd — the one
                    // descriptor the book holds open, on the same state
                    // volume, for the same quiesce contract. Read-only, so
                    // it holds no journal back on its own, but the contract
                    // is that the stop leaves *no* descriptor of the
                    // daemon's on the volume.
                    self.loopback.close();
                    Ok(Ok(()))
                })
                .await
            }
            // Actor-initiated termination: drop the running entry. The
            // actor already handled its record and hostname; ids are never
            // reused, so a stale evict can't remove a fresh actor.
            ManagerMessage::Evict(id) => {
                self.running.remove(&id);
            }
        }
    }
}

/// A teardown task that ended by a panic or a cancel took its responder
/// with it, so its caller saw a closed channel and nothing said why: the
/// join error is the only record of it, so it goes to the log.
fn log_teardown_join(joined: Result<(), tokio::task::JoinError>) {
    if let Err(e) = joined {
        tracing::error!(error = %e, "a session teardown task did not finish on its own");
    }
}

/// Removes a session from the manager's tearing-down set when its teardown
/// task ends, however it ends.
struct TearingDown {
    set: Arc<std::sync::Mutex<BTreeSet<SessionId>>>,
    id: SessionId,
}

impl Drop for TearingDown {
    fn drop(&mut self) {
        self.set
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&self.id);
    }
}

#[cfg(test)]
#[cfg(test)]
pub(crate) mod tests;

/// The create path's stamping (BOX-001), driven through the manager actor
/// the `CreateSession` handler calls.
#[cfg(test)]
mod create_stamp_tests {
    use super::*;
    use tempfile::TempDir;

    fn daemon_abs(p: &std::path::Path) -> DaemonAbsPath {
        DaemonAbsPath::try_new(p.to_str().unwrap()).unwrap()
    }

    /// A manager over fresh state and cache directories, its sessions on
    /// the mock launcher, so no create here starts a real box.
    async fn manager() -> (TempDir, TempDir, BoxManagerHandle) {
        let state = TempDir::new().unwrap();
        let cache = TempDir::new().unwrap();
        let switch = Arc::new(Mutex::new(crate::net::SwitchClient::new(
            "/nonexistent/gvproxy",
            state.path().join("gvproxy"),
        )));
        let mctx_config = mctx::ConfigBuilder::new()
            .with_cache_dir(cache.path())
            .with_state_dir(state.path())
            .with_daemon_id("test".to_string())
            .build()
            .unwrap();
        let daemon_ctx = Arc::new(mctx::DaemonContext::init(mctx_config).unwrap());
        let mngr = BoxManager::init(
            daemon_abs(state.path()),
            daemon_abs(cache.path()),
            daemon_ctx,
            switch,
            false,
        )
        .await
        .unwrap();
        (state, cache, mngr)
    }

    /// A create request that tries to assert a parent and a type through
    /// the one free-form field a client fills.
    fn config(name: &str, project: &str) -> minimald_rpc::BoxConfig {
        minimald_rpc::BoxConfig {
            name: Some(name.to_string()),
            project_path: paths::HostAbsPath::try_new(project).unwrap(),
            network: boxes::NetworkMode::default(),
            policy: Default::default(),
            task_addresses: Vec::new(),
            box_id: None,
            box_addresses: None,
            hooks_enabled: true,
            attrs: [
                ("parent".to_string(), SessionId::mint().to_string()),
                ("box_type".to_string(), "task".to_string()),
            ]
            .into_iter()
            .collect(),
            sealed_deliveries: Vec::new(),
            root_certificate: None,
            creating_verb: minimald_rpc::CreatingVerb::Session,
            project_root: None,
        }
    }

    /// The bytes of the spec file beside the record of box `id`, if any.
    fn stored_spec(state: &TempDir, id: SessionId) -> Option<Vec<u8>> {
        for dir in std::fs::read_dir(state.path().join("sessions")).unwrap() {
            let dir = dir.unwrap().path();
            let Ok(record) = std::fs::read_to_string(dir.join("record.json")) else {
                continue;
            };
            if record.contains(&id.to_string()) {
                return std::fs::read(dir.join(boxes::store::SPEC_FILE)).ok();
            }
        }
        None
    }

    /// BOX-068: the spec on the create request is stored beside the new
    /// box's record. A create with no spec stores none, and a spec without
    /// a version is refused before any record is filed.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn create_stores_the_spec_beside_the_record() {
        let (state, _cache, mngr) = manager().await;
        let spec = serde_json_lenient::json!({
            "v": 0,
            "entry": "default",
            "box": {"type": "session"},
            "install": {"packages": ["git"]},
            "network": {"mode": "host_ip"},
        });
        let id = mngr
            .create_box_with_spec(
                config("specced", "/home/dev/proj"),
                Some(spec.clone()),
                None,
                None,
            )
            .await
            .unwrap();
        let stored = stored_spec(&state, id).expect("the spec is stored beside the record");
        let stored: serde_json_lenient::Value = serde_json_lenient::from_slice(&stored).unwrap();
        assert_eq!(stored, spec);

        let id = mngr
            .create_box_with_spec(config("no-spec", "/home/dev/proj"), None, None, None)
            .await
            .unwrap();
        assert_eq!(stored_spec(&state, id), None);

        let err = mngr
            .create_box_with_spec(
                config("bad-spec", "/home/dev/proj"),
                Some(serde_json_lenient::json!({"box": {"type": "session"}})),
                None,
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert!(
            mngr.get_record(BoxKeyPredicate::Name("bad-spec".to_string()))
                .await
                .unwrap()
                .is_none(),
            "a refused spec files no record"
        );
    }

    async fn record(mngr: &BoxManagerHandle, id: SessionId) -> boxes::Record {
        mngr.get_record(BoxKeyPredicate::Id(id))
            .await
            .unwrap()
            .expect("the created record is filed")
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn create_assigns_uuidv7_id_type_and_parent() {
        let (_state, _cache, mngr) = manager().await;
        let first = mngr
            .create_session(config("first", "/home/dev/proj"), None)
            .await
            .unwrap();
        let second = mngr
            .create_session(config("second", "/home/dev/proj"), None)
            .await
            .unwrap();
        assert_ne!(first, second, "each create mints its own id");

        for id in [first, second] {
            let record = record(&mngr, id).await;
            assert_eq!(record.id, id);
            assert_eq!(
                record.id.as_ref().get_version(),
                Some(uuid::Version::SortRand),
                "the box id is a UUIDv7"
            );
            assert_eq!(record.box_type.as_deref(), Some(boxes::SESSION_BOX_TYPE));
            assert_eq!(
                record.parent, None,
                "a caller outside any box creates a box with no parent, \
                 whatever the request carries"
            );
        }
    }

    /// BOX-001: the record's type is the creating verb's, one box per verb.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn legacy_create_path_records_type_from_creating_verb() {
        let (_state, _cache, mngr) = manager().await;
        for (name, verb, expected) in [
            (
                "by-session",
                minimald_rpc::CreatingVerb::Session,
                boxes::SESSION_BOX_TYPE,
            ),
            (
                "by-task",
                minimald_rpc::CreatingVerb::Task,
                boxes::TASK_BOX_TYPE,
            ),
        ] {
            let mut config = config(name, "/home/dev/proj");
            config.creating_verb = verb;
            let id = mngr.create_session(config, None).await.unwrap();
            assert_eq!(record(&mngr, id).await.box_type.as_deref(), Some(expected));
        }
    }

    /// BOX-001: the record holds the project root the client resolved, not
    /// the working path. A client that sends no root gets the working path.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn create_records_project_root() {
        let (_state, _cache, mngr) = manager().await;
        let mut rooted = config("rooted", "/home/dev/proj/sub");
        rooted.project_root = Some(paths::HostAbsPath::try_new("/home/dev/proj").unwrap());
        let id = mngr.create_session(rooted, None).await.unwrap();
        assert_eq!(
            record(&mngr, id).await.project_root,
            Some(paths::HostAbsPath::try_new("/home/dev/proj").unwrap())
        );

        let id = mngr
            .create_session(config("older-client", "/home/dev/proj/sub"), None)
            .await
            .unwrap();
        assert_eq!(
            record(&mngr, id).await.project_root,
            Some(paths::HostAbsPath::try_new("/home/dev/proj/sub").unwrap())
        );
    }
}
