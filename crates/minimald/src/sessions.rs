use std::{
    collections::{BTreeMap, HashSet},
    io::ErrorKind::NotFound,
};

use crate::{
    session::{Session, SessionConfig, SessionHandle},
    session_host::HostAttrs,
    store::{RecordPredicate, SessionRecordHandle, Store, StoreHandle},
};
use common::SpecHash;
use paths::DaemonAbsPath;
use sessions::SessionId;
#[cfg(target_os = "linux")]
use std::collections::BTreeSet;
#[cfg(target_os = "linux")]
use std::net::Ipv4Addr;
use std::sync::Arc;
#[cfg(target_os = "linux")]
use std::sync::RwLock;
use tokio::sync::{Mutex, mpsc, oneshot};

pub(crate) mod composables;
#[cfg(test)]
use composables::{ProjectResolution, build_composables, run_composer};

/// A short summary of the metadata of a session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionInfo {
    pub id: SessionId,
    pub name: Option<String>,
    /// The absolute host path the session was built from. Surfaced through
    /// `ListSessions` so a client can match sessions against the current
    /// working directory without a per-session `GetSessionRecord` round-trip.
    pub project_path: paths::HostAbsPath,
    /// The session's lifecycle status, surfaced so a client picker can
    /// render a state glyph.
    pub status: sessions::SessionStatus,
    pub attrs: Option<HostAttrs>,
}

/// A key you can use to identify a session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionKeyPredicate {
    Id(SessionId),
    Name(String),
}

impl From<SessionKeyPredicate> for RecordPredicate {
    fn from(pred: SessionKeyPredicate) -> Self {
        match pred {
            SessionKeyPredicate::Id(id) => RecordPredicate::Id(id),
            SessionKeyPredicate::Name(name) => RecordPredicate::Name(name),
        }
    }
}

/// Transport / internal error when communicating with the sessions actor.
type SessionsError = std::io::Error;

/// Assemble a [`sessions::Record`] from the out-of-band session
/// config and the SSH-supplied username, then validate its policy.
/// Returns `Err(io::InvalidInput)` if the policy is incompatible
/// with the network mode (R2.1) — so an invalid session is never
/// written to the store. The `id` field is left as `nil`; the store
/// allocates the real id at `create` time.
///
/// The `CreateSession` handler always persists the record as
/// `Pending`; the session actor's create flow promotes it to
/// `Active` once composition finalizes.
fn build_record(
    config: minimald_rpc::SessionConfig,
    username: Option<String>,
    status: sessions::SessionStatus,
) -> Result<sessions::Record, std::io::Error> {
    let record = sessions::Record {
        id: SessionId::nil(),
        name: config.name,
        username,
        project_path: config.project_path,
        network: config.network,
        policy: config.policy,
        // The handed addresses ride the record: the attach path reads the
        // switch address back out of it, so a re-attach — after a restart
        // included — reuses the address the host table still holds instead
        // of drawing a new one the row would not match.
        box_addresses: config.box_addresses,
        status,
        hooks_enabled: config.hooks_enabled,
        // Daemon-owned from its first line: a create holds no launch's
        // outcome to record, and the key a client might assert in `attrs`
        // is stripped above, so only a launch ever writes this field.
        host_ip_enforcement: None,
        attrs: config.attrs,
    };
    record
        .validate_policy()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    Ok(record)
}

/// Encapsulates the return channel for messages back from the actor.
#[derive(Debug)]
pub(crate) struct Responder<T>(oneshot::Sender<Result<T, SessionsError>>);

impl<T> Responder<T> {
    /// Constructs both ends of the return channel.
    pub(crate) fn channel() -> (Self, oneshot::Receiver<Result<T, SessionsError>>) {
        let (send, recv) = oneshot::channel();
        (Self(send), recv)
    }

    /// Awaits the provided future, transmitting its result to the caller.
    pub(crate) async fn handle<F>(self, fut: F)
    where
        F: Future<Output = Result<T, SessionsError>>,
    {
        let _ = self.0.send(fut.await);
    }
}

/// CreateSession payload — boxed so it doesn't dominate
/// `ManagerMessage`'s size (the variant carries a full session
/// config; other variants are just a few words).
#[derive(Debug)]
struct CreateSessionMsg {
    config: minimald_rpc::SessionConfig,
    /// Authenticated SSH username, supplied by the RPC handler from
    /// the SSH connection context (never the client).
    username: Option<String>,
    responder: Responder<SessionId>,
}

enum ManagerMessage {
    List(Responder<Vec<SessionInfo>>),
    GetRecord(SessionKeyPredicate, Responder<Option<sessions::Record>>),
    GetSession(SessionKeyPredicate, Responder<Option<SessionHandle>>),
    /// Snapshot a running session's terminal screen (`min dash`'s
    /// `GetSessionScreen`). Read-only against the `running` map — unlike
    /// [`GetSession`](Self::GetSession) it never starts an actor, and a
    /// session with no live host answers `None`.
    GetScreen(
        SessionKeyPredicate,
        Responder<Option<minimald_rpc::ScreenSnapshot>>,
    ),
    /// Read a session's persisted composition snapshot. Read-only
    /// against the store — like [`GetRecord`](Self::GetRecord) and
    /// unlike [`GetSession`](Self::GetSession), it never starts an
    /// actor, so inspecting a stopped session leaves it stopped.
    GetComposition(
        SessionKeyPredicate,
        Responder<Option<sessions::core::compose::Composition>>,
    ),
    /// How many session actors are live. Test-only, and the only way
    /// to observe the read-only-ness of [`GetRecord`](Self::GetRecord)
    /// and [`GetComposition`](Self::GetComposition) — "did that query
    /// start an actor?" is otherwise invisible from outside.
    #[cfg(test)]
    RunningCount(Responder<usize>),
    CreateSession(Box<CreateSessionMsg>),
    DeleteSession(SessionId, Responder<()>),
    Shutdown(bool, Responder<Result<(), ()>>),
    /// Fire-and-forget: drop the `running` entry for a session whose actor
    /// terminated on its own (abort, failed verdict resume, create failure).
    /// A no-op for an id already removed; ids are never reused, so a stale
    /// evict can't remove a fresh actor.
    Evict(SessionId),
}

/// Routes session operations to per-session [`Session`] actors, spawning
/// them as needed: `CreateSession` allocates a record and spawns the actor
/// that owns the create flow, `GetSession` brings a known session's actor up
/// from disk, and `DeleteSession` tears one down. Everything session-
/// specific (compose state, verdicts, rename, attach) lives on the session
/// actor behind its [`SessionHandle`].
///
/// Follows the actor pattern.
#[derive(Debug)]
pub struct Manager {
    in_shutdown: bool,
    receiver: mpsc::Receiver<ManagerMessage>,
    running: BTreeMap<SessionId, SessionHandle>,
    store: StoreHandle,

    /// A weak handle to this manager, which can be duplicated so
    /// that downstream actors (session, session host) have a handle
    /// to do operations on us.
    weak_self: WeakManagerHandle,

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
    /// through its `SessionConfig`. Every ask is a synchronous
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

impl Manager {
    /// Launches a sessions manager managing sessions in
    /// the given minimal state dir.
    pub async fn init(
        minimal_state_dir: DaemonAbsPath,
        minimal_cache_dir: DaemonAbsPath,
        daemon_ctx: Arc<mctx::DaemonContext>,
        net_switch: Arc<Mutex<crate::net::SwitchClient>>,
        deny_all_opt_out: bool,
    ) -> Result<ManagerHandle, std::io::Error> {
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
        let (sender, receiver) = mpsc::channel(8);
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
            // it on `Manager::init`'s critical path, which is the one path
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
                        tokio::task::spawn_blocking(crate::net::loopback::probe)
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
            // (`Session::report_unrecorded_publishes`) catches the grants a
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
                tokio::spawn(async move {
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
        let handle = ManagerHandle {
            sender,
            #[cfg(target_os = "linux")]
            hostnames: Arc::clone(&hostnames),
            #[cfg(all(test, target_os = "linux"))]
            loopback: Arc::clone(&loopback),
        };
        // A non-owning path back to this actor, handed to each spawned session
        // so its binding can request destruction (see `weak_self`).
        let weak_self = handle.downgrade();
        let mngr = Self {
            in_shutdown: false,
            receiver,
            running,
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

        tokio::spawn(mngr.mainloop());
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
/// ([`crate::sessions::Manager::init`]'s spawned probe): the state moves
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
/// the box may have been stopped or destroyed, its name taken over by a
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
/// draw recorded, and a stopped or renamed one is answered with it at its
/// next registration; releasing it would free an address a live box holds.
///
/// The re-check is a runtime one, not an ordering argument: the landing
/// runs on the deferred walk's own spawned task
/// ([`crate::sessions::Manager::init`]), never through the manager's
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
/// daemon restart. See [`Manager::init`] for why `Pending` and
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
            sessions::SessionStatus::Pending | sessions::SessionStatus::Materializing => {
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
            sessions::SessionStatus::Active => {}
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
const HOST_PROBE_TIMEOUT: std::time::Duration = crate::session::HOST_PROBE_TIMEOUT;

impl Manager {
    /// The async task which handles interactions with the
    /// manager.
    async fn mainloop(mut self) {
        while let Some(msg) = self.receiver.recv().await {
            self.handle_message(msg).await;
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
        pred: SessionKeyPredicate,
    ) -> Result<Option<SessionHandle>, SessionsError> {
        if self.in_shutdown {
            return Err(SessionsError::new(
                std::io::ErrorKind::ConnectionRefused,
                "in shutdown",
            ));
        }
        let Some(handle) = self.store.find(pred.into()).await? else {
            return Ok(None);
        };
        let session_id = *handle.id();
        if let Some(h) = self.running.get(&session_id) {
            return Ok(Some(h.clone()));
        }
        // Not running, start it!
        let h = Session::run(self.session_config(handle)).await?;
        self.running.insert(session_id, h.clone());
        Ok(Some(h))
    }

    /// The spawn-time config for a session actor backing `record`. The one
    /// place the daemon-scoped dependencies are gathered, so the create and
    /// bring-up-from-disk paths can't hand their actors different worlds.
    fn session_config(&self, record: SessionRecordHandle) -> SessionConfig {
        SessionConfig {
            minimal_state_dir: self.minimal_state_dir.clone(),
            minimal_cache_dir: self.minimal_cache_dir.clone(),
            daemon_ctx: Arc::clone(&self.daemon_ctx),
            record,
            net_switch: Arc::clone(&self.net_switch),
            manager: self.weak_self.clone(),
            deny_all_opt_out: self.deny_all_opt_out,
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
    async fn create_session(
        &mut self,
        config: minimald_rpc::SessionConfig,
        username: Option<String>,
    ) -> Result<SessionId, SessionsError> {
        if self.in_shutdown {
            return Err(SessionsError::new(
                std::io::ErrorKind::ConnectionRefused,
                "in shutdown",
            ));
        }
        // Allocate the record up front: `store.create` assigns the id and
        // catches a name collision (`AlreadyExists`) before any actor exists.
        let record = build_record(config, username, sessions::SessionStatus::Pending)?;
        let handle = self.store.create(record).await?;
        let session_id = *handle.id();

        match Session::run(self.session_config(handle.clone())).await {
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
                r.handle(async move {
                    let mut records = Vec::with_capacity(32);
                    for handle in store.handles().await? {
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
                            SessionInfo {
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
                r.handle(async {
                    Ok::<_, SessionsError>(match self.store.find(pred.into()).await? {
                        Some(handle) => Some(handle.record().await?),
                        None => None,
                    })
                })
                .await;
            }
            #[cfg(test)]
            ManagerMessage::RunningCount(r) => {
                let n = self.running.len();
                r.handle(async move { Ok::<_, SessionsError>(n) }).await;
            }
            ManagerMessage::GetComposition(pred, r) => {
                r.handle(async {
                    Ok::<_, SessionsError>(match self.store.find(pred.into()).await? {
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
                        SessionKeyPredicate::Id(id) => id,
                        SessionKeyPredicate::Name(name) => {
                            match self.store.find(RecordPredicate::Name(name)).await? {
                                Some(handle) => handle.record().await?.id,
                                None => return Ok(None),
                            }
                        }
                    };
                    Ok::<_, SessionsError>(self.running.get(&id).cloned())
                }
                .await;
                match resolved {
                    // Spawned *and* bounded: spawning alone would only move
                    // the hang off this loop and onto a task nothing reaps,
                    // leaving the client on an unanswered oneshot.
                    Ok(Some(h)) => {
                        tokio::spawn(async move {
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
                    responder,
                } = *msg;
                let created = self.create_session(config, username).await;
                responder.handle(async move { created }).await;
            }
            // Deletes a session: tears down its running host and actor (if
            // any), then removes its on-disk record.
            ManagerMessage::DeleteSession(id, r) => {
                r.handle(async {
                    if self.in_shutdown {
                        return Err(SessionsError::new(
                            std::io::ErrorKind::ConnectionRefused,
                            "in shutdown",
                        ));
                    }
                    let handle =
                        self.store
                            .find(RecordPredicate::Id(id))
                            .await?
                            .ok_or_else(|| {
                                std::io::Error::new(
                                    NotFound,
                                    format!("no session with ID `{}`", id.as_ref()),
                                )
                            })?;
                    // Teardown belongs to the actor, so an idle session gets
                    // one brought up rather than having its record deleted
                    // out from under it. That used to be a fair shortcut —
                    // "nothing to undo" — but a session's `on_destroy` hooks
                    // now run on this path, and skipping the actor skipped
                    // them silently for any session whose actor had been
                    // reaped (every session, after a daemon restart).
                    //
                    // Spawning is cheap: the actor reads its record and
                    // composition, and only mints a sandbox if there are
                    // destroy hooks to run in one.
                    let actor = match self.running.remove(&id) {
                        Some(hnd) => Some(hnd),
                        None => match Session::run(self.session_config(handle.clone())).await {
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
                    };
                    match actor {
                        Some(hnd) => {
                            hnd.destroy().await?;
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
                        }
                        None => handle.delete().await?,
                    }
                    Ok(())
                })
                .await
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

                    self.in_shutdown = true;
                    // Stop live sessions. Each actor kills its host and
                    // withdraws its own PTask hostname (R3.5) on the way
                    // down; records — and, with them, the loopback grants
                    // their boxes would resume at — are kept, since shutdown
                    // is not deletion.
                    for hnd in self.running.values() {
                        hnd.stop().await;
                    }
                    self.running.clear();
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

/// The handle to the session manager.
#[derive(Debug, Clone)]
pub struct ManagerHandle {
    sender: mpsc::Sender<ManagerMessage>,
    /// A clone of the actor's shared PTask hostname registry, handed to the
    /// host-side proxies so they resolve `Host:` headers without a round-trip
    /// through the actor mainloop.
    #[cfg(target_os = "linux")]
    hostnames: Arc<RwLock<crate::net::dns::HostnameRegistry>>,
    /// The actor's lease book, held only for the one test seam below: a test
    /// that needs this daemon to be in the state a daemon whose deferred
    /// probe is still walking holds its book in. Production callers reach
    /// the book through the manager actor, which owns it.
    #[cfg(all(test, target_os = "linux"))]
    loopback: Arc<crate::net::dns::LoopbackLeaseBook>,
}

/// A non-owning handle to the [`Manager`] actor.
///
/// Held by per-session machinery that must be able to reach the manager
/// (notably a session's [`Binding`](crate::session_host), to request its own
/// destruction) without keeping the actor alive. See [`Manager::weak_self`] for
/// why the path back to the manager must be weak.
#[derive(Debug, Clone)]
pub struct WeakManagerHandle {
    sender: mpsc::WeakSender<ManagerMessage>,
    /// Mirrors [`ManagerHandle::hostnames`]; the registry `Arc` is held so an
    /// [`upgrade`](Self::upgrade) can reconstruct a full handle. This does not
    /// keep the actor alive (only live senders do).
    #[cfg(target_os = "linux")]
    hostnames: Arc<RwLock<crate::net::dns::HostnameRegistry>>,
    /// Mirrors [`ManagerHandle::loopback`], for the same reason: the test seam
    /// must survive an upgrade.
    #[cfg(all(test, target_os = "linux"))]
    loopback: Arc<crate::net::dns::LoopbackLeaseBook>,
}

impl WeakManagerHandle {
    /// Promotes to a strong [`ManagerHandle`], or `None` if the manager actor
    /// has already shut down (all strong senders dropped).
    #[must_use]
    pub fn upgrade(&self) -> Option<ManagerHandle> {
        Some(ManagerHandle {
            sender: self.sender.upgrade()?,
            #[cfg(target_os = "linux")]
            hostnames: Arc::clone(&self.hostnames),
            #[cfg(all(test, target_os = "linux"))]
            loopback: Arc::clone(&self.loopback),
        })
    }
}

/// A non-owning handle to manipulate a specific session on a sessions actor.
///
/// Used by downstream actors (i.e. [`Binding`](crate::session_host)) to
/// manipulate the session itself, such as deletion.
#[derive(Debug, Clone)]
pub struct SessionControl {
    manager: WeakManagerHandle,
    id: SessionId,
}

impl SessionControl {
    /// Binds the destroy capability to a specific session.
    #[must_use]
    pub fn new(manager: WeakManagerHandle, id: SessionId) -> Self {
        Self { manager, id }
    }

    /// Requests the manager delete this session: kills the host and removes the
    /// on-disk record. Errors if the manager has already shut down, or if the
    /// delete itself fails (e.g. the manager is mid-shutdown).
    pub async fn destroy(&self) -> Result<(), SessionsError> {
        match self.manager.upgrade() {
            Some(mngr) => mngr.delete_session(self.id).await,
            None => Err(SessionsError::new(
                std::io::ErrorKind::NotConnected,
                "sessions manager is gone",
            )),
        }
    }

    /// Reports that a binding has left a session that outlives it, so the
    /// session runs its `on_detach` hooks.
    ///
    /// Returns nothing: leaving is not a fallible operation from the
    /// departing side, and every way this can come up empty — the manager
    /// already shut down, the session already gone — means there is nothing
    /// left to run hooks against. Those are logged where they can be
    /// explained, not raised here.
    pub async fn detached(&self) {
        let Some(mngr) = self.manager.upgrade() else {
            return;
        };
        match mngr.get_session(SessionKeyPredicate::Id(self.id)).await {
            Ok(Some(session)) => session.run_detach_hooks().await,
            Ok(None) => {}
            Err(e) => tracing::warn!(
                error = %e,
                session = %self.id,
                "could not reach the session to run its detach hooks",
            ),
        }
    }
}

impl ManagerHandle {
    /// Returns a non-owning handle to this manager.
    #[must_use]
    pub fn downgrade(&self) -> WeakManagerHandle {
        WeakManagerHandle {
            sender: self.sender.downgrade(),
            #[cfg(target_os = "linux")]
            hostnames: Arc::clone(&self.hostnames),
            #[cfg(all(test, target_os = "linux"))]
            loopback: Arc::clone(&self.loopback),
        }
    }

    /// Returns a shared handle to the in-memory PTask hostname registry, for the
    /// daemon's host-side proxies ([`crate::net::proxy`]) to route by `Host:`
    /// header.
    #[cfg(target_os = "linux")]
    #[must_use]
    pub fn hostnames(&self) -> Arc<RwLock<crate::net::dns::HostnameRegistry>> {
        Arc::clone(&self.hostnames)
    }

    /// Puts this daemon's verdict over the reserved local range back in the
    /// state a daemon whose forwarder-conducted probe is still walking holds
    /// its book in ([`crate::net::dns::RangeVerdict::Pending`]) — the window a
    /// microVM daemon is already serving RPCs in, and the one a box resumed
    /// by the first of them must still be answered in (NET-013).
    ///
    /// Test-only: no production path needs to *un-know* a verdict it has, and
    /// one that did would want a message, not a setter.
    ///
    /// The daemon's one verdict deadline restarts with it, as it does for a
    /// daemon that has just started, so the window is the full
    /// [`crate::net::dns::HAND_VERDICT_WAIT`] however long the harness took
    /// to come up.
    #[cfg(all(test, target_os = "linux"))]
    pub(crate) fn hold_range_verdict_pending(&self) {
        self.loopback
            .set_range_verdict(crate::net::dns::RangeVerdict::Pending);
        self.loopback
            .reset_hand_verdict_deadline(crate::net::dns::HAND_VERDICT_WAIT.as_millis() as u64);
    }

    /// Lands a range verdict with the arms the deferred walk runs when it
    /// lands one — the state change and the re-publishes that follow it — so
    /// a test drives the window's endings the way the walk does.
    /// [`Self::hold_range_verdict_pending`] opens the window; this closes it,
    /// over whatever the window published.
    ///
    /// Test-only: the production path that lands a verdict is the walk
    /// itself, and it lands the probe's answer, never a test's.
    #[cfg(all(test, target_os = "linux"))]
    pub(crate) fn land_range_verdict(&self, verdict: crate::net::dns::RangeVerdict) {
        land_range_verdict(&self.loopback, &self.hostnames, verdict);
    }

    /// The daemon's answerer lease book, for the tests that drive a
    /// landing's two halves apart — the draw and the apply between which a
    /// box can die — the way the walk's single landing never does.
    ///
    /// Test-only: production code reaches the book through the paths that
    /// ask it, not by handle.
    #[cfg(all(test, target_os = "linux"))]
    pub(crate) fn loopback_book(&self) -> &std::sync::Arc<crate::net::dns::LoopbackLeaseBook> {
        &self.loopback
    }

    /// Moves the daemon's one verdict deadline to `millis` from now, so a
    /// test proves the expiry shape — the interim published when the
    /// deadline runs out — without paying the real deadline, or holds the
    /// window open long enough to tell a registration that waited from one
    /// that did not.
    ///
    /// Test-only: no production path changes a deadline it is itself bounded
    /// by.
    #[cfg(all(test, target_os = "linux"))]
    pub(crate) fn reset_hand_verdict_deadline(&self, millis: u64) {
        self.loopback.reset_hand_verdict_deadline(millis);
    }

    /// How many registrations are waiting on the range verdict right now
    /// ([`crate::net::dns::LoopbackLeaseBook::verdict_waiters`]), so a test
    /// lands the verdict only once a registration provably waits for it.
    #[cfg(all(test, target_os = "linux"))]
    pub(crate) fn verdict_waiters(&self) -> usize {
        self.loopback.verdict_waiters()
    }

    /// Lists the sessions known to this (minimald) instance.
    pub async fn list(&self) -> Result<Vec<SessionInfo>, SessionsError> {
        let (send, recv) = Responder::channel();
        // Ignore send errors - the recv will also fail.
        let _ = self.sender.send(ManagerMessage::List(send)).await;
        recv.await.expect("corresponding sessions manager is dead")
    }

    /// How many session actors are live. See
    /// [`ManagerMessage::RunningCount`].
    #[cfg(test)]
    pub(crate) async fn running_count(&self) -> usize {
        let (send, recv) = Responder::channel();
        let _ = self.sender.send(ManagerMessage::RunningCount(send)).await;
        recv.await
            .expect("corresponding sessions manager is dead")
            .expect("counting live actors cannot fail")
    }

    /// Reads a session's persisted composition snapshot.
    ///
    /// Read-only: unlike [`Self::get_session`] this never brings the
    /// session's actor up, so a query about a stopped session does not
    /// start it. `None` for an unknown session and for one with no
    /// snapshot — the two are indistinguishable here on purpose, since
    /// both mean "nothing recorded to report".
    pub async fn get_composition(
        &self,
        pred: SessionKeyPredicate,
    ) -> Result<Option<sessions::core::compose::Composition>, SessionsError> {
        let (send, recv) = Responder::channel();
        // Ignore send errors - the recv will also fail.
        let _ = self
            .sender
            .send(ManagerMessage::GetComposition(pred, send))
            .await;
        recv.await.expect("corresponding sessions manager is dead")
    }

    /// Gets the session record which corresponds to the given predicate.
    pub async fn get_record(
        &self,
        pred: SessionKeyPredicate,
    ) -> Result<Option<sessions::Record>, SessionsError> {
        let (send, recv) = Responder::channel();
        // Ignore send errors - the recv will also fail.
        let _ = self
            .sender
            .send(ManagerMessage::GetRecord(pred, send))
            .await;
        recv.await.expect("corresponding sessions manager is dead")
    }

    /// Creates a session from the given config, returning its allocated id.
    /// The session comes up live but unconfigured — [`configure_loadout`]
    /// against the returned id composes its loadout and finalizes it.
    ///
    /// `username` is the authenticated SSH user from the connection context;
    /// pass `None` for non-SSH callers (e.g. in-process daemon callers and
    /// tests).
    ///
    /// [`configure_loadout`]: crate::session::SessionHandle::configure_loadout
    pub async fn create_session(
        &self,
        config: minimald_rpc::SessionConfig,
        username: Option<String>,
    ) -> Result<SessionId, SessionsError> {
        let (send, recv) = Responder::channel();
        // Ignore send errors - the recv will also fail.
        let _ = self
            .sender
            .send(ManagerMessage::CreateSession(Box::new(CreateSessionMsg {
                config,
                username,
                responder: send,
            })))
            .await;
        recv.await.expect("corresponding sessions manager is dead")
    }

    /// The union of what every active session needs: the spec hash of each package
    /// reachable from any session's tasks, stack, or `[session]` block.
    ///
    /// Resolving a session brings its actor up if it isn't running, exactly as
    /// [`get_session`](Self::get_session) does.
    pub async fn needed_packages(&self) -> Result<HashSet<SpecHash>, SessionsError> {
        let mut out = HashSet::new();
        for info in self.list().await? {
            if info.status != sessions::SessionStatus::Active {
                continue;
            }
            // Deleted between the list and the lookup: gone, so needs nothing.
            let Some(session) = self.get_session(SessionKeyPredicate::Id(info.id)).await? else {
                continue;
            };
            let pkgs = session
                .needed_packages()
                .await
                .map_err(|e| SessionsError::other(format!("session {}: {e}", info.id)))?;
            out.extend(pkgs);
        }

        Ok(out)
    }

    /// Gets a handle to the session corresponding with the given predicate.
    pub async fn get_session(
        &self,
        pred: SessionKeyPredicate,
    ) -> Result<Option<SessionHandle>, SessionsError> {
        let (send, recv) = Responder::channel();
        // Ignore send errors - the recv will also fail.
        let _ = self
            .sender
            .send(ManagerMessage::GetSession(pred, send))
            .await;
        recv.await.expect("corresponding sessions manager is dead")
    }

    /// Snapshots the terminal screen of a running session. `Ok(None)` when
    /// the session is unknown or has no live host — never starts an actor.
    pub async fn get_screen(
        &self,
        pred: SessionKeyPredicate,
    ) -> Result<Option<minimald_rpc::ScreenSnapshot>, SessionsError> {
        let (send, recv) = Responder::channel();
        // Ignore send errors - the recv will also fail.
        let _ = self
            .sender
            .send(ManagerMessage::GetScreen(pred, send))
            .await;
        recv.await.expect("corresponding sessions manager is dead")
    }

    /// Deletes the session with the given ID, cascadingly tearing down its
    /// running host and actor (if any) before removing its on-disk record.
    ///
    /// Returns a `NotFound` error if no session with that ID is known.
    pub async fn delete_session(&self, id: SessionId) -> Result<(), SessionsError> {
        let (send, recv) = Responder::channel();
        // Ignore send errors - the recv will also fail.
        let _ = self
            .sender
            .send(ManagerMessage::DeleteSession(id, send))
            .await;
        recv.await.expect("corresponding sessions manager is dead")
    }

    /// Shuts down all sessions for process termination. If force is true, live sessions are killed.
    /// If force is false but there are live sessions, an error is returned.
    pub async fn shutdown(&self, force: bool) -> Result<(), ()> {
        let (send, recv) = Responder::channel();
        // Ignore send errors - the recv will also fail.
        let _ = self
            .sender
            .send(ManagerMessage::Shutdown(force, send))
            .await;
        recv.await
            .expect("corresponding sessions manager is dead")
            .expect("no SessionError expected from shutdown msg")
    }

    /// Drop the `running` entry for a session whose actor terminated on its
    /// own (abort, failed verdict resume, create failure). Fire-and-forget:
    /// never awaits a reply, so a self-terminating actor can call it without
    /// any risk of a cycle with a manager that might be awaiting the actor.
    pub(crate) async fn evict(&self, id: SessionId) {
        let _ = self.sender.send(ManagerMessage::Evict(id)).await;
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use paths::HostAbsPath;
    use sessions::daemon::composer::ComposeOutcome;
    use sessions::wire::request::{ContributionVerdict, SessionStep, WireContribution};
    use std::io::ErrorKind;
    use tempfile::TempDir;

    /// A stand-in for the client-side project path a session record
    /// carries — the identity the composer stamps onto the project's
    /// contributions, distinct from the daemon workspace it reads.
    fn declared_path() -> paths::HostAbsPath {
        paths::HostAbsPath::try_new("/home/dev/myproject").unwrap()
    }

    /// Resolves the session's live actor and peeks its held
    /// [`Composition`](sessions::core::compose::Composition).
    async fn peek_composition(
        mngr: &ManagerHandle,
        id: SessionId,
    ) -> Arc<sessions::core::compose::Composition> {
        mngr.get_session(SessionKeyPredicate::Id(id))
            .await
            .expect("get_session succeeds")
            .expect("session resolves")
            .peek_composition()
            .await
            .expect("the session actor should hold a composition")
    }

    /// Resolves the session's live actor.
    async fn session(mngr: &ManagerHandle, id: SessionId) -> SessionHandle {
        mngr.get_session(SessionKeyPredicate::Id(id))
            .await
            .expect("get_session succeeds")
            .expect("session resolves")
    }

    /// Writes `contents` as the project mfile in the session's daemon-side
    /// workspace, standing in for the client's `WorkspaceFilesTarZst`
    /// upload. The compose path reads the mfile off that workspace, so
    /// tests that want `configure_loadout` to see a project seed it here
    /// between `create_session` and `configure_loadout` — exactly the
    /// spot a real client's upload lands in.
    async fn seed_workspace_mfile(mngr: &ManagerHandle, id: SessionId, contents: &str) {
        let paths = session(mngr, id).await.paths().await.unwrap();
        tokio::fs::write(
            paths.working.as_utf8_path().join(mfile::MFILE_NAME),
            contents,
        )
        .await
        .unwrap();
    }

    /// Creates a session, seeds `mfile` into its workspace, and configures
    /// its loadout with an empty client contribution — the whole create
    /// flow a client drives, in one call. Returns the manager and the id
    /// alongside the compose outcome.
    async fn create_and_configure(
        mfile: &str,
    ) -> (
        TempDir,
        TempDir,
        ManagerHandle,
        SessionId,
        Option<sessions::wire::request::ContributionResponse>,
    ) {
        let (state, cache, mngr) = manager().await;
        let id = mngr.create_session(sample_config(), None).await.unwrap();
        seed_workspace_mfile(&mngr, id, mfile).await;
        let response = session(&mngr, id)
            .await
            .configure_loadout(WireContribution::default())
            .await
            .expect("configuring the loadout should succeed");
        (state, cache, mngr, id, response)
    }

    /// A project mfile whose `[session.vars]` entry forces the composer down
    /// the Pending path: a daemon-collected var must be gated by the client.
    const PENDING_VAR_MFILE: &str = "[session.vars]\nRUST_LOG = \"info\"\n";

    /// Drives a session to the point of awaiting a verdict: created,
    /// workspace seeded with [`PENDING_VAR_MFILE`], loadout configured and
    /// come back `Pending`. Returns the manager, the id, and the wire
    /// response carrying the pending var.
    async fn create_pending_session() -> (
        TempDir,
        TempDir,
        ManagerHandle,
        SessionId,
        sessions::wire::request::ContributionResponse,
    ) {
        let (state, cache, mngr, id, response) = create_and_configure(PENDING_VAR_MFILE).await;
        let response = response.expect("a daemon-side var should pend, not finalize");
        (state, cache, mngr, id, response)
    }

    /// An approve-everything verdict for the given pending response.
    fn approve_all(
        id: SessionId,
        response: &sessions::wire::request::ContributionResponse,
    ) -> ContributionVerdict {
        ContributionVerdict {
            session_id: id,
            vars: response
                .vars
                .iter()
                .map(|pv| sessions::wire::policy::WireVarVerdict::Approved {
                    id: pv.id,
                    value: sessions::wire::primitives::WireResolvedVar {
                        name: pv.name.clone(),
                        value: "info".into(),
                        carries_user_data: true,
                    },
                })
                .collect(),
            patches: vec![],
            lifecycle_hooks: vec![],
        }
    }

    fn sample_config() -> minimald_rpc::SessionConfig {
        minimald_rpc::SessionConfig {
            name: Some("doomed".to_string()),
            project_path: HostAbsPath::try_new("/proj").unwrap(),
            network: sessions::NetworkMode::default(),
            policy: Default::default(),
            box_addresses: None,
            hooks_enabled: true,
            attrs: Default::default(),
        }
    }

    /// Test helper: create a session via the in-process manager actor (not
    /// RPC) and configure its loadout against an empty workspace, so it
    /// lands `Active` with an empty composition — the shape most lifecycle
    /// tests want.
    async fn create_active_session(mngr: &ManagerHandle) -> SessionId {
        create_active_session_with(mngr, sample_config()).await
    }

    /// [`create_active_session`] with a caller-supplied config.
    /// Drives the whole `CreateSession → ConfigureLoadout →
    /// FinalizeSession` sequence in-process so the returned
    /// session's record is `Active` (attachable, hostname
    /// registered). No patches for these fixtures, so the
    /// composition-empty short-circuit in `finalize` covers the
    /// marker precondition.
    async fn create_active_session_with(
        mngr: &ManagerHandle,
        config: minimald_rpc::SessionConfig,
    ) -> SessionId {
        create_active_session_contributing(mngr, config, WireContribution::default()).await
    }

    /// [`create_active_session_with`] carrying a client contribution —
    /// the way a test gets lifecycle hooks into a session's composition.
    async fn create_active_session_contributing(
        mngr: &ManagerHandle,
        config: minimald_rpc::SessionConfig,
        contribution: WireContribution,
    ) -> SessionId {
        let id = mngr.create_session(config, None).await.unwrap();
        let handle = session(mngr, id).await;
        let response = handle
            .configure_loadout(contribution)
            .await
            .expect("configuring an empty loadout should succeed");
        assert!(response.is_none(), "an empty loadout should finalize");
        handle
            .finalize()
            .await
            .expect("finalize should succeed for a patchless composition");
        id
    }

    async fn manager() -> (TempDir, TempDir, ManagerHandle) {
        let state = TempDir::new().unwrap();
        let cache = TempDir::new().unwrap();
        let mngr = manager_over(state.path(), cache.path()).await;
        (state, cache, mngr)
    }

    /// A manager rooted at existing state and cache directories, so a
    /// test can stand a second one up over the first's store — the way
    /// a daemon restart sees a session it never started.
    async fn manager_over(state: &std::path::Path, cache: &std::path::Path) -> ManagerHandle {
        let state = state.to_path_buf();
        let cache = cache.to_path_buf();
        // These tests never start an `OwnIp` launch (they use the mock
        // launcher), so the switch is never spawned; a placeholder binary path
        // is sufficient.
        let switch = Arc::new(Mutex::new(crate::net::SwitchClient::new(
            "/nonexistent/gvproxy",
            state.join("gvproxy"),
        )));
        // Tests use per-TempDir cache/state dirs so they don't pollute the
        // shared daemon paths a real invocation would touch.
        let mctx_config = mctx::ConfigBuilder::new()
            .with_cache_dir(&cache)
            .with_state_dir(&state)
            .with_daemon_id("test".to_string())
            .build()
            .unwrap();
        let daemon_ctx = Arc::new(mctx::DaemonContext::init(mctx_config).unwrap());
        // `false`: these tests run the default the build ships, not the
        // opt-out.
        Manager::init(
            daemon_abs(&state),
            daemon_abs(&cache),
            daemon_ctx,
            switch,
            false,
        )
        .await
        .unwrap()
    }

    /// A [`DaemonAbsPath`] for a test directory.
    fn daemon_abs(p: &std::path::Path) -> DaemonAbsPath {
        DaemonAbsPath::try_new(p.to_str().unwrap()).unwrap()
    }

    /// `GetScreen` answers every resolution outcome, by id and by name.
    ///
    /// Worth pinning because the probe no longer runs on the manager's
    /// mainloop: it is spawned, so the responder travels into a task and a
    /// mis-wired arm would leave the caller on a oneshot that is never sent
    /// rather than failing loudly. A live session with no host takes the
    /// spawned path, which is what proves that wiring delivers.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn get_screen_answers_whether_or_not_a_session_resolves() {
        let (_state, _cache, mngr) = manager().await;

        // Nothing created yet: neither predicate resolves.
        assert!(
            mngr.get_screen(SessionKeyPredicate::Id(SessionId::nil()))
                .await
                .unwrap()
                .is_none(),
            "an unknown id should answer None, not hang or error"
        );
        assert!(
            mngr.get_screen(SessionKeyPredicate::Name("nonesuch".to_string()))
                .await
                .unwrap()
                .is_none(),
            "an unknown name should answer None, not hang or error"
        );

        // A live actor that never launched a host: resolves, so the probe
        // is spawned, and the session reports no screen.
        let id = create_active_session(&mngr).await;
        assert!(
            mngr.get_screen(SessionKeyPredicate::Id(id))
                .await
                .unwrap()
                .is_none(),
            "a session with no running host should answer None"
        );
        assert!(
            mngr.get_screen(SessionKeyPredicate::Name("doomed".to_string()))
                .await
                .unwrap()
                .is_none(),
            "resolving by name should reach the same session"
        );

        // The mainloop is still serving after all of it.
        assert_eq!(mngr.list().await.unwrap().len(), 1);
    }

    /// Destroying a known-but-not-running session removes its record so it no
    /// longer resolves or lists, and frees its name for reuse.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn destroy_removes_a_non_running_session() {
        let (_state, _cache, mngr) = manager().await;
        let id = create_active_session(&mngr).await;

        mngr.delete_session(id).await.unwrap();

        assert!(
            mngr.get_record(SessionKeyPredicate::Id(id))
                .await
                .unwrap()
                .is_none(),
            "the record should be gone after destroy"
        );
        assert!(mngr.list().await.unwrap().is_empty());
        // The name index entry was dropped, so the name can be taken again.
        let _ = create_active_session(&mngr).await;
    }

    /// Destroying a session whose actor is not running must still go
    /// through that actor, because teardown is the actor's job — and now
    /// includes running the session's `on_destroy` hooks.
    ///
    /// The shortcut this replaced ("never spawned, so nothing to undo —
    /// just remove the record") predated hooks and skipped them in
    /// silence for every session whose actor had been reaped, which after
    /// a daemon restart is all of them. Asserted through the live-actor
    /// count: the destroy has to bring one up.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn destroying_an_idle_session_goes_through_its_actor() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("destroyed");

        let (state, cache, mngr) = manager().await;
        // A destroy hook is the discriminator: both the actor path and the
        // old shortcut delete the record, so only the hook's side effect
        // tells them apart.
        let id = create_active_session_contributing(
            &mngr,
            sample_config(),
            WireContribution {
                lifecycle_hooks: vec![sessions::wire::primitives::WireProvenancedHook {
                    hook: sessions::wire::primitives::WireLifecycleHook {
                        on_destroy: Some(sessions::wire::primitives::WireHookScript::Inline {
                            body: format!("echo ran > {}", marker.display()),
                            timeout_secs: 60,
                        }),
                        ..Default::default()
                    },
                    source: sessions::wire::primitives::WireSource::UserLoadout {
                        name: "test".to_string(),
                    },
                }],
                ..Default::default()
            },
        )
        .await;

        // A second manager over the same store knows the session from disk
        // and has never run it — a daemon restart's view, and the state the
        // old shortcut applied to.
        let restarted = manager_over(state.path(), cache.path()).await;
        assert_eq!(restarted.running_count().await, 0);

        restarted.delete_session(id).await.unwrap();

        assert!(
            marker.exists(),
            "destroying an idle session skipped its on_destroy hook",
        );
        assert!(
            restarted
                .get_record(SessionKeyPredicate::Id(id))
                .await
                .unwrap()
                .is_none(),
            "the record should be gone after destroy"
        );
    }

    /// Reading a session's composition must not resurrect it.
    ///
    /// `min session hooks` is a report, and a report has no business
    /// starting what it reports on — `get_session` would, since it
    /// brings an actor up from disk on demand. Asserted against the
    /// live-actor count because that is the only place the difference
    /// shows.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reading_a_composition_does_not_start_the_session() {
        let (state, cache, mngr) = manager().await;
        let id = create_active_session(&mngr).await;

        // A second manager over the same store: it knows the session
        // from disk and has never run it, which is the state a daemon
        // restart leaves and the one where "did this start an actor?"
        // is answerable.
        let restarted = manager_over(state.path(), cache.path()).await;
        assert_eq!(
            restarted.running_count().await,
            0,
            "a fresh manager should not have started anything",
        );

        // The read answers for the session...
        let composition = restarted
            .get_composition(SessionKeyPredicate::Id(id))
            .await
            .expect("reading the snapshot should succeed");
        assert!(
            composition.is_some(),
            "an Active session should have a persisted composition",
        );
        // ...without bringing it up. `get_session` here would.
        assert_eq!(
            restarted.running_count().await,
            0,
            "reading the composition started the session's actor",
        );
    }

    /// no host is attached) tears the actor down and removes the record.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn destroy_tears_down_a_running_session() {
        let (_state, _cache, mngr) = manager().await;
        let id = create_active_session(&mngr).await;

        // Bring the session actor up (populating the running map) without
        // attaching a host.
        let handle = mngr
            .get_session(SessionKeyPredicate::Id(id))
            .await
            .unwrap()
            .expect("session should resolve");

        mngr.delete_session(id).await.unwrap();

        // The destroy cascade completed: the record is gone, and a fresh
        // get_session no longer resolves the (now removed) session.
        assert!(
            mngr.get_record(SessionKeyPredicate::Id(id))
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            mngr.get_session(SessionKeyPredicate::Id(id))
                .await
                .unwrap()
                .is_none(),
            "the session should no longer resolve after destroy"
        );
        drop(handle);
    }

    /// Destroying an unknown ID is a `NotFound` error.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn destroy_unknown_id_errors() {
        let (_state, _cache, mngr) = manager().await;
        let err = mngr
            .delete_session(SessionId::nil())
            .await
            .expect_err("deleting an unknown id should error");
        assert_eq!(err.kind(), ErrorKind::NotFound);
    }

    /// A non-empty `WireContribution` from the client is accepted:
    /// the composer produces a non-empty
    /// [`Composition`](sessions::core::compose::Composition), the
    /// create flow holds it on the live [`Session`] actor, and the
    /// record persists as `Active`.
    ///
    /// Replaces an earlier test that asserted the opposite while
    /// no apply layer existed to consume the composition; that
    /// silent-data-loss guard is gone now that the actor keeps
    /// its composition.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn create_session_accepts_non_empty_client_contribution() {
        use sessions::core::source::Source;
        use sessions::wire::primitives::{WireResolvedVar, WireSessionVar, WireSource};

        let (_state, _cache, mngr) = manager().await;
        let mut contribution = WireContribution::default();
        contribution.vars.push(WireSessionVar {
            var: WireResolvedVar {
                name: "EDITOR".into(),
                value: "hx".into(),
                carries_user_data: true,
            },
            source: WireSource::from(Source::UserLoadout {
                name: "test".into(),
            }),
        });

        let id = mngr.create_session(sample_config(), None).await.unwrap();
        let response = session(&mngr, id)
            .await
            .configure_loadout(contribution)
            .await
            .expect("a non-empty client contribution should compose");
        assert!(
            response.is_none(),
            "an already-gated client contribution needs no verdict, so the \
             loadout should finalize in one shot",
        );
        // Compose returned `Materialized` — the record status is
        // `Materializing`, not `Active`. Attach requires an
        // explicit `FinalizeSession` after any patches have
        // uploaded; this fixture doesn't drive that step.
        assert_eq!(
            mngr.get_record(SessionKeyPredicate::Id(id))
                .await
                .unwrap()
                .expect("the record should survive")
                .status,
            sessions::SessionStatus::Materializing,
        );
    }

    /// An unknown id resolves to no session at all — the `NotFound`
    /// (abort/rename) and `Fault::UnknownSessionId` (verdict) wire
    /// mappings all hang off this `None`, in the RPC handlers.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn get_session_unknown_id_resolves_to_none() {
        let (_state, _cache, mngr) = manager().await;
        assert!(
            mngr.get_session(SessionKeyPredicate::Id(SessionId::nil()))
                .await
                .expect("get_session succeeds")
                .is_none(),
        );
    }

    /// Abort refuses `Active` sessions — abort is for `Pending`
    /// only; `DeleteSession` handles `Active`. Guards against a
    /// client accidentally tearing down a running session via the
    /// wrong RPC.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn abort_refuses_active_session() {
        let (_state, _cache, mngr) = manager().await;
        let id = create_active_session(&mngr).await;
        let handle = mngr
            .get_session(SessionKeyPredicate::Id(id))
            .await
            .unwrap()
            .expect("session resolves");
        let err = handle
            .abort()
            .await
            .expect_err("aborting an Active session should error");
        assert_eq!(err.kind(), ErrorKind::InvalidInput);
        // Record is untouched.
        assert!(
            mngr.get_record(SessionKeyPredicate::Id(id))
                .await
                .unwrap()
                .is_some(),
            "the Active record should survive a refused abort"
        );
    }

    /// The full Pending → verdict → Active flow through the session
    /// actor's state machine: a project `[session.vars]` entry pends
    /// the loadout, `get_session` resolves the live Draft actor, an
    /// approving verdict promotes the on-disk record to `Active`,
    /// and the finalized composition (carrying the gated var) stays
    /// on the actor.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pending_session_activates_on_approving_verdict() {
        let (_state, _cache, mngr, id, response) = create_pending_session().await;
        assert_eq!(response.vars.len(), 1, "the project var should pend");
        assert_eq!(
            response.session_id, id,
            "the response should carry the allocated id, not the composer's \
             placeholder",
        );
        assert_eq!(
            mngr.get_record(SessionKeyPredicate::Id(id))
                .await
                .unwrap()
                .expect("the Pending record should exist")
                .status,
            sessions::SessionStatus::Pending,
        );

        let handle = mngr
            .get_session(SessionKeyPredicate::Id(id))
            .await
            .expect("get_session succeeds")
            .expect("a Pending session's live actor should resolve");
        let step = handle
            .submit_verdict(approve_all(id, &response))
            .await
            .expect("the verdict should be accepted");
        assert_eq!(step, SessionStep::Materialized { id });

        // SubmitVerdict promotes Pending → Materializing, not
        // Pending → Active. The client still has to upload
        // patches (there are none for this fixture) and call
        // FinalizeSession before the record advances to Active.
        assert_eq!(
            mngr.get_record(SessionKeyPredicate::Id(id))
                .await
                .unwrap()
                .expect("the record should survive promotion")
                .status,
            sessions::SessionStatus::Materializing,
        );
        let comp = handle
            .peek_composition()
            .await
            .expect("the promoted actor should hold the composition");
        assert!(
            comp.vars().iter().any(|v| v.var().name() == "RUST_LOG"),
            "the gated var should reach the composition",
        );
    }

    /// A verdict against an `Active` session is answered by the
    /// actor's state machine with a structured `WrongState` fault —
    /// not an error, and not silent acceptance.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn submit_verdict_on_active_session_returns_wrong_state() {
        let (_state, _cache, mngr) = manager().await;
        let id = create_active_session(&mngr).await;
        let handle = mngr
            .get_session(SessionKeyPredicate::Id(id))
            .await
            .unwrap()
            .expect("session resolves");
        let step = handle
            .submit_verdict(ContributionVerdict {
                session_id: id,
                vars: vec![],
                patches: vec![],
                lifecycle_hooks: vec![],
            })
            .await
            .expect("actor reply should succeed");
        match step {
            SessionStep::Fault {
                error: sessions::wire::errors::WireError::WrongState { what },
            } => assert!(what.contains("expected Pending"), "got: {what}"),
            other => panic!("expected Fault::WrongState, got {other:?}"),
        }
    }

    /// Aborting a Draft session through its handle deletes the
    /// record and stops the actor; the session no longer resolves
    /// (the actor evicted itself from the manager's running map, and
    /// the record is gone).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn abort_via_handle_deletes_pending_session() {
        let (_state, _cache, mngr, id, _response) = create_pending_session().await;
        let handle = mngr
            .get_session(SessionKeyPredicate::Id(id))
            .await
            .unwrap()
            .expect("the Draft actor should resolve");
        handle.abort().await.expect("abort should succeed");

        assert!(
            mngr.get_record(SessionKeyPredicate::Id(id))
                .await
                .unwrap()
                .is_none(),
            "the record should be deleted by the abort",
        );
        assert!(
            mngr.get_session(SessionKeyPredicate::Id(id))
                .await
                .unwrap()
                .is_none(),
            "the aborted session should no longer resolve",
        );
    }

    /// A verdict the composer can't apply (a denied project item)
    /// faults, but isn't terminal: the session stays `Pending` and
    /// resumable, so the client can correct the verdict and re-submit
    /// rather than lose the session to a mis-gated item.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn denying_verdict_faults_and_leaves_session_resumable() {
        let (_state, _cache, mngr, id, response) = create_pending_session().await;
        let handle = session(&mngr, id).await;
        let verdict = ContributionVerdict {
            session_id: id,
            vars: response
                .vars
                .iter()
                .map(|pv| sessions::wire::policy::WireVarVerdict::Denied {
                    id: pv.id,
                    name: pv.name.clone(),
                })
                .collect(),
            patches: vec![],
            lifecycle_hooks: vec![],
        };
        let step = handle
            .submit_verdict(verdict)
            .await
            .expect("actor reply should succeed");
        assert!(
            matches!(step, SessionStep::Fault { .. }),
            "a denied item should fault the resume, got {step:?}",
        );
        assert_eq!(
            mngr.get_record(SessionKeyPredicate::Id(id))
                .await
                .unwrap()
                .expect("the record should survive a faulted resume")
                .status,
            sessions::SessionStatus::Pending,
        );

        // The compose state survived the fault: a corrected verdict still
        // finalizes the same session.
        let step = handle
            .submit_verdict(approve_all(id, &response))
            .await
            .expect("the corrected verdict should be accepted");
        assert_eq!(step, SessionStep::Materialized { id });
    }

    /// Renaming a session that owns no PTask hostname route (NoNet here)
    /// must not touch the registry: it is keyed by name alone, so an
    /// ungated deregister would withdraw an unrelated routable session's
    /// route that shares the same *derived* name (both unnamed, projects
    /// with the same basename).
    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rename_of_unroutable_session_leaves_other_routes_alone() {
        let (_state, _cache, mngr) = manager().await;

        // Two unnamed sessions whose projects share the basename "app":
        // both derive the registry name "app". Only the HostNet one
        // registers a route when its actor spawns.
        let routable_project = TempDir::new().unwrap();
        let routable_dir = routable_project.path().join("app");
        std::fs::create_dir_all(&routable_dir).unwrap();
        let unroutable_project = TempDir::new().unwrap();
        let unroutable_dir = unroutable_project.path().join("app");
        std::fs::create_dir_all(&unroutable_dir).unwrap();

        let mut config = sample_config();
        config.name = None;
        config.network = sessions::NetworkMode::HostNet;
        config.project_path = HostAbsPath::try_new(routable_dir.to_str().unwrap()).unwrap();
        // Finalizing the loadout registers the "app" route.
        let _routable_id = create_active_session_with(&mngr, config).await;

        let mut config = sample_config();
        config.name = None;
        config.network = sessions::NetworkMode::NoNet;
        config.project_path = HostAbsPath::try_new(unroutable_dir.to_str().unwrap()).unwrap();
        let unroutable_id = create_active_session_with(&mngr, config).await;
        let handle = session(&mngr, unroutable_id).await;

        handle
            .rename("renamed".to_string())
            .await
            .expect("rename should succeed");

        // The routable session's route survived the other session's rename.
        assert!(
            mngr.hostnames()
                .write()
                .expect("registry lock")
                .deregister("app")
                .is_some(),
            "the HostNet session's route must survive a NoNet rename \
             under the same derived name",
        );
    }

    /// A handle to a self-terminated actor answers `paths`/`record`/
    /// `context` with errors, not panics — callers (SFTP, exec, uploads)
    /// race actor death.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dead_actor_handle_reads_error_instead_of_panicking() {
        let (_state, _cache, mngr, id, _response) = create_pending_session().await;
        let handle = mngr
            .get_session(SessionKeyPredicate::Id(id))
            .await
            .unwrap()
            .expect("the Draft actor should resolve");
        handle.abort().await.expect("abort should succeed");

        let err = handle
            .paths()
            .await
            .expect_err("paths on a dead actor should error");
        assert_eq!(err.kind(), ErrorKind::NotConnected);
        let err = handle
            .record()
            .await
            .expect_err("record on a dead actor should error");
        assert_eq!(err.kind(), ErrorKind::NotConnected);
        assert!(
            handle
                .context()
                .await
                .expect_err("context on a dead actor should error")
                .contains("gone"),
        );
    }

    /// A Draft session refuses context creation — there is no
    /// workspace-rooted context to build until composition
    /// finalizes.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn draft_session_refuses_context_creation() {
        let (_state, _cache, mngr, id, _response) = create_pending_session().await;
        let handle = mngr
            .get_session(SessionKeyPredicate::Id(id))
            .await
            .unwrap()
            .expect("the Draft actor should resolve");
        let err = handle
            .context()
            .await
            .expect_err("a Draft session should refuse context creation");
        assert!(err.contains("pending"), "got: {err}");
    }

    /// An idle `Active` session (created, never attached) does not
    /// block an unforced shutdown — every created session now has a
    /// live actor, so mere existence can't be the guard.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn idle_session_does_not_block_unforced_shutdown() {
        let (_state, _cache, mngr) = manager().await;
        let _id = create_active_session(&mngr).await;
        mngr.shutdown(false)
            .await
            .expect("an idle session should not block unforced shutdown");
    }

    /// A Draft session (mid create flow, awaiting its verdict) is
    /// busy: it blocks an unforced shutdown until the client
    /// finalizes or aborts.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn draft_session_blocks_unforced_shutdown() {
        let (_state, _cache, mngr, _id, _response) = create_pending_session().await;
        mngr.shutdown(false)
            .await
            .expect_err("a Draft session should block unforced shutdown");
    }

    /// `CreateSession` against a `project_path` that has a real
    /// `minimal.toml` shouldn't error out — the mfile parse
    /// succeeds and graph resolution is attempted; both feed
    /// nowhere (yet), and the session persists `Active` on the
    /// empty-contribution fast path.
    ///
    /// The graph-resolution outcome isn't observed by the test —
    /// depending on how `Graph::new_from_chain` handles a bare
    /// `minimal.toml` in a scratch dir, it may return an empty
    /// graph or an error. Either branch must leave `CreateSession`
    /// returning `Ready`; that's the invariant guarded here.
    /// Guards against a regression where the mfile parse or graph
    /// pipeline breaks creation for real projects. Once composition
    /// consumes the parsed mfile + graph, this test evolves.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn configure_loadout_with_real_project_mfile_succeeds() {
        let (_state, _cache, _mngr, _id, response) =
            create_and_configure("[stack]\nuse = \"empty\"\n").await;
        assert!(
            response.is_none(),
            "a stack-only mfile gates nothing, so the loadout should finalize"
        );
    }

    /// Configuring a loadout against a workspace with no `minimal.toml`
    /// scaffolds a default one *before* composing, so the packages that
    /// default declares land in the composition — and from there in the
    /// launcher's package set, which is its baseline unioned with the
    /// composition's packages and nothing else. Scaffolding after the
    /// compose (as `build_context` alone used to) left a session running
    /// without the packages its own workspace mfile declared.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn configure_loadout_scaffolds_missing_mfile_into_composition() {
        let (_state, _cache, mngr) = manager().await;
        // No `seed_workspace_mfile`: the workspace stays empty, mirroring
        // an activation against a directory with no `minimal.toml`.
        let id = mngr.create_session(sample_config(), None).await.unwrap();
        let response = session(&mngr, id)
            .await
            .configure_loadout(WireContribution::default())
            .await
            .expect("configuring against a missing mfile should still succeed");
        assert!(response.is_none(), "the scaffolded default gates nothing");

        let comp = peek_composition(&mngr, id).await;
        let package_names: std::collections::BTreeSet<&str> =
            comp.packages().iter().map(|p| p.package()).collect();
        assert!(
            package_names.contains("vim"),
            "the scaffolded mfile's packages should reach the composition, \
             got {package_names:?}"
        );
    }

    /// A `[session]` block that contributes a package is picked up
    /// by [`ProjectComposable`] and lands in the composition. With
    /// the non-empty-composition guard gone, the record now
    /// persists as `Active` and the composition stays on the live
    /// [`Session`] actor.
    ///
    /// Uses a package contribution rather than a var so no
    /// env-resolution (or graph presence) is needed — the test
    /// stays a pure-parse exercise regardless of stdlib config.
    ///
    /// [`ProjectComposable`]: mfile::ProjectComposable
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn project_composable_contribution_reaches_composer() {
        let (_state, _cache, mngr, id, response) =
            create_and_configure("[session]\npackages = [\"rustc\"]\n").await;
        assert!(
            response.is_none(),
            "a project package needs no client gate, so the loadout finalizes"
        );
        // Compose advances the record to `Materializing`, not
        // `Active` — see the note on
        // `create_session_accepts_non_empty_client_contribution`.
        assert_eq!(
            mngr.get_record(SessionKeyPredicate::Id(id))
                .await
                .unwrap()
                .expect("the record should survive")
                .status,
            sessions::SessionStatus::Materializing,
        );
    }

    /// A finalized loadout leaves the session's actor live and holding its
    /// composition — the actor `get_session` resolves is the same one the
    /// create flow spawned, composition intact.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn created_session_actor_holds_its_composition() {
        let (_state, _cache, mngr) = manager().await;
        let id = create_active_session(&mngr).await;
        assert!(
            session(&mngr, id).await.peek_composition().await.is_some(),
            "the create-flow actor should still hold its composition",
        );
    }

    /// Writes `pkg` as a package of the session's own workspace layer, so its
    /// graph resolves the name with no upstream layer (and no network) in play.
    async fn seed_workspace_package(mngr: &ManagerHandle, id: SessionId, pkg: &str) {
        let paths = session(mngr, id).await.paths().await.unwrap();
        let dir = paths.working.as_utf8_path().join("packages").join(pkg);
        tokio::fs::create_dir_all(&dir).await.unwrap();
        tokio::fs::write(
            dir.join("build.ncl"),
            format!(
                r#"let {{ BuildSpec, .. }} = import "minimal.ncl" in
{{
  name = "{pkg}",
  build_deps = [],
  runtime_deps = [],
  outputs = {{}},
}} | BuildSpec
"#
            ),
        )
        .await
        .unwrap();
    }

    /// Brings up an `Active` session called `name` whose workspace declares
    /// local package `pkg` in its `[session]` block — a session that needs
    /// exactly one package, and a different one per call.
    pub(crate) async fn active_session_needing(
        mngr: &ManagerHandle,
        name: &str,
        pkg: &str,
    ) -> SessionId {
        let config = minimald_rpc::SessionConfig {
            name: Some(name.to_string()),
            ..sample_config()
        };
        let id = mngr.create_session(config, None).await.unwrap();
        seed_workspace_package(mngr, id, pkg).await;
        seed_workspace_mfile(mngr, id, &format!("[session]\npackages = [\"{pkg}\"]\n")).await;

        let handle = session(mngr, id).await;
        handle
            .configure_loadout(WireContribution::default())
            .await
            .expect("a project-only loadout gates nothing");
        // The composition carries packages but no patches, so finalize skips
        // the patches marker and the record lands `Active`.
        handle.finalize().await.expect("finalize should succeed");
        id
    }

    /// The manager's answer is the union of what each session answered, and
    /// each session resolved its own package against its own workspace.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn needed_packages_unions_across_sessions() {
        let (_state, _cache, mngr) = manager().await;
        let a = active_session_needing(&mngr, "sess-a", "pkg-a").await;
        let b = active_session_needing(&mngr, "sess-b", "pkg-b").await;

        let from_a = session(&mngr, a).await.needed_packages().await.unwrap();
        let from_b = session(&mngr, b).await.needed_packages().await.unwrap();
        assert_eq!(from_a.len(), 1, "session a needs exactly its own package");
        assert_eq!(from_b.len(), 1, "session b needs exactly its own package");
        assert_ne!(from_a, from_b, "different packages hash differently");

        let want: HashSet<SpecHash> = from_a.union(&from_b).cloned().collect();
        assert_eq!(mngr.needed_packages().await.unwrap(), want);
    }

    /// A session that hasn't composed yet has no workspace context to resolve,
    /// so it is skipped rather than faulting the whole union.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn needed_packages_skips_sessions_that_arent_active() {
        let (_state, _cache, mngr) = manager().await;
        // Created but never configured: the record stays `Pending`.
        let _pending = mngr.create_session(sample_config(), None).await.unwrap();

        assert!(mngr.needed_packages().await.unwrap().is_empty());
    }

    /// The held [`Composition`] actually carries the project
    /// composable's packages — not just an entry-shaped placeholder.
    /// Guards against a `run_composer` refactor that would produce
    /// a well-shaped-but-empty composition and silently pass the
    /// existing lifecycle tests.
    ///
    /// [`Composition`]: sessions::core::compose::Composition
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn created_session_composition_carries_project_packages() {
        let (_state, _cache, mngr, id, _response) =
            create_and_configure("[session]\npackages = [\"ripgrep\", \"jq\"]\n").await;

        let comp = peek_composition(&mngr, id).await;
        let package_names: std::collections::BTreeSet<&str> =
            comp.packages().iter().map(|p| p.package()).collect();
        assert!(
            package_names.contains("ripgrep"),
            "ripgrep should be in composition packages, got {package_names:?}"
        );
        assert!(
            package_names.contains("jq"),
            "jq should be in composition packages, got {package_names:?}"
        );
    }

    /// `[stack] build_packages` and `runtime_packages` land in the
    /// composition alongside any `[session] packages`, so a project
    /// declaring stack extras (or having no `[session]` block at
    /// all) still gets those packages into its sessions.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn created_session_composition_includes_stack_packages() {
        let (_state, _cache, mngr, id, _response) = create_and_configure(
            "[stack]\n\
             use = \"shell\"\n\
             build_packages = [\"cmake\"]\n\
             runtime_packages = [\"postgres\"]\n",
        )
        .await;

        let comp = peek_composition(&mngr, id).await;
        let package_names: std::collections::BTreeSet<&str> =
            comp.packages().iter().map(|p| p.package()).collect();
        assert!(
            package_names.contains("cmake"),
            "stack build_packages should reach the composition, got {package_names:?}"
        );
        assert!(
            package_names.contains("postgres"),
            "stack runtime_packages should reach the composition, got {package_names:?}"
        );
    }

    /// [`build_composables`] with a [`ProjectResolution::NoMFile`]
    /// yields no composables regardless of the wire contribution.
    /// The wire contribution isn't discarded by the composer — it
    /// still lands via `SessionComposer::new(contribution)`; this
    /// helper is only responsible for daemon-side additions.
    #[test]
    fn build_composables_no_mfile_yields_nothing() {
        use sessions::wire::primitives::{WirePackageRef, WireSource};

        let path = DaemonAbsPath::try_new("/proj").unwrap();
        let mut contribution = WireContribution::default();
        contribution.requested_packages.push(WirePackageRef {
            name: "helix".into(),
            source: WireSource::UserLoadout {
                name: "test".into(),
            },
        });
        let (project, packages) = build_composables(
            &path,
            &declared_path(),
            &ProjectResolution::NoMFile,
            &contribution,
            true,
        )
        .unwrap();
        assert!(project.is_none(), "NoMFile → no ProjectComposable");
        assert!(packages.is_empty(), "NoMFile → no PackageComposables");
    }

    /// [`build_composables`] with an [`ProjectResolution::MFileOnly`]
    /// carrying a `[session]` block produces a [`ProjectComposable`];
    /// package composables stay empty because the graph is absent.
    /// The MFileOnly path exercises the "graph resolve failed but
    /// project still declares packages" branch — project packages
    /// don't get their own PackageComposables, they just wait for
    /// the composer to see them via the ProjectComposable's
    /// contribution.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn build_composables_mfile_only_yields_project_composable_and_no_packages() {
        use std::io::Write;

        let project = TempDir::new().unwrap();
        let mfile_path = project.path().join(mfile::MFILE_NAME);
        let mut f = std::fs::File::create(&mfile_path).unwrap();
        writeln!(f, "[session]\npackages = [\"cargo\"]").unwrap();
        drop(f);

        // Build a `Context` directly (no graph); the manager sets
        // the same shape internally on the MFileOnly branch.
        let cache = TempDir::new().unwrap();
        let state = TempDir::new().unwrap();
        let mctx_config = mctx::ConfigBuilder::new()
            .with_cache_dir(cache.path())
            .with_state_dir(state.path())
            .with_daemon_id("test".to_string())
            .build()
            .unwrap();
        let daemon = std::sync::Arc::new(mctx::DaemonContext::init(mctx_config).unwrap());
        let mfile = mctx::MFileSearchStrategy::Override(project.path().to_path_buf())
            .find_mfile()
            .unwrap();
        let ctx = mctx::Context::from_daemon(daemon, mfile);

        let path = DaemonAbsPath::try_new(project.path().to_str().unwrap()).unwrap();
        let (project_composable, packages) = build_composables(
            &path,
            &declared_path(),
            &ProjectResolution::MFileOnly(ctx),
            &WireContribution::default(),
            true,
        )
        .unwrap();
        assert!(
            project_composable.is_some(),
            "MFileOnly with [session] block → ProjectComposable present",
        );
        assert!(
            packages.is_empty(),
            "MFileOnly → no PackageComposables (no graph to walk)",
        );

        // Provenance names the project as the *user* knows it, not the
        // per-session workspace the mfile was read out of. The hooks
        // policy matches projects by this path and every error message
        // quotes it, so a per-session value would be unmatchable and
        // unrecognizable — see `build_composables`.
        use sessions::core::compose::Composable as _;
        let contribution = project_composable
            .unwrap()
            .contribute(&|_| Err(std::env::VarError::NotPresent))
            .expect("the fixture's [session] block contributes cleanly");
        let sources: Vec<_> = contribution
            .packages()
            .iter()
            .map(sessions::core::source::Provenanced::source)
            .collect();
        assert!(!sources.is_empty(), "fixture should contribute a package");
        for source in sources {
            let sessions::core::source::Source::Project { path } = source else {
                panic!("project material should carry Source::Project, got {source:?}");
            };
            assert_eq!(
                path.as_utf8_path().as_str(),
                declared_path().as_utf8_path().as_str(),
                "provenance should name the declared project path, not the workspace",
            );
        }
    }

    /// [`run_composer`] with an empty client contribution and no
    /// daemon-side composables produces a Ready outcome with an
    /// empty [`Composition`]. Baseline for the composer wiring.
    #[test]
    fn run_composer_empty_inputs_yield_ready_empty() {
        let outcome =
            run_composer(WireContribution::default(), None, Vec::new()).expect("no failures");
        match outcome {
            ComposeOutcome::Ready(composition) => {
                assert!(composition.packages().is_empty());
                assert!(composition.vars().is_empty());
                assert!(composition.patches().is_empty());
                assert!(composition.lifecycle_hooks().is_empty());
            }
            other => panic!("expected Ready, got {other:?}"),
        }
    }

    /// `min check` runs as a session side-op, so the stream contract the
    /// renderer in `env::run_check` depends on has to hold: the actor accepts
    /// a `StartCheck`, results flow, and the channel closes after exactly one
    /// terminal outcome. This workspace holds no `packages/`, `profiles/`, or
    /// `stacks/` dirs, so there is nothing to check and the run completes
    /// clean — the terminal update is the whole point here.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn start_check_closes_with_exactly_one_terminal_outcome() {
        use crate::session_sop::{CheckOpts, CheckOutcome, CheckUpdate};

        let (_state, _cache, mngr) = manager().await;
        let id = create_active_session(&mngr).await;
        // `start_check` builds a fresh workspace-rooted context per call, so
        // the workspace needs an mfile for it to resolve at all.
        seed_workspace_mfile(&mngr, id, "").await;

        let mut updates = session(&mngr, id)
            .await
            .start_check(CheckOpts {
                packages: true,
                stacks: true,
                fix: false,
                filter_names: vec![],
                skip_checkers: vec![],
            })
            .await
            .expect("starting a check on an Active session should succeed");

        let mut outcomes = Vec::new();
        while let Some(update) = updates.recv().await {
            match update {
                CheckUpdate::Checked { object, .. } => {
                    panic!("nothing to check in an empty workspace, got {object}")
                }
                CheckUpdate::Finished(o) => outcomes.push(o),
            }
        }

        assert!(
            matches!(
                outcomes.as_slice(),
                [CheckOutcome::Completed { failed: false }]
            ),
            "expected exactly one clean terminal outcome, got {outcomes:?}",
        );
    }

    /// The output is resolved before the side-op spawns, so an unknown name is
    /// a plain error rather than a terminal update on a channel the caller
    /// would first have to be handed and drain.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn start_materialize_rejects_an_unknown_output_by_name() {
        use crate::session_sop::MaterializeOpts;

        let (_state, _cache, mngr) = manager().await;
        let id = create_active_session(&mngr).await;
        // Builds a fresh workspace-rooted context, so an mfile must exist.
        seed_workspace_mfile(&mngr, id, "").await;

        let err = session(&mngr, id)
            .await
            .start_materialize(MaterializeOpts {
                output_name: "no-such-output".to_string(),
                arch: None,
            })
            .await
            .expect_err("an output the minimal file does not declare must be refused");

        assert_eq!(
            err.kind(),
            std::io::ErrorKind::NotFound,
            "an undeclared output is a NotFound, got {err:?}"
        );
        assert!(
            err.to_string().contains("no-such-output"),
            "the error must name the output that was asked for, got {err}"
        );
    }
}
