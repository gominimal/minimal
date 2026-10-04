//! Listen-published ingress (NET-016, NET-017): the ports a box publishes
//! because its processes listen on them.
//!
//! A declaration's forwards are static — bound at publish, held until the
//! box stops (NET-121) — but a port a permit range names has no forward to
//! hold: it exists to the processes inside the box alone, so the story's
//! shape is the kernel's socket table's. This module reads the box's
//! listening sockets through its leader's `/proc` entry — one table per
//! network namespace, so it names every listening socket in the box,
//! whichever of its processes holds it — polls and diffs them, and:
//!
//! * **publishes** each new listening port the shared verdict permits
//!   ([`SessionGate::listen_verdict`], the pure decision in
//!   `sessions::core::egress` the Kani harness exhausts): a forward bound at
//!   the box's own address, at the port the process listens on — no
//!   translation, the same number on both sides, exactly as a declaration's
//!   mapping publishes its external port (NET-010) — and the port admitted
//!   at the box's ingress gate for as long as the listener holds it;
//! * **leaves unpublished** every listening port the rules do not permit,
//!   so a connection to it is refused at the box's address (NET-014) and
//!   never forwarded by a listener nobody declared;
//! * **withdraws** each published port whose listener closed: the gate
//!   refuses it first — terminating the connections the publication held at
//!   both ends, the same end a revoked declared forwarder's connections come
//!   to — and the forward comes down after (NET-017).
//!
//! The watcher owns only the runtime-published set. A declared port is
//! never its to publish — its forward was bound before the box's name was
//! even registered — and never its to withdraw: a withdrawal applies only to
//! the runtime-published set (NET-081's sub-requirement), which is why the
//! two halves are tracked apart all the way down to the gate.
//!
//! But the runtime-published set has two publishers. The runtime
//! `min net expose` (NET-044) publishes a port on the user's own request,
//! and the watcher publishes one because the box's process listens on it —
//! and both bind at the box's published address, on whatever port they were
//! each asked for, so one port can be asked of the switch twice. It never
//! is: both surfaces read one per-box publication set
//! ([`BoxPublications`]) before they bind, a port the other surface already
//! holds is answered — by the expose path with the typed
//! already-published refusal, by the watcher with a silent skip that never
//! retries, because a publication that stands is not a failure — and
//! withdrawal belongs to whoever published: the watcher never withdraws a
//! port the expose path holds, and the expose path never asks down a port
//! the watcher published. Every publication the two surfaces make is one
//! entry with one owner, so a port is bound once however many surfaces ask
//! for it.
//!
//! The plan a launch gathers rides [`crate::session_host::Launched`] to the
//! host that runs its box — no process-global table between them — so a
//! plan is the launch's own from the moment it is built, and a launch that
//! built none starts no watcher at all.
//!
//! Two properties the story's shape rides on, beside the diff itself. The
//! table is read as the forward reads the box: a listener counts only when
//! its bind can answer the dial a publication makes — to the box's lease —
//! so a process bound to the box's loopback alone is not published at all
//! ([`binds_for_the_lease`]); and nothing here is one-shot — a publication
//! whose bind failed is retried on a per-port backoff that doubles off the
//! poll interval, a withdrawal whose unexpose failed is retried on every
//! poll the box still runs and through the stop's passes, so a transient
//! refusal on the control channel never settles into a port that stays
//! missing or a forward that stays bound, and a leader the box's host could
//! not resolve when it built is asked for again on every poll ([`Leader`]),
//! so a shell that was mid-spawn or a `/proc` that could not answer for the
//! moment costs the moment between two polls and never the box's whole
//! listen-published surface. Neither half says its failure
//! more than once while it keeps failing: the first refusal of a streak
//! is the line, and the line that ends a streak is the publication's or
//! the withdrawal's own — so a forwarder that is down for as long as the
//! box lives is waited for, not written over and over.
//!
//! Polling, not a socket-diagnostic netlink socket or an inotify watch, is
//! the honest read here: `/proc/<pid>/net/tcp` emits no change notification
//! there is to subscribe to, and a process inside the box can bind without
//! the daemon ever being told — the table *is* the notification, and reading
//! it on an interval is the only way the daemon has of learning a listener
//! exists. The interval ([`LISTEN_POLL_INTERVAL`]) is a person-facing
//! number: a server a developer starts is published inside the second they
//! finish typing its port.
//!
//! One info line per publication and per withdrawal — each naming the port,
//! the box, and whether the rules permitted it — so the diagnostics
//! bundle's daemon log tail reads the whole surface (the observability
//! contract of the story this module implements).

use std::collections::{HashMap, HashSet};
use std::io;
use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::watch;

use sessions::IpProto;
use sessions::core::egress::ListenVerdict;

use super::policy::{ControlChannel, ExposedMapping, expose_mapping, unexpose_mapping};
use super::switch::SessionGate;

/// How often the watcher reads the box's socket table: often enough that a
/// listener a person starts is published before they look for it, rare
/// enough that one box's watcher is not a load on the daemon — one small
/// `/proc` read per box per quarter second.
const LISTEN_POLL_INTERVAL: Duration = Duration::from_millis(250);

/// How many passes the stop's withdrawal ([`WatchState::withdraw_all`])
/// makes at the forwards still standing: the first, then a bounded number
/// of retries for those a pass could not bring down — enough that a
/// transient refusal does not leave a forward bound past its box, holding
/// the box's published address:port against a future session there, never
/// enough that a control channel that is down outright hangs the stop.
const WITHDRAW_PASSES: usize = 3;

/// The longest a permitted port's publish waits between attempts: the
/// backoff doubles off the poll interval once per refusal in the streak, so
/// the first refusal costs exactly the one poll the one-shot retry paid and
/// a refusal that persists is *waited for* — one attempt every half minute,
/// never one per poll — while never being given up on.
const PUBLISH_RETRY_CAP: Duration = Duration::from_secs(30);

/// Everything a box's listener watcher needs, gathered by the launch that
/// attached the box: its name (each publication's line names the box), its
/// switch lease (the address a publication's forward delivers to), the
/// published address the forward binds — the box's own address (NET-010),
/// wherever it was granted, read back the same way the attach path reads
/// it — the gvproxy control channel the forwarder verbs ride, the box's
/// session gate, which holds the shared permit decision
/// ([`SessionGate::listen_verdict`]) and the admission a published port is
/// given through, and the box's publication set, shared with the runtime
/// expose surface so neither binds a port the other already holds.
pub struct ListenPlan {
    /// The box's name, as the daemon's own session lines name it.
    box_name: String,
    /// The box's address on the switch — where a publication's forward
    /// delivers.
    lease: Ipv4Addr,
    /// The box's published address (NET-010) — where a publication binds.
    published: Ipv4Addr,
    /// The gvproxy control channel: `expose` to publish, `unexpose` to
    /// withdraw.
    control: ControlChannel,
    /// The box's session gate: the permit decision and the admission.
    gate: Arc<SessionGate>,
    /// The box's publications, shared with the runtime expose surface
    /// ([`crate::session::Session`]): the one set both read before they
    /// bind, and the one place a publication's owner is written down.
    publications: BoxPublications,
}

impl ListenPlan {
    /// Assembles the plan from the facts its launch holds. The gate must be
    /// the one the box's relay registered — the gate the connections a
    /// publication forwards are admitted by on their way through the
    /// relay — and the publication set must be the one the session's
    /// runtime expose surface reads, so the two surfaces never bind the
    /// same port.
    #[must_use]
    pub fn new(
        box_name: String,
        lease: Ipv4Addr,
        published: Ipv4Addr,
        control: ControlChannel,
        gate: Arc<SessionGate>,
        publications: BoxPublications,
    ) -> Self {
        Self {
            box_name,
            lease,
            published,
            control,
            gate,
            publications,
        }
    }
}

/// Which of the box's two runtime ingress surfaces owns a publication: the
/// runtime `min net expose` (NET-044), or the listen watcher this module
/// runs (NET-016). Ownership decides who may withdraw — a publication comes
/// down with whoever published it, never with the other surface that
/// declined to bind it — and it is the field the publication and refusal
/// lines carry, so a daemon log's tail reads whose publication every port
/// is from either surface's lines.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicationOwner {
    /// The runtime expose path: a publication the user asked for with
    /// `min net expose`.
    Expose,
    /// The listen watcher: a publication the box's own listening process
    /// earned.
    Listen,
}

impl PublicationOwner {
    /// How the owner is named on the lines its publications and their
    /// refusals carry.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Expose => "expose",
            Self::Listen => "listen",
        }
    }
}

/// The box's runtime publications, one entry per port the switch holds a
/// forward for, carrying the surface that owns it. Both surfaces that
/// publish at runtime — the expose path and the listen watcher — read this
/// one set before they bind, so a port the other surface already holds is
/// never asked of the switch twice, and the set is the one place the answer
/// to "who owns this publication" lives, so withdrawal can be refused
/// everywhere it does not belong.
///
/// The set belongs to one *launch*, not to the session for good: the
/// session's launcher ([`crate::session::Session::session_launcher`])
/// builds a fresh one for the spawn it is about to run, hands it to the
/// launcher beside the plan, and the session actor reads the same one — so
/// a respawn starts with an empty set by construction, never with the
/// entries of a spawn whose box has gone, and the set is bounded by the
/// ports one box has published, never grown over the daemon's life.
#[derive(Debug, Default, Clone)]
pub struct BoxPublications {
    /// The ports this box's two surfaces have published, each with its
    /// owner. The lock is a plain mutex held for map reads and writes only,
    /// never across a switch round trip.
    ports: Arc<Mutex<HashMap<u16, PublicationOwner>>>,
}

impl BoxPublications {
    /// The surface that owns `port`'s publication, if the box has one: the
    /// answer both surfaces read before they bind, and the answer a
    /// refusal line names when the other surface already holds the port.
    pub fn held_by(&self, port: u16) -> Option<PublicationOwner> {
        self.ports
            .lock()
            .expect("box publications lock poisoned")
            .get(&port)
            .copied()
    }

    /// Writes `port` down as `owner`'s publication. Fails, naming the owner
    /// that holds it, when the other surface published while this caller
    /// was binding — the race both surfaces close the same way: unbind, and
    /// answer as the duplicate the switch never doubled.
    pub fn record(&self, port: u16, owner: PublicationOwner) -> Result<(), PublicationOwner> {
        let mut ports = self.ports.lock().expect("box publications lock poisoned");
        match ports.get(&port) {
            Some(&held) if held != owner => Err(held),
            _ => {
                ports.insert(port, owner);
                Ok(())
            }
        }
    }

    /// Withdraws `port` from the set — `owner`'s own publication only. The
    /// other surface's entry is left standing whatever the caller meant,
    /// because the publisher is the one who withdraws: a port held by
    /// `Expose` here is never taken down by the watcher, and one held by
    /// `Listen` is never taken down by the expose path.
    pub fn withdraw(&self, port: u16, owner: PublicationOwner) {
        let mut ports = self.ports.lock().expect("box publications lock poisoned");
        if ports.get(&port).is_some_and(|held| *held == owner) {
            ports.remove(&port);
        }
    }
}

/// The box's leader as the watcher holds it: the PID whose `/proc` entry
/// reads the box's whole network namespace — or, while that PID is still to
/// be found, the container PID the resolution is owed from.
///
/// The leader is not a precondition of the watcher's existence. The
/// resolution can be refused for reasons that pass — a shell that is
/// mid-spawn, a `/proc` whose `children` file cannot answer for the moment —
/// and a watcher that needed it to have succeeded would turn each of those
/// into a box whose ports are never published by listening, for its whole
/// life. So the watcher starts with what it has — a leader the box's host
/// resolved, or the container PID to resolve one from — and asks again on
/// every poll the leader is still owed ([`WatchState::resolve_leader`]):
/// the nothing-is-one-shot contract the module's publish and withdraw halves
/// hold, held of its start too.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Leader {
    /// The session leader — the program the box runs, whose `/proc` entry
    /// names every listening socket in the box. Pinned for the watcher's
    /// life once resolved: the box's table is the box's, whichever of its
    /// processes the entry belongs to, and a leader that has gone is the
    /// box ending — the host's stop is what ends the watcher, not a fact
    /// to re-resolve.
    Resolved(u32),
    /// The container PID [`crate::nsenter::session_leader_pid`] resolves the
    /// leader from — `hakoniwa`'s supervisor, the daemon-side handle whose
    /// sole child is the program the box runs.
    Pending {
        /// The container supervisor the leader is resolved from.
        container_pid: u32,
    },
}

/// The running watcher: what a host holds for its box's lifetime, stopped by
/// [`Self::stop`] at session end. Stopping is the one other thing the
/// watcher does — its loop polls, and everything it published comes down
/// before `stop` returns, so no runtime-published forward outlives its box.
pub struct ListenWatcher {
    /// Signals the loop out of its poll cycle. The withdrawal that follows
    /// is the stop's own work, and the loop's last.
    stop: watch::Sender<bool>,
    /// The loop task: it ends after withdrawing everything, so awaiting it
    /// *is* awaiting the withdrawal.
    task: tokio::task::JoinHandle<()>,
}

impl ListenWatcher {
    /// Starts the box's watcher: a loop that reads the listening sockets of
    /// the process tree `leader` names — the box's leader, whose `/proc`
    /// entry names the whole box's network namespace — and keeps the
    /// box's publications in step with them. The first poll happens at
    /// once, so a listener that outlived a previous host is published
    /// before a person can look for it.
    ///
    /// `leader` may still be owed ([`Leader::Pending`]): the box's host
    /// stages the container PID it holds and the watcher resolves the
    /// program itself, so a box whose leader could not be found when its
    /// host built — a shell mid-spawn, a `/proc` that could not answer —
    /// publishes the moment the next poll finds it, rather than never.
    #[must_use]
    pub fn start(plan: ListenPlan, leader: Leader) -> Self {
        let (stop, mut stop_rx) = watch::channel(false);
        let task = tokio::spawn(async move {
            let mut state = WatchState::new(plan, leader);
            loop {
                state.poll().await;
                tokio::select! {
                    _ = stop_rx.changed() => break,
                    _ = tokio::time::sleep(LISTEN_POLL_INTERVAL) => {}
                }
            }
            // The stop's own work: everything the box's processes published
            // comes down here, before the stopper's teardown continues.
            state.withdraw_all().await;
        });
        Self { stop, task }
    }

    /// Stops the watcher and withdraws every port it still publishes — the
    /// gate refusing each first, the switch's forward second — so that when
    /// this returns, no port the box's processes published by listening is
    /// published any more. The declared forwards are not this call's:
    /// they come down with the attachment's own teardown (NET-121).
    pub async fn stop(mut self) {
        #[expect(
            clippy::let_underscore_must_use,
            reason = "the loop may already have ended; the join below is what reports that"
        )]
        let _ = self.stop.send(true);
        // The task is awaited by reference, not moved out of `self` — the
        // [`Drop`] below ends the watcher a host that never reaches this
        // stop leaves, and the drop at this stop's end finds a loop that
        // has already finished.
        if let Err(join) = (&mut self.task).await {
            tracing::warn!(
                error = %join,
                "the listen-publication watcher ended without withdrawing everything"
            );
        }
    }
}

impl Drop for ListenWatcher {
    /// The ending a host that never reached its mainloop's stop gives its
    /// watcher: dropped, not stopped — a host build abandoned, a future
    /// cancelled mid-flight. The drop is the loop's stop signal, so the poll
    /// ends and the loop runs the same withdrawal every stop runs: the gate
    /// refusing each port first, the forward coming down after, everything
    /// it published — no forward a box's processes published by listening
    /// outlives the watcher, whichever way the watcher ended.
    ///
    /// The signal is all the guard sends; the task is not aborted, on
    /// purpose. The withdrawal is the loop's own last act, and the loop is
    /// the only owner of the forwards map — an abort would kill it
    /// mid-withdrawal and leave every forward still standing on the switch
    /// for the switch's lifetime, the outcome the stop exists to prevent.
    /// Dropping the task's handle detaches it, so it finishes its epilogue
    /// the way `Host::mainloop`'s own kill does (the session's
    /// detach-over-abort choice, held here for the same reason).
    fn drop(&mut self) {
        #[expect(
            clippy::let_underscore_must_use,
            reason = "the loop may already have ended, and nothing here awaits its \
                      join to report that — the drop's caller is gone"
        )]
        let _ = self.stop.send(true);
    }
}

/// The watcher's own state: what the box's processes were listening on at
/// the last read, and which of those the watcher published. `forwards` is
/// exactly the runtime-published set (NET-081's sub-requirement's own set):
/// a declared port is never in it, and a port the rules did not permit
/// never enters it.
struct WatchState {
    plan: ListenPlan,
    /// The box's leader — resolved, or the container PID it is still owed
    /// from ([`Leader`]).
    leader: Leader,
    /// Whether the streak of resolutions that could not find the box's
    /// leader has been said already: the first refusal is the line, and
    /// the polls that retry it are the same failure waited out — the
    /// publish half's own discipline, held of the leader. The line that
    /// ends the streak is the resolution's own: the publications the leader
    /// it found makes.
    reported_leader_refusal: bool,
    /// The listening ports the last read settled — published, declined by
    /// the rules, or a declaration's own. A port whose publication failed to
    /// bind is held out until a poll binds it, so the diff reads it as
    /// appeared again: the retry the bind failure's line promises.
    listening: HashSet<u16>,
    /// The forwards standing for the ports the watcher published — standing
    /// on the switch, including one whose unexpose failed and whose
    /// withdrawal is therefore still owed.
    forwards: HashMap<u16, ExposedMapping>,
    /// One entry per permitted port whose publish the switch has refused
    /// and not yet re-granted: when its next attempt may run, and how many
    /// attempts the streak has refused. A port with an entry is one the
    /// box is still listening on and the watcher still owes a publication,
    /// which is exactly the set [`Self::listening`] is held down to.
    backoff: HashMap<u16, PublishBackoff>,
    /// The ports whose failed unexpose has been said once already: a
    /// withdrawal that keeps failing is the *same* failure on every poll
    /// and every stop pass, so its line is written once — the withdrawal's
    /// own line, when the unexpose finally comes down, ends the streak.
    reported_withdrawal_failures: HashSet<u16>,
}

/// One permitted port whose publish the switch refused: the book
/// [`WatchState::poll`] keeps so a refusal that is not transient is waited
/// out per port rather than re-asked on every poll.
struct PublishBackoff {
    /// When the next expose attempt may run — the backoff the streak's last
    /// refusal chose.
    retry_at: std::time::Instant,
    /// How many attempts the streak has refused: the count the publication
    /// that ends it carries, and the doubling's own counter.
    refusals: u32,
}

/// The wait a refused publish's next attempt takes: the poll interval
/// doubled once per refusal already in the streak, capped at
/// [`PUBLISH_RETRY_CAP`]. The first refusal costs one poll — exactly the
/// retry a single failure always paid — and each one after it doubles, so a
/// forwarder that is down for as long as it takes is asked about once every
/// half minute at most instead of four times a second.
fn retry_after(refusals: u32) -> Duration {
    let mut delay = LISTEN_POLL_INTERVAL;
    for _ in 1..refusals {
        delay = delay.saturating_mul(2).min(PUBLISH_RETRY_CAP);
    }
    delay
}

impl WatchState {
    fn new(plan: ListenPlan, leader: Leader) -> Self {
        Self {
            plan,
            leader,
            reported_leader_refusal: false,
            listening: HashSet::new(),
            forwards: HashMap::new(),
            backoff: HashMap::new(),
            reported_withdrawal_failures: HashSet::new(),
        }
    }

    /// The PID this poll reads the box's table through, resolving the leader
    /// first when it is still owed: the resolution is retried on every poll
    /// that fails, so a refusal that passes costs the moment between two
    /// polls — never the box's whole listen-published surface, which is
    /// what a start that needed the resolution to have succeeded would
    /// cost it. A resolved leader is pinned ([`Leader::Resolved`]).
    ///
    /// `None` while the leader is still owed, the refusal said once for its
    /// streak the way a refused publish's is.
    fn resolve_leader(&mut self) -> Option<u32> {
        match self.leader {
            Leader::Resolved(leader) => Some(leader),
            Leader::Pending { container_pid } => {
                match crate::nsenter::session_leader_pid(container_pid) {
                    Ok(leader) => {
                        // The streak of refused resolutions — if there was
                        // one — is over, and a later refusal is a streak of
                        // its own.
                        self.reported_leader_refusal = false;
                        self.leader = Leader::Resolved(leader);
                        Some(leader)
                    }
                    Err(e) => {
                        if !self.reported_leader_refusal {
                            self.reported_leader_refusal = true;
                            tracing::warn!(
                                session = %self.plan.box_name,
                                container_pid,
                                error = %e,
                                "resolving the box's leader to read its listening sockets, \
                                 retrying on every poll"
                            );
                        }
                        None
                    }
                }
            }
        }
    }

    /// One poll: resolve the box's leader when it is still owed, read the
    /// box's listening sockets, publish what appeared, withdraw what
    /// closed, and ask again for what a refusal has left owed. A poll that
    /// has not found the leader publishes nothing and withdraws nothing —
    /// it has no table to diff — and asks again on the next one. A
    /// publication that failed to bind keeps its port out of the
    /// book ([`Self::listening`]), so the next poll reads the port as
    /// appeared again — the appearance is not consumed by the failure, and
    /// a transient refusal on the control channel never turns into a
    /// permitted port that stays unpublished until its server restarts.
    async fn poll(&mut self) {
        // The leader first, when the box's host could not resolve it.
        let Some(leader) = self.resolve_leader() else {
            return;
        };
        let listening = match listening_ports(leader, self.plan.lease) {
            Ok(listening) => listening,
            Err(e) => {
                // The leader's entry is gone or unreadable — the box's
                // shell has exited, and the host stops the watcher with
                // the session. Keep the last diff rather than publishing
                // or withdrawing on a table that could not be read: the
                // stop withdraws everything still standing.
                tracing::debug!(
                    session = %self.plan.box_name,
                    leader,
                    error = %e,
                    "reading the box's listening sockets"
                );
                return;
            }
        };
        // The diff is taken before anything mutates, so a publication made
        // here cannot be seen by the withdrawal beside it.
        let appeared: Vec<u16> = listening.difference(&self.listening).copied().collect();
        let disappeared: HashSet<u16> = self.listening.difference(&listening).copied().collect();
        for port in appeared {
            self.publish(port).await;
        }
        for port in &disappeared {
            self.close(*port, "listener closed").await;
        }
        // The withdraw half of the nothing-is-one-shot promise: a forward
        // whose unexpose failed is still standing on the switch —
        // delivering to a lease:port nothing answers — for as long as the
        // box runs, and the port left the listening book the poll its
        // listener closed in, so the diff above never reads it as
        // disappeared twice. Every port held in `forwards` that this
        // poll's table does not name is a withdrawal the watcher still
        // owes, and is asked for again here — bar one the diff above just
        // tried, which this poll has already asked for and the next one
        // will.
        let owed: Vec<u16> = self
            .forwards
            .keys()
            .copied()
            .filter(|port| !listening.contains(port) && !disappeared.contains(port))
            .collect();
        for port in owed {
            self.close(port, "the listener had closed and its unexpose failed")
                .await;
        }
        // A port whose listener closed takes its backoff streak with it: the
        // book keeps a backed-off port out of the listening table (below), so
        // the diff above never reads one as disappeared — without this, the
        // entry outlives the listener it was refused for, and the next server
        // the box binds on that port number inherits a wait it did not earn
        // and a count whose first failure was never said. The fresh table is
        // the fact that decides: an entry survives only while a process in
        // the box is still listening on its port.
        self.backoff.retain(|port, _| listening.contains(port));
        self.listening = listening;
        // A port in the backoff book is one the box is listening on and
        // the watcher has still not published, so it stays out of the
        // book the diff reads: every poll that does not retry it sees it
        // as appeared again, and the poll that does keeps it unsettled
        // until the forward binds.
        self.listening
            .retain(|port| !self.backoff.contains_key(port));
    }

    /// NET-016: one listening port appeared, published unless the switch is
    /// still refusing its publish. A port whose last attempt failed waits
    /// its backoff out first — the appearance it still owes is kept while
    /// it waits, never dropped and never re-asked on every poll.
    async fn publish(&mut self, port: u16) {
        let refusals = match self.backoff.get(&port) {
            // The streak's backoff has not elapsed: this poll does not ask.
            Some(wait) if wait.retry_at > std::time::Instant::now() => return,
            Some(wait) => wait.refusals,
            None => 0,
        };
        if self.open(port, refusals).await {
            // The streak ends: the port is published, and the next failure
            // — if the box's server ever makes one — is a streak of its own.
            self.backoff.remove(&port);
        } else {
            let refusals = refusals + 1;
            self.backoff.insert(
                port,
                PublishBackoff {
                    retry_at: std::time::Instant::now() + retry_after(refusals),
                    refusals,
                },
            );
        }
    }

    /// NET-016: one listening port appeared. The shared verdict decides
    /// what the appearance is worth before anything is bound, and the box's
    /// publication set decides it with them: a port the runtime expose
    /// already published is settled the way one the rules do not permit is
    /// — left alone, never bound, never withdrawn, never retried —
    /// because a publication that already stands is not this watcher's to
    /// double. Returns whether the appearance is settled — `false` only
    /// for a permitted port whose forward failed to bind, the one
    /// appearance [`Self::poll`] hands back to the next poll as appeared
    /// again, on the backoff its refusals have earned.
    ///
    /// `refusals` counts the attempts this port's publish streak has
    /// already been refused, so the failure is said once per streak — the
    /// first refusal's line, never the retries' — and the publication that
    /// ends a streak names what it took.
    async fn open(&mut self, port: u16, refusals: u32) -> bool {
        // TCP is the transport the watcher knows a listener in: the kernel
        // tables it reads name TCP listening sockets, and the forward it
        // binds answers TCP — so TCP is the transport it asks the shared
        // verdict for. A declaration that names the port on UDP alone is
        // not a publication of this listener (its forward would never
        // answer the protocol the watcher dials), so the verdict falls to
        // the rules rather than answering `Declared` transport-blind.
        match self.plan.gate.listen_verdict(IpProto::Tcp, port) {
            ListenVerdict::Publish => {
                if self.forwards.contains_key(&port) {
                    // The port's listener closed, the withdrawal's unexpose
                    // failed, and the listener is back before the stop
                    // could retry the forward down: the forward never came
                    // down, so the publication still stands and still
                    // delivers to a port the rules permit. Re-admit it
                    // rather than ask the switch to bind a second forward
                    // onto the bind this one still holds.
                    self.reported_withdrawal_failures.remove(&port);
                    self.plan.gate.admit_published(port);
                    tracing::info!(
                        session = %self.plan.box_name,
                        host = %self.plan.published,
                        port,
                        verdict = "permitted",
                        reason = "the listener returned while its withdrawal had failed",
                        "re-admitted a listening port on the box's address"
                    );
                    return true;
                }
                // The box's other runtime surface may already hold this
                // port: a `min net expose` published it live, and its
                // forward stands until the box does (NET-044). A second
                // bind would double-bind the box's own address at the same
                // port, and the publication is not this watcher's to
                // withdraw — so the appearance is settled the way one the
                // rules do not permit settles: said once, never bound,
                // never withdrawn, and never retried, because the
                // settlement enters the port in the poll's book and a
                // backoff is for a publish that failed, not for a
                // publication that already stands.
                if self.plan.publications.held_by(port) == Some(PublicationOwner::Expose) {
                    tracing::info!(
                        session = %self.plan.box_name,
                        host = %self.plan.published,
                        port,
                        verdict = "permitted",
                        owner = %PublicationOwner::Expose.as_str(),
                        "left a listening port the runtime expose already published"
                    );
                    return true;
                }
                // The forward binds before the gate admits — the order the
                // declaration's own apply holds (NET-121), so a port is
                // never admitted while nothing answers for it, and a bind
                // that fails admits nothing: the failure is said below,
                // once per streak, and the poll keeps the port out of its
                // book, so a later poll sees it still unpublished and asks
                // again on the backoff the refusals have earned.
                match expose_mapping(
                    &self.plan.control,
                    self.plan.published,
                    self.plan.lease,
                    port,
                )
                .await
                {
                    Ok(mapping) => {
                        // The publication is written down as this
                        // watcher's before the port is served, and the race
                        // the check above could not see — the expose
                        // surface binding across the await — is closed
                        // here: the expose won the port while this bind was
                        // in flight, so this forward comes straight back
                        // down, said with the reason it came down, and the
                        // appearance is settled the way the skip above
                        // settles it.
                        if let Err(_holder) = self
                            .plan
                            .publications
                            .record(port, PublicationOwner::Listen)
                        {
                            self.forwards.insert(port, mapping);
                            self.close(
                                port,
                                "the runtime expose published while the watcher was binding",
                            )
                            .await;
                            return true;
                        }
                        self.plan.gate.admit_published(port);
                        self.forwards.insert(port, mapping);
                        tracing::info!(
                            session = %self.plan.box_name,
                            host = %self.plan.published,
                            port,
                            verdict = "permitted",
                            owner = %PublicationOwner::Listen.as_str(),
                            refusals,
                            "published a listening port on the box's address"
                        );
                        true
                    }
                    Err(e) => {
                        if refusals == 0 {
                            // One line per streak: the refusals after this
                            // one are the same failure, waited out rather
                            // than repeated — the daemon log's tail is the
                            // diagnostics bundle's.
                            tracing::warn!(
                                session = %self.plan.box_name,
                                host = %self.plan.published,
                                port,
                                verdict = "permitted",
                                retry_in = ?retry_after(refusals + 1),
                                error = %e,
                                "publishing a listening port on the switch failed"
                            );
                        }
                        false
                    }
                }
            }
            // A declaration names the port: its forward was bound at
            // publish and is held until the box stops (NET-121), so there
            // is nothing to publish — and when the listener closes, nothing
            // to withdraw (NET-081's sub-requirement). The declaration's
            // own bind lines already name the port.
            ListenVerdict::Declared => true,
            ListenVerdict::Deny => {
                tracing::info!(
                    session = %self.plan.box_name,
                    port,
                    verdict = "not permitted",
                    "left a listening port unpublished"
                );
                true
            }
        }
    }

    /// NET-017: one published listening port closed — or the box stopped,
    /// which closes all of them at once. The gate refuses the port first,
    /// terminating the connections the publication held at both ends, so no
    /// new connection crosses the gap between a listener already gone and a
    /// forward still bound; the forward comes down after. The order a
    /// revoked declared forwarder's own `revoke` holds (NET-121).
    ///
    /// `reason` names what ended the publication: the listener closing under
    /// the box's own life, the box's stop taking every publication with it,
    /// or a poll asking again for a forward whose unexpose failed while the
    /// box still runs. A port the runtime expose published never reaches
    /// the unexpose here — it is not in the watcher's forwards — so a
    /// publication comes down with whoever published it, never with the
    /// other surface that declined to bind it.
    async fn close(&mut self, port: u16, reason: &'static str) {
        let Some(mapping) = self.forwards.remove(&port) else {
            // Never published by the watcher: a declared port, whose
            // forward is the declaration's (NET-121), one the rules did
            // not permit, whose publication never existed — or one the
            // runtime expose holds, whose forward is the expose path's and
            // whose withdrawal is the expose path's alone.
            return;
        };
        // The gate withdraws before the forward comes down, and the order is
        // the point: between the two, the listener is already gone and the
        // forward still bound, so a connection arriving in that gap would be
        // accepted by the box's own address and delivered to nothing. With
        // the gate first, that connection is refused at the address instead
        // — the same order a revoked declared forwarder's `revoke` holds
        // (NET-121), so both ingress surfaces end a publication the same
        // way.
        let terminated = self.plan.gate.withdraw_published(port);
        match unexpose_mapping(&self.plan.control, &mapping).await {
            Ok(()) => {
                // The publication is the watcher's own and it came down, so
                // the set gives the port back: the next surface that wants
                // it — this watcher, when the box's next server binds the
                // same number, or the expose path on a runtime request —
                // finds it free to publish.
                self.plan
                    .publications
                    .withdraw(port, PublicationOwner::Listen);
                // The withdrawal came down, so the streak of its failures —
                // if it had one — is over and a later failure is its own.
                self.reported_withdrawal_failures.remove(&port);
                tracing::info!(
                    session = %self.plan.box_name,
                    host = %self.plan.published,
                    port,
                    verdict = "permitted",
                    terminated,
                    reason,
                    "withdrew a listening port from the box's address"
                );
            }
            Err(e) => {
                // One line per streak, like the publish half: the retries
                // the poll makes while the box runs and the stop's own
                // passes are the same failure, and repeating it four times
                // a second is what a forwarder that is down outright fills
                // the daemon log with.
                if self.reported_withdrawal_failures.insert(port) {
                    tracing::warn!(
                        session = %self.plan.box_name,
                        host = %self.plan.published,
                        port,
                        verdict = "permitted",
                        error = %e,
                        "unpublishing a listening port on the switch failed"
                    );
                }
                // The unexpose failed and said so. The gate already refuses
                // the port, so nothing reaches the box through the forward
                // left standing; keep it in the published set — and in the
                // box's publication set, whose entry says the watcher owns
                // a forward that is still bound, so no second surface asks
                // the switch for a port the first still holds — the next
                // poll asks for it again while the box runs, the stop's
                // withdrawal passes retry it before the watcher ends, and a
                // listener that comes back first re-admits the forward it
                // still holds — rather than leaving it for the switch's
                // lifetime.
                self.forwards.insert(port, mapping);
            }
        }
    }

    /// Stops the box's whole runtime-published surface: every forward still
    /// standing, withdrawn in the same order a listener's closing takes. A
    /// forward whose unexpose failed is retried on the next pass, one
    /// poll-interval apart, so a transient refusal does not leave it bound
    /// past its box holding the box's published address:port — and the
    /// passes are bounded, so a control channel that is down outright ends
    /// the stop rather than hanging it. Whatever still stands when they are
    /// spent is named, never left silent — and nothing else is: a last pass
    /// that brings everything down ends the stop with nothing to warn
    /// about.
    async fn withdraw_all(&mut self) {
        for attempt in 0..WITHDRAW_PASSES {
            if self.forwards.is_empty() {
                return;
            }
            if attempt > 0 {
                // A moment between passes, so a forwarder that was refusing
                // while mid-restart can answer the retry.
                tokio::time::sleep(LISTEN_POLL_INTERVAL).await;
            }
            let ports: Vec<u16> = self.forwards.keys().copied().collect();
            for port in ports {
                self.close(port, "box stopped").await;
            }
        }
        if self.forwards.is_empty() {
            // The last pass brought the last forward down: every port the
            // box's processes published is unpublished, and a warning that
            // named none of them would only say the stop happened — which
            // the stop itself already says.
            return;
        }
        let still: Vec<&str> = self.forwards.values().map(ExposedMapping::local).collect();
        tracing::warn!(
            session = %self.plan.box_name,
            still_published = ?still,
            "the box stopped with listening ports its watcher could not withdraw"
        );
    }
}

/// The TCP ports the listening sockets of the network namespace `leader`'s
/// `/proc` entry name hold at the box's `lease` — the box's own table, read
/// through its leader: the kernel's socket tables are per-network-namespace,
/// so one process's entry names every listening socket in the box, whichever
/// of its processes holds it. Both tables are read — a server bound on the
/// IPv6 any address accepts IPv4 connections, and its row lives in `tcp6` —
/// and only the rows a publication's forward can deliver to are kept
/// ([`binds_for_the_lease`]).
///
/// # Errors
///
/// Any read failure, so a caller decides what an unreadable table means
/// rather than silently acting on half of one.
fn listening_ports(leader: u32, lease: Ipv4Addr) -> io::Result<HashSet<u16>> {
    let entry = Path::new("/proc").join(leader.to_string());
    let mut ports = read_listening(&entry.join("net/tcp"), false, lease)?;
    ports.extend(read_listening(&entry.join("net/tcp6"), true, lease)?);
    Ok(ports)
}

/// One kernel socket table's listening ports: every row in state `0A`
/// (`TCP_LISTEN`) whose local address a forward dialing the box's lease can
/// deliver to. The first line is the table's header.
fn read_listening(table: &Path, v6: bool, lease: Ipv4Addr) -> io::Result<HashSet<u16>> {
    let text = std::fs::read_to_string(table)?;
    Ok(text
        .lines()
        .skip(1)
        .filter_map(|line| listen_port(line, v6, lease))
        .collect())
}

/// The port of one listening row of the kernel's socket table, or `None`
/// for any other row: the header, a truncated row, a socket in any state
/// but `TCP_LISTEN` — an established or time-wait socket is a connection,
/// not a listener — or a listener whose bind the forward's dial cannot
/// reach, whichever table it is in.
fn listen_port(line: &str, v6: bool, lease: Ipv4Addr) -> Option<u16> {
    let mut fields = line.split_whitespace();
    // `sl:` — the table's index column, always first.
    fields.next()?;
    let local = fields.next()?;
    // `rem_address`, then `st`.
    fields.next()?;
    if fields.next()? != "0A" {
        return None;
    }
    let (address, port) = local.rsplit_once(':')?;
    if !binds_for_the_lease(address, v6, lease) {
        return None;
    }
    u16::from_str_radix(port, 16).ok()
}

/// Whether a listening row's local address can answer the connection a
/// publication's forward makes. The forward dials `lease:port` — never
/// another address in the box's namespace — so only a socket bound to the
/// any address, which answers on every address the namespace holds, or to
/// the lease itself ever hears it. A socket bound anywhere else — the
/// box's loopback, the shape a dev server binds by default — would leave
/// the publication a phantom: the box's address accepting a connection
/// only for the dial to be refused at the lease, a reset in the place
/// NET-014 owes a refusal. Such a row is left unpublished, so nothing is
/// ever bound at the box's address for the port at all.
///
/// For a `tcp6` row the same rule reads the IPv4 address the v6 socket can
/// serve: the dual-stack any (`::`), which accepts IPv4 by mapping, or a
/// mapped address (`::ffff:a.b.c.d`) whose v4 part is the any or the lease.
/// A listener on any other v6 address cannot be reached at the box's IPv4
/// lease at all.
fn binds_for_the_lease(address: &str, v6: bool, lease: Ipv4Addr) -> bool {
    if !v6 {
        return match v4_word(address) {
            Some(bound) => bound.is_unspecified() || bound == lease,
            None => false,
        };
    }
    if address.len() != 32 {
        return false;
    }
    // The kernel prints each 32-bit word little-endian, so the mapped
    // marker reads `FFFF0000` and the dual-stack any as four zero words.
    if address.bytes().all(|b| b == b'0') {
        return true;
    }
    address.starts_with("0000000000000000FFFF0000")
        && match address.get(24..32).and_then(v4_word) {
            Some(bound) => bound.is_unspecified() || bound == lease,
            None => false,
        }
}

/// One word of the kernel's address column as the IPv4 address it names:
/// the table prints each 32-bit word little-endian — `127.0.0.1` reads
/// `0100007F` — so the eight hex digits are byte-swapped back into network
/// order. `None` for anything that is not exactly that.
fn v4_word(word: &str) -> Option<Ipv4Addr> {
    if word.len() != 8 || !word.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    u32::from_str_radix(word, 16)
        .ok()
        .map(|word| Ipv4Addr::from(word.swap_bytes()))
}

#[cfg(test)]
mod tests {
    use std::net::TcpListener;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
    use std::time::Duration;

    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::{UnixListener, UnixStream};
    use tokio::sync::mpsc;

    use crate::net::SwitchSubnet;

    use super::*;

    /// One request the fake forwarder served: the verb's path and the
    /// `local`/`remote`/`protocol` fields its body carried.
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct Served {
        path: String,
        local: String,
        remote: String,
        protocol: String,
    }

    /// The `name` field of a JSON request body, spelled as the serializer
    /// wrote it.
    fn field_of(body: &[u8], name: &str) -> String {
        let text = String::from_utf8_lossy(body);
        text.split(&format!("\"{name}\":\""))
            .nth(1)
            .and_then(|rest| rest.split('"').next())
            .unwrap_or_default()
            .to_string()
    }

    /// Reads one control request off `sock`: its head up to the end-of-head
    /// marker, then exactly its `Content-Length` body — the mirror of
    /// `post_json`'s keep-alive framing, so the fake forwarder never blocks
    /// reading past what the watcher sent. Returns the request's path and
    /// body.
    async fn read_request(sock: &mut UnixStream) -> (String, Vec<u8>) {
        let mut buf = Vec::with_capacity(256);
        let mut scratch = [0u8; 512];
        let head_end = loop {
            if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4) {
                break i;
            }
            let n = sock
                .read(&mut scratch)
                .await
                .expect("the fake forwarder must receive the request head");
            assert!(n > 0, "the watcher closed before sending its head");
            buf.extend_from_slice(&scratch[..n]);
        };
        let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
        let path = head
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .unwrap_or_default()
            .to_string();
        let len: usize = head
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().ok())?
            })
            .unwrap_or(0);
        while buf.len() < head_end + len {
            let n = sock
                .read(&mut scratch)
                .await
                .expect("the fake forwarder must receive the request body");
            assert!(n > 0, "the watcher closed mid-body");
            buf.extend_from_slice(&scratch[..n]);
        }
        (path, buf[head_end..head_end + len].to_vec())
    }

    /// A gvproxy-shaped control channel at `path`: every request is read in
    /// full, answered with the status `decide` picks for it, and recorded as
    /// its verb, `local` and `remote`. The channel the real switch's
    /// forwarder verbs ride, with its binds recorded instead of performed —
    /// what the proofs here read is the request the watcher made, because
    /// the switch's behaviour is `policy`'s own to prove. The server ends
    /// when the test drops its receiver.
    fn spawn_forwarder_deciding(
        path: PathBuf,
        decide: impl Fn(&Served) -> u16 + Send + Sync + 'static,
    ) -> (tokio::task::JoinHandle<()>, mpsc::Receiver<Served>) {
        let listener = UnixListener::bind(&path).expect("the control socket binds");
        let (tx, rx) = mpsc::channel(64);
        let decide = std::sync::Arc::new(decide);
        let handle = tokio::spawn(async move {
            // Sequential on purpose: the watcher publishes and withdraws one
            // port at a time, awaited, so one connection served at a time is
            // its shape.
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                let (path, body) = read_request(&mut sock).await;
                let served = Served {
                    path,
                    local: field_of(&body, "local"),
                    remote: field_of(&body, "remote"),
                    protocol: field_of(&body, "protocol"),
                };
                let status = decide(&served);
                let reason = if status == 200 {
                    "OK"
                } else {
                    "Internal Server Error"
                };
                sock.write_all(
                    format!("HTTP/1.1 {status} {reason}\r\nContent-Length: 0\r\n\r\n").as_bytes(),
                )
                .await
                .expect("the fake forwarder must answer");
                if tx.send(served).await.is_err() {
                    return;
                }
            }
        });
        (handle, rx)
    }

    /// [`spawn_forwarder_deciding`] for a forwarder that accepts everything
    /// — the shape every proof needs but the ones whose refusals are the
    /// point.
    fn spawn_forwarder(path: PathBuf) -> (tokio::task::JoinHandle<()>, mpsc::Receiver<Served>) {
        spawn_forwarder_deciding(path, |_| 200)
    }

    /// A bound, listening TCP socket in this process — the stand-in for the
    /// server a box's process runs: the watcher reads the kernel's socket
    /// table, and the test's own process is a leader whose table the port is
    /// genuinely in. Bound to the any address, the one bind a publication's
    /// dial can always reach at the box's lease, so the row is one the
    /// watcher publishes.
    fn listening_socket() -> TcpListener {
        TcpListener::bind((Ipv4Addr::UNSPECIFIED, 0))
            .expect("an ephemeral port binds on the any address")
    }

    /// The port a bound listener holds.
    fn port_of(listener: &TcpListener) -> u16 {
        listener
            .local_addr()
            .expect("a bound socket has an address")
            .port()
    }

    /// The box's lease on the test switch.
    const LEASE: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 9);
    /// The box's published address (NET-010).
    const PUBLISHED: Ipv4Addr = Ipv4Addr::new(127, 64, 0, 9);

    /// The box's ingress declaration: nothing statically mapped, a permit
    /// range covering exactly `port`, and the stance that lets listening
    /// publish (NET-016).
    fn permit_policy(port: u16) -> sessions::SessionPolicy {
        sessions::SessionPolicy {
            ingress: Some(sessions::IngressPolicy {
                port_mappings: Vec::new(),
                dynamic_allowed_range: Some((port, port)),
                dynamic_ingress: Some(sessions::DynamicIngress::Allow),
            }),
            egress: None,
            // No credentialed upstream (NET-134): these tests hold no lane,
            // so the compiled egress they observe is the rules' alone.
            credentialed_upstream: None,
        }
    }

    /// The box's watcher against the fake forwarder bound at `sock`, with
    /// its gate answering the given policy and the leader the test names.
    /// The box's publication set is the watcher's alone here — no expose
    /// surface shares it in these proofs — so an empty one stands in for
    /// the set the launch would share.
    fn watcher_with(
        sock: PathBuf,
        policy: &sessions::SessionPolicy,
        leader: Leader,
    ) -> (ListenWatcher, Arc<SessionGate>) {
        let gate = Arc::new(SessionGate::for_session(
            "listen-box".into(),
            LEASE,
            policy,
            SwitchSubnet::default(),
        ));
        let plan = ListenPlan::new(
            "listen-box".into(),
            LEASE,
            PUBLISHED,
            ControlChannel::Unix(sock),
            Arc::clone(&gate),
            BoxPublications::default(),
        );
        (ListenWatcher::start(plan, leader), gate)
    }

    /// The box's watcher, this process its leader: the watcher's own `/proc`
    /// entry is the table it reads, and the sockets the test binds are in
    /// it — the shape a box whose host resolved its leader starts with.
    fn watcher_at(
        sock: PathBuf,
        policy: &sessions::SessionPolicy,
    ) -> (ListenWatcher, Arc<SessionGate>) {
        watcher_with(sock, policy, Leader::Resolved(std::process::id()))
    }

    /// The box's watcher, started against a fake gvproxy control channel
    /// bound at a fresh socket, with its gate answering the given policy.
    /// Returns the watcher, the gate, and the fake's served-request
    /// receiver.
    fn started_watcher(
        dir: &tempfile::TempDir,
        policy: &sessions::SessionPolicy,
    ) -> (
        ListenWatcher,
        Arc<SessionGate>,
        tokio::task::JoinHandle<()>,
        mpsc::Receiver<Served>,
    ) {
        let sock = dir.path().join("gvproxy.sock");
        let (server, served) = spawn_forwarder(sock.clone());
        let (watcher, gate) = watcher_at(sock, policy);
        (watcher, gate, server, served)
    }

    /// [`started_watcher`], with the box's publication set seeded by `seed`
    /// before the watcher starts — the way a launch hands its host the set
    /// already holding what the expose surface published.
    fn started_watcher_with_publications(
        dir: &tempfile::TempDir,
        policy: &sessions::SessionPolicy,
        seed: impl FnOnce(&BoxPublications),
    ) -> (
        ListenWatcher,
        Arc<SessionGate>,
        tokio::task::JoinHandle<()>,
        mpsc::Receiver<Served>,
    ) {
        let sock = dir.path().join("gvproxy.sock");
        let (server, served) = spawn_forwarder(sock.clone());
        let publications = BoxPublications::default();
        seed(&publications);
        let gate = Arc::new(SessionGate::for_session(
            "listen-box".into(),
            LEASE,
            policy,
            SwitchSubnet::default(),
        ));
        let plan = ListenPlan::new(
            "listen-box".into(),
            LEASE,
            PUBLISHED,
            ControlChannel::Unix(sock),
            Arc::clone(&gate),
            publications,
        );
        let watcher = ListenWatcher::start(plan, Leader::Resolved(std::process::id()));
        (watcher, gate, server, served)
    }

    /// Awaits the fake forwarder's next record, or fails the proof: nothing
    /// the watcher does should take past this bound — one poll interval for
    /// the work, and the bound is a person's patience, not the poll's.
    async fn next_served(served: &mut mpsc::Receiver<Served>) -> Served {
        tokio::time::timeout(Duration::from_secs(10), served.recv())
            .await
            .expect("the watcher acts within the bound")
            .expect("the fake forwarder stays alive")
    }

    /// Awaits `what` until it holds, or fails the proof: the fake serves
    /// its record *before* the watcher takes the step the proof reads next
    /// (the gate's admission follows the bind, the withdrawal's unexpose
    /// follows the refusal), so a served record alone does not order them.
    async fn soon(mut what: impl FnMut() -> bool) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while !what() {
            assert!(
                tokio::time::Instant::now() < deadline,
                "the watcher did not reach the awaited state in the bound"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    /// Every record the fake forwarder holds that the test has not read:
    /// called after the watcher has stopped, so the set is complete.
    fn drained(served: &mut mpsc::Receiver<Served>) -> Vec<Served> {
        let mut records = Vec::new();
        while let Ok(served) = served.try_recv() {
            records.push(served);
        }
        records
    }

    /// NET-016: a process in the box listens on a permitted port and the
    /// port is published — a forward bound at the box's own address, at the
    /// port the process listens on (NET-010: the same number on both sides,
    /// no translation), delivering to the box's lease at that same number —
    /// and admitted at the box's ingress gate, with no ingress declaration
    /// involved anywhere.
    #[tokio::test]
    async fn listen_publishes_permitted_port() {
        let listener = listening_socket();
        let port = port_of(&listener);
        let dir = tempfile::tempdir().unwrap();
        let (watcher, gate, server, mut served) = started_watcher(&dir, &permit_policy(port));

        assert!(
            !gate.admits_tcp(port),
            "nothing is published before the listener is seen"
        );
        let published = next_served(&mut served).await;
        assert_eq!(published.path, "/services/forwarder/expose");
        assert_eq!(published.local, format!("{PUBLISHED}:{port}"));
        assert_eq!(
            published.remote,
            format!("{LEASE}:{port}"),
            "the port is published at its own number, delivered at its own number"
        );
        // The admission is the step after the bind the record names, so it
        // is awaited, not assumed: the gate admits a port only once
        // something answers for it.
        soon(|| gate.admits_tcp(port)).await;

        // The stop withdraws what it published: the port's publication ends
        // with the watcher, exactly as the story ends it with the box.
        watcher.stop().await;
        let withdrawn = next_served(&mut served).await;
        assert_eq!(withdrawn.path, "/services/forwarder/unexpose");
        assert_eq!(withdrawn.local, format!("{PUBLISHED}:{port}"));
        assert!(!gate.admits_tcp(port));
        server.abort();
    }

    /// NET-016, the declaration's transport: a mapping named for UDP answers
    /// UDP alone, so a TCP listener on a port the declaration names on UDP
    /// only is not published already — the verdict reads the transport
    /// before it answers `Declared`, and a box whose rules permit the port
    /// publishes the TCP listener, bound for the protocol the listener
    /// holds. The shape a transport-blind `Declared` answered wrong: the
    /// UDP mapping's forward never answers a TCP dial, so holding the
    /// listener back would leave the server unreachable at the box's
    /// address on TCP whatever the rules said.
    #[tokio::test]
    async fn listen_publishes_a_tcp_port_the_declaration_names_only_on_udp() {
        let listener = listening_socket();
        let port = port_of(&listener);
        let dir = tempfile::tempdir().unwrap();
        // The declaration maps the port for UDP alone, while the range and
        // the stance permit it: the TCP listener must fall to the rules and
        // be published by them, not answered "published already" under a
        // forward that would never answer its protocol.
        let policy = sessions::SessionPolicy {
            ingress: Some(sessions::IngressPolicy {
                port_mappings: vec![sessions::PortMapping {
                    external_port: port,
                    internal_port: port,
                    proto: sessions::IpProto::Udp,
                }],
                dynamic_allowed_range: Some((port, port)),
                dynamic_ingress: Some(sessions::DynamicIngress::Allow),
            }),
            egress: None,
            credentialed_upstream: None,
        };
        let (watcher, gate, server, mut served) = started_watcher(&dir, &policy);

        let published = next_served(&mut served).await;
        assert_eq!(published.path, "/services/forwarder/expose");
        assert_eq!(
            published.protocol, "tcp",
            "the publication is bound for the transport the listener holds"
        );
        assert_eq!(published.local, format!("{PUBLISHED}:{port}"));
        assert_eq!(published.remote, format!("{LEASE}:{port}"));
        soon(|| gate.admits_tcp(port)).await;

        // The stop withdraws it like any runtime-published port: the
        // declaration's UDP forward is not the watcher's and never comes
        // down this path (NET-081's sub-requirement).
        watcher.stop().await;
        let withdrawn = next_served(&mut served).await;
        assert_eq!(withdrawn.path, "/services/forwarder/unexpose");
        assert_eq!(withdrawn.protocol, "tcp");
        assert_eq!(withdrawn.local, format!("{PUBLISHED}:{port}"));
        server.abort();
    }

    /// NET-016's sub-requirement: a listener on a port the rules do not
    /// permit is never published — no forward, no admission — while a
    /// permitted listener beside it publishes, so the proof's silence is
    /// the watcher's own decision and not a loop that never ran.
    #[tokio::test]
    async fn listen_on_undeclared_port_not_published() {
        let permitted = listening_socket();
        let port = port_of(&permitted);
        let declined = listening_socket();
        let other = port_of(&declined);
        assert_ne!(port, other, "two bound sockets hold two ports");
        let dir = tempfile::tempdir().unwrap();
        let (watcher, gate, server, mut served) = started_watcher(&dir, &permit_policy(port));

        // The permitted listener publishes: this is the control that the
        // poll ran and read both sockets.
        let published = next_served(&mut served).await;
        assert_eq!(published.local, format!("{PUBLISHED}:{port}"));
        soon(|| gate.admits_tcp(port)).await;
        assert!(
            !gate.admits_tcp(other),
            "a port the rules do not permit is never admitted"
        );

        // The other listener, seen in the same poll, publishes nothing: no
        // request ever names it — across the stop's own withdrawal too, so
        // the silence is the watcher's decision and not a drained record.
        watcher.stop().await;
        let records = drained(&mut served);
        assert!(
            records
                .iter()
                .all(|served| served.local != format!("{PUBLISHED}:{other}")),
            "no request ever names the port the rules do not permit: {records:?}"
        );
        server.abort();
    }

    /// NET-017: the listener closes and the port's publication is withdrawn
    /// — the forward comes down, the gate stops admitting — and a fresh
    /// listener on the same port (the restart every server makes) is
    /// published again.
    #[tokio::test]
    async fn listener_close_withdraws_publication() {
        let listener = listening_socket();
        let port = port_of(&listener);
        let dir = tempfile::tempdir().unwrap();
        let (watcher, gate, server, mut served) = started_watcher(&dir, &permit_policy(port));

        let published = next_served(&mut served).await;
        assert_eq!(published.local, format!("{PUBLISHED}:{port}"));
        soon(|| gate.admits_tcp(port)).await;

        // The listener closes. The next poll sees the port gone and
        // withdraws the publication.
        drop(listener);
        let withdrawn = next_served(&mut served).await;
        assert_eq!(withdrawn.path, "/services/forwarder/unexpose");
        assert_eq!(withdrawn.local, format!("{PUBLISHED}:{port}"));
        assert!(
            !gate.admits_tcp(port),
            "the port's admission went with its listener"
        );

        // A fresh listener on the same port publishes it again: the
        // withdrawal held nothing back.
        let restarted = std::net::TcpListener::bind((Ipv4Addr::UNSPECIFIED, port))
            .expect("a closed listener leaves its port free to rebind");
        let republished = next_served(&mut served).await;
        assert_eq!(republished.path, "/services/forwarder/expose");
        assert_eq!(republished.local, format!("{PUBLISHED}:{port}"));
        soon(|| gate.admits_tcp(port)).await;

        drop(restarted);
        watcher.stop().await;
        let last = next_served(&mut served).await;
        assert_eq!(last.path, "/services/forwarder/unexpose");
        server.abort();
    }

    /// The leader is not a precondition of the watcher's start: a box whose
    /// program was not there to be found when its host built — a shell
    /// mid-spawn, or a `/proc` that could not answer for the moment — still
    /// publishes, because the watcher starts with the container PID the
    /// resolution is owed from and asks again on every poll. The refusal is
    /// said once for its streak, and the moment the program is there the
    /// box's port publishes: the same publication a build that resolved
    /// would have had, late by the moment between two polls and never
    /// missing.
    #[tokio::test]
    async fn a_watcher_whose_leader_was_not_yet_findable_publishes_when_it_is() {
        use std::io::Write as _;
        use std::os::unix::process::CommandExt as _;
        use std::process::Stdio;

        let listener = listening_socket();
        let port = port_of(&listener);
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("gvproxy.sock");
        let (server, mut served) = spawn_forwarder(sock.clone());
        // The box's container supervisor: `/bin/sh` stands in for the
        // supervisor hakoniwa hands its host — it holds no child while it
        // waits on `read`, a shell builtin, so nothing is forked — and forks
        // `sleep`, the program the box "runs", the moment its stdin is
        // given a line. The `& wait` is load-bearing: bash exec-optimizes a
        // `-c` script's last external command, which would replace the
        // supervisor with its program instead of forking one for the
        // resolution to find. The supervisor and the program it forks are
        // their own process group, so the proof takes them both down
        // together at its end and leaves neither behind.
        let mut supervisor = std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg("read line; sleep 60 & wait")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0)
            .spawn()
            .expect("spawning the box's container supervisor");
        let (lines, _guard) = captured_lines();
        let (watcher, gate) = watcher_with(
            sock,
            &permit_policy(port),
            Leader::Pending {
                container_pid: supervisor.id(),
            },
        );

        // A poll ran and its resolution was refused: the box's program is
        // not there to be found, and nothing was published.
        soon(|| !lines_saying(&lines.contents(), "resolving the box's leader").is_empty()).await;
        assert!(
            served.try_recv().is_err(),
            "nothing is published while the box's leader is still to be found"
        );
        assert!(!gate.admits_tcp(port));

        // The program appears — the sole child the resolution reads — and a
        // later poll finds it, so the box's port publishes.
        let mut stdin = supervisor
            .stdin
            .take()
            .expect("the supervisor reads the line that forks its program");
        writeln!(stdin, "go").expect("the supervisor takes the line it forks its program on");
        drop(stdin);
        let published = next_served(&mut served).await;
        assert_eq!(published.path, "/services/forwarder/expose");
        assert_eq!(published.local, format!("{PUBLISHED}:{port}"));
        assert_eq!(
            published.remote,
            format!("{LEASE}:{port}"),
            "the publication is the one the rules permit, at its own number"
        );
        soon(|| gate.admits_tcp(port)).await;

        // The refusal was said once for its whole streak — the polls that
        // retried it in between are the same failure — and the leader it
        // found is pinned: no resolution is asked for again.
        assert_eq!(
            lines_saying(&lines.contents(), "resolving the box's leader").len(),
            1,
            "the refused resolution is said once, not once per poll"
        );

        // The publication is the watcher's to withdraw like any other.
        watcher.stop().await;
        let withdrawn = next_served(&mut served).await;
        assert_eq!(withdrawn.path, "/services/forwarder/unexpose");
        assert_eq!(withdrawn.local, format!("{PUBLISHED}:{port}"));
        assert!(!gate.admits_tcp(port));
        // The supervisor and the program it forked go down together, as the
        // one process group the launch put them in, so neither outlives the
        // proof.
        // SAFETY: `kill` takes a signal number and a process-group id, both
        // plain integers, and reads no user memory; the id is the group
        // `process_group` gave this launch, and nothing else signals it.
        let _ = unsafe { libc::kill(-(supervisor.id() as libc::pid_t), libc::SIGKILL) };
        supervisor
            .wait()
            .expect("the box's supervisor reaps after its group is killed");
        server.abort();
    }

    /// A publication whose bind failed is not consumed by the failure: the
    /// next poll sees the port still unpublished — a transient refusal on
    /// the control channel must not leave a permitted port unpublished
    /// until its server restarts — and the retry that binds admits the
    /// port, so the failure cost only the moment between the two requests.
    #[tokio::test]
    async fn a_failed_publish_is_retried_on_the_next_poll() {
        let listener = listening_socket();
        let port = port_of(&listener);
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("gvproxy.sock");
        // The forwarder refuses the port's first expose — the shape of a
        // forwarder mid-restart, or a bind not free yet — and accepts every
        // request after it.
        let refused = AtomicBool::new(true);
        let (server, mut served) = spawn_forwarder_deciding(sock.clone(), move |served| {
            if served.path.ends_with("/expose") && refused.swap(false, Ordering::SeqCst) {
                500
            } else {
                200
            }
        });
        let (watcher, gate) = watcher_at(sock, &permit_policy(port));

        // The first poll's expose is refused: nothing is published and
        // nothing is admitted.
        let first = next_served(&mut served).await;
        assert_eq!(first.path, "/services/forwarder/expose");
        assert_eq!(first.local, format!("{PUBLISHED}:{port}"));
        assert!(!gate.admits_tcp(port));

        // A later poll asks for the same port again — the appearance the
        // failure could not settle — and the retry binds and admits.
        let retried = next_served(&mut served).await;
        assert_eq!(
            retried,
            Served {
                path: "/services/forwarder/expose".into(),
                local: format!("{PUBLISHED}:{port}"),
                remote: format!("{LEASE}:{port}"),
                protocol: "tcp".into(),
            },
            "the retry is the same publication the refusal turned away"
        );
        soon(|| gate.admits_tcp(port)).await;

        watcher.stop().await;
        let withdrawn = next_served(&mut served).await;
        assert_eq!(withdrawn.path, "/services/forwarder/unexpose");
        server.abort();
    }

    /// A withdrawal whose unexpose failed is not abandoned by the stop: the
    /// stop retries it before it returns, so no forward a box's processes
    /// published by listening outlives the box — a stale forward would hold
    /// the box's published address:port against a future session there.
    #[tokio::test]
    async fn a_failed_withdrawal_is_retried_before_the_stop_returns() {
        let listener = listening_socket();
        let port = port_of(&listener);
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("gvproxy.sock");
        // The forwarder refuses the port's first unexpose — the stop's first
        // pass — and accepts every request after it, the retry included.
        let refused = AtomicBool::new(true);
        let (server, mut served) = spawn_forwarder_deciding(sock.clone(), move |served| {
            if served.path.ends_with("/unexpose") && refused.swap(false, Ordering::SeqCst) {
                500
            } else {
                200
            }
        });
        let (watcher, gate) = watcher_at(sock, &permit_policy(port));

        let published = next_served(&mut served).await;
        assert_eq!(published.path, "/services/forwarder/expose");
        soon(|| gate.admits_tcp(port)).await;

        // The stop refuses to return with the forward still standing: the
        // refused withdrawal is retried inside it and comes down.
        watcher.stop().await;
        let records = drained(&mut served);
        let withdrawals: Vec<&Served> = records
            .iter()
            .filter(|served| served.path == "/services/forwarder/unexpose")
            .collect();
        assert_eq!(
            withdrawals.len(),
            2,
            "the refused withdrawal was retried before the stop returned: {records:?}"
        );
        assert!(
            withdrawals
                .iter()
                .all(|served| served.local == format!("{PUBLISHED}:{port}")),
            "both passes named the same publication: {records:?}"
        );
        assert!(!gate.admits_tcp(port), "the publication ended with the box");
        server.abort();
    }

    /// A listener bound to the box's loopback alone is never published,
    /// whatever the rules permit: a publication's forward dials the box's
    /// lease, which such a bind never answers, so publishing it would bind
    /// a forward to nothing — the box's address accepting a connection only
    /// to have it refused at the lease. The port the rules permit beside it
    /// publishes, which is the control that the poll ran and read both
    /// sockets and chose between them.
    #[tokio::test]
    async fn a_loopback_bound_listener_is_not_published() {
        let loopback = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .expect("an ephemeral port binds on the loopback alone");
        let loop_port = port_of(&loopback);
        let any = listening_socket();
        let any_port = port_of(&any);
        let dir = tempfile::tempdir().unwrap();
        // The rules permit both ports: only the binds differ.
        let policy = sessions::SessionPolicy {
            ingress: Some(sessions::IngressPolicy {
                port_mappings: Vec::new(),
                dynamic_allowed_range: Some((loop_port.min(any_port), loop_port.max(any_port))),
                dynamic_ingress: Some(sessions::DynamicIngress::Allow),
            }),
            egress: None,
            credentialed_upstream: None,
        };
        let (watcher, gate, server, mut served) = started_watcher(&dir, &policy);

        // The any-bound listener publishes: the poll ran, read both rows,
        // and it is the loopback bind alone that made the other unpublished.
        let published = next_served(&mut served).await;
        assert_eq!(published.local, format!("{PUBLISHED}:{any_port}"));
        soon(|| gate.admits_tcp(any_port)).await;
        assert!(
            !gate.admits_tcp(loop_port),
            "a bind the forward's dial cannot reach is never admitted"
        );

        // No request ever names the loopback port — across the stop's own
        // withdrawal too, so the silence is the watcher's decision and not a
        // record the test drained early.
        watcher.stop().await;
        let records = drained(&mut served);
        assert!(
            records
                .iter()
                .all(|served| served.local != format!("{PUBLISHED}:{loop_port}")),
            "no request ever names the loopback-bound port: {records:?}"
        );
        server.abort();
    }

    /// A listener that returns while its withdrawal had failed finds the
    /// forward it never lost: the publication never came down, so it is
    /// re-admitted rather than re-bound — the switch still holds the first
    /// forward, and a second expose against that bind would fail every poll
    /// the port's rules permit. The withdrawal it still owes is asked for
    /// again while the box runs, and the stop that ends the watcher tries
    /// the forward down too, bounded, never hanging on a channel that
    /// refuses every unexpose — so how many unexposes were made is not a
    /// number this proof can fix, only that they never stopped.
    #[tokio::test]
    async fn a_listener_back_before_its_failed_withdrawal_keeps_the_publication() {
        let listener = listening_socket();
        let port = port_of(&listener);
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("gvproxy.sock");
        // The forwarder accepts every expose and refuses every unexpose: a
        // switch whose unbind verb is failing outright.
        let (server, mut served) = spawn_forwarder_deciding(sock.clone(), |served| {
            if served.path.ends_with("/unexpose") {
                500
            } else {
                200
            }
        });
        let (watcher, gate) = watcher_at(sock, &permit_policy(port));

        // Every request the watcher made: the awaited ones kept beside the
        // ones the stop's teardown leaves unread, so the counts below read
        // the whole exchange and not a tail of it.
        let mut requests = Vec::new();
        let published = next_served(&mut served).await;
        assert_eq!(published.path, "/services/forwarder/expose");
        requests.push(published);
        soon(|| gate.admits_tcp(port)).await;

        // The listener closes and the withdrawal is refused: the record is
        // awaited, not assumed, so the rebind below cannot race the poll
        // that has to see the closure first.
        drop(listener);
        let refused = next_served(&mut served).await;
        assert_eq!(refused.path, "/services/forwarder/unexpose");
        requests.push(refused);
        soon(|| !gate.admits_tcp(port)).await;

        // The listener returns on the same port. The forward never came
        // down, so the publication it still holds serves the port again —
        // re-admitted, with no second bind asked of the switch.
        let restarted = std::net::TcpListener::bind((Ipv4Addr::UNSPECIFIED, port))
            .expect("a closed listener leaves its port free to rebind");
        soon(|| gate.admits_tcp(port)).await;

        // The stop tries the never-withdrawn forward down across its
        // bounded passes and returns without hanging on the channel that
        // refuses them all.
        watcher.stop().await;
        requests.extend(drained(&mut served));
        let exposes = requests
            .iter()
            .filter(|served| served.path == "/services/forwarder/expose")
            .count();
        assert_eq!(
            exposes, 1,
            "the returning listener was served by the forward still standing, never re-bound: {requests:?}"
        );
        let withdrawals = requests
            .iter()
            .filter(|served| served.path == "/services/forwarder/unexpose")
            .count();
        assert!(
            withdrawals > WITHDRAW_PASSES,
            "the refused withdrawal is asked for again — once mid-life, then on every one \
             of the stop's {} passes: {} requests, {requests:?}",
            WITHDRAW_PASSES,
            withdrawals
        );
        assert!(!gate.admits_tcp(port), "the publication ended with the box");
        drop(restarted);
        server.abort();
    }

    /// A withdrawal whose unexpose failed is retried while the box still
    /// runs, not only at its stop: the forward left standing delivers to a
    /// lease:port nothing answers, so every poll asks for it again until it
    /// comes down — here the second unexpose, one poll later, with no stop
    /// anywhere near it, and the stop that follows has nothing left to ask
    /// of the switch.
    #[tokio::test]
    async fn a_failed_withdrawal_is_retried_while_the_box_runs() {
        let listener = listening_socket();
        let port = port_of(&listener);
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("gvproxy.sock");
        // The forwarder refuses the port's first unexpose — the shape of a
        // forwarder mid-restart — and accepts every request after it.
        let refused = AtomicBool::new(true);
        let (server, mut served) = spawn_forwarder_deciding(sock.clone(), move |served| {
            if served.path.ends_with("/unexpose") && refused.swap(false, Ordering::SeqCst) {
                500
            } else {
                200
            }
        });
        let (watcher, gate) = watcher_at(sock, &permit_policy(port));

        let published = next_served(&mut served).await;
        assert_eq!(published.path, "/services/forwarder/expose");
        soon(|| gate.admits_tcp(port)).await;

        // The listener closes and the unexpose is refused.
        drop(listener);
        let first = next_served(&mut served).await;
        assert_eq!(first.path, "/services/forwarder/unexpose");
        assert_eq!(first.local, format!("{PUBLISHED}:{port}"));
        soon(|| !gate.admits_tcp(port)).await;

        // The box is still running — no stop has been asked for — and the
        // poll asks again for the withdrawal it owes, one poll later, for
        // the same `local`.
        let retried = next_served(&mut served).await;
        assert_eq!(
            retried,
            Served {
                path: "/services/forwarder/unexpose".into(),
                local: format!("{PUBLISHED}:{port}"),
                remote: String::new(),
                protocol: "tcp".into(),
            },
            "the failed withdrawal is retried while the box runs"
        );

        // So the stop has nothing left to withdraw: not one request.
        watcher.stop().await;
        let records = drained(&mut served);
        assert!(
            records.is_empty(),
            "the withdrawal was already made while the box ran: {records:?}"
        );
        assert!(
            !gate.admits_tcp(port),
            "the publication ended with its listener"
        );
        server.abort();
    }

    /// A permitted port whose publish the switch refuses every time is
    /// retried on a per-port backoff, not on every poll: the attempts space
    /// out, doubling off the poll interval, so a forwarder that is down for
    /// as long as it takes is waited for rather than hammered — and the
    /// backoff never gives up on the port, which publishes the moment the
    /// forwarder starts accepting.
    #[tokio::test]
    async fn a_persistently_refused_publish_backs_off() {
        let listener = listening_socket();
        let port = port_of(&listener);
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("gvproxy.sock");
        // The forwarder refuses the port's exposes while the test says so,
        // and accepts them once the test clears the flag.
        let refusing = Arc::new(AtomicBool::new(true));
        let flag = Arc::clone(&refusing);
        let (server, mut served) = spawn_forwarder_deciding(sock.clone(), move |served| {
            if served.path.ends_with("/expose") && flag.load(Ordering::SeqCst) {
                500
            } else {
                200
            }
        });
        let (watcher, gate) = watcher_at(sock, &permit_policy(port));

        // Three seconds of the switch refusing every publish: far fewer
        // attempts than one per poll once the first few failures have the
        // backoff doubling.
        let started = std::time::Instant::now();
        let mut attempts = 0;
        while started.elapsed() < Duration::from_secs(3) {
            match served.try_recv() {
                Ok(attempt) => {
                    assert_eq!(
                        attempt.path, "/services/forwarder/expose",
                        "only the port's publish is asked for: {attempt:?}"
                    );
                    assert_eq!(attempt.local, format!("{PUBLISHED}:{port}"));
                    attempts += 1;
                }
                Err(mpsc::error::TryRecvError::Empty) => {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    panic!("the fake forwarder ended before the backoff was read")
                }
            }
        }
        assert!(
            attempts <= 6,
            "a forwarder that refuses every publish is waited for, not asked \
             on every poll: {attempts} attempts in three seconds"
        );
        assert!(
            !gate.admits_tcp(port),
            "nothing is published while the switch refuses the bind"
        );

        // The moment the forwarder accepts, the next attempt lands: the
        // port a box's process is listening on is published, late, never
        // missing.
        refusing.store(false, Ordering::SeqCst);
        let published = next_served(&mut served).await;
        assert_eq!(published.path, "/services/forwarder/expose");
        assert_eq!(published.local, format!("{PUBLISHED}:{port}"));
        soon(|| gate.admits_tcp(port)).await;

        watcher.stop().await;
        let withdrawn = next_served(&mut served).await;
        assert_eq!(withdrawn.path, "/services/forwarder/unexpose");
        assert_eq!(withdrawn.local, format!("{PUBLISHED}:{port}"));
        assert!(!gate.admits_tcp(port));
        server.abort();
    }

    /// A backoff streak belongs to one listener: a port whose listener closed
    /// while its publish was waiting out a refusal starts a fresh streak when
    /// the box's next server binds the same port number — not the wait and the
    /// count the closed listener earned. The book keeps a backed-off port out
    /// of the listening table, so the poll's diff never reads one as
    /// disappeared, and the entry would otherwise outlive its listener: the
    /// next server would inherit a wait it did not earn and a count whose
    /// first failure was never said. The fresh server's first failure is its
    /// own streak's first — said, at the poll's own cadence — and the streak
    /// still ends the way every one does: the port publishes the moment the
    /// forwarder accepts.
    #[tokio::test]
    async fn a_backed_off_port_that_closes_starts_a_fresh_streak() {
        let listener = listening_socket();
        let port = port_of(&listener);
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("gvproxy.sock");
        // The forwarder refuses every expose while the test says so, so both
        // servers' publishes fail under it until the test clears the flag.
        let refusing = Arc::new(AtomicBool::new(true));
        let flag = Arc::clone(&refusing);
        let (server, mut served) = spawn_forwarder_deciding(sock.clone(), move |served| {
            if served.path.ends_with("/expose") && flag.load(Ordering::SeqCst) {
                500
            } else {
                200
            }
        });
        let (lines, _guard) = captured_lines();
        let (watcher, gate) = watcher_at(sock, &permit_policy(port));

        // The first server's publish is refused and said — one streak's first
        // failure, at the poll's own cadence: the fresh wait is one poll
        // (`retry_in` below).
        let first_attempt = next_served(&mut served).await;
        assert_eq!(first_attempt.path, "/services/forwarder/expose");
        assert_eq!(first_attempt.local, format!("{PUBLISHED}:{port}"));
        soon(|| {
            !lines_saying(
                &lines.contents(),
                "publishing a listening port on the switch failed",
            )
            .is_empty()
        })
        .await;

        // The first server closes, and a poll reads its port gone — two
        // poll intervals leave no doubt the fresh table was read — so the
        // streak it never finished goes with it.
        drop(listener);
        tokio::time::sleep(Duration::from_millis(700)).await;
        assert_eq!(
            lines_saying(
                &lines.contents(),
                "publishing a listening port on the switch failed"
            )
            .len(),
            1,
            "the closed listener's streak said its one failure and no more"
        );

        // The box's next server binds the same port number: a listener of its
        // own, whose first failure must be said too — the count the old
        // streak earned would swallow it — and at the poll's cadence, not
        // made to wait the old streak's backoff out.
        let second = TcpListener::bind((Ipv4Addr::UNSPECIFIED, port))
            .expect("the box's next server binds the port its old one held");
        let second_attempt = next_served(&mut served).await;
        assert_eq!(
            second_attempt,
            Served {
                path: "/services/forwarder/expose".into(),
                local: format!("{PUBLISHED}:{port}"),
                remote: format!("{LEASE}:{port}"),
                protocol: "tcp".into(),
            },
            "the new server's publish is asked for like any fresh appearance"
        );
        soon(|| {
            lines_saying(
                &lines.contents(),
                "publishing a listening port on the switch failed",
            )
            .len()
                == 2
        })
        .await;
        let log = lines.contents();
        let failed = lines_saying(&log, "publishing a listening port on the switch failed");
        assert_eq!(failed.len(), 2, "two streaks, one line each: {failed:?}");
        for line in failed {
            assert!(
                line.contains("retry_in=250ms"),
                "each streak's first failure waits one poll, not the count \
                 an earlier listener earned: {line}"
            );
        }
        assert!(
            !gate.admits_tcp(port),
            "nothing is published while the switch refuses the binds"
        );

        // The fresh streak still ends the way every one does: the moment the
        // forwarder accepts, the port the new server holds publishes.
        refusing.store(false, Ordering::SeqCst);
        let published = next_served(&mut served).await;
        assert_eq!(published.path, "/services/forwarder/expose");
        assert_eq!(published.local, format!("{PUBLISHED}:{port}"));
        soon(|| gate.admits_tcp(port)).await;

        drop(second);
        watcher.stop().await;
        let withdrawn = next_served(&mut served).await;
        assert_eq!(withdrawn.path, "/services/forwarder/unexpose");
        assert_eq!(withdrawn.local, format!("{PUBLISHED}:{port}"));
        assert!(!gate.admits_tcp(port));
        server.abort();
    }

    /// Everything the watcher wrote on the thread it runs on, so a proof can
    /// read the lines it left. The watcher's task shares a current-thread
    /// runtime with the test, so `set_default` reaches it.
    #[derive(Clone, Default)]
    struct CaptureWriter(Arc<std::sync::Mutex<Vec<u8>>>);

    impl CaptureWriter {
        fn contents(&self) -> String {
            let kept = self
                .0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            String::from_utf8(kept.clone()).unwrap()
        }
    }

    impl std::io::Write for CaptureWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            // A poisoned buffer is a bug in this proof's own code, and the
            // lines it holds are what the proof reads: recover the buffer
            // rather than drop the write on the floor.
            let mut kept = self
                .0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            kept.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl tracing_subscriber::fmt::MakeWriter<'_> for CaptureWriter {
        type Writer = CaptureWriter;
        fn make_writer(&self) -> Self::Writer {
            self.clone()
        }
    }

    /// Starts reading the watcher's own lines: the guard holds this thread's
    /// default subscriber for as long as the proof does.
    fn captured_lines() -> (CaptureWriter, tracing::subscriber::DefaultGuard) {
        let buf = CaptureWriter::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(buf.clone())
            .with_ansi(false)
            .finish();
        let guard = tracing::subscriber::set_default(subscriber);
        (buf, guard)
    }

    /// The whole log lines carrying `what`, so a proof reads one event's
    /// fields off the line that event landed on.
    fn lines_saying<'a>(log: &'a str, what: &str) -> Vec<&'a str> {
        log.lines().filter(|line| line.contains(what)).collect()
    }

    /// The publication's two endings carry the same facts its start does:
    /// the withdrawal that ends it, and the failure of the unexpose that
    /// cannot end it yet, each name the port, the box and the verdict — so
    /// the daemon log's tail reads a publication's whole life whichever way
    /// it ends. And the failure is said once per streak, not once per
    /// attempt: the poll's retry is the same failure.
    #[tokio::test]
    async fn the_withdrawal_lines_carry_the_box_port_and_verdict() {
        let listener = listening_socket();
        let port = port_of(&listener);
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("gvproxy.sock");
        // The forwarder refuses the port's first unexpose and accepts every
        // request after it, so the publication ends through one failed
        // withdrawal and the retry that lands.
        let refused = AtomicBool::new(true);
        let (server, mut served) = spawn_forwarder_deciding(sock.clone(), move |served| {
            if served.path.ends_with("/unexpose") && refused.swap(false, Ordering::SeqCst) {
                500
            } else {
                200
            }
        });
        let (lines, _guard) = captured_lines();
        let (watcher, gate) = watcher_at(sock, &permit_policy(port));

        let published = next_served(&mut served).await;
        assert_eq!(published.path, "/services/forwarder/expose");
        soon(|| gate.admits_tcp(port)).await;

        drop(listener);
        let first = next_served(&mut served).await;
        assert_eq!(first.path, "/services/forwarder/unexpose");
        let retried = next_served(&mut served).await;
        assert_eq!(retried.path, "/services/forwarder/unexpose");
        soon(|| !gate.admits_tcp(port)).await;
        watcher.stop().await;
        let log = lines.contents();

        let withdrew = lines_saying(&log, "withdrew a listening port from the box's address");
        assert_eq!(withdrew.len(), 1, "one withdrawal line, got: {log}");
        assert!(
            withdrew[0].contains("session=listen-box"),
            "{}",
            withdrew[0]
        );
        assert!(
            withdrew[0].contains(&format!("port={port}")),
            "{}",
            withdrew[0]
        );
        assert!(
            withdrew[0].contains("verdict=\"permitted\""),
            "the withdrawal names its verdict as the publication does: {}",
            withdrew[0]
        );

        let failed = lines_saying(&log, "unpublishing a listening port on the switch failed");
        assert_eq!(
            failed.len(),
            1,
            "the failed unexpose is said once, not once per attempt, got: {log}"
        );
        assert!(failed[0].contains("session=listen-box"), "{}", failed[0]);
        assert!(failed[0].contains(&format!("port={port}")), "{}", failed[0]);
        assert!(
            failed[0].contains("verdict=\"permitted\""),
            "the failure names its verdict as the publication does: {}",
            failed[0]
        );
        server.abort();
    }

    /// The stop's "could not withdraw" warning names what it could not bring
    /// down, and nothing else: a stop whose last pass succeeds — two refused
    /// unexposes, then the third that comes down — warns of nothing, because
    /// there is no forward left standing to name.
    #[tokio::test]
    async fn a_withdrawal_that_succeeds_on_the_last_pass_warns_of_nothing() {
        let listener = listening_socket();
        let port = port_of(&listener);
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("gvproxy.sock");
        // The forwarder refuses the stop's first two unexposes — its first
        // two passes — and accepts the third, the last.
        let refused = AtomicU32::new(2);
        let (server, mut served) = spawn_forwarder_deciding(sock.clone(), move |served| {
            if served.path.ends_with("/unexpose")
                && refused.load(Ordering::SeqCst) > 0
                && refused.fetch_sub(1, Ordering::SeqCst) > 0
            {
                500
            } else {
                200
            }
        });
        let (lines, _guard) = captured_lines();
        let (watcher, gate) = watcher_at(sock, &permit_policy(port));

        let published = next_served(&mut served).await;
        assert_eq!(published.path, "/services/forwarder/expose");
        soon(|| gate.admits_tcp(port)).await;

        // The listener still holds the port when the box stops, so the
        // stop's own passes are the whole withdrawal: two refused, the
        // third down.
        watcher.stop().await;
        let records = drained(&mut served);
        let withdrawals = records
            .iter()
            .filter(|served| served.path == "/services/forwarder/unexpose")
            .count();
        assert_eq!(
            withdrawals, 3,
            "two refused passes and the one that came down: {records:?}"
        );
        assert!(!gate.admits_tcp(port), "the publication ended with the box");
        let log = lines.contents();
        assert!(
            lines_saying(&log, "could not withdraw").is_empty(),
            "a stop whose last pass withdrew everything warns of nothing: {log}"
        );
        assert_eq!(
            lines_saying(&log, "unpublishing a listening port on the switch failed").len(),
            1,
            "the refusal is said once across the passes, got: {log}"
        );
        server.abort();
    }

    /// The watcher a host never stopped — dropped or abandoned before its
    /// mainloop reached the stop — ends itself: no poll outlives the
    /// watcher, and everything it published comes down the way a stop takes
    /// it down, so no runtime-published forward outlives the watcher
    /// whichever way its host ended.
    #[tokio::test]
    async fn dropping_a_watcher_stops_its_poll() {
        let listener = listening_socket();
        let port = port_of(&listener);
        let dir = tempfile::tempdir().unwrap();
        let (watcher, gate, server, mut served) = started_watcher(&dir, &permit_policy(port));

        let published = next_served(&mut served).await;
        assert_eq!(published.path, "/services/forwarder/expose");
        assert_eq!(published.local, format!("{PUBLISHED}:{port}"));
        soon(|| gate.admits_tcp(port)).await;

        // Dropped, not stopped: the ending a host build abandoned mid-flight
        // gives its watcher.
        drop(watcher);

        // The drop ends the poll, and the loop runs the stop's own last act:
        // the gate refuses the port first, the forward comes down after.
        soon(|| !gate.admits_tcp(port)).await;
        let withdrawn = next_served(&mut served).await;
        assert_eq!(withdrawn.path, "/services/forwarder/unexpose");
        assert_eq!(withdrawn.local, format!("{PUBLISHED}:{port}"));

        // And the loop is gone, not merely quiet: the box's server restarts
        // on the same port — the appearance a still-polling watcher would
        // publish again — and several poll intervals later nothing has been
        // asked for it.
        drop(listener);
        tokio::time::sleep(Duration::from_millis(700)).await;
        let again = TcpListener::bind((Ipv4Addr::UNSPECIFIED, port))
            .expect("the box's server restarts on its own port");
        tokio::time::sleep(Duration::from_millis(700)).await;
        let records = drained(&mut served);
        assert!(
            records.is_empty(),
            "a dropped watcher never polls again: {records:?}"
        );
        drop(again);
        server.abort();
    }

    /// A port the runtime expose already published is treated as published
    /// by the watcher too: the appearance is settled — never bound, so the
    /// switch is never asked for a second forward onto the one address —
    /// and the settlement is said once, never retried under a backoff a
    /// publication that stands does not earn, and never withdrawn, because
    /// the publication is the expose surface's to take down: closing the
    /// listener the box held on the port changes nothing the switch holds.
    #[tokio::test]
    async fn a_port_the_runtime_expose_published_is_never_bound_or_withdrawn() {
        let listener = listening_socket();
        let port = port_of(&listener);
        let dir = tempfile::tempdir().unwrap();
        let (_watcher, _gate, server, mut served) = started_watcher_with_publications(
            &dir,
            &permit_policy(port),
            // The expose surface's own publication of the port, standing
            // before the watcher ever polls: the set both surfaces read,
            // holding the port the way a runtime `min net expose` does.
            |publications| {
                publications
                    .record(port, PublicationOwner::Expose)
                    .expect("nothing holds the port yet");
            },
        );
        let (lines, _guard) = captured_lines();

        // Several poll intervals with the listener standing: the watcher
        // reads its port, sees whose publication it is, and asks nothing —
        // one skip line, and no expose the fake forwarder would record.
        tokio::time::sleep(Duration::from_millis(900)).await;
        let log = lines.contents();
        let skipped = lines_saying(
            &log,
            "left a listening port the runtime expose already published",
        );
        assert_eq!(
            skipped.len(),
            1,
            "the skip is said once, never retried under backoff: {log}"
        );
        assert!(
            skipped[0].contains("owner=expose"),
            "the refusal line names whose publication holds the port: {}",
            skipped[0]
        );
        assert!(
            skipped[0].contains(&format!("port={port}")),
            "the refusal line names the port the other surface holds: {}",
            skipped[0]
        );

        // The box's listener on the port closes, and the publication is
        // the expose surface's — so nothing comes down: no unexpose is
        // asked, across several more poll intervals, and the skip stays
        // the one line the port ever wrote.
        drop(listener);
        tokio::time::sleep(Duration::from_millis(900)).await;
        let records = drained(&mut served);
        assert!(
            records.is_empty(),
            "the watcher neither published the port nor withdrew the expose \
             surface's publication: {records:?}"
        );
        let log = lines.contents();
        assert_eq!(
            lines_saying(
                &log,
                "left a listening port the runtime expose already published"
            )
            .len(),
            1,
            "the settlement is one line, not one per poll: {log}"
        );
        assert!(
            lines_saying(&log, "published a listening port on the box's address").is_empty(),
            "the port the expose surface holds is never bound by the watcher: {log}"
        );
        server.abort();
    }

    /// The two halves of the shared set's ownership rule: a publication is
    /// withdrawn by whoever published it and by nobody else — a `Listen`
    /// entry ignores an `Expose` withdrawal and an `Expose` entry ignores a
    /// `Listen` one — and a record refuses the other owner's port, so the
    /// bind races both surfaces close are answered the same way the
    /// duplicate checks are.
    #[test]
    fn publications_withdraw_with_their_owner_only() {
        let publications = BoxPublications::default();
        assert!(
            publications.held_by(8080).is_none(),
            "a fresh box's set holds nothing"
        );
        for (holder, other) in [
            (PublicationOwner::Listen, PublicationOwner::Expose),
            (PublicationOwner::Expose, PublicationOwner::Listen),
        ] {
            publications
                .record(8080, holder)
                .expect("the first surface to publish wins the port");
            assert_eq!(
                publications.record(8080, other),
                Err(holder),
                "the other surface's record names the owner that holds the port"
            );
            assert_eq!(publications.held_by(8080), Some(holder));
            // The other surface's withdrawal is refused by the rule, not
            // by an error: the entry stands, because the publisher is the
            // one who withdraws.
            publications.withdraw(8080, other);
            assert_eq!(
                publications.held_by(8080),
                Some(holder),
                "the other surface's withdrawal leaves the publication standing"
            );
            // And the owner's own withdrawal is the one that clears it, so
            // the next publisher finds the port free.
            publications.withdraw(8080, holder);
            assert!(
                publications.held_by(8080).is_none(),
                "the publisher's withdrawal gives the port back"
            );
        }
    }

    /// The kernel socket table's rows read as the watcher reads them: a
    /// listener's port, and only a listener's — an established socket is a
    /// connection, not a publication — from either table, and only where
    /// the bind can answer a forward dialing the box's lease: the any
    /// address and the lease itself, in either table's spelling.
    #[test]
    fn socket_rows_read_their_listening_port() {
        // The v4 table: header, a listener on the any address
        // (`00000000:1F90`), one on the box's lease (`09004064`, the
        // little-endian word for 100.64.0.9), a loopback-bound listener
        // (`0100007F:1F92`) no dial at the lease can reach, an established
        // socket, and a row too short to read.
        let v4 = "  sl  local_address  rem_address   st\n\
                  0: 00000000:1F90 00000000:0000 0A 00000000:00000000\n\
                  1: 09004064:1F91 00000000:0000 0A 00000000:00000000\n\
                  2: 0100007F:1F92 00000000:0000 0A 00000000:00000000\n\
                  3: 0100007F:1F90 0100007F:9C4A 01 00000000:00000000\n\
                  4: 0100007F";
        let ports: HashSet<u16> = v4
            .lines()
            .skip(1)
            .filter_map(|line| listen_port(line, false, LEASE))
            .collect();
        assert_eq!(ports, HashSet::from([8080, 8081]));

        // The v6 table: the dual-stack any (`::`), a v4-mapped bind on the
        // lease, a v4-mapped loopback bind, and a pure v6 address — the
        // last two answer no IPv4 dial at the lease.
        let v6 = "  sl  local_address  rem_address   st\n\
                  0: 00000000000000000000000000000000:1F90 00000000000000000000000000000000:0000 0A\n\
                  1: 0000000000000000FFFF000009004064:2328 00000000000000000000000000000000:0000 0A\n\
                  2: 0000000000000000FFFF00000100007F:2329 00000000000000000000000000000000:0000 0A\n\
                  3: 00000000000000000000000100000000:2329 00000000000000000000000000000000:0000 0A\n";
        let ports: HashSet<u16> = v6
            .lines()
            .skip(1)
            .filter_map(|line| listen_port(line, true, LEASE))
            .collect();
        assert_eq!(ports, HashSet::from([8080, 9000]));
        assert!(
            binds_for_the_lease("00000000000000000000000000000000", true, LEASE),
            "the dual-stack any"
        );
        assert!(
            binds_for_the_lease("0000000000000000FFFF000009004064", true, LEASE),
            "a mapped bind on the lease"
        );
        assert!(
            !binds_for_the_lease("0000000000000000FFFF00000100007F", true, LEASE),
            "a mapped loopback bind"
        );
        assert!(
            !binds_for_the_lease("00000000000000000000000100000000", true, LEASE),
            "a pure v6 address"
        );
        assert!(binds_for_the_lease("00000000", false, LEASE), "the v4 any");
        assert!(binds_for_the_lease("09004064", false, LEASE), "the lease");
        assert!(
            !binds_for_the_lease("0100007F", false, LEASE),
            "the box's loopback"
        );
    }

    /// The leader's process entry names its own listening sockets, and stops
    /// naming them when they close: the table the watcher's whole story
    /// reads, proved against the real kernel rather than a fixture — with
    /// the bind shape the watcher distinguishes: a loopback-bound listener
    /// is in the kernel's table but is never one of the box's publications.
    #[test]
    fn the_leader_entry_names_its_own_listeners() {
        let reachable = listening_socket();
        let reachable_port = port_of(&reachable);
        let loopback = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .expect("an ephemeral port binds on the loopback alone");
        let loop_port = port_of(&loopback);
        let ports =
            listening_ports(std::process::id(), LEASE).expect("this process's entry is readable");
        assert!(
            ports.contains(&reachable_port),
            "a listener bound to the any address is in the leader's table"
        );
        assert!(
            !ports.contains(&loop_port),
            "a loopback-bound listener is no publication: a forward dials the lease"
        );
        drop(reachable);
        let ports =
            listening_ports(std::process::id(), LEASE).expect("this process's entry is readable");
        assert!(
            !ports.contains(&reachable_port),
            "a closed listener leaves the leader's table"
        );
    }

    /// The listen-publication surface against the real gvproxy, not the
    /// stand-in: the watcher's expose verbs land on a real forwarder, which
    /// binds the box's published address at the port the process listens on
    /// — and, when the listener closes, comes down with the port, so a
    /// client after the close is refused at the box's own address, never
    /// accepted by a forward delivering to nothing (NET-016's publish half
    /// and NET-017's withdraw half, against the switch the daemon itself
    /// spawns). The proof's client is the client a published box serves:
    /// what it sees is the bind at the box's own address — the address it
    /// connects to — appearing when the listener appears and refusing when
    /// the listener closes. The bytes' other leg, through the switch to the
    /// attached box's tap, is the netns and VM lanes' own proof — a
    /// stand-in process has no tap on the switch's stack, so it is not
    /// proven here.
    ///
    /// The stand-in box is this process: its listener is bound at its lease
    /// — the host's own loopback, the address a dial into this namespace
    /// reaches — and the watcher reads this process's `/proc` entry as the
    /// box's leader, the way every proof in this module does. The bind at
    /// the lease alone is what makes the proof's connect read the forward
    /// rather than the listener: a wildcard bind answers at every local
    /// address, the published one included, and the connect would reach
    /// the listener without the forward at all. Gated on `GVPROXY_BIN`, the
    /// way the netns proofs are gated on their own host facts:
    /// `scripts/fetch-gvproxy.sh` fetches the pinned binary, so the proof is
    /// run as
    /// `GVPROXY_BIN=./gvproxy cargo nextest run -p minimald --run-ignored only a_published_listener_is_reachable_and_refused_on_the_real_switch`.
    #[ignore = "needs the real gvproxy binary; gated on GVPROXY_BIN (scripts/fetch-gvproxy.sh fetches the pinned one)"]
    #[tokio::test]
    async fn a_published_listener_is_reachable_and_refused_on_the_real_switch() {
        let Some(bin) = std::env::var_os("GVPROXY_BIN") else {
            eprintln!(
                "skipping real-switch listen proof: GVPROXY_BIN not set \
                 (scripts/fetch-gvproxy.sh fetches the pinned binary)"
            );
            return;
        };
        // The stand-in box's lease: this process's own loopback, so a dial
        // the real forwarder makes to the lease reaches the listener the
        // test binds — the reachability a real box's own address is its
        // published address for (NET-010).
        const STANDIN_LEASE: Ipv4Addr = Ipv4Addr::LOCALHOST;
        // The box's listener is bound at its lease, not the any address: in
        // the stand-in's own namespace a wildcard bind answers at every
        // local address, the published one included, so the proof's connect
        // would reach the listener without the forward at all. A lease bind
        // answers only the forward's dial — the shape a publication carries
        // — and `binds_for_the_lease` reads it as the box's own.
        let listener = TcpListener::bind((STANDIN_LEASE, 0))
            .expect("the stand-in box's listener binds at its lease");
        let port = port_of(&listener);
        listener
            .set_nonblocking(true)
            .expect("the listener can go nonblocking");
        let listener = tokio::net::TcpListener::from_std(listener)
            .expect("the listener joins the runtime that awaits it");
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("gvproxy.sock");

        // The real switch, brought up the way the daemon brings it up: the
        // rendered config, the control socket, the PID file, and no SSH
        // forward. `kill_on_drop` takes it with the handle, so a proof that
        // ends anywhere leaves no gvproxy behind.
        let config = dir.path().join("switch.yml");
        std::fs::write(
            &config,
            crate::net::render_gvproxy_config(SwitchSubnet::default(), &[]),
        )
        .expect("the switch config writes");
        let gvproxy = tokio::process::Command::new(&bin)
            .arg("-config")
            .arg(&config)
            .arg("-listen")
            .arg(format!("unix://{}", sock.display()))
            .arg("-pid-file")
            .arg(dir.path().join("gvproxy.pid"))
            .arg("-ssh-port")
            .arg("-1")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .expect("GVPROXY_BIN spawns the real gvproxy");
        // Waited for with a real connect, the way the daemon's own bring-up
        // waits: the socket's file appears before its listen does.
        soon(|| std::os::unix::net::UnixStream::connect(&sock).is_ok()).await;

        let gate = Arc::new(SessionGate::for_session(
            "listen-box".into(),
            STANDIN_LEASE,
            &permit_policy(port),
            SwitchSubnet::default(),
        ));
        let watcher = ListenWatcher::start(
            ListenPlan::new(
                "listen-box".into(),
                STANDIN_LEASE,
                PUBLISHED,
                ControlChannel::Unix(sock.clone()),
                Arc::clone(&gate),
                BoxPublications::default(),
            ),
            Leader::Resolved(std::process::id()),
        );

        // The watcher publishes the listener's port on the real switch: a
        // forward bound at the box's published address, at the process's own
        // port number, delivering to the box's lease — the no-translation
        // rule NET-010 holds of runtime publications too. Until the bind
        // lands, a connect at the published address is refused, so the probe
        // retries within the bound — and the bind it waits for is the
        // forward's own: the stand-in's listener answers at its lease alone,
        // so nothing but the published forward can answer at `PUBLISHED`.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        let mut last_probe = String::new();
        let published = loop {
            assert!(
                tokio::time::Instant::now() < deadline,
                "the listener's port never published at the box's own \
                 address (last probe: {last_probe})"
            );
            match tokio::net::TcpStream::connect((std::net::IpAddr::from(PUBLISHED), port)).await {
                Ok(client) => break client,
                Err(e) => last_probe = e.to_string(),
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        };
        drop(published);

        // The box's server closes — the one fact NET-017 turns on — and the
        // watcher withdraws the publication: the gate refuses the port
        // first, the forward comes down after.
        drop(listener);
        soon(|| !gate.admits_tcp(port)).await;

        // A fresh client is refused at the box's own address — a connection
        // refused, the port bound by nothing, not a published forward
        // accepting a connection to deliver to a listener that is gone. The
        // refusal is waited for within the bound, because the unbind follows
        // the gate's own withdrawal by a control round trip.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        let mut last_probe = String::new();
        loop {
            assert!(
                tokio::time::Instant::now() < deadline,
                "the port is still published after its listener closed \
                 (last probe: {last_probe})"
            );
            match tokio::net::TcpStream::connect((std::net::IpAddr::from(PUBLISHED), port)).await {
                Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => break,
                Ok(_) => last_probe = "still connected".into(),
                Err(e) => last_probe = e.to_string(),
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        watcher.stop().await;
        drop(gvproxy);
    }
}
