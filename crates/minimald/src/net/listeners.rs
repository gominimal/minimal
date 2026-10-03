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
//! Two properties the story's shape rides on, beside the diff itself. The
//! table is read as the forward reads the box: a listener counts only when
//! its bind can answer the dial a publication makes — to the box's lease —
//! so a process bound to the box's loopback alone is not published at all
//! ([`binds_for_the_lease`]); and nothing here is one-shot — a publication
//! whose bind failed is retried on a per-port backoff that doubles off the
//! poll interval, a withdrawal whose unexpose failed is retried on every
//! poll the box still runs and through the stop's passes, so a transient
//! refusal on the control channel never settles into a port that stays
//! missing or a forward that stays bound. Neither half says its failure
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
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;

use tokio::sync::watch;

use sessions::SessionId;
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
/// it — the gvproxy control channel the forwarder verbs ride, and the box's
/// session gate, which holds the shared permit decision
/// ([`SessionGate::listen_verdict`]) and the admission a published port is
/// given through.
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
}

impl ListenPlan {
    /// Assembles the plan from the facts its launch holds. The gate must be
    /// the one the box's relay registered — the gate the connections a
    /// publication forwards are admitted by on their way through the
    /// relay.
    #[must_use]
    pub fn new(
        box_name: String,
        lease: Ipv4Addr,
        published: Ipv4Addr,
        control: ControlChannel,
        gate: Arc<SessionGate>,
    ) -> Self {
        Self {
            box_name,
            lease,
            published,
            control,
            gate,
        }
    }
}

/// The plans launches have built and hosts have not taken: the handoff from
/// a session's launcher (which holds the lease, the switch and the gate the
/// attach registered) to the host about to run the box, keyed by the
/// session id both hold. A launch stages its plan as its last act, the host
/// takes it as its first — [`Host::build`](crate::session_host::Host::build)
/// — so the plan never rides a struct every launcher would have to name,
/// and a mock launch that stages nothing starts no watcher at all.
///
/// The take is destructive on purpose: a plan belongs to the one host that
/// runs its box, and a reattach's launch stages a fresh one. A build that
/// never takes its plan — a cancelled launch — leaves one entry behind for
/// as long as one poll interval, until the next launch for the same session
/// stages its own or clears the table's entry ([`clear_listen_plan`]); the
/// table is bounded by the sessions that exist.
static STAGED_PLANS: LazyLock<Mutex<HashMap<SessionId, ListenPlan>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Leaves the plan a launch built for the host about to run its box,
/// replacing any a cancelled build left behind.
pub(crate) fn stage_listen_plan(session_id: SessionId, plan: ListenPlan) {
    STAGED_PLANS
        .lock()
        .expect("staged listen-plan lock poisoned")
        .insert(session_id, plan);
}

/// Clears the table's entry for a launch that staged no plan — the box has
/// no lease, no published address or no live gate, so none of its ports can
/// be published by listening. The clear is the launch's own work, because
/// what it removes is a *previous* launch's plan for the same session id: a
/// cancelled launch staged one and never handed its box to a host, and the
/// host the next launch does build must not take that orphan and start a
/// watcher on a lease, an address and a gate the cancelled launch's attach
/// already tore down.
pub(crate) fn clear_listen_plan(session_id: SessionId) {
    STAGED_PLANS
        .lock()
        .expect("staged listen-plan lock poisoned")
        .remove(&session_id);
}

/// Takes the plan staged for `session_id` — once, so the host that runs the
/// box owns its box's publications and a second host cannot stop its
/// watcher.
pub(crate) fn take_listen_plan(session_id: SessionId) -> Option<ListenPlan> {
    STAGED_PLANS
        .lock()
        .expect("staged listen-plan lock poisoned")
        .remove(&session_id)
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
    /// the process tree `leader` leads — the box's leader, whose `/proc`
    /// entry names the whole box's network namespace — and keeps the
    /// box's publications in step with them. The first poll happens at
    /// once, so a listener that outlived a previous host is published
    /// before a person can look for it.
    #[must_use]
    pub fn start(plan: ListenPlan, leader: u32) -> Self {
        let (stop, mut stop_rx) = watch::channel(false);
        let task = tokio::spawn(async move {
            let mut state = WatchState::new(plan);
            loop {
                state.poll(leader).await;
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
    pub async fn stop(self) {
        #[expect(
            clippy::let_underscore_must_use,
            reason = "the loop may already have ended; the join below is what reports that"
        )]
        let _ = self.stop.send(true);
        if let Err(join) = self.task.await {
            tracing::warn!(
                error = %join,
                "the listen-publication watcher ended without withdrawing everything"
            );
        }
    }
}

/// The watcher's own state: what the box's processes were listening on at
/// the last read, and which of those the watcher published. `forwards` is
/// exactly the runtime-published set (NET-081's sub-requirement's own set):
/// a declared port is never in it, and a port the rules did not permit
/// never enters it.
struct WatchState {
    plan: ListenPlan,
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
    fn new(plan: ListenPlan) -> Self {
        Self {
            plan,
            listening: HashSet::new(),
            forwards: HashMap::new(),
            backoff: HashMap::new(),
            reported_withdrawal_failures: HashSet::new(),
        }
    }

    /// One poll: read the box's listening sockets, publish what appeared,
    /// withdraw what closed, and ask again for what a refusal has left
    /// owed. A publication that failed to bind keeps its port out of the
    /// book ([`Self::listening`]), so the next poll reads the port as
    /// appeared again — the appearance is not consumed by the failure, and
    /// a transient refusal on the control channel never turns into a
    /// permitted port that stays unpublished until its server restarts.
    async fn poll(&mut self, leader: u32) {
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
    /// what the appearance is worth before anything is bound. Returns
    /// whether the appearance is settled — `false` only for a permitted
    /// port whose forward failed to bind, the one appearance
    /// [`Self::poll`] hands back to the next poll as appeared again, on
    /// the backoff its refusals have earned.
    ///
    /// `refusals` counts the attempts this port's publish streak has
    /// already been refused, so the failure is said once per streak — the
    /// first refusal's line, never the retries' — and the publication that
    /// ends a streak names what it took.
    async fn open(&mut self, port: u16, refusals: u32) -> bool {
        match self.plan.gate.listen_verdict(port) {
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
                        self.plan.gate.admit_published(port);
                        self.forwards.insert(port, mapping);
                        tracing::info!(
                            session = %self.plan.box_name,
                            host = %self.plan.published,
                            port,
                            verdict = "permitted",
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
    /// box still runs.
    async fn close(&mut self, port: u16, reason: &'static str) {
        let Some(mapping) = self.forwards.remove(&port) else {
            // Never published by the watcher: a declared port, whose
            // forward is the declaration's (NET-121), or one the rules did
            // not permit, whose publication never existed.
            return;
        };
        let terminated = self.plan.gate.withdraw_published(port);
        match unexpose_mapping(&self.plan.control, &mapping).await {
            Ok(()) => {
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
                // left standing; keep it in the published set — the next
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
    /// `local`/`remote` pair its body carried.
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct Served {
        path: String,
        local: String,
        remote: String,
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
        }
    }

    /// The box's watcher against the fake forwarder bound at `sock`, with
    /// its gate answering the given policy. This process is the leader: its
    /// own `/proc` entry is the table the watcher reads, and the sockets the
    /// test binds are in it.
    fn watcher_at(
        sock: PathBuf,
        policy: &sessions::SessionPolicy,
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
        );
        (ListenWatcher::start(plan, std::process::id()), gate)
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

    /// A launch that stages no plan still clears the table's entry for its
    /// session, so the host a later launch builds never takes the plan a
    /// cancelled launch left behind — one naming a lease, an address and a
    /// gate that launch's attach already tore down.
    #[test]
    fn a_launch_that_stages_no_plan_clears_the_one_before_it() {
        let cleared = SessionId::parse_str("00000000-0000-0000-0000-00000000a5c1").unwrap();
        let kept = SessionId::parse_str("00000000-0000-0000-0000-00000000a5c2").unwrap();
        let gate = Arc::new(SessionGate::for_session(
            "listen-box".into(),
            LEASE,
            &permit_policy(8080),
            SwitchSubnet::default(),
        ));
        let plan = || {
            ListenPlan::new(
                "listen-box".into(),
                LEASE,
                PUBLISHED,
                ControlChannel::Unix(PathBuf::from("/nowhere")),
                Arc::clone(&gate),
            )
        };
        stage_listen_plan(cleared, plan());
        stage_listen_plan(kept, plan());

        // The new path: a launch that stages nothing removes what its
        // session still holds.
        clear_listen_plan(cleared);
        assert!(
            take_listen_plan(cleared).is_none(),
            "the cancelled launch's plan is gone, so no later host takes it"
        );
        assert!(
            take_listen_plan(kept).is_some(),
            "the plan nobody cleared is still there to take"
        );
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
}
