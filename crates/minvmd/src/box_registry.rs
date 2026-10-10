//! The host-side table of every published namespace (NET-138) — the rows the
//! VM host daemon's egress gate decides by (NET-081).
//!
//! On a VM-backed host the guest cannot be trusted to say what its boxes may
//! reach: the in-VM daemon is *inside* the escape boundary, and a process
//! that breaks out of a box into the VM controls it. The per-box,
//! source-addressed egress rules NET-081 asks for therefore live **outside**
//! the VM, in `minvmd`, applied by [`crate::net::egress_gate`] between the
//! guest's shuttle and the switch socket. This module is the table that gate
//! reads: one row per published namespace, holding its name, its addresses on
//! the switch and on the loopback, the ports it admitted, the names it
//! declared, and its compiled [`EgressRules`] — the rules the gate decides
//! every frame by, the same set the in-guest relay applies, now held where
//! nothing inside the VM can change it. The publish half of the gate
//! (NET-081's control verbs) reads the row's ports and names as the records
//! it will admit a switch publish for; the frame half reads the rules alone.
//!
//! The trust boundary is the type boundary. Rows are filled **in this
//! process**, from the host side — the host's own derivation of the guest
//! node's namespace ([`BoxRegistry::register_node_namespace`]), and the
//! client's box declarations carried over the host's control path — and never
//! from anything the guest says. The gate is handed a [`BoxTable`], the
//! read-only view whose only row operations are lookups, so the one component
//! that reads guest frames cannot add, replace, or withdraw a row. The
//! registration path that carries a client's box declarations into this
//! registry is [`crate::control`] — the host daemon's control socket, over
//! which the activating client registers a box and reads the addresses the
//! allocation hands back.
//!
//! This registry is also the proxy's attachment source (NET-133): when the
//! host hands it the attachment table
//! ([`BoxRegistry::feeding_proxy_attachments`]), every box row it publishes
//! is an attachment issued ahead of the row and every retirement takes the
//! attachment with it — the same host-side facts, the same trust boundary,
//! the one writer.
//!
//! One dimension of a row is filled from the in-VM daemon's own reports —
//! the **runtime-admitted ports** (NET-138's sanctioned exception, NET-045's
//! decisions), reported over the daemon's control channel and recorded only
//! inside the grant the row's host-side registration holds: the box's
//! dynamic-ingress stance, its allowed range, the per-row cap, and the
//! per-row admit rate ([`BoxRegistry::admit_runtime_port`]). Everything the
//! guest says still passes that check; a row's other facts stay host-sourced
//! alone.
//!
//! A row's liveness is read at the host's end of the box's attachment
//! (NET-138): a relay that carries a box's frames holds its row attached,
//! and the end of the last such relay marks the row **detached** rather than
//! withdrawing it at once. A detached row decides frames exactly as before;
//! it is withdrawn once [`DETACH_GRACE`] passes with no relay carrying it
//! again, so a box whose shuttle reconnects keeps its row. The client boxes'
//! registrations — the creator's declarations, never anything the guest said
//! — are persisted in this daemon's state dir ([`BoxRegistry::persisting_to`])
//! and reloaded detached at start, and a creator whose box outlived its row
//! asks for the row back from that persisted record
//! ([`BoxRegistry::resume_client_box`]).

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::net::Ipv4Addr;
#[cfg(test)]
use std::sync::atomic::AtomicU32;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, RwLock};
use std::time::{Duration, Instant};

use sessions::core::egress::EgressRules;
use sessions::core::zone_answer;
use sessions::{DynamicIngress, EgressPolicy, IpProto};
use switch::SwitchSubnet;

use crate::bep_attach::BoxId;
use crate::net::answerer::canonical_box_name;

/// The per-row cap on runtime-admitted ports (NET-138): the row's
/// runtime-published set answers to this bound, so a report storm cannot
/// grow a row without limit — the cap is the row-state half of the grant,
/// beside the stance and range the declaration carries. An admit report a
/// row at its cap receives is refused when it names a new port; a re-admit
/// of a port the row already holds is answered as recorded and changes
/// nothing, so a client that retries a lost reply never draws a refusal for
/// a port the host holds.
pub(crate) const RUNTIME_PORT_CAP: usize = 256;

/// The per-row admit rate (NET-138): at most this many admit reports are
/// recorded per trailing second. The rate bounds the *reports*, not the
/// ports (the cap bounds the ports): a box that churns its mappings faster
/// than this is a loop, and a loop must not hold the serving thread. Only
/// reports that pass every grant check and record a new port count toward
/// it — a refusal records nothing and paces nothing, a re-admit of a held
/// port changes nothing and is not counted, and a withdrawal never counts.
pub(crate) const ROW_ADMIT_RATE_PER_SECOND: usize = 10;

/// The window the admit rate is measured over, matching
/// [`ROW_ADMIT_RATE_PER_SECOND`] one trailing second.
const ADMIT_RATE_WINDOW: std::time::Duration = std::time::Duration::from_secs(1);

/// The allow-list spelling of the absent egress dimension: every address,
/// the compiled rules' `None` meaning as the row's derived allow-list
/// answers it.
const ALLOW_ALL_SUBNET: &str = "0.0.0.0/0";

/// How long a detached row — one whose last carrying relay ended, or one
/// reloaded from the persisted registry at start — stands before it is
/// withdrawn, unless a relay carries its box's frames again first.
///
/// NET-138 bounds a row's withdrawal at 60 seconds from the end of the
/// box's attachment. The grace runs from the drainer's arrival of the
/// relay's end report, and the drainer sweeps expired rows every
/// [`DETACH_SWEEP_INTERVAL`], so a row is withdrawn no later than the grace
/// plus one sweep after its attachment ended; 45 seconds leaves a quarter
/// of the bound for a drainer held up behind a slow withdrawal. It is long
/// enough for a box's host to be relaunched and its shuttle to carry a
/// frame again — a terminal's respawn, a detach hook's run — without the
/// row, its addresses and its proxy attachment going and coming back.
pub const DETACH_GRACE: Duration = Duration::from_secs(45);

/// How long a row its creator resumed ([`BoxRegistry::resume_client_box`])
/// awaits its box's first frame before it is withdrawn as a detached row
/// is at its grace's end: its switch address back to the book, its
/// loopback address back to the answerer, its creation kept dormant so a
/// later resume still works.
///
/// The creator resumes before it attaches or execs, and the first frame
/// comes once the box's host is launched in the guest and its shuttle
/// carries one. After a minvmd restart that is a VM cold boot (40 to 70
/// seconds), the guest daemon's start, and the box host's launch; five
/// minutes covers several times that, so a slow boot does not lose the
/// row it was resumed for, while a resume nobody follows with an attach
/// holds its addresses no longer than this. NET-138's 60 s runs from the
/// end of an attachment, and a reinstated row has had none since it was
/// published. The bound is armed only when a resume reinstates a withdrawn
/// row: a resume of a row that stands changes nothing about its liveness,
/// so it never stretches a detached row's grace past
/// [`NET_138_WITHDRAWAL_BOUND`] nor puts a bound on a row a relay carries.
pub const RESUME_ATTACH_BOUND: Duration = Duration::from_secs(300);

/// NET-138's bound on a detached row: withdrawn no later than 60 seconds
/// from the end of its box's attachment, whatever its creator asks for in
/// between ([`BoxRegistry::resume_client_box`] leaves a standing row's
/// grace as it runs).
pub const NET_138_WITHDRAWAL_BOUND: Duration = Duration::from_secs(60);

/// How often the drainer looks for detached rows whose grace has passed.
pub const DETACH_SWEEP_INTERVAL: Duration = Duration::from_secs(1);

const _: () = assert!(
    DETACH_GRACE.as_secs() + DETACH_SWEEP_INTERVAL.as_secs() < NET_138_WITHDRAWAL_BOUND.as_secs(),
    "a detached row must be withdrawn inside NET-138's 60 s bound"
);
const _: () = assert!(
    NET_138_WITHDRAWAL_BOUND.as_secs() == 60,
    "NET-138 bounds a detached row's withdrawal at 60 s from its attachment's end"
);

/// The file the registry persists its client boxes' registrations to, in
/// the VM host daemon's state dir ([`BoxRegistry::persisting_to`]).
pub const REGISTRY_FILE: &str = "box-registry.json";

/// The persisted registry's format version. A file of any other version is
/// not read: its rows are not reloaded, which leaves those boxes rowless —
/// the fail-closed reading of a file this build cannot vouch for.
const REGISTRY_FILE_VERSION: u32 = 1;

/// One relay's end, as the host reports it: the switch addresses whose
/// relayed traffic that connection carried, each with the id of the box
/// whose row it attributed them to, for the registry to detach by. The id
/// keeps a late report from detaching a newer box handed the same address.
/// Reported, not held — the gate has no say over what the report does to a
/// row.
type WithdrawalReport = Vec<([u8; 4], BoxId)>;

/// The subscribers to row withdrawals: one sender per subscriber, each told
/// of every row the registry removes ([`RowWithdrawal`]). Shared by the
/// registry and every [`BoxTable`] it hands out.
type RowWithdrawals = Arc<Mutex<Vec<tokio::sync::mpsc::UnboundedSender<RowWithdrawal>>>>;

/// How long a client-driven registration waits for a withdrawn box's
/// revocation to release the addresses it asks for, before it is refused
/// with [`AllocationError::RevocationPending`]. A revocation that goes well
/// holds an address for one unexpose per forward, which takes milliseconds.
/// The bound is for a switch that is slow to answer, and it keeps a control
/// connection's thread from waiting on a switch that never answers.
pub const REVOCATION_WAIT: Duration = Duration::from_secs(5);

/// The addresses a withdrawn box's revocation still holds against reuse
/// (design §7.1): the switch address its forwards dial and the published
/// loopback address they listen on. Each is held from the row's withdrawal
/// until every subscriber is done with it. No row is registered at a held
/// address ([`BoxRegistry::try_register`]), so the forwards a revocation
/// unbinds, and the connections it ends, are always the withdrawn box's. A
/// new box at the same address can neither receive the old box's forwarded
/// connections nor have its own forwards unbound by the old box's end.
///
/// The holds are counted, because two of them may name one address.
#[derive(Debug, Default)]
struct Revoking {
    held: Mutex<BTreeMap<[u8; 4], usize>>,
    /// Signalled whenever a hold is released, for the registrations that
    /// wait on one ([`Revoking::wait_released`]).
    released: Condvar,
}

impl Revoking {
    fn lock(&self) -> MutexGuard<'_, BTreeMap<[u8; 4], usize>> {
        self.held
            .lock()
            .expect("the revocation holds' lock is held only across a map update")
    }

    /// The first of `addrs` a revocation still holds, when one does.
    fn first_held(&self, addrs: &[[u8; 4]]) -> Option<[u8; 4]> {
        let held = self.lock();
        addrs.iter().find(|addr| held.contains_key(*addr)).copied()
    }

    fn hold(&self, addrs: &[[u8; 4]]) {
        let mut held = self.lock();
        for addr in addrs {
            *held.entry(*addr).or_default() += 1;
        }
    }

    fn release(&self, addrs: &[[u8; 4]]) {
        let mut held = self.lock();
        for addr in addrs {
            if let Some(count) = held.get_mut(addr) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    held.remove(addr);
                }
            }
        }
        drop(held);
        self.released.notify_all();
    }

    /// Waits up to `bound` for every one of `addrs` to be released. Returns
    /// the first address still held at the bound, or `None` once none is.
    fn wait_released(&self, addrs: &[[u8; 4]], bound: Duration) -> Option<[u8; 4]> {
        let deadline = Instant::now() + bound;
        let mut held = self.lock();
        loop {
            let still = addrs
                .iter()
                .find(|addr| held.contains_key(*addr))
                .copied()?;
            let now = Instant::now();
            if now >= deadline {
                return Some(still);
            }
            held = self
                .released
                .wait_timeout(held, deadline - now)
                .expect("the revocation holds' lock is held only across a map update")
                .0;
        }
    }
}

/// The addresses a row's revocation holds: its switch address, and its
/// published loopback address when that is one of the reserved range's
/// per-box addresses. The shared `127.0.0.1` is never held: every
/// host-address namespace publishes there, so it is no one box's to hold.
fn revocation_addrs(switch_addr: Ipv4Addr, loopback_addr: Ipv4Addr) -> Vec<[u8; 4]> {
    let mut addrs = vec![switch_addr.octets()];
    if in_reserved_local_range(loopback_addr) {
        addrs.push(loopback_addr.octets());
    }
    addrs
}

/// One withdrawn row, as a row-withdrawal subscriber receives it
/// ([`BoxTable::subscribe_row_withdrawals`]). It holds the row's addresses
/// against reuse for as long as any subscriber keeps a copy: a registration
/// at one of them is refused until every copy is dropped. The egress gate
/// keeps its copy until it has unbound the box's forwards, so no new box is
/// registered at an address an old box's forward still dials or listens on.
#[derive(Debug, Clone)]
pub struct RowWithdrawal {
    switch_addr: Ipv4Addr,
    hold: Arc<RevocationHold>,
}

impl RowWithdrawal {
    /// The withdrawn row's switch address: the address its forwards dial.
    #[must_use]
    pub fn switch_addr(&self) -> Ipv4Addr {
        self.switch_addr
    }

    /// The addresses this withdrawal holds against reuse.
    #[must_use]
    pub fn held_addrs(&self) -> &[[u8; 4]] {
        &self.hold.addrs
    }
}

/// The hold a [`RowWithdrawal`]'s copies share, released when the last copy
/// drops.
#[derive(Debug)]
struct RevocationHold {
    addrs: Vec<[u8; 4]>,
    revoking: Arc<Revoking>,
}

impl Drop for RevocationHold {
    fn drop(&mut self) {
        self.revoking.release(&self.addrs);
    }
}

/// The guest node namespace's name in the table: the in-VM daemon, whose own
/// root-netns tap [`BoxRegistry::register_node_namespace`] publishes. Read
/// from the sessions zone so the registry and the store's reserved names
/// spell the one label the zone defines.
const NODE_NAMESPACE: &str = zone_answer::NODE_ROW_LABEL;

/// The node namespace's row's name under the zone, as
/// [`BoxRegistry::zone_view`] holds it: `minimald.min.internal`, the same
/// name every VM host daemon's table holds its own node's row under. The
/// row never travels the answerer channel (`net::answerer::zone_rows`
/// excludes it): one name for every VM means a second VM's registration of
/// it is refused by the holder's first-writer rule by construction — a
/// standing clash-warn for the normal multi-VM case — so the holder's own
/// node row is the one the zone answers host-side, and inside the guest
/// the node's DNS layer keeps answering the name for its own VM.
#[must_use]
pub fn node_zone_name() -> String {
    zone_name(NODE_NAMESPACE)
}

/// The published rows, keyed by switch address in wire octets — the key the
/// gate's per-frame lookup uses, straight off the frame summary. A `BTreeMap`
/// because the row set's order escapes to diagnostics and to
/// [`BoxTable::rows`], and the same declarations must produce the same order
/// every time (a hash map's would vary run to run).
type Rows = BTreeMap<[u8; 4], Arc<BoxRecord>>;

/// One published namespace's row in the host-side table. Of what it holds,
/// two dimensions decide a frame from this namespace's address: its switch
/// address, the lease the shared verdict checks every frame's source against
/// (NET-084), and its compiled egress rules — beside which the dimensions
/// the frame rules cannot carry travel in the row too: the DNS hosts its
/// declaration named ([`Self::allow_dns_hosts`]), for the gate's DNS
/// admission table to pin the row's destinations from, and whether its box
/// declared a credentialed upstream
/// ([`Self::declares_credentialed_upstream`], NET-134), for the gate to
/// admit the proxy's address by. The rest — its name
/// (diagnostics), its loopback address, the ports it admitted, the names it
/// declared — is the declaration itself, carried for the host-side paths that
/// attach and name the namespace, and for the publish half of the gate, which
/// reads the ports and names as the records a switch publish may carry. Owned
/// outright, so no borrow of a client's declaration survives the registration
/// that built it. Not [`PartialEq`]: the row's runtime half is interior and
/// mutable ([`RowRuntime`]), so no two records the same registration built
/// stay comparable for the record's life.
#[derive(Debug)]
pub struct BoxRecord {
    name: String,
    box_id: BoxId,
    switch_addr: Ipv4Addr,
    loopback_addr: Ipv4Addr,
    admitted_ports: Vec<u16>,
    declared_names: Vec<String>,
    egress: EgressRules,
    resolves_names: bool,
    dns_hosts: Vec<String>,
    /// Whether the declaration the host registered the row with is the
    /// deny-all shape ([`EgressPolicy::admits_nothing`]). Read off the
    /// registration's own policy, never off anything the guest reports.
    deny_all: bool,
    credentialed_upstream: bool,
    /// The box's dynamic-ingress stance (NET-045): the stance half of the
    /// grant a runtime port report is checked against. Carried from the
    /// host-side registration — the same create inputs the session record
    /// holds — never from the guest: the guest reports, the host decides.
    /// The default an absent declaration carries is [`DynamicIngress::Deny`],
    /// which admits nothing.
    dynamic_ingress: DynamicIngress,
    /// The range the stance admits runtime ports in, inclusive at both
    /// ends — the grant's range half. `None` permits nothing even under an
    /// `allow` stance, the same meaning the session policy's absent range
    /// carries.
    dynamic_range: Option<(u16, u16)>,
    /// The row's runtime-admitted ports and the admit timestamps its rate
    /// is measured by (NET-138): the one row dimension the in-VM daemon's
    /// reports fill, guarded by the grant the two fields above hold.
    /// Interior to the row because reports arrive while the row is
    /// published and shared — the gate reads the ports as the row's
    /// runtime-published set, the read-only row verb answers with them,
    /// and the row's withdrawal takes the whole set with it structurally.
    runtime_ports: Mutex<RowRuntime>,
    /// The row's egress allow-list as derived at registration: the
    /// declaration's `allow_subnets` dimension in its own spelling, or the
    /// allow-all one when the dimension is absent. Carried for the
    /// read-only row verb — a person's surface, where the strings are the
    /// policy as it was declared, not the compiled form only the gate
    /// reads.
    egress_allow_list: Vec<String>,
    /// Whether a frame of the box ever crossed the gate under this row
    /// ([`BoxTable::carry`]): set once by the relay that first
    /// attributes the row's source, never cleared. A row withdrawn before
    /// it was ever attributed returns its switch address with no
    /// quarantine ([`SwitchAddressBook`]), since nothing on the host keyed
    /// state by it. Bookkeeping, like the rate window: not compared.
    attributed: AtomicBool,
    /// Whether a relay carries the box's frames now, read at the host's
    /// end of its attachment (NET-138, [`RowLiveness`]). Bookkeeping, like
    /// the attribution mark: not compared.
    liveness: Mutex<RowLiveness>,
    /// The switch address of the box row this is a **task row** of
    /// (NET-138): a row filed with its box at registration, at one of the
    /// box's task addresses, carrying the box's id (NET-133) and its egress,
    /// with no ingress, no names and no credentialed lane. A task row stands
    /// exactly as long as its box's row: it is withdrawn with the box on
    /// every path that removes the box, never because its own relay ended,
    /// and restored with it. `None` for a box's own row.
    task_row_of: Option<Ipv4Addr>,
    /// The task addresses filed with this box ([`Self::task_row_of`]):
    /// empty for a task row, and for a box that registered none.
    task_addrs: Vec<Ipv4Addr>,
}

/// A row's liveness as the host reads it at its end of the box's
/// attachment (NET-138): how many relays are carrying the box's frames
/// right now, and, once the last of them has ended, since when the row has
/// been **detached**. A row is in one of three states:
///
/// - **awaiting** — no relay has carried it yet, and no grace runs: a
///   fresh registration stands until its box's first frame or its
///   creator's withdrawal; one its creator reinstated
///   ([`BoxRegistry::resume_client_box`]) stands until a relay carries its
///   box or one of its task rows, or until [`RESUME_ATTACH_BOUND`] passes
///   and it is withdrawn as at a grace's end;
/// - **attached** — at least one relay carries it;
/// - **detached** — its last relay ended, or it was reloaded from the
///   persisted registry at start ([`BoxRegistry::persisting_to`]); it is
///   withdrawn once [`DETACH_GRACE`] passes unless a relay carries it
///   again first.
///
/// A detached row decides frames exactly as an attached one does: the
/// gate's verdict reads the row's rules, never its liveness, and the row's
/// addresses stay held.
#[derive(Debug, Default)]
struct RowLiveness {
    carriers: usize,
    detached_since: Option<Instant>,
    /// When its creator reinstated the row, while no relay has carried it
    /// since ([`RESUME_ATTACH_BOUND`]). Never set on a row that stood when
    /// it was resumed.
    resumed_since: Option<Instant>,
}

/// Manual because the row's runtime half is interior ([`RowRuntime`]): the
/// derive cannot compare through a mutex, and equality that ignored the
/// half would call two rows with different runtime admissions equal. Two
/// records are equal when every dimension matches, the runtime set under
/// its own lock included — an instantaneous comparison, never a stable
/// ordering across concurrent reports. The set is compared through one
/// lock at a time, each side's taken and released before the other's: a
/// row compared with itself — and the table's live rows are the
/// registrations' own Arcs, so [`BoxRegistry::try_register`]'s caller holds
/// the very record the table resolves — must never take its own lock
/// twice, which a std mutex refuses. The rate window the half also holds
/// is the limiter's bookkeeping, never the row's identity, so it is not
/// compared.
impl PartialEq for BoxRecord {
    fn eq(&self, other: &Self) -> bool {
        if !(self.name == other.name
            && self.box_id == other.box_id
            && self.switch_addr == other.switch_addr
            && self.loopback_addr == other.loopback_addr
            && self.admitted_ports == other.admitted_ports
            && self.declared_names == other.declared_names
            && self.egress == other.egress
            && self.resolves_names == other.resolves_names
            && self.dns_hosts == other.dns_hosts
            && self.deny_all == other.deny_all
            && self.credentialed_upstream == other.credentialed_upstream
            && self.dynamic_ingress == other.dynamic_ingress
            && self.dynamic_range == other.dynamic_range
            && self.egress_allow_list == other.egress_allow_list
            && self.task_row_of == other.task_row_of
            && self.task_addrs == other.task_addrs)
        {
            return false;
        }
        let own_ports = self
            .runtime_ports
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .ports
            .clone();
        let other_ports = other
            .runtime_ports
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .ports
            .clone();
        own_ports == other_ports
    }
}

impl Eq for BoxRecord {}

/// A row's mutable runtime half: the ports the in-VM daemon's admit reports
/// recorded — each the port and protocol pair the report named, so one port
/// number published under two protocols is two admissions, not one — and
/// the timestamps of the admits the trailing-second rate is measured by.
/// Guarded by its own mutex, never the row lock: the ports change with the
/// box's runtime publications, while every other row dimension is
/// registration-frozen.
#[derive(Debug, Default, PartialEq, Eq)]
struct RowRuntime {
    ports: Vec<RuntimePort>,
    admits: VecDeque<Instant>,
}

/// One runtime-admitted port: the port number and the protocol it was
/// published under — the pair a report names and a withdrawal removes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RuntimePort {
    port: u16,
    proto: IpProto,
}

impl BoxRecord {
    /// The namespace's name — what a diagnostic names a row by.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Whether a frame of the box ever crossed the gate under this row
    /// ([`BoxTable::carry`]).
    #[must_use]
    pub fn was_attributed(&self) -> bool {
        self.attributed.load(Ordering::Relaxed)
    }

    /// Whether the row is detached ([`RowLiveness`]): no relay carries its
    /// box's frames, and the grace it is withdrawn after is running.
    #[must_use]
    pub fn is_detached(&self) -> bool {
        self.liveness().detached_since.is_some()
    }

    /// When the row's attachment ended, if it is due its withdrawal at
    /// `now`: the instant it detached, once it has stood detached for
    /// [`DETACH_GRACE`]; or `now`, once its creator reinstated it
    /// [`RESUME_ATTACH_BOUND`] ago and no relay has carried its box since —
    /// neither the box's own address nor any of its task rows in `rows`,
    /// the one liveness unit a box and its task runs are (NET-138).
    /// A task row has no bound of its own: it goes with its box's row.
    fn past_its_bound(&self, rows: &Rows, now: Instant) -> Option<Instant> {
        if self.is_task_row() {
            return None;
        }
        let liveness = self.liveness();
        let past = |since: Option<Instant>, bound| {
            since.filter(|since| now.saturating_duration_since(*since) >= bound)
        };
        past(liveness.detached_since, DETACH_GRACE).or_else(|| {
            (liveness.carriers == 0 && !task_rows_carried(rows, self))
                .then(|| past(liveness.resumed_since, RESUME_ATTACH_BOUND).map(|_| now))
                .flatten()
        })
    }

    fn liveness(&self) -> MutexGuard<'_, RowLiveness> {
        self.liveness
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// The switch address of the box row this is a task row of, or `None`
    /// for a box's own row ([`BoxRecord`]'s task rows, NET-138).
    #[must_use]
    pub fn task_row_of(&self) -> Option<Ipv4Addr> {
        self.task_row_of
    }

    /// Whether this is a task row: one filed with a box at one of its task
    /// addresses, rather than the box's own row.
    #[must_use]
    pub fn is_task_row(&self) -> bool {
        self.task_row_of.is_some()
    }

    /// The task addresses filed with this box, in the order they were
    /// drawn: each the key of a task row of this box's.
    #[must_use]
    pub fn task_addrs(&self) -> &[Ipv4Addr] {
        &self.task_addrs
    }

    /// The addresses this row's withdrawal holds against reuse: its switch
    /// address, and its box's published loopback address for a box's own
    /// row. A task row publishes nothing at the loopback, which its box's
    /// row holds.
    fn revocation_addrs(&self) -> Vec<[u8; 4]> {
        if self.is_task_row() {
            vec![self.switch_addr.octets()]
        } else {
            revocation_addrs(self.switch_addr, self.loopback_addr)
        }
    }

    /// The box's own id (BEP-070): minted once for this creation — by
    /// the registration that published the row, or taken from the id a
    /// re-registration presented — with its random bytes from the host's
    /// OS CSPRNG. Unique per creation, so a box recreated with the same
    /// name and addresses carries a different id, and the id never
    /// returns to use: a revocation scoped to it stays scoped forever.
    /// This is what the proxy's attachment names the box by and a
    /// delivered connection's header carries (NET-133).
    #[must_use]
    pub fn box_id(&self) -> BoxId {
        self.box_id
    }

    /// The namespace's address on the switch: the lease its frames must carry
    /// (NET-084) and the key the gate resolves a frame's source through.
    #[must_use]
    pub fn switch_addr(&self) -> Ipv4Addr {
        self.switch_addr
    }

    /// The namespace's address on the guest's loopback.
    #[must_use]
    pub fn loopback_addr(&self) -> Ipv4Addr {
        self.loopback_addr
    }

    /// The ports this namespace admitted, in the order the declaration
    /// carried them.
    ///
    /// Two readings, both of them the declaration's own and neither one the
    /// frame verdict's:
    ///
    /// * An **ingress** dimension — what may be sent *to* this namespace,
    ///   which the host attaches it by on the registration path (T66's
    ///   client-driven one, the same path that fills this table). The frame
    ///   verdict reads [`Self::egress`] alone and never this.
    /// * The **publish** dimension — the ports a switch publish at this
    ///   namespace's address may name: the host-side listener a forwarder
    ///   binds, the end the registration wire carries. A mapping's inside
    ///   end is not a record of the publish — it is the port the forwarder
    ///   dials on the target, governed by the target's own ingress
    ///   declaration inside the VM, which no row here is compiled from. The
    ///   gate's publish decision (NET-081's control verbs) reads this and
    ///   [`Self::declared_names`] as the records it admits a publish by;
    ///   nothing outside the declaration is publishable, so a row that names
    ///   no ports publishes none.
    ///
    /// It is carried in the row because NET-138's row holds a namespace's
    /// whole declaration, where both the attaching side and the publish
    /// decision reach it without a second table.
    #[must_use]
    pub fn admitted_ports(&self) -> &[u16] {
        &self.admitted_ports
    }

    /// The zone names this namespace declared, in the order the declaration
    /// carried them — the publish dimension's name half: the records a
    /// `dns/add` at this namespace's address may carry. A row that names none
    /// publishes none.
    #[must_use]
    pub fn declared_names(&self) -> &[String] {
        &self.declared_names
    }

    /// The namespace's compiled egress rules — the decision the gate applies
    /// to every frame leaving the VM from its address.
    #[must_use]
    pub fn egress(&self) -> &EgressRules {
        &self.egress
    }

    /// Whether the namespace's own declaration named DNS hosts: `true` when
    /// [`Self::allow_dns_hosts`] is non-empty. Such a row has destinations
    /// its compiled frame rules cannot carry — the addresses its declared
    /// names resolve to — so its undeclared-destination drops are decided
    /// by the host-side DNS admission table
    /// ([`crate::net::dns_pins`], NET-081 deciding NET-066's admission
    /// outside the VM) against the answers its own lookups received. `false`
    /// — no names declared — means the frame rules are the whole decision,
    /// and the table is never consulted for the row.
    #[must_use]
    pub fn resolves_names(&self) -> bool {
        self.resolves_names
    }

    /// The DNS hostnames the namespace's declaration named in
    /// `egress.allow_dns_hosts`, as the client spelled them — the one egress
    /// dimension that compiles to nothing in the frame rules, because a
    /// name is not an address: NET-066 enforces it as the addresses the
    /// box's own lookups resolved to, admitted for the shared admission
    /// window. The host-side admission table reads this — it pins only
    /// answers to a name the row declared here, so every pin it holds is an
    /// answer the box's own query received. Empty for a row that declared
    /// none: a name grant is earned by an entry, never by an absent field
    /// (the dns-gate module doc records why `None` is not allow-all names).
    #[must_use]
    pub fn allow_dns_hosts(&self) -> &[String] {
        &self.dns_hosts
    }

    /// Whether the row's egress is the deny-all shape: every `allow_*`
    /// dimension present and empty, the section
    /// [`EgressPolicy::deny_all`] materializes (NET-141's deny-all case).
    ///
    /// Derived once, at registration, from the egress policy the host
    /// registered the row with — the host-side create inputs, never a guest
    /// report — so nothing inside the VM can flip it: the runtime half the
    /// guest's reports fill ([`RowRuntime`]) is not read. A row with no
    /// egress declaration (the node namespace's among them, which carries
    /// every host-address box's frames) is never deny-all. The host-side
    /// gate reads this to drop a deny-all box's DNS queries for names
    /// outside the box zone ([`crate::net::dns_pins::deny_all_refusal`]).
    #[must_use]
    pub fn is_deny_all(&self) -> bool {
        self.deny_all
    }

    /// Whether this box's declaration named a credentialed upstream
    /// (NET-134): `true` marks the Box Egress Proxy's listener as this
    /// box's infrastructure — the one destination its compiled frame rules
    /// never decide, because the credentials the proxy redeems are the
    /// lane's own and no egress rule of the box's says anything about them.
    /// `false`, the absent declaration, is no lane: the proxy's address
    /// stays under the box-to-host default-deny like any other host-side
    /// destination, whatever the box's rules would allow.
    ///
    /// The gate reads this beside the row's rules ([`crate::net::egress_gate`]),
    /// never through them: the declaration is a fact about the box, reduced
    /// from the session policy's own field at registration — nothing the
    /// guest says can add a lane to a row behind the gate's back.
    #[must_use]
    pub fn declares_credentialed_upstream(&self) -> bool {
        self.credentialed_upstream
    }

    /// The box's dynamic-ingress stance (NET-045): the stance half of the
    /// grant a runtime port report is checked against ([`Self::admit` is
    /// not this — that is the registry's]). `allow` and `ask` are the two
    /// stances that can record a report in range; `deny`, the default,
    /// admits none.
    #[must_use]
    pub fn dynamic_ingress(&self) -> DynamicIngress {
        self.dynamic_ingress
    }

    /// The range the stance admits runtime ports in, inclusive at both
    /// ends — the grant's range half. `None` permits nothing even under an
    /// `allow` stance.
    #[must_use]
    pub fn dynamic_range(&self) -> Option<(u16, u16)> {
        self.dynamic_range
    }

    /// The row's runtime-admitted port numbers recorded under `proto`, in
    /// report order: the runtime half of the set the gate admits the box's
    /// publications in that protocol by — the declared half is
    /// [`Self::admitted_ports`]. Keyed on the (port, protocol) pair the
    /// report named, so a port admitted for udp never admits its tcp twin.
    #[must_use]
    pub fn runtime_port_numbers_in(&self, proto: IpProto) -> Vec<u16> {
        let runtime = self
            .runtime_ports
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        runtime
            .ports
            .iter()
            .filter(|reported| reported.proto == proto)
            .map(|reported| reported.port)
            .collect()
    }

    /// The row's runtime-admitted ports, distinct port numbers in report
    /// order, across both protocols: the read-only row verb's answer's
    /// runtime dimension. The gate decides by the protocol-keyed half
    /// ([`Self::runtime_port_numbers_in`]). Reported by the in-VM daemon
    /// within the grant the registration holds
    /// ([`BoxRegistry::admit_runtime_port`]), removed by its withdrawal
    /// reports, and gone with the row itself when the row is withdrawn.
    #[must_use]
    pub fn runtime_port_numbers(&self) -> Vec<u16> {
        let runtime = self
            .runtime_ports
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut seen = Vec::new();
        for port in runtime.ports.iter().map(|reported| reported.port) {
            if !seen.contains(&port) {
                seen.push(port);
            }
        }
        seen
    }

    /// The row's egress allow-list, derived at registration from the same
    /// declaration the frame rules compiled from: the `allow_subnets`
    /// dimension's own spelling when the declaration named one, and the
    /// allow-all one when it did not. The read-only row verb's answer — a
    /// person's surface, so the list is the policy as it was declared, not
    /// the compiled form the gate decides by (the deny dimension stays the
    /// gate's to apply; this names what the allow dimension admits).
    #[must_use]
    pub fn egress_allow_list(&self) -> &[String] {
        &self.egress_allow_list
    }
}

/// A namespace's declaration as it arrives on the host, before any frame
/// exists: the facts a row is compiled from. Builder-shaped (the crate's
/// `VmEgressPolicy` style) because the addresses alone make a namespace and
/// everything else is optional.
#[derive(Debug, Clone)]
pub struct BoxRegistration {
    name: String,
    box_id: Option<BoxId>,
    switch_addr: Ipv4Addr,
    loopback_addr: Ipv4Addr,
    admitted_ports: Vec<u16>,
    declared_names: Vec<String>,
    egress: Option<EgressPolicy>,
    credentialed_upstream: Option<sessions::CredentialedUpstream>,
    dynamic_ingress: Option<DynamicIngress>,
    dynamic_allowed_range: Option<(u16, u16)>,
    task_addrs: Vec<Ipv4Addr>,
}

impl BoxRegistration {
    /// A declaration for the namespace `name`, addressed at `switch_addr` on
    /// the switch and `loopback_addr` on the guest's loopback. The egress
    /// policy is absent (allow-all, the shipped default) until
    /// [`with_egress_policy`](Self::with_egress_policy) declares one, and
    /// the box's id is minted at registration
    /// ([`crate::bep_attach::mint_box_id`]).
    #[must_use]
    pub fn new(name: impl Into<String>, switch_addr: Ipv4Addr, loopback_addr: Ipv4Addr) -> Self {
        Self {
            name: name.into(),
            box_id: None,
            switch_addr,
            loopback_addr,
            admitted_ports: Vec::new(),
            declared_names: Vec::new(),
            egress: None,
            credentialed_upstream: None,
            dynamic_ingress: None,
            dynamic_allowed_range: None,
            task_addrs: Vec::new(),
        }
    }

    /// The task addresses filed with the box (NET-138): one task row each,
    /// published and withdrawn with the box's own row.
    #[must_use]
    pub fn with_task_addresses(mut self, addrs: impl IntoIterator<Item = Ipv4Addr>) -> Self {
        self.task_addrs = addrs.into_iter().collect();
        self
    }

    /// The ports this namespace admitted — the ingress **and** publish
    /// dimensions [`BoxRecord::admitted_ports`] documents, not a dimension
    /// the gate's frame verdict reads.
    #[must_use]
    pub fn with_admitted_ports(mut self, ports: impl IntoIterator<Item = u16>) -> Self {
        self.admitted_ports = ports.into_iter().collect();
        self
    }

    /// The zone names this namespace declared — the name half of the publish
    /// dimension [`BoxRecord::declared_names`] documents. Names are matched
    /// exactly, as the client's own client spells them.
    #[must_use]
    pub fn with_declared_names(
        mut self,
        names: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        self.declared_names = names.into_iter().map(Into::into).collect();
        self
    }

    /// The namespace's egress policy, as the client declared it at launch.
    /// Compiled at registration; the declaration itself is not retained.
    #[must_use]
    pub fn with_egress_policy(mut self, policy: EgressPolicy) -> Self {
        self.egress = Some(policy);
        self
    }

    /// The namespace's declaration of a credentialed upstream (NET-134):
    /// `Some` marks the Box Egress Proxy's listener as this box's
    /// infrastructure, so the gate admits its address beside — never
    /// through — whatever egress rules the declaration also carries. The
    /// declaration is reduced to a lane in the row; its own content is the
    /// proxy document's to extend, so nothing of it is retained here.
    #[must_use]
    pub fn with_credentialed_upstream(
        mut self,
        declaration: sessions::CredentialedUpstream,
    ) -> Self {
        self.credentialed_upstream = Some(declaration);
        self
    }

    /// The box's dynamic-ingress grant (NET-045, NET-138): the stance and
    /// the range a runtime port report is checked against — the row's own
    /// copy of the same create inputs the session record holds, carried at
    /// registration so the host decides every report against a fact the
    /// guest cannot change. `None` for the stance is the declaration's
    /// `deny` default; `None` for the range permits nothing under any
    /// stance.
    #[must_use]
    pub fn with_dynamic_ingress(
        mut self,
        stance: DynamicIngress,
        range: Option<(u16, u16)>,
    ) -> Self {
        self.dynamic_ingress = Some(stance);
        self.dynamic_allowed_range = range;
        self
    }
}

/// A box declaration as the activating client carries it over the host's
/// control socket: the facts a row is compiled from, without the addresses —
/// a client-driven registration allocates those on the host, from the
/// address plan this registry's switch serves, and hands them back with the
/// row ([`BoxRegistry::register_client_box`]).
#[derive(Debug, Clone)]
pub struct ClientBoxSpec {
    /// The box's name: what the row is named by, and the name the create
    /// request will carry — a box's id on the host is its name.
    pub name: String,
    /// The external ports the box's ingress rules admit, as the client
    /// expanded them.
    pub ingress_ports: Vec<u16>,
    /// The box's egress policy, as the client declared it. Absent compiles
    /// the egress default the registry's phase and opt-out resolve
    /// (`sessions::effective_egress`), the same meaning the create request's
    /// absent policy carries in the guest.
    pub egress: Option<EgressPolicy>,
    /// The box's declaration of a credentialed upstream (NET-134), carried
    /// from the session's policy: `Some` makes the Box Egress Proxy's
    /// listener this box's infrastructure — reachable whatever the egress
    /// rules say — while `None` is no lane, and the proxy's address stays
    /// refused under the box-to-host default-deny. The one field a client
    /// that predates NET-134 sends absent, every time.
    pub credentialed_upstream: Option<sessions::CredentialedUpstream>,
    /// The box's dynamic-ingress stance (NET-045): the stance half of the
    /// grant the row holds a runtime port report against. `None` is the
    /// declaration's `deny` default — a client that predates the grant
    /// fields registers a row that admits no runtime port, exactly as one
    /// whose declaration said `deny` does.
    pub dynamic_ingress: Option<DynamicIngress>,
    /// The range the stance admits runtime ports in, inclusive at both
    /// ends. `None` permits nothing even under an `allow` stance.
    pub dynamic_allowed_range: Option<(u16, u16)>,
}

/// One client box's creation as the registry keeps it past its row and
/// persists it ([`BoxRegistry::persisting_to`]): the declaration its
/// creator registered — never a fact the guest reported (NET-138) — with
/// the addresses and the box id the registration handed back, and whether
/// a row stands for it. A creation lives from its registration until its
/// creator withdraws the box ([`BoxRegistry::withdraw_client_box`]) or a
/// new registration takes its name; a row withdrawn at the end of its
/// detach grace leaves the creation **dormant** (`standing: false`) for
/// its creator to resume ([`BoxRegistry::resume_client_box`]). A creation,
/// standing or dormant, keeps its addresses reserved: its switch and task
/// addresses stay out of the hand-out book — taken again from a fresh book
/// at reload — and its published loopback address stays the answerer's
/// link for its name, so a resume finds every address its box was created
/// with. Its creator's withdrawal releases them all. There is at most one
/// creation per box name.
///
/// The file format: one JSON object per creation in
/// [`RegistryFile::boxes`], its fields named as here.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Creation {
    name: String,
    box_id: minimald_rpc::BoxId,
    switch_address: Ipv4Addr,
    loopback_address: Ipv4Addr,
    ingress_ports: Vec<u16>,
    egress: Option<EgressPolicy>,
    credentialed_upstream: Option<sessions::CredentialedUpstream>,
    dynamic_ingress: Option<DynamicIngress>,
    dynamic_allowed_range: Option<(u16, u16)>,
    /// The task addresses filed with the box (NET-138), persisted with it
    /// so a reload and a resume restore its task rows with its own.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    task_addresses: Vec<Ipv4Addr>,
    standing: bool,
}

impl Creation {
    fn new(
        spec: &ClientBoxSpec,
        switch_address: Ipv4Addr,
        loopback_address: Ipv4Addr,
        task_addresses: Vec<Ipv4Addr>,
        id: BoxId,
    ) -> Self {
        Self {
            name: spec.name.clone(),
            box_id: minimald_rpc::BoxId::from_bytes(id),
            switch_address,
            loopback_address,
            ingress_ports: spec.ingress_ports.clone(),
            egress: spec.egress.clone(),
            credentialed_upstream: spec.credentialed_upstream.clone(),
            dynamic_ingress: spec.dynamic_ingress,
            dynamic_allowed_range: spec.dynamic_allowed_range,
            task_addresses,
            standing: true,
        }
    }

    fn id(&self) -> BoxId {
        self.box_id.to_bytes()
    }

    /// The declaration the creation was registered from, for the same
    /// compile a registration runs ([`BoxRegistry::client_registration`]).
    fn spec(&self) -> ClientBoxSpec {
        ClientBoxSpec {
            name: self.name.clone(),
            ingress_ports: self.ingress_ports.clone(),
            egress: self.egress.clone(),
            credentialed_upstream: self.credentialed_upstream.clone(),
            dynamic_ingress: self.dynamic_ingress,
            dynamic_allowed_range: self.dynamic_allowed_range,
        }
    }
}

/// The persisted registry ([`REGISTRY_FILE`]): its format version, then
/// every creation the registry keeps.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RegistryFile {
    version: u32,
    boxes: Vec<Creation>,
}

/// Writes `file` to `path` the one way the registry's file is ever
/// written: to a sibling temporary file created afresh with mode 0600 —
/// the registry names every box and its policy, which is no other user's
/// to read — synced, then renamed over `path`, and the directory synced,
/// so a crash at any point leaves either the old file or the new one,
/// whole, and never a partial one.
fn write_registry_file(path: &std::path::Path, file: &RegistryFile) -> std::io::Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let bytes = serde_json_lenient::to_vec_pretty(file).map_err(std::io::Error::other)?;
    let tmp = path.with_extension("json.tmp");
    match std::fs::remove_file(&tmp) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    {
        let mut out = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)?;
        out.write_all(&bytes)?;
        out.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    if let Some(dir) = path.parent() {
        std::fs::File::open(dir)?.sync_all()?;
    }
    Ok(())
}

/// Reads the creations persisted at `path`: none when there is no file
/// yet. A file that cannot be read, does not parse, or is of another
/// version than [`REGISTRY_FILE_VERSION`] reloads no row — its boxes are
/// unregistered sources the gate drops (NET-085): fail-closed — and is set
/// aside ([`set_aside_registry_file`]) rather than written over, said as an
/// error line, so the creations it may still hold are there to recover.
/// `None` when it could not be set aside: the caller then persists
/// nothing, since the first write would replace it.
fn read_registry_file(path: &std::path::Path) -> Option<Vec<Creation>> {
    #[derive(serde::Deserialize)]
    struct Version {
        version: u32,
    }
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Some(Vec::new()),
        Err(error) => return set_aside_registry_file(path, &error.to_string()),
    };
    match serde_json_lenient::from_slice::<Version>(&bytes) {
        Ok(Version { version }) if version == REGISTRY_FILE_VERSION => {}
        Ok(Version { version }) => {
            return set_aside_registry_file(
                path,
                &format!("version {version}, this build reads {REGISTRY_FILE_VERSION}"),
            );
        }
        Err(error) => return set_aside_registry_file(path, &error.to_string()),
    }
    match serde_json_lenient::from_slice::<RegistryFile>(&bytes) {
        Ok(file) => Some(file.boxes),
        Err(error) => set_aside_registry_file(path, &error.to_string()),
    }
}

/// Renames the unusable registry file at `path` aside, to the same name
/// with an `.unusable-<unix seconds>` suffix, and says so as an error line
/// naming `why`. Returns no creations when it is set aside, and `None` —
/// persistence off for this process, said as a second error line — when
/// the rename fails.
fn set_aside_registry_file(path: &std::path::Path, why: &str) -> Option<Vec<Creation>> {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_secs());
    let mut aside = path.as_os_str().to_owned();
    aside.push(format!(".unusable-{stamp}"));
    let aside = std::path::PathBuf::from(aside);
    match std::fs::rename(path, &aside) {
        Ok(()) => {
            tracing::error!(
                path = %path.display(),
                aside = %aside.display(),
                why,
                "the persisted box registry is unusable; it is set aside and no rows are reloaded"
            );
            Some(Vec::new())
        }
        Err(error) => {
            tracing::error!(
                path = %path.display(),
                why,
                %error,
                "the persisted box registry is unusable and could not be set aside; \
                 no rows are reloaded and none are persisted by this process"
            );
            None
        }
    }
}

/// The run of `subnet`'s address plan the host hands registered boxes from:
/// the PTask run's upper half, `[midpoint + 1, last_ptask]`, as an inclusive
/// `(first, last)` pair — one address more than the daemon's reserve below
/// it, a PTask run holding an odd number of addresses.
///
/// The plan's PTask run is split into two disjoint sub-runs so the two
/// allocators that draw on it cannot meet: this host hands a registered box
/// and its task addresses only from the upper half, and the lower half — the
/// run below this hand-out run — is the self-allocation reserve a native
/// daemon draws from. The daemon's half is the same midpoint rule mirrored
/// in `minimald::net::self_allocation_run`; one rule, two statements, so
/// change both together — each side's tests pin the default plan's split
/// literally.
///
/// An in-VM daemon draws nothing (NET-138): every own-address box arrives
/// handed, and so does every task run, at a task address filed with its box
/// here. The reserve stays unused under a host that registers boxes.
#[must_use]
fn hand_out_run(subnet: SwitchSubnet) -> (u32, u32) {
    let first = subnet.first_ptask();
    let last = subnet.last_ptask();
    let reserve_len = (last - first).div_ceil(2);
    (first + reserve_len, last)
}

/// How long a released hand-out address waits before it is handed again:
/// the switch crate's one quarantine, shared with the daemon's
/// self-allocation reserve ([`switch::SWITCH_ADDRESS_REUSE_QUARANTINE`]).
/// Asserted below to outlast every timer on this host that keys state by a
/// box's switch address past its row: the gate's reply-flow records (both
/// windows a replied flow lives under) and the DNS admission window a pin
/// lives under. Pins and reply flows are also retired when the relay that
/// carried them ends ([`crate::net::dns_pins`]) — the only end an
/// established pinned flow's day-long idle cap gets short of a FIN — so the
/// quarantine is the bound for a row withdrawn while its relay lives on.
const SWITCH_REUSE_QUARANTINE: Duration = switch::SWITCH_ADDRESS_REUSE_QUARANTINE;

const _: () = assert!(
    SWITCH_REUSE_QUARANTINE.as_millis()
        >= sessions::core::egress::REPLY_UDP_REPLIED_WINDOW.as_millis(),
    "the switch address quarantine must outlast a replied UDP flow's record"
);
const _: () = assert!(
    SWITCH_REUSE_QUARANTINE.as_millis() >= sessions::core::egress::REPLY_TCP_IDLE_CAP.as_millis(),
    "the switch address quarantine must outlast an idle TCP flow's record"
);
const _: () = assert!(
    SWITCH_REUSE_QUARANTINE.as_millis() >= sessions::core::egress::DNS_ADMISSION_WINDOW.as_millis(),
    "the switch address quarantine must outlast a DNS pin's admission window"
);

/// The box row `record` is a task row of, when it is one and that box
/// row stands for the same box (NET-138).
fn box_row_of<'rows>(rows: &'rows Rows, record: &BoxRecord) -> Option<&'rows Arc<BoxRecord>> {
    let parent = rows.get(&record.task_row_of()?.octets())?;
    (parent.box_id == record.box_id).then_some(parent)
}

/// Whether a relay carries any of `parent`'s task rows. Called with the
/// box row's liveness held: each task row's lock is taken after it.
fn task_rows_carried(rows: &Rows, parent: &BoxRecord) -> bool {
    parent.task_addrs().iter().any(|addr| {
        rows.get(&addr.octets())
            .filter(|task| task.box_id == parent.box_id && task.is_task_row())
            .is_some_and(|task| task.liveness().carriers > 0)
    })
}

/// How many hand-out addresses a task-slot draw always leaves for a new
/// box's own address (NET-138): task slots are best-effort, so the
/// registry stops drawing them once the book could hand fewer than this,
/// and a box is never refused because task slots took its address. Sixteen
/// keeps room for sixteen new boxes once task slots stop being handed:
/// about an eighth of a carved /24's hand-out run of 125, so the first
/// twenty-odd boxes there still get their full
/// [`minimald_rpc::TASK_SLOTS_PER_BOX`] slots each, and a rounding error
/// against the default plan's run of thousands.
pub const TASK_SLOT_FLOOR: usize = 16;

/// The hand-out run's book (NET-138, design §7.1): which of the run's
/// switch addresses are out — drawn for a row that stands or a
/// registration in flight — and which came back, when. Modeled on the
/// daemon's own self-allocation book (`minimald::net::IpAllocator`): an
/// address is reused, never shared, and never wraps.
///
/// Addresses are handed longest-free first: the run's never-drawn
/// addresses in plan order, then returned ones in return order, so the
/// quarantine is the normal case rather than the edge. A returned address
/// is handed again only once its quarantine ([`SWITCH_REUSE_QUARANTINE`])
/// has passed **and** no row and no withdrawn box's revocation still holds
/// it — the registry checks both at the draw. A row withdrawn before it
/// was ever attributed — no frame of its box ever crossed the gate — comes
/// back with no quarantine: nothing on the host keyed state by it, so an
/// activation that withdraws and re-registers (an autogen name's retry)
/// spends nothing.
///
/// A row's box id is the epoch its address carries between two hands: a
/// re-handed address is a new box with a new id (BEP-070), and a
/// withdrawal that names the old id removes nothing of the new row
/// ([`BoxRegistry::withdraw_client_box`]).
#[derive(Debug)]
struct SwitchAddressBook {
    /// The hand-out run, inclusive at both ends (`hand_out_run`).
    first: u32,
    last: u32,
    /// The next never-drawn address; `None` once the run is drawn through.
    /// Only ever advances, by a checked add, so it can never wrap.
    next: Option<u32>,
    /// The addresses drawn and not yet returned.
    out: BTreeSet<u32>,
    /// Returned addresses, oldest return first, each with the instant it
    /// becomes eligible again — its return plus the quarantine, or its
    /// return alone for a row that was never attributed — and the id of
    /// the box that returned it, the one box that may take it back inside
    /// its quarantine ([`Self::take`]).
    ///
    /// Not persisted: a minvmd restart is a VM restart, and every
    /// switch-keyed host-side state the quarantine outlasts — the gate's
    /// reply flows and DNS pins, the proxy's attachments, gvproxy's
    /// neighbour entries — lives in this process and the VM it supervises,
    /// and ends with them, so a book reloaded at start
    /// ([`BoxRegistry::persisting_to`]) holds only what reloaded rows hold.
    free: VecDeque<(u32, Instant, BoxId)>,
}

/// Where the hand-out run stands when a draw hands nothing: the counts an
/// [`AllocationError::SwitchExhausted`] names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandOutCounts {
    /// Addresses out: drawn for a row that stands or a registration in
    /// flight.
    pub live: usize,
    /// Addresses returned but not yet eligible — inside their quarantine,
    /// or still held by a row or a withdrawn box's revocation.
    pub quarantined: usize,
    /// Every address the hand-out run holds.
    pub capacity: u64,
    /// How long until the soonest returned address's quarantine passes,
    /// when one was returned at all.
    pub next_free_in: Option<Duration>,
}

impl std::fmt::Display for HandOutCounts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} of {} box addresses are held by live boxes and {} are in their {} s reuse \
             quarantine",
            self.live,
            self.capacity,
            self.quarantined,
            SWITCH_REUSE_QUARANTINE.as_secs()
        )?;
        if let Some(wait) = self.next_free_in {
            // Rounded up: an address that frees in 0.4 s is not free now.
            let secs = wait
                .as_secs()
                .saturating_add(u64::from(wait.subsec_nanos() > 0));
            write!(f, "; the next one frees in {} s", secs.max(1))?;
        }
        Ok(())
    }
}

impl SwitchAddressBook {
    fn new(subnet: SwitchSubnet) -> Self {
        let (first, last) = hand_out_run(subnet);
        Self {
            first,
            last,
            next: (first <= last).then_some(first),
            out: BTreeSet::new(),
            free: VecDeque::new(),
        }
    }

    /// Draws an address at `now`: a never-drawn one first, then the
    /// returned address free longest whose eligibility has passed and that
    /// `held` does not name. Hands nothing, and says where the run stands,
    /// when no address qualifies.
    fn draw(
        &mut self,
        now: Instant,
        held: impl Fn(Ipv4Addr) -> bool,
    ) -> Result<Ipv4Addr, HandOutCounts> {
        // A never-drawn address a row took by name ([`Self::take`]) is out
        // or returned already, never the cursor's to hand.
        while let Some(next) = self.next {
            self.next = next.checked_add(1).filter(|after| *after <= self.last);
            if !self.free.iter().any(|&(addr, ..)| addr == next) && self.out.insert(next) {
                return Ok(Ipv4Addr::from(next));
            }
        }
        let reusable = self
            .free
            .iter()
            .position(|&(addr, eligible, _)| now >= eligible && !held(Ipv4Addr::from(addr)));
        if let Some((addr, ..)) = reusable.and_then(|at| self.free.remove(at)) {
            self.out.insert(addr);
            return Ok(Ipv4Addr::from(addr));
        }
        Err(HandOutCounts {
            live: self.out.len(),
            quarantined: self.free.len(),
            capacity: u64::from(self.last)
                .saturating_sub(u64::from(self.first))
                .saturating_add(1),
            next_free_in: self
                .free
                .iter()
                .map(|&(_, eligible, _)| eligible.saturating_duration_since(now))
                .filter(|wait| !wait.is_zero())
                .min(),
        })
    }

    /// How many addresses draws at `now` could still hand, by the rules
    /// [`Self::draw`] keeps: the run's never-drawn addresses, and the
    /// returned ones whose eligibility has passed that `held` does not
    /// hold. The task-slot floor ([`TASK_SLOT_FLOOR`]) is measured on it.
    fn spare(&self, now: Instant, held: impl Fn(Ipv4Addr) -> bool) -> usize {
        let never_drawn = self.next.map_or(0, |next| {
            let ahead = usize::try_from(self.last - next).map_or(usize::MAX, |n| n + 1);
            let taken = self.out.range(next..).count()
                + self.free.iter().filter(|&&(addr, ..)| addr >= next).count();
            ahead.saturating_sub(taken)
        });
        let reusable = self
            .free
            .iter()
            .filter(|&&(addr, eligible, _)| now >= eligible && !held(Ipv4Addr::from(addr)))
            .count();
        never_drawn + reusable
    }

    /// Returns `addr` at `now` from the box `returned_by`, quarantined
    /// unless `quarantine` is false. Only an address this book drew and has
    /// not had back is returned: one an explicit registration brought
    /// ([`BoxRegistry::try_register`]) is not the run's to hand, and a
    /// second return is a no-op. An eligibility past the clock's range
    /// keeps the address out for good — the fail-closed reading of an
    /// overflow, never a wrap to an early one. Returns whether the address
    /// came back.
    fn give_back(
        &mut self,
        addr: Ipv4Addr,
        now: Instant,
        quarantine: bool,
        returned_by: BoxId,
    ) -> bool {
        let addr = u32::from(addr);
        let eligible = if quarantine {
            now.checked_add(SWITCH_REUSE_QUARANTINE)
        } else {
            Some(now)
        };
        let Some(eligible) = eligible else {
            return false;
        };
        if !self.out.remove(&addr) {
            return false;
        }
        self.free.push_back((addr, eligible, returned_by));
        true
    }

    /// Takes `addr` itself out for the box `taker`, at `now`: the draw a
    /// creation reloaded at start makes for its own addresses
    /// ([`BoxRegistry::persisting_to`]). An
    /// address inside the run that is not out is taken: a never-drawn one,
    /// a returned one whose eligibility has passed, or a returned one
    /// inside its quarantine when `taker` is the box that returned it —
    /// the state the quarantine guards is that box's own. Refused for an
    /// address outside the run, one already out, and one another box
    /// returned inside its quarantine. Returns whether it was taken.
    fn take(&mut self, addr: Ipv4Addr, now: Instant, taker: BoxId) -> bool {
        let addr = u32::from(addr);
        if addr < self.first || addr > self.last || self.out.contains(&addr) {
            return false;
        }
        if let Some(at) = self.free.iter().position(|&(free, ..)| free == addr) {
            let (_, eligible, returned_by) = self.free[at];
            if now < eligible && returned_by != taker {
                return false;
            }
            self.free.remove(at);
        }
        self.out.insert(addr);
        true
    }
}

/// Why a client-driven registration could not be allocated. Both runs a
/// box address comes from — the plan's switch lease run and the published
/// loopback slice — are finite; exhausting one is an answer to hand back
/// over the control socket, not a panic.
///
/// Not `Copy`: every variant that names a box carries its [`String`] name,
/// and the refusal is built once, answered with, and dropped.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AllocationError {
    /// Every switch address in the hand-out run is out or not yet eligible
    /// again: held by a live row or a registration in flight, or returned
    /// and still inside its reuse quarantine ([`SwitchAddressBook`]). The
    /// counts say which, so the refusal tells an exhausted plan from one
    /// that frees an address shortly.
    #[error("{}: {}", minimald_rpc::SWITCH_PLAN_EXHAUSTED, .0)]
    SwitchExhausted(HandOutCounts),
    /// Every address in the loopback slice this subnet's switch publishes
    /// at is handed out.
    #[error(
        "{}; no published address remains",
        minimald_rpc::LOOPBACK_SLICE_EXHAUSTED
    )]
    LoopbackExhausted,
    /// The address plan does not serve this registry's subnet, so no box
    /// address can be allocated against it. An explicit registration
    /// ([`BoxRegistry::try_register`]) still works: it brings its own
    /// addresses.
    #[error("the address plan does not serve subnet {0}; no box address can be allocated")]
    UnplannedSubnet(SwitchSubnet),
    /// The id minted for the registration is already held by a live row or
    /// attachment: one id names one box (BEP-070), so the registration is
    /// refused — never re-minted — before any address is spent, so the
    /// refusal leaves no new fact on the host.
    #[error(
        "box id {} is already held by a live row or attachment",
        crate::bep_attach::BoxIdText(id)
    )]
    CollidingBoxId {
        /// The id a live row or attachment already holds.
        id: BoxId,
    },
    /// The address is still held by a withdrawn box's revocation: the host
    /// has not finished unbinding the forwards that box published there
    /// (design §7.1). A row at the address now would receive the old box's
    /// forwarded connections, or have its own forwards unbound at the old
    /// box's end, so the registration is refused instead.
    #[error(
        "address {addr} is still held by a withdrawn box whose forwards the host has not \
         finished unbinding"
    )]
    RevocationPending {
        /// The held address: a switch address or a published loopback one.
        addr: Ipv4Addr,
    },
    /// A withdrawal under the box's name landed while the answerer was
    /// allocating its published address: the withdrawal is ordered after
    /// the registration was read, so the registration writes no row.
    #[error("the box was withdrawn while its address was being allocated")]
    WithdrawnWhileAllocating,
    /// The name folds to one a live row already holds: the answerer keys
    /// an address by the name's canonical form
    /// ([`crate::net::answerer::canonical_box_name`]), so two rows under
    /// folded-equal names would share one published address — one box, one
    /// address, one row. The registration is refused before any address is
    /// spent, and names the spelling the live row holds.
    ///
    /// Box names are DNS labels under `min.internal`, and DNS compares
    /// names case-insensitively (RFC 4343); the answerer already keys this
    /// way and session names are unique under the same fold, so one row per
    /// name (NET-138) means one row per folded name.
    #[error("a box named {held} already exists")]
    NameAlreadyHeld {
        /// The name the live row holds, in its registered spelling: the
        /// one the refusal reports back to the asking client.
        held: String,
    },
}

/// One box name's registration bookkeeping: how many registrations of it
/// are in flight — between reading the generation and the end of their
/// turn — and how many withdrawals under the name landed while they were.
/// A registration is refused when the generation moved past the one it
/// read ([`BoxRegistry::register_client_box_since`]).
#[derive(Debug, Default)]
pub struct NameRegistrations {
    generation: u64,
    in_flight: u32,
}

fn lock_generations(
    generations: &Mutex<HashMap<String, NameRegistrations>>,
) -> MutexGuard<'_, HashMap<String, NameRegistrations>> {
    generations
        .lock()
        .expect("the withdrawal generations' lock is held only across a map read or update")
}

/// One registration of a box name in flight
/// ([`BoxRegistry::begin_registration`]). Dropping it ends the count, and
/// the name's entry goes with its last registration, so the map holds only
/// names with a registration in flight.
#[derive(Debug)]
pub struct RegistrationClaim {
    generations: Arc<Mutex<HashMap<String, NameRegistrations>>>,
    /// The box's name in [`canonical_box_name`] form: the map's key.
    key: String,
    generation: u64,
}

impl RegistrationClaim {
    /// The name's withdrawal generation when the registration began.
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.generation
    }
}

impl Drop for RegistrationClaim {
    fn drop(&mut self) {
        let mut generations = lock_generations(&self.generations);
        if let Some(entry) = generations.get_mut(&self.key) {
            entry.in_flight = entry.in_flight.saturating_sub(1);
            if entry.in_flight == 0 {
                generations.remove(&self.key);
            }
        }
    }
}

/// Why a creator's resume of its box's row was refused
/// ([`BoxRegistry::resume_client_box`]). Every refusal leaves the table as
/// it was: no row, no spent address.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ResumeError {
    /// The registry keeps no creation under the name: the box was never
    /// registered on this host, its creator withdrew it, or a newer
    /// registration took the name.
    #[error("no box {name:?} is registered on this host to resume")]
    NoCreation {
        /// The name the resume presented.
        name: String,
    },
    /// The creation under the name was handed another pair than the one
    /// presented: not the resuming client's box.
    #[error(
        "box {name:?} was handed switch address {held_switch} and loopback address \
         {held_loopback}, not the pair the resume presented"
    )]
    NotTheHandedPair {
        /// The name the resume presented.
        name: String,
        /// The switch address the creation holds.
        held_switch: Ipv4Addr,
        /// The loopback address the creation holds.
        held_loopback: Ipv4Addr,
    },
    /// The creation under the name is another box than the id the resume
    /// named: a newer creation took the name and its addresses.
    #[error(
        "box {name:?} is box id {}, not the {} the resume named",
        crate::bep_attach::BoxIdText(held_box_id),
        crate::bep_attach::BoxIdText(asked_box_id)
    )]
    NotTheBoxId {
        /// The name the resume presented.
        name: String,
        /// The id the creation holds.
        held_box_id: BoxId,
        /// The id the resume named.
        asked_box_id: BoxId,
    },
    /// The answerer handed the name another published address than the
    /// one the box was created with: the box's address moved while it had
    /// no row, and a row at the old one would answer for an address the
    /// box no longer holds.
    #[error(
        "box {name:?} was created at loopback address {held}, but the answerer now holds \
         {allocated} for it"
    )]
    LoopbackMoved {
        /// The name the resume presented.
        name: String,
        /// The loopback address the creation holds.
        held: Ipv4Addr,
        /// The address the answerer allocated for the name now.
        allocated: Ipv4Addr,
    },
    /// The row could not be published at the box's addresses.
    #[error(transparent)]
    Allocation(#[from] AllocationError),
}

/// What a resume finds before anything is allocated for it
/// ([`BoxRegistry::resumable`]).
#[derive(Debug)]
pub enum Resumable {
    /// The creation's row stands: the resume's answer, as it stands.
    Standing(Arc<BoxRecord>),
    /// The creation is dormant: its row is reinstated under `name`, the
    /// name it was registered under, which the answerer holds its
    /// published address by.
    Dormant {
        /// The creation's own name.
        name: String,
    },
}

/// The row that stands for `creation`, when one does: the row at its
/// switch address, of its box id.
fn standing_row_of<'rows>(rows: &'rows Rows, creation: &Creation) -> Option<&'rows Arc<BoxRecord>> {
    rows.get(&creation.switch_address.octets())
        .filter(|record| record.box_id == creation.id() && !record.is_task_row())
}

/// Why a client-driven withdrawal was refused. The pair a withdrawal
/// presents is the proof that its client is the row's creator (T66), so a
/// refusal is the daemon saying the proof does not match the row the
/// switch address publishes — never a failure of the goal state, which
/// [`BoxRegistry::withdraw_client_box`] reports as `Ok(None)`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WithdrawError {
    /// A row is published at the switch address under another box's name:
    /// the requesting client is not its creator.
    #[error(
        "the row at switch address {switch_addr} is held by box {held_name:?}, \
         not by the withdrawing {asked_name:?}"
    )]
    NotTheCreatorsRow {
        /// The switch address the withdrawal named.
        switch_addr: Ipv4Addr,
        /// The name the published row carries.
        held_name: String,
        /// The name the withdrawal presented.
        asked_name: String,
    },
    /// The row at the switch address carries the requested name but another
    /// loopback address than the pair presented: not the pair the
    /// registration handed back.
    #[error(
        "the row at switch address {switch_addr} carries loopback address \
         {held_loopback}, not the {asked_loopback} the withdrawal presented"
    )]
    NotTheHandedPair {
        /// The switch address the withdrawal named.
        switch_addr: Ipv4Addr,
        /// The loopback address the published row carries.
        held_loopback: Ipv4Addr,
        /// The loopback address the withdrawal presented.
        asked_loopback: Ipv4Addr,
    },
    /// The row at the switch address carries the requested name and pair
    /// but another box id than the withdrawal named: a newer creation was
    /// handed the same name and addresses since, and the withdrawing client
    /// is the creator of the row before it, not of this one.
    #[error(
        "the row at switch address {switch_addr} is box id {}, not the {} the withdrawal \
         named; it is a newer box under the same name and addresses",
        crate::bep_attach::BoxIdText(held_box_id),
        crate::bep_attach::BoxIdText(asked_box_id)
    )]
    NotTheBoxId {
        /// The switch address the withdrawal named.
        switch_addr: Ipv4Addr,
        /// The id the published row holds.
        held_box_id: BoxId,
        /// The id the withdrawal named.
        asked_box_id: BoxId,
    },
}

/// Why an admit report was refused against the host-held grant (NET-138):
/// the one refusal the in-VM daemon's publish unwinds by. Every variant
/// names the box whose row was asked about — except the first, which names
/// the address no row answered at, because the box is exactly what the
/// report could not prove — and the port and protocol the report carried,
/// so the refusal the guest unwinds its publish on says what was refused
/// and which check refused it, in one sentence the wire carries verbatim.
///
/// Refused reports record nothing: not the port, not a rate timestamp, not
/// a fact the host did not already hold. Not `Copy`: every variant that
/// names a box carries its [`String`] name, and the refusal is built once,
/// answered with, and dropped.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PortReportRefusal {
    /// No row is held at the switch address the report named — the box was
    /// never registered, its row was withdrawn, or the daemon restarted
    /// since: the guest cannot invent a row by reporting at an address.
    #[error(
        "no box row is held at switch address {switch_addr}; the reported port {port} \
         records nowhere"
    )]
    NoRow {
        /// The switch address the report named.
        switch_addr: Ipv4Addr,
        /// The port the report carried.
        port: u16,
        /// The protocol the report carried.
        proto: IpProto,
    },
    /// The row's dynamic-ingress stance is `deny` — or the declaration
    /// carried no stance, its default — which admits no runtime port.
    #[error("box {name} declared dynamic ingress deny; its runtime port reports record nothing")]
    DenyStance {
        /// The name the row was registered under.
        name: String,
        /// The port the report carried.
        port: u16,
        /// The protocol the report carried.
        proto: IpProto,
    },
    /// The row's stance is `ask`, and a guest's admit report is not the
    /// attached human's yes: an `ask` admission records only from the host
    /// side, where the answer is seen, so the guest's report records
    /// nothing under it.
    #[error(
        "box {name} declared dynamic ingress ask; ask-yes must be host-recorded, so the \
         guest's report of port {port} records nothing"
    )]
    AskNotHostRecorded {
        /// The name the row was registered under.
        name: String,
        /// The port the report carried.
        port: u16,
        /// The protocol the report carried.
        proto: IpProto,
    },
    /// The row's stance is `allow` but its declaration named no allowed
    /// range, and an absent range permits nothing.
    #[error("box {name} declared no dynamic allowed range; no runtime port is permitted")]
    NoAllowedRange {
        /// The name the row was registered under.
        name: String,
        /// The port the report carried.
        port: u16,
        /// The protocol the report carried.
        proto: IpProto,
    },
    /// The reported port is outside the row's allowed range, inclusive at
    /// both ends.
    #[error(
        "runtime port {port} is outside box {name}'s allowed range \
         {}-{}",
        range.0,
        range.1
    )]
    OutsideAllowedRange {
        /// The name the row was registered under.
        name: String,
        /// The port the report carried.
        port: u16,
        /// The protocol the report carried.
        proto: IpProto,
        /// The row's allowed range, inclusive at both ends.
        range: (u16, u16),
    },
    /// The row already holds the per-row cap of runtime-admitted ports
    /// ([`RUNTIME_PORT_CAP`]).
    #[error(
        "box {name} already holds {cap} runtime-admitted ports, its per-row cap; \
         the reported port {port} records nothing"
    )]
    RowCapReached {
        /// The name the row was registered under.
        name: String,
        /// The port the report carried.
        port: u16,
        /// The protocol the report carried.
        proto: IpProto,
        /// The cap the row reached.
        cap: usize,
    },
    /// The row is over its per-row admit rate
    /// ([`ROW_ADMIT_RATE_PER_SECOND`] per trailing second).
    #[error(
        "box {name} is over its per-row admit rate ({rate} per second); the reported \
         port {port} records nothing"
    )]
    RateExceeded {
        /// The name the row was registered under.
        name: String,
        /// The port the report carried.
        port: u16,
        /// The protocol the report carried.
        proto: IpProto,
        /// The rate the row is over.
        rate: usize,
    },
}

/// The per-row bound on pending asks (NET-045): a row's ask queue holds at
/// most this many asks — the offered one and those waiting behind it — so a
/// guest that asks in a loop cannot grow a row's ask state without limit.
/// The honest reporter asks at most once per exposure, and the queue exists
/// for the exposures that overlap the dialog a row already holds open; past
/// the bound the guest's ask is refused at once, so the exposure answers
/// its own refusal rather than waiting behind a wall of asks.
pub(crate) const PENDING_ASKS_PER_ROW: usize = 8;

/// Mints the id one pending ask is named by (NET-045): one UUIDv4 — all
/// random, no timestamp, because an ask is an event, not an entity with a
/// creation order to keep — with its bytes from the host's OS CSPRNG and
/// from nothing the guest could observe, predict or arrange. The offer
/// hands the id to the attached host client and the recorded answer
/// carries it back; an answer for an id the book does not hold pending is
/// refused, and a resolved id leaves the book for good, so no id is ever
/// answered twice.
fn mint_ask_id() -> minimald_rpc::AskId {
    minimald_rpc::AskId::from_bytes(uuid::Uuid::new_v4().into_bytes())
}

/// One pending ask's host-sourced facts (NET-045): what a dialog, a log
/// line and an audit line name the ask by. The name, the box id and the
/// switch address are copied from the host row at record time; the port
/// and the protocol are the two fields the guest's ask carries. Nothing
/// else the guest could say reaches them, so the offer's dialog text is
/// built from the host row alone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AskFacts {
    /// The box's name, from the host's own row.
    pub(crate) name: String,
    /// The row's box id: the host-minted identity clients subscribe by.
    pub(crate) box_id: BoxId,
    /// The row's switch address: the ask's own row key.
    pub(crate) switch_address: Ipv4Addr,
    /// The port the exposure asks to publish.
    pub(crate) port: u16,
    /// The protocol the port would publish under.
    pub(crate) proto: IpProto,
}

impl AskFacts {
    /// The offer an attached client renders its dialog from.
    fn offer(&self, ask_id: minimald_rpc::AskId) -> minimald_rpc::BoxControlReply {
        minimald_rpc::BoxControlReply::PendingAskOffer(minimald_rpc::PendingAskOffer {
            ask_id,
            box_id: minimald_rpc::BoxId::from_bytes(self.box_id),
            name: self.name.clone(),
            port: self.port,
            proto: self.proto,
        })
    }
}

/// One pending ask as the book holds it: its facts and the sending end of
/// the guest's outcome channel. The end is sent once, by whichever of an
/// answer or a cancellation removes the ask from the book first. No timer
/// ever touches it.
struct PendingAsk {
    facts: AskFacts,
    reply: std::sync::mpsc::Sender<minimald_rpc::AskAdmitOutcome>,
}

/// One attached host client's subscription: the push channel its serving
/// thread writes to the client, keyed by an id so the client's own detach
/// removes exactly its own entry. Only the detach removes an entry; a push
/// that fails is not counted as delivered, and the client's serving thread
/// unsubscribes it on its way out.
struct AskSubscriber {
    id: u64,
    pushes: std::sync::mpsc::Sender<minimald_rpc::BoxControlReply>,
}

/// The host's record of pending asks (NET-045), held by the registry beside
/// the rows it asks about:
///
/// * the pending asks by their host-minted id; resolving an ask removes it,
///   so the first recorded answer is the only one an id ever takes;
/// * each row's queue of them in arrival order, keyed by switch address.
///   The front is the one offered: one dialog at a time per row, the rest
///   waiting behind it within [`PENDING_ASKS_PER_ROW`];
/// * the attached host clients by the box id of the row each subscribed
///   to, never a name.
///
/// Lock order: a path that reads the rows takes the row lock first and the
/// book second, and no path takes them the other way round; a recorded
/// yes takes the row's runtime lock innermost.
#[derive(Default)]
struct AskBook {
    pending: std::collections::HashMap<minimald_rpc::AskId, PendingAsk>,
    queues: std::collections::HashMap<[u8; 4], VecDeque<minimald_rpc::AskId>>,
    subscribers: std::collections::HashMap<BoxId, Vec<AskSubscriber>>,
    next_subscriber: u64,
    /// The most recent ends, oldest first, bounded at
    /// [`ENDED_ASKS_REMEMBERED`]: what a late answer for an ended ask is
    /// told instead of a bare refusal. Never consulted to admit anything.
    ended: VecDeque<EndedAsk>,
}

/// How many ended asks the book remembers for late answers (NET-045). An
/// answer that arrives after its ask's end was evicted is refused as an
/// unknown id, which admits nothing either.
pub(crate) const ENDED_ASKS_REMEMBERED: usize = 256;

/// One ended ask as the book remembers it for a late answer.
#[derive(Debug, Clone, Copy)]
struct EndedAsk {
    ask_id: minimald_rpc::AskId,
    port: u16,
    proto: IpProto,
    end: minimald_rpc::AskLateEnd,
}

/// Why a recorded answer was refused (NET-045). Neither records anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AnswerRefusal {
    /// The book never minted the id, or its end has been forgotten.
    UnknownId,
    /// The ask already ended: how, and what it was about.
    AlreadyEnded {
        port: u16,
        proto: IpProto,
        end: minimald_rpc::AskLateEnd,
    },
}

/// How an outcome reads to a late answer: allowed only when admitted,
/// denied for a no or a no-tty, and every other end as the cancellation it
/// is — a yes the row could no longer take included, since its row went.
fn late_end(outcome: &minimald_rpc::AskAdmitOutcome) -> minimald_rpc::AskLateEnd {
    use minimald_rpc::{AskCancelCause, AskLateEnd, AskRefused};
    match outcome {
        minimald_rpc::AskAdmitOutcome::Admitted { .. } => AskLateEnd::Allowed,
        minimald_rpc::AskAdmitOutcome::Refused {
            reason: AskRefused::Denied | AskRefused::NoTty,
            ..
        } => AskLateEnd::Denied,
        minimald_rpc::AskAdmitOutcome::Refused { cause, .. } => AskLateEnd::Cancelled {
            cause: cause.unwrap_or(AskCancelCause::RowWithdrawn),
        },
    }
}

/// A count of live connections of one kind, with an optional cap: the ask
/// verbs' threads (NET-045) are bounded by it, and a graceful stop waits on
/// one to reach zero.
#[derive(Debug, Default)]
pub(crate) struct ConnectionGauge {
    count: Mutex<usize>,
    idle: std::sync::Condvar,
}

/// One counted connection; the count drops with the guard.
#[derive(Debug)]
pub(crate) struct GaugeGuard(Arc<ConnectionGauge>);

impl Drop for GaugeGuard {
    fn drop(&mut self) {
        let mut count = self
            .0
            .count
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *count = count.saturating_sub(1);
        if *count == 0 {
            self.0.idle.notify_all();
        }
    }
}

impl ConnectionGauge {
    /// Count one more connection, unless `cap` are already counted.
    pub(crate) fn try_acquire(self: &Arc<Self>, cap: usize) -> Option<GaugeGuard> {
        let mut count = self
            .count
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if *count >= cap {
            return None;
        }
        *count += 1;
        Some(GaugeGuard(Arc::clone(self)))
    }

    /// Wait until nothing is counted, at most `bound`; whether it emptied.
    pub(crate) fn wait_idle(&self, bound: std::time::Duration) -> bool {
        let count = self
            .count
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (count, _) = self
            .idle
            .wait_timeout_while(count, bound, |count| *count > 0)
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *count == 0
    }
}

/// The held connections' gauges, shared by every clone of a registry: the
/// ask verbs' (NET-045) guest-door ask connections and host subscriptions,
/// and the held registrations' lease connections
/// ([`minimald_rpc::RegisterBoxRequest::hold`]), each capped by the door,
/// and the asks whose end is not yet audited, which a graceful stop waits
/// on.
#[derive(Debug)]
pub(crate) struct AskGauges {
    pub(crate) guest_asks: Arc<ConnectionGauge>,
    pub(crate) subscriptions: Arc<ConnectionGauge>,
    pub(crate) leases: Arc<ConnectionGauge>,
    pub(crate) unaudited: Arc<ConnectionGauge>,
    guest_ask_cap: std::sync::atomic::AtomicUsize,
    subscription_cap: std::sync::atomic::AtomicUsize,
    lease_cap: std::sync::atomic::AtomicUsize,
}

impl Default for AskGauges {
    fn default() -> Self {
        Self {
            guest_asks: Arc::default(),
            subscriptions: Arc::default(),
            leases: Arc::default(),
            unaudited: Arc::default(),
            guest_ask_cap: crate::control::MAX_GUEST_ASK_CONNECTIONS.into(),
            subscription_cap: crate::control::MAX_ASK_SUBSCRIPTIONS.into(),
            lease_cap: crate::control::MAX_REGISTRATION_LEASES.into(),
        }
    }
}

impl AskGauges {
    /// The guest-door ask connection cap.
    pub(crate) fn guest_ask_cap(&self) -> usize {
        self.guest_ask_cap.load(Ordering::Relaxed)
    }

    /// The host subscription cap.
    pub(crate) fn subscription_cap(&self) -> usize {
        self.subscription_cap.load(Ordering::Relaxed)
    }

    /// Lower both caps, so a test can fill them.
    #[cfg(test)]
    pub(crate) fn set_caps(&self, guest_asks: usize, subscriptions: usize) {
        self.guest_ask_cap.store(guest_asks, Ordering::Relaxed);
        self.subscription_cap
            .store(subscriptions, Ordering::Relaxed);
    }

    /// The held registrations' lease connection cap.
    pub(crate) fn lease_cap(&self) -> usize {
        self.lease_cap.load(Ordering::Relaxed)
    }

    /// Lower the lease cap, so a test can fill it.
    #[cfg(test)]
    pub(crate) fn set_lease_cap(&self, leases: usize) {
        self.lease_cap.store(leases, Ordering::Relaxed);
    }
}

/// Counts, not contents: the reply and push channels have no useful debug
/// form, and the ids and facts are what the log lines carry.
impl std::fmt::Debug for AskBook {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AskBook")
            .field("pending", &self.pending.len())
            .field("rows", &self.queues.len())
            .field("subscribed_boxes", &self.subscribers.len())
            .finish()
    }
}

impl AskBook {
    /// Push `message` to the clients attached to `box_id` — every one, or
    /// only the subscriber `only` names — and answer how many took it.
    fn push(
        &self,
        box_id: &BoxId,
        message: &minimald_rpc::BoxControlReply,
        only: Option<u64>,
    ) -> usize {
        self.subscribers.get(box_id).map_or(0, |clients| {
            clients
                .iter()
                .filter(|client| only.is_none_or(|id| client.id == id))
                .filter(|client| client.pushes.send(message.clone()).is_ok())
                .count()
        })
    }

    /// Whether any client is attached to `box_id`.
    fn has_client(&self, box_id: &BoxId) -> bool {
        self.subscribers
            .get(box_id)
            .is_some_and(|clients| !clients.is_empty())
    }

    /// Offer the ask at the front of the row's queue to every attached
    /// client, when the queue holds one.
    fn offer_front(&self, switch_address: Ipv4Addr) -> Option<AskOffered> {
        let ask_id = *self.queues.get(&switch_address.octets())?.front()?;
        let facts = &self.pending.get(&ask_id)?.facts;
        let offered_to = self.push(&facts.box_id, &facts.offer(ask_id), None);
        Some(AskOffered {
            ask_id,
            facts: facts.clone(),
            offered_to,
        })
    }

    /// End one pending ask with `outcome`: remove it from the book and its
    /// row's queue, answer the guest's held reply, dismiss the dialogs still
    /// showing it, and offer the row's next queued ask when the ended one
    /// was the row's offered dialog. `None` when the book does not hold the
    /// ask: it was already answered, cancelled, or never minted.
    fn end(
        &mut self,
        ask_id: minimald_rpc::AskId,
        outcome: impl FnOnce(&AskFacts) -> minimald_rpc::AskAdmitOutcome,
    ) -> Option<AskEnded> {
        let pending = self.pending.remove(&ask_id)?;
        let key = pending.facts.switch_address.octets();
        let mut was_front = false;
        if let Some(queue) = self.queues.get_mut(&key) {
            was_front = queue.front() == Some(&ask_id);
            queue.retain(|queued| *queued != ask_id);
            if queue.is_empty() {
                self.queues.remove(&key);
            }
        }
        let outcome = outcome(&pending.facts);
        if self.ended.len() >= ENDED_ASKS_REMEMBERED {
            self.ended.pop_front();
        }
        self.ended.push_back(EndedAsk {
            ask_id,
            port: pending.facts.port,
            proto: pending.facts.proto,
            end: late_end(&outcome),
        });
        // The guest may already be gone; its connection's end is its own
        // cancellation, and there is nothing left to tell it.
        let _ = pending.reply.send(outcome);
        let dismissed = if was_front {
            self.push(
                &pending.facts.box_id,
                &minimald_rpc::BoxControlReply::PendingAskDismissed {
                    ask_id,
                    dismissed: true,
                },
                None,
            )
        } else {
            0
        };
        let offered_next = if was_front {
            self.offer_front(pending.facts.switch_address)
        } else {
            None
        };
        Some(AskEnded {
            ask_id,
            facts: pending.facts,
            outcome,
            dismissed,
            offered_next,
        })
    }

    /// How a recorded answer for an ask the book no longer holds is
    /// refused: with the ask's remembered end, or as an unknown id.
    fn late_refusal(&self, ask_id: minimald_rpc::AskId) -> AnswerRefusal {
        self.ended
            .iter()
            .rev()
            .find(|ended| ended.ask_id == ask_id)
            .map_or(AnswerRefusal::UnknownId, |ended| {
                AnswerRefusal::AlreadyEnded {
                    port: ended.port,
                    proto: ended.proto,
                    end: ended.end,
                }
            })
    }

    /// End every pending ask the predicate selects as cancelled by `cause`.
    fn cancel_where(
        &mut self,
        select: impl Fn(&AskFacts) -> bool,
        cause: minimald_rpc::AskCancelCause,
    ) -> Vec<AskEnded> {
        let ids: Vec<minimald_rpc::AskId> = self
            .pending
            .iter()
            .filter(|(_, pending)| select(&pending.facts))
            .map(|(ask_id, _)| *ask_id)
            .collect();
        ids.into_iter()
            .filter_map(|ask_id| self.end(ask_id, |_| cancelled(ask_id, cause)))
            .collect()
    }
}

/// The cancelled end of `ask_id`, by `cause`.
fn cancelled(
    ask_id: minimald_rpc::AskId,
    cause: minimald_rpc::AskCancelCause,
) -> minimald_rpc::AskAdmitOutcome {
    minimald_rpc::AskAdmitOutcome::Refused {
        ask_id,
        reason: minimald_rpc::AskRefused::Cancelled,
        cause: Some(cause),
    }
}

/// An ask offered to the clients attached to its row (NET-045): what the
/// door's log and audit lines record the offer by.
#[derive(Debug, Clone)]
pub(crate) struct AskOffered {
    /// The ask's own id.
    pub(crate) ask_id: minimald_rpc::AskId,
    /// The host-sourced facts the dialog is built from.
    pub(crate) facts: AskFacts,
    /// How many attached clients the offer reached.
    pub(crate) offered_to: usize,
}

/// An ask the book recorded pending (NET-045). `offered` is the offer when
/// the ask became the row's offered dialog at once, and `None` when it
/// waits behind the one the row already holds open; it is offered when it
/// reaches the front, by whichever path ends the ask ahead of it.
#[derive(Debug)]
pub(crate) struct AskRecorded {
    /// The ask's host-minted id.
    pub(crate) ask_id: minimald_rpc::AskId,
    /// The ask's host-sourced facts.
    pub(crate) facts: AskFacts,
    /// The offer, when the ask is the row's offered dialog.
    pub(crate) offered: Option<AskOffered>,
}

/// Why the book refused to record an ask (NET-045): the minted id the
/// refusal is audited under, the host row's facts where a row exists at the
/// named address, and the typed reason the guest's exposure is refused
/// with.
#[derive(Debug)]
pub(crate) struct AskRecordRefusal {
    /// The id minted for the refused ask; never offered, never answerable.
    pub(crate) ask_id: minimald_rpc::AskId,
    /// The host row's facts; `None` when no row is held at the address.
    pub(crate) facts: Option<AskFacts>,
    /// Why the ask was refused.
    pub(crate) reason: minimald_rpc::AskRefused,
}

/// A pending ask's end (NET-045), by a recorded answer or a cancellation:
/// the outcome the guest's held reply was answered with, how many dialogs
/// were dismissed, and the row's next ask when one was offered in its
/// place.
#[derive(Debug)]
pub(crate) struct AskEnded {
    /// The ended ask's id.
    pub(crate) ask_id: minimald_rpc::AskId,
    /// The ended ask's host-sourced facts.
    pub(crate) facts: AskFacts,
    /// The outcome the guest's held reply was answered with.
    pub(crate) outcome: minimald_rpc::AskAdmitOutcome,
    /// How many attached clients the ended dialog was dismissed from.
    pub(crate) dismissed: usize,
    /// The row's next queued ask, offered now that this one ended.
    pub(crate) offered_next: Option<AskOffered>,
}

impl BoxRegistry {
    /// Record the in-VM daemon's ask (NET-045): mint the ask's id, check the
    /// ask against the host row, queue it on the row, and offer it to every
    /// client attached to the row's box id when it is the row's front.
    /// `reply` is the sending end of the guest's outcome channel; the book
    /// sends the ask's end on it once, on the first answer or cancellation,
    /// and never on a timer.
    ///
    /// The checks, in order: a row is held at the address
    /// ([`minimald_rpc::AskRefused::NoRow`]); its stance is `ask`
    /// ([`minimald_rpc::AskRefused::StanceNotAsk`]); its range admits the
    /// port ([`minimald_rpc::AskRefused::OutsideGrant`]), so no client is
    /// asked about a publish the grant would refuse anyway; a client is
    /// attached to answer ([`minimald_rpc::AskRefused::NoClient`]); and the
    /// row's queue is inside its bound
    /// ([`minimald_rpc::AskRefused::QueueFull`]). A refusal records nothing
    /// and drops `reply` unsent: the refusal is the caller's answer.
    pub(crate) fn record_ask(
        &self,
        switch_addr: Ipv4Addr,
        port: u16,
        proto: IpProto,
        reply: std::sync::mpsc::Sender<minimald_rpc::AskAdmitOutcome>,
    ) -> Result<AskRecorded, AskRecordRefusal> {
        let ask_id = mint_ask_id();
        let refuse = |facts: Option<AskFacts>, reason| AskRecordRefusal {
            ask_id,
            facts,
            reason,
        };
        let rows = self
            .rows
            .read()
            .expect("the row lock is never held across a panic, so it cannot be poisoned");
        let Some(record) = rows.get(&switch_addr.octets()) else {
            return Err(refuse(None, minimald_rpc::AskRefused::NoRow));
        };
        let facts = AskFacts {
            name: record.name().to_string(),
            box_id: record.box_id(),
            switch_address: record.switch_addr(),
            port,
            proto,
        };
        if record.dynamic_ingress() != DynamicIngress::Ask {
            return Err(refuse(Some(facts), minimald_rpc::AskRefused::StanceNotAsk));
        }
        if !in_range(record.dynamic_range(), port) {
            return Err(refuse(Some(facts), minimald_rpc::AskRefused::OutsideGrant));
        }
        let mut book = self
            .asks
            .lock()
            .expect("the ask book's lock is never held across a panic");
        drop(rows);
        if !book.has_client(&facts.box_id) {
            return Err(refuse(Some(facts), minimald_rpc::AskRefused::NoClient));
        }
        let queue = book.queues.entry(switch_addr.octets()).or_default();
        if queue.len() >= PENDING_ASKS_PER_ROW {
            return Err(refuse(Some(facts), minimald_rpc::AskRefused::QueueFull));
        }
        let is_front = queue.is_empty();
        queue.push_back(ask_id);
        book.pending.insert(
            ask_id,
            PendingAsk {
                facts: facts.clone(),
                reply,
            },
        );
        let offered = if is_front {
            book.offer_front(switch_addr)
        } else {
            None
        };
        Ok(AskRecorded {
            ask_id,
            facts,
            offered,
        })
    }

    /// Record a host client's answer for one pending ask (NET-045). The ask
    /// is removed from the book before its outcome is decided, so the first
    /// answer is the only one it takes and a second finds nothing.
    ///
    /// A yes records the ask's port in the row the table holds now, inside
    /// the grant ([`record_ask_yes`]), and answers the guest's held reply
    /// [`minimald_rpc::AskAdmitOutcome::Admitted`]: that reply is the one
    /// admit the yes is consumed by. A no and a no-tty record nothing: the
    /// ask leaves the book, and nothing is stored that could later count as
    /// a yes.
    ///
    /// # Errors
    ///
    /// [`AnswerRefusal`] when the book holds no pending ask under `ask_id`:
    /// how it ended, when the book still remembers, or an unknown id.
    /// Nothing is recorded either way: a late yes never admits.
    pub(crate) fn record_ask_answer(
        &self,
        ask_id: minimald_rpc::AskId,
        answer: minimald_rpc::AskAnswer,
    ) -> Result<AskEnded, AnswerRefusal> {
        let rows = self
            .rows
            .read()
            .expect("the row lock is never held across a panic, so it cannot be poisoned");
        let mut book = self
            .asks
            .lock()
            .expect("the ask book's lock is never held across a panic");
        if !book.pending.contains_key(&ask_id) {
            return Err(book.late_refusal(ask_id));
        }
        book.end(ask_id, |facts| match answer {
            minimald_rpc::AskAnswer::Yes => match record_ask_yes(&rows, facts) {
                Ok(()) => minimald_rpc::AskAdmitOutcome::Admitted {
                    ask_id,
                    port: facts.port,
                    proto: facts.proto,
                },
                Err(reason) => minimald_rpc::AskAdmitOutcome::Refused {
                    ask_id,
                    reason,
                    cause: None,
                },
            },
            minimald_rpc::AskAnswer::No => minimald_rpc::AskAdmitOutcome::Refused {
                ask_id,
                reason: minimald_rpc::AskRefused::Denied,
                cause: None,
            },
            minimald_rpc::AskAnswer::NoTty => minimald_rpc::AskAdmitOutcome::Refused {
                ask_id,
                reason: minimald_rpc::AskRefused::NoTty,
                cause: None,
            },
        })
        .ok_or(AnswerRefusal::UnknownId)
    }

    /// Cancel one pending ask (NET-045): the guest withdrew it — its
    /// connection ended — so the ask leaves the book unanswered and its
    /// dialogs are dismissed. `None` when the ask already ended: a
    /// cancellation never undoes an answer.
    pub(crate) fn cancel_ask(&self, ask_id: minimald_rpc::AskId) -> Option<AskEnded> {
        self.asks
            .lock()
            .expect("the ask book's lock is never held across a panic")
            .end(ask_id, |_| {
                cancelled(ask_id, minimald_rpc::AskCancelCause::GuestClosed)
            })
    }

    /// Cancel every pending ask the row at `switch_addr` holds (NET-045):
    /// the row's withdrawal takes the grant the asks would publish under,
    /// so each ends cancelled and the guest's exposure is refused.
    fn cancel_asks_for_row(&self, switch_addr: Ipv4Addr) -> Vec<AskEnded> {
        self.asks
            .lock()
            .expect("the ask book's lock is never held across a panic")
            .cancel_where(
                |facts| facts.switch_address == switch_addr,
                minimald_rpc::AskCancelCause::RowWithdrawn,
            )
    }

    /// Subscribe an attached host client to the pending asks of the row
    /// holding `box_id` (NET-045): keyed by the host-minted box id, never a
    /// name. Answers the subscription's id, for the detach to end exactly
    /// this subscription, and the row's standing offered ask, pushed to this
    /// client alone so a client attaching mid-ask sees the open dialog.
    /// `None` when no live row holds `box_id`: there is nothing to subscribe
    /// to.
    pub(crate) fn subscribe_asks(
        &self,
        box_id: BoxId,
        pushes: std::sync::mpsc::Sender<minimald_rpc::BoxControlReply>,
    ) -> Option<(u64, Option<AskOffered>)> {
        let rows = self
            .rows
            .read()
            .expect("the row lock is never held across a panic, so it cannot be poisoned");
        let switch_address = rows
            .values()
            .find(|record| record.box_id == box_id && !record.is_task_row())?
            .switch_addr();
        let mut book = self
            .asks
            .lock()
            .expect("the ask book's lock is never held across a panic");
        drop(rows);
        let id = book.next_subscriber;
        book.next_subscriber += 1;
        book.subscribers
            .entry(box_id)
            .or_default()
            .push(AskSubscriber { id, pushes });
        let standing = book
            .queues
            .get(&switch_address.octets())
            .and_then(|queue| queue.front().copied())
            .and_then(|ask_id| {
                let facts = book.pending.get(&ask_id)?.facts.clone();
                let offered_to = book.push(&box_id, &facts.offer(ask_id), Some(id));
                Some(AskOffered {
                    ask_id,
                    facts,
                    offered_to,
                })
            });
        Some((id, standing))
    }

    /// End one client's subscription (NET-045). When it was the last client
    /// attached to the box, every pending ask the box holds is cancelled:
    /// nobody is left to answer, and an ask must not hold the exposure
    /// behind a dialog nobody can see. The cancelled asks come back for the
    /// caller's log lines; their audit lines are the guests' own serving
    /// threads', which receive the cancellation.
    pub(crate) fn unsubscribe_asks(&self, box_id: BoxId, subscriber: u64) -> Vec<AskEnded> {
        let mut book = self
            .asks
            .lock()
            .expect("the ask book's lock is never held across a panic");
        if let Some(clients) = book.subscribers.get_mut(&box_id) {
            clients.retain(|client| client.id != subscriber);
            if clients.is_empty() {
                book.subscribers.remove(&box_id);
            }
        }
        if book.has_client(&box_id) {
            return Vec::new();
        }
        book.cancel_where(
            |facts| facts.box_id == box_id,
            minimald_rpc::AskCancelCause::LastDetach,
        )
    }

    /// Cancel every pending ask for a graceful stop (NET-045): each ends
    /// through the same path as any cancellation, by
    /// [`minimald_rpc::AskCancelCause::MinvmdStopping`], so its guest's
    /// serving thread audits it; then wait, at most `bound`, for every
    /// ended ask's audit line to be written. Answers the ended asks.
    pub(crate) fn stop_asks(&self, bound: std::time::Duration) -> Vec<AskEnded> {
        let ended = self
            .asks
            .lock()
            .expect("the ask book's lock is never held across a panic")
            .cancel_where(|_| true, minimald_rpc::AskCancelCause::MinvmdStopping);
        if !self.ask_gauges.unaudited.wait_idle(bound) {
            tracing::warn!(
                "some cancelled asks' audit lines were not written before the stop's bound"
            );
        }
        ended
    }

    /// The ask verbs' connection gauges (NET-045).
    pub(crate) fn ask_gauges(&self) -> &AskGauges {
        &self.ask_gauges
    }

    /// How many asks the book holds pending: the tests' view that an ask
    /// ended and left nothing behind.
    #[cfg(test)]
    pub(crate) fn pending_ask_count(&self) -> usize {
        self.asks
            .lock()
            .expect("the ask book's lock is never held across a panic")
            .pending
            .len()
    }
}

/// Whether `range`, inclusive at both ends, admits `port`; an absent range
/// admits nothing.
fn in_range(range: Option<(u16, u16)>, port: u16) -> bool {
    range.is_some_and(|(low, high)| (low..=high).contains(&port))
}

/// Record an answered yes's port in the row the table holds now (NET-045):
/// the port joins the row's runtime-admitted set, the same set the in-VM
/// daemon's reports fill under `allow`, and a port the row already holds
/// is recorded already.
///
/// The row is looked up again at answer time and checked again: a row
/// withdrawn and registered anew at the address is another box the human
/// was not asked about. The report path's cap and rate bound a guest's
/// report storm (NET-138); a yes is the host's own decision at human pace,
/// bounded by the ask queue and the dialog, so neither applies.
///
/// # Errors
///
/// The row is gone or is another box ([`minimald_rpc::AskRefused::NoRow`]),
/// its stance is no longer `ask` ([`minimald_rpc::AskRefused::StanceNotAsk`]),
/// or its range no longer admits the port
/// ([`minimald_rpc::AskRefused::OutsideGrant`]). Nothing is recorded.
fn record_ask_yes(
    rows: &std::sync::RwLockReadGuard<'_, Rows>,
    facts: &AskFacts,
) -> Result<(), minimald_rpc::AskRefused> {
    let record = rows
        .get(&facts.switch_address.octets())
        .filter(|record| record.box_id == facts.box_id)
        .ok_or(minimald_rpc::AskRefused::NoRow)?;
    if record.dynamic_ingress() != DynamicIngress::Ask {
        return Err(minimald_rpc::AskRefused::StanceNotAsk);
    }
    if !in_range(record.dynamic_range(), facts.port) {
        return Err(minimald_rpc::AskRefused::OutsideGrant);
    }
    let reported = RuntimePort {
        port: facts.port,
        proto: facts.proto,
    };
    let mut runtime = record
        .runtime_ports
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if !runtime.ports.contains(&reported) {
        runtime.ports.push(reported);
    }
    Ok(())
}

/// The writable half of the host-side table, held by the host process: the
/// registration surface — the host's own node-namespace row, and T66's
/// client-driven path — and the source of the read-only [`BoxTable`] the
/// gate reads.
///
/// Cheap to clone, and every clone shares the rows, the hand-out book,
/// and the withdrawal channel: the table the gate holds is the same one every
/// later registration lands in, which is how a box published after the gate
/// started is decided by its rules from that moment on, an address a
/// registration takes on one clone is never handed twice, and a report any
/// handle files reaches the one drainer. The subnet a registry is built with
/// fixes the address plan its rows compile against — the resolver the
/// carve-out is keyed to, the node address, and the runs the client-driven
/// allocation draws from — so it must be the same subnet the gate's switch
/// serves.
#[derive(Debug)]
pub struct BoxRegistry {
    subnet: SwitchSubnet,
    rows: Arc<RwLock<Rows>>,
    /// The switch addresses whose rows this daemon has marked stopped —
    /// namespaces whose declarations stay published while they are not
    /// running, keyed by the row's own key and shared by every clone.
    stopped: Arc<RwLock<BTreeSet<[u8; 4]>>>,
    /// The box names this daemon holds in the zone with no row behind them
    /// (the `host_ip` interim): a name held here answers NODATA under the
    /// zone apex where an unheld name answers NXDOMAIN. Keyed by the
    /// name's [`canonical_box_name`] form and shared by every clone; the
    /// [`Self::zone_view`] fold keeps a row's entry for a name a row
    /// publishes, so a hold never shadows a row. Each hold carries the
    /// session that made it, when its client named one, so a release
    /// frees only that session's hold, never a newer session's under the
    /// same name.
    held_names: Arc<RwLock<BTreeMap<String, Option<sessions::SessionId>>>>,
    /// The table's change pings: one `()` to every live subscriber whenever
    /// a row lands, goes, or is marked stopped. The host answerer
    /// ([`crate::net::answerer`]) subscribes — a daemon that does not hold
    /// the answerer port re-registers its zone rows with the one that does
    /// on every change — and the zone-table dump does
    /// ([`crate::diag`]). Senders whose subscriber is gone are pruned on
    /// the next ping, so a dead subscriber is never held past one change.
    table_pings: Arc<Mutex<Vec<std::sync::mpsc::Sender<()>>>>,
    /// The sending end of the withdrawal reports, cloned into every
    /// [`BoxTable`] this registry hands out — one channel for the whole
    /// registry, whatever handle files a report into it.
    withdrawal_reports: std::sync::mpsc::Sender<WithdrawalReport>,
    /// The receiving end, taken once — by [`Self::spawn_withdrawal_drainer`]
    /// or, in tests, by whatever wants to read the reports directly.
    withdrawal_reports_rx: Mutex<Option<std::sync::mpsc::Receiver<WithdrawalReport>>>,
    /// The row-withdrawal subscribers ([`BoxTable::subscribe_row_withdrawals`]):
    /// told the switch address of every row removed, whichever path removed
    /// it. The egress gate subscribes, to unbind a withdrawn box's forwards.
    row_withdrawals: RowWithdrawals,
    /// The addresses withdrawn boxes' revocations still hold against reuse
    /// ([`Revoking`]), shared by every clone and every [`BoxTable`].
    revoking: Arc<Revoking>,
    /// The book the client-driven allocation hands switch addresses from
    /// and returns them to ([`SwitchAddressBook`]), shared by every clone of
    /// this registry. Draws from the hand-out run — the plan run's upper
    /// half, above the daemon's self-allocation reserve (`hand_out_run`) —
    /// never from the reserve itself. A draw reads the rows while it holds
    /// the book, so the book is never taken while a row lock is held: every
    /// return lands after the row lock that removed the row is dropped.
    switch_book: Arc<Mutex<SwitchAddressBook>>,
    /// How far the tests have moved this registry's clock past the real
    /// one ([`Self::now`]), shared by every clone, so a quarantine is
    /// driven without waiting it out.
    #[cfg(test)]
    clock_skew: Arc<Mutex<Duration>>,
    /// The next published loopback address the tests' single-node
    /// allocation hands out, shared the same way. The daemon's addresses
    /// are the answerer's ([`Self::register_client_box_at`]).
    #[cfg(test)]
    next_loopback_addr: Arc<AtomicU32>,
    /// The loopback slice this subnet's switch publishes at, when the
    /// address plan serves it. A registry the plan does not serve cannot
    /// register a client box. `None` for a subnet the plan
    /// does not serve — such a registry still holds explicit registrations
    /// (the node's own row among them), it just cannot allocate for a
    /// client box.
    loopback_slice: Option<switch::LoopbackSlice>,
    /// The proxy's attachment table this registry feeds (NET-133), when the
    /// host handed one over: every box row published here is an attachment
    /// first and every row retired here retires its attachment with it.
    /// `None` for a registry that feeds no proxy — a table-less registry
    /// still publishes rows, it just gives no attachments.
    attachments: Option<crate::bep_attach::Attachments>,
    /// The record of pending asks (NET-045): the unresolved asks by their
    /// host-minted ids, each row's queue of them, and the attached host
    /// clients by the box id each subscribed to — shared by every clone,
    /// because the clients the doors register are the same clients every
    /// clone's offers must reach.
    asks: Arc<Mutex<AskBook>>,
    /// The ask verbs' connection gauges (NET-045), shared by every clone.
    ask_gauges: Arc<AskGauges>,
    /// The registrations in flight per box name, with the name's withdrawal
    /// generation ([`NameRegistrations`]), keyed by the name in
    /// [`canonical_box_name`] form: the answerer allocates per canonical
    /// name, so "Web" and "web" are one box here too. Shared by every clone, and
    /// bounded by the registrations in flight: an entry goes once its last
    /// registration ends.
    withdrawal_generations: Arc<Mutex<HashMap<String, NameRegistrations>>>,
    /// The egress default's rollout phase a client box with no `egress`
    /// section is compiled under: the gate's own phase
    /// ([`crate::net::egress_gate::UNREGISTERED_SOURCE_PHASE`]), so the row's
    /// frame half and the gate's publish half read one constant.
    egress_default_phase: sessions::EgressDefaultPhase,
    /// The operator's deny-all opt-out (NET-077), read from
    /// `MINVMD_EGRESS_DENY_ALL_OPT_OUT` by the supervisor: with it set, a
    /// client box with no `egress` section keeps the earlier allow-all in
    /// every phase — the same default the guest daemon is handed on its boot
    /// line, so the host gate never denies what the guest allows. That
    /// agreement also needs this registry's phase to match the guest's
    /// (`sessions::EGRESS_DEFAULT_PHASE`); if the two constants diverge, the
    /// stricter side wins.
    egress_deny_all_opt_out: bool,
    /// The client boxes' creations ([`Creation`]), keyed by the name's
    /// [`canonical_box_name`] form and shared by every clone: what a row
    /// is reinstated from at start and at its creator's resume. Taken
    /// inside the row lock when both are held — a creation is inserted,
    /// ended, and marked dormant under the same write of the row lock
    /// that publishes or removes its row — and never the other way round.
    creations: Arc<Mutex<BTreeMap<String, Creation>>>,
    /// Where the creations are persisted ([`Self::persisting_to`]), when
    /// this registry persists at all: the supervisor's does, in its VM's
    /// state dir; a test's need not.
    persisted_at: Option<Arc<std::path::PathBuf>>,
    /// Serializes the persisted file's writes, so the last write to land
    /// is of the newest creations, whichever handle wrote it.
    persist_turn: Arc<Mutex<()>>,
    /// The table's row epoch, shared by every clone and every [`BoxTable`]:
    /// bumped each time a row lands, so a relay that marked a source
    /// carried learns that the row there may be a new one to mark
    /// ([`BoxTable::carry`]).
    row_epoch: Arc<AtomicU64>,
}

/// A clone shares the live rows, the hand-out book, and the withdrawal
/// channel but not the receiver: only the registry that created the channel —
/// the one [`Self::spawn_withdrawal_drainer`] (or a test) drains — holds the
/// receiving end, so a clone can register, allocate, and file reports like
/// the original but has nothing to take.
impl Clone for BoxRegistry {
    fn clone(&self) -> Self {
        BoxRegistry {
            subnet: self.subnet,
            rows: self.rows.clone(),
            stopped: Arc::clone(&self.stopped),
            held_names: Arc::clone(&self.held_names),
            table_pings: Arc::clone(&self.table_pings),
            withdrawal_reports: self.withdrawal_reports.clone(),
            withdrawal_reports_rx: Mutex::new(None),
            row_withdrawals: Arc::clone(&self.row_withdrawals),
            revoking: Arc::clone(&self.revoking),
            switch_book: Arc::clone(&self.switch_book),
            #[cfg(test)]
            clock_skew: Arc::clone(&self.clock_skew),
            #[cfg(test)]
            next_loopback_addr: Arc::clone(&self.next_loopback_addr),
            loopback_slice: self.loopback_slice,
            attachments: self.attachments.clone(),
            asks: Arc::clone(&self.asks),
            ask_gauges: Arc::clone(&self.ask_gauges),
            withdrawal_generations: Arc::clone(&self.withdrawal_generations),
            egress_default_phase: self.egress_default_phase,
            egress_deny_all_opt_out: self.egress_deny_all_opt_out,
            creations: Arc::clone(&self.creations),
            persisted_at: self.persisted_at.clone(),
            persist_turn: Arc::clone(&self.persist_turn),
            row_epoch: Arc::clone(&self.row_epoch),
        }
    }
}

impl BoxRegistry {
    /// An empty registry for a switch serving `subnet`. Every row registered
    /// here compiles its lease from its own switch address and the resolver
    /// carve-out from this subnet, so `subnet` must be the one the switch was
    /// configured with.
    #[must_use]
    pub fn new(subnet: SwitchSubnet) -> Self {
        let (reports, reports_rx) = std::sync::mpsc::channel();
        let loopback_slice = switch::AddressPlan::default().loopback_slice_for_switch(subnet);
        Self {
            subnet,
            rows: Arc::new(RwLock::new(BTreeMap::new())),
            stopped: Arc::new(RwLock::new(BTreeSet::new())),
            held_names: Arc::new(RwLock::new(BTreeMap::new())),
            table_pings: Arc::new(Mutex::new(Vec::new())),
            withdrawal_reports: reports,
            withdrawal_reports_rx: Mutex::new(Some(reports_rx)),
            row_withdrawals: Arc::new(Mutex::new(Vec::new())),
            revoking: Arc::new(Revoking::default()),
            switch_book: Arc::new(Mutex::new(SwitchAddressBook::new(subnet))),
            #[cfg(test)]
            clock_skew: Arc::new(Mutex::new(Duration::ZERO)),
            #[cfg(test)]
            next_loopback_addr: Arc::new(AtomicU32::new(
                loopback_slice.map_or(0, |slice| box_loopback_run(slice).0),
            )),
            loopback_slice,
            attachments: None,
            asks: Arc::new(Mutex::new(AskBook::default())),
            ask_gauges: Arc::new(AskGauges::default()),
            withdrawal_generations: Arc::new(Mutex::new(HashMap::new())),
            egress_default_phase: crate::net::egress_gate::UNREGISTERED_SOURCE_PHASE
                .into_sessions_phase(),
            egress_deny_all_opt_out: false,
            creations: Arc::new(Mutex::new(BTreeMap::new())),
            persisted_at: None,
            persist_turn: Arc::new(Mutex::new(())),
            row_epoch: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Sets the operator's deny-all opt-out (NET-077) this registry compiles
    /// a client box with no `egress` section under: `true` keeps the shipped
    /// allow-all whatever the phase, `false` (the default) lets the phase
    /// decide. The supervisor passes the value it read from
    /// `MINVMD_EGRESS_DENY_ALL_OPT_OUT`, the same one the VMM child hands the
    /// guest daemon. Returns `self`, for the supervisor's call chain.
    #[must_use]
    pub fn with_egress_deny_all_opt_out(mut self, opt_out: bool) -> Self {
        self.egress_deny_all_opt_out = opt_out;
        self
    }

    /// Builds this registry under a named egress default phase, for the
    /// tests that pin what an undeclared row compiles to under each arm —
    /// the announced one no build ships now as well as the in-force one.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn with_egress_default_phase(mut self, phase: sessions::EgressDefaultPhase) -> Self {
        self.egress_default_phase = phase;
        self
    }

    /// Start a registration of box `name`: count it in flight and read the
    /// name's withdrawal generation, before the answerer allocates its
    /// address. The claim is held until the registration's turn ends, and
    /// its drop ends the count — on success, refusal and panic alike.
    #[must_use]
    pub fn begin_registration(&self, name: &str) -> RegistrationClaim {
        let key = canonical_box_name(name);
        let mut generations = self.generations();
        let entry = generations.entry(key.clone()).or_default();
        entry.in_flight = entry.in_flight.saturating_add(1);
        let generation = entry.generation;
        RegistrationClaim {
            generations: Arc::clone(&self.withdrawal_generations),
            key,
            generation,
        }
    }

    /// Box `name`'s withdrawal generation, as an in-flight registration
    /// compares it to the one its claim read. A name with no registration
    /// in flight reads 0.
    fn withdrawal_generation(&self, name: &str) -> u64 {
        self.generations()
            .get(&canonical_box_name(name))
            .map_or(0, |entry| entry.generation)
    }

    /// Bump box `name`'s withdrawal generation. Every withdrawal path calls
    /// it under the row lock it withdraws under, so a registration's check
    /// under the same lock sees every withdrawal ordered before it. A name
    /// with no registration in flight has nobody to tell, so nothing is
    /// kept for it.
    fn bump_withdrawal_generation(&self, name: &str) {
        if let Some(entry) = self.generations().get_mut(&canonical_box_name(name)) {
            entry.generation = entry.generation.wrapping_add(1);
        }
    }

    /// Hand a refused registration's address back to the answerer, by
    /// running `release`, unless something else owns it: a live row under
    /// the claim's name, or another registration of the name still in
    /// flight — names compared in [`canonical_box_name`] form, the form the
    /// answerer holds the address under. The answerer allocates per name, so either one holds the
    /// very address a release by name would free. Decided under the row
    /// lock and the generations' lock, and `release` runs under both, so no
    /// registration of the name can start between the decision and the
    /// release. Returns whether `release` ran.
    pub fn release_unless_owned(&self, claim: &RegistrationClaim, release: impl FnOnce()) -> bool {
        self.release_unless_owned_past(&claim.key, 1, release)
    }

    /// Hand a withdrawn box's address back to the answerer, by running
    /// `release`, unless something else owns it: [`Self::release_unless_owned`]
    /// for a withdrawal, which holds no registration of its own, so every
    /// registration of the name in flight counts as another owner. Returns
    /// whether `release` ran.
    pub fn release_withdrawn_unless_owned(&self, name: &str, release: impl FnOnce()) -> bool {
        self.release_unless_owned_past(&canonical_box_name(name), 0, release)
    }

    /// The one locked decision both releases take: under the row lock and
    /// then the generations' lock, `release` runs unless a live row or a
    /// kept creation holds `key` — a dormant creation's published address
    /// stays reserved for its resume ([`Creation`]) — or more than `own`
    /// registrations of it are in flight.
    fn release_unless_owned_past(&self, key: &str, own: u32, release: impl FnOnce()) -> bool {
        let rows = self
            .rows
            .read()
            .expect("the row lock is never held across a panic, so it cannot be poisoned");
        let generations = self.generations();
        let row_holds = rows
            .values()
            .any(|record| canonical_box_name(record.name()) == key);
        let others_in_flight = generations
            .get(key)
            .map_or(0, |entry| entry.in_flight.saturating_sub(own));
        if row_holds || others_in_flight > 0 || self.creations().contains_key(key) {
            return false;
        }
        release();
        true
    }

    /// Whether the registry keeps an entry for box `name`: only while a
    /// registration of it is in flight.
    #[cfg(test)]
    pub(crate) fn tracks_registrations_of(&self, name: &str) -> bool {
        self.generations().contains_key(&canonical_box_name(name))
    }

    fn generations(&self) -> MutexGuard<'_, HashMap<String, NameRegistrations>> {
        lock_generations(&self.withdrawal_generations)
    }

    /// Hands this registry the proxy's attachment table to feed
    /// (NET-133): from here on every box row it publishes is an attachment
    /// issued ahead of the row — the proxy holds the box before its first
    /// connection could arrive — and every row it retires takes the
    /// attachment with it, ahead of the row's own removal. Returns `self`,
    /// for the supervisor's call chain.
    ///
    /// The table is the host's own; feeding it is the registry's one write
    /// path, so the attachments stay sourced from the host-side creator
    /// alone: nothing the guest says reaches either table (NET-138's
    /// boundary, which NET-133 borrows for the proxy).
    #[must_use]
    pub fn feeding_proxy_attachments(
        mut self,
        attachments: crate::bep_attach::Attachments,
    ) -> Self {
        self.attachments = Some(attachments);
        self
    }

    /// Persists this registry's client-box creations at `path` — the
    /// supervisor passes [`REGISTRY_FILE`] in its VM's state dir — and
    /// reloads what a previous run persisted there first. Returns `self`,
    /// for the supervisor's call chain, and is the chain's last link: a
    /// reloaded row is compiled under the egress default and issues its
    /// proxy attachment exactly as a registration does, so both must be
    /// set before.
    ///
    /// Every creation whose row stood at the last write is reinstated at
    /// its own addresses with its own box id, compiled from its creator's
    /// declaration as a registration is, and marked **detached** from this
    /// instant ([`RowLiveness`]): the VM the row's box ran in ended with
    /// the previous run, so the row is withdrawn once [`DETACH_GRACE`]
    /// passes unless the box's shuttle carries a frame from its address
    /// again. A resume does not extend that grace; once the row has gone,
    /// its creator's resume reinstates it ([`Self::resume_client_box`]). A
    /// dormant creation stays dormant. The hand-out book takes every
    /// creation's switch and task addresses, dormant ones' included, so a
    /// fresh book hands none of them to a new box; their quarantine is not
    /// persisted ([`SwitchAddressBook`]). A creation whose addresses the
    /// book will not give — an address outside the run, or one an earlier
    /// entry took — is dropped and said as a warn line; one whose row
    /// cannot be published is kept dormant, its addresses reserved.
    ///
    /// The file is written after every change to the creations: mode 0600,
    /// written to a temporary file and renamed over the last
    /// ([`write_registry_file`]), versioned ([`REGISTRY_FILE_VERSION`]).
    /// A write that fails is a warn line, and the creations stay held in
    /// this process: the rows decide frames from memory, and the file only
    /// outlives the process. A file found unusable is set aside, never
    /// written over ([`read_registry_file`]); when it cannot be, this
    /// registry persists nothing.
    #[must_use]
    pub fn persisting_to(mut self, path: std::path::PathBuf) -> Self {
        let Some(loaded) = read_registry_file(&path) else {
            return self;
        };
        self.persisted_at = Some(Arc::new(path));
        let now = self.now();
        for mut creation in loaded {
            let key = canonical_box_name(&creation.name);
            if self.creations().contains_key(&key) {
                tracing::warn!(
                    box = %creation.name,
                    "the persisted box registry names a box twice; reloading the first only"
                );
                continue;
            }
            // Every creation, dormant ones included, holds its switch and
            // task addresses: a fresh book hands none of them to a new box.
            if let Err(addr) = self.take_creation_addrs(&creation, now) {
                tracing::warn!(
                    box = %creation.name,
                    %addr,
                    "could not reload a persisted box: one of its switch addresses is not the \
                     hand-out run's to give it; its creation is dropped"
                );
                continue;
            }
            if creation.standing {
                creation.standing = self.reinstate(&creation, now);
            }
            self.creations().insert(key, creation);
        }
        self.persist();
        self
    }

    /// Republishes a persisted standing creation's row at load, detached
    /// from `now`, its addresses already taken back from the book
    /// ([`Self::take_creation_addrs`]). Returns whether the row stands; a
    /// row that cannot be published leaves the creation dormant, its
    /// addresses still reserved for a later resume.
    fn reinstate(&self, creation: &Creation, now: Instant) -> bool {
        let registration = self.client_registration(
            creation.spec(),
            creation.switch_address,
            creation.loopback_address,
            creation.task_addresses.clone(),
            creation.id(),
        );
        match self.try_register_since(registration, None, None) {
            Ok(record) => {
                record.liveness().detached_since = Some(now);
                tracing::info!(
                    box = %record.name(),
                    switch_addr = %record.switch_addr(),
                    grace = ?DETACH_GRACE,
                    "reloaded a persisted box's row detached; it is withdrawn after the \
                     grace unless its box attaches again or its creator resumes it"
                );
                true
            }
            Err(error) => {
                tracing::warn!(box = %creation.name, %error, "could not reload a persisted box's row");
                false
            }
        }
    }

    /// Takes every switch address `creation` holds — its box's and each of
    /// its task addresses — from the hand-out book, all or none: on the
    /// first one the book will not give, the ones taken go back, and that
    /// address is the error.
    fn take_creation_addrs(&self, creation: &Creation, now: Instant) -> Result<(), Ipv4Addr> {
        let mut book = self.switch_book();
        let addrs =
            std::iter::once(creation.switch_address).chain(creation.task_addresses.iter().copied());
        let mut taken = Vec::new();
        for addr in addrs {
            if !book.take(addr, now, creation.id()) {
                for addr in taken {
                    book.give_back(addr, now, false, creation.id());
                }
                return Err(addr);
            }
            taken.push(addr);
        }
        Ok(())
    }

    /// Returns every switch address `creation` holds to the hand-out book:
    /// its creator withdrew a dormant box. Quarantined, as a row that was
    /// attributed returns its address: a dormant creation's row stood once.
    fn give_back_creation_addrs(&self, creation: &Creation) {
        for addr in
            std::iter::once(creation.switch_address).chain(creation.task_addresses.iter().copied())
        {
            self.give_back_switch_addr(addr, true, creation.id());
        }
    }

    fn creations(&self) -> MutexGuard<'_, BTreeMap<String, Creation>> {
        self.creations
            .lock()
            .expect("the creations' lock is never held across a panic")
    }

    /// Writes the creations to the persisted file, when this registry
    /// persists ([`Self::persisting_to`]). Called after every change to
    /// them, with no row lock held; the snapshot is taken inside the
    /// write's turn, so the last write to land holds the newest creations.
    fn persist(&self) {
        let Some(path) = &self.persisted_at else {
            return;
        };
        let _turn = self
            .persist_turn
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let file = RegistryFile {
            version: REGISTRY_FILE_VERSION,
            boxes: self.creations().values().cloned().collect(),
        };
        if let Err(error) = write_registry_file(path, &file) {
            tracing::warn!(
                path = %path.display(),
                %error,
                "could not persist the box registry; its rows will not survive this process"
            );
        }
    }

    /// Marks `record`'s creation dormant, when the record is the
    /// creation's row: its row is gone, and its addresses stay reserved
    /// for it ([`Creation`]). Called
    /// under the row lock that removed the row. Returns whether a creation
    /// changed.
    fn creation_rowless(&self, record: &BoxRecord) -> bool {
        let mut creations = self.creations();
        match creations.get_mut(&canonical_box_name(record.name())) {
            Some(creation) if creation.id() == record.box_id && creation.standing => {
                creation.standing = false;
                true
            }
            _ => false,
        }
    }

    /// The subnet this registry's rows are addressed on.
    #[must_use]
    pub fn subnet(&self) -> SwitchSubnet {
        self.subnet
    }

    /// The instant the hand-out book draws and returns at: the real clock,
    /// moved by [`Self::advance_clock`] in tests.
    fn now(&self) -> Instant {
        #[cfg(test)]
        {
            let skew = *self
                .clock_skew
                .lock()
                .expect("the test clock's lock is held only across a read or an add");
            Instant::now()
                .checked_add(skew)
                .expect("a test moves the clock by minutes, never past the clock's range")
        }
        #[cfg(not(test))]
        {
            Instant::now()
        }
    }

    /// Moves this registry's clock, and every clone's, `by` past the real
    /// one: the seam that drives the hand-out quarantine in tests.
    #[cfg(test)]
    pub(crate) fn advance_clock(&self, by: Duration) {
        let mut skew = self
            .clock_skew
            .lock()
            .expect("the test clock's lock is held only across a read or an add");
        *skew = skew.saturating_add(by);
    }

    fn switch_book(&self) -> MutexGuard<'_, SwitchAddressBook> {
        self.switch_book
            .lock()
            .expect("the hand-out book's lock is never held across a panic")
    }

    /// Draws a switch address from the hand-out book ([`SwitchAddressBook`]):
    /// a returned address only once it is eligible and no row and no
    /// withdrawn box's revocation holds it.
    fn draw_switch_addr(&self) -> Result<Ipv4Addr, AllocationError> {
        let now = self.now();
        let mut book = self.switch_book();
        let rows = self
            .rows
            .read()
            .expect("the row lock is never held across a panic, so it cannot be poisoned");
        book.draw(now, |addr| {
            rows.contains_key(&addr.octets())
                || self.revoking.first_held(&[addr.octets()]).is_some()
        })
        .map_err(AllocationError::SwitchExhausted)
    }

    /// Draws a task address from the hand-out book, as [`Self::draw_switch_addr`]
    /// draws a box's, but only while the book could still hand more than
    /// [`TASK_SLOT_FLOOR`] addresses: `None` once a task slot would eat into
    /// what new boxes need, or the book hands nothing.
    fn draw_task_addr(&self) -> Option<Ipv4Addr> {
        let now = self.now();
        let mut book = self.switch_book();
        let rows = self
            .rows
            .read()
            .expect("the row lock is never held across a panic, so it cannot be poisoned");
        let held = |addr: Ipv4Addr| {
            rows.contains_key(&addr.octets())
                || self.revoking.first_held(&[addr.octets()]).is_some()
        };
        if book.spare(now, held) <= TASK_SLOT_FLOOR {
            return None;
        }
        book.draw(now, held).ok()
    }

    /// Returns a removed row's switch address to the hand-out book:
    /// quarantined when the row was ever attributed
    /// ([`BoxRecord::was_attributed`]), at once when no frame of its box
    /// ever crossed the gate. Called after the row lock that removed it is
    /// dropped. An address the book did not draw is not returned.
    fn give_back_switch_addr(&self, addr: Ipv4Addr, quarantine: bool, returned_by: BoxId) {
        let now = self.now();
        self.switch_book()
            .give_back(addr, now, quarantine, returned_by);
    }

    /// How many hand-out addresses are out: drawn for a row that stands or
    /// a registration in flight.
    #[cfg(test)]
    pub(crate) fn live_switch_addrs(&self) -> usize {
        self.switch_book().out.len()
    }

    /// The returned hand-out addresses, oldest return first, each with
    /// whether it is eligible to be handed again now.
    #[cfg(test)]
    pub(crate) fn returned_switch_addrs(&self) -> Vec<(Ipv4Addr, bool)> {
        let now = self.now();
        self.switch_book()
            .free
            .iter()
            .map(|&(addr, eligible, _)| (Ipv4Addr::from(addr), now >= eligible))
            .collect()
    }

    /// Publishes one namespace: compiles the declaration into a row keyed by
    /// its switch address — the lease the shared verdict checks every
    /// frame's source against (NET-084) — and returns it. Registering an
    /// address that is already published replaces that row with the newest
    /// declaration, whatever it holds: the table compares no policy against
    /// the row it holds — a rule set's absent dimensions are allow-all, so
    /// there is not even a widest one to rank against — and a re-registration
    /// can widen a namespace's reach as readily as narrow it. Whether a
    /// re-declaration may widen is the registering side's contract to enforce
    /// (T66's client-driven path, which decides whether re-declaring a live
    /// namespace is even possible); what this table enforces is NET-138's
    /// boundary — only the host process holding this registry can publish at
    /// all, so nothing inside the VM can change a row behind the gate's back.
    ///
    /// A row that declared DNS hosts carries those names in the row itself
    /// ([`BoxRecord::allow_dns_hosts`]), beside the rules: the name-based
    /// admission is decided against them, on the host, by the gate's DNS
    /// admission table ([`crate::net::dns_pins`]).
    ///
    /// # Errors
    ///
    /// [`AllocationError::RevocationPending`] when the registration's switch
    /// address, or its per-box published loopback address, is still held by
    /// a withdrawn box's revocation ([`RowWithdrawal`], design §7.1). The
    /// check and the insert happen under one write of the row lock, and a
    /// withdrawal takes its hold under the same lock, so no row can land at
    /// an address between its withdrawal and the end of its revocation. A
    /// refused registration leaves nothing behind: no row and no attachment.
    ///
    /// # Panics
    ///
    /// Never: the row lock is only ever held across this map update, never
    /// across a panic.
    pub fn try_register(
        &self,
        registration: BoxRegistration,
    ) -> Result<Arc<BoxRecord>, AllocationError> {
        self.try_register_since(registration, None, None)
    }

    /// [`Self::try_register`], refused with
    /// [`AllocationError::WithdrawnWhileAllocating`] when `generation` is
    /// given and the box name's withdrawal generation is no longer it. The
    /// check runs under the row lock every withdrawal bumps the generation
    /// under, before anything is published. `creation`, for a client box,
    /// is kept — replacing any creation under the name — under the same
    /// write of the row lock that publishes the row, and persisted after.
    fn try_register_since(
        &self,
        registration: BoxRegistration,
        generation: Option<u64>,
        creation: Option<Creation>,
    ) -> Result<Arc<BoxRecord>, AllocationError> {
        // The name-based admission lives beside the frame rules, not in
        // them: whether a row's undeclared destinations are the DNS
        // admission table's to decide is the declaration's own fact, read
        // off the policy here and carried in the row for the gate's table
        // to pin from.
        let dns_hosts = registration
            .egress
            .as_ref()
            .and_then(|policy| policy.allow_dns_hosts.as_ref())
            .cloned()
            .unwrap_or_default();
        let resolves_names = !dns_hosts.is_empty();
        let deny_all = registration
            .egress
            .as_ref()
            .is_some_and(EgressPolicy::admits_nothing);
        // The box's own id (BEP-070): the one a client-driven registration
        // minted and checked ([`Self::register_client_box_at`]), or a fresh
        // UUIDv7 minted here for this creation — never a counter, never a
        // digest of the declaration below, never one a client presented.
        // Minted once, before anything else, so the row and the attachment
        // it issues hold the one identity this registration created the
        // box with.
        let box_id = registration
            .box_id
            .unwrap_or_else(crate::bep_attach::mint_box_id);
        // The row's derived allow-list: the declaration's `allow_subnets`
        // dimension in its own spelling. `None` reaches this row only from
        // the opt-out or the announced arm (`sessions::effective_egress`
        // resolves it to present and empty in force), and there it is
        // allow-all, the meaning the compiled rules give `None`.
        let egress_allow_list = registration
            .egress
            .as_ref()
            .and_then(|policy| policy.allow_subnets.clone())
            .unwrap_or_else(|| vec![ALLOW_ALL_SUBNET.to_string()]);
        // The dynamic-ingress grant (NET-045, NET-138): the stance and range
        // the host holds every runtime port report against, from the same
        // create inputs the session record holds. Absent is deny with no
        // range — the row a pre-grant client registers admits no runtime
        // port.
        let dynamic_ingress = registration.dynamic_ingress.unwrap_or(DynamicIngress::Deny);
        let dynamic_range = registration.dynamic_allowed_range;
        // The box's task rows (NET-138), compiled from the same declaration
        // the box's row is: its id, its egress — the lease each checks is
        // the task's own address — and nothing else. No ingress, no names,
        // no dynamic grant, no credentialed lane: a task run reaches out
        // under its box's egress and is reached by nothing.
        let task_rows: Vec<Arc<BoxRecord>> = registration
            .task_addrs
            .iter()
            .map(|&task_addr| {
                Arc::new(BoxRecord {
                    name: registration.name.clone(),
                    box_id,
                    switch_addr: task_addr,
                    loopback_addr: registration.loopback_addr,
                    admitted_ports: Vec::new(),
                    declared_names: Vec::new(),
                    egress: EgressRules::from_policy(
                        registration.egress.as_ref(),
                        self.subnet.dns_server().octets(),
                        task_addr.octets(),
                    ),
                    resolves_names,
                    dns_hosts: dns_hosts.clone(),
                    deny_all,
                    credentialed_upstream: false,
                    dynamic_ingress: DynamicIngress::Deny,
                    dynamic_range: None,
                    runtime_ports: Mutex::new(RowRuntime::default()),
                    egress_allow_list: egress_allow_list.clone(),
                    attributed: AtomicBool::new(false),
                    liveness: Mutex::new(RowLiveness::default()),
                    task_row_of: Some(registration.switch_addr),
                    task_addrs: Vec::new(),
                })
            })
            .collect();
        let record = Arc::new(BoxRecord {
            name: registration.name,
            box_id,
            // The lease the compiled rules check is the row's own switch
            // address: the one source its frames may carry. The resolver the
            // carve-out is keyed to is the switch this registry was built for
            // — the resolver Minimal owns for every box on it.
            egress: EgressRules::from_policy(
                registration.egress.as_ref(),
                self.subnet.dns_server().octets(),
                registration.switch_addr.octets(),
            ),
            resolves_names,
            dns_hosts,
            deny_all,
            // NET-134: the lane is the one egress dimension that compiles
            // to nothing in the frame rules — a declaration, not a rule —
            // so it travels in the row itself, reduced to the fact the
            // gate reads beside those rules.
            credentialed_upstream: registration.credentialed_upstream.is_some(),
            dynamic_ingress,
            dynamic_range,
            // A row starts with no runtime-admitted ports: the box's
            // runtime publications are reported one by one, inside the
            // grant, and a re-registration at the same address starts the
            // set empty again — the newest declaration never inherits the
            // box it replaced's runtime facts.
            runtime_ports: Mutex::new(RowRuntime::default()),
            egress_allow_list,
            attributed: AtomicBool::new(false),
            // Awaiting its box's first frame: no grace runs until a relay
            // that carried the row has ended, or the row was reloaded
            // rather than registered ([`Self::persisting_to`]).
            liveness: Mutex::new(RowLiveness::default()),
            switch_addr: registration.switch_addr,
            loopback_addr: registration.loopback_addr,
            admitted_ports: registration.admitted_ports,
            declared_names: registration.declared_names,
            task_row_of: None,
            task_addrs: registration.task_addrs,
        });
        // NET-133: the box's proxy attachment is issued from the row's own
        // host facts — the name, both addresses, and the box's own id
        // minted above — and issued **before** the row is visible, so the
        // proxy holds the box ahead of its first connection: the box-egress
        // pool's listeners are partitioned by rows, a delivered connection
        // can only exist once the row made the box a share, and the share
        // comes a pool turn after the row. The guest node's own namespace
        // is not a box: its row buys no share in the pool (the same one
        // address `RegisteredBoxes` excludes) and no attachment either —
        // the plan keeps that address outside the run every client box is
        // handed from, so excluding it names exactly the node row.
        //
        // Both happen under the row lock, after the revocation check: a
        // withdrawal takes its hold under the same lock, so an address is
        // either still a live row's or held until its revocation ends.
        #[expect(
            clippy::unwrap_in_result,
            reason = "the expect is the lock's poison guard, not this function's error \
                      handling: the row lock is never held across a panic, so it cannot be \
                      poisoned"
        )]
        let mut rows = self
            .rows
            .write()
            .expect("the row lock is never held across a panic, so it cannot be poisoned");
        let held_against = std::iter::once(&record)
            .chain(&task_rows)
            .flat_map(|row| row.revocation_addrs())
            .collect::<Vec<_>>();
        if let Some(held) = self.revoking.first_held(&held_against) {
            drop(rows);
            let addr = Ipv4Addr::from(held);
            tracing::warn!(
                box = %record.name(),
                %addr,
                "refused a box registration at an address a withdrawn box's revocation still holds"
            );
            return Err(AllocationError::RevocationPending { addr });
        }
        if generation.is_some_and(|read| read != self.withdrawal_generation(record.name())) {
            drop(rows);
            return Err(AllocationError::WithdrawnWhileAllocating);
        }
        if let Some(attachments) = &self.attachments
            && record.switch_addr != self.subnet.daemon_ip()
        {
            attachments.issue(
                record.name(),
                record.box_id(),
                record.switch_addr,
                record.loopback_addr,
                record.declares_credentialed_upstream(),
            );
        }
        rows.insert(record.switch_addr.octets(), Arc::clone(&record));
        for task in &task_rows {
            rows.insert(task.switch_addr.octets(), Arc::clone(task));
        }
        // Under the write that published the rows: a relay that reads the
        // new epoch finds them ([`BoxTable::carry`]).
        self.row_epoch.fetch_add(1, Ordering::Release);
        let created = creation.is_some();
        if let Some(creation) = creation {
            self.creations()
                .insert(canonical_box_name(&creation.name), creation);
        }
        drop(rows);
        if created {
            self.persist();
        }
        // The newest declaration is a namespace that is running: whatever
        // stopped mark the address carried is stale now, and the change is
        // a ping every subscriber re-derives from.
        self.stopped
            .write()
            .expect("the stopped set's lock is never held across a panic, so it cannot be poisoned")
            .remove(&record.switch_addr.octets());
        self.ping();
        Ok(record)
    }

    /// Removes the task rows filed with `record` ([`BoxRecord::task_row_of`])
    /// from `rows`, under the write of the row lock that removed `record`,
    /// and takes each one's revocation hold under the same lock: a task row
    /// is withdrawn with its box, on every path that removes the box
    /// (NET-138). A row at a task address that is not this box's task row
    /// is left alone. Hand the result to [`Self::retire_task_rows`] once
    /// the lock is dropped.
    fn remove_task_rows(
        &self,
        rows: &mut Rows,
        record: &BoxRecord,
    ) -> Vec<(Arc<BoxRecord>, Option<RowWithdrawal>)> {
        let mut removed = Vec::new();
        for addr in &record.task_addrs {
            let ours = rows.get(&addr.octets()).is_some_and(|task| {
                task.task_row_of == Some(record.switch_addr) && task.box_id == record.box_id
            });
            if let Some(task) = rows.remove(&addr.octets()).filter(|_| ours) {
                let withdrawal = self.begin_revocation(&task);
                removed.push((task, withdrawal));
            }
        }
        removed
    }

    /// Retires the task rows [`Self::remove_task_rows`] removed, as the
    /// box's own row is retired, and returns each one's switch address to
    /// the hand-out book when `give_back` says to — not for a box whose
    /// creation keeps them reserved. Called after the row lock is dropped.
    fn retire_task_rows(
        &self,
        task_rows: Vec<(Arc<BoxRecord>, Option<RowWithdrawal>)>,
        give_back: bool,
    ) {
        for (task, withdrawal) in task_rows {
            let (addr, attributed, box_id) = (task.switch_addr, task.was_attributed(), task.box_id);
            self.retired(&Some(task), withdrawal);
            if give_back {
                self.give_back_switch_addr(addr, attributed, box_id);
            }
        }
    }

    /// [`Self::try_register`] for a test that never registers at a held
    /// address.
    #[cfg(test)]
    pub fn register(&self, registration: BoxRegistration) -> Arc<BoxRecord> {
        self.try_register(registration)
            .expect("a test registration never lands at an address a revocation holds")
    }

    /// Waits up to `bound` for a withdrawn box's revocation to release
    /// `addrs` ([`RowWithdrawal`]). Returns the first address still held at
    /// the bound, or `None` once none is.
    fn wait_for_revocations(&self, addrs: &[[u8; 4]], bound: Duration) -> Option<Ipv4Addr> {
        self.revoking
            .wait_released(addrs, bound)
            .map(Ipv4Addr::from)
    }

    /// Withdraws the row published for `switch_addr`, returning it when one
    /// was held. From here on the gate holds no namespace at that address, and
    /// no rules are decided by it: withdrawing is how the host retires a
    /// namespace's declaration, never a way to leave its address attributed.
    ///
    /// What the address's frames do next is unconditional
    /// ([`crate::net::egress_gate`]): an address inside the plan's lease block
    /// is an unregistered source the gate drops (NET-085), so a withdrawal
    /// inside that block ends the address's reach at once, and outside it the
    /// frames were already an unknown source's refusal (NET-081's failure
    /// case). The row is gone either way, and a re-registration starts from
    /// the newest declaration.
    pub fn withdraw(&self, switch_addr: Ipv4Addr) -> Option<Arc<BoxRecord>> {
        // The box's end is observed here, so the withdrawal's own line
        // measures itself against this instant (NET-133's bound).
        self.withdraw_where(switch_addr, |_, _| Some(Instant::now()))
    }

    /// Withdraws the row at `switch_addr` when `ended_at` says its box
    /// ended — the instant it ended — deciding under the write of the row
    /// lock the row leaves under, so nothing that changes the row's
    /// liveness lands between the decision and the removal. The proxy
    /// attachment is retired inside the same critical section, as the
    /// creator's withdrawal retires it ([`Self::withdraw_client_box`]);
    /// the row's creation, when it is a client box's, goes dormant
    /// ([`Creation`]) and is persisted; and the switch address returns to
    /// the hand-out book, quarantined when the row was ever attributed.
    fn withdraw_where(
        &self,
        switch_addr: Ipv4Addr,
        ended_at: impl FnOnce(&Rows, &BoxRecord) -> Option<Instant>,
    ) -> Option<Arc<BoxRecord>> {
        let mut rows = self
            .rows
            .write()
            .expect("the row lock is never held across a panic, so it cannot be poisoned");
        let box_ended = ended_at(&rows, rows.get(&switch_addr.octets())?)?;
        self.retire_proxy_attachment(switch_addr, box_ended);
        let removed = rows.remove(&switch_addr.octets());
        let mut rowless = false;
        let mut task_rows = Vec::new();
        if let Some(record) = removed.as_deref().filter(|record| !record.is_task_row()) {
            self.bump_withdrawal_generation(record.name());
            rowless = self.creation_rowless(record);
            task_rows = self.remove_task_rows(&mut rows, record);
        }
        // The hold is taken under the same lock the row leaves under, so no
        // registration can land at the address in between.
        let withdrawal = removed
            .as_deref()
            .and_then(|record| self.begin_revocation(record));
        drop(rows);
        self.retired(&removed, withdrawal);
        // A dormant creation keeps its switch and task addresses reserved
        // ([`Creation`]): only a row no creation is kept for returns them.
        self.retire_task_rows(task_rows, !rowless);
        if let Some(record) = removed.as_ref().filter(|_| !rowless) {
            self.give_back_switch_addr(record.switch_addr, record.was_attributed(), record.box_id);
        }
        if rowless {
            self.persist();
        }
        removed
    }

    /// Retires the proxy attachment issued for `switch_addr`, when this
    /// registry feeds a table and one is held: the host-side half of the
    /// requirement's "the attachment is the box's row, withdrawn with it"
    /// (NET-133). Retired **before** the row it goes with, so a delivery
    /// racing the box's end finds no attachment and is refused rather than
    /// attributed to a namespace the table no longer holds.
    ///
    /// `box_ended` is the instant this process observed the box's end —
    /// the drainer's arrival of the relay's report, or the creator's
    /// withdrawal request reaching the control socket — and the one line
    /// the withdrawal logs measures itself against, so a tail can see a
    /// withdrawal that did not keep the requirement's bound.
    fn retire_proxy_attachment(&self, switch_addr: Ipv4Addr, box_ended: Instant) {
        if let Some(attachments) = &self.attachments {
            attachments.withdraw(switch_addr, box_ended);
        }
    }

    /// Registers a client box: allocates its switch address from the plan's
    /// lease run and its published loopback address from the slice this
    /// subnet's switch serves at, then fills the row from `spec` — the same
    /// compile [`Self::try_register`] does, addressed at the allocation — and
    /// returns the row, whose addresses are the ones to hand back over the
    /// control socket.
    ///
    /// The switch address comes from the hand-out book
    /// ([`SwitchAddressBook`]), shared by every clone of this registry, so
    /// no address is ever out to two rows at once. The book draws only from
    /// the hand-out run — the plan run's upper half, above the daemon's
    /// self-allocation reserve (`hand_out_run`) — so the two allocators
    /// cannot meet. The run is finite, and exhausting it is the
    /// [`AllocationError::SwitchExhausted`] the control socket hands back as
    /// the registration's failure, naming the live, quarantined and total
    /// counts.
    ///
    /// Every path that removes a row returns its switch address — the
    /// drainer's [`Self::withdraw`], the creator's
    /// [`Self::withdraw_client_box`], and a refusal after the draw — and a
    /// returned address is handed again only after its quarantine and once
    /// nothing holds it. A withdrawn address's host-side state — the gate's
    /// reply flows and DNS pins, the BEP leg's neighbour entry — is keyed
    /// by it, and the quarantine outlasts every one of those timers
    /// ([`SWITCH_REUSE_QUARANTINE`]), so a re-handed address starts clean.
    /// A row never attributed keyed nothing, and its address comes back at
    /// once.
    ///
    /// While a row this registration filled stands, the box's frames are
    /// decided by its rules; a box with **no** row — one whose registration
    /// never reached the daemon, or whose row was withdrawn — is an
    /// unregistered source the gate drops unconditionally (NET-085), so no
    /// egress default phase changes it, and this registration makes none.
    ///
    /// The published loopback address is not this registry's to pick:
    /// allocation is host-global (design §7.1), so `loopback_addr` comes from
    /// the machine's answerer — the installed service, or the interim when
    /// this daemon hosts it — which hands each node's boxes distinct
    /// addresses from the reserved range. Co-resident nodes never
    /// self-assign.
    ///
    /// The box's id is always minted here, for this creation
    /// ([`crate::bep_attach::mint_box_id`]): a spec carries none, so no
    /// client can present an id, and a re-registration under the same
    /// name and addresses is a new box with a new id. Ids are never reused.
    /// A mint that collides with an id a live row or attachment already
    /// holds is refused ([`AllocationError::CollidingBoxId`], BEP-070) —
    /// never re-minted — before any address is spent, and said as one warn
    /// line naming the id. A name that folds to one a live row already
    /// holds is refused the same way ([`AllocationError::NameAlreadyHeld`]):
    /// the answerer keys a published address by the name's canonical form,
    /// so two rows under folded-equal names would share one address.
    pub fn register_client_box_at(
        &self,
        spec: ClientBoxSpec,
        loopback_addr: Ipv4Addr,
    ) -> Result<Arc<BoxRecord>, AllocationError> {
        self.register_client_box_as(
            spec,
            loopback_addr,
            0,
            crate::bep_attach::mint_box_id(),
            None,
        )
    }

    /// [`Self::register_client_box_at`] for a registration that read its
    /// name's withdrawal generation as `generation`
    /// ([`Self::begin_registration`]) before the answerer allocated
    /// `loopback_addr`. When a withdrawal under the name
    /// landed since, the registration is refused with
    /// [`AllocationError::WithdrawnWhileAllocating`]: no row, no attachment,
    /// and the caller hands the address back to the answerer unless
    /// something else owns it ([`Self::release_unless_owned`]).
    ///
    /// Up to `task_slots` task addresses are filed with the box (NET-138) —
    /// at most [`minimald_rpc::TASK_SLOTS_PER_BOX`], whatever the client
    /// asked for — each drawn from the same hand-out book as the box's own
    /// and published as a task row of it ([`BoxRecord::task_row_of`]). They
    /// are best-effort: the draw stops while the book is at
    /// [`TASK_SLOT_FLOOR`], and the box registers with however many it got,
    /// which the row's [`BoxRecord::task_addrs`] says.
    pub fn register_client_box_since(
        &self,
        spec: ClientBoxSpec,
        loopback_addr: Ipv4Addr,
        task_slots: u8,
        generation: u64,
    ) -> Result<Arc<BoxRecord>, AllocationError> {
        self.register_client_box_as(
            spec,
            loopback_addr,
            task_slots,
            crate::bep_attach::mint_box_id(),
            Some(generation),
        )
    }

    /// [`Self::register_client_box_at`] with the freshly minted `id` it
    /// creates the box as: the one door the collision checks guard, split
    /// out so a test can drive a colliding mint.
    fn register_client_box_as(
        &self,
        spec: ClientBoxSpec,
        loopback_addr: Ipv4Addr,
        task_slots: u8,
        id: BoxId,
        generation: Option<u64>,
    ) -> Result<Arc<BoxRecord>, AllocationError> {
        // One id names one box (BEP-070): the check runs before any
        // address is spent, so a refused registration leaves nothing
        // behind — no row, no share, no attachment, no spent address.
        // A colliding mint is refused, never re-minted: a collision means
        // the mint is broken, and a second draw would hide it.
        if self.holds_box_id(id) {
            tracing::warn!(
                box_id = %crate::bep_attach::BoxIdText(&id),
                "refused a box registration whose id a live row or attachment already holds"
            );
            return Err(AllocationError::CollidingBoxId { id });
        }
        if self.loopback_slice.is_none() {
            return Err(AllocationError::UnplannedSubnet(self.subnet));
        }
        // A withdrawal that landed while the address was being allocated
        // refuses the registration before anything is waited on or spent;
        // the check under the row lock in `try_register_since` is the one
        // that decides.
        if generation.is_some_and(|read| read != self.withdrawal_generation(&spec.name)) {
            return Err(AllocationError::WithdrawnWhileAllocating);
        }
        // The answerer keys a published address by the name's canonical
        // form, so a registration whose name folds to a live row's would
        // share that row's address: one box, one address, one row. The
        // check runs after the withdrawal-generation one — a registration
        // raced by a withdrawal answers as withdrawn while allocating —
        // and before any address is spent. The collision is decided in
        // the answerer's fold, and the refusal reports the held row's own
        // spelling, so the asking client learns which box holds the name.
        if let Some(held) = self.held_name_for(&spec.name) {
            tracing::warn!(
                asked = %spec.name,
                held = %held,
                "refused a box registration whose name a live row already holds"
            );
            return Err(AllocationError::NameAlreadyHeld { held });
        }
        // A withdrawn box's revocation may still hold the published address
        // the answerer handed back: the answerer releases a box's address at
        // its withdrawal, and the next box can draw it at once. The wait is
        // bounded, and normally the revocation is long done. It runs before a
        // switch address is drawn, so a registration refused here holds none.
        // The book never draws an address a row or a revocation holds, and
        // `try_register` still checks both.
        if let Some(addr) = self.wait_for_revocations(&[loopback_addr.octets()], REVOCATION_WAIT) {
            tracing::warn!(
                box = %spec.name,
                %addr,
                wait = ?REVOCATION_WAIT,
                "a withdrawn box's revocation still holds an address this registration needs"
            );
            return Err(AllocationError::RevocationPending { addr });
        }
        let switch_addr = self.draw_switch_addr()?;
        // The task addresses come from the same book, after the box's own,
        // best-effort: as many as the book can spare above the floor it
        // keeps for new boxes ([`TASK_SLOT_FLOOR`]), zero included. A box
        // is refused only when its own address cannot be drawn.
        let task_addrs: Vec<Ipv4Addr> = (0..task_slots.min(minimald_rpc::TASK_SLOTS_PER_BOX))
            .map_while(|_| self.draw_task_addr())
            .collect();
        if task_addrs.len() < usize::from(task_slots.min(minimald_rpc::TASK_SLOTS_PER_BOX)) {
            tracing::warn!(
                box = %spec.name,
                asked = task_slots,
                filed = task_addrs.len(),
                floor = TASK_SLOT_FLOOR,
                "the hand-out run is nearly full; the box registers with fewer task addresses \
                 than it asked for"
            );
        }
        let creation = Creation::new(&spec, switch_addr, loopback_addr, task_addrs.clone(), id);
        let registration =
            self.client_registration(spec, switch_addr, loopback_addr, task_addrs.clone(), id);
        // A refusal after the draw publishes no row, so no frame of the box
        // was ever attributed: the addresses go straight back, with no
        // quarantine, and the refusal spends nothing.
        self.try_register_since(registration, generation, Some(creation))
            .inspect_err(|_| {
                for &addr in std::iter::once(&switch_addr).chain(&task_addrs) {
                    self.give_back_switch_addr(addr, false, id);
                }
            })
    }

    /// The registration a client box's declaration compiles to at its
    /// addresses, as box `id`: the one compile a registration, a reload
    /// ([`Self::persisting_to`]) and a resume ([`Self::resume_client_box`])
    /// all run, so a reinstated row is the row its declaration registers
    /// under this registry's egress default.
    fn client_registration(
        &self,
        spec: ClientBoxSpec,
        switch_addr: Ipv4Addr,
        loopback_addr: Ipv4Addr,
        task_addrs: Vec<Ipv4Addr>,
        id: BoxId,
    ) -> BoxRegistration {
        let mut registration = BoxRegistration::new(spec.name, switch_addr, loopback_addr)
            .with_admitted_ports(spec.ingress_ports)
            .with_task_addresses(task_addrs);
        // A client box is an own-address box (only those register), so an
        // absent `egress` section is the egress default's to fill, exactly as
        // the guest daemon fills it (NET-074/NET-077): deny-all once the
        // default is in force, unless the operator opted out — the shipped
        // allow-all otherwise. The row is compiled from what the box is held
        // to, so the host gate and the guest's gate agree.
        let egress = match sessions::effective_egress(
            spec.egress.as_ref(),
            sessions::NetworkMode::OwnIp,
            self.egress_default_phase,
            self.egress_deny_all_opt_out,
        ) {
            sessions::EffectiveEgress::Declared(policy) => Some(policy),
            sessions::EffectiveEgress::DenyAll => Some(EgressPolicy::deny_all()),
            sessions::EffectiveEgress::AllowAll => None,
        };
        if let Some(policy) = egress {
            registration = registration.with_egress_policy(policy);
        }
        if let Some(declaration) = spec.credentialed_upstream {
            registration = registration.with_credentialed_upstream(declaration);
        }
        // The dynamic-ingress grant rides the same registration: the
        // stance's absent default is deny, so a pre-grant client's row
        // admits no runtime port — and a range declared without a stance
        // changes nothing under it, exactly as it does inside the VM.
        if let Some(stance) = spec.dynamic_ingress {
            registration = registration.with_dynamic_ingress(stance, spec.dynamic_allowed_range);
        }
        registration.box_id = Some(id);
        registration
    }

    /// [`Self::register_client_box_at`] with the published loopback address
    /// drawn from this registry's own slice cursor — the single-node shape
    /// the registry's own tests drive, where no answerer arbitrates. The
    /// daemon never registers this way: its addresses are the answerer's.
    #[cfg(test)]
    pub fn register_client_box(
        &self,
        spec: ClientBoxSpec,
    ) -> Result<Arc<BoxRecord>, AllocationError> {
        let slice = self
            .loopback_slice
            .ok_or(AllocationError::UnplannedSubnet(self.subnet))?;
        let (first, last) = box_loopback_run(slice);
        let loopback_addr = take_next(&self.next_loopback_addr, first, last)
            .ok_or(AllocationError::LoopbackExhausted)?;
        self.register_client_box_at(spec, loopback_addr)
    }

    /// [`Self::register_client_box`] with `task_slots` task addresses filed
    /// with the box, as the control socket's registration files them
    /// ([`Self::register_client_box_since`]).
    #[cfg(test)]
    pub fn register_client_box_with_task_slots(
        &self,
        spec: ClientBoxSpec,
        task_slots: u8,
    ) -> Result<Arc<BoxRecord>, AllocationError> {
        let slice = self
            .loopback_slice
            .ok_or(AllocationError::UnplannedSubnet(self.subnet))?;
        let (first, last) = box_loopback_run(slice);
        let loopback_addr = take_next(&self.next_loopback_addr, first, last)
            .ok_or(AllocationError::LoopbackExhausted)?;
        self.register_client_box_at_with_task_slots(spec, loopback_addr, task_slots)
    }

    /// [`Self::register_client_box_with_task_slots`] at a published
    /// loopback address the test picks.
    #[cfg(test)]
    pub fn register_client_box_at_with_task_slots(
        &self,
        spec: ClientBoxSpec,
        loopback_addr: Ipv4Addr,
        task_slots: u8,
    ) -> Result<Arc<BoxRecord>, AllocationError> {
        self.register_client_box_as(
            spec,
            loopback_addr,
            task_slots,
            crate::bep_attach::mint_box_id(),
            None,
        )
    }

    /// Whether some live row, attachment or kept creation already holds
    /// `id` (BEP-070): the collision check every client-driven
    /// registration runs on the id it minted. A dormant creation
    /// ([`Creation`]) is a retained box record: its id stays its box's
    /// while its creator may still resume it. An id is never reused
    /// because no client can present one and the mint never draws the same
    /// UUIDv7 twice, not because this check remembers spent ids.
    fn holds_box_id(&self, id: BoxId) -> bool {
        let rows = self
            .rows
            .read()
            .expect("the row lock is never held across a panic, so it cannot be poisoned");
        if rows.values().any(|record| record.box_id == id) {
            return true;
        }
        drop(rows);
        if self
            .creations()
            .values()
            .any(|creation| creation.id() == id)
        {
            return true;
        }
        self.attachments
            .as_ref()
            .is_some_and(|attachments| attachments.holds_id(id))
    }

    /// The name a live row or a kept creation holds that `name` folds to,
    /// in its own spelling, or `None` when none folds to it. The answerer
    /// allocates a published address by the name's canonical form
    /// ([`crate::net::answerer::canonical_box_name`]), so two live rows
    /// under folded-equal names would share one address; this is the check
    /// that keeps the live set one row per folded name. A dormant creation
    /// holds its name too ([`Creation`]): its creator may still resume it,
    /// and a registration under the name would replace it.
    fn held_name_for(&self, name: &str) -> Option<String> {
        let asked = canonical_box_name(name);
        let rows = self
            .rows
            .read()
            .expect("the row lock is never held across a panic, so it cannot be poisoned");
        let live = rows
            .values()
            .find(|record| canonical_box_name(record.name()) == asked)
            .map(|record| record.name().to_string());
        drop(rows);
        live.or_else(|| {
            self.creations()
                .get(&asked)
                .map(|creation| creation.name.clone())
        })
    }

    /// Withdraws the client box's row when the pair `(name, switch_addr,
    /// loopback_addr)` proves its client is the row's creator, returning the
    /// row removed — `Ok(None)` when no row is published at `switch_addr` at
    /// all: the row is already withdrawn, or the daemon restarted since the
    /// registration, and either way the goal state — nothing admits the
    /// pair's addresses by a row — already holds. Lookup, proof, and removal
    /// happen under one write of the row lock, so no registration can land
    /// between the proof and the removal.
    ///
    /// The proof is the same pair the registration handed back
    /// ([`ClientBoxSpec`]'s allocation), which only the registering session's
    /// record carries; a row published under another name or another
    /// loopback is not the requesting client's to remove and is refused with
    /// [`WithdrawError`]. The name in the proof is compared in its
    /// canonical form, the answerer's fold: a box registered under "Web"
    /// is withdrawn by its own name in any spelling that folds to it.
    ///
    /// `box_id`, when the withdrawing client knows it, is the epoch the
    /// proof is held to: the id the registration minted for the row it
    /// handed the pair with. A row at the pair under another id is a newer
    /// creation that was handed the same name and addresses — the switch
    /// address re-handed after its quarantine, or at once when the old row
    /// was never attributed, and the loopback one handed back to the same
    /// name by the answerer — so a stale creator's withdrawal is refused
    /// with [`WithdrawError::NotTheBoxId`] and removes nothing of it.
    /// `None`, from a client that predates the field, keeps the pair proof
    /// alone.
    ///
    /// The withdrawn switch address returns to the hand-out book
    /// ([`SwitchAddressBook`]): quarantined when the row was ever
    /// attributed, at once when it never was. What the address's frames do
    /// next is the gate phase's to say ([`Self::withdraw`]). The box's
    /// proxy attachment goes with the row (NET-133), retired under the same
    /// row lock that removes it.
    ///
    /// This is the host-side half of the withdrawal a destroyed or failed
    /// activation sends over the control socket
    /// ([`crate::control::serve_request`]) — the guest daemon never asserts
    /// or withdraws address→box facts (NET-138).
    pub fn withdraw_client_box(
        &self,
        name: &str,
        switch_addr: Ipv4Addr,
        loopback_addr: Ipv4Addr,
        box_id: Option<BoxId>,
    ) -> Result<Option<Arc<BoxRecord>>, WithdrawError> {
        #[expect(
            clippy::unwrap_in_result,
            reason = "the expect is the lock's poison guard, not this function's error \
                      handling: the row lock is never held across a panic, so it cannot be \
                      poisoned"
        )]
        let mut rows = self
            .rows
            .write()
            .expect("the row lock is never held across a panic, so it cannot be poisoned");
        // A task row is never withdrawn by itself: it goes with its box's
        // row, which is what the pair names (NET-138).
        let Some(record) = rows
            .get(&switch_addr.octets())
            .filter(|record| !record.is_task_row())
        else {
            // Nothing to remove, but the withdrawal still counts: a
            // registration under the name whose address is still being
            // allocated must not land after it.
            self.bump_withdrawal_generation(name);
            // A dormant creation the pair proves is the creator's ends
            // with its box: nothing can resume it from here on.
            let ended = {
                let mut creations = self.creations();
                let key = canonical_box_name(name);
                let proven = creations.get(&key).is_some_and(|creation| {
                    !creation.standing
                        && creation.switch_address == switch_addr
                        && creation.loopback_address == loopback_addr
                        && box_id.is_none_or(|asked| asked == creation.id())
                });
                if proven { creations.remove(&key) } else { None }
            };
            drop(rows);
            // Its addresses were reserved for it while it was dormant; they
            // go back with it.
            if let Some(creation) = &ended {
                self.give_back_creation_addrs(creation);
                self.persist();
            }
            return Ok(None);
        };
        if canonical_box_name(record.name()) != canonical_box_name(name) {
            return Err(WithdrawError::NotTheCreatorsRow {
                switch_addr,
                held_name: record.name().to_string(),
                asked_name: name.to_string(),
            });
        }
        if record.loopback_addr() != loopback_addr {
            return Err(WithdrawError::NotTheHandedPair {
                switch_addr,
                held_loopback: record.loopback_addr(),
                asked_loopback: loopback_addr,
            });
        }
        if let Some(asked) = box_id
            && asked != record.box_id
        {
            return Err(WithdrawError::NotTheBoxId {
                switch_addr,
                held_box_id: record.box_id,
                asked_box_id: asked,
            });
        }
        // The attachment goes with the row (NET-133), retired inside the
        // same critical section that removes the row: a registration
        // landing after cannot retire the new box's attachment, and one
        // landing before is the row the proof above matched. The paths
        // that hold a row lock across the attachment table's — this one
        // and the drainer's ([`Self::withdraw_where`]) — take the row lock
        // first, and no path takes them the other way, so the order never
        // inverts.
        self.retire_proxy_attachment(switch_addr, Instant::now());
        let removed = rows.remove(&switch_addr.octets());
        self.bump_withdrawal_generation(name);
        // The creator withdrew its box: its creation ends with the row,
        // when the row is the creation's.
        let ended = removed.as_deref().is_some_and(|record| {
            let mut creations = self.creations();
            let key = canonical_box_name(record.name());
            creations
                .get(&key)
                .is_some_and(|creation| creation.id() == record.box_id)
                && creations.remove(&key).is_some()
        });
        let task_rows = removed
            .as_deref()
            .map(|record| self.remove_task_rows(&mut rows, record))
            .unwrap_or_default();
        let withdrawal = removed
            .as_deref()
            .and_then(|record| self.begin_revocation(record));
        drop(rows);
        self.retired(&removed, withdrawal);
        self.retire_task_rows(task_rows, true);
        if let Some(record) = &removed {
            self.give_back_switch_addr(record.switch_addr, record.was_attributed(), record.box_id);
        }
        if ended {
            self.persist();
        }
        Ok(removed)
    }

    /// The creation a resume presenting `(name, switch_addr, loopback_addr)`
    /// and `box_id` proves its creator holds: looked up by the box id when
    /// the resume names one — a session renamed since its registration
    /// still finds its box — and by the name otherwise, or when no creation
    /// holds the id.
    fn resumable_creation(
        &self,
        name: &str,
        switch_addr: Ipv4Addr,
        loopback_addr: Ipv4Addr,
        box_id: Option<BoxId>,
    ) -> Result<Creation, ResumeError> {
        let creations = self.creations();
        let creation = box_id
            .and_then(|asked| creations.values().find(|creation| creation.id() == asked))
            .or_else(|| creations.get(&canonical_box_name(name)))
            .cloned();
        drop(creations);
        let Some(creation) = creation else {
            return Err(ResumeError::NoCreation {
                name: name.to_string(),
            });
        };
        if creation.switch_address != switch_addr || creation.loopback_address != loopback_addr {
            return Err(ResumeError::NotTheHandedPair {
                name: name.to_string(),
                held_switch: creation.switch_address,
                held_loopback: creation.loopback_address,
            });
        }
        if let Some(asked) = box_id
            && asked != creation.id()
        {
            return Err(ResumeError::NotTheBoxId {
                name: name.to_string(),
                held_box_id: creation.id(),
                asked_box_id: asked,
            });
        }
        Ok(creation)
    }

    /// What a resume presenting `(name, switch_addr, loopback_addr)` and
    /// `box_id` finds, read before anything is allocated for it: the row,
    /// when it stands — the resume's whole answer, which needs no published
    /// address asked of the answerer — or the creation's own name, under
    /// which its dormant row is reinstated ([`Self::resume_client_box`]).
    ///
    /// # Errors
    ///
    /// [`ResumeError`], as [`Self::resume_client_box`] refuses.
    pub fn resumable(
        &self,
        name: &str,
        switch_addr: Ipv4Addr,
        loopback_addr: Ipv4Addr,
        box_id: Option<BoxId>,
    ) -> Result<Resumable, ResumeError> {
        let creation = self.resumable_creation(name, switch_addr, loopback_addr, box_id)?;
        self.withdraw_if_past_its_bound(&creation);
        let rows = self
            .rows
            .read()
            .expect("the row lock is never held across a panic, so it cannot be poisoned");
        Ok(match standing_row_of(&rows, &creation) {
            Some(record) => Resumable::Standing(Arc::clone(record)),
            None => Resumable::Dormant {
                name: creation.name,
            },
        })
    }

    /// Withdraws `creation`'s row when it stands past its bound — its grace
    /// or its resume bound has run out, and the drainer's next sweep
    /// withdraws it ([`Self::withdraw_expired_detached`]) — so a resume
    /// racing that sweep reinstates the row rather than answering with one
    /// about to go.
    fn withdraw_if_past_its_bound(&self, creation: &Creation) {
        let now = self.now();
        self.withdraw_where(creation.switch_address, |rows, record| {
            (record.box_id == creation.id())
                .then(|| record.past_its_bound(rows, now))
                .flatten()
        });
    }

    /// Gives a creator its box's row back (NET-138): the row its creator
    /// registered as box `name`, handed the pair `(switch_addr,
    /// loopback_addr)` — and, when the creator knows it, created as
    /// `box_id` — reinstated from the registry's own creation ([`Creation`])
    /// when the row was withdrawn after its detach grace, or held as it
    /// stands when it was not. The pair is the creator's proof, as for a
    /// withdrawal ([`Self::withdraw_client_box`]), and the lookup key: every
    /// fact the row holds comes from the creation this host kept — the
    /// declaration its creator registered, compiled under this registry's
    /// egress default — never from the request, and never from the guest.
    ///
    /// A row that stands is answered as it stands ([`RowLiveness`]): a
    /// detached row's grace keeps running from its attachment's end, so a
    /// resume never holds it past [`NET_138_WITHDRAWAL_BOUND`]. A dormant
    /// creation's row is published at its own switch address and task
    /// addresses, which the creation kept reserved while it was dormant
    /// ([`Creation`]), and at the published loopback address the answerer
    /// holds for the name now, `allocated_loopback`, which must be the one
    /// the box was created with. The creation is found by `box_id` when
    /// the resume names one, so a session renamed since still resumes it. The reinstated row is awaiting, under its original id: no
    /// grace runs until a relay that carried it ends, and a row no relay
    /// carries — neither its box nor any of its task rows — within
    /// [`RESUME_ATTACH_BOUND`] is withdrawn as at a grace's end, its
    /// creation kept for a later resume.
    ///
    /// `generation` is the name's withdrawal generation read before the
    /// answerer allocated ([`Self::begin_registration`]): a withdrawal that
    /// landed since refuses the resume, as it refuses a registration.
    ///
    /// # Errors
    ///
    /// [`ResumeError`]: the registry keeps no creation under the name, the
    /// pair or the id is not the creation's, or the row cannot be
    /// published. A refusal
    /// changes nothing; the caller hands the answerer's address back unless
    /// something else owns it ([`Self::release_unless_owned`]).
    pub fn resume_client_box(
        &self,
        name: &str,
        switch_addr: Ipv4Addr,
        loopback_addr: Ipv4Addr,
        box_id: Option<BoxId>,
        allocated_loopback: Ipv4Addr,
        generation: u64,
    ) -> Result<Arc<BoxRecord>, ResumeError> {
        let creation = self.resumable_creation(name, switch_addr, loopback_addr, box_id)?;
        self.withdraw_if_past_its_bound(&creation);
        let rows = self
            .rows
            .read()
            .expect("the row lock is never held across a panic, so it cannot be poisoned");
        let name = creation.name.clone();
        // A row that stands is answered as it stands: its liveness is the
        // relays' to change, never the creator's. A detached row's grace
        // keeps running from its attachment's end (NET-138's 60 s), and a
        // row a relay carries, or one awaiting its first frame, takes no
        // bound from a resume.
        if let Some(record) = standing_row_of(&rows, &creation) {
            tracing::info!(
                box = %record.name(),
                switch_addr = %record.switch_addr(),
                detached = record.is_detached(),
                "its creator resumed a box whose row stands; the row is left as it stands"
            );
            return Ok(Arc::clone(record));
        }
        drop(rows);
        if allocated_loopback != creation.loopback_address {
            return Err(ResumeError::LoopbackMoved {
                name: name.to_string(),
                held: creation.loopback_address,
                allocated: allocated_loopback,
            });
        }
        let mut addrs = revocation_addrs(creation.switch_address, creation.loopback_address);
        addrs.extend(creation.task_addresses.iter().map(|addr| addr.octets()));
        if let Some(addr) = self.wait_for_revocations(&addrs, REVOCATION_WAIT) {
            return Err(AllocationError::RevocationPending { addr }.into());
        }
        let now = self.now();
        // The box's switch and task addresses stayed reserved for its
        // creation while it was dormant ([`Creation`]), so the row and its
        // task rows are restored at them with nothing to take.
        let registration = self.client_registration(
            creation.spec(),
            creation.switch_address,
            creation.loopback_address,
            creation.task_addresses.clone(),
            creation.id(),
        );
        let standing = Creation {
            standing: true,
            ..creation
        };
        let record = self.try_register_since(registration, Some(generation), Some(standing))?;
        record.liveness().resumed_since = Some(now);
        tracing::info!(
            box = %record.name(),
            switch_addr = %record.switch_addr(),
            "its creator resumed a box whose row was withdrawn; the row is reinstated from \
             the host's own record of its creation"
        );
        Ok(record)
    }

    /// Marks the row at `switch_addr` carried by one relay fewer, when it
    /// is still box `box_id`'s row: a relay that carried its frames ended
    /// ([`BoxTable::report_withdrawals`]). The last carrier's end detaches
    /// the row ([`RowLiveness`]), from this instant. A report for a box
    /// whose row has gone, or whose address a newer box holds, changes
    /// nothing.
    fn detach(&self, switch_addr: [u8; 4], box_id: BoxId) {
        let now = self.now();
        let rows = self
            .rows
            .read()
            .expect("the row lock is never held across a panic, so it cannot be poisoned");
        let Some(record) = rows
            .get(&switch_addr)
            .filter(|record| record.box_id == box_id)
        else {
            return;
        };
        // A box and its task rows are one liveness unit (NET-138): a task
        // run carrying keeps its box's row standing, so the box row is
        // detached only once no relay carries the box's own address nor
        // any of its task addresses. Locks run box row, then task rows.
        let parent = match record.task_row_of() {
            None => Arc::clone(record),
            Some(_) => {
                {
                    let mut liveness = record.liveness();
                    liveness.carriers = liveness.carriers.saturating_sub(1);
                }
                let Some(parent) = box_row_of(&rows, record) else {
                    return;
                };
                Arc::clone(parent)
            }
        };
        let mut liveness = parent.liveness();
        if !record.is_task_row() {
            liveness.carriers = liveness.carriers.saturating_sub(1);
        }
        if liveness.carriers == 0
            && liveness.detached_since.is_none()
            && !task_rows_carried(&rows, &parent)
        {
            liveness.detached_since = Some(now);
            tracing::info!(
                box = %parent.name(),
                switch_addr = %parent.switch_addr(),
                grace = ?DETACH_GRACE,
                "a box's attachment and every task run's ended; its row is detached and is \
                 withdrawn with its task rows after the grace unless the box or a task run \
                 attaches again"
            );
        }
    }

    /// Withdraws every row detached for [`DETACH_GRACE`] or longer, or
    /// resumed [`RESUME_ATTACH_BOUND`] ago and not carried since, and
    /// returns them: the same withdrawal the drainer always made, at the
    /// bound's end rather than at the relay's ([`Self::withdraw_where`]).
    /// Each row's bound is decided again under the write of the row lock it
    /// leaves under, so a row a relay carried since the scan stays.
    fn withdraw_expired_detached(&self) -> Vec<Arc<BoxRecord>> {
        let now = self.now();
        let rows = self
            .rows
            .read()
            .expect("the row lock is never held across a panic, so it cannot be poisoned");
        let expired: Vec<Ipv4Addr> = rows
            .values()
            .filter(|record| record.past_its_bound(&rows, now).is_some())
            .map(|record| record.switch_addr)
            .collect();
        drop(rows);
        expired
            .into_iter()
            .filter_map(|addr| {
                self.withdraw_where(addr, |rows, record| record.past_its_bound(rows, now))
            })
            .collect()
    }

    /// Holds a removed row's addresses against reuse until its revocation
    /// ends ([`RowWithdrawal`]). Called under the row lock that removed it.
    /// `None`, and no hold, when nothing subscribes to withdrawals: then
    /// nothing will unbind the row's forwards, and nothing would release
    /// the hold either.
    fn begin_revocation(&self, record: &BoxRecord) -> Option<RowWithdrawal> {
        let subscribed = !self
            .row_withdrawals
            .lock()
            .expect("the withdrawal subscribers' lock is held only across pushes and sends")
            .is_empty();
        if !subscribed {
            return None;
        }
        let addrs = record.revocation_addrs();
        self.revoking.hold(&addrs);
        Some(RowWithdrawal {
            switch_addr: record.switch_addr,
            hold: Arc::new(RevocationHold {
                addrs,
                revoking: Arc::clone(&self.revoking),
            }),
        })
    }

    /// Retires a removed row's side facts: its pending asks are cancelled
    /// (NET-045), its stopped mark is stale with the row gone, the
    /// row-withdrawal subscribers are each handed a copy of `withdrawal`
    /// (design §7.1: the gate unbinds the box's forwards, holding the row's
    /// addresses until it has), and the change is a ping like any other. A
    /// subscriber that is gone drops its copy, so it holds nothing.
    fn retired(&self, removed: &Option<Arc<BoxRecord>>, withdrawal: Option<RowWithdrawal>) {
        if let Some(record) = removed {
            if let Some(withdrawal) = withdrawal {
                self.row_withdrawals
                    .lock()
                    .expect("the withdrawal subscribers' lock is held only across pushes and sends")
                    .retain(|subscriber| subscriber.send(withdrawal.clone()).is_ok());
            }
            // The row's pending asks go with it (NET-045): with no grant
            // left to publish under, each ends cancelled, and its guest's
            // serving thread audits the cancellation it receives.
            for ended in self.cancel_asks_for_row(record.switch_addr) {
                tracing::info!(
                    ask_id = %ended.ask_id,
                    box = %ended.facts.name,
                    port = ended.facts.port,
                    proto = %ended.facts.proto,
                    dismissed = ended.dismissed,
                    "cancelled a pending ask: its box's row was withdrawn"
                );
            }
            self.stopped
                .write()
                .expect(
                    "the stopped set's lock is never held across a panic, so it cannot be \
                     poisoned",
                )
                .remove(&record.switch_addr.octets());
            self.ping();
        }
    }

    /// Records the in-VM daemon's admit report of one runtime-published
    /// port (NET-138, NET-045) into the row at `switch_addr` — the one row
    /// dimension a guest's own report fills, and only within the grant the
    /// row's host-side registration holds. The checks, in order:
    ///
    /// 1. **A row exists** at the switch address the registration handed
    ///    back — a report keyed anywhere else is no row's and is refused.
    /// 2. **The stance** is `allow`: `deny`, the default an absent
    ///    declaration carries, admits nothing, and `ask` admits nothing a
    ///    guest reports — ask-yes must be host-recorded, because only the
    ///    host sees the attached human's answer.
    /// 3. **The port is inside the row's allowed range**, inclusively at
    ///    both ends; a row that declared no range permits nothing.
    /// 4. **A port the row already holds** is answered as recorded, a
    ///    no-op: the report's goal state already holds, so it spends
    ///    neither the cap nor the rate. A retry after a lost reply is this
    ///    case, and it must never be refused for a port the host holds —
    ///    a refusal is not withdrawn, so the row would keep a port its
    ///    reporter believes was refused.
    /// 5. **The row holds fewer than [`RUNTIME_PORT_CAP`] runtime ports.**
    /// 6. **The row is inside its admit rate** — at most
    ///    [`ROW_ADMIT_RATE_PER_SECOND`] recorded reports per trailing
    ///    second, counting every report that records a new port: the rate
    ///    bounds the reporting, not the ports.
    ///
    /// A report that passes records the port idempotently — the port and
    /// protocol pair the report named — and answers the row it recorded
    /// into, so the caller can name the box its line speaks for. A refusal
    /// answers [`PortReportRefusal`] naming the box where the row exists and
    /// the check that refused, and records nothing: no rate timestamp, no
    /// port, no fact the host did not hold.
    ///
    /// `now` is the instant the report arrived, injected so the rate and
    /// the cap are testable without waiting real seconds.
    ///
    /// # Errors
    ///
    /// [`PortReportRefusal`] — never a panic; the lock guards are poison
    /// guards only, and no lock is held across a panic.
    pub fn admit_runtime_port(
        &self,
        switch_addr: Ipv4Addr,
        port: u16,
        proto: IpProto,
        now: Instant,
    ) -> Result<Arc<BoxRecord>, PortReportRefusal> {
        // The rows guard is a read lock held for the whole call — the row's
        // registration-frozen facts first, then the runtime half nested
        // inside — so reports against different rows run concurrently and
        // the registration's write lock only waits out its own turn. No
        // path takes the two in the other order (a row's withdrawal drops
        // the row from the map without touching its runtime half), so the
        // nesting is acyclic.
        let rows = self
            .rows
            .read()
            .expect("the row lock is never held across a panic, so it cannot be poisoned");
        let record = rows
            .get(&switch_addr.octets())
            .ok_or(PortReportRefusal::NoRow {
                switch_addr,
                port,
                proto,
            })?;
        let name = record.name().to_string();
        match record.dynamic_ingress() {
            DynamicIngress::Deny => {
                return Err(PortReportRefusal::DenyStance { name, port, proto });
            }
            // `ask` records only what the attached human answered yes to
            // (NET-045), and the guest's report is not that answer: ask-yes
            // must be host-recorded, so a guest report under `ask` is
            // refused and records nothing.
            DynamicIngress::Ask => {
                return Err(PortReportRefusal::AskNotHostRecorded { name, port, proto });
            }
            DynamicIngress::Allow => {}
        }
        let range = record
            .dynamic_range()
            .ok_or_else(|| PortReportRefusal::NoAllowedRange {
                name: name.clone(),
                port,
                proto,
            })?;
        if port < range.0 || port > range.1 {
            return Err(PortReportRefusal::OutsideAllowedRange {
                name,
                port,
                proto,
                range,
            });
        }
        // The row's runtime half: a held port, then cap, then rate, then the
        // recording — one lock section, so a report that passes every check
        // is recorded in the order it arrived.
        let reported = RuntimePort { port, proto };
        let mut runtime = record
            .runtime_ports
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if runtime.ports.contains(&reported) {
            return Ok(Arc::clone(record));
        }
        if runtime.ports.len() >= RUNTIME_PORT_CAP {
            return Err(PortReportRefusal::RowCapReached {
                name,
                port,
                proto,
                cap: RUNTIME_PORT_CAP,
            });
        }
        // The trailing-second window: every recorded report inside it
        // counts, and a report over the rate is refused without pacing.
        while runtime
            .admits
            .front()
            .is_some_and(|at| now.duration_since(*at) >= ADMIT_RATE_WINDOW)
        {
            runtime.admits.pop_front();
        }
        if runtime.admits.len() >= ROW_ADMIT_RATE_PER_SECOND {
            return Err(PortReportRefusal::RateExceeded {
                name,
                port,
                proto,
                rate: ROW_ADMIT_RATE_PER_SECOND,
            });
        }
        runtime.admits.push_back(now);
        runtime.ports.push(reported);
        Ok(Arc::clone(record))
    }

    /// Applies the in-VM daemon's withdrawal report of one runtime-published
    /// port: the port leaves the row's runtime set, so the gate no longer
    /// admits a retraction of it and the read-only row verb no longer lists
    /// it. Never refused — the cap and the rate are the admit path's bounds,
    /// and removing a fact the row holds (or already lacks) is always the
    /// goal state — and never counted against the rate. Answers the row the
    /// port was withdrawn from, `None` when no row is held at the address:
    /// the report was accepted either way.
    pub fn withdraw_runtime_port(
        &self,
        switch_addr: Ipv4Addr,
        port: u16,
        proto: IpProto,
    ) -> Option<Arc<BoxRecord>> {
        let rows = self
            .rows
            .read()
            .expect("the row lock is never held across a panic, so it cannot be poisoned");
        let record = rows.get(&switch_addr.octets())?;
        let mut runtime = record
            .runtime_ports
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        runtime
            .ports
            .retain(|reported| !(reported.port == port && reported.proto == proto));
        Some(Arc::clone(record))
    }

    /// The live row registered under `name` (the read-only row verb's
    /// resolution, NET-138), under the alias rule: a name is an alias,
    /// never identity — the box's identity is its id (BEP-070) — so the
    /// name resolves to the live box that holds it, and liveness is the
    /// table's own fact. A box whose row is withdrawn is gone, not
    /// archived, so a name no live row holds answers no row, never a
    /// destroyed box's last row. `None` when no live row carries the name.
    ///
    /// Exact match alone is not the rule: the table does not hold names
    /// unique. Rows are keyed by switch address; a client registration is
    /// refused while a live row holds its folded name
    /// ([`AllocationError::NameAlreadyHeld`]), but a row registered in
    /// process ([`Self::try_register`]) can sit beside an older one under
    /// the same name until the older one's withdrawal lands.
    /// While both are held, the alias resolves to the newest creation —
    /// the row with the greatest id, because every id is a UUIDv7 this
    /// process minted ([`crate::bep_attach::mint_box_id`]), and the crate
    /// orders those by creation within a process. The name is matched in
    /// its canonical form ([`crate::net::answerer::canonical_box_name`]):
    /// the answerer keys the box's published address by that form, so the
    /// row table and the address hold one box to a folded-equal name.
    #[must_use]
    pub fn row_by_name(&self, name: &str) -> Option<Arc<BoxRecord>> {
        let asked = canonical_box_name(name);
        let rows = self
            .rows
            .read()
            .expect("the row lock is never held across a panic, so it cannot be poisoned");
        rows.values()
            .filter(|record| !record.is_task_row() && canonical_box_name(record.name()) == asked)
            .max_by_key(|record| record.box_id())
            .cloned()
    }

    /// Marks the namespace published at `switch_addr` stopped: its row
    /// stays — a stopped namespace is never mistaken for one that never
    /// existed, so its zone name stays held and answers NODATA rather than
    /// NXDOMAIN (NET-128) — but it answers no address while the mark
    /// stands. A registration at the same address clears the mark, because
    /// the newest declaration is a namespace that is running. Returns
    /// whether a row was published at the address: marking an address no
    /// row holds marks nothing.
    ///
    /// No production path marks a row stopped yet. A box's lifecycle lives
    /// with the guest daemon that runs it, and the host learns a box
    /// stopped when the task that carries box lifecycle over the host's
    /// control path lands; this mutator is the seam that task writes
    /// through, and the zone view and the state dump already carry the
    /// mark.
    pub fn mark_stopped(&self, switch_addr: Ipv4Addr) -> bool {
        let held = self
            .rows
            .read()
            .expect("the row lock is never held across a panic, so it cannot be poisoned")
            .contains_key(&switch_addr.octets());
        if held {
            self.stopped
                .write()
                .expect(
                    "the stopped set's lock is never held across a panic, so it cannot be \
                     poisoned",
                )
                .insert(switch_addr.octets());
            self.ping();
        }
        held
    }

    /// Holds box `name`'s name in the zone with no row behind it (the
    /// `host_ip` interim): from here a lookup of `<name>.min.internal`
    /// answers NODATA where an unheld name answers NXDOMAIN. Idempotent;
    /// a name a live row publishes is the row's — the fold in
    /// [`Self::zone_view`] keeps the row's entry, so the two coexist.
    /// `owner` is the session the hold is for: a later hold of the name
    /// takes it over. Returns whether the table did not hold the name
    /// already.
    pub fn hold_box_name(&self, name: &str, owner: Option<sessions::SessionId>) -> bool {
        let inserted = self
            .held_names
            .write()
            .expect("the held names' lock is never held across a panic, so it cannot be poisoned")
            .insert(canonical_box_name(name), owner)
            .is_none();
        if inserted {
            tracing::info!(
                box = %name,
                "held a box name in the zone with no row behind it; it answers NODATA"
            );
            self.ping();
        }
        inserted
    }

    /// Releases a name [`Self::hold_box_name`] holds: the name answers
    /// nothing again — NXDOMAIN, the pre-box state. A name no hold kept
    /// is the goal state already holding. Returns whether a hold was
    /// actually released.
    ///
    /// With an `owner`, the release frees every hold that session made,
    /// under whatever name it holds now (a rename moved it), plus `name`'s
    /// hold when no session owns it; a hold another session made under
    /// `name` stays. Without one, `name`'s hold goes whoever made it.
    pub fn release_held_name(&self, name: &str, owner: Option<sessions::SessionId>) -> bool {
        let canonical = canonical_box_name(name);
        let mut held = self
            .held_names
            .write()
            .expect("the held names' lock is never held across a panic, so it cannot be poisoned");
        let before = held.len();
        match owner {
            Some(owner) => held.retain(|held_name, held_by| match held_by {
                Some(session) => *session != owner,
                None => *held_name != canonical,
            }),
            None => {
                held.remove(&canonical);
            }
        }
        let removed = held.len() != before;
        drop(held);
        if removed {
            tracing::info!(
                box = %name,
                "released a held box name; it answers nothing again"
            );
            self.ping();
        }
        removed
    }

    /// Subscribes to the table's change pings: one `()` per registration,
    /// withdrawal, and stopped mark, for as long as the returned receiver
    /// lives. The host answerer subscribes — a daemon that does not hold
    /// the answerer port re-registers its zone rows with the one that does
    /// on every change — and so does the zone-table dump
    /// ([`crate::diag`]); a subscriber is pruned with its receiver, and a
    /// ping to a dead one is dropped, never a registration held back. The
    /// channel is unbounded and every sender drops a refused send, so a
    /// slow registrar holds its own pings back, never the table's.
    pub fn subscribe_table_pings(&self) -> std::sync::mpsc::Receiver<()> {
        let (sender, receiver) = std::sync::mpsc::channel();
        self.table_pings
            .lock()
            .expect("the ping channels' lock is held only across pushes and pings")
            .push(sender);
        receiver
    }

    /// Files one change ping to every live subscriber, pruning the dead
    /// ones as it goes.
    fn ping(&self) {
        self.table_pings
            .lock()
            .expect("the ping channels' lock is held only across pushes and pings")
            .retain(|sender| sender.send(()).is_ok());
    }

    /// The zone view the host answerer answers the box zone from (NET-138):
    /// every published row's name under the zone apex —
    /// `<name>.min.internal`, the form the shared decision matches — with
    /// the host-answerable address a lookup may be told (NET-127) and the
    /// row's liveness (NET-128). One row per namespace, held in name
    /// order, so the view a lookup answers from and the table the state
    /// dump writes are the same rows.
    ///
    /// The address is the row's published loopback address when it is one
    /// the host may be told and `None` when it is not: a row's switch
    /// lease is inside the guest's fabric, nothing on the host OS routes
    /// to it, and a name held only there answers NODATA rather than
    /// pointing a lookup somewhere it cannot go (the same gate the native
    /// daemon's registry applies, [`is_host_answerable`]). The node's own
    /// namespace is a row like any other — its services sit at the
    /// machine's shared loopback address, which is answerable, so the row
    /// answers with it.
    ///
    /// Liveness is the table's own fact: a row is live from its
    /// registration, and [`Self::mark_stopped`] holds it NODATA while the
    /// namespace it names is not running. The view is a snapshot, built
    /// fresh by whoever asks — a lookup, a dump, a registration — so it
    /// can never hold a row the table has already let go.
    ///
    /// The names held with no row behind them ([`Self::hold_box_name`],
    /// the `host_ip` interim) fold in after the rows as address-less
    /// entries: a name a row publishes is the row's, and a name only
    /// held answers NODATA.
    #[must_use]
    pub fn zone_view(&self) -> zone_answer::ZoneView {
        // The rows lock first, the stopped set inside it — the order every
        // other path through both takes (`register`, `retired`,
        // `mark_stopped`), so the two locks never wait on each other.
        let rows = self
            .rows
            .read()
            .expect("the row lock is never held across a panic, so it cannot be poisoned");
        let stopped = self.stopped.read().expect(
            "the stopped set's lock is never held across a panic, so it cannot be \
                 poisoned",
        );
        let mut view = zone_answer::ZoneView::new();
        // A task row publishes no name: its box's row holds the box's.
        for record in rows.values().filter(|record| !record.is_task_row()) {
            view.hold(
                zone_name(record.name()),
                zone_answer::ZoneRow {
                    address: is_host_answerable(record.loopback_addr())
                        .then_some(record.loopback_addr()),
                    live: !stopped.contains(&record.switch_addr.octets()),
                },
            );
        }
        drop(stopped);
        drop(rows);
        // Held names fold in after the rows: a name a row publishes keeps
        // the row's entry — replacing it would drop the address a live box
        // answers with — and a name only held answers NODATA.
        let held_names = self
            .held_names
            .read()
            .expect("the held names' lock is never held across a panic, so it cannot be poisoned");
        for name in held_names.keys() {
            let zone_name = zone_name(name);
            if view.rows().find(|(held, _)| *held == zone_name).is_none() {
                view.hold(
                    zone_name,
                    zone_answer::ZoneRow {
                        address: None,
                        live: true,
                    },
                );
            }
        }
        view
    }

    /// Publishes the guest **node's** own namespace: the in-VM daemon's
    /// root-netns tap, the plane design §5.1 names node-plane. The address is
    /// the host's own derivation from the subnet it configured the switch
    /// with ([`SwitchSubnet::daemon_ip`]) — the guest is neither asked nor
    /// able to influence what this row holds.
    ///
    /// The admitted port is the one the daemon's own setup publishes at its
    /// address: the hostname proxy's, assigned by the VM host before the VM
    /// boots ([`crate::cmd::run`] hands it to the guest on the kernel command
    /// line) and bound by the guest daemon as handed — so the publishes the
    /// daemon makes to attach it are publishes of a port this row already
    /// names, not requests for the host to open its own. The zone answerer is
    /// not the node's to admit (NET-138): on a VM-backed host the in-VM daemon
    /// starts no answerer — the host answerer serves the zone — so an
    /// answerer port on this row would be an admitted port with nothing
    /// behind it, a standing grant.
    ///
    /// The rules are the allow-all interim the absent-policy default ships:
    /// the node-plane baseline set is un-enrolled until NET-130's enumeration
    /// lands, and until then the daemon keeps the reach it had before the
    /// gate existed — its own package fetches above all, which is the
    /// VM-side shape of NET-080. NET-130 tightens this row to the categories
    /// design §5.1 enumerates.
    ///
    /// # Errors
    ///
    /// [`AllocationError::RevocationPending`] when the node's previous row
    /// was withdrawn and its revocation still holds the node's address past
    /// [`REVOCATION_WAIT`] ([`Self::try_register`]).
    pub fn try_register_node_namespace(
        &self,
        proxy_port: u16,
    ) -> Result<Arc<BoxRecord>, AllocationError> {
        let daemon_ip = self.subnet.daemon_ip();
        let _still_held = self.wait_for_revocations(
            &revocation_addrs(daemon_ip, Ipv4Addr::LOCALHOST),
            REVOCATION_WAIT,
        );
        self.try_register(
            BoxRegistration::new(NODE_NAMESPACE, daemon_ip, Ipv4Addr::LOCALHOST)
                .with_admitted_ports([proxy_port]),
        )
    }

    /// [`Self::try_register_node_namespace`] for a test whose node address
    /// no revocation holds.
    #[cfg(test)]
    pub fn register_node_namespace(&self, proxy_port: u16) -> Arc<BoxRecord> {
        self.try_register_node_namespace(proxy_port)
            .expect("a test's node address is never held by a revocation")
    }

    /// Takes the receiving end of the gate's withdrawal reports, once: every
    /// [`BoxTable`] clone holds the sending end, and the reports a relay
    /// files at its end — the switch addresses whose traffic it relayed —
    /// arrive here for the registry to withdraw by. `None` once taken; the
    /// caller that wants them drained by a thread wants
    /// [`Self::spawn_withdrawal_drainer`] instead.
    pub fn take_withdrawal_reports(&self) -> Option<std::sync::mpsc::Receiver<WithdrawalReport>> {
        self.withdrawal_reports_rx
            .lock()
            .expect("the report channel's lock is held only across this take")
            .take()
    }

    /// Spawns the thread that applies the gate's withdrawal reports and
    /// withdraws the rows they leave detached past their grace. One report
    /// — the switch addresses whose relayed traffic ended with a
    /// connection, each with the box it was attributed to — detaches each
    /// row no other relay still carries ([`RowLiveness`]), and every
    /// [`DETACH_SWEEP_INTERVAL`] the thread withdraws the rows detached for
    /// [`DETACH_GRACE`] ([`Self::withdraw_where`]): so a box whose shuttle
    /// reconnects and carries a frame from its address inside the grace
    /// keeps its row, and one whose attachment stays ended loses it no
    /// later than the grace plus one sweep after its end — inside NET-138's
    /// 60 s. The box's own shuttle connection, the one its frames travel
    /// by, is what the report rides (and a row whose traffic never ends is
    /// never detached).
    ///
    /// A withdrawn row whose creation the registry keeps leaves the
    /// creation dormant with every address reserved for it ([`Creation`]):
    /// its switch and task addresses stay out of the hand-out book, and its
    /// published loopback address stays its name's at the answerer, so its
    /// creator's resume finds them all. Any other withdrawal hands the
    /// box's published loopback address back to the machine's answerer, by
    /// running `release_address` with the row's name, unless something else
    /// owns it ([`Self::release_withdrawn_unless_owned`]: a live row or a
    /// kept creation under the name, or a registration of it in flight),
    /// and its switch address goes back to the hand-out book inside the
    /// withdrawal.
    ///
    /// The thread holds a clone of this registry, so it withdraws the same
    /// rows every other handle sees. That clone carries one of the
    /// reports' senders — the very channel the thread drains — so the
    /// senders are never all gone while the thread runs: the loop does not
    /// exit. The thread is for the process's lifetime, which is the
    /// design's intent, and nothing in teardown may rely on its exit.
    ///
    /// Idempotent by the take underneath: a second call finds no receiver
    /// and spawns nothing.
    pub fn spawn_withdrawal_drainer(&self, release_address: impl Fn(&str) + Send + 'static) {
        // Taken from this registry, never a clone: the receiver lives only
        // on the registry that created the channel, and a clone carries
        // `None` for it, so a clone's take would return `None` and spawn
        // nothing.
        let Some(reports) = self.take_withdrawal_reports() else {
            return;
        };
        let registry = self.clone();
        let spawned = std::thread::Builder::new()
            .name("box-row-withdrawals".to_string())
            .spawn(move || {
                loop {
                    match reports.recv_timeout(DETACH_SWEEP_INTERVAL) {
                        Ok(report) => {
                            for (addr, box_id) in report {
                                registry.detach(addr, box_id);
                            }
                        }
                        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                    }
                    for record in registry.withdraw_expired_detached() {
                        registry.release_withdrawn_unless_owned(record.name(), || {
                            release_address(record.name());
                        });
                    }
                }
            });
        if let Err(error) = spawned {
            // The reports keep buffering; the rows stay held. A thread the
            // host could not spare is a host that is not running a VM long —
            // but a silent drop of the withdrawal path would leave rows
            // published past their boxes, so say so.
            tracing::warn!(
                %error,
                "could not spawn the box-row withdrawal drainer; rows will \
                 outlive their shuttle connections until it starts"
            );
        }
    }

    /// The read-only view the egress gate decides by — the same rows this
    /// registry holds, shared, so every later registration reaches the
    /// running gate. The view carries a clone of the withdrawal reports'
    /// sender with it: filing one is the view's single write-shaped act, and
    /// it is a report to this process, not a row operation — see
    /// [`BoxTable`].
    #[must_use]
    pub fn table(&self) -> BoxTable {
        BoxTable {
            rows: Arc::clone(&self.rows),
            subnet: self.subnet,
            withdrawal_reports: self.withdrawal_reports.clone(),
            row_withdrawals: Arc::clone(&self.row_withdrawals),
            revoking: Arc::clone(&self.revoking),
            row_epoch: Arc::clone(&self.row_epoch),
        }
    }
}

/// The run of published loopback addresses a box may take inside `slice`:
/// the slice clamped to the reserved local range's interior. The range's
/// network address, `.1` and its broadcast address are never a box's — a
/// slice that starts at or ends on one of them keeps it out of a box's
/// hands too.
///
/// That interior is the answerer's own hand-out run, read from its one
/// definition ([`switch::box_loopback_interior`]) rather than restated;
/// this run is the tests' single-node cursor clamped to it, so a test box
/// never holds an address the answerer would refuse.
#[cfg(test)]
fn box_loopback_run(slice: switch::LoopbackSlice) -> (u32, u32) {
    let (box_first, box_last) = switch::box_loopback_interior();
    let first = u32::from(slice.first()).max(u32::from(box_first));
    let last = u32::from(slice.last()).min(u32::from(box_last));
    (first, last)
}

/// Takes the next unspent address from `cursor`, when `first..=last` still
/// holds one: the tests' single-node loopback cursor
/// ([`BoxRegistry::register_client_box`]); the daemon's switch addresses
/// come from the hand-out book ([`SwitchAddressBook`]). Relaxed ordering: a
/// cursor's only invariant is that no two takes return the same address,
/// which an atomic update gives on every ordering. The cursor advances by
/// a checked add, so it stops at `u32::MAX` rather than wrapping back
/// into a run it already handed out, and the run's bounds are checked on
/// the taken value, so a cursor past its run's end hands out nothing.
#[cfg(test)]
fn take_next(cursor: &AtomicU32, first: u32, last: u32) -> Option<Ipv4Addr> {
    let next = cursor
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |next| {
            next.checked_add(1)
        })
        .ok()?;
    (first <= next && next <= last).then(|| Ipv4Addr::from(next))
}

/// A namespace's name under the zone apex, as the zone view holds it:
/// `<name>.min.internal`. The view normalizes what it is given, so the
/// row's name passes through exactly as the declaration spelled it.
fn zone_name(name: &str) -> String {
    format!("{name}.{}", zone_answer::ZONE_APEX)
}

/// Whether `addr` is one an A answer in the box zone may carry (NET-127):
/// the host's shared loopback address, or an address from the reserved
/// local range the address plan publishes boxes at. Anything else — a box's
/// switch lease inside the guest's fabric, an address another host holds —
/// is not one the host OS can reach, and a name held only there answers
/// NODATA rather than pointing a lookup somewhere it cannot go. The same
/// gate the native daemon's registry applies
/// (`minimald::net::dns::is_host_answerable`), restated against the range's
/// one definition in the switch crate so the two cannot drift.
pub(crate) fn is_host_answerable(addr: Ipv4Addr) -> bool {
    addr == Ipv4Addr::LOCALHOST || in_reserved_local_range(addr)
}

/// Whether `addr` falls in the reserved local range the address plan
/// publishes boxes at.
fn in_reserved_local_range(addr: Ipv4Addr) -> bool {
    let (network, prefix) = switch::RESERVED_LOCAL_RANGE;
    let host_bits = 32 - u32::from(prefix);
    // A /0 range would mean "every address"; the shift below needs a
    // network part to keep.
    if host_bits >= 32 {
        return true;
    }
    let mask = u32::MAX << host_bits;
    u32::from(network) & mask == u32::from(addr) & mask
}

/// The read-only view of the published rows the egress gate decides by: the
/// lookup a frame's source address resolves through, and nothing else that
/// touches a row. The registry hands the gate this view because its row
/// operations are lookups only — the component that reads guest frames
/// cannot add, replace, or withdraw a row (NET-138: the table is filled on
/// the host, never from the guest).
///
/// What the view carries beside the lookups is one channel: filing a
/// withdrawal report at a relay's end. It is deliberately **not** a row
/// operation — the report leaves this process as a fact the host acts on
/// ([`BoxRegistry::detach`] through the drainer, then the withdrawal once
/// the grace passes unreattributed), so the guest's
/// influence on the table is still bounded by what it can make the host
/// observe: that a connection whose relayed traffic named an address is
/// over. Which is the withdrawal NET-133 asks for, and nothing more.
///
/// Cheap to clone; every clone shares the registry's rows, carries the
/// registry's plan beside them, and files its reports into the one channel.
#[derive(Debug, Clone)]
pub struct BoxTable {
    rows: Arc<RwLock<Rows>>,
    subnet: SwitchSubnet,
    withdrawal_reports: std::sync::mpsc::Sender<WithdrawalReport>,
    row_withdrawals: RowWithdrawals,
    revoking: Arc<Revoking>,
    row_epoch: Arc<AtomicU64>,
}

impl BoxTable {
    /// Subscribes to row withdrawals: the receiver gets the switch address
    /// of every row the registry removes from here on, whichever path
    /// removed it (the drainer's grace sweep, [`BoxRegistry::withdraw`] or
    /// the creator's
    /// [`BoxRegistry::withdraw_client_box`]). Like the withdrawal report,
    /// this is a fact the host observed, never a row operation: the
    /// subscriber learns that a box ended and cannot add, replace or
    /// withdraw a row. The egress gate subscribes, so that it unbinds a
    /// withdrawn box's forwards and terminates their connections (design
    /// §7.1, host-side ingress revocation). A subscriber that drops its
    /// receiver is pruned on the next withdrawal.
    ///
    /// Each [`RowWithdrawal`] holds the row's addresses against reuse until
    /// the subscriber drops it, so a subscriber keeps it exactly as long as
    /// the work it does for the row's end.
    #[must_use]
    pub fn subscribe_row_withdrawals(&self) -> tokio::sync::mpsc::UnboundedReceiver<RowWithdrawal> {
        let (sender, receiver) = tokio::sync::mpsc::unbounded_channel();
        self.row_withdrawals
            .lock()
            .expect("the withdrawal subscribers' lock is held only across pushes and sends")
            .push(sender);
        receiver
    }

    /// Whether a withdrawn box's revocation still holds `addr` against
    /// reuse ([`RowWithdrawal`]): the gate refuses a publish there until
    /// the revocation ends, so that it never unbinds a forward that a later
    /// publish at the same address bound.
    #[must_use]
    pub fn revocation_pending(&self, addr: [u8; 4]) -> bool {
        self.revoking.first_held(&[addr]).is_some()
    }

    /// Marks the row at `src` attributed and carried, when one is held, and
    /// returns its box's id: a frame of its box crossed the gate on a relay
    /// that reports the address, with the id, at its end. A relay marks
    /// through [`Self::carry`], once per row it carries. Like the withdrawal
    /// report, it is a fact the host observed at its end of the box's
    /// attachment, not a row operation: it changes nothing the gate decides
    /// by, only whether the row's switch address is quarantined when the
    /// row goes ([`BoxRecord::was_attributed`]) and whether the row is
    /// attached ([`RowLiveness`]) — a detached row a relay carries again is
    /// re-attributed and stays. Both are stored under the row lock's read
    /// half, and a withdrawal decides after taking the write half, so a
    /// mark made while the row stood is always seen.
    #[cfg(test)]
    pub fn mark_attributed(&self, src: [u8; 4]) -> Option<BoxId> {
        let rows = self
            .rows
            .read()
            .expect("the row lock is never held across a panic, so it cannot be poisoned");
        let record = rows.get(&src)?;
        mark_row(&rows, record);
        Some(record.box_id)
    }

    /// Marks `src` carried by the relay `relay` is the record of: attributes
    /// the row at it and counts the relay as one of its carriers, once per
    /// row rather than once per source. A source the relay already marked
    /// is marked again when the row at it is a new one — its creator
    /// reinstated it while this relay carried its box (NET-138), or a row
    /// landed where none stood when the relay first attributed the source
    /// — so a live relay always counts as one carrier of the row its box's
    /// frames are decided by. A frame of a source the relay marked, while
    /// no row has landed since, costs one atomic read.
    pub fn carry(&self, src: [u8; 4], relay: &mut RelayCarry) {
        let epoch = self.row_epoch.load(Ordering::Acquire);
        let seen = relay.marked.iter().any(|(addr, _)| *addr == src);
        if seen && epoch == relay.epoch {
            return;
        }
        let stale = epoch != relay.epoch;
        relay.epoch = epoch;
        if !seen {
            relay.marked.push((src, std::sync::Weak::new()));
        }
        let rows = self
            .rows
            .read()
            .expect("the row lock is never held across a panic, so it cannot be poisoned");
        for (addr, marked) in &mut relay.marked {
            if !stale && *addr != src {
                continue;
            }
            let Some(record) = rows.get(addr) else {
                continue;
            };
            if std::sync::Weak::ptr_eq(marked, &Arc::downgrade(record)) {
                continue;
            }
            mark_row(&rows, record);
            *marked = Arc::downgrade(record);
            if !relay.carried.contains(&(*addr, record.box_id)) {
                relay.carried.push((*addr, record.box_id));
            }
        }
    }
}

/// What one relay marked carried ([`BoxTable::carry`]): each source it
/// attributed with the row it marked there, and the sources with the box
/// ids it reports at its end ([`BoxTable::report_withdrawals`]). Bounded
/// by the rows: a source is recorded once, whatever the guest sends.
#[derive(Debug, Default)]
pub struct RelayCarry {
    /// The table's row epoch the marks were last checked against.
    epoch: u64,
    /// Each source the relay attributed, with the row it marked for it —
    /// dangling when no row stood there.
    marked: Vec<([u8; 4], std::sync::Weak<BoxRecord>)>,
    /// The sources the relay carried, each with its row's box id: the
    /// report the relay files at its end.
    carried: WithdrawalReport,
}

impl RelayCarry {
    /// The report the relay files at its end: every source it carried,
    /// with the box id of the row it marked there.
    #[must_use]
    pub fn into_report(self) -> WithdrawalReport {
        self.carried
    }
}

/// Marks `record` attributed and carried by one relay more: the row's
/// half of [`BoxTable::carry`]. Called under the read of the row lock
/// `rows` was read through.
fn mark_row(rows: &Rows, record: &Arc<BoxRecord>) {
    record.attributed.store(true, Ordering::Relaxed);
    // A task row carried keeps its box's row standing (NET-138): the
    // box row's detach and resume bound clear as if the box carried.
    // Locks run box row, then task row, as in the drainer's detach.
    let parent = box_row_of(rows, record).unwrap_or(record);
    let mut parent_liveness = parent.liveness();
    parent_liveness.resumed_since = None;
    if parent_liveness.detached_since.take().is_some() {
        tracing::info!(
            box = %parent.name(),
            switch_addr = %parent.switch_addr(),
            task_addr = ?record.is_task_row().then(|| record.switch_addr()),
            "a detached box or one of its task runs attached again; its row stays"
        );
    }
    if record.is_task_row() {
        let mut liveness = record.liveness();
        liveness.carriers = liveness.carriers.saturating_add(1);
    } else {
        parent_liveness.carriers = parent_liveness.carriers.saturating_add(1);
    }
}

impl BoxTable {
    /// The published namespace holding the switch address `src`, when one
    /// does. This is the whole of the gate's per-frame routing: an address a
    /// row holds is decided by that row's rules, and an address no row holds
    /// is the phase's to decide ([`crate::net::egress_gate`]), never a
    /// rule's.
    #[must_use]
    pub fn by_source(&self, src: [u8; 4]) -> Option<Arc<BoxRecord>> {
        self.rows
            .read()
            .expect("the row lock is never held across a panic, so it cannot be poisoned")
            .get(&src)
            .cloned()
    }

    /// Whether the plan could ever hand `src` to a box: inside the registry's
    /// subnet, and inside the run its address plan allocates PTask leases from
    /// ([`SwitchSubnet::first_ptask`] through [`SwitchSubnet::last_ptask`]) —
    /// the one set of addresses a published row is ever keyed by, and so the
    /// one set whose rows the host-side creator will supply (T66's registration
    /// path). The run spans both of the plan's sub-runs — the daemon's
    /// self-allocation reserve included, which an in-VM daemon no longer
    /// draws from (NET-138), so a source there is an unregistered one; the
    /// host hands registered boxes and their task addresses only from the
    /// upper half (`hand_out_run`). The subnet's own infrastructure sits outside that
    /// run: the gateway the resolver carve-out is keyed to, the host alias,
    /// and the guest daemon's own tap, which the registry publishes a row for
    /// itself. The gate's unregistered drop (NET-085) refuses a source only
    /// from here, so no amount of it can borrow the plan's infrastructure as
    /// a source, and this predicate is what keeps that drop and the
    /// unknown-source refusal one address range apart.
    #[must_use]
    pub fn is_allocatable(&self, src: [u8; 4]) -> bool {
        let addr = u32::from(Ipv4Addr::from(src));
        self.subnet.first_ptask() <= addr && addr <= self.subnet.last_ptask()
    }

    /// Every published row, in switch-address order.
    #[must_use]
    pub fn rows(&self) -> Vec<Arc<BoxRecord>> {
        self.rows
            .read()
            .expect("the row lock is never held across a panic, so it cannot be poisoned")
            .values()
            .cloned()
            .collect()
    }

    /// Whether no namespace is published.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rows
            .read()
            .expect("the row lock is never held across a panic, so it cannot be poisoned")
            .is_empty()
    }

    /// The plan's lease run — `first_ptask` through `last_ptask` — as the
    /// octet arrays the publish decision compares a request's switch address
    /// by. The same bounds [`Self::is_allocatable`] decides frames by; the
    /// publish decision needs them as values because its table is an owned,
    /// pure one ([`sessions::core::switch_request`]), built fresh per
    /// request.
    #[must_use]
    pub fn ptask_run(&self) -> ([u8; 4], [u8; 4]) {
        (
            Ipv4Addr::from(self.subnet.first_ptask()).octets(),
            Ipv4Addr::from(self.subnet.last_ptask()).octets(),
        )
    }

    /// The switch's own address — the plan's gateway, the address the
    /// resolver answers at ([`SwitchSubnet::dns_server`], which is the same
    /// address) — as the octet array a frame's destination is compared by.
    /// The one destination inside the fabric that is a control surface, not
    /// a destination a box's egress rules decide: the gate refuses every
    /// frame headed here but a TCP or UDP query to the resolver's port,
    /// before any row or phase is consulted — a row's admitted ports are its
    /// own ingress, never a flow to the gateway.
    #[must_use]
    pub fn gateway(&self) -> [u8; 4] {
        self.subnet.gateway().octets()
    }

    /// The subnet the rows live in — the node's own switch block, the one
    /// slice of the fabric plane a box's frames may name as local reach
    /// (a sibling, the host alias, the daemon), decided by the row's own
    /// rules and the target's ingress rather than by the gate's
    /// infrastructure rule ([`crate::net::egress_gate`]).
    #[must_use]
    pub fn subnet(&self) -> SwitchSubnet {
        self.subnet
    }

    /// Files a withdrawal report: `sources` are the switch addresses whose
    /// relayed traffic the calling connection carried, each with the box id
    /// [`Self::carry`] filed for it, and the connection is at
    /// its end — the guest closed it, it errored, or the gate refused what
    /// followed. The registry's drainer detaches each reported row no other
    /// relay still carries, and withdraws it once its grace passes with no
    /// relay carrying it again ([`BoxRegistry::spawn_withdrawal_drainer`];
    /// NET-133, NET-138: a box's row goes with its attachment).
    ///
    /// Filing is the view's one write-shaped act and never blocks: the
    /// channel is unbounded and the drainer consumes it, and a send that
    /// fails — every receiver gone, which is a host shutting down — is
    /// dropped silently, because there is nothing left to withdraw for.
    pub fn report_withdrawals(&self, sources: WithdrawalReport) {
        if sources.is_empty() {
            return;
        }
        if let Err(_disconnected) = self.withdrawal_reports.send(sources) {
            // Every receiver is gone: the drainer was never started or the
            // host is shutting down. Nothing to withdraw for, nowhere to
            // say so that is not noise at teardown.
        }
    }
}

/// The registered boxes the proxy's pool partitions its listeners by
/// (NET-132): the box rows this registry publishes — every one a
/// host-side fact the guest never asserts — polled by the pool every
/// stack turn, so a row that lands grows its box's share within a turn
/// and a row that leaves takes its sockets with it. The box id a
/// delivery's header is filled from resolves through the same source
/// (NET-133): the attachment the source's row holds, issued by the
/// registration and withdrawn with it.
///
/// The guest node namespace's row is not one of them, so it buys no
/// share (see the [`BepBoxSource`](switch::bep_host::BepBoxSource)
/// impl) — and it holds no attachment either, so a delivery from it
/// names nothing. The host's own address outside the box host — the
/// cohort address host-address boxes arrive from (NET-078) — is a row
/// like a box's when the host published one there: its attachment is
/// the cohort's, and a delivered connection from it carries the
/// cohort's id.
pub struct RegisteredBoxes {
    /// The registry's live read-only view: every registration and
    /// withdrawal the table sees reaches the pool through it.
    table: BoxTable,
    /// The proxy's attachment table: what a delivery's box id resolves
    /// by, looked up through and never written — the registry is the one
    /// writer (NET-133).
    attachments: crate::bep_attach::Attachments,
}

impl RegisteredBoxes {
    /// The source over `table`'s rows and the proxy's `attachments` —
    /// the two tables one registry writes, handed to the supervisor
    /// that owns both.
    #[must_use]
    pub fn new(table: BoxTable, attachments: crate::bep_attach::Attachments) -> Self {
        Self { table, attachments }
    }
}

impl switch::bep_host::BepBoxSource for RegisteredBoxes {
    fn box_switch_addresses(&self) -> Vec<Ipv4Addr> {
        // The guest node namespace's row is the VM's own root netns, the
        // daemon's tap — never a box, and a share in its name would
        // partition the pool by a row no box ever speaks from. Its
        // address is fixed, the subnet's daemon address, which sits
        // outside the hand-out run every client box is allocated from,
        // so excluding that one address names exactly the node row.
        let node_addr = self.table.subnet().daemon_ip();
        // A task row declares no credentialed lane, so it buys no share
        // either: the pool is partitioned by the boxes that may reach it.
        self.table
            .rows()
            .iter()
            .filter(|row| !row.is_task_row())
            .map(|row| row.switch_addr())
            .filter(|addr| *addr != node_addr)
            .collect()
    }

    fn box_id_for_source(&self, source: Ipv4Addr) -> Option<crate::bep_attach::BoxId> {
        // The delivery's id is the box's own — resolved through the
        // attachment its source holds, the same host-side table the row
        // the source is keyed by came from, never a fact the flow
        // carries. A source with no attachment — the node namespace
        // above all, which holds none — names nothing, and the pool
        // aborts what it accepts from it rather than deliver a
        // connection it cannot attribute. The host's cohort row
        // (NET-078) holds one like any box's, so a host-address box's
        // delivery carries the cohort's own id.
        self.attachments
            .by_source(source.octets())
            .map(|attachment| attachment.box_id())
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use sessions::IpProto;
    use sessions::core::egress::FrameVerdict;
    use switch::SwitchSubnet;
    use tokio::io::AsyncWriteExt;

    use crate::net::egress_gate::test_support::{
        DEADLINE, arp_frame, expect_frame, expect_silence, gate_over, ipv4_frame, send_frame,
    };

    use super::*;

    /// The default switch subnet, the plan every registry below is built for.
    const SUBNET: SwitchSubnet = switch::DEFAULT_SUBNET;

    /// A published namespace's identity, as a comparable value: the row's
    /// whole content, flattened — what a before/after comparison of the table
    /// asserts on (see `host_table_never_sourced_from_guest`).
    fn row_identity(record: &BoxRecord) -> (Ipv4Addr, String, Ipv4Addr, Vec<u16>, EgressRules) {
        (
            record.switch_addr(),
            record.name().to_string(),
            record.loopback_addr(),
            record.admitted_ports().to_vec(),
            record.egress().clone(),
        )
    }

    /// NET-138: the host-side table holds every published namespace — one
    /// row each, keyed by the switch address the gate resolves frames by,
    /// carrying the name, both addresses, the admitted ports, and the rules
    /// compiled from the declaration; the guest node's own namespace is a row
    /// like any other; a withdrawn namespace's row is gone; and the table the
    /// gate holds is the registry's live rows, so a registration made after
    /// the table was handed out is decided by from that moment on.
    #[test]
    fn host_table_holds_every_published_namespace() {
        let registry = BoxRegistry::new(SUBNET);
        let table = registry.table();
        assert!(
            table.is_empty(),
            "a fresh registry publishes nothing until the host fills it"
        );

        // Two boxes, each with a declared policy; the node namespace beside
        // them, as run.rs publishes it.
        let web = registry.register(
            BoxRegistration::new("web", Ipv4Addr::new(100, 64, 0, 9), Ipv4Addr::LOCALHOST)
                .with_admitted_ports([8080])
                .with_egress_policy(EgressPolicy {
                    allow_protocols: Some(vec![IpProto::Tcp]),
                    allow_subnets: Some(vec!["10.0.0.0/8".to_string()]),
                    allow_dns_hosts: None,
                    deny_subnets: None,
                }),
        );
        let db = registry.register(
            BoxRegistration::new("db", Ipv4Addr::new(100, 64, 0, 10), Ipv4Addr::LOCALHOST)
                .with_admitted_ports([5432, 5433]),
        );
        let node = registry.register_node_namespace(7654);

        // Every published namespace holds a row, resolved by the address the
        // gate's per-frame lookup uses.
        let rows = table.rows();
        assert_eq!(
            rows.iter().map(|row| row.switch_addr()).collect::<Vec<_>>(),
            [
                Ipv4Addr::new(100, 64, 0, 9),
                Ipv4Addr::new(100, 64, 0, 10),
                SUBNET.daemon_ip(),
            ],
            "every published namespace holds a row, in switch-address order"
        );
        assert_eq!(web.name(), "web");
        assert_eq!(web.loopback_addr(), Ipv4Addr::LOCALHOST);
        assert_eq!(web.admitted_ports(), [8080]);
        assert_eq!(db.name(), "db");
        assert_eq!(db.admitted_ports(), [5432, 5433]);
        assert_eq!(node.name(), "minimald");
        assert_eq!(node.switch_addr(), SUBNET.daemon_ip());
        assert_eq!(
            node.admitted_ports(),
            [7654],
            "the node's row names the proxy port the VM host assigned and \
             handed over — the answerer is not the node's to admit (NET-138) — \
             so the daemon's own publishes are publishes of a port the row \
             already declares"
        );

        // The table carries the plan its rows are addressed on, and the plan's
        // own answer to which addresses a box could ever hold: every row's
        // switch address is allocatable, and the subnet's infrastructure — the
        // gateway the resolver carve-out is keyed to, the host alias, the
        // daemon address the node row holds — is not, nor is anything outside
        // the subnet. That answer is what the gate's interim keys its one
        // concession on, so it is pinned here, against the plan itself.
        for row in [web.clone(), db.clone()] {
            assert!(
                table.is_allocatable(row.switch_addr().octets()),
                "a box's lease is an address the plan could hand out"
            );
        }
        for infra in [
            SUBNET.dns_server(),
            SUBNET.host_alias(),
            SUBNET.daemon_ip(),
            Ipv4Addr::new(203, 0, 113, 7),
        ] {
            assert!(
                !table.is_allocatable(infra.octets()),
                "the plan never hands out {infra}"
            );
        }
        for row in [web.clone(), db.clone(), node.clone()] {
            assert_eq!(
                table.by_source(row.switch_addr().octets()).as_deref(),
                Some(row.as_ref()),
                "the row is resolved by the address the gate looks frames up by"
            );
        }

        // The row's rules are the declaration, compiled against the registry's
        // subnet: the lease is the row's own switch address (NET-084) and the
        // resolver carve-out is keyed to the switch this registry serves —
        // and the node's interim row compiles from no declaration at all.
        let web_policy = EgressPolicy {
            allow_protocols: Some(vec![IpProto::Tcp]),
            allow_subnets: Some(vec!["10.0.0.0/8".to_string()]),
            allow_dns_hosts: None,
            deny_subnets: None,
        };
        assert_eq!(
            web.egress(),
            &EgressRules::from_policy(
                Some(&web_policy),
                SUBNET.dns_server().octets(),
                Ipv4Addr::new(100, 64, 0, 9).octets(),
            )
        );
        assert_eq!(
            db.egress(),
            &EgressRules::from_policy(
                None,
                SUBNET.dns_server().octets(),
                db.switch_addr().octets()
            )
        );

        // Withdrawal retires the row: the address is held by no namespace and
        // no rules are decided by it. Whether its frames are dropped with it
        // is the phase's to say, not the table's — see `withdraw`'s docs.
        assert!(registry.withdraw(db.switch_addr()).is_some());
        assert!(
            table.by_source(db.switch_addr().octets()).is_none(),
            "a withdrawn namespace holds no row"
        );
        assert!(registry.withdraw(db.switch_addr()).is_none());
        assert_eq!(table.rows().len(), 2);

        // The table is the registry's live rows, shared: a registration made
        // through another handle — the shape T66's client-driven path will
        // use — is decided by from the moment it lands.
        let peer = registry.clone();
        let late = peer.register(BoxRegistration::new(
            "late",
            Ipv4Addr::new(100, 64, 0, 11),
            Ipv4Addr::LOCALHOST,
        ));
        assert_eq!(
            table.by_source(late.switch_addr().octets()).as_deref(),
            Some(late.as_ref()),
            "a registration after the table was handed out reaches it"
        );

        // Re-registering an address replaces the row with the newest
        // declaration, compared against nothing: this restatement is wider
        // than the one it replaces — no declared policy, so allow-all where
        // the first said TCP to a LAN — and the table holds it anyway,
        // because the reach a row grants is its latest registration's, and
        // whether a re-declaration may widen is the registering side's
        // contract (T66's path), not the table's.
        let restated = registry.register(BoxRegistration::new(
            "web",
            Ipv4Addr::new(100, 64, 0, 9),
            Ipv4Addr::LOCALHOST,
        ));
        let rows = table.rows();
        assert_eq!(rows.len(), 3);
        let restated_row = table
            .by_source(Ipv4Addr::new(100, 64, 0, 9).octets())
            .expect("the address is still published");
        assert_eq!(restated_row.egress(), restated.egress());
        assert!(
            restated_row.egress() != web.egress(),
            "the re-registration replaced the row the gate resolves"
        );
        // And it widens, visibly: the shared verdict — the decision the gate
        // applies — drops a frame to an address outside the LAN the first
        // declaration allowed, and admits the same frame under the row the
        // re-registration left.
        let outside = sessions::core::egress::summarize(&ipv4_frame(
            Ipv4Addr::new(100, 64, 0, 9).octets(),
            6,
            [203, 0, 113, 7],
            443,
        ));
        assert!(matches!(
            sessions::core::egress::verdict(&outside, web.egress()),
            FrameVerdict::Drop(_)
        ));
        assert!(
            matches!(
                sessions::core::egress::verdict(&outside, restated_row.egress()),
                FrameVerdict::Admit
            ),
            "the re-registration's reach is what the gate now decides by"
        );
    }

    /// NET-074/NET-077 at the host gate: a client box with no `egress`
    /// section is compiled under the egress default's phase and the
    /// operator's opt-out — the same pair the guest daemon resolves it by —
    /// so an opted-out VM host never denies at the host what the guest
    /// allows. Announced, it allows all; in force, it denies all unless the
    /// opt-out is set, when it keeps the earlier allow-all. A declared
    /// section's own lists are carried in every arm; in force without the
    /// opt-out, the destination list it left absent is resolved to present
    /// and empty (NET-074), which does not touch the address rules below.
    #[test]
    fn undeclared_row_default_follows_phase_and_opt_out() {
        use sessions::EgressDefaultPhase::{Announced, InForce};

        let reach_to = |phase, opt_out, egress: Option<EgressPolicy>, dest: [u8; 4]| {
            let registry = BoxRegistry::new(SUBNET)
                .with_egress_default_phase(phase)
                .with_egress_deny_all_opt_out(opt_out);
            let row = registry
                .register_client_box(ClientBoxSpec {
                    name: "web".to_string(),
                    ingress_ports: Vec::new(),
                    egress,
                    credentialed_upstream: None,
                    dynamic_ingress: None,
                    dynamic_allowed_range: None,
                })
                .expect("the default plan hands out a client box");
            let outside = sessions::core::egress::summarize(&ipv4_frame(
                row.switch_addr().octets(),
                6,
                dest,
                443,
            ));
            matches!(
                sessions::core::egress::verdict(&outside, row.egress()),
                FrameVerdict::Admit
            )
        };
        let reach = |phase, opt_out, egress| reach_to(phase, opt_out, egress, [203, 0, 113, 7]);

        assert!(
            reach(Announced, false, None),
            "announced, an undeclared box keeps the earlier allow-all"
        );
        assert!(
            reach(InForce, true, None),
            "in force but opted out (NET-077), an undeclared box keeps allow-all"
        );
        assert!(
            !reach(InForce, false, None),
            "in force and not opted out (NET-074), an undeclared box reaches nothing"
        );

        // A declaration is the box's own and survives every arm untouched.
        let lan_only = EgressPolicy {
            allow_subnets: Some(vec!["10.0.0.0/8".to_string()]),
            ..EgressPolicy::default()
        };
        // Both directions are pinned: the declared allow is still admitted
        // (deny-all would refuse it) and the outside stays refused
        // (allow-all would admit it), so neither default can stand in.
        for (phase, opt_out) in [
            (Announced, false),
            (Announced, true),
            (InForce, false),
            (InForce, true),
        ] {
            assert!(
                reach_to(phase, opt_out, Some(lan_only.clone()), [10, 1, 2, 3]),
                "a declared LAN-only box still reaches the LAN under {phase:?}, opt-out {opt_out}"
            );
            assert!(
                !reach(phase, opt_out, Some(lan_only.clone())),
                "a declared LAN-only box stays LAN-only under {phase:?}, opt-out {opt_out}"
            );
        }
    }

    /// The host hands registered boxes only from the hand-out run — the plan
    /// run's upper half, above the daemon's self-allocation reserve — and
    /// the loopback run's exhaustion stays an explicit refusal, with no
    /// wrap. Driven on a planned carved /24, whose runs are small enough to
    /// see both edges of.
    #[test]
    fn client_boxes_hand_out_from_the_run_above_the_reserve() {
        // The plan's default subnet splits at 100.64.127.255 — pinned
        // literally, mirrored from `minimald::net::self_allocation_run`:
        // the first box takes the hand-out run's first address, never the
        // PTask run's first (that is the daemon's reserve).
        let registry = BoxRegistry::new(SUBNET);
        let first = registry
            .register_client_box(ClientBoxSpec {
                name: "web".to_string(),
                ingress_ports: Vec::new(),
                egress: None,
                credentialed_upstream: None,
                dynamic_ingress: None,
                dynamic_allowed_range: None,
            })
            .expect("the default plan has hand-out addresses");
        assert_eq!(
            first.switch_addr(),
            Ipv4Addr::new(100, 64, 127, 255),
            "the first box takes the hand-out run's first address, above the \
             daemon's reserve"
        );

        // A planned carved /24: its PTask run is 100.64.1.2 through
        // 100.64.1.252, so its hand-out run starts at .127 — and its
        // loopback slice holds 32 addresses, which run out first. The
        // refusal is explicit and repeats: no wrap, no reuse.
        let carved = SwitchSubnet::new(Ipv4Addr::new(100, 64, 1, 0), 24).expect("valid");
        assert!(
            switch::AddressPlan::default()
                .loopback_slice_for_switch(carved)
                .is_some(),
            "the carved subnet is planned, so a refusal is a run's exhaustion, not the plan's absence"
        );
        let registry = BoxRegistry::new(carved);
        let first = registry
            .register_client_box(ClientBoxSpec {
                name: "web".to_string(),
                ingress_ports: Vec::new(),
                egress: None,
                credentialed_upstream: None,
                dynamic_ingress: None,
                dynamic_allowed_range: None,
            })
            .expect("the carved subnet has hand-out addresses");
        assert_eq!(
            first.switch_addr(),
            Ipv4Addr::new(100, 64, 1, 127),
            "the carved /24's hand-out run also starts above its reserve"
        );
        for index in 1..32 {
            registry
                .register_client_box(ClientBoxSpec {
                    name: format!("box{index}"),
                    ingress_ports: Vec::new(),
                    egress: None,
                    credentialed_upstream: None,
                    dynamic_ingress: None,
                    dynamic_allowed_range: None,
                })
                .expect("the slice holds 32 published addresses");
        }
        for _ in 0..2 {
            assert!(
                matches!(
                    registry.register_client_box(ClientBoxSpec {
                        name: "late".to_string(),
                        ingress_ports: Vec::new(),
                        egress: None,
                        credentialed_upstream: None,
                        dynamic_ingress: None,
                        dynamic_allowed_range: None,
                    }),
                    Err(AllocationError::LoopbackExhausted)
                ),
                "exhaustion is explicit and never wraps"
            );
        }
    }

    /// Design §7.1, the loopback run a box may take: the reserved local
    /// range's `.2` to its last-but-one address, never its network
    /// address, `.1` or its broadcast — the answerer's own hand-out run
    /// ([`switch::box_loopback_interior`]), clamped to the single-node
    /// cursor's slice. Pinned on both ends: the reserved local range's
    /// default slice and its last.
    #[test]
    fn client_boxes_take_only_the_range_s_interior() {
        // The default plan's slice starts at the range's network address,
        // and a box takes none of it: its first loopback is the run's.
        let registry = BoxRegistry::new(SUBNET);
        let first = registry
            .register_client_box(ClientBoxSpec {
                name: "web".to_string(),
                ingress_ports: Vec::new(),
                egress: None,
                credentialed_upstream: None,
                dynamic_ingress: None,
                dynamic_allowed_range: None,
            })
            .expect("the default plan has published addresses");
        assert_eq!(
            first.loopback_addr(),
            Ipv4Addr::new(127, 0, 64, 2),
            "the first box takes the run's first address, never the range's \
             network address nor .1"
        );

        // The last slice ends on the range's broadcast address, and a box
        // takes none of that either: its last address is the run's, and a
        // further box is refused as before.
        let last = SwitchSubnet::new(Ipv4Addr::new(100, 64, 7, 0), 24).expect("valid");
        assert!(
            switch::AddressPlan::default()
                .loopback_slice_for_switch(last)
                .is_some(),
            "the last slice's subnet is planned, so the refusal below is a \
             run's exhaustion, not the plan's absence"
        );
        let registry = BoxRegistry::new(last);
        for index in 0..30 {
            registry
                .register_client_box(ClientBoxSpec {
                    name: format!("box{index}"),
                    ingress_ports: Vec::new(),
                    egress: None,
                    credentialed_upstream: None,
                    dynamic_ingress: None,
                    dynamic_allowed_range: None,
                })
                .expect("the last slice hands out 30 addresses below its last");
        }
        assert_eq!(
            registry
                .register_client_box(ClientBoxSpec {
                    name: "last".to_string(),
                    ingress_ports: Vec::new(),
                    egress: None,
                    credentialed_upstream: None,
                    dynamic_ingress: None,
                    dynamic_allowed_range: None,
                })
                .expect("the last slice holds one more published address")
                .loopback_addr(),
            Ipv4Addr::new(127, 0, 64, 254),
            "the last box takes the run's last address, never the range's \
             broadcast"
        );
        assert!(
            matches!(
                registry.register_client_box(ClientBoxSpec {
                    name: "late".to_string(),
                    ingress_ports: Vec::new(),
                    egress: None,
                    credentialed_upstream: None,
                    dynamic_ingress: None,
                    dynamic_allowed_range: None,
                }),
                Err(AllocationError::LoopbackExhausted)
            ),
            "exhaustion stays explicit and never wraps"
        );

        // A slice inside the range touches none of its reserved ends, so
        // the clamp keeps every one of its addresses.
        let middle = switch::AddressPlan::default()
            .loopback_slice_for_switch(
                SwitchSubnet::new(Ipv4Addr::new(100, 64, 3, 0), 24).expect("valid"),
            )
            .expect("a middle slice is planned");
        assert_eq!(
            box_loopback_run(middle),
            (u32::from(middle.first()), u32::from(middle.last())),
            "a middle slice loses no address to the clamp"
        );
    }

    /// BEP-070, one id names one box, so a registration whose minted id a
    /// live row or attachment already holds is refused — never re-minted,
    /// and before any address is spent, so the refusal leaves no new fact
    /// on the host — and said as one warn line naming the id. A real mint
    /// does not collide, so the test drives the collision through the
    /// registration's own door with the id it would have minted fixed.
    #[test]
    fn colliding_box_id_refused() {
        let (log, _guard) = crate::net::egress_gate::test_support::capture_log();
        let attachments = crate::bep_attach::Attachments::new();
        let registry = BoxRegistry::new(SUBNET).feeding_proxy_attachments(attachments.clone());
        let web = registry
            .register_client_box(ClientBoxSpec {
                name: "web".to_string(),
                ingress_ports: Vec::new(),
                egress: None,
                credentialed_upstream: None,
                dynamic_ingress: None,
                dynamic_allowed_range: None,
            })
            .expect("the plan has an address for the first box");
        assert!(
            attachments.holds_id(web.box_id()),
            "the box's id is held by its row's attachment, the half of the live \
             set a source's delivery resolves through"
        );

        // A registration whose mint landed on the live row's id would name
        // the web box: refused, and the refusal names the colliding id.
        let refused = registry
            .register_client_box_as(
                ClientBoxSpec {
                    name: "impostor".to_string(),
                    ingress_ports: Vec::new(),
                    egress: None,
                    credentialed_upstream: None,
                    dynamic_ingress: None,
                    dynamic_allowed_range: None,
                },
                Ipv4Addr::from(u32::from(web.loopback_addr()) + 1),
                0,
                web.box_id(),
                None,
            )
            .expect_err("an id a live box holds is not a second box's");
        assert_eq!(
            refused,
            AllocationError::CollidingBoxId { id: web.box_id() },
            "the refusal names the colliding id, the one the registration claimed"
        );

        // The refusal spent nothing: no row was published for the impostor,
        // the live row is untouched, and the hand-out run's next address is
        // still the next registration's to take.
        let rows = registry.table().rows();
        assert_eq!(rows.len(), 1, "a refused registration publishes no row");
        assert_eq!(
            row_identity(&rows[0]),
            row_identity(&web),
            "the live row is the live box's, untouched by the refusal"
        );
        let next = registry
            .register_client_box(ClientBoxSpec {
                name: "db".to_string(),
                ingress_ports: Vec::new(),
                egress: None,
                credentialed_upstream: None,
                dynamic_ingress: None,
                dynamic_allowed_range: None,
            })
            .expect("the plan has a second hand-out address");
        assert_eq!(
            next.switch_addr(),
            Ipv4Addr::from(u32::from(web.switch_addr()) + 1),
            "the refusal spent no address: the next registration takes the \
             hand-out run's next, the address the refused one would have spent"
        );

        // One warn line names the refusal and the id it refused — the line a
        // bundle's daemon log tail reads a refused registration by.
        let logged = log.contents();
        assert_eq!(
            logged
                .matches(
                    "refused a box registration whose id a live row or attachment already holds"
                )
                .count(),
            1,
            "one warn line per refused registration, got: {logged}"
        );
        assert!(
            logged.contains(&format!(
                "box_id={}",
                crate::bep_attach::BoxIdText(&web.box_id())
            )),
            "the warn line names the colliding id, got: {logged}"
        );
    }

    /// A row-withdrawal subscriber is told every removed row's address,
    /// whichever path removed it: the drainer's withdrawal and the
    /// creator's. A withdrawal that removes nothing tells it nothing, and a
    /// subscriber that dropped its receiver is pruned without failing the
    /// withdrawal.
    #[test]
    fn row_withdrawals_reach_every_subscriber_by_either_path() {
        let registry = BoxRegistry::new(SUBNET);
        let spec = |name: &str| ClientBoxSpec {
            name: name.to_string(),
            ingress_ports: vec![8080],
            egress: None,
            credentialed_upstream: None,
            dynamic_ingress: None,
            dynamic_allowed_range: None,
        };
        let mut withdrawn = registry.table().subscribe_row_withdrawals();
        drop(registry.table().subscribe_row_withdrawals());
        let web = registry
            .register_client_box(spec("web"))
            .expect("the plan has an address for the first box");
        let db = registry
            .register_client_box(spec("db"))
            .expect("the plan has an address for the second box");

        assert!(registry.withdraw(web.switch_addr()).is_some());
        assert!(registry.withdraw(web.switch_addr()).is_none());
        assert!(
            registry
                .withdraw_client_box("db", db.switch_addr(), db.loopback_addr(), None)
                .expect("the withdrawing client is the row's creator")
                .is_some()
        );

        assert_eq!(
            withdrawn.try_recv().map(|w| w.switch_addr()),
            Ok(web.switch_addr())
        );
        assert_eq!(
            withdrawn.try_recv().map(|w| w.switch_addr()),
            Ok(db.switch_addr())
        );
        assert!(
            withdrawn.try_recv().is_err(),
            "a withdrawal that removed nothing told the subscriber nothing"
        );
    }

    /// The registration half of design §7.1's revocation, for a new row
    /// that arrives before the old box's revocation has run. While a
    /// subscriber holds a withdrawal, neither the row's switch address nor
    /// its per-box published address can be registered again, by any door.
    /// A row there now would receive the old box's forwarded connections,
    /// or have its own forwards unbound at the old box's end. Once the
    /// subscriber drops the withdrawal (its revocation is done), both are
    /// free.
    #[test]
    fn a_withdrawn_rows_addresses_stay_unregistrable_until_its_revocation_ends() {
        let registry = BoxRegistry::new(SUBNET);
        let mut withdrawn = registry.table().subscribe_row_withdrawals();
        let web = registry
            .register_client_box(ClientBoxSpec {
                name: "web".to_string(),
                ingress_ports: vec![8080],
                egress: None,
                credentialed_upstream: None,
                dynamic_ingress: None,
                dynamic_allowed_range: None,
            })
            .expect("the plan has an address for the box");
        assert!(registry.withdraw(web.switch_addr()).is_some());
        let withdrawal = withdrawn.try_recv().expect("the subscriber is told");
        assert_eq!(
            withdrawal.held_addrs(),
            [web.switch_addr().octets(), web.loopback_addr().octets()],
            "the switch address and the per-box published address are both held"
        );

        // The same switch address, under another published address.
        let other_switch = Ipv4Addr::from(u32::from(web.switch_addr()) + 7);
        assert_eq!(
            registry
                .try_register(BoxRegistration::new(
                    "again",
                    web.switch_addr(),
                    Ipv4Addr::LOCALHOST
                ))
                .map(|row| row.name().to_string()),
            Err(AllocationError::RevocationPending {
                addr: web.switch_addr()
            }),
        );
        // The same published address, at another switch address.
        assert_eq!(
            registry
                .try_register(BoxRegistration::new(
                    "again",
                    other_switch,
                    web.loopback_addr()
                ))
                .map(|row| row.name().to_string()),
            Err(AllocationError::RevocationPending {
                addr: web.loopback_addr()
            }),
        );
        assert!(
            registry
                .table()
                .by_source(web.switch_addr().octets())
                .is_none()
                && registry.table().by_source(other_switch.octets()).is_none(),
            "a refused registration leaves no row behind"
        );
        assert!(
            registry
                .table()
                .revocation_pending(web.switch_addr().octets())
        );

        drop(withdrawal);
        assert!(
            !registry
                .table()
                .revocation_pending(web.switch_addr().octets())
        );
        registry
            .try_register(BoxRegistration::new(
                "again",
                web.switch_addr(),
                web.loopback_addr(),
            ))
            .expect("the revocation is done, so the addresses are free");
    }

    /// The client door waits, bounded, for a revocation to release the
    /// published address the answerer handed back, rather than refusing a
    /// box created just after another one ended.
    #[test]
    fn a_client_registration_waits_for_the_revocation_holding_its_address() {
        let registry = BoxRegistry::new(SUBNET);
        let mut withdrawn = registry.table().subscribe_row_withdrawals();
        let spec = |name: &str| ClientBoxSpec {
            name: name.to_string(),
            ingress_ports: vec![8080],
            egress: None,
            credentialed_upstream: None,
            dynamic_ingress: None,
            dynamic_allowed_range: None,
        };
        let web = registry
            .register_client_box(spec("web"))
            .expect("the plan has an address for the box");
        // Its creator's destroy, which ends the creation and its name's
        // hold, not only the row.
        assert!(
            registry
                .withdraw_client_box("web", web.switch_addr(), web.loopback_addr(), None)
                .expect("the creator's pair")
                .is_some()
        );
        let withdrawal = withdrawn.try_recv().expect("the subscriber is told");

        let started = Instant::now();
        let revoker = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            drop(withdrawal);
        });
        let again = registry
            .register_client_box_at(spec("web"), web.loopback_addr())
            .expect("the registration waited for the revocation to end");
        revoker.join().expect("the revoker thread");
        assert_eq!(again.loopback_addr(), web.loopback_addr());
        assert!(started.elapsed() >= Duration::from_millis(100));
        assert!(started.elapsed() < REVOCATION_WAIT);
    }

    /// A client registration refused because a revocation still holds its
    /// published address spends no switch address: the cursor never hands
    /// one out twice, so a retry loop against a held address would
    /// otherwise use up the plan.
    #[test]
    fn a_registration_refused_for_a_held_address_spends_no_switch_address() {
        let registry = BoxRegistry::new(SUBNET);
        let mut withdrawn = registry.table().subscribe_row_withdrawals();
        let spec = |name: &str| ClientBoxSpec {
            name: name.to_string(),
            ingress_ports: vec![8080],
            egress: None,
            credentialed_upstream: None,
            dynamic_ingress: None,
            dynamic_allowed_range: None,
        };
        let web = registry
            .register_client_box(spec("web"))
            .expect("the plan has an address for the box");
        assert!(registry.withdraw(web.switch_addr()).is_some());
        let withdrawal = withdrawn.try_recv().expect("the subscriber is told");

        assert_eq!(
            registry
                .register_client_box_at(spec("db"), web.loopback_addr())
                .map(|row| row.name().to_string()),
            Err(AllocationError::RevocationPending {
                addr: web.loopback_addr()
            }),
        );
        drop(withdrawal);
        let next = registry
            .register_client_box(spec("next"))
            .expect("the plan has an address for the next box");
        assert_eq!(
            next.switch_addr(),
            Ipv4Addr::from(u32::from(web.switch_addr()) + 1),
            "the refused registration drew no switch address"
        );
    }

    /// A planned carved /24 — its hand-out run is 100.64.1.127 through
    /// 100.64.1.251, 125 addresses — small enough to draw through, with the
    /// one loopback address every box below registers at: the answerer's
    /// half is not under test, and with no withdrawal subscriber nothing
    /// holds it.
    fn carved() -> SwitchSubnet {
        SwitchSubnet::new(Ipv4Addr::new(100, 64, 1, 0), 24).expect("a /24 is a valid plan")
    }
    const CARVED_RUN: usize = 125;
    const CARVED_LOOPBACK: Ipv4Addr = Ipv4Addr::new(127, 0, 64, 40);

    fn client_spec(name: &str) -> ClientBoxSpec {
        ClientBoxSpec {
            name: name.to_string(),
            ingress_ports: Vec::new(),
            egress: None,
            credentialed_upstream: None,
            dynamic_ingress: None,
            dynamic_allowed_range: None,
        }
    }

    fn register_carved(
        registry: &BoxRegistry,
        name: &str,
    ) -> Result<Arc<BoxRecord>, AllocationError> {
        registry.register_client_box_at(client_spec(name), CARVED_LOOPBACK)
    }

    /// Draws the carved run through: one row per address, each attributed
    /// as a relay that carried its frames would mark it.
    fn fill_carved_run(registry: &BoxRegistry) -> Vec<Arc<BoxRecord>> {
        (0..CARVED_RUN)
            .map(|index| {
                let row = register_carved(registry, &format!("box{index}"))
                    .expect("the carved run holds an address for every box");
                registry.table().mark_attributed(row.switch_addr().octets());
                row
            })
            .collect()
    }

    /// Files the report a relay that carried `rows`' frames files at its
    /// end: each row marked attributed as the relay's first frame from it
    /// marks it, then the relay's end reported with the ids the marks
    /// returned.
    fn relay_carried_and_ended(registry: &BoxRegistry, rows: &[&Arc<BoxRecord>]) {
        let table = registry.table();
        let carried = rows
            .iter()
            .map(|row| {
                let addr = row.switch_addr().octets();
                (addr, table.mark_attributed(addr).expect("the row stands"))
            })
            .collect();
        table.report_withdrawals(carried);
    }

    /// Its creator's destroy of the client box `row` is: the creator's
    /// withdrawal, which ends the creation and returns its addresses — a
    /// row the drainer withdraws leaves them reserved ([`Creation`]).
    fn destroy(registry: &BoxRegistry, row: &BoxRecord) {
        assert!(
            registry
                .withdraw_client_box(
                    row.name(),
                    row.switch_addr(),
                    row.loopback_addr(),
                    Some(row.box_id())
                )
                .expect("the creator's own pair")
                .is_some(),
            "the creator's destroy removes the row"
        );
    }

    /// Polls `holds` until it does, failing the test after five seconds.
    fn wait_until(holds: impl Fn() -> bool, what: &str) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !holds() {
            assert!(Instant::now() < deadline, "{what}: not within 5 s");
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// Lets the drainer sweep at least twice, for a test that asserts a
    /// sweep withdrew nothing.
    fn let_the_drainer_sweep() {
        std::thread::sleep(DETACH_SWEEP_INTERVAL * 2 + Duration::from_millis(200));
    }

    /// NET-138: a relay's end detaches the rows it carried rather than
    /// withdrawing them. While detached a row stands as it stood — the gate
    /// resolves its source to the same row and its rules, and its switch
    /// address stays out of the hand-out book — until its grace passes.
    #[test]
    fn a_closed_shuttle_detaches_rows_until_the_grace() {
        let registry = BoxRegistry::new(SUBNET);
        registry.spawn_withdrawal_drainer(|_| {});
        let web = registry
            .register_client_box(client_spec("web"))
            .expect("the plan has an address for the box");
        assert!(!web.is_detached(), "a fresh row awaits its box's frames");

        relay_carried_and_ended(&registry, &[&web]);
        wait_until(|| web.is_detached(), "the row detaches at its relay's end");
        // Short of the grace by more than the real time the sweeps take.
        registry.advance_clock(DETACH_GRACE.saturating_sub(Duration::from_secs(10)));
        let_the_drainer_sweep();

        let table = registry.table();
        let held = table
            .by_source(web.switch_addr().octets())
            .expect("a detached row stands until its grace passes");
        assert!(Arc::ptr_eq(&held, &web), "the gate decides by the same row");
        assert_eq!(held.egress(), web.egress(), "and by the same rules");
        assert_eq!(
            registry.live_switch_addrs(),
            1,
            "its switch address stays out"
        );

        registry.advance_clock(Duration::from_secs(10));
        wait_until(
            || table.by_source(web.switch_addr().octets()).is_none(),
            "the row is withdrawn once its grace passes",
        );
    }

    /// NET-138: a detached row a relay carries again — the box's shuttle
    /// reconnected and carried a frame from its address — is re-attributed
    /// and keeps its row past the grace it was detached under.
    #[test]
    fn a_reattributed_box_keeps_its_row() {
        let registry = BoxRegistry::new(SUBNET);
        registry.spawn_withdrawal_drainer(|_| {});
        let web = registry
            .register_client_box(client_spec("web"))
            .expect("the plan has an address for the box");
        relay_carried_and_ended(&registry, &[&web]);
        wait_until(|| web.is_detached(), "the row detaches at its relay's end");

        let reconnected = registry.table().mark_attributed(web.switch_addr().octets());
        assert_eq!(
            reconnected,
            Some(web.box_id()),
            "the new relay attributes the same box"
        );
        assert!(
            !web.is_detached(),
            "a relay carrying it again re-attaches the row"
        );
        registry.advance_clock(DETACH_GRACE * 2);
        let_the_drainer_sweep();
        assert!(
            registry
                .row_by_name("web")
                .is_some_and(|row| Arc::ptr_eq(&row, &web)),
            "the re-attributed row stands past the grace"
        );
    }

    /// NET-138, design §7.1: a row detached past its grace is withdrawn,
    /// and its creation kept dormant with both addresses reserved for its
    /// resume ([`Creation`]): its published address is not handed back to
    /// the answerer, its switch address not returned to the book. The
    /// creator's destroy returns the switch address, under the quarantine
    /// its attribution earned.
    #[test]
    fn a_detached_row_is_withdrawn_after_the_grace_and_keeps_both_addresses() {
        let registry = BoxRegistry::new(SUBNET);
        let (released, releases) = std::sync::mpsc::channel();
        registry.spawn_withdrawal_drainer(move |name| {
            let _ = released.send(name.to_string());
        });
        let web = registry
            .register_client_box(client_spec("web"))
            .expect("the plan has an address for the box");
        relay_carried_and_ended(&registry, &[&web]);
        wait_until(|| web.is_detached(), "the row detaches at its relay's end");

        registry.advance_clock(DETACH_GRACE);
        wait_until(
            || registry.row_by_name("web").is_none(),
            "the row is withdrawn at its grace's end",
        );
        assert!(
            releases.recv_timeout(Duration::from_millis(200)).is_err(),
            "the dormant creation keeps its published address"
        );
        assert_eq!(
            registry.live_switch_addrs(),
            1,
            "and its switch address stays out"
        );
        assert!(registry.returned_switch_addrs().is_empty());

        assert_eq!(
            registry.withdraw_client_box("web", web.switch_addr(), web.loopback_addr(), None),
            Ok(None),
            "the creator's destroy ends the dormant creation"
        );
        assert_eq!(registry.live_switch_addrs(), 0);
        assert_eq!(
            registry.returned_switch_addrs(),
            vec![(web.switch_addr(), false)],
            "the switch address is back in the book, inside its quarantine"
        );
    }

    /// The registry a test persists at `dir`, under its default plan.
    fn persisted_registry(dir: &tempfile::TempDir) -> BoxRegistry {
        BoxRegistry::new(SUBNET).persisting_to(dir.path().join(REGISTRY_FILE))
    }

    /// NET-138: the client boxes' registrations persist host-side, and a
    /// registry started over the file reinstates each standing row — its
    /// name, both addresses, its box id and its compiled rules — detached
    /// from the load, with its switch address out of the hand-out book.
    #[test]
    fn registry_persists_and_reloads_rows_as_detached() {
        let dir = tempfile::tempdir().expect("a temp dir");
        let before = persisted_registry(&dir);
        let mut spec = client_spec("web");
        spec.ingress_ports = vec![8080];
        spec.egress = Some(EgressPolicy {
            allow_subnets: Some(vec!["10.0.0.0/8".to_string()]),
            ..EgressPolicy::default()
        });
        let web = before
            .register_client_box(spec)
            .expect("the plan has an address for the box");

        let after = persisted_registry(&dir);
        let reloaded = after
            .row_by_name("web")
            .expect("the standing row is reloaded");
        assert_eq!(reloaded.box_id(), web.box_id(), "under its own box id");
        assert_eq!(reloaded.switch_addr(), web.switch_addr());
        assert_eq!(reloaded.loopback_addr(), web.loopback_addr());
        assert_eq!(reloaded.admitted_ports(), web.admitted_ports());
        assert_eq!(
            reloaded.egress(),
            web.egress(),
            "compiled from its declaration"
        );
        assert!(reloaded.is_detached(), "reloaded detached");
        assert_eq!(after.live_switch_addrs(), 1, "its switch address is out");
        let api = after
            .register_client_box(client_spec("api"))
            .expect("the plan has an address for another box");
        assert_ne!(
            api.switch_addr(),
            web.switch_addr(),
            "and never handed again"
        );
    }

    /// NET-138: a reloaded row no relay carries again is withdrawn after its
    /// grace, as any detached row is, and stays withdrawn across the next
    /// reload: its creation is kept dormant, its switch address reserved
    /// for it across the reload too, so the reloaded book hands it to no
    /// other box.
    #[test]
    fn a_reloaded_row_not_reattributed_is_withdrawn() {
        let dir = tempfile::tempdir().expect("a temp dir");
        let web = persisted_registry(&dir)
            .register_client_box(client_spec("web"))
            .expect("the plan has an address for the box");

        let after = persisted_registry(&dir);
        let (released, releases) = std::sync::mpsc::channel();
        after.spawn_withdrawal_drainer(move |name| {
            let _ = released.send(name.to_string());
        });
        after.advance_clock(DETACH_GRACE);
        wait_until(
            || after.row_by_name("web").is_none(),
            "the reloaded row is withdrawn once its grace passes",
        );
        assert!(
            releases.recv_timeout(Duration::from_millis(200)).is_err(),
            "its published address stays the dormant creation's"
        );
        assert!(after.returned_switch_addrs().is_empty());
        assert_eq!(after.live_switch_addrs(), 1, "its switch address stays out");

        let again = persisted_registry(&dir);
        assert!(
            again.row_by_name("web").is_none(),
            "a dormant creation reloads no row"
        );
        assert_eq!(
            again.live_switch_addrs(),
            1,
            "the reload reserves the dormant creation's switch address"
        );
        let api = again
            .register_client_box(client_spec("api"))
            .expect("the plan has an address for another box");
        assert_ne!(
            api.switch_addr(),
            web.switch_addr(),
            "and never hands it to another box"
        );
        assert_eq!(
            again.withdraw_client_box("web", web.switch_addr(), web.loopback_addr(), None),
            Ok(None),
            "the creator's destroy ends the dormant creation"
        );
        assert_eq!(again.live_switch_addrs(), 1, "only the new box's is out");
    }

    /// NET-138: the persisted registry is its owner's alone — mode 0600,
    /// whatever a stale temporary file left behind held — written whole by
    /// a rename, versioned, and a file of another version reloads nothing.
    #[test]
    fn the_persisted_registry_is_0600_and_atomic() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().expect("a temp dir");
        let path = dir.path().join(REGISTRY_FILE);
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, b"half a file").expect("a stale temporary file");
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o644))
            .expect("a world-readable stale file");

        let registry = persisted_registry(&dir);
        registry
            .register_client_box(client_spec("web"))
            .expect("the plan has an address for the box");

        let mode = std::fs::metadata(&path)
            .expect("the file is written")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "the registry is its owner's alone");
        assert!(
            !tmp.exists(),
            "the temporary file was renamed over the registry"
        );
        let file: RegistryFile =
            serde_json_lenient::from_slice(&std::fs::read(&path).expect("the file reads"))
                .expect("the file parses whole");
        assert_eq!(file.version, REGISTRY_FILE_VERSION);
        assert_eq!(file.boxes.len(), 1);
        assert!(file.boxes[0].standing);

        let text = std::fs::read_to_string(&path).expect("the file reads");
        std::fs::write(&path, text.replacen("\"version\": 1", "\"version\": 99", 1))
            .expect("a future version's file");
        assert!(
            persisted_registry(&dir).row_by_name("web").is_none(),
            "a file of another version reloads no row"
        );
    }

    /// NET-138: a registry file this build cannot use — of another version,
    /// or not parsing — is set aside under a suffixed name, never written
    /// over by the next registration, so what it held is there to recover.
    #[test]
    fn an_unusable_registry_file_is_set_aside_not_overwritten() {
        let dir = tempfile::tempdir().expect("a temp dir");
        let path = dir.path().join(REGISTRY_FILE);
        for unusable in [&br#"{"version": 99, "boxes": []}"#[..], b"not json at all"] {
            for entry in std::fs::read_dir(dir.path()).expect("the dir lists") {
                std::fs::remove_file(entry.expect("an entry").path()).expect("a file removed");
            }
            std::fs::write(&path, unusable).expect("an unusable file");

            let registry = persisted_registry(&dir);
            registry
                .register_client_box(client_spec("web"))
                .expect("the plan has an address for the box");

            let aside: Vec<_> = std::fs::read_dir(dir.path())
                .expect("the dir lists")
                .map(|entry| entry.expect("an entry").path())
                .filter(|entry| entry.to_string_lossy().contains(".unusable-"))
                .collect();
            assert_eq!(aside.len(), 1, "the unusable file is set aside");
            assert_eq!(
                std::fs::read(&aside[0]).expect("the set-aside file reads"),
                unusable,
                "as it was"
            );
            let file: RegistryFile =
                serde_json_lenient::from_slice(&std::fs::read(&path).expect("the file reads"))
                    .expect("the new file parses whole");
            assert_eq!(file.boxes.len(), 1, "and a new file holds the new creation");
        }
    }

    /// NET-138: a creator resumes its box's row once the row was withdrawn
    /// after its grace — the same id, the same addresses, reinstated from
    /// the host's own record of the registration and awaiting its box's
    /// frames — and a resume whose pair or id is not the creation's is
    /// refused, changing nothing.
    #[test]
    fn a_creator_resumes_a_row_withdrawn_after_its_grace() {
        let dir = tempfile::tempdir().expect("a temp dir");
        let registry = persisted_registry(&dir);
        registry.spawn_withdrawal_drainer(|_| {});
        let web = registry
            .register_client_box(client_spec("web"))
            .expect("the plan has an address for the box");
        relay_carried_and_ended(&registry, &[&web]);
        wait_until(|| web.is_detached(), "the row detaches at its relay's end");
        registry.advance_clock(DETACH_GRACE);
        wait_until(
            || registry.row_by_name("web").is_none(),
            "the row is withdrawn",
        );

        let resume = |switch_addr, box_id| {
            let claim = registry.begin_registration("web");
            registry.resume_client_box(
                "web",
                switch_addr,
                web.loopback_addr(),
                box_id,
                web.loopback_addr(),
                claim.generation(),
            )
        };
        let other = Ipv4Addr::new(100, 64, 0, 200);
        assert!(
            matches!(
                resume(other, None),
                Err(ResumeError::NotTheHandedPair { .. })
            ),
            "another pair is not the creator's proof"
        );
        assert!(
            matches!(
                resume(web.switch_addr(), Some([7; 16])),
                Err(ResumeError::NotTheBoxId { .. })
            ),
            "another id is another box"
        );
        assert!(
            registry.row_by_name("web").is_none(),
            "a refusal changes nothing"
        );

        let resumed = resume(web.switch_addr(), Some(web.box_id()))
            .expect("the creator resumes its box inside the address's quarantine");
        assert_eq!(resumed.box_id(), web.box_id(), "under its own box id");
        assert_eq!(resumed.switch_addr(), web.switch_addr());
        assert_eq!(resumed.loopback_addr(), web.loopback_addr());
        assert!(
            !resumed.is_detached(),
            "awaiting its box's frames, with no grace running"
        );
        assert_eq!(
            registry.live_switch_addrs(),
            1,
            "its switch address is out again"
        );
        assert!(
            persisted_registry(&dir).row_by_name("web").is_some(),
            "the resumed row is persisted standing"
        );

        let again = resume(web.switch_addr(), None).expect("a standing row resumes as it is");
        assert!(Arc::ptr_eq(&again, &resumed), "the standing row itself");
    }

    /// NET-138: a dormant creation holds its name — a registration under
    /// it, in any spelling that folds to it, is refused rather than taking
    /// the name its creator may still resume — until its creator destroys
    /// it.
    #[test]
    fn a_dormant_creation_holds_its_name() {
        let registry = BoxRegistry::new(SUBNET);
        let web = registry
            .register_client_box(client_spec("web"))
            .expect("the plan has an address for the box");
        assert!(registry.withdraw(web.switch_addr()).is_some());
        assert!(registry.row_by_name("web").is_none(), "the row is gone");
        for asked in ["web", "WEB"] {
            assert_eq!(
                registry
                    .register_client_box(client_spec(asked))
                    .map(|row| row.box_id()),
                Err(AllocationError::NameAlreadyHeld {
                    held: "web".to_string()
                }),
                "{asked} folds to the dormant creation's name"
            );
        }
        assert_eq!(
            registry.withdraw_client_box("web", web.switch_addr(), web.loopback_addr(), None),
            Ok(None)
        );
        registry
            .register_client_box(client_spec("web"))
            .expect("a destroyed creation holds no name");
    }

    /// NET-138: a resume naming the box's id finds its creation whatever the
    /// session is called now — renamed since its registration — and answers
    /// the row under the creation's own name; without the id, a renamed
    /// session's resume finds nothing. [`BoxRegistry::resumable`] reads
    /// the same lookup, answering a standing row as itself and a dormant
    /// creation by its own name.
    #[test]
    fn a_resume_by_box_id_survives_a_rename() {
        let registry = BoxRegistry::new(SUBNET);
        let web = registry
            .register_client_box(client_spec("web"))
            .expect("the plan has an address for the box");
        let (switch, loopback) = (web.switch_addr(), web.loopback_addr());
        assert!(
            matches!(
                registry.resumable("renamed", switch, loopback, Some(web.box_id())),
                Ok(Resumable::Standing(row)) if Arc::ptr_eq(&row, &web)
            ),
            "a standing row is the resume's whole answer"
        );
        assert!(registry.withdraw(switch).is_some());
        assert!(
            matches!(
                registry.resumable("renamed", switch, loopback, Some(web.box_id())),
                Ok(Resumable::Dormant { name }) if name == "web"
            ),
            "a dormant creation is resumed under its own name"
        );
        assert!(
            matches!(
                registry.resumable("renamed", switch, loopback, None),
                Err(ResumeError::NoCreation { .. })
            ),
            "by name alone a renamed session finds nothing"
        );

        let claim = registry.begin_registration("web");
        let resumed = registry
            .resume_client_box(
                "renamed",
                switch,
                loopback,
                Some(web.box_id()),
                loopback,
                claim.generation(),
            )
            .expect("the id finds the creation");
        assert_eq!(resumed.name(), "web", "under the creation's own name");
        assert_eq!(resumed.box_id(), web.box_id());
    }

    /// NET-138: a resume that reinstates a withdrawn row arms its bound: the
    /// row no relay carries within it is withdrawn as a detached row is at
    /// its grace's end, its addresses still reserved for the dormant
    /// creation left behind, which a later resume reinstates again.
    #[test]
    fn an_unattributed_resume_is_withdrawn_after_its_bound() {
        let dir = tempfile::tempdir().expect("a temp dir");
        let registry = persisted_registry(&dir);
        let released = Arc::new(Mutex::new(Vec::<String>::new()));
        let sink = Arc::clone(&released);
        registry.spawn_withdrawal_drainer(move |name| {
            sink.lock().expect("the test's lock").push(name.to_string());
        });
        let web = registry
            .register_client_box(client_spec("web"))
            .expect("the plan has an address for the box");
        relay_carried_and_ended(&registry, &[&web]);
        wait_until(|| web.is_detached(), "the row detaches at its relay's end");
        registry.advance_clock(DETACH_GRACE);
        wait_until(
            || registry.row_by_name("web").is_none(),
            "the row is withdrawn at its grace's end",
        );
        let resume = || {
            let claim = registry.begin_registration("web");
            registry.resume_client_box(
                "web",
                web.switch_addr(),
                web.loopback_addr(),
                Some(web.box_id()),
                web.loopback_addr(),
                claim.generation(),
            )
        };
        resume().expect("the creator reinstates its withdrawn row");
        registry.advance_clock(RESUME_ATTACH_BOUND.saturating_sub(Duration::from_secs(10)));
        let_the_drainer_sweep();
        assert!(
            registry.row_by_name("web").is_some(),
            "the row stands inside its bound"
        );

        registry.advance_clock(Duration::from_secs(10));
        wait_until(
            || registry.row_by_name("web").is_none(),
            "the row is withdrawn at its bound",
        );
        assert_eq!(
            registry.live_switch_addrs(),
            1,
            "the dormant creation keeps its switch address reserved"
        );
        assert!(
            released.lock().expect("the test's lock").is_empty(),
            "and its loopback address: nothing goes back to the answerer"
        );

        let again = resume().expect("the kept creation resumes again");
        assert_eq!(again.box_id(), web.box_id(), "under its own box id");
        let table = registry.table();
        table.mark_attributed(web.switch_addr().octets());
        registry.advance_clock(RESUME_ATTACH_BOUND);
        let_the_drainer_sweep();
        assert!(
            registry.row_by_name("web").is_some(),
            "a resumed row its box attached to is no longer bound"
        );
    }

    /// NET-138 (finding: a resume extends a detached row): a resume of a
    /// row that stands — detached, its grace running — leaves the row as it
    /// stands. It neither clears the grace nor arms the longer resume
    /// bound, so the row is withdrawn at its grace's end, inside
    /// [`NET_138_WITHDRAWAL_BOUND`] of its attachment's end; and a resume
    /// of a fresh, never-attached row arms nothing either.
    #[test]
    fn a_standing_resume_leaves_the_detached_rows_grace() {
        let registry = BoxRegistry::new(SUBNET);
        registry.spawn_withdrawal_drainer(|_| {});
        let web = registry
            .register_client_box(client_spec("web"))
            .expect("the plan has an address for the box");
        let resume = || {
            let claim = registry.begin_registration("web");
            registry.resume_client_box(
                "web",
                web.switch_addr(),
                web.loopback_addr(),
                Some(web.box_id()),
                web.loopback_addr(),
                claim.generation(),
            )
        };
        let fresh = resume().expect("a standing row resumes as it is");
        assert!(Arc::ptr_eq(&fresh, &web), "the standing row itself");
        registry.advance_clock(RESUME_ATTACH_BOUND * 2);
        let_the_drainer_sweep();
        assert!(
            registry.row_by_name("web").is_some(),
            "a standing row's resume arms no bound"
        );

        relay_carried_and_ended(&registry, &[&web]);
        wait_until(|| web.is_detached(), "the row detaches at its relay's end");
        registry.advance_clock(DETACH_GRACE.saturating_sub(Duration::from_secs(10)));
        let resumed = resume().expect("a detached row resumes as it stands");
        assert!(Arc::ptr_eq(&resumed, &web), "the standing row itself");
        assert!(web.is_detached(), "its grace still runs");
        registry.advance_clock(Duration::from_secs(10));
        wait_until(
            || registry.row_by_name("web").is_none(),
            "the row is withdrawn at its grace's end, not held to the resume bound",
        );
    }

    /// NET-138: a resume that arrives once a detached row's grace has run
    /// out, before the drainer's sweep withdrew it, does not answer with
    /// the row about to go: the row is withdrawn and reinstated, under the
    /// resume's bound.
    #[test]
    fn a_resume_racing_the_grace_end_reinstates_the_row() {
        // No drainer: the sweep has not run yet.
        let registry = BoxRegistry::new(SUBNET);
        let web = registry
            .register_client_box(client_spec("web"))
            .expect("the plan has an address for the box");
        // A relay carried the row and ended, as the drainer detaches it.
        registry.table().mark_attributed(web.switch_addr().octets());
        registry.detach(web.switch_addr().octets(), web.box_id());
        assert!(web.is_detached(), "the row detaches at its relay's end");
        registry.advance_clock(DETACH_GRACE);
        assert!(
            matches!(
                registry.resumable(
                    "web",
                    web.switch_addr(),
                    web.loopback_addr(),
                    Some(web.box_id())
                ),
                Ok(Resumable::Dormant { .. })
            ),
            "a row past its grace is no standing answer"
        );
        let claim = registry.begin_registration("web");
        let resumed = registry
            .resume_client_box(
                "web",
                web.switch_addr(),
                web.loopback_addr(),
                Some(web.box_id()),
                web.loopback_addr(),
                claim.generation(),
            )
            .expect("the creator reinstates its row");
        assert!(!Arc::ptr_eq(&resumed, &web), "a reinstated row");
        assert!(!resumed.is_detached(), "awaiting its box under the bound");
    }

    /// NET-138: a reinstated row's bound is its unit's — a task row its
    /// task run's relay carries keeps the reinstated box row standing past
    /// the resume bound, as it keeps a detached one past the grace.
    #[test]
    fn a_reinstated_unit_a_task_run_carries_is_not_withdrawn_at_the_bound() {
        let registry = BoxRegistry::new(SUBNET);
        registry.spawn_withdrawal_drainer(|_| {});
        let web = registry
            .register_client_box_with_task_slots(client_spec("web"), 1)
            .expect("the plan has addresses for the box and its task");
        relay_carried_and_ended(&registry, &[&web]);
        wait_until(|| web.is_detached(), "the row detaches at its relay's end");
        registry.advance_clock(DETACH_GRACE);
        wait_until(
            || registry.row_by_name("web").is_none(),
            "the unit is withdrawn at its grace's end",
        );

        let claim = registry.begin_registration("web");
        let resumed = registry
            .resume_client_box(
                "web",
                web.switch_addr(),
                web.loopback_addr(),
                Some(web.box_id()),
                web.loopback_addr(),
                claim.generation(),
            )
            .expect("the creator reinstates its withdrawn row");
        let [task] = task_rows_of(&registry, &resumed)
            .try_into()
            .expect("its task row is reinstated with it");
        let table = registry.table();
        // A task row is carried without its box's own row being marked:
        // the carrier count on the box row stays zero.
        let mut relay = RelayCarry::default();
        table.carry(task.switch_addr().octets(), &mut relay);
        registry.advance_clock(RESUME_ATTACH_BOUND * 2);
        let_the_drainer_sweep();
        assert!(
            registry
                .row_by_name("web")
                .is_some_and(|row| Arc::ptr_eq(&row, &resumed)),
            "a unit a relay carries stands past the resume bound"
        );
    }

    /// NET-138: a relay that carried a box's source before its row was
    /// withdrawn and reinstated — the box's shuttle stayed up while the row
    /// went — counts as a carrier of the reinstated row on its next frame,
    /// so the row is attributed and its bound cleared, and the relay's end
    /// detaches it rather than leaving it to the bound alone.
    #[test]
    fn a_relay_already_carrying_a_source_re_attributes_a_reinstated_row() {
        let registry = BoxRegistry::new(SUBNET);
        registry.spawn_withdrawal_drainer(|_| {});
        let web = registry
            .register_client_box(client_spec("web"))
            .expect("the plan has an address for the box");
        let table = registry.table();
        let src = web.switch_addr().octets();
        let mut relay = RelayCarry::default();
        table.carry(src, &mut relay);
        // The row goes from under the live relay.
        assert!(registry.withdraw(web.switch_addr()).is_some());

        let claim = registry.begin_registration("web");
        let resumed = registry
            .resume_client_box(
                "web",
                web.switch_addr(),
                web.loopback_addr(),
                Some(web.box_id()),
                web.loopback_addr(),
                claim.generation(),
            )
            .expect("the creator reinstates its withdrawn row");
        assert!(!Arc::ptr_eq(&resumed, &web), "a new row at the address");
        assert!(!resumed.was_attributed(), "not yet carried");

        table.carry(src, &mut relay);
        assert!(
            resumed.was_attributed(),
            "the relay's next frame attributes the reinstated row"
        );
        registry.advance_clock(RESUME_ATTACH_BOUND * 2);
        let_the_drainer_sweep();
        assert!(
            registry.row_by_name("web").is_some(),
            "a reinstated row a relay carries is past its bound"
        );
        table.report_withdrawals(relay.into_report());
        wait_until(
            || resumed.is_detached(),
            "the relay's end detaches the reinstated row",
        );
    }

    /// The task rows filed with `web`, as the gate resolves them by source.
    fn task_rows_of(registry: &BoxRegistry, web: &BoxRecord) -> Vec<Arc<BoxRecord>> {
        let table = registry.table();
        web.task_addrs()
            .iter()
            .filter_map(|addr| table.by_source(addr.octets()))
            .collect()
    }

    /// NET-138, NET-133: a task row carries its box's id and its box's
    /// egress — compiled with the task's own address as its lease — and
    /// nothing else: no ingress, no names, no dynamic grant, no credentialed
    /// lane. It publishes no name and is no box to look up by one.
    #[test]
    fn task_row_carries_box_egress_and_no_credentialed_lane() {
        let registry = BoxRegistry::new(SUBNET);
        let mut spec = client_spec("web");
        spec.ingress_ports = vec![8080];
        spec.egress = Some(EgressPolicy {
            allow_subnets: Some(vec!["10.0.0.0/8".to_string()]),
            allow_dns_hosts: Some(vec!["example.com".to_string()]),
            ..EgressPolicy::default()
        });
        spec.credentialed_upstream = Some(sessions::CredentialedUpstream {});
        spec.dynamic_ingress = Some(DynamicIngress::Allow);
        spec.dynamic_allowed_range = Some((9000, 9100));
        let web = registry
            .register_client_box_with_task_slots(spec, 2)
            .expect("the plan has addresses for the box and its tasks");
        assert!(
            web.declares_credentialed_upstream(),
            "the box keeps its lane"
        );

        let tasks = task_rows_of(&registry, &web);
        assert_eq!(tasks.len(), 2, "one row per task address");
        for task in &tasks {
            assert_eq!(task.task_row_of(), Some(web.switch_addr()));
            assert_eq!(task.box_id(), web.box_id(), "the box's own id");
            assert_eq!(task.egress_allow_list(), web.egress_allow_list());
            assert_eq!(task.allow_dns_hosts(), web.allow_dns_hosts());
            assert_eq!(
                task.egress(),
                &EgressRules::from_policy(
                    Some(&EgressPolicy {
                        allow_subnets: Some(vec!["10.0.0.0/8".to_string()]),
                        allow_dns_hosts: Some(vec!["example.com".to_string()]),
                        ..EgressPolicy::default()
                    }),
                    SUBNET.dns_server().octets(),
                    task.switch_addr().octets(),
                ),
                "the box's egress, leased to the task's own address"
            );
            assert!(!task.declares_credentialed_upstream(), "no lane");
            assert!(task.admitted_ports().is_empty(), "no ingress");
            assert!(task.declared_names().is_empty(), "no names");
            assert_eq!(task.dynamic_ingress(), DynamicIngress::Deny);
            assert_eq!(task.dynamic_range(), None);
            assert!(task.task_addrs().is_empty());
        }
        assert!(
            registry
                .row_by_name("web")
                .is_some_and(|row| Arc::ptr_eq(&row, &web)),
            "the box's name finds the box's row, never a task's"
        );
        assert_eq!(
            registry.zone_view().rows().count(),
            1,
            "a task row publishes no name"
        );
    }

    /// NET-138: a task run's relay ending detaches nothing while its box's
    /// own relay carries: the task row stands as long as its box's, for the
    /// next run.
    #[test]
    fn task_row_outlives_its_attachment_ending() {
        let registry = BoxRegistry::new(SUBNET);
        registry.spawn_withdrawal_drainer(|_| {});
        let web = registry
            .register_client_box_with_task_slots(client_spec("web"), 1)
            .expect("the plan has addresses for the box and its task");
        let [task] = task_rows_of(&registry, &web)
            .try_into()
            .expect("one task row");
        registry
            .table()
            .mark_attributed(web.switch_addr().octets())
            .expect("the box's relay carries its row");

        relay_carried_and_ended(&registry, &[&task]);
        let_the_drainer_sweep();
        registry.advance_clock(DETACH_GRACE * 2);
        let_the_drainer_sweep();
        assert!(!task.is_detached(), "a task run's end detaches nothing");
        assert!(!web.is_detached(), "nor its box, whose relay carries");
        let held = registry
            .table()
            .by_source(task.switch_addr().octets())
            .expect("the task row stands past any grace");
        assert!(Arc::ptr_eq(&held, &task));
        assert_eq!(registry.live_switch_addrs(), 2, "both addresses stay out");
    }

    /// NET-138: a box and its task rows are one liveness unit. A task run
    /// whose relay carries keeps its box's row standing past the grace after
    /// the box's own relay ends; once the task's relay ends too, the box row
    /// detaches and the unit is withdrawn after the grace.
    #[test]
    fn a_running_task_keeps_its_box_row_past_the_grace() {
        let registry = BoxRegistry::new(SUBNET);
        registry.spawn_withdrawal_drainer(|_| {});
        let web = registry
            .register_client_box_with_task_slots(client_spec("web"), 1)
            .expect("the plan has addresses for the box and its task");
        let [task] = task_rows_of(&registry, &web)
            .try_into()
            .expect("one task row");
        let table = registry.table();
        let task_carried = table
            .mark_attributed(task.switch_addr().octets())
            .expect("the task's relay carries its row");

        relay_carried_and_ended(&registry, &[&web]);
        let_the_drainer_sweep();
        assert!(
            !web.is_detached(),
            "a task run carrying keeps the box attached"
        );
        registry.advance_clock(DETACH_GRACE * 2);
        let_the_drainer_sweep();
        for row in [&web, &task] {
            let held = table
                .by_source(row.switch_addr().octets())
                .expect("the box and its task row stand past the grace");
            assert!(Arc::ptr_eq(&held, row));
        }

        table.report_withdrawals(vec![(task.switch_addr().octets(), task_carried)]);
        wait_until(
            || web.is_detached(),
            "the box row detaches once no relay carries the unit",
        );
        registry.advance_clock(DETACH_GRACE);
        wait_until(
            || {
                table.by_source(web.switch_addr().octets()).is_none()
                    && table.by_source(task.switch_addr().octets()).is_none()
            },
            "the unit is withdrawn once its grace passes",
        );
        assert_eq!(
            registry.live_switch_addrs(),
            2,
            "the dormant creation keeps both addresses reserved"
        );
    }

    fn register_carved_with_task_slots(
        registry: &BoxRegistry,
        name: &str,
    ) -> Result<Arc<BoxRecord>, AllocationError> {
        registry.register_client_box_at_with_task_slots(
            client_spec(name),
            CARVED_LOOPBACK,
            minimald_rpc::TASK_SLOTS_PER_BOX,
        )
    }

    /// NET-138: task slots are best-effort. A box registers with as many as
    /// the book can spare above [`TASK_SLOT_FLOOR`] — fewer than it asked
    /// for, down to none — and is never refused for want of them.
    #[test]
    fn a_box_registers_with_fewer_task_slots_when_the_book_is_short() {
        let registry = BoxRegistry::new(carved());
        // Leave the floor and three more: the box's own address and two
        // task slots.
        for index in 0..CARVED_RUN - TASK_SLOT_FLOOR - 3 {
            register_carved(&registry, &format!("box{index}"))
                .expect("the carved run holds an address for every box");
        }

        let web = register_carved_with_task_slots(&registry, "web")
            .expect("a box is registered on its own address");
        assert_eq!(web.task_addrs().len(), 2, "two of the four task slots");
        assert_eq!(task_rows_of(&registry, &web).len(), 2);

        let api = register_carved_with_task_slots(&registry, "api")
            .expect("a box with no task slot to spare still registers");
        assert!(api.task_addrs().is_empty(), "the book is at its floor");
        assert_eq!(
            registry.live_switch_addrs(),
            CARVED_RUN - TASK_SLOT_FLOOR + 1,
            "the floor gave only the new box's own address"
        );
    }

    /// NET-138: task slots never take the addresses new boxes need. Boxes
    /// that each ask for every task slot register until the run is drawn
    /// through, and the last [`TASK_SLOT_FLOOR`] of them register with none:
    /// the floor was held for their own addresses.
    #[test]
    fn task_slots_never_starve_a_new_box() {
        let registry = BoxRegistry::new(carved());
        let mut boxes = Vec::new();
        let refusal = loop {
            match register_carved_with_task_slots(&registry, &format!("box{}", boxes.len())) {
                Ok(row) => boxes.push(row),
                Err(error) => break error,
            }
        };
        assert!(
            matches!(refusal, AllocationError::SwitchExhausted(_)),
            "only an exhausted run refuses a box: {refusal:?}"
        );
        assert_eq!(
            registry.live_switch_addrs(),
            CARVED_RUN,
            "every address out"
        );
        let slotless = boxes
            .iter()
            .rev()
            .take_while(|row| row.task_addrs().is_empty())
            .count();
        assert!(
            slotless >= TASK_SLOT_FLOOR,
            "the floor kept {slotless} addresses for new boxes, short of {TASK_SLOT_FLOOR}"
        );
        assert!(
            boxes[0].task_addrs().len() == usize::from(minimald_rpc::TASK_SLOTS_PER_BOX),
            "a box registered while the book is roomy gets every task slot"
        );
    }

    /// NET-138: a task row is withdrawn with its box on every path that
    /// removes the box — its creator's withdrawal and the end of its grace
    /// (the resume bound and an uncommitted lease end through the same two).
    /// Its address goes back to the book with its box's when the creator
    /// withdraws, and stays reserved with its box's while the creation is
    /// dormant. A withdrawal naming a task address withdraws nothing: the
    /// row goes with its box, not alone.
    #[test]
    fn task_rows_withdrawn_with_their_box() {
        let registry = BoxRegistry::new(SUBNET);
        let web = registry
            .register_client_box_with_task_slots(client_spec("web"), 2)
            .expect("the plan has addresses for the box and its tasks");
        let tasks = task_rows_of(&registry, &web);
        assert_eq!(registry.live_switch_addrs(), 3);
        assert_eq!(
            registry.withdraw_client_box("web", tasks[0].switch_addr(), web.loopback_addr(), None),
            Ok(None),
            "a task address names no row its creator withdraws"
        );
        assert_eq!(task_rows_of(&registry, &web).len(), 2, "nothing withdrawn");

        registry
            .withdraw_client_box("web", web.switch_addr(), web.loopback_addr(), None)
            .expect("the creator withdraws its box");
        assert!(
            task_rows_of(&registry, &web).is_empty(),
            "with its task rows"
        );
        assert_eq!(registry.live_switch_addrs(), 0, "every address goes back");
        assert!(registry.table().is_empty());

        let registry = BoxRegistry::new(SUBNET);
        registry.spawn_withdrawal_drainer(|_| {});
        let web = registry
            .register_client_box_with_task_slots(client_spec("web"), 2)
            .expect("the plan has addresses for the box and its tasks");
        relay_carried_and_ended(&registry, &[&web]);
        wait_until(|| web.is_detached(), "the row detaches at its relay's end");
        registry.advance_clock(DETACH_GRACE);
        wait_until(
            || registry.table().is_empty(),
            "the box's row and its task rows go at its grace's end",
        );
        assert_eq!(
            registry.live_switch_addrs(),
            3,
            "the dormant creation keeps every address reserved"
        );
        assert_eq!(
            registry.withdraw_client_box("web", web.switch_addr(), web.loopback_addr(), None),
            Ok(None),
            "the creator's destroy ends the dormant creation"
        );
        assert_eq!(registry.live_switch_addrs(), 0, "every address goes back");
    }

    /// NET-138: a box's task rows persist with it — reloaded with its row,
    /// and restored with it when its creator resumes a row withdrawn after
    /// its grace — at the same addresses, under the box's id.
    #[test]
    fn task_rows_restored_with_a_resumed_box() {
        let dir = tempfile::tempdir().expect("a temp dir");
        let web = persisted_registry(&dir)
            .register_client_box_with_task_slots(client_spec("web"), 2)
            .expect("the plan has addresses for the box and its tasks");

        let registry = persisted_registry(&dir);
        let reloaded = registry.row_by_name("web").expect("the row is reloaded");
        assert_eq!(reloaded.task_addrs(), web.task_addrs());
        let tasks = task_rows_of(&registry, &reloaded);
        assert_eq!(tasks.len(), 2, "its task rows are reloaded with it");
        assert!(tasks.iter().all(|task| task.box_id() == web.box_id()));
        assert_eq!(registry.live_switch_addrs(), 3);

        registry.spawn_withdrawal_drainer(|_| {});
        registry.advance_clock(DETACH_GRACE);
        wait_until(
            || registry.table().is_empty(),
            "the reloaded box goes at its grace's end, its task rows with it",
        );
        let claim = registry.begin_registration("web");
        let resumed = registry
            .resume_client_box(
                "web",
                web.switch_addr(),
                web.loopback_addr(),
                Some(web.box_id()),
                web.loopback_addr(),
                claim.generation(),
            )
            .expect("the creator resumes its box");
        assert_eq!(resumed.task_addrs(), web.task_addrs());
        assert_eq!(
            task_rows_of(&registry, &resumed).len(),
            2,
            "its task rows are restored with it"
        );
        assert_eq!(registry.live_switch_addrs(), 3);
    }

    /// NET-138: a box whose creator withdrew it cannot be resumed — the
    /// creation ends with the creator's withdrawal, row or no row.
    #[test]
    fn a_withdrawn_box_cannot_be_resumed() {
        let registry = BoxRegistry::new(SUBNET);
        let web = registry
            .register_client_box(client_spec("web"))
            .expect("the plan has an address for the box");
        registry
            .withdraw_client_box("web", web.switch_addr(), web.loopback_addr(), None)
            .expect("the creator withdraws its box");
        let claim = registry.begin_registration("web");
        assert_eq!(
            registry
                .resume_client_box(
                    "web",
                    web.switch_addr(),
                    web.loopback_addr(),
                    None,
                    web.loopback_addr(),
                    claim.generation(),
                )
                .map(|row| row.box_id()),
            Err(ResumeError::NoCreation {
                name: "web".to_string()
            })
        );
    }

    /// NET-138, design §7.1: a withdrawn row's switch address goes back to
    /// the hand-out book, but is handed again only once the shared reuse
    /// quarantine has passed — not a second before — and then to a new box
    /// with a new id.
    #[test]
    fn withdrawn_switch_address_rehanded_only_after_quarantine() {
        let registry = BoxRegistry::new(carved());
        let rows = fill_carved_run(&registry);
        let gone = &rows[7];
        destroy(&registry, gone);

        assert!(
            matches!(
                register_carved(&registry, "late"),
                Err(AllocationError::SwitchExhausted(_))
            ),
            "a returned address is not handed inside its quarantine"
        );
        registry.advance_clock(SWITCH_REUSE_QUARANTINE.saturating_sub(Duration::from_secs(1)));
        assert!(
            matches!(
                register_carved(&registry, "late"),
                Err(AllocationError::SwitchExhausted(_))
            ),
            "nor a second before the quarantine ends"
        );
        registry.advance_clock(Duration::from_secs(1));
        let again = register_carved(&registry, "late").expect("the quarantine has passed");
        assert_eq!(again.switch_addr(), gone.switch_addr());
        assert_ne!(
            again.box_id(),
            gone.box_id(),
            "a re-handed address is a new box"
        );
        assert_eq!(registry.live_switch_addrs(), CARVED_RUN);
    }

    /// The book hands never-drawn addresses first, then returned ones in
    /// return order: the address free longest goes first.
    #[test]
    fn hand_out_reuses_longest_free_first() {
        let registry = BoxRegistry::new(carved());
        let rows = fill_carved_run(&registry);
        let (first_back, second_back) = (&rows[40], &rows[3]);
        destroy(&registry, first_back);
        registry.advance_clock(Duration::from_secs(10));
        destroy(&registry, second_back);
        registry.advance_clock(SWITCH_REUSE_QUARANTINE);

        let next = register_carved(&registry, "next").expect("both quarantines have passed");
        assert_eq!(
            next.switch_addr(),
            first_back.switch_addr(),
            "the longest free goes first"
        );
        let after = register_carved(&registry, "after").expect("one more address is free");
        assert_eq!(after.switch_addr(), second_back.switch_addr());
    }

    /// A registration refused after its switch address was drawn — here a
    /// withdrawal under its name that landed while it waited — returns the
    /// address at once, unquarantined: no row was published, so no frame
    /// was ever attributed to it, and the refusal spends nothing.
    #[test]
    fn refused_registration_returns_its_switch_address() {
        let registry = BoxRegistry::new(SUBNET);
        let mut withdrawn = registry.table().subscribe_row_withdrawals();
        let old = registry
            .register_client_box(client_spec("old"))
            .expect("the plan has an address for the box");
        registry.table().mark_attributed(old.switch_addr().octets());
        destroy(&registry, &old);
        // The old box's revocation holds its loopback address, so the next
        // registration at it waits — past its early checks, before its draw.
        let hold = withdrawn.try_recv().expect("the subscriber is told");
        let claim = registry.begin_registration("web");
        let generation = claim.generation();
        let loopback = old.loopback_addr();
        let waiting = registry.clone();
        let registering = std::thread::spawn(move || {
            waiting.register_client_box_since(client_spec("web"), loopback, 0, generation)
        });
        std::thread::sleep(Duration::from_millis(200));
        // A withdrawal under the name lands while the registration waits,
        // then the revocation ends and the registration draws and is
        // refused in its turn.
        assert_eq!(
            registry.withdraw_client_box("web", Ipv4Addr::new(100, 64, 200, 1), loopback, None),
            Ok(None)
        );
        let live_before = registry.live_switch_addrs();
        drop(hold);
        assert_eq!(
            registering
                .join()
                .expect("the registering thread")
                .map(|row| row.name().to_string()),
            Err(AllocationError::WithdrawnWhileAllocating)
        );
        drop(claim);
        assert_eq!(
            registry.live_switch_addrs(),
            live_before,
            "the refusal holds no address"
        );
        let next_never_drawn = Ipv4Addr::from(u32::from(old.switch_addr()) + 1);
        assert_eq!(
            registry.returned_switch_addrs(),
            vec![(old.switch_addr(), false), (next_never_drawn, true)],
            "the refused registration's draw came back at once, unquarantined, behind the \
             attributed old row's quarantined one"
        );
    }

    /// A row withdrawn before any frame of its box crossed the gate keyed
    /// no state by its switch address, so the address comes back with no
    /// quarantine and is handed at once; an attributed row's is not.
    #[test]
    fn unattached_withdrawal_skips_quarantine() {
        let registry = BoxRegistry::new(carved());
        let attributed = register_carved(&registry, "attributed").expect("the run is empty");
        registry
            .table()
            .mark_attributed(attributed.switch_addr().octets());
        // A row no relay ever carried a frame for.
        let never = register_carved(&registry, "never").expect("the run has room");
        for index in 2..CARVED_RUN {
            register_carved(&registry, &format!("box{index}")).expect("the run has room");
        }
        assert!(matches!(
            register_carved(&registry, "late"),
            Err(AllocationError::SwitchExhausted(_))
        ));
        destroy(&registry, &attributed);
        destroy(&registry, &never);

        let quiet = register_carved(&registry, "quiet")
            .expect("nothing was attributed to the row, so its address is free at once");
        assert_eq!(quiet.switch_addr(), never.switch_addr());
        // The creator's withdrawal of a row never attributed skips the
        // quarantine too.
        assert_eq!(
            registry.withdraw_client_box(
                "quiet",
                quiet.switch_addr(),
                quiet.loopback_addr(),
                Some(quiet.box_id())
            ),
            Ok(Some(Arc::clone(&quiet)))
        );
        let again = register_carved(&registry, "again").expect("free at once again");
        assert_eq!(again.switch_addr(), never.switch_addr());
        assert!(
            matches!(
                register_carved(&registry, "late"),
                Err(AllocationError::SwitchExhausted(_))
            ),
            "the attributed row's address is still in its quarantine"
        );
    }

    /// An exhausted hand-out run names where it stands: the live and
    /// quarantined counts, the capacity, and when the next address frees.
    #[test]
    fn switch_exhaustion_names_live_and_quarantined() {
        let registry = BoxRegistry::new(carved());
        let rows = fill_carved_run(&registry);
        destroy(&registry, &rows[0]);
        registry.advance_clock(Duration::from_secs(100));
        let error = register_carved(&registry, "late").expect_err("the run is exhausted");
        let AllocationError::SwitchExhausted(counts) = &error else {
            panic!("the refusal is the run's exhaustion, got: {error}");
        };
        assert_eq!(
            (counts.live, counts.quarantined, counts.capacity),
            (CARVED_RUN - 1, 1, CARVED_RUN as u64)
        );
        // The real clock moves under the test's skew, so the wait is a
        // hair under the 200 s left.
        let wait = counts.next_free_in.expect("one address is quarantined");
        assert!(
            Duration::from_secs(199) < wait && wait <= Duration::from_secs(200),
            "the next address frees when its quarantine ends, got {wait:?}"
        );
        let said = error.to_string();
        assert!(
            said.contains(
                "124 of 125 box addresses are held by live boxes and 1 are in their 300 s \
                 reuse quarantine; the next one frees in 200 s"
            ),
            "the refusal names the counts, got: {said}"
        );
        assert_eq!(
            registry.live_switch_addrs(),
            CARVED_RUN - 1,
            "the refusal holds nothing"
        );
    }

    /// The box id is the epoch a withdrawal is held to: once a newer box
    /// was handed the same name and both addresses, a stale creator naming
    /// the old id removes nothing; the new row's own creator, or a client
    /// predating the field, still withdraws it.
    #[test]
    fn stale_withdrawal_with_old_box_id_leaves_new_row() {
        let registry = BoxRegistry::new(carved());
        let mut rows = fill_carved_run(&registry);
        let filler = rows.pop().expect("the run is full");
        destroy(&registry, &filler);
        registry.advance_clock(SWITCH_REUSE_QUARANTINE);
        let old = register_carved(&registry, "web").expect("the address is free again");
        // The old box is destroyed; a duplicate of its creator's
        // withdrawal arrives late.
        destroy(&registry, &old);
        let new = register_carved(&registry, "web").expect("never attributed, so free at once");
        assert_eq!(
            (new.switch_addr(), new.loopback_addr()),
            (old.switch_addr(), old.loopback_addr())
        );

        assert_eq!(
            registry.withdraw_client_box(
                "web",
                old.switch_addr(),
                old.loopback_addr(),
                Some(old.box_id())
            ),
            Err(WithdrawError::NotTheBoxId {
                switch_addr: old.switch_addr(),
                held_box_id: new.box_id(),
                asked_box_id: old.box_id(),
            })
        );
        assert_eq!(
            registry.row_by_name("web").map(|row| row.box_id()),
            Some(new.box_id()),
            "the stale withdrawal left the newer row"
        );
        assert_eq!(
            registry.withdraw_client_box("web", new.switch_addr(), new.loopback_addr(), None),
            Ok(Some(Arc::clone(&new))),
            "a client predating the field keeps the pair proof alone"
        );
    }

    /// NET-133, NET-138, design §7.1: the drainer's withdrawal of a client
    /// box — a box whose shuttle closed, once its detach grace passed —
    /// leaves its published address with the answerer: the dormant
    /// creation keeps it reserved for its resume, and only its creator's
    /// destroy hands it back.
    #[test]
    fn drainer_withdrawal_keeps_a_dormant_creations_answerer_address() {
        let registry = BoxRegistry::new(SUBNET);
        let (released, releases) = std::sync::mpsc::channel();
        registry.spawn_withdrawal_drainer(move |name| {
            let _ = released.send(name.to_string());
        });
        let web = registry
            .register_client_box(client_spec("web"))
            .expect("the plan has an address for the box");

        relay_carried_and_ended(&registry, &[&web]);
        wait_until(|| web.is_detached(), "the row detaches");
        registry.advance_clock(DETACH_GRACE);
        wait_until(
            || registry.row_by_name("web").is_none(),
            "the row is withdrawn",
        );
        assert!(
            releases.recv_timeout(Duration::from_millis(200)).is_err(),
            "the dormant creation owns the address, so it is not released"
        );
        assert!(
            !registry.release_withdrawn_unless_owned("web", || {}),
            "nor by any withdrawal's release while the creation is kept"
        );
        assert_eq!(
            registry.withdraw_client_box("web", web.switch_addr(), web.loopback_addr(), None),
            Ok(None)
        );
        assert!(
            registry.release_withdrawn_unless_owned("web", || {}),
            "the destroy's release hands it back"
        );
    }

    /// The loopback cursor never wraps (#1790): at `u32::MAX` it stops,
    /// so a run that spans the whole space hands nothing past its end
    /// rather than handing its first address again.
    #[test]
    fn take_next_never_wraps_its_cursor() {
        let cursor = AtomicU32::new(u32::MAX - 1);
        assert_eq!(
            take_next(&cursor, 0, u32::MAX),
            Some(Ipv4Addr::from(u32::MAX - 1))
        );
        assert_eq!(take_next(&cursor, 0, u32::MAX), None, "the cursor's end");
        assert_eq!(
            take_next(&cursor, 0, u32::MAX),
            None,
            "a cursor at its end stays there, never wrapping back to 0.0.0.0"
        );
        assert_eq!(cursor.load(Ordering::Relaxed), u32::MAX);
    }

    /// Activate-and-destroy cycles past the run's size never exhaust it: a
    /// destroyed box's switch address comes back and, once its quarantine
    /// has passed, is handed again — the leak the count-up cursor had.
    #[test]
    fn hundreds_of_activate_destroy_cycles_never_exhaust() {
        let registry = BoxRegistry::new(carved());
        for cycle in 0..CARVED_RUN * 3 {
            let row = register_carved(&registry, &format!("cycle{cycle}"))
                .unwrap_or_else(|error| panic!("cycle {cycle} found the run exhausted: {error}"));
            registry.table().mark_attributed(row.switch_addr().octets());
            destroy(&registry, &row);
            registry.advance_clock(SWITCH_REUSE_QUARANTINE);
        }
        assert_eq!(
            registry.live_switch_addrs(),
            0,
            "every destroyed box's address came back"
        );
    }

    /// An autogen name's retry — register, withdraw the unused row, re-mint
    /// and register again — leaves the live count where one activation
    /// leaves it, and the abandoned row's address free at once.
    #[test]
    fn autogen_retry_leaves_live_counts_unchanged() {
        let registry = BoxRegistry::new(SUBNET);
        let first = registry
            .register_client_box(client_spec("proj-ab12"))
            .expect("the plan has an address for the box");
        assert_eq!(registry.live_switch_addrs(), 1);
        assert!(
            registry
                .withdraw_client_box(
                    "proj-ab12",
                    first.switch_addr(),
                    first.loopback_addr(),
                    Some(first.box_id())
                )
                .expect("the creator's pair and id")
                .is_some()
        );
        registry
            .register_client_box(client_spec("proj-cd34"))
            .expect("the plan has an address for the retry");
        assert_eq!(
            registry.live_switch_addrs(),
            1,
            "the retry holds one address, not two"
        );
        assert_eq!(
            registry.returned_switch_addrs(),
            vec![(first.switch_addr(), true)],
            "the abandoned row's address is free to hand at once"
        );
    }

    /// With nothing subscribed to withdrawals, nothing would ever release a
    /// hold, so a withdrawal takes none.
    #[test]
    fn a_withdrawal_with_no_subscriber_holds_nothing() {
        let registry = BoxRegistry::new(SUBNET);
        let row = registry.register(BoxRegistration::new(
            "web",
            Ipv4Addr::from(SUBNET.first_ptask() + 1),
            Ipv4Addr::LOCALHOST,
        ));
        assert!(registry.withdraw(row.switch_addr()).is_some());
        assert!(
            !registry
                .table()
                .revocation_pending(row.switch_addr().octets())
        );
    }

    /// BEP-070: ids are never reused. A box registered, withdrawn, and
    /// registered again under the same name is a new creation with a new
    /// id — through the client-driven door, which spends fresh addresses,
    /// and through the explicit one on the very addresses the first box
    /// held — so a revocation scoped to the first id never names the
    /// second box.
    #[test]
    fn re_registration_never_reuses_an_id() {
        let attachments = crate::bep_attach::Attachments::new();
        let registry = BoxRegistry::new(SUBNET).feeding_proxy_attachments(attachments.clone());
        let spec = || ClientBoxSpec {
            name: "web".to_string(),
            ingress_ports: vec![8080],
            egress: None,
            credentialed_upstream: None,
            dynamic_ingress: None,
            dynamic_allowed_range: None,
        };
        let first = registry
            .register_client_box(spec())
            .expect("the plan has an address for the first box");
        assert!(
            registry
                .withdraw_client_box("web", first.switch_addr(), first.loopback_addr(), None)
                .expect("the withdrawing client is the row's creator")
                .is_some(),
            "the first box's row was published"
        );

        // The client-driven re-registration under the same name: a new id.
        let second = registry
            .register_client_box(spec())
            .expect("the plan has an address for the second box");
        assert_ne!(
            second.box_id(),
            first.box_id(),
            "a re-registration under the same name is a new box with a new id"
        );

        // The explicit door on the first box's own name and addresses: a
        // new id again, neither of the two before it.
        let third = registry.register(
            BoxRegistration::new("web", first.switch_addr(), first.loopback_addr())
                .with_admitted_ports([8080]),
        );
        assert_eq!(
            (third.switch_addr(), third.loopback_addr()),
            (first.switch_addr(), first.loopback_addr()),
            "the third box sits on the first box's addresses"
        );
        assert!(
            third.box_id() != first.box_id() && third.box_id() != second.box_id(),
            "a box on the same name and addresses is a new box with a new id"
        );
        assert!(
            !attachments.holds_id(first.box_id())
                && attachments.holds_id(second.box_id())
                && attachments.holds_id(third.box_id()),
            "the live attachments carry the new ids; the withdrawn id is never handed out again"
        );
    }

    /// NET-138's trust boundary: the guest never sources a row. The table the
    /// gate holds is read-only by construction — `BoxTable`'s only operations
    /// are lookups — and what that means behaviourally is that no amount of
    /// guest traffic changes it: frames driven through a live gate, hostile
    /// ones included, leave the published rows exactly as they were.
    #[tokio::test]
    async fn host_table_never_sourced_from_guest() {
        // One published box, declared as a real one is (TCP to a LAN, nothing
        // else), and the guest node beside it — the shape run.rs boots with.
        let registry = BoxRegistry::new(SUBNET);
        let lease = [100, 64, 0, 9];
        registry.register(
            BoxRegistration::new("web", Ipv4Addr::from(lease), Ipv4Addr::LOCALHOST)
                .with_egress_policy(EgressPolicy {
                    allow_protocols: Some(vec![IpProto::Tcp]),
                    allow_subnets: Some(vec!["10.0.0.0/8".to_string()]),
                    allow_dns_hosts: None,
                    deny_subnets: None,
                }),
        );
        registry.register_node_namespace(7654);
        let mut harness = gate_over(registry).await;

        let before: Vec<_> = harness
            .table
            .rows()
            .iter()
            .map(|row| row_identity(row))
            .collect();

        // Guest-side traffic, hostile included: a frame the published box did
        // not declare, a frame from an address no namespace holds but the plan
        // could lease, a frame carrying the node namespace's own address, and
        // an ARP announcing a foreign address. The gate decides each against
        // the table — the undeclared frame by its row's own rules, the
        // made-up lease by the unregistered drop (NET-085), the node's by
        // its row, and the foreign ARP by rule 0 — and the marker after them
        // proves the whole lot was decided before the comparison.
        let undeclared = ipv4_frame(lease, 6, [203, 0, 113, 7], 443);
        let unknown = ipv4_frame([100, 64, 0, 99], 6, [10, 1, 2, 3], 80);
        let node_frame = ipv4_frame(SUBNET.daemon_ip().octets(), 6, [10, 1, 2, 3], 80);
        let foreign_arp = arp_frame([203, 0, 113, 7]);
        let marker = ipv4_frame(lease, 6, [10, 1, 2, 3], 80);
        for frame in [&undeclared, &unknown, &node_frame, &foreign_arp] {
            send_frame(&mut harness.guest, frame).await;
        }
        send_frame(&mut harness.guest, &marker).await;
        // What the gate admitted, in order: the node namespace's frame, then
        // the published box's marker. The undeclared frame, the foreign ARP,
        // and the made-up lease — the in-plan address no row holds — are
        // simply absent.
        assert_eq!(
            expect_frame(&mut harness.switch).await,
            node_frame,
            "the node namespace's frame is decided by its own row"
        );
        assert_eq!(
            expect_frame(&mut harness.switch).await,
            marker,
            "the marker arrives: everything before it was decided"
        );
        expect_silence(&mut harness.switch).await;

        let after: Vec<_> = harness
            .table
            .rows()
            .iter()
            .map(|row| row_identity(row))
            .collect();
        assert_eq!(
            before, after,
            "no guest frame published, replaced, or withdrew a row: the gate reads \
             the table, it is never sourced from the guest"
        );
        assert!(
            harness.table.by_source(lease).is_some(),
            "the published box's row survived the guest's traffic"
        );
        assert!(
            harness.table.by_source([100, 64, 0, 99]).is_none(),
            "the guest's made-up address published no row — the drop that \
             refused its frame published nothing either"
        );
    }

    /// The zone view the host answerer answers from (NET-138): every
    /// published row's name under the zone apex, the host-answerable
    /// address a lookup may be told (NET-127), and the row's liveness
    /// (NET-128) — a row live from its registration, held NODATA once it
    /// is marked stopped, and gone with its withdrawal, never NXDOMAIN for
    /// a namespace that exists.
    #[test]
    fn the_zone_view_exposes_every_row_s_name_address_and_liveness() {
        let registry = BoxRegistry::new(SUBNET);
        assert!(
            registry.zone_view().is_empty(),
            "a fresh table's zone view holds nothing"
        );

        // One published box at its own address from the reserved local
        // range, one whose declared loopback address is not one the host
        // may be told — its switch lease, inside the guest's fabric — and
        // the node's own namespace at the shared loopback.
        let web = registry.register(BoxRegistration::new(
            "web",
            Ipv4Addr::new(100, 64, 0, 9),
            Ipv4Addr::new(127, 0, 64, 9),
        ));
        registry.register(BoxRegistration::new(
            "lease-only",
            Ipv4Addr::new(100, 64, 0, 10),
            Ipv4Addr::new(100, 64, 0, 10),
        ));
        registry.register_node_namespace(7654);

        let view = registry.zone_view();
        let rows: Vec<(String, Option<Ipv4Addr>, bool)> = view
            .rows()
            .map(|(name, row)| (name.to_string(), row.address, row.live))
            .collect();
        assert_eq!(
            rows,
            [
                ("lease-only.min.internal".to_string(), None, true),
                (
                    "minimald.min.internal".to_string(),
                    Some(Ipv4Addr::LOCALHOST),
                    true
                ),
                (
                    "web.min.internal".to_string(),
                    Some(web.loopback_addr()),
                    true
                ),
            ],
            "every published row is held under its name, its host-answerable \
             address, and its liveness, in name order"
        );

        // The decision over the view answers the same shapes the native
        // daemon's registry does: an A lookup for the published address,
        // NODATA for the name held at an address the host may not be told,
        // NXDOMAIN for a name no row holds.
        let a = sessions::core::zone_answer::Lookup {
            name: "web.min.internal".to_string(),
            record: sessions::core::zone_answer::RecordType::A,
            origin: sessions::core::zone_answer::Origin::OnMachine,
        };
        assert_eq!(
            sessions::core::zone_answer::decide(&a, &view),
            sessions::core::zone_answer::Verdict::Address(web.loopback_addr()),
            "a held live name answers A with its published address"
        );
        let lease_only = sessions::core::zone_answer::Lookup {
            name: "lease-only.min.internal".to_string(),
            record: sessions::core::zone_answer::RecordType::A,
            origin: sessions::core::zone_answer::Origin::OnMachine,
        };
        assert_eq!(
            sessions::core::zone_answer::decide(&lease_only, &view),
            sessions::core::zone_answer::Verdict::Nodata,
            "a name held only at an address the host may not be told is NODATA"
        );

        // A stopped namespace keeps its name held and answers NODATA, never
        // NXDOMAIN (NET-128), and its re-registration clears the mark: the
        // newest declaration is a namespace that is running.
        assert!(registry.mark_stopped(web.switch_addr()));
        let view = registry.zone_view();
        assert_eq!(
            view.rows()
                .find(|(name, _)| *name == "web.min.internal")
                .map(|(_, row)| *row),
            Some(zone_answer::ZoneRow {
                address: Some(web.loopback_addr()),
                live: false,
            }),
            "a stopped namespace keeps its name held, live: false"
        );
        assert_eq!(
            sessions::core::zone_answer::decide(&a, &view),
            sessions::core::zone_answer::Verdict::Nodata,
            "a stopped namespace answers NODATA, held"
        );
        registry.register(BoxRegistration::new(
            "web",
            web.switch_addr(),
            web.loopback_addr(),
        ));
        assert_eq!(
            sessions::core::zone_answer::decide(&a, &registry.zone_view()),
            sessions::core::zone_answer::Verdict::Address(web.loopback_addr()),
            "a re-registration is a namespace that is running again"
        );

        // And a withdrawn namespace's name is gone with its row — held by
        // no name, so NXDOMAIN, never a stopped name held forever.
        assert!(registry.withdraw(web.switch_addr()).is_some());
        assert_eq!(
            sessions::core::zone_answer::decide(&a, &registry.zone_view()),
            sessions::core::zone_answer::Verdict::Nxdomain,
            "a withdrawn namespace's name is held by nothing"
        );
    }

    /// The `host_ip` interim: a box that shares the node's own row
    /// publishes no row of its own, so its name is held with no row
    /// behind it — NODATA, never NXDOMAIN for a box that exists — and the
    /// release ends the interim with the session that bought it.
    #[test]
    fn the_zone_view_holds_a_host_ip_box_name_with_no_row_behind_it() {
        let registry = BoxRegistry::new(SUBNET);
        let a = sessions::core::zone_answer::Lookup {
            name: "web.min.internal".to_string(),
            record: sessions::core::zone_answer::RecordType::A,
            origin: sessions::core::zone_answer::Origin::OnMachine,
        };
        assert_eq!(
            sessions::core::zone_answer::decide(&a, &registry.zone_view()),
            sessions::core::zone_answer::Verdict::Nxdomain,
            "a name nothing holds is NXDOMAIN, the pre-box state"
        );

        // The hold: NODATA, idempotent whatever the case it was asked in.
        assert!(registry.hold_box_name("web", None));
        assert!(!registry.hold_box_name("WEB", None));
        let view = registry.zone_view();
        assert_eq!(
            view.rows()
                .find(|(name, _)| *name == "web.min.internal")
                .map(|(_, row)| *row),
            Some(zone_answer::ZoneRow {
                address: None,
                live: true,
            }),
            "a held name is held with no address and live"
        );
        assert_eq!(
            sessions::core::zone_answer::decide(&a, &view),
            sessions::core::zone_answer::Verdict::Nodata,
            "a held name answers NODATA: the box exists, no address to tell"
        );

        // The release: back to the pre-box state; a repeat is the goal
        // state already holding.
        assert!(registry.release_held_name("web", None));
        assert!(!registry.release_held_name("web", None));
        assert_eq!(
            sessions::core::zone_answer::decide(&a, &registry.zone_view()),
            sessions::core::zone_answer::Verdict::Nxdomain,
            "a released name answers nothing again"
        );

        // A row's name is the row's: the hold does not shadow the address
        // the row answers with, and releasing it leaves the row standing.
        let web = registry.register(BoxRegistration::new(
            "web",
            Ipv4Addr::new(100, 64, 0, 9),
            Ipv4Addr::new(127, 0, 64, 9),
        ));
        assert!(registry.hold_box_name("web", None));
        assert_eq!(
            sessions::core::zone_answer::decide(&a, &registry.zone_view()),
            sessions::core::zone_answer::Verdict::Address(web.loopback_addr()),
            "a name a row publishes answers the row's address, hold or no hold"
        );
        assert!(registry.release_held_name("web", None));
        assert_eq!(
            sessions::core::zone_answer::decide(&a, &registry.zone_view()),
            sessions::core::zone_answer::Verdict::Address(web.loopback_addr()),
            "the row keeps answering its address once the hold is gone"
        );
    }

    /// A release that names its session frees only that session's hold: a
    /// newer session that took the name keeps its own, and a hold a rename
    /// moved to another name is freed by the session it belongs to.
    #[test]
    fn a_session_release_frees_only_that_sessions_holds() {
        let registry = BoxRegistry::new(SUBNET);
        let held = |registry: &BoxRegistry, name: &str| {
            registry
                .zone_view()
                .rows()
                .any(|(held, _)| held == zone_name(name))
        };
        let old = sessions::SessionId::parse_str("00000000-0000-4000-8000-000000000001").unwrap();
        let new = sessions::SessionId::parse_str("00000000-0000-4000-8000-000000000002").unwrap();

        // A newer session took the name: the old session's release leaves it.
        assert!(registry.hold_box_name("web", Some(old)));
        assert!(!registry.hold_box_name("web", Some(new)));
        assert!(!registry.release_held_name("web", Some(old)));
        assert!(held(&registry, "web"), "the newer session's hold stays");
        assert!(registry.release_held_name("web", Some(new)));
        assert!(!held(&registry, "web"));

        // A rename moved the hold: the session's release frees it there.
        assert!(registry.hold_box_name("api", Some(old)));
        assert!(registry.release_held_name("web", Some(old)));
        assert!(
            !held(&registry, "api"),
            "the moved hold went with its session"
        );

        // A hold no session owns goes with its name.
        assert!(registry.hold_box_name("db", None));
        assert!(registry.release_held_name("db", Some(new)));
        assert!(!held(&registry, "db"));
    }

    /// NET-133's trust boundary, on the proxy's attachments: the guest never
    /// sources one. The registry is the attachment table's one writer, and
    /// what that means behaviourally is that no amount of guest traffic
    /// changes what the proxy holds: frames driven through a live gate,
    /// hostile ones included, leave the attachments exactly as the
    /// registrations issued them — the same traffic, frame for frame, that
    /// `host_table_never_sourced_from_guest` proves leaves the rows alone.
    #[tokio::test]
    async fn proxy_attachment_never_sourced_from_guest() {
        // One published box, declared as a real one is, and the guest node
        // beside it — the shape run.rs boots with — over a registry that
        // feeds the proxy's table.
        let attachments = crate::bep_attach::Attachments::new();
        let registry = BoxRegistry::new(SUBNET).feeding_proxy_attachments(attachments.clone());
        let lease = [100, 64, 0, 9];
        registry.register(
            BoxRegistration::new("web", Ipv4Addr::from(lease), Ipv4Addr::LOCALHOST)
                .with_egress_policy(EgressPolicy {
                    allow_protocols: Some(vec![IpProto::Tcp]),
                    allow_subnets: Some(vec!["10.0.0.0/8".to_string()]),
                    allow_dns_hosts: None,
                    deny_subnets: None,
                }),
        );
        registry.register_node_namespace(7654);
        let mut harness = gate_over(registry).await;

        // The host's own issuances, before any guest byte is written: the
        // published box's attachment, and no attachment for the node
        // namespace, which is not a box.
        let before = attachments.rows();
        assert_eq!(
            before.len(),
            1,
            "the registry issued one attachment: the published box's, not the \
             node namespace's"
        );
        assert!(
            attachments.by_source(SUBNET.daemon_ip().octets()).is_none(),
            "the guest node's namespace is not a box: its row buys no attachment"
        );

        // Guest-side traffic, hostile included — the same set the row
        // table's own test drives: a frame the published box did not
        // declare, a frame from an address no namespace holds but the plan
        // could lease, a frame carrying the node namespace's own address,
        // an ARP announcing a foreign address, and the marker after them
        // that proves the whole lot was decided before the comparison.
        let undeclared = ipv4_frame(lease, 6, [203, 0, 113, 7], 443);
        let unknown = ipv4_frame([100, 64, 0, 99], 6, [10, 1, 2, 3], 80);
        let node_frame = ipv4_frame(SUBNET.daemon_ip().octets(), 6, [10, 1, 2, 3], 80);
        let foreign_arp = arp_frame([203, 0, 113, 7]);
        let marker = ipv4_frame(lease, 6, [10, 1, 2, 3], 80);
        for frame in [&undeclared, &unknown, &node_frame, &foreign_arp] {
            send_frame(&mut harness.guest, frame).await;
        }
        send_frame(&mut harness.guest, &marker).await;
        // What the gate admitted, in order — the node namespace's frame by
        // its own row, and the published box's marker: everything was
        // decided. The undeclared frame, the foreign ARP, and the made-up
        // lease — the in-plan address no row holds — are simply absent.
        assert_eq!(
            expect_frame(&mut harness.switch).await,
            node_frame,
            "the node namespace's frame is decided by its own row"
        );
        assert_eq!(
            expect_frame(&mut harness.switch).await,
            marker,
            "the marker arrives: everything before it was decided"
        );
        expect_silence(&mut harness.switch).await;

        // The attachments are exactly what the host issued: no guest frame
        // issued, replaced, or withdrew one.
        let after = attachments.rows();
        assert_eq!(
            before, after,
            "no guest frame reached the attachment table: it is written by \
             the registry alone, and never sourced from the guest"
        );
        assert!(
            attachments.by_source(lease).is_some(),
            "the published box's attachment survived the guest's traffic"
        );
        assert!(
            attachments.by_source([100, 64, 0, 99]).is_none(),
            "the guest's made-up address bought no attachment — the drop \
             that refused its frame attached nothing either"
        );
    }

    /// NET-133: an ended box's attachment is withdrawn within the
    /// requirement's bound of its end. The event the withdrawal keys to is
    /// the same one the row's own withdrawal keys to (NET-138, the row
    /// test above): the box's own shuttle connection — the one its frames
    /// travel by — ending, reported by the relay and applied by the
    /// registry's drainer, so the attachment goes with the row. The report
    /// detaches the row, and the attachment stands with it through the
    /// detach grace ([`DETACH_GRACE`], inside the bound): the box may
    /// attach again. From the moment the grace passes the proxy attributes
    /// nothing to the box, even though the box's revocation was never
    /// recorded anywhere: the attachment that would have named it is gone.
    /// The test clock stands in for the grace, and the poll bounds the
    /// withdrawal after it at the harness's deadline.
    #[tokio::test]
    async fn proxy_attachment_withdrawn_within_60s_of_box_end() {
        let attachments = crate::bep_attach::Attachments::new();
        let registry = BoxRegistry::new(SUBNET).feeding_proxy_attachments(attachments.clone());
        let lease = [100, 64, 0, 9];
        let row = registry.register(BoxRegistration::new(
            "web",
            Ipv4Addr::from(lease),
            Ipv4Addr::LOCALHOST,
        ));
        registry.spawn_withdrawal_drainer(|_| {});
        let clock = registry.clone();
        let mut harness = gate_over(registry).await;

        // The box's attachment is held before its traffic: issued by the
        // registration, ahead of the row, carrying the box's own id — the
        // one its row holds.
        let attachment = attachments
            .by_source(lease)
            .expect("the registration issued the box's attachment");
        assert_eq!(attachment.switch_addr(), Ipv4Addr::from(lease));
        assert_eq!(
            attachment.box_id(),
            row.box_id(),
            "the attachment carries the box's own id, the one its row holds"
        );
        assert_ne!(
            attachment.box_id(),
            [0u8; 16],
            "the attachment names the box, never the all-zero non-id"
        );

        // The box's frame, admitted by its row: the traffic the
        // connection will attribute.
        let frame = ipv4_frame(lease, 6, [10, 1, 2, 3], 80);
        send_frame(&mut harness.guest, &frame).await;
        assert_eq!(
            expect_frame(&mut harness.switch).await,
            frame,
            "the box's declared frame reaches the switch"
        );
        assert!(
            row.was_attributed(),
            "the relay that carried the box's frame marked its row attributed, so its \
             switch address is quarantined at the row's withdrawal"
        );

        // The box's connection ends: the guest closes its side.
        harness
            .guest
            .shutdown()
            .await
            .expect("closing the guest's side");

        // The row detaches, and the attachment stands with it until the
        // grace passes.
        let deadline = tokio::time::Instant::now() + DEADLINE;
        while !row.is_detached() {
            assert!(
                tokio::time::Instant::now() < deadline,
                "the row did not detach at its shuttle connection's end within {DEADLINE:?}"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            attachments.by_source(lease).is_some(),
            "a detached box keeps its attachment through the grace"
        );
        clock.advance_clock(DETACH_GRACE);

        // The attachment goes once the grace passes, and the row goes with
        // the attachment: withdrawn together, under one row lock.
        let deadline = tokio::time::Instant::now() + DEADLINE;
        while attachments.by_source(lease).is_some() {
            assert!(
                tokio::time::Instant::now() < deadline,
                "the attachment outlived its shuttle connection past {DEADLINE:?}"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            harness.table.by_source(lease).is_none(),
            "the row went with the attachment: the two are withdrawn together"
        );
    }

    /// NET-138, NET-045: an admit report inside the grant the host-side
    /// registration holds records into the row it named — the port and
    /// protocol pair, idempotently — and the row's derived egress allow-list
    /// answers the declaration's own spelling, the allow-all one when the
    /// declaration named no subnets.
    #[test]
    fn admit_report_recorded_within_host_grant() {
        let registry = BoxRegistry::new(SUBNET);
        let web = registry.register(
            BoxRegistration::new("web", Ipv4Addr::new(100, 64, 0, 9), Ipv4Addr::LOCALHOST)
                .with_admitted_ports([8080])
                .with_dynamic_ingress(DynamicIngress::Allow, Some((3000, 3999)))
                .with_egress_policy(EgressPolicy {
                    allow_protocols: Some(vec![IpProto::Tcp]),
                    allow_subnets: Some(vec!["10.0.0.0/8".to_string()]),
                    allow_dns_hosts: None,
                    deny_subnets: None,
                }),
        );
        let db = registry.register(
            BoxRegistration::new("db", Ipv4Addr::new(100, 64, 0, 10), Ipv4Addr::LOCALHOST)
                .with_dynamic_ingress(DynamicIngress::Allow, Some((5000, 5999))),
        );

        // The derived allow-list: the declaration's own spelling where the
        // declaration named one, the allow-all one where it did not — the
        // read-only row verb's answer, so a person reads the policy as it
        // was declared.
        assert_eq!(web.egress_allow_list(), ["10.0.0.0/8"]);
        assert_eq!(
            db.egress_allow_list(),
            ["0.0.0.0/0"],
            "an allow_subnets dimension still absent at registration (the opt-out or announced \
             arm hands one) is allow-all, the compiled rules' meaning of None"
        );

        // A report within the grant records, and answers the row it
        // recorded into — the row a serving line names the box by.
        let now = Instant::now();
        let recorded = registry
            .admit_runtime_port(web.switch_addr(), 3000, IpProto::Tcp, now)
            .expect("a report within the grant records");
        assert_eq!(
            recorded.name(),
            "web",
            "the report is answered with the row it recorded into"
        );
        assert_eq!(
            recorded.runtime_port_numbers(),
            [3000],
            "the recorded port is the row's one runtime-admitted port"
        );
        assert_eq!(
            registry
                .row_by_name("web")
                .expect("the row is live under the name the read resolves by")
                .runtime_port_numbers(),
            [3000],
            "the row the read resolves to carries the recorded port"
        );

        // Idempotent by the port and protocol pair: a report the row already
        // answered records the same fact again, not a second one.
        registry
            .admit_runtime_port(web.switch_addr(), 3000, IpProto::Tcp, now)
            .expect("a duplicate report re-records the same fact");
        assert_eq!(
            web.runtime_port_numbers(),
            [3000],
            "the same port and protocol pair records once, not twice"
        );

        // One port number under two protocols is two admissions — the pair
        // the report names is the unit — and a second `allow` row records
        // inside its own grant.
        registry
            .admit_runtime_port(web.switch_addr(), 3000, IpProto::Udp, now)
            .expect("the same port under another protocol is another admission");
        assert_eq!(
            web.runtime_port_numbers(),
            [3000],
            "the numbers stay distinct while the pair-keyed set holds two"
        );
        registry
            .admit_runtime_port(db.switch_addr(), 5000, IpProto::Tcp, now)
            .expect("an allow stance records a report inside its own grant");
        assert_eq!(db.runtime_port_numbers(), [5000]);
    }

    /// NET-045: under `ask` a guest's admit report is refused — ask-yes
    /// must be host-recorded, because only the host sees the attached
    /// human's answer — with a typed refusal naming the box, and nothing is
    /// recorded: not the port, not a rate timestamp.
    #[test]
    fn ask_admit_from_guest_refused_without_host_record() {
        let registry = BoxRegistry::new(SUBNET);
        let asked = registry.register(
            BoxRegistration::new("ask-box", Ipv4Addr::new(100, 64, 0, 9), Ipv4Addr::LOCALHOST)
                .with_dynamic_ingress(DynamicIngress::Ask, Some((3000, 3999))),
        );

        let refused = registry
            .admit_runtime_port(asked.switch_addr(), 3000, IpProto::Tcp, Instant::now())
            .expect_err("a guest report under ask is refused");
        assert_eq!(
            refused,
            PortReportRefusal::AskNotHostRecorded {
                name: "ask-box".to_string(),
                port: 3000,
                proto: IpProto::Tcp,
            }
        );
        assert!(
            refused
                .to_string()
                .contains("ask-yes must be host-recorded"),
            "the refusal's reason names the rule: {refused}"
        );
        assert!(
            asked.runtime_port_numbers().is_empty(),
            "the refused report records no port"
        );
        assert!(
            asked
                .runtime_ports
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .admits
                .is_empty(),
            "the refused report records no rate timestamp"
        );
    }

    /// NET-138: the alias rule resolves a name held by two live rows — a box
    /// recreated under its name while the old row's withdrawal is pending —
    /// to the newest creation, never the old row, whatever the switch
    /// addresses' order; once the newest row is withdrawn the old one is the
    /// name's live box, and once both are gone the name answers no row.
    #[test]
    fn row_by_name_resolves_newest_live_creation() {
        let registry = BoxRegistry::new(SUBNET);
        // The newer creation sits at the lower address, so the map's own
        // order would answer it last.
        let old = registry.register(BoxRegistration::new(
            "web",
            Ipv4Addr::new(100, 64, 0, 20),
            Ipv4Addr::LOCALHOST,
        ));
        let new = registry.register(BoxRegistration::new(
            "web",
            Ipv4Addr::new(100, 64, 0, 9),
            Ipv4Addr::LOCALHOST,
        ));
        assert!(new.box_id() > old.box_id(), "ids order by creation");
        let resolved = registry.row_by_name("web").expect("the name is live");
        assert_eq!(
            resolved.box_id(),
            new.box_id(),
            "the alias resolves to the newest creation"
        );
        let _ = registry.withdraw(new.switch_addr());
        assert_eq!(
            registry
                .row_by_name("web")
                .expect("the old row is still live")
                .box_id(),
            old.box_id()
        );
        let _ = registry.withdraw(old.switch_addr());
        assert!(registry.row_by_name("web").is_none());
        assert!(
            registry.row_by_name("Web").is_none(),
            "a withdrawn name answers no row in any folded spelling"
        );
    }

    /// The answerer keys a published address by the name's canonical
    /// form, so a client registration whose name folds to a live row's
    /// is refused — one box, one address, one row — before any address
    /// is spent, naming the spelling the live row holds; the row's own
    /// spelling is what everyone reads back.
    #[test]
    fn folded_equal_name_refused_and_the_live_row_keeps_its_spelling() {
        let (log, _guard) = crate::net::egress_gate::test_support::capture_log();
        let registry = BoxRegistry::new(SUBNET);
        let web = registry
            .register_client_box(ClientBoxSpec {
                name: "Web".to_string(),
                ingress_ports: Vec::new(),
                egress: None,
                credentialed_upstream: None,
                dynamic_ingress: None,
                dynamic_allowed_range: None,
            })
            .expect("the plan has an address for the first box");

        // A second client asks under a spelling that folds to the live
        // row's name: refused, naming the spelling the row holds.
        let refused = registry
            .register_client_box(ClientBoxSpec {
                name: "web".to_string(),
                ingress_ports: Vec::new(),
                egress: None,
                credentialed_upstream: None,
                dynamic_ingress: None,
                dynamic_allowed_range: None,
            })
            .expect_err("one published address is one box's");
        assert_eq!(
            refused,
            AllocationError::NameAlreadyHeld {
                held: "Web".to_string()
            },
            "the refusal names the held spelling, not the asking one"
        );
        assert!(
            refused
                .to_string()
                .contains("a box named Web already exists"),
            "the refusal's sentence names the held spelling: {refused}"
        );

        // The refusal spent nothing: the live row stands untouched, in
        // its own spelling, and resolves under every folded spelling.
        let rows = registry.table().rows();
        assert_eq!(rows.len(), 1, "a refused registration publishes no row");
        assert_eq!(
            row_identity(&rows[0]),
            row_identity(&web),
            "the live row is the live box's, untouched by the refusal"
        );
        assert_eq!(
            registry
                .row_by_name("WEB")
                .expect("the name resolves in every folded spelling")
                .name(),
            "Web",
            "the row keeps its holder's spelling, the one its holder reads"
        );
        let next = registry
            .register_client_box(ClientBoxSpec {
                name: "db".to_string(),
                ingress_ports: Vec::new(),
                egress: None,
                credentialed_upstream: None,
                dynamic_ingress: None,
                dynamic_allowed_range: None,
            })
            .expect("the plan has a second hand-out address");
        assert_eq!(
            next.switch_addr(),
            Ipv4Addr::from(u32::from(web.switch_addr()) + 1),
            "the refusal spent no address: the next registration takes the \
             hand-out run's next, the address the refused one would have spent"
        );

        // One warn line names the refusal and both spellings — the line a
        // bundle's daemon log tail reads a refused registration by.
        let logged = log.contents();
        assert_eq!(
            logged
                .matches("refused a box registration whose name a live row already holds")
                .count(),
            1,
            "one warn line per refused registration, got: {logged}"
        );
        assert!(
            logged.contains("asked=web") && logged.contains("held=Web"),
            "the warn line names the asking and the held spelling, got: {logged}"
        );
    }

    /// A withdrawal presents the same name-folding proof the registration
    /// answers under: a box registered as "web" is withdrawn by its own
    /// creator under "WEB", and the row the matching address pair points
    /// at is removed — never refused as another box's row.
    #[test]
    fn withdraw_folds_the_asking_name() {
        let registry = BoxRegistry::new(SUBNET);
        let web = registry
            .register_client_box(ClientBoxSpec {
                name: "web".to_string(),
                ingress_ports: Vec::new(),
                egress: None,
                credentialed_upstream: None,
                dynamic_ingress: None,
                dynamic_allowed_range: None,
            })
            .expect("the plan has an address for the first box");
        assert!(
            registry
                .withdraw_client_box("WEB", web.switch_addr(), web.loopback_addr(), None)
                .expect("the asking name folds to the row's, so the proof stands")
                .is_some(),
            "the folded-equal name withdraws the row its pair proves"
        );
        assert!(
            registry.row_by_name("web").is_none(),
            "the row is withdrawn, not held against a folded-equal ask"
        );
    }

    /// NET-138, NET-045: every grant check refuses its own case, naming the
    /// box where a row exists and the check that refused — a report at an
    /// address no row holds, a deny stance (declared or the absent
    /// declaration's default), a stance whose declaration named no range, and
    /// a port outside the range — and a refusal records nothing: not the
    /// port, not a rate timestamp, no fact the host did not already hold.
    #[test]
    fn admit_report_refused_outside_range_or_under_deny() {
        let registry = BoxRegistry::new(SUBNET);
        let allow = registry.register(
            BoxRegistration::new(
                "allow-box",
                Ipv4Addr::new(100, 64, 0, 9),
                Ipv4Addr::LOCALHOST,
            )
            .with_dynamic_ingress(DynamicIngress::Allow, Some((3000, 3999))),
        );
        let denied = registry.register(
            BoxRegistration::new(
                "denied-box",
                Ipv4Addr::new(100, 64, 0, 10),
                Ipv4Addr::LOCALHOST,
            )
            .with_dynamic_ingress(DynamicIngress::Deny, Some((3000, 3999))),
        );
        let ungranted = registry.register(BoxRegistration::new(
            "ungranted-box",
            Ipv4Addr::new(100, 64, 0, 11),
            Ipv4Addr::LOCALHOST,
        ));
        let rangeless = registry.register(
            BoxRegistration::new(
                "rangeless-box",
                Ipv4Addr::new(100, 64, 0, 12),
                Ipv4Addr::LOCALHOST,
            )
            .with_dynamic_ingress(DynamicIngress::Allow, None),
        );

        // No row at the address the report named: the box is exactly what the
        // report could not prove.
        let refused = registry
            .admit_runtime_port(
                Ipv4Addr::new(100, 64, 0, 99),
                3000,
                IpProto::Tcp,
                Instant::now(),
            )
            .expect_err("a report at an address no row holds is refused");
        assert_eq!(
            refused,
            PortReportRefusal::NoRow {
                switch_addr: Ipv4Addr::new(100, 64, 0, 99),
                port: 3000,
                proto: IpProto::Tcp
            },
            "the refusal names the address no row answered at and the report it refused"
        );
        assert_eq!(
            refused.to_string(),
            "no box row is held at switch address 100.64.0.99; the reported port 3000 records \
             nowhere",
            "the wire carries the refusal's sentence verbatim"
        );

        // The deny stance — and the absent declaration's own default, which
        // is the same stance — admits nothing, whatever its range says.
        let refused = registry
            .admit_runtime_port(denied.switch_addr(), 3000, IpProto::Tcp, Instant::now())
            .expect_err("a report under a deny stance is refused");
        assert_eq!(
            refused,
            PortReportRefusal::DenyStance {
                name: "denied-box".to_string(),
                port: 3000,
                proto: IpProto::Tcp
            }
        );
        let refused = registry
            .admit_runtime_port(ungranted.switch_addr(), 3000, IpProto::Tcp, Instant::now())
            .expect_err("a registration that carried no grant admits nothing");
        assert_eq!(
            refused,
            PortReportRefusal::DenyStance {
                name: "ungranted-box".to_string(),
                port: 3000,
                proto: IpProto::Tcp
            },
            "an absent stance is the declaration's deny default, not a permissive one"
        );

        // A stance without a range permits nothing, and a port outside the
        // range is refused naming the range it missed — inclusive at both
        // ends, so the boundaries themselves record.
        let refused = registry
            .admit_runtime_port(rangeless.switch_addr(), 3000, IpProto::Tcp, Instant::now())
            .expect_err("a stance with no range permits nothing");
        assert_eq!(
            refused,
            PortReportRefusal::NoAllowedRange {
                name: "rangeless-box".to_string(),
                port: 3000,
                proto: IpProto::Tcp
            }
        );
        for outside in [2999, 4000] {
            let refused = registry
                .admit_runtime_port(allow.switch_addr(), outside, IpProto::Tcp, Instant::now())
                .expect_err("a report outside the range is refused");
            assert_eq!(
                refused,
                PortReportRefusal::OutsideAllowedRange {
                    name: "allow-box".to_string(),
                    port: outside,
                    proto: IpProto::Tcp,
                    range: (3000, 3999)
                },
                "the range is inclusive, so {outside} alone is outside it"
            );
            assert_eq!(
                refused.to_string(),
                format!(
                    "runtime port {outside} is outside box allow-box's allowed range 3000-3999"
                ),
                "the refusal names the port, the box and the range it missed"
            );
        }
        for boundary in [3000, 3999] {
            registry
                .admit_runtime_port(allow.switch_addr(), boundary, IpProto::Tcp, Instant::now())
                .unwrap_or_else(|refusal| panic!("the range's own ends record, got {refusal}"));
        }

        // Every refusal recorded nothing: no port a refused report named
        // sits on any row it was checked against — the allow row holds only
        // the boundaries that recorded, and the refusals paced no rate
        // timestamp the rows' later reports answer to.
        assert_eq!(
            allow.runtime_port_numbers(),
            vec![3000, 3999],
            "only the range's own ends recorded on the allow row: no refused \
             report's port joined them"
        );
        assert!(
            denied.runtime_port_numbers().is_empty()
                && ungranted.runtime_port_numbers().is_empty()
                && rangeless.runtime_port_numbers().is_empty(),
            "a refused report records no port on any row it was checked against"
        );
        let refused = registry
            .admit_runtime_port(allow.switch_addr(), 3001, IpProto::Tcp, Instant::now())
            .expect("the refusals above did not spend the row's rate");
        assert_eq!(refused.name(), "allow-box");
    }

    /// A re-admit of a port the row already holds — the retry after a lost
    /// reply — is answered as recorded and spends neither the rate nor the
    /// cap: a row whose window is full still answers it, a full row still
    /// answers it, and the row's set is unchanged. A withdrawal of a port the
    /// row does not hold is answered too.
    #[test]
    fn readmit_of_a_held_port_is_idempotent_and_consumes_no_budget() {
        let registry = BoxRegistry::new(SUBNET);
        let web = registry.register(
            BoxRegistration::new("web", Ipv4Addr::new(100, 64, 0, 9), Ipv4Addr::LOCALHOST)
                .with_dynamic_ingress(DynamicIngress::Allow, Some((3000, 3999))),
        );
        let at = Instant::now();
        registry
            .admit_runtime_port(web.switch_addr(), 3000, IpProto::Tcp, at)
            .expect("the first admit records");
        for _ in 0..ROW_ADMIT_RATE_PER_SECOND * 3 {
            registry
                .admit_runtime_port(web.switch_addr(), 3000, IpProto::Tcp, at)
                .expect("a re-admit of a held port is answered as recorded");
        }
        assert_eq!(
            web.runtime_port_numbers(),
            vec![3000],
            "the re-admits change nothing"
        );
        // The re-admits spent nothing: the rest of the second's rate still
        // records new ports, and only the report past it is refused.
        for port in 3001..3000 + ROW_ADMIT_RATE_PER_SECOND as u16 {
            registry
                .admit_runtime_port(web.switch_addr(), port, IpProto::Tcp, at)
                .unwrap_or_else(|refusal| panic!("port {port} records inside the rate: {refusal}"));
        }
        assert!(matches!(
            registry.admit_runtime_port(web.switch_addr(), 3999, IpProto::Tcp, at),
            Err(PortReportRefusal::RateExceeded { .. })
        ));
        // With the window full, a held port is still answered.
        registry
            .admit_runtime_port(web.switch_addr(), 3000, IpProto::Tcp, at)
            .expect("a full window still answers a re-admit of a held port");
        assert_eq!(web.runtime_port_numbers().len(), ROW_ADMIT_RATE_PER_SECOND);

        // A withdrawal of a port the row does not hold is answered.
        assert!(
            registry
                .withdraw_runtime_port(web.switch_addr(), 3998, IpProto::Tcp)
                .is_some(),
            "a withdrawal of an unheld port is the goal state already"
        );
        assert_eq!(web.runtime_port_numbers().len(), ROW_ADMIT_RATE_PER_SECOND);
    }

    /// NET-138: the per-row cap and the per-row admit rate bound what the
    /// reports can do to the host's state. A row holding
    /// [`RUNTIME_PORT_CAP`] ports refuses a report of a new port, and a row
    /// over [`ROW_ADMIT_RATE_PER_SECOND`] recorded reports in a
    /// trailing second refuses until the second passes, while a refusal paces
    /// nothing and a withdrawal never counts.
    #[test]
    fn admit_report_refused_past_row_cap_or_rate() {
        let registry = BoxRegistry::new(SUBNET);
        let web = registry.register(
            BoxRegistration::new("web", Ipv4Addr::new(100, 64, 0, 9), Ipv4Addr::LOCALHOST)
                .with_dynamic_ingress(DynamicIngress::Allow, Some((3000, 3999))),
        );

        // The cap: one report per port of a 256-port span, each a second
        // apart — past the rate window, so the cap is the only bound the
        // reports meet — and then the 257th is refused.
        let base = Instant::now();
        for (spent, port) in (3000..3000 + RUNTIME_PORT_CAP as u16).enumerate() {
            registry
                .admit_runtime_port(
                    web.switch_addr(),
                    port,
                    IpProto::Tcp,
                    base + Duration::from_secs(spent as u64),
                )
                .unwrap_or_else(|refusal| {
                    panic!("report {spent} records inside the cap, got {refusal}")
                });
        }
        assert_eq!(
            web.runtime_port_numbers().len(),
            RUNTIME_PORT_CAP,
            "the row holds the cap's worth of runtime ports"
        );
        let refused = registry
            .admit_runtime_port(
                web.switch_addr(),
                3999,
                IpProto::Tcp,
                base + Duration::from_secs(300),
            )
            .expect_err("a report past the cap is refused");
        assert_eq!(
            refused,
            PortReportRefusal::RowCapReached {
                name: "web".to_string(),
                port: 3999,
                proto: IpProto::Tcp,
                cap: RUNTIME_PORT_CAP
            }
        );
        assert_eq!(
            refused.to_string(),
            "box web already holds 256 runtime-admitted ports, its per-row cap; the reported \
             port 3999 records nothing"
        );
        registry
            .admit_runtime_port(
                web.switch_addr(),
                3000,
                IpProto::Tcp,
                base + Duration::from_secs(301),
            )
            .expect("a full row still answers a re-admit of a port it holds");

        // The rate: a fresh row's own trailing second. Ten distinct ports
        // record in one instant; the eleventh is refused, is still refused
        // half a second later, and records again once the second has passed.
        let ratebound = registry.register(
            BoxRegistration::new(
                "ratebound",
                Ipv4Addr::new(100, 64, 0, 10),
                Ipv4Addr::LOCALHOST,
            )
            .with_dynamic_ingress(DynamicIngress::Allow, Some((3000, 3999))),
        );
        let at = Instant::now();
        for port in 3000..3000 + ROW_ADMIT_RATE_PER_SECOND as u16 {
            registry
                .admit_runtime_port(ratebound.switch_addr(), port, IpProto::Tcp, at)
                .unwrap_or_else(|refusal| {
                    panic!("report {port} records inside the rate, got {refusal}")
                });
        }
        let refused = registry
            .admit_runtime_port(ratebound.switch_addr(), 3999, IpProto::Tcp, at)
            .expect_err("the eleventh report inside one second is refused");
        assert_eq!(
            refused,
            PortReportRefusal::RateExceeded {
                name: "ratebound".to_string(),
                port: 3999,
                proto: IpProto::Tcp,
                rate: ROW_ADMIT_RATE_PER_SECOND
            }
        );
        // A refused report paces nothing: the row's window still holds the
        // ten recorded reports, so the half-second mark refuses the same way.
        let refused = registry
            .admit_runtime_port(
                ratebound.switch_addr(),
                3999,
                IpProto::Tcp,
                at + Duration::from_millis(500),
            )
            .expect_err("a refused report does not spend the window it was refused in");
        assert!(
            matches!(refused, PortReportRefusal::RateExceeded { .. }),
            "the window holds recorded reports alone: got {refused}"
        );
        registry
            .admit_runtime_port(
                ratebound.switch_addr(),
                3999,
                IpProto::Tcp,
                at + Duration::from_secs(1),
            )
            .expect("the rate is a trailing second, so the second's passing records again");
        assert_eq!(
            ratebound.runtime_port_numbers().len(),
            ROW_ADMIT_RATE_PER_SECOND + 1,
            "eleven ports record across the window's passing"
        );

        // A withdrawal never counts against the rate and is never refused:
        // the eleventh report that the rate refused records the instant a
        // withdrawal answered between it and the window's edge.
        registry
            .withdraw_runtime_port(ratebound.switch_addr(), 3999, IpProto::Tcp)
            .expect("a withdrawal report is answered with the row it named");
    }

    /// NET-138: a withdrawal report removes the port and protocol pair it
    /// named — never refused by the cap or the rate — and a row's withdrawal
    /// takes its runtime set with it structurally: a re-registration at the
    /// same address starts empty, never inheriting the box it replaced's
    /// runtime facts.
    #[test]
    fn runtime_port_withdrawn_on_report_and_on_row_withdrawal() {
        let registry = BoxRegistry::new(SUBNET);
        let web = registry.register(
            BoxRegistration::new("web", Ipv4Addr::new(100, 64, 0, 9), Ipv4Addr::LOCALHOST)
                .with_dynamic_ingress(DynamicIngress::Allow, Some((3000, 3999))),
        );
        let now = Instant::now();
        registry
            .admit_runtime_port(web.switch_addr(), 3000, IpProto::Tcp, now)
            .expect("the first report records");
        registry
            .admit_runtime_port(web.switch_addr(), 3001, IpProto::Tcp, now)
            .expect("the second report records");
        registry
            .admit_runtime_port(web.switch_addr(), 3000, IpProto::Udp, now)
            .expect("the third report records");

        // The withdrawal report removes the pair it named and only that pair:
        // the same port number under the other protocol stays — the pair is
        // the unit the report names and the withdrawal removes.
        let row = registry
            .withdraw_runtime_port(web.switch_addr(), 3000, IpProto::Tcp)
            .expect("the withdrawal is answered with the row it named");
        assert_eq!(row.name(), "web");
        assert_eq!(
            web.runtime_port_numbers(),
            [3001, 3000],
            "the withdrawn pair is gone and the same number under the other protocol stays, \
             in report order"
        );

        // Withdrawing a pair the row no longer holds is accepted all the
        // same: the row already at the report's goal state.
        assert!(
            registry
                .withdraw_runtime_port(web.switch_addr(), 3000, IpProto::Tcp)
                .is_some(),
            "a repeated withdrawal is answered with the row, never refused"
        );
        assert!(
            registry
                .withdraw_runtime_port(web.switch_addr(), 3999, IpProto::Tcp)
                .is_some(),
            "a withdrawal of a port the row never held is accepted: the goal state already holds"
        );

        // The row's own withdrawal takes the runtime set with it: the row is
        // gone, a report at its address finds no row, and the re-registration
        // that follows starts the set empty.
        let removed = registry
            .withdraw(web.switch_addr())
            .expect("the row's withdrawal answers with the row it removed");
        assert_eq!(removed.name(), "web");
        assert!(
            registry.row_by_name("web").is_none(),
            "a withdrawn row is gone, not archived"
        );
        assert!(
            matches!(
                registry.admit_runtime_port(web.switch_addr(), 3000, IpProto::Tcp, now),
                Err(PortReportRefusal::NoRow { .. })
            ),
            "a report at the withdrawn row's address records nowhere"
        );
        assert!(
            registry
                .withdraw_runtime_port(web.switch_addr(), 3001, IpProto::Tcp)
                .is_none(),
            "a withdrawal report after the row's withdrawal answers no row, and is accepted"
        );
        let fresh = registry.register(
            BoxRegistration::new("web", web.switch_addr(), Ipv4Addr::LOCALHOST)
                .with_dynamic_ingress(DynamicIngress::Allow, Some((3000, 3999))),
        );
        assert!(
            fresh.runtime_port_numbers().is_empty(),
            "a re-registration starts the runtime set empty — the newest declaration never \
             inherits the row it replaced's runtime facts"
        );
    }

    /// The host-side deny-all predicate is the host-registered declaration's
    /// own fact: the deny-all shape — and only it — reads deny-all, and
    /// nothing the guest reports moves it. A runtime port report, the one
    /// row dimension the in-VM daemon fills, leaves both rows as they were.
    #[test]
    fn deny_all_predicate_reads_the_host_registration_only() {
        let registry = BoxRegistry::new(SUBNET);
        let sealed = registry.register(
            BoxRegistration::new("sealed", Ipv4Addr::new(100, 64, 0, 9), Ipv4Addr::LOCALHOST)
                .with_dynamic_ingress(DynamicIngress::Allow, Some((3000, 3999)))
                .with_egress_policy(EgressPolicy::deny_all()),
        );
        let open = registry.register(
            BoxRegistration::new("open", Ipv4Addr::new(100, 64, 0, 10), Ipv4Addr::LOCALHOST)
                .with_dynamic_ingress(DynamicIngress::Allow, Some((3000, 3999))),
        );
        let listed = registry.register(
            BoxRegistration::new("listed", Ipv4Addr::new(100, 64, 0, 11), Ipv4Addr::LOCALHOST)
                .with_egress_policy(EgressPolicy {
                    allow_protocols: Some(Vec::new()),
                    allow_subnets: Some(Vec::new()),
                    allow_dns_hosts: Some(vec!["example.com".to_string()]),
                    deny_subnets: None,
                }),
        );
        let node = registry.register_node_namespace(7655);
        assert!(sealed.is_deny_all(), "the deny-all section reads deny-all");
        assert!(!open.is_deny_all(), "no egress declaration is not deny-all");
        assert!(!listed.is_deny_all(), "one declared name is not deny-all");
        assert!(
            !node.is_deny_all(),
            "the node namespace, which host-address boxes ride, is never deny-all"
        );

        let now = Instant::now();
        for row in [&sealed, &open] {
            registry
                .admit_runtime_port(row.switch_addr(), 3000, IpProto::Tcp, now)
                .expect("the report is inside the host's grant");
        }
        let table = registry.table();
        let sealed_now = table
            .by_source(sealed.switch_addr().octets())
            .expect("the sealed row is published");
        let open_now = table
            .by_source(open.switch_addr().octets())
            .expect("the open row is published");
        assert!(
            sealed_now.is_deny_all(),
            "a guest report never lifts the host's deny-all"
        );
        assert!(
            !open_now.is_deny_all(),
            "a guest report never makes a row deny-all"
        );
    }
}
