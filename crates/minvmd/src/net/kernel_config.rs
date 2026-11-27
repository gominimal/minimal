//! The configuration the verified network kernel (`netcore`) decides frames
//! against, and the builders that make each part of it from the product's
//! own facts.
//!
//! The kernel's [`Config`] changes only through its own operations, so the
//! holder here starts it empty (no row, no member, the node's baseline not
//! in force, no alias opening) and every part that goes in is built by one
//! function of this module:
//!
//! - a row's rules come from the policy the registry registered the row
//!   with, the policy after `boxes::effective_egress` filled it, read into
//!   the kernel's [`Declared`] ([`declared`]) and made enforceable by
//!   [`policy::effective`], the one way the kernel makes rules
//!   ([`effective_of`]);
//! - a row's names are numbers from one interner ([`NameIds`]): its own box
//!   name, and the box-zone names its `allow_dns_hosts` lists;
//! - a resident `host_ip` box's rules are kept by session beside the
//!   configuration, because the kernel takes the whole member list each
//!   time it changes and its rules cannot be copied;
//! - the host alias's state comes from the product's own listeners and the
//!   exposure table ([`alias_state`]).
//!
//! The registry keeps the configuration in step: every write section that
//! changes a row or a resident `host_ip` box makes the matching change here,
//! under its own lock, and a change the configuration cannot follow is
//! counted, logged and repaired by rebuilding it from the registry in the
//! same section. The egress gate decides every frame it relays, in both
//! directions, by this configuration.

use std::collections::BTreeMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, LockResult, Mutex, OnceLock, PoisonError};
use std::time::Duration;

use boxes::core::egress::{
    DNS_ADMISSION_WINDOW, DNS_FLOW_IDLE_CAP, DNS_MAX_ADDRESSES_PER_NAME, DNS_MAX_FLOWS_PER_BOX,
    DNS_OUTSTANDING_QUERY_CAP, DNS_QUERY_EXPIRY, IPPROTO_TCP, IPPROTO_UDP,
    REPLY_FLOW_SWEEP_INTERVAL, REPLY_MAX_FLOWS_PER_BOX, REPLY_TCP_IDLE_CAP,
    REPLY_UDP_REPLIED_WINDOW, REPLY_UDP_UNREPLIED_WINDOW,
};
use boxes::{EgressPolicy, IpProto, SessionId};
use netcore::alias::{AliasState, Exposure, Holder, PortRange};
use netcore::cohort::Member;
use netcore::finish::{TableLimits, tables_for};
use netcore::flow::Windows;
use netcore::judge::BoxTables;
use netcore::origin::{CohortSpelling, Sources};
use netcore::pins::{self, Pins};
use netcore::plan::{Plan, PlanError};
use netcore::policy::{self, Abilities, Declared, Effective, Enforced, Net, Section};
use netcore::row::Cidr;
use netcore::split::{Config, RowDecl};
use netcore::time::Span;
use switch::SwitchSubnet;

use crate::net::baseline::ALIAS_FETCH_PROTOCOL;
use crate::net::dns_pins;
use crate::net::egress_gate::{REFUSAL_NOTES_PER_SOURCE, REFUSAL_WINDOW};
use crate::net::host_exposures::{self, HostExposure};
use crate::net::kernel_names::{NO_NAME, NameIds, listed_zone_names, names_host, zone_name};

/// A lock a frame is decided under was poisoned: a panic happened while it
/// was held, so what it guards may be half changed, and no frame is decided
/// on it ([`unpoisoned`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Poisoned;

/// The guard `taken` holds, or [`Poisoned`] when its lock was poisoned: the
/// one way the frame path takes the configuration's lock and a box's
/// tables' locks. A poisoned lock is never decided on, and the frame it
/// meets is dropped. The registry's write sections take the configuration's
/// lock another way ([`crate::box_registry`]): they decide nothing, and go
/// on keeping the configuration in step with the registry.
pub(crate) fn unpoisoned<G>(taken: LockResult<G>) -> Result<G, Poisoned> {
    taken.map_err(|_| Poisoned)
}

/// What this host can enforce, as the kernel's policy reads it. The flag
/// changes only what is reported as unenforced for a box at the host's
/// address, and no rule: the kernel hands over the same policy either way.
const HOST: Abilities = Abilities {
    per_box_host_address: true,
};

/// The block that holds every IPv4 address: what an absent `allow_subnets`
/// reaches in the product's compiled rules once `effective_egress` has left
/// it absent (the allow-all reading before the deny-all default is in force,
/// or behind the daemon's opt-out).
const EVERY_SUBNET: Net = Net::V4(Cidr { addr: 0, prefix: 0 });

/// The box zone's apex on the wire, `min.internal`: the name the kernel
/// narrows a DNS query from a row that names nothing to.
pub(crate) const ZONE_APEX_WIRE: &[u8] = b"\x03min\x08internal\x00";

/// The ICMP protocol number, as the product's compiled rules write it.
const IPPROTO_ICMP: u8 = 1;

/// Why the configuration could not be built or a row could not join it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum KernelConfigError {
    /// The switch subnet is not a block the kernel can plan.
    #[error("the switch subnet is not a block the network kernel can plan: {0:?}")]
    Plan(PlanError),
    /// Every name number has been given out.
    #[error("the network kernel's name numbers are exhausted")]
    NamesExhausted,
    /// A row already holds the address, or it is not one a row may hold.
    #[error("the network kernel refused a row at {addr}")]
    RowRefused { addr: Ipv4Addr },
    /// The kernel refused the configuration's starting row list.
    #[error("the network kernel refused an empty row list")]
    Sources,
    /// A box's kernel tables cannot be made for `names` declared names: its
    /// DNS table would need room for more admissions than the table holds.
    #[error("the network kernel cannot make tables for a box declaring {names} names")]
    TablesRefused { names: usize },
}

/// How long a TCP reply record lives after the first FIN, and after every
/// later segment while one side has sent FIN and the other has not.
const TCP_CLOSING_WINDOW: Duration = Duration::from_secs(120);

/// How long a TCP reply record lives after the second FIN, or a reset.
const TCP_CLOSED_WINDOW: Duration = Duration::from_secs(10);

/// `d` in whole milliseconds, as the kernel's clock counts.
fn ms(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

/// The limits of the DNS tables of a box whose declaration names `names`
/// DNS hosts (the node: its baseline's endpoint names; the cohort: its
/// members' names together): the gate's existing capacities and windows,
/// with room for a name's full quota of admissions for each name, and for
/// one name when none is declared.
fn pin_limits(names: usize) -> pins::Limits {
    pins::Limits {
        asked_cap: DNS_OUTSTANDING_QUERY_CAP,
        asked_per_name: DNS_OUTSTANDING_QUERY_CAP,
        admitted_cap: names.max(1).saturating_mul(DNS_MAX_ADDRESSES_PER_NAME),
        admitted_per_name: DNS_MAX_ADDRESSES_PER_NAME,
        flows_cap: DNS_MAX_FLOWS_PER_BOX,
        flows_per_destination: DNS_MAX_FLOWS_PER_BOX,
        query_ms: ms(DNS_QUERY_EXPIRY),
        window_ms: ms(DNS_ADMISSION_WINDOW),
        idle_ms: ms(DNS_FLOW_IDLE_CAP),
    }
}

/// The limits of one box's three kernel tables, for a box whose
/// declaration names `names` DNS hosts: the reply table's capacity, sweep
/// interval and windows, the refusal notes' and the DNS tables', each the
/// gate's existing value, and the closing windows.
fn table_limits(names: usize) -> TableLimits {
    TableLimits {
        windows: Windows {
            tcp_idle_ms: ms(REPLY_TCP_IDLE_CAP),
            tcp_closing_ms: ms(TCP_CLOSING_WINDOW),
            tcp_closed_ms: ms(TCP_CLOSED_WINDOW),
            udp_unreplied_ms: ms(REPLY_UDP_UNREPLIED_WINDOW),
            udp_replied_ms: ms(REPLY_UDP_REPLIED_WINDOW),
            evict_after_ms: None,
        },
        flows_cap: REPLY_MAX_FLOWS_PER_BOX,
        sweep: Span {
            ms: ms(REPLY_FLOW_SWEEP_INTERVAL),
        },
        notes_cap: REPLY_MAX_FLOWS_PER_BOX,
        notes_per_client: REFUSAL_NOTES_PER_SOURCE,
        note_window: Span {
            ms: ms(REFUSAL_WINDOW),
        },
        pins: pin_limits(names),
    }
}

/// The DNS hosts `policy` declares, as the box's DNS table numbers them:
/// each normalized as a question is matched against it
/// ([`dns_pins::normalized`]), the first occurrence kept. A name's number is
/// its position here.
pub(crate) fn dns_names(policy: Option<&EgressPolicy>) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    for host in policy
        .and_then(|policy| policy.allow_dns_hosts.as_ref())
        .into_iter()
        .flatten()
    {
        let name = dns_pins::normalized(host);
        if !names.contains(&name) {
            names.push(name);
        }
    }
    names
}

/// One box's tables, or the cohort's DNS table, with the names its DNS
/// table numbers by position, each table under its own lock.
struct Held<T> {
    names: Vec<String>,
    tables: Mutex<T>,
}

/// The three empty tables of the box at `addr` whose DNS table numbers
/// `names`, made by the kernel's one constructor.
fn row_held(addr: Ipv4Addr, names: Vec<String>) -> Result<Held<BoxTables>, KernelConfigError> {
    match tables_for(u32::from(addr), table_limits(names.len())) {
        Some(tables) => Ok(Held {
            names,
            tables: Mutex::new(tables),
        }),
        None => Err(KernelConfigError::TablesRefused { names: names.len() }),
    }
}

/// A DNS table owned by `owner` with room for `names`; when the kernel
/// cannot make one that large, an empty one at the largest size it makes,
/// said in an error line: names past its room are refused for room.
fn pins_or_largest(owner: u32, names: usize, whose: &'static str) -> Pins {
    if let Some(pins) = Pins::new(owner, pin_limits(names)) {
        return pins;
    }
    let most = most_declared_names();
    tracing::error!(
        whose,
        names,
        most,
        "the network kernel cannot make a DNS table with room for every name; it holds an empty \
         one at the largest size, and names past its room are refused for room"
    );
    Pins::new(owner, pin_limits(most))
        .expect("a DNS table at the largest size the kernel makes is made")
}

/// The most distinct DNS hosts one box may declare: the most a DNS table
/// holds room for, at a name's quota of admissions each. Derived once from
/// the kernel's own refusal, so the number is written nowhere: the largest
/// count whose DNS table the kernel makes.
pub(crate) fn most_declared_names() -> usize {
    static MOST: OnceLock<usize> = OnceLock::new();
    *MOST.get_or_init(|| {
        let mut most = 0;
        let mut step = 1 << 20;
        while step > 0 {
            let names = most + step;
            if Pins::new(0, pin_limits(names)).is_some() {
                most = names;
            }
            step >>= 1;
        }
        most
    })
}

/// What a registration says of one row, as the registry holds it while the
/// row is inserted.
#[derive(Debug, Clone, Copy)]
pub(crate) struct RowFacts<'a> {
    /// The box's name.
    pub(crate) name: &'a str,
    /// The row's egress policy after `boxes::effective_egress`; `None` is
    /// the allow-all that function leaves.
    pub(crate) policy: Option<&'a EgressPolicy>,
    /// The box declares a credentialed upstream.
    pub(crate) laned: bool,
    /// The row is a task row of a box: it has no name and no lane.
    pub(crate) task_row: bool,
    /// The registry record's generation (`BoxRecord::generation`).
    pub(crate) generation: u64,
}

/// What the registry says of one row when its configuration is rebuilt:
/// the row's policy is the one the holder kept for its address.
#[derive(Debug, Clone, Copy)]
pub(crate) struct RowShape<'a> {
    /// The box's name.
    pub(crate) name: &'a str,
    /// The box declares a credentialed upstream.
    pub(crate) laned: bool,
    /// The row is a task row of a box.
    pub(crate) task_row: bool,
    /// The registry record's generation (`BoxRecord::generation`).
    pub(crate) generation: u64,
}

/// A change the configuration could not follow: the registry changed the
/// row at `addr` and the kernel's operation found the configuration
/// different from it. The registry repairs it ([`KernelConfig::rebuild`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Diverged {
    /// The operation that failed.
    op: &'static str,
    /// The row's address.
    addr: Ipv4Addr,
    /// What refused it, when it was refused rather than not found.
    refused: Option<KernelConfigError>,
}

impl Diverged {
    fn missing(op: &'static str, addr: Ipv4Addr) -> Self {
        Self {
            op,
            addr,
            refused: None,
        }
    }

    fn refused(op: &'static str, addr: Ipv4Addr, error: KernelConfigError) -> Self {
        Self {
            op,
            addr,
            refused: Some(error),
        }
    }
}

/// What an admit says of one resident `host_ip` box.
#[derive(Debug, Clone, Copy)]
pub(crate) struct MemberFacts<'a> {
    /// The box's egress policy after `boxes::effective_egress`; `None` is
    /// the allow-all that function leaves.
    pub(crate) policy: Option<&'a EgressPolicy>,
    /// The box declares a credentialed upstream.
    pub(crate) laned: bool,
}

/// The names one row holds in the interner, so its retirement gives them
/// back.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RowNames {
    /// The row's own zone name; `None` for a task row.
    own: Option<String>,
    /// The box-zone names its `allow_dns_hosts` lists.
    listed: Vec<String>,
}

/// One resident `host_ip` box's enforced policy, and the DNS hosts it
/// declares.
struct MemberRules {
    effective: Effective,
    resolves_names: bool,
    names: Vec<String>,
}

/// What the alias's state is built from: the node row's ports, where the
/// hostname proxy listens; the baseline's ports at the alias; and the
/// exposure table.
#[derive(Debug, Clone, Default)]
struct AliasInputs {
    hostname_proxy: Vec<u16>,
    baseline_alias_ports: Vec<host_exposures::PortRange>,
    exposures: Vec<HostExposure>,
}

/// The kernel's configuration, with what keeps it in step with the
/// registry: the name numbers, the names and the policy of each row, each
/// resident `host_ip` box's policy by session, what the alias is built
/// from, and how many times the configuration was found different from the
/// registry.
pub(crate) struct KernelConfig {
    subnet: SwitchSubnet,
    config: Config,
    names: NameIds,
    /// By row address: the names the row holds.
    row_names: BTreeMap<u32, RowNames>,
    /// By row address: the policy the registry registered the row with,
    /// after `boxes::effective_egress`. Kept for every row the registry
    /// holds, so a rebuild reads each row's policy here.
    row_policies: BTreeMap<u32, Option<EgressPolicy>>,
    /// By row address: the generation of the registry record the row was
    /// made or last restated from ([`Self::generation_at`]).
    row_generations: BTreeMap<u32, u64>,
    /// The generation of the resident `host_ip` boxes' record the members
    /// were last given with (`BoxRegistry::host_ip_cohort`), `None` while
    /// there is none.
    cohort_generation: Option<u64>,
    /// By session: the resident `host_ip` boxes' policies, in session order.
    members: BTreeMap<SessionId, MemberRules>,
    alias_inputs: AliasInputs,
    /// The exposure list last given ([`Self::set_exposures`]), kept so a
    /// list the exposure table hands out again unchanged is known as given
    /// without comparing its entries.
    exposures_from: Option<Arc<[HostExposure]>>,
    /// How many times an operation found the configuration different from
    /// the registry and it was rebuilt.
    divergences: u64,
    /// By row address: the row's kernel tables, with the names its DNS
    /// table numbers. They exist exactly while a row holds the address: made
    /// empty when the row is registered, made empty again when it is
    /// registered again or at the end of a relay that carried it, and
    /// dropped with the row. The node's own row has these too: they are the
    /// ones its frames are decided by while the node's baseline is not in
    /// force, when the node's address routes as its row both ways.
    row_tables: BTreeMap<u32, Held<BoxTables>>,
    /// The node's tables, owned by the node's address, with its baseline's
    /// endpoint names in the baseline's order. Reached while the baseline is
    /// in force: by the node's unmarked frames and by frames toward the
    /// node's address, and, under the mark spelling, by the cohort for its
    /// reply records and notes. Its DNS table is made empty again when the
    /// baseline changes.
    node_tables: Held<BoxTables>,
    /// The cohort's DNS table, owned by the address the cohort sends from
    /// under the configuration's spelling, with its members' names together,
    /// normalized and sorted. Reached by the cohort's frames while the
    /// baseline is in force. Made empty again when the members change.
    cohort_pins: Held<Pins>,
    /// The baseline's endpoints last adopted, as given and in their order:
    /// its names and its blocks, which the node's DNS admissions are
    /// checked against.
    node_endpoints: Vec<String>,
}

/// The cohort's names: its members' DNS hosts together, normalized, each
/// once, sorted (members come and go in no fixed order).
fn cohort_names(members: &BTreeMap<SessionId, MemberRules>) -> Vec<String> {
    let names: std::collections::BTreeSet<String> = members
        .values()
        .flat_map(|member| member.names.iter().map(|name| dns_pins::normalized(name)))
        .collect();
    names.into_iter().collect()
}

/// The address the cohort sends from under `sources`' spelling: the node's
/// with the mark, or the plan's own cohort address.
fn cohort_owner(sources: &Sources) -> u32 {
    let plan = sources.plan();
    match sources.spelling() {
        CohortSpelling::NodeWithMark => plan.node(),
        CohortSpelling::OwnAddress => plan.cohort(),
    }
}

impl fmt::Debug for KernelConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KernelConfig")
            .field("subnet", &self.subnet)
            .field("rows", &self.row_names.len())
            .field("members", &self.members.len())
            .field("divergences", &self.divergences)
            .finish_non_exhaustive()
    }
}

impl KernelConfig {
    /// The configuration of a switch with nothing registered: no row, no
    /// member, the node's baseline not in force and nothing in it, and no
    /// exposure open at the alias; Minimal's own listeners' ports held.
    /// Host-address boxes are told apart from the node
    /// by the mark on the node's address.
    pub(crate) fn new(subnet: SwitchSubnet) -> Result<Self, KernelConfigError> {
        let plan = plan_of(subnet).map_err(KernelConfigError::Plan)?;
        let sources = Sources::new(plan, Vec::new(), false, CohortSpelling::NodeWithMark)
            .ok_or(KernelConfigError::Sources)?;
        let node_tables = tables_for(plan.node(), table_limits(0))
            .ok_or(KernelConfigError::TablesRefused { names: 0 })?;
        let cohort_pins = Pins::new(cohort_owner(&sources), pin_limits(0))
            .ok_or(KernelConfigError::TablesRefused { names: 0 })?;
        Ok(Self {
            subnet,
            config: Config {
                sources,
                decls: Vec::new(),
                baseline: Vec::new(),
                members: Vec::new(),
                alias: alias_state(&[], &[], &[]),
            },
            names: NameIds::new(),
            row_names: BTreeMap::new(),
            row_policies: BTreeMap::new(),
            row_generations: BTreeMap::new(),
            cohort_generation: None,
            members: BTreeMap::new(),
            alias_inputs: AliasInputs::default(),
            exposures_from: None,
            divergences: 0,
            row_tables: BTreeMap::new(),
            node_tables: Held {
                names: Vec::new(),
                tables: Mutex::new(node_tables),
            },
            cohort_pins: Held {
                names: Vec::new(),
                tables: Mutex::new(cohort_pins),
            },
            node_endpoints: Vec::new(),
        })
    }

    /// The configuration of a switch whose registry holds `rows`, in the
    /// order given, and the resident `host_ip` boxes `members`: each row and
    /// each member built by the same builders a registration uses. The
    /// node's baseline and the alias are as [`Self::new`] leaves them.
    #[cfg(test)]
    pub(crate) fn from_parts<'a>(
        subnet: SwitchSubnet,
        rows: impl IntoIterator<Item = (Ipv4Addr, RowFacts<'a>)>,
        members: impl IntoIterator<Item = (SessionId, MemberFacts<'a>)>,
    ) -> Result<Self, KernelConfigError> {
        let mut built = Self::new(subnet)?;
        for (addr, facts) in rows {
            built.note_policy(addr, facts.policy);
            built.register_row(addr, &facts)?;
        }
        for (session, facts) in members {
            built.members.insert(session, member_rules(session, &facts));
        }
        built.sync_members();
        Ok(built)
    }

    /// The kernel's configuration, to decide by.
    pub(crate) fn config(&self) -> &Config {
        &self.config
    }

    /// The generation of the registry record the row at `addr` was made or
    /// last restated from, when a row holds `addr`.
    pub(crate) fn generation_at(&self, addr: [u8; 4]) -> Option<u64> {
        self.row_generations.get(&u32::from_be_bytes(addr)).copied()
    }

    /// The generation of the resident `host_ip` boxes' record, as the last
    /// change of the members set it.
    pub(crate) fn cohort_generation(&self) -> Option<u64> {
        self.cohort_generation
    }

    /// Adds a row at `addr`, after every row there is. Refused, with nothing
    /// changed and no name held, when a row already holds `addr`, when `addr`
    /// is not an address a row may hold, or when the name numbers run out.
    pub(crate) fn register_row(
        &mut self,
        addr: Ipv4Addr,
        facts: &RowFacts<'_>,
    ) -> Result<(), KernelConfigError> {
        let tables = row_held(addr, dns_names(facts.policy))?;
        let (decl, names) = self.row_decl(facts)?;
        if self.config.register(u32::from(addr), decl) {
            self.row_names.insert(u32::from(addr), names);
            self.row_tables.insert(u32::from(addr), tables);
            self.row_generations
                .insert(u32::from(addr), facts.generation);
            Ok(())
        } else {
            self.release_names(&names);
            Err(KernelConfigError::RowRefused { addr })
        }
    }

    /// The declaration of one row, holding its names in the interner. On
    /// an error no name is held.
    fn row_decl(&mut self, facts: &RowFacts<'_>) -> Result<(RowDecl, RowNames), KernelConfigError> {
        let dns_hosts: &[String] = facts
            .policy
            .and_then(|policy| policy.allow_dns_hosts.as_deref())
            .unwrap_or(&[]);
        let listed = listed_zone_names(dns_hosts);
        let names_boxes = self
            .names
            .hold_all(&listed)
            .ok_or(KernelConfigError::NamesExhausted)?;
        let (own, name_id) = if facts.task_row {
            (None, NO_NAME)
        } else {
            let own = zone_name(facts.name);
            let Some(id) = self.names.hold(&own) else {
                self.names.release_all(&listed);
                return Err(KernelConfigError::NamesExhausted);
            };
            (Some(own), id)
        };
        // A task row reaches out under its box's egress, never on its lane.
        let laned = facts.laned && !facts.task_row;
        let effective = effective_of(
            &declared(facts.policy, laned, false, facts.name),
            facts.name,
        );
        let decl = RowDecl {
            rules: effective.rules(),
            resolves_names: !dns_hosts.is_empty(),
            alias_by_name: names_host(dns_hosts),
            name_id,
            task_row: facts.task_row,
            names_boxes,
        };
        Ok((decl, RowNames { own, listed }))
    }

    /// Whether a row may hold `addr`: an address the plan leases, the
    /// node's, or the cohort's, which is an ordinary lease while host-address
    /// boxes send from the node's address with the mark. Whether a row holds
    /// it already is not asked.
    pub(crate) fn may_hold(&self, addr: Ipv4Addr) -> bool {
        let plan = self.config.sources.plan();
        let addr = u32::from(addr);
        plan.is_leasable(addr)
            || addr == plan.node()
            || (self.config.sources.spelling() == CohortSpelling::NodeWithMark
                && addr == plan.cohort())
    }

    /// Keeps the policy the registry registered the row at `addr` with.
    pub(crate) fn note_policy(&mut self, addr: Ipv4Addr, policy: Option<&EgressPolicy>) {
        self.row_policies.insert(u32::from(addr), policy.cloned());
    }

    /// Follows the registry's insert of a row at `addr`: a restate of the
    /// row held there when the registry held one (`occupied`), so no other
    /// row's index moves, and a registration otherwise.
    pub(crate) fn keep_row(
        &mut self,
        addr: Ipv4Addr,
        facts: &RowFacts<'_>,
        occupied: bool,
    ) -> Result<(), Diverged> {
        if occupied {
            return self.restate_row(addr, facts);
        }
        self.register_row(addr, facts)
            .map_err(|error| Diverged::refused("register", addr, error))
    }

    /// Replaces the declaration of the row at `addr` in place. The names the
    /// new declaration holds are taken before the old ones are given back,
    /// so a name both hold keeps its number.
    fn restate_row(&mut self, addr: Ipv4Addr, facts: &RowFacts<'_>) -> Result<(), Diverged> {
        let tables = row_held(addr, dns_names(facts.policy))
            .map_err(|error| Diverged::refused("restate", addr, error))?;
        let (decl, names) = self
            .row_decl(facts)
            .map_err(|error| Diverged::refused("restate", addr, error))?;
        let key = u32::from(addr);
        if self.config.restate_at(key, decl).is_none() {
            self.release_names(&names);
            return Err(Diverged::missing("restate", addr));
        }
        if let Some(before) = self.row_names.insert(key, names) {
            self.release_names(&before);
        }
        // A row registered again starts with empty tables.
        self.row_tables.insert(key, tables);
        self.row_generations.insert(key, facts.generation);
        Ok(())
    }

    /// Follows the registry's removal of the row at `addr`: the row, its
    /// names and its policy go. The node's row takes the hostname proxy's
    /// ports at the alias with it.
    pub(crate) fn drop_row(&mut self, addr: Ipv4Addr) -> Result<(), Diverged> {
        let key = u32::from(addr);
        self.row_policies.remove(&key);
        self.row_tables.remove(&key);
        self.row_generations.remove(&key);
        if let Some(names) = self.row_names.remove(&key) {
            self.release_names(&names);
        }
        if addr == self.subnet.daemon_ip() {
            self.set_hostname_proxy(&[]);
        }
        if self.config.retire_at(key).is_some() {
            Ok(())
        } else {
            Err(Diverged::missing("retire", addr))
        }
    }

    /// Follows the registry's rename of the row at `addr` to `name`. A task
    /// row has no name, so only that it is held is checked.
    pub(crate) fn rename_row(&mut self, addr: Ipv4Addr, name: &str) -> Result<(), Diverged> {
        let key = u32::from(addr);
        let Some(task_row) = self.row_names.get(&key).map(|names| names.own.is_none()) else {
            return Err(Diverged::missing("rename", addr));
        };
        if task_row {
            return if self.config.sources.index_of(key).is_some() {
                Ok(())
            } else {
                Err(Diverged::missing("rename", addr))
            };
        }
        let own = zone_name(name);
        let Some(id) = self.names.hold(&own) else {
            return Err(Diverged::refused(
                "rename",
                addr,
                KernelConfigError::NamesExhausted,
            ));
        };
        if !self.config.rename_at(key, id) {
            self.names.release(&own);
            return Err(Diverged::missing("rename", addr));
        }
        if let Some(names) = self.row_names.get_mut(&key)
            && let Some(before) = names.own.replace(own)
        {
            self.names.release(&before);
        }
        Ok(())
    }

    /// Follows the admit of a resident `host_ip` box, or of new rules for
    /// one: the members go to the kernel again, in session order, and
    /// `generation` is the generation of the resident boxes' record after
    /// the admit. Both change in this one call, so no frame is decided on
    /// the new members under the old record's generation, or the reverse.
    pub(crate) fn keep_member(
        &mut self,
        session: SessionId,
        facts: &MemberFacts<'_>,
        generation: Option<u64>,
    ) {
        self.members.insert(session, member_rules(session, facts));
        self.sync_members();
        self.renew_cohort_pins();
        self.cohort_generation = generation;
    }

    /// Follows a resident `host_ip` box's leaving the union, with
    /// `generation` the generation of the resident boxes' record after it,
    /// as [`Self::keep_member`] takes it.
    pub(crate) fn drop_member(&mut self, session: SessionId, generation: Option<u64>) {
        if self.members.remove(&session).is_some() {
            self.sync_members();
            self.renew_cohort_pins();
        }
        self.cohort_generation = generation;
    }

    /// Makes the cohort's DNS table empty again, numbering its members'
    /// names together.
    fn renew_cohort_pins(&mut self) {
        let names = cohort_names(&self.members);
        let pins = pins_or_largest(
            cohort_owner(&self.config.sources),
            names.len(),
            "the host_ip boxes together",
        );
        self.cohort_pins = Held {
            names,
            tables: Mutex::new(pins),
        };
    }

    /// Makes the tables of the row at `addr` empty again, when a row holds
    /// it: the end of a relay that carried it. Nothing else changes.
    pub(crate) fn empty_tables_at(&mut self, addr: Ipv4Addr) {
        let key = u32::from(addr);
        if !self.row_tables.contains_key(&key) {
            return;
        }
        let policy = self.row_policies.get(&key).cloned().flatten();
        let names = dns_names(policy.as_ref());
        let held = match row_held(addr, names.clone()) {
            Ok(held) => held,
            Err(error) => {
                tracing::error!(
                    address = %addr,
                    %error,
                    "the network kernel could not make a carried row's tables at their size; \
                     they are made empty for no name, and its names are refused for room"
                );
                let Some(tables) = tables_for(key, table_limits(0)) else {
                    return;
                };
                Held {
                    names,
                    tables: Mutex::new(tables),
                }
            }
        };
        self.row_tables.insert(key, held);
    }

    /// Adopts the node's baseline: whether it is in force, the blocks its
    /// endpoints name (each endpoint the product's compiled rules read as an
    /// IPv4 block), and its ports at the alias. An endpoint that is not such
    /// a block is left out: a host name, which the node plane pins by its
    /// answers, or a bare address, silently; a term spelled as a block, with
    /// a warning.
    /// `node_names` are the baseline's endpoint names in its order, each
    /// once, as the node's DNS table numbers them. The node's DNS table is
    /// kept when the baseline's in-force flag, its endpoints (names, and the
    /// blocks the node's admissions were checked against) and its names are
    /// unchanged; otherwise made empty, so no address admitted under an old
    /// allow list outlives it. The node's address is the plan's, fixed for
    /// the configuration's life, and an entry's category is not given: a
    /// category is a label; it decides nothing the table holds. Node tables
    /// whose lock was poisoned are never adopted: the node gets empty ones.
    pub(crate) fn adopt_baseline<'a>(
        &mut self,
        in_force: bool,
        endpoints: impl IntoIterator<Item = &'a str>,
        node_names: Vec<String>,
        alias_ports: &[host_exposures::PortRange],
    ) {
        let endpoints: Vec<&str> = endpoints.into_iter().collect();
        let unchanged = self.config.sources.node_in_force() == in_force
            && self.node_endpoints.len() == endpoints.len()
            && self
                .node_endpoints
                .iter()
                .zip(&endpoints)
                .all(|(kept, given)| kept == given)
            && self.node_tables.names == node_names;
        let poisoned = self.node_tables.tables.is_poisoned();
        if !unchanged || poisoned {
            let node = self.config.sources.plan().node();
            let pins = pins_or_largest(node, node_names.len(), "the node's baseline");
            if poisoned && let Some(mut emptied) = tables_for(node, table_limits(0)) {
                tracing::error!(
                    "the node's kernel tables' lock was poisoned by a panic; the node's baseline \
                     is adopted with empty tables"
                );
                emptied.pins = pins;
                self.node_tables.tables = Mutex::new(emptied);
            } else {
                self.node_tables
                    .tables
                    .get_mut()
                    .unwrap_or_else(PoisonError::into_inner)
                    .pins = pins;
            }
        }
        self.node_tables.names = node_names;
        self.node_endpoints = endpoints.iter().map(ToString::to_string).collect();
        let baseline = endpoints
            .into_iter()
            .filter_map(|endpoint| match net_of(endpoint) {
                Net::V4(cidr) if cidr.prefix <= 32 => Some(cidr),
                _ => {
                    // A host name, and a bare address, are left out without
                    // a word: the node plane pins a name by its answers, and
                    // the baseline's reader warns of a bare address. A term
                    // spelled as a block that is not one should never get
                    // here, as both readers refuse it.
                    if endpoint.contains('/') {
                        tracing::warn!(
                            endpoint = %endpoint,
                            "the network kernel's baseline leaves out an endpoint spelled as a \
                             block that is not an IPv4 block of prefix at most 32"
                        );
                    }
                    None
                }
            })
            .collect();
        self.config.adopt_baseline(in_force, baseline);
        self.alias_inputs.baseline_alias_ports = alias_ports.to_vec();
        self.refresh_alias();
    }

    /// Sets the ports the node's row admits, where the hostname proxy
    /// listens at the alias, and the alias's state from them.
    pub(crate) fn set_hostname_proxy(&mut self, ports: &[u16]) {
        self.alias_inputs.hostname_proxy = ports.to_vec();
        self.refresh_alias();
    }

    /// Whether `open` is the exposure list last given, the same list the
    /// exposure table handed out then.
    pub(crate) fn holds_exposures(&self, open: &Arc<[HostExposure]>) -> bool {
        // Identity, not contents: this relies on `HostExposures::current`
        // handing back the same `Arc` while neither the table nor the
        // listeners change.
        self.exposures_from
            .as_ref()
            .is_some_and(|given| Arc::ptr_eq(given, open))
    }

    /// Sets the host exposures the alias opens at, as the exposure table
    /// gives them with Minimal's own listeners' ports left out, and the
    /// alias's state from them. Whether the configuration changed: `false`
    /// when the list holds the exposures already set.
    pub(crate) fn set_exposures(&mut self, open: &Arc<[HostExposure]>) -> bool {
        self.exposures_from = Some(Arc::clone(open));
        if self.alias_inputs.exposures.as_slice() == open.as_ref() {
            return false;
        }
        self.alias_inputs.exposures = open.to_vec();
        self.refresh_alias();
        true
    }

    /// Rebuilds the configuration from the registry's `rows` after `cause`
    /// showed it different from them: counted, logged, and each row built
    /// again from its kept policy by the builders a registration uses. The
    /// members, the baseline and the alias are kept. Tables are kept only
    /// for the registration they were made for, and never when their lock
    /// was poisoned: such a row, the node or the cohort gets empty ones.
    pub(crate) fn rebuild<'a>(
        &mut self,
        rows: impl IntoIterator<Item = (Ipv4Addr, RowShape<'a>)>,
        cause: Diverged,
    ) {
        self.divergences = self.divergences.saturating_add(1);
        tracing::error!(
            op = cause.op,
            address = %cause.addr,
            refused = ?cause.refused,
            divergences = self.divergences,
            "the network kernel's configuration differed from the box registry; rebuilding it \
             from the registry"
        );
        let mut fresh = match Self::new(self.subnet) {
            Ok(fresh) => fresh,
            Err(error) => {
                tracing::error!(
                    %error,
                    "the network kernel's configuration could not be built again; the one that \
                     differs from the box registry stays"
                );
                return;
            }
        };
        for (addr, shape) in rows {
            let Some(policy) = self.row_policies.get(&u32::from(addr)) else {
                tracing::error!(
                    address = %addr,
                    "the network kernel holds no policy for a box registry row; the row is \
                     left out of its configuration"
                );
                continue;
            };
            let facts = RowFacts {
                name: shape.name,
                policy: policy.as_ref(),
                laned: shape.laned,
                task_row: shape.task_row,
                generation: shape.generation,
            };
            if let Err(error) = fresh.register_row(addr, &facts) {
                tracing::error!(
                    address = %addr,
                    %error,
                    "the network kernel refused a box registry row while rebuilding its \
                     configuration"
                );
            }
        }
        // The reply records and notes of every row the rebuilt configuration
        // holds are the ones it held: a rebuild repairs the rules, and keeps
        // a row's records only for the registration they were made for. A
        // row whose registration differs from the one its tables were made
        // for, or whose tables' lock was poisoned, keeps the rebuilt row's
        // empty tables, as a new registration's are. A row's DNS table is kept
        // only while its names are numbered as before; otherwise it is the
        // rebuilt row's empty one, so no admission is ever read under
        // another name.
        for (key, held) in std::mem::take(&mut self.row_tables) {
            let Some(kept) = fresh.row_tables.get_mut(&key) else {
                continue;
            };
            if self.row_generations.get(&key) != fresh.row_generations.get(&key) {
                tracing::debug!(
                    address = %Ipv4Addr::from(key),
                    "a rebuild finds the row registered again since its tables were made; its \
                     tables start empty"
                );
                continue;
            }
            let Ok(mut tables) = held.tables.into_inner() else {
                tracing::error!(
                    address = %Ipv4Addr::from(key),
                    "a row's kernel tables' lock was poisoned by a panic; the rebuilt row's \
                     tables start empty"
                );
                continue;
            };
            let rebuilt = kept
                .tables
                .get_mut()
                .unwrap_or_else(PoisonError::into_inner);
            if held.names != kept.names {
                std::mem::swap(&mut tables.pins, &mut rebuilt.pins);
                tracing::debug!(
                    address = %Ipv4Addr::from(key),
                    "a rebuild numbers the row's DNS names differently; its DNS table starts empty"
                );
            }
            *rebuilt = tables;
        }
        // The node's numbering comes from the baseline, which a rebuild
        // keeps, and so do its endpoints, which the next adoption of the
        // same baseline compares with. The node's tables belong to the
        // node's own address, fixed for the configuration's life; they are
        // kept unless their lock was poisoned.
        if self.node_tables.tables.is_poisoned() {
            tracing::error!(
                "the node's kernel tables' lock was poisoned by a panic; the rebuilt node's \
                 tables start empty"
            );
            let pins = pins_or_largest(
                fresh.config.sources.plan().node(),
                self.node_tables.names.len(),
                "the node's baseline",
            );
            fresh
                .node_tables
                .tables
                .get_mut()
                .unwrap_or_else(PoisonError::into_inner)
                .pins = pins;
            fresh.node_tables.names = std::mem::take(&mut self.node_tables.names);
        } else {
            std::mem::swap(&mut fresh.node_tables, &mut self.node_tables);
        }
        fresh.node_endpoints = std::mem::take(&mut self.node_endpoints);
        fresh.row_policies = std::mem::take(&mut self.row_policies);
        fresh.members = std::mem::take(&mut self.members);
        // The cohort's tables were made for the resident boxes' record, which
        // a rebuild keeps with its generation.
        fresh.cohort_generation = self.cohort_generation;
        if self.cohort_pins.tables.is_poisoned() {
            tracing::error!(
                "the host_ip boxes' kernel DNS table's lock was poisoned by a panic; the rebuilt \
                 one starts empty"
            );
            fresh.renew_cohort_pins();
        } else if cohort_names(&fresh.members) == self.cohort_pins.names {
            std::mem::swap(&mut fresh.cohort_pins, &mut self.cohort_pins);
        } else {
            tracing::debug!(
                "a rebuild numbers the host_ip boxes' DNS names differently; their DNS table \
                 starts empty"
            );
            fresh.renew_cohort_pins();
        }
        fresh.sync_members();
        fresh.alias_inputs = std::mem::take(&mut self.alias_inputs);
        fresh.exposures_from = self.exposures_from.take();
        fresh.refresh_alias();
        fresh.config.adopt_baseline(
            self.config.sources.node_in_force(),
            self.config.baseline.clone(),
        );
        fresh.divergences = self.divergences;
        *self = fresh;
    }

    /// How many times the configuration was found different from the
    /// registry and rebuilt.
    #[cfg(test)]
    pub(crate) fn divergences(&self) -> u64 {
        self.divergences
    }

    /// Gives the kernel the members again, in session order.
    fn sync_members(&mut self) {
        let members = self.members_list();
        self.config.set_members(members);
    }

    /// Gives the kernel the alias's state built from its inputs.
    fn refresh_alias(&mut self) {
        let alias = alias_state(
            &self.alias_inputs.hostname_proxy,
            &self.alias_inputs.baseline_alias_ports,
            &self.alias_inputs.exposures,
        );
        self.config.set_alias(alias);
    }

    /// Gives back every name one row holds.
    fn release_names(&mut self, names: &RowNames) {
        if let Some(own) = &names.own {
            self.names.release(own);
        }
        self.names.release_all(&names.listed);
    }

    /// The members, in session order, each with rules made afresh from its
    /// kept policy.
    fn members_list(&self) -> Vec<Member> {
        self.members
            .values()
            .map(|member| Member {
                rules: member.effective.rules(),
                resolves_names: member.resolves_names,
            })
            .collect()
    }

    /// The policy kept for the row at `addr`, when one is: what the
    /// registration's warning for subnets the gate does not enforce compares
    /// a new registration's policy with, and what the tests read.
    pub(crate) fn row_policy(&self, addr: Ipv4Addr) -> Option<Option<EgressPolicy>> {
        self.row_policies.get(&u32::from(addr)).cloned()
    }
}

#[cfg(test)]
impl KernelConfig {
    /// Panics, naming what differs, unless `self` and `other` hold the same
    /// rows by address, each with the same rules, flags, names, kept policy
    /// and record generation, and the same members in session order with the same rules;
    /// and unless each gives one number to each name.
    pub(crate) fn assert_in_step_with(&self, other: &KernelConfig) {
        assert_eq!(
            self.row_names.keys().collect::<Vec<_>>(),
            other.row_names.keys().collect::<Vec<_>>(),
            "the same row addresses"
        );
        for held in [self, other] {
            assert_eq!(held.config.sources.len(), held.row_names.len());
            assert_eq!(held.config.decls.len(), held.row_names.len());
            held.assert_one_number_per_name();
        }
        for (key, names) in &self.row_names {
            let addr = Ipv4Addr::from(*key);
            assert_eq!(
                Some(names),
                other.row_names.get(key),
                "the names of the row at {addr}"
            );
            assert_eq!(
                self.row_policies.get(key),
                other.row_policies.get(key),
                "the policy kept for the row at {addr}"
            );
            assert_eq!(
                self.row_generations.get(key),
                other.row_generations.get(key),
                "the record generation kept for the row at {addr}"
            );
            let mine = self.decl_at(*key);
            let theirs = other.decl_at(*key);
            assert!(
                same_rules(mine.rules.get(), theirs.rules.get()),
                "the rules of the row at {addr}"
            );
            assert_eq!(mine.resolves_names, theirs.resolves_names, "{addr}");
            assert_eq!(mine.alias_by_name, theirs.alias_by_name, "{addr}");
            assert_eq!(mine.task_row, theirs.task_row, "{addr}");
        }
        assert_eq!(
            self.members.keys().collect::<Vec<_>>(),
            other.members.keys().collect::<Vec<_>>(),
            "the same members, in session order"
        );
        assert_eq!(self.config.members.len(), other.config.members.len());
        for (mine, theirs) in self.config.members.iter().zip(&other.config.members) {
            assert!(same_rules(mine.rules.get(), theirs.rules.get()));
            assert_eq!(mine.resolves_names, theirs.resolves_names);
        }
    }

    /// Panics unless the tables are held as the rule says: exactly the
    /// registered rows have tables, each owned by its row's address; the
    /// node's are owned by the node's address; and the cohort's DNS table by
    /// the address the cohort sends from under the configuration's spelling.
    /// Presence and owners only: a rebuilt configuration's tables are new.
    pub(crate) fn assert_tables_held(&self) {
        let rows: Vec<u32> = self.row_names.keys().copied().collect();
        assert_eq!(
            rows.len(),
            self.config.sources.len(),
            "one name record for each row"
        );
        let held: Vec<u32> = self.row_tables.keys().copied().collect();
        assert_eq!(held, rows, "exactly the registered rows have tables");
        for (key, held) in &self.row_tables {
            let policy = self.row_policies.get(key).cloned().flatten();
            assert_eq!(
                held.names,
                dns_names(policy.as_ref()),
                "a row's names are its policy's"
            );
            let tables = held.tables.lock().unwrap_or_else(PoisonError::into_inner);
            assert_eq!(
                tables.flows.box_addr(),
                *key,
                "a row's reply table is its own"
            );
            assert_eq!(tables.notes.box_addr(), *key, "a row's notes are its own");
            assert_eq!(tables.pins.owner(), *key, "a row's DNS table is its own");
        }
        let node = self.config.sources.plan().node();
        // The node's row declares no DNS host. While the baseline is in
        // force the node's questions are recorded in the node's tables under
        // the baseline's endpoint names; a DNS host declared on the node's
        // row would have no number there.
        if let Some(held) = self.row_tables.get(&node) {
            assert!(held.names.is_empty(), "the node's row declares no DNS host");
        }
        let tables = self
            .node_tables
            .tables
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        assert_eq!(
            tables.flows.box_addr(),
            node,
            "the node's reply table is its own"
        );
        assert_eq!(
            tables.notes.box_addr(),
            node,
            "the node's notes are its own"
        );
        assert_eq!(tables.pins.owner(), node, "the node's DNS table is its own");
        let cohort = self
            .cohort_pins
            .tables
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        assert_eq!(
            cohort.owner(),
            cohort_owner(&self.config.sources),
            "the cohort's DNS table is owned by the address it sends from"
        );
    }

    /// The DNS table of the row at `addr`, for a test to write to and read.
    pub(crate) fn with_row_pins<T>(
        &self,
        addr: Ipv4Addr,
        f: impl FnOnce(&mut Pins) -> T,
    ) -> Option<T> {
        let held = self.row_tables.get(&u32::from(addr))?;
        let mut tables = held.tables.lock().unwrap_or_else(PoisonError::into_inner);
        Some(f(&mut tables.pins))
    }

    /// Panics unless the alias's state is the one built from the node row's
    /// `hostname_proxy` ports, which the registry holds, and from this
    /// holder's own baseline ports and exposures, which no registry holds:
    /// so this checks the hostname-proxy part, and the exposures rest on the
    /// test that writes an exposure file and reads the kernel's arm.
    pub(crate) fn assert_alias_built_from(&self, hostname_proxy: &[u16]) {
        let want = alias_state(
            hostname_proxy,
            &self.alias_inputs.baseline_alias_ports,
            &self.alias_inputs.exposures,
        );
        let alias = &self.config.alias;
        assert_eq!(alias.node_ports, want.node_ports, "the alias's node ports");
        assert_eq!(alias.held, want.held, "the alias's held ports");
        assert_eq!(alias.exposures, want.exposures, "the alias's exposures");
    }

    /// The declaration of the registered row at `key`.
    fn decl_at(&self, key: u32) -> &RowDecl {
        let index = self
            .config
            .sources
            .index_of(key)
            .expect("a row that holds names is registered");
        &self.config.decls[index]
    }

    /// Panics unless only a task row is without a name, two rows have one
    /// number exactly when they have one name, and a listed name has the
    /// number of the box of that name.
    fn assert_one_number_per_name(&self) {
        let rows: Vec<(&RowNames, &RowDecl)> = self
            .row_names
            .iter()
            .map(|(key, names)| (names, self.decl_at(*key)))
            .collect();
        for (names, decl) in &rows {
            assert_eq!(names.own.is_none(), decl.name_id == NO_NAME);
            for (other_names, other_decl) in &rows {
                if names.own.is_some() && other_names.own.is_some() {
                    assert_eq!(
                        names.own == other_names.own,
                        decl.name_id == other_decl.name_id,
                        "one number per name"
                    );
                }
                for (listed, number) in names.listed.iter().zip(&decl.names_boxes) {
                    if other_names.own.as_ref() == Some(listed) {
                        assert_eq!(*number, other_decl.name_id, "a listed name's number");
                    }
                }
            }
        }
    }
}

/// Whether two rule sets are the same, field by field.
#[cfg(test)]
fn same_rules(a: &netcore::row::RowRules, b: &netcore::row::RowRules) -> bool {
    a.allow_protocols == b.allow_protocols
        && a.deny == b.deny
        && a.allow_subnets == b.allow_subnets
        && a.laned == b.laned
}

/// The kernel's plan of the switch's block: the same reserved addresses the
/// switch keeps (gateway, host alias, node, proxy peer), by the same layout.
pub(crate) fn plan_of(subnet: SwitchSubnet) -> Result<Plan, PlanError> {
    Plan::new(u32::from(subnet.network()), subnet.prefix())
}

/// The kernel's reading of a policy after `boxes::effective_egress`. A list
/// that is present stays a list, an empty one included, and an absent one
/// keeps its meaning in the product's compiled rules: an absent
/// `deny_subnets` denies nothing and an absent `allow_protocols` passes every
/// protocol, as the kernel's absent sections do; an absent `allow_subnets`,
/// or no policy at all, reaches every subnet, which the kernel spells as the
/// one block that holds every address. A protocol this crate has no number
/// for is left out, which narrows what passes, and logged under `subject`.
pub(crate) fn declared(
    policy: Option<&EgressPolicy>,
    laned: bool,
    host_address: bool,
    subject: &str,
) -> Declared {
    let allow_subnets = match policy.and_then(|policy| policy.allow_subnets.as_ref()) {
        Some(list) => Section::Listed(list.iter().map(String::as_str).map(net_of).collect()),
        None => Section::Listed(vec![EVERY_SUBNET]),
    };
    let deny_subnets = match policy.and_then(|policy| policy.deny_subnets.as_ref()) {
        Some(list) => Section::Listed(list.iter().map(String::as_str).map(net_of).collect()),
        None => Section::Absent,
    };
    let allow_protocols = match policy.and_then(|policy| policy.allow_protocols.as_ref()) {
        Some(list) => Section::Listed(
            list.iter()
                .filter_map(|&proto| {
                    let number = wire_number(proto);
                    if number.is_none() {
                        tracing::warn!(
                            subject = %subject,
                            protocol = %proto,
                            "the network kernel leaves out an allowed protocol it has no number \
                             for: its list is behind the product's protocols"
                        );
                    }
                    number
                })
                .collect(),
        ),
        None => Section::Absent,
    };
    Declared {
        allow_subnets,
        deny_subnets,
        allow_protocols,
        laned,
        host_address,
    }
}

/// The enforced policy of `declared`. A declaration of which part is not
/// enforced (an IPv6 block, a block that cannot be read, a prefix past 32)
/// is accepted as the product's compiled rules accept it, enforcing the
/// rest, and the skipped entries are logged by their place, under
/// `subject`.
pub(crate) fn effective_of(declared: &Declared, subject: &str) -> Effective {
    match policy::effective(declared, &HOST).enforced() {
        Enforced::Whole(effective) => effective,
        Enforced::Part(part) => {
            tracing::debug!(
                subject = %subject,
                skipped_allowed = ?part.skipped_allowed,
                skipped_denied = ?part.skipped_denied,
                host_address_unenforced = part.host_address,
                "the network kernel enforces the egress policy without the entries it cannot \
                 enforce, as the compiled rules do"
            );
            part.accept()
        }
    }
}

/// The alias's state: the node's baseline ports there, every port one of
/// Minimal's own listeners holds there (the hostname proxy's ports, the
/// box-name answerer, the Box Egress Proxy, the baseline endpoints), one
/// holder for each port of a range, and the exposures the table opens.
pub(crate) fn alias_state(
    hostname_proxy: &[u16],
    baseline_alias_ports: &[host_exposures::PortRange],
    exposures: &[HostExposure],
) -> AliasState {
    let listeners = host_exposures::minimal_listeners(
        hostname_proxy,
        baseline_alias_ports,
        ALIAS_FETCH_PROTOCOL,
    );
    AliasState {
        node_ports: baseline_alias_ports
            .iter()
            .map(|&(lo, hi)| PortRange { lo, hi })
            .collect(),
        held: listeners
            .iter()
            .flat_map(|listener| {
                let (lo, hi) = listener.ports;
                (lo..=hi).map(move |port| Holder {
                    proto: listener.protocol,
                    port,
                })
            })
            .collect(),
        exposures: exposures
            .iter()
            .map(|exposure| Exposure {
                proto: exposure.protocol,
                port: exposure.port,
            })
            .collect(),
    }
}

/// One resident `host_ip` box's enforced policy. The box runs at the host's
/// address.
fn member_rules(session: SessionId, facts: &MemberFacts<'_>) -> MemberRules {
    let resolves_names = facts
        .policy
        .and_then(|policy| policy.allow_dns_hosts.as_ref())
        .is_some_and(|hosts| !hosts.is_empty());
    let subject = session.to_string();
    let effective = effective_of(
        &declared(facts.policy, facts.laned, true, &subject),
        &subject,
    );
    let names = facts
        .policy
        .and_then(|policy| policy.allow_dns_hosts.as_ref())
        .cloned()
        .unwrap_or_default();
    MemberRules {
        effective,
        resolves_names,
        names,
    }
}

/// The entries of `policy`'s allowed and denied subnets the gate does not
/// enforce: every entry that is not an IPv4 block of prefix at most 32 (an
/// IPv6 block, a prefix past 32, an entry that cannot be read), which the
/// kernel's configuration leaves out as the product's compiled rules do.
/// For the warning a registration writes; it decides nothing.
pub(crate) fn unenforced_subnets(policy: Option<&EgressPolicy>) -> (Vec<String>, Vec<String>) {
    let unenforced = |list: Option<&Vec<String>>| -> Vec<String> {
        list.into_iter()
            .flatten()
            .filter(|entry| !matches!(net_of(entry), Net::V4(cidr) if cidr.prefix <= 32))
            .cloned()
            .collect()
    };
    (
        unenforced(policy.and_then(|policy| policy.allow_subnets.as_ref())),
        unenforced(policy.and_then(|policy| policy.deny_subnets.as_ref())),
    )
}

/// Whether a box with `policy` names nothing the gate enforces, read as the
/// kernel reads its row: the rules [`declared`] and [`effective_of`] make
/// (the ones [`KernelConfig::register_row`] gives the kernel) allow no
/// subnet, present and empty, and the box names no DNS host, an absent list
/// and an empty one alike. The condition is the one the kernel decides a
/// row's DNS refusal by. For the warning a registration writes; it decides
/// nothing.
pub(crate) fn names_nothing(
    policy: Option<&EgressPolicy>,
    laned: bool,
    host_address: bool,
    subject: &str,
) -> bool {
    let effective = effective_of(&declared(policy, laned, host_address, subject), subject);
    let rules = effective.rules();
    let resolves_names = policy
        .and_then(|policy| policy.allow_dns_hosts.as_ref())
        .is_some_and(|hosts| !hosts.is_empty());
    match &rules.get().allow_subnets {
        Some(v) => v.as_slice().is_empty() && !resolves_names,
        None => false,
    }
}

/// One `allow_subnets` or `deny_subnets` entry as the kernel reads it. An
/// IPv4 block with a prefix of at most 32 is the set of entries the
/// product's compiled rules keep; every other entry is named and not
/// enforced by the kernel.
fn net_of(entry: &str) -> Net {
    let Some((addr, prefix)) = entry.split_once('/') else {
        return Net::Unreadable;
    };
    let Ok(prefix) = prefix.parse::<u8>() else {
        return Net::Unreadable;
    };
    match addr.parse::<IpAddr>() {
        Ok(IpAddr::V4(addr)) => Net::V4(Cidr {
            addr: u32::from(addr),
            prefix,
        }),
        Ok(IpAddr::V6(_)) => Net::V6,
        Err(_) => Net::Unreadable,
    }
}

/// A protocol's IPv4 wire number, as the product's compiled rules write it;
/// `None` for a protocol this crate does not know.
fn wire_number(proto: IpProto) -> Option<u8> {
    match proto {
        IpProto::Tcp => Some(IPPROTO_TCP),
        IpProto::Udp => Some(IPPROTO_UDP),
        IpProto::Icmp => Some(IPPROTO_ICMP),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use netcore::report::Reported;
    use netcore::split::First;

    use crate::box_registry::{BoxRegistration, BoxRegistry};
    use crate::net::answerer::DEFAULT_ANSWERER_PORT;
    use crate::net::egress_gate::test_support::{NC7_EXPOSURE, gate_decides};

    /// A /24 carved from the default block: the gateway is .1, the cohort
    /// .251, the proxy peer .252, the node .253 and the host alias .254.
    fn subnet() -> SwitchSubnet {
        SwitchSubnet::new(Ipv4Addr::new(100, 64, 7, 0), 24).unwrap()
    }

    fn at(last: u8) -> Ipv4Addr {
        Ipv4Addr::new(100, 64, 7, last)
    }

    fn cidr(a: u8, b: u8, c: u8, d: u8, prefix: u8) -> Cidr {
        Cidr {
            addr: u32::from(Ipv4Addr::new(a, b, c, d)),
            prefix,
        }
    }

    fn strings(entries: &[&str]) -> Vec<String> {
        entries.iter().map(|entry| (*entry).to_string()).collect()
    }

    fn row<'a>(name: &'a str, policy: Option<&'a EgressPolicy>) -> RowFacts<'a> {
        RowFacts {
            name,
            policy,
            laned: false,
            task_row: false,
            generation: 0,
        }
    }

    /// The rules the kernel enforces for `policy` on a box's own row.
    fn row_rules(policy: Option<&EgressPolicy>) -> netcore::row::RowRules {
        let rules = effective_of(&declared(policy, false, false, "test"), "test").rules();
        let read = rules.get();
        netcore::row::RowRules {
            allow_protocols: read.allow_protocols.clone(),
            deny: read.deny.clone(),
            allow_subnets: read.allow_subnets.clone(),
            laned: read.laned,
        }
    }

    #[test]
    fn a_new_configuration_holds_no_row_no_exposure_and_the_baseline_is_not_in_force() {
        let built = KernelConfig::new(subnet()).unwrap();
        let config = built.config();
        assert_eq!(config.sources.len(), 0);
        assert!(config.decls.is_empty());
        assert!(!config.sources.node_in_force());
        assert_eq!(config.sources.spelling(), CohortSpelling::NodeWithMark);
        assert!(config.baseline.is_empty());
        assert!(config.members.is_empty());
        // The alias as the constructor builds it: no node port and no
        // exposure, and Minimal's own two listeners' ports held.
        assert!(config.alias.node_ports.is_empty());
        assert_eq!(config.alias.held, alias_state(&[], &[], &[]).held);
        assert_eq!(config.alias.held.len(), 2);
        assert!(config.alias.exposures.is_empty());
    }

    /// Every prefix a switch subnet can hold (8 through 29), at bases across
    /// the address space, and the default subnet, are blocks the kernel
    /// plans: the box registry's constructor builds its configuration on
    /// that.
    #[test]
    fn every_switch_subnet_is_a_block_the_kernel_plans() {
        let bases = [
            Ipv4Addr::new(0, 0, 0, 0),
            Ipv4Addr::new(10, 0, 0, 0),
            Ipv4Addr::new(100, 64, 7, 0),
            Ipv4Addr::new(192, 168, 255, 255),
            Ipv4Addr::new(255, 255, 255, 255),
        ];
        let mut held = 0;
        for prefix in 0..=32 {
            for base in bases {
                if let Ok(subnet) = SwitchSubnet::new(base, prefix) {
                    held += 1;
                    assert!(plan_of(subnet).is_ok(), "{subnet} is planned");
                }
            }
        }
        assert_eq!(
            held,
            22 * bases.len(),
            "every prefix from 8 to 29 is a switch subnet"
        );
        assert!(
            plan_of(switch::DEFAULT_SUBNET).is_ok(),
            "the default subnet is planned"
        );
    }

    #[test]
    fn the_plan_reserves_the_addresses_the_switch_reserves() {
        let subnet = subnet();
        let plan = plan_of(subnet).unwrap();
        assert_eq!(plan.network(), u32::from(subnet.network()));
        assert_eq!(plan.gateway(), u32::from(subnet.gateway()));
        assert_eq!(plan.host_alias(), u32::from(subnet.host_alias()));
        assert_eq!(plan.node(), u32::from(subnet.daemon_ip()));
        assert_eq!(
            plan.proxy_peer(),
            u32::from(subnet.box_egress_proxy_address())
        );
        let default = plan_of(SwitchSubnet::default()).unwrap();
        assert_eq!(
            default.host_alias(),
            u32::from(SwitchSubnet::default().host_alias())
        );
    }

    #[test]
    fn an_absent_list_keeps_its_meaning_and_an_empty_one_reaches_nothing() {
        // No policy: the allow-all `effective_egress` leaves.
        let all = row_rules(None);
        assert_eq!(all.allow_subnets, None);
        assert_eq!(all.allow_protocols, None);
        assert!(all.deny.is_empty());
        // A section with every list absent reads the same.
        let absent = row_rules(Some(&EgressPolicy::default()));
        assert_eq!(absent.allow_subnets, None);
        assert_eq!(absent.allow_protocols, None);
        assert!(absent.deny.is_empty());
        // The deny-all section: present and empty reaches nothing.
        let none = row_rules(Some(&EgressPolicy::deny_all()));
        assert_eq!(none.allow_subnets, Some(Vec::new()));
        assert_eq!(none.allow_protocols, Some(Vec::new()));
        assert!(none.deny.is_empty());
    }

    #[test]
    fn the_declared_entries_are_enforced_as_written() {
        let policy = EgressPolicy {
            allow_subnets: Some(strings(&["10.0.0.0/8", "192.168.1.5/32"])),
            allow_dns_hosts: None,
            allow_protocols: Some(vec![IpProto::Tcp, IpProto::Udp, IpProto::Icmp]),
            deny_subnets: Some(strings(&["10.1.0.0/16"])),
        };
        let rules = row_rules(Some(&policy));
        assert_eq!(
            rules.allow_subnets,
            Some(vec![cidr(10, 0, 0, 0, 8), cidr(192, 168, 1, 5, 32)])
        );
        assert_eq!(rules.deny, vec![cidr(10, 1, 0, 0, 16)]);
        assert_eq!(rules.allow_protocols, Some(vec![6, 17, 1]));
        assert!(!rules.laned);
    }

    #[test]
    fn an_entry_the_compiled_rules_drop_is_not_enforced() {
        // The written-out allow-all: the IPv6 half grants nothing.
        let all = EgressPolicy {
            allow_subnets: Some(strings(&["0.0.0.0/0", "::/0"])),
            ..EgressPolicy::default()
        };
        assert_eq!(row_rules(Some(&all)).allow_subnets, None);
        let some = EgressPolicy {
            allow_subnets: Some(strings(&["10.0.0.0/8", "::/0", "10.0.0.0/40", "nonsense"])),
            deny_subnets: Some(strings(&["fd00::/8", "172.16.0.0/12"])),
            ..EgressPolicy::default()
        };
        let rules = row_rules(Some(&some));
        assert_eq!(rules.allow_subnets, Some(vec![cidr(10, 0, 0, 0, 8)]));
        assert_eq!(rules.deny, vec![cidr(172, 16, 0, 0, 12)]);
    }

    #[test]
    fn the_entries_are_read_as_the_kernel_names_them() {
        assert_eq!(net_of("10.0.0.0/8"), Net::V4(cidr(10, 0, 0, 0, 8)));
        assert_eq!(net_of("10.0.0.0/40"), Net::V4(cidr(10, 0, 0, 0, 40)));
        assert_eq!(net_of("::/0"), Net::V6);
        assert_eq!(net_of("10.0.0.0"), Net::Unreadable);
        assert_eq!(net_of("10.0.0.0/x"), Net::Unreadable);
        assert_eq!(net_of("ten/8"), Net::Unreadable);
    }

    #[test]
    fn a_row_declares_its_names_and_the_alias_by_number() {
        let policy = EgressPolicy {
            allow_dns_hosts: Some(strings(&[
                "Web.min.internal.",
                "host.min.internal",
                "github.com",
            ])),
            ..EgressPolicy::deny_all()
        };
        let mut built = KernelConfig::new(subnet()).unwrap();
        built
            .register_row(at(2), &row("client", Some(&policy)))
            .unwrap();
        built.register_row(at(3), &row("WEB", None)).unwrap();
        let decls = &built.config().decls;
        assert!(decls[0].resolves_names);
        assert!(decls[0].alias_by_name);
        assert!(!decls[0].task_row);
        // The box listed before it existed has the number it was listed by.
        assert_eq!(decls[0].names_boxes, vec![decls[1].name_id]);
        assert_ne!(decls[0].name_id, decls[1].name_id);
        assert_ne!(decls[1].name_id, NO_NAME);
        assert!(!decls[1].resolves_names);
        assert!(!decls[1].alias_by_name);
        assert!(decls[1].names_boxes.is_empty());
    }

    #[test]
    fn a_task_row_has_no_name_and_no_lane() {
        let mut built = KernelConfig::new(subnet()).unwrap();
        let laned = RowFacts {
            laned: true,
            ..row("box", None)
        };
        built.register_row(at(2), &laned).unwrap();
        let task = RowFacts {
            task_row: true,
            ..laned
        };
        built.register_row(at(3), &task).unwrap();
        let decls = &built.config().decls;
        assert!(decls[0].rules.get().laned);
        assert_ne!(decls[0].name_id, NO_NAME);
        assert!(decls[1].task_row);
        assert!(!decls[1].rules.get().laned);
        assert_eq!(decls[1].name_id, NO_NAME);
        assert_eq!(built.row_names[&u32::from(at(3))].own, None);
    }

    #[test]
    fn a_refused_row_changes_nothing_and_holds_no_name() {
        let listing = EgressPolicy {
            allow_dns_hosts: Some(strings(&["db.min.internal"])),
            ..EgressPolicy::default()
        };
        let mut built = KernelConfig::new(subnet()).unwrap();
        built.register_row(at(2), &row("web", None)).unwrap();
        // The address is held, and the gateway is no row's.
        for addr in [at(2), at(1)] {
            assert_eq!(
                built.register_row(addr, &row("api", Some(&listing))),
                Err(KernelConfigError::RowRefused { addr })
            );
        }
        assert_eq!(built.config().decls.len(), 1);
        assert_eq!(built.row_names.len(), 1);
        // Neither refused row kept a hold: a name taken now and given back
        // is forgotten, and comes back under a new number.
        for name in ["api.min.internal", "db.min.internal"] {
            let first = built.names.hold(name).unwrap();
            built.names.release(name);
            assert_ne!(built.names.hold(name), Some(first));
        }
    }

    #[test]
    fn a_row_gives_back_every_name_it_holds() {
        let listing = EgressPolicy {
            allow_dns_hosts: Some(strings(&["db.min.internal", "web.min.internal"])),
            ..EgressPolicy::default()
        };
        let mut built = KernelConfig::new(subnet()).unwrap();
        built
            .register_row(at(2), &row("web", Some(&listing)))
            .unwrap();
        let names = built.row_names[&u32::from(at(2))].clone();
        assert_eq!(names.own.as_deref(), Some("web.min.internal"));
        assert_eq!(
            names.listed,
            strings(&["db.min.internal", "web.min.internal"])
        );
        built.release_names(&names);
        // The own name was held twice (as its own and as listed): both
        // holds are given back.
        for name in ["web.min.internal", "db.min.internal"] {
            let first = built.names.hold(name).unwrap();
            built.names.release(name);
            assert_ne!(built.names.hold(name), Some(first));
        }
    }

    #[test]
    fn the_members_keep_their_rules_by_session_in_session_order() {
        let names = EgressPolicy {
            allow_dns_hosts: Some(strings(&["github.com"])),
            ..EgressPolicy::deny_all()
        };
        let early = SessionId::from_bytes([1; 16]);
        let late = SessionId::from_bytes([2; 16]);
        let built = KernelConfig::from_parts(
            subnet(),
            Vec::new(),
            vec![
                (
                    late,
                    MemberFacts {
                        policy: None,
                        laned: true,
                    },
                ),
                (
                    early,
                    MemberFacts {
                        policy: Some(&names),
                        laned: false,
                    },
                ),
            ],
        )
        .unwrap();
        let members = &built.config().members;
        assert_eq!(members.len(), 2);
        assert!(members[0].resolves_names);
        assert!(!members[0].rules.get().laned);
        assert_eq!(members[0].rules.get().allow_subnets, Some(Vec::new()));
        assert!(!members[1].resolves_names);
        assert!(members[1].rules.get().laned);
        assert_eq!(members[1].rules.get().allow_subnets, None);
        assert_eq!(
            built.members.keys().copied().collect::<Vec<_>>(),
            vec![early, late]
        );
        assert_eq!(built.members_list().len(), 2);
    }

    #[test]
    fn from_parts_registers_every_row_in_the_order_given() {
        let built = KernelConfig::from_parts(
            subnet(),
            vec![(at(9), row("b", None)), (at(4), row("a", None))],
            Vec::new(),
        )
        .unwrap();
        let sources = &built.config().sources;
        assert_eq!(sources.index_of(u32::from(at(9))), Some(0));
        assert_eq!(sources.index_of(u32::from(at(4))), Some(1));
        assert!(built.config().members.is_empty());
        let twice = KernelConfig::from_parts(
            subnet(),
            vec![(at(4), row("a", None)), (at(4), row("b", None))],
            Vec::new(),
        );
        assert_eq!(
            twice.err(),
            Some(KernelConfigError::RowRefused { addr: at(4) })
        );
    }

    /// A rebuild keeps a row's reply records, and its DNS table only while
    /// the row's DNS names are numbered as before: the same list keeps both;
    /// a list in another order leaves the DNS table empty and the reply
    /// records in place.
    #[test]
    fn a_rebuild_keeps_a_rows_dns_table_only_while_its_names_are_numbered_as_before() {
        let row = at(9);
        let declaring = |hosts: &[&str]| EgressPolicy {
            allow_subnets: Some(Vec::new()),
            allow_dns_hosts: Some(strings(hosts)),
            allow_protocols: None,
            deny_subnets: None,
        };
        let first = declaring(&["example.org", "example.net"]);
        let mut config = KernelConfig::new(subnet()).unwrap();
        config.note_policy(row, Some(&first));
        config
            .register_row(
                row,
                &RowFacts {
                    name: "probe",
                    policy: Some(&first),
                    laned: false,
                    task_row: false,
                    generation: 0,
                },
            )
            .unwrap();
        let then = netcore::time::Instant { ms: 1 };
        let later = netcore::time::Instant { ms: 2 };
        {
            let held = &config.row_tables[&u32::from(row)];
            let mut tables = held.tables.lock().unwrap();
            let _asked = tables.pins.ask(0, 0x522a, 40000, then);
            let _opened = tables.flows.inbound(
                netcore::flow::Conversation {
                    proto: 17,
                    client: u32::from(Ipv4Addr::new(203, 0, 113, 7)),
                    client_port: 5353,
                    box_addr: u32::from(row),
                    box_port: 8080,
                },
                0,
                then,
            );
        }
        let read = |config: &KernelConfig| {
            let held = &config.row_tables[&u32::from(row)];
            let tables = held.tables.lock().unwrap();
            (
                tables.pins.asked_live(0, 0x522a, 40000, later),
                tables.flows.len(),
            )
        };
        let shape = || {
            [(
                row,
                RowShape {
                    name: "probe",
                    laned: false,
                    task_row: false,
                    generation: 0,
                },
            )]
        };
        assert_eq!(read(&config), (true, 1));
        config.rebuild(shape(), Diverged::missing("test", row));
        assert_eq!(read(&config), (true, 1), "the same numbering keeps both");
        config.note_policy(row, Some(&declaring(&["example.net", "example.org"])));
        config.rebuild(shape(), Diverged::missing("test", row));
        assert_eq!(
            read(&config),
            (false, 1),
            "another numbering empties the DNS table and keeps the records"
        );
    }

    /// Poisons `lock`: a panic while it is held, caught here.
    fn poison<T>(lock: &Mutex<T>) {
        let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _held = lock.lock().unwrap_or_else(PoisonError::into_inner);
            panic!("a panic while a kernel table's lock is held");
        }));
        assert!(caught.is_err(), "the closure panicked");
        assert!(lock.is_poisoned(), "the lock is poisoned");
    }

    /// A row at `addr` declaring `example.org` and `example.net`, made for
    /// registration `generation`, with a question asked in its DNS table and
    /// an inbound flow in its reply table at instant 1.
    fn row_with_records(config: &mut KernelConfig, addr: Ipv4Addr, generation: u64) {
        let policy = EgressPolicy {
            allow_subnets: Some(Vec::new()),
            allow_dns_hosts: Some(strings(&["example.org", "example.net"])),
            allow_protocols: None,
            deny_subnets: None,
        };
        config.note_policy(addr, Some(&policy));
        config
            .register_row(
                addr,
                &RowFacts {
                    name: "probe",
                    policy: Some(&policy),
                    laned: false,
                    task_row: false,
                    generation,
                },
            )
            .unwrap();
        let held = &config.row_tables[&u32::from(addr)];
        let mut tables = held.tables.lock().unwrap();
        let then = netcore::time::Instant { ms: 1 };
        let _asked = tables.pins.ask(0, 0x522a, 40000, then);
        let _opened = tables.flows.inbound(
            netcore::flow::Conversation {
                proto: 17,
                client: u32::from(Ipv4Addr::new(203, 0, 113, 7)),
                client_port: 5353,
                box_addr: u32::from(addr),
                box_port: 8080,
            },
            0,
            then,
        );
    }

    /// The question and the inbound flow [`row_with_records`] put at `addr`,
    /// read at instant 2: whether the question is live, and how many flows.
    fn records_at(config: &KernelConfig, addr: Ipv4Addr) -> (bool, usize) {
        let held = &config.row_tables[&u32::from(addr)];
        assert!(
            !held.tables.is_poisoned(),
            "a rebuilt row's lock is not poisoned"
        );
        let tables = held.tables.lock().unwrap();
        let later = netcore::time::Instant { ms: 2 };
        (
            tables.pins.asked_live(0, 0x522a, 40000, later),
            tables.flows.len(),
        )
    }

    /// The shape of the row at `addr` the registry holds, made for
    /// registration `generation`.
    fn probe_shape(addr: Ipv4Addr, generation: u64) -> (Ipv4Addr, RowShape<'static>) {
        (
            addr,
            RowShape {
                name: "probe",
                laned: false,
                task_row: false,
                generation,
            },
        )
    }

    /// A rebuild keeps a row's records only for the registration they were
    /// made for. Here the registry holds a newer registration at one address
    /// than the one the configuration made its tables for, as when the
    /// registration's restate was refused; no registry path refuses a
    /// restate in a test, so the rebuild is driven directly. That row's
    /// tables start empty, with the newer generation; the row registered
    /// once keeps its question and its flow.
    #[test]
    fn a_rebuild_keeps_a_rows_records_only_for_the_registration_they_were_made_for() {
        let (kept, again) = (at(9), at(10));
        let mut config = KernelConfig::new(subnet()).unwrap();
        row_with_records(&mut config, kept, 0);
        row_with_records(&mut config, again, 0);
        assert_eq!(records_at(&config, kept), (true, 1));
        assert_eq!(records_at(&config, again), (true, 1));
        config.rebuild(
            [probe_shape(kept, 0), probe_shape(again, 1)],
            Diverged::missing("test", again),
        );
        assert_eq!(
            records_at(&config, kept),
            (true, 1),
            "the same registration keeps both"
        );
        assert_eq!(
            records_at(&config, again),
            (false, 0),
            "a newer registration starts with empty tables"
        );
        assert_eq!(config.generation_at(again.octets()), Some(1));
    }

    /// A rebuild never carries tables whose lock was poisoned: the row's,
    /// the node's and the host_ip boxes' are made empty, with locks that are
    /// not poisoned, while a row whose lock holds keeps its records.
    #[test]
    fn a_rebuild_never_carries_tables_whose_lock_was_poisoned() {
        let (kept, poisoned) = (at(9), at(10));
        let mut config = KernelConfig::new(subnet()).unwrap();
        row_with_records(&mut config, kept, 0);
        row_with_records(&mut config, poisoned, 0);
        poison(&config.row_tables[&u32::from(poisoned)].tables);
        poison(&config.node_tables.tables);
        poison(&config.cohort_pins.tables);
        config.rebuild(
            [probe_shape(kept, 0), probe_shape(poisoned, 0)],
            Diverged::missing("test", poisoned),
        );
        assert_eq!(records_at(&config, kept), (true, 1));
        assert_eq!(records_at(&config, poisoned), (false, 0));
        assert!(!config.node_tables.tables.is_poisoned());
        assert!(!config.cohort_pins.tables.is_poisoned());
    }

    /// After a rebuild, the node's baseline adopted again unchanged keeps
    /// the node's DNS table, since the rebuild carries the baseline's
    /// endpoints with its names. Node tables whose lock was poisoned are
    /// never adopted: the same baseline then gives the node empty tables.
    #[test]
    fn an_unchanged_baseline_adopted_after_a_rebuild_keeps_the_nodes_dns_table() {
        let mut config = KernelConfig::new(subnet()).unwrap();
        let names = || strings(&["example.com"]);
        config.adopt_baseline(true, ["example.com", "192.0.2.0/24"], names(), &[]);
        let then = netcore::time::Instant { ms: 1 };
        let later = netcore::time::Instant { ms: 2 };
        let _asked = config
            .node_tables
            .tables
            .lock()
            .unwrap()
            .pins
            .ask(0, 0x522a, 40000, then);
        let live = |config: &KernelConfig| {
            config
                .node_tables
                .tables
                .lock()
                .unwrap()
                .pins
                .asked_live(0, 0x522a, 40000, later)
        };
        config.rebuild(
            std::iter::empty::<(Ipv4Addr, RowShape<'static>)>(),
            Diverged::missing("test", at(9)),
        );
        config.adopt_baseline(true, ["example.com", "192.0.2.0/24"], names(), &[]);
        assert!(
            live(&config),
            "the unchanged baseline keeps the node's DNS table"
        );

        poison(&config.node_tables.tables);
        config.adopt_baseline(true, ["example.com", "192.0.2.0/24"], names(), &[]);
        assert!(!config.node_tables.tables.is_poisoned());
        assert!(!live(&config), "the node's tables are empty");
    }

    #[test]
    fn the_alias_state_holds_every_port_of_the_products_listeners() {
        let alias = alias_state(&[8080], &[(443, 445)], &[HostExposure::tcp(5432)]);
        assert_eq!(alias.node_ports, vec![PortRange { lo: 443, hi: 445 }]);
        let held = |proto, port| Holder { proto, port };
        assert_eq!(
            alias.held,
            vec![
                held(None, 8080),
                held(None, DEFAULT_ANSWERER_PORT),
                held(None, switch::bep_host::PROXY_PORT),
                held(Some(IPPROTO_TCP), 443),
                held(Some(IPPROTO_TCP), 444),
                held(Some(IPPROTO_TCP), 445),
            ]
        );
        assert_eq!(
            alias.exposures,
            vec![Exposure {
                proto: IPPROTO_TCP,
                port: 5432,
            }]
        );
        let closed = alias_state(&[], &[], &[]);
        assert!(closed.node_ports.is_empty());
        assert_eq!(closed.held.len(), 2);
        assert!(closed.exposures.is_empty());
    }

    /// A configuration just made, with nothing registered and no baseline
    /// adopted, holds Minimal's own listeners' ports at the alias (the
    /// answerer's and the Box Egress Proxy's), as the gate's listeners always
    /// have: an exposure pushed at one of them is not open for the kernel's
    /// arm, while one at another port is.
    #[test]
    fn a_new_configuration_holds_minimals_own_listener_ports_at_the_alias() {
        let fresh = KernelConfig::new(subnet()).expect("the subnet makes a plan");
        let held = |port| Holder { proto: None, port };
        let proxy = switch::bep_host::PROXY_PORT;
        assert_eq!(
            fresh.config().alias.held,
            vec![held(DEFAULT_ANSWERER_PORT), held(proxy)]
        );
        assert!(fresh.config().alias.exposures.is_empty());

        let row = at(9);
        let registry = BoxRegistry::new(subnet());
        registry.register(BoxRegistration::new("probe", row, Ipv4Addr::LOCALHOST));
        registry.table().push_exposures(&Arc::from(vec![
            HostExposure::tcp(proxy),
            HostExposure::tcp(8080),
        ]));
        let alias_arm = |port: u16| {
            let probe = probe(
                "a SYN to the alias",
                subnet().host_alias().octets(),
                TCP,
                port,
            );
            match registry
                .kernel_for_tests()
                .config()
                .egress_first(&frame_of(row, &probe), APEX)
            {
                First::Frame { arm, .. } => arm,
                other => panic!("a whole frame: {other:?}"),
            }
        };
        let closed = netcore::split::Arm::Row(0, netcore::row::RowArm::AliasClosed);
        assert_eq!(alias_arm(proxy), closed, "the proxy's port is held");
        assert_ne!(alias_arm(8080), closed, "another exposed port is open");
    }

    #[test]
    fn the_zone_apex_on_the_wire_is_the_box_zones() {
        let mut wire = Vec::new();
        for label in boxes::core::zone_answer::ZONE_APEX.split('.') {
            wire.push(u8::try_from(label.len()).unwrap());
            wire.extend_from_slice(label.as_bytes());
        }
        wire.push(0);
        assert_eq!(ZONE_APEX_WIRE, wire.as_slice());
    }

    #[test]
    fn a_protocol_is_read_by_its_wire_number() {
        assert_eq!(wire_number(IpProto::Tcp), Some(6));
        assert_eq!(wire_number(IpProto::Udp), Some(17));
        assert_eq!(wire_number(IpProto::Icmp), Some(1));
    }

    /// The zone's name on the wire, as the kernel reads a query against it.
    const APEX: &[u8] = b"\x03min\x08internal\x00";

    const TCP: u8 = 6;
    const UDP: u8 = 17;

    /// What a side says of a frame: `None` admits, `Some` drops under the
    /// rule named.
    type Said = Option<&'static str>;

    const ADMIT: Said = None;
    const CONTROL: Said = Some("egress-switch-control-surface");
    const INFRA: Said = Some("egress-infrastructure-destination");
    const ALIAS: Said = Some("host-alias");
    const LANE: Said = Some("egress-uncredentialed-proxy-destination");
    const PROTO: Said = Some("egress-undeclared-protocol");
    const DENIED: Said = Some("egress-denied-subnet");
    const UNDECLARED: Said = Some("egress-undeclared-subnet");
    const DENY_ALL_DNS: Said = Some("egress-deny-all-dns-query");
    const TRUNCATED: Said = Some("egress-truncated-ipv4");

    /// A destination outside every list and every block, under the policies
    /// none, default, deny-all, mixed and allow-all.
    const PUBLIC: [Said; 5] = [ADMIT, ADMIT, PROTO, UNDECLARED, ADMIT];
    /// A private address no list covers.
    const UNCOVERED_PRIVATE: [Said; 5] = [ADMIT, ADMIT, INFRA, INFRA, ADMIT];
    /// A query to the resolver that only a row naming nothing is refused.
    const NARROWED: [Said; 5] = [ADMIT, ADMIT, DENY_ALL_DNS, ADMIT, ADMIT];

    /// The DNS header of a standard query with one question.
    const QUERY_HEADER: &[u8] = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00";
    /// `web.min.internal`, a name below the zone's apex.
    const ZONE_NAME: &[u8] = b"\x03web\x03min\x08internal\x00";
    /// `example.org`, a name outside the zone.
    const OUTSIDE_NAME: &[u8] = b"\x07example\x03org\x00";
    /// Type A, class IN.
    const A_IN: [u8; 4] = [0, 1, 0, 1];
    /// Type AAAA, class IN.
    const AAAA_IN: [u8; 4] = [0, 28, 0, 1];
    /// Type HTTPS, class IN.
    const HTTPS_IN: [u8; 4] = [0, 65, 0, 1];

    /// A standard query for `name` with `kind` and class.
    fn query(name: &[u8], kind: [u8; 4]) -> Vec<u8> {
        [QUERY_HEADER, name, kind.as_slice()].concat()
    }

    /// A standard query whose header counts `questions` questions and
    /// `additional` additional records, with no answer or authority record,
    /// followed by `body` as written.
    fn counted(questions: u16, additional: u16, body: &[u8]) -> Vec<u8> {
        let mut payload = vec![0x12, 0x34, 0x01, 0x00];
        payload.extend_from_slice(&questions.to_be_bytes());
        payload.extend_from_slice(&[0, 0, 0, 0]);
        payload.extend_from_slice(&additional.to_be_bytes());
        payload.extend_from_slice(body);
        payload
    }

    /// One frame a box sends: where it goes, over what, with what, and
    /// whether its IPv4 total length is written as 0.
    struct Probe {
        what: &'static str,
        dst: [u8; 4],
        proto: u8,
        port: u16,
        payload: Vec<u8>,
        total_length_zero: bool,
    }

    fn probe(what: &'static str, dst: [u8; 4], proto: u8, port: u16) -> Probe {
        Probe {
            what,
            dst,
            proto,
            port,
            payload: Vec::new(),
            total_length_zero: false,
        }
    }

    /// A UDP datagram to the resolver at 53 carrying `payload`.
    fn to_resolver(what: &'static str, payload: Vec<u8>) -> Probe {
        Probe {
            payload,
            ..probe(what, [100, 64, 7, 1], UDP, 53)
        }
    }

    /// NC7's table, the kernel's expected behaviour for a row's frame: for
    /// each frame, what both the relay's decision and the kernel's say
    /// under the policies none, default (every list absent), deny-all,
    /// mixed (10/8 and 198.51.100/24 allowed, 10.1/16 denied inside it, TCP
    /// and UDP only) and the written-out allow-all with its IPv6 half, in
    /// that order. The row is at 100.64.7.9 on 100.64.7.0/24: gateway .1,
    /// proxy .252, node .253, alias .254; the host exposes TCP 8080 at the
    /// alias. Filled by reading the gate, the relay and the kernel, not by
    /// running them.
    fn nc7_table() -> Vec<(Probe, [Said; 5])> {
        let gateway = [100, 64, 7, 1];
        let proxy = [100, 64, 7, 252];
        vec![
            (
                to_resolver("an A query inside the zone", query(ZONE_NAME, A_IN)),
                [ADMIT; 5],
            ),
            (
                to_resolver("an A query outside the zone", query(OUTSIDE_NAME, A_IN)),
                NARROWED,
            ),
            (
                to_resolver("an A query for the apex", query(APEX, A_IN)),
                NARROWED,
            ),
            (
                to_resolver("three bytes to the resolver", vec![0x12, 0x34, 0x01]),
                NARROWED,
            ),
            (
                probe("the gateway, TCP 53", gateway, TCP, 53),
                [ADMIT, ADMIT, PROTO, UNDECLARED, ADMIT],
            ),
            (
                probe("the gateway, TCP 443", gateway, TCP, 443),
                [CONTROL; 5],
            ),
            (
                probe("the proxy's listener, TCP 8118", proxy, TCP, 8118),
                [LANE; 5],
            ),
            (probe("the proxy, TCP 3128", proxy, TCP, 3128), [LANE; 5]),
            (
                probe(
                    "the alias, TCP 5432, no exposure",
                    [100, 64, 7, 254],
                    TCP,
                    5432,
                ),
                [ALIAS; 5],
            ),
            // Open only to a row that names the host. An allow list that is
            // absent or covers every address names it; the deny-all and the
            // mixed rows do not (the alias is in none of their lists and
            // they declare no DNS host), so the alias stays closed to them
            // at the exposure too: their drops are not an exposure failing.
            (
                probe(
                    "the alias, TCP 8080, an exposure",
                    [100, 64, 7, 254],
                    TCP,
                    8080,
                ),
                [ADMIT, ADMIT, ALIAS, ALIAS, ADMIT],
            ),
            (
                probe("link-local", [169, 254, 169, 254], TCP, 80),
                [INFRA; 5],
            ),
            (
                probe("below link-local", [169, 253, 255, 255], TCP, 443),
                PUBLIC,
            ),
            (
                probe("above link-local", [169, 255, 0, 0], TCP, 443),
                PUBLIC,
            ),
            (probe("loopback", [127, 0, 0, 1], TCP, 443), [INFRA; 5]),
            (
                probe("below loopback", [126, 255, 255, 255], TCP, 443),
                PUBLIC,
            ),
            (probe("above loopback", [128, 0, 0, 0], TCP, 443), PUBLIC),
            (
                probe(
                    "the plane, inside the row's block",
                    [100, 64, 7, 50],
                    TCP,
                    443,
                ),
                PUBLIC,
            ),
            (
                probe(
                    "the plane, outside the row's block",
                    [100, 64, 8, 1],
                    TCP,
                    443,
                ),
                [INFRA; 5],
            ),
            (
                probe("below the plane", [100, 63, 255, 255], TCP, 443),
                PUBLIC,
            ),
            (probe("above the plane", [100, 128, 0, 0], TCP, 443), PUBLIC),
            (
                probe("10/8, allowed", [10, 2, 3, 4], TCP, 443),
                [ADMIT, ADMIT, INFRA, ADMIT, ADMIT],
            ),
            (
                probe("10/8, denied inside the allow", [10, 1, 2, 3], TCP, 443),
                [ADMIT, ADMIT, INFRA, DENIED, ADMIT],
            ),
            (probe("below 10/8", [9, 255, 255, 255], TCP, 443), PUBLIC),
            (probe("above 10/8", [11, 0, 0, 0], TCP, 443), PUBLIC),
            (
                probe("172.16/12", [172, 16, 0, 1], TCP, 443),
                UNCOVERED_PRIVATE,
            ),
            (
                probe("below 172.16/12", [172, 15, 255, 255], TCP, 443),
                PUBLIC,
            ),
            (probe("above 172.16/12", [172, 32, 0, 0], TCP, 443), PUBLIC),
            (
                probe("192.168/16", [192, 168, 1, 1], TCP, 443),
                UNCOVERED_PRIVATE,
            ),
            (
                probe("below 192.168/16", [192, 167, 255, 255], TCP, 443),
                PUBLIC,
            ),
            (
                probe("above 192.168/16", [192, 169, 0, 0], TCP, 443),
                PUBLIC,
            ),
            (
                probe("public, in the mixed allow", [198, 51, 100, 7], TCP, 443),
                [ADMIT, ADMIT, PROTO, ADMIT, ADMIT],
            ),
            (
                probe("public, in no list", [203, 0, 113, 7], TCP, 443),
                PUBLIC,
            ),
            (probe("multicast", [224, 0, 0, 251], UDP, 5353), PUBLIC),
            (
                probe("the limited broadcast", [255, 255, 255, 255], UDP, 67),
                PUBLIC,
            ),
            (probe("this host", [0, 0, 0, 1], TCP, 443), PUBLIC),
        ]
    }

    /// The deny-all section, with its DNS-host list absent rather than
    /// empty: what `effective_egress` leaves outside the default phase for
    /// a section that names no subnet.
    fn subnets_empty_names_absent() -> EgressPolicy {
        EgressPolicy {
            allow_dns_hosts: None,
            ..EgressPolicy::deny_all()
        }
    }

    /// The frames on which the relay, as it decided before the kernel did,
    /// and the kernel decide differently. Each entry: what kind of
    /// difference it is, the row's policy, the frame, what that relay said
    /// and what the kernel says. The relay's column is literal: what the
    /// relay decided before the kernel did (the gate called whole, then its
    /// deny-all DNS check). The test checks that the kernel and the gate
    /// both say the kernel's side and that it is not the relay's.
    fn nc7_differences() -> Vec<(&'static str, Option<EgressPolicy>, Probe, Said, Said)> {
        vec![
            (
                "a zone question from a row that names nothing",
                Some(EgressPolicy::deny_all()),
                to_resolver("an AAAA query inside the zone", query(ZONE_NAME, AAAA_IN)),
                DENY_ALL_DNS,
                ADMIT,
            ),
            (
                "a zone question from a row that names nothing",
                Some(EgressPolicy::deny_all()),
                to_resolver("an HTTPS query inside the zone", query(ZONE_NAME, HTTPS_IN)),
                DENY_ALL_DNS,
                ADMIT,
            ),
            // The test asserts that the kernel and the gate drop this frame
            // as no frame, where the relay admitted it. The relay's summary does not read
            // the total length, so the gate admits the query by the
            // resolver's carve-out, and the deny-all check is skipped because
            // the datagram's payload cannot be taken; the kernel's reader
            // says the bytes are no frame. Were the gate itself to refuse a
            // total length of 0, this would be a drop on both sides under
            // different rule names, and the entry would say that instead.
            // The difference is real in the code and is not reached in
            // ordinary traffic (netcore's NX6).
            (
                "an IPv4 total length of 0",
                Some(EgressPolicy::deny_all()),
                Probe {
                    total_length_zero: true,
                    ..to_resolver(
                        "an A query inside the zone, total length 0",
                        query(ZONE_NAME, A_IN),
                    )
                },
                ADMIT,
                TRUNCATED,
            ),
            (
                "a row with no subnet and no DNS-host list",
                Some(subnets_empty_names_absent()),
                to_resolver("an A query outside the zone", query(OUTSIDE_NAME, A_IN)),
                ADMIT,
                DENY_ALL_DNS,
            ),
            // The kernel reads a question's class and admits only IN; the
            // relay reads only the type and the name.
            (
                "a question in a form the kernel reads strictly",
                Some(EgressPolicy::deny_all()),
                to_resolver(
                    "an A query inside the zone, class CH",
                    query(ZONE_NAME, [0, 1, 0, 3]),
                ),
                ADMIT,
                DENY_ALL_DNS,
            ),
            // Two questions: the first is the zone name written plainly at
            // offset 12, then type A, class IN; the second's name is the
            // pointer 0xC0 0x0C back to offset 12, then type A, class IN.
            // The relay follows the pointer; the kernel refuses any pointer.
            (
                "a question in a form the kernel reads strictly",
                Some(EgressPolicy::deny_all()),
                to_resolver(
                    "a second question named by a pointer to the first",
                    counted(
                        2,
                        0,
                        &[
                            ZONE_NAME,
                            A_IN.as_slice(),
                            b"\xc0\x0c".as_slice(),
                            A_IN.as_slice(),
                        ]
                        .concat(),
                    ),
                ),
                ADMIT,
                DENY_ALL_DNS,
            ),
            // The header counts one additional record and none follows the
            // question: the relay cannot parse the message, and the kernel
            // reads nothing after the questions.
            (
                "a question in a form the kernel reads strictly",
                Some(EgressPolicy::deny_all()),
                to_resolver(
                    "an A query inside the zone, an additional record counted and absent",
                    counted(1, 1, &[ZONE_NAME, A_IN.as_slice()].concat()),
                ),
                DENY_ALL_DNS,
                ADMIT,
            ),
            // The question, then an OPT record cut short after its root name
            // (0x00) and its type (0x00 0x29).
            (
                "a question in a form the kernel reads strictly",
                Some(EgressPolicy::deny_all()),
                to_resolver(
                    "an A query inside the zone, an OPT record cut short",
                    counted(
                        1,
                        1,
                        &[ZONE_NAME, A_IN.as_slice(), b"\x00\x00\x29".as_slice()].concat(),
                    ),
                ),
                DENY_ALL_DNS,
                ADMIT,
            ),
        ]
    }

    /// An OPT record as written: the root name, type 41, a UDP size of 1232
    /// as the class, a TTL of 0, eight bytes of data holding one option of
    /// code 65001 (a local code), length 4, and four arbitrary bytes.
    const OPT_RECORD: &[u8] = &[
        0x00, 0x00, 0x29, 0x04, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0xfd, 0xe9, 0x00, 0x04,
        0xde, 0xad, 0xbe, 0xef,
    ];

    /// Frames of a strictly read question on which the relay, as it decided before
    /// the kernel did, and the kernel agree, written for the deny-all row
    /// only. Each entry: what kind of question it is, the row's policy, the
    /// frame, and what both said; the test checks that the kernel and the
    /// gate both say it.
    fn nc7_row12_agreeing() -> Vec<(&'static str, Option<EgressPolicy>, Probe, Said)> {
        vec![
            // A label of 64 bytes: its length byte 0x40, then 64 bytes of
            // `a`, then the apex, type A, class IN. Neither side reads a
            // length byte above 63 as a label.
            (
                "a question in a form the kernel reads strictly",
                Some(EgressPolicy::deny_all()),
                to_resolver(
                    "an A query whose first label's length byte is 0x40",
                    counted(
                        1,
                        0,
                        &[
                            b"\x40".as_slice(),
                            [b'a'; 64].as_slice(),
                            APEX,
                            A_IN.as_slice(),
                        ]
                        .concat(),
                    ),
                ),
                DENY_ALL_DNS,
            ),
            // The header counts two questions and one follows.
            (
                "a question in a form the kernel reads strictly",
                Some(EgressPolicy::deny_all()),
                to_resolver(
                    "an A query inside the zone, two questions counted and one present",
                    counted(2, 0, &[ZONE_NAME, A_IN.as_slice()].concat()),
                ),
                DENY_ALL_DNS,
            ),
            // A well-formed record after the question: the relay and the
            // kernel both admit the query.
            (
                "a question in a form the kernel reads strictly",
                Some(EgressPolicy::deny_all()),
                to_resolver(
                    "an A query inside the zone, a well-formed OPT record",
                    counted(1, 1, &[ZONE_NAME, A_IN.as_slice(), OPT_RECORD].concat()),
                ),
                ADMIT,
            ),
        ]
    }

    /// The five policies of NC7's table, in its order.
    fn nc7_policies() -> [(&'static str, Option<EgressPolicy>); 5] {
        [
            ("none", None),
            ("default", Some(EgressPolicy::default())),
            ("deny-all", Some(EgressPolicy::deny_all())),
            (
                "mixed",
                Some(EgressPolicy {
                    allow_subnets: Some(strings(&["10.0.0.0/8", "198.51.100.0/24"])),
                    allow_dns_hosts: None,
                    allow_protocols: Some(vec![IpProto::Tcp, IpProto::Udp]),
                    deny_subnets: Some(strings(&["10.1.0.0/16"])),
                }),
            ),
            (
                "allow-all",
                Some(EgressPolicy {
                    allow_subnets: Some(strings(&["0.0.0.0/0", "::/0"])),
                    ..EgressPolicy::default()
                }),
            ),
        ]
    }

    /// The Ethernet frame a box at `src` sends: an IPv4 header with its
    /// total length (or 0 when the probe asks for it), and a whole TCP
    /// header (a SYN) or UDP header with its length, then the payload.
    fn frame_of(src: Ipv4Addr, probe: &Probe) -> Vec<u8> {
        let l4 = if probe.proto == TCP { 20 } else { 8 };
        let total = if probe.total_length_zero {
            0
        } else {
            u16::try_from(20 + l4 + probe.payload.len()).unwrap()
        };
        let mut frame = vec![0x52, 0x54, 0, 0, 0, 1, 0x52, 0x54, 0, 0, 0, 2, 0x08, 0x00];
        frame.extend_from_slice(&[0x45, 0]);
        frame.extend_from_slice(&total.to_be_bytes());
        frame.extend_from_slice(&[0, 0, 0, 0, 64, probe.proto, 0, 0]);
        frame.extend_from_slice(&src.octets());
        frame.extend_from_slice(&probe.dst);
        frame.extend_from_slice(&40000u16.to_be_bytes());
        frame.extend_from_slice(&probe.port.to_be_bytes());
        if probe.proto == TCP {
            frame.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 0, 0x50, 0x02, 0xff, 0xff, 0, 0, 0, 0]);
        } else {
            let length = u16::try_from(8 + probe.payload.len()).unwrap();
            frame.extend_from_slice(&length.to_be_bytes());
            frame.extend_from_slice(&[0, 0]);
        }
        frame.extend_from_slice(&probe.payload);
        frame
    }

    /// The rule the kernel reports for what it says of a frame's bytes, by
    /// its own report table: the one correspondence between the kernel's
    /// outcomes and the gate's rule names. `None` is an admit.
    fn kernel_rule(first: First) -> Said {
        let rule = match first {
            First::NotAFrame(why) => netcore::report::not_a_frame(why),
            First::ShortHeader => netcore::report::SHORT_HEADER_OUT,
            First::Frame { arm, .. } => match netcore::report::arm(arm, false) {
                Reported::Rule(rule) => rule,
                Reported::Internal => return Some("internal"),
            },
        };
        (rule != netcore::report::NONE).then_some(netcore::report::NAMES[usize::from(rule)])
    }

    /// What the gate and the kernel each say of `probe` from a row
    /// registered with `policy`, the kernel deciding by the configuration
    /// the registry keeps, and the kernel's outcome as it named it (its arm,
    /// or why the bytes are no frame).
    fn both_say(policy: Option<EgressPolicy>, probe: &Probe) -> (Said, Said, String) {
        let row = at(9);
        let registry = BoxRegistry::new(subnet());
        let mut registration = BoxRegistration::new("probe", row, Ipv4Addr::LOCALHOST);
        if let Some(policy) = policy {
            registration = registration.with_egress_policy(policy);
        }
        registry.register(registration);
        // The exposure both sides decide under, given to the kernel where
        // the frame path would give it.
        registry
            .table()
            .push_exposures(&Arc::from(vec![NC7_EXPOSURE]));
        registry.assert_kernel_in_step();
        let frame = frame_of(row, probe);
        let gate = gate_decides(&registry, &frame).err();
        let first = registry
            .kernel_for_tests()
            .config()
            .egress_first(&frame, APEX);
        let outcome = match first {
            First::Frame { arm, .. } => format!("{arm:?}"),
            other => format!("{other:?}"),
        };
        (gate, kernel_rule(first), outcome)
    }

    /// A side's answer in the gate's drop-line shape.
    fn action(said: Said) -> String {
        match said {
            None => "action=admit".to_string(),
            Some(rule) => format!("action=drop rule_matched=\"{rule}\""),
        }
    }

    /// NC7's test: for every policy of the table and every frame, the
    /// kernel, deciding by the configuration the registry keeps for a row
    /// registered with the policy, says what the table says, admit or drop
    /// and the rule a drop is reported under, and so does the gate called
    /// whole, with no reply, refusal or pin; and for each frame of
    /// `nc7_differences` the kernel and the gate say the kernel's side,
    /// which is not the relay's, with one line printed for each saying what
    /// both returned.
    #[test]
    fn nc7_a_rows_frame_is_decided_by_the_kernel_as_by_the_relay() {
        for (probe, wants) in nc7_table() {
            for ((policy_name, policy), want) in nc7_policies().into_iter().zip(wants) {
                let case = format!("{policy_name}, {}", probe.what);
                let (gate, kernel, _) = both_say(policy, &probe);
                assert_eq!(kernel, want, "{case}: the kernel");
                assert_eq!(gate, want, "{case}: the gate");
            }
        }
        for (row, policy, probe, relay_was, kernel_want) in nc7_differences() {
            let case = format!("{row}, {}", probe.what);
            let (gate, kernel, outcome) = both_say(policy, &probe);
            // The record of each named difference, as the run computed it:
            // `cargo nextest run --no-capture` prints it.
            println!(
                "{case}: relay before the kernel {} | kernel {outcome} {} | gate {}",
                action(relay_was),
                action(kernel),
                action(gate)
            );
            assert_eq!(kernel, kernel_want, "{case}: the kernel");
            assert_eq!(gate, kernel_want, "{case}: the gate");
            assert_ne!(relay_was, kernel_want, "{case}: a named difference");
        }
        // The frames of a strictly read question that both sides decided alike,
        // printed as the differences are.
        for (row, policy, probe, both_said) in nc7_row12_agreeing() {
            let case = format!("{row}, {}", probe.what);
            let (gate, kernel, outcome) = both_say(policy, &probe);
            println!(
                "{case}: relay before the kernel {} | kernel {outcome} {} | gate {}",
                action(both_said),
                action(kernel),
                action(gate)
            );
            assert_eq!(kernel, both_said, "{case}: the kernel");
            assert_eq!(gate, both_said, "{case}: the gate");
        }
    }
}
