//! The classifier a host-address box's egress verdict is decided on
//! (NET-079): which cohort subtree a box's declaration places it in, and
//! whether this host can decide a verdict per box at all.
//!
//! A host-address box shares its host's network namespace, so no address of
//! its own can carry its verdict. The classifier decides it on the box's
//! *cgroup* instead: the box host places each host-address box in a leaf of
//! its own under the classifier tree, and the packet filter matches that
//! cgroup before any source translation — the verdict is decided inside the
//! box host (NET-079) while the cohort still leaves as one identity outside
//! it (NET-078).
//!
//! The two subtrees are the whole vocabulary. A box whose declaration
//! admits no destination is placed under `boxes/deny`, where the table the
//! privileged step installs refuses every connection it opens except the
//! one to the resolver Minimal owns for it, at that resolver's own address
//! and port; every other box is placed under `boxes/allow`, where only the
//! cohort's identity is carried on its traffic. A leaf directly under
//! `boxes/` sits outside both subtrees, so the refusing rule's match on the
//! subtree would silently miss it — [`verdict_of`] and the sandbox layer's
//! leaf arithmetic are what keep that shape out of the daemon.
//!
//! Flow termination is the declaration's and the kernel's, never this
//! module's. A box's declaration is fixed at create, so tightening its
//! egress is a recreate, not an edit of a running box's subtree; a session
//! stop kills the leaf's processes, and their sockets close with them —
//! the classifier owns no conntrack writer and flushes nothing, because
//! the sockets closing *is* the termination. The rule set is fixed with
//! the table: nothing is edited at box launch or stop.
//!
//! Whether the host can decide per box is read from the table's *effect*,
//! never from a fact that merely vouches for it (design §7.4): the probe
//! below places a short-lived child in a deny-subtree leaf and connects to
//! a loopback listener the daemon holds, control leg first, and only a
//! connection the filter refused reads as `per_box`. The step's presence
//! marker says only that the installer ran — a marker survives a reboot
//! whose table reload failed, a flush, a conflicting ruleset; the refusal
//! does not, so the marker is the advisory's fact and the probe's is the
//! verdict. The probe runs at daemon start and again before each
//! host-address launch, because a table can go away between them. A host
//! that decides nothing per box runs its host-address boxes unenforced
//! (NET-079's exception), with the cause named at session start and the
//! install command printed only when a command can end the cause — except
//! the one state where the box's own declaration is the thing this host
//! cannot honour: a deny-all box over either probe cause — the table not
//! refusing, or its effect unreadable — would run placed and looking
//! decided while nothing refuses it, so the launch refuses it on either
//! kind of host, and its other host-address boxes run unenforced and say
//! so per launch. The guest refuses on the same ground plus its own: its
//! daemon is the only one that could have made its image load the table,
//! so until it does, a deny-all host-address box is refused rather than
//! run on a refusal that is not there (design §7.1) — and no installer
//! exists for a person to run, so none is named; its other host-address
//! boxes run unenforced like any host's and say so per launch, in the
//! interim's words.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::time::Duration;

use common::fetchers::AnyUrl;
use sandbox2::config::Verdict;

/// The loopback address the box zone's answerer serves at — the one
/// destination a deny-all host-address box's connections are admitted to
/// (NET-079): the resolver Minimal owns for the box, which answers the box
/// zone and forwards nothing. A loopback-wide exception was considered and
/// rejected (design §4.1): the rest of the host's loopback is where the
/// host's own services and its forwarding resolver listen, and admitting a
/// deny-all box to them would admit it to everything upstream.
pub(crate) const ANSWERER_ADDRESS: Ipv4Addr = Ipv4Addr::LOCALHOST;

/// Which cohort subtree `declaration` places a box's leaf in (NET-079): the
/// deny subtree is for the declaration that admits no destination — the one
/// shape `sessions::EgressPolicy::deny_all` materializes, every `allow_*`
/// dimension present and empty — and nothing else. A box that declares
/// anything it can reach is placed under `allow`, where the cohort's
/// identity is carried and nothing is refused on its behalf: the
/// classifier's per-box enforcement is the deny-all verdict, and a
/// declaration that admits anything is not that. An absent section is the
/// default's to decide, never a deny-all here — the deny-all default is an
/// own-address box's (NET-074).
pub(crate) fn verdict_of(declaration: Option<&sessions::EgressPolicy>) -> Verdict {
    if declaration.is_some_and(admits_nothing) {
        return Verdict::Deny;
    }
    Verdict::Allow
}

/// Whether `section` is the declaration that admits no destination: every
/// `allow_*` dimension present and empty. `deny_subnets` is not read — it
/// subtracts from what the `allow_*` fields admit, and there is nothing
/// there to subtract from.
fn admits_nothing(section: &sessions::EgressPolicy) -> bool {
    section.allow_subnets.as_ref().is_some_and(Vec::is_empty)
        && section.allow_dns_hosts.as_ref().is_some_and(Vec::is_empty)
        && section.allow_protocols.as_ref().is_some_and(Vec::is_empty)
}

/// Why a host cannot decide a box's egress verdict per box (NET-079): the
/// causes the requirement names, each with its own remedy or none.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cause {
    /// The privileged step's half is missing: the cohort's subtrees, or the
    /// loaded table's presence marker, are not installed on this host.
    /// Installing the step ends it, so the install command is named.
    StepNotInstalled,
    /// The host cannot confine a box: no cgroup2 mount with `nsdelegate`
    /// covers the classifier tree, so a box's cgroup namespace is not a
    /// delegation boundary and no leaf under it confines a process. No
    /// command ends it — the mount is the host's to make, and the step
    /// refuses to install over a tree no cgroup2 covers — so none is
    /// named.
    CannotConfine,
    /// The guest's boot has not loaded the deny table: guest-side classifier
    /// enforcement is not available yet — no guest image loads the table
    /// today — and there is no privileged step a person can run inside a
    /// microVM to load one, so the person to tell is the image's builder,
    /// not whoever is holding the session. A deny-all host-address box is
    /// refused on this ground rather than placed in a leaf that decides
    /// nothing, so no command is named.
    GuestTableNotLoaded,
    /// The step's half is installed and its marker says the table loaded,
    /// but the table is not refusing: a probe placed in a deny leaf made a
    /// connection the deny chain would have refused — completed, refused
    /// with an errno the chain never reads as, or never reported inside the
    /// probe's deadline. A marker survives a reboot whose reload failed or
    /// a flush; a refusal does not, and the refusal is the fact a `per_box`
    /// record rests on (design §7.4), so the marker alone decides nothing
    /// here. A deny-all host-address box over this cause is refused on
    /// either kind of host: its declaration promises a refusal this host is
    /// not making, and it must not run looking decided while nothing
    /// refuses it. The step is installed, so the step is not what is
    /// missing, and no install command is named.
    TableNotEffective,
    /// The table's effect could not be read: the daemon's own control-leg
    /// connection to the probe's listener failed, or no probe child could be
    /// placed in a deny leaf — so whether the table is refusing is unknown,
    /// and an unknown effect is not a verdict (the probe reports the least
    /// it can prove, never the most it can guess). A deny-all host-address
    /// box over this cause is refused on either kind of host: an unproven
    /// refusal is not one, and the box's declaration must not run on it.
    /// No command is named because none is known to end it: the cause says
    /// what failed to be read, and a person reading it decides what to look
    /// at.
    ProbeUnreadable,
}

impl Cause {
    /// The fact a person reads, spelled once here so the daemon's log line
    /// and the advisory a client prints agree by construction.
    pub fn detail(self) -> &'static str {
        match self {
            Self::StepNotInstalled => {
                "the classifier's privileged step is not installed on this host"
            }
            Self::CannotConfine => {
                "no cgroup2 mount with nsdelegate covers the classifier tree, so a \
                 box could migrate out of its leaf"
            }
            Self::GuestTableNotLoaded => {
                "guest-side classifier enforcement is not available yet: this \
                 guest image has not loaded the classifier's packet-filter \
                 table, so no per-box verdict is decided in it"
            }
            Self::TableNotEffective => {
                "the classifier's table is marked loaded but its refusal is not \
                 in force: a probe's connection out of a deny leaf was not \
                 refused"
            }
            Self::ProbeUnreadable => {
                "the classifier table's effect could not be read: the daemon's \
                 own control connection or the probe's placement failed, so \
                 whether the table is refusing is unknown"
            }
        }
    }

    /// What this daemon does with a host-address box on this cause, spelled
    /// for the cause's own host: the half of the start-up line that must say
    /// what the next launch will actually do, because the two hosts answer
    /// a host that cannot decide per box differently. In the guest the tree
    /// and the table were the image's own to build: a tree that cannot
    /// confine a box leaves nothing to place one in, so every host-address
    /// box is refused, and on a table that is not loaded — guest-side
    /// enforcement not being available yet — a deny-all box is refused
    /// rather than run on a refusal that is not there, while every other
    /// box needs no verdict enforced and runs.
    ///
    /// Natively, the causes the step or the host's own mount can end keep
    /// the requirement's own exception (NET-079): the boxes run unenforced
    /// and the launch's record says so. [`Cause::GuestTableNotLoaded`]
    /// cannot arise natively ([`decide`] spells the same state
    /// [`Cause::StepNotInstalled`] there), so it takes the state's native
    /// meaning. The two probe causes are the exception's one limit — the
    /// one state where the box's own declaration is the thing this host
    /// cannot honour: a deny-all box placed in a leaf whose table is not
    /// refusing, or whose effect could not be read, would run looking
    /// decided while nothing refuses it, so the launch refuses it and the
    /// boxes that need no verdict enforced still run. The match stays
    /// exhaustive over causes, never claiming a host kind that cannot
    /// produce it.
    pub fn host_ip_box_outcome(self, guest: bool) -> &'static str {
        if guest {
            return match self {
                Self::CannotConfine => {
                    "its host-address boxes are refused: it cannot place one in a \
                     leaf that confines"
                }
                Self::StepNotInstalled
                | Self::GuestTableNotLoaded
                | Self::TableNotEffective
                | Self::ProbeUnreadable => {
                    "its deny-all host-address boxes are refused and its other \
                     host-address boxes run unenforced"
                }
            };
        }
        match self {
            Self::StepNotInstalled | Self::CannotConfine | Self::GuestTableNotLoaded => {
                "its host-address boxes run unenforced"
            }
            Self::TableNotEffective | Self::ProbeUnreadable => {
                "its deny-all host-address boxes are refused and its other \
                 host-address boxes run unenforced"
            }
        }
    }

    /// The exact command that ends this cause, when one can: the step's
    /// install when the step is what is missing — NET-079 names that one —
    /// and nothing for a host that cannot confine a box, because installing
    /// the step over that tree would leave the cause standing, or for a
    /// guest whose table its own image never loaded, because the person to
    /// tell is the image's builder and no installer exists there. A table
    /// the marker vouches for but the probe does not names nothing either:
    /// the step is installed, so the step is not what is missing, and no
    /// re-run of it is known to make the table refuse — and a probe that
    /// could not read the table names nothing, because no command is known
    /// to make a probe run.
    pub fn install_command(self) -> Option<String> {
        match self {
            Self::StepNotInstalled => Some(sandbox2::classifier::install_hint()),
            Self::CannotConfine
            | Self::GuestTableNotLoaded
            | Self::TableNotEffective
            | Self::ProbeUnreadable => None,
        }
    }
}

/// Whether this host can decide a host-address box's egress verdict per box
/// (NET-079), and why not when it cannot: the fact the daemon reads at
/// start and again before each host-address launch, the create response
/// carries, and `min session activate` turns into the advisory at session
/// start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    decided: bool,
    cause: Option<Cause>,
}

impl Decision {
    /// A host that decides per box: its covering cgroup2 confines, the
    /// step's subtrees and marker are there, and a probe's connection out
    /// of a deny leaf was refused the way the loaded table refuses — the
    /// facts a verdict needs to be decided *on* something, guest or native
    /// alike. The refusal is the one of them a reboot empties, which is why
    /// it, not the marker beside it, is the fact the verdict rests on.
    pub fn decided() -> Self {
        Self {
            decided: true,
            cause: None,
        }
    }

    /// A host that decides nothing per box, because `cause`.
    pub fn undecidable(cause: Cause) -> Self {
        Self {
            decided: false,
            cause: Some(cause),
        }
    }

    /// Whether a host-address box here has a verdict of its own.
    pub fn can_decide_per_box(&self) -> bool {
        self.decided
    }

    /// Why not, when it cannot.
    pub fn cause(&self) -> Option<Cause> {
        self.cause
    }
}

/// The cgroup v2 delegation contract, the same three files the privileged
/// step installs and refuses to run without: a delegated cgroup is its
/// directory plus its `cgroup.procs`, `cgroup.threads` and
/// `cgroup.subtree_control`.
const DELEGATION_FILES: [&str; 3] = ["cgroup.procs", "cgroup.threads", "cgroup.subtree_control"];

/// The loopback families the probe reads the filter over. Loopback is
/// where the probe's own listener sits, and the two addresses are the two
/// ways a process on this host reaches it. A family that is not enabled on
/// this host is not probed — which is why [`Reading::Refused`] carries the
/// families it read: a family it did not read is a family whose bypass it
/// cannot see.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    /// IPv4 loopback, where a connection the chain rejects with `icmpx
    /// admin-prohibited` reads as EHOSTUNREACH.
    V4,
    /// IPv6 loopback, where the same rejection reads as EACCES.
    V6,
}

impl Family {
    /// The loopback address this family probes: the address its listener
    /// binds and its child connects to.
    pub(crate) const fn loopback(self) -> IpAddr {
        match self {
            Self::V4 => IpAddr::V4(Ipv4Addr::LOCALHOST),
            Self::V6 => IpAddr::V6(Ipv6Addr::LOCALHOST),
        }
    }

    /// The family's own spelling for the probe's log record: the address a
    /// person reads, not the enum's.
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::V4 => "127.0.0.1",
            Self::V6 => "::1",
        }
    }
}

/// The errnos by which a connection refused by the table's deny chain reads
/// on loopback (design §4.1): `reject with icmpx admin-prohibited`
/// surfaces as EHOSTUNREACH over IPv4 and as EACCES over IPv6, and EPERM
/// is a security module's refusal of the same connection. Nothing else
/// reads as the table talking — ECONNREFUSED is the probe's own listener
/// gone, ENETUNREACH a routing answer — so a refusal outside this set is
/// evidence the table is not what refused, and no `per_box` reading is
/// ever built on one.
const REJECT_SET: [libc::c_int; 3] = [libc::EHOSTUNREACH, libc::EACCES, libc::EPERM];

/// How long the parent waits for one probe child's report: the child does
/// one migration write and one loopback connect, both of which the kernel
/// answers in its own time, so a child that outlives this will not report —
/// and reads as [`Observed::TimedOut`], never as a refusal. A refused
/// connect takes about a second: the ICMP reject for the first SYN lands
/// while `connect()` still holds the socket, so the kernel records it as a
/// soft error and `connect()` fails only at the first SYN retransmit
/// (initial RTO, 1 s). Three seconds outlasts that retransmit with room.
const PROBE_DEADLINE: Duration = Duration::from_secs(3);

/// The migration file a child writes its own pid into: `cgroup.procs`, the
/// file the kernel makes in every cgroup2 directory and the one a stand-in
/// tree must carry for a probe child to place itself in.
const PROCS_FILE: &str = "cgroup.procs";

/// What one probe child's connection met, with the errno where one was
/// read: one leg of the probe, kept per family so the decision's record
/// names the evidence it rests on and not only the verdict it settled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Observed {
    /// `connect()` completed: the filter admitted a connection out of a
    /// deny leaf, which a loaded table never does.
    Connected,
    /// `connect()` was refused with this errno.
    Refused(i32),
    /// The child never reported inside the probe's deadline — a hang, not
    /// a refusal, and read as the least the leg can prove.
    TimedOut,
    /// The child could not be placed in the deny leaf (this errno), so no
    /// connection was made and the leg read nothing.
    Unplaced(i32),
    /// The child reported nothing legible: the fork failed, the pipe broke,
    /// or the report did not decode.
    Silent,
}

impl Observed {
    /// The leg's own spelling for the probe's log record, the errno
    /// included where one was read.
    pub(crate) fn describe(self) -> String {
        match self {
            Self::Connected => "connected".to_string(),
            Self::Refused(errno) => format!("refused, errno {errno}"),
            Self::TimedOut => "did not report within the deadline".to_string(),
            Self::Unplaced(errno) => format!("was not placed, errno {errno}"),
            Self::Silent => "reported nothing legible".to_string(),
        }
    }
}

/// What the probe read the table's effect as: the fact a `per_box` record
/// rests on and no marker can vouch for (design §7.4) — a marker survives
/// a reboot whose reload failed; the refusal it vouched for does not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reading {
    /// Every family read was refused with an errno in [`REJECT_SET`]: the
    /// table is loaded and its chain is refusing, each leg's observation
    /// carried for the record.
    Refused(Vec<(Family, Observed)>),
    /// A family's connection met what a loaded table would not let it meet
    /// — it completed, was refused with an errno the chain never reads as,
    /// or never reported in time — so the table is not refusing and
    /// `per_box` would be a claim the filter does not back.
    NotRefused {
        /// The leg that settled it, with what it met.
        because: String,
        /// Every leg the probe ran, the evidence the record names.
        families: Vec<(Family, Observed)>,
    },
    /// The table's effect could not be read: the daemon's own control
    /// connection failed, or no probe child could be placed. Unknown is
    /// not a verdict, and the reading never claims one.
    Inconclusive {
        /// What failed, in the failing call's own words.
        because: String,
    },
}

impl Reading {
    /// The reading a set of per-family legs settles, pure over its input —
    /// the reject set and the every-family rule are decided here, pinned
    /// where they are written, not inside the probe that must not decide.
    ///
    /// One family that connected, timed out, or was refused outside the
    /// set settles the whole reading as [`Reading::NotRefused`]: a bypass
    /// on any family is a full bypass, and no other leg can un-meet that
    /// connection. A family whose leg could not be read — unplaced, or
    /// silent — leaves the effect unseen on it, so with no positive
    /// evidence the reading is [`Reading::Inconclusive`] rather than a
    /// refusal that may not have survived the leg that never ran. Only
    /// when every family it read was refused the table's own way does the
    /// reading say [`Reading::Refused`].
    pub(crate) fn of(observations: &[(Family, Observed)]) -> Self {
        if let Some((family, observed)) = observations.iter().find(|(_, observed)| {
            matches!(observed, Observed::Connected | Observed::TimedOut)
                || matches!(observed, Observed::Refused(errno) if !REJECT_SET.contains(errno))
        }) {
            return Self::NotRefused {
                because: format!("{} {}", family.name(), observed.describe()),
                families: observations.to_vec(),
            };
        }
        if let Some((family, observed)) = observations
            .iter()
            .find(|(_, observed)| matches!(observed, Observed::Unplaced(_) | Observed::Silent))
        {
            return Self::Inconclusive {
                because: format!("the leg on {} {}", family.name(), observed.describe()),
            };
        }
        if observations.is_empty() {
            return Self::Inconclusive {
                because: "no loopback family could be probed on this host".to_string(),
            };
        }
        Self::Refused(observations.to_vec())
    }

    /// Every leg the probe ran, with what each met — the evidence behind
    /// the reading, so a test can read the leg itself (a stand-in tree with
    /// no table connects on every family it bound) and not only the reading
    /// the legs settle. An inconclusive reading ran no leg it can vouch
    /// for: its control connection failed or no child was placed, so it
    /// names no evidence. No production surface reads a leg on its own —
    /// the reading is what they answer with — so the accessor is the
    /// root lane's, whose live proof pins the errno each family of a
    /// loaded table reads.
    pub fn legs(&self) -> Vec<(Family, Observed)> {
        match self {
            Self::Refused(legs) | Self::NotRefused { families: legs, .. } => legs.clone(),
            Self::Inconclusive { .. } => Vec::new(),
        }
    }

    /// The probe's own record, one line naming every family it read and
    /// what the leg there met, errno included — the evidence, spelled once
    /// so the decision that logs it and a bundle's tail agree by
    /// construction.
    pub fn record(&self) -> String {
        match self {
            Self::Refused(families) => format!(
                "the table refused the probe out of a deny leaf on every family read ({})",
                Self::leg_names(families)
            ),
            Self::NotRefused { because, families } => format!(
                "the table did not refuse the probe: {because} ({})",
                Self::leg_names(families)
            ),
            Self::Inconclusive { because } => {
                format!("the table's effect could not be read: {because}")
            }
        }
    }

    /// The per-family tail of the record.
    fn leg_names(families: &[(Family, Observed)]) -> String {
        families
            .iter()
            .map(|(family, observed)| format!("{} {}", family.name(), observed.describe()))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// The probe (NET-079, design §4.1, §7.4): reads the filter's effect the
/// way a deny-all box's connections meet it — a short-lived child placed in
/// a deny-subtree leaf of the daemon's delegated tree, connecting to the
/// loopback listener the daemon holds at each `endpoints` entry.
///
/// The control leg runs first: the daemon connects to each listener from
/// its own cgroup, outside the deny subtree, because a listener the daemon
/// itself cannot reach says nothing about the filter — any probe leg to it
/// could only have read its own listener. A control failure makes the
/// reading inconclusive before any child is forked.
///
/// Each family then gets one child, which places itself in the probe's
/// throwaway leaf — the one migration primitive a launch's placement probe
/// performs too — connects once, reports both errnos over a pipe, and
/// exits; the parent waits inside [`PROBE_DEADLINE`] and reads what the
/// child met. No capability beyond that: no `CAP_NET_ADMIN`, no root
/// helper, and no byte written outside the leaf the probe names after
/// itself and removes.
pub(crate) fn probe_effect(root: &Path, endpoints: &[(Family, SocketAddr)]) -> Reading {
    for (family, addr) in endpoints {
        if let Err(cause) = TcpStream::connect(addr) {
            return Reading::Inconclusive {
                because: format!(
                    "the daemon's own connect to its probe listener on {} failed: {cause}",
                    family.name()
                ),
            };
        }
    }
    let leaf = probe_leaf(root);
    // A probe that died before its own cleanup leaves its leaf behind, and
    // this probe removes it rather than wedging into it: the file first —
    // over a stand-in tree that is the modeled `cgroup.procs` a previous
    // probe made, while a kernel-owned one refuses removal and stays the
    // kernel's — then the leaf itself.
    let _ = std::fs::remove_file(leaf.join(PROCS_FILE));
    let _ = std::fs::remove_dir(&leaf);
    if let Err(cause) = std::fs::create_dir(&leaf) {
        return Reading::Inconclusive {
            because: format!("making the probe's deny leaf: {cause}"),
        };
    }
    // The kernel makes `cgroup.procs` at mkdir on cgroup2 and removes it
    // with the cgroup; a tree with no kernel behind it — a test's
    // stand-in — has no file for the child to write its pid into, so the
    // probe makes the one for its own throwaway leaf, the only leaf here
    // it would ever create, and owes its removal below.
    let procs = leaf.join(PROCS_FILE);
    let made_procs = !procs.exists() && std::fs::write(&procs, b"").is_ok();
    let observations = endpoints
        .iter()
        .map(|(family, addr)| probe_family(&procs, *family, addr))
        .collect::<Vec<_>>();
    // The throwaway leaf is owed its removal even when a leg read nothing.
    if made_procs {
        let _ = std::fs::remove_file(&procs);
    }
    let _ = std::fs::remove_dir(&leaf);
    Reading::of(&observations)
}

/// The probe's throwaway leaf, in the deny subtree the refusing rule
/// matches: `<root>/boxes/deny/filter-probe-<pid>`, named by this daemon's
/// own pid so two daemons probing one tree never share one. A leaf left
/// behind by a probe that died before its own cleanup is remade, not
/// wedged into, by the next.
fn probe_leaf(root: &Path) -> PathBuf {
    sandbox2::classifier::box_leaf(
        root,
        &format!("filter-probe-{}", std::process::id()),
        Verdict::Deny,
    )
}

/// One probe leg: forks a child, hands it the probe leaf's `cgroup.procs`
/// and this family's listener, waits inside [`PROBE_DEADLINE`] for its
/// report, and returns what the child's connect met. The child is killed
/// and reaped at the deadline if it has not reported — no probe child
/// outlives the decision it was forked for.
fn probe_family(procs: &Path, family: Family, addr: &SocketAddr) -> (Family, Observed) {
    // Everything the child needs is prepared before the fork, the only
    // place allocation still may run: after the fork the child touches
    // nothing but raw syscalls, the same pre-exec discipline a sandbox's
    // closure keeps.
    let c_procs = match std::ffi::CString::new(procs.as_os_str().as_encoded_bytes()) {
        Ok(c_procs) => c_procs,
        Err(_) => return (family, Observed::Unplaced(libc::EINVAL)),
    };
    let port = addr.port();
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: `pipe2(2)` writes two descriptors into `fds` and touches
    // nothing else.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return (family, Observed::Silent);
    }
    // SAFETY: `fork(2)` runs in this (possibly multithreaded) process, and
    // the child runs only async-signal-safe calls between the fork and its
    // `_exit` — open, write, close, getpid, socket, connect — so no
    // allocator or lock can be held across the fork by the child itself,
    // in kind with the pre-exec closure this probe models.
    let pid = unsafe { libc::fork() };
    if pid == -1 {
        // SAFETY: both descriptors were made above and none crossed a fork.
        unsafe {
            libc::close(fds[0]);
            libc::close(fds[1]);
        }
        return (family, Observed::Silent);
    }
    if pid == 0 {
        // SAFETY: the read end belongs to the parent; the write end is the
        // child's whole report channel, and `probe_child` never returns.
        unsafe {
            libc::close(fds[0]);
            probe_child(c_procs.as_ptr(), family, port, fds[1]);
        }
    }
    // SAFETY: the write end is the child's, closed here so the read below
    // can see the report's end.
    unsafe { libc::close(fds[1]) };
    let observed = wait_for_report(fds[0], pid);
    // SAFETY: the read end, which this half owns.
    unsafe { libc::close(fds[0]) };
    (family, observed)
}

/// The parent's half of one leg: poll the child's pipe for its report
/// inside [`PROBE_DEADLINE`], read and reap it when it comes, kill and reap
/// it when it does not. The report is the placement's errno then the
/// connect's, each 0 standing for "made / completed" — so a leg that was
/// placed and connected reads connected, and one that was placed and
/// refused reads the refusal's errno. `fd` is the read end this half owns
/// and `pid` the unreaped child holding its write end.
fn wait_for_report(fd: libc::c_int, pid: libc::pid_t) -> Observed {
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: `poll(2)` writes into `pfd` and reads `fd`, both this half's.
    let ready = unsafe { libc::poll(&mut pfd, 1, PROBE_DEADLINE.as_millis() as libc::c_int) };
    if ready <= 0 {
        // A timeout and an unreadable pipe are both a leg that read nothing
        // — never a refusal — and the child never outlives either.
        // SAFETY: `kill(2)` and `waitpid(2)` address the child this leg
        // forked, which is reaped either way.
        unsafe {
            libc::kill(pid, libc::SIGKILL);
            libc::waitpid(pid, std::ptr::null_mut(), 0);
        }
        return if ready == 0 {
            Observed::TimedOut
        } else {
            Observed::Silent
        };
    }
    let mut report = [0 as libc::c_int; 2];
    // SAFETY: `read(2)` writes into `report` from the pipe `fd` reads.
    let read = unsafe { libc::read(fd, report.as_mut_ptr().cast(), 8) };
    // SAFETY: reaping the child this leg forked, which has exited by the
    // report it just wrote.
    unsafe { libc::waitpid(pid, std::ptr::null_mut(), 0) };
    if read != 8 {
        return Observed::Silent;
    }
    let [placement, connect] = report;
    if placement != 0 {
        return Observed::Unplaced(placement);
    }
    if connect == 0 {
        return Observed::Connected;
    }
    Observed::Refused(connect)
}

/// The probe child's half, raw syscalls only: this runs between a `fork`
/// and its `_exit`, where only async-signal-safe calls belong. The child
/// opens the probe leaf's `cgroup.procs` for append and writes its own pid
/// into it — the one migration primitive the placement rests on — then
/// connects once to the family's loopback listener, whose address it
/// rebuilds from the family and the port it is handed: the listener is
/// bound at the family's own loopback address, so nothing of the parent's
/// but the copy the fork made survives to borrow. It reports the
/// placement's errno then the connect's over the pipe and exits either
/// way.
///
/// # Safety
///
/// `c_procs` is a live C string and `report` the write end of a pipe the
/// parent is polling; the function never returns.
unsafe fn probe_child(
    c_procs: *const libc::c_char,
    family: Family,
    port: u16,
    report: libc::c_int,
) -> ! {
    // SAFETY: `open(2)` reads `c_procs`; the flags are the append the
    // migration primitive uses — no `O_CREAT`, because a missing
    // `cgroup.procs` is a missing leaf and is reported, not made — and
    // `O_CLOEXEC` keeps the descriptor from crossing an exec this child
    // never reaches anyway.
    let procs = unsafe { libc::open(c_procs, libc::O_WRONLY | libc::O_APPEND | libc::O_CLOEXEC) };
    if procs == -1 {
        // `Error::last_os_error` is `Error::Os(RawOsError)` around this
        // thread's errno — no allocation, so it belongs to the
        // async-signal-safe set the child may run.
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(1);
        tell(report, errno, 0);
        // SAFETY: `_exit(2)` never returns, so the child ends here.
        unsafe { libc::_exit(1) };
    }
    if !write_own_pid(procs) {
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(1);
        // SAFETY: the descriptor just opened, closed on the failing path.
        unsafe { libc::close(procs) };
        tell(report, errno, 0);
        // SAFETY: the child ends here.
        unsafe { libc::_exit(1) };
    }
    // SAFETY: the migration's file, done with.
    unsafe { libc::close(procs) };
    let domain = match family {
        Family::V4 => libc::AF_INET,
        Family::V6 => libc::AF_INET6,
    };
    // SAFETY: `socket(2)` makes the one descriptor this child connects with.
    let socket = unsafe { libc::socket(domain, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if socket == -1 {
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(1);
        tell(report, 0, errno);
        // SAFETY: the child ends here.
        unsafe { libc::_exit(1) };
    }
    let connected = match family {
        Family::V4 => {
            // SAFETY: `sockaddr_in` is a C struct of integers and padding;
            // zeroed is its init, and every field that matters is set below.
            let mut to: libc::sockaddr_in = unsafe { std::mem::zeroed() };
            to.sin_family = libc::AF_INET as libc::sa_family_t;
            to.sin_port = port.to_be();
            // `s_addr` is the address in the machine's own byte order, and
            // `INADDR_LOOPBACK` is the literal `0x7f000001` — written into
            // `s_addr` as-is on a little-endian host it is 1.0.0.127, the
            // wire order of 127.0.0.1's bytes reversed, so the leg connects
            // to an address nothing listens on and reads as a timeout. The
            // v6 arm builds its address from the address type's own octets;
            // this arm does the same, which is `INADDR_LOOPBACK` after
            // `htonl`.
            to.sin_addr = libc::in_addr {
                s_addr: u32::from_ne_bytes(Ipv4Addr::LOCALHOST.octets()),
            };
            // SAFETY: `connect(2)` reads the `sockaddr_in` filled in above.
            unsafe {
                libc::connect(
                    socket,
                    (&raw const to).cast(),
                    std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                )
            }
        }
        Family::V6 => {
            // SAFETY: `sockaddr_in6` is a C struct of integers and padding;
            // zeroed is its init, and every field that matters is set below.
            let mut to: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
            to.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            to.sin6_port = port.to_be();
            to.sin6_addr = libc::in6_addr {
                s6_addr: Ipv6Addr::LOCALHOST.octets(),
            };
            // SAFETY: `connect(2)` reads the `sockaddr_in6` filled in above.
            unsafe {
                libc::connect(
                    socket,
                    (&raw const to).cast(),
                    std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
                )
            }
        }
    };
    // SAFETY: the one descriptor this child made, done with either way.
    unsafe { libc::close(socket) };
    if connected == 0 {
        tell(report, 0, 0);
        // SAFETY: the child ends here.
        unsafe { libc::_exit(0) };
    }
    let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(1);
    tell(report, 0, errno);
    // SAFETY: the child ends here.
    unsafe { libc::_exit(0) };
}

/// Writes this process's own pid, decimal and newline-terminated, to `fd`
/// with raw writes — the migration itself: a pid in `cgroup.procs` is a
/// process in the cgroup. `format!` allocates and cannot run here, so the
/// digits are placed by hand, most-significant first, and a pid is at most
/// seven decimal digits on any Linux, so the newline never runs out of
/// room. `fd` is an open file.
fn write_own_pid(fd: libc::c_int) -> bool {
    let mut text = [0u8; 8];
    // SAFETY: `getpid(2)` cannot fail.
    let mut pid = unsafe { libc::getpid() };
    let mut at = text.len() - 1;
    text[at] = b'\n';
    loop {
        at -= 1;
        text[at] = b'0' + (pid % 10) as u8;
        pid /= 10;
        if pid == 0 {
            break;
        }
    }
    write_all(fd, &text[at..])
}

/// One raw write of exactly `bytes`, retrying the short writes and
/// interruptions a blocking fd can produce; `false` when the write failed
/// for any other reason. `fd` is an open file.
fn write_all(fd: libc::c_int, bytes: &[u8]) -> bool {
    let mut done = 0;
    while done < bytes.len() {
        // SAFETY: `write(2)` reads `bytes[done..]`, which outlives the call.
        let n = unsafe { libc::write(fd, bytes[done..].as_ptr().cast(), bytes.len() - done) };
        if n > 0 {
            done += n as usize;
        } else if n < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            continue;
        } else {
            return false;
        }
    }
    true
}

/// The child's whole report — two native-endian words, the placement's
/// errno then the connect's — over the pipe. A parent that has gone first
/// loses the report with the pipe, which is the parent's problem; the
/// child never waits on it. `fd` is the write end of the pipe.
fn tell(fd: libc::c_int, placement: libc::c_int, connect: libc::c_int) {
    let words = [placement, connect];
    // SAFETY: the two words are read as the eight bytes they are.
    let bytes = unsafe { std::slice::from_raw_parts(words.as_ptr().cast::<u8>(), words.len() * 4) };
    write_all(fd, bytes);
}

/// Binds one family's probe listener on an ephemeral loopback port, retrying
/// in the practically impossible case the kernel hands out the answerer's
/// own: the answerer's address is the one destination the deny chain
/// admits (NET-079's carve-out), so a probe connection landed there would
/// be admitted by a table doing exactly what it was told and read as the
/// table being absent.
fn bind_probe_listener(family: Family) -> std::io::Result<TcpListener> {
    for _ in 0..4 {
        let listener = TcpListener::bind(SocketAddr::new(family.loopback(), 0))?;
        if listener.local_addr()?.port() != crate::net::answerer::ANSWERER_PORT {
            return Ok(listener);
        }
    }
    Err(std::io::Error::other(
        "the probe's port choice collided with the answerer's",
    ))
}

/// The probe's listeners, one per family this host's loopback can carry.
fn bind_probe_listeners() -> std::io::Result<Vec<(Family, TcpListener)>> {
    let mut listeners = Vec::new();
    for family in [Family::V4, Family::V6] {
        match bind_probe_listener(family) {
            Ok(listener) => listeners.push((family, listener)),
            // A bind that fails for want of the family itself — no IPv6
            // loopback on this host — is one family fewer to read, not an
            // error: a host without the family cannot bypass through it,
            // and the reading names the families it did read.
            Err(cause)
                if family == Family::V6
                    && matches!(
                        cause.raw_os_error(),
                        Some(libc::EAFNOSUPPORT) | Some(libc::EADDRNOTAVAIL)
                    ) => {}
            Err(cause) => return Err(cause),
        }
    }
    Ok(listeners)
}

/// Reads the table's effect on this host (NET-079, design §7.4): the probe,
/// with its own listener — a destination the daemon holds on loopback, on
/// a port other than the answerer's, is the place a deny-all box's
/// connections would be refused. The probe binds, forks, connects, and
/// waits, so an async caller runs it on the blocking pool; it logs one
/// record per run, naming every family it read and what the leg there met,
/// the errno included.
///
/// The one probe surface outside the crate: the native lane's root harness
/// proves the *loaded* table's effect with the daemon's own probe, over a
/// scratch tree the installer laid out — the only artifact that can
/// produce the reading. No other caller reads a reading directly.
pub fn read_filter(root: &Path) -> Reading {
    // Held for the probe's whole duration: a listener nothing holds is the
    // dead-listener case the control leg exists to catch.
    let listeners = match bind_probe_listeners() {
        Ok(listeners) => listeners,
        Err(cause) => {
            return Reading::Inconclusive {
                because: format!("binding the probe's loopback listener: {cause}"),
            };
        }
    };
    let endpoints: Vec<_> = listeners
        .iter()
        .filter_map(|(family, listener)| listener.local_addr().ok().map(|addr| (*family, addr)))
        .collect();
    let reading = probe_effect(root, &endpoints);
    // The healthy refusal is the quiet case — a launch's own record already
    // names its enforcement — while anything else is the state a person
    // reading the log has to see.
    if matches!(reading, Reading::Refused(_)) {
        tracing::debug!(probe = %reading.record(), "the classifier table refused the probe's connection out of a deny leaf");
    } else {
        tracing::info!(probe = %reading.record(), "read the classifier table's effect on this host");
    }
    reading
}

/// The check (NET-079, design §7.4): whether this host can decide a
/// host-address box's egress verdict per box, and why not when it cannot.
/// It runs at daemon start and again before each host-address launch,
/// because the fact it rests on does not outlive the table.
///
/// Read-only over the same facts the privileged step installs — the
/// cgroup2 the tree sits on (`nsdelegate` is what makes a box's cgroup
/// namespace a delegation boundary, so a box cannot migrate out of its
/// leaf), the cohort's two delegated subtrees, and the loaded table's
/// presence marker — and then over the one fact none of those can vouch
/// for: `read` probes the table's effect, and only a connection refused
/// the way the loaded chain refuses turns the marker's claim into a
/// verdict. The facts gate the probe, so a host missing the step pays no
/// probe — and no fact is taken as evidence of another: a marker present
/// over a table whose refusal is gone is its own cause, not a decision.
/// Nothing here needs `CAP_NET_ADMIN`, a root helper, or a byte written
/// outside the probe's own throwaway leaf: the step's `--pid` half, a
/// loopback connect, and a migration the launch's placement probe performs
/// too are all the privileges it uses.
///
/// The guest answers the same questions, and for the same reason: its
/// daemon is the microVM's pid 1, so the tree it mounts and the table its
/// image loads are its own boot's work — and reporting a guest as decided
/// while its table is not loaded would place a deny-all box in a leaf that
/// decides nothing while looking decided, on the one host whose image is
/// the fix. The guest's cause is named for the image's builder: no
/// installer exists inside a microVM, so no command is named for it.
pub(crate) fn decide(
    root: &Path,
    mountinfo: Option<&str>,
    guest: bool,
    read: impl FnOnce() -> Reading,
) -> Decision {
    // The confinement half first: without `nsdelegate` a cgroup namespace
    // is not a delegation boundary, so no leaf under this tree confines a
    // process however installed — the cause no command clears, on either
    // kind of host. A mount table that cannot be read is the same absence
    // of evidence, and the check may not report a host as confining on no
    // evidence.
    let confining = sandbox2::classifier::cgroup2_covering(root, mountinfo.unwrap_or(""))
        .is_some_and(|(_, nsdelegate)| nsdelegate);
    if !confining {
        return Decision::undecidable(Cause::CannotConfine);
    }
    // The step's half: the cohort's two subtrees — a box's leaf is always
    // in one of them, so one missing is the whole step missing — and the
    // marker the loaded table's presence rests on. Natively that is the
    // step a person can run, so its cause names the install; in the guest
    // it is the image's own half, so its cause names the table and nothing
    // can be run.
    if !subtrees_delegated(root) || !table_marker_present(root) {
        return Decision::undecidable(if guest {
            Cause::GuestTableNotLoaded
        } else {
            Cause::StepNotInstalled
        });
    }
    // The table's half, the one the facts above cannot vouch for: the
    // marker says the install ran, not that the refusal it recorded is
    // still in force — a reboot that lost the reload, a flush, or a
    // conflicting ruleset leaves the marker standing over an empty filter,
    // which is the false `per_box` this decision must not claim. Only the
    // probe's refusal reads as decided; a connection the chain did not
    // refuse is its own cause, and a probe that could not read the table
    // says so and claims nothing.
    match read() {
        Reading::Refused(_) => Decision::decided(),
        Reading::NotRefused { .. } => Decision::undecidable(Cause::TableNotEffective),
        Reading::Inconclusive { because } => {
            tracing::info!(
                cause = %Cause::ProbeUnreadable.detail(),
                because = %because,
                "the classifier table's effect could not be read on this host"
            );
            Decision::undecidable(Cause::ProbeUnreadable)
        }
    }
}

/// [`decide`] with its probe attached: the decision the daemon reads, over
/// the tree, mount table, and host kind its caller names for it — the
/// daemon's own in every production path. The probe binds a listener, forks
/// a child, and waits, so an async caller runs it on the blocking pool.
pub fn decide_now(root: &Path, mountinfo: Option<&str>, guest: bool) -> Decision {
    decide(root, mountinfo, guest, || read_filter(root))
}

/// The leaf the daemon's own fetches are recorded as leaving from: its own,
/// where this daemon stands in one — the leaf it entered at start, or the one
/// the installer's `--pid` step placed a native daemon in — and `None` where
/// it does not.
///
/// This is the one fact of [`record_node_plane_fetch`] that is about the
/// *host* rather than about the fetch, so it is read, not assumed: a daemon
/// that starts outside the tree never gets in, because its entry is a
/// migration whose common ancestor this account cannot write to from outside
/// (the reason the step's `--pid` half exists), and a host without the step
/// has no tree to stand in at all — on both, the record must not claim a
/// leaf. Read the way the placement is written ([`enter_daemon_leaf`] at
/// start, `--pid` natively): this process's own pid among the members of its
/// leaf's `cgroup.procs`, the one place a cgroup's membership is stated, so
/// no path is derived here from a mount table a host may spell some other
/// way. A leaf that is not there, or one this daemon is not in, reads as
/// what it is: no leaf of the daemon's own.
///
/// [`enter_daemon_leaf`]: sandbox2::classifier::enter_daemon_leaf
pub fn daemon_fetch_leaf(root: &Path) -> Option<&'static str> {
    let members =
        std::fs::read_to_string(sandbox2::classifier::daemon_leaf(root).join(PROCS_FILE)).ok()?;
    members
        .lines()
        .any(|member| member.trim().parse::<u32>() == Ok(std::process::id()))
        .then_some(sandbox2::classifier::DAEMON_LEAF)
}

/// NET-080: the node-plane record for the daemon's own fetches — one line
/// per fetch the daemon itself makes, naming the box the fetch was made
/// for, the host it left for, and the object it brought back, which is the
/// line a diagnostics bundle's daemon-log tail reads each fetch from. One
/// call per fetch, the caller naming the four.
///
/// The fetch a `min add` inside a host-address box triggers is the
/// *daemon's*, never the box's: the build runs in the daemon's own process,
/// outside every box on every host, so a deny-all box's declaration refuses
/// nothing of it and the fetch completes on the same host while the box
/// reaches nothing (the root lane's `snat_identity_is_seen_by_the_peer`
/// reads the identity the node plane's own rule gives a real peer, under a
/// loaded table). The fact is otherwise invisible: a fetch that completes
/// says nothing about whose it was, and a person reading a bundle for why
/// the box's install worked while the box's own connects are refused has
/// this record to answer with.
///
/// `leaf` is the one claim that is about the host rather than the fetch —
/// that the daemon stands in a leaf of its own beside the cohort, so the
/// loaded chain's refusing match cannot cover it. That holds where the
/// step's tree is installed and this daemon was placed in it, and not on a
/// host without the step or a daemon still outside the slice, so it is the
/// caller's to pass ([`daemon_fetch_leaf`]) and the line makes it only
/// where it holds: named as the leaf the fetch left from where the daemon
/// is in one, and spelled out as absent where it is not — a reader on an
/// unclassified host is told the fetch was the daemon's own process's, not
/// that it left a leaf no tree there holds. One line per fetch, at info,
/// with the box, the host, the leaf it left from where there is one, and
/// the object — a fetch is an event, not a meter, so no byte counts and no
/// deduplication: each fetch is recorded, and nothing else is.
pub fn record_node_plane_fetch(box_id: &str, leaf: Option<&str>, host: &str, object: &str) {
    match leaf {
        Some(leaf) => tracing::info!(
            host = %host,
            leaf = %leaf,
            box_id = %box_id,
            object = %object,
            "the daemon's own fetch is node-plane traffic, from its own leaf \
             beside the cohort: never the box's, so a deny-all host-address \
             box's declaration refuses nothing of it"
        ),
        None => tracing::info!(
            host = %host,
            box_id = %box_id,
            object = %object,
            "the daemon's own fetch is node-plane traffic, made in the daemon's \
             own process and never the box's; this daemon stands in no \
             classifier leaf of its own, so the record names no leaf"
        ),
    }
}

/// The host a fetch location is fetched from, spelled for the two forms the
/// configured remote cache takes: the mirror URL's own host, or the bucket
/// a GCS location names. The mirror's host is read from the URL the
/// newtype holds — its own `host_str` for the host, its own `port` for the
/// port — never from a rendering of it: a `Debug` print is a formatting
/// choice of the newtype's, and a spelling that changes with it changes
/// which host the record names while nothing else does. The port rides the
/// one rule every fetch kind's host field carries: a mirror on a
/// non-default port is named with it, one on https's own default without.
pub(crate) fn cache_host(location: &AnyUrl) -> String {
    match location {
        // The mirror is an https location, so the one port rule reads its
        // scheme as https: 443 is the default it drops.
        AnyUrl::Https(https) => {
            host_field(https.host_str().unwrap_or_default(), https.port(), "https")
        }
        AnyUrl::Gcs(gcs) => gcs.bucket.clone(),
    }
}

/// The host inside an authority: the authority minus any userinfo before
/// the last `@`. A `FetchSource` URL may carry a credential in its userinfo
/// (`https://<token>@github.com/…`), and the record is a log line a bundle
/// keeps on disk, so no spelling it writes carries one; the host the fetch
/// left for is the host, never the credential before it.
fn authority_host(authority: &str) -> &str {
    match authority.rsplit_once('@') {
        Some((_, host)) => host,
        None => authority,
    }
}

/// The port a fetch record's host field carries, one rule for both
/// spellings a fetch's host is read from — the configured cache's
/// location and a source URL: the port the fetch's URL spells, kept when
/// it is not the scheme's own default and dropped when it is (443 for
/// `https`, 80 for `http`). A non-default port is the one way two
/// fetches of the same host differ, so the record keeps it the same way
/// for every fetch kind; a default port is a fact the scheme already
/// says, so the field never carries it.
fn kept_port(scheme: &str, port: Option<u16>) -> Option<u16> {
    match (scheme, port) {
        ("https", Some(443)) | ("http", Some(80)) => None,
        (_, port) => port,
    }
}

/// The host a fetch's record names — `host` with the port [`kept_port`]
/// keeps — one spelling for both spellings the host is read from, so the
/// field reads the same way whatever the fetch left for.
fn host_field(host: &str, port: Option<u16>, scheme: &str) -> String {
    match kept_port(scheme, port) {
        Some(port) => format!("{host}:{port}"),
        None => host.to_owned(),
    }
}

/// The host a URL names — its authority, between the scheme and the first
/// path, query, or fragment delimiter, with any userinfo dropped and the
/// port carried only as the one rule every fetch kind's host field
/// carries it — which is where a `FetchSource` fetch leaves for. A
/// spelling with no scheme (a local source tarball) names no host and
/// crosses no network: the record's object still carries the whole
/// spelling, so the fetch is read whole from the two fields.
pub(crate) fn url_host(url: &str) -> String {
    let Some((scheme, rest)) = url.split_once("://") else {
        return String::new();
    };
    let authority = authority_host(rest.split(['/', '?', '#']).next().unwrap_or_default());
    // The port the authority spells after its last colon, when what
    // follows that colon is one: the colons inside a bracketed IPv6
    // literal are not a port, so an authority that spells none is the
    // host whole.
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) => match port.parse::<u16>() {
            Ok(port) => (host, Some(port)),
            Err(_) => (authority, None),
        },
        None => (authority, None),
    };
    host_field(host, port, scheme)
}

/// The object a `FetchSource` record names its fetch by: the URL's own
/// spelling minus the parts that never belong in a log line — the userinfo
/// before the last `@` (a credential), and the query and fragment after the
/// path (a query is where a signed URL carries its signature). A spelling
/// with no scheme (a local source tarball) names no host and crosses no
/// network, and is the object whole: the way the record has always spelled
/// a source it read off the operator's own disk.
pub(crate) fn url_object(url: &str) -> String {
    let Some((scheme, rest)) = url.split_once("://") else {
        return url.to_owned();
    };
    let before_query = rest.split(['?', '#']).next().unwrap_or_default();
    let (authority, path) = match before_query.split_once('/') {
        Some((authority, path)) => (authority, format!("/{path}")),
        None => (before_query, String::new()),
    };
    format!("{scheme}://{}{path}", authority_host(authority))
}

/// Whether the cohort's two subtrees are there as the step delegates them:
/// each directory with its delegation-contract files. Their absence is the
/// step not having run, not a host that cannot confine — the covering
/// cgroup2 was checked first.
fn subtrees_delegated(root: &Path) -> bool {
    [Verdict::Deny, Verdict::Allow].iter().all(|verdict| {
        let subtree = root
            .join(sandbox2::classifier::BOXES_DIR)
            .join(verdict.dir_name());
        DELEGATION_FILES
            .iter()
            .all(|file| subtree.join(file).exists())
    })
}

/// Whether the loaded table's presence marker is there, with the ct-mark
/// mask it classifies with recorded beside it: the directory the step
/// writes only after its `nft -f` transaction succeeded, and the record
/// naming the two bits that transaction rendered — the facts that say the
/// installer ran and say what it classifies with; the probe says whether
/// the refusal it recorded is still in force. A marker without its record
/// is a step that did not finish — the state a failed re-install leaves —
/// and reads the same as no step at all.
fn table_marker_present(root: &Path) -> bool {
    root.join(sandbox2::classifier::TABLE_MARKER).is_dir() && recorded_ct_mark_mask(root).is_some()
}

/// The ct-mark mask the loaded table classifies cohort and node plane
/// with, as the step recorded it beside the presence marker — the one fact
/// of the table's classification half a probe with no `CAP_NET_ADMIN` can
/// read, the way the marker itself is the one fact it can read of the
/// table's presence. Only the record's prefix is this side's spelling
/// (scripts/install-host-classifier.sh writes the same one): which two
/// bits an install chose is the record's to say, never a default this
/// probe assumes, and an install run with `--ct-mark-mask` is as
/// installed as one run without. One well-formed value or nothing: a
/// record that cannot be parsed, or two that disagree, is a step this
/// probe cannot read the classification of, and an unreadable
/// classification is no classification.
fn recorded_ct_mark_mask(root: &Path) -> Option<u32> {
    let recorded = std::fs::read_dir(root).ok()?;
    let mut mask = None;
    for entry in recorded.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Some(value) = name.strip_prefix(MASK_RECORD_PREFIX) else {
            continue;
        };
        let hex = value.strip_prefix("0x")?;
        let bits = u32::from_str_radix(hex, 16).ok()?;
        if mask.is_some_and(|other| other != bits) {
            return None;
        }
        mask = Some(bits);
    }
    mask
}

/// The prefix of the ct-mark mask record the privileged step writes beside
/// the presence marker: a cgroup named `ct-mark-mask-0x…`, its name
/// carrying the two bits the loaded table classifies with. The step's own
/// spelling of the same prefix is `MASK_RECORD_PREFIX` in
/// scripts/install-host-classifier.sh.
const MASK_RECORD_PREFIX: &str = "ct-mark-mask-";

/// The two source identities the ruleset tests render the installer's
/// table with: any two distinct addresses would do, and these are the
/// installer's own harness pair, so a rule named here is spelled the way
/// the step's own tests spell it.
#[cfg(test)]
pub(crate) const TEST_COHORT_ADDRESS: &str = "100.72.0.9";
#[cfg(test)]
pub(crate) const TEST_NODE_PLANE_ADDRESS: &str = "100.72.0.1";

/// The stand-in mount the step's own tests render and load over, the one
/// [`rendered_ruleset`] and the install-lane test below share: a plain
/// directory standing in for the cgroup2 mount, the slice below it named as
/// the production one is, and a mount table spelling the two facts
/// `verify_mount` demands — the hierarchy itself, mounted `nsdelegate`, this
/// namespace's view of it — so the cgroup paths both lanes render are the
/// ones they name on a real host.
#[cfg(test)]
struct StandinMount {
    /// Held, so the directories it names outlive the step's run.
    _scratch: tempfile::TempDir,
    root: PathBuf,
    mountinfo: PathBuf,
}

#[cfg(test)]
fn standin_mount() -> StandinMount {
    let scratch = tempfile::tempdir().expect("a temp dir standing in for the cgroup2 mount");
    // The tree root named as the production one is: the slice under its own
    // mount, so the cgroup paths the rendered rules name are the ones they
    // name on a real host.
    let mountpoint = scratch.path().join("cgroup");
    let root = mountpoint.join(
        std::path::Path::new(sandbox2::classifier::TREE_ROOT)
            .file_name()
            .expect("the tree root is a slice below the cgroup2 mount root"),
    );
    std::fs::create_dir_all(&root).expect("the mount covers the tree root");
    let mountinfo = scratch.path().join("mountinfo");
    std::fs::write(
        &mountinfo,
        format!(
            "35 30 0:26 / {} rw,relatime shared:2 - cgroup2 cgroup2 rw,nsdelegate\n",
            mountpoint.display(),
        ),
    )
    .expect("writing the stand-in mount table");
    StandinMount {
        _scratch: scratch,
        root,
        mountinfo,
    }
}

/// Builds the privileged step's command over a stand-in mount: `mode`
/// names the flags after `--root` (`--print-ruleset`, or nothing for the
/// install itself), plus the two source identities the step refuses to
/// render half of. `nft` is looked up on a PATH with `nft_dir` prepended,
/// so the install lane can hand its transaction to a recording stub rather
/// than a real `nft` — the one difference between the two lanes, and the
/// reason both read the same mount facts.
#[cfg(test)]
fn step_command(
    mount: &StandinMount,
    mode: &[&str],
    nft_dir: Option<&Path>,
) -> std::process::Command {
    let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../scripts/install-host-classifier.sh");
    let mut step = std::process::Command::new("bash");
    step.env("MINIMAL_OVERRIDE_CGROUP_MOUNTINFO", &mount.mountinfo);
    if let Some(dir) = nft_dir {
        let mut path = vec![dir.to_path_buf()];
        if let Some(existing) = std::env::var_os("PATH") {
            path.extend(std::env::split_paths(&existing));
        }
        step.env(
            "PATH",
            std::env::join_paths(path).expect("the stub's directory joins the PATH"),
        );
    }
    step.arg(script)
        .arg("--root")
        .arg(&mount.root)
        .args(mode)
        .arg("--cohort-address")
        .arg(TEST_COHORT_ADDRESS)
        .arg("--node-plane-address")
        .arg(TEST_NODE_PLANE_ADDRESS);
    step
}

/// Runs the privileged step over a stand-in mount, in the mode the test is
/// driving.
#[cfg(test)]
fn run_step(mount: &StandinMount, mode: &[&str], nft_dir: Option<&Path>) -> std::process::Output {
    step_command(mount, mode, nft_dir)
        .output()
        .expect("running the privileged step over the stand-in mount")
}

/// The install lane over a stand-in mount: the step lays out its tree,
/// delegates it, and hands its one transaction to whatever `nft` a PATH
/// with `nft_dir` prepended resolves to — a recording stub, so the bytes
/// it pipes to the packet filter are captured whole. The account the tree
/// is delegated to is this process's own, named through the step's sudo
/// seam, because an install a person runs names the account that ran
/// sudo. `None` when this process is root: the step refuses to delegate
/// its tree to root, so there is no install to rehearse.
#[cfg(test)]
fn run_install(mount: &StandinMount, nft_dir: &Path) -> Option<std::process::Output> {
    let uid = unsafe { libc::geteuid() };
    if uid == 0 {
        return None;
    }
    let mut step = step_command(mount, &[], Some(nft_dir));
    step.env("SUDO_UID", uid.to_string())
        .env("SUDO_GID", unsafe { libc::getegid() }.to_string());
    Some(
        step.output()
            .expect("running the privileged step's install over the stand-in mount"),
    )
}

/// The installer's rendered table, exactly as a host loads it, over a
/// stand-in tree the caller never sees: the privileged step's
/// `--print-ruleset` mode prints the transaction its install would hand
/// `nft -f`, with the cgroup paths and match levels derived from the same
/// mount facts an install reads. Reading the step's own output — rather
/// than restating its rules here — is what makes the tests below pin what
/// a host actually loads.
#[cfg(test)]
pub(crate) fn rendered_ruleset() -> String {
    let mount = standin_mount();
    let printed = run_step(&mount, &["--print-ruleset"], None);
    assert!(
        printed.status.success(),
        "the step's print mode renders its ruleset: {}",
        String::from_utf8_lossy(&printed.stderr),
    );
    String::from_utf8(printed.stdout).expect("the rendered ruleset is text")
}

/// The rules of one chain in a rendered ruleset, in the order the table
/// loads them, indentation-trimmed: the chains are the whole story of a
/// verdict — what the output chain routes, what `deny_out` admits, what
/// postrouting translates — and reading them by name is how the tests
/// below pin each one. The chain's own `type … hook …` declaration is
/// plumbing, not a rule, and is not included.
#[cfg(test)]
pub(crate) fn chain_rules<'a>(ruleset: &'a str, chain: &str) -> Vec<&'a str> {
    let mut rules = Vec::new();
    let mut inside = false;
    for line in ruleset.lines() {
        let line = line.trim_start();
        if line.starts_with("chain ") {
            inside = line.starts_with(&format!("chain {chain} "));
            continue;
        }
        if !inside {
            continue;
        }
        if line == "}" {
            break;
        }
        if !line.is_empty() && !line.starts_with("type ") {
            rules.push(line);
        }
    }
    rules
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A mount table whose cgroup2 covers `tree` with `nsdelegate`, the one
    /// a host that can confine a box has; `bare` covers it without one.
    fn mountinfo(tree: &Path, nsdelegate: bool) -> String {
        let mountpoint = tree
            .parent()
            .expect("a tree inside a temp dir has a mountpoint above it");
        format!(
            "35 30 0:26 / {} rw,relatime shared:2 - cgroup2 cgroup2 rw,{}\n",
            mountpoint.display(),
            if nsdelegate {
                "nsdelegate"
            } else {
                "memory_recursiveprot"
            }
        )
    }

    /// The tree root's own name — the component the installer renders a
    /// ruleset's cgroup paths below their covering mount from.
    fn tree_root_name() -> &'static str {
        std::path::Path::new(sandbox2::classifier::TREE_ROOT)
            .file_name()
            .and_then(std::ffi::OsStr::to_str)
            .expect("the tree root is a slice below the cgroup2 mount root")
    }

    /// The ct-mark mask the step's default install classifies with, and the
    /// record name it writes beside the marker: `--print-ruleset` renders
    /// these two bits, and the daemon's probe reads the record without
    /// assuming them — a host may have installed with an override.
    const TEST_CT_MARK_MASK: u32 = 0x3000_0000;
    const TEST_CT_MARK_RECORD: &str = "ct-mark-mask-0x30000000";

    /// The cohort the step installs: both subtrees with their
    /// delegation-contract files, the table's marker, and the ct-mark mask
    /// recorded beside it — the probe reads both, and a marker without its
    /// record is a step that did not finish.
    fn installed_cohort(root: &Path) {
        for verdict in [Verdict::Deny, Verdict::Allow] {
            let subtree = root
                .join(sandbox2::classifier::BOXES_DIR)
                .join(verdict.dir_name());
            std::fs::create_dir_all(&subtree).expect("the step makes the subtree");
            model_delegation_files(&subtree);
        }
        std::fs::create_dir_all(root.join(sandbox2::classifier::TABLE_MARKER))
            .expect("the step writes the table's marker");
        std::fs::create_dir_all(root.join(TEST_CT_MARK_RECORD))
            .expect("the step records the ct-mark mask beside the marker");
    }

    fn model_delegation_files(dir: &Path) {
        for file in DELEGATION_FILES {
            std::fs::write(dir.join(file), "")
                .unwrap_or_else(|e| panic!("modeling {file} in {}: {e}", dir.display()));
        }
    }

    /// NET-078: the node plane and the host-address cohort are classified
    /// separately, with distinct source identities — the layout the packet
    /// filter's two identities are keyed on, which is the daemon's to keep:
    /// the daemon's own leaf (node-plane traffic, NET-080) outside the
    /// cohort, and every box leaf inside it under one of the two subtrees
    /// at one depth, so the cohort's match covers both subtrees and nothing
    /// of the node plane.
    #[test]
    fn node_plane_and_cohort_distinct_sources() {
        let tree = tempfile::tempdir().expect("a temp dir standing in for the tree");
        let root = tree.path();
        let cohort = root.join(sandbox2::classifier::BOXES_DIR);
        let daemon = sandbox2::classifier::daemon_leaf(root);

        // The node plane's identity is keyed on the daemon's leaf, a sibling
        // of the cohort and never inside it: a daemon leaf under `boxes/`
        // would be matched by the cohort's source translation, and the
        // daemon's own fetches would leave as the cohort.
        assert_eq!(
            daemon.parent(),
            Some(root),
            "the daemon's leaf is one component under the tree root"
        );
        assert!(
            !daemon.starts_with(&cohort),
            "the node plane's leaf is outside the cohort: {}",
            daemon.display()
        );

        // The cohort's identity is keyed on `boxes/`: both subtrees are its
        // direct children — one match level, no per-subtree rules — and
        // every box leaf is one deeper, in one subtree or the other, never
        // the cohort itself.
        for (verdict, id) in [(Verdict::Deny, "a deny-all box"), (Verdict::Allow, "a box")] {
            let leaf = sandbox2::classifier::box_leaf(root, id, verdict);
            assert_eq!(
                leaf.parent().and_then(Path::parent),
                Some(cohort.as_path()),
                "the {id}'s leaf is one level under its subtree, which is one \
                 level under the cohort: {}",
                leaf.display()
            );
            assert_ne!(
                leaf, daemon,
                "no box leaf is the node plane's leaf, and vice versa"
            );
        }

        // The subtrees are the only direct children the step makes, so the
        // cohort's match is over exactly them: an entry directly under the
        // cohort would be node-plane traffic wearing the cohort's identity,
        // which is why the layout admits none.
        installed_cohort(root);
        let mut children: Vec<String> = std::fs::read_dir(&cohort)
            .expect("the cohort exists")
            .map(|entry| {
                entry
                    .expect("a readable entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        children.sort();
        assert_eq!(
            children,
            [sandbox2::config::ALLOW_DIR, sandbox2::config::DENY_DIR],
            "the cohort holds the two subtrees and nothing else"
        );

        // The rendered table's classify chain is that layout made real, at
        // output's mangle priority — the last place the kernel admits a
        // socket-cgroup match, which is why the classification lives
        // there while the postrouting chain translates by its result: the
        // kernel refuses a socket match at postrouting, so the two
        // identities were never loadable as one chain. The cohort's rule
        // keys on `boxes/` — one match level over both subtrees, covering
        // every box leaf and no node-plane leaf — and marks a new
        // connection's ct mark with the cohort bit; the node plane's keys
        // on the slice with the node bit, guarded by the mask so a flow
        // the boxes rule already classed is never re-decided, because
        // every box leaf is inside the slice too. Both rules write the
        // mask's two bits and nothing else (`and ~mask or bit`), so bits
        // another component of the host classes with survive; the
        // postrouting chain translates by the mark, never a socket, and
        // its `lo` guard keeps a packet to the answerer, which never
        // leaves the host, from being rewritten on its own way there.
        // The identities and the bits are the ones the step was told and
        // the ones its default mask chose, not ones it guessed: it
        // refuses to render half a pair, and refuses a mask that is not
        // two contiguous bits.
        let rel = tree_root_name();
        let cohort_path = format!("{}/{}", rel, sandbox2::classifier::BOXES_DIR);
        let ruleset = rendered_ruleset();
        assert!(
            ruleset.contains("type filter hook output priority mangle"),
            "the classify chain runs at output's mangle priority, ahead of \
             the filter chain and of postrouting: the kernel admits a \
             socket-cgroup match nowhere later: {ruleset}"
        );
        let clear = !TEST_CT_MARK_MASK;
        let cohort_bit = TEST_CT_MARK_MASK & TEST_CT_MARK_MASK.wrapping_neg();
        let node_bit = TEST_CT_MARK_MASK ^ cohort_bit;
        let classify = chain_rules(&ruleset, "classify");
        let cohort_rule = format!(
            "ct state new socket cgroupv2 level {} \"{}\" ct mark set ct mark and 0x{clear:08x} or 0x{cohort_bit:08x}",
            cohort_path.split('/').count(),
            cohort_path,
        );
        let node_plane_rule = format!(
            "ct state new ct mark and 0x{:08x} == 0 socket cgroupv2 level {} \"{}\" \
             ct mark set ct mark and 0x{clear:08x} or 0x{node_bit:08x}",
            TEST_CT_MARK_MASK,
            rel.split('/').count(),
            rel,
        );
        assert_eq!(
            classify.first(),
            Some(&cohort_rule.as_str()),
            "the cohort is classed first, on a new connection, by its \
             subtree at its own level: {classify:?}"
        );
        assert_eq!(
            classify.get(1),
            Some(&node_plane_rule.as_str()),
            "the node plane follows, guarded by the mask so the boxes \
             rule's mark is final: {classify:?}"
        );
        assert_eq!(
            classify.len(),
            2,
            "nothing else is classed: no per-box rule, no uid, no pid: {classify:?}"
        );
        let postrouting = chain_rules(&ruleset, "postrouting");
        assert!(
            !postrouting.iter().any(|rule| rule.contains("socket")),
            "postrouting translates by the mark: a socket-cgroup match there \
             is a rule the kernel has never loaded: {postrouting:?}"
        );
        let cohort_snat = format!(
            "ct mark and 0x{:08x} == 0x{cohort_bit:08x} oifname != \"lo\" snat ip to {}",
            TEST_CT_MARK_MASK, TEST_COHORT_ADDRESS
        );
        let node_plane_snat = format!(
            "ct mark and 0x{:08x} == 0x{node_bit:08x} oifname != \"lo\" snat ip to {}",
            TEST_CT_MARK_MASK, TEST_NODE_PLANE_ADDRESS
        );
        assert_eq!(
            postrouting.first(),
            Some(&cohort_snat.as_str()),
            "the cohort leaves as its own identity, translated by its bit: {postrouting:?}"
        );
        assert_eq!(
            postrouting.get(1),
            Some(&node_plane_snat.as_str()),
            "the node plane leaves as its own, translated by its own bit: {postrouting:?}"
        );
        assert_eq!(
            postrouting.len(),
            2,
            "nothing else is source-translated: no per-box rule, no uid, no pid: {postrouting:?}"
        );
    }

    /// NET-079: a box declared deny-all is placed under the subtree whose
    /// rule refuses every connection it opens — the deny subtree, and
    /// nothing else in its declaration can move it out or let another box
    /// in. The refusal is total: the box's leaf is a child of the subtree
    /// the refusing rule matches, and every process the box forks inherits
    /// the leaf, so nothing it spawns is under the match's level and
    /// outside its reach.
    #[test]
    fn host_ip_deny_all_no_outbound() {
        // The deny subtree is the declaration that admits no destination,
        // spelled the one shape that does: every `allow_*` dimension present
        // and empty.
        let deny_all = sessions::EgressPolicy::deny_all();
        assert_eq!(verdict_of(Some(&deny_all)), Verdict::Deny);

        // Nothing else gets the deny subtree. A declaration that admits
        // anything — an allowed subnet, an allowed protocol, an allowed
        // name — is placed under `allow`, so the refusing rule is never the
        // one a box that said what it wanted is held to; an absent section
        // is the default's to decide, never a deny-all.
        let reachable = sessions::EgressPolicy {
            allow_subnets: Some(vec!["10.0.0.0/8".to_string()]),
            ..deny_all.clone()
        };
        let names_only = sessions::EgressPolicy {
            allow_dns_hosts: Some(vec!["example.com".to_string()]),
            ..deny_all.clone()
        };
        let absent = None;
        for (declaration, why) in [
            (Some(&reachable), "a box that allows a subnet"),
            (Some(&names_only), "a box that allows a name"),
            (absent, "a box with no egress section"),
        ] {
            assert_eq!(
                verdict_of(declaration),
                Verdict::Allow,
                "{why} is placed under allow: the deny subtree refuses \
                 everything, and only a declaration that admits nothing is"
            );
        }

        // The leaf the deny-all verdict picks is inside the subtree the
        // refusing rule matches — a child of it, so the rule's match on the
        // subtree covers the box and every process it forks, which inherit
        // the cgroup and cannot fork their way out.
        let tree = tempfile::tempdir().expect("a temp dir standing in for the tree");
        let root = tree.path();
        let deny_subtree = root
            .join(sandbox2::classifier::BOXES_DIR)
            .join(sandbox2::config::DENY_DIR);
        let leaf = sandbox2::config::ClassifierLeaf::under(root, "a session", Verdict::Deny);
        assert_eq!(
            leaf.dir().parent(),
            Some(deny_subtree.as_path()),
            "the deny-all box's leaf is a child of the refusing subtree: {}",
            leaf.dir().display()
        );
        // The two cohorts are distinct: a deny-all box is never in the allow
        // subtree, and no other box is in its leaf — the leaf is named by
        // its session and sits in the subtree its declaration picked.
        assert_ne!(
            leaf.dir().parent(),
            Some(
                root.join(sandbox2::classifier::BOXES_DIR)
                    .join(sandbox2::config::ALLOW_DIR)
                    .as_path()
            ),
            "the deny-all box's leaf is in the deny subtree alone"
        );

        // The rendered table is what makes the subtree mean refusal, and
        // the whole placement above is what makes it mean it for *this*
        // box: the filter output chain routes every socket the deny
        // subtree holds — the box's leaf's own parent, so the box and
        // every process it forks, which inherit the cgroup and cannot
        // fork their way out — to `deny_out`, at the subtree's own depth
        // in the hierarchy.
        let rel = tree_root_name();
        let deny_subtree = format!(
            "{}/{}/{}",
            rel,
            sandbox2::classifier::BOXES_DIR,
            sandbox2::config::DENY_DIR
        );
        let ruleset = rendered_ruleset();
        let output = chain_rules(&ruleset, "output");
        let jump = format!(
            "socket cgroupv2 level {} \"{}\" jump deny_out",
            deny_subtree.split('/').count(),
            deny_subtree
        );
        assert!(
            output.contains(&jump.as_str()),
            "the output chain matches the deny subtree at its own level and \
             routes it to deny_out: {output:?}"
        );
        // The refusal is total on new connections and active on every
        // one: the chain ends in a rejection, and nothing in it drops —
        // a silent drop would hide the refused connections from a
        // diagnostics bundle's daemon log, the one place a person reads
        // them.
        let deny_out = chain_rules(&ruleset, "deny_out");
        assert_eq!(
            deny_out.last(),
            Some(&"reject with icmpx admin-prohibited"),
            "the deny chain ends in an active refusal: {deny_out:?}"
        );
        assert!(
            deny_out.iter().all(|rule| !rule.contains("drop")),
            "nothing in the deny chain drops: {deny_out:?}"
        );
    }

    /// NET-079: the one carve-out from a deny-all verdict is the address
    /// and port of the resolver Minimal owns for the box — one destination,
    /// not the loopback, and not the host's own resolver at DNS's port.
    /// Read off the table a host actually loads, because that table is the
    /// carve-out: a wider rule here is a wider rule in the box, and the
    /// daemon's own constants — the address the answerer serves at, the
    /// port it serves on — are what the rendered default must equal, not
    /// numbers restated beside them.
    #[test]
    fn host_ip_deny_all_reaches_only_the_answerer() {
        let ruleset = rendered_ruleset();
        let deny_out = chain_rules(&ruleset, "deny_out");

        // The answerer is admitted at its own address *and* port — the
        // destination the daemon serves the box zone from, so the rule a
        // host loads without asking names the same one the daemon answers
        // on. An address alone is the loopback baseline exception design
        // §4.1 rejects; a port alone matches anything on it.
        let answerer = format!(
            "ip daddr {ANSWERER_ADDRESS} udp dport {} accept",
            crate::net::answerer::ANSWERER_PORT
        );
        assert!(
            deny_out.contains(&answerer.as_str()),
            "the deny chain admits the answerer at its own address and port: {deny_out:?}"
        );

        // And nothing else is: the chain's accepts are the conntrack one —
        // the reply direction only, the one admission a box's answer to a
        // connection someone else opened needs, never a direction the box
        // originates — and the answerer's. Every other destination a
        // deny-all box's connections can name meets the rejection at the
        // chain's end, which is what makes the carve-out the *only* thing
        // the box reaches.
        let accepts: Vec<&str> = deny_out
            .iter()
            .filter(|rule| rule.ends_with("accept"))
            .copied()
            .collect();
        assert_eq!(
            accepts,
            [
                "ct state established,related ct direction reply accept",
                answerer.as_str()
            ],
            "the deny chain's accepts are the reply direction and the answerer's, \
             nothing else: {deny_out:?}"
        );
        assert!(
            !deny_out
                .iter()
                .any(|rule| rule.contains("127.0.0.1") && !rule.contains(&answerer)),
            "no rule admits the loopback wide: {deny_out:?}"
        );
    }

    /// The reply admission (NET-079, as the architecture review ruled it):
    /// a box's answer to a connection someone else opened is not egress the
    /// box originates, so the deny subtree's chain admits that one
    /// direction — and *only* it, before the deny verdict, in the deny
    /// subtree alone. A direction-less `ct state established` accept would
    /// admit a flow the box itself originated the moment conntrack holds it
    /// (loose tracking is the host's, never this table's to tighten), and
    /// the same admission in any other chain would admit replies a subtree
    /// never asked for.
    #[test]
    fn rendered_ruleset_admits_only_reply_direction_in_deny_subtree() {
        let ruleset = rendered_ruleset();
        let reply = "ct state established,related ct direction reply accept";
        let deny_out = chain_rules(&ruleset, "deny_out");
        let admitted = deny_out
            .iter()
            .position(|rule| *rule == reply)
            .unwrap_or_else(|| panic!("the deny chain admits the reply direction: {deny_out:?}"));
        let refused = deny_out
            .iter()
            .position(|rule| rule.starts_with("reject"))
            .unwrap_or_else(|| panic!("the deny chain carries its verdict: {deny_out:?}"));
        assert!(
            admitted < refused,
            "the reply is admitted before the deny verdict: {deny_out:?}"
        );

        // Only the reply direction: the chain's one conntrack admission
        // names the direction it admits, so no direction-less accept — and
        // no explicit original one — can be built from the text a host
        // loads. What the box itself originates still meets the verdict.
        for rule in &deny_out {
            if rule.contains("ct state") {
                assert_eq!(
                    *rule, reply,
                    "the chain's one conntrack admission is the reply direction: {deny_out:?}"
                );
            }
            assert!(
                !rule.contains("ct direction original"),
                "the original direction is never admitted, so a flow the box \
                 itself originates is refused: {deny_out:?}"
            );
        }

        // And in the deny subtree only: no other chain carries a
        // conntrack-direction admission, and the one route into the deny
        // chain is the jump the deny subtree's own match makes — an allow
        // box's replies never pass through a chain that could refuse them.
        for chain in ["output", "dstnat", "classify", "postrouting"] {
            let rules = chain_rules(&ruleset, chain);
            assert!(
                rules.iter().all(|rule| !rule.contains("ct direction")),
                "the reply admission lives in the deny chain alone, not {chain}: {rules:?}"
            );
        }
        let output = chain_rules(&ruleset, "output");
        assert_eq!(
            output.len(),
            1,
            "the output chain does one thing, route a cgroup to its chain: {output:?}"
        );
        assert!(
            output[0].contains(sandbox2::config::DENY_DIR) && output[0].ends_with("jump deny_out"),
            "the one jump is the deny subtree's, so nothing else is decided \
             against a deny-all box: {output:?}"
        );
    }

    /// NET-079, as the architecture review ruled it: a deny-all
    /// host-address box with a listener answers a request through the
    /// hostname proxy, while its own outbound connect is still refused. The
    /// request's leg is driven live, end to end, through the proxy the
    /// daemon serves — a host-address box serves on the host's loopback, the
    /// name routes there, and the proxy's dial is the daemon's own, outside
    /// the cohort — and the box's half of that connection, its answer leg,
    /// is the reply direction the table has to admit for the request to
    /// ever be answered: without that admission the client hangs on a box
    /// whose SYN-ACK never left it, and with an admission any wider the box
    /// originates flows the deny was written to refuse.
    #[tokio::test]
    async fn deny_all_host_ip_box_answers_the_proxy() {
        // The box's declaration is the deny-all one, so its leaf is in the
        // subtree whose chain every rule below is read from — the verdict
        // the launch's own placement would pick for this box.
        let deny_all = sessions::EgressPolicy::deny_all();
        assert_eq!(verdict_of(Some(&deny_all)), Verdict::Deny);

        // The box's listener, on the loopback a host-address box shares with
        // its host, and the daemon's proxy serving the zone the box's name
        // lives in — the pieces the request runs over, as they run in the
        // daemon.
        let backend_port = crate::net::proxy::spawn_backend().await;
        let registry = std::sync::Arc::new(std::sync::RwLock::new(
            crate::net::dns::HostnameRegistry::new("dev", false),
        ));
        registry
            .write()
            .unwrap()
            .register_host_net(sessions::SessionId::nil(), "denybox");
        let router = crate::net::proxy::Router::new(
            std::sync::Arc::clone(&registry),
            crate::net::switch::proxied_request_verdict,
        );
        let proxy = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("the proxy binds a loopback port");
        let proxy_addr = proxy.local_addr().expect("the proxy's address");
        tokio::spawn(crate::net::proxy::serve(proxy, router));
        let answered = crate::net::proxy::proxy_get(
            proxy_addr,
            &format!("denybox.min.internal:{backend_port}"),
        )
        .await;
        assert!(
            answered.contains("200 OK"),
            "a request through the hostname proxy reaches the deny-all box's \
             listener and is answered, got: {answered}"
        );

        // The table's half of the same connection: the proxy opened it, so
        // the box's answer leg is the reply direction, and the chain admits
        // exactly that — before its verdict, so the answer leaves the box
        // — while nothing the box itself originates is admitted, so the
        // connect it opens meets the refusal the declaration asked for.
        let ruleset = rendered_ruleset();
        let deny_out = chain_rules(&ruleset, "deny_out");
        let reply = "ct state established,related ct direction reply accept";
        let admitted = deny_out
            .iter()
            .position(|rule| *rule == reply)
            .unwrap_or_else(|| panic!("the box's answer leg is admitted: {deny_out:?}"));
        let refused = deny_out
            .iter()
            .position(|rule| rule.starts_with("reject"))
            .unwrap_or_else(|| panic!("the deny chain carries its verdict: {deny_out:?}"));
        assert!(
            admitted < refused,
            "the reply is admitted before the deny verdict, so the box's \
             answer to the proxy's connection leaves it: {deny_out:?}"
        );
        assert_eq!(
            deny_out
                .iter()
                .filter(|rule| rule.contains("ct state"))
                .count(),
            1,
            "one conntrack admission, the reply direction, and nothing the box \
             originates: {deny_out:?}"
        );
        assert_eq!(
            deny_out.last(),
            Some(&"reject with icmpx admin-prohibited"),
            "a connect the box itself opens is refused, actively: {deny_out:?}"
        );
    }

    /// Whether a rendered `socket cgroupv2 level <N> "<path>"` match covers
    /// `cgroup`: the kernel's own prefix semantics, which is what decides
    /// whether a rule in the loaded table reaches a leaf — the first N
    /// components of the socket's cgroup equal the N components the match's
    /// path names, so a rule reaches a leaf at that depth and every leaf
    /// under it, and no leaf whose own path diverges inside those components.
    fn cgroup_match_covers(rule: &str, cgroup: &str) -> bool {
        let level = rule
            .split("level ")
            .nth(1)
            .and_then(|rest| rest.split(' ').next())
            .and_then(|level| level.parse::<usize>().ok())
            .unwrap_or_else(|| panic!("a rendered match names its level: {rule}"));
        let named = rule
            .split('"')
            .nth(1)
            .unwrap_or_else(|| panic!("a rendered match names its cgroup path: {rule}"))
            .split('/')
            .collect::<Vec<_>>();
        assert_eq!(
            named.len(),
            level,
            "the rendered match's level is the depth of the path it names: {rule}"
        );
        let of = cgroup.split('/').collect::<Vec<_>>();
        of.len() >= level && of[..level] == named[..]
    }

    /// Captures what this process writes to its log, so a test can read the
    /// record the way a diagnostics bundle's daemon-log tail does.
    #[derive(Clone, Default)]
    struct LogCapture(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    impl LogCapture {
        fn contents(&self) -> String {
            String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
        }
    }

    impl std::io::Write for LogCapture {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl tracing_subscriber::fmt::MakeWriter<'_> for LogCapture {
        type Writer = LogCapture;
        fn make_writer(&self) -> Self::Writer {
            self.clone()
        }
    }

    /// NET-080: the daemon's own package fetch survives a deny-all
    /// host-address box on the same host, and is recorded as node-plane
    /// traffic. Both halves are driven over the one tree: the box is
    /// *resident* — its declaration is the one that admits no destination,
    /// its leaf in the deny subtree — and the daemon is in its own leaf,
    /// entered the way it enters it at start, from which the connection a
    /// fetch makes completes. The rendered table is why it completes: the
    /// one rule that refuses matches the deny subtree by cgroup path, and
    /// the daemon's leaf is not under that path, while the classify chain's
    /// two rules divide the leaves between them — the cohort's rule, the
    /// chain's first, which sets the final mark, covers the box's leaf and
    /// never the daemon's, and the node plane's own rule, guarded by the
    /// mask, matches the daemon's leaf, so the fetch is classed as the node
    /// plane's and leaves as its identity (the root lane's
    /// `snat_identity_is_seen_by_the_peer` reads that identity at a real
    /// peer, under a loaded table). The record is the half a person reads:
    /// one info line per fetch, with the box it was made for, the host
    /// fetched, the leaf it left from, and the object, because a fetch that
    /// completes says nothing about which identity carried it.
    #[test]
    fn daemon_fetch_survives_cohort_deny() {
        // The tree as a host has it: the step's subtrees, the loaded table's
        // marker with its recorded mask, and one deny-all host-address box
        // resident in the deny subtree.
        let mount = standin_mount();
        let root = mount.root.clone();
        installed_cohort(&root);
        let deny_all = sessions::EgressPolicy::deny_all();
        assert_eq!(
            verdict_of(Some(&deny_all)),
            Verdict::Deny,
            "the resident box is declared deny-all, so its leaf sits in the \
             subtree the refusing rule matches"
        );
        let resident = sandbox2::classifier::create_box_leaf(&root, "a session", Verdict::Deny)
            .expect("the launch makes the deny-all box's leaf");

        // The daemon's own leaf, entered the way the daemon enters it at
        // start. Over the stand-in tree the entry is the placement the daemon
        // performs — its own pid into its leaf's `cgroup.procs` — and the
        // leaf needs the delegation-contract files modelled into it, because
        // nothing behind the stand-in makes them at mkdir.
        let daemon = sandbox2::classifier::daemon_leaf(&root);
        std::fs::create_dir_all(&daemon).expect("the step makes the daemon's own leaf");
        model_delegation_files(&daemon);
        sandbox2::classifier::enter_daemon_leaf(&root)
            .expect("the daemon enters its own leaf, in the tree the box is resident in");

        // The fetch's leg: a connection the daemon opens from its own leaf,
        // to the listener this test holds standing in for the registry host
        // its packages come from. Over the stand-in tree the leg shows the
        // daemon's placement and nothing more — its leaf sits beside the
        // cohort, so the tree's own layout confines nothing the daemon does
        // — and claims nothing about enforcement, because no table is
        // loaded here. What a loaded table does with the same leaves is the
        // rendered ruleset below, and the live leg under one is the root
        // lane's `snat_identity_is_seen_by_the_peer`, which reads the
        // identity the fetch leaves as at a real peer.
        let registry = TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .expect("a loopback listener standing in for the registry host");
        let fetched = registry.local_addr().expect("the registry host's address");
        let fetch = TcpStream::connect(fetched).expect(
            "the daemon opens the fetch's connection from its own leaf, \
             which sits beside the cohort rather than inside it",
        );
        drop(fetch);

        // The rendered spelling of a cgroup on this tree, relative to the
        // cgroup2 mount the table renders its matches from, so the paths
        // below and the paths in the table are the same paths.
        let mount_root = mount
            .root
            .parent()
            .expect("the tree root sits on the cgroup2 mount")
            .to_path_buf();
        let rendered = |cgroup: &Path| {
            cgroup
                .strip_prefix(&mount_root)
                .expect("the cgroup is under the mount the table renders from")
                .to_string_lossy()
                .into_owned()
        };
        let box_path = rendered(&resident);
        let daemon_path = rendered(&daemon);

        // The refusing rule reaches the box and not the daemon: it matches
        // the deny subtree the resident box's leaf is in, at the level the
        // kernel prefixes by, and the daemon's leaf diverges from that path a
        // component above it — the sibling-of-the-cohort placement
        // `enter_daemon_leaf` performs is what makes that so.
        let ruleset = rendered_ruleset();
        let output = chain_rules(&ruleset, "output");
        assert_eq!(
            output.len(),
            1,
            "one rule refuses, the deny subtree's: {output:?}"
        );
        let refusing = output[0];
        let deny_subtree = rendered(
            resident
                .parent()
                .expect("the box's leaf sits in the deny subtree"),
        );
        assert!(
            refusing.contains(&format!("\"{deny_subtree}\"")),
            "the refusing rule matches the deny subtree the resident box's leaf \
             is in: {refusing}"
        );
        assert!(
            cgroup_match_covers(refusing, &box_path),
            "the refusing rule reaches the deny-all box's own leaf ({box_path}): {refusing}"
        );
        assert!(
            !cgroup_match_covers(refusing, &daemon_path),
            "the refusing rule cannot reach the daemon's leaf ({daemon_path}), \
             so no connection the daemon opens is routed into the chain that \
             refuses: {refusing}"
        );

        // The classify chain's two rules divide the leaves between them, and
        // the cohort's is the one that decides for boxes: it is the chain's
        // first rule — the one the node plane's is guarded not to re-decide,
        // so the mark it sets is final — and it matches the cohort at the
        // level the daemon's leaf diverges above, so it covers the box's
        // leaf and never the daemon's. A cohort rule rendered at the slice
        // instead would take the daemon's leaf in with it, and these are the
        // assertions that fail when it does.
        let classify = chain_rules(&ruleset, "classify");
        let cohort = classify.first().copied().unwrap_or_else(|| {
            panic!("the cohort is classed by the chain's first rule: {classify:?}")
        });
        assert!(
            cgroup_match_covers(cohort, &box_path),
            "the cohort's classify rule, the final mark's setter, covers the \
             deny-all box's leaf ({box_path}): {cohort}"
        );
        assert!(
            !cgroup_match_covers(cohort, &daemon_path),
            "the cohort's classify rule cannot cover the daemon's leaf \
             ({daemon_path}), so the daemon's fetch is never classed as the \
             cohort's: {cohort}"
        );

        // The node plane's own rule does match the daemon's leaf, so the
        // fetch is classed as the node plane's — the half the cohort's rule
        // decides for boxes, decided here for the daemon, and the identity
        // the fetch leaves as.
        let node_plane = classify
            .iter()
            .find(|rule| rule.contains(&format!("\"{}\"", tree_root_name())))
            .unwrap_or_else(|| panic!("the node plane is classed by its own rule: {classify:?}"));
        assert!(
            cgroup_match_covers(node_plane, &daemon_path),
            "the node plane's rule matches the daemon's own leaf \
             ({daemon_path}), so the daemon's fetch is classed as the node \
             plane's: {node_plane}"
        );

        // The record, one line per fetch: the leg above is the fetch, made
        // for the resident box, and the daemon records it with the box, the
        // host it fetched, the object, and the leaf the fetch left from —
        // read here the way the daemon reads it at install time, off the
        // placement the entry above made of this very process, so the
        // record's leaf claim is a fact the tree states and not a constant
        // it asserts wherever it runs. Here the address the leg went to and
        // the package it brought back, then a second fetch, of the
        // registry's index, to a named host, so the per-fetch half is pinned
        // and not only the spelling. The box is named the way the tree names
        // it, by its leaf. Read the way a bundle's daemon-log tail reads it:
        // two fetches, two lines, each at info, each naming its own host, the
        // leaf the fetch left from, the box it was made for, and the object.
        let box_id = resident
            .file_name()
            .and_then(|n| n.to_str())
            .expect("the box's leaf is named with its id")
            .to_owned();
        let leaf = daemon_fetch_leaf(&root);
        assert_eq!(
            leaf,
            Some(sandbox2::classifier::DAEMON_LEAF),
            "the daemon that entered its own leaf above reads back as in it, \
             which is the premise the record's leaf field is about to claim"
        );
        let log = LogCapture::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(log.clone())
            .with_ansi(false)
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);
        let second = "pkgs.min.internal";
        let fetched_object = "jq";
        let second_object = "index";
        record_node_plane_fetch(&box_id, leaf, &fetched.to_string(), fetched_object);
        record_node_plane_fetch(&box_id, leaf, second, second_object);
        let recorded = log.contents();
        let lines: Vec<&str> = recorded
            .lines()
            .filter(|line| line.contains("node-plane traffic"))
            .collect();
        assert_eq!(
            lines.len(),
            2,
            "one record per fetch, two fetches: {recorded}"
        );
        for (line, (host, object)) in lines.iter().zip([
            (&fetched.to_string(), fetched_object),
            (&second.to_string(), second_object),
        ]) {
            assert!(
                line.contains("INFO"),
                "the record is at the level a bundle's tail reads: {line}"
            );
            assert!(
                line.contains(host.as_str()),
                "the record names the host fetched: {line}"
            );
            assert!(
                line.contains(sandbox2::classifier::DAEMON_LEAF),
                "the record names the leaf the fetch left from: {line}"
            );
            assert!(
                line.contains(box_id.as_str()),
                "the record names the box the fetch was made for: {line}"
            );
            assert!(
                line.contains(object),
                "the record names the object fetched: {line}"
            );
        }
        assert!(
            lines[0].contains(&fetched.to_string()) && !lines[0].contains(second),
            "the first record is the first fetch, not a summary: {lines:?}"
        );
    }

    /// NET-080: the record's leaf field is the one claim in it about the
    /// host rather than about the fetch, so it is made only where it holds.
    /// A daemon standing in its own leaf is recorded as fetching from it;
    /// one that is not — a host without the step's tree, or a daemon its
    /// `--pid` step has not placed in one — is recorded as fetching in its
    /// own process and naming no leaf, because that is what happened: a
    /// person reading a bundle on such a host must not be told the fetch
    /// left a leaf no tree there holds, and `daemon_fetch_leaf` is what
    /// keeps the record from saying it.
    #[test]
    fn a_record_names_a_leaf_only_where_the_daemon_stands_in_one() {
        // The tree as a host has it, and this process is placed in its own
        // leaf the way the daemon is at start: the leaf the record then
        // names, read off the placement rather than assumed of any host.
        let mount = standin_mount();
        let root = mount.root.clone();
        installed_cohort(&root);
        let daemon = sandbox2::classifier::daemon_leaf(&root);
        std::fs::create_dir_all(&daemon).expect("the step makes the daemon's own leaf");
        model_delegation_files(&daemon);

        // The half every unclassified host runs on: the leaf is there and
        // this daemon is not in it, so no leaf of the daemon's own exists
        // and the record says so instead of naming one. The line still
        // carries the fetch's own three — the box, the host, the object —
        // and the claim that holds on every host: the fetch was the
        // daemon's own process's, never the box's.
        assert_eq!(
            daemon_fetch_leaf(&root),
            None,
            "a daemon outside its own leaf has no leaf of its own to name, \
             which is the fact the record below must spell rather than assume"
        );
        let (log, guard) = capture_node_plane_log();
        record_node_plane_fetch(
            "a session",
            daemon_fetch_leaf(&root),
            "cache.min.internal",
            "jq",
        );
        let unplaced = the_one_record(&log);
        assert!(
            unplaced.contains("INFO"),
            "the record is at the level a bundle's tail reads: {unplaced}"
        );
        assert!(
            !unplaced.contains("leaf="),
            "the record names no leaf where the daemon stands in none: {unplaced}"
        );
        assert!(
            unplaced.contains("stands in no classifier leaf of its own"),
            "the record says why it names no leaf, so the absence reads as a \
             fact about the host and not as a field that went missing: {unplaced}"
        );
        assert!(
            unplaced.contains("never the box's"),
            "the claim that holds on every host is made on this one too: {unplaced}"
        );
        for needle in ["box_id=a session", "host=cache.min.internal", "object=jq"] {
            assert!(
                unplaced.contains(needle),
                "the record still names the {needle} of the fetch: {unplaced}"
            );
        }
        drop(guard);

        // The entry the daemon performs at start, over the same tree: the
        // leaf read turns, and the line with it — the fetch is now recorded
        // as leaving from the leaf the tree holds for it, beside the cohort.
        sandbox2::classifier::enter_daemon_leaf(&root)
            .expect("the daemon enters its own leaf over the stand-in tree");
        assert_eq!(
            daemon_fetch_leaf(&root),
            Some(sandbox2::classifier::DAEMON_LEAF),
            "the daemon that entered its leaf reads back as in it"
        );
        let (log, guard) = capture_node_plane_log();
        record_node_plane_fetch(
            "a session",
            daemon_fetch_leaf(&root),
            "cache.min.internal",
            "jq",
        );
        let placed = the_one_record(&log);
        assert!(
            placed.contains("leaf=daemon"),
            "the record names the leaf the fetch left from, where the daemon \
             stands in one: {placed}"
        );
        assert!(
            placed.contains("from its own leaf beside the cohort"),
            "the record claims the leaf-beside-the-cohort placement where \
             there is a leaf to claim it from: {placed}"
        );
        drop(guard);

        // The host without the step at all: no tree, so no leaf to read and
        // none to name — the same line as the unplaced daemon's, read the
        // same way by a bundle's tail on a host that never ran the install.
        let bare = tempfile::tempdir().expect("a bare stand-in tree, nothing installed in it");
        let slice = std::path::Path::new(sandbox2::classifier::TREE_ROOT)
            .file_name()
            .expect("the tree root is a path with a name");
        assert_eq!(
            daemon_fetch_leaf(&bare.path().join(slice)),
            None,
            "a host without the step's tree has no leaf of the daemon's"
        );
    }

    /// Captures this thread's log, the way the record's tests read the line
    /// a bundle's daemon-log tail reads it.
    fn capture_node_plane_log() -> (LogCapture, tracing::subscriber::DefaultGuard) {
        let log = LogCapture::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(log.clone())
            .with_ansi(false)
            .finish();
        let guard = tracing::subscriber::set_default(subscriber);
        (log, guard)
    }

    /// The one node-plane record a captured log holds, or a panic naming
    /// everything it holds instead.
    fn the_one_record(log: &LogCapture) -> String {
        let recorded = log.contents();
        let lines: Vec<&str> = recorded
            .lines()
            .filter(|line| line.contains("node-plane traffic"))
            .collect();
        assert_eq!(lines.len(), 1, "one record for one fetch: {recorded}");
        lines[0].to_owned()
    }

    /// NET-080: the host each fetch's record names, read from the location
    /// the configured remote cache takes. The mirror's is the URL's own
    /// host — the parsed host, with neither the path nor the scheme spelled
    /// beside it, and the port carried only when it is not https's own
    /// default, the one rule every fetch kind's host field keeps — and the
    /// GCS location's is the bucket it names, the spelling `mctx` resolves
    /// `gs://…` and a bare bucket name into. Both spellings are what a
    /// person reading a bundle's daemon-log tail matches the fetch
    /// against, so a host read out of a rendering of the URL rather than
    /// out of the URL itself is a host the record can silently stop
    /// naming.
    #[test]
    fn cache_host_reads_https_host_and_gcs_bucket() {
        // The mirror's own non-default port, kept: a fetch to port 8443
        // and one to the default are two different fetches, and the
        // record's one port rule names them apart.
        let mirror = AnyUrl::Https(
            common::fetchers::ReqwestUrl::try_from(
                "https://cache.example.com:8443/prefix/index.shisha",
            )
            .expect("the configured remote cache's mirror URL parses"),
        );
        assert_eq!(
            cache_host(&mirror),
            "cache.example.com:8443",
            "the mirror's host keeps its own non-default port: the path is \
             never part of the host a fetch leaves for, but a port is"
        );
        // The scheme's own default, dropped by the same one rule the
        // source-URL spelling below is read by: a default port is a fact
        // the scheme already says, so the field never carries it.
        let default = AnyUrl::Https(
            common::fetchers::ReqwestUrl::try_from(
                "https://cache.example.com:443/prefix/index.shisha",
            )
            .expect("the default-port mirror URL parses"),
        );
        assert_eq!(
            cache_host(&default),
            "cache.example.com",
            "the mirror's host drops https's own default port: 443 is what \
             the scheme already says"
        );
        let bare = AnyUrl::Https(
            common::fetchers::ReqwestUrl::try_from("https://cache.example.com/prefix/index.shisha")
                .expect("the portless mirror URL parses"),
        );
        assert_eq!(
            cache_host(&bare),
            "cache.example.com",
            "a mirror that spells no port is named without one"
        );
        let ipv6 = AnyUrl::Https(
            common::fetchers::ReqwestUrl::try_from("https://[::1]:8080/prefix/index.shisha")
                .expect("the IPv6 mirror URL parses"),
        );
        assert_eq!(
            cache_host(&ipv6),
            "[::1]:8080",
            "host_str keeps an IPv6 mirror's brackets, so its port reads apart from the address"
        );
        assert_eq!(
            cache_host(&ipv6),
            url_host("https://[::1]:8080/prefix/index.shisha"),
            "the cache and source spellings agree for the same IPv6 host"
        );
        let bucket = AnyUrl::Gcs(common::fetchers::GcsUrl {
            bucket: "projects/_/buckets/minimal-cache".to_string(),
            object: String::new(),
        });
        assert_eq!(
            cache_host(&bucket),
            "projects/_/buckets/minimal-cache",
            "a GCS location's host is the bucket it names"
        );
    }

    /// NET-080: the two spellings a `FetchSource` URL's record carries — the
    /// host it names and the object it is recorded as — never carry the
    /// parts of the URL that must not reach a log line. The record is an
    /// INFO line a bundle's daemon-log tail keeps on disk, and a source URL
    /// can carry a credential in its userinfo (`https://<token>@github.com/…`)
    /// and a signature in its query (`?X-Amz-Signature=…`), so the host is
    /// the URL's authority minus its userinfo and the object is its spelling
    /// minus the userinfo, the query, and the fragment. The port rides the
    /// one rule every fetch kind's host field keeps — kept when it is not
    /// the scheme's own default, dropped when it is, the same rule the
    /// cache's host is spelled by — and that rule is the host field's
    /// alone: the object keeps the URL's own spelling. A source with no
    /// scheme — a tarball off the operator's own disk — names no host and
    /// crosses no network, and stays the object whole.
    #[test]
    fn url_host_and_object_carry_no_credentials() {
        // A credential in the userinfo, before the host a GitHub source
        // fetch actually leaves for.
        let tokened = "https://ghp_deadbeef@github.com/example/example/archive/v1.tar.gz";
        assert_eq!(
            url_host(tokened),
            "github.com",
            "the host is the authority minus its userinfo, so the token never \
             reaches the record: {}",
            url_host(tokened)
        );
        assert_eq!(
            url_object(tokened),
            "https://github.com/example/example/archive/v1.tar.gz",
            "the object is the URL minus its userinfo, so the token never \
             reaches the record: {}",
            url_object(tokened)
        );
        // A login pair, a port, a query, and a fragment: each is dropped or
        // kept by what it is, not by where it sits.
        let signed = "https://user:pass@mirror.example.com:8443/src/v2.tar.gz?X-Amz-Signature=deadbeef#fragment";
        assert_eq!(
            url_host(signed),
            "mirror.example.com:8443",
            "the host keeps the port and drops the login pair before it"
        );
        assert_eq!(
            url_object(signed),
            "https://mirror.example.com:8443/src/v2.tar.gz",
            "the object keeps the host and port and drops the login pair, the \
             query, and the fragment"
        );
        // Each scheme's own default port, dropped by the same one rule the
        // cache's host is spelled by — while the object keeps the URL's
        // whole spelling, because the port rule is the host field's.
        let https_default = "https://mirror.example.com:443/src/v2.tar.gz";
        assert_eq!(
            url_host(https_default),
            "mirror.example.com",
            "the host drops https's own default port: 443 is what the scheme \
             already says"
        );
        assert_eq!(
            url_object(https_default),
            "https://mirror.example.com:443/src/v2.tar.gz",
            "the object keeps the URL's spelling whole minus what must not be \
             logged: the port rule is the host field's alone"
        );
        let http_default = "http://mirror.example.com:80/src/v2.tar.gz";
        assert_eq!(
            url_host(http_default),
            "mirror.example.com",
            "the host drops http's own default port, the same one rule"
        );
        let http_kept = "http://mirror.example.com:8080/src/v2.tar.gz";
        assert_eq!(
            url_host(http_kept),
            "mirror.example.com:8080",
            "the host keeps http's non-default port the same way it keeps \
             https's: one rule for every fetch kind"
        );
        // A URL with nothing to drop is spelled whole in both fields.
        let plain = "https://example.com/src/v3.tar.gz";
        assert_eq!(url_host(plain), "example.com");
        assert_eq!(url_object(plain), "https://example.com/src/v3.tar.gz");
        // A local source names no host and is the object whole.
        let local = "../tarballs/v4.tar.gz";
        assert_eq!(url_host(local), "", "a local source names no host");
        assert_eq!(
            url_object(local),
            "../tarballs/v4.tar.gz",
            "a local source stays the object whole"
        );
    }

    /// The one rendered text, in both lanes that load it: the install's own
    /// `nft -f` transaction — the bytes a native host's privileged step
    /// pipes to the packet filter — and the print mode's output, the text a
    /// guest load renders from and the daemon's own tests read. Both come
    /// from `render_ruleset` and neither spells a rule the other does not,
    /// so a digest over each must be the same digest: a rule added to one
    /// lane and not the other is a host whose two spellings of the same
    /// table disagree. Read by driving the install itself, over a
    /// recording stand-in for `nft`, so what is compared is what the step
    /// really hands the packet filter — and the reply admission this round
    /// added is part of that one text.
    #[test]
    fn ruleset_digest_covers_bytes_piped_to_nft_in_both_lanes() {
        // A recording stand-in for `nft`: the packet filter is the step's
        // own dependency, and what a test can pin of it without the
        // capability to load one is the bytes it was handed, captured whole
        // — the same capture the step's own installer case reads.
        let stub = tempfile::tempdir().expect("a temp dir holding the recording nft");
        std::fs::write(
            stub.path().join("nft"),
            "#!/bin/sh\n\
             [ \"$1\" = \"-f\" ] && [ -n \"${2:-}\" ] && cat \"$2\" >\"${0%/*}/nft.input\"\n\
             exit 0\n",
        )
        .expect("writing the recording stub");
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(
                stub.path().join("nft"),
                std::fs::Permissions::from_mode(0o755),
            )
            .expect("the recording stub is executable");
        }
        let mount = standin_mount();
        // The install lane: the step lays out its stand-in tree, renders its
        // one transaction, and hands it to `nft` — the recording one, so
        // the bytes it was handed are this proof's own artifact. The step
        // refuses to delegate its tree to root, so a test running as root
        // cannot rehearse an install at all — the root check the rehearsal
        // posture lifts is the only privilege it does. Say so and pin the
        // print lane alone, which needs none of this.
        let installed = match run_install(&mount, stub.path()) {
            Some(installed) => installed,
            None => {
                eprintln!(
                    "skipping ruleset_digest_covers_bytes_piped_to_nft_in_both_lanes: \
                     the install this lane rehearses refuses to delegate its tree \
                     to root, and this test runs as root"
                );
                let printed = rendered_ruleset();
                assert!(
                    printed.contains("ct state established,related ct direction reply accept"),
                    "the reply admission is part of the one rendered text: {printed}"
                );
                return;
            }
        };
        assert!(
            installed.status.success(),
            "the install lays out its tree and hands its one transaction to nft: {}{}",
            String::from_utf8_lossy(&installed.stdout),
            String::from_utf8_lossy(&installed.stderr),
        );
        let piped = std::fs::read_to_string(stub.path().join("nft.input"))
            .expect("the recording stub captured the bytes nft was handed");

        // The print lane: the same transaction as text.
        let printed = rendered_ruleset();
        assert_eq!(
            blake3::hash(piped.as_bytes()),
            blake3::hash(printed.as_bytes()),
            "the bytes piped to nft are the one rendered text in both lanes:\n\
             -- piped --\n{piped}-- printed --\n{printed}"
        );
        assert!(
            piped.contains("ct state established,related ct direction reply accept"),
            "the reply admission is part of the one rendered text: {piped}"
        );
    }

    /// The reading a loaded table gives: every family the probe read,
    /// refused with an errno in the reject set — the pair the design says
    /// the two loopbacks read (`icmpx admin-prohibited` as EHOSTUNREACH
    /// over IPv4, EACCES over IPv6, design §4.1). Handed to [`decide`] as
    /// the probe's answer, so the facts that gate it are pinned against a
    /// reading that would decide anything it was handed.
    fn refused_reading() -> Reading {
        Reading::Refused(vec![
            (Family::V4, Observed::Refused(libc::EHOSTUNREACH)),
            (Family::V6, Observed::Refused(libc::EACCES)),
        ])
    }

    /// The check names the cause, and the cause names the remedy — or says,
    /// by naming none, that there is not one to run: the step's own
    /// install ends the step-not-installed cause on a native host (NET-079
    /// names that one), while a host that cannot confine a box, a probe
    /// that could not read the table, and a guest whose image never loaded
    /// the table have no command, because running one would leave each
    /// cause standing. The facts gate the probe, so every undecidable cause
    /// below is pinned against a reading that would have decided per box —
    /// a refusal the probe never observed cannot rescue a tree that fails
    /// its facts. The cause and the command are spelled once in [`Cause`],
    /// so they are pinned here as data.
    #[test]
    fn decide_names_the_cause_and_the_command_that_ends_it() {
        let tree = tempfile::tempdir().expect("a temp dir standing in for the tree");
        let root = tree.path();

        // A host whose cgroup2 covers the tree without `nsdelegate` cannot
        // confine a box, whatever kind of host it is — the cause is the
        // confinement, on native and guest alike, and no command ends it.
        let undelegated = decide(root, Some(&mountinfo(root, false)), false, refused_reading);
        assert!(
            !undelegated.can_decide_per_box(),
            "a cgroup2 without nsdelegate decides nothing per box"
        );
        let cause = undelegated.cause().expect("the cause is named");
        assert_eq!(cause, Cause::CannotConfine, "the cause is the confinement");
        assert!(
            cause.install_command().is_none(),
            "no install command is named for a host that cannot confine a box"
        );
        assert_eq!(
            decide(root, Some(&mountinfo(root, false)), true, refused_reading).cause(),
            Some(Cause::CannotConfine),
            "the guest answers the confinement question the same way"
        );

        // A confining host with no step installed names the step, with the
        // exact command that installs it.
        let step_missing = decide(root, Some(&mountinfo(root, true)), false, refused_reading);
        let cause = step_missing
            .cause()
            .expect("a host with no step names the step");
        assert_eq!(
            cause,
            Cause::StepNotInstalled,
            "the subtrees and the marker are the step's to install"
        );
        let command = cause
            .install_command()
            .expect("the step's cause is the one a command ends");
        assert!(
            command.contains("install-host-classifier.sh"),
            "the command is the privileged step's install: {command}"
        );
        assert!(
            command.contains("sudo bash ./install-host-classifier.sh"),
            "the command is the one a person runs, spelled exactly: {command}"
        );

        // The same shape in a guest names its own image's half instead:
        // the tree and the table were its boot's work, and guest-side
        // classifier enforcement is not available yet, so a missing table
        // is the interim rather than a broken image — and no installer
        // exists inside a microVM, so no command is named for a person who
        // cannot run one.
        let guest_unloaded = decide(root, Some(&mountinfo(root, true)), true, refused_reading);
        assert_eq!(
            guest_unloaded.cause(),
            Some(Cause::GuestTableNotLoaded),
            "the guest's missing table is its image's own half"
        );
        let detail = guest_unloaded.cause().expect("the cause is named").detail();
        assert!(
            detail.contains("not available yet"),
            "the guest's cause names the interim: {detail}"
        );
        assert!(
            !detail.contains("broken"),
            "the interim is not a broken image: {detail}"
        );
        assert!(
            !guest_unloaded.can_decide_per_box(),
            "a guest whose table is not loaded decides nothing per box, \
             whatever its tree looks like"
        );
        assert!(
            guest_unloaded
                .cause()
                .expect("the cause is named")
                .install_command()
                .is_none(),
            "no install command is named inside a guest"
        );

        // The marker alone is not what says the table is in force: a host
        // with the subtrees but no marker has no refusal installed, and a
        // deny-all box there would run as though refused when nothing is
        // — for a guest, that is the state a launch refuses rather than
        // places (design §7.1).
        installed_cohort(root);
        std::fs::remove_dir_all(root.join(sandbox2::classifier::TABLE_MARKER))
            .expect("removing the marker");
        assert_eq!(
            decide(root, Some(&mountinfo(root, true)), false, refused_reading).cause(),
            Some(Cause::StepNotInstalled),
            "the table's marker is the step's half too, on the native host"
        );
        assert_eq!(
            decide(root, Some(&mountinfo(root, true)), true, refused_reading).cause(),
            Some(Cause::GuestTableNotLoaded),
            "and the guest's subtrees alone do not decide anything per box \
             in it either"
        );

        // The marker's record is the other half of its own fact: the step
        // writes the ct-mark mask it classifies with beside the marker, so
        // a marker without its record is a step that did not finish — and
        // a probe that cannot read the classification reads the step as
        // not installed, never as installed on the strength of a marker
        // whose table's bits it cannot name.
        std::fs::remove_dir_all(root.join(TEST_CT_MARK_RECORD))
            .expect("removing the recorded mask");
        std::fs::create_dir_all(root.join(sandbox2::classifier::TABLE_MARKER))
            .expect("the step writes the table's marker");
        assert_eq!(
            decide(root, Some(&mountinfo(root, true)), false, refused_reading).cause(),
            Some(Cause::StepNotInstalled),
            "a marker without the recorded mask beside it decides nothing \
             per box: the step did not finish"
        );
        std::fs::create_dir_all(root.join(TEST_CT_MARK_RECORD))
            .expect("the step records the mask beside the marker");
        // A record the probe cannot parse is no record: the classification
        // it would name is unreadable, and an unreadable classification is
        // not one a verdict can rest on.
        std::fs::rename(
            root.join(TEST_CT_MARK_RECORD),
            root.join("ct-mark-mask-not-a-mask"),
        )
        .expect("malforming the recorded mask");
        assert_eq!(
            decide(root, Some(&mountinfo(root, true)), false, refused_reading).cause(),
            Some(Cause::StepNotInstalled),
            "a recorded mask the probe cannot parse is no classification"
        );
        std::fs::rename(
            root.join("ct-mark-mask-not-a-mask"),
            root.join(TEST_CT_MARK_RECORD),
        )
        .expect("restoring the recorded mask");
        // Two records naming different bits are the state a half-finished
        // re-install leaves, and the one value the table classifies by
        // cannot be told from either: the step reads as not installed.
        std::fs::create_dir_all(root.join("ct-mark-mask-0x0000c000"))
            .expect("a second recorded mask");
        assert_eq!(
            decide(root, Some(&mountinfo(root, true)), false, refused_reading).cause(),
            Some(Cause::StepNotInstalled),
            "two recorded masks are no mask: the step did not finish"
        );
        std::fs::remove_dir_all(root.join("ct-mark-mask-0x0000c000"))
            .expect("removing the second recorded mask");

        // A host with both halves and a table that is refusing decides per
        // box, guest or native: the probe read the effect the marker
        // vouches for, and the guest's own boot is the one step that can
        // write it there.
        std::fs::create_dir_all(root.join(sandbox2::classifier::TABLE_MARKER))
            .expect("the step writes the table's marker");
        for (kind, guest) in [("native", false), ("guest", true)] {
            let decided = decide(root, Some(&mountinfo(root, true)), guest, refused_reading);
            assert!(
                decided.can_decide_per_box(),
                "a confining {kind} host with the step installed and its table \
                 refusing decides per box"
            );
            assert_eq!(
                decided.cause(),
                None,
                "a decided {kind} host names no cause"
            );
        }

        // The same host, the same marker, a table whose refusal is not in
        // force: the probe's connection was not refused the chain's way, so
        // the marker's claim does not become a verdict — this is the false
        // `per_box` the probe exists to refuse to claim (design §7.4).
        let marker_only = decide(root, Some(&mountinfo(root, true)), false, || {
            Reading::NotRefused {
                because: "127.0.0.1 connected".to_string(),
                families: vec![(Family::V4, Observed::Connected)],
            }
        });
        assert!(
            !marker_only.can_decide_per_box(),
            "a marker that survived its table decides nothing"
        );
        let cause = marker_only.cause().expect("the cause is named");
        assert_eq!(
            cause,
            Cause::TableNotEffective,
            "the marker is not the verdict"
        );
        let detail = cause.detail();
        assert!(
            detail.contains("marked loaded") && detail.contains("was not refused"),
            "the cause names what the marker said and what the probe read: {detail}"
        );
        assert!(
            cause.install_command().is_none(),
            "the step is installed, so no install command is named for a \
             table the probe does not see refusing"
        );

        // And a probe that could not read the table at all claims nothing:
        // unknown is not a verdict, and no command is named for it because
        // none is known to make a probe run.
        let unreadable = decide(root, Some(&mountinfo(root, true)), false, || {
            Reading::Inconclusive {
                because: "the leg on 127.0.0.1 was not placed, errno 13".to_string(),
            }
        });
        assert!(
            !unreadable.can_decide_per_box(),
            "an unreadable table is not a decided one"
        );
        let cause = unreadable.cause().expect("the cause is named");
        assert_eq!(
            cause,
            Cause::ProbeUnreadable,
            "the unreadable table is its own cause"
        );
        let detail = cause.detail();
        assert!(
            detail.contains("could not be read") && detail.contains("unknown"),
            "the cause says what is unknown, not what is missing: {detail}"
        );
        assert!(
            cause.install_command().is_none(),
            "no install command is named for a probe that could not run"
        );
    }

    /// NET-079 names the install command only "when that step is what is
    /// missing": the one cause that says the step is missing is the one cause
    /// that names a command, and every other cause — the step installed but
    /// its table not refusing among them — names none.
    #[test]
    fn install_command_is_named_only_when_the_step_is_missing() {
        for cause in [
            Cause::StepNotInstalled,
            Cause::CannotConfine,
            Cause::GuestTableNotLoaded,
            Cause::TableNotEffective,
            Cause::ProbeUnreadable,
        ] {
            assert_eq!(
                cause.install_command().is_some(),
                cause == Cause::StepNotInstalled,
                "{cause:?}: only the missing step names the install command"
            );
        }
        assert_eq!(
            Cause::StepNotInstalled.install_command(),
            Some(sandbox2::classifier::install_hint()),
            "the command named is the step's own install, spelled as the hint"
        );
    }

    /// The cause names what happens to a host-address box on the host it was
    /// decided on — the half of the start-up line that must match what the
    /// next launch actually does, because the two hosts answer a host that
    /// cannot decide per box differently. The step's and the mount's causes
    /// keep NET-079's exception on either kind of host's *other* grounds —
    /// natively they run the boxes unenforced, never refusing them on this
    /// ground — while the two probe causes are the one state where the
    /// box's own declaration is the thing the host cannot honour, on either
    /// kind of host: a refusal that is not in force, or one the host could
    /// not see, is not a verdict to run a deny-all box on, so the deny-all
    /// box is refused and every other — which needs no verdict enforced —
    /// runs. The guest refuses more: a tree that cannot confine a box leaves
    /// nothing to place one in, so every host-address box is refused, and
    /// the interim's table refuses the deny-all box with the guest's own
    /// words. Pinned as data, the same spelling the start-up line renders.
    #[test]
    fn the_cause_names_what_happens_to_the_box_on_each_host() {
        for (cause, why) in [
            (Cause::StepNotInstalled, "a host without the step"),
            (Cause::CannotConfine, "a host that cannot confine a box"),
            (
                Cause::GuestTableNotLoaded,
                "a native host, which cannot read this cause (decide spells \
                 the same state StepNotInstalled there)",
            ),
        ] {
            assert_eq!(
                cause.host_ip_box_outcome(false),
                "its host-address boxes run unenforced",
                "natively, {why} is the exception, never a refusal"
            );
        }
        for (cause, why) in [
            (
                Cause::TableNotEffective,
                "a host whose marker survived its table",
            ),
            (Cause::ProbeUnreadable, "a host whose probe read nothing"),
        ] {
            assert_eq!(
                cause.host_ip_box_outcome(false),
                "its deny-all host-address boxes are refused and its other \
                 host-address boxes run unenforced",
                "natively, {why} refuses the deny-all box rather than run it \
                 on a refusal nothing is making, and runs the rest"
            );
        }
        assert_eq!(
            Cause::CannotConfine.host_ip_box_outcome(true),
            "its host-address boxes are refused: it cannot place one in a \
             leaf that confines",
            "a guest that cannot confine a box has no leaf to decide anything in"
        );
        for (cause, why) in [
            (Cause::GuestTableNotLoaded, "the interim"),
            (
                Cause::TableNotEffective,
                "a table whose refusal is not in force",
            ),
            (Cause::ProbeUnreadable, "an effect the host could not read"),
        ] {
            assert_eq!(
                cause.host_ip_box_outcome(true),
                "its deny-all host-address boxes are refused and its other \
                 host-address boxes run unenforced",
                "{why} refuses the deny-all box and runs the rest"
            );
        }
    }

    /// The reading's own rule (design §4.1, §7.4): a `per_box` fact is
    /// built only from refusals the loaded chain itself reads as —
    /// EHOSTUNREACH over IPv4 loopback, EACCES over IPv6, EPERM a security
    /// module's — and only when every family the probe read was refused
    /// that way, because a connection that completed on any family is a
    /// full bypass and no other leg can un-meet it. The errnos the probe
    /// read are carried per family into the record, so the evidence a
    /// `per_box` rests on is what a person reads. Pinned as data here, and
    /// not in the probe: the probe reports, the reading decides.
    #[test]
    fn a_per_box_reading_rests_only_on_the_set_the_chain_reads_as() {
        // The pair the design says the probe reads on the two loopbacks
        // (design §4.1): one `reject with icmpx admin-prohibited`, two
        // errnos.
        let legs = [
            (Family::V4, Observed::Refused(libc::EHOSTUNREACH)),
            (Family::V6, Observed::Refused(libc::EACCES)),
        ];
        let reading = Reading::of(&legs);
        let carried = match &reading {
            Reading::Refused(families) => families.clone(),
            other => panic!("two in-set refusals read as the table refusing: {other:?}"),
        };
        assert_eq!(
            carried, legs,
            "the reading carries the evidence it rests on, per family"
        );
        // The record names each family's errno: the evidence a `per_box`
        // rests on is what a person reads in the daemon's log.
        let record = reading.record();
        for (family, errno) in [("127.0.0.1", libc::EHOSTUNREACH), ("::1", libc::EACCES)] {
            assert!(
                record.contains(family) && record.contains(&format!("errno {errno}")),
                "the record names what {family} read, errno included: {record}"
            );
        }

        // EPERM is the set's third face — a security module refusing the
        // same connection — and reads as the table too.
        let permed = [
            (Family::V4, Observed::Refused(libc::EPERM)),
            (Family::V6, Observed::Refused(libc::EHOSTUNREACH)),
        ];
        assert!(
            matches!(Reading::of(&permed), Reading::Refused(_)),
            "EPERM is in the set the loaded chain reads as"
        );

        // A host whose IPv6 loopback is not enabled reads only v4, and one
        // in-set refusal over the only family it could read is the table
        // refusing: the family the host does not have is not a family
        // anything can bypass through.
        let v4_only = [(Family::V4, Observed::Refused(libc::EHOSTUNREACH))];
        assert!(
            matches!(Reading::of(&v4_only), Reading::Refused(_)),
            "a family not enabled on this host is not read, and the one read \
             decides"
        );

        // Anything else — a connection that completed, a leg that never
        // reported, or a refusal with an errno the chain never reads as
        // (ECONNREFUSED is the probe's own listener gone, ENETUNREACH a
        // routing answer) — is evidence the table is not what refused, on
        // any family, and settles the whole reading that way: a bypass on
        // any family is a full bypass.
        for (observed, why) in [
            (Observed::Connected, "a connection the filter admitted"),
            (Observed::TimedOut, "a leg that never reported"),
            (
                Observed::Refused(libc::ECONNREFUSED),
                "the probe's own listener gone",
            ),
            (Observed::Refused(libc::ENETUNREACH), "a routing answer"),
        ] {
            for family in [Family::V4, Family::V6] {
                let (other, errno) = if family == Family::V4 {
                    (Family::V6, libc::EACCES)
                } else {
                    (Family::V4, libc::EHOSTUNREACH)
                };
                let legs = [(other, Observed::Refused(errno)), (family, observed)];
                match Reading::of(&legs) {
                    Reading::NotRefused { because, .. } => assert!(
                        because.starts_with(family.name()),
                        "{why} on {} settles the reading, in its own words: \
                         {because}",
                        family.name()
                    ),
                    other => panic!(
                        "{why} on {} voids the reading, not {other:?}",
                        family.name()
                    ),
                }
            }
        }

        // A leg that could not be read is not a refusal it never observed:
        // with no positive evidence anywhere, the effect is unknown, and
        // unknown is not a verdict — which is what keeps a `per_box` from
        // resting on a reading that could not see one family.
        let unplaced = [
            (Family::V4, Observed::Unplaced(libc::EACCES)),
            (Family::V6, Observed::Unplaced(libc::EACCES)),
        ];
        match Reading::of(&unplaced) {
            Reading::Inconclusive { because } => assert!(
                because.contains("was not placed"),
                "the unreadable legs are named: {because}"
            ),
            other => panic!("a probe that placed no child read nothing: {other:?}"),
        }
        let mixed = [
            (Family::V4, Observed::Refused(libc::EHOSTUNREACH)),
            (Family::V6, Observed::Unplaced(libc::EACCES)),
        ];
        assert!(
            matches!(Reading::of(&mixed), Reading::Inconclusive { .. }),
            "a refused leg does not stand in for a family the probe could not \
             read"
        );
        assert!(
            matches!(Reading::of(&[]), Reading::Inconclusive { .. }),
            "a probe with no family to read knows nothing"
        );
    }

    /// The control leg is what makes the probe's reading mean anything: a
    /// listener the daemon itself cannot reach from its own cgroup says
    /// nothing about the filter, so the reading is inconclusive and no
    /// probe child is forked — the daemon's own connect runs first, and its
    /// failure is the reading's cause, named in the daemon's words.
    #[test]
    fn a_listener_the_daemon_cannot_reach_reads_as_inconclusive() {
        let tree = tempfile::tempdir().expect("a temp dir standing in for the tree");
        // A listener bound and then dropped: a port that was once live and
        // is on nobody's socket now — the daemon's own connect to it fails,
        // with nothing of the filter involved.
        let listener = TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .expect("a loopback listener to point the probe at");
        let addr = listener.local_addr().expect("the dead listener's address");
        drop(listener);
        match probe_effect(tree.path(), &[(Family::V4, addr)]) {
            Reading::Inconclusive { because } => assert!(
                because.contains("the daemon's own connect"),
                "the reading names the control leg that failed: {because}"
            ),
            other => panic!("a dead listener is inconclusive, not {other:?}"),
        }
        // The control leg never forked a child, so the probe's leaf was
        // never made either: a probe that read nothing leaves nothing.
        assert!(
            !probe_leaf(tree.path()).exists(),
            "the control leg runs before any child is placed"
        );
    }

    /// The marker is not the verdict, over a tree a table is not refusing
    /// behind: the step's half present — subtrees delegated, marker written
    /// — and no table loaded, which is exactly what a stand-in tree is
    /// (and what a real tree whose table lost its reboot's reload is, the
    /// state the marker survives and the refusal does not). The probe reads
    /// the effect itself: its child places into a deny leaf, connects to
    /// the daemon's held listener, is admitted, and the decision is the
    /// cause that says so — the box recorded `none`, never a `per_box`
    /// claimed over a filter that admits the probe (design §7.4).
    #[test]
    fn a_marker_survives_its_table_but_decides_nothing() {
        let tree = tempfile::tempdir().expect("a temp dir standing in for the tree");
        let root = tree.path();
        installed_cohort(root);
        // The probe's own reading, taken before any decision is built over
        // it: behind no table every leg the probe ran must have connected —
        // 127.0.0.1's leg included — and must have connected with the leg's
        // own answer, not the deadline's. A leg that cannot reach its
        // listener reads as `TimedOut`, settles the same `TableNotEffective`,
        // and stays invisible in the decision; the leg itself is the fact
        // that shows the probe placed its child where it meant to and the
        // child reached the address it was handed — a v4 leg that built its
        // address in the wrong byte order read exactly that way, and no
        // decision over its reading could see it.
        let began = std::time::Instant::now();
        let reading = read_filter(root);
        let elapsed = began.elapsed();
        let legs = reading.legs();
        assert!(
            legs.contains(&(Family::V4, Observed::Connected)),
            "the leg on 127.0.0.1 connects behind no table: {legs:?}"
        );
        for (family, observed) in &legs {
            assert_eq!(
                *observed,
                Observed::Connected,
                "every family the probe bound — {} among them — connects \
                 behind no table: {legs:?}",
                family.name()
            );
        }
        assert!(
            elapsed < PROBE_DEADLINE,
            "the probe ends with its legs' answers, not with the deadline: \
             {elapsed:?} for {legs:?}"
        );
        let decision = decide(root, Some(&mountinfo(root, true)), false, || {
            reading.clone()
        });
        assert!(
            !decision.can_decide_per_box(),
            "the marker's claim is cross-checked against the table's own \
             effect, and there is no refusal behind it"
        );
        assert_eq!(
            decision.cause(),
            Some(Cause::TableNotEffective),
            "a marker that survived its table is its own cause"
        );
        // The probe cleaned up its own leaf: the reading a launch takes
        // leaves the tree as it found it, bar the tree's own facts.
        assert!(
            !probe_leaf(root).exists(),
            "the probe removes the throwaway leaf it placed its child in"
        );
    }

    /// The decision a launch answers with is read fresh, over the tree it
    /// is about to place a box in — never a start fact kept between
    /// launches, because a table can go away between them and a kept
    /// decision would outlive its probe the way a marker outlives its
    /// table. Pinned over a stand-in tree the host's own mount table does
    /// not cover: the reading is undecidable for the confinement cause
    /// whatever the step's half under it looks like, and reading it again
    /// answers the same — nothing was kept, so there is nothing for the
    /// second reading to inherit.
    #[test]
    fn the_decision_is_read_fresh_over_the_tree_it_answers_for() {
        let tree = tempfile::tempdir().expect("a temp dir standing in for the tree");
        let root = tree.path();
        installed_cohort(root);
        // The reading a launch takes, over the daemon's own facts — its tree,
        // its mount table, its host kind — nothing kept anywhere between two
        // readings, because the fact a marker vouched for outlived the table
        // it vouched against.
        let read = || {
            decide_now(
                root,
                sandbox2::classifier::own_mountinfo().as_deref(),
                crate::guest::is_microvm_daemon(),
            )
        };
        let first = read();
        assert!(
            !first.can_decide_per_box(),
            "a tree the host's own mount table does not cover decides nothing \
             per box, step's half or no step's half"
        );
        assert_eq!(
            first.cause(),
            Some(Cause::CannotConfine),
            "the real mount table is the fact the launch reads, not the one a \
             test would like it to"
        );
        assert_eq!(
            read(),
            first,
            "nothing is kept between readings: the fact is the tree's own, \
             re-read per launch"
        );
    }
}
