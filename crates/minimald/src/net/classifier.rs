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

use sandbox2::config::Verdict;

/// The loopback address the box zone's answerer serves at — the one
/// destination a deny-all host-address box's connections are admitted to
/// (NET-079): the resolver Minimal owns for the box, which answers the box
/// zone and forwards nothing. A loopback-wide exception was considered and
/// rejected (design §4.1): the rest of the host's loopback is where the
/// host's own services and its forwarding resolver listen, and admitting a
/// deny-all box to them would admit it to everything upstream.
pub const ANSWERER_ADDRESS: Ipv4Addr = Ipv4Addr::LOCALHOST;

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
    /// refuses it. Reloading the table ends it, so the install command is
    /// named.
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
    /// the marker vouches for but the probe does not ends with the same
    /// command — the install is the one thing that reloads it — while a
    /// probe that could not read the table names nothing: no command is
    /// known to make a probe run.
    pub fn install_command(self) -> Option<String> {
        match self {
            Self::StepNotInstalled | Self::TableNotEffective => {
                Some(sandbox2::classifier::install_hint())
            }
            Self::CannotConfine | Self::GuestTableNotLoaded | Self::ProbeUnreadable => None,
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

/// The guest's own copy of the installer, `include_str!` of the very file the
/// native lane runs — never a restatement: the script is the one authority
/// for the tree it lays out and the table it renders, and a copy would be a
/// second authority the moment either lane moved. The guest's load runs the
/// script's render half only; the daemon has already made its own cgroups.
const INSTALLER_SCRIPT: &str = include_str!("../../../../scripts/install-host-classifier.sh");

/// Where the guest's `nft` and `bash` live, absolute: the render and the load
/// both run with the environment cleared, so neither may depend on a `PATH`
/// this daemon did not choose.
pub const GUEST_NFT: &str = "/usr/sbin/nft";
pub const GUEST_BASH: &str = "/bin/bash";

/// The name of the table both lanes load, and the chain a deny-all box's
/// verdict rides on: `nft list` must show both behind the marker for a
/// guest's decision to rest on more than the marker's existence.
const TABLE_NAME: &str = "minimal_class";
const DENY_OUT_CHAIN: &str = "chain deny_out";

/// The ct-mark bits the guest's own boot classifies with: the step's default,
/// because a guest's kernel is this image's alone — there is no other
/// ruleset whose bits could conflict, and the mask recorded beside the
/// marker keeps the daemon's probe and the loaded table spelling one fact.
pub const GUEST_CT_MARK_MASK: u32 = 0x3000_0000;

/// The installer's rehearsal seam: honoured only where a caller names a
/// stand-in mount table, because the production call passes `None` and the
/// guest then reads the mount table its own kernel wrote.
const REHEARSAL_MOUNTINFO_ENV: &str = "MINIMAL_OVERRIDE_CGROUP_MOUNTINFO";

/// What the guest's own boot hands the installer's render: the tree this
/// daemon mounted, the answerer as this daemon serves it, and NET-078's two
/// source identities — which on a guest are both the guest's own address,
/// but the render is told so, never left to assume.
pub struct GuestRender<'a> {
    /// The tree root this daemon itself laid out: `sandbox2`'s
    /// `classifier::TREE_ROOT`, under the cgroup2 its boot mounted.
    pub tree_root: &'a Path,
    /// The one destination a deny-all box may reach, at the port this
    /// daemon's answerer serves on this guest.
    pub answerer_address: Ipv4Addr,
    pub answerer_port: u16,
    /// What the boxes cohort leaves as, and what everything else in the
    /// slice leaves as.
    pub cohort_address: IpAddr,
    pub node_plane_address: IpAddr,
    /// The ct-mark bits the table classifies with.
    pub ct_mark_mask: u32,
    /// A stand-in mount table, tests only.
    pub mountinfo_override: Option<&'a Path>,
}

/// The guest's rendered table, by the guest's own rules: the installer is
/// fed to `bash` on its stdin and told everything as argv — `bash -s --` —
/// with the environment cleared, so no `BASH_ENV`, no `ENV` and no inherited
/// `PATH` can tell bash what else to read, and no parameter is interpolated
/// into script text. `--print-ruleset` prints the transaction an install
/// would hand `nft -f`, which is the transaction the guest hands it.
pub fn render_guest_ruleset(bash: &Path, params: &GuestRender<'_>) -> Result<Vec<u8>, String> {
    use std::io::Write as _;
    use std::process::{Command, Stdio};

    let mut installer = Command::new(bash);
    installer
        .arg("-s")
        // Ends bash's own option parsing, so the first argument after it is
        // the script's first flag and never an option bash re-reads.
        .arg("--")
        .arg("--print-ruleset")
        .arg("--root")
        .arg(params.tree_root)
        .arg("--answerer-address")
        .arg(params.answerer_address.to_string())
        .arg("--answerer-port")
        .arg(params.answerer_port.to_string())
        .arg("--cohort-address")
        .arg(params.cohort_address.to_string())
        .arg("--node-plane-address")
        .arg(params.node_plane_address.to_string())
        .arg("--ct-mark-mask")
        .arg(format!("0x{:08x}", params.ct_mark_mask))
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(mountinfo) = params.mountinfo_override {
        installer.env(REHEARSAL_MOUNTINFO_ENV, mountinfo);
    }
    let mut child = installer
        .spawn()
        .map_err(|cause| format!("spawning {}: {cause}", bash.display()))?;
    // The script is read from the child's stdin, so feed it and close the
    // pipe; a child that stops reading before the script ends makes the
    // write fail, and its own output says why.
    if let Some(mut stdin) = child.stdin.take()
        && let Err(cause) = stdin.write_all(INSTALLER_SCRIPT.as_bytes())
    {
        tracing::debug!("the installer stopped reading its script: {cause}");
    }
    let printed = child
        .wait_with_output()
        .map_err(|cause| format!("waiting on {}: {cause}", bash.display()))?;
    if !printed.status.success() {
        return Err(String::from_utf8_lossy(&printed.stderr).trim().to_string());
    }
    Ok(printed.stdout)
}

/// What the guest's load left behind when it succeeded: the digest of the
/// exact bytes handed to `nft`, over which no later render is ever taken.
#[derive(Debug)]
pub struct GuestLoad {
    pub digest: String,
}

/// Which half of the guest's own load failed, with the refusing program's
/// own words: the render, the check, the load itself, or the marker — named
/// so the daemon's log says what to look at, and so the guest's decision
/// stays `GuestTableNotLoaded` for every one of them.
#[derive(Debug)]
pub enum GuestLoadFailure {
    Render(String),
    Check(String),
    Load(String),
    Marker(String),
}

/// The guest's own boot load (NET-079): renders the installer's table for
/// the tree this daemon mounted, checks it with `nft -c -f -`, loads it with
/// `nft -f -`, and only then writes the presence marker the daemon's check
/// reads — the same discipline the installer's own load keeps, over the
/// same render function's bytes. The check and the load are one render's
/// bytes, piped, never a re-render; the digest the caller logs covers
/// exactly those bytes, the same digest the installer's own load prints.
///
/// A failure at any point writes no marker, so the decision below reports
/// the guest as unable to decide per box until a boot that succeeds — and
/// the failure is this function's to name, nft's own error included.
pub fn load_guest_table(
    bash: &Path,
    nft: &Path,
    params: &GuestRender<'_>,
) -> Result<GuestLoad, GuestLoadFailure> {
    // The marker's discipline first, as the installer's re-install keeps it:
    // a marker or a stale mask record that cannot come away means the load
    // stops before touching the table, so nothing ever vouches for a table
    // this boot did not render.
    clear_marker_records(params.tree_root).map_err(GuestLoadFailure::Marker)?;
    let ruleset = render_guest_ruleset(bash, params).map_err(GuestLoadFailure::Render)?;
    // The check is the render's own verdict on the guest's kernel — the one
    // expression the guest's image is being fixed to carry — and it is
    // logged as its own line, with nft's own error when it refuses, because
    // it is the line the image's builder reads.
    let checked = run_guest_nft(nft, true, &ruleset);
    if let Err(cause) = checked {
        tracing::error!(
            error = %cause,
            "the guest's nft -c refused the rendered classifier table: no load ran and no marker was written, so minimald reports no per-box verdict until a boot succeeds"
        );
        return Err(GuestLoadFailure::Check(cause));
    }
    tracing::info!("the guest's nft -c accepted the rendered classifier table");
    // The load: one transaction, whole or not at all, over the same bytes
    // the check read — the ruleset's own prelude deletes any previous table
    // first, so a failed load leaves the previous one untouched.
    let loaded = run_guest_nft(nft, false, &ruleset);
    if let Err(cause) = loaded {
        tracing::error!(
            error = %cause,
            "the guest's nft -f refused the classifier table: the previous table, if any, is untouched and no marker was written, so minimald reports no per-box verdict until a boot succeeds"
        );
        return Err(GuestLoadFailure::Load(cause));
    }
    let digest = sha256_hex(&ruleset);
    // The marker last: the mask record beside it first, then the marker —
    // the commit point, never there without the record — and only after the
    // load succeeded, so the marker vouches for the table this boot rendered
    // and nothing else.
    write_guest_marker(params.ct_mark_mask, params.tree_root).map_err(GuestLoadFailure::Marker)?;
    tracing::info!(
        sha256 = %digest,
        marker = %sandbox2::classifier::TABLE_MARKER,
        "loaded the guest's classifier table and wrote its presence marker"
    );
    Ok(GuestLoad { digest })
}

/// Removes the marker and every ct-mark mask record beside it, refusing a
/// load that cannot take a stale one away: on the guest these are cgroups
/// this daemon made, so only a daemon still holding one keeps the removal
/// from succeeding.
fn clear_marker_records(root: &Path) -> Result<(), String> {
    let marker = root.join(sandbox2::classifier::TABLE_MARKER);
    if marker.exists() {
        std::fs::remove_dir(&marker).map_err(|cause| {
            format!("removing the stale marker at {}: {cause}", marker.display())
        })?;
    }
    for record in std::fs::read_dir(root).map_err(|cause| {
        format!(
            "reading {} for stale ct-mark records: {cause}",
            root.display()
        )
    })? {
        let record = record.map_err(|cause| format!("reading a record's name: {cause}"))?;
        let name = record.file_name();
        if name
            .to_str()
            .is_some_and(|name| name.strip_prefix(MASK_RECORD_PREFIX).is_some())
        {
            std::fs::remove_dir(record.path()).map_err(|cause| {
                format!(
                    "removing the stale ct-mark record {}: {cause}",
                    record.path().display()
                )
            })?;
        }
    }
    Ok(())
}

/// Writes the mask record and then the marker beside it — the commit point,
/// last, as the installer writes them: on real cgroupfs a directory *is* the
/// cgroup, and both hold no process and are delegated to nobody.
fn write_guest_marker(mask: u32, root: &Path) -> Result<(), String> {
    let record = root.join(format!("{MASK_RECORD_PREFIX}0x{mask:08x}"));
    std::fs::create_dir(&record).or_else(|cause| {
        if cause.kind() == std::io::ErrorKind::AlreadyExists {
            Ok(())
        } else {
            Err(format!(
                "recording the table's ct-mark mask at {}: {cause}",
                record.display()
            ))
        }
    })?;
    let marker = root.join(sandbox2::classifier::TABLE_MARKER);
    std::fs::create_dir(&marker).or_else(|cause| {
        if cause.kind() == std::io::ErrorKind::AlreadyExists {
            Ok(())
        } else {
            Err(format!(
                "writing the table's presence marker at {}: {cause}",
                marker.display()
            ))
        }
    })
}

/// Runs the guest's `nft` over one render's bytes, with the environment
/// cleared: `-c` asks it to parse and validate without applying, which is how
/// the render's own table is checked before anything loads; without it the
/// batch is applied whole. The bytes are piped, so the digest the caller
/// names covers exactly what nft received.
fn run_guest_nft(nft: &Path, check: bool, ruleset: &[u8]) -> Result<(), String> {
    use std::io::Write as _;
    use std::process::{Command, Stdio};

    let mut load = Command::new(nft);
    load.env_clear();
    if check {
        load.arg("-c");
    }
    load.arg("-f")
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = load
        .spawn()
        .map_err(|cause| format!("spawning {}: {cause}", nft.display()))?;
    if let Some(mut stdin) = child.stdin.take()
        && let Err(cause) = stdin.write_all(ruleset)
    {
        tracing::debug!("the guest's nft stopped reading the ruleset: {cause}");
    }
    let applied = child
        .wait_with_output()
        .map_err(|cause| format!("waiting on {}: {cause}", nft.display()))?;
    if applied.status.success() {
        return Ok(());
    }
    Err(String::from_utf8_lossy(&applied.stderr).trim().to_string())
}

/// The sha256 of exactly the bytes it is given — the bytes piped to nft, so
/// a logged digest and a render's bytes can be compared off-host without
/// re-rendering anything.
fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest as _;
    let mut hasher = sha2::Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

/// What the guest's recheck found when it read its own kernel's table back:
/// listed with its deny chain, or gone with the reading's own words.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Listing {
    Listed,
    Gone(String),
}

/// Reads the guest's loaded table back with `nft list`: the marker says the
/// load ran, and this is the fact it cannot vouch for — a table emptied by
/// a flush, a failed reload or a name collision leaves the marker standing.
/// The table is there when `nft list` succeeds naming the deny chain the
/// verdict rides on; anything else reads as gone, with nft's own error.
pub(crate) fn guest_table_listed(nft: &Path) -> Listing {
    use std::process::{Command, Stdio};

    let listed = Command::new(nft)
        .env_clear()
        .arg("list")
        .arg("table")
        .arg("inet")
        .arg(TABLE_NAME)
        .stdin(Stdio::null())
        .output();
    let listed = match listed {
        Ok(listed) => listed,
        Err(cause) => {
            return Listing::Gone(format!(
                "running {} to list the table: {cause}",
                nft.display()
            ));
        }
    };
    if !listed.status.success() {
        return Listing::Gone(format!(
            "nft list table inet {TABLE_NAME} failed: {}",
            String::from_utf8_lossy(&listed.stderr).trim()
        ));
    }
    if String::from_utf8_lossy(&listed.stdout).contains(DENY_OUT_CHAIN) {
        return Listing::Listed;
    }
    Listing::Gone(format!(
        "nft lists the table inet {TABLE_NAME} without its {DENY_OUT_CHAIN} chain"
    ))
}

/// The probe's loopback listeners, held for the daemon's life: the guest's
/// effect probe connects to a destination the daemon itself holds, so the
/// listener must be there before any launch reads the table's effect, not
/// bound and dropped per reading. A listener the kernel queues against but
/// nobody accepts would fill its backlog and read the table as
/// inconclusive, so each one is drained by its own thread — connections
/// are accepted and dropped, because the probe's evidence is the refused
/// connect, never a connection's life past it.
static HELD_PROBE_ENDPOINTS: std::sync::Mutex<Vec<(Family, SocketAddr)>> =
    std::sync::Mutex::new(Vec::new());

/// Binds and holds the probe's listeners, one thread per family this host's
/// loopback can carry: the endpoints it returns are the ones the guest's
/// readings connect to, for as long as this daemon runs. Native readings
/// keep binding their own, held for one probe's duration — the guest's
/// start holds them instead, because a guest that loaded its table at
/// boot reads its effect per launch, and a listener per reading would be
/// a port the box never saw refused.
pub fn hold_probe_listeners() -> std::io::Result<Vec<(Family, SocketAddr)>> {
    let listeners = bind_probe_listeners()?;
    let endpoints: Vec<(Family, SocketAddr)> = listeners
        .iter()
        .filter_map(|(family, listener)| listener.local_addr().ok().map(|addr| (*family, addr)))
        .collect();
    for (family, listener) in listeners {
        let draining = std::thread::Builder::new()
            .name(format!("minimald-classifier-probe-{}", family.name()))
            .spawn(move || {
                while let Ok(connection) = listener.accept() {
                    drop(connection);
                }
            });
        draining.map_err(|cause| {
            std::io::Error::other(format!(
                "holding the probe's {} listener: {cause}",
                family.name()
            ))
        })?;
    }
    *HELD_PROBE_ENDPOINTS
        .lock()
        .expect("the probe's listeners are only held by this daemon") = endpoints.clone();
    Ok(endpoints)
}

/// Forgets the held listeners, so a test reading the guest's paths does not
/// read the listeners another test left behind.
#[cfg(test)]
pub(crate) fn clear_probe_listeners() {
    HELD_PROBE_ENDPOINTS
        .lock()
        .expect("the probe's listeners are only held by this daemon")
        .clear();
}

/// Reads the table's effect over the listeners this daemon holds: the
/// guest's own reading, whose listener is its boot's, not one bound and
/// dropped per probe — so the probe's evidence is about the table, never
/// about whether a listener happened to be there.
pub(crate) fn read_held_filter(root: &Path) -> Reading {
    let endpoints = HELD_PROBE_ENDPOINTS
        .lock()
        .expect("the probe's listeners are only held by this daemon")
        .clone();
    if endpoints.is_empty() {
        tracing::warn!(
            "the daemon holds no loopback listener for its effect probe: its boot loaded no classifier table, so the table's effect was never read"
        );
        return Reading::Inconclusive {
            because: "the daemon holds no loopback listener for its effect probe".to_string(),
        };
    }
    read_over(root, &endpoints)
}

/// Reads the table's effect on this host (NET-079, design §7.4): the probe,
/// with its own listener — a destination the daemon holds on loopback, on
/// a port other than the answerer's, is the place a deny-all box's
/// connections would be refused. The probe connects and waits, so an async
/// caller runs it on the blocking pool; it logs one record per run, naming
/// every family it read and what the leg there met, the errno included.
///
/// The healthy refusal is the quiet case — a launch's own record already
/// names its enforcement — while anything else is the state a person
/// reading the log has to see: a control leg that did not connect, or a
/// family that connected, timed out or failed with an errno outside the
/// reject set, is the launch's own line to carry.
fn read_over(root: &Path, endpoints: &[(Family, SocketAddr)]) -> Reading {
    let reading = probe_effect(root, endpoints);
    if matches!(reading, Reading::Refused(_)) {
        tracing::debug!(probe = %reading.record(), "the classifier table refused the probe's connection out of a deny leaf");
    } else {
        tracing::warn!(probe = %reading.record(), "read the classifier table's effect on this host");
    }
    reading
}

/// Reads the table's effect with a listener of its own, held for the
/// probe's whole duration — the native reading, whose host binds and drops
/// per probe; a listener nothing holds is the dead-listener case the
/// control leg exists to catch.
///
/// The one probe surface outside the crate: the native lane's root harness
/// proves the *loaded* table's effect with the daemon's own probe, over a
/// scratch tree the installer laid out — the only artifact that can
/// produce the reading. No other caller reads a reading directly.
pub fn read_filter(root: &Path) -> Reading {
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
    read_over(root, &endpoints)
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
/// boot loads are its own work — and reporting a guest as decided while
/// its table is not loaded would place a deny-all box in a leaf that
/// decides nothing while looking decided, on the one host whose daemon is
/// the fix. The guest's cause is named for the image's builder: no
/// installer exists inside a microVM, so no command is named for it.
pub(crate) fn decide(
    root: &Path,
    mountinfo: Option<&str>,
    guest: bool,
    read: impl FnOnce() -> Reading,
) -> Decision {
    decide_over(root, mountinfo, guest, read, || {
        // The native host's facts are the installer's own artifacts, and
        // the probe reads their effect directly; the guest is the one
        // host whose kernel the load was handed to, so its marker is
        // read back against that kernel before anything rests on it.
        if guest {
            guest_table_listed(Path::new(GUEST_NFT))
        } else {
            Listing::Listed
        }
    })
}

/// [`decide`] with its table's listing handed in — the guest's recheck, as
/// the one fact the caller can name: the daemon's own call reads its kernel
/// with `nft list`, and a test reads the listing it is pinning.
pub(crate) fn decide_over(
    root: &Path,
    mountinfo: Option<&str>,
    guest: bool,
    read: impl FnOnce() -> Reading,
    list: impl FnOnce() -> Listing,
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
    // it is the boot's own half, so its cause names the table and nothing
    // can be run.
    if !subtrees_delegated(root) || !table_marker_present(root) {
        return Decision::undecidable(if guest {
            Cause::GuestTableNotLoaded
        } else {
            Cause::StepNotInstalled
        });
    }
    // The guest's recheck, the one half a native host cannot need: its
    // kernel is this daemon's own to read, so the marker's claim is checked
    // against the table itself — `nft list` must name the table and the
    // deny chain the verdict rides on. A table gone behind its marker is
    // its own cause, and the probe does not run over it: a reading taken
    // from a kernel that answers nothing would dress the absence up as the
    // table not refusing, when the fact is the table not being there.
    if guest && let Listing::Gone(why) = list() {
        tracing::warn!(
            recheck = %why,
            "the guest's marker stands over a table that is not there: the launch reads it back before deciding anything per box"
        );
        return Decision::undecidable(Cause::TableNotEffective);
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

/// [`decide`] with its probes attached: the decision the daemon reads, over
/// the tree, mount table, and host kind its caller names for it — the
/// daemon's own in every production path. A native host binds a listener
/// per reading, held for the probe's duration; the guest connects to the
/// listener its boot holds, because its reading is per launch and the
/// listener must not be a port that was refused only when the probe was
/// looking. The probe connects and waits, so an async caller runs it on
/// the blocking pool.
pub fn decide_now(root: &Path, mountinfo: Option<&str>, guest: bool) -> Decision {
    let decision = decide(root, mountinfo, guest, || {
        if guest {
            read_held_filter(root)
        } else {
            read_filter(root)
        }
    });
    note_decision(&decision);
    decision
}

/// The freshest decision this daemon read — `decide_now`'s own record, held
/// for the one reader that follows the decision but runs after it: the
/// guest's network plan, which builds a deny-all box's resolver after the
/// launch refused everything it must refuse. A guest that decides per box
/// resolves such a box through its own answerer, the one carve-out its
/// table admits; a guest that decides nothing keeps the node's DNS layer
/// (NET-079, design §5.3). Held per launch rather than shared across them,
/// because the decision is read fresh before each host-address launch — so
/// what this carries is the launch's own decision, never another's.
static READ_DECISION: std::sync::Mutex<Option<Decision>> = std::sync::Mutex::new(None);

/// Records the decision the daemon just read, for the reader that follows it.
pub(crate) fn note_decision(decision: &Decision) {
    *READ_DECISION
        .lock()
        .expect("the decision memo is only written by this daemon") = Some(decision.clone());
}

/// The decision the current launch read, if it read one: `None` until the
/// first `decide_now` runs — which every launch's own decision is, so a
/// plan built before any decision ran is a plan that decides nothing.
pub(crate) fn freshest_decision() -> Option<Decision> {
    READ_DECISION
        .lock()
        .expect("the decision memo is only written by this daemon")
        .clone()
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
    step_command_over(
        mount,
        mode,
        nft_dir,
        TEST_COHORT_ADDRESS,
        TEST_NODE_PLANE_ADDRESS,
    )
}

/// [`step_command`] with the two source identities named by the caller: the
/// step renders its table from the pair it is handed, so a test can render
/// the guest's own pair through the step's own print mode and compare the
/// bytes with the render the daemon asks for over the same pair.
#[cfg(test)]
fn step_command_over(
    mount: &StandinMount,
    mode: &[&str],
    nft_dir: Option<&Path>,
    cohort: &str,
    node_plane: &str,
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
        .arg(cohort)
        .arg("--node-plane-address")
        .arg(node_plane);
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

/// The `bash` the guest-lane tests render through, as the guest's own load
/// hands it: the daemon's production path is absolute (`GUEST_BASH`), so the
/// tests resolve the same program on the host that runs the suite — the
/// installer is fed to it on stdin either way, which is what the render's own
/// tests pin.
#[cfg(test)]
fn guest_bash() -> PathBuf {
    let on_path = std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths).find_map(|dir| {
            let candidate = dir.join("bash");
            candidate.is_file().then_some(candidate)
        })
    });
    on_path.unwrap_or_else(|| PathBuf::from(GUEST_BASH))
}

/// The parameters a guest's own boot renders its table with, over a
/// stand-in mount: the answerer at the address and port this daemon serves
/// it (NET-079's one carve-out), the ct-mark bits the boot classifies with,
/// and the two source identities named by the caller — which a guest hands
/// as two inputs even where they are the one address an un-enrolled guest
/// has (NET-078).
#[cfg(test)]
fn guest_params<'a>(
    mount: &'a StandinMount,
    mountinfo: Option<&'a Path>,
    cohort: IpAddr,
    node_plane: IpAddr,
) -> GuestRender<'a> {
    GuestRender {
        tree_root: &mount.root,
        answerer_address: ANSWERER_ADDRESS,
        answerer_port: crate::net::answerer::ANSWERER_PORT,
        cohort_address: cohort,
        node_plane_address: node_plane,
        ct_mark_mask: GUEST_CT_MARK_MASK,
        mountinfo_override: mountinfo,
    }
}

/// The guest's rendered table for one pair of source identities, as its own
/// load renders it: the installer is fed to `bash` on stdin with everything
/// it needs as argv (see `render_guest_ruleset`), over the stand-in mount the
/// step's own tests render and load over.
#[cfg(test)]
fn guest_ruleset(cohort: IpAddr, node_plane: IpAddr) -> Vec<u8> {
    let mount = standin_mount();
    // The stand-in mount table, as the guest's own render would read none: the
    // environment is cleared, so this is the one fact the render is told
    // rather than one it inherits, and the cgroup paths it renders are the
    // ones the same stand-in mount spells for the step's own lanes.
    render_guest_ruleset(
        &guest_bash(),
        &guest_params(&mount, Some(&mount.mountinfo), cohort, node_plane),
    )
    .expect("the installer renders the guest's table over the stand-in mount")
}

/// Writes a stand-in for the guest's `nft` into `dir` and returns its path:
/// it records every invocation it was handed — one file per call, its argv
/// as one argument per line and exactly the bytes it was piped on stdin —
/// and answers the way the caller named. `refuse_on` lists the argv tokens a
/// call must refuse (`-c` for the check, `-f` for the load); a refused call
/// answers with nft's own shape of error on stderr and a non-zero exit, and
/// every other call exits 0, so the marker's discipline is read against a
/// packet filter that says no when the test wants it to.
#[cfg(test)]
fn recording_nft(dir: &Path, refuse_on: &[&str]) -> PathBuf {
    let nft = dir.join("nft");
    let dir = dir.display();
    let refusals = if refuse_on.is_empty() {
        "''".to_string()
    } else {
        refuse_on
            .iter()
            .map(|token| format!("'{token}'"))
            .collect::<Vec<_>>()
            .join(" ")
    };
    std::fs::write(
        &nft,
        format!(
            "#!/bin/sh\n\
             dir='{dir}'\n\
             n=0\n\
             while [ -e \"$dir/call$n.argv\" ]; do n=$((n + 1)); done\n\
             printf '%s\\n' \"$@\" >\"$dir/call$n.argv\"\n\
             cat >\"$dir/call$n.stdin\"\n\
             for refuse in {refusals}; do\n\
                 [ \"$refuse\" = \"$1\" ] && {{\n\
                     printf 'Error: Could not process rule: Operation not supported\\n' >&2\n\
                     exit 1\n\
                 }}\n\
             done\n\
             exit 0\n"
        ),
    )
    .expect("writing the recording nft stub");
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&nft, std::fs::Permissions::from_mode(0o755))
            .expect("the recording nft stub is executable");
    }
    nft
}

/// The calls a recording `nft` was handed, in the order it was handed them:
/// each one's argv and exactly the bytes it was piped on stdin — the bytes
/// the digest of a load covers, read back off the stub that received them.
#[cfg(test)]
fn nft_calls(dir: &Path) -> Vec<(Vec<String>, Vec<u8>)> {
    let mut calls = Vec::new();
    for n in 0.. {
        let argv = std::fs::read_to_string(dir.join(format!("call{n}.argv")))
            .ok()
            .map(|argv| {
                argv.lines()
                    .filter(|line| !line.is_empty())
                    .map(str::to_string)
                    .collect()
            });
        let piped = std::fs::read(dir.join(format!("call{n}.stdin"))).ok();
        match (argv, piped) {
            (Some(argv), Some(piped)) => calls.push((argv, piped)),
            _ => return calls,
        }
    }
    calls
}

/// Writes a stand-in for the guest's `bash` into `dir` and returns its path:
/// it records what the daemon handed it — its argv, one argument per line;
/// the environment it runs in, as the shell it is hands that on; and exactly
/// the script it was fed on stdin — then answers with a ruleset, so the
/// render it was asked for succeeds and the recording is what the test reads.
///
/// The environment is recorded the only way a script can record it, which is
/// why the two variables it names are the two the assertions can say
/// something about: `PATH` — a shell handed no `PATH` synthesizes its own
/// default, so "the daemon's own did not arrive" is the honest pin, not
/// "none did" — and the one variable the render is allowed to set, the
/// stand-in mount table. A shell cannot vouch for what it was handed beyond
/// that: it rewrites its environment before a script's first line runs.
///
/// The stub is `/bin/sh`, not bash: the point is what the *daemon* handed
/// its child, and a shell that read `BASH_ENV` would have already broken
/// that before the recording could see it.
#[cfg(test)]
fn recording_bash(dir: &Path) -> PathBuf {
    let bash = dir.join("bash");
    let dir = dir.display();
    std::fs::write(
        &bash,
        format!(
            "#!/bin/sh\n\
             dir='{dir}'\n\
             printf '%s\\n' \"$@\" >\"$dir/argv\"\n\
             {{\n\
                 [ -n \"${{PATH:-}}\" ] && printf 'PATH=%s\\n' \"$PATH\"\n\
                 [ -n \"${{MINIMAL_OVERRIDE_CGROUP_MOUNTINFO:-}}\" ] && \\\n\
                     printf 'MINIMAL_OVERRIDE_CGROUP_MOUNTINFO=%s\\n' \\\n\
                         \"$MINIMAL_OVERRIDE_CGROUP_MOUNTINFO\"\n\
             }} >\"$dir/env\"\n\
             cat >\"$dir/stdin\"\n\
             printf 'add table inet minimal_class\\n'\n\
             exit 0\n"
        ),
    )
    .expect("writing the recording bash stub");
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&bash, std::fs::Permissions::from_mode(0o755))
            .expect("the recording bash stub is executable");
    }
    bash
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

    /// The one rendered text, in both lanes that load it: the install's own
    /// `nft -f` transaction — the bytes a native host's privileged step
    /// pipes to the packet filter — and the guest's boot load, which hands
    /// the same render to the guest's own `nft`, twice, as a check and then
    /// as the load. Both come from `render_ruleset` and neither spells a
    /// rule the other does not, so a digest over each must be the same
    /// digest, and both digests must cover exactly the bytes the lane piped
    /// — never a re-render: a rule added to one lane and not the other is a
    /// host whose two spellings of the same table disagree, and a digest
    /// over anything but the piped bytes is a digest a person cannot
    /// compare against the table their host loaded. Read by driving both
    /// loads, each over a recording stand-in for `nft`, so what is compared
    /// is what each lane really hands the packet filter — and the reply
    /// admission this round added is part of that one text.
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
        // The guest lane: one render, handed to the guest's nft twice — as
        // `-c -f -` and then as `-f -` — and digested once, over the bytes
        // the load piped, which is the digest the boot logs and a person
        // reads in a bundle.
        let guest_mount = standin_mount();
        let guest_nft = tempfile::tempdir().expect("a temp dir holding the guest's recording nft");
        let nft = recording_nft(guest_nft.path(), &[]);
        let params = guest_params(
            &guest_mount,
            Some(&guest_mount.mountinfo),
            TEST_COHORT_ADDRESS
                .parse()
                .expect("the harness cohort address"),
            TEST_NODE_PLANE_ADDRESS
                .parse()
                .expect("the harness node-plane address"),
        );
        let loaded = load_guest_table(&guest_bash(), &nft, &params)
            .expect("the guest's load runs over a stub that accepts it");
        let calls = nft_calls(guest_nft.path());
        assert_eq!(
            calls.len(),
            2,
            "the guest's load is a check and then a load: {calls:?}"
        );
        assert_eq!(
            calls[0].1, calls[1].1,
            "one render's bytes reach the guest's nft twice, never a re-render"
        );
        let guest_piped = calls[1].1.clone();
        assert_eq!(
            loaded.digest,
            sha256_hex(&guest_piped),
            "the digest the boot logs covers exactly the bytes piped to the load"
        );

        // The print lane: the same transaction as text.
        let printed = rendered_ruleset();
        assert_eq!(
            blake3::hash(&guest_piped),
            blake3::hash(printed.as_bytes()),
            "the bytes the guest's boot pipes are the one rendered text in \
             both lanes:\n-- piped --\n{}-- printed --\n{printed}",
            String::from_utf8_lossy(&guest_piped),
        );
        assert!(
            printed.contains("ct state established,related ct direction reply accept"),
            "the reply admission is part of the one rendered text: {printed}"
        );
        let mount = standin_mount();
        // The install lane: the step lays out its stand-in tree, renders its
        // one transaction, and hands it to `nft` — the recording one, so
        // the bytes it was handed are this proof's own artifact. The step
        // refuses to delegate its tree to root, so a test running as root
        // cannot rehearse an install at all — the root check the rehearsal
        // posture lifts is the only privilege it does. Say so: the guest
        // lane above and the print lane already pin the one text, which
        // needs none of this.
        let installed = match run_install(&mount, stub.path()) {
            Some(installed) => installed,
            None => {
                eprintln!(
                    "skipping the install lane of \
                     ruleset_digest_covers_bytes_piped_to_nft_in_both_lanes: \
                     the install this lane rehearses refuses to delegate its tree \
                     to root, and this test runs as root"
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
        assert_eq!(
            blake3::hash(piped.as_bytes()),
            blake3::hash(printed.as_bytes()),
            "the bytes the install pipes are the one rendered text in both \
             lanes:\n-- piped --\n{piped}-- printed --\n{printed}"
        );
        assert!(
            piped.contains("ct state established,related ct direction reply accept"),
            "the reply admission is part of the one rendered text: {piped}"
        );
        // And the digests agree: the digest the install printed over the
        // bytes it piped is the one the guest's load logged over the bytes
        // it piped — one render, one digest, both lanes.
        let reported = String::from_utf8_lossy(&installed.stdout);
        let reported = reported
            .split_once("sha256 ")
            .and_then(|(_, tail)| tail.split_once(','))
            .map(|(digest, _)| digest.to_string())
            .expect("the install prints the digest of the bytes it piped");
        assert_eq!(
            reported, loaded.digest,
            "the install's digest and the guest load's digest cover the same \
             bytes"
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
            command.starts_with("sudo "),
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
        // write it there. The guest's half has one more fact than the
        // native host's — its recheck reads the table back out of its own
        // kernel with `nft list`, which no test host can answer for it, so
        // the listing is handed to the decision here as the fact a guest
        // whose boot loaded its table reads (the recheck itself is pinned
        // in `guest_decide_rechecks_table_not_only_marker`).
        std::fs::create_dir_all(root.join(sandbox2::classifier::TABLE_MARKER))
            .expect("the step writes the table's marker");
        let decided = decide(root, Some(&mountinfo(root, true)), false, refused_reading);
        assert!(
            decided.can_decide_per_box(),
            "a confining native host with the step installed and its table \
             refusing decides per box"
        );
        assert_eq!(
            decided.cause(),
            None,
            "a decided native host names no cause"
        );
        let guest_decided = decide_over(
            root,
            Some(&mountinfo(root, true)),
            true,
            refused_reading,
            || Listing::Listed,
        );
        assert!(
            guest_decided.can_decide_per_box(),
            "a confining guest with its table loaded, listed and refusing \
             decides per box"
        );
        assert_eq!(
            guest_decided.cause(),
            None,
            "a decided guest names no cause"
        );

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
        let command = cause
            .install_command()
            .expect("reloading the table is the command that ends it");
        assert!(
            command.contains("install-host-classifier.sh"),
            "the command is the one thing that reloads the table: {command}"
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

    /// NET-079: the guest loads the installer's own render, not a second
    /// spelling of it kept in step. The daemon compiles the installer in
    /// from the one file — `include_str!`, never a copy staged anywhere a
    /// box could reach — and asks it for `--print-ruleset`; the step's own
    /// print mode renders the same table over the same mount facts, so the
    /// two renders must agree byte for byte, or the guest's table and the
    /// native host's would be two tables wearing one name. Pinned over both
    /// spellings of the identities the render takes: the harness pair the
    /// step's own tests render, and the guest's own collapsed pair, where
    /// both identities are the one address an un-enrolled guest has
    /// (NET-078) — an enrolled guest is handed the design §4.2 pair and
    /// renders it the same way.
    #[test]
    fn guest_table_is_the_installers_rendered_ruleset() {
        let mount = standin_mount();
        let guest_ip = IpAddr::V4(crate::net::SwitchSubnet::default().daemon_ip());
        let harness = (
            TEST_COHORT_ADDRESS
                .parse()
                .expect("the harness cohort address renders"),
            TEST_NODE_PLANE_ADDRESS
                .parse()
                .expect("the harness node-plane address renders"),
        );
        for (cohort, node_plane, why) in [
            (guest_ip, guest_ip, "the guest's own collapsed pair"),
            (
                harness.0,
                harness.1,
                "the harness pair the step's own tests render",
            ),
        ] {
            let step = step_command_over(
                &mount,
                &["--print-ruleset"],
                None,
                &cohort.to_string(),
                &node_plane.to_string(),
            )
            .output()
            .expect("running the step's print mode over the stand-in mount");
            assert!(
                step.status.success(),
                "the step renders the table over {why}: {}",
                String::from_utf8_lossy(&step.stderr),
            );
            let rendered = render_guest_ruleset(
                &guest_bash(),
                &guest_params(&mount, Some(&mount.mountinfo), cohort, node_plane),
            )
            .unwrap_or_else(|cause| panic!("the guest's render runs for {why}: {cause}"));
            assert_eq!(
                rendered,
                step.stdout,
                "the guest's render is the installer's own, byte for byte, over \
                 {why}:\n-- the guest's boot asks for --\n{}\n-- the step prints \
                 --\n{}",
                String::from_utf8_lossy(&rendered),
                String::from_utf8_lossy(&step.stdout),
            );
        }
    }

    /// The render's own discipline (NET-079): the installer is compiled into
    /// the daemon and fed to bash on stdin — invoked by absolute path, with
    /// the environment cleared, so no `BASH_ENV` and no `ENV` can tell the
    /// shell what else to read and no inherited `PATH` can pick a different
    /// toolchain for it — and every parameter arrives as argv after
    /// `--print-ruleset`, never interpolated into script text, so nothing a
    /// parameter spells can become a line the installer runs. Pinned over a
    /// recording stand-in for the guest's bash, because what is pinned is
    /// what the *daemon* handed its child, not what a shell chose to do with
    /// it.
    #[test]
    fn guest_installer_runs_with_cleared_env_and_argv_params() {
        let mount = standin_mount();
        let stubs = tempfile::tempdir().expect("a temp dir holding the recording bash");
        let bash = recording_bash(stubs.path());
        let guest_ip = IpAddr::V4(crate::net::SwitchSubnet::default().daemon_ip());
        render_guest_ruleset(&bash, &guest_params(&mount, None, guest_ip, guest_ip))
            .expect("the render runs over the recording bash");

        // The argv, one argument per line: bash's own `-s`, the `--` that
        // ends its option parsing so the first script flag is never one bash
        // re-reads, then the mode and every parameter the render takes.
        let argv: Vec<String> = std::fs::read_to_string(stubs.path().join("argv"))
            .expect("the recording bash captured its argv")
            .lines()
            .map(str::to_string)
            .collect();
        assert_eq!(
            argv,
            [
                "-s".to_string(),
                "--".to_string(),
                "--print-ruleset".to_string(),
                "--root".to_string(),
                mount.root.display().to_string(),
                "--answerer-address".to_string(),
                ANSWERER_ADDRESS.to_string(),
                "--answerer-port".to_string(),
                crate::net::answerer::ANSWERER_PORT.to_string(),
                "--cohort-address".to_string(),
                guest_ip.to_string(),
                "--node-plane-address".to_string(),
                guest_ip.to_string(),
                "--ct-mark-mask".to_string(),
                format!("0x{:08x}", GUEST_CT_MARK_MASK),
            ],
            "every parameter arrives as argv after --print-ruleset, none \
             interpolated into the script the daemon pipes"
        );

        // The environment, when the render reads the mount table its own
        // kernel wrote: the render names no stand-in mount table — the one
        // variable it is allowed to set is absent — and the PATH the child
        // runs with is not this daemon's own. A shell handed no PATH
        // synthesizes its own default, so "none was handed" is not
        // observable from inside one; what *is* observable, and what the
        // cleared handoff is for, is that the environment this daemon
        // inherited does not arrive.
        let bare = std::fs::read_to_string(stubs.path().join("env"))
            .expect("the recording bash captured the environment it runs in");
        let inherited = format!("PATH={}", std::env::var("PATH").unwrap_or_default());
        assert!(
            !bare.lines().any(|line| line == inherited),
            "the daemon's own PATH must not reach the installer's shell: {bare:?}"
        );
        assert!(
            !bare
                .lines()
                .any(|line| line.starts_with("MINIMAL_OVERRIDE_CGROUP_MOUNTINFO=")),
            "a render that reads its own kernel's mount table names no \
             stand-in: {bare:?}"
        );

        // The rehearsal seam named: the one variable the render may set is
        // the stand-in mount table, and it is there with the value the
        // render was told — the whole of what the cleared environment
        // carries, and still not this daemon's PATH.
        render_guest_ruleset(
            &bash,
            &guest_params(&mount, Some(&mount.mountinfo), guest_ip, guest_ip),
        )
        .expect("the render runs over the recording bash");
        let told = std::fs::read_to_string(stubs.path().join("env"))
            .expect("the recording bash captured the environment it runs in");
        let mountinfo = format!(
            "MINIMAL_OVERRIDE_CGROUP_MOUNTINFO={}",
            mount.mountinfo.display()
        );
        assert!(
            told.lines().any(|line| line == mountinfo),
            "the one variable the render sets is the stand-in mount table, \
             with the value it was told: {told:?}"
        );
        assert!(
            !told.lines().any(|line| line == inherited),
            "naming the stand-in does not un-clear the environment: {told:?}"
        );

        // And the script on stdin: the one file, compiled in — the bytes the
        // daemon pipes are the bytes `include_str!` read at build time, so
        // the guest's table is rendered by the installer a native host's
        // step runs, never a copy that could drift.
        let stdin = std::fs::read(stubs.path().join("stdin"))
            .expect("the recording bash captured the script it was fed");
        assert_eq!(
            stdin,
            INSTALLER_SCRIPT.as_bytes(),
            "the installer is fed to bash whole, from the one compiled-in file"
        );
    }

    /// NET-078's two identities as the guest's render takes them: two
    /// separate inputs, keyed separately — the boxes cohort's SNAT names the
    /// cohort identity and the node plane's names the node's, in that order,
    /// and nothing else in the table names an address. Swapping the two
    /// inputs swaps the two rules and moves nothing else, which is what
    /// makes them two inputs rather than one; and where the guest has only
    /// the one address an un-enrolled host gives it, both rules still
    /// render — the daemon hands the render the pair, never leaves it to
    /// assume one identity from the other.
    #[test]
    fn guest_render_takes_node_plane_and_cohort_separately() {
        let cohort = IpAddr::V4(Ipv4Addr::new(100, 72, 0, 9));
        let node_plane = IpAddr::V4(Ipv4Addr::new(100, 72, 0, 1));
        let rendered = String::from_utf8(guest_ruleset(cohort, node_plane))
            .expect("the guest's render is text");

        // What each postrouting rule translates to: the identity it was
        // handed, in the order the table loads them — the cohort first, the
        // node plane behind it.
        let identities = |ruleset: &str| {
            chain_rules(ruleset, "postrouting")
                .iter()
                .map(|rule| {
                    rule.rsplit("snat ip to ")
                        .next()
                        .unwrap_or_else(|| panic!("each rule names one identity: {rule}"))
                        .to_string()
                })
                .collect::<Vec<_>>()
        };
        let postrouting = chain_rules(&rendered, "postrouting");
        assert_eq!(
            postrouting.len(),
            2,
            "one translation per identity: {postrouting:?}"
        );
        assert_eq!(
            identities(&rendered),
            [cohort.to_string(), node_plane.to_string()],
            "the cohort's rule names the cohort identity and the node plane's \
             names the node's, in that order: {postrouting:?}"
        );

        // Swapping the inputs swaps the two rules and moves nothing else in
        // the table: an identity is a value the two rules read, not a fact
        // the table's shape depends on.
        let swapped = String::from_utf8(guest_ruleset(node_plane, cohort))
            .expect("the guest's render is text");
        assert_eq!(
            identities(&swapped),
            [node_plane.to_string(), cohort.to_string()],
            "the identities are two inputs: swapping them swaps the rules that \
             name them"
        );
        // Every line the identities do not touch, compared whole: the two
        // renders agree everywhere but the two SNAT rules.
        fn without_identities(ruleset: &str) -> Vec<&str> {
            ruleset
                .lines()
                .filter(|line| !line.contains("snat ip to "))
                .collect()
        }
        assert_eq!(
            without_identities(&rendered),
            without_identities(&swapped),
            "the identities move the two SNAT rules and nothing else"
        );

        // The collapsed pair an un-enrolled guest hands: both identities are
        // its one address, and both rules still render — the daemon tells
        // the render so, so the table it loads spells both identities.
        let guest_ip = IpAddr::V4(crate::net::SwitchSubnet::default().daemon_ip());
        let collapsed = String::from_utf8(guest_ruleset(guest_ip, guest_ip))
            .expect("the guest's render is text");
        assert_eq!(
            identities(&collapsed),
            [guest_ip.to_string(), guest_ip.to_string()],
            "the collapsed pair still renders both rules, one per identity"
        );
    }

    /// NET-079's one carve-out, as the guest's own render spells it: the
    /// dstnat rule retargets a *deny-subtree* socket's lookups at DNS's port
    /// onto the answerer's address and port — matched by address and port,
    /// never loopback-wide :53 and never the node plane's DNS — so a
    /// deny-all box's resolver is the one destination its connections are
    /// admitted to and nothing else's lookups are moved. Read off the
    /// guest's own render, the one its boot loads, over the collapsed pair
    /// of identities an un-enrolled guest has.
    #[test]
    fn guest_dstnat_scoped_to_deny_subtree() {
        let guest_ip = IpAddr::V4(crate::net::SwitchSubnet::default().daemon_ip());
        let ruleset = String::from_utf8(guest_ruleset(guest_ip, guest_ip))
            .expect("the guest's render is text");
        let dstnat = chain_rules(&ruleset, "dstnat");
        assert_eq!(
            dstnat.len(),
            1,
            "one retargeting rule, nothing else at dstnat: {dstnat:?}"
        );
        let rel = tree_root_name();
        let deny_subtree = format!(
            "{}/{}/{}",
            rel,
            sandbox2::classifier::BOXES_DIR,
            sandbox2::config::DENY_DIR
        );
        assert_eq!(
            dstnat[0],
            format!(
                "socket cgroupv2 level {} \"{}\" ip daddr {ANSWERER_ADDRESS} udp dport 53 \
                 dnat ip to {ANSWERER_ADDRESS}:{}",
                deny_subtree.split('/').count(),
                deny_subtree,
                crate::net::answerer::ANSWERER_PORT,
            ),
            "the rule matches a deny-subtree socket at the subtree's own level, \
             sending to the answerer's address on DNS's port, and retargets \
             exactly that one destination onto the answerer"
        );

        // Nothing else in the table moves a lookup: no other chain dnat's
        // anything, and no rule outside dstnat matches DNS's port — so a
        // lookup from anywhere but the deny subtree, and a lookup on any
        // other port from inside it, meets the table it always met.
        for chain in ["output", "deny_out", "classify", "postrouting"] {
            let rules = chain_rules(&ruleset, chain);
            assert!(
                rules.iter().all(|rule| !rule.contains("dnat ")),
                "the retargeting lives in dstnat alone, not {chain}: {rules:?}"
            );
            assert!(
                rules.iter().all(|rule| !rule.contains("udp dport 53")),
                "no rule outside dstnat matches DNS's port, so nothing is \
                 retargeted loopback-wide: {rules:?}"
            );
        }

        // And the node plane's DNS is never the destination: the resolver a
        // guest that decides nothing falls back to is the switch gateway, and
        // the carve-out never reaches it — the dstnat rule names the
        // answerer's address, the one address the deny chain admits.
        let node_dns = crate::net::SwitchSubnet::default().dns_server();
        assert!(
            !ruleset.contains(&node_dns.to_string()),
            "the node plane's DNS at {node_dns} is never the carve-out's \
             destination"
        );
    }

    /// The marker's discipline (NET-079), as the guest's own boot keeps it:
    /// the marker is the commit point of a load, written only after the
    /// check and the load both ran, and it is cleared before either — so a
    /// boot whose kernel refuses the render never leaves a marker standing
    /// over a table it did not load, not even one a previous boot wrote.
    /// Read over a recording stand-in for the guest's `nft`, so the calls
    /// the proof counts are the ones the daemon really made, and nft's own
    /// error is the failure the daemon logs.
    #[test]
    fn guest_marker_written_only_after_the_table_loads() {
        let mount = standin_mount();
        let root = &mount.root;
        let guest_ip = IpAddr::V4(crate::net::SwitchSubnet::default().daemon_ip());
        let params = guest_params(&mount, Some(&mount.mountinfo), guest_ip, guest_ip);

        // A load that succeeds: the check parses the render first, the load
        // applies it, both over one render's bytes, and only then the marker
        // — with the ct-mark mask recorded beside it, the one fact the
        // probe reads of the table's classification.
        let accepted = tempfile::tempdir().expect("a temp dir holding the recording nft");
        let nft = recording_nft(accepted.path(), &[]);
        let loaded = load_guest_table(&guest_bash(), &nft, &params)
            .expect("the load runs over an nft stub that accepts it");
        let calls = nft_calls(accepted.path());
        assert_eq!(
            calls.len(),
            2,
            "a load is a check and then a load: {calls:?}"
        );
        assert_eq!(
            calls[0].0,
            ["-c", "-f", "-"],
            "the check parses the render before anything applies: {:?}",
            calls[0].0
        );
        assert_eq!(
            calls[1].0,
            ["-f", "-"],
            "the load applies what the check accepted: {:?}",
            calls[1].0
        );
        assert_eq!(
            calls[0].1, calls[1].1,
            "one render's bytes reach nft twice, never a re-render"
        );
        assert_eq!(
            loaded.digest,
            sha256_hex(&calls[1].1),
            "the digest the boot logs covers exactly the bytes piped to the load"
        );
        assert!(
            root.join(sandbox2::classifier::TABLE_MARKER).is_dir(),
            "the marker is written after the load"
        );
        assert!(
            root.join(TEST_CT_MARK_RECORD).is_dir(),
            "the ct-mark mask is recorded beside it"
        );

        // A check that refuses: nft's own error is the failure the daemon
        // logs, no load ran behind it, and no marker stands — the marker the
        // load above wrote is taken away first, so it cannot vouch for a
        // table this boot never had.
        let refused = tempfile::tempdir().expect("a temp dir holding the recording nft");
        let nft = recording_nft(refused.path(), &["-c"]);
        match load_guest_table(&guest_bash(), &nft, &params) {
            Err(GuestLoadFailure::Check(cause)) => assert!(
                cause.contains("Operation not supported"),
                "nft's own error names what it refused: {cause}"
            ),
            other => panic!("a refused check is the check's own failure, not {other:?}"),
        }
        assert_eq!(
            nft_calls(refused.path()).len(),
            1,
            "the check that refused is the only call: no load ran behind it"
        );
        assert!(
            !root.join(sandbox2::classifier::TABLE_MARKER).is_dir(),
            "a refused check writes no marker, and the one a previous load \
             wrote does not survive a load that did not run"
        );

        // A load that refuses after its check accepted: the previous table,
        // if any, is untouched and still no marker stands.
        let failed = tempfile::tempdir().expect("a temp dir holding the recording nft");
        let nft = recording_nft(failed.path(), &["-f"]);
        match load_guest_table(&guest_bash(), &nft, &params) {
            Err(GuestLoadFailure::Load(cause)) => assert!(
                cause.contains("Operation not supported"),
                "nft's own error names what it refused: {cause}"
            ),
            other => panic!("a refused load is the load's own failure, not {other:?}"),
        }
        assert!(
            !root.join(sandbox2::classifier::TABLE_MARKER).is_dir(),
            "a refused load writes no marker"
        );
        assert!(
            !root.join(TEST_CT_MARK_RECORD).is_dir(),
            "the record goes with the marker: only a load that succeeds \
             writes either again"
        );
    }

    /// A load that failed is the state the launch answers for (NET-079):
    /// the guest reports the interim — its own cause, never a broken
    /// image's — and the interim refuses a deny-all host-address box again
    /// rather than running it on a refusal nothing is making, with no
    /// installer named for a person who cannot run one inside a microVM.
    /// And the decision the launch reads is the one its own reader carries,
    /// so a guest's network plan follows a fact, not a hope.
    #[test]
    #[serial_test::serial]
    fn guest_load_failure_keeps_deny_all_refused() {
        let mount = standin_mount();
        let root = &mount.root;
        let table = mountinfo(root, true);
        let guest_ip = IpAddr::V4(crate::net::SwitchSubnet::default().daemon_ip());
        // The cohort the boot would install is still there: the subtrees are
        // this daemon's own half, and only the table's marker is the load's.
        installed_cohort(root);

        let failed = tempfile::tempdir().expect("a temp dir holding the recording nft");
        let nft = recording_nft(failed.path(), &["-f"]);
        let params = guest_params(&mount, Some(&mount.mountinfo), guest_ip, guest_ip);
        assert!(
            load_guest_table(&guest_bash(), &nft, &params).is_err(),
            "the load the stub refuses fails"
        );
        assert!(
            !root.join(sandbox2::classifier::TABLE_MARKER).is_dir(),
            "a failed load leaves no marker to vouch for a table"
        );
        assert!(
            root.join(sandbox2::classifier::BOXES_DIR)
                .join(sandbox2::config::DENY_DIR)
                .is_dir(),
            "the subtrees stay: only the table's marker is the boot's half"
        );

        // The decision over that tree, over a reading that would have
        // decided per box: the facts gate the probe, so the failure is what
        // the launch reads, whatever its effect would have said.
        let decision = decide(root, Some(&table), true, refused_reading);
        assert!(
            !decision.can_decide_per_box(),
            "a guest whose table never loaded decides nothing per box"
        );
        let cause = decision.cause().expect("the failure names its cause");
        assert_eq!(
            cause,
            Cause::GuestTableNotLoaded,
            "the cause is the interim"
        );
        let detail = cause.detail();
        assert!(
            detail.contains("not available yet") && !detail.contains("broken"),
            "the interim is not a broken image: {detail}"
        );
        assert!(
            cause.install_command().is_none(),
            "no installer exists for a person to run inside a microVM"
        );
        assert_eq!(
            cause.host_ip_box_outcome(true),
            "its deny-all host-address boxes are refused and its other \
             host-address boxes run unenforced",
            "the interim refuses the deny-all box rather than run it on nothing"
        );

        // And the launch's own reader carries the same undecidable decision,
        // so the plan that follows it resolves through the node's DNS layer.
        note_decision(&decision);
        assert!(
            !freshest_decision().is_some_and(|read| read.can_decide_per_box()),
            "the decision memo says nothing per box either, over a reading \
             that would have decided per box had the facts held"
        );
    }

    /// The guest's recheck (NET-079): a marker is the boot's claim, and the
    /// kernel is the fact — `nft list` must name the table *and* the deny
    /// chain the verdict rides on before anything rests on the marker, and
    /// a table gone behind it is its own cause, read before the probe runs,
    /// because a connect that nothing refused would dress the absence up as
    /// the table not refusing. The native host has no recheck to make: its
    /// step's marker and the probe are the whole decision there.
    #[test]
    fn guest_decide_rechecks_table_not_only_marker() {
        let mount = standin_mount();
        let root = &mount.root;
        let table = mountinfo(root, true);
        let probes = std::cell::Cell::new(0);
        let rechecks = std::cell::Cell::new(0);

        // No marker: nothing is read back from any kernel, and the guest
        // does not decide — the boot's half is missing before any fact of
        // the table's could matter.
        let unmarked = decide_over(
            root,
            Some(&table),
            true,
            || {
                probes.set(probes.get() + 1);
                refused_reading()
            },
            || panic!("a tree with no marker is not read back from any kernel"),
        );
        assert_eq!(
            unmarked.cause(),
            Some(Cause::GuestTableNotLoaded),
            "a tree with no marker is the interim, whatever its table"
        );
        assert_eq!(probes.get(), 0, "no probe runs over a tree with no marker");

        // The recheck runs after the marker, not instead of it: a tree with
        // its subtrees but no marker is still the interim, and no listing is
        // consulted for it either.
        installed_cohort(root);
        std::fs::remove_dir_all(root.join(sandbox2::classifier::TABLE_MARKER))
            .expect("removing the marker");
        let listed = std::cell::Cell::new(0);
        let still_unmarked = decide_over(root, Some(&table), true, refused_reading, || {
            listed.set(listed.get() + 1);
            Listing::Listed
        });
        assert_eq!(
            still_unmarked.cause(),
            Some(Cause::GuestTableNotLoaded),
            "the marker gates the recheck too: subtrees alone are no table"
        );
        assert_eq!(listed.get(), 0, "no listing is read without the marker");
        std::fs::create_dir_all(root.join(sandbox2::classifier::TABLE_MARKER))
            .expect("restoring the marker");

        // A table the kernel no longer holds behind its marker — a flush, a
        // failed reload — is its own cause, with the recheck's own words in
        // the daemon's log, and the probe does not run over it.
        let gone = decide_over(
            root,
            Some(&table),
            true,
            || {
                probes.set(probes.get() + 1);
                refused_reading()
            },
            || {
                rechecks.set(rechecks.get() + 1);
                Listing::Gone(
                    "nft list table inet minimal_class failed: No such file or \
                     directory"
                        .to_string(),
                )
            },
        );
        assert!(
            !gone.can_decide_per_box(),
            "a marker over a table that is not there decides nothing"
        );
        assert_eq!(
            gone.cause(),
            Some(Cause::TableNotEffective),
            "the gone table is the cause, never the probe's to read"
        );
        assert_eq!(
            probes.get(),
            0,
            "no probe runs over a kernel that holds no table"
        );
        assert_eq!(
            rechecks.get(),
            1,
            "the recheck is the guest's own read of its kernel"
        );

        // A listing that names the table without its deny chain is the same
        // state: the chain is where the verdict rides, and a table that
        // carries no chain decides nothing.
        let bare = decide_over(root, Some(&table), true, refused_reading, || {
            Listing::Gone(
                "nft lists the table inet minimal_class without its chain \
                     deny_out chain"
                    .to_string(),
            )
        });
        assert_eq!(
            bare.cause(),
            Some(Cause::TableNotEffective),
            "a table without its deny chain is not a table that refuses"
        );

        // With the table listed behind it, the marker's claim is the
        // probe's to check — and only a refusal the chain itself read as
        // decides per box.
        let decided = decide_over(root, Some(&table), true, refused_reading, || {
            Listing::Listed
        });
        assert!(decided.can_decide_per_box());
        assert_eq!(decided.cause(), None, "a decided guest names no cause");

        // The native host has no recheck to make: no listing is consulted
        // there, and its marker and the probe decide.
        let native = decide_over(root, Some(&table), false, refused_reading, || {
            panic!("the native decision does not read its kernel back")
        });
        assert!(
            native.can_decide_per_box(),
            "natively the marker and the probe are the whole decision"
        );
    }

    /// The guest's verdict rests on the effect, read through the listener its
    /// boot holds (NET-079, design §7.4): with no marker nothing is spawned
    /// and the guest does not decide; with the cohort installed, the reading
    /// the daemon takes live — over a held listener, from a probe child
    /// placed in a deny leaf — is the only thing that can decide per box,
    /// and behind no table it says so: connected, not refused, never a
    /// `per_box` claimed over a filter that admits the probe.
    #[test]
    #[serial_test::serial]
    fn guest_effect_probe_decides_per_box() {
        let mount = standin_mount();
        let root = &mount.root;
        let table = mountinfo(root, true);

        // No marker: nothing is spawned and the guest does not decide, so a
        // boot whose table never loaded costs no fork and claims no verdict.
        let probes = std::cell::Cell::new(0);
        let unmarked = decide_over(
            root,
            Some(&table),
            true,
            || {
                probes.set(probes.get() + 1);
                refused_reading()
            },
            || Listing::Listed,
        );
        assert!(!unmarked.can_decide_per_box());
        assert_eq!(
            unmarked.cause(),
            Some(Cause::GuestTableNotLoaded),
            "the boot's half is missing, whatever the effect would read"
        );
        assert_eq!(probes.get(), 0, "no probe runs over a tree with no marker");

        // The cohort the boot installs, and the listeners the daemon holds:
        // the guest's reading connects to a listener its boot held, never
        // one bound for the probe's duration — a port refused only while
        // the probe was looking would be a reading about the probe.
        installed_cohort(root);
        clear_probe_listeners();
        let held = hold_probe_listeners().expect("the daemon holds its probe listeners");
        assert!(
            held.iter().any(|(family, _)| *family == Family::V4),
            "127.0.0.1 is always among the families the daemon probes"
        );

        // The reading itself, live: behind no table the probe's child
        // connects and the reading says so in its own words — the decision
        // built over it decides nothing, because a marker is not a verdict
        // and on this host nothing is refusing (the table itself is pinned
        // in `guest_decide_rechecks_table_not_only_marker`).
        let reading = read_held_filter(root);
        let legs = reading.legs();
        assert!(
            legs.contains(&(Family::V4, Observed::Connected)),
            "behind no table the probe's own v4 leg connects: {legs:?}"
        );
        let not_refused = decide_over(
            root,
            Some(&table),
            true,
            || reading.clone(),
            || Listing::Listed,
        );
        assert!(
            !not_refused.can_decide_per_box(),
            "a reading the table did not refuse decides nothing"
        );
        assert_eq!(
            not_refused.cause(),
            Some(Cause::TableNotEffective),
            "the effect is the verdict's whole second half"
        );

        // And only a reading every family of which the chain refused decides
        // per box: the guest's verdict is the effect, never the marker.
        let decided = decide_over(root, Some(&table), true, refused_reading, || {
            Listing::Listed
        });
        assert!(decided.can_decide_per_box());
        assert_eq!(decided.cause(), None, "a decided guest names no cause");
        clear_probe_listeners();
    }

    /// A boot that holds no listener cannot read its table's effect, and
    /// unknown is not a verdict (design §7.4): the reading says so in its
    /// own words, carries no evidence it cannot vouch for, and the decision
    /// over it is the probe's own cause — which refuses the deny-all box
    /// again rather than running it on an unreadable refusal. Held, the
    /// listeners are live and none of them is the answerer's port, so what
    /// the probe's child meets is the table's verdict and never the
    /// carve-out; and a listener the daemon does not hold is caught by the
    /// control leg first, read as unknown with the daemon's own connect
    /// named.
    #[test]
    #[serial_test::serial]
    fn guest_effect_probe_inconclusive_without_live_listener() {
        let mount = standin_mount();
        let root = &mount.root;
        let table = mountinfo(root, true);
        installed_cohort(root);

        // A boot that holds no listener reads its table's effect as unknown:
        // there is no destination the probe's child could be refused at.
        clear_probe_listeners();
        let unreadable = read_held_filter(root);
        match &unreadable {
            Reading::Inconclusive { because } => assert!(
                because.contains("holds no loopback listener"),
                "the reading names the listener that is not there: {because}"
            ),
            other => panic!("no held listener reads as unknown, not {other:?}"),
        }
        assert!(
            unreadable.legs().is_empty(),
            "an unknown effect carries no evidence it cannot vouch for"
        );
        let undecidable = decide_over(
            root,
            Some(&table),
            true,
            || unreadable.clone(),
            || Listing::Listed,
        );
        assert!(!undecidable.can_decide_per_box());
        assert_eq!(
            undecidable.cause(),
            Some(Cause::ProbeUnreadable),
            "an effect that could not be read is its own cause"
        );
        assert_eq!(
            Cause::ProbeUnreadable.host_ip_box_outcome(true),
            "its deny-all host-address boxes are refused and its other \
             host-address boxes run unenforced",
            "unknown refuses the deny-all box rather than guess either way"
        );

        // Held, the listeners are live and none is the answerer's port: the
        // probe's destination is a port the carve-out does not admit, so
        // what its child meets is the table's own verdict.
        let held = hold_probe_listeners().expect("the daemon holds its probe listeners");
        for (family, addr) in &held {
            assert_ne!(
                addr.port(),
                crate::net::answerer::ANSWERER_PORT,
                "the probe never connects to the answerer's port"
            );
            assert_eq!(
                addr.ip(),
                family.loopback(),
                "each held listener is this family's loopback"
            );
        }
        // And the control leg reads the same listeners the child will: the
        // daemon's own connect, from outside the deny subtree, ran first
        // and succeeded — the reading is about the table, not its listener.
        let live = read_held_filter(root);
        assert!(
            matches!(live, Reading::NotRefused { .. }),
            "behind no table the held reading is not a refusal: {:?}",
            live.record()
        );

        // A listener the daemon does not hold — a port that was live and is
        // no longer — is caught by the control leg before any child is
        // forked, and read as unknown naming the daemon's own connect:
        // never as the table not refusing, never as it refusing.
        let stale = {
            let listener = TcpListener::bind(SocketAddr::new(Family::V4.loopback(), 0))
                .expect("a loopback listener to point the probe at");
            let addr = listener.local_addr().expect("the dead listener's address");
            drop(listener);
            addr
        };
        match probe_effect(root, &[(Family::V4, stale)]) {
            Reading::Inconclusive { because } => assert!(
                because.contains("the daemon's own connect"),
                "the control leg is the failure the reading names: {because}"
            ),
            other => panic!("a dead endpoint reads as unknown, not {other:?}"),
        }
        clear_probe_listeners();
    }
}
