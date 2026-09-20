//! The host-address cohort: boxes that share the host's address, classified
//! apart from the daemon's own traffic by the cgroup each socket was opened in.
//!
//! A host-address box has no address of its own, so nothing on the wire tells
//! it apart from the daemon's own package fetch. The classifier (design §4.1,
//! proved by `docs/spikes/2026-09-22-cohort-cgroup-classifier.md`) tells them
//! apart where the socket is created instead: one cgroup tree per daemon, the
//! daemon in a leaf of its own and every host-address box in a leaf under the
//! cohort directory, and a packet-filter rule per subtree matching
//! `socket cgroupv2`. The two identities NET-078 asks for are those two match
//! identities and their counters, not two addresses.
//!
//! ```text
//! <root>/            the daemon's tree; no controller is enabled here
//!   daemon/          node-plane traffic: the daemon and its own helpers
//!   boxes/           the host-address cohort, one identity outside the box host
//!     deny/<box>/    one leaf per deny-all box: refused, less the answerer
//!     open/<box>/    one leaf per box with nothing decided per box here
//! ```
//!
//! A box's verdict is encoded by placement: a deny-all box's leaf sits under
//! `boxes/deny`, which one static rule refuses (NET-079), so the ruleset never
//! changes after it is installed and root never loads what the unprivileged
//! daemon wrote. The daemon's fetch from its sibling leaf is node-plane traffic
//! and never meets a box's rules (NET-080). The one carve-out from a deny-all
//! verdict is the resolver Minimal owns for the box, by address and port: the
//! box zone's answerer ([`ANSWERER`]), which forwards nothing.
//!
//! ## What confines a box to its leaf
//!
//! The box unshares its cgroup namespace while the daemon's leaf is still its
//! cgroup (the sandbox layer unshares before any placement), so that namespace
//! is rooted at the daemon's leaf; the daemon then moves the box into its own
//! leaf, which is outside that root. With cgroup2 mounted `nsdelegate` the
//! kernel refuses every migration whose source or destination is outside the
//! mover's namespace root, so from inside the box neither a sibling's leaf nor
//! the daemon's is reachable, through the host's cgroup2 mount or a fresh one
//! (the box's rootfs mounts no sysfs, and a box holds no capability to mount).
//!
//! ## The native install step
//!
//! The ruleset needs `CAP_NET_ADMIN`, which the native daemon lacks, so a
//! native host takes one privileged install step ([`install_command`]): it
//! copies the ruleset the daemon rendered under root's ownership and installs
//! a root service that reloads it whenever the daemon asks, which the daemon
//! does at every start, since a re-created tree has new cgroup ids. Where the
//! step, the delegated subtree, `nsdelegate` or the daemon's own placement is
//! missing the host cannot decide per box: session start says so, names every
//! cause, and records that host-address boxes run unenforced there (design
//! §7.4). A box is never refused on that ground.

use std::fmt;
use std::io;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{Duration, SystemTime};

use sessions::EgressPolicy;
use sessions::core::net_verdict::{DropRule, Endpoint, IPPROTO_TCP, IPPROTO_UDP, Verdict};

use super::answerer;

/// The name of the daemon's cgroup tree. The spike's name; nothing depends on
/// the suffix, but the depth of the tree's root renders into every rule, so it
/// is fixed here once and [`Layout::level`] derives from it.
pub const TREE_NAME: &str = "minimald.slice";
/// The daemon's own leaf under the root: the node-plane identity.
pub const DAEMON_LEAF: &str = "daemon";
/// The cohort directory under the root: every host-address box's leaf is two
/// levels below it, and the directory itself is the cohort identity.
pub const COHORT_DIR: &str = "boxes";
/// The class directory under the cohort whose leaves one static rule refuses.
pub const DENY_CLASS: &str = "deny";
/// The class directory under the cohort whose leaves the cohort rule admits.
pub const OPEN_CLASS: &str = "open";
/// Where the host mounts cgroup2.
pub const CGROUP2_MOUNT: &str = "/sys/fs/cgroup";
/// The nftables table every daemon's chain lives in.
pub const TABLE: &str = "minimal";

/// The box zone's answerer on a native host: the one carve-out from a deny-all
/// host-address box's verdict (address and port, never loopback-wide), and the
/// nameserver such a box resolves through instead of the host's own resolver.
/// Derived from where the answerer binds, so the two cannot disagree.
pub const ANSWERER: Endpoint = Endpoint {
    ip: match answerer::BIND_ADDR.ip() {
        IpAddr::V4(ip) => ip,
        IpAddr::V6(_) => panic!("the box-zone answerer binds IPv4 loopback"),
    },
    port: answerer::BIND_ADDR.port(),
};

/// Where the install step keeps what root loads: `<uid>.nft` per daemon uid,
/// and the reloader beside them.
pub const INSTALL_DIR: &str = "/etc/minimal/host-classifier";
/// Where the reloader stamps what it loaded, root-owned and world-readable,
/// so the daemon can tell its current ruleset is in the kernel without root
/// ever writing under the daemon's own directory.
pub const LOADED_STAMP_DIR: &str = "/run/minimal/host-classifier";
/// Under the daemon's state dir: the installer, the rendered ruleset and the
/// reload request the daemon writes for the install step to find.
pub const STATE_SUBDIR: &str = "net/host-classifier";
const INSTALLER_NAME: &str = "install-host-classifier.sh";
const RULES_NAME: &str = "rules.nft";
const REQUEST_NAME: &str = "request";
/// The installer, shipped inside the daemon so the command the advisory names
/// exists on every host the advisory prints on. The checkout copy is what the
/// shell lint runs over.
const INSTALLER_SOURCE: &str = include_str!("../../../../scripts/install-host-classifier.sh");

/// The session attribute recording whether this host decides per box for its
/// host-address boxes: `per-box` or `none`. What it records covers addresses,
/// never names.
pub const ENFORCEMENT_ATTR: &str = "host_ip_enforcement";
/// The same record inside the box, for the shell and anything it runs.
pub const ENFORCEMENT_ENV: &str = "MINIMAL_HOST_IP_ENFORCEMENT";
/// The session-start advisory, carried into the box for the banner to print.
pub const ADVISORY_ENV: &str = "MINIMAL_HOST_IP_ADVISORY";

/// The refusal a deny-all leaf's rule ends with. `reject` answers in 0 ms where
/// `drop` costs the box a connect timeout per attempt; NET-079 says refuse.
const REFUSAL: &str = "reject with icmpx admin-prohibited";

/// How long a session start waits for the install step's reloader to stamp
/// the daemon's request before deciding the ruleset is not loaded.
const LOAD_WAIT: Duration = Duration::from_secs(3);

/// Whether `policy` declares a box deny-all: an `allow_subnets` that admits
/// nothing and no name allow list. A box with no `egress` section is not
/// deny-all here (NET-074 scopes the deny-all default to own-address boxes),
/// and neither is one with a name allow list, which is bound by the open
/// question on native forwarding rather than by this module.
#[must_use]
pub fn is_deny_all(policy: Option<&EgressPolicy>) -> bool {
    policy.is_some_and(|p| {
        p.allow_subnets.as_ref().is_some_and(Vec::is_empty)
            && p.allow_dns_hosts.as_ref().is_none_or(Vec::is_empty)
    })
}

/// Whether `policy` carries any rule at all: a subnet or name list, or a
/// denied range. What such a box declares beyond deny-all is not decided per
/// box by the static classifier.
#[must_use]
pub fn has_rules(policy: Option<&EgressPolicy>) -> bool {
    let listed = |v: &Option<Vec<String>>| v.as_ref().is_some_and(|v| !v.is_empty());
    policy.is_some_and(|p| {
        p.allow_subnets.is_some()
            || listed(&p.allow_dns_hosts)
            || listed(&p.deny_subnets)
            || p.allow_protocols.is_some()
    })
}

/// The two source identities the classifier tells apart (NET-078).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SourceIdentity {
    /// The daemon's own traffic: package fetches, the switch, its helpers.
    NodePlane,
    /// Every host-address box; one identity outside the box host.
    Cohort,
}

impl SourceIdentity {
    /// The identity as logs and counters spell it.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NodePlane => "node-plane",
            Self::Cohort => "host-address-cohort",
        }
    }
}

impl fmt::Display for SourceIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What the classifier makes of one cgroup path.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Classified {
    /// The daemon's leaf, or anything below it.
    NodePlane,
    /// A host-address box's leaf, or anything below it: the move a confined
    /// box can still make is into a child of its own leaf, which the prefix
    /// match covers.
    Box {
        /// The leaf's name.
        id: String,
        /// Under the deny class, where the static rule refuses.
        deny_all: bool,
    },
    /// Under the cohort directory but in no leaf this daemon placed: the
    /// cohort identity, which is all that is known outside the box host.
    Cohort,
}

impl Classified {
    /// The source identity this classification carries.
    #[must_use]
    pub fn source(&self) -> SourceIdentity {
        match self {
            Self::NodePlane => SourceIdentity::NodePlane,
            Self::Box { .. } | Self::Cohort => SourceIdentity::Cohort,
        }
    }
}

/// What a rule matches beyond the cgroup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Filter {
    /// Every destination.
    Any,
    /// TCP or UDP to one address and port: the resolver carve-out.
    Resolver(Endpoint),
}

/// What a matched rule does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Accept,
    Reject,
}

/// One rule of the static ruleset: a `socket cgroupv2` prefix match at a
/// depth, a filter, and an action. [`Layout::ruleset`] renders these and
/// [`Layout::verdict`] evaluates them, so what the tests prove is what root
/// loads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    /// The depth of the matched path: `level N` compares the socket's first
    /// `N` cgroup components with `cgroup`.
    pub level: usize,
    /// The kernel cgroup path matched, relative to the cgroup2 mount.
    pub cgroup: String,
    pub filter: Filter,
    pub action: Action,
    /// The rule's comment: the identity it counts for.
    pub comment: &'static str,
}

impl Rule {
    /// Whether a socket opened from `cgroup_path` to `dst` over `proto`
    /// matches this rule.
    fn matches(&self, cgroup_path: &str, dst: Endpoint, proto: u8) -> bool {
        let prefix_matches = cgroup_path
            .split('/')
            .filter(|c| !c.is_empty())
            .take(self.level)
            .eq(self.cgroup.split('/').filter(|c| !c.is_empty()));
        prefix_matches
            && match self.filter {
                Filter::Any => true,
                Filter::Resolver(ep) => dst == ep && matches!(proto, IPPROTO_TCP | IPPROTO_UDP),
            }
    }

    /// The rule as `nft` reads it, without the `add rule` prefix.
    fn render(&self) -> String {
        let filter = match self.filter {
            Filter::Any => String::new(),
            Filter::Resolver(ep) => format!(
                " ip daddr {} meta l4proto {{ tcp, udp }} th dport {}",
                ep.ip, ep.port
            ),
        };
        let action = match self.action {
            Action::Accept => "accept",
            Action::Reject => REFUSAL,
        };
        format!(
            "socket cgroupv2 level {} \"{}\"{filter} counter {action} comment \"{}\"",
            self.level, self.cgroup, self.comment
        )
    }
}

/// One connection's classification and verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    /// Which of the two identities the connection carries.
    pub source: SourceIdentity,
    /// The box whose placement decided it, when one did.
    pub box_id: Option<String>,
    /// Admitted or refused.
    pub verdict: Verdict,
}

/// The daemon's cgroup tree: where its root is, and so where every leaf is,
/// how deep the rules match, and which chain carries them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layout {
    /// The root's kernel path, relative to the cgroup2 mount, no surrounding
    /// slashes: `user.slice/user-1000.slice/user@1000.service/minimald.slice`.
    root: String,
}

impl Layout {
    /// A tree rooted at `root`, a kernel cgroup path with or without slashes
    /// around it.
    #[must_use]
    pub fn new(root: &str) -> Self {
        Self {
            root: root.trim_matches('/').to_string(),
        }
    }

    /// The tree a guest daemon owns: it is pid 1 and root, so its tree sits
    /// at the top of the mount.
    #[must_use]
    pub fn guest() -> Self {
        Self::new(TREE_NAME)
    }

    /// The tree a native, unprivileged daemon can own: under the subtree the
    /// user manager delegates to it, found from the daemon's own placement
    /// (`/proc/self/cgroup`). `None` when no user manager placed it there: a
    /// daemon outside its user manager's delegation cannot move itself or a
    /// box into the subtree, since the common ancestor is root's.
    #[must_use]
    pub fn native(self_cgroup: &str) -> Option<Self> {
        let path = self_cgroup
            .lines()
            .find_map(|l| l.strip_prefix("0::"))?
            .trim()
            .trim_matches('/');
        let mut prefix = Vec::new();
        for component in path.split('/') {
            prefix.push(component);
            if user_manager_uid(component).is_some() {
                return Some(Self::new(&format!("{}/{TREE_NAME}", prefix.join("/"))));
            }
        }
        None
    }

    /// The root's kernel path.
    #[must_use]
    pub fn root(&self) -> &str {
        &self.root
    }

    /// The uid whose user manager delegates this tree; `None` for the guest
    /// tree at the top of the mount.
    #[must_use]
    pub fn uid(&self) -> Option<u32> {
        self.root.split('/').find_map(user_manager_uid)
    }

    /// The chain this tree's rules live in: one per daemon uid, so two users'
    /// daemons on one host never flush each other's rules.
    #[must_use]
    pub fn chain(&self) -> String {
        match self.uid() {
            Some(uid) => format!("host_cohort_{uid}"),
            None => "host_cohort".to_string(),
        }
    }

    /// The depth of the root: the `level` a `socket cgroupv2` match on the
    /// root itself would carry. Leaves match one and two levels deeper.
    #[must_use]
    pub fn level(&self) -> usize {
        self.root.split('/').filter(|c| !c.is_empty()).count()
    }

    /// The daemon's own leaf.
    #[must_use]
    pub fn daemon_leaf(&self) -> String {
        format!("{}/{DAEMON_LEAF}", self.root)
    }

    /// The cohort directory.
    #[must_use]
    pub fn cohort(&self) -> String {
        format!("{}/{COHORT_DIR}", self.root)
    }

    /// The class directory a box's leaf sits under.
    #[must_use]
    pub fn class_dir(&self, deny_all: bool) -> String {
        let class = if deny_all { DENY_CLASS } else { OPEN_CLASS };
        format!("{}/{class}", self.cohort())
    }

    /// The leaf a host-address box `id` is placed in.
    #[must_use]
    pub fn box_leaf(&self, id: &str, deny_all: bool) -> String {
        format!("{}/{id}", self.class_dir(deny_all))
    }

    /// Where `leaf` is on the host's cgroup2 mount.
    #[must_use]
    pub fn sysfs(&self, leaf: &str) -> PathBuf {
        Path::new(CGROUP2_MOUNT).join(leaf)
    }

    /// What `cgroup_path` (a kernel path, as `/proc/<pid>/cgroup` or the
    /// packet filter sees it) is in this tree; `None` for a path outside it.
    #[must_use]
    pub fn classify(&self, cgroup_path: &str) -> Option<Classified> {
        let path = cgroup_path.trim().trim_matches('/');
        let rest = strip_component_prefix(path, &self.root)?;
        let (head, tail) = rest.split_once('/').unwrap_or((rest, ""));
        match head {
            DAEMON_LEAF => Some(Classified::NodePlane),
            COHORT_DIR => {
                let (class, tail) = tail.split_once('/').unwrap_or((tail, ""));
                let id = tail.split('/').next().unwrap_or("");
                let deny_all = match class {
                    DENY_CLASS => true,
                    OPEN_CLASS => false,
                    _ => return Some(Classified::Cohort),
                };
                if id.is_empty() {
                    Some(Classified::Cohort)
                } else {
                    Some(Classified::Box {
                        id: id.to_string(),
                        deny_all,
                    })
                }
            }
            _ => None,
        }
    }

    /// The static ruleset that decides every box on this tree, in match
    /// order: the deny class's carve-out and refusal first, then the cohort
    /// identity, then the node-plane identity, each a counted
    /// `socket cgroupv2` prefix match. `level N` matches the first `N` path
    /// components, so the more specific rule comes first.
    #[must_use]
    pub fn rules(&self, answerer: Endpoint) -> Vec<Rule> {
        let level = self.level();
        vec![
            Rule {
                level: level + 2,
                cgroup: self.class_dir(true),
                filter: Filter::Resolver(answerer),
                action: Action::Accept,
                comment: "deny-all resolver",
            },
            Rule {
                level: level + 2,
                cgroup: self.class_dir(true),
                filter: Filter::Any,
                action: Action::Reject,
                comment: "deny-all refuse",
            },
            Rule {
                level: level + 1,
                cgroup: self.cohort(),
                filter: Filter::Any,
                action: Action::Accept,
                comment: SourceIdentity::Cohort.as_str(),
            },
            Rule {
                level: level + 1,
                cgroup: self.daemon_leaf(),
                filter: Filter::Any,
                action: Action::Accept,
                comment: SourceIdentity::NodePlane.as_str(),
            },
        ]
    }

    /// The ruleset as `nft -f` loads it: idempotent, so the reloader can run
    /// it at every daemon start, and confined to this tree's chain.
    #[must_use]
    pub fn ruleset(&self, answerer: Endpoint) -> String {
        let chain = self.chain();
        let mut out = format!(
            "# Minimal host-address classifier for {}; rendered by minimald, loaded by root.\n\
             add table inet {TABLE}\n\
             add chain inet {TABLE} {chain} {{ type filter hook output priority filter; policy accept; }}\n\
             flush chain inet {TABLE} {chain}\n",
            self.root
        );
        for rule in self.rules(answerer) {
            out.push_str(&format!(
                "add rule inet {TABLE} {chain} {}\n",
                rule.render()
            ));
        }
        out
    }

    /// The verdict the ruleset gives a connection opened from `cgroup_path`
    /// to `dst` over IPv4 protocol `proto`, or `None` for a socket outside
    /// the tree, which the classifier has nothing to say about. Evaluates
    /// [`Self::rules`] in order, as the kernel does the rendered chain.
    #[must_use]
    pub fn verdict(
        &self,
        cgroup_path: &str,
        dst: Endpoint,
        proto: u8,
        answerer: Endpoint,
    ) -> Option<Decision> {
        let classified = self.classify(cgroup_path)?;
        let box_id = match &classified {
            Classified::Box { id, .. } => Some(id.clone()),
            Classified::NodePlane | Classified::Cohort => None,
        };
        let path = cgroup_path.trim().trim_matches('/');
        let verdict = self
            .rules(answerer)
            .iter()
            .find(|rule| rule.matches(path, dst, proto))
            .map_or(Verdict::Admit, |rule| match rule.action {
                Action::Accept => Verdict::Admit,
                Action::Reject => Verdict::Drop(DropRule::Undeclared),
            });
        Some(Decision {
            source: classified.source(),
            box_id,
            verdict,
        })
    }
}

/// The uid a `user@<uid>.service` component names.
fn user_manager_uid(component: &str) -> Option<u32> {
    component
        .strip_prefix("user@")?
        .strip_suffix(".service")?
        .parse()
        .ok()
}

/// `path` with `prefix` (a whole number of components) removed, or `None`
/// when `path` is not at or below `prefix`.
fn strip_component_prefix<'a>(path: &'a str, prefix: &str) -> Option<&'a str> {
    let rest = path.strip_prefix(prefix)?;
    match rest.strip_prefix('/') {
        Some(rest) => Some(rest),
        None if rest.is_empty() => Some(""),
        None => None,
    }
}

/// Records one of the daemon's own package fetches as node-plane traffic:
/// it is opened from the daemon's leaf, so no host-address box's declaration
/// reaches it, deny-all or not (NET-080).
pub fn record_node_plane_fetch(what: &str) -> SourceIdentity {
    tracing::info!(
        what,
        source = %SourceIdentity::NodePlane,
        "daemon package fetch recorded as node-plane traffic"
    );
    SourceIdentity::NodePlane
}

/// Whether the host's cgroup2 mount carries `nsdelegate`, read from a
/// `/proc/self/mountinfo`; `None` when nothing mounts cgroup2 at all. Without
/// `nsdelegate` a cgroup namespace is no barrier to migration and a box as the
/// daemon's uid walks into a sibling's leaf.
#[must_use]
pub fn cgroup2_nsdelegate(mountinfo: &str) -> Option<bool> {
    mountinfo.lines().find_map(|line| {
        // `... - <fstype> <source> <super options>` after the separator.
        let (_, after) = line.split_once(" - ")?;
        let mut fields = after.split_whitespace();
        (fields.next()? == "cgroup2").then(|| {
            fields
                .nth(1)
                .is_some_and(|opts| opts.split(',').any(|o| o == "nsdelegate"))
        })
    })
}

/// The cgroup a `/proc/<pid>/cgroup` names, without surrounding slashes.
#[must_use]
pub fn cgroup_of(proc_cgroup: &str) -> Option<String> {
    proc_cgroup
        .lines()
        .find_map(|l| l.strip_prefix("0::"))
        .map(|p| p.trim().trim_matches('/').to_string())
}

/// The name a session's leaf carries: the session name with anything a
/// cgroup name cannot hold replaced.
#[must_use]
pub fn leaf_id(session: &str) -> String {
    let id: String = session
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
                c
            } else {
                '_'
            }
        })
        .collect();
    if id.is_empty() || id.starts_with('.') {
        format!("s_{id}")
    } else {
        id
    }
}

/// What the install step has left on this host, against what the daemon
/// renders now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallState {
    /// No ruleset is installed for this daemon's uid.
    Missing,
    /// A ruleset is installed but is not the one the daemon renders now: the
    /// tree or the answerer moved since the step ran.
    Stale,
    /// The installed ruleset is the current one.
    Current,
}

/// What a native host offers the classifier, read once per launch so a step
/// installed since the daemon started is seen at the next session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostProbe {
    /// What the privileged install step has left, against the current
    /// ruleset.
    pub install: InstallState,
    /// The exact command that runs the install step.
    pub install_command: String,
    /// The tree the daemon can own, if a user manager delegated one.
    pub delegated_root: Option<Layout>,
    /// cgroup2's `nsdelegate` mount option; `None` with no cgroup2 mount.
    pub nsdelegate: Option<bool>,
    /// The daemon sits in its own leaf, so a box's cgroup namespace roots
    /// there and the cohort is outside it.
    pub daemon_in_leaf: bool,
    /// Root's reloader has loaded the current ruleset since the daemon last
    /// asked, so the tree the daemon created is the one the rules name.
    pub ruleset_loaded: bool,
}

impl HostProbe {
    /// Reads the live host.
    #[must_use]
    pub fn live() -> Self {
        match native_host() {
            Some(host) => host.probe(),
            None => NativeHost::unstarted().probe(),
        }
    }
}

/// Why a native host cannot decide per box.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Cause {
    /// The ruleset's privileged install step has not run; the one cause an
    /// install command clears.
    InstallStepMissing,
    /// The install step ran for another ruleset than the one the daemon
    /// renders now, so what root loads does not name this tree.
    InstallStepStale,
    /// The daemon is not under a subtree its user manager delegated, so
    /// there is no root it can place itself or a box under.
    NoDelegatedSubtree,
    /// cgroup2 is mounted without `nsdelegate` (or not at all), so a cgroup
    /// namespace does not confine a box to its leaf.
    CgroupNotDelegated,
    /// The daemon could not enter its own leaf, so a box's cgroup namespace
    /// would root above the cohort and reach every leaf in it.
    DaemonNotInItsLeaf,
    /// The install step is in place but its reloader has not loaded the
    /// ruleset for the tree this daemon created.
    RulesetNotLoaded,
}

impl Cause {
    /// The cause as the advisory names it.
    #[must_use]
    pub fn describe(self) -> &'static str {
        match self {
            Self::InstallStepMissing => "the classifier's privileged install step has not run",
            Self::InstallStepStale => {
                "the classifier's privileged install step ran for another ruleset than this daemon's"
            }
            Self::NoDelegatedSubtree => {
                "the daemon is not under a cgroup subtree its user manager delegates (start it \
                 under the user manager, e.g. systemd-run --user --scope)"
            }
            Self::CgroupNotDelegated => "cgroup2 is not mounted with nsdelegate",
            Self::DaemonNotInItsLeaf => "the daemon could not enter its own classifier leaf",
            Self::RulesetNotLoaded => {
                "the classifier ruleset has not been loaded for this daemon's tree (check the \
                 minimal-host-classifier-<uid>.path unit)"
            }
        }
    }

    /// Whether running the install step clears this cause.
    fn cleared_by_install(self) -> bool {
        matches!(self, Self::InstallStepMissing | Self::InstallStepStale)
    }
}

/// The exact command that runs the privileged install step: the installer
/// the daemon wrote beside its rendered ruleset under `dir`.
#[must_use]
pub fn install_command(dir: &Path) -> String {
    format!("sudo bash {}", dir.join(INSTALLER_NAME).display())
}

/// Whether this native host decides per box for its host-address boxes.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PerBoxEnforcement {
    /// Every host-address box gets its own verdict on this tree.
    Enforced(Layout),
    /// No per-box verdict exists; each box runs with its declaration
    /// unenforced, for these causes, and the install command clears them
    /// when it is named.
    Unenforced {
        causes: Vec<Cause>,
        install_command: String,
    },
}

impl PerBoxEnforcement {
    /// Decided from what the host offers. Every missing piece is a cause, so
    /// the advisory names all of them rather than the first.
    #[must_use]
    pub fn decide(probe: &HostProbe) -> Self {
        let mut causes = Vec::new();
        match probe.install {
            InstallState::Missing => causes.push(Cause::InstallStepMissing),
            InstallState::Stale => causes.push(Cause::InstallStepStale),
            InstallState::Current => {}
        }
        if probe.delegated_root.is_none() {
            causes.push(Cause::NoDelegatedSubtree);
        }
        if probe.nsdelegate != Some(true) {
            causes.push(Cause::CgroupNotDelegated);
        }
        if !probe.daemon_in_leaf {
            causes.push(Cause::DaemonNotInItsLeaf);
        }
        if probe.install == InstallState::Current && !probe.ruleset_loaded {
            causes.push(Cause::RulesetNotLoaded);
        }
        match (causes.is_empty(), &probe.delegated_root) {
            (true, Some(layout)) => Self::Enforced(layout.clone()),
            _ => Self::Unenforced {
                causes,
                install_command: probe.install_command.clone(),
            },
        }
    }

    /// Whether a box's verdict is its own here.
    #[must_use]
    pub fn per_box(&self) -> bool {
        matches!(self, Self::Enforced(_))
    }

    /// The value [`ENFORCEMENT_ATTR`] records. It covers addresses, never
    /// names: name rules on a native host belong to the open question on
    /// native forwarding.
    #[must_use]
    pub fn record(&self) -> &'static str {
        if self.per_box() { "per-box" } else { "none" }
    }

    /// The session-start advisory, or `None` when nothing needs saying. Names
    /// every cause; carries the install command only when a cause it clears
    /// is among them. A statement, never a prompt: session start does not
    /// wait on it.
    #[must_use]
    pub fn advisory(&self) -> Option<String> {
        let Self::Unenforced {
            causes,
            install_command,
        } = self
        else {
            return None;
        };
        let named: Vec<&str> = causes.iter().map(|c| c.describe()).collect();
        let mut text = format!(
            "host-address boxes have no per-box egress enforcement on this host: {}.",
            named.join("; ")
        );
        if causes.iter().any(|c| c.cleared_by_install()) {
            text.push_str(&format!(
                " Install the classifier (one-time, needs root): {install_command}"
            ));
        }
        Some(text)
    }

    /// What a host-address box launched under this decision carries into
    /// its environment: the record, and the advisory when there is one.
    #[must_use]
    pub fn session_env(&self) -> Vec<(String, String)> {
        let mut env = vec![(ENFORCEMENT_ENV.to_string(), self.record().to_string())];
        if let Some(advisory) = self.advisory() {
            env.push((ADVISORY_ENV.to_string(), advisory));
        }
        env
    }
}

/// Where an enforcing host places one box.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Placement {
    /// The tree the leaf is created in.
    pub layout: Layout,
    /// The leaf's name.
    pub id: String,
    /// Under the deny class, refused by the static rule.
    pub deny_all: bool,
}

impl Placement {
    /// The leaf's kernel path.
    #[must_use]
    pub fn leaf(&self) -> String {
        self.layout.box_leaf(&self.id, self.deny_all)
    }
}

/// What session start decided for one host-address box.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionStart {
    /// The record and the advisory, for the box's environment.
    pub env: Vec<(String, String)>,
    /// The leaf to place the box in, on a host that decides per box.
    pub placement: Option<Placement>,
}

/// Decides, logs and records a native host's per-box enforcement for a
/// host-address box `session` at its start. Never an error: a box on an
/// unenforcing host runs. On an enforcing host a deny-all box is placed under
/// the deny class and a box with no rules under the open class; a box whose
/// rules go beyond deny-all is placed under the open class too, since the
/// static ruleset decides nothing finer, and is recorded unenforced with that
/// said.
#[must_use]
pub fn decide_session_start(
    session: &str,
    policy: Option<&EgressPolicy>,
    probe: &HostProbe,
) -> SessionStart {
    let enforcement = PerBoxEnforcement::decide(probe);
    let deny_all = is_deny_all(policy);
    let placement = match &enforcement {
        PerBoxEnforcement::Enforced(layout) => Some(Placement {
            layout: layout.clone(),
            id: leaf_id(session),
            deny_all,
        }),
        PerBoxEnforcement::Unenforced { .. } => None,
    };
    let identity = placement
        .as_ref()
        .map_or_else(|| SourceIdentity::Cohort.to_string(), Placement::leaf);
    // A list beyond deny-all on an enforcing host: the box runs, in the open
    // class, and its record says the list is not decided here.
    let listed_unenforced = enforcement.per_box() && !deny_all && has_rules(policy);
    let record = if listed_unenforced {
        "none"
    } else {
        enforcement.record()
    };
    tracing::info!(
        session,
        classifier_identity = %identity,
        deny_all,
        host_ip_enforcement = record,
        "host-address box launch"
    );
    let mut env = vec![(ENFORCEMENT_ENV.to_string(), record.to_string())];
    let advisory = if listed_unenforced {
        Some(
            "this host decides deny-all per host-address box and nothing finer: the box's \
             subnet or name list is not enforced here."
                .to_string(),
        )
    } else {
        enforcement.advisory()
    };
    if let Some(advisory) = advisory {
        tracing::warn!(session, %advisory, "host-address box runs unenforced");
        env.push((ADVISORY_ENV.to_string(), advisory));
    }
    SessionStart { env, placement }
}

/// [`decide_session_start`] against the live host, after giving the install
/// step's reloader [`LOAD_WAIT`] to answer a request the daemon made at its
/// start.
pub async fn native_session_start(session: &str, policy: Option<&EgressPolicy>) -> SessionStart {
    let probe = match native_host() {
        Some(host) => host.probe_settled().await,
        None => HostProbe::live(),
    };
    decide_session_start(session, policy, &probe)
}

/// The native daemon's side of the classifier: its tree and the directory it
/// writes for the install step.
#[derive(Debug)]
pub struct NativeHost {
    layout: Option<Layout>,
    /// `<state>/net/host-classifier`.
    dir: PathBuf,
}

static NATIVE: OnceLock<NativeHost> = OnceLock::new();

/// The native host [`native_daemon_start`] set up, if it ran.
#[must_use]
pub fn native_host() -> Option<&'static NativeHost> {
    NATIVE.get()
}

/// Creates the daemon's tree, enters its leaf, writes what the install step
/// needs and asks root's reloader for a load. Once per daemon, at start, on a
/// native host. Nothing here fails the daemon: whatever is missing shows up
/// as a cause at the next session start.
pub fn native_daemon_start(state_dir: &Path) {
    let host = NativeHost::start(state_dir);
    if NATIVE.set(host).is_err() {
        tracing::debug!("host-address classifier already started");
    }
}

impl NativeHost {
    fn unstarted() -> Self {
        let read = |p: &str| std::fs::read_to_string(p).unwrap_or_default();
        Self {
            layout: Layout::native(&read("/proc/self/cgroup")),
            dir: paths::minimal_state_dir()
                .as_utf8_path()
                .as_std_path()
                .join(STATE_SUBDIR),
        }
    }

    fn start(state_dir: &Path) -> Self {
        let read = |p: &str| std::fs::read_to_string(p).unwrap_or_default();
        let host = Self {
            layout: Layout::native(&read("/proc/self/cgroup")),
            dir: state_dir.join(STATE_SUBDIR),
        };
        let Some(layout) = &host.layout else {
            tracing::info!(
                "no user manager delegates a cgroup subtree to this daemon; host-address \
                 boxes run unenforced here"
            );
            return host;
        };
        if let Err(error) = host.create_tree(layout) {
            tracing::warn!(%error, root = layout.root(), "creating the classifier tree");
        }
        if let Err(error) = host.enter_daemon_leaf(layout) {
            tracing::warn!(%error, leaf = %layout.daemon_leaf(), "entering the daemon's classifier leaf");
        }
        if let Err(error) = host.write_install_files(layout) {
            tracing::warn!(%error, dir = %host.dir.display(), "writing the classifier install files");
        }
        tracing::info!(
            root = layout.root(),
            chain = %layout.chain(),
            dir = %host.dir.display(),
            "host-address classifier tree created"
        );
        host
    }

    /// The tree, and every leaf a previous daemon left empty removed.
    fn create_tree(&self, layout: &Layout) -> io::Result<()> {
        for leaf in [
            layout.daemon_leaf(),
            layout.class_dir(true),
            layout.class_dir(false),
        ] {
            std::fs::create_dir_all(layout.sysfs(&leaf))?;
        }
        for class in [layout.class_dir(true), layout.class_dir(false)] {
            if let Ok(entries) = std::fs::read_dir(layout.sysfs(&class)) {
                for entry in entries.flatten() {
                    // rmdir fails on a leaf that still holds a process, which
                    // is a leaf that is still in use.
                    let _ = std::fs::remove_dir(entry.path());
                }
            }
        }
        Ok(())
    }

    /// Moves this process into its leaf. Whole-process: cgroup2 domain
    /// cgroups take thread groups.
    fn enter_daemon_leaf(&self, layout: &Layout) -> io::Result<()> {
        adopt_pid(&layout.sysfs(&layout.daemon_leaf()), std::process::id())
    }

    fn write_install_files(&self, layout: &Layout) -> io::Result<()> {
        std::fs::create_dir_all(&self.dir)?;
        std::fs::write(self.dir.join(INSTALLER_NAME), INSTALLER_SOURCE)?;
        std::fs::write(self.dir.join(RULES_NAME), layout.ruleset(ANSWERER))?;
        // Written in place, not renamed into place: the install step's path
        // unit watches this file for a close-after-write.
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        std::fs::write(
            self.dir.join(REQUEST_NAME),
            format!("{} {now}\n", std::process::id()),
        )
    }

    /// The directory the install step reads.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// What this host offers, read now.
    #[must_use]
    pub fn probe(&self) -> HostProbe {
        let read = |p: &Path| std::fs::read_to_string(p).unwrap_or_default();
        let (install, daemon_in_leaf, ruleset_loaded) = match &self.layout {
            Some(layout) => {
                let rendered = layout.ruleset(ANSWERER);
                let install = match layout
                    .uid()
                    .and_then(|uid| std::fs::read_to_string(installed_ruleset(uid)).ok())
                {
                    None => InstallState::Missing,
                    Some(installed) if installed == rendered => InstallState::Current,
                    Some(_) => InstallState::Stale,
                };
                let in_leaf = cgroup_of(&read(Path::new("/proc/self/cgroup")))
                    .is_some_and(|c| c == layout.daemon_leaf());
                (install, in_leaf, self.ruleset_loaded(layout, &rendered))
            }
            None => (InstallState::Missing, false, false),
        };
        HostProbe {
            install,
            install_command: install_command(&self.dir),
            delegated_root: self.layout.clone(),
            nsdelegate: cgroup2_nsdelegate(&read(Path::new("/proc/self/mountinfo"))),
            daemon_in_leaf,
            ruleset_loaded,
        }
    }

    /// [`Self::probe`], waiting up to [`LOAD_WAIT`] for the reloader's stamp
    /// when everything but the load is in place.
    pub async fn probe_settled(&self) -> HostProbe {
        let deadline = tokio::time::Instant::now() + LOAD_WAIT;
        loop {
            let probe = self.probe();
            let decided = PerBoxEnforcement::decide(&probe);
            let only_the_load = matches!(
                &decided,
                PerBoxEnforcement::Unenforced { causes, .. }
                    if causes.as_slice() == [Cause::RulesetNotLoaded]
            );
            if !only_the_load || tokio::time::Instant::now() >= deadline {
                return probe;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// Whether root's stamp says the current ruleset was loaded after this
    /// daemon's request.
    fn ruleset_loaded(&self, layout: &Layout, rendered: &str) -> bool {
        let Some(uid) = layout.uid() else {
            return false;
        };
        let stamp = loaded_stamp(uid);
        let Ok(loaded) = std::fs::read_to_string(&stamp) else {
            return false;
        };
        if loaded != rendered {
            return false;
        }
        let mtime = |p: &Path| std::fs::metadata(p).and_then(|m| m.modified()).ok();
        match (mtime(&stamp), mtime(&self.dir.join(REQUEST_NAME))) {
            (Some(loaded_at), Some(asked_at)) => loaded_at >= asked_at,
            _ => false,
        }
    }

    /// Creates the leaf for `placement`, ready to adopt the box's process.
    pub fn place(&self, placement: &Placement) -> io::Result<Leaf> {
        let mut id = placement.id.clone();
        let mut leaf = placement.layout.box_leaf(&id, placement.deny_all);
        // Two live sessions may sanitize to one name; the second takes a
        // suffix rather than the first's leaf.
        for n in 2.. {
            match std::fs::create_dir(placement.layout.sysfs(&leaf)) {
                Ok(()) => break,
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists && n < 100 => {
                    id = format!("{}-{n}", placement.id);
                    leaf = placement.layout.box_leaf(&id, placement.deny_all);
                }
                Err(e) => return Err(e),
            }
        }
        tracing::info!(
            box_id = %id,
            classifier_identity = %leaf,
            deny_all = placement.deny_all,
            "host-address box placed in its classifier leaf"
        );
        Ok(Leaf {
            sysfs: placement.layout.sysfs(&leaf),
            kernel: leaf,
        })
    }
}

/// The installed ruleset for `uid`, the install step's marker.
#[must_use]
pub fn installed_ruleset(uid: u32) -> PathBuf {
    Path::new(INSTALL_DIR).join(format!("{uid}.nft"))
}

/// Root's stamp of what it last loaded for `uid`.
#[must_use]
pub fn loaded_stamp(uid: u32) -> PathBuf {
    Path::new(LOADED_STAMP_DIR).join(format!("{uid}.loaded"))
}

/// Writes `pid` into the cgroup at `sysfs`'s `cgroup.procs`.
fn adopt_pid(sysfs: &Path, pid: u32) -> io::Result<()> {
    std::fs::write(sysfs.join("cgroup.procs"), format!("{pid}\n"))
}

/// One box's leaf on the host's cgroup2 mount, removed at session end.
#[derive(Debug)]
pub struct Leaf {
    sysfs: PathBuf,
    kernel: String,
}

impl Leaf {
    /// The leaf's `cgroup.procs`, which a process the daemon injects into
    /// the box writes itself into before it joins the box's namespaces.
    #[must_use]
    pub fn procs_file(&self) -> PathBuf {
        self.sysfs.join("cgroup.procs")
    }

    /// The leaf's kernel path.
    #[must_use]
    pub fn kernel_path(&self) -> &str {
        &self.kernel
    }

    /// Moves the box's supervisor `pid` and whatever it has forked so far
    /// into this leaf. The supervisor is moved first, so a child forked after
    /// the move inherits the leaf; children forked before it are swept up by
    /// pid, and the sweep repeats until nothing new is found. Verified: the
    /// supervisor's cgroup is read back.
    pub fn adopt(&self, pid: u32) -> io::Result<()> {
        adopt_pid(&self.sysfs, pid)?;
        let mut seen = vec![pid];
        loop {
            let mut moved = false;
            for p in seen.clone() {
                for child in children_of(p) {
                    if !seen.contains(&child) {
                        adopt_pid(&self.sysfs, child)?;
                        seen.push(child);
                        moved = true;
                    }
                }
            }
            if !moved {
                break;
            }
        }
        let placed = std::fs::read_to_string(format!("/proc/{pid}/cgroup"))
            .ok()
            .and_then(|c| cgroup_of(&c));
        if placed.as_deref() != Some(self.kernel.as_str()) {
            return Err(io::Error::other(format!(
                "box process {pid} is in {} after placement, not {}",
                placed.unwrap_or_default(),
                self.kernel
            )));
        }
        Ok(())
    }

    /// Removes the leaf at once, for a launch abandoned before the box's
    /// process was moved in (or after it was killed): nothing counts against
    /// the leaf, so no retry is needed, and a failure is logged.
    pub fn remove_now(self) {
        if let Err(error) = std::fs::remove_dir(&self.sysfs)
            && error.kind() != io::ErrorKind::NotFound
        {
            tracing::debug!(%error, leaf = %self.kernel, "removing the classifier leaf");
        }
    }

    /// Removes the leaf. Retried briefly: a process reaped a moment ago can
    /// still count against its cgroup.
    pub async fn remove(self) {
        for _ in 0..10 {
            match std::fs::remove_dir(&self.sysfs) {
                Ok(()) => return,
                Err(e) if e.kind() == io::ErrorKind::NotFound => return,
                Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
            }
        }
        tracing::debug!(leaf = %self.kernel, "classifier leaf left for the next daemon start to remove");
    }
}

/// The pids `/proc/<pid>/task/<pid>/children` lists.
fn children_of(pid: u32) -> Vec<u32> {
    std::fs::read_to_string(format!("/proc/{pid}/task/{pid}/children"))
        .map(|s| {
            s.split_whitespace()
                .filter_map(|p| p.parse().ok())
                .collect()
        })
        .unwrap_or_default()
}

/// The session's network guard with its classifier leaf attached: the leaf
/// is removed after the provider's own teardown, once the box is gone.
pub struct LeafGuard {
    inner: Option<Box<dyn sandbox2::NetGuard>>,
    leaf: Leaf,
}

impl LeafGuard {
    #[must_use]
    pub fn new(inner: Option<Box<dyn sandbox2::NetGuard>>, leaf: Leaf) -> Self {
        Self { inner, leaf }
    }
}

impl sandbox2::NetGuard for LeafGuard {
    fn teardown(
        self: Box<Self>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> {
        Box::pin(async move {
            if let Some(inner) = self.inner {
                inner.teardown().await;
            }
            self.leaf.remove().await;
        })
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;
    use sessions::core::net_verdict::IPPROTO_ICMP;

    const NATIVE_ROOT: &str = "user.slice/user-1000.slice/user@1000.service/minimald.slice";

    fn policy(allow: &[&str], deny: &[&str]) -> EgressPolicy {
        EgressPolicy {
            allow_subnets: Some(allow.iter().map(ToString::to_string).collect()),
            allow_dns_hosts: None,
            allow_protocols: None,
            deny_subnets: Some(deny.iter().map(ToString::to_string).collect()),
        }
    }

    fn deny_all() -> EgressPolicy {
        policy(&[], &[])
    }

    fn ep(ip: [u8; 4], port: u16) -> Endpoint {
        Endpoint {
            ip: Ipv4Addr::from(ip),
            port,
        }
    }

    fn native() -> Layout {
        Layout::new(NATIVE_ROOT)
    }

    /// A host that can decide per box: every fact present.
    fn capable_host() -> HostProbe {
        HostProbe {
            install: InstallState::Current,
            install_command: install_command(Path::new("/state/net/host-classifier")),
            delegated_root: Some(native()),
            nsdelegate: Some(true),
            daemon_in_leaf: true,
            ruleset_loaded: true,
        }
    }

    /// NET-078. Node-plane traffic and the host-address cohort are two
    /// identities: two leaves under one root, classified apart by path, with
    /// a counted rule each in the ruleset and the deny class's rules ahead of
    /// both.
    #[test]
    fn node_plane_and_cohort_distinct_sources() {
        let layout = native();
        assert_eq!(layout.level(), 4);
        assert_eq!(layout.uid(), Some(1000));
        assert_eq!(layout.chain(), "host_cohort_1000");
        assert_eq!(
            layout.classify(&layout.daemon_leaf()),
            Some(Classified::NodePlane)
        );
        assert_eq!(
            layout.classify(&layout.box_leaf("b1", true)),
            Some(Classified::Box {
                id: "b1".into(),
                deny_all: true
            })
        );
        assert_eq!(
            layout.classify(&layout.box_leaf("b2", false)),
            Some(Classified::Box {
                id: "b2".into(),
                deny_all: false
            })
        );
        assert_eq!(layout.classify(&layout.cohort()), Some(Classified::Cohort));
        assert_eq!(
            layout.classify(&layout.class_dir(true)),
            Some(Classified::Cohort)
        );
        // A helper the daemon spawns for itself stays node-plane.
        assert_eq!(
            layout.classify(&format!("{}/helper", layout.daemon_leaf())),
            Some(Classified::NodePlane)
        );
        // Outside the tree, or a sibling that merely shares the prefix, is
        // nobody's.
        assert_eq!(layout.classify("user.slice/user-1000.slice"), None);
        assert_eq!(
            layout.classify(&format!("{NATIVE_ROOT}-other/daemon")),
            None
        );
        assert_ne!(
            Classified::NodePlane.source(),
            Classified::Box {
                id: "b1".into(),
                deny_all: true
            }
            .source()
        );
        assert_eq!(Classified::Cohort.source(), SourceIdentity::Cohort);

        // The guest daemon roots at the top of the mount.
        assert_eq!(Layout::guest().root(), "minimald.slice");
        assert_eq!(Layout::guest().level(), 1);
        assert_eq!(Layout::guest().chain(), "host_cohort");
        // The native daemon roots under its user manager's delegation.
        let found = Layout::native(
            "0::/user.slice/user-1000.slice/user@1000.service/app.slice/minimald.service\n",
        )
        .expect("a delegated subtree");
        assert_eq!(found.root(), NATIVE_ROOT);
        assert_eq!(Layout::native("0::/system.slice/some.service\n"), None);
        assert_eq!(
            Layout::native("0::/user.slice/user-1000.slice/session-4.scope\n"),
            None,
            "a session scope is outside the delegation"
        );

        // The ruleset: deny class first, then cohort, then node-plane, each
        // at the level its depth needs, with a counter of its own, in one
        // chain per uid, loaded idempotently.
        let rules = layout.ruleset(ANSWERER);
        let at = |s: &str| {
            rules
                .find(s)
                .unwrap_or_else(|| panic!("missing {s:?} in:\n{rules}"))
        };
        let deny = at(&format!(
            "socket cgroupv2 level 6 \"{}\"",
            layout.class_dir(true)
        ));
        let cohort = at(&format!(
            "socket cgroupv2 level 5 \"{}\" counter accept comment \"host-address-cohort\"",
            layout.cohort()
        ));
        let daemon = at(&format!(
            "socket cgroupv2 level 5 \"{}\" counter accept comment \"node-plane\"",
            layout.daemon_leaf()
        ));
        assert!(deny < cohort && cohort < daemon, "order in:\n{rules}");
        assert!(rules.contains("add table inet minimal\n"));
        assert!(rules.contains("flush chain inet minimal host_cohort_1000\n"));
        assert!(!rules.contains("\"open"), "the open class needs no rule");

        // The model and the rendering are one rule table.
        assert_eq!(layout.rules(ANSWERER).len(), 4);
        assert_eq!(rules.matches("add rule ").count(), 4);
    }

    /// NET-079. A deny-all host-address box opens nothing: not a public
    /// address, not a private one, not the host's own loopback, not the
    /// host's stub resolver, over any transport. The ruleset refuses on the
    /// box's own leaf and names the box.
    #[test]
    fn host_ip_deny_all_no_outbound() {
        let layout = native();
        let leaf = layout.box_leaf("locked", true);
        let attempts = [
            (ep([93, 184, 216, 34], 443), IPPROTO_TCP),
            (ep([1, 1, 1, 1], 53), IPPROTO_UDP),
            (ep([10, 0, 0, 5], 22), IPPROTO_TCP),
            (ep([127, 0, 0, 1], 8080), IPPROTO_TCP),
            (ep([127, 0, 0, 53], 53), IPPROTO_UDP),
            (ep([127, 0, 0, 53], 53), IPPROTO_TCP),
            (ep([8, 8, 8, 8], 0), IPPROTO_ICMP),
        ];
        for (dst, proto) in attempts {
            let d = layout
                .verdict(&leaf, dst, proto, ANSWERER)
                .expect("in the tree");
            assert_eq!(d.source, SourceIdentity::Cohort);
            assert_eq!(d.box_id.as_deref(), Some("locked"));
            assert!(
                matches!(d.verdict, Verdict::Drop(DropRule::Undeclared)),
                "{dst:?}/{proto} must be refused, got {:?}",
                d.verdict
            );
        }
        // A child of its own leaf, the one move a confined box can make,
        // takes the same verdict.
        let child = format!("{leaf}/child");
        let d = layout
            .verdict(&child, ep([93, 184, 216, 34], 443), IPPROTO_TCP, ANSWERER)
            .unwrap();
        assert!(matches!(d.verdict, Verdict::Drop(_)));

        // The rendered rule for the class refuses, immediately, after the
        // one carve-out and nothing else.
        let rules = layout.ruleset(ANSWERER);
        let deny_rules: Vec<&str> = rules
            .lines()
            .filter(|l| l.contains(&format!("\"{}\"", layout.class_dir(true))))
            .collect();
        assert_eq!(deny_rules.len(), 2, "{rules}");
        assert!(deny_rules[0].contains("resolver") && deny_rules[0].contains("accept"));
        assert!(deny_rules[1].ends_with(&format!("counter {REFUSAL} comment \"deny-all refuse\"")));

        // A deny-all declaration places the box under the deny class; a box
        // with no rules, or with a list the static ruleset does not decide,
        // under the open class, where the cohort admits it.
        let start = decide_session_start("locked", Some(&deny_all()), &capable_host());
        let placement = start.placement.expect("an enforcing host places");
        assert!(placement.deny_all);
        assert_eq!(placement.leaf(), leaf);
        assert_eq!(
            start.env,
            vec![(ENFORCEMENT_ENV.to_string(), "per-box".to_string())]
        );
        let open = decide_session_start("open", None, &capable_host());
        assert!(!open.placement.unwrap().deny_all);
        assert_eq!(
            open.env,
            vec![(ENFORCEMENT_ENV.to_string(), "per-box".to_string())]
        );
        assert_eq!(
            layout
                .verdict(
                    &layout.box_leaf("open", false),
                    ep([1, 1, 1, 1], 443),
                    IPPROTO_TCP,
                    ANSWERER
                )
                .unwrap()
                .verdict,
            Verdict::Admit
        );
    }

    /// NET-080. With a deny-all box resident, the daemon's own package fetch
    /// from its sibling leaf is admitted and recorded as node-plane traffic;
    /// the same destination from the box's leaf is refused.
    #[test]
    fn daemon_fetch_survives_cohort_deny() {
        let layout = native();
        let upstream = ep([151, 101, 1, 91], 443);
        let fetch = layout
            .verdict(&layout.daemon_leaf(), upstream, IPPROTO_TCP, ANSWERER)
            .expect("the daemon's leaf is in the tree");
        assert_eq!(fetch.verdict, Verdict::Admit);
        assert_eq!(fetch.source, SourceIdentity::NodePlane);
        assert_eq!(fetch.box_id, None);
        assert_eq!(
            record_node_plane_fetch("package fetch"),
            SourceIdentity::NodePlane
        );

        let from_box = layout
            .verdict(
                &layout.box_leaf("locked", true),
                upstream,
                IPPROTO_TCP,
                ANSWERER,
            )
            .unwrap();
        assert!(matches!(from_box.verdict, Verdict::Drop(_)));
        assert_eq!(from_box.source, SourceIdentity::Cohort);
        assert_eq!(from_box.box_id.as_deref(), Some("locked"));
        // A daemon helper forked from the leaf is still the daemon's.
        let helper = layout
            .verdict(
                &format!("{}/gvproxy", layout.daemon_leaf()),
                upstream,
                IPPROTO_TCP,
                ANSWERER,
            )
            .unwrap();
        assert_eq!(helper.verdict, Verdict::Admit);
    }

    /// NET-079's carve-out. A deny-all box reaches the resolver Minimal owns
    /// for it, at that address and port over TCP or UDP, and no other
    /// loopback destination: not another port at the answerer's address, not
    /// the answerer's port at another loopback address, not ICMP to the
    /// answerer. The carve-out is the answerer's own bind address.
    #[test]
    fn host_ip_deny_all_reaches_only_the_answerer() {
        let layout = native();
        let leaf = layout.box_leaf("locked", true);
        let verdict = |dst, proto| layout.verdict(&leaf, dst, proto, ANSWERER).unwrap().verdict;

        assert_eq!(
            std::net::SocketAddr::from((ANSWERER.ip, ANSWERER.port)),
            answerer::BIND_ADDR,
            "the carve-out is where the answerer listens"
        );
        assert!(ANSWERER.ip.is_loopback());
        assert_eq!(verdict(ANSWERER, IPPROTO_UDP), Verdict::Admit);
        assert_eq!(verdict(ANSWERER, IPPROTO_TCP), Verdict::Admit);
        assert!(matches!(
            verdict(ep(ANSWERER.ip.octets(), 80), IPPROTO_TCP),
            Verdict::Drop(_)
        ));
        assert!(matches!(
            verdict(ep(ANSWERER.ip.octets(), 53), IPPROTO_UDP),
            Verdict::Drop(_)
        ));
        assert!(matches!(
            verdict(ep([127, 0, 0, 53], ANSWERER.port), IPPROTO_UDP),
            Verdict::Drop(_)
        ));
        assert!(matches!(
            verdict(ep([127, 0, 0, 53], 53), IPPROTO_UDP),
            Verdict::Drop(_)
        ));
        assert!(matches!(verdict(ANSWERER, IPPROTO_ICMP), Verdict::Drop(_)));

        // The rendered carve-out names exactly that address and port.
        let rules = layout.ruleset(ANSWERER);
        assert!(rules.contains(&format!(
            "ip daddr {} meta l4proto {{ tcp, udp }} th dport {} counter accept",
            ANSWERER.ip, ANSWERER.port
        )));
        // The guest tree carries the same rules one level up.
        let guest = Layout::guest();
        assert_eq!(
            guest
                .verdict(
                    &guest.box_leaf("locked", true),
                    ANSWERER,
                    IPPROTO_UDP,
                    ANSWERER
                )
                .unwrap()
                .verdict,
            Verdict::Admit
        );
        assert!(
            guest
                .ruleset(ANSWERER)
                .contains("level 3 \"minimald.slice/boxes/deny\"")
        );
    }

    /// NET-079. The verdict is per box only while every process of the box
    /// stays in the leaf it is decided on: a cgroup namespace rooted at the
    /// daemon's leaf, so the cohort is outside it, on a mount that treats
    /// namespaces as delegation boundaries, with the daemon under a delegated
    /// subtree and root's reloader holding the current rules. Each missing
    /// piece is a named cause, and the host then decides nothing per box.
    #[test]
    fn host_ip_box_cannot_leave_its_cgroup() {
        let capable = capable_host();
        assert_eq!(
            PerBoxEnforcement::decide(&capable),
            PerBoxEnforcement::Enforced(native())
        );

        let without = |f: fn(&mut HostProbe)| {
            let mut p = capable_host();
            f(&mut p);
            match PerBoxEnforcement::decide(&p) {
                PerBoxEnforcement::Unenforced { causes, .. } => causes,
                PerBoxEnforcement::Enforced(_) => panic!("must not enforce"),
            }
        };
        assert_eq!(
            without(|p| p.nsdelegate = Some(false)),
            vec![Cause::CgroupNotDelegated]
        );
        assert_eq!(
            without(|p| p.nsdelegate = None),
            vec![Cause::CgroupNotDelegated]
        );
        assert_eq!(
            without(|p| p.daemon_in_leaf = false),
            vec![Cause::DaemonNotInItsLeaf]
        );
        assert_eq!(
            without(|p| p.delegated_root = None),
            vec![Cause::NoDelegatedSubtree]
        );
        assert_eq!(
            without(|p| p.ruleset_loaded = false),
            vec![Cause::RulesetNotLoaded]
        );
        assert_eq!(
            without(|p| p.install = InstallState::Stale),
            vec![Cause::InstallStepStale]
        );
        // With no step at all, the load is not a cause of its own.
        assert_eq!(
            without(|p| {
                p.install = InstallState::Missing;
                p.ruleset_loaded = false;
            }),
            vec![Cause::InstallStepMissing]
        );
        // An unenforcing host places nothing.
        let mut unenforcing = capable_host();
        unenforcing.nsdelegate = Some(false);
        assert_eq!(
            decide_session_start("s", Some(&deny_all()), &unenforcing).placement,
            None
        );

        // The mount option is read from the host's own mount table.
        let with = "36 25 0:31 / /sys/fs/cgroup rw,nosuid,nodev,noexec,relatime shared:9 - cgroup2 cgroup2 rw,nsdelegate,memory_recursiveprot\n";
        let without_opt = "36 25 0:31 / /sys/fs/cgroup rw,nosuid,nodev,noexec,relatime shared:9 - cgroup2 cgroup2 rw,memory_recursiveprot\n";
        let none = "25 1 0:22 / /proc rw,relatime shared:5 - proc proc rw\n";
        assert_eq!(cgroup2_nsdelegate(with), Some(true));
        assert_eq!(cgroup2_nsdelegate(without_opt), Some(false));
        assert_eq!(cgroup2_nsdelegate(none), None);
        // And the daemon's own placement from its cgroup file.
        assert_eq!(
            cgroup_of("0::/user.slice/user-1000.slice/user@1000.service/minimald.slice/daemon\n"),
            Some(native().daemon_leaf())
        );

        // Inside its leaf the only move a box has is into a child of that
        // leaf, and the classifier still names the box.
        let layout = native();
        let leaf = layout.box_leaf("b1", true);
        assert_eq!(
            layout.classify(&format!("{leaf}/child/grandchild")),
            Some(Classified::Box {
                id: "b1".into(),
                deny_all: true
            })
        );
        assert_eq!(
            layout.sysfs(&leaf),
            PathBuf::from(format!("/sys/fs/cgroup/{NATIVE_ROOT}/boxes/deny/b1"))
        );
        // A session name is made a cgroup name.
        assert_eq!(leaf_id("my-box.2"), "my-box.2");
        assert_eq!(leaf_id("a b/c"), "a_b_c");
        assert_eq!(leaf_id(".hidden"), "s_.hidden");
    }

    /// NET-079. When the install step is what is missing, session start
    /// names it and the exact command that runs it, asks nothing, and
    /// records that the host decides nothing per box. When something else is
    /// missing the cause is named without the command, since installing the
    /// step would not clear it.
    #[test]
    fn native_host_advises_classifier_install_without_prompt() {
        let mut probe = capable_host();
        probe.install = InstallState::Missing;
        probe.ruleset_loaded = false;
        let e = PerBoxEnforcement::decide(&probe);
        assert!(!e.per_box());
        let advisory = e.advisory().expect("an unenforcing host says so");
        assert!(advisory.contains(Cause::InstallStepMissing.describe()));
        assert!(advisory.contains(&probe.install_command), "{advisory}");
        assert!(
            advisory.contains("sudo bash /state/net/host-classifier/install-host-classifier.sh")
        );
        // A statement, not a question: nothing for session start to wait on.
        assert!(!advisory.contains('?'), "{advisory}");
        assert!(!advisory.to_lowercase().contains("[y/n]"), "{advisory}");
        assert!(!advisory.to_lowercase().contains("continue"), "{advisory}");
        assert_eq!(e.record(), "none");

        // The record and the advisory travel into the box, and nothing is
        // placed.
        let start = decide_session_start("s", Some(&deny_all()), &probe);
        assert!(start.placement.is_none());
        assert!(
            start
                .env
                .contains(&(ENFORCEMENT_ENV.to_string(), "none".to_string()))
        );
        assert!(
            start
                .env
                .iter()
                .any(|(k, v)| k == ADVISORY_ENV && v == &advisory)
        );

        // A stale step names the command too: re-running it is the fix.
        let mut stale = capable_host();
        stale.install = InstallState::Stale;
        let advisory = PerBoxEnforcement::decide(&stale).advisory().unwrap();
        assert!(advisory.contains(Cause::InstallStepStale.describe()));
        assert!(advisory.contains("install-host-classifier.sh"));

        // A cause the install step does not clear names no command.
        let mut confinement_only = capable_host();
        confinement_only.nsdelegate = Some(false);
        let advisory = PerBoxEnforcement::decide(&confinement_only)
            .advisory()
            .unwrap();
        assert!(advisory.contains(Cause::CgroupNotDelegated.describe()));
        assert!(
            !advisory.contains("install-host-classifier.sh"),
            "{advisory}"
        );
        assert!(!advisory.contains("sudo"), "{advisory}");

        // Both missing: both named, the command once.
        let mut both = confinement_only;
        both.install = InstallState::Missing;
        let advisory = PerBoxEnforcement::decide(&both).advisory().unwrap();
        assert!(advisory.contains(Cause::InstallStepMissing.describe()));
        assert!(advisory.contains(Cause::CgroupNotDelegated.describe()));
        assert_eq!(advisory.matches("install-host-classifier.sh").count(), 1);

        // A capable host says nothing and records per-box.
        let capable = PerBoxEnforcement::decide(&capable_host());
        assert_eq!(capable.advisory(), None);
        assert_eq!(capable.record(), "per-box");
        assert_eq!(
            decide_session_start("s", None, &capable_host()).env,
            vec![(ENFORCEMENT_ENV.to_string(), "per-box".to_string())]
        );
        // A list beyond deny-all on a capable host: the box runs in the open
        // class, recorded unenforced, with the advisory saying why and no
        // install command, since the step is in place.
        let listed = decide_session_start(
            "listed",
            Some(&policy(&["10.0.0.0/8"], &[])),
            &capable_host(),
        );
        assert!(!listed.placement.unwrap().deny_all);
        assert!(
            listed
                .env
                .contains(&(ENFORCEMENT_ENV.to_string(), "none".to_string()))
        );
        let advisory = listed
            .env
            .iter()
            .find(|(k, _)| k == ADVISORY_ENV)
            .map(|(_, v)| v.clone())
            .unwrap();
        assert!(advisory.contains("not enforced here"), "{advisory}");
        assert!(!advisory.contains("sudo"));

        // The installer the command names is what the daemon writes: the
        // checkout's script, shipped inside the binary.
        assert!(INSTALLER_SOURCE.starts_with("#!/usr/bin/env bash"));
        assert!(INSTALLER_SOURCE.contains(INSTALL_DIR));
        assert!(INSTALLER_SOURCE.contains(LOADED_STAMP_DIR));
        assert!(INSTALLER_SOURCE.contains(RULES_NAME));
        assert!(INSTALLER_SOURCE.contains(REQUEST_NAME));

        // The live probe reads this host without failing, whatever it is.
        let live = HostProbe::live();
        assert!(live.install_command.ends_with(INSTALLER_NAME));
        if live.delegated_root.is_none() {
            assert!(!live.daemon_in_leaf);
        }
    }

    /// The deny-all declaration this module keys on: an empty
    /// `allow_subnets` and no name list. An absent section and a name allow
    /// list are not deny-all.
    #[test]
    fn deny_all_is_an_empty_allow_list_and_no_names() {
        assert!(is_deny_all(Some(&deny_all())));
        assert!(!is_deny_all(None));
        assert!(!is_deny_all(Some(&EgressPolicy::default())));
        assert!(!is_deny_all(Some(&policy(&["10.0.0.0/8"], &[]))));
        let mut named = deny_all();
        named.allow_dns_hosts = Some(vec!["example.com".into()]);
        assert!(!is_deny_all(Some(&named)));
        assert!(has_rules(Some(&named)));
        let mut empty_names = deny_all();
        empty_names.allow_dns_hosts = Some(vec![]);
        assert!(is_deny_all(Some(&empty_names)));
        assert!(!has_rules(None));
        assert!(!has_rules(Some(&EgressPolicy::default())));
        assert!(has_rules(Some(&policy(&["10.0.0.0/8"], &[]))));
    }
}
