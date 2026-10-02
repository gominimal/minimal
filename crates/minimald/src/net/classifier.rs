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
//! Whether the host can decide per box is a start-time fact, read here once
//! and recorded: the privileged step installs the tree, delegates it, and
//! loads the table, and a host missing any of that decides nothing per box
//! — its host-address boxes run unenforced, never refused (NET-079's
//! exception), with the cause named at session start and the install
//! command printed only when the missing step is the cause.

use std::net::Ipv4Addr;
#[cfg(test)]
use std::net::SocketAddr;
use std::path::Path;

use sandbox2::config::Verdict;

/// The loopback address the box zone's answerer serves at — the one
/// destination a deny-all host-address box's connections are admitted to
/// (NET-079): the resolver Minimal owns for the box, which answers the box
/// zone and forwards nothing. A loopback-wide exception was considered and
/// rejected (design §4.1): the rest of the host's loopback is where the
/// host's own services and its forwarding resolver listen, and admitting a
/// deny-all box to them would admit it to everything upstream.
pub(crate) const ANSWERER_ADDRESS: Ipv4Addr = Ipv4Addr::LOCALHOST;

/// The one destination a deny-all host-address box's connections are
/// admitted to (NET-079): the resolver Minimal owns for it, at that
/// resolver's own address *and port*. An address alone would be the
/// loopback baseline exception design §4.1 rejects; a port alone is nothing
/// a packet can match. `port` is the answerer's own — the port the daemon
/// serves the box zone on, the same one the privileged step's
/// `--answerer-port` names in the rule that admits it.
///
/// Test-only: the destination is pinned as data (below), because it is the
/// installer's rule that enforces it, not the daemon — nothing in the
/// daemon builds one at runtime.
#[cfg(test)]
pub(crate) fn answerer_destination(port: u16) -> SocketAddr {
    SocketAddr::new(std::net::IpAddr::V4(ANSWERER_ADDRESS), port)
}

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
        }
    }

    /// The exact command that ends this cause, when one can: the step's
    /// install when the step is what is missing — NET-079 names that one —
    /// and nothing for a host that cannot confine a box, because installing
    /// the step over that tree would leave the cause standing.
    pub fn install_command(self) -> Option<String> {
        match self {
            Self::StepNotInstalled => Some(sandbox2::classifier::install_hint()),
            Self::CannotConfine => None,
        }
    }
}

/// Whether this host can decide a host-address box's egress verdict per box
/// (NET-079), and why not when it cannot: the start-time fact the daemon
/// records, the create response carries, and `min session activate` turns
/// into the advisory at session start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    decided: bool,
    cause: Option<Cause>,
}

impl Decision {
    /// A host that decides per box. The guest's answer: its daemon is the
    /// microVM's pid 1, the tree it mounts is its own, and a box it cannot
    /// place is refused at launch rather than advised about.
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

/// The start-time check (NET-079): whether this host can decide a
/// host-address box's egress verdict per box, and why not when it cannot.
///
/// Read-only, over the same facts the privileged step installs — the
/// cgroup2 the tree sits on (`nsdelegate` is what makes a box's cgroup
/// namespace a delegation boundary, so a box cannot migrate out of its
/// leaf), the cohort's two delegated subtrees, and the loaded table's
/// presence marker, the one fact that says the refusal a deny-all box's
/// connections meet is actually there, written only by an install whose
/// `nft -f` transaction succeeded. Nothing here needs `CAP_NET_ADMIN` or
/// writes a byte: the step's own `--pid` half and the launch's placement
/// probe decide what only a migration can.
pub fn decide(root: &Path, mountinfo: Option<&str>, guest: bool) -> Decision {
    // The guest's tree is its own boot's work, and a box it cannot place is
    // refused at launch (design §7.1): a host-shaped start-time fact about a
    // step this image has no installer for would advise a person who is not
    // there, and never the image's own builder.
    if guest {
        return Decision::decided();
    }
    // The confinement half first: without `nsdelegate` a cgroup namespace
    // is not a delegation boundary, so no leaf under this tree confines a
    // process however installed — the cause no command clears. A mount
    // table that cannot be read is the same absence of evidence, and the
    // check may not report a host as confining on no evidence.
    let confining = sandbox2::classifier::cgroup2_covering(root, mountinfo.unwrap_or(""))
        .is_some_and(|(_, nsdelegate)| nsdelegate);
    if !confining {
        return Decision::undecidable(Cause::CannotConfine);
    }
    // The step's half: the cohort's two subtrees — a box's leaf is always
    // in one of them, so one missing is the whole step missing — and the
    // marker the loaded table's presence rests on.
    if !subtrees_delegated(root) || !table_marker_present(root) {
        return Decision::undecidable(Cause::StepNotInstalled);
    }
    Decision::decided()
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

/// Whether the loaded table's presence marker is there: the directory the
/// step writes only after its `nft -f` transaction succeeded, and the one
/// fact that says the refusal a deny-all box's connections meet is loaded.
fn table_marker_present(root: &Path) -> bool {
    root.join(sandbox2::classifier::TABLE_MARKER).is_dir()
}

/// The decision this daemon recorded at start. `None` until the start
/// block records one, and then [`recorded`] probes again rather than answer
/// from nothing: the facts it reads are read-only, so re-reading them
/// changes nothing and cannot lie.
static RECORDED: std::sync::RwLock<Option<Decision>> = std::sync::RwLock::new(None);

/// Records `decision` as this daemon's start-time fact about its host.
pub fn record(decision: Decision) {
    *RECORDED.write().expect("classifier decision lock poisoned") = Some(decision);
}

/// The decision to answer a create with: the one [`record`] wrote, or a
/// fresh probe when nothing did.
pub(crate) fn recorded() -> Decision {
    if let Some(recorded) = RECORDED
        .read()
        .expect("classifier decision lock poisoned")
        .clone()
    {
        return recorded;
    }
    decide(
        Path::new(sandbox2::classifier::TREE_ROOT),
        sandbox2::classifier::own_mountinfo().as_deref(),
        crate::guest::is_microvm_daemon(),
    )
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

    /// The cohort the step installs: both subtrees with their
    /// delegation-contract files, and the table's marker.
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
    }

    /// NET-079: the one carve-out from a deny-all verdict is the address
    /// and port of the resolver Minimal owns for the box — one destination,
    /// not the loopback, and not the host's own resolver at DNS's port.
    #[test]
    fn host_ip_deny_all_reaches_only_the_answerer() {
        let answerer = answerer_destination(crate::net::answerer::ANSWERER_PORT);
        assert_eq!(
            answerer,
            SocketAddr::new(
                std::net::IpAddr::V4(ANSWERER_ADDRESS),
                crate::net::answerer::ANSWERER_PORT
            ),
            "the carve-out is the answerer's own address and port"
        );
        // Whether a destination is admitted is one comparison, so nothing
        // wider can creep in: an address alone is the loopback baseline
        // exception design §4.1 rejects, and a port alone matches anything
        // on it.
        let admitted = |destination: SocketAddr| destination == answerer;
        assert!(
            admitted(answerer),
            "the resolver Minimal owns for the box is admitted"
        );
        for (destination, why) in [
            (
                SocketAddr::new(
                    std::net::IpAddr::V4(ANSWERER_ADDRESS),
                    crate::net::answerer::ANSWERER_PORT + 1,
                ),
                "the right address at the wrong port",
            ),
            (
                SocketAddr::new(std::net::IpAddr::V4(ANSWERER_ADDRESS), 53),
                "the host's own resolver, at DNS's port",
            ),
            (
                SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::LOCALHOST), 53),
                "any other loopback service",
            ),
            (
                SocketAddr::new(
                    std::net::IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
                    crate::net::answerer::ANSWERER_PORT,
                ),
                "another loopback address, at the answerer's port",
            ),
            (
                SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53),
                "an outside destination",
            ),
        ] {
            assert!(
                !admitted(destination),
                "{why} is not admitted: only the answerer's address and port is ({destination})"
            );
        }
    }

    /// NET-079: on a host that cannot decide per box, session start names
    /// the cause, prints the exact install command only when the missing
    /// step is the cause, and never asks anything. The daemon's half of
    /// that is what the create response carries, so the cause and the
    /// command are pinned here as data.
    #[test]
    fn native_host_advises_classifier_install_without_prompt() {
        let tree = tempfile::tempdir().expect("a temp dir standing in for the tree");
        let root = tree.path();

        // A host whose cgroup2 covers the tree without `nsdelegate` cannot
        // confine a box, and the advisory names that — never the install
        // command, which would leave the cause standing.
        let undelegated = decide(root, Some(&mountinfo(root, false)), false);
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
        assert!(
            !cause.detail().contains('?'),
            "the cause is a fact, never a question: {}",
            cause.detail()
        );

        // A confining host with no step installed names the step, with the
        // exact command that installs it.
        let step_missing = decide(root, Some(&mountinfo(root, true)), false);
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
        assert!(
            !cause.detail().contains('?') && !command.contains('?'),
            "an advisory never asks a question — it names a command: {} / {command}",
            cause.detail()
        );

        // A host with both halves decides per box, and advises nothing: the
        // absence of an advisory is the fact a decided host reports.
        installed_cohort(root);
        let decided = decide(root, Some(&mountinfo(root, true)), false);
        assert!(
            decided.can_decide_per_box(),
            "a confining host with the step installed decides per box"
        );
        assert_eq!(
            decided.cause(),
            None,
            "a decided host names no cause, so session start prints nothing"
        );

        // The marker alone is what says the table is loaded: a host with the
        // subtrees but no marker has no refusal installed, and a deny-all
        // box there would run as though refused when nothing is.
        std::fs::remove_dir_all(root.join(sandbox2::classifier::TABLE_MARKER))
            .expect("removing the marker");
        let no_table = decide(root, Some(&mountinfo(root, true)), false);
        assert_eq!(
            no_table.cause(),
            Some(Cause::StepNotInstalled),
            "the table's marker is the step's half too"
        );
    }

    /// The recorded decision answers a create from the fact the start block
    /// wrote, and a daemon that never recorded one probes again — read-only
    /// facts, so the re-read answers the same.
    #[test]
    fn recorded_decision_answers_from_the_start_fact() {
        record(Decision::decided());
        assert!(
            recorded().can_decide_per_box(),
            "what the start block recorded is what a create is answered with"
        );
        record(Decision::undecidable(Cause::StepNotInstalled));
        assert_eq!(
            recorded().cause(),
            Some(Cause::StepNotInstalled),
            "the recorded cause outlives the probe that found it"
        );
    }
}
