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
//! command printed only when the missing step is the cause. The guest is
//! the one exception to that exception: its daemon is the only one that
//! could have made its image load the table, so until it does, a deny-all
//! host-address box is refused rather than run on a refusal that is not
//! there (design §7.1) — and no installer exists for a person to run, so
//! none is named.

use std::net::Ipv4Addr;
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
        }
    }

    /// What this daemon does with a host-address box on this cause, spelled
    /// for the cause's own host: the half of the start-up line that must say
    /// what the next launch will actually do, because the two hosts answer
    /// a host that cannot decide per box differently. Natively every cause
    /// is the requirement's own exception (NET-079) — the box runs
    /// unenforced, never refused on this ground. In the guest the tree and
    /// the table were the image's own to build: a tree that cannot confine
    /// a box leaves nothing to place one in, so every host-address box is
    /// refused, and on a table that is not loaded — guest-side enforcement
    /// not being available yet — a deny-all box is refused rather than run
    /// on a refusal that is not there, while every other box needs no
    /// verdict enforced and runs.
    ///
    /// [`Cause::StepNotInstalled`] is the one cause this cannot arise as in
    /// a guest ([`decide`] maps the missing step to the guest's own
    /// cause), so it takes the deny-all spelling with
    /// [`Cause::GuestTableNotLoaded`]: the match stays exhaustive over
    /// causes, never claiming a host kind that cannot produce it.
    pub fn host_ip_box_outcome(self, guest: bool) -> &'static str {
        if !guest {
            return "its host-address boxes run unenforced";
        }
        match self {
            Self::CannotConfine => {
                "its host-address boxes are refused: it cannot place one in a \
                 leaf that confines"
            }
            Self::StepNotInstalled | Self::GuestTableNotLoaded => {
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
    /// tell is the image's builder and no installer exists there.
    pub fn install_command(self) -> Option<String> {
        match self {
            Self::StepNotInstalled => Some(sandbox2::classifier::install_hint()),
            Self::CannotConfine | Self::GuestTableNotLoaded => None,
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
    /// A host that decides per box: its covering cgroup2 confines, the
    /// cohort's subtrees are delegated, and the loaded table's presence
    /// marker is there — the three facts a verdict needs to be decided
    /// *on* something, guest or native alike.
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
///
/// The guest answers the same three questions, and for the same reason:
/// its daemon is the microVM's pid 1, so the tree it mounts and the table
/// its image loads are its own boot's work — and reporting a guest as
/// decided while its table is not loaded would place a deny-all box in a
/// leaf that decides nothing while looking decided, on the one host whose
/// image is the fix. The guest's cause is named for the image's builder:
/// no installer exists inside a microVM, so no command is named for it.
pub fn decide(root: &Path, mountinfo: Option<&str>, guest: bool) -> Decision {
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

/// The two source identities the ruleset tests render the installer's
/// table with: any two distinct addresses would do, and these are the
/// installer's own harness pair, so a rule named here is spelled the way
/// the step's own tests spell it.
#[cfg(test)]
pub(crate) const TEST_COHORT_ADDRESS: &str = "100.72.0.9";
#[cfg(test)]
pub(crate) const TEST_NODE_PLANE_ADDRESS: &str = "100.72.0.1";

/// The installer's rendered table, exactly as a host loads it, over a
/// stand-in tree the caller never sees: the privileged step's
/// `--print-ruleset` mode prints the transaction its install would hand
/// `nft -f`, with the cgroup paths and match levels derived from the same
/// mount facts an install reads. Reading the step's own output — rather
/// than restating its rules here — is what makes the tests below pin what
/// a host actually loads.
#[cfg(test)]
pub(crate) fn rendered_ruleset() -> String {
    let scratch = tempfile::tempdir().expect("a temp dir standing in for the cgroup2 mount");
    // The tree root named as the production one is: the slice under its
    // own mount, so the cgroup paths the rendered rules name are the ones
    // they name on a real host.
    let mountpoint = scratch.path().join("cgroup");
    let root = mountpoint.join(
        std::path::Path::new(sandbox2::classifier::TREE_ROOT)
            .file_name()
            .expect("the tree root is a slice below the cgroup2 mount root"),
    );
    std::fs::create_dir_all(&root).expect("the print mode's mount covers the tree root");
    let mountinfo = scratch.path().join("mountinfo");
    std::fs::write(
        &mountinfo,
        format!(
            "35 30 0:26 / {} rw,relatime shared:2 - cgroup2 cgroup2 rw,nsdelegate\n",
            mountpoint.display(),
        ),
    )
    .expect("writing the stand-in mount table");
    let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../scripts/install-host-classifier.sh");
    let printed = std::process::Command::new("bash")
        .env("MINIMAL_OVERRIDE_CGROUP_MOUNTINFO", &mountinfo)
        .arg(script)
        .arg("--print-ruleset")
        .arg("--root")
        .arg(&root)
        .arg("--cohort-address")
        .arg(TEST_COHORT_ADDRESS)
        .arg("--node-plane-address")
        .arg(TEST_NODE_PLANE_ADDRESS)
        .output()
        .expect("running the privileged step's print mode");
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

        // The rendered table's postrouting chain is that layout made
        // real: the cohort's rule keys on `boxes/` — one match level over
        // both subtrees, covering every box leaf and no node-plane leaf —
        // with the cohort's identity, and the node plane's keys on the
        // slice with its own, so the daemon's traffic leaves as the node
        // plane and a box's leaves as the cohort. The cohort's rule comes
        // first, because a slice-wide match would otherwise swallow it; the
        // loopback guard keeps a packet to the answerer, which never
        // leaves the host, from being rewritten on its own way there. The
        // identities are the ones the step was told, not ones it guessed:
        // it refuses to render the pair half-done.
        let rel = tree_root_name();
        let cohort_path = format!("{}/{}", rel, sandbox2::classifier::BOXES_DIR);
        let ruleset = rendered_ruleset();
        let postrouting = chain_rules(&ruleset, "postrouting");
        let cohort_rule = format!(
            "socket cgroupv2 level {} \"{}\" oifname != \"lo\" snat ip to {}",
            cohort_path.split('/').count(),
            cohort_path,
            TEST_COHORT_ADDRESS
        );
        let node_plane_rule = format!(
            "socket cgroupv2 level {} \"{}\" oifname != \"lo\" snat ip to {}",
            rel.split('/').count(),
            rel,
            TEST_NODE_PLANE_ADDRESS
        );
        assert_eq!(
            postrouting.first(),
            Some(&cohort_rule.as_str()),
            "the cohort's rule is first, keyed on the cohort at its own level: {postrouting:?}"
        );
        assert_eq!(
            postrouting.get(1),
            Some(&node_plane_rule.as_str()),
            "the node plane's rule follows, keyed on the slice with its own identity: {postrouting:?}"
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
        // a flow already admitted stays in on its own conntrack state —
        // and the answerer's. Every other destination a deny-all box's
        // connections can name meets the rejection at the chain's end,
        // which is what makes the carve-out the *only* thing the box
        // reaches.
        let accepts: Vec<&str> = deny_out
            .iter()
            .filter(|rule| rule.ends_with("accept"))
            .copied()
            .collect();
        assert_eq!(
            accepts,
            ["ct state established,related accept", answerer.as_str()],
            "the deny chain's only non-established accept is the answerer: {deny_out:?}"
        );
        assert!(
            !deny_out
                .iter()
                .any(|rule| rule.contains("127.0.0.1") && !rule.contains(&answerer)),
            "no rule admits the loopback wide: {deny_out:?}"
        );
    }

    /// The start-time check names the cause, and the cause names the
    /// remedy — or says, by naming none, that there is not one to run:
    /// the step's own install ends the step-not-installed cause on a
    /// native host (NET-079 names that one), while a host that cannot
    /// confine a box and a guest whose image never loaded the table have
    /// no command, because running one would leave each cause standing.
    /// The cause and the command are the daemon's start-time facts, spelled
    /// once in [`Cause`], so they are pinned here as data.
    #[test]
    fn decide_names_the_cause_and_the_command_that_ends_it() {
        let tree = tempfile::tempdir().expect("a temp dir standing in for the tree");
        let root = tree.path();

        // A host whose cgroup2 covers the tree without `nsdelegate` cannot
        // confine a box, whatever kind of host it is — the cause is the
        // confinement, on native and guest alike, and no command ends it.
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
        assert_eq!(
            decide(root, Some(&mountinfo(root, false)), true).cause(),
            Some(Cause::CannotConfine),
            "the guest answers the confinement question the same way"
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

        // The same shape in a guest names its own image's half instead:
        // the tree and the table were its boot's work, and guest-side
        // classifier enforcement is not available yet, so a missing table
        // is the interim rather than a broken image — and no installer
        // exists inside a microVM, so no command is named for a person who
        // cannot run one.
        let guest_unloaded = decide(root, Some(&mountinfo(root, true)), true);
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

        // The marker alone is what says the table is loaded: a host with
        // the subtrees but no marker has no refusal installed, and a
        // deny-all box there would run as though refused when nothing is
        // — for a guest, that is the state a launch refuses rather than
        // places (design §7.1).
        installed_cohort(root);
        std::fs::remove_dir_all(root.join(sandbox2::classifier::TABLE_MARKER))
            .expect("removing the marker");
        assert_eq!(
            decide(root, Some(&mountinfo(root, true)), false).cause(),
            Some(Cause::StepNotInstalled),
            "the table's marker is the step's half too, on the native host"
        );
        assert_eq!(
            decide(root, Some(&mountinfo(root, true)), true).cause(),
            Some(Cause::GuestTableNotLoaded),
            "and the guest's subtrees alone do not decide anything per box \
             in it either"
        );

        // A host with both halves decides per box, guest or native: the
        // marker is what the decision rests on, and the guest's own boot
        // is the one step that can write it there.
        std::fs::create_dir_all(root.join(sandbox2::classifier::TABLE_MARKER))
            .expect("the step writes the table's marker");
        for (kind, guest) in [("native", false), ("guest", true)] {
            let decided = decide(root, Some(&mountinfo(root, true)), guest);
            assert!(
                decided.can_decide_per_box(),
                "a confining {kind} host with the step installed decides per box"
            );
            assert_eq!(
                decided.cause(),
                None,
                "a decided {kind} host names no cause"
            );
        }
    }

    /// The cause names what happens to a host-address box on the host it was
    /// decided on — the half of the start-up line that must match what the
    /// next launch actually does, because the two hosts answer a host that
    /// cannot decide per box differently. Natively every cause is NET-079's
    /// own exception: the box runs unenforced, never refused on this ground.
    /// The guest refuses instead, and its two grounds say so differently:
    /// a tree that cannot confine a box leaves nothing to place one in, so
    /// every host-address box is refused, while a table that is not loaded —
    /// guest-side enforcement not being available yet — refuses the deny-all
    /// box, whose declaration promises a verdict nothing would enforce, and
    /// runs every other, which needs no verdict enforced. Pinned as data,
    /// the same spelling the start-up line renders.
    #[test]
    fn the_cause_names_what_happens_to_the_box_on_each_host() {
        for (cause, why) in [
            (Cause::StepNotInstalled, "a host without the step"),
            (Cause::CannotConfine, "a host that cannot confine a box"),
        ] {
            assert_eq!(
                cause.host_ip_box_outcome(false),
                "its host-address boxes run unenforced",
                "natively, {why} is the exception, never a refusal"
            );
        }
        assert_eq!(
            Cause::CannotConfine.host_ip_box_outcome(true),
            "its host-address boxes are refused: it cannot place one in a \
             leaf that confines",
            "a guest that cannot confine a box has no leaf to decide anything in"
        );
        assert_eq!(
            Cause::GuestTableNotLoaded.host_ip_box_outcome(true),
            "its deny-all host-address boxes are refused and its other \
             host-address boxes run unenforced",
            "the interim refuses the deny-all box and runs the rest"
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
