//! Host-address egress enforcement: the host's fact, the per-box
//! classifier leaf, and the launch gate over both.

use super::*;

/// What the launch's leaf placement means for the box's egress record: the
/// placement is the outcome the launch records — `per_box` when this launch
/// placed this host-address box in a classifier leaf of the host's tree,
/// `none` when it did not — never the node fact re-read beside it, because
/// the record is the box's own launch outcome, not the host's state as it
/// stands now. A leaf placed over a table that is not refusing still carries
/// the leaf: the reads lower it to the state the host can currently honour
/// ([`displayed_host_ip_enforcement`]), and when the table comes back the
/// box is in the leaf its launch placed it in, so the record says so without
/// a relaunch. A host-address box without a leaf ran with the host's address
/// and no verdict of its own, and any other network mode has no host address
/// to decide on at all.
///
/// The box's declaration is the placement's other half (NET-079): a leaf
/// is only an enforcement while the declaration is one the classifier can
/// enforce, so the record is derived from the placement *plus*
/// [`classifier::unenforceable_rules`] — never from the placement or the
/// node fact alone — and a placed box whose declaration names a rule the
/// loaded table cannot enforce is recorded `none`, the state it ran in, on
/// whatever host it ran on. That is the shape the launch gate above refuses
/// when the host decides per box; this derivation is what keeps the record
/// honest for the one host that cannot decide, where the box still runs and
/// the record must not promise a verdict its rules never had.
///
/// Pure over its inputs, so the mapping is pinned where it is written.
pub(super) fn host_ip_enforcement(
    network_mode: NetworkMode,
    leaf: Option<&sandbox::config::ClassifierLeaf>,
    declaration: Option<&boxes::EgressPolicy>,
) -> Option<HostIpEnforcement> {
    match network_mode {
        NetworkMode::HostNet => Some(match leaf {
            Some(_) if crate::net::classifier::unenforceable_rules(declaration).is_empty() => {
                HostIpEnforcement::PerBox
            }
            _ => HostIpEnforcement::None,
        }),
        _ => None,
    }
}

/// The daemon's one node fact about per-box egress enforcement (NET-079):
/// whether this host can decide a host-address box's egress verdict per box,
/// and — while it cannot — the cause it cannot. One fact for the whole node,
/// because nothing it rests on is a session's: the decision reads the host's
/// own cgroup tree, its mount table, and the loaded table's effect, and the
/// cause names a state of the host, not of any box on it. The daemon's
/// start-up read seeds it ([`set_host_ip_enforcement_fact`]'s caller in
/// `main`) and every host-address launch's [`re_read_classifier_fact`]
/// refreshes it, because the fact it rests on is the table's *effect*
/// (design §7.4) — a marker survives whatever emptied the table and the
/// refusal does not.
///
/// Held as a process-global rather than a field on the server's state for
/// the same reason: the start-up read that seeds it runs before any server
/// exists. It is the node's half of every surface that shows a session: the
/// create reply states it outright (no box has launched yet to have its own
/// outcome), each read surface's refusal gate answers over its cause, and
/// the listing and the runtime-facts reply lower a box's own launch record
/// by its state — never raise one to it.
///
/// `cause` rides beside the state because the two are one fact: the state a
/// display shows and the advice the create reply carries both come from the
/// one decision the probe read — the cause is `None` only while the host
/// decides — and a fact that held the state alone could not say why.
#[derive(Clone, Copy)]
pub(crate) struct HostIpEnforcementFact {
    /// The state itself, in the enum the listing's entries carry.
    pub(crate) enforcement: minimald_rpc::HostIpEnforcement,
    /// Why the host cannot decide per box; `None` while it can, and on a
    /// fact no read has set yet (the cell's default, below), where the
    /// cause is as unread as the state.
    pub(crate) cause: Option<crate::net::classifier::Cause>,
}

impl HostIpEnforcementFact {
    /// The fact as a [`classifier::Decision`], for the gate that refuses a
    /// box over a cause. Lossless in the one direction that matters: a
    /// `per_box` state is a decided verdict with no cause, and a cause
    /// carries its own state — while a cause-less `none` state (the cell's
    /// default, before any read has set it) is not a decision at all, so it
    /// is `None`: a daemon that has not read its host refuses nothing over
    /// it, and its displays show the state without claiming a cause.
    fn decision(&self) -> Option<crate::net::classifier::Decision> {
        match (self.enforcement, self.cause) {
            (minimald_rpc::HostIpEnforcement::PerBox, _) => {
                Some(crate::net::classifier::Decision::decided())
            }
            (_, Some(cause)) => Some(crate::net::classifier::Decision::undecidable(cause)),
            (_, None) => None,
        }
    }

    /// Whether the host this fact stands for can decide a host-address
    /// box's egress verdict per box (NET-079) — the one bit of the node
    /// fact the create path reads, taking the fact exactly as the create
    /// response does rather than re-probing the host itself: a create is
    /// not a place that decides a box, and the launch that follows reads
    /// the host again for its own gate. A fact no read has set yet — the
    /// cell's default — answers `false`, so a daemon that has not read its
    /// host creates what it is handed and leaves the verdicts to its
    /// launches.
    pub(crate) fn can_decide_per_box(&self) -> bool {
        self.enforcement == minimald_rpc::HostIpEnforcement::PerBox
    }
}

/// The fact itself: the cell every surface that shows a session reads, in
/// the state the daemon's start-up read left it — `none`, with no cause, the
/// state of a daemon that has not read its host yet. Const-initializable,
/// so the one lock it sits behind is taken only by the reads and writes
/// that swap or copy a fact two machine words wide.
pub(super) static HOST_IP_ENFORCEMENT_FACT: std::sync::Mutex<HostIpEnforcementFact> =
    std::sync::Mutex::new(HostIpEnforcementFact {
        enforcement: minimald_rpc::HostIpEnforcement::None,
        cause: None,
    });

/// Sets the fact from a decision the classifier read — the one write path
/// both its writers go through: the daemon's start-up read, which owns the
/// host before any session exists, and each host-address launch's
/// [`re_read_classifier_fact`], whose re-read keeps the fact current in the
/// face of the table's own effect changing under it. `pub` because the
/// start-up read is the daemon binary's (`main`), which owns the fact before
/// any of this crate's servers exist.
pub fn set_host_ip_enforcement_fact(decision: &crate::net::classifier::Decision) {
    let mut fact = HOST_IP_ENFORCEMENT_FACT
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    fact.enforcement = if decision.can_decide_per_box() {
        minimald_rpc::HostIpEnforcement::PerBox
    } else {
        minimald_rpc::HostIpEnforcement::None
    };
    fact.cause = decision.cause();
}

/// The fact as it stands, copied out for a surface that shows a session —
/// the copy is two machine words, so the lock is held for the copy alone and
/// never across a decision a re-read is making.
pub(crate) fn host_ip_enforcement_fact() -> HostIpEnforcementFact {
    *HOST_IP_ENFORCEMENT_FACT
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Puts the fact back to its start-up default — no read, no cause — so a
/// test that set a fact of its own leaves the daemon it shares a process
/// with as it found it.
#[cfg(test)]
pub(crate) fn clear_host_ip_enforcement_fact() {
    let mut fact = HOST_IP_ENFORCEMENT_FACT
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    fact.enforcement = minimald_rpc::HostIpEnforcement::None;
    fact.cause = None;
}

/// The per-box egress enforcement a session's display surfaces show
/// (NET-079): the box's own launch record — what the launch that produced
/// this box decided about it, `per_box` if it placed the box in a classifier
/// leaf and `none` if it did not — for a host-address box the classifier did
/// not refuse, and nothing for any other box. An own-address or none box's
/// verdict is decided on address leases, never on the host's cgroup tree, and
/// a box the classifier refused at placement has no state to show, because
/// the refusal is what its launch said.
///
/// The record is lowered by the daemon's one node fact, never raised above
/// either half: a box whose launch placed it shows `per_box` only while
/// this host can decide per box, and `none` whenever it cannot — whether
/// the table stopped deciding after the placement or had not decided when
/// the placement was made, because a leaf over a table that is not
/// refusing decides nothing until it refuses again. A box its launch left
/// unplaced stays `none` for its life, whatever a later launch of another
/// box decided, because the outcome belongs to the launch that produced
/// it, not to the node as it stands now. Only a host-address box that has
/// not launched yet — a created session, or one whose launch never minted
/// a host — shows the fact alone.
///
/// The refusal half is the launch's own gate —
/// [`refused_unenforced_host_address_box`] — so a display cannot disagree
/// with a launch over which box is refused: the gate's `placed` fact, which a
/// launch knows from its own placement, is inferred here from the fact's
/// cause ([`fact_places_a_leaf`]), because the causes are what place or
/// refuse the box natively and in the guest. A cause-less fact — the cell's
/// default — places, and its gate refuses nothing, so the state shows as it
/// stands.
///
/// Pure over its inputs, so the gate and its lowering are pinned where they
/// are written.
pub(crate) fn displayed_host_ip_enforcement(
    guest: bool,
    network_mode: NetworkMode,
    verdict: sandbox::config::Verdict,
    fact: &HostIpEnforcementFact,
    launch_record: Option<HostIpEnforcement>,
) -> Option<minimald_rpc::HostIpEnforcement> {
    if refused_unenforced_host_address_box(
        guest,
        network_mode,
        verdict,
        fact_places_a_leaf(fact.cause),
        fact.decision().as_ref(),
    )
    .is_some()
    {
        return None;
    }
    match network_mode {
        NetworkMode::HostNet => Some(match launch_record {
            // The box's own launch outcome: shown as recorded while the host
            // can still decide per box, lowered to the undecidable state the
            // host is in when it cannot — never raised above either.
            Some(recorded) => match (recorded, fact.enforcement) {
                (HostIpEnforcement::PerBox, HostIpEnforcement::PerBox) => HostIpEnforcement::PerBox,
                _ => HostIpEnforcement::None,
            },
            // No box of this session has launched yet, so there is no
            // outcome to show: the node's state is the best either half of
            // the daemon knows about a box that does not exist yet.
            None => fact.enforcement,
        }),
        _ => None,
    }
}

/// Whether a fact's cause says the step's tree is there to place a leaf in:
/// the causes that imply a box nothing places are the step's absence and the
/// mount that cannot confine, and every other cause — the two probe causes,
/// the guest's unloaded table — arises only over a tree the step already
/// installed (the marker and the delegated subtrees gate the probe), which is
/// also where a decided fact's box goes. `None` — a decided fact, or the
/// cell's default — places, so a display's refusal inference reads a decided
/// host as the placement its launches make.
///
/// `pub(crate)`: the test launcher's mock models its placement's outcome
/// from the same cause the displays infer a launch's placement over, so
/// the two never disagree about which causes place.
pub(crate) fn fact_places_a_leaf(cause: Option<crate::net::classifier::Cause>) -> bool {
    !matches!(
        cause,
        Some(
            crate::net::classifier::Cause::StepNotInstalled
                | crate::net::classifier::Cause::CannotConfine
        )
    )
}

/// Serializes the window in which a process-global test stand-in is
/// installed, or the enforcement fact a test sets: a loopback-probe one
/// (`net::loopback`), the classifier reading's (below), or the fact a launch
/// or a test wrote — under libtest, where every test in this binary shares
/// one process, a create, launch, or listing driven by another test would
/// answer over it too. Nextest runs each test in its own process; the mutex
/// keeps the in-process runner as safe.
///
/// Lives here — the module that owns the fact and the reading stand-in — so
/// the launch tests that write the fact and the RPC tests that read it share
/// one guard.
#[cfg(test)]
pub(crate) static PROBE_TEST_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// The test stand-in for the probe's reading: a `Reading` a test hands the
/// decision in place of the live probe's, so the decision logic itself still
/// runs over the facts a test laid out — the tree and mount table a test
/// spells — and the one thing a stand-in tree cannot model, a table whose
/// effect the probe reads, is the one thing a test injects. The same
/// stand-in discipline the session-host knobs use: a fact in, never an
/// answer.
#[cfg(test)]
pub(super) static CLASSIFIER_READING_STANDIN: std::sync::Mutex<
    Option<crate::net::classifier::Reading>,
> = std::sync::Mutex::new(None);

/// Points the decision's probe at `reading` for the rest of this process —
/// the stand-in state a test built. See [`CLASSIFIER_READING_STANDIN`].
///
/// The tests that use this take the probe-test mutex in this module for the
/// whole install→read→assert→clear window: the stand-in is process-global,
/// so under libtest — where the tests of one binary share a process — a
/// launch driven by another test would read it too.
#[cfg(test)]
pub(crate) fn install_classifier_reading_standin(reading: crate::net::classifier::Reading) {
    *CLASSIFIER_READING_STANDIN
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(reading);
}

/// Withdraws the reading stand-in [`install_classifier_reading_standin`]
/// installed, so later reads probe the table for real again.
#[cfg(test)]
pub(crate) fn clear_classifier_reading_standin() {
    *CLASSIFIER_READING_STANDIN
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
}

/// The probe's reading the decision answers over: the live probe, except
/// under test, where a stand-in reading may be installed over the same tree
/// facts the test laid out.
#[cfg(test)]
pub(super) fn classifier_reading(
    root: &std::path::Path,
    guest: bool,
) -> crate::net::classifier::Reading {
    let standin = CLASSIFIER_READING_STANDIN
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone();
    standin.unwrap_or_else(|| live_classifier_reading(root, guest))
}

/// The probe's reading the decision answers over: the live probe, always —
/// the non-test twin of [`classifier_reading`], spelled separately so the
/// test arm's lock is never compiled into a daemon that cannot install a
/// stand-in.
#[cfg(not(test))]
pub(super) fn classifier_reading(
    root: &std::path::Path,
    guest: bool,
) -> crate::net::classifier::Reading {
    live_classifier_reading(root, guest)
}

/// The live probe a launch reads: a guest connects to the listener its boot
/// holds, so the port the probe is refused at is one the daemon held all
/// along, never one bound for this reading (NET-079, design §7.4); a native
/// host binds a listener per reading.
pub(super) fn live_classifier_reading(
    root: &std::path::Path,
    guest: bool,
) -> crate::net::classifier::Reading {
    if guest {
        crate::net::classifier::read_held_filter(root)
    } else {
        crate::net::classifier::read_filter(root)
    }
}

/// The classifier fact every host-address launch reads the host for,
/// freshly, on the blocking pool: the mount table the tree answers over —
/// the knob's when one was set, the daemon's own, read live, when none was
/// ([`launch_mountinfo`]) — and the decision over the tree and that one
/// table (NET-079), returned together because the two are one fact: a
/// launch that decides a box over a table and then places it over another
/// has read nothing.
///
/// The launch's read — the decision the placement and the refusal answer
/// over — and the write that keeps the daemon's
/// one node fact ([`HOST_IP_ENFORCEMENT_FACT`]) current, in one move: the
/// read is fresh rather than a kept start-time reading, because the fact
/// the decision rests on is the table's *effect* (design §7.4) — a marker
/// survives whatever emptied the table and the refusal does not, and a
/// kept reading would survive it the same way — and the surfaces that show
/// a session read the fact, so they show this read's state and not one a
/// re-read has replaced.
///
/// The mount table rides back out beside the decision because the launch
/// answers its placement over the same one table the decision just read —
/// one blocking hop, so the live mount-table read never runs on the async
/// worker a session is being created on. `Err` says the read did not run
/// at all — the blocking task was lost or panicked — which is the launch's
/// own cause to name: a launch that cannot read the fact cannot place a
/// box.
pub(crate) async fn re_read_classifier_fact(
    root: std::path::PathBuf,
    mountinfo_knob: Option<String>,
    guest: bool,
) -> std::io::Result<(Option<String>, crate::net::classifier::Decision)> {
    crate::traced::spawn_blocking(move || {
        let mountinfo = launch_mountinfo(mountinfo_knob);
        let decision = crate::net::classifier::decide(&root, mountinfo.as_deref(), guest, || {
            classifier_reading(&root, guest)
        });
        set_host_ip_enforcement_fact(&decision);
        (mountinfo, decision)
    })
    .await
    .map_err(std::io::Error::other)
}

/// Creates the classifier leaf this session's host-address box is placed in
/// (NET-079), under the tree the privileged step installs on a native host
/// (`scripts/install-host-classifier.sh`) and the guest daemon mounts for
/// itself, named by the session's id: the leaf belongs to a session, not to
/// a display name a person can type twice.
///
/// The tree has to be *real* first — on this host's cgroup2, and in the
/// guest with `nsdelegate` — or the leaf this function would create decides
/// nothing while looking placed; see [`refused_unenforced_host_address_box`]
/// for the guest, where that state refuses a host-address launch instead of
/// running it unenforced.
///
/// And the daemon has to be able to *place a process* in a leaf of it: a
/// real tree the daemon is not inside decides its verdicts on a join the box
/// dies making, because the kernel gates a `cgroup.procs` write on write
/// permission to the common ancestor of source and destination — the
/// root-owned mount root above the tree for a daemon still in `user.slice`.
/// [`sandbox::classifier::probe_child_placement`] performs the migration
/// with a throwaway child first, so the box's own join never runs where it
/// cannot succeed: an unplaceable session is decided here, at the launch,
/// not by a box that dies with `127` in a closure whose stderr reaches no
/// log.
///
/// `Ok(None)` means this host places no box: the tree is absent, or the
/// daemon cannot place a child in it. The session still launches, and its
/// box runs unenforced — NET-079's exception, that a host which cannot
/// decide per box never refuses the box or its connections on that ground.
///
/// `Err` means the leaf exists but cannot be this session's: another session
/// holds it, which a fresh launch of the same id cannot tolerate — two
/// sessions in one leaf would decide both their verdicts together.
pub(super) async fn create_session_leaf(
    root: &std::path::Path,
    mountinfo: Option<&str>,
    guest: bool,
    session_id: &boxes::SessionId,
    session_name: &str,
    verdict: sandbox::config::Verdict,
    can_decide_per_box: bool,
) -> io::Result<Option<sandbox::config::ClassifierLeaf>> {
    if !sandbox::classifier::tree_is_real(root, mountinfo, guest) {
        tracing::info!(
            session = session_name,
            tree = sandbox::classifier::TREE_ROOT,
            install = %sandbox::classifier::install_hint(),
            "this host has no classifier tree to place a box in; the session's \
             box runs unenforced",
        );
        return Ok(None);
    }
    // The placement the box's own join performs, tried first by a throwaway
    // child of this daemon: the proof is a migration the kernel accepted, not
    // the tree's existence. On the blocking pool, because a fork and its reap
    // do not belong on an executor thread. The probe makes its leaf in the
    // subtree this box's verdict picked, the same one its own leaf will
    // live in.
    let placement = match crate::traced::spawn_blocking({
        let root = root.to_path_buf();
        move || sandbox::classifier::probe_child_placement(&root, verdict)
    })
    .await
    {
        Ok(placement) => placement,
        Err(join) => Err(io::Error::other(join)),
    };
    if let Err(e) = placement {
        // Which step is missing decides what a person is told to do next: a
        // tree that is not there is the installer's to install, and a tree
        // that is there but refuses this daemon means the daemon is not
        // inside the delegated slice — the state the installer's `--pid`
        // step exists for, effective on the very next launch because the
        // probe is per-launch.
        let (what, hint) = match e.kind() {
            std::io::ErrorKind::NotFound => (
                "the classifier tree is not installed on this host — the \
                 placement probe cannot even make its throwaway leaf in it",
                "the installer has to install the tree",
            ),
            std::io::ErrorKind::PermissionDenied => (
                "this daemon cannot place a process in the classifier tree",
                "it is not inside the delegated slice, so the installer's \
                 --pid step or a Delegate=yes unit has to place it",
            ),
            _ => (
                "the placement probe of the classifier tree failed",
                "the probe's error is where to start",
            ),
        };
        tracing::info!(
            session = session_name,
            error = %e,
            daemon_cgroup = ?sandbox::classifier::own_cgroup_path(),
            install = %sandbox::classifier::install_hint(),
            hint,
            "{what}; {hint} — the session's box runs unenforced",
        );
        return Ok(None);
    }
    match create_or_reclaim_box_leaf(root, session_id, verdict) {
        Ok((leaf, reclaimed)) => {
            if reclaimed {
                tracing::info!(
                    session = session_name,
                    leaf = %leaf.display(),
                    "reclaimed this session's empty classifier leaf — a leftover a \
                     daemon death left behind; the kernel's rmdir emptiness test \
                     let it go, and the launch created it again for this box",
                );
            }
            // One info line per host-address box launch naming its classifier
            // identity (NET-079's observability): the subtree its declaration
            // picked, the leaf that verdict placed it in, and whether this
            // host can decide per box — the fresh fact this launch's probe
            // just read from the table's effect. A leaf placed on a host
            // whose table is not loaded decides nothing while looking
            // decided, so the line never says `per_box` for one.
            if can_decide_per_box {
                tracing::info!(
                    session = session_name,
                    classifier = verdict.dir_name(),
                    leaf = %leaf.display(),
                    host_ip_enforcement = %HostIpEnforcement::PerBox.machine_str(),
                    "the host-address box's egress verdict is decided on its \
                     classifier leaf, in the {} subtree",
                    verdict.dir_name()
                );
            } else {
                tracing::info!(
                    session = session_name,
                    classifier = verdict.dir_name(),
                    leaf = %leaf.display(),
                    host_ip_enforcement = %HostIpEnforcement::None.machine_str(),
                    "the host-address box's leaf is placed in the {} subtree, \
                     but this host's classifier table is not loaded, so its \
                     egress verdict is not decided per box",
                    verdict.dir_name()
                );
            }
            Ok(Some(sandbox::config::ClassifierLeaf::new(leaf)))
        }
        // `NotFound` is the ordinary shape of "no tree on this host": the
        // privileged step has not run. Info, not warn — it is a deployment
        // state, not a fault, and the next step on this host is to run the
        // installer, not to debug one launch.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            tracing::info!(
                session = session_name,
                install = %sandbox::classifier::install_hint(),
                "the classifier tree is not installed on this host; \
                 the session's box runs unenforced",
            );
            Ok(None)
        }
        // A leaf named by this session's id that survives the reclaim is
        // another session's, and the refusal below says so: two sessions in
        // one leaf would decide both their verdicts together.
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Err(e),
        Err(e) => {
            tracing::warn!(
                session = session_name,
                error = %e,
                "creating the session's classifier leaf; the box runs unenforced",
            );
            Ok(None)
        }
    }
}

/// Creates the session's classifier leaf, reclaiming a leftover empty one.
///
/// The sweep at daemon start takes the empty leaves a daemon death leaves
/// behind, but it cannot take one made after it ran: a daemon that died
/// between creating the leaf and spawning the box into it leaves a leaf a
/// fresh launch of the same session id then finds. Whether that leaf is a
/// leftover or another session's is not for this code to guess — the
/// kernel's own emptiness test tells them apart, and it is the same
/// primitive [`sandbox::classifier::remove_box_leaf`] runs: an `rmdir`,
/// which the kernel refuses while the cgroup holds a process. A leftover
/// goes and the leaf is created again for this launch; a leaf that stays
/// belongs to a live session, and the refusal names the `rmdir` that
/// refused, so what a person reads is what would have had to be true for
/// the leaf to have been reclaimable.
///
/// Returns the leaf and whether it is a reclaimed leftover, so the launch
/// can say so. Split out of [`create_session_leaf`] so the two halves can
/// be driven over a stand-in tree: the real tree's emptiness test is the
/// kernel's, but the reclaims over a plain directory are the same code
/// paths.
pub(super) fn create_or_reclaim_box_leaf(
    root: &std::path::Path,
    session_id: &boxes::SessionId,
    verdict: sandbox::config::Verdict,
) -> io::Result<(std::path::PathBuf, bool)> {
    let id = session_id.to_string();
    match sandbox::classifier::create_box_leaf(root, &id, verdict) {
        Ok(leaf) => Ok((leaf, false)),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            let leftover = sandbox::classifier::box_leaf(root, &id, verdict);
            sandbox::classifier::remove_box_leaf(&leftover)
                .and_then(|()| sandbox::classifier::create_box_leaf(root, &id, verdict))
                .map(|leaf| (leaf, true))
                .map_err(|refused| {
                    io::Error::new(
                        std::io::ErrorKind::AlreadyExists,
                        format!(
                            "another session holds this one's classifier leaf \
                             ({session_id}): the leaf this launch found still exists \
                             and its rmdir — the kernel's own test that a cgroup \
                             holds no process — refused ({refused}), so the launch \
                             is refused rather than placing this box in another \
                             session's cgroup"
                        ),
                    )
                })
        }
        Err(e) => Err(e),
    }
}

/// Whether a host-address box this host cannot give a verdict of its own
/// must be refused rather than launched unenforced, and with what words:
/// the gate and the refusal are decided in one place, because the one
/// thing worse than either alone is a gate that said "refused" for words
/// that spell what the box did instead.
///
/// In the guest — this daemon being the microVM's pid 1 — the tree and the
/// table were this daemon's own boot's work, so there is no privileged step
/// a person could run to fix either half: a box that cannot be placed in a
/// leaf has no leaf to decide on at all, and a deny-all box whose table is
/// not loaded would run placed while nothing refuses its connections — a
/// verdict that looks decided and is not. The first is a broken guest
/// image; the second is the interim, guest-side classifier enforcement not
/// being available yet. Both are refused, each with the error that says
/// which it is (design §7.1). An allow box needs no verdict enforced, so a
/// guest that places it runs it.
///
/// Natively, NET-079's exception stands for every state this host can still
/// fix from itself: the step not installed, a tree no cgroup2 with
/// `nsdelegate` confines, a box that declares no verdict to enforce. Those
/// run unenforced, and the record and notice below say so. The exception
/// stops where the box's own declaration becomes the thing this host cannot
/// honour — a *placed* deny-all box over one of the two probe causes: a
/// table whose marker vouches for a refusal the probe did not read
/// (`TableNotEffective`), and a table whose effect could not be read at all
/// (`ProbeUnreadable`). Running that box would promise a refusal nothing
/// here is making, so the launch refuses it and names the cause, because
/// natively both halves are this host's to fix and the words are what tell
/// a person which one. Both causes arise only over a tree the step already
/// installed — the marker and the delegated subtrees gate the probe — so
/// the refusal is a placed box's, never an unplaced one's: a host that
/// cannot place a box has nothing decided-looking to refuse, and it keeps
/// the advisory.
///
/// Pure over its inputs, so the gate and its words are pinned where they
/// are written.
pub(super) fn refused_unenforced_host_address_box(
    guest: bool,
    network_mode: NetworkMode,
    verdict: sandbox::config::Verdict,
    placed: bool,
    decision: Option<&crate::net::classifier::Decision>,
) -> Option<String> {
    // Only a host-address box has a verdict the classifier could decide, and
    // only its launch reads a decision — the two facts are one, so the mode
    // check and the read are the same check, and a launch that read nothing
    // refuses nothing here.
    if !matches!(network_mode, NetworkMode::HostNet) {
        return None;
    }
    // The guest's unplaced box needs no decision read to refuse: there is no
    // tree to decide anything in, and that is the ground itself.
    if guest && !placed {
        return Some(
            "this guest has no classifier tree to place a host-address \
             box in: its cgroup2 is not mounted with nsdelegate, so the \
             box's verdict could not be decided and the box was refused \
             rather than run unenforced (broken guest image)"
                .to_string(),
        );
    }
    let decision = decision?;
    if guest {
        if verdict == sandbox::config::Verdict::Deny && !decision.can_decide_per_box() {
            return Some(
                "this guest has not loaded the classifier table, so a \
                 deny-all box's connections would not be refused: the box's \
                 declaration promises a verdict nothing here refuses yet, \
                 and the box was refused rather than run unenforced \
                 (guest-side classifier enforcement is not available yet)"
                    .to_string(),
            );
        }
        return None;
    }
    if placed && verdict == sandbox::config::Verdict::Deny {
        return match decision.cause() {
            Some(crate::net::classifier::Cause::TableNotEffective) => Some(format!(
                "this host's classifier table is marked loaded but its refusal \
                 is not in force, so a deny-all box's connections would not be \
                 refused: the box's declaration promises a verdict nothing here \
                 enforces, and the box was refused rather than run unenforced \
                 (the table's refusal is not in force — the marker says loaded, so \
                 {install} alone is a no-op; {install} --undo, then {install}, \
                 reloads it)",
                install = sandbox::classifier::install_hint()
            )),
            Some(crate::net::classifier::Cause::ProbeUnreadable) => Some(
                "this host's classifier table's effect could not be read, so \
                 whether a deny-all box's connections would be refused is \
                 unknown: the box's declaration promises a verdict this host \
                 cannot prove, and the box was refused rather than run \
                 unenforced (the table's effect could not be read — this \
                 daemon's log carries the probe's own failure)"
                    .to_string(),
            ),
            // Everything else natively is the state this host can still fix
            // from itself — the step not installed, a tree that cannot
            // confine — or a host that decides, whose refusal no gate makes.
            // Those keep NET-079's exception, and the record and notice
            // below say what they run instead.
            _ => None,
        };
    }
    None
}

/// Whether a launch whose host-address box was not placed in a classifier
/// leaf, or was placed on a host that cannot decide per box, advises about
/// that state.
///
/// The counterpart of [`refused_unenforced_host_address_box`]: an unenforced
/// host-address box is the advisory posture on *either* kind of host —
/// natively NET-079's exception, in the guest the interim's own state — so
/// every *session* launch whose box runs without a verdict of its own says
/// so, once per launch like the resolver advisory it is modelled on
/// (design §7.1), never once per daemon. The refusals stand untouched
/// beside it: a box the guest cannot place is refused and advises nothing
/// (the refusal is that state's surface), and so is a deny-all box on a
/// table the guest has not loaded, and natively a deny-all box over either
/// probe cause — the advisory is the *other* host-address boxes' state, the
/// ones that need no verdict enforced to run, and the ruling's ask is that
/// their state be said at every session start, not left as a daemon log
/// line alone.
///
/// The state is read from the placement and the decision, not from the
/// launch's record: the record carries the placement — `per_box` for a
/// placed box, whatever the table decides — while the advisory is the box's
/// *current* state, the one the notice names, so a leaf placed over a table
/// that is not deciding advises exactly like a box nothing placed. What
/// this predicate does not carry is the launch's audience — a launch
/// minted for lifecycle hooks advises nobody (a hook run is not a session
/// start), which the launch itself folds in over
/// [`SandboxLauncher::for_hooks`]. Pure over its inputs, so the gate is
/// pinned where it is written.
pub(super) fn advises_unenforced_placement(
    network_mode: NetworkMode,
    leaf: Option<&sandbox::config::ClassifierLeaf>,
    decision: Option<&crate::net::classifier::Decision>,
) -> bool {
    matches!(network_mode, NetworkMode::HostNet)
        && !(leaf.is_some() && decision.is_some_and(|d| d.can_decide_per_box()))
}

/// The advisory text for a launch whose host-address box runs unenforced:
/// what the state is, and what would change it — spelled for the host and
/// the state that produced it, so a person reading the log is told which
/// half of the step this host owes. The guest names no install command:
/// no privileged step exists inside a microVM, so the person to tell is the
/// image's builder, and the interim's words are all the guest has to say.
pub(super) fn unenforced_placement_notice(
    guest: bool,
    leaf: Option<&sandbox::config::ClassifierLeaf>,
) -> String {
    if guest {
        return "guest-side classifier enforcement is not available yet; \
                this host-address box runs unenforced (host_ip_enforcement=none)"
            .to_string();
    }
    match leaf {
        None => format!(
            "this host places no classifier leaf for this session: its box \
             runs with the host's address and no egress verdict of its own \
             — {}",
            sandbox::classifier::install_hint()
        ),
        Some(_) => format!(
            "this host's classifier table is not loaded, so the leaf this \
             session's box was placed in decides nothing: the box runs with \
             the host's address and no egress verdict of its own — {}",
            sandbox::classifier::install_hint()
        ),
    }
}

/// Moves the box's container supervisor into its classifier leaf, now that
/// it exists.
///
/// The supervisor is the one process of the box that never passes through the
/// sandbox's pre-exec closure: hakoniwa forks it inside `spawn()`, before the
/// program's own child runs the closure that joins the leaf and unshares the
/// cgroup namespace onto it. It is written in by the daemon, from its own
/// namespaces where the leaf is reachable — the same place the shim later
/// writes an injected process. Everything the program forks later takes the
/// leaf from its parent, so the box is in its leaf from its first process to
/// its last.
pub(super) fn place_box_processes(
    leaf: &sandbox::config::ClassifierLeaf,
    supervisor: u32,
) -> std::io::Result<()> {
    sandbox::classifier::place_pid(&leaf.procs(), supervisor)
}
