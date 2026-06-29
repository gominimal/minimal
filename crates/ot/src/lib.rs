//! Tracking of long-running operations, so that pretty progress bars
//! can be printed.

use std::fmt::Display;
use std::sync::{
    Arc, Mutex, Weak,
    atomic::{AtomicU64, Ordering},
};

use tokio::sync::watch;

#[cfg(feature = "indicatif")]
mod indicatif_shim;
#[cfg(feature = "indicatif")]
pub use indicatif_shim::{IndicatifShim, StdoutWriter, render_operations_while, render_to_stderr};

#[derive(Debug, Clone)]
pub enum CheckKind {
    CheckPackages,
    CheckStacks,
    CheckProfiles,
}
impl Display for CheckKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CheckKind::CheckPackages => f.write_str("package"),
            CheckKind::CheckStacks => f.write_str("stack"),
            CheckKind::CheckProfiles => f.write_str("profile"),
        }
    }
}

/// An operation being tracked.
#[derive(Debug, Clone)]
pub enum Operation {
    PackageBuild { name: String },
    CollectOutputs { name: String, outputs: Vec<String> },
    FetchPkg { name: String },
    CompressPkg { name: String },
    ExtractPkg { name: String },
    FetchSource { url: String },
    Check { kind: CheckKind, name: String },
    StandaloneTest { name: String },
    FetchIndex,
}

/// A stable identifier for a node in the operation tree.
///
/// Ids are unique within a single tree (i.e. per [`RootShared`]) and never
/// reused, so a renderer can diff successive snapshots to learn which rows
/// appeared, changed, or vanished. `0` is reserved for the root node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct OpId(u64);

/// Quantitative progress of an operation: how far through, and the total if
/// known. Stored in the state core so a renderer can draw a bar without
/// reaching into indicatif.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Progress {
    pub pos: u64,
    pub len: Option<u64>,
}

/// State shared by every node of a single operation tree, owned via `Arc`.
///
/// Created once per root (see [`OpTracker::new_root`]) and cloned into each
/// child so the whole tree shares one change counter and wakeup primitive.
#[derive(Debug)]
struct RootShared {
    /// Monotonic change counter, bumped on every mutation anywhere in the tree,
    /// carried as the value of a [`watch`] channel. `watch` supports any number
    /// of independent receivers (one per renderer/driver), each woken on change
    /// and tracking its own last-seen version — so multiple drivers (e.g. a CLI
    /// stderr renderer plus a logger, or two terminals attached to one daemon
    /// session) can observe the same root without missed wakeups.
    version: watch::Sender<u64>,
    /// Allocator for [`OpId`]s within this tree.
    next_id: AtomicU64,
}

impl Default for RootShared {
    fn default() -> Self {
        // The initial receiver is dropped; drivers obtain their own via
        // `Sender::subscribe`, which works even with no live receivers.
        Self {
            version: watch::channel(0).0,
            next_id: AtomicU64::new(0),
        }
    }
}

impl RootShared {
    /// Records a mutation: bump the version, waking every subscribed driver.
    fn bump(&self) {
        self.version.send_modify(|v| *v += 1);
    }

    /// Allocates the next unique [`OpId`] for this tree (root is `0`).
    fn alloc_id(&self) -> OpId {
        OpId(self.next_id.fetch_add(1, Ordering::Relaxed) + 1)
    }
}

/// An immutable view of one operation, produced by [`OpTracker::snapshot`].
///
/// A flat `Vec<OpSnapshot>` in pre-order is the "slice of progress" a renderer
/// consumes: already in display order, with `depth` carrying the indentation.
#[derive(Debug, Clone)]
pub struct OpSnapshot {
    pub id: OpId,
    pub depth: usize,
    pub op: Option<Operation>,
    pub progress: Option<Progress>,
}

#[derive(Debug)]
struct TrackerInner {
    id: OpId,
    depth: usize,
    // Strong reference to the parent, pinning the ancestor chain alive so a live
    // node stays reachable from the root during `snapshot` traversal, which
    // descends through `children` (held only by `Weak`). Never read directly;
    // its role is purely to own the chain upward.
    #[allow(dead_code)]
    parent: Option<OpTracker>,
    op: Option<Operation>,
    progress: Option<Progress>,
    children: Vec<Weak<Mutex<TrackerInner>>>,
    shared: Arc<RootShared>,
}

impl TrackerInner {
    fn set_length(&mut self, length: u64) {
        self.progress = Some(Progress {
            pos: self.progress.map_or(0, |p| p.pos),
            len: Some(length),
        });
        self.shared.bump();
    }
    fn increment(&mut self, amt: u64) {
        self.progress = Some(Progress {
            pos: self.progress.map_or(amt, |p| p.pos + amt),
            len: self.progress.and_then(|p| p.len),
        });
        self.shared.bump();
    }

    fn set_op(&mut self, op: Option<Operation>) {
        self.op = op;
        // A fresh operation starts with no measured progress; FetchPkg & co.
        // call set_length once they learn the content length.
        self.progress = None;
        self.shared.bump();
    }
}

/// A node in the operation tree, potentially describing an operation.
///
/// Nodes may have a parent (unless they are the root) or children.
/// Nodes never outlive their parents.
#[derive(Debug, Clone)]
pub struct OpTracker {
    inner: Arc<Mutex<TrackerInner>>,
}

impl OpTracker {
    /// Creates a fresh root of a new operation tree, with its own change
    /// counter and wakeup primitive. Each independent rendering context (the
    /// CLI process, or a single daemon session) owns one root.
    pub fn new_root() -> OpTracker {
        OpTracker {
            inner: Arc::new(Mutex::new(TrackerInner {
                id: OpId(0),
                depth: 0,
                parent: None,
                op: None,
                progress: None,
                children: Vec::with_capacity(32),
                shared: Arc::new(RootShared::default()),
            })),
        }
    }

    /// Creates a new operation node as a child of the given root.
    ///
    /// `None` means "untracked": the node is created under a fresh, unrendered
    /// throwaway tree, so progress calls on it are valid no-ops. Pass `Some` to
    /// attach the operation to a real, rendered tree.
    pub fn new_with_root(root_op: &Option<OpTracker>) -> OpTracker {
        match root_op {
            None => OpTracker::new_root().new_child(),
            Some(root) => root.new_child(),
        }
    }

    /// Creates and returns a new operation which is a child of self.
    pub fn new_child(&self) -> OpTracker {
        let mut parent = self.inner.lock().unwrap();
        let shared = parent.shared.clone();

        let new = OpTracker {
            inner: Arc::new(Mutex::new(TrackerInner {
                id: shared.alloc_id(),
                depth: parent.depth + 1,
                parent: Some(self.clone()),
                op: None,
                progress: None,
                children: Vec::new(),
                shared,
            })),
        };

        parent.children.push(Arc::downgrade(&new.inner));
        new
    }

    pub fn with_op(self, op: Operation) -> Self {
        self.set_op(op);
        self
    }
    pub fn set_op(&self, op: Operation) {
        self.inner.lock().unwrap().set_op(Some(op));
    }
    pub fn set_done(&self) {
        self.inner.lock().unwrap().set_op(None);
    }
    pub fn set_length(&self, length: u64) {
        self.inner.lock().unwrap().set_length(length);
    }
    pub fn increment(&self, amt: u64) {
        self.inner.lock().unwrap().increment(amt);
    }

    /// Returns how deep in the operation tree the operation is.
    pub fn depth(&self) -> usize {
        self.inner.lock().unwrap().depth
    }

    /// Returns a pre-order (depth-first) snapshot of this subtree, in display
    /// order. The returned `Vec` is decoupled from the live tree: a renderer
    /// can hold and diff it without keeping any lock.
    pub fn snapshot(&self) -> Vec<OpSnapshot> {
        let mut out = Vec::new();
        self.snapshot_into(&mut out);
        out
    }

    fn snapshot_into(&self, out: &mut Vec<OpSnapshot>) {
        // Collect this node's row and its live children under a single brief
        // lock, then recurse with the lock released so we never hold two node
        // locks at once.
        let children = {
            let s = self.inner.lock().unwrap();
            out.push(OpSnapshot {
                id: s.id,
                depth: s.depth,
                op: s.op.clone(),
                progress: s.progress,
            });
            s.children
                .iter()
                .filter_map(Weak::upgrade)
                .map(|inner| OpTracker { inner })
                .collect::<Vec<_>>()
        };
        for child in children {
            child.snapshot_into(out);
        }
    }

    /// Returns the tree's current change version. Increases on every mutation
    /// anywhere in the tree; a driver polls this to decide whether to repaint.
    pub fn version(&self) -> u64 {
        *self.inner.lock().unwrap().shared.version.borrow()
    }

    /// Subscribes to changes anywhere in the tree, returning a [`watch`]
    /// receiver carrying the change [`version`](Self::version).
    ///
    /// Each driver owns its own receiver and tracks its own last-seen version,
    /// so any number of drivers can observe the same root concurrently. The
    /// typical loop renders, then `rx.changed().await` (which also returns
    /// immediately if the version advanced since the last `borrow_and_update`),
    /// then re-snapshots. `changed()` resolves to `Err` once the tree is
    /// dropped, giving drivers a clean exit.
    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.inner.lock().unwrap().shared.version.subscribe()
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    // Each test creates a child of the global root tracker. The core no longer
    // renders, so these exercise pure state transitions with no terminal output.

    fn make_tracker() -> OpTracker {
        OpTracker::new_with_root(&None)
    }

    #[test]
    fn set_op_package_build_and_clear_does_not_panic() {
        let t = make_tracker();
        t.set_op(Operation::PackageBuild {
            name: "mypkg".into(),
        });
        t.set_done();
    }

    #[test]
    fn set_op_collect_outputs_and_clear_does_not_panic() {
        let t = make_tracker();
        t.set_op(Operation::CollectOutputs {
            name: "pkg".into(),
            outputs: vec!["out1".into(), "out2".into()],
        });
        t.set_done();
    }

    #[test]
    fn set_op_fetch_pkg_and_clear_does_not_panic() {
        let t = make_tracker();
        t.set_op(Operation::FetchPkg {
            name: "mypkg".into(),
        });
        t.set_done();
    }

    #[test]
    fn set_op_compress_pkg_and_clear_does_not_panic() {
        let t = make_tracker();
        t.set_op(Operation::CompressPkg {
            name: "mypkg".into(),
        });
        t.set_done();
    }

    #[test]
    fn set_op_extract_pkg_and_clear_does_not_panic() {
        let t = make_tracker();
        t.set_op(Operation::ExtractPkg {
            name: "mypkg".into(),
        });
        t.set_done();
    }

    #[test]
    fn set_op_fetch_source_and_clear_does_not_panic() {
        let t = make_tracker();
        t.set_op(Operation::FetchSource {
            url: "https://example.com/src.tar.gz".into(),
        });
        t.set_done();
    }

    #[test]
    fn set_op_check_packages_and_clear_does_not_panic() {
        let t = make_tracker();
        t.set_op(Operation::Check {
            kind: CheckKind::CheckPackages,
            name: "pkg".into(),
        });
        t.set_done();
    }

    #[test]
    fn set_op_check_stacks_and_clear_does_not_panic() {
        let t = make_tracker();
        t.set_op(Operation::Check {
            kind: CheckKind::CheckStacks,
            name: "stk".into(),
        });
        t.set_done();
    }

    #[test]
    fn set_op_check_profiles_and_clear_does_not_panic() {
        let t = make_tracker();
        t.set_op(Operation::Check {
            kind: CheckKind::CheckProfiles,
            name: "prof".into(),
        });
        t.set_done();
    }

    #[test]
    fn set_op_standalone_test_and_clear_does_not_panic() {
        let t = make_tracker();
        t.set_op(Operation::StandaloneTest {
            name: "mytest".into(),
        });
        t.set_done();
    }

    #[test]
    fn set_op_fetch_index_and_clear_does_not_panic() {
        let t = make_tracker();
        t.set_op(Operation::FetchIndex);
        t.set_done();
    }

    #[test]
    fn new_child_after_set_op_does_not_panic() {
        let parent = make_tracker();
        parent.set_op(Operation::PackageBuild {
            name: "parent".into(),
        });
        let child = parent.new_child();
        child.set_op(Operation::ExtractPkg {
            name: "child".into(),
        });
        child.set_done();
        parent.set_done();
    }

    #[test]
    fn set_op_collect_outputs_long_name_truncated_does_not_panic() {
        let t = make_tracker();
        // outputs string exceeds 30 chars to exercise the truncation branch
        t.set_op(Operation::CollectOutputs {
            name: "pkg".into(),
            outputs: vec!["a-very-long-output-name-that-exceeds-thirty-characters".into()],
        });
        t.set_done();
    }

    #[test]
    fn depth_of_child_is_one_more_than_parent() {
        let parent = make_tracker();
        let parent_depth = parent.depth();
        let child = parent.new_child();
        assert_eq!(child.depth(), parent_depth + 1);
    }

    #[test]
    fn snapshot_is_preorder_with_node_and_children() {
        let root = OpTracker::new_root();
        root.set_op(Operation::PackageBuild {
            name: "root".into(),
        });
        let a = root
            .new_child()
            .with_op(Operation::ExtractPkg { name: "a".into() });
        let _b = root
            .new_child()
            .with_op(Operation::CompressPkg { name: "b".into() });
        let _a1 = a
            .new_child()
            .with_op(Operation::FetchPkg { name: "a1".into() });

        let snap = root.snapshot();
        // root, a, a1, b — pre-order: a's subtree before sibling b.
        let names: Vec<_> = snap
            .iter()
            .map(|s| match &s.op {
                Some(Operation::PackageBuild { name })
                | Some(Operation::ExtractPkg { name })
                | Some(Operation::CompressPkg { name })
                | Some(Operation::FetchPkg { name }) => name.clone(),
                other => format!("{other:?}"),
            })
            .collect();
        assert_eq!(names, vec!["root", "a", "a1", "b"]);
        // Depth carries indentation: root at 0, children at 1, grandchild at 2.
        assert_eq!(
            snap.iter().map(|s| s.depth).collect::<Vec<_>>(),
            vec![0, 1, 2, 1]
        );
    }

    #[test]
    fn snapshot_ids_are_unique_within_a_tree() {
        let root = OpTracker::new_root();
        let _a = root.new_child();
        let _b = root.new_child();
        let mut ids: Vec<_> = root.snapshot().iter().map(|s| s.id).collect();
        let total = ids.len();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), total, "ids must be unique");
    }

    #[test]
    fn version_advances_on_each_mutation() {
        let root = OpTracker::new_root();
        let child = root.new_child();
        let v0 = root.version();
        child.set_op(Operation::FetchPkg { name: "p".into() });
        let v1 = root.version();
        child.set_length(100);
        let v2 = root.version();
        child.increment(10);
        let v3 = root.version();
        child.set_done();
        let v4 = root.version();
        assert!(v0 < v1 && v1 < v2 && v2 < v3 && v3 < v4);
    }

    #[test]
    fn progress_is_tracked_in_state() {
        let root = OpTracker::new_root();
        let child = root.new_child();
        child.set_op(Operation::FetchPkg { name: "p".into() });
        child.set_length(100);
        child.increment(30);
        child.increment(12);

        let row = root
            .snapshot()
            .into_iter()
            .find(|s| s.depth == 1)
            .expect("child row present");
        assert_eq!(
            row.progress,
            Some(Progress {
                pos: 42,
                len: Some(100)
            })
        );
    }

    #[test]
    fn set_op_resets_progress() {
        let root = OpTracker::new_root();
        let child = root.new_child();
        child.set_op(Operation::FetchPkg { name: "p".into() });
        child.set_length(100);
        child.increment(50);
        // Transitioning to a new operation clears the measured progress.
        child.set_op(Operation::ExtractPkg { name: "p".into() });

        let row = root
            .snapshot()
            .into_iter()
            .find(|s| s.depth == 1)
            .expect("child row present");
        assert_eq!(row.progress, None);
    }

    #[test]
    fn distinct_roots_have_independent_versions() {
        let r1 = OpTracker::new_root();
        let r2 = OpTracker::new_root();
        r1.new_child()
            .set_op(Operation::PackageBuild { name: "x".into() });
        assert!(r1.version() > 0);
        assert_eq!(r2.version(), 0, "mutating one tree must not touch another");
    }

    #[tokio::test]
    async fn changed_wakes_on_mutation() {
        let root = OpTracker::new_root();
        let child = root.new_child();
        let mut rx = root.subscribe();
        // Register the wait, then mutate from another task; the watch must wake.
        let h = tokio::spawn(async move { rx.changed().await });
        // Yield so the spawned task reaches the await point before we notify.
        tokio::task::yield_now().await;
        child.set_op(Operation::PackageBuild { name: "x".into() });
        tokio::time::timeout(Duration::from_secs(1), h)
            .await
            .expect("changed() should wake within timeout")
            .expect("waiter task should not panic")
            .expect("watch sender should be alive");
    }

    #[tokio::test]
    async fn two_concurrent_watchers_both_wake_on_mutation() {
        // The multi-consumer guarantee `watch` buys us over `notify_one`: a
        // single mutation wakes *every* subscribed driver, not just one.
        let root = OpTracker::new_root();
        let child = root.new_child();
        let mut rx1 = root.subscribe();
        let mut rx2 = root.subscribe();
        let h1 = tokio::spawn(async move { rx1.changed().await });
        let h2 = tokio::spawn(async move { rx2.changed().await });
        // Yield so both watchers are parked before the mutation lands.
        tokio::task::yield_now().await;
        child.set_op(Operation::PackageBuild { name: "x".into() });
        for h in [h1, h2] {
            tokio::time::timeout(Duration::from_secs(1), h)
                .await
                .expect("both watchers should wake within timeout")
                .expect("watcher task should not panic")
                .expect("watch sender should be alive");
        }
    }
}
