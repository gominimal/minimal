//! Represents the state of deliverables and activity within an orchestration.

use std::{collections::HashMap, fmt::Display, sync::Arc};

use common::SpecHash;
use generational_arena::{Arena, Index};
use graph::{BinProvider, BuildSpecRef, DepGraph, ExecPlan, SubsetInput, Transitives};
use tokio::{
    sync::{MappedMutexGuard, Mutex, MutexGuard},
    task::AbortHandle,
};

use crate::Error;

/// A references to a [Deliverable] within [State].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeliverableRef(Index);

/// Variants of [Deliverable].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeliverableInner {
    /// A BuildSpec that needs to be built.
    Build {
        /// Which spec to build.
        bsr: BuildSpecRef,
        /// The hash of the build.
        spec_hash: SpecHash,
        /// True if no cycle breakers are used.
        full_build: bool,
        /// Which dependencies to be wired to the build.
        /// Subsets are represented as pointers to a [Deliverable] with
        /// a field `inner` of variant [DeliverableInner::Subset].
        dependencies: Vec<DeliverableRef>,
    },
    /// A subset that needs to be materialized.
    ///
    /// Subsets are just a selection of some of the outputs/files from a build.
    Subset {
        /// The subset to materialize.
        subset: SubsetInput,
        /// The hash of the subset.
        spec_hash: SpecHash,
        /// The build this subset depends on. May point to any kind of [Deliverable].
        build: DeliverableRef,
    },
    /// Something that needs to be fetched from a cache.
    ///
    /// Note that `CacheFill` deliverables are generated for stuff thats in the local cache too.
    CacheFill {
        /// The spec being fetched.
        bsr: BuildSpecRef,
        /// The cache key of the unit.
        spec_hash: SpecHash,
    },
}

impl DeliverableInner {
    /// If the enum is variant `Build`, returns the list of deliverables that build depends on.
    pub fn build_deps(&self) -> Option<&Vec<DeliverableRef>> {
        if let DeliverableInner::Build { dependencies, .. } = self {
            Some(dependencies)
        } else {
            None
        }
    }

    /// Pretty-prints the structure.
    pub fn display<'a>(&'a self, g: &'a DepGraph) -> DeliverableInnerDisplay<'a> {
        DeliverableInnerDisplay(self, g)
    }
}

/// A wrapper which implements pretty-printing for errors and debugging.
pub struct DeliverableInnerDisplay<'a>(&'a DeliverableInner, &'a DepGraph);

impl<'a> Display for DeliverableInnerDisplay<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let DeliverableInnerDisplay(i, graph) = self;

        match i {
            DeliverableInner::Build {
                bsr,
                spec_hash,
                full_build,
                dependencies: _,
            } => {
                let build = graph.get(bsr).unwrap();
                f.debug_struct("build")
                    .field("full", full_build)
                    .field("hash", &spec_hash.0.to_hex())
                    .field("spec", &build.name)
                    .finish()
            }
            DeliverableInner::CacheFill { bsr, spec_hash } => {
                let build = graph.get(bsr).unwrap();
                f.debug_struct("cache_fetch")
                    .field("hash", &spec_hash.0.to_hex())
                    .field("spec", &build.name)
                    .finish()
            }
            DeliverableInner::Subset {
                build: _,
                spec_hash,
                subset,
            } => {
                let build = graph.get(&subset.from).unwrap();
                f.debug_struct("cache_fetch")
                    .field("hash", &spec_hash.0.to_hex())
                    .field("from_spec", &build.name)
                    .field("from_spec_hash", &graph.spec_hash(&subset.from))
                    .field("outputs", &subset.outputs)
                    .finish()
            }
        }
    }
}

/// The runtime/action state regarding the creation of a [Deliverable].
#[derive(Debug, Default)]
pub enum DeliverableState<B: super::Backend> {
    /// Nothing has yet happened to construct this deliverable.
    #[default]
    Pending,
    /// A task has been started to construct this deliverable.
    InProgress(AbortHandle),
    /// The task is complete, and the contained output [B::Artifact] can be used.
    Complete(B::Artifact),
}

/// A unit of work: Something that needs to be built, fetched, or materialized,
///
/// This is the core unit of action within the orchestration system. See [DeliverableInner] for
/// the different kinds of work a deliverable can be.
#[derive(Debug)]
pub struct Deliverable<B: super::Backend> {
    pub inner: DeliverableInner,
    pub state: DeliverableState<B>,
}

/// A wrapper type for all the underlying storage within a [State] object.
#[derive(Debug)]
pub(crate) struct StateInner<B: super::Backend> {
    pub(crate) deliverables: Arena<Deliverable<B>>,
    fills_by_ref: HashMap<BuildSpecRef, DeliverableRef>,
    builds_by_ref: HashMap<BuildSpecRef, Vec<DeliverableRef>>,
    subsets_by_ref: HashMap<SubsetInput, DeliverableRef>,
}

impl<B: super::Backend> StateInner<B> {
    fn new() -> Self {
        Self {
            deliverables: Arena::with_capacity(512),
            fills_by_ref: HashMap::with_capacity(512),
            builds_by_ref: HashMap::with_capacity(512),
            subsets_by_ref: HashMap::with_capacity(512),
        }
    }

    fn get(&self, dr: &DeliverableRef) -> Option<&Deliverable<B>> {
        self.deliverables.get(dr.0)
    }
    fn get_mut(&mut self, dr: &DeliverableRef) -> Option<&mut Deliverable<B>> {
        self.deliverables.get_mut(dr.0)
    }

    fn insert(&mut self, di: DeliverableInner) -> DeliverableRef {
        let (fills_key, builds_key, subsets_key) = match &di {
            DeliverableInner::Build { bsr, .. } => (None, Some(*bsr), None),
            DeliverableInner::CacheFill { bsr, spec_hash: _ } => (Some(*bsr), None, None),
            DeliverableInner::Subset { subset, .. } => (None, None, Some(subset.clone())),
        };
        let dr = DeliverableRef(self.deliverables.insert(Deliverable {
            inner: di,
            state: DeliverableState::Pending,
        }));

        if let Some(fills_key) = fills_key {
            self.fills_by_ref.insert(fills_key, dr);
        }
        if let Some(builds_key) = builds_key {
            match self.builds_by_ref.get_mut(&builds_key) {
                None => {
                    self.builds_by_ref.insert(builds_key, vec![dr]);
                }
                Some(v) => v.push(dr),
            };
        }
        if let Some(subsets_key) = subsets_key {
            self.subsets_by_ref.insert(subsets_key, dr);
        }

        dr
    }

    fn get_cached(&self, bsr: &BuildSpecRef) -> Option<&DeliverableRef> {
        self.fills_by_ref.get(bsr)
    }
    fn get_built(&self, bsr: &BuildSpecRef) -> Option<&Vec<DeliverableRef>> {
        self.builds_by_ref.get(bsr)
    }
    fn get_subset(&self, si: &SubsetInput) -> Option<&DeliverableRef> {
        self.subsets_by_ref.get(si)
    }

    fn done(&self) -> bool {
        self.deliverables
            .iter()
            .all(|d| matches!(d.1.state, DeliverableState::Complete(_)))
    }
    fn runnable(&self) -> impl Iterator<Item = (DeliverableRef, &Deliverable<B>)> {
        self.deliverables
            .iter()
            .filter_map(|(idx, d)| match d.state {
                DeliverableState::Pending => {
                    // Check all the dependencies are complete
                    let deps_satisfied = match &d.inner {
                        DeliverableInner::CacheFill { .. } => true,
                        DeliverableInner::Subset { build, .. } => matches!(
                            self.deliverables.get(build.0).unwrap().state,
                            DeliverableState::Complete(_)
                        ),
                        DeliverableInner::Build { dependencies, .. } => {
                            dependencies.iter().all(|dr| {
                                matches!(
                                    self.deliverables.get(dr.0).unwrap().state,
                                    DeliverableState::Complete(_)
                                )
                            })
                        }
                    };
                    if deps_satisfied {
                        Some((DeliverableRef(idx), d))
                    } else {
                        None
                    }
                }
                _ => None,
            })
    }
}

/// A cloneable, thread-safe handle to orchestrator state.
///
/// Be careful with what you do while holding the lock you get from `lock()`
/// or `lock_for_deliverable()` - make sure you do your mutation and drop the lock.
#[derive(Debug)]
pub struct StateHandle<B: super::Backend>(Arc<Mutex<State<B>>>);

impl<B: super::Backend> Clone for StateHandle<B> {
    fn clone(&self) -> Self {
        StateHandle(self.0.clone())
    }
}

impl<B: super::Backend> StateHandle<B> {
    /// Returns true when all deliverables are complete or in an error state.
    pub async fn done(&self) -> bool {
        self.0.lock().await.s.done()
    }
    /// Returns a list of all deliverables which are ready to be executed.
    pub async fn runnables(&self) -> Vec<DeliverableRef> {
        self.0.lock().await.s.runnable().map(|(r, _d)| r).collect()
    }
    /// Takes the lock, allowing mutable access to [State].
    ///
    /// Drop the result as quickly as possible to yield the lock for other async tasks.
    pub async fn lock(&self) -> MutexGuard<'_, State<B>> {
        self.0.lock().await
    }

    /// Takes the lock, allowing mutable access to the given [Deliverable] under [State].
    ///
    /// Drop the result as quickly as possible to yield the lock for other async tasks.
    pub async fn lock_for_deliverable(
        &self,
        dr: &DeliverableRef,
    ) -> MappedMutexGuard<'_, Deliverable<B>> {
        MutexGuard::map(self.0.lock().await, |s| s.get_mut(dr).unwrap())
    }

    /// If there is only one remaining instance of [State], it unwraps the mutex and arc to
    /// return that instance.
    pub fn into_inner(self) -> Option<State<B>> {
        Arc::into_inner(self.0).map(Mutex::into_inner)
    }
}

/// The runtime state of an orchestration, notably storing [Deliverable]'s (the units of work).
#[derive(Debug)]
pub struct State<B: super::Backend> {
    pub(crate) s: StateInner<B>,
}

impl<B: super::Backend> Display for State<B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f)?;
        for (k, v) in self.s.deliverables.iter() {
            write!(f, "{}:\n\t{:?}", k.into_raw_parts().0, v)?;
        }
        Ok(())
    }
}

impl<B: super::Backend> State<B> {
    pub fn from_plan<'a, BP: BinProvider>(
        graph: &'a DepGraph,
        p: ExecPlan<'a, BP>,
    ) -> Result<Self, Error> {
        let plan: Vec<_> = p
            .into_iter()
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| Error::Plan(graph.clone(), e))?;

        let mut inner = StateInner::<B>::new();

        for phase in plan.into_iter() {
            for build in phase.builds.into_iter() {
                let d = DeliverableInner::Build {
                    bsr: build.spec,
                    spec_hash: graph.spec_hash(&build.spec),
                    full_build: build.full_build(),
                    dependencies: build
                        .with_deps
                        .into_iter()
                        .map(|d| {
                            use graph::planner::Dep;
                            match d {
                                Dep::Cached {
                                    bsr,
                                    outputs,
                                    cycle_breaker_for: _,
                                } => {
                                    let fill_deliverable =
                                        inner.get_cached(&bsr).copied().unwrap_or_else(|| {
                                            // No entry for fetching from the cache, populate it
                                            inner.insert(DeliverableInner::CacheFill {
                                                bsr,
                                                spec_hash: graph.spec_hash(&bsr),
                                            })
                                        });
                                    match outputs {
                                        None => fill_deliverable,
                                        Some(outputs) => {
                                            let subset: SubsetInput = (bsr, outputs).into();
                                            inner.get_subset(&subset).copied().unwrap_or_else(
                                                || {
                                                    // No entry for that subset, populate it
                                                    inner.insert(DeliverableInner::Subset {
                                                        subset,
                                                        spec_hash: graph.spec_hash(&bsr),
                                                        build: fill_deliverable,
                                                    })
                                                },
                                            )
                                        }
                                    }
                                }
                                Dep::Built {
                                    bsr,
                                    cycle_breaker_for: _,
                                    built_with_breakers: _,
                                    outputs,
                                } => {
                                    let build_deliverable = inner
                                        .get_built(&bsr)
                                        .map(|v| v.last().unwrap())
                                        .copied()
                                        .unwrap(); // Must reference something which is already built
                                    match outputs {
                                        None => build_deliverable,
                                        Some(outputs) => {
                                            let subset: SubsetInput = (bsr, outputs).into();
                                            inner.get_subset(&subset).copied().unwrap_or_else(
                                                || {
                                                    // No entry for that subset, populate it
                                                    let subset_hash = graph.subset_hash(&subset);
                                                    inner.insert(DeliverableInner::Subset {
                                                        subset,
                                                        spec_hash: subset_hash,
                                                        build: build_deliverable,
                                                    })
                                                },
                                            )
                                        }
                                    }
                                }
                            }
                        })
                        .collect(),
                };
                inner.insert(d);
            }
        }

        // So the planner ignores stuff that was requested which is fully provided by a cache.
        // We need to represent those as cache fill events.
        Transitives::for_toplevels(graph, graph.top_levels.to_vec(), false)
            .iter()
            .for_each(|(bsr, dep)| {
                let bsr_represented =
                    inner.builds_by_ref.contains_key(bsr) | inner.fills_by_ref.contains_key(bsr);

                match &dep.outputs {
                    // Full build
                    None => {
                        if bsr_represented {
                            // Already brought in
                        } else {
                            inner.insert(DeliverableInner::CacheFill {
                                bsr: *bsr,
                                spec_hash: graph.spec_hash(bsr),
                            });
                        }
                    }
                    // Subset needed
                    Some(outputs) => {
                        let si: SubsetInput = (*bsr, outputs.clone()).into();
                        if inner.subsets_by_ref.contains_key(&si) {
                            // Subset already represented
                        } else if bsr_represented {
                            let subset_hash = graph.subset_hash(&si);
                            inner.insert(DeliverableInner::Subset {
                                subset: si,
                                spec_hash: subset_hash,
                                build: if let Some(dr) = inner.builds_by_ref.get(bsr) {
                                    *dr.last().unwrap()
                                } else {
                                    *inner.fills_by_ref.get(bsr).unwrap()
                                },
                            });
                        } else {
                            // Emit both the cache fill and the subset
                            let dr = inner.insert(DeliverableInner::CacheFill {
                                bsr: *bsr,
                                spec_hash: graph.spec_hash(bsr),
                            });
                            let subset_hash = graph.subset_hash(&si);
                            inner.insert(DeliverableInner::Subset {
                                subset: si,
                                spec_hash: subset_hash,
                                build: dr,
                            });
                        }
                    }
                }
            });

        Ok(Self { s: inner })
    }

    /// Moves self onto the heap, returning a cloneable, thread-safe handle.
    pub fn into_handle(self) -> StateHandle<B> {
        StateHandle(Arc::new(Mutex::new(self)))
    }

    /// Resolves the given [DeliverableRef] into a &[Deliverable].
    pub fn get(&self, dr: &DeliverableRef) -> Option<&Deliverable<B>> {
        self.s.get(dr)
    }
    /// Mutably resolves the given [DeliverableRef] into a &mut [Deliverable].
    pub fn get_mut(&mut self, dr: &DeliverableRef) -> Option<&mut Deliverable<B>> {
        self.s.get_mut(dr)
    }

    /// Returns true when all deliverables are complete or in an error state.
    pub fn done(&self) -> bool {
        self.s.done()
    }
    /// Returns an iterator of all deliverables which are ready to run immediately.
    pub fn runnable(&self) -> impl Iterator<Item = (DeliverableRef, &Deliverable<B>)> {
        self.s.runnable()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use decode::Layer;
    use indoc::indoc;

    #[test]
    fn from_plan() {
        let layer = Layer::new_for_test(
            indoc! {
                "
                let {BuildSpec, HostPath, OutputLib, ..} = import \"minimal.ncl\" in

                let no_deps_spec = {
        			name = \"no deps\",
        			inputs = [],
        			cmd = \"\",
        		} | BuildSpec
        		in
                let rec self_ref = {
        			name = \"self ref\",
        			inputs = [self_ref],
        			cmd = \"\",
                    replace_on_cycle = {
                        name = \"breaker\",
                        inputs = [],
                        cmd = \"\",
                    } | BuildSpec,
        		} | BuildSpec
        		in

        		{
        			name = \"top\",
        			inputs = [no_deps_spec],
        			runtime_deps = [self_ref],
        			cmd = \"\",
        		} | BuildSpec
        		"
            }
            .to_string(),
        );
        // So we can see the actual error when parsing fails
        layer.as_ref().err().into_iter().for_each(|e| {
            e.report_to_stderr();
            panic!("spec parsing failed");
        });
        let layer = layer.unwrap();

        let dp = DepGraph::new().ingest(layer).unwrap();
        let planner: ExecPlan<()> = ExecPlan::new(&dp);
        let state = State::<()>::from_plan(&dp, planner).unwrap();

        assert_eq!(
            state
                .s
                .deliverables
                .iter()
                .map(|(_dr, d)| d.inner.clone())
                .collect::<Vec<_>>(),
            vec![
                DeliverableInner::Build {
                    bsr: *dp.by_name("no deps").unwrap(),
                    spec_hash: dp.spec_hash(dp.by_name("no deps").unwrap()),
                    full_build: true,
                    dependencies: vec![],
                },
                DeliverableInner::Build {
                    bsr: *dp.by_name("breaker").unwrap(),
                    spec_hash: dp.spec_hash(dp.by_name("breaker").unwrap()),
                    full_build: true,
                    dependencies: vec![],
                },
                DeliverableInner::Build {
                    bsr: *dp.by_name("top").unwrap(),
                    spec_hash: dp.spec_hash(dp.by_name("top").unwrap()),
                    full_build: false,
                    dependencies: vec![
                        *state
                            .s
                            .get_built(dp.by_name("no deps").unwrap())
                            .unwrap()
                            .first()
                            .unwrap(),
                        *state
                            .s
                            .get_built(dp.by_name("breaker").unwrap())
                            .unwrap()
                            .first()
                            .unwrap(),
                    ],
                },
                DeliverableInner::Build {
                    bsr: *dp.by_name("self ref").unwrap(),
                    spec_hash: dp.spec_hash(dp.by_name("self ref").unwrap()),
                    full_build: false,
                    dependencies: vec![
                        *state
                            .s
                            .get_built(dp.by_name("breaker").unwrap())
                            .unwrap()
                            .first()
                            .unwrap(),
                    ],
                },
                DeliverableInner::Build {
                    bsr: *dp.by_name("top").unwrap(),
                    spec_hash: dp.spec_hash(dp.by_name("top").unwrap()),
                    full_build: true,
                    dependencies: vec![
                        *state
                            .s
                            .get_built(dp.by_name("no deps").unwrap())
                            .unwrap()
                            .first()
                            .unwrap(),
                        *state
                            .s
                            .get_built(dp.by_name("self ref").unwrap())
                            .unwrap()
                            .first()
                            .unwrap(),
                    ],
                },
                DeliverableInner::Build {
                    bsr: *dp.by_name("self ref").unwrap(),
                    spec_hash: dp.spec_hash(dp.by_name("self ref").unwrap()),
                    full_build: true,
                    dependencies: vec![
                        *state
                            .s
                            .get_built(dp.by_name("self ref").unwrap())
                            .unwrap()
                            .first()
                            .unwrap(),
                    ],
                },
            ],
        );
    }

    #[test]
    fn runnable() {
        let layer = Layer::new_for_test(
            indoc! {
                "
                let {BuildSpec, HostPath, OutputLib, ..} = import \"minimal.ncl\" in

                let no_deps_spec = {
        			name = \"no deps\",
        			inputs = [],
        			cmd = \"\",
        		} | BuildSpec
        		in
        		{
        			name = \"top\",
        			inputs = [no_deps_spec],
        			runtime_deps = [],
        			cmd = \"\",
        		} | BuildSpec
        		"
            }
            .to_string(),
        );
        // So we can see the actual error when parsing fails
        layer.as_ref().err().into_iter().for_each(|e| {
            e.report_to_stderr();
            panic!("spec parsing failed");
        });
        let layer = layer.unwrap();

        let dp = DepGraph::new().ingest(layer).unwrap();
        let planner: ExecPlan<()> = ExecPlan::new(&dp);
        let mut state = State::<()>::from_plan(&dp, planner).unwrap();

        // runnable() should yield the build with no deps, but once
        // thats done, it can yield the one that depends on that one.
        assert_eq!(
            state.runnable().map(|r| r.0).collect::<Vec<_>>(),
            vec![
                *state
                    .s
                    .get_built(dp.by_name("no deps").unwrap())
                    .unwrap()
                    .first()
                    .unwrap(),
            ]
        );
        state
            .s
            .get_mut(
                state
                    .s
                    .get_built(dp.by_name("no deps").unwrap())
                    .cloned()
                    .unwrap()
                    .first()
                    .unwrap(),
            )
            .unwrap()
            .state = DeliverableState::Complete(());
        assert_eq!(
            state.runnable().map(|r| r.0).collect::<Vec<_>>(),
            vec![
                *state
                    .s
                    .get_built(dp.by_name("top").unwrap())
                    .unwrap()
                    .first()
                    .unwrap(),
            ]
        );

        // Make sure done() works while we are at it.
        state
            .s
            .get_mut(
                state
                    .s
                    .get_built(dp.by_name("top").unwrap())
                    .cloned()
                    .unwrap()
                    .first()
                    .unwrap(),
            )
            .unwrap()
            .state = DeliverableState::Complete(());
        assert!(state.done());
    }
}
