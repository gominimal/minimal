use crate::{BuildSpecInput, BuildSpecRef, DepGraph, SubsetInput};
use nickel_lang_core::term::IndexMap;
use std::collections::HashMap;

/// The status of a build spec / dependency at some moment during planning.
#[derive(Debug, Default, Clone, Ord, PartialOrd, PartialEq, Eq)]
enum BuildState {
    /// The dep has not been built - not available.
    #[default]
    NotBuilt,
    /// The dep has been built using cycle breakers - its available for use but should be
    /// rebuilt.
    BuiltUsingBreakers,
    /// The dep has been built without cycle breakers.
    FullyBuilt,
    /// The dep was just fetched.
    Fetched,
}

impl BuildState {
    fn is_built(&self) -> bool {
        use BuildState::*;
        match self {
            NotBuilt => false,
            BuiltUsingBreakers | FullyBuilt | Fetched => true,
        }
    }
    fn is_fully_built(&self) -> bool {
        use BuildState::*;
        match self {
            NotBuilt | BuiltUsingBreakers => false,
            FullyBuilt | Fetched => true,
        }
    }
}

/// The internal state of a build spec / dependency at some moment during planning.
#[derive(Debug, Default, Clone, PartialEq)]
struct BuildInfo {
    state: BuildState,

    /// The build-spec this build was brought in to break the cycle of,
    /// if any.
    cycle_breaker_of: Option<BuildSpecRef>,

    /// A cycle-breaker declared on this build-spec, if any
    cycle_breaker: Option<BuildSpecRef>,
}

impl BuildInfo {
    /// combines build information into a single instance of [BuildInfo].
    fn union(&mut self, other: Self) {
        if other.state > self.state {
            self.state = other.state;
        }
        match (self.cycle_breaker_of, other.cycle_breaker_of) {
            (None, None) => {}
            (Some(_), None) => {}
            (None, Some(cbo)) => {
                self.cycle_breaker_of = Some(cbo);
            }
            (Some(cbo1), Some(cbo2)) => {
                if cbo1 != cbo2 {
                    panic!(
                        "union with differing cycle_breaker_of: {:?}, {:?}",
                        cbo1, cbo2
                    );
                }
            }
        }
        match (self.cycle_breaker, other.cycle_breaker) {
            (None, None) => {}
            (Some(_), None) => {}
            (None, Some(cbo)) => {
                self.cycle_breaker = Some(cbo);
            }
            (Some(cbo1), Some(cbo2)) => {
                if cbo1 != cbo2 {
                    panic!("union with differing cycle_breaker: {:?}, {:?}", cbo1, cbo2);
                }
            }
        }
    }

    fn default_fetched() -> Self {
        Self {
            state: BuildState::Fetched,
            ..Default::default()
        }
    }
    fn default_not_built() -> Self {
        Self {
            state: BuildState::NotBuilt,
            ..Default::default()
        }
    }
}

/// Types which can tell the planner what build-specs are built & available.
pub trait BinProvider: std::fmt::Debug {
    fn exists(&self, bsr: &BuildSpecRef) -> bool;
}

impl BinProvider for () {
    fn exists(&self, _bsr: &BuildSpecRef) -> bool {
        false
    }
}

impl<BP1: BinProvider, BP2: BinProvider> BinProvider for (BP1, BP2) {
    fn exists(&self, bsr: &BuildSpecRef) -> bool {
        self.0.exists(bsr) || self.1.exists(bsr)
    }
}

impl<BP1: BinProvider, BP2: BinProvider, BP3: BinProvider> BinProvider for (BP1, BP2, BP3) {
    fn exists(&self, bsr: &BuildSpecRef) -> bool {
        self.0.exists(bsr) || self.1.exists(bsr) || self.2.exists(bsr)
    }
}

/// Describes the ordered set of builds required to materialize some top-level build specs.
///
/// Users should iterate this plan to get the ordering that build specs must be built.
/// When multiple build specs are yielded in one iteration, these builds may be executed in parallel.
#[derive(Debug)]
pub struct ExecPlan<'a, BP: BinProvider> {
    graph: &'a DepGraph,
    bin_provider: BP,

    // the apex of the build graph - the set of build-specs we want compiled.
    toplevels: Vec<BuildSpecRef>,

    // all build-specs and their state which are relevant to this execution plan.
    // All transitive dependencies of toplevel, along with any cycle-breakers that were included,
    // should be enumerated here.
    builds: IndexMap<BuildSpecRef, BuildInfo>,
}

/// ensures the given build-spec is represented in the builds map, including all necessary transitive
/// dependencies.
fn make_reachable<BP: BinProvider>(
    bsr: &BuildSpecRef,
    graph: &DepGraph,
    bin_provider: &mut BP,
    builds: &mut IndexMap<BuildSpecRef, BuildInfo>,
) -> Result<(), ()> {
    let mut upsert = |bsr: &BuildSpecRef, info: BuildInfo| -> bool {
        if let Some(stored_info) = builds.get_mut(bsr) {
            stored_info.union(info);
            true
        } else {
            builds.insert(*bsr, info);
            false
        }
    };

    let build = graph.get(bsr).unwrap();
    if bin_provider.exists(bsr) {
        let seen_before = upsert(
            bsr,
            BuildInfo {
                cycle_breaker: build.replace_on_cycle.to_owned(),
                ..BuildInfo::default_fetched()
            },
        );
        // We have access to a build of this build-spec, so all we need
        // is the runtime deps.
        if !seen_before {
            for runtime_dep in &build.runtime_deps {
                make_reachable(runtime_dep.bsr(), graph, bin_provider, builds)?;
            }
        }
        Ok(())
    } else {
        let seen_before = upsert(
            bsr,
            BuildInfo {
                cycle_breaker: build.replace_on_cycle.to_owned(),
                ..BuildInfo::default_not_built()
            },
        );
        // We need to build this build-spec. Bring in not only its runtime deps,
        // but its inputs as well (so we can do da build).
        if !seen_before {
            for bsr in build
                .inputs
                .iter()
                .filter_map(|i| match i {
                    BuildSpecInput::Build(bsr) => Some(bsr),
                    _ => None,
                })
                .chain(build.runtime_deps.iter().map(|dep| dep.bsr()))
            {
                make_reachable(bsr, graph, bin_provider, builds)?;
            }
        }
        Ok(())
    }
}

impl<'a> ExecPlan<'a, ()> {
    /// Initializes a new execution plan to materialize the top levels of the given dependency graph.
    #[tracing::instrument]
    pub fn new(dep_graph: &'a DepGraph) -> Self {
        ExecPlan::with_toplevels((), dep_graph, &dep_graph.top_levels)
    }
}

impl<'a, BP: BinProvider> ExecPlan<'a, BP> {
    /// Initializes a new execution plan to materialize the top levels of the given dependency graph,
    /// leveraging the provided bin provider to know which dependencies are already available.
    #[tracing::instrument]
    pub fn new_with_bin_provider(dep_graph: &'a DepGraph, bin_provider: BP) -> ExecPlan<'a, BP> {
        ExecPlan::with_toplevels(bin_provider, dep_graph, &dep_graph.top_levels)
    }

    /// Initializes a new execution plan to materialize the specified deps within the given dependency graph.
    pub fn with_toplevels(
        mut bin_provider: BP,
        graph: &'a DepGraph,
        toplevels: &[BuildSpecRef],
    ) -> ExecPlan<'a, BP> {
        let mut toplevels = toplevels.to_owned();
        toplevels.sort();
        toplevels.dedup();

        let mut builds: IndexMap<_, _> = IndexMap::with_capacity(4096);
        for bsr in toplevels.iter() {
            make_reachable(bsr, graph, &mut bin_provider, &mut builds).unwrap();
        }

        Self {
            bin_provider,
            graph,
            toplevels,
            builds,
        }
    }

    /// Returns true if the given dependency should be considered built in an earlier phase.
    fn is_built(&self, dependency: &BuildSpecRef, cycle_breakers_allowed: bool) -> bool {
        if self.bin_provider.exists(dependency) {
            return true;
        }

        match self.builds.get(dependency) {
            None => {
                // queried dependency was not in .builds, this can happen for cycle breakers
                // which have not been added in to be reachable. Obviously not built in that case
                false
            }
            Some(info) => {
                if info.state.is_built() {
                    return true;
                }

                if cycle_breakers_allowed {
                    info.cycle_breaker
                        .as_ref()
                        .map(|bsr| self.is_built(bsr, cycle_breakers_allowed))
                        .unwrap_or(false)
                } else {
                    false
                }
            }
        }
    }

    /// Returns true when the build plan is complete.
    pub fn finished(&self) -> bool {
        // fast path: If the top level itself isnt satisfied, then we are definitely not done.
        let tops_sat = self.toplevels.iter().all(|bsr| {
            matches!(
                self.builds.get(bsr).unwrap().state,
                BuildState::FullyBuilt | BuildState::Fetched
            )
        });
        if !tops_sat {
            return false;
        }

        // If all the top levels are satisfied, we could still have some work to do if a transitive
        // dep isn't satisfied.
        fn check_runtime_deps_recursive(
            bsr: &BuildSpecRef,
            graph: &DepGraph,
            builds: &IndexMap<BuildSpecRef, BuildInfo>,
            seen: &mut HashMap<BuildSpecRef, ()>,
        ) -> bool {
            let self_satisfied = matches!(
                builds.get(bsr).unwrap().state,
                BuildState::FullyBuilt | BuildState::Fetched
            );

            // If we've already recursed, return early
            if seen.contains_key(bsr) {
                return self_satisfied;
            }
            seen.insert(*bsr, ());

            let build = graph.get(bsr).unwrap();
            build
                .runtime_deps
                .iter()
                .map(|dep| dep.bsr())
                .all(|bsr| check_runtime_deps_recursive(bsr, graph, builds, seen))
                && self_satisfied
        }

        let mut seen: HashMap<BuildSpecRef, ()> = HashMap::with_capacity(5 * self.toplevels.len());
        self.toplevels
            .iter()
            .all(|bsr| check_runtime_deps_recursive(bsr, self.graph, &self.builds, &mut seen))
    }

    fn find_cycles(&mut self) -> Vec<Vec<BuildSpecRef>> {
        let mut cycles: Vec<Vec<BuildSpecRef>> = Vec::with_capacity(32);

        let mut path: Vec<BuildSpecRef> = Vec::with_capacity(self.builds.len() + 256);
        let mut seen: HashMap<BuildSpecRef, ()> = HashMap::with_capacity(self.builds.len());

        for cursor in self.builds.keys() {
            if self.is_built(cursor, false) {
                continue;
            }
            seen.clear();

            path.clear();
            path.push(*cursor);
            if let Some(paths) = Self::dfs_iter(self.graph, cursor, &mut path, &mut seen) {
                cycles.extend(paths);
            }
        }

        cycles.sort();
        cycles.dedup();
        cycles
    }

    fn dfs_iter(
        g: &DepGraph,
        cursor: &BuildSpecRef,
        path: &mut Vec<BuildSpecRef>,
        seen: &mut HashMap<BuildSpecRef, ()>,
    ) -> Option<Vec<Vec<BuildSpecRef>>> {
        if seen.contains_key(cursor) {
            return None;
        }
        let bs = g.get(cursor).unwrap();
        // println!(
        //     "dfs_iter(): {}, {:?}",
        //     bs.name,
        //     path.iter()
        //         .map(|bsr| g.get(bsr).unwrap().name.clone())
        //         .collect::<Vec<_>>()
        // );

        let mut out: Option<Vec<Vec<BuildSpecRef>>> = None;

        // Look at a node which is a dependency of cursor.
        let mut process = |bsr,
                           seen: &mut HashMap<BuildSpecRef, ()>,
                           out: &mut Option<Vec<Vec<BuildSpecRef>>>| {
            // println!("-process: {}", g.get(bsr).unwrap().name.clone());

            // We've seen this build-spec before, therefore theres a cycle in our path.
            if path.contains(bsr) {
                // Trim off path so its just representative of the cycle (and not the path to get to the cycle)
                let mut out_path = path.clone();
                let cycle_start_idx = out_path.iter().position(|x| x == bsr).unwrap();
                out_path.drain(..cycle_start_idx);
                match out {
                    None => {
                        *out = Some(vec![out_path]);
                    }
                    Some(l) => {
                        l.push(out_path);
                    }
                };
            } else {
                let bsr = *bsr;
                path.push(bsr);
                let paths = Self::dfs_iter(g, &bsr, path, seen);
                path.pop();
                if let Some(new_paths) = paths {
                    match out {
                        None => {
                            *out = Some(new_paths);
                        }
                        Some(out) => {
                            out.extend(new_paths);
                        }
                    }
                }
            }
        };

        // Search through all inputs and runtime deps.
        for input in bs.inputs.iter() {
            use BuildSpecInput::*;
            match input {
                Build(bsr) | Subset(SubsetInput { from: bsr, .. }) => {
                    process(bsr, seen, &mut out);
                }
                Source(_) | HostPath(_) | Local(_) | Prebuilt(_, _) => {}
            }
        }
        for dep in bs.runtime_deps.iter() {
            process(dep.bsr(), seen, &mut out);
        }

        seen.insert(*cursor, ());
        out
    }
}

/// Errors that can occur when planning an execution.
#[derive(Debug, Clone, PartialEq)]
pub enum PlanErr {
    Cycles(Vec<Vec<BuildSpecRef>>),
}

/// The set of build-specs which can be built in parallel with all deps satisfied by
/// the planners' associated [BinProvider], or built in a preceeding phase.
#[derive(Debug, Clone, PartialEq)]
pub struct BuildPhase {
    // (bsr, full_build)
    pub builds: Vec<(BuildSpecRef, bool)>,
}

impl<'a, BP: BinProvider> Iterator for ExecPlan<'a, BP> {
    type Item = Result<BuildPhase, PlanErr>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.finished() {
            return None;
        }
        // println!("iteration:");
        // for (candidate, info) in self.builds.iter() {
        //     println!("\t{}: {:?}", self.graph.get(candidate).unwrap().name, info);
        // }

        // (bsr, used_breakers)
        let mut built_this_phase: HashMap<BuildSpecRef, bool> = HashMap::new();
        // (bsr, full_build)
        let mut met: Vec<(BuildSpecRef, bool)> = Vec::new();

        // Iterate all reachable builds which have not been fully built.
        for (candidate, info) in self.builds.iter().filter_map(|(candidate, info)| {
            if info.state.is_fully_built() {
                None // Ignore fully-built or fetched
            } else {
                Some((candidate, info))
            }
        }) {
            // This build-spec is either not built at all, or built using cycle breakers.
            let cycle_breakers_allowed = info.state != BuildState::BuiltUsingBreakers;
            let build = self.graph.get(candidate).unwrap();

            // no need to recurse as if the top-level inputs/runtime-deps are resolved, that implies
            // their dependents are resolved.
            let (can_build_full, can_build_breakers) = build
                .inputs
                .iter()
                .filter_map(|i| match i {
                    BuildSpecInput::Build(bsr) => Some(bsr),
                    _ => None,
                })
                .chain(build.runtime_deps.iter().map(|dep| dep.bsr()))
                .fold((true, true), |acc, dep_bsr| {
                    (
                        acc.0 & self.is_built(dep_bsr, false),
                        acc.1 & self.is_built(dep_bsr, true),
                    )
                });

            // Prefer a full build if all the deps have been fully built. If deps are satisfied
            // by cycle breakers, we can do a cycle-breaker build.
            match (can_build_full, can_build_breakers, cycle_breakers_allowed) {
                (true, _, _) => {
                    built_this_phase.insert(*candidate, false);
                    met.push((*candidate, true));
                }
                (false, true, true) => {
                    built_this_phase.insert(*candidate, true);
                    met.push((*candidate, false));
                }
                _ => {}
            }
        }

        if met.is_empty() {
            let cycles = self.find_cycles().into_iter().collect::<Vec<_>>();
            // println!(
            //     "cycle(s) detected! {:?}",
            //     cycles
            //         .iter()
            //         .map(|c| {
            //             c.into_iter()
            //                 .map(|bsr| self.graph.get(&bsr).unwrap().name.clone())
            //                 .collect::<Vec<_>>()
            //         })
            //         .collect::<Vec<_>>()
            // );

            let mut added_cycle_breaker = false;
            for path in &cycles {
                let (first, last) = (path.first().unwrap(), path.last().unwrap());
                for cycle in &[first, last] {
                    if let Some(cycle_breaker) = self.graph.get(cycle).unwrap().replace_on_cycle {
                        if !self.builds.contains_key(&cycle_breaker) {
                            // We found a new cycle breaker we haven't brought into the fray yet.
                            make_reachable(
                                &cycle_breaker,
                                self.graph,
                                &mut self.bin_provider,
                                &mut self.builds,
                            )
                            .unwrap();
                            self.builds
                                .get_mut(&cycle_breaker)
                                .unwrap()
                                .cycle_breaker_of = Some(**cycle);
                            added_cycle_breaker = true;
                        }
                    }
                }
            }
            if !added_cycle_breaker {
                return Some(Err(PlanErr::Cycles(cycles)));
            } else {
                return self.next();
            }
        }

        let out = BuildPhase { builds: met };
        for (bsr, used_breakers) in built_this_phase.into_iter() {
            self.builds.get_mut(&bsr).unwrap().state = if used_breakers {
                BuildState::BuiltUsingBreakers
            } else {
                BuildState::FullyBuilt
            };
        }
        Some(Ok(out))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SpecReader, SpecReaderOptions};
    use indoc::indoc;

    #[test]
    fn inputs_and_runtime_deps_reachable_when_not_built() {
        let sr = SpecReader::new(
            indoc! {
                "
                let {BuildSpec, HostPath, OutputLib, ..} = import \"minimal.ncl\" in

                let no_deps_spec = {
        			name = \"no deps\",
        			inputs = [],
        			cmd = \"\",
        		} | BuildSpec
        		in
                let no_deps_spec2 = {
        			name = \"no deps 2\",
        			inputs = [],
        			cmd = \"\",
        		} | BuildSpec
        		in

        		{
        			name = \"top\",
        			inputs = [no_deps_spec],
        			runtime_deps = [no_deps_spec2],
        			cmd = \"\",
        		} | BuildSpec
        		"
            }
            .to_string(),
            &SpecReaderOptions::for_test(),
        );
        // So we can see the actual error when parsing fails
        sr.as_ref().err().into_iter().for_each(|e| {
            e.report_to_stderr();
            panic!("spec parsing failed");
        });
        let sr = sr.unwrap();

        let dp = DepGraph::new(sr)
            .map_err(|e| {
                e.report_to_stderr();
                Err::<DepGraph, ()>(())
            })
            .unwrap();
        let planner: ExecPlan<()> = ExecPlan::new(&dp);

        assert_eq!(
            planner
                .builds
                .into_iter()
                .collect::<Vec<(BuildSpecRef, BuildInfo)>>(),
            vec![
                (
                    dp.by_name("top").next().unwrap(),
                    BuildInfo::default_not_built()
                ),
                (
                    dp.by_name("no deps").next().unwrap(),
                    BuildInfo::default_not_built()
                ),
                (
                    dp.by_name("no deps 2").next().unwrap(),
                    BuildInfo::default_not_built()
                ),
            ],
        );
    }

    #[test]
    fn input_chain() {
        let sr = SpecReader::new(
            indoc! {
                "
                let {BuildSpec, ..} = import \"minimal.ncl\" in

                let rec nested_dep = {
                    name = \"nested dep\",
                    inputs = [],
                    cmd = \"\",
                } | BuildSpec,
                dep = {
                    name = \"dep\",
                    inputs = [nested_dep],
                    cmd = \"\",
                } | BuildSpec,
                top = {
                    name = \"top\",
                    inputs = [dep],
                    cmd = \"\",
                } | BuildSpec,
                in
                top
                "
            }
            .to_string(),
            &SpecReaderOptions::for_test(),
        );
        // So we can see the actual error when parsing fails
        sr.as_ref().err().into_iter().for_each(|e| {
            e.report_to_stderr();
            panic!("spec parsing failed");
        });
        let sr = sr.unwrap();

        let dp = DepGraph::new(sr)
            .map_err(|e| {
                e.report_to_stderr();
                Err::<DepGraph, ()>(())
            })
            .unwrap();
        let planner: ExecPlan<()> = ExecPlan::new(&dp);

        // true = all builds without cycle-breakers
        assert_eq!(
            planner.collect::<Result<Vec<_>, _>>().unwrap(),
            vec![
                BuildPhase {
                    builds: vec![(dp.by_name("nested dep").next().unwrap(), true)]
                },
                BuildPhase {
                    builds: vec![(dp.by_name("dep").next().unwrap(), true)]
                },
                BuildPhase {
                    builds: vec![(dp.by_name("top").next().unwrap(), true)]
                },
            ],
        );
    }

    #[test]
    fn find_cycles_easy() {
        let sr = SpecReader::new(
            indoc! {
                "
                let {BuildSpec, ..} = import \"minimal.ncl\" in

                let rec b1 = {
                    name = \"build 1\",
                    inputs = [b2],
                    cmd = \"\",
                } | BuildSpec,
                b2 = {
                    name = \"build 2\",
                    inputs = [b1],
                    cmd = \"\",
                } | BuildSpec,
                in
                b1
                "
            }
            .to_string(),
            &SpecReaderOptions::for_test(),
        );
        // So we can see the actual error when parsing fails
        sr.as_ref().err().into_iter().for_each(|e| {
            e.report_to_stderr();
            panic!("spec parsing failed");
        });
        let sr = sr.unwrap();

        let dp = DepGraph::new(sr)
            .map_err(|e| {
                e.report_to_stderr();
                Err::<DepGraph, ()>(())
            })
            .unwrap();
        let mut cycles = ExecPlan::new(&dp)
            .find_cycles()
            .into_iter()
            .map(|c| {
                c.into_iter()
                    .map(|bsr| dp.get(&bsr).unwrap().name.clone())
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        cycles.sort();

        assert_eq!(
            cycles,
            vec![vec!["build 1", "build 2"], vec!["build 2", "build 1"]],
        );
    }

    #[test]
    fn cycle_breaking_easy() {
        let sr = SpecReader::new(
            indoc! {
                "
                let {BuildSpec, ..} = import \"minimal.ncl\" in

                let rec self_ref = {
                    name = \"self ref\",
                    inputs = [self_ref],
                    cmd = \"\",
                    replace_on_cycle = {
                        name = \"breaker\",
                        inputs = [breaker_dep],
                        cmd = \"\",
                    } | BuildSpec,
                } | BuildSpec,
                breaker_dep = {
                    name = \"breaker dep\",
                    inputs = [],
                    cmd = \"\",
                } | BuildSpec,
                top = {
                    name = \"top\",
                    inputs = [self_ref],
                    cmd = \"\",
                } | BuildSpec,
                in
                top
                "
            }
            .to_string(),
            &SpecReaderOptions::for_test(),
        );
        // So we can see the actual error when parsing fails
        sr.as_ref().err().into_iter().for_each(|e| {
            e.report_to_stderr();
            panic!("spec parsing failed");
        });
        let sr = sr.unwrap();

        let dp = DepGraph::new(sr)
            .map_err(|e| {
                e.report_to_stderr();
                Err::<DepGraph, ()>(())
            })
            .unwrap();
        let plan: Vec<BuildPhase> = ExecPlan::new(&dp).collect::<Result<_, _>>().unwrap();

        assert_eq!(
            plan,
            vec![
                BuildPhase {
                    builds: vec![(dp.by_name("breaker dep").next().unwrap(), true)]
                },
                BuildPhase {
                    builds: vec![(dp.by_name("breaker").next().unwrap(), true)]
                },
                BuildPhase {
                    builds: vec![
                        (dp.by_name("top").next().unwrap(), false),
                        (dp.by_name("self ref").next().unwrap(), false),
                    ]
                },
                BuildPhase {
                    builds: vec![
                        (dp.by_name("top").next().unwrap(), true),
                        (dp.by_name("self ref").next().unwrap(), true),
                    ]
                },
            ],
        );
    }

    #[derive(Debug)]
    struct BinProviderFake(HashMap<BuildSpecRef, ()>);

    impl BinProvider for BinProviderFake {
        fn exists(&self, bsr: &BuildSpecRef) -> bool {
            self.0.contains_key(bsr)
        }
    }

    impl From<HashMap<BuildSpecRef, ()>> for BinProviderFake {
        fn from(hm: HashMap<BuildSpecRef, ()>) -> Self {
            BinProviderFake(hm)
        }
    }

    #[test]
    fn bin_provider_elludes_present() {
        let sr = SpecReader::new(
            indoc! {
                "
                let {BuildSpec, ..} = import \"minimal.ncl\" in

                let rec nested_dep = {
                    name = \"nested dep\",
                    inputs = [],
                    cmd = \"\",
                } | BuildSpec,
                dep = {
                    name = \"dep\",
                    inputs = [nested_dep],
                    cmd = \"\",
                } | BuildSpec,
                top = {
                    name = \"top\",
                    inputs = [dep],
                    cmd = \"\",
                } | BuildSpec,
                in
                top
                "
            }
            .to_string(),
            &SpecReaderOptions::for_test(),
        );
        // So we can see the actual error when parsing fails
        sr.as_ref().err().into_iter().for_each(|e| {
            e.report_to_stderr();
            panic!("spec parsing failed");
        });
        let sr = sr.unwrap();

        let dp = DepGraph::new(sr)
            .map_err(|e| {
                e.report_to_stderr();
                Err::<DepGraph, ()>(())
            })
            .unwrap();

        let bin_provider: BinProviderFake =
            HashMap::from([(dp.by_name("nested dep").next().unwrap(), ())]).into();

        let planner: ExecPlan<BinProviderFake> = ExecPlan::new_with_bin_provider(&dp, bin_provider);

        // BinProvider declares "nested dep" exists, so it shouldn't be part of the build plan
        // true = all builds without cycle-breakers
        assert_eq!(
            planner.collect::<Result<Vec<_>, _>>().unwrap(),
            vec![
                BuildPhase {
                    builds: vec![(dp.by_name("dep").next().unwrap(), true)]
                },
                BuildPhase {
                    builds: vec![(dp.by_name("top").next().unwrap(), true)]
                },
            ],
        );
    }

    #[test]
    fn bin_provider_not_ellude_runtime_dep() {
        let sr = SpecReader::new(
            indoc! {
                "
                let {BuildSpec, ..} = import \"minimal.ncl\" in

                let rec nested_deeper_dep = {
                    name = \"nested deeper dep\",
                    inputs = [],
                    cmd = \"\",
                } | BuildSpec,
                nested_dep = {
                    name = \"nested dep\",
                    inputs = [],
                    runtime_deps = [nested_deeper_dep],
                    cmd = \"\",
                } | BuildSpec,
                dep = {
                    name = \"dep\",
                    inputs = [],
                    runtime_deps = [nested_dep],
                    cmd = \"\",
                } | BuildSpec,
                top = {
                    name = \"top\",
                    inputs = [],
                    runtime_deps = [dep],
                    cmd = \"\",
                } | BuildSpec,
                in
                top
                "
            }
            .to_string(),
            &SpecReaderOptions::for_test(),
        );
        // So we can see the actual error when parsing fails
        sr.as_ref().err().into_iter().for_each(|e| {
            e.report_to_stderr();
            panic!("spec parsing failed");
        });
        let sr = sr.unwrap();

        let dp = DepGraph::new(sr)
            .map_err(|e| {
                e.report_to_stderr();
                Err::<DepGraph, ()>(())
            })
            .unwrap();

        let bin_provider: BinProviderFake = HashMap::from([
            (dp.by_name("top").next().unwrap(), ()),
            (dp.by_name("nested dep").next().unwrap(), ()),
        ])
        .into();

        let planner: ExecPlan<BinProviderFake> = ExecPlan::new_with_bin_provider(&dp, bin_provider);

        // BinProvider declares "top" exists, but its runtime dep "dep" is missing so should be built,
        // as well as the transitive runtime dep "nested deeper dep". Theres no interdependency between
        // those two so they should be built in the same cycle.
        // true = all builds without cycle-breakers
        assert_eq!(
            planner.collect::<Result<Vec<_>, _>>().unwrap(),
            vec![BuildPhase {
                builds: vec![
                    (dp.by_name("dep").next().unwrap(), true),
                    (dp.by_name("nested deeper dep").next().unwrap(), true),
                ]
            },],
        );
    }
}
