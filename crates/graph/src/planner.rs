use crate::{BuildSpecInput, BuildSpecRef, DepGraph};
use nickel_lang_core::term::IndexMap;
use std::collections::HashMap;

/// Describes the ordered set of builds required to materialize some top-level build spec.
///
/// Users should iterate this plan to get the ordering that build specs must be built.
/// When multiple build specs are yielded in one iteration, these builds may be executed in parallel.
pub struct ExecPlan<'a> {
    dep_graph: &'a DepGraph,

    // the apex of the build graph - the ultimate build-spec we want compiled.
    toplevels: Vec<BuildSpecRef>,

    // built tracks the build-specs which were compiled in a previous phase.
    built: HashMap<BuildSpecRef, ()>,

    // emitted_toplevel tracks if the final phase for building the toplevel was emitted.
    emitted_toplevel: bool,

    // all build-specs which are transitive dependencies of toplevel.
    reachable: Vec<BuildSpecRef>,

    // additional build-specs made reachable to break cycles in the dependency graph.
    cycle_breakers: IndexMap<BuildSpecRef, ()>,

    // lets a build-spec consider one of its dependencies met if any of the build-specs
    // in value are built.
    //
    // key: (build-spec in question, dependency in question)
    // value: [build-spec which if built allows the dependency to be considered built]
    met_dependency_overrides: IndexMap<(BuildSpecRef, BuildSpecRef), Vec<BuildSpecRef>>,
}

impl<'a> ExecPlan<'a> {
    pub fn new(dep_graph: &'a DepGraph) -> Self {
        ExecPlan::with_toplevels(dep_graph, &dep_graph.top_levels)
    }

    pub fn with_toplevels(dep_graph: &'a DepGraph, toplevels: &[BuildSpecRef]) -> Self {
        let built = HashMap::with_capacity(dep_graph.len());
        let mut reachable: Vec<_> = toplevels
            .iter()
            .flat_map(|toplevel| dep_graph.transitive_specs_of(toplevel))
            .collect();
        reachable.sort();
        reachable.dedup();

        let mut toplevels = toplevels.to_owned();
        toplevels.sort();
        toplevels.dedup();

        Self {
            dep_graph,
            toplevels,
            built,
            reachable,
            emitted_toplevel: false,
            cycle_breakers: IndexMap::with_capacity(32),
            met_dependency_overrides: IndexMap::with_capacity(32),
        }
    }

    /// Returns true if the given dependency should be considered built in an earlier phase.
    ///
    /// Takes into account overrides.
    fn is_built(&self, dependency: BuildSpecRef, used_by: Option<BuildSpecRef>) -> bool {
        self.built.contains_key(&dependency)
            || used_by
                .map(|used_by| {
                    if let Some(overrides) =
                        self.met_dependency_overrides.get(&(used_by, dependency))
                    {
                        overrides.iter().any(|x| self.built.contains_key(x))
                    } else {
                        false
                    }
                })
                .unwrap_or(false)
    }

    fn find_cycles(&mut self) -> Vec<Vec<BuildSpecRef>> {
        let mut cycles: Vec<Vec<BuildSpecRef>> = Vec::with_capacity(32);

        let mut path: Vec<BuildSpecRef> = Vec::with_capacity(self.reachable.len() + 256);
        let mut seen: HashMap<BuildSpecRef, ()> = HashMap::with_capacity(self.reachable.len());

        for cursor in self.reachable.iter().chain(
            self.reachable
                .iter()
                .filter_map(|bsr| self.dep_graph.get(bsr).unwrap().replace_on_cycle.as_ref()),
        ) {
            if self.is_built(*cursor, None) {
                continue;
            }
            seen.clear();

            path.clear();
            path.push(*cursor);
            if let Some(paths) = Self::dfs_iter(self.dep_graph, cursor, &mut path, &mut seen) {
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
                Build(bsr) => {
                    process(bsr, seen, &mut out);
                }
                Source(_) | HostPath(_) | Local(_) | Prebuilt(_, _) => {}
            }
        }
        for bsr in bs.runtime_deps.iter() {
            process(bsr, seen, &mut out);
        }

        seen.insert(*cursor, ());
        out
    }
}

impl<'a> Iterator for ExecPlan<'a> {
    type Item = Vec<BuildSpecRef>;

    fn next(&mut self) -> Option<Self::Item> {
        let unique_reachable_len = self.reachable.iter().fold(0, |acc, x| {
            acc + if self.cycle_breakers.contains_key(x) {
                0
            } else {
                1
            }
        });
        if unique_reachable_len + self.cycle_breakers.len() == self.built.len() {
            // All dependent build-specs have been emitted as phases.
            // As a final step, emit any toplevels that haven't already
            // been emitted.
            if !self.emitted_toplevel {
                self.emitted_toplevel = true;
                let remaining: Vec<_> = self
                    .toplevels
                    .iter()
                    .filter_map(|bsr| match self.built.get(bsr) {
                        None => Some(*bsr),
                        Some(_) => None, // already emitted
                    })
                    .collect();

                return if !remaining.is_empty() {
                    Some(remaining)
                } else {
                    None
                };
            }
            return None;
        }
        let mut built_this_phase: HashMap<BuildSpecRef, ()> = HashMap::new();

        // Check every reachable build, and add them to this phase if all their dependencies are met.
        let mut met: Vec<BuildSpecRef> = Vec::new();
        'candidate_loop: for candidate in self.reachable.iter().chain(self.cycle_breakers.keys()) {
            if self.is_built(*candidate, None) {
                continue;
            }

            // This build spec has all its dependencies met if all its build-spec inputs have been built, as well
            // as all of its runtime dependencies.
            // Stuff thats built this phase is not considered met, as that would mean builds within a phase cannot
            // be executed in parallel.
            let bs = self.dep_graph.get(candidate).unwrap();
            for input in bs.inputs.iter() {
                use BuildSpecInput::*;
                match input {
                    Build(bsr) => {
                        if !self.is_built(*bsr, Some(*candidate)) {
                            continue 'candidate_loop;
                        }
                    }
                    Source(_) | HostPath(_) | Local(_) | Prebuilt(_, _) => {}
                }
            }
            for bsr in bs.runtime_deps.iter() {
                if !self.is_built(*bsr, Some(*candidate)) {
                    continue 'candidate_loop;
                }
            }
            // If we got this far, all build-spec dependencies have been built. It can be emitted this phase.
            met.push(*candidate);
            built_this_phase.insert(*candidate, ());
        }

        if met.is_empty() {
            // If this happened, theres a cycle preventing further progress. We need to do a depth-first search to find it.
            let cycles = self.find_cycles().into_iter().collect::<Vec<_>>();

            let mut at_least_one_cycle_breaker = false;

            for path in &cycles {
                for (head, used_by) in &[
                    // try seeing if theres a replace_on_cycle as the last element
                    (
                        path.last().unwrap(),
                        path.iter()
                            .rev()
                            .nth(1)
                            .unwrap_or(path.last().unwrap())
                            .to_owned(),
                    ),
                    // try seeing if theres a replace_on_cycle as the first element
                    (path.first().unwrap(), *path.last().unwrap()),
                ] {
                    if let Some(replace_on_cycle) =
                        self.dep_graph.get(head).unwrap().replace_on_cycle
                    {
                        if !self.cycle_breakers.contains_key(&replace_on_cycle) {
                            // A cycle was for a build-spec which 1) declared a cycle breaker, and 2) hasnt been used yet.
                            at_least_one_cycle_breaker = true;
                            // Bring the cycle-breaker into scope along with all its transitive dependencies
                            self.cycle_breakers.insert(replace_on_cycle, ());
                            self.dep_graph
                                .transitive_specs_of(&replace_on_cycle)
                                .into_iter()
                                .filter(|bsr| {
                                    !self.reachable.contains(bsr)
                                        && !self.cycle_breakers.contains_key(bsr)
                                })
                                .collect::<Vec<_>>()
                                .into_iter()
                                .for_each(|bsr| {
                                    self.cycle_breakers.insert(bsr, ());
                                });
                        }

                        // Make sure the satisfaction of the cycle-breaker counts for resolving the previous dependent in the cycle chain.
                        // Also allow the cycle breaker to use any of the satisfactions.
                        match self.met_dependency_overrides.get_mut(&(*used_by, **head)) {
                            Some(v) => {
                                if !v.contains(&replace_on_cycle) {
                                    v.push(replace_on_cycle);
                                }
                            }
                            None => {
                                self.met_dependency_overrides
                                    .insert((*used_by, **head), vec![replace_on_cycle]);
                            }
                        }
                    }
                }
            }

            if !at_least_one_cycle_breaker {
                // println!(
                //     "requested cycle breakers: {}",
                //     self.cycle_breakers
                //         .keys()
                //         .map(|bsr| self.dep_graph.get(&bsr).unwrap().name.clone())
                //         .collect::<Vec<_>>()
                //         .join(",")
                // );
                // for ((bsr, dep_bsr), breakers) in &self.met_dependency_overrides {
                //     let b = self.dep_graph.get(bsr).unwrap();
                //     let dep = self.dep_graph.get(dep_bsr).unwrap();
                //     let conditionals = breakers
                //         .iter()
                //         .map(|b| self.dep_graph.get(b).unwrap().name.clone())
                //         .collect::<Vec<_>>()
                //         .join(",");
                //     println!(
                //         "{} was allowed to satisfy {} using {}",
                //         b.name, dep.name, conditionals
                //     );
                // }

                panic!(
                    "cycle(s) detected! {:?}",
                    cycles
                        .into_iter()
                        .map(|c| {
                            c.into_iter()
                                .map(|bsr| self.dep_graph.get(&bsr).unwrap().name.clone())
                                .collect::<Vec<_>>()
                        })
                        .collect::<Vec<_>>()
                );
            } else {
                // Recurse so we don't have to emit an empty phase
                return self.next();
            }
        }

        // Update the built set with stuff build this phase.
        self.built.extend(built_this_phase.drain());
        Some(met)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SpecReader, SpecReaderOptions};
    use indoc::indoc;

    #[test]
    fn simple() {
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

        		{
        			name = \"top\",
        			inputs = [no_deps_spec],
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

        let dp = DepGraph::new(sr).unwrap();
        let plan: Vec<Vec<BuildSpecRef>> = ExecPlan::new(&dp).collect();

        // We expect two phases - one for the transistive dep, and a second for the toplevel.
        assert_eq!(
            plan,
            vec![
                vec![dp.iter().find(|b| b.1.name == "no deps").unwrap().0],
                vec![dp.iter().find(|b| b.1.name == "top").unwrap().0],
            ],
        );
    }

    #[test]
    fn multiple() {
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
                let depends_one_spec = {
        			name = \"depends one\",
        			inputs = [no_deps_spec],
        			cmd = \"\",
        		} | BuildSpec
        		in
                let depends_one_other_spec = {
        			name = \"depends one other\",
        			inputs = [no_deps_spec],
        			cmd = \"\",
        		} | BuildSpec
        		in

        		{
        			name = \"top\",
        			inputs = [depends_one_spec, depends_one_other_spec, no_deps_spec],
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

        let dp = DepGraph::new(sr).unwrap();
        let plan: Vec<Vec<BuildSpecRef>> = ExecPlan::new(&dp).collect();

        assert_eq!(
            plan,
            vec![
                vec![dp.iter().find(|b| b.1.name == "no deps").unwrap().0],
                vec![
                    dp.iter().find(|b| b.1.name == "depends one").unwrap().0,
                    dp.iter()
                        .find(|b| b.1.name == "depends one other")
                        .unwrap()
                        .0,
                ],
                vec![dp.iter().find(|b| b.1.name == "top").unwrap().0],
            ],
        );
    }

    #[test]
    fn with_runtime_deps() {
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
                let runtime_dep_spec = {
                    name = \"runtime dep\",
                    inputs = [],
                    cmd = \"\",
                } | BuildSpec
                in
                let depends_one_spec = {
                    name = \"depends one\",
                    inputs = [no_deps_spec],
                    cmd = \"\",
                } | BuildSpec
                in

                {
                    name = \"top\",
                    inputs = [depends_one_spec],
                    runtime_deps = [runtime_dep_spec],
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

        let dp = DepGraph::new(sr).unwrap();
        let plan: Vec<Vec<BuildSpecRef>> = ExecPlan::new(&dp).collect();

        assert_eq!(
            plan,
            vec![
                vec![
                    dp.by_name("no deps").next().unwrap(),
                    dp.by_name("runtime dep").next().unwrap()
                ],
                vec![dp.by_name("depends one").next().unwrap(),],
                vec![dp.by_name("top").next().unwrap()],
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

        let dp = DepGraph::new(sr).unwrap();
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

        let dp = DepGraph::new(sr).unwrap();
        let plan: Vec<Vec<BuildSpecRef>> = ExecPlan::new(&dp).collect();

        assert_eq!(
            plan,
            vec![
                vec![dp.by_name("breaker dep").next().unwrap(),],
                vec![dp.by_name("breaker").next().unwrap(),],
                vec![dp.by_name("self ref").next().unwrap(),],
                vec![dp.by_name("top").next().unwrap()],
            ],
        );
    }
}
