use crate::{BuildSpecInput, BuildSpecRef, DepGraph};
use std::collections::HashMap;

/// The 'color' of a build spec in the context of a depth-first search to identify cycles.
///
/// I know these aren't colors bruh, dont @ me.
#[derive(Debug, Clone, PartialEq)]
enum DFSColor {
    /// The build-spec has no color: that is, it has not been visited by any DFS iteration.
    Pristine,
    /// The build-spec has been visited at the stored generation. This should be considered
    /// to be Pristine if the generation is less than the current generation.
    Marred(usize),
}

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
}

impl<'a> ExecPlan<'a> {
    pub fn new(dep_graph: &'a DepGraph) -> Self {
        ExecPlan::with_toplevel(dep_graph, dep_graph.top_level)
    }

    pub fn with_toplevel(dep_graph: &'a DepGraph, toplevel: BuildSpecRef) -> Self {
        let built = HashMap::with_capacity(dep_graph.len());
        let reachable = dep_graph
            .transitive_specs_of(&toplevel)
            .into_iter()
            .collect();

        Self {
            dep_graph,
            toplevels: vec![toplevel],
            built,
            reachable,
            emitted_toplevel: false,
        }
    }

    pub fn new_with_all(dep_graph: &'a DepGraph) -> Self {
        let built = HashMap::with_capacity(dep_graph.len());
        let all: Vec<BuildSpecRef> = dep_graph.all().collect();

        Self {
            dep_graph,
            toplevels: all.clone(),
            built,
            reachable: all,
            emitted_toplevel: false,
        }
    }

    fn find_cycles(&mut self) -> Vec<Vec<BuildSpecRef>> {
        let mut cycles: Vec<Vec<BuildSpecRef>> = Vec::with_capacity(32);

        let mut generation: usize = 0;
        let mut path: Vec<BuildSpecRef> = Vec::with_capacity(self.reachable.len() + 256);
        let mut colors = HashMap::with_capacity(self.reachable.len());

        for cursor in self.reachable.iter() {
            if self.built.contains_key(cursor) {
                continue;
            }

            path.clear();
            path.push(cursor.clone());
            match Self::dfs_iter(self.dep_graph, cursor, generation, &mut colors, &mut path) {
                Ok(()) => {
                    cycles.push(path.clone());
                }
                Err(()) => {}
            }
            generation += 1;
        }

        cycles
    }

    fn dfs_iter(
        g: &DepGraph,
        cursor: &BuildSpecRef,
        generation: usize,
        colors: &mut HashMap<BuildSpecRef, DFSColor>,
        path: &mut Vec<BuildSpecRef>,
    ) -> Result<(), ()> {
        let bs = g.get(cursor).unwrap();

        // Look at a node which is a dependency of cursor.
        let mut process = |bsr| -> Result<(), ()> {
            let color = colors.get(bsr).unwrap_or(&DFSColor::Pristine).clone();

            let mut recurse = |bsr: &BuildSpecRef| -> Result<(), ()> {
                let bsr = bsr.clone();
                path.push(bsr);
                colors.insert(bsr, DFSColor::Marred(generation));
                match Self::dfs_iter(g, &bsr, generation, colors, path) {
                    Err(()) => {
                        path.pop();
                        Err(())
                    }
                    Ok(()) => Ok(()),
                }
            };

            match color {
                // This node hasn't been seen in this search, marr it as seen and recurse.
                DFSColor::Pristine => recurse(bsr),
                // If this node has been seen, check the generation to see if its valid, marring it again
                // and recursing if so.
                DFSColor::Marred(marred_gen) => {
                    if generation == marred_gen {
                        Ok(())
                    } else {
                        recurse(bsr)
                    }
                }
            }
        };

        // Search through all inputs and runtime deps.
        for input in bs.inputs.iter() {
            use BuildSpecInput::*;
            match input {
                Build(bsr) => {
                    if let Ok(ok) = process(bsr) {
                        return Ok(ok);
                    }
                }
                Source(_) | HostPath(_) | Local(_) | Prebuilt(_) => {}
            }
        }
        for bsr in bs.runtime_deps.iter() {
            if let Ok(ok) = process(bsr) {
                return Ok(ok);
            }
        }

        Err(()) // no cycles found from this node
    }
}

impl<'a> Iterator for ExecPlan<'a> {
    type Item = Vec<BuildSpecRef>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.reachable.len() == self.built.len() {
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
        'candidate_loop: for candidate in self.reachable.iter() {
            if self.built.contains_key(candidate) {
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
                        if !self.built.contains_key(bsr) {
                            continue 'candidate_loop;
                        }
                    }
                    Source(_) | HostPath(_) | Local(_) | Prebuilt(_) => {}
                }
            }
            for bsr in bs.runtime_deps.iter() {
                if !self.built.contains_key(bsr) {
                    continue 'candidate_loop;
                }
            }
            // If we got this far, all build-spec dependencies have been built. It can be emitted this phase.
            met.push(*candidate);
            built_this_phase.insert(*candidate, ());
        }

        if met.len() == 0 {
            // If this happened, theres a cycle preventing further progress. We need to do a depth-first search to find it.
            let cycles_with_named_specs = self
                .find_cycles()
                .into_iter()
                .map(|c| {
                    c.into_iter()
                        .map(|bsr| self.dep_graph.get(&bsr).unwrap().name.clone())
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>();
            panic!("cycle(s) detected! {:?}", cycles_with_named_specs);
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
        let cycles = ExecPlan::new(&dp)
            .find_cycles()
            .into_iter()
            .map(|c| {
                c.into_iter()
                    .map(|bsr| dp.get(&bsr).unwrap().name.clone())
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();

        // We expect two phases - one for the transistive dep, and a second for the toplevel.
        assert_eq!(
            cycles,
            vec![
                vec!["build 2", "build 1", "build 2"],
                vec!["build 1", "build 2", "build 1"],
            ],
        );
    }
}
