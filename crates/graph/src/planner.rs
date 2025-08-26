use crate::{BuildSpecInput, BuildSpecRef, DepGraph};
use std::collections::HashMap;

/// Describes the ordered set of builds required to materialize some top-level build spec.
///
/// Users should iterate this plan to get the ordering that build specs must be built.
/// When multiple build specs are yielded in one iteration, these builds may be executed in parallel.
pub struct ExecPlan<'a> {
    dep_graph: &'a DepGraph,

    // the apex of the build graph - the ultimate build-spec we want compiled.
    toplevel: BuildSpecRef,

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
        let built = HashMap::with_capacity(dep_graph.builds.len());
        let reachable = dep_graph.transitive_specs_of(&toplevel);

        Self {
            dep_graph,
            toplevel,
            built,
            reachable,
            emitted_toplevel: false,
        }
    }
}

impl<'a> Iterator for ExecPlan<'a> {
    type Item = Vec<BuildSpecRef>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.reachable.len() == self.built.len() {
            // All dependent build-specs have been emitted as phases.
            // As a final step, emit the toplevel in question.
            if !self.emitted_toplevel {
                self.emitted_toplevel = true;
                return Some(vec![self.toplevel]);
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

            // This build spec has all its dependencies met if all its build-spec inputs have been built.
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
            // If we got this far, all build-spec input dependencies have been built. It can be emitted this phase.
            met.push(*candidate);
            built_this_phase.insert(*candidate, ());
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
                vec![BuildSpecRef(
                    dp.builds.iter().find(|b| b.1.name == "no deps").unwrap().0
                )],
                vec![BuildSpecRef(
                    dp.builds.iter().find(|b| b.1.name == "top").unwrap().0
                )],
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
                vec![BuildSpecRef(
                    dp.builds.iter().find(|b| b.1.name == "no deps").unwrap().0
                )],
                vec![
                    BuildSpecRef(
                        dp.builds
                            .iter()
                            .find(|b| b.1.name == "depends one")
                            .unwrap()
                            .0
                    ),
                    BuildSpecRef(
                        dp.builds
                            .iter()
                            .find(|b| b.1.name == "depends one other")
                            .unwrap()
                            .0
                    ),
                ],
                vec![BuildSpecRef(
                    dp.builds.iter().find(|b| b.1.name == "top").unwrap().0
                )],
            ],
        );
    }
}
