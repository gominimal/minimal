use crate::{BuildSpecInput, BuildSpecRef, DepGraph, RuntimeDep, SubsetInput};
use std::{
    collections::{HashMap, HashSet},
    ops::Deref,
};

/// Information about a dependency.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dep {
    pub needed_by: Vec<Attribution>,
    pub outputs: Option<HashSet<String>>,
}

impl From<Vec<Attribution>> for Dep {
    fn from(needed_by: Vec<Attribution>) -> Self {
        Self {
            needed_by,
            outputs: None,
        }
    }
}

/// Information about why a transitive dependency exists.
#[derive(Debug, Clone, PartialEq, PartialOrd, Ord, Eq)]
pub enum Attribution {
    /// The dependency is declared on the build spec.
    Ours,
    /// The dependency is transitively required by a input spec.
    Inherited { from: BuildSpecRef },
}

/// Describes the transitive requirements of some build.
#[derive(Debug, Clone)]
pub struct Transitives {
    pub build: BuildSpecRef,

    /// The transitive runtime dependencies any use of this build needs, along with attribution.
    pub transitive_runtime_deps: HashMap<BuildSpecRef, Dep>,
}

impl Transitives {
    fn upsert<I: Iterator<Item = Attribution>, IT: Into<String>, O: IntoIterator<Item = IT>>(
        transitive_runtime_deps: &mut HashMap<BuildSpecRef, Dep>,
        bsr: &BuildSpecRef,
        needed_by: I,
        outputs: Option<O>,
    ) {
        match transitive_runtime_deps.get_mut(bsr) {
            Some(existing) => {
                // union attributions
                existing.needed_by.extend(needed_by);
                existing.needed_by.sort();
                existing.needed_by.dedup();

                // union outputs
                match (&mut existing.outputs, outputs) {
                    (None, _) | (_, None) => {
                        // One of the outputs wasnt a subset, so we turn into the full build.
                        existing.outputs = None;
                    }
                    (Some(stored), Some(new)) => {
                        // Both stored & incoming are subsets, union the outputs they are requesting
                        stored.extend(new.into_iter().map(|s| s.into()));
                    }
                }
            }
            None => {
                // New entry
                transitive_runtime_deps.insert(
                    *bsr,
                    Dep {
                        needed_by: needed_by.collect(),
                        outputs: outputs.map(|v| v.into_iter().map(|s| s.into()).collect()),
                    },
                );
            }
        }
    }

    /// Constructs the set of transitive dependencies for the given build.
    pub fn new(g: &DepGraph, bsr: &BuildSpecRef, include_inputs: bool) -> Self {
        Self::new_with_seenset(&mut HashSet::with_capacity(256), g, bsr, include_inputs)
    }
    fn new_with_seenset(
        seen: &mut HashSet<BuildSpecRef>,
        g: &DepGraph,
        bsr: &BuildSpecRef,
        include_inputs: bool,
    ) -> Self {
        let build = g.get(bsr).unwrap();

        let mut out = Transitives {
            build: *bsr,
            transitive_runtime_deps: HashMap::with_capacity(
                2 * (build.inputs.len() + 2 * build.runtime_deps.len()),
            ),
        };

        for dep in build.runtime_deps.iter() {
            match dep {
                RuntimeDep::Build(bsr) => {
                    Self::upsert(
                        &mut out.transitive_runtime_deps,
                        bsr,
                        [Attribution::Ours].into_iter(),
                        None::<Vec<String>>,
                    );
                }
                RuntimeDep::Subset(SubsetInput { from: bsr, outputs }) => {
                    Self::upsert(
                        &mut out.transitive_runtime_deps,
                        bsr,
                        [Attribution::Ours].into_iter(),
                        Some(outputs.clone()),
                    );
                }
            }
        }
        if include_inputs {
            for dep in build.inputs.iter() {
                use BuildSpecInput::*;
                match dep {
                    Build(bsr) => {
                        Self::upsert(
                            &mut out.transitive_runtime_deps,
                            bsr,
                            [Attribution::Ours].into_iter(),
                            None::<Vec<String>>,
                        );
                    }
                    Subset(SubsetInput { from: bsr, outputs }) => {
                        Self::upsert(
                            &mut out.transitive_runtime_deps,
                            bsr,
                            [Attribution::Ours].into_iter(),
                            Some(outputs.clone()),
                        );
                    }
                    Source(_) | Local { .. } | HostPath(_) => {}
                }
            }
        }
        if build.abstract_deps.contains_key("internet") {
            g.iter()
                .filter(|(_bsr, b)| b.attrs.contains_key("needed_for_internet"))
                .for_each(|(bsr, _b)| {
                    Self::upsert(
                        &mut out.transitive_runtime_deps,
                        &bsr,
                        [Attribution::Ours].into_iter(),
                        None::<Vec<String>>,
                    )
                });
        }

        // Collect all transitive runtime_deps by recursing into the [BuildManifest] of
        // all inputs, as well as all runtime_deps.
        use BuildSpecInput::*;
        build
            .inputs
            .iter()
            .filter_map(|input| match (input, include_inputs) {
                (Build(bsr), true) => Some((bsr, None)),
                (Subset(SubsetInput { from: bsr, outputs }), true) => Some((bsr, Some(outputs))),
                (Build(_) | Subset(_), false) => None,
                (Source(_) | HostPath(_) | Local { .. }, _) => None,
            })
            .chain(build.runtime_deps.iter().map(|dep| match dep {
                RuntimeDep::Build(bsr) => (bsr, None),
                RuntimeDep::Subset(SubsetInput { from: bsr, outputs }) => (bsr, Some(outputs)),
            }))
            .for_each(|(bsr, outputs)| {
                if !seen.contains(bsr) {
                    seen.insert(*bsr);
                    for (dep_bsr, info) in Transitives::new_with_seenset(seen, g, bsr, false)
                        .transitive_runtime_deps
                        .into_iter()
                        .map(|(dep_bsr, mut info)| {
                            (dep_bsr, {
                                info.needed_by.clear();
                                info.needed_by.push(Attribution::Inherited { from: *bsr });
                                info
                            })
                        })
                    {
                        Self::upsert(
                            &mut out.transitive_runtime_deps,
                            &dep_bsr,
                            info.needed_by.into_iter(),
                            info.outputs,
                        );
                    }
                } else {
                    Self::upsert(
                        &mut out.transitive_runtime_deps,
                        bsr,
                        [Attribution::Ours].into_iter(),
                        outputs.map(|v| v.deref()),
                    );
                }
            });

        out
    }

    /// Returns the transitive dependencies required to materialize the given toplevels.
    pub fn for_toplevels(
        graph: &DepGraph,
        top_levels: Vec<BuildSpecRef>,
        include_inputs: bool,
    ) -> HashMap<BuildSpecRef, Dep> {
        let mut seenset = HashSet::with_capacity(256);
        let mut out: HashMap<BuildSpecRef, Dep> = HashMap::with_capacity(512);
        top_levels
            .iter()
            .flat_map(|base| {
                seenset.clear();
                Transitives::new_with_seenset(&mut seenset, graph, base, include_inputs)
                    .transitive_runtime_deps
                    .into_iter()
                    .map(|(dep_bsr, mut info)| {
                        (dep_bsr, {
                            info.needed_by.clear();
                            info.needed_by.push(Attribution::Inherited { from: *base });
                            info
                        })
                    })
            })
            .chain(top_levels.iter().copied().map(|bsr| {
                (
                    bsr,
                    Dep {
                        needed_by: vec![Attribution::Ours],
                        outputs: None,
                    },
                )
            }))
            .for_each(|(bsr, info)| {
                Self::upsert(&mut out, &bsr, info.needed_by.into_iter(), info.outputs)
            });

        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use decode::Layer;
    use indoc::indoc;

    #[test]
    fn direct_runtime_deps() {
        let layer = Layer::new_for_test(
            indoc! {
                "
                let {BuildSpec, Source, ..} = import \"minimal.ncl\" in

                let runtime_dep = {
                    name = \"runtime dep\",
                    inputs = [
                        {url = \"http://uwu.com\", sha256 = \"abcdef\"} | Source,
                    ],
                    cmd = \"\",
                } | BuildSpec
                in

                {
                    name = \"top build\",
                    inputs = [
                        {
                            name = \"input\",
                            inputs = [],
                            cmd = \"\",
                        } | BuildSpec,
                    ],
                    runtime_deps = [runtime_dep],
                    cmd = \"\",
                } | BuildSpec"
            }
            .to_string(),
        )
        .unwrap_or_else(|e| {
            e.report_to_stderr();
            panic!("spec parsing failed");
        });

        let dg = DepGraph::new().ingest(layer).unwrap();

        let toplevel_manifest = Transitives::new(&dg, &dg.top_levels[0], false);
        assert_eq!(
            toplevel_manifest.build,
            dg.by_name("top build").unwrap().clone()
        );

        assert_eq!(
            toplevel_manifest
                .transitive_runtime_deps
                .into_iter()
                .collect::<Vec<_>>(),
            vec![(
                *dg.by_name("runtime dep").unwrap(),
                Dep {
                    needed_by: vec![Attribution::Ours],
                    outputs: None,
                }
            )],
        );
    }

    #[test]
    fn input_nested_runtime_deps() {
        let layer = Layer::new_for_test(
            indoc! {
                "
                let {BuildSpec, Source, ..} = import \"minimal.ncl\" in

                let runtime_dep = {
                    name = \"runtime dep\",
                    inputs = [
                        {url = \"http://uwu.com\", sha256 = \"abcdef\"} | Source,
                    ],
                    cmd = \"\",
                } | BuildSpec
                in

                {
                    name = \"top build\",
                    inputs = [
                        {
                            name = \"nested input\",
                            inputs = [],
                            runtime_deps = [runtime_dep],
                            cmd = \"\",
                        } | BuildSpec,
                    ],
                    cmd = \"\",
                } | BuildSpec"
            }
            .to_string(),
        )
        .unwrap_or_else(|e| {
            e.report_to_stderr();
            panic!("spec parsing failed");
        });

        let dg = DepGraph::new().ingest(layer).unwrap();

        let toplevel_manifest = Transitives::new(&dg, &dg.top_levels[0], true);
        assert_eq!(
            toplevel_manifest.build,
            dg.by_name("top build").unwrap().clone()
        );

        let mut deps = toplevel_manifest
            .transitive_runtime_deps
            .into_iter()
            .collect::<Vec<_>>();
        deps.sort_by(|(a, _), (b, _)| a.cmp(b));
        assert_eq!(
            deps,
            vec![
                (
                    *dg.by_name("nested input").unwrap(),
                    Dep {
                        needed_by: vec![Attribution::Ours],
                        outputs: None,
                    }
                ),
                (
                    *dg.by_name("runtime dep").unwrap(),
                    Dep {
                        needed_by: vec![Attribution::Inherited {
                            from: *dg.by_name("nested input").unwrap()
                        }],
                        outputs: None,
                    }
                )
            ],
        );
    }

    #[test]
    fn runtime_deps_nested_runtime_deps() {
        let layer = Layer::new_for_test(
            indoc! {
                "
                let {BuildSpec, Source, ..} = import \"minimal.ncl\" in

                let nested_dep = {
                    name = \"nested dep\",
                    inputs = [
                        {url = \"http://uwu.com\", sha256 = \"abcdef\"} | Source,
                    ],
                    cmd = \"\",
                } | BuildSpec
                in
                let top_dep = {
                    name = \"top dep\",
                    inputs = [],
                    runtime_deps = [nested_dep],
                    cmd = \"\",
                } | BuildSpec
                in

                {
                    name = \"top build\",
                    inputs = [],
                    runtime_deps = [top_dep],
                    cmd = \"\",
                } | BuildSpec"
            }
            .to_string(),
        )
        .unwrap_or_else(|e| {
            e.report_to_stderr();
            panic!("spec parsing failed");
        });

        let dg = DepGraph::new().ingest(layer).unwrap();

        let toplevel_manifest = Transitives::new(&dg, &dg.top_levels[0], true);
        assert_eq!(
            toplevel_manifest.build,
            dg.by_name("top build").unwrap().clone()
        );

        let mut deps = toplevel_manifest
            .transitive_runtime_deps
            .into_iter()
            .collect::<Vec<_>>();
        deps.sort_by(|(a, _), (b, _)| a.cmp(b));

        assert_eq!(
            deps,
            vec![
                (
                    *dg.by_name("top dep").unwrap(),
                    Dep {
                        needed_by: vec![Attribution::Ours],
                        outputs: None,
                    }
                ),
                (
                    *dg.by_name("nested dep").unwrap(),
                    Dep {
                        needed_by: vec![Attribution::Inherited {
                            from: *dg.by_name("top dep").unwrap()
                        }],
                        outputs: None,
                    }
                )
            ],
        );
    }

    #[test]
    fn subsets_combined() {
        let layer = Layer::new_for_test(
            indoc! {
                "
                let {subsetOf, BuildSpec, Source, OutputData, ..} = import \"minimal.ncl\" in

                let runtime_dep = {
                    name = \"runtime dep\",
                    inputs = [
                        {url = \"http://uwu.com\", sha256 = \"abcdef\"} | Source,
                    ],
                    cmd = \"\",
                    outputs = {
                      a = {glob = \"a\"} | OutputData,
                      b = {glob = \"b\"} | OutputData,
                    }
                } | BuildSpec
                in
                let collection = {
                  name = \"collection\",
                  inputs = [],
                  cmd = \"\",
                  runtime_deps = [subsetOf runtime_dep [\"a\"]],
                } | BuildSpec
                in

                {
                    name = \"top build\",
                    inputs = [
                        {
                            name = \"input\",
                            inputs = [],
                            cmd = \"\",
                        } | BuildSpec,
                    ],
                    runtime_deps = [
                        collection,
                        subsetOf runtime_dep [\"b\"],
                    ],
                    cmd = \"\",
                } | BuildSpec"
            }
            .to_string(),
        )
        .unwrap_or_else(|e| {
            e.report_to_stderr();
            panic!("spec parsing failed");
        });

        let dg = DepGraph::new().ingest(layer).unwrap();

        let toplevel_manifest = Transitives::new(&dg, &dg.top_levels[0], false);
        assert_eq!(
            toplevel_manifest.build,
            dg.by_name("top build").unwrap().clone()
        );

        let mut result = toplevel_manifest
            .transitive_runtime_deps
            .into_iter()
            .collect::<Vec<_>>();
        result.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(
            result,
            vec![
                (
                    *dg.by_name("collection").unwrap(),
                    Dep {
                        needed_by: vec![Attribution::Ours],
                        outputs: None,
                    }
                ),
                (
                    *dg.by_name("runtime dep").unwrap(),
                    Dep {
                        needed_by: vec![
                            Attribution::Ours,
                            Attribution::Inherited {
                                from: *dg.by_name("collection").unwrap()
                            }
                        ],
                        outputs: Some(["a", "b"].into_iter().map(|s| s.to_string()).collect()),
                    }
                ),
            ],
        );
    }

    #[test]
    fn subset_promoted() {
        let layer = Layer::new_for_test(
            indoc! {
                "
                let {subsetOf, BuildSpec, Source, OutputData, ..} = import \"minimal.ncl\" in

                let runtime_dep = {
                    name = \"runtime dep\",
                    inputs = [
                        {url = \"http://uwu.com\", sha256 = \"abcdef\"} | Source,
                    ],
                    cmd = \"\",
                    outputs = {
                      a = {glob = \"a\"} | OutputData,
                      b = {glob = \"a\"} | OutputData,
                    }
                } | BuildSpec
                in

                {
                    name = \"top build\",
                    inputs = [
                        {
                            name = \"input\",
                            inputs = [],
                            cmd = \"\",
                        } | BuildSpec,
                        runtime_dep,
                    ],
                    runtime_deps = [
                        subsetOf runtime_dep [\"a\"],
                    ],
                    cmd = \"\",
                } | BuildSpec"
            }
            .to_string(),
        )
        .unwrap_or_else(|e| {
            e.report_to_stderr();
            panic!("spec parsing failed");
        });

        let dg = DepGraph::new().ingest(layer).unwrap();

        let toplevel_manifest = Transitives::new(&dg, &dg.top_levels[0], true);
        assert_eq!(
            toplevel_manifest.build,
            dg.by_name("top build").unwrap().clone()
        );

        let mut result = toplevel_manifest
            .transitive_runtime_deps
            .into_iter()
            .collect::<Vec<_>>();
        result.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(
            result,
            vec![
                (
                    *dg.by_name("input").unwrap(),
                    Dep {
                        needed_by: vec![Attribution::Ours],
                        outputs: None,
                    }
                ),
                (
                    *dg.by_name("runtime dep").unwrap(),
                    Dep {
                        needed_by: vec![Attribution::Ours],
                        outputs: None,
                    }
                ),
            ],
        );
    }

    #[test]
    fn nested_needs_internet() {
        let layer = Layer::new_for_test(
            indoc! {
                "
                let {build, Needs, ..} = import \"minimal.ncl\" in

                let nested = build {
                    name = \"nested\",
                    inputs = [],
                    needs = {
                        internet = {},
                    } | Needs,
                    cmd = \"\",
                }
                in

                [
                    build {
                        name = \"top build\",
                        inputs = [nested],
                        cmd = \"\",
                    },
                    build {
                        name = \"internet provider\",
                        inputs = [],
                        cmd = \"\",
                        attrs.needed_for_internet = {},
                    },
                ]
                "
            }
            .to_string(),
        )
        .unwrap_or_else(|e| {
            e.report_to_stderr();
            panic!("spec parsing failed");
        });

        let dg = DepGraph::new().ingest(layer).unwrap();

        let toplevel_manifest = Transitives::new(&dg, &dg.top_levels[0], true);
        assert_eq!(
            toplevel_manifest.build,
            dg.by_name("top build").unwrap().clone()
        );

        assert!(
            toplevel_manifest
                .transitive_runtime_deps
                .contains_key(&dg.by_name("internet provider").unwrap().clone())
        )
    }
}
