use crate::{BuildSpecInput, BuildSpecRef, DepGraph};
use std::collections::HashMap;

/// Information about why a transitive dependency exists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DepInfo {
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
    pub transitive_runtime_deps: HashMap<BuildSpecRef, Vec<DepInfo>>,
}

impl Transitives {
    /// Constructs the set of transitive dependencies for the given build.
    pub fn new(g: &DepGraph, bsr: &BuildSpecRef, include_inputs: bool) -> Self {
        let build = g.get(bsr).unwrap();

        let mut out = Transitives {
            build: *bsr,
            transitive_runtime_deps: HashMap::with_capacity(
                2 * (build.inputs.len() + build.runtime_deps.len()),
            ),
        };

        for bsr in build.runtime_deps.iter() {
            out.transitive_runtime_deps
                .insert(*bsr, vec![DepInfo::Ours]);
        }

        // Collect all transitive runtime_deps by recursing into the [BuildManifest] of
        // all inputs, as well as all runtime_deps.
        use BuildSpecInput::*;
        build
            .inputs
            .iter()
            .filter_map(|input| match (input, include_inputs) {
                (Build(bsr), true) => Some(bsr),
                (Build(_), false) => None,
                (Source(_) | HostPath(_) | Local(_) | Prebuilt(_, _), _) => None,
            })
            .chain(build.runtime_deps.iter())
            .for_each(|bsr| {
                for (hash, source) in Transitives::new(g, bsr, false)
                    .transitive_runtime_deps
                    .keys()
                    .map(|runtime_dep| (*runtime_dep, DepInfo::Inherited { from: *bsr }))
                {
                    match out.transitive_runtime_deps.get_mut(&hash) {
                        Some(source_list) => source_list.push(source),
                        None => {
                            out.transitive_runtime_deps.insert(hash, vec![source]);
                        }
                    }
                }
            });

        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DepGraph, SpecReader, SpecReaderOptions};
    use indoc::indoc;

    #[test]
    fn direct_runtime_deps() {
        let sr = SpecReader::new(
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
            &SpecReaderOptions::for_test(),
        );
        // So we can see the actual error when parsing fails
        sr.as_ref().err().into_iter().for_each(|e| {
            e.report_to_stderr();
            panic!("spec parsing failed");
        });
        let sr = sr.unwrap();

        let dg = DepGraph::new(sr).unwrap();

        let toplevel_manifest = Transitives::new(&dg, &dg.top_levels[0], true);
        assert_eq!(
            toplevel_manifest.build,
            dg.by_name("top build").next().unwrap()
        );

        assert_eq!(
            toplevel_manifest
                .transitive_runtime_deps
                .into_iter()
                .collect::<Vec<_>>(),
            vec![(
                dg.by_name("runtime dep").next().unwrap(),
                vec![DepInfo::Ours]
            )],
        );
    }

    #[test]
    fn input_nested_runtime_deps() {
        let sr = SpecReader::new(
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
            &SpecReaderOptions::for_test(),
        );
        // So we can see the actual error when parsing fails
        sr.as_ref().err().into_iter().for_each(|e| {
            e.report_to_stderr();
            panic!("spec parsing failed");
        });
        let sr = sr.unwrap();

        let dg = DepGraph::new(sr).unwrap();

        let toplevel_manifest = Transitives::new(&dg, &dg.top_levels[0], true);
        assert_eq!(
            toplevel_manifest.build,
            dg.by_name("top build").next().unwrap()
        );

        assert_eq!(
            toplevel_manifest
                .transitive_runtime_deps
                .into_iter()
                .collect::<Vec<_>>(),
            vec![(
                dg.by_name("runtime dep").next().unwrap(),
                vec![DepInfo::Inherited {
                    from: dg.by_name("nested input").next().unwrap()
                }]
            )],
        );
    }

    #[test]
    fn runtime_deps_nested_runtime_deps() {
        let sr = SpecReader::new(
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
            &SpecReaderOptions::for_test(),
        );
        // So we can see the actual error when parsing fails
        sr.as_ref().err().into_iter().for_each(|e| {
            e.report_to_stderr();
            panic!("spec parsing failed");
        });
        let sr = sr.unwrap();

        let dg = DepGraph::new(sr).unwrap();

        let toplevel_manifest = Transitives::new(&dg, &dg.top_levels[0], true);
        assert_eq!(
            toplevel_manifest.build,
            dg.by_name("top build").next().unwrap()
        );

        let mut deps = toplevel_manifest
            .transitive_runtime_deps
            .into_iter()
            .collect::<Vec<_>>();
        deps.sort_by(|(a, _), (b, _)| a.cmp(b));

        assert_eq!(
            deps,
            vec![
                (dg.by_name("top dep").next().unwrap(), vec![DepInfo::Ours],),
                (
                    dg.by_name("nested dep").next().unwrap(),
                    vec![DepInfo::Inherited {
                        from: dg.by_name("top dep").next().unwrap()
                    }]
                )
            ],
        );
    }
}
