use crate::{BuildSpecInput, BuildSpecRef, DepGraph, SpecHash, SpecHashable};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Information about why a transitive dependency exists.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub enum DepInfo {
    /// The dependency is declared on the build spec.
    Ours,
    /// The dependency is transitively required by a input spec.
    Inherited { from: SpecHash },
}

/// Describes metadata about the output of some build, and all its transitive requirements.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BuildManifest {
    /// The spec hash of the build this refers to.
    pub hash: SpecHash,

    /// The transitive runtime dependencies any use of this build needs, along with attribution.
    pub transitive_runtime_deps: HashMap<SpecHash, Vec<DepInfo>>,
    // TODO: transitive output dependencies
}

impl BuildManifest {
    /// Constructs a manifest of transitive dependencies for the given build, which has the given hash.
    pub fn make(g: &DepGraph, build: &BuildSpecRef, hash: &SpecHash) -> Self {
        let build = g.get(build).unwrap();

        let mut out = BuildManifest {
            hash: hash.clone(),
            transitive_runtime_deps: HashMap::with_capacity(
                2 * (build.inputs.len() + build.runtime_deps.len()),
            ),
        };
        for input in build.inputs.iter() {
            use BuildSpecInput::*;
            // Collect all transitive runtime_deps by recursing into the [BuildManifest] of
            // all inputs.
            match input {
                Build(bsr) => {
                    let dep_build = g.get(bsr).unwrap();
                    let dep_hash = dep_build.spec_hash(g);

                    for (hash, source) in BuildManifest::make(g, bsr, &dep_hash)
                        .transitive_runtime_deps
                        .iter()
                        .map(|(runtime_dep, _sources)| {
                            (
                                runtime_dep.clone(),
                                DepInfo::Inherited {
                                    from: dep_hash.clone(),
                                },
                            )
                        })
                    {
                        match out.transitive_runtime_deps.get_mut(&hash) {
                            Some(source_list) => source_list.push(source),
                            None => {
                                out.transitive_runtime_deps.insert(hash, vec![source]);
                            }
                        }
                    }
                }

                Source(_) | HostPath(_) | Local(_) | Prebuilt(_) => {}
            }
        }
        // Lastly lets add runtime deps declared on this build.
        for bsr in build.runtime_deps.iter() {
            let dep_build = g.get(bsr).unwrap();
            let dep_hash = dep_build.spec_hash(g);
            match out.transitive_runtime_deps.get_mut(&dep_hash) {
                Some(source_list) => source_list.push(DepInfo::Ours),
                None => {
                    out.transitive_runtime_deps
                        .insert(dep_hash, vec![DepInfo::Ours]);
                }
            }
        }

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
        let build = dg.get(&dg.by_name("top build").next().unwrap()).unwrap();
        let bsh = build.spec_hash(&dg);

        let toplevel_manifest = BuildManifest::make(&dg, &dg.top_level, &bsh);
        assert_eq!(toplevel_manifest.hash, bsh);

        let runtime_dep_hash = dg
            .get(&dg.by_name("runtime dep").next().unwrap())
            .unwrap()
            .spec_hash(&dg);

        assert_eq!(
            toplevel_manifest
                .transitive_runtime_deps
                .into_iter()
                .collect::<Vec<_>>(),
            vec![(runtime_dep_hash, vec![DepInfo::Ours])],
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
        let build = dg.get(&dg.by_name("top build").next().unwrap()).unwrap();
        let bsh = build.spec_hash(&dg);

        let toplevel_manifest = BuildManifest::make(&dg, &dg.top_level, &bsh);
        assert_eq!(toplevel_manifest.hash, bsh);

        let runtime_dep_hash = dg
            .get(&dg.by_name("runtime dep").next().unwrap())
            .unwrap()
            .spec_hash(&dg);
        let nested_input_hash = dg
            .get(&dg.by_name("nested input").next().unwrap())
            .unwrap()
            .spec_hash(&dg);

        assert_eq!(
            toplevel_manifest
                .transitive_runtime_deps
                .into_iter()
                .collect::<Vec<_>>(),
            vec![(
                runtime_dep_hash,
                vec![DepInfo::Inherited {
                    from: nested_input_hash
                }]
            )],
        );
    }
}
