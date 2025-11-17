use crate::{
    BuildOutput, BuildSpec, BuildSpecInput, BuildSpecRef, DepGraph, RuntimeDep, SpecHash,
    dep_graph::SourceFetch,
};
use blake3::Hasher;
use common::{SubsetSpec, Target, target};
use decode::AttrValue;
use smallvec::SmallVec;
use std::collections::HashMap;
use std::io::Write;

type Edges = SmallVec<[Edge; 12]>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SpecIndex(usize);

#[derive(Debug, Clone, PartialEq, Eq)]
struct SubsetInfo(SmallVec<[String; 4]>);

#[derive(Debug, Clone, PartialEq, Eq)]
enum Edge {
    BuildInput(SpecIndex, Option<SubsetInfo>),
    RuntimeDep(SpecIndex, Option<SubsetInfo>),
    ReplaceOnCycle(SpecIndex),
}

/// Computes the [SpecHash] for a build spec.
pub struct SpecHasher<'a> {
    graph: &'a DepGraph,
    specs: Vec<(BuildSpecRef, Option<Edges>)>,
    spec_idx: HashMap<BuildSpecRef, SpecIndex>,
}

impl<'a> SpecHasher<'a> {
    pub fn hash(graph: &'a DepGraph, bsr: &'a BuildSpecRef) -> SpecHash {
        let mut sh = SpecHasher {
            graph,
            specs: Vec::with_capacity(2048),
            spec_idx: HashMap::with_capacity(2048),
        };
        sh.process(bsr);

        let mut h = Hasher::new();

        // compute the hash by walking all seen build-specs in the order they were seen,
        // first writing base (non-edge) attributes into the hash before describing edges
        // by index.
        for (i, (bsr, edges)) in sh.specs.into_iter().enumerate() {
            let build = sh.graph.get(&bsr).unwrap();

            h.write_all(&i.to_le_bytes()).unwrap();
            build_attrs_hash(build, &mut h);

            for edge in edges.unwrap().into_iter() {
                use Edge::*;
                match edge {
                    BuildInput(input_idx, subset_info) => {
                        h.write_all(b"i").unwrap();
                        h.write_all(&input_idx.0.to_le_bytes()).unwrap();
                        if let Some(SubsetInfo(outputs)) = subset_info {
                            h.write_all(b"ss").unwrap();
                            for output in &outputs {
                                h.write_all(output.as_bytes()).unwrap();
                                h.write_all(b",").unwrap();
                            }
                            h.write_all(b"l").unwrap(); // TODO: Remove the next time we break spec-hash values
                        }
                    }
                    RuntimeDep(dep_idx, subset_info) => {
                        h.write_all(b"r").unwrap();
                        h.write_all(&dep_idx.0.to_le_bytes()).unwrap();
                        if let Some(SubsetInfo(outputs)) = subset_info {
                            h.write_all(b"ss").unwrap();
                            for output in &outputs {
                                h.write_all(output.as_bytes()).unwrap();
                                h.write_all(b",").unwrap();
                            }
                            h.write_all(b"l").unwrap(); // TODO: Remove the next time we break spec-hash values
                        }
                    }
                    ReplaceOnCycle(r_idx) => {
                        h.write_all(b"c").unwrap();
                        h.write_all(&r_idx.0.to_le_bytes()).unwrap();
                    }
                }
            }
        }

        SpecHash(h.finalize())
    }

    fn process(&mut self, bsr: &BuildSpecRef) -> SpecIndex {
        if let Some(idx) = self.spec_idx.get(bsr) {
            return *idx;
        }
        let build = self.graph.get(bsr).unwrap();

        // allocate a spot in the specs array, remember our index
        let idx = SpecIndex(self.specs.len());
        self.specs.push((*bsr, None));
        self.spec_idx.insert(*bsr, idx);

        // recurse in a well-defined order to capture referenced specs.
        let mut edges = Edges::new();
        for (bsr, subset_info) in build.inputs.iter().filter_map(|i| match i {
            BuildSpecInput::Build(bsr) => Some((bsr, None)),
            BuildSpecInput::Subset(si) => Some((&si.from, Some(SubsetInfo(si.outputs.clone())))),
            _ => None,
        }) {
            edges.push(Edge::BuildInput(self.process(bsr), subset_info));
        }
        for d in build.runtime_deps.iter() {
            match d {
                RuntimeDep::Build(bsr) => edges.push(Edge::RuntimeDep(self.process(bsr), None)),
                RuntimeDep::Subset(si) => edges.push(Edge::RuntimeDep(
                    self.process(&si.from),
                    Some(SubsetInfo(si.outputs.clone())),
                )),
            }
        }
        if let Some(replace_on_cycle) = build.replace_on_cycle.as_ref() {
            edges.push(Edge::ReplaceOnCycle(self.process(replace_on_cycle)));
        }

        // update our spot in the specs array with the data
        self.specs[idx.0].1 = Some(edges);

        idx
    }
}

fn build_output_hash(output: &BuildOutput, h: &mut Hasher) {
    use BuildOutput::*;
    match output {
        Library { glob } => {
            h.write_all(b"lib").unwrap();
            h.write_all(glob.as_bytes()).unwrap();
        }
        Data { glob } => {
            h.write_all(b"data").unwrap();
            h.write_all(glob.as_bytes()).unwrap();
        }
        Binary { glob } => {
            h.write_all(b"bin").unwrap();
            h.write_all(glob.as_bytes()).unwrap();
        }
    }
}

fn build_input_hash(input: &BuildSpecInput, h: &mut Hasher) {
    use BuildSpecInput::*;
    match input {
        Build(_) | Subset(_) => {
            unreachable!();
        }
        Source(s) => {
            h.write_all(b"src").unwrap();
            match &s.from {
                SourceFetch::URL(url) => {
                    h.write_all(b"url").unwrap();
                    h.write_all(url.as_bytes()).unwrap()
                }
            };
            h.write_all(s.sha256.as_bytes()).unwrap();
            if s.extract {
                h.write_all(b"ext").unwrap();
            }
            if let Some(prefix) = &s.strip_prefix {
                h.write_all(b"strip_prefix").unwrap();
                h.write_all(prefix.as_bytes()).unwrap();
            }
        }
        HostPath(p) => {
            h.write_all(b"host path").unwrap();
            h.write_all(p.as_path().to_string_lossy().as_bytes())
                .unwrap();
        }
        Local {
            full_path: _,
            filename,
            file_hash,
        } => {
            h.write_all(b"local").unwrap();
            h.write_all(filename.as_bytes()).unwrap();
            h.write_all(file_hash.as_bytes()).unwrap();
        }
        Prebuilt(package, sha256) => {
            h.write_all(b"prebuilt").unwrap();
            h.write_all(package.as_bytes()).unwrap();
            if let Some(hash) = sha256 {
                h.write_all(b"sha256").unwrap();
                h.write_all(hash.as_bytes()).unwrap();
            }
        }
    }
}

// NB: 'attrs' in this context means the fields of the build, not
// literally attributes defined on the build (those are not part of the hash).
fn build_attrs_hash(spec: &BuildSpec, h: &mut Hasher) {
    h.write_all(b"build spec").unwrap();
    h.write_all(spec.name.as_bytes()).unwrap();
    h.write_all(spec.cmd.as_bytes()).unwrap();
    if let Some(build_args) = &spec.build_args {
        if !build_args.is_empty() {
            h.write_all(b"-build args").unwrap();
            for (name, value) in build_args.iter() {
                h.write_all(b"k").unwrap();
                h.write_all(name.as_bytes()).unwrap();
                h.write_all(b"v").unwrap();
                h.write_all(value.as_bytes()).unwrap();
            }
        }
    }

    h.write_all(b"-inputs").unwrap();
    spec.inputs
        .iter()
        .filter(|i| i.as_build().is_none())
        .for_each(|i| build_input_hash(i, h));

    h.write_all(b"-outputs").unwrap();
    for (name, output) in spec.outputs.iter() {
        h.write_all(name.as_bytes()).unwrap();
        build_output_hash(output, h);
    }

    if spec.target != Target::new(target::Arch::Amd64, target::OS::Linux) {
        h.write_all(b"-target").unwrap();
        spec.target.hash_to(h);
    }

    if !spec.abstract_deps.is_empty() {
        h.write_all(b"-needs").unwrap();
        for (name, v) in spec.abstract_deps.iter() {
            h.write_all(b"k").unwrap();
            h.write_all(name.as_bytes()).unwrap();
            h.write_all(b"v").unwrap();
            build_attrvalue_hash(v, h);
        }
    }
}

fn build_attrvalue_hash(v: &AttrValue, h: &mut Hasher) {
    match v {
        AttrValue::Bool(b) => {
            h.write_all(b"b").unwrap();
            h.write_all(if *b { b"1" } else { b"0" }).unwrap();
        }
        AttrValue::String(s) => {
            h.write_all(b"s").unwrap();
            h.write_all(s.as_bytes()).unwrap();
        }

        AttrValue::List(v) => {
            h.write_all(b"v").unwrap();
            if !v.is_empty() {
                v.iter().for_each(|av| build_attrvalue_hash(av, h));
            }
        }
        AttrValue::Map(m) => {
            h.write_all(b"m").unwrap();
            if !m.is_empty() {
                m.iter().for_each(|(k, av)| {
                    h.write_all(k.as_bytes()).unwrap();
                    build_attrvalue_hash(av, h);
                });
            }
        }
    }
}

/// Computes the [SpecHash] for a subset.
pub struct SubsetHasher;

impl SubsetHasher {
    /// Computs the [SpecHash] of a subset of outputs from the given [BuildSpecRef].
    pub fn hash_single<'a, S: Into<String>>(
        graph: &'a DepGraph,
        bsr: &'a BuildSpecRef,
        outputs: Vec<S>,
    ) -> SpecHash {
        let build = graph.get(bsr).unwrap();
        let outputs: Vec<_> = outputs.into_iter().map(|s| s.into()).collect();
        for output in outputs.iter() {
            if build.outputs.get(output).is_none() {
                panic!(
                    "consistency check: cannot form subset over non-existent output {}",
                    output
                );
            }
        }

        let subset_spec = SubsetSpec::new_single(&graph.spec_hash(bsr), outputs);
        Self::hash(&subset_spec)
    }

    /// Computs the [SpecHash] of the given [SubsetSpec].
    pub fn hash(subset_spec: &SubsetSpec) -> SpecHash {
        let mut h = Hasher::new();
        h.write_all(b"subset").unwrap();
        for (spec, sorted_outputs) in subset_spec.iter_components() {
            h.write_all(spec.as_bytes()).unwrap();
            for output in sorted_outputs {
                h.write_all(b"-output").unwrap();
                h.write_all(output.as_bytes()).unwrap();
            }
        }

        SpecHash(h.finalize())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use decode::Layer;
    use indoc::indoc;

    #[test]
    fn attrs_hash() {
        let layer = Layer::new_for_test(
            indoc! {
                "
                let {BuildSpec, HostPath, Source, Prebuilt, OutputLib, OutputBin, OutputData, ..} = import \"minimal.ncl\" in
                {
                    name = \"single buildspec\",
                    inputs = [
                        {url = \"http://uwu.com\", sha256 = \"abcdef\"} | Source,
                        {package = \"uwu\"} | Prebuilt,
                        {path = \"/\"} | HostPath,
                    ],
                    outputs = {
                        something = { glob = \"/usr/lib/something.*.so\" } | OutputLib,
                        uwu_tool = { glob = \"/bin/uwu\" } | OutputBin,
                        some_data = { glob = \"/data/locale/*\"  } | OutputData,
                    },
                    cmd = \"something\",
                } | BuildSpec"
            }
            .to_string(),
        )
        .unwrap_or_else(|e| {
            e.report_to_stderr();
            panic!("spec parsing failed");
        });

        let dp = DepGraph::new().ingest(layer).unwrap();

        // println!("{}", SpecHasher::hash(&dp, &dp.top_levels[0]).0.to_hex());
        assert_eq!(
            SpecHasher::hash(&dp, &dp.top_levels[0]),
            SpecHash::from_hex("48d0229ccc7973402752c4a62a5d09875c5db3c426d31655520710626340a4b8")
                .unwrap(),
        );
    }

    #[test]
    fn abstract_deps_hashed() {
        let layer = Layer::new_for_test(
            indoc! {
                "
                let {Needs, BuildSpec, ..} = import \"minimal.ncl\" in
                {
                    name = \"single buildspec\",
                    inputs = [],
                    cmd = \"something\",
                    needs = {
                        dns = {},
                    } | Needs,
                } | BuildSpec"
            }
            .to_string(),
        )
        .unwrap_or_else(|e| {
            e.report_to_stderr();
            panic!("spec parsing failed");
        });

        let dp = DepGraph::new().ingest(layer).unwrap();

        assert_eq!(
            SpecHasher::hash(&dp, &dp.top_levels[0]),
            SpecHash::from_hex("619459fa530bedc77f035ab942ef45e8e08a9f10407333a64a2e0367869fb197")
                .unwrap(),
        );

        assert_ne!(SpecHasher::hash(&dp, &dp.top_levels[0]), {
            // Identical except without setting needs
            let layer = Layer::new_for_test(
                indoc! {
                    "
                        let {Needs, BuildSpec, ..} = import \"minimal.ncl\" in
                        {
                            name = \"single buildspec\",
                            inputs = [],
                            cmd = \"something\",
                        } | BuildSpec"
                }
                .to_string(),
            )
            .unwrap_or_else(|e| {
                e.report_to_stderr();
                panic!("spec parsing failed");
            });
            let dp = DepGraph::new().ingest(layer).unwrap();
            SpecHasher::hash(&dp, &dp.top_levels[0])
        });
    }

    #[test]
    fn spec_tree() {
        let layer = Layer::new_for_test(
            indoc! {
                "
                let {BuildSpec, Source, OutputLib, OutputBin, OutputData, ..} = import \"minimal.ncl\" in
                {
                    name = \"top\",
                    inputs = [
                        {url = \"http://uwu.com\", sha256 = \"abcdef\"} | Source,
                        {
                            name = \"nested input\",
                            inputs = [],
                            cmd = \"\",
                        } | BuildSpec
                    ],
                    runtime_deps = [
                        {
                            name = \"nested runtime dep\",
                            inputs = [],
                            cmd = \"\",
                        } | BuildSpec
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

        let dp = DepGraph::new().ingest(layer).unwrap();

        // println!("{}", SpecHasher::hash(&dp, &dp.top_levels[0]).0.to_hex());
        assert_eq!(
            SpecHasher::hash(&dp, &dp.top_levels[0]),
            SpecHash::from_hex("f804bd63f9f0f86e675561d73c72c3e76feaae4d874b9c5ab730def9c5d822f3")
                .unwrap(),
        );
    }

    #[test]
    fn cycle() {
        let layer = Layer::new_for_test(
            indoc! {
                "
                let {BuildSpec, Source, ..} = import \"minimal.ncl\" in

                let rec b1 = {
                    name = \"b1\",
                    inputs = [
                        b2,
                    ],
                    cmd = \"\",
                } | BuildSpec,
                b2 = {
                    name = \"b2\",
                    inputs = [
                        b1,
                    ],
                    cmd = \"\",
                } | BuildSpec,
                in
                b1
                "
            }
            .to_string(),
        )
        .unwrap_or_else(|e| {
            e.report_to_stderr();
            panic!("spec parsing failed");
        });

        let dp = DepGraph::new().ingest(layer).unwrap();

        // println!("{}", SpecHasher::hash(&dp, &dp.top_levels[0]).0.to_hex());
        assert_eq!(
            SpecHasher::hash(&dp, &dp.top_levels[0]),
            SpecHash::from_hex("e9bc6fb92d25f8c86d83a132d7bc5121a4571a7117554cf59169d2010a695e86")
                .unwrap(),
        );
    }

    #[test]
    fn subset_hash() {
        let layer = Layer::new_for_test(
            indoc! {
                "
                let {BuildSpec, HostPath, Source, Prebuilt, OutputLib, OutputBin, OutputData, ..} = import \"minimal.ncl\" in
                {
                    name = \"single buildspec\",
                    inputs = [
                        {url = \"http://uwu.com\", sha256 = \"abcdef\"} | Source,
                        {package = \"uwu\"} | Prebuilt,
                        {path = \"/\"} | HostPath,
                    ],
                    outputs = {
                        something = { glob = \"/usr/lib/something.*.so\" } | OutputLib,
                        uwu_tool = { glob = \"/bin/uwu\" } | OutputBin,
                        some_data = { glob = \"/data/locale/*\"  } | OutputData,
                    },
                    cmd = \"something\",
                } | BuildSpec"
            }
            .to_string(),
        )
        .unwrap_or_else(|e| {
            e.report_to_stderr();
            panic!("spec parsing failed");
        });

        let dp = DepGraph::new().ingest(layer).unwrap();

        // println!("{}", SpecHasher::hash(&dp, &dp.top_levels[0]).0.to_hex());
        assert_eq!(
            SubsetHasher::hash_single(&dp, &dp.top_levels[0], vec!["uwu_tool", "something"]),
            SpecHash::from_hex("23d6c828d07f1572f7d8ec315c0a0fb92b00079d290692358cefad45b4b51cc5")
                .unwrap(),
        );
    }
}
