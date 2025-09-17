use crate::{
    dep_graph::SourceFetch, BuildOutput, BuildSpec, BuildSpecInput, BuildSpecRef, DepGraph,
    SpecHash,
};
use blake3::Hasher;
use smallvec::SmallVec;
use std::collections::HashMap;
use std::io::Write;

type Edges = SmallVec<[Edge; 12]>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SpecIndex(usize);

#[derive(Debug, Clone, PartialEq, Eq)]
enum Edge {
    BuildInput(SpecIndex),
    RuntimeDep(SpecIndex),
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
                    BuildInput(input_idx) => {
                        h.write_all(b"i").unwrap();
                        h.write_all(&input_idx.0.to_le_bytes()).unwrap();
                    }
                    RuntimeDep(dep_idx) => {
                        h.write_all(b"r").unwrap();
                        h.write_all(&dep_idx.0.to_le_bytes()).unwrap();
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
        for i in build.inputs.iter().filter_map(|i| i.as_build()) {
            edges.push(Edge::BuildInput(self.process(i)));
        }
        for d in build.runtime_deps.iter() {
            edges.push(Edge::RuntimeDep(self.process(d)));
        }
        if let Some(replace_on_cycle) = build.replace_on_cycle.as_ref() {
            edges.push(Edge::ReplaceOnCycle(self.process(replace_on_cycle)));
        }

        // update our spot in the specs array with the data
        self.specs[idx.0].1 = Some(edges);

        idx
    }
}

#[allow(dead_code)]
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
        Binary { path } => {
            h.write_all(b"bin").unwrap();
            h.write_all(path.as_bytes()).unwrap();
        }
    }
}

#[allow(dead_code)]
fn build_input_hash(input: &BuildSpecInput, h: &mut Hasher) {
    use BuildSpecInput::*;
    match input {
        Build(_bsr) => {
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
            h.write_all(s.sha256.as_bytes()).unwrap()
        }
        HostPath(p) => {
            h.write_all(b"host path").unwrap();
            h.write_all(p.as_path().to_string_lossy().as_bytes())
                .unwrap();
        }
        Local(p) => {
            h.write_all(b"local").unwrap();
            h.write_all(p.0.as_path().to_string_lossy().as_bytes())
                .unwrap();
            h.write_all(p.1.as_bytes()).unwrap();
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

#[allow(dead_code)]
fn build_attrs_hash(spec: &BuildSpec, h: &mut Hasher) {
    h.write_all(b"build spec").unwrap();
    h.write_all(spec.name.as_bytes()).unwrap();
    h.write_all(spec.cmd.as_bytes()).unwrap();

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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SpecReader, SpecReaderOptions};
    use indoc::indoc;

    #[test]
    fn attrs_hash() {
        let sr = SpecReader::new(
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
                        uwu_tool = { path = \"/bin/uwu\" } | OutputBin,
                        some_data = { data = \"/data/locale/*\"  } | OutputData,
                    },
                    cmd = \"something\",
                } | BuildSpec"
            }
            .to_string(),
            &SpecReaderOptions::for_test(),
        )
        .unwrap_or_else(|e| {
            e.report_to_stderr();
            panic!("spec parsing failed");
        });

        let dp = DepGraph::new(sr).unwrap();

        // println!("{}", SpecHasher::hash(&dp, &dp.top_levels[0]).0.to_hex());
        assert_eq!(
            SpecHasher::hash(&dp, &dp.top_levels[0]),
            SpecHash::from_hex("48d0229ccc7973402752c4a62a5d09875c5db3c426d31655520710626340a4b8")
                .unwrap(),
        );
    }

    #[test]
    fn spec_tree() {
        let sr = SpecReader::new(
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
            &SpecReaderOptions::for_test(),
        )
        .unwrap_or_else(|e| {
            e.report_to_stderr();
            panic!("spec parsing failed");
        });

        let dp = DepGraph::new(sr).unwrap();

        // println!("{}", SpecHasher::hash(&dp, &dp.top_levels[0]).0.to_hex());
        assert_eq!(
            SpecHasher::hash(&dp, &dp.top_levels[0]),
            SpecHash::from_hex("f804bd63f9f0f86e675561d73c72c3e76feaae4d874b9c5ab730def9c5d822f3")
                .unwrap(),
        );
    }

    #[test]
    fn cycle() {
        let sr = SpecReader::new(
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
            &SpecReaderOptions::for_test(),
        )
        .unwrap_or_else(|e| {
            e.report_to_stderr();
            panic!("spec parsing failed");
        });

        let dp = DepGraph::new(sr).unwrap();

        // println!("{}", SpecHasher::hash(&dp, &dp.top_levels[0]).0.to_hex());
        assert_eq!(
            SpecHasher::hash(&dp, &dp.top_levels[0]),
            SpecHash::from_hex("e9bc6fb92d25f8c86d83a132d7bc5121a4571a7117554cf59169d2010a695e86")
                .unwrap(),
        );
    }
}
