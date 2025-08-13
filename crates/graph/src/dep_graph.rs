//! The machinery for processing build specs into a dependency graph.

#![allow(clippy::result_large_err)]

use nickel_lang_core::position::TermPos;
use nickel_lang_core::term::{RichTerm, SharedTerm, Term};

use crate::term_hasher::TermHasher;
use generational_arena::Arena;
use std::collections::HashMap;
use std::io::Write;
use std::path::PathBuf;

use crate::{Error, SpecReader};

use crate::spec_schema::*;
use serde::Deserialize;

/// A map with ordered iteration semantics - we need this for stable spec hashes.
type OutputMap = nickel_lang_core::term::IndexMap<String, BuildOutput>;

/// A reference to some other [BuildSpec] in a [DepGraph].
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
pub struct BuildSpecRef(pub(crate) generational_arena::Index);

/// A description of pulling source code regardless of form.
#[derive(Debug, Clone, PartialEq)]
pub enum SourceFetch {
    URL(String),
}

/// A description of source code thats used as an input.
#[derive(Debug, Clone, PartialEq)]
pub struct SourceInput {
    from: SourceFetch,
    sha256: String,
}

/// An input to a build spec.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum BuildSpecInput {
    Build(BuildSpecRef),
    Source(SourceInput),
    Path(PathBuf),
}

impl crate::SpecHash for BuildSpecInput {
    fn spec_hash(&self, g: &DepGraph) -> blake3::Hash {
        let mut h = blake3::Hasher::new();

        use BuildSpecInput::*;
        match self {
            Build(bsr) => {
                h.write_all(b"input").unwrap();
                h.write_all(g.builds.get(bsr.0).unwrap().spec_hash(g).as_bytes())
                    .unwrap();
            }
            Source(s) => {
                h.write_all(b"source").unwrap();
                match &s.from {
                    SourceFetch::URL(url) => {
                        h.write_all(b"url").unwrap();
                        h.write_all(url.as_bytes()).unwrap()
                    }
                };
                h.write_all(s.sha256.as_bytes()).unwrap()
            }
            Path(p) => {
                h.write_all(b"library").unwrap();
                h.write_all(p.as_path().to_string_lossy().as_bytes())
                    .unwrap();
            }
        }

        h.finalize()
    }
}

/// An output from a build.
#[derive(Debug, Clone, PartialEq)]
#[allow(dead_code)]
pub enum BuildOutput {
    Library { glob: String },
    Binary { path: String },
}

impl BuildOutput {
    #[allow(dead_code)]
    fn partial_spec_hash(&self, h: &mut blake3::Hasher) {
        use BuildOutput::*;
        match self {
            Library { glob } => {
                h.write_all(b"library").unwrap();
                h.write_all(glob.as_bytes()).unwrap();
            }
            Binary { path } => {
                h.write_all(b"binary").unwrap();
                h.write_all(path.as_bytes()).unwrap();
            }
        }
    }
}

/// Some task or build in the dependency graph.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct BuildSpec {
    pub name: String,
    pub cmd: String,

    pub inputs: Vec<BuildSpecInput>,
    pub outputs: OutputMap,
}

impl crate::SpecHash for BuildSpec {
    fn spec_hash(&self, g: &DepGraph) -> blake3::Hash {
        let mut h = blake3::Hasher::new();

        h.write_all(b"build spec").unwrap();
        h.write_all(self.name.as_bytes()).unwrap();
        h.write_all(self.cmd.as_bytes()).unwrap();

        // We don't want the spec hash to change if the order of the inputs change, so lets sort
        // the hashes before they are updated to our spec hash.
        // TODO: Consider performance implications of linear sort
        let mut input_hashes: Vec<blake3::Hash> =
            self.inputs.iter().map(|i| i.spec_hash(g)).collect();
        input_hashes.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
        for hash in input_hashes.drain(..) {
            h.write_all(hash.as_bytes()).unwrap();
        }

        for (name, output) in self.outputs.iter() {
            h.write_all(name.as_bytes()).unwrap();
            output.partial_spec_hash(&mut h);
        }

        h.finalize()
    }
}

/// The dependency graph.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct DepGraph {
    pub builds: Arena<BuildSpec>,
    pub top_level: BuildSpecRef,
}

impl DepGraph {
    pub fn new(sr: SpecReader) -> Result<Self, Error> {
        let mut graph = GraphBuilder {
            builds: Arena::with_capacity(4096),
            term_lookup: HashMap::with_capacity(4096),
            hash_lookup: HashMap::with_capacity(4096),
            term_hasher: TermHasher::new(),
        };

        let top_level = graph.read_buildspec(&sr.finish()?)?;
        Ok(graph.finish(top_level))
    }
    pub fn get(&self, bsr: &BuildSpecRef) -> Option<&BuildSpec> {
        self.builds.get(bsr.0)
    }

    /// Returns the unique set of transitive build-spec dependencies of the given toplevel.
    pub fn transitive_specs_of(&self, toplevel: &BuildSpecRef) -> Vec<BuildSpecRef> {
        let mut seen: HashMap<BuildSpecRef, ()> = HashMap::with_capacity(self.builds.len());
        let mut reachable = Vec::with_capacity(self.builds.len());
        self.collect_transitive_buildspecs(toplevel, &mut seen, &mut reachable);

        reachable
    }

    fn collect_transitive_buildspecs(
        &self,
        bsr: &BuildSpecRef,
        seen: &mut HashMap<BuildSpecRef, ()>,
        reachable: &mut Vec<BuildSpecRef>,
    ) {
        let build_spec = self.get(bsr).unwrap();

        use BuildSpecInput::*;
        build_spec.inputs.iter().for_each(|input| match input {
            Build(bsr) => {
                if !seen.contains_key(bsr) {
                    seen.insert(bsr.clone(), ());
                    reachable.push(bsr.clone());
                    self.collect_transitive_buildspecs(bsr, seen, reachable);
                }
            }
            Source(_) | Path(_) => {}
        })
    }
}

/// A graph thats under construction.
#[allow(dead_code)]
struct GraphBuilder {
    builds: Arena<BuildSpec>,

    // Fast path for nickel records representing buildspecs we have already seen.
    //  - Key: Position the record was defined + name of buildspec.
    //  - Value: Unique records we have seen with that key, and the referenced to their
    //    already-processed BuildSpec.
    term_lookup: HashMap<(TermPos, String), Vec<(SharedTerm, BuildSpecRef)>>,

    // Medium-fast path: Buildspecs with identical nickel records (by hash) + same buildspec name.
    hash_lookup: HashMap<(String, u64), BuildSpecRef>,
    term_hasher: TermHasher,
}

impl GraphBuilder {
    fn finish(self, top_level: BuildSpecRef) -> DepGraph {
        let Self { builds, .. } = self;
        DepGraph { builds, top_level }
    }

    /// Recursively processes and inserts a buildspec into the graph, returning
    /// a handle to it in the build graph.
    fn read_buildspec(&mut self, rt: &RichTerm) -> Result<BuildSpecRef, Error> {
        // Read out the simple attributes
        let base = ObjBaseBuildSpec::deserialize(rt.clone()).unwrap();
        if base.ty != ObjTy::Builder {
            return Err(Error::UnexpectedObject {
                got: base.ty,
                want: ObjTy::Builder,
                pos: rt.pos,
            });
        }

        // Fast path: this declaration has already been processed, as the recursive dep
        // of another spec somewhere else. Lets short-circuit and wire up to its previously-processed
        // reference.
        // TODO: Can we remove the clone
        if let Some(existing_refs) = self.term_lookup.get(&(rt.pos, base.name.clone())) {
            // See if any of these builds are for the same nickel record
            for (ncl_term, bsr) in existing_refs.iter() {
                if SharedTerm::ptr_eq(&rt.term, ncl_term) {
                    return Ok(*bsr);
                }
            }
        }

        let record_hash = self.term_hasher.hash(&rt.term);
        // Medium-fast path: Theres a buildspec with the same name + built from an identical record.
        if let Some(bsr) = self.hash_lookup.get(&(base.name.clone(), record_hash)) {
            return Ok(*bsr);
        }

        // Start constructing the BuildSpec object
        let mut bs = BuildSpec {
            name: base.name,
            cmd: base.cmd,
            inputs: Vec::new(),
            outputs: OutputMap::new(),
        };

        // More complicated processing (recursing) requires explicitly iterating the record.
        match rt.term.as_ref() {
            Term::Record(r) => {
                r.fields
                    .iter()
                    .for_each(|(ident_and_loc, field)| match ident_and_loc.label() {
                        "inputs" => {
                            if let Term::Array(a, _attrs) =
                                field.value.as_ref().unwrap().term.as_ref()
                            {
                                bs.inputs = a
                                    .iter()
                                    .map(|input| self.read_input(input).unwrap())
                                    .collect();
                            } else {
                                todo!("handle value being non-array {:?}", field.value);
                            };
                        }
                        "outputs" => {
                            if let Term::Record(r) = field.value.as_ref().unwrap().term.as_ref() {
                                bs.outputs = r
                                    .iter_serializable()
                                    .map(|entry| entry.unwrap())
                                    .map(|(ident, val)| {
                                        (
                                            ident.label().to_string(),
                                            self.read_output_value(val).unwrap(),
                                        )
                                    })
                                    .collect();
                            } else {
                                todo!("handle value being non-dict {:?}", field.value);
                            };
                        }
                        _ => (),
                    });
            }
            _ => panic!("unexpected type: want Record, got {:?}", rt.term),
        }

        // [OutputMap] has a defined iteration order. For stable hashes, sort this by key.
        bs.outputs.sort_by(|k1, _v1, k2, _v2| String::cmp(k1, k2));

        let name = bs.name.clone();
        let lookup_key = (rt.pos, bs.name.clone());
        let bsr = BuildSpecRef(self.builds.insert(bs));

        // Insert into our caches.
        if let Some(exists) = self.term_lookup.get_mut(&lookup_key) {
            exists.push((rt.term.clone(), bsr));
        } else {
            self.term_lookup
                .insert(lookup_key, vec![(rt.term.clone(), bsr)]);
        }
        self.hash_lookup.insert((name, record_hash), bsr);
        Ok(bsr)
    }

    /// Recursively reads a buildspec input, inserting it into the graph.
    fn read_input(&mut self, rt: &RichTerm) -> Result<BuildSpecInput, Error> {
        let obj = OnlyObj::deserialize(rt.clone()).unwrap();

        // The type hint ty identifies which input variant this term represents
        match obj.ty {
            ObjTy::Builder => Ok(BuildSpecInput::Build(self.read_buildspec(rt)?)),
            ObjTy::Source => {
                let src = ObjSource::deserialize(rt.clone()).unwrap();
                Ok(BuildSpecInput::Source(SourceInput {
                    from: SourceFetch::URL(src.url),
                    sha256: src.sha256,
                }))
            }
            ObjTy::Path => {
                let host_path = ObjHostPath::deserialize(rt.clone()).unwrap();
                Ok(BuildSpecInput::Path(host_path.path.into()))
            }
            ObjTy::OutputLib | ObjTy::OutputBin => Err(Error::UnexpectedObject {
                got: obj.ty,
                want: ObjTy::Builder,
                pos: rt.pos,
            }),
        }
    }

    /// Recursively reads a buildspec output value, inserting it into the graph.
    fn read_output_value(&mut self, rt: &RichTerm) -> Result<BuildOutput, Error> {
        let obj = OnlyObj::deserialize(rt.clone()).unwrap();

        match obj.ty {
            ObjTy::OutputLib => {
                let lib = ObjLibraryOutput::deserialize(rt.clone()).unwrap();
                Ok(BuildOutput::Library { glob: lib.glob })
            }
            ObjTy::OutputBin => {
                let bin = ObjBinaryOutput::deserialize(rt.clone()).unwrap();
                Ok(BuildOutput::Binary { path: bin.path })
            }
            _ => Err(Error::UnexpectedObject {
                got: obj.ty,
                want: ObjTy::OutputLib,
                pos: rt.pos,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SpecReaderOptions;
    use indoc::indoc;

    #[test]
    fn single() {
        let sr = SpecReader::new(
            indoc! {
                "
                let {BuildSpec, HostPath, OutputLib, ..} = import \"minimal.ncl\" in
                {
        			name = \"single buildspec\",
        			inputs = [
                        {path = \"/\"} | HostPath,
                    ],
                    outputs = {
                        something = { glob = \"/usr/lib/something.*.so\" } | OutputLib,
                    },
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

        let dp = DepGraph::new(sr).unwrap();
        // We expect a single buildspec with a known name
        assert_eq!(
            vec!["single buildspec".to_string()],
            dp.builds
                .iter()
                .map(|b| b.1.name.clone())
                .collect::<Vec<String>>()
        );
        // We expect that buildspec to have one HostPath input
        assert!(matches!(
            dp.builds.iter().next().unwrap().1.inputs[0],
            BuildSpecInput::Path(_)
        ));
    }

    #[test]
    fn source_input() {
        let sr = SpecReader::new(
            indoc! {
                "
                let {BuildSpec, HostPath, OutputLib, Source, ..} = import \"minimal.ncl\" in
                {
                    name = \"single buildspec\",
                    inputs = [
                        {url = \"http://uwu.com\", sha256 = \"abcdef\"} | Source,
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

        let dp = DepGraph::new(sr).unwrap();
        // We expect that buildspec to have one Source input
        assert!(matches!(
            dp.builds.iter().next().unwrap().1.inputs[0].clone(),
            BuildSpecInput::Source(SourceInput {
                from: SourceFetch::URL(url),
                sha256: sha,
            }) if url == "http://uwu.com" && sha == "abcdef",
        ));
    }

    #[test]
    fn outputs() {
        let sr = SpecReader::new(
            indoc! {
                "
                let {BuildSpec, HostPath, OutputLib, OutputBin, Source, ..} = import \"minimal.ncl\" in
                {
                    name = \"single buildspec\",
                    inputs = [
                        {url = \"http://uwu.com\", sha256 = \"abcdef\"} | Source,
                    ],
                    outputs = {
                        something = { glob = \"/usr/lib/something.*.so\" } | OutputLib,
                        uwu_tool = { path = \"/bin/uwu\" } | OutputBin,
                    },
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

        let dp = DepGraph::new(sr).unwrap();
        // We expect that buildspec to have one Library output
        assert_eq!(
            dp.builds.iter().next().unwrap().1.outputs["something"],
            BuildOutput::Library {
                glob: "/usr/lib/something.*.so".to_string()
            },
        );
        // We expect that buildspec to have one Binary output
        assert_eq!(
            dp.builds.iter().next().unwrap().1.outputs["uwu_tool"],
            BuildOutput::Binary {
                path: "/bin/uwu".to_string()
            },
        );
    }

    #[test]
    fn one_nested() {
        let sr = SpecReader::new(
            indoc! {
                "
                let {BuildSpec, ..} = import \"minimal.ncl\" in
                {
        			name = \"top build\",
        			inputs = [
						{
		        			name = \"nested build\",
		        			inputs = [],
		        			cmd = \"\",
		        		} | BuildSpec
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

        let dp = DepGraph::new(sr).unwrap();
        // We expect two buildspecs - deeper first
        assert_eq!(
            vec!["nested build".to_string(), "top build".to_string()],
            dp.builds
                .into_iter()
                .map(|b| b.name)
                .collect::<Vec<String>>()
        );
    }

    #[test]
    fn shared_spec_not_duplicated() {
        let sr = SpecReader::new(
            indoc! {
                "
                let {BuildSpec, ..} = import \"minimal.ncl\" in

                let shared = {
        			name = \"sharing is caringgggg\",
        			inputs = [],
        			cmd = \"\",
        		} | BuildSpec
        		in

                {
        			name = \"top build\",
        			inputs = [
						{
		        			name = \"nested build\",
		        			inputs = [shared],
		        			cmd = \"\",
		        		} | BuildSpec,
		        		shared,
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

        let dp = DepGraph::new(sr).unwrap();
        // We expect three buildspecs - four buildspecs would mean that `shared` (referenced twice) was duplicated
        assert_eq!(
            vec![
                "sharing is caringgggg".to_string(),
                "nested build".to_string(),
                "top build".to_string()
            ],
            dp.builds
                .into_iter()
                .map(|b| b.name)
                .collect::<Vec<String>>()
        );
    }

    #[test]
    fn computed_spec_not_shared() {
        let sr = SpecReader::new(
            indoc! {
                "
                let {BuildSpec, ..} = import \"minimal.ncl\" in

                let shared = {
                    name = \"shared\",
                    inputs = [],
                    cmd = \"\",
                } | BuildSpec
                in

                let make_build : Number -> BuildSpec
                    = fun num =>
                        {
                            name = \"build-\" ++ \"%{num}\",
                            inputs = [shared],
                            cmd = \"\",
                        } | BuildSpec
                in

                {
                    name = \"top build\",
                    inputs = [
                        make_build 1,
                        make_build 2,
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

        let dp = DepGraph::new(sr).unwrap();
        // We expect four buildspecs - the two that were generated in a function are not the same despite being
        // inherited from the same record.
        assert_eq!(
            vec![
                "shared".to_string(),
                "build-1".to_string(),
                "build-2".to_string(),
                "top build".to_string()
            ],
            dp.builds
                .into_iter()
                .map(|b| b.name)
                .collect::<Vec<String>>()
        );
    }

    #[test]
    fn spec_hash_smoketest() {
        let sr = SpecReader::new(
            indoc! {
                "
                let {BuildSpec, Source, ..} = import \"minimal.ncl\" in

                let shared = {
                    name = \"shared\",
                    inputs = [
                        {url = \"http://uwu.com\", sha256 = \"abcdef\"} | Source,
                    ],
                    cmd = \"\",
                } | BuildSpec
                in

                {
                    name = \"top build\",
                    inputs = [
                        shared,
                        {
                            name = \"second build\",
                            inputs = [],
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

        let mut dp = DepGraph::new(sr).unwrap();

        use crate::SpecHash;
        let top_hash = dp
            .builds
            .iter()
            .find(|b| b.1.name == "top build")
            .unwrap()
            .1
            .spec_hash(&dp);

        {
            let (mut input1, mut input2) = dp
                .builds
                .iter_mut()
                .find(|b| b.1.name == "top build")
                .unwrap()
                .1
                .inputs
                .split_at_mut(1);
            std::mem::swap(&mut input1, &mut input2);
        }

        // check the spec hash is the same even if the input order changes
        assert_eq!(
            top_hash,
            dp.builds
                .iter()
                .find(|b| b.1.name == "top build")
                .unwrap()
                .1
                .spec_hash(&dp),
        );
    }

    #[test]
    fn transitive_specs_of() {
        let sr = SpecReader::new(
            indoc! {
                "
                let {BuildSpec, Source, ..} = import \"minimal.ncl\" in

                let shared = {
                    name = \"shared\",
                    inputs = [
                        {url = \"http://uwu.com\", sha256 = \"abcdef\"} | Source,
                    ],
                    cmd = \"\",
                } | BuildSpec
                in

                {
                    name = \"top build\",
                    inputs = [
                        shared,
                        {
                            name = \"second build\",
                            inputs = [],
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

        let dp = DepGraph::new(sr).unwrap();
        assert_eq!(
            dp.transitive_specs_of(&dp.top_level),
            vec![
                BuildSpecRef(dp.builds.iter().find(|b| b.1.name == "shared").unwrap().0),
                BuildSpecRef(
                    dp.builds
                        .iter()
                        .find(|b| b.1.name == "second build")
                        .unwrap()
                        .0
                )
            ]
        );
    }
}
