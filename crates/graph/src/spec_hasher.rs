use crate::{
    BuildDep, BuildOutput, BuildSpec, BuildSpecRef, Graph, RuntimeDep, SourceFetch, SpecHash,
};
use blake3::Hasher;
use common::{SubsetSpec, Target, target};
use decode::AttrValue;
use smallvec::SmallVec;
use std::collections::HashMap;
use std::io::Write;

type Edges = SmallVec<[Edge; 12]>;

/// The byte-encoding primitives the spec-hash serializer emits through.
///
/// This trait is the seam between two concerns that used to be interleaved:
/// - **traversal** — [`SpecHasher::process`] discovers every referenced spec
///   and assigns it a stable discovery index (unchanged by this split);
/// - **encoding** — turning each spec's fields and edges into the bytes fed to
///   Blake3, which now happens exclusively through this trait.
///
/// Isolating encoding behind one trait means a future hash format (the injective
/// redesign — length-prefixed framing, deps-as-sets) is a *new impl of this
/// trait*, selected at the call site, rather than edits threaded through the
/// walk. It also localizes the layer where the known non-injectivity lives
/// (unframed concatenation, in-band markers).
///
/// The method names carry semantic intent that today's [`LegacyEncoder`]
/// deliberately collapses — a structural `tag` and variable `bytes` are both raw
/// `write_all` in the legacy scheme — but a framed successor distinguishes (a
/// tag is fixed; content gets a length prefix). This split is **byte-for-byte
/// preserving**: the golden hash tests below pin concrete digests and are
/// unchanged.
trait SpecEncoder {
    /// A fixed structural marker (e.g. `b"src"`, `b"i"`, `b"-outputs"`).
    fn tag(&mut self, tag: &[u8]);
    /// Variable content (a name, glob, url, sha, ...).
    fn bytes(&mut self, bytes: &[u8]);
    /// A discovery/traversal index.
    fn index(&mut self, idx: usize);
    /// A hashed number (`AttrValue::Number`).
    fn number(&mut self, n: f64);
    /// The build target.
    fn target(&mut self, target: &Target);
    /// Consume the encoder and produce the digest.
    fn finish(self) -> SpecHash;
}

/// Epoch-0 encoder: byte-for-byte the historical scheme — raw concatenation,
/// in-band markers, platform-width little-endian indices.
///
/// **Do not change its output.** These bytes are the live cache keyspace
/// (~46k entries, sealed per-commit closures, signed catalogs). A new hash
/// format is a *sibling* `SpecEncoder` impl chosen at the call site, never an
/// edit to this one.
struct LegacyEncoder {
    h: Hasher,
}

impl LegacyEncoder {
    fn new() -> Self {
        Self { h: Hasher::new() }
    }
}

impl SpecEncoder for LegacyEncoder {
    fn tag(&mut self, tag: &[u8]) {
        self.h.write_all(tag).unwrap();
    }
    fn bytes(&mut self, bytes: &[u8]) {
        self.h.write_all(bytes).unwrap();
    }
    fn index(&mut self, idx: usize) {
        self.h.write_all(&idx.to_le_bytes()).unwrap();
    }
    fn number(&mut self, n: f64) {
        self.h.write_all(&n.to_le_bytes()).unwrap();
    }
    fn target(&mut self, target: &Target) {
        target.hash_to(&mut self.h);
    }
    fn finish(self) -> SpecHash {
        SpecHash(self.h.finalize())
    }
}

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
    graph: &'a Graph,
    specs: Vec<(BuildSpecRef, Option<Edges>)>,
    spec_idx: HashMap<BuildSpecRef, SpecIndex>,
}

impl<'a> SpecHasher<'a> {
    pub fn hash(graph: &'a Graph, bsr: &'a BuildSpecRef) -> SpecHash {
        let mut sh = SpecHasher {
            graph,
            specs: Vec::with_capacity(2048),
            spec_idx: HashMap::with_capacity(2048),
        };
        sh.process(bsr);
        sh.encode(LegacyEncoder::new())
    }

    /// The encoding pass: walk the specs discovered by [`Self::process`] in
    /// discovery order, emitting each spec's fields then its edges through
    /// `enc`. Pure over `self.specs` — contains no traversal. The hash *format*
    /// is entirely the choice of `enc`; swapping in a different [`SpecEncoder`]
    /// is the whole surface a future hash epoch touches here.
    fn encode<E: SpecEncoder>(self, mut enc: E) -> SpecHash {
        let SpecHasher { graph, specs, .. } = self;
        for (i, (bsr, edges)) in specs.into_iter().enumerate() {
            let build = graph.get(&bsr).unwrap();

            enc.index(i);
            build_attrs_hash(build, &mut enc);

            for edge in edges.unwrap().into_iter() {
                use Edge::*;
                match edge {
                    BuildInput(input_idx, subset_info) => {
                        enc.tag(b"i");
                        enc.index(input_idx.0);
                        encode_subset_info(subset_info.as_ref(), &mut enc);
                    }
                    RuntimeDep(dep_idx, subset_info) => {
                        enc.tag(b"r");
                        enc.index(dep_idx.0);
                        encode_subset_info(subset_info.as_ref(), &mut enc);
                    }
                    ReplaceOnCycle(r_idx) => {
                        enc.tag(b"c");
                        enc.index(r_idx.0);
                    }
                }
            }
        }

        enc.finish()
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
        for (bsr, subset_info) in build.build_deps.iter().filter_map(|i| match i {
            BuildDep::Build(bsr) => Some((bsr, None)),
            BuildDep::Subset(si) => Some((&si.from, Some(SubsetInfo(si.outputs.clone())))),
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

/// Emit a build/runtime edge's optional subset-output list. Factored from the
/// two byte-identical inline copies the edge encoding used to carry.
fn encode_subset_info<E: SpecEncoder>(subset_info: Option<&SubsetInfo>, enc: &mut E) {
    if let Some(SubsetInfo(outputs)) = subset_info {
        enc.tag(b"ss");
        for output in outputs {
            enc.bytes(output.as_bytes());
            enc.tag(b",");
        }
        enc.tag(b"l"); // TODO: Remove the next time we break spec-hash values
    }
}

fn build_output_hash<E: SpecEncoder>(output: &BuildOutput, enc: &mut E) {
    use BuildOutput::*;
    match output {
        Library { glob, allow_data } => {
            enc.tag(b"lib");
            enc.bytes(glob.as_bytes());
            if *allow_data {
                enc.tag(b"-allow_data");
            }
        }
        Data {
            glob,
            allow_executable,
        } => {
            enc.tag(b"data");
            enc.bytes(glob.as_bytes());
            if *allow_executable {
                enc.tag(b"-allow_exec");
            }
        }
        Binary {
            glob,
            allow_missing_interpreter,
        } => {
            enc.tag(b"bin");
            enc.bytes(glob.as_bytes());
            if *allow_missing_interpreter {
                enc.tag(b"-allow_missing_interp");
            }
        }
    }
}

fn build_input_hash<E: SpecEncoder>(input: &BuildDep, enc: &mut E) {
    use BuildDep::*;
    match input {
        Build(_) | Subset(_) => {
            unreachable!();
        }
        Source(s) => {
            enc.tag(b"src");
            match &s.from {
                SourceFetch::Web {
                    url,
                    sha256,
                    url_pos: _,
                    sha256_pos: _,
                } => {
                    enc.tag(b"url");
                    enc.bytes(url.as_bytes());
                    enc.bytes(sha256.as_bytes());
                }
                SourceFetch::Local {
                    filename,
                    file_hash,
                    full_path: _,
                } => {
                    enc.tag(b"local source");
                    enc.bytes(filename.as_bytes());
                    enc.bytes(file_hash.as_bytes());
                }
            };
            if s.extract {
                enc.tag(b"ext");
            }
            if let Some(prefix) = &s.strip_prefix {
                enc.tag(b"strip_prefix");
                enc.bytes(prefix.as_bytes());
            }
        }
        Local {
            full_path: _,
            filename,
            file_hash,
        } => {
            enc.tag(b"local");
            enc.bytes(filename.as_bytes());
            enc.bytes(file_hash.as_bytes());
        }
    }
}

// NB: 'attrs' in this context means the fields of the build, not
// literally attributes defined on the build (those are not part of the hash).
fn build_attrs_hash<E: SpecEncoder>(spec: &BuildSpec, enc: &mut E) {
    enc.tag(b"build spec");
    enc.bytes(spec.name.as_bytes());
    if spec.prebuilt {
        enc.tag(b"-prebuilt");
    }
    for cmd in &spec.cmds {
        cmd.iter().for_each(|e| enc.bytes(e.as_bytes()));
    }
    if let Some(build_args) = &spec.build_args
        && !build_args.is_empty()
    {
        enc.tag(b"-build args");
        for (name, value) in build_args.iter() {
            enc.tag(b"k");
            enc.bytes(name.as_bytes());
            enc.tag(b"v");
            enc.bytes(value.as_bytes());
        }
    }

    enc.tag(b"-inputs");
    // Build and Subset deps are hashed as edges (by index) in SpecHasher::encode,
    // not as inline inputs — build_input_hash treats both as `unreachable!()`.
    spec.build_deps
        .iter()
        .filter(|i| !matches!(i, BuildDep::Build(_) | BuildDep::Subset(_)))
        .for_each(|i| build_input_hash(i, enc));

    enc.tag(b"-outputs");
    for (name, output) in spec.outputs.iter() {
        enc.bytes(name.as_bytes());
        build_output_hash(output, enc);
    }

    if spec.target != Target::new(target::Arch::Amd64, target::OS::Linux) {
        enc.tag(b"-target");
        enc.target(&spec.target);
    }

    if !spec.abstract_deps.is_empty() {
        enc.tag(b"-needs");
        for (name, v) in spec.abstract_deps.iter() {
            enc.tag(b"k");
            enc.bytes(name.as_bytes());
            enc.tag(b"v");
            build_attrvalue_hash(v, enc);
        }
    }
}

fn build_attrvalue_hash<E: SpecEncoder>(v: &AttrValue, enc: &mut E) {
    match v {
        AttrValue::Bool(b) => {
            enc.tag(b"b");
            enc.tag(if *b { b"1" } else { b"0" });
        }
        AttrValue::String(s, _str_pos) => {
            enc.tag(b"s");
            enc.bytes(s.as_bytes());
        }
        AttrValue::Number(n) => {
            enc.tag(b"n");
            enc.number(*n);
        }

        AttrValue::List(v) => {
            enc.tag(b"v");
            if !v.is_empty() {
                v.iter().for_each(|av| build_attrvalue_hash(av, enc));
            }
        }
        AttrValue::Map(m) => {
            enc.tag(b"m");
            if !m.is_empty() {
                m.iter().for_each(|(k, av)| {
                    enc.bytes(k.as_bytes());
                    build_attrvalue_hash(av, enc);
                });
            }
        }
        AttrValue::EnumVariant(name, v) => {
            enc.tag(b"ev");
            enc.bytes(name.as_bytes());
            build_attrvalue_hash(v, enc);
        }
    }
}

/// Computes the [SpecHash] for a subset.
pub struct SubsetHasher;

impl SubsetHasher {
    /// Computs the [SpecHash] of a subset of outputs from the given [BuildSpecRef].
    pub fn hash_single<'a, S: Into<String>>(
        graph: &'a Graph,
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
        let mut enc = LegacyEncoder::new();
        enc.tag(b"subset");
        for (spec, sorted_outputs) in subset_spec.iter_components() {
            enc.bytes(spec.as_bytes());
            for output in sorted_outputs {
                enc.tag(b"-output");
                enc.bytes(output.as_bytes());
            }
        }

        enc.finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use decode::Layer;
    use indoc::indoc;

    /// Expected hash values differ by architecture because the nickel stdlib
    /// evaluation is sensitive to the target config injected at load time.
    macro_rules! arch_hash {
        ($amd64:expr, $arm64:expr) => {{
            #[cfg(target_arch = "x86_64")]
            {
                $amd64
            }
            #[cfg(target_arch = "aarch64")]
            {
                $arm64
            }
        }};
    }

    #[test]
    fn subset_build_dep_does_not_panic() {
        // Regression: a BuildDep::Subset in build_deps used to reach
        // build_input_hash's `Build(_) | Subset(_) => unreachable!()` because
        // build_attrs_hash's filter only excluded the Build variant. process()
        // already treats Subset build-deps as edges, so this is a real state.
        use crate::SubsetInput;
        let mut g = Graph::new();
        let b = g.insert_build(BuildSpec {
            name: "b".into(),
            ..Default::default()
        });
        let a = g.insert_build(BuildSpec {
            name: "a".into(),
            build_deps: [BuildDep::Subset(SubsetInput {
                from: b,
                outputs: ["out".into()].into_iter().collect(),
            })]
            .into_iter()
            .collect(),
            ..Default::default()
        });
        // Must not panic.
        let _ = SpecHasher::hash(&g, &a);
    }

    /// Builds the representative spec that `attrs_hash` and `subset_hash`
    /// pin a golden hash over: a Source build-dep plus one output of each
    /// kind. Constructed in Rust rather than via Nickel so the hash is
    /// deterministic across architectures — Nickel stdlib evaluation is
    /// host-sensitive, which is why the Nickel-backed hash tests still need
    /// the `arch_hash!` macro.
    fn representative_spec(g: &mut Graph) -> BuildSpecRef {
        use crate::SourceInput;
        g.insert_build(BuildSpec {
            name: "single buildspec".into(),
            cmds: vec![vec!["something".into()]],
            build_deps: [BuildDep::Source(SourceInput {
                from: SourceFetch::Web {
                    url: "http://uwu.com".into(),
                    sha256: "abcdef".into(),
                    url_pos: None,
                    sha256_pos: None,
                },
                extract: false,
                strip_prefix: None,
            })]
            .into_iter()
            .collect(),
            outputs: [
                (
                    "something".to_string(),
                    BuildOutput::Library {
                        glob: "/usr/lib/something.*.so".into(),
                        allow_data: false,
                    },
                ),
                (
                    "uwu_tool".to_string(),
                    BuildOutput::Binary {
                        glob: "/bin/uwu".into(),
                        allow_missing_interpreter: false,
                    },
                ),
                (
                    "some_data".to_string(),
                    BuildOutput::Data {
                        glob: "/data/locale/*".into(),
                        allow_executable: false,
                    },
                ),
            ]
            .into_iter()
            .collect(),
            ..Default::default()
        })
    }

    #[test]
    fn attrs_hash() {
        let mut g = Graph::new();
        let a = representative_spec(&mut g);

        // println!("{}", SpecHasher::hash(&g, &a).0.to_hex());
        assert_eq!(
            SpecHasher::hash(&g, &a),
            SpecHash::from_hex("a806fdf8423fc0dd9d7109814a08ea7f82a77407b22d4f596e3961bc8f61d31d")
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
                    build_deps = [],
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

        let dp = Graph::new().ingest(layer).unwrap();

        assert_eq!(
            SpecHasher::hash(&dp, &dp.top_levels[0]),
            SpecHash::from_hex(arch_hash!(
                "619459fa530bedc77f035ab942ef45e8e08a9f10407333a64a2e0367869fb197",
                "dfd836d397a534735e55c8507a654366ee8ef803b8220a06fd13ab92eb4b1850"
            ))
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
                            build_deps = [],
                            cmd = \"something\",
                        } | BuildSpec"
                }
                .to_string(),
            )
            .unwrap_or_else(|e| {
                e.report_to_stderr();
                panic!("spec parsing failed");
            });
            let dp = Graph::new().ingest(layer).unwrap();
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
                    build_deps = [
                        {url = \"http://uwu.com\", sha256 = \"abcdef\"} | Source,
                        {
                            name = \"nested input\",
                            build_deps = [],
                            cmd = \"\",
                        } | BuildSpec
                    ],
                    runtime_deps = [
                        {
                            name = \"nested runtime dep\",
                            build_deps = [],
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

        let dp = Graph::new().ingest(layer).unwrap();

        // println!("{}", SpecHasher::hash(&dp, &dp.top_levels[0]).0.to_hex());
        assert_eq!(
            SpecHasher::hash(&dp, &dp.top_levels[0]),
            SpecHash::from_hex(arch_hash!(
                "f804bd63f9f0f86e675561d73c72c3e76feaae4d874b9c5ab730def9c5d822f3",
                "08bdd0ff44ac171cfde13d461473e71bf36c446f08ccc0a7e7ac49f43304db82"
            ))
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
                    build_deps = [
                        b2,
                    ],
                    cmd = \"\",
                } | BuildSpec,
                b2 = {
                    name = \"b2\",
                    build_deps = [
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

        let dp = Graph::new().ingest(layer).unwrap();

        // println!("{}", SpecHasher::hash(&dp, &dp.top_levels[0]).0.to_hex());
        assert_eq!(
            SpecHasher::hash(&dp, &dp.top_levels[0]),
            SpecHash::from_hex(arch_hash!(
                "e9bc6fb92d25f8c86d83a132d7bc5121a4571a7117554cf59169d2010a695e86",
                "86349cc737dac5a7532b8271cb6a84c476dcca8238e63774a07dc4b7c96405a4"
            ))
            .unwrap(),
        );
    }

    #[test]
    fn subset_hash() {
        let mut g = Graph::new();
        let a = representative_spec(&mut g);

        // println!("{}", SubsetHasher::hash_single(&g, &a, vec!["uwu_tool", "something"]).0.to_hex());
        assert_eq!(
            SubsetHasher::hash_single(&g, &a, vec!["uwu_tool", "something"]),
            SpecHash::from_hex("c5c005aebf5871b30387126e5052e48206f19112fb9d2c5127c5303195726780")
                .unwrap(),
        );
    }
}
