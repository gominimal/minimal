use crate::{
    BuildDep, BuildOutput, BuildSpec, BuildSpecRef, Error, Graph, RuntimeDep, SourceFetch, SpecHash,
};
use blake3::Hasher;
use common::{SubsetSpec, Target, target};
use decode::{AttrValue, Container};
use nickel_lang_core::term::IndexMap;
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

/// Computes the [SpecHash] for a container.
///
/// A container is a declaration *over* packages rather than a build of its own,
/// so its hash combines two things: the packages it embeds, hashed **by
/// content** (their [SpecHash], not their name — an image must change when what
/// goes into it changes), and every field of the image config it declares.
///
/// A package's own [SpecHash] already covers its transitive runtime closure, so
/// the closure needs no separate walk here.
pub struct ContainerHasher;

impl ContainerHasher {
    /// Computes the [SpecHash] of `container` against the packages in `graph`.
    ///
    /// The [`SpecEncoder`] chosen here is the whole surface a future hash epoch
    /// touches for containers.
    ///
    /// Returns [`Error::NoSuchPkg`] if a named package is not in the graph.
    pub fn hash(graph: &Graph, container: &Container) -> Result<SpecHash, Error> {
        let mut enc = LegacyEncoder::new();
        Self::encode(graph, container, &mut enc)?;
        Ok(enc.finish())
    }

    /// The encoding pass, generic over the encoder for the same reason
    /// [`SpecHasher::encode`] is: the hash *format* is the encoder's choice.
    fn encode<E: SpecEncoder>(
        graph: &Graph,
        container: &Container,
        enc: &mut E,
    ) -> Result<(), Error> {
        // Destructured exhaustively on purpose: a field added to Container
        // fails to compile here rather than silently falling out of the hash.
        let Container {
            name,
            packages,
            entrypoint,
            cmd,
            arch,
            working_dir,
            env_vars,
            exposed_ports,
            volumes,
            user,
            stop_signal,
            labels,
            config,
        } = container;

        enc.tag(b"container");
        enc.bytes(name.as_bytes());

        // Packages enter as a set of *content* hashes: an image must change
        // when what goes into it changes, but not when the same packages are
        // listed in a different order, or listed twice.
        enc.tag(b"-packages");
        let mut package_hashes = Vec::with_capacity(packages.len());
        for pkg in packages {
            let bsr = graph.by_name(pkg).ok_or_else(|| Error::NoSuchPkg {
                name: pkg.to_string(),
            })?;
            package_hashes.push(graph.spec_hash(bsr));
        }
        package_hashes.sort_unstable();
        package_hashes.dedup();
        enc.index(package_hashes.len());
        for hash in &package_hashes {
            enc.bytes(hash.as_bytes());
        }

        enc.tag(b"-entrypoint");
        encode_opt_argv(entrypoint.as_deref(), enc);
        enc.tag(b"-cmd");
        encode_opt_argv(cmd.as_deref(), enc);

        enc.tag(b"-arch");
        encode_opt_bytes(arch.as_ref().map(|a| a.as_nickel_str()), enc);
        enc.tag(b"-working_dir");
        encode_opt_bytes(working_dir.as_deref(), enc);
        enc.tag(b"-user");
        encode_opt_bytes(user.as_deref(), enc);
        enc.tag(b"-stop_signal");
        encode_opt_bytes(stop_signal.as_deref(), enc);

        enc.tag(b"-env_vars");
        encode_string_map(env_vars, enc);

        // Both become keys of a JSON object in the image config, so both are
        // sets: `ExposedPorts` keyed `"80/tcp"`, and `Volumes` keyed by path.
        enc.tag(b"-exposed_ports");
        encode_string_set(
            exposed_ports
                .iter()
                .map(|p| format!("{}/{}", p.port, p.proto))
                .collect(),
            enc,
        );

        enc.tag(b"-volumes");
        encode_string_set(volumes.iter().map(String::as_str).collect(), enc);

        enc.tag(b"-labels");
        encode_string_map(labels, enc);
        enc.tag(b"-config");
        encode_string_map(config, enc);

        Ok(())
    }
}

/// An absent optional field carries a marker rather than being skipped:
/// skipping is what lets "unset" alias "set to the next field's value".
fn encode_opt_bytes<E: SpecEncoder>(value: Option<&str>, enc: &mut E) {
    match value {
        Some(v) => {
            enc.tag(b"some");
            enc.bytes(v.as_bytes());
        }
        None => enc.tag(b"none"),
    }
}

fn encode_opt_argv<E: SpecEncoder>(argv: Option<&[String]>, enc: &mut E) {
    match argv {
        Some(argv) => {
            enc.tag(b"some");
            enc.index(argv.len());
            for arg in argv {
                enc.bytes(arg.as_bytes());
            }
        }
        None => enc.tag(b"none"),
    }
}

/// Length-prefixed and sorted by key, so the declaration order of a map that
/// becomes an unordered image-config object does not reach the hash — see
/// [`ContainerHasher`]. Keys are unique within an [`IndexMap`], so the sort is
/// total and needs no dedup.
///
/// The `k`/`v` markers are the legacy scheme's idiom for maps, matching
/// `build_attrs_hash`'s `build_args` encoding: without them `{AB: "C"}` and
/// `{A: "BC"}` are the same bytes.
fn encode_string_map<E: SpecEncoder>(map: &IndexMap<String, String>, enc: &mut E) {
    let mut entries: Vec<(&String, &String)> = map.iter().collect();
    entries.sort_unstable_by_key(|(key, _)| *key);

    enc.index(entries.len());
    for (key, value) in entries {
        enc.tag(b"k");
        enc.bytes(key.as_bytes());
        enc.tag(b"v");
        enc.bytes(value.as_bytes());
    }
}

/// Length-prefixed, sorted, and deduplicated: the collection describes a set in
/// the image config, so neither order nor a repeat says anything.
fn encode_string_set<E: SpecEncoder, S: AsRef<str> + Ord>(mut values: Vec<S>, enc: &mut E) {
    values.sort_unstable();
    values.dedup();

    enc.index(values.len());
    for value in &values {
        enc.bytes(value.as_ref().as_bytes());
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

    // ── Container hashing ────────────────────────────────────────────────────

    /// A graph with two packages plus a container that embeds both, with every
    /// image-config field set — the shape the golden hash below pins.
    fn container_fixture() -> (Graph, Container) {
        use decode::{ExposedPort, ExposedPortProto};

        let mut g = Graph::new();
        g.insert_build(BuildSpec {
            name: "glibc".into(),
            cmds: vec![vec!["make".into()]],
            ..Default::default()
        });
        g.insert_build(BuildSpec {
            name: "nginx".into(),
            cmds: vec![vec!["configure".into()]],
            ..Default::default()
        });

        let container = Container {
            name: "web".into(),
            packages: vec!["glibc".into(), "nginx".into()],
            entrypoint: Some(vec!["/usr/bin/nginx".into(), "-g".into()]),
            cmd: Some(vec!["-c".into(), "/etc/nginx/nginx.conf".into()]),
            arch: Some(target::Arch::Amd64),
            working_dir: Some("/srv".into()),
            env_vars: IndexMap::from_iter([("PORT".to_string(), "8080".to_string())]),
            exposed_ports: vec![
                ExposedPort {
                    proto: ExposedPortProto::Tcp,
                    port: 80,
                },
                ExposedPort {
                    proto: ExposedPortProto::Udp,
                    port: 443,
                },
            ],
            volumes: vec!["/var/lib/nginx".into()],
            user: Some("nginx".into()),
            stop_signal: Some("SIGQUIT".into()),
            labels: IndexMap::from_iter([(
                "org.opencontainers.image.title".to_string(),
                "web".to_string(),
            )]),
            config: IndexMap::from_iter([("StopTimeout".to_string(), "30".to_string())]),
        };
        (g, container)
    }

    /// Golden hash. Built in Rust rather than Nickel, so it is stable across
    /// architectures — see [`representative_spec`].
    #[test]
    fn container_hash() {
        let (g, c) = container_fixture();

        // println!("{}", ContainerHasher::hash(&g, &c).unwrap().0.to_hex());
        assert_eq!(
            ContainerHasher::hash(&g, &c).unwrap(),
            SpecHash::from_hex("ddaa6e2ea3b3921d2c977bb6ff34597a762de4686503c1bb2020fd42a66f87dc")
                .unwrap(),
        );
    }

    /// The point of hashing packages by [SpecHash] rather than by name: an
    /// image must change when what goes into it changes, even though the
    /// container declaration is untouched.
    #[test]
    fn container_hash_tracks_package_contents() {
        let (g, c) = container_fixture();
        let before = ContainerHasher::hash(&g, &c).unwrap();

        let mut g2 = Graph::new();
        g2.insert_build(BuildSpec {
            name: "glibc".into(),
            cmds: vec![vec!["make".into()]],
            ..Default::default()
        });
        g2.insert_build(BuildSpec {
            name: "nginx".into(),
            // The one difference: nginx builds with a different command.
            cmds: vec![vec!["configure".into(), "--with-http_v3_module".into()]],
            ..Default::default()
        });

        assert_ne!(
            before,
            ContainerHasher::hash(&g2, &c).unwrap(),
            "a package rebuild must change the hash of the image embedding it"
        );
    }

    /// The `k`/`v` markers and the list-length prefixes earn their keep: without
    /// them the legacy scheme's raw concatenation hashes both of these pairs
    /// identically.
    #[test]
    fn container_hash_separates_string_boundaries() {
        let (g, base) = container_fixture();

        let ab_c = Container {
            env_vars: IndexMap::from_iter([("AB".to_string(), "C".to_string())]),
            ..base.clone()
        };
        let a_bc = Container {
            env_vars: IndexMap::from_iter([("A".to_string(), "BC".to_string())]),
            ..base.clone()
        };
        assert_ne!(
            ContainerHasher::hash(&g, &ab_c).unwrap(),
            ContainerHasher::hash(&g, &a_bc).unwrap(),
            "key/value boundary must be part of the hash"
        );

        // Same property across a list's element boundaries.
        let split = Container {
            volumes: vec!["/a".into(), "/b".into()],
            ..base.clone()
        };
        let joined = Container {
            volumes: vec!["/a/b".into()],
            ..base
        };
        assert_ne!(
            ContainerHasher::hash(&g, &split).unwrap(),
            ContainerHasher::hash(&g, &joined).unwrap(),
            "element boundaries must be part of the hash"
        );
    }

    /// What the `k`/`v` markers do *not* fix, pinned so the state of play is
    /// visible rather than folklore: they are in-band, so content containing a
    /// marker still aliases. `Av` + `B` and `A` + `vB` both encode to `kAvvB`.
    ///
    /// This is inherited from the legacy scheme, not specific to containers.
    /// **Flip this to `assert_ne!` when the injective encoder lands** — it is
    /// the executable form of that migration's success criterion.
    #[test]
    fn container_hash_marker_aliasing_is_a_known_legacy_gap() {
        let (g, base) = container_fixture();

        let key_holds_marker = Container {
            env_vars: IndexMap::from_iter([("Av".to_string(), "B".to_string())]),
            ..base.clone()
        };
        let value_holds_marker = Container {
            env_vars: IndexMap::from_iter([("A".to_string(), "vB".to_string())]),
            ..base
        };

        assert_eq!(
            ContainerHasher::hash(&g, &key_holds_marker).unwrap(),
            ContainerHasher::hash(&g, &value_holds_marker).unwrap(),
            "if this now differs, the encoder gained framing: flip to assert_ne"
        );
    }

    /// An unset field must not hash like a set-but-empty one — the reason
    /// optional fields carry a present/absent marker instead of being skipped.
    #[test]
    fn container_hash_distinguishes_absent_from_empty() {
        let (g, base) = container_fixture();

        let unset = Container {
            user: None,
            cmd: None,
            ..base.clone()
        };
        let empty = Container {
            user: Some(String::new()),
            cmd: Some(Vec::new()),
            ..base
        };
        assert_ne!(
            ContainerHasher::hash(&g, &unset).unwrap(),
            ContainerHasher::hash(&g, &empty).unwrap(),
        );
    }

    /// Collections that become unordered image-config objects are hashed as
    /// sets: reordering a declaration describes the same image and must reach
    /// the same cache entry.
    #[test]
    fn container_hash_ignores_collection_order() {
        use decode::{ExposedPort, ExposedPortProto};

        let (g, base) = container_fixture();
        let baseline = ContainerHasher::hash(&g, &base).unwrap();

        let reordered = Container {
            packages: vec!["nginx".into(), "glibc".into()],
            exposed_ports: vec![
                ExposedPort {
                    proto: ExposedPortProto::Udp,
                    port: 443,
                },
                ExposedPort {
                    proto: ExposedPortProto::Tcp,
                    port: 80,
                },
            ],
            ..base.clone()
        };
        assert_eq!(
            baseline,
            ContainerHasher::hash(&g, &reordered).unwrap(),
            "packages and ports are sets, not sequences"
        );

        // Maps, over more than one entry so the order can actually differ.
        let pairs = [
            ("A".to_string(), "1".to_string()),
            ("B".to_string(), "2".to_string()),
        ];
        let reversed: Vec<_> = pairs.iter().rev().cloned().collect();
        let declared = Container {
            env_vars: IndexMap::from_iter(pairs.clone()),
            labels: IndexMap::from_iter(pairs.clone()),
            config: IndexMap::from_iter(pairs),
            ..base.clone()
        };
        let declared_reversed = Container {
            env_vars: IndexMap::from_iter(reversed.clone()),
            labels: IndexMap::from_iter(reversed.clone()),
            config: IndexMap::from_iter(reversed),
            ..base.clone()
        };
        assert_eq!(
            ContainerHasher::hash(&g, &declared).unwrap(),
            ContainerHasher::hash(&g, &declared_reversed).unwrap(),
            "env_vars, labels and config are unordered in an image config"
        );

        // But argv order is argv's whole meaning.
        let flipped_argv = Container {
            cmd: Some(vec!["/etc/nginx/nginx.conf".into(), "-c".into()]),
            ..base
        };
        assert_ne!(
            baseline,
            ContainerHasher::hash(&g, &flipped_argv).unwrap(),
            "cmd is a sequence"
        );
    }

    /// Naming a package twice adds nothing to an image, so it must not change
    /// the hash — the set is deduplicated, not merely sorted.
    #[test]
    fn container_hash_ignores_duplicate_set_entries() {
        let (g, base) = container_fixture();
        let baseline = ContainerHasher::hash(&g, &base).unwrap();

        let with_repeats = Container {
            packages: vec!["glibc".into(), "nginx".into(), "glibc".into()],
            volumes: vec!["/var/lib/nginx".into(), "/var/lib/nginx".into()],
            ..base
        };
        assert_eq!(baseline, ContainerHasher::hash(&g, &with_repeats).unwrap());
    }

    /// Sorting must not blur *which* values are present: a set that ignores
    /// order still distinguishes contents.
    #[test]
    fn container_hash_tracks_set_membership() {
        let (g, base) = container_fixture();
        let baseline = ContainerHasher::hash(&g, &base).unwrap();

        let dropped_package = Container {
            packages: vec!["glibc".into()],
            ..base.clone()
        };
        assert_ne!(
            baseline,
            ContainerHasher::hash(&g, &dropped_package).unwrap()
        );

        let extra_env = Container {
            env_vars: IndexMap::from_iter([
                ("PORT".to_string(), "8080".to_string()),
                ("TZ".to_string(), "UTC".to_string()),
            ]),
            ..base
        };
        assert_ne!(baseline, ContainerHasher::hash(&g, &extra_env).unwrap());
    }

    /// A graph decoded off the wire carries whatever containers the peer sent,
    /// with no package validation — so this is an error, not a panic.
    #[test]
    fn container_hash_rejects_unknown_package() {
        let (g, base) = container_fixture();
        let c = Container {
            packages: vec!["glibc".into(), "not-in-this-graph".into()],
            ..base
        };

        let err = ContainerHasher::hash(&g, &c).unwrap_err();
        assert!(
            matches!(err, Error::NoSuchPkg { ref name } if name == "not-in-this-graph"),
            "got {err:?}"
        );
    }

    /// The leading `container` tag keeps the keyspace disjoint from the build
    /// specs' (which open with a discovery index) and subsets' (`subset`): a
    /// container whose only content is one package must not hash like that
    /// package.
    #[test]
    fn container_hash_does_not_alias_spec_hash() {
        let mut g = Graph::new();
        let pkg = g.insert_build(BuildSpec {
            name: "solo".into(),
            ..Default::default()
        });
        let c = Container {
            name: "solo".into(),
            packages: vec!["solo".into()],
            ..Default::default()
        };

        assert_ne!(ContainerHasher::hash(&g, &c).unwrap(), g.spec_hash(&pkg));
    }
}
