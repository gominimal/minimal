//! The dependency graph.

#![allow(clippy::result_large_err)]
#![allow(clippy::single_match)]

use common::{SpecOrigin, SubsetSpec, Target};
use decode::{Layer, builds};
use nickel_lang_core::term::IndexMap;

use generational_arena::Arena;
use smallvec::SmallVec;
use std::cell::RefCell;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use crate::spec_hasher::SubsetHasher;
use crate::{SpecHash, SpecHasher};

/// A map with ordered iteration semantics - we need this for stable spec hashes.
type OutputMap = IndexMap<String, BuildOutput>;

/// A reference to some other [BuildSpec] in a [DepGraph].
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq, PartialOrd, Ord)]
pub struct BuildSpecRef(pub(crate) generational_arena::Index);

/// A description of pulling source code regardless of form.
#[derive(Debug, Clone, PartialEq)]
pub enum SourceFetch {
    URL(String),
}

impl From<builds::SourceFetch> for SourceFetch {
    fn from(value: builds::SourceFetch) -> Self {
        match value {
            builds::SourceFetch::URL(url) => SourceFetch::URL(url),
        }
    }
}

/// A description of source code thats used as an input.
#[derive(Debug, Clone, PartialEq)]
pub struct SourceInput {
    pub from: SourceFetch,
    pub sha256: String,
    pub extract: bool,
    pub strip_prefix: Option<String>,
}

impl From<builds::SourceInput> for SourceInput {
    fn from(value: builds::SourceInput) -> Self {
        Self {
            from: value.from.into(),
            sha256: value.sha256,
            extract: value.extract,
            strip_prefix: value.strip_prefix,
        }
    }
}

/// A dependency on some of the outputs of a build-spec.
#[derive(Debug, Clone, PartialEq)]
pub struct SubsetInput {
    pub from: BuildSpecRef,
    pub outputs: SmallVec<[String; 4]>,
}

impl SubsetInput {
    /// Constructs a new [SubsetInput], except using the given build instead.
    pub fn override_build(&self, bsr: BuildSpecRef) -> Self {
        Self {
            from: bsr,
            ..self.clone()
        }
    }

    pub fn as_spec(&self, graph: &DepGraph) -> SubsetSpec {
        SubsetSpec::new_single(&graph.spec_hash(&self.from), self.outputs.to_vec())
    }

    fn from_decoded(si: &builds::SubsetInput, loader: &Loader) -> Self {
        Self {
            from: loader.load(&si.from),
            outputs: si.outputs.clone(),
        }
    }
}

/// An input to a build spec.
///
/// Each entry in a build-spec's `inputs` array corresponds to one [BuildSpecInput].
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum BuildSpecInput {
    Build(BuildSpecRef),
    Source(SourceInput),
    HostPath(PathBuf),
    Local {
        full_path: PathBuf,
        filename: String,
        file_hash: blake3::Hash,
    },
    Prebuilt(String, Option<String>), // Package name, sha256
    Subset(SubsetInput),
}

#[allow(dead_code)]
impl BuildSpecInput {
    /// Returns the underlying build-spec reference if this value was the Build variant.
    pub(crate) fn as_build(&self) -> Option<&BuildSpecRef> {
        match self {
            BuildSpecInput::Build(bsr) => Some(bsr),
            _ => None,
        }
    }

    fn from_decoded(i: &builds::BuildDeclInput, loader: &Loader) -> Self {
        match i {
            builds::BuildDeclInput::Build(br) => Self::Build(loader.load(br)),
            builds::BuildDeclInput::Source(s) => Self::Source(s.clone().into()),
            builds::BuildDeclInput::HostPath(p) => Self::HostPath(p.clone()),
            builds::BuildDeclInput::Local {
                full_path,
                filename,
                file_hash,
            } => Self::Local {
                full_path: full_path.clone(),
                filename: filename.clone(),
                file_hash: *file_hash,
            },
            builds::BuildDeclInput::Prebuilt(name, sha256) => {
                Self::Prebuilt(name.clone(), sha256.clone())
            }
            builds::BuildDeclInput::Subset(si) => {
                Self::Subset(SubsetInput::from_decoded(si, loader))
            }
        }
    }
}

/// An output from a build.
#[derive(Debug, Clone, PartialEq)]
#[allow(dead_code)]
pub enum BuildOutput {
    /// This output describes shared libraries matched with the given glob.
    Library { glob: String },
    /// This output describes data files matched with the given glob.
    Data { glob: String },
    /// This output describes binaries matched with the given glob.
    Binary { glob: String },
}

impl BuildOutput {
    pub fn glob(&self) -> &String {
        match self {
            BuildOutput::Binary { glob } => glob,
            BuildOutput::Data { glob } => glob,
            BuildOutput::Library { glob } => glob,
        }
    }

    fn from_decoded(bd: &builds::BuildOutput) -> Self {
        match bd.clone() {
            builds::BuildOutput::Binary { glob } => Self::Binary { glob },
            builds::BuildOutput::Data { glob } => Self::Data { glob },
            builds::BuildOutput::Library { glob } => Self::Library { glob },
        }
    }
}

/// A runtime dependency declared on a build-spec.
///
/// Each entry in a build-spec's `runtime_deps` array corresponds to one [RuntimeDep].
#[derive(Debug, Clone, PartialEq)]
pub enum RuntimeDep {
    /// A direct runtime dependency on the build-spec described by the contained reference.
    Build(BuildSpecRef),
    /// A direct runtime dependency on a subset of the outputs of some other build-spec.
    Subset(SubsetInput),
}

impl RuntimeDep {
    /// Returns the build spec that the runtime dependency ultimately depends on.
    pub fn bsr(&self) -> &BuildSpecRef {
        match self {
            RuntimeDep::Build(bsr) => bsr,
            RuntimeDep::Subset(SubsetInput { from, .. }) => from,
        }
    }

    fn from_decoded(d: &builds::RuntimeDep, loader: &Loader) -> Self {
        match d {
            builds::RuntimeDep::Build(br) => Self::Build(loader.load(br)),
            builds::RuntimeDep::Subset(si) => Self::Subset(SubsetInput::from_decoded(si, loader)),
        }
    }
}

/// Some task or build in the dependency graph.
#[derive(Debug, Clone, Default)]
#[allow(dead_code)]
pub struct BuildSpec {
    /// The human-readable name declared on the build spec.
    pub name: String,
    /// The system this build-spec is meant to run on. Defaults to amd64 Linux.
    pub target: Target,

    /// The build command declared on the build spec.
    pub cmd: String,
    /// Any arguments to the build command, ultimately passed as environment variables.
    pub build_args: Option<IndexMap<String, String>>,

    /// The dependencies needed to execute the build spec.
    pub inputs: SmallVec<[BuildSpecInput; 10]>,
    /// The dependencies needed to run outputs of this build spec, as well as possibly needed
    /// during the build.
    pub runtime_deps: SmallVec<[RuntimeDep; 8]>,
    /// The named outputs (and match patterns) produced by executing this build spec.
    pub outputs: OutputMap,

    /// An alternative build spec to use to break cycles in resolving dependencies on this build spec.
    pub replace_on_cycle: Option<BuildSpecRef>,

    /// Identifies the collection of build-specs where this was defined.
    pub from: Arc<SpecOrigin>,
}

impl BuildSpec {
    /// Returns true if the build-spec represents a fetch of files but no actual computation.
    pub fn is_pure_prebuilt(&self) -> bool {
        let has_prebuilt = self
            .inputs
            .iter()
            .any(|input| matches!(input, BuildSpecInput::Prebuilt(_, _)));
        let has_local_or_source = self.inputs.iter().any(|input| {
            matches!(
                input,
                BuildSpecInput::Local { .. } | BuildSpecInput::Source(_)
            )
        });

        has_prebuilt && !has_local_or_source
    }

    /// Returns true if the build-spec represents a rollup of runtime_deps but no substance or computation of its own.
    pub fn is_pure_collection(&self) -> bool {
        self.inputs.is_empty() && self.cmd.is_empty()
    }

    fn from_decoded(bd: &builds::BuildDecl, loader: &Loader) -> Self {
        Self {
            name: bd.name.clone(),
            target: bd.target.clone(),
            cmd: bd.cmd.clone(),
            build_args: bd.build_args.clone(),

            inputs: bd
                .inputs
                .iter()
                .map(|i| BuildSpecInput::from_decoded(i, loader))
                .collect::<SmallVec<_>>(),
            runtime_deps: bd
                .runtime_deps
                .iter()
                .map(|d| RuntimeDep::from_decoded(d, loader))
                .collect::<SmallVec<_>>(),

            outputs: bd
                .outputs
                .iter()
                .map(|(k, v)| (k.clone(), BuildOutput::from_decoded(v)))
                .collect(),
            replace_on_cycle: bd.replace_on_cycle.as_ref().map(|br| loader.load(br)),

            from: loader.origin.clone(),
        }
    }
}

/// Manages loading a [Layer] into [DepGraph].
struct Loader {
    from: Layer,
    origin: Arc<SpecOrigin>,
    into_graph: RefCell<DepGraph>,
    resolved: RefCell<HashMap<generational_arena::Index, BuildSpecRef>>,
}

impl Loader {
    /// upserts the specified build ref, returning the new or already-existing BSR.
    fn load(&self, br: &builds::BuildRef) -> BuildSpecRef {
        let idx = self.from.resolve(br).unwrap();
        self.load_idx(idx)
    }

    /// upserts the specified layer idx, returning the new or already-existing BSR.
    fn load_idx(&self, idx: &generational_arena::Index) -> BuildSpecRef {
        // Fast path: already loaded.
        if let Some(bsr) = self.resolved.borrow().get(idx) {
            return *bsr;
        }

        let decl = self.from.get(*idx).unwrap();

        // Insert a placeholder that can be used in the short-circuit path in the case of cycles.
        let bsr = BuildSpecRef(
            self.into_graph
                .borrow_mut()
                .builds
                .insert(BuildSpec::default()),
        );
        self.resolved.borrow_mut().insert(*idx, bsr);

        // Decode the build-spec and write it back to the allocated position.
        let build = BuildSpec::from_decoded(decl, self);
        *self.into_graph.borrow_mut().builds.get_mut(bsr.0).unwrap() = build;

        bsr
    }

    fn load_toplevels(&mut self) -> Vec<BuildSpecRef> {
        self.from
            .top_levels
            .clone()
            .iter()
            .map(|idx| self.load_idx(idx))
            .collect::<Vec<_>>()
    }
}

/// The dependency graph.
#[derive(Debug)]
#[allow(dead_code)]
pub struct DepGraph {
    /// All the build-specs known to this dependency graph.
    builds: Arena<BuildSpec>,
    /// The top level build-specs (i.e. non-transitive) that were read when
    /// constructing this dependency graph.
    pub top_levels: Vec<BuildSpecRef>,

    /// The cache of build specs to their [SpecHash]. There is also a
    /// reverse cache of [SpecHash]'s to the build spec they correspond to.
    #[allow(clippy::type_complexity)]
    hash_cache: Arc<
        RwLock<(
            HashMap<BuildSpecRef, SpecHash>,
            HashMap<SpecHash, BuildSpecRef>,
        )>,
    >,
}

impl Default for DepGraph {
    fn default() -> Self {
        Self::new()
    }
}

impl DepGraph {
    /// Constructs an empty dependency graph.
    pub fn new() -> Self {
        Self {
            builds: Arena::with_capacity(4096),
            top_levels: Vec::new(),
            hash_cache: Arc::new(RwLock::new((
                HashMap::with_capacity(4096),
                HashMap::with_capacity(4096),
            ))),
        }
    }

    /// Loads build declarations in from the given layer.
    pub fn ingest(self, layer: Layer) -> Self {
        let mut loader = Loader {
            origin: Arc::new(layer.origin.clone()),
            from: layer,
            into_graph: RefCell::new(self),
            resolved: RefCell::new(HashMap::with_capacity(1024)),
        };
        let new_toplevels = loader.load_toplevels();

        let mut slf = loader.into_graph.into_inner();
        slf.top_levels.extend(new_toplevels);
        slf
    }

    /// Fetches a build-spec by reference.
    pub fn get(&self, bsr: &BuildSpecRef) -> Option<&BuildSpec> {
        self.builds.get(bsr.0)
    }

    /// Returns an iterator over all build-spec references with the given name.
    pub fn by_name<S: AsRef<str>>(
        &self,
        name: S,
    ) -> impl Iterator<Item = BuildSpecRef> + use<'_, S> {
        self.builds.iter().filter_map(move |(bsr, b)| {
            if b.name == name.as_ref() {
                Some(BuildSpecRef(bsr))
            } else {
                None
            }
        })
    }

    /// Returns the specification hash of the given build spec.
    pub fn spec_hash(&self, bsr: &BuildSpecRef) -> SpecHash {
        {
            if let Some(hash) = self.hash_cache.read().unwrap().0.get(bsr) {
                return hash.clone();
            }
        }

        let hash = SpecHasher::hash(self, bsr);

        {
            let mut hashes = self.hash_cache.write().unwrap();
            hashes.0.insert(*bsr, hash.clone());
            hashes.1.insert(hash.clone(), *bsr);
        }
        hash
    }

    /// Returns the specification hash of a subset.
    pub fn subset_hash(&self, subset: &SubsetInput) -> SpecHash {
        SubsetHasher::hash_single(self, &subset.from, subset.outputs.to_vec())
    }

    /// Returns an iterator over all build-spec references.
    pub fn all(&self) -> impl Iterator<Item = BuildSpecRef> + use<'_> {
        self.builds.iter().map(|e| BuildSpecRef(e.0))
    }

    /// Returns the number of build-specs in the graph.
    pub fn len(&self) -> usize {
        self.builds.len()
    }
    /// Returns true if the graph contains no build-specs.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Iterates over all build specs and their keys.
    pub fn iter(&self) -> impl Iterator<Item = (BuildSpecRef, &BuildSpec)> + use<'_> {
        self.builds
            .iter()
            .map(|(index, spec)| (BuildSpecRef(index), spec))
    }

    /// Returns the unique set of transitive build-spec dependencies of the given toplevel.
    ///
    /// Dependencies of a build-spec are its inputs and its runtime dependencies.
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
        build_spec
            .inputs
            .iter()
            .filter_map(|input| match input {
                Build(bsr) => Some(bsr),
                Subset(si) => Some(&si.from),
                Source(_) | HostPath(_) | Local { .. } | Prebuilt(_, _) => None,
            })
            .chain(build_spec.runtime_deps.iter().map(|dep| match dep {
                RuntimeDep::Build(bsr) => bsr,
                RuntimeDep::Subset(si) => &si.from,
            }))
            .for_each(|bsr| {
                if !seen.contains_key(bsr) {
                    seen.insert(*bsr, ());
                    reachable.push(*bsr);
                    self.collect_transitive_buildspecs(bsr, seen, reachable);
                }
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use decode::Layer;
    use indoc::indoc;

    #[test]
    fn spec_hash_doesnt_explode_on_cycles() {
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
                b1"
            }
            .to_string(),
        )
        .unwrap_or_else(|e| {
            e.report_to_stderr();
            panic!("spec parsing failed");
        });

        let dp = DepGraph::new().ingest(layer);
        assert!(
            dp.spec_hash(&dp.by_name("b1").next().unwrap())
                != dp.spec_hash(&dp.by_name("b2").next().unwrap()),
        );
    }

    #[test]
    fn transitive_specs_of() {
        let layer = Layer::new_for_test(
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
        )
        .unwrap_or_else(|e| {
            e.report_to_stderr();
            panic!("spec parsing failed");
        });

        let dp = DepGraph::new().ingest(layer);
        assert_eq!(
            dp.transitive_specs_of(&dp.top_levels[0]),
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

    #[test]
    fn circular_ref_doesnt_crash() {
        let layer = Layer::new_for_test(
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
        )
        .unwrap_or_else(|e| {
            e.report_to_stderr();
            panic!("spec parsing failed");
        });

        let dp = DepGraph::new().ingest(layer);
        // We expect two buildspecs
        assert_eq!(
            vec!["build 1".to_string(), "build 2".to_string(),],
            dp.builds
                .into_iter()
                .map(|b| b.name)
                .collect::<Vec<String>>()
        );
    }
}
