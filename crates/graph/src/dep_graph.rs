//! The dependency graph.

#![allow(clippy::result_large_err)]
#![allow(clippy::single_match)]

use common::repo_spec::Repo;
use common::{SpecOrigin, SubsetSpec, Target};
use decode::builds::BuildRef;
use decode::{Harness, Layer, Profile, builds};
use mfile::{self, LinkConfig};
use nickel_lang_core::term::IndexMap;

use generational_arena::Arena;
use smallvec::SmallVec;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use crate::spec_hasher::SubsetHasher;
use crate::{Error, SpecHash, SpecHasher};

/// A map with ordered iteration semantics - we need this for stable spec hashes.
type OutputMap = IndexMap<String, BuildOutput>;

pub use decode::AttrValue;

/// A reference to some other [BuildSpec] in a [DepGraph].
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq, PartialOrd, Ord)]
pub struct BuildSpecRef(pub(crate) generational_arena::Index);

impl BuildSpecRef {
    /// returns the index of the BuildSpec in the arena
    pub fn index(&self) -> usize {
        self.0.into_raw_parts().0
    }
}
/// A description of pulling source code regardless of form.
#[derive(Debug, Clone, PartialEq)]
pub enum SourceFetch {
    Web {
        url: String,
        sha256: String,
    },
    Local {
        full_path: PathBuf,
        filename: String,
        file_hash: blake3::Hash,
    },
}

impl From<builds::SourceFetch> for SourceFetch {
    fn from(value: builds::SourceFetch) -> Self {
        match value {
            builds::SourceFetch::Web { url, sha256 } => SourceFetch::Web { url, sha256 },
            builds::SourceFetch::Local {
                full_path,
                filename,
                file_hash,
            } => SourceFetch::Local {
                full_path,
                filename,
                file_hash,
            },
        }
    }
}

/// A description of source code thats used as an input.
#[derive(Debug, Clone, PartialEq)]
pub struct SourceInput {
    pub from: SourceFetch,
    pub extract: bool,
    pub strip_prefix: Option<String>,
}

impl From<builds::SourceInput> for SourceInput {
    fn from(value: builds::SourceInput) -> Self {
        Self {
            from: value.from.into(),
            extract: value.extract,
            strip_prefix: value.strip_prefix,
        }
    }
}

/// A dependency on some of the outputs of a build-spec.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
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

    fn from_decoded(si: &builds::SubsetInput, loader: &Loader) -> Result<Self, Error> {
        Ok(Self {
            from: loader.load(&si.from)?,
            outputs: si.outputs.clone(),
        })
    }
}

impl From<(BuildSpecRef, HashSet<String>)> for SubsetInput {
    fn from(value: (BuildSpecRef, HashSet<String>)) -> Self {
        let (from, outputs) = value;
        let mut outputs: SmallVec<[String; 4]> = outputs.into_iter().collect();
        outputs.sort();
        outputs.dedup();
        Self { from, outputs }
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

    fn from_decoded(i: &builds::BuildDeclInput, loader: &Loader) -> Result<Self, Error> {
        Ok(match i {
            builds::BuildDeclInput::Build(br) => Self::Build(loader.load(br)?),
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
            builds::BuildDeclInput::Subset(si) => {
                Self::Subset(SubsetInput::from_decoded(si, loader)?)
            }
        })
    }
}

/// An output from a build.
#[derive(Debug, Clone, PartialEq)]
#[allow(dead_code)]
pub enum BuildOutput {
    /// This output describes shared libraries matched with the given glob.
    Library { glob: String, allow_data: bool },
    /// This output describes data files matched with the given glob.
    Data {
        glob: String,
        allow_executable: bool,
    },
    /// This output describes binaries matched with the given glob.
    Binary { glob: String },
}

impl BuildOutput {
    pub fn glob(&self) -> &String {
        match self {
            BuildOutput::Binary { glob } => glob,
            BuildOutput::Data {
                glob,
                allow_executable: _,
            } => glob,
            BuildOutput::Library {
                glob,
                allow_data: _,
            } => glob,
        }
    }

    fn from_decoded(bd: &builds::BuildOutput) -> Self {
        match bd.clone() {
            builds::BuildOutput::Binary { glob } => Self::Binary { glob },
            builds::BuildOutput::Data {
                glob,
                allow_executable,
            } => Self::Data {
                glob,
                allow_executable,
            },
            builds::BuildOutput::Library { glob, allow_data } => Self::Library { glob, allow_data },
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

    fn from_decoded(d: &builds::RuntimeDep, loader: &Loader) -> Result<Self, Error> {
        Ok(match d {
            builds::RuntimeDep::Build(br) => Self::Build(loader.load(br)?),
            builds::RuntimeDep::Subset(si) => Self::Subset(SubsetInput::from_decoded(si, loader)?),
        })
    }
}

/// A unit test defined on a build spec.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SpecTest {
    /// The test needs to run in the build sandbox, rather than standalone.
    pub build_test: bool,
    /// Additional dependencies needed for the test.
    pub deps: Option<SmallVec<[BuildSpecRef; 6]>>,
    /// The tests commands.
    pub cmds: Vec<Vec<String>>,
}

impl SpecTest {
    fn from_decoded(t: &decode::Test, loader: &Loader) -> Result<Self, Error> {
        Ok(Self {
            build_test: t.build_test,
            deps: match &t.deps {
                None => None,
                Some(deps) => Some(
                    deps.iter()
                        .map(|d| loader.load(d))
                        .collect::<Result<SmallVec<_>, _>>()?,
                ),
            },
            cmds: t.cmds.clone(),
        })
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
    /// This spec was marked as a prebuilt - no computation, fetch the output from an archive directly.
    pub(crate) prebuilt: bool,

    /// The build commands declared on the build spec.
    pub cmds: Vec<Vec<String>>,
    /// Any arguments to the build command, ultimately passed as environment variables.
    pub build_args: Option<IndexMap<String, String>>,

    /// The dependencies needed to execute the build spec.
    pub inputs: SmallVec<[BuildSpecInput; 10]>,
    /// The dependencies needed to run outputs of this build spec, as well as possibly needed
    /// during the build.
    pub runtime_deps: SmallVec<[RuntimeDep; 8]>,
    /// The 'needs' (abstract dependencies) defined on the build-spec.
    pub abstract_deps: IndexMap<String, AttrValue>,
    /// The named outputs (and match patterns) produced by executing this build spec.
    pub outputs: OutputMap,

    /// An alternative build spec to use to break cycles in resolving dependencies on this build spec.
    pub replace_on_cycle: Option<BuildSpecRef>,

    /// The attributes defined on the build-spec.
    pub attrs: IndexMap<String, AttrValue>,

    /// Any unit tests defined on the build-spec.
    pub tests: Option<IndexMap<String, SpecTest>>,

    /// Identifies the collection of build-specs where this was defined.
    pub from: Arc<SpecOrigin>,
}

impl BuildSpec {
    /// Returns true if the build-spec represents a fetch of files but no actual computation.
    pub fn is_pure_prebuilt(&self) -> bool {
        self.prebuilt
    }

    /// Returns true if the build-spec represents a rollup of runtime_deps but no substance or computation of its own.
    pub fn is_pure_collection(&self) -> bool {
        self.inputs.is_empty()
            && (self.cmds.is_empty()
                || (self.cmds.len() == 1
                    && (self.cmds[0].is_empty() || self.cmds[0][0].is_empty())))
    }

    fn from_decoded(bd: &builds::BuildDecl, loader: &Loader) -> Result<Self, Error> {
        Ok(Self {
            name: bd.name.clone(),
            target: bd.target.clone(),
            prebuilt: bd.prebuilt,
            cmds: bd.cmds.clone(),
            build_args: bd.build_args.clone(),

            inputs: bd
                .inputs
                .iter()
                .map(|i| BuildSpecInput::from_decoded(i, loader))
                .collect::<Result<SmallVec<_>, _>>()?,
            runtime_deps: bd
                .runtime_deps
                .iter()
                .map(|d| RuntimeDep::from_decoded(d, loader))
                .collect::<Result<SmallVec<_>, _>>()?,
            abstract_deps: bd
                .abstract_deps
                .as_ref()
                .cloned()
                .unwrap_or(IndexMap::new()),

            outputs: bd
                .outputs
                .iter()
                .map(|(k, v)| (k.clone(), BuildOutput::from_decoded(v)))
                .collect(),
            replace_on_cycle: match &bd.replace_on_cycle {
                Some(br) => Some(loader.load(br)?),
                None => None,
            },

            attrs: bd.attrs.as_ref().cloned().unwrap_or(IndexMap::new()),

            tests: match &bd.tests {
                None => None,
                Some(tests) => Some(
                    tests
                        .iter()
                        .map(|(n, t)| match SpecTest::from_decoded(t, loader) {
                            Ok(t) => Ok((n.clone(), t)),
                            Err(e) => Err(e),
                        })
                        .collect::<Result<IndexMap<String, SpecTest>, _>>()?,
                ),
            },

            from: loader.origin.clone(),
        })
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
    fn load(&self, br: &builds::BuildRef) -> Result<BuildSpecRef, Error> {
        if let BuildRef::Upstream { name } = br {
            return match self.into_graph.borrow().by_name(name) {
                Some(bsr) => Ok(*bsr),
                None => Err(Error::NoSuchPkg { name: name.clone() }),
            };
        }

        let idx = self.from.resolve(br).unwrap();
        self.load_idx(idx)
    }

    /// upserts the specified layer idx, returning the new or already-existing BSR.
    fn load_idx(&self, idx: &generational_arena::Index) -> Result<BuildSpecRef, Error> {
        // Fast path: already loaded.
        if let Some(bsr) = self.resolved.borrow().get(idx) {
            return Ok(*bsr);
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
        let build = BuildSpec::from_decoded(decl, self)?;
        *self.into_graph.borrow_mut().builds.get_mut(bsr.0).unwrap() = build;

        Ok(bsr)
    }

    fn load_toplevels(&mut self) -> Result<Vec<BuildSpecRef>, Error> {
        self.from
            .top_levels
            .clone()
            .iter()
            .map(|idx| self.load_idx(idx))
            .collect::<Result<Vec<_>, _>>()
    }
}

/// Describes something that can resolve the upstream a layer declares it chains from, into the
/// source tree on disk it represents.
pub trait SourceProvider {
    type Error: std::fmt::Debug + std::error::Error;

    fn checkout_of(&mut self, upstream: &LinkConfig) -> Result<PathBuf, Self::Error>;
}

impl SourceProvider for checkouts::Manager {
    type Error = checkouts::Error;

    fn checkout_of(&mut self, upstream: &LinkConfig) -> Result<PathBuf, Self::Error> {
        match upstream {
            LinkConfig::Dir { dir } => Ok(dir.into()),
            LinkConfig::Git {
                repo,
                branch: _,
                locked_commit,
            } => {
                let (path, _hash) = checkouts::Manager::checkout_of(
                    self,
                    repo,
                    checkouts::GitRef::Commit(locked_commit.clone().unwrap()),
                )?;
                Ok(path)
            }
        }
    }
}

/// The dependency graph.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct DepGraph {
    /// All the build-specs known to this dependency graph.
    builds: Arena<BuildSpec>,
    /// The top level build-specs (i.e. non-transitive) that were read when
    /// constructing this dependency graph.
    pub top_levels: Vec<BuildSpecRef>,

    /// Profiles (custom packages, env vars etc) by name.
    profiles: HashMap<String, Profile>,
    /// Harnesses (a way to build a directory of software) by name.
    harnesses: HashMap<String, Harness>,

    /// Indexes build-specs by name.
    by_name: HashMap<String, BuildSpecRef>,

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
            by_name: HashMap::with_capacity(2048),
            top_levels: Vec::new(),
            profiles: HashMap::with_capacity(32),
            harnesses: HashMap::with_capacity(32),
            hash_cache: Arc::new(RwLock::new((
                HashMap::with_capacity(4096),
                HashMap::with_capacity(4096),
            ))),
        }
    }

    /// Constructs a dependency graph using the given origin to load the leaf layer,
    /// and resolving the files for upstream layers using the given implementation of [SourceProvider].
    ///
    /// The given leaf paramater must not be `SpecOrigin::Inline`, or this function will panic.
    pub fn new_from_chain<SP: SourceProvider>(
        sp: &mut SP,
        leaf: SpecOrigin,
        minimal_lib_path: PathBuf,
    ) -> Result<Self, Error> {
        let mut layers = Vec::with_capacity(6);

        let mut cursor = Some(leaf);

        while let Some(upstream) = cursor.take() {
            let src_path = match &upstream {
                SpecOrigin::Inline => {
                    panic!("SpecOrigin::Inline given as leaf to new_from_chain()")
                }
                SpecOrigin::Repo(Repo::Git { url, rev, tracking }) => sp
                    .checkout_of(&LinkConfig::Git {
                        repo: url.clone(),
                        branch: tracking.as_ref().and_then(|b| match b {
                            common::repo_spec::GitRef::Branch(b) => Some(b.clone()),
                            common::repo_spec::GitRef::Tag(_t) => None,
                        }),
                        locked_commit: Some(rev.clone()),
                    })
                    .map_err(|e| Error::Fetch(e.to_string()))?,
                SpecOrigin::LocalDir { absolute, .. } => absolute.clone(),
            };

            let layer = Layer::new(
                src_path,
                &decode::LoadOptions {
                    minimal_lib_path: minimal_lib_path.clone(),
                    from: upstream.clone(),
                },
            )
            .map_err(Error::Decode)?;

            cursor = if let Some(next_upstream) = layer.upstream() {
                match next_upstream {
                    LinkConfig::Git {
                        repo,
                        branch: _,
                        locked_commit,
                    } => {
                        if upstream
                            .as_repo()
                            .is_some_and(|r| matches!(r, Repo::Git { url, ..} if url == repo))
                        {
                            return Err(Error::Fetch(format!(
                                "layer at {} defines an upstream that points to itself",
                                repo.clone(),
                            )));
                        }
                        if locked_commit.is_none() {
                            return Err(Error::UpstreamNotPinned {
                                upstream: repo.to_string(),
                                at_layer: layer.origin,
                            });
                        }
                    }
                    LinkConfig::Dir { .. } => {} // nothing to validate
                };

                Some(next_upstream.as_spec_origin().unwrap())
            } else {
                None
            };
            layers.push(layer);
        }

        let mut out = Self::new();
        for layer in layers.into_iter().rev() {
            out = out.ingest(layer)?;
        }
        Ok(out)
    }

    /// Loads build declarations in from the given layer.
    pub fn ingest(self, layer: Layer) -> Result<Self, Error> {
        let mut loader = Loader {
            origin: Arc::new(layer.origin.clone()),
            from: layer,
            into_graph: RefCell::new(self),
            resolved: RefCell::new(HashMap::with_capacity(1024)),
        };
        let new_toplevels = loader.load_toplevels()?;

        let mut slf = loader.into_graph.into_inner();
        slf.top_levels.extend(new_toplevels);

        // Iterate all the builds that were just added.
        for (bsr, b) in slf
            .builds
            .iter()
            .filter(|(_bsr, b)| b.from.as_ref() == &loader.from.origin)
        {
            // Subsets reference outputs by name. Validate for these new
            // build-specs that any subsets reference outputs that exist.
            for subset in b
                .inputs
                .iter()
                .filter_map(|input| {
                    if let BuildSpecInput::Subset(s) = input {
                        Some(s)
                    } else {
                        None
                    }
                })
                .chain(b.runtime_deps.iter().filter_map(|rd| {
                    if let RuntimeDep::Subset(s) = rd {
                        Some(s)
                    } else {
                        None
                    }
                }))
            {
                let build = slf.builds.get(subset.from.0).unwrap();
                for output in &subset.outputs {
                    if !build.outputs.contains_key(output) {
                        return Err(Error::NoSuchOutput {
                            from: (subset.from, build.name.clone()),
                            build: (BuildSpecRef(bsr), b.name.clone()),
                            output: output.clone(),
                        });
                    }
                }
            }

            // Add new builds by name to the name index. Error out if there are duplicates - thats illegal for now.
            if let Some(exists) = slf.by_name.insert(b.name.clone(), BuildSpecRef(bsr)) {
                return Err(Error::ConflictingPackage {
                    from: (exists, b.name.clone()),
                    build: (BuildSpecRef(bsr), b.name.clone()),
                });
            }
        }

        // Load/union profiles
        for (name, mut profile) in loader.from.profiles {
            // Apply any inheritance
            if let Some(base_profile_name) = &profile.from_profile {
                match slf.profiles.get(base_profile_name) {
                    None => {
                        return Err(Error::NoSuchProfile {
                            name: base_profile_name.clone(),
                        });
                    }
                    Some(base_profile) => {
                        let mut new = base_profile.clone();
                        new.union(&profile);
                        profile = new;
                    }
                }
            }

            // Verify all packages exist
            for pkg in &profile.packages {
                if slf.by_name(pkg).is_none() {
                    return Err(Error::NoSuchPkg { name: pkg.clone() });
                }
            }

            if let Some(existing) = slf.profiles.get_mut(&name) {
                // Its illegal to shadow a profile of the same name from upstream,
                // unless you inherit from some upstream profile.
                if profile.from_profile.is_none() {
                    return Err(Error::ConflictingProfile { name });
                }
                *existing = profile;
            } else {
                slf.profiles.insert(name, profile);
            }
        }
        // Load harnesses
        for (name, harness) in loader.from.harnesses {
            // Verify all packages exist
            for pkg in &harness.build_packages {
                if slf.by_name(pkg).is_none() {
                    return Err(Error::NoSuchPkg { name: pkg.clone() });
                }
            }
            for pkg in &harness.runtime_packages {
                if slf.by_name(pkg).is_none() {
                    return Err(Error::NoSuchPkg { name: pkg.clone() });
                }
            }

            if slf.harnesses.contains_key(&name) {
                // Its illegal to shadow a harness of the same name from upstream.
                return Err(Error::ConflictingHarness { name });
            }
            slf.harnesses.insert(name, harness);
        }

        Ok(slf)
    }

    /// Fetches a build-spec by reference.
    pub fn get(&self, bsr: &BuildSpecRef) -> Option<&BuildSpec> {
        self.builds.get(bsr.0)
    }

    /// Returns the build-spec reference with the given name.
    pub fn by_name<S: AsRef<str>>(&self, name: S) -> Option<&BuildSpecRef> {
        self.by_name.get(name.as_ref())
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

    /// Returns an iterator over all build-spec references which originated from the
    /// given layer/repository.
    pub fn from_origin(&self, origin: &SpecOrigin) -> impl Iterator<Item = BuildSpecRef> {
        self.builds
            .iter()
            .filter(move |(_bsr, b)| b.from.as_ref() == origin)
            .map(|(bsr, _b)| BuildSpecRef(bsr))
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
                Source(_) | HostPath(_) | Local { .. } => None,
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

    /// Hydrates a minimal task with configuration based on the harness and
    /// any profile it calls for, if any.
    pub fn hydrate_task(&self, harness: Option<&str>, task: &mut mfile::Task) -> Result<(), Error> {
        if let Some(name) = harness {
            let harness = self.harness(name).ok_or_else(|| Error::NoSuchHarness {
                name: name.to_string(),
            })?;
            // Upsert the packages list
            task.packages.extend(
                harness
                    .build_packages
                    .iter()
                    .chain(harness.runtime_packages.iter())
                    .filter(|p| !task.packages.contains(p))
                    .cloned()
                    .collect::<Vec<_>>(),
            );
            // Set environment variables, but only if they are not set already
            for (k, v) in &harness.build_env_vars {
                if !task.vars.contains_key(k) {
                    task.vars.insert(k.clone(), v.clone());
                }
            }
        }

        match &task.profile {
            None => Ok(()),
            Some(s) if s.is_empty() => Ok(()),
            Some(profile) => {
                if let Some(profile) = self.profiles.get(profile) {
                    // Upsert the packages list
                    task.packages.extend(
                        profile
                            .packages
                            .iter()
                            .filter(|p| !task.packages.contains(p))
                            .cloned()
                            .collect::<Vec<_>>(),
                    );
                    // Set environment variables, but only if they are not set already
                    for (k, v) in &profile.env_vars {
                        if !task.vars.contains_key(k) {
                            task.vars.insert(k.clone(), v.clone());
                        }
                    }
                    // Union any file patches, if they are not set already
                    let mut patches = profile.patch.clone();
                    patches.union(&task.patch);
                    task.patch = patches;
                    Ok(())
                } else {
                    Err(Error::NoSuchProfile {
                        name: profile.clone(),
                    })
                }
            }
        }
    }

    /// Returns the named harness, if it exists.
    pub fn harness(&self, name: &str) -> Option<&Harness> {
        self.harnesses.get(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use decode::{Layer, LoadOptions};
    use indoc::indoc;
    use mfile::MFILE_NAME;
    use tempfile::TempDir;

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

        let dp = DepGraph::new().ingest(layer).unwrap();
        assert!(dp.spec_hash(dp.by_name("b1").unwrap()) != dp.spec_hash(dp.by_name("b2").unwrap()),);
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

        let dp = DepGraph::new().ingest(layer).unwrap();
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

        let dp = DepGraph::new().ingest(layer).unwrap();
        // We expect two buildspecs
        assert_eq!(
            vec!["build 1".to_string(), "build 2".to_string(),],
            dp.builds
                .into_iter()
                .map(|b| b.name)
                .collect::<Vec<String>>()
        );
    }

    #[test]
    fn ingest_profile() {
        let layer = Layer::new_for_test(
            indoc! {
                "
                let {layer, profile, ..} = import \"minimal.ncl\" in

                layer {
                  builds = [],
                  profiles = [
                    profile {
                      name = \"profile 1\",
                    }
                  ],
                }
                "
            }
            .to_string(),
        )
        .unwrap_or_else(|e| {
            e.report_to_stderr();
            panic!("spec parsing failed");
        });

        let dp = DepGraph::new().ingest(layer).unwrap();
        assert_eq!(
            dp.profiles.get("profile 1"),
            Some(&Profile {
                name: "profile 1".to_string(),
                from_profile: None,
                packages: vec![],
                env_vars: Default::default(),
                patch: Default::default(),
            })
        );
    }

    #[test]
    fn profile_overwrites_on_conflict() {
        let mut dp = DepGraph::new();
        dp.profiles.insert(
            "prof".to_string(),
            Profile {
                name: "prof".to_string(),
                from_profile: None,
                packages: vec!["base".to_string()],
                env_vars: IndexMap::from_iter([("CC".to_string(), "gcc".to_string())]),
                patch: Default::default(),
            },
        );
        dp.builds.insert(BuildSpec {
            name: "base".to_string(),
            ..Default::default()
        });

        let layer = Layer::new_for_test(
            indoc! {
                "
                let {build, layer, profile, ..} = import \"minimal.ncl\" in

                layer {
                  builds = [
                    build{name = \"extra\", inputs = [], cmd = \"\"},
                  ],
                  profiles = [
                    profile {
                      name = \"prof\",
                      from_profile = \"prof\",
                      packages = [\"extra\"],
                      env_vars = {
                        CC = \"clang\",
                      }
                    }
                  ],
                }
                "
            }
            .to_string(),
        )
        .unwrap_or_else(|e| {
            e.report_to_stderr();
            panic!("spec parsing failed");
        });
        let dp = dp.ingest(layer).unwrap();

        assert_eq!(
            dp.profiles.get("prof"),
            Some(&Profile {
                name: "prof".to_string(),
                from_profile: Some("prof".to_string()),
                packages: vec!["base".to_string(), "extra".to_string()],
                env_vars: IndexMap::from_iter([("CC".to_string(), "clang".to_string())]),
                patch: Default::default(),
            })
        );
    }
    #[test]
    fn ingest_harness() {
        let layer = Layer::new_for_test(
            indoc! {
                "
                let {layer, harness, ..} = import \"minimal.ncl\" in

                layer {
                  builds = [],
                  harnesses = [
                    harness {
                      name = \"harness 1\",
                      build_cmd = \"beep boop\",
                    }
                  ],
                }
                "
            }
            .to_string(),
        )
        .unwrap_or_else(|e| {
            e.report_to_stderr();
            panic!("spec parsing failed");
        });

        let dp = DepGraph::new().ingest(layer).unwrap();
        assert_eq!(
            dp.harnesses.get("harness 1"),
            Some(&Harness {
                name: "harness 1".to_string(),
                build_cmds: Some(vec![vec!["beep".to_string(), "boop".to_string()]]),
                ..Default::default()
            })
        );
    }

    struct SourceProviderFake(HashMap<LinkConfig, TempDir>);

    impl SourceProvider for SourceProviderFake {
        type Error = std::io::Error;

        fn checkout_of(&mut self, upstream: &LinkConfig) -> Result<PathBuf, Self::Error> {
            match self.0.get(upstream) {
                None => Err(std::io::Error::other("not found")),
                Some(td) => Ok(td.path().to_path_buf()),
            }
        }
    }

    #[test]
    fn basic_chain() {
        let apex = TempDir::new().unwrap();
        std::fs::create_dir_all(apex.path().join("packages").join("top")).unwrap();
        std::fs::write(
            apex.path().join("packages").join("top").join("build.ncl"),
            indoc! {
            "
            let {build, ..} = import \"minimal.ncl\" in

            build {
                name = \"top\",
                inputs = [],
                cmd = \"\",
            }"
            },
        )
        .unwrap();
        let apex_repo = LinkConfig::Git {
            repo: "git@fakehub.com:minimal/apex.git".to_string(),
            locked_commit: Some("abc123".to_string()),
            branch: None,
        };

        let middle = TempDir::new().unwrap();
        std::fs::write(
            middle.path().join(MFILE_NAME),
            indoc! {
            "
            [upstream]
            repo = \"git@fakehub.com:minimal/apex.git\"
            locked_commit = \"abc123\"
            "
            },
        )
        .unwrap();
        std::fs::create_dir_all(middle.path().join("packages").join("middle")).unwrap();
        std::fs::write(
            middle
                .path()
                .join("packages")
                .join("middle")
                .join("build.ncl"),
            indoc! {
            "
            let {build, upstream, ..} = import \"minimal.ncl\" in

            build {
                name = \"middle\",
                inputs = [upstream \"top\"],
                cmd = \"\",
            }"
            },
        )
        .unwrap();
        let middle_repo = LinkConfig::Git {
            repo: "git@fakehub.com:minimal/middle.git".to_string(),
            locked_commit: Some("abc123".to_string()),
            branch: None,
        };

        let mut sp = SourceProviderFake(HashMap::from_iter([
            (apex_repo.clone(), apex),
            (middle_repo.clone(), middle),
        ]));
        let graph = DepGraph::new_from_chain(
            &mut sp,
            middle_repo.as_spec_origin().unwrap(),
            LoadOptions::for_test().minimal_lib_path,
        )
        .unwrap();

        // Make sure the build from both layers is present
        assert_eq!(
            graph
                .builds
                .iter()
                .map(|(_, b)| &b.name)
                .collect::<Vec<_>>(),
            vec!["top", "middle"]
        );
        // Make sure the middle reference to the upstream package is well formed
        let m = graph.get(graph.by_name("middle").unwrap()).unwrap();
        assert_eq!(
            m.inputs[0].as_build().unwrap(),
            graph.by_name("top").unwrap()
        );
    }

    #[test]
    fn ingest_test() {
        let layer = Layer::new_for_test(
            indoc! {
                "
                let {standaloneTest, BuildSpec, ..} = import \"minimal.ncl\" in

                let
                    b1 = {
                        name = \"build 1\",
                        inputs = [],
                        cmd = \"\",
                    } | BuildSpec,
                    b2 = {
                        name = \"build 2\",
                        inputs = [],
                        tests.smoketest = standaloneTest \"some_cmd\",
                        cmd = \"\",
                    } | BuildSpec,
                in
                b2
                "
            }
            .to_string(),
        )
        .unwrap_or_else(|e| {
            e.report_to_stderr();
            panic!("spec parsing failed");
        });

        let dp = DepGraph::new().ingest(layer).unwrap();
        let build = dp.get(dp.by_name("build 2").unwrap()).unwrap();
        assert_eq!(
            build.tests,
            Some(
                [(
                    "smoketest".to_string(),
                    SpecTest {
                        build_test: false,
                        deps: None,
                        cmds: vec![vec!["some_cmd".to_string()]],
                    }
                )]
                .into()
            )
        );
    }
}
