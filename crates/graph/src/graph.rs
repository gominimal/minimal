//! The dependency graph.

#![allow(clippy::result_large_err)]
#![allow(clippy::single_match)]

use common::repo_spec::Repo;
use common::{SpecOrigin, Target};
use decode::builds::BuildRef;
use decode::{Harness, Layer, Profile, builds};
use mfile::{self, LinkConfig};
use nickel_lang_core::term::IndexMap;

use generational_arena::Arena;
use smallvec::SmallVec;
use std::cell::RefCell;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use crate::spec_hasher::SubsetHasher;
use crate::{Error, SpecHash, SpecHasher};

use crate::BuildSpecRef;
use crate::builds::*;

/// Manages loading a [Layer] into [DepGraph].
struct Loader {
    from: Layer,
    origin: Arc<SpecOrigin>,
    into_graph: RefCell<Graph>,
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

// === from_decoded impls (kept here because they depend on Loader) ===

impl SubsetInput {
    fn from_decoded(si: &builds::SubsetInput, loader: &Loader) -> Result<Self, Error> {
        Ok(Self {
            from: loader.load(&si.from)?,
            outputs: si.outputs.clone(),
        })
    }
}

impl BuildDep {
    fn from_decoded(i: &builds::BuildDep, loader: &Loader) -> Result<Self, Error> {
        Ok(match i {
            builds::BuildDep::Build(br) => Self::Build(loader.load(br)?),
            builds::BuildDep::Source(s) => Self::Source(s.clone().into()),
            builds::BuildDep::HostPath(p) => Self::HostPath(p.clone()),
            builds::BuildDep::Local {
                full_path,
                filename,
                file_hash,
            } => Self::Local {
                full_path: full_path.clone(),
                filename: filename.clone(),
                file_hash: *file_hash,
            },
            builds::BuildDep::Subset(si) => Self::Subset(SubsetInput::from_decoded(si, loader)?),
        })
    }
}

impl BuildOutput {
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

impl RuntimeDep {
    fn from_decoded(d: &builds::RuntimeDep, loader: &Loader) -> Result<Self, Error> {
        Ok(match d {
            builds::RuntimeDep::Build(br) => Self::Build(loader.load(br)?),
            builds::RuntimeDep::Subset(si) => Self::Subset(SubsetInput::from_decoded(si, loader)?),
        })
    }
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

impl BuildSpec {
    fn from_decoded(bd: &builds::BuildDecl, loader: &Loader) -> Result<Self, Error> {
        Ok(Self {
            name: bd.name.clone(),
            target: bd.target.clone(),
            prebuilt: bd.prebuilt,
            cmds: bd.cmds.clone(),
            build_args: bd.build_args.clone(),

            build_deps: bd
                .build_deps
                .iter()
                .map(|i| BuildDep::from_decoded(i, loader))
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

/// Describes something that can cache a [Layer], that is, the result of parsing/eval of nickel.
pub trait LayerCache {
    type Error: std::fmt::Debug;

    fn insert(&mut self, origin: SpecOrigin, layer: &Layer) -> Result<(), Self::Error>;
    fn get(&mut self, origin: &SpecOrigin) -> Result<Option<Layer>, Self::Error>;
}

impl LayerCache for () {
    type Error = ();

    fn insert(&mut self, _origin: SpecOrigin, _layer: &Layer) -> Result<(), Self::Error> {
        Ok(())
    }
    fn get(&mut self, _origin: &SpecOrigin) -> Result<Option<Layer>, Self::Error> {
        Ok(None)
    }
}

/// The in-memory representation of the software supply chain: all packages, profiles, and harnesses.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct Graph {
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

impl Default for Graph {
    fn default() -> Self {
        Self::new()
    }
}

impl Graph {
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
    pub fn new_from_chain<SP: SourceProvider, LC: LayerCache>(
        sp: &mut SP,
        lc: &mut LC,
        leaf: SpecOrigin,
        minimal_lib_path: PathBuf,
        for_target: Target,
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

            // Load the layer, either from the layer cache or by doing a full load via [Layer::new].
            let layer = if let Some(layer) = lc
                .get(&upstream)
                .map_err(|e| Error::Fetch(format!("layer-cache fetch: {:?}", e)))?
            {
                layer
            } else {
                let layer = Layer::new(
                    src_path,
                    &decode::LoadOptions {
                        minimal_lib_path: minimal_lib_path.clone(),
                        from: upstream.clone(),
                        target: for_target.clone(),
                    },
                )
                .map_err(Error::Decode)?;

                if let Err(e) = lc.insert(upstream.clone(), &layer) {
                    tracing::warn!("Failed to cache layer for origin {:?}: {:?}", upstream, e);
                }
                layer
            };

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
                .build_deps
                .iter()
                .filter_map(|input| {
                    if let BuildDep::Subset(s) = input {
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
    /// Dependencies of a build-spec are its build dependencies and its runtime dependencies.
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

        use BuildDep::*;
        build_spec
            .build_deps
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

    /// Returns an iterator over all harnesses configured in the graph.
    pub fn iter_harnesses(&self) -> impl Iterator<Item = (&String, &Harness)> {
        self.harnesses.iter()
    }

    /// Returns a list of [BuildSpecRef] objects who's names matched the given search term.
    pub fn fuzzy_name_search(&self, term: &str, num_results: usize) -> Vec<(BuildSpecRef, u32)> {
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
        struct SearchEntry {
            score: u32,
            bsr: BuildSpecRef,
        }

        use std::collections::BinaryHeap;
        let mut results = BinaryHeap::with_capacity(num_results);

        for (bsr, build) in self.builds.iter() {
            let score = fuzzy_match(term, &build.name);
            results.push(std::cmp::Reverse(SearchEntry {
                score,
                bsr: BuildSpecRef(bsr),
            }));
            if results.len() > num_results {
                results.pop();
            }
        }

        // Little-known fact: into_iter() of a vec followed by a collect into a vec
        // where the memory needed is less, doesnt allocate.
        results
            .into_sorted_vec()
            .into_iter()
            .map(|std::cmp::Reverse(SearchEntry { score, bsr })| (bsr, score))
            .collect()
    }
}

fn fuzzy_match(needle: &str, haystack: &str) -> u32 {
    let n = needle.trim().to_lowercase();
    let h = haystack.trim().to_lowercase();

    if n == h {
        return 1000;
    }
    if h.contains(n.as_str()) {
        return 950;
    }

    let mut h_rest = h.as_str();
    let mut score = 0u32;
    let mut consecutive_bonus = 0u32;
    let mut matched = 0u32;

    for ch in n.chars() {
        if let Some(idx) = h_rest.find(ch) {
            consecutive_bonus = if idx == 0 && matched > 0 {
                consecutive_bonus + 1
            } else {
                0
            };
            score += 10 + consecutive_bonus;
            h_rest = &h_rest[idx + ch.len_utf8()..];
            matched += 1;
        }
    }

    let n_len = n.chars().count() as u32;
    let h_len = h.chars().count() as u32;
    let char_score = score * 10 / (n_len * 11); // approx divide by 1.1
    let length_penalty_num = n_len * 100 / n_len.max(h_len);
    (char_score * length_penalty_num / 100).min(900)
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
                b1"
            }
            .to_string(),
        )
        .unwrap_or_else(|e| {
            e.report_to_stderr();
            panic!("spec parsing failed");
        });

        let dp = Graph::new().ingest(layer).unwrap();
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
                    build_deps = [
                        {url = \"http://uwu.com\", sha256 = \"abcdef\"} | Source,
                    ],
                    cmd = \"\",
                } | BuildSpec
                in

                {
                    name = \"top build\",
                    build_deps = [
                        shared,
                        {
                            name = \"second build\",
                            build_deps = [],
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

        let dp = Graph::new().ingest(layer).unwrap();
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
                    build_deps = [b2],
                    cmd = \"\",
                } | BuildSpec,
                b2 = {
                    name = \"build 2\",
                    build_deps = [b1],
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

        let dp = Graph::new().ingest(layer).unwrap();
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
        let mut dp = Graph::new();
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
                    build{name = \"extra\", build_deps = [], cmd = \"\"},
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

        let dp = Graph::new().ingest(layer).unwrap();
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
                build_deps = [],
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
                build_deps = [upstream \"top\"],
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
        let graph = Graph::new_from_chain(
            &mut sp,
            &mut (),
            middle_repo.as_spec_origin().unwrap(),
            LoadOptions::for_test().minimal_lib_path,
            Target::default(),
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
            m.build_deps[0].as_build().unwrap(),
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
                        build_deps = [],
                        cmd = \"\",
                    } | BuildSpec,
                    b2 = {
                        name = \"build 2\",
                        build_deps = [],
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

        let dp = Graph::new().ingest(layer).unwrap();
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

    #[test]
    fn fuzzy_name_search() {
        let layer = Layer::new_for_test(
            indoc! {
                "
                let {BuildSpec, ..} = import \"minimal.ncl\" in

                let
                    b1 = {
                        name = \"libffi\",
                        build_deps = [],
                        cmd = \"\",
                    } | BuildSpec,
                    b2 = {
                        name = \"libxml2\",
                        build_deps = [],
                        cmd = \"\",
                    } | BuildSpec,
                    b3 = {
                        name = \"zlib\",
                        build_deps = [],
                        cmd = \"\",
                    } | BuildSpec,
                in
                [b1, b2, b3]
                "
            }
            .to_string(),
        )
        .unwrap_or_else(|e| {
            e.report_to_stderr();
            panic!("spec parsing failed");
        });

        let dp = Graph::new().ingest(layer).unwrap();

        // Exact match should rank highest
        let results = dp.fuzzy_name_search("libffi", 3);
        assert_eq!(results.len(), 3);
        assert_eq!(dp.get(&results[0].0).unwrap().name, "libffi");

        // Partial match: "lib" should prefer libffi/libxml2 over zlib
        let results = dp.fuzzy_name_search("lib", 2);
        let names: Vec<&str> = results
            .iter()
            .map(|r| dp.get(&r.0).unwrap().name.as_str())
            .collect();
        assert!(names.contains(&"libffi") || names.contains(&"libxml2"));

        // Limiting num_results works
        let results = dp.fuzzy_name_search("lib", 1);
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn conditional_on_config() {
        let layer = Layer::new_for_test(
            indoc! {
                "
                let {BuildSpec, ..} = import \"minimal.ncl\" in
                let {target, ..} = import \"config.ncl\" in

                {
                    name = \"build 1\",
                    build_deps = [],
                    cmd = match {
                      {arch = 'Amd64, ..} => \"good\",
                      _ => \"bad\",
                    } target,
                } | BuildSpec
                "
            }
            .to_string(),
        )
        .unwrap_or_else(|e| {
            e.report_to_stderr();
            panic!("spec parsing failed");
        });

        let dp = Graph::new().ingest(layer).unwrap();
        // We expect the singular buildspec to have a command 'good', because
        // the default target (used in tests) is amd64/linux.
        assert_eq!(
            Some(vec![vec!["good".to_string()]]),
            dp.builds.into_iter().map(|b| b.cmds).next()
        );
    }
}
