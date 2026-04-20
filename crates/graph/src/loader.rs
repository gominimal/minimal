//! Construction of a [Graph] from decoded [Layer]s.
//!
//! This module owns the "how do I turn nickel output into a graph" half of the crate:
//! the [SourceProvider] / [LayerCache] abstractions that feed layers in, the
//! [ChainLoader] that walks an upstream chain, the internal `Loader` that hydrates
//! a single layer's build declarations into [`BuildSpec`]s, and the [`Graph::ingest`]
//! / [`Graph::new_from_chain`] entry points on [Graph] itself.
//!
//! [Graph]'s query / mutation surface lives in `graph.rs`; this file only adds
//! construction methods.

#![allow(clippy::result_large_err)]
#![allow(clippy::single_match)]

use common::repo_spec::Repo;
use common::{SpecOrigin, Target};
use decode::builds::BuildRef;
use decode::{Layer, LoadOptions, builds};
use mfile::{LinkConfig, Upstream};
use nickel_lang_core::term::IndexMap;

use smallvec::SmallVec;
use std::cell::RefCell;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use crate::builds::*;
use crate::{BuildSpecRef, Error, Graph};

/// Manages loading a [Layer] into a [Graph].
struct Loader {
    from: Layer,
    origin: Arc<SpecOrigin>,
    into_graph: RefCell<Graph>,
    resolved: RefCell<HashMap<generational_arena::Index, BuildSpecRef>>,
    /// The target the containing graph is being constructed for. Used to hydrate
    /// any [`decode::builds::BuildDecl::target`] that was left `None` by the
    /// decoder (i.e. no explicit target in the NCL).
    for_target: Target,
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
            builds::BuildOutput::Binary {
                glob,
                allow_missing_interpreter,
            } => Self::Binary {
                glob,
                allow_missing_interpreter,
            },
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
            // If the NCL didn't explicitly set a target, inherit from the
            // graph's target. This is how a graph constructed on amd64 for
            // arm64 execution (e.g. buildbot dispatching to res-server-arm64)
            // produces specs that match the destination host.
            target: bd
                .target
                .clone()
                .unwrap_or_else(|| loader.for_target.clone()),
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

impl SourceProvider for checkouts::ManagerHandle {
    type Error = checkouts::Error;

    fn checkout_of(&mut self, upstream: &LinkConfig) -> Result<PathBuf, Self::Error> {
        match upstream {
            LinkConfig::Dir { dir } => Ok(dir.into()),
            LinkConfig::Git {
                repo,
                branch: _,
                locked_commit,
            } => {
                let (path, _hash) = checkouts::ManagerHandle::checkout_of(
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

    fn insert(&mut self, lo: LoadOptions, layer: &Layer) -> Result<(), Self::Error>;
    fn get(&mut self, lo: &LoadOptions) -> Result<Option<Layer>, Self::Error>;
}

impl LayerCache for () {
    type Error = ();

    fn insert(&mut self, _lo: LoadOptions, _layer: &Layer) -> Result<(), Self::Error> {
        Ok(())
    }
    fn get(&mut self, _lo: &LoadOptions) -> Result<Option<Layer>, Self::Error> {
        Ok(None)
    }
}

/// A layer cache which serializes layers in the given directory.
pub struct LayerCacheDir(pub PathBuf);

impl LayerCache for LayerCacheDir {
    type Error = ();

    fn insert(&mut self, lo: LoadOptions, layer: &Layer) -> Result<(), Self::Error> {
        // Its only safe to cache stuff that is pinned to a hash
        if !matches!(lo.from, SpecOrigin::Repo(_)) {
            return Ok(());
        }

        let p = self.0.join(lo.input_hash().to_hex().as_ref());
        if std::fs::exists(&p).unwrap_or(false) {
            return Ok(());
        }

        let f = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&p)
            .map_err(|e| {
                tracing::warn!("LayerCacheDir::insert failed open: {}", e);
            })?;
        serde_json::to_writer(f, layer).map_err(|e| {
            tracing::warn!("LayerCacheDir::insert failed to serialize layer: {}", e);
            std::fs::remove_file(p).ok(); // best effort
        })?;

        Ok(())
    }
    fn get(&mut self, lo: &LoadOptions) -> Result<Option<Layer>, Self::Error> {
        let p = self.0.join(lo.input_hash().to_hex().as_ref());

        if let Ok(f) = std::fs::File::open(&p) {
            let layer: Layer = serde_json::from_reader(f).map_err(|e| {
                tracing::warn!("LayerCacheDir::get failed to deserialize: {}", e);
            })?;

            // Local BuildDeps point to the file they represent by path, typically a VCS checkout.
            // As a quick correctness check, spot-check a few local files to make sure the path
            // they reference exists, and the hashes match.
            for (lp, hash) in layer
                .builds
                .iter()
                .flat_map(|(_, b)| &b.build_deps)
                .filter_map(|d| {
                    if let decode::builds::BuildDep::Local {
                        full_path,
                        file_hash,
                        ..
                    } = d
                    {
                        Some((full_path, file_hash))
                    } else {
                        None
                    }
                })
                .take(5)
            {
                if !lp.exists() || hash != &blake3::hash(&std::fs::read(lp).unwrap()) {
                    tracing::warn!(
                        "Skipping layer-cache entry, {} not found or hash mismatch",
                        lp.display()
                    );
                    if let Err(e) = std::fs::remove_file(p) {
                        // best effort
                        tracing::warn!("Failed to clean up layer-cache entry: {}", e);
                    }
                    return Ok(None);
                }
            }

            Ok(Some(layer))
        } else {
            Ok(None)
        }
    }
}

/// Loads layers from source with caching, and assembles them into a [Graph].
///
/// This struct encapsulates the infrastructure needed for chain loading: source resolution
/// via [SourceProvider] and parsed-layer caching via [LayerCache]. The traversal logic
/// (following upstream links, loading sideloads) is implemented as methods, making it
/// easy to reuse `load_layer` for both upstream and sideload loading.
pub struct ChainLoader<'lc, SP: SourceProvider, LC: LayerCache> {
    sp: SP,
    lc: &'lc mut LC,
    minimal_lib_path: PathBuf,
    for_target: Target,
}

impl<'lc, SP: SourceProvider, LC: LayerCache> ChainLoader<'lc, SP, LC> {
    pub fn new(sp: SP, lc: &'lc mut LC, minimal_lib_path: PathBuf, for_target: Target) -> Self {
        Self {
            sp,
            lc,
            minimal_lib_path,
            for_target,
        }
    }

    /// Resolves a [SpecOrigin] to a filesystem path using the [SourceProvider].
    fn resolve_source(&mut self, origin: &SpecOrigin) -> Result<PathBuf, Error> {
        match origin {
            SpecOrigin::Inline => {
                unreachable!()
            }
            SpecOrigin::Repo(Repo::Git { url, rev, tracking }) => self
                .sp
                .checkout_of(&LinkConfig::Git {
                    repo: url.clone(),
                    branch: tracking.as_ref().and_then(|b| match b {
                        common::repo_spec::GitRef::Branch(b) => Some(b.clone()),
                        common::repo_spec::GitRef::Tag(_t) => None,
                    }),
                    locked_commit: Some(rev.clone()),
                })
                .map_err(|e| Error::Fetch(e.to_string())),
            SpecOrigin::LocalDir { absolute, .. } => Ok(absolute.clone()),
        }
    }

    /// Loads a single layer from the given origin, using the cache where possible.
    fn load_layer(
        &mut self,
        upstream: &Upstream,
        params: Option<HashMap<String, args::DiskArg>>,
    ) -> Result<Layer, Error> {
        let origin = upstream.link.as_spec_origin().unwrap();
        let src_path = self.resolve_source(&origin)?;
        let load_opts = LoadOptions {
            minimal_lib_path: self.minimal_lib_path.clone(),
            from: origin.clone(),
            target: self.for_target.clone(),
            params,
        };

        if let Some(layer) = self
            .lc
            .get(&load_opts)
            .map_err(|e| Error::Fetch(format!("layer-cache fetch: {:?}", e)))?
        {
            Ok(layer)
        } else {
            let layer = Layer::new(src_path, &load_opts).map_err(Error::Decode)?;
            if let Err(e) = self.lc.insert(load_opts, &layer) {
                tracing::warn!("Failed to cache layer for origin {:?}: {:?}", origin, e);
            }
            Ok(layer)
        }
    }

    /// Validates a layer's upstream reference and returns the next [Upstream] to load,
    /// or `None` if this layer is the root of the chain.
    fn next_upstream(
        layer: &Layer,
        current_origin: &SpecOrigin,
    ) -> Result<Option<Upstream>, Error> {
        let Some(next_upstream) = layer.upstream() else {
            return Ok(None);
        };

        match &next_upstream.link {
            LinkConfig::Git {
                repo,
                branch: _,
                locked_commit,
            } => {
                if current_origin
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
                        at_layer: layer.origin.clone(),
                    });
                }
            }
            LinkConfig::Dir { .. } => {}
        };

        Ok(Some(next_upstream.clone()))
    }

    /// Loads the full layer chain starting from a leaf, including any sideloads
    /// declared by layers in the chain, and assembles them into a [Graph].
    pub fn load_chain(&mut self, leaf: LinkConfig) -> Result<Graph, Error> {
        let mut layers = Vec::with_capacity(6);
        let mut cursor = Some(Upstream::from_link(leaf));

        while let Some(upstream) = cursor.take() {
            // Load sideloads declared by this layer. They are pushed before
            // the declaring layer so they can depend on packages from the upstream.
            for sideload in upstream.sideloads().iter().rev() {
                layers.push(self.load_layer(
                    &Upstream::from_link(sideload.link().clone()),
                    sideload.params().cloned(),
                )?);
            }

            let layer = self.load_layer(&upstream, None)?;
            cursor = Self::next_upstream(&layer, &upstream.link.as_spec_origin().unwrap())?;
            layers.push(layer);
        }

        let mut out = Graph::new();
        out.target = self.for_target.clone();
        for layer in layers.into_iter().rev() {
            out = out.ingest(layer)?;
        }
        Ok(out)
    }
}

// =============================================================================
// Graph construction entry points.
// =============================================================================

impl Graph {
    /// Constructs a dependency graph using the given origin to load the leaf layer,
    /// and resolving the files for upstream layers using the given implementation of [SourceProvider].
    ///
    /// This is a convenience wrapper around [ChainLoader]. For more control over the
    /// loading process (e.g. loading individual layers), construct a [ChainLoader] directly.
    pub fn new_from_chain<SP: SourceProvider, LC: LayerCache>(
        sp: SP,
        lc: &mut LC,
        leaf: LinkConfig,
        minimal_lib_path: PathBuf,
        for_target: Target,
    ) -> Result<Self, Error> {
        ChainLoader::new(sp, lc, minimal_lib_path, for_target).load_chain(leaf)
    }

    /// Loads build declarations in from the given layer.
    pub fn ingest(self, layer: Layer) -> Result<Self, Error> {
        // Capture the target before self moves into the Loader. Set by
        // `new_from_chain` (`out.target = for_target`) prior to ingesting layers.
        let for_target = self.target.clone();
        let mut loader = Loader {
            origin: Arc::new(layer.origin.clone()),
            from: layer,
            into_graph: RefCell::new(self),
            resolved: RefCell::new(HashMap::with_capacity(1024)),
            for_target,
        };
        let new_toplevels = loader.load_toplevels()?;

        let mut slf = loader.into_graph.into_inner();
        slf.top_levels.extend(new_toplevels);
        slf.supply_chain.push(loader.origin.as_ref().clone());

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
}

#[cfg(test)]
mod tests {
    use super::*;
    use decode::{Layer, LoadOptions, Profile};
    use indoc::indoc;
    use mfile::{EnvVarValue, MFILE_NAME};
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
                env_vars: IndexMap::from_iter([(
                    "CC".to_string(),
                    EnvVarValue::Value("gcc".to_string()),
                )]),
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
                env_vars: IndexMap::from_iter([(
                    "CC".to_string(),
                    EnvVarValue::Value("clang".to_string())
                )]),
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
            Some(&decode::Harness {
                name: "harness 1".to_string(),
                build_cmds: Some(vec![vec!["beep".to_string(), "boop".to_string()]]),
                ..Default::default()
            })
        );
    }

    struct SourceProviderFake(HashMap<LinkConfig, TempDir>);

    impl SourceProvider for &mut SourceProviderFake {
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
            middle_repo.clone(),
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

        // Make sure the supply chain was tracked in the correct order
        assert_eq!(
            graph.software_supply_chain(),
            &vec![
                apex_repo.as_spec_origin().unwrap(),
                middle_repo.as_spec_origin().unwrap(),
            ],
        )
    }

    #[test]
    fn sideload_chain() {
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

        let root = TempDir::new().unwrap();
        std::fs::write(
            root.path().join(MFILE_NAME),
            indoc! {
            "
            [upstream]
            repo = \"git@fakehub.com:minimal/apex.git\"
            locked_commit = \"abc123\"

            [[upstream.sideload]]
            repo = \"git@fakehub.com:minimal/sideload-noparams.git\"
            locked_commit = \"def\"

            [[upstream.sideload]]
            repo = \"git@fakehub.com:minimal/sideload-params.git\"
            locked_commit = \"def\"
            params.enum = \"a\"
            "
            },
        )
        .unwrap();
        std::fs::create_dir_all(root.path().join("packages").join("root")).unwrap();
        std::fs::write(
            root.path().join("packages").join("root").join("build.ncl"),
            indoc! {
            "
            let {build, upstream, ..} = import \"minimal.ncl\" in

            build {
                name = \"root\",
                build_deps = [upstream \"top\"],
                cmd = \"\",
            }"
            },
        )
        .unwrap();
        let root_repo = LinkConfig::Git {
            repo: "git@fakehub.com:minimal/root.git".to_string(),
            locked_commit: Some("abc123".to_string()),
            branch: None,
        };

        let sideload_noparams = TempDir::new().unwrap();
        std::fs::write(
            sideload_noparams.path().join(MFILE_NAME),
            indoc! {
            "
            [upstream]
            repo = \"git@fakehub.com:minimal/apex.git\"
            locked_commit = \"abc123\"
            "
            },
        )
        .unwrap();
        std::fs::create_dir_all(
            sideload_noparams
                .path()
                .join("packages")
                .join("sideload-noparams"),
        )
        .unwrap();
        std::fs::write(
            sideload_noparams
                .path()
                .join("packages")
                .join("sideload-noparams")
                .join("build.ncl"),
            indoc! {
            "
            let {build, upstream, ..} = import \"minimal.ncl\" in

            build {
                name = \"sideload-noparams\",
                build_deps = [upstream \"top\"],
                cmd = \"\",
            }"
            },
        )
        .unwrap();
        let sideload_noparams_repo = LinkConfig::Git {
            repo: "git@fakehub.com:minimal/sideload-noparams.git".to_string(),
            locked_commit: Some("def".to_string()),
            branch: None,
        };
        let sideload_params = TempDir::new().unwrap();
        std::fs::write(
            sideload_params.path().join(MFILE_NAME),
            indoc! {
            "
            [upstream]
            repo = \"git@fakehub.com:minimal/apex.git\"
            locked_commit = \"abc123\"

            [params]
            enum = {type = \"[\\\"a\\\", \\\"b\\\"]\", default =\"b\"}
            cmd = {type = \"string\", default =\"tar\"}
            "
            },
        )
        .unwrap();
        std::fs::create_dir_all(
            sideload_params
                .path()
                .join("packages")
                .join("sideload-params"),
        )
        .unwrap();
        std::fs::write(
            sideload_params
                .path()
                .join("packages")
                .join("sideload-params")
                .join("build.ncl"),
            indoc! {
            "
            let {build, upstream, ..} = import \"minimal.ncl\" in
            let {param, ..} = import \"config.ncl\" in

            build {
                name = \"sideload-params\",
                build_deps = [upstream \"top\"],
                cmd = param \"cmd\",
                attrs.upstream_version = param \"enum\",
            }"
            },
        )
        .unwrap();
        let sideload_params_repo = LinkConfig::Git {
            repo: "git@fakehub.com:minimal/sideload-params.git".to_string(),
            locked_commit: Some("def".to_string()),
            branch: None,
        };

        let mut sp = SourceProviderFake(HashMap::from_iter([
            (apex_repo.clone(), apex),
            (root_repo.clone(), root),
            (sideload_noparams_repo.clone(), sideload_noparams),
            (sideload_params_repo.clone(), sideload_params),
        ]));
        let graph = Graph::new_from_chain(
            &mut sp,
            &mut (),
            root_repo.clone(),
            LoadOptions::for_test().minimal_lib_path,
            Target::default(),
        )
        .unwrap();

        // Make sure the build from both apex, middle, & sideloads are present
        assert_eq!(
            graph
                .builds
                .iter()
                .map(|(_, b)| &b.name)
                .collect::<Vec<_>>(),
            vec!["top", "sideload-noparams", "sideload-params", "root"]
        );

        // Check the parameterization that set on sideload-params
        // Param 'cmd' should have gotten default 'tar'.
        assert_eq!(
            graph
                .get(graph.by_name("sideload-params").unwrap())
                .unwrap()
                .cmds,
            vec![vec!["tar".to_string()]]
        );
        // Param 'enum' should have gotten defined value (not default) 'a'.
        // We stuffed it into upstream_version.
        assert_eq!(
            graph
                .get(graph.by_name("sideload-params").unwrap())
                .unwrap()
                .upstream_version(),
            Some(&"a".to_string()),
        );

        // Make sure the supply chain was tracked in the correct order
        assert_eq!(
            graph.software_supply_chain(),
            &vec![
                apex_repo.as_spec_origin().unwrap(),
                sideload_noparams_repo.as_spec_origin().unwrap(),
                sideload_params_repo.as_spec_origin().unwrap(),
                root_repo.as_spec_origin().unwrap(),
            ],
        )
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
