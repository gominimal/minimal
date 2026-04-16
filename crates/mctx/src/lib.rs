//! Top-level API for minimal tooling.

use std::{
    collections::{HashMap, HashSet},
    fmt,
    path::{Path, PathBuf},
    time::SystemTime,
};

use anyhow::anyhow;
use checkouts::{Manager as VcsManager, ManagerHandle as VcsManagerHandle};
use common::{SpecOrigin, Target};
use google_cloud_storage::{Error as GcsError, client::Storage as GcsStorage};
use lcache::CacheBinProvider;
use ot::OpTracker;
use rcache::{Error as RemoteError, RemoteBinProvider, RemoteCache};

mod error;
pub use error::Error;
mod config;
pub use config::{Config, ConfigBuilder, ConfigError};
mod env;
use graph::{BinProvider, BuildSpecRef, Graph, MaskingBinProvider, Transitives};
use mfile::{EnvPatches, EnvVarValue, Task};
pub use sandbox2::config::Invocation;

pub use env::Env;
use toml_edit::{Array, DocumentMut, Item, TableLike, Value};

use crate::env::EnvArgs;

/// The local cache.
pub type Cache = lcache::Cache<lcache::LocalDir>;

/// Anything which represents a set of packages.
///
/// Anywhere you see this as a parameter, you can pass:
///
///  - `Vec<String>`
///  - `Vec<BuildSpecRef>`
///  - `HashSet<BuildSpecRef>`
///  - `["literal strings"]`
///  - `[String]`
pub trait PackageSelection {
    type NameIter<'a>: Iterator<Item = &'a str>
    where
        Self: 'a;
    type RefIter<'a>: Iterator<Item = &'a BuildSpecRef>
    where
        Self: 'a;

    fn as_names(&self) -> Option<Self::NameIter<'_>>;
    fn as_refs(&self) -> Option<Self::RefIter<'_>> {
        None
    }

    fn as_bsrs(&self, g: &Graph) -> Result<Vec<BuildSpecRef>, Error> {
        if let Some(bsrs) = self.as_refs() {
            Ok(bsrs.copied().collect())
        } else {
            self.as_names()
                .unwrap()
                .map(|n| match g.by_name(n) {
                    Some(bsr) => Ok(*bsr),
                    None => Err(Error::Other(anyhow!("No such package: {}", n))),
                })
                .collect::<Result<_, _>>()
        }
    }
}

impl PackageSelection for Vec<String> {
    type NameIter<'a>
        = std::iter::Map<std::slice::Iter<'a, String>, fn(&'a String) -> &'a str>
    where
        Self: 'a;
    type RefIter<'a> = std::slice::Iter<'a, BuildSpecRef>;

    fn as_names(&self) -> Option<Self::NameIter<'_>> {
        Some(self.iter().map(|s| s.as_str()))
    }
}

impl PackageSelection for HashSet<String> {
    type NameIter<'a>
        = std::iter::Map<std::collections::hash_set::Iter<'a, String>, fn(&'a String) -> &'a str>
    where
        Self: 'a;
    type RefIter<'a> = std::slice::Iter<'a, BuildSpecRef>;

    fn as_names(&self) -> Option<Self::NameIter<'_>> {
        Some(self.iter().map(|s| s.as_str()))
    }
}

impl PackageSelection for Vec<BuildSpecRef> {
    type NameIter<'a>
        = std::iter::Map<std::slice::Iter<'a, String>, fn(&'a String) -> &'a str>
    where
        Self: 'a;
    type RefIter<'a> = std::slice::Iter<'a, BuildSpecRef>;

    fn as_names(&self) -> Option<Self::NameIter<'_>> {
        None
    }
    fn as_refs(&self) -> Option<Self::RefIter<'_>> {
        Some(self.iter())
    }
}

impl PackageSelection for HashSet<BuildSpecRef> {
    type NameIter<'a>
        = std::iter::Map<std::slice::Iter<'a, String>, fn(&'a String) -> &'a str>
    where
        Self: 'a;
    type RefIter<'a> = std::collections::hash_set::Iter<'a, BuildSpecRef>;

    fn as_names(&self) -> Option<Self::NameIter<'_>> {
        None
    }
    fn as_refs(&self) -> Option<Self::RefIter<'_>> {
        Some(self.iter())
    }
}

impl<const N: usize> PackageSelection for [&str; N] {
    type NameIter<'a>
        = std::iter::Copied<std::slice::Iter<'a, &'a str>>
    where
        Self: 'a;
    type RefIter<'a>
        = std::iter::Empty<&'a BuildSpecRef>
    where
        Self: 'a;

    fn as_names(&self) -> Option<Self::NameIter<'_>> {
        Some(self.iter().copied())
    }
}

impl<const N: usize> PackageSelection for [String; N] {
    type NameIter<'a>
        = std::iter::Map<std::slice::Iter<'a, String>, fn(&'a String) -> &'a str>
    where
        Self: 'a;
    type RefIter<'a>
        = std::iter::Empty<&'a BuildSpecRef>
    where
        Self: 'a;

    fn as_names(&self) -> Option<Self::NameIter<'_>> {
        Some(self.iter().map(|s| s.as_str()))
    }
}

/// A top-level context for operations in a minimal-configured repo.
#[derive(Debug)]
pub struct Context {
    config: Config,

    stdlib_dir: PathBuf,
    mfile: mfile::File,

    vcs: VcsManagerHandle,
    cache: Cache,
}

impl fmt::Display for Context {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "mctx{{")?;
        if let Some(p) = self.mfile.dir_path().map(|p| p.to_path_buf()) {
            write!(f, " mfile repo at {} ", p.display())?;
        } else {
            write!(f, "{:?}", self.config)?;
        }
        write!(f, "}}")
    }
}

impl Context {
    /// Initializes a bunch of internals and returns them. Use [Self::new] instead.
    ///
    /// This separation is needed to power logic in `minimal init`, which needs
    /// to use a bunch of this stuff without being able to initialize a full [Context].
    pub fn sub_setup(config: &Config) -> Result<(VcsManagerHandle, Cache, PathBuf), Error> {
        // Upsert dirs
        use std::fs::create_dir_all;
        create_dir_all(config.downloads_dir())
            .map_err(|e| Error::setup_dirs(e, config.downloads_dir()))?;
        create_dir_all(config.builds_base_dir())
            .map_err(|e| Error::setup_dirs(e, config.builds_base_dir()))?;
        create_dir_all(config.cache_dir()).map_err(|e| Error::setup_dirs(e, config.cache_dir()))?;
        create_dir_all(config.state_base_dir())
            .map_err(|e| Error::setup_dirs(e, config.state_base_dir()))?;
        create_dir_all(config.task_base_dir())
            .map_err(|e| Error::setup_dirs(e, config.task_base_dir()))?;
        create_dir_all(config.vcs_dir()).map_err(|e| Error::setup_dirs(e, config.vcs_dir()))?;
        create_dir_all(config.index_dir()).map_err(|e| Error::setup_dirs(e, config.index_dir()))?;
        create_dir_all(config.stdlib_dir())
            .map_err(|e| Error::setup_dirs(e, config.stdlib_dir()))?;
        create_dir_all(config.layer_cache_dir())
            .map_err(|e| Error::setup_dirs(e, config.layer_cache_dir()))?;

        // Initialize subsystems that are always present/used
        let vcs = if let Some(vcs_manager) = config.vcs_manager_override() {
            vcs_manager
        } else {
            VcsManager::new_in_dir(config.vcs_dir())?
        };
        let cache = Cache::at_dir(config.cache_dir())
            .map_err(|e| Error::Other(anyhow!("initializing local cache: {}", e)))?;

        // Figure out a path to the standard library. Roughly speaking this is loaded from:
        //  - Any override in the config
        //  - The version embedded in the binary, stamped to disk
        let stdlib_dir = {
            if let Some(dir) = config.stdlib_dir_override() {
                dir.clone()
            } else {
                stdlib::upsert_stdlib_to_disk(config.stdlib_dir()).map_err(|e| {
                    Error::Other(anyhow!("loading embedded standard library: {}", e))
                })?
            }
        };

        Ok((vcs, cache, stdlib_dir))
    }

    /// Initializes a new context using the given configuration.
    pub fn new(config: Config) -> Result<Self, Error> {
        let (vcs, cache, stdlib_dir) = Self::sub_setup(&config)?;

        // Load the minimal file. All error are terminal.
        let mfile = match config
            .repo_dir_override()
            .as_ref()
            .map(|d| mfile::File::from_dir(d.clone()))
            .unwrap_or_else(|| mfile::File::from_dir_recursive(std::env::current_dir().unwrap()))
        {
            Ok(mfile) => mfile,
            Err(e) => {
                return Err(Error::MFile(e));
            }
        };

        Ok(Self {
            config,
            stdlib_dir,
            mfile,
            vcs,
            cache,
        })
    }

    /// Constructs a new context using the lower-level primitives.
    ///
    /// DO NOT USE unless you know what you are doing - use [Context::new] instead.
    pub fn new_from_parts(
        config: Config,
        mfile: mfile::File,
        vcs: VcsManagerHandle,
        cache: Cache,
        stdlib_dir: PathBuf,
    ) -> Self {
        Self {
            config,
            stdlib_dir,
            mfile,
            vcs,
            cache,
        }
    }
}

/// Low-level API
impl Context {
    /// Clones and reinitializes the context. Intended only
    /// to be used after the minimal file has been mutated.
    pub fn cloned_reinit(&self) -> Result<Self, Error> {
        Self::new(self.config.clone())
    }

    /// Returns a handle to the local cache.
    pub fn local_cache(&self) -> Cache {
        self.cache.clone()
    }
    /// Returns the vcs manager.
    pub fn vcs_manager(&self) -> VcsManagerHandle {
        self.vcs.clone()
    }

    /// Returns true if the context is configured to use the local cache.
    pub fn use_local_cache(&self) -> bool {
        self.config.use_local_cache()
    }
    /// Returns true if the context is configured to use a remote cache.
    pub fn use_remote_cache(&self) -> bool {
        self.config.use_remote_cache()
    }
    /// Returns the base directory for build sandboxes.
    pub fn builds_base_dir(&self) -> PathBuf {
        self.config.builds_base_dir()
    }
    /// Returns the base directory for task sandboxes.
    pub fn tasks_base_dir(&self) -> PathBuf {
        self.config.task_base_dir()
    }
    /// Returns the base directory for the artifact/binary cache.
    ///
    /// DO NOT USE unless you really know what you
    /// are doing - prefer [Context::local_cache] instead.
    pub fn cache_base_dir(&self) -> PathBuf {
        self.config.cache_dir()
    }
    /// Returns the base directory where source checkouts are stored.
    pub fn vcs_dir(&self) -> PathBuf {
        self.config.vcs_dir()
    }
    /// Returns the base directory where the remote index is cached.
    pub fn index_dir(&self) -> PathBuf {
        self.config.index_dir()
    }
    /// Returns the path to the root of the repo.
    pub fn repo_dir(&self) -> &Path {
        self.mfile.repo_path().unwrap()
    }
    /// Returns a path to the standard library.
    pub fn stdlib_dir(&self) -> &PathBuf {
        &self.stdlib_dir
    }

    /// Returns the minimal file loaded from disk.
    pub fn minimal_file(&self) -> &mfile::File {
        &self.mfile
    }

    /// Builds and returns a remote cache with default configurations.
    pub async fn remote_cache(
        &self,
        auth: bool,
        force_fresh: bool,
    ) -> Result<RemoteCache<GcsStorage>, RemoteError<GcsError>> {
        let start = SystemTime::now();
        let backend = if auth {
            GcsStorage::builder().build().await.unwrap()
        } else {
            GcsStorage::builder()
                .with_credentials(google_cloud_auth::credentials::anonymous::Builder::new().build())
                .build()
                .await
                .unwrap()
        };

        let res = RemoteCache::new_with_gcs_bucket(
            backend,
            "minimal-staging-cache",
            if force_fresh {
                None
            } else {
                Some(self.config.index_dir())
            },
            self.config.ot.clone(),
        )
        .await;
        tracing::trace!("remote cache init took {:?}", start.elapsed());
        res
    }
    pub async fn remote_storage(&self) -> Result<common::RemoteStorage, Error> {
        let start = SystemTime::now();
        let rs = common::RemoteStorage::new(self.config.downloads_dir(), false)
            .await
            .unwrap();
        tracing::trace!("remote storage init took {:?}", start.elapsed());
        Ok(rs)
    }

    /// Returns a [SpecOrigin] representing the top-level repository.
    pub fn repo_origin(&self) -> SpecOrigin {
        SpecOrigin::from_dir(self.repo_dir())
    }
    /// Returns the [OpTracker] to be used as the root for tracking long-running operations.
    pub fn op_tracker(&self) -> Option<OpTracker> {
        self.config.ot.clone()
    }

    /// Builds & returns the graph with the given packages specified as top levels.
    pub fn graph_from_package_names<S: PackageSelection>(
        &mut self,
        pkgs: S,
    ) -> Result<Graph, Error> {
        let mut graph = self.graph_from_all_packages()?;
        graph.top_levels = pkgs.as_bsrs(&graph)?;

        Ok(graph)
    }

    /// Builds & returns a graph of all packages.
    pub fn graph_from_all_packages(&mut self) -> Result<Graph, Error> {
        self.graph_from_all_packages_with_target(Target::host())
    }

    /// Builds & returns a graph of all packages for a specific target.
    pub fn graph_from_all_packages_with_target(&mut self, target: Target) -> Result<Graph, Error> {
        let leaf_layer = self.repo_origin();

        let start = SystemTime::now();
        let res = Graph::new_from_chain(
            self.vcs_manager(),
            &mut graph::LayerCacheDir(self.config.layer_cache_dir()),
            leaf_layer,
            self.stdlib_dir.clone(),
            target,
        )
        .map_err(|e| e.into());
        tracing::trace!("graph parse/load took {:?}", start.elapsed());

        res
    }

    /// Builds & returns the graph with the given packages for a specific target.
    pub fn graph_from_package_names_with_target<S: PackageSelection>(
        &mut self,
        pkgs: S,
        target: Target,
    ) -> Result<Graph, Error> {
        let mut graph = self.graph_from_all_packages_with_target(target)?;
        graph.top_levels = pkgs.as_bsrs(&graph)?;
        Ok(graph)
    }
}

/// Outcome-oriented API
impl Context {
    /// Ensures the top-level packages of the given graph are built and available locally.
    ///
    /// Use [Context::download_if_available] if you want to only fetch packages.
    pub async fn build_graph(
        &mut self,
        graph: &Graph,
        rebuild_top_level: bool,
        log_sink: Option<futures::channel::mpsc::UnboundedSender<orchestrator::BuildEvent>>,
    ) -> Result<(), Error> {
        self.build_graph_with_cancel(
            graph,
            rebuild_top_level,
            log_sink,
            tokio_util::sync::CancellationToken::new(),
        )
        .await
    }

    pub async fn build_graph_with_cancel(
        &mut self,
        graph: &Graph,
        rebuild_top_level: bool,
        log_sink: Option<futures::channel::mpsc::UnboundedSender<orchestrator::BuildEvent>>,
        cancel: tokio_util::sync::CancellationToken,
    ) -> Result<(), Error> {
        let cache = self.local_cache();
        let rc = if self.config.use_remote_cache() {
            Some(self.remote_cache(false, false).await.unwrap())
        } else {
            None
        };

        use orchestrator::LocalBackend;
        let orchestrator = LocalBackend::new_orchestrator(
            graph.top_levels.clone(),
            self.config.builds_base_dir(),
            rc.clone(),
            self.remote_storage().await?,
            self.config.num_parallel_builds(),
            graph.clone(),
            cache.clone(),
            log_sink,
            self.config.ot.clone(),
            cancel,
        )?;

        let mut bin_provider: Box<dyn BinProvider> = match (
            self.config.use_local_cache(),
            self.config.use_remote_cache(),
        ) {
            // No local or remote cache
            (false, false) => Box::new(()),
            // Both caches
            (true, true) => {
                let local_adapter = CacheBinProvider::new(graph, cache.clone());
                let remote_adapter = RemoteBinProvider::new(graph, rc.as_ref().unwrap());
                Box::new((local_adapter, remote_adapter))
            }
            // Only remote cache
            (false, true) => Box::new(RemoteBinProvider::new(graph, rc.as_ref().unwrap())),
            // Only local cache
            (true, false) => Box::new(CacheBinProvider::new(graph, cache.clone())),
        };
        if rebuild_top_level {
            // Forcing a rebuild of named packages was requested. To do this, we wrap the BinProvider
            // with one that pretends the named packages are never in any cache, resulting in a build for them.
            bin_provider = Box::new(MaskingBinProvider::new(
                bin_provider,
                graph.top_levels.clone(),
            ));
        }

        let (built, result) = LocalBackend::run_local_build(orchestrator, bin_provider).await;

        // commit all built artifacts to the local cache
        for (pending_dir, meta) in built {
            pending_dir
                .finalize(meta)
                .map_err(|e| Error::Other(e.into()))?;
        }
        // propergate any error
        result?;

        Ok(())
    }

    /// Returns the task of the given name, fully hydrated based on profiles. If no task
    /// is declared in the minimal file with the given name, harnesses are considered.
    ///
    /// The returned task will not have had any string interpolations applied.
    pub fn task(&mut self, mut graph: Graph, name: &str) -> Result<Option<(Task, Graph)>, Error> {
        let mfile = self.minimal_file();
        let mut task = match mfile.task(name) {
            Some(t) => t,
            None => {
                // Task requested but none defined, lets see if the harness provides an implementation.
                if let Some(h_conf) = &mfile.harness {
                    if let Some(harness) = graph.harness(&h_conf.name) {
                        if let Some(mut task) = harness.task_by_name(name) {
                            mfile.hydrate_task_defaults(&mut task);
                            task
                        } else {
                            return Ok(None);
                        }
                    } else {
                        return Ok(None);
                    }
                } else {
                    return Ok(None);
                }
            }
        };
        // Apply the specifics (pkgs etc) of the harness & profile
        graph.hydrate_task(mfile.harness.as_ref().map(|h| h.name.as_str()), &mut task)?;

        // TODO: Probably time to retire this top_levels concept
        graph.top_levels = task.packages.as_bsrs(&graph)?;

        Ok(Some((task, graph)))
    }

    /// Constructs an environment from which executions can be run, based on the given parameters.
    #[allow(clippy::too_many_arguments)]
    pub async fn make_env<'a, S: PackageSelection>(
        &'a mut self,
        name: &'a str,
        graph: &'a mut Graph,
        wd: Option<PathBuf>,
        state_key: Option<&String>,
        patches: Option<&'a EnvPatches>,
        env_vars: Option<&'a HashMap<String, EnvVarValue>>,
        packages: S,
    ) -> Result<env::Env<'a>, Error> {
        let mfile = self.minimal_file();

        let mut temp_dirs = vec![];
        let wd = if let Some(wd) = wd {
            wd
        } else {
            mfile.repo_path().unwrap().to_path_buf()
        };
        let state_base_dir = match state_key {
            Some(name) if !name.is_empty() => {
                mfile.state_dir(name, self.config.state_base_dir()).unwrap()
            }
            _ => {
                let tmp = self.cache.temp_dir().map_err(|e| {
                    Error::Other(
                        anyhow::Error::from(e).context("creating temporary state directory"),
                    )
                })?;
                let tmp_path = tmp.path().to_path_buf();
                temp_dirs.push(tmp);
                tmp_path
            }
        };
        graph.top_levels = packages.as_bsrs(graph)?;

        // /usr/bin/min needs bash and socat
        {
            if let Some(bash) = graph.by_name("bash")
                && !graph.top_levels.contains(bash)
            {
                graph.top_levels.push(*bash);
            }
            if let Some(socat) = graph.by_name("socat")
                && !graph.top_levels.contains(socat)
            {
                graph.top_levels.push(*socat);
            }
        }

        let cache = self.local_cache();
        let transitive_deps = Transitives::for_toplevels(graph, graph.top_levels.clone(), false);
        let all_built = transitive_deps
            .iter()
            .all(|(bsr, _dep)| cache.read_dir(&graph.spec_hash(bsr)).is_ok());

        if !all_built {
            tracing::trace!("missing local packages, calling mctx.build_graph()");
            self.build_graph(graph, false, None).await?;
        } else {
            tracing::trace!("all packages available locally, eluding build");
        }

        let base = tempfile::TempDir::with_suffix_in(
            format!("-{}", std::process::id()),
            self.config.task_base_dir(),
        )
        .map_err(|e| {
            Error::Other(anyhow::Error::from(e).context("creating base sandbox directory"))
        })?;

        let mut env = Env::build(
            self,
            graph,
            EnvArgs {
                name,
                state_base_dir,
                transitives: transitive_deps,
                cwd: wd,
                patches,
                env_vars,
                hostname: Some(name.to_string()),
                override_disable_networking: Some(false),
                ot: self.config.ot.clone(),
            },
        )
        .await?;
        env.associate_tempdirs(temp_dirs);
        env.associate_tempdirs([base]);

        Ok(env)
    }

    /// Returns the list of all packages brought in through tasks, profiles and harnesses.
    pub fn scaffolding_packages(&mut self) -> Result<Vec<BuildSpecRef>, Error> {
        let mut out = std::collections::HashSet::new();
        let mut graph = self.graph_from_all_packages()?;
        let mfile = self.minimal_file().clone();
        for (name, _) in mfile.tasks.iter() {
            let res = self.task(graph, name)?.unwrap();
            let task = res.0;
            graph = res.1;

            out.extend(task.packages);
        }
        if let Some(harness) = &mfile.harness {
            let h = graph.harness(&harness.name).unwrap();
            out.extend(h.build_packages.clone());
            out.extend(h.runtime_packages.clone());
        }

        out.as_bsrs(&graph)
    }

    /// Downloads the specified packages and their dependencies, if they are missing locally
    /// but present in the remote cache.
    ///
    /// Use [Context::build_graph] instead if you want to also build packages that
    /// aren't available for download.
    pub async fn download_if_available<I: IntoIterator<Item = BuildSpecRef>>(
        &mut self,
        graph: &Graph,
        pkgs: I,
    ) -> Result<(), Error> {
        let rc = self.remote_cache(false, true).await.unwrap();
        let mut task_set = tokio::task::JoinSet::new();
        let fetch_start = SystemTime::now();
        for (bsr, _depinfo) in Transitives::for_toplevels(graph, pkgs.into_iter().collect(), false)
        {
            let b = graph.get(&bsr).unwrap();
            let name = b.name.clone();
            let origin = b.from.as_ref().clone();
            let spec_hash = graph.spec_hash(&bsr);
            if let Err(lcache::CacheErr::NotFound) = self.cache.read_dir(&spec_hash)
                && rc.exists(&spec_hash)
            {
                let rc_clone = rc.clone(); // TODO: This is trash
                let cache_clone = self.cache.clone();
                task_set.spawn(async move {
                    rc_clone
                        .materialize(&spec_hash, &cache_clone, &name)
                        .await
                        .map(|(t, d)| {
                            (
                                d,
                                lcache::EntryMeta {
                                    inner: lcache::MetaInner::Spec(name),
                                    fetched: true,
                                    fetch_ms: Some(t.as_millis() as usize),
                                    origin: Some(origin),
                                    ..Default::default()
                                },
                            )
                        })
                });
            }
        }

        // Wait for all materialization tasks to complete, committing each pending dir
        // to the cache as it is finished being staged
        while let Some(result) = task_set.join_next().await {
            let (pending_dir, meta) = result
                .unwrap()
                .map_err(|e| Error::Other(anyhow::Error::from(e)))?;
            pending_dir.finalize(meta).unwrap();
        }
        tracing::trace!("package fetch took {:?}", fetch_start.elapsed());

        Ok(())
    }

    /// Adds the specified dependencies if they arent already present.
    pub fn add_deps<S: PackageSelection>(
        &mut self,
        graph: &Graph,
        deps: S,
        mode: AddDepMode,
    ) -> Result<(), Error> {
        let mfile = self.minimal_file();
        let mfile_path = match mfile.file_path() {
            Some(p) => p.clone(),
            None => {
                return Err(Error::Other(anyhow!(
                    "Cannot add dependency - no minimal.toml located."
                )));
            }
        };

        let toml = std::fs::read_to_string(&mfile_path)
            .map_err(|e| Error::IO("reading minimal.toml for add", mfile_path.to_path_buf(), e))?;
        let mut doc = toml
            .parse::<DocumentMut>()
            .map_err(|e| Error::Other(anyhow!("parsing minimal.toml: {}", e)))?;

        let resolved: Vec<String> = deps
            .as_bsrs(graph)?
            .into_iter()
            .map(|bsr| graph.get(&bsr).unwrap().name.clone())
            .collect();

        let mut did_edit = false;
        match mode {
            AddDepMode::BuildPackages => {
                if let Some(h) = doc["harness"].as_table_mut() {
                    did_edit |= upsert_toml_packages_list(h, "build_packages", &resolved);
                    println!("Added [{}] to harness.build_packages", resolved.join(","));
                } else {
                    return Err(Error::Other(anyhow!(
                        "could not find [harness] in minimal.toml: needed for update"
                    )));
                }
            }
            AddDepMode::RuntimePackages => {
                if let Some(h) = doc["harness"].as_table_mut() {
                    did_edit |= upsert_toml_packages_list(h, "runtime_packages", &resolved);
                    println!("Added [{}] to harness.runtime_packages", resolved.join(","));
                } else {
                    return Err(Error::Other(anyhow!(
                        "could not find [harness] in minimal.toml: needed for update"
                    )));
                }
            }
            AddDepMode::TaskPackages { name } => {
                if let Some(tasks) = doc.get_mut("tasks")
                    && let Some(t) = tasks.get_mut(&name)
                    && let Some(t) = t.as_table_mut()
                {
                    did_edit |= upsert_toml_packages_list(t, "packages", &resolved);
                    println!("Added [{}] to tasks.{}.packages", resolved.join(","), name);
                } else {
                    return Err(Error::Other(anyhow!(
                        "could not find [tasks.{}] in minimal.toml: needed for update",
                        name
                    )));
                }
            }
        }

        if did_edit {
            std::fs::write(&mfile_path, doc.to_string())
                .map_err(|e| Error::Other(anyhow::Error::from(e)))?;
            *self = self.cloned_reinit()?;
        }
        Ok(())
    }
}

/// How to add a set of dependencies - as a build dep, a runtime dep, or a tool.
pub enum AddDepMode {
    /// Add the specified packages to harness.build_packages.
    BuildPackages,
    /// Add the specified packages to harness.runtime_packages.
    RuntimePackages,
    /// Add the specified packages to a task with a given name.
    TaskPackages { name: String },
}

fn upsert_toml_packages_list<T: TableLike>(t: &mut T, key: &str, upsert: &[String]) -> bool {
    if let Some(bp) = t.get_mut(key) {
        let mut existing: Vec<_> = bp
            .as_array()
            .unwrap()
            .iter()
            .map(|i| i.as_str().unwrap())
            .collect();

        let mut did_edit = false;
        upsert.iter().for_each(|p| {
            if !existing.contains(&p.as_str()) {
                existing.push(p);
                did_edit = true;
            }
        });
        *bp = Item::Value(Value::Array(Array::from_iter(existing)));
        did_edit
    } else {
        t.insert(key, Item::Value(Value::Array(Array::from_iter(upsert))));
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use indoc::indoc;
    use mfile::EnvVarValue;
    use op::{Runnable, StandaloneTest};
    use tempfile::tempdir;

    #[test]
    #[ignore] // Do not run in github: does not support nested namespaces
    fn toplevel_layer_init_and_build() {
        let state = tempdir().unwrap();
        let config = ConfigBuilder::new()
            .with_state_dir(state.path().to_path_buf())
            .with_repo_dir(
                std::path::Path::new(&std::env::var("CARGO_MANIFEST_DIR").unwrap())
                    .join("testdata")
                    .join("fakepkgs"),
            )
            .with_stdlib_dir(
                std::path::Path::new(&std::env::var("CARGO_MANIFEST_DIR").unwrap())
                    .join("../stdlib/minimal-ncl"),
            )
            .build()
            .unwrap();

        let mut ctx = Context::new(config).unwrap();
        let graph = ctx
            .graph_from_all_packages()
            .inspect_err(|e| {
                if let Error::Graph(e) = e {
                    e.report_to_stderr();
                }
            })
            .unwrap();
        assert!(graph.by_name("uroot").is_some());

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        rt.block_on(async {
            let graph = ctx.graph_from_package_names(["uroot"]).unwrap();
            ctx.build_graph(&graph, false, None).await.unwrap();

            let temp_dir = ctx.local_cache().temp_dir().unwrap();
            let mut t = StandaloneTest {
                spec: graph.by_name("uroot").unwrap(),
                test_name: "smoke",
                stdout_writer: None,
                stderr_writer: None,
            };
            let opts = op::Options {
                cache: ctx.local_cache(),
                exec_base: temp_dir.path().to_path_buf(),
                graph: &graph,
                ot: ctx.config.ot.clone(),
            };

            assert_eq!(t.run(&opts).await.unwrap(), vec![]);
            drop(temp_dir);
        });
    }

    #[test]
    fn repo_init() {
        let state = tempdir().unwrap();
        let config = ConfigBuilder::new()
            .with_state_dir(state.path().to_path_buf())
            .with_repo_dir(
                std::path::Path::new(&std::env::var("CARGO_MANIFEST_DIR").unwrap())
                    .join("testdata")
                    .join("fakerepo"),
            )
            .with_stdlib_dir(
                std::path::Path::new(&std::env::var("CARGO_MANIFEST_DIR").unwrap())
                    .join("../stdlib/minimal-ncl"),
            )
            .build()
            .unwrap();

        let mut ctx = Context::new(config).unwrap();

        let graph = ctx.graph_from_all_packages().unwrap();
        let (_task_smoketest, _graph) = ctx.task(graph, "task-smoketest").unwrap().unwrap();
    }

    #[test]
    fn task_inherits_harness() {
        let state = tempdir().unwrap();
        let config = ConfigBuilder::new()
            .with_state_dir(state.path().to_path_buf())
            .with_repo_dir(
                std::path::Path::new(&std::env::var("CARGO_MANIFEST_DIR").unwrap())
                    .join("testdata")
                    .join("fakerepo-with-harness"),
            )
            .with_stdlib_dir(
                std::path::Path::new(&std::env::var("CARGO_MANIFEST_DIR").unwrap())
                    .join("../stdlib/minimal-ncl"),
            )
            .build()
            .unwrap();

        let mut ctx = Context::new(config).unwrap();

        let graph = ctx.graph_from_all_packages().unwrap();
        let (task, _graph) = ctx.task(graph, "task-inherits-harness").unwrap().unwrap();

        // println!("task = {:#?}", task);
        // task inherited harness build_packages and runtime_packages, as well as any
        // extras defined in the minimal file
        assert_eq!(
            task.packages,
            vec![
                "uroot".to_string(),
                "extra-build-pkg".to_string(),
                "extra-runtime-pkg".to_string(),
                "harness-build-pkg".to_string(),
                "harness-runtime-pkg".to_string(),
            ]
        );
        // task inherited harness build env vars
        assert_eq!(
            task.vars.get("HARNESS_VAR"),
            Some(&EnvVarValue::Value("set".to_string()))
        );
    }

    #[test]
    #[ignore] // Do not run in github- does not support nested namespaces
    fn task_env() {
        let state = tempdir().unwrap();
        let config = ConfigBuilder::new()
            .with_state_dir(state.path().to_path_buf())
            .with_repo_dir(
                std::path::Path::new(&std::env::var("CARGO_MANIFEST_DIR").unwrap())
                    .join("testdata")
                    .join("fakerepo"),
            )
            .with_stdlib_dir(
                std::path::Path::new(&std::env::var("CARGO_MANIFEST_DIR").unwrap())
                    .join("../stdlib/minimal-ncl"),
            )
            .build()
            .unwrap();

        let mut ctx = Context::new(config).unwrap();

        let graph = ctx.graph_from_all_packages().unwrap();
        let (task_smoketest, mut graph) = ctx.task(graph, "task-smoketest").unwrap().unwrap();

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            // Build an environment based on the task
            let mut env = ctx
                .make_env(
                    "test",
                    &mut graph,
                    None,
                    task_smoketest.state_key.as_ref(),
                    Some(&task_smoketest.patch),
                    Some(&task_smoketest.vars),
                    task_smoketest.packages,
                )
                .await
                .unwrap();

            let container = env.container().unwrap();

            // Smoketest: date command should succeed, and regardless of the time the output should contain a colon.
            let output = env
                .command(&container, "/bbin/date", [""; 0])
                .unwrap()
                .output()
                .unwrap();
            assert!(output.status.success());
            assert!(
                output.stdout.contains(&b':'), // The colons in the time
                "unexpected output: {:?}",
                output
            );

            // cwd should be the repo root
            let output = env
                .command(&container, "/bbin/pwd", [""; 0])
                .unwrap()
                .output()
                .unwrap();
            assert!(output.status.success());
            assert_eq!(
                String::from_utf8(output.stdout.clone()).unwrap(),
                std::path::Path::new(&std::env::var("CARGO_MANIFEST_DIR").unwrap())
                    .join("testdata")
                    .join("fakerepo")
                    .to_str()
                    .unwrap()
                    .to_string()
                    + "\n",
                "unexpected output: {:?}",
                output
            );
        });
    }

    #[test]
    fn add_deps() {
        let state = tempdir().unwrap();
        let cwd = tempdir().unwrap();
        let mfile_path = cwd.path().join("minimal.toml");
        std::fs::write(
            &mfile_path,
            format!(
                indoc! {
                    "
                    [upstream]
                    dir = \"{}\"

                    [harness]
                    use = \"fake-harness\"

                    [tasks.something]
                    exec = \"./something\"
                    "
                },
                std::path::Path::new(&std::env::var("CARGO_MANIFEST_DIR").unwrap())
                    .join("testdata")
                    .join("fakerepo-with-harness")
                    .to_str()
                    .unwrap()
            ),
        )
        .unwrap();

        let config = ConfigBuilder::new()
            .with_state_dir(state.path().to_path_buf())
            .with_repo_dir(cwd.path().to_path_buf())
            .with_stdlib_dir(
                std::path::Path::new(&std::env::var("CARGO_MANIFEST_DIR").unwrap())
                    .join("../stdlib/minimal-ncl"),
            )
            .build()
            .unwrap();

        let mut ctx = Context::new(config).unwrap();
        let graph = ctx.graph_from_all_packages().unwrap();

        // Add a build package, make sure it is written back and also is now
        // part of the packages
        ctx.add_deps(&graph, ["uroot"], AddDepMode::BuildPackages)
            .unwrap();
        assert!(
            String::from_utf8(std::fs::read(&mfile_path).unwrap())
                .unwrap()
                .contains("build_packages = [\"uroot\"]")
        );
        let (task, graph) = ctx.task(graph, "build").unwrap().unwrap();
        assert!(task.packages.contains(&"uroot".to_string()));
        // Add a runtime package, make sure it is written back and also is now
        // part of the packages
        ctx.add_deps(&graph, ["extra-runtime-pkg"], AddDepMode::RuntimePackages)
            .unwrap();
        assert!(
            String::from_utf8(std::fs::read(&mfile_path).unwrap())
                .unwrap()
                .contains("runtime_packages = [\"extra-runtime-pkg\"]")
        );
        let (task, graph) = ctx.task(graph, "build").unwrap().unwrap();
        assert!(task.packages.contains(&"extra-runtime-pkg".to_string()));
        // Add a package to a task.
        ctx.add_deps(
            &graph,
            ["uroot"],
            AddDepMode::TaskPackages {
                name: "something".to_string(),
            },
        )
        .unwrap();
        assert!(
            String::from_utf8(std::fs::read(&mfile_path).unwrap())
                .unwrap()
                .contains("[tasks.something]\nexec = \"./something\"\npackages = [\"uroot\"]")
        );

        // Make sure it errors when theres no such package
        assert!(
            ctx.add_deps(&graph, ["missingggggg"], AddDepMode::BuildPackages)
                .is_err()
        );
    }

    #[test]
    #[ignore] // Do not run in github- does not support nested namespaces
    fn task_resolve_string_interpolation() {
        let state = tempdir().unwrap();
        let config = ConfigBuilder::new()
            .with_state_dir(state.path().to_path_buf())
            .with_repo_dir(
                std::path::Path::new(&std::env::var("CARGO_MANIFEST_DIR").unwrap())
                    .join("testdata")
                    .join("fakerepo"),
            )
            .with_stdlib_dir(
                std::path::Path::new(&std::env::var("CARGO_MANIFEST_DIR").unwrap())
                    .join("../stdlib/minimal-ncl"),
            )
            .build()
            .unwrap();

        let mut ctx = Context::new(config).unwrap();

        let graph = ctx.graph_from_all_packages().unwrap();
        let (task, mut graph) = ctx.task(graph, "task-interpolation-test").unwrap().unwrap();

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            // Build an environment based on the task
            let mut env = ctx
                .make_env(
                    "test",
                    &mut graph,
                    None,
                    task.state_key.as_ref(),
                    Some(&task.patch),
                    Some(&task.vars),
                    task.packages.clone(),
                )
                .await
                .unwrap();

            let (interactive, invocations) = env
                .task_invocations(
                    &task,
                    Some(&std::collections::HashMap::from([(
                        "input".to_string(),
                        args::Arg::Scalar(args::ScalarArg::String("beep".to_string())),
                    )])),
                )
                .await
                .unwrap();
            assert!(interactive);
            assert_eq!(
                invocations,
                vec![Invocation {
                    envs: Default::default(),
                    executable: "/bin/sh".to_string(),
                    args: vec![
                        "-c".to_string(),
                        "echo".to_string(),
                        "val: beep".to_string()
                    ]
                },]
            );
        });
    }
}
