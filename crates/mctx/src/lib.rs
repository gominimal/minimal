//! Top-level API for minimal tooling.

use std::{collections::HashMap, fmt, path::PathBuf};

use anyhow::anyhow;
use cache::{CacheBinProvider, RemoteBinProvider, RemoteCache, RemoteError};
use checkouts::{GitRef, Manager as VcsManager};
use common::SpecOrigin;
use google_cloud_storage::{Error as GcsError, client::Storage as GcsStorage};

mod error;
pub use error::Error;
mod config;
pub use config::{Config, ConfigBuilder, ConfigError};
use graph::{BuildSpecRef, DepGraph, Transitives};
use mfile::{EnvPatches, Task};
use op::RunnableEnv;

/// The local cache.
pub type Cache = cache::Cache<cache::LocalDir>;

/// Anything which represents a set of packages.
///
/// Anywhere you see this as a parameter, you can pass:
///
///  - `Vec<String>`
///  - `Vec<BuildSpecRef>`
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

    fn as_bsrs(&self, g: &DepGraph) -> Result<Vec<BuildSpecRef>, Error> {
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
    stdlib_origin: SpecOrigin,
    mfile: Option<mfile::File>,

    vcs: VcsManager,
    cache: Cache,
}

impl fmt::Display for Context {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "mctx{{")?;
        if let Some(p) = self
            .mfile
            .as_ref()
            .and_then(|f| f.dir_path().map(|p| p.to_path_buf()))
        {
            write!(f, " mfile repo at {} ", p.display())?;
        } else {
            write!(f, "{:?}", self.config)?;
        }
        write!(f, "}}")
    }
}

impl Context {
    /// Initializes a new context using the given configuration.
    pub fn new(config: Config) -> Result<Self, Error> {
        // Upsert dirs
        use std::fs::create_dir_all;
        create_dir_all(config.cache_dir()).map_err(|e| Error::setup_dirs(e, config.cache_dir()))?;
        create_dir_all(config.downloads_dir())
            .map_err(|e| Error::setup_dirs(e, config.downloads_dir()))?;
        create_dir_all(config.builds_base_dir())
            .map_err(|e| Error::setup_dirs(e, config.builds_base_dir()))?;
        create_dir_all(config.state_base_dir())
            .map_err(|e| Error::setup_dirs(e, config.state_base_dir()))?;
        create_dir_all(config.run_base_dir())
            .map_err(|e| Error::setup_dirs(e, config.run_base_dir()))?;
        create_dir_all(config.vcs_dir()).map_err(|e| Error::setup_dirs(e, config.vcs_dir()))?;

        // Initialize subsystems that are always present/used
        let mut vcs = VcsManager::new(config.vcs_dir())?;
        let cache = Cache::at_dir(config.cache_dir())
            .map_err(|e| Error::Other(anyhow!("initializing local cache: {}", e)))?;

        // Load the minimal file. All error are terminal except not found.
        let mfile = match config
            .repo_dir_override()
            .as_ref()
            .map(|d| mfile::File::from_dir(d.clone()))
            .unwrap_or_else(|| mfile::File::from_dir_recursive(std::env::current_dir().unwrap()))
        {
            Ok(mfile) => Some(mfile),
            Err(mfile::Error::NotFound) => None,
            Err(e) => {
                return Err(Error::MFile(e));
            }
        };

        // Figure out a path to the standard library. Roughly speaking this is loaded from:
        //  - Any override in the config
        //  - The minimal file, if one was found
        //  - The fallback `mfile::default_stdlib()`
        let (stdlib_dir, stdlib_origin) = {
            if let Some(dir) = config.stdlib_dir_override() {
                (dir.clone(), SpecOrigin::from_dir(dir))
            } else {
                let stdlib_link = if let Some(mfile) = &mfile {
                    &mfile.stdlib
                } else {
                    &mfile::default_stdlib()
                };

                match &stdlib_link {
                    mfile::LinkConfig::Git { repo, .. } => {
                        let git_ref: GitRef = stdlib_link.try_into().unwrap();
                        let (dir, git_hash) = vcs.checkout_of(repo, git_ref.clone())?;
                        (
                            dir,
                            SpecOrigin::Repo(git_ref.as_repo(repo.clone(), git_hash)),
                        )
                    }
                    mfile::LinkConfig::Dir { dir } => (dir.into(), SpecOrigin::from_dir(dir)),
                }
            }
        };

        Ok(Self {
            config,
            stdlib_dir,
            stdlib_origin,
            mfile,
            vcs,
            cache,
        })
    }
}

/// Low-level API
impl Context {
    /// Returns a handle to the local cache.
    pub fn local_cache(&self) -> Cache {
        self.cache.clone()
    }
    /// Returns the vcs manager.
    pub fn vcs_manager(&mut self) -> &mut VcsManager {
        &mut self.vcs
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
    /// Returns the base directory where source checkouts are stored.
    pub fn vcs_dir(&self) -> PathBuf {
        self.config.vcs_dir()
    }
    /// Returns the path to the root of the repo.
    pub fn repo_dir(&self) -> Result<PathBuf, Error> {
        match (&self.mfile, self.config.repo_dir_override()) {
            (Some(mfile), _) => Ok(mfile.dir_path().unwrap().to_path_buf()),
            (None, Some(d)) => Ok(d.to_path_buf()),
            (None, None) => Err(Error::MFile(mfile::Error::NotFound)),
        }
    }
    /// Returns a path to the standard library, as well as info about where its from.
    pub fn stdlib_dir_and_origin(&self) -> (&PathBuf, &SpecOrigin) {
        (&self.stdlib_dir, &self.stdlib_origin)
    }

    /// Returns the minimal file loaded from disk.
    ///
    /// Its possible for some layers to not have a minimal file (i.e. 'pkgs'), these
    /// return `Error::MFile(mfile::Error::NotFound)`.
    pub fn minimal_file(&self) -> Result<&mfile::File, Error> {
        match &self.mfile {
            Some(mfile) => Ok(mfile),
            None => Err(Error::MFile(mfile::Error::NotFound)),
        }
    }

    /// Builds and returns a remote cache with default configurations.
    pub async fn remote_cache(
        &self,
        auth: bool,
    ) -> Result<RemoteCache<GcsStorage>, RemoteError<GcsError>> {
        let backend = if auth {
            GcsStorage::builder().build().await.unwrap()
        } else {
            GcsStorage::builder()
                .with_credentials(google_cloud_auth::credentials::anonymous::Builder::new().build())
                .build()
                .await
                .unwrap()
        };

        RemoteCache::new_with_gcs_bucket(backend, "minimal-staging-cache").await
    }
    pub async fn remote_storage(&self) -> Result<common::RemoteStorage, Error> {
        Ok(
            common::RemoteStorage::new(self.config.downloads_dir(), false)
                .await
                .unwrap(),
        )
    }

    /// Returns a [SpecOrigin] representing the top-level repository.
    pub fn repo_origin(&self) -> Result<SpecOrigin, Error> {
        Ok(SpecOrigin::from_dir(self.repo_dir()?))
    }

    /// Builds & returns the graph with the given packages specified as top levels.
    pub fn graph_from_package_names<S: PackageSelection>(
        &mut self,
        pkgs: S,
    ) -> Result<DepGraph, Error> {
        let mut graph = self.graph_from_all_packages()?;
        graph.top_levels = pkgs.as_bsrs(&graph)?;

        Ok(graph)
    }

    /// Builds & returns a graph of all packages.
    pub fn graph_from_all_packages(&mut self) -> Result<DepGraph, Error> {
        let leaf_layer = self.repo_origin()?;

        DepGraph::new_from_chain(&mut self.vcs, leaf_layer, self.stdlib_dir.clone())
            .map_err(|e| e.into())
    }
}

/// Outcome-oriented API
impl Context {
    /// Ensures the top-level packages of the given graph are built and available locally.
    pub async fn build_graph(&mut self, graph: &DepGraph) -> Result<(), Error> {
        let cache = self.local_cache();

        use orchestrator::LocalBackend;
        let orchestrator = LocalBackend::new_orchestrator(
            graph.top_levels.clone(),
            self.config.builds_base_dir(),
            if self.config.use_remote_cache() {
                Some(self.remote_cache(false).await.unwrap())
            } else {
                None
            },
            self.remote_storage().await?,
            self.config.num_parallel_builds(),
            graph.clone(),
            cache.clone(),
        )?;

        let run_result = match (
            self.config.use_local_cache(),
            self.config.use_remote_cache(),
        ) {
            // No local or remote cache
            (false, false) => LocalBackend::run_local_build(orchestrator, ()).await,
            // Both caches
            (true, true) => {
                let local_adapter = CacheBinProvider::new(graph, cache.clone());
                let remote_cache = self.remote_cache(false).await.unwrap();
                let remote_adapter = RemoteBinProvider::new(graph, &remote_cache);
                LocalBackend::run_local_build(orchestrator, (local_adapter, remote_adapter)).await
            }
            // Only remote cache
            (false, true) => {
                let remote_cache = self.remote_cache(false).await.unwrap();
                let remote_adapter = RemoteBinProvider::new(graph, &remote_cache);
                LocalBackend::run_local_build(orchestrator, remote_adapter).await
            }
            // Only local cache
            (true, false) => {
                let local_adapter = CacheBinProvider::new(graph, cache.clone());
                LocalBackend::run_local_build(orchestrator, local_adapter).await
            }
        };

        // let build_succeeded = run_result.is_ok();
        // let error_message = run_result.as_ref().err().map(|e| e.to_string());

        // Propagate error if build failed, and commit all artifacts to the local cache
        for (pending_dir, meta) in run_result? {
            pending_dir
                .finalize(meta)
                .map_err(|e| Error::Other(e.into()))?;
        }

        Ok(())
    }

    /// Returns the task of the given name, fully hydrated based on profiles. If none
    /// are declared in the minimal file with that name, harnesses are considered.
    pub fn task(
        &mut self,
        mut graph: DepGraph,
        name: &str,
    ) -> Result<Option<(Task, DepGraph)>, Error> {
        let mfile = self.minimal_file()?;
        let mut task = match mfile.task(name) {
            Some(t) => t,
            None if name == "build" => {
                // Task 'build' requested but none defined, lets see if theres a harness we can use instead.
                if let Some(h_conf) = &mfile.harness {
                    if let Some(harness) = graph.harness(&h_conf.name) {
                        let mut task = harness.build_task();
                        mfile.hydrate_task_defaults(&mut task);
                        task
                    } else {
                        return Ok(None);
                    }
                } else {
                    return Ok(None);
                }
            }
            _ => return Ok(None),
        };
        graph.hydrate_task(&mut task)?; // Apply profile settings

        // TODO: Probably time to retire this top_levels concept
        graph.top_levels = task.packages.as_bsrs(&graph)?;

        Ok(Some((task, graph)))
    }

    /// Constructs an environment from which executions can be run, based on the given parameters.
    pub async fn make_env<S: PackageSelection>(
        &mut self,
        mut graph: DepGraph,
        wd: Option<PathBuf>,
        state_key: Option<&String>,
        patches: Option<&EnvPatches>,
        env_vars: Option<&HashMap<String, String>>,
        packages: S,
    ) -> Result<RunnableEnv, Error> {
        let mfile = self.minimal_file()?;

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
        graph.top_levels = packages.as_bsrs(&graph)?;

        self.build_graph(&graph).await?;

        let transitive_deps = Transitives::for_toplevels(&graph, graph.top_levels.clone(), false);
        let base = tempfile::tempdir_in(self.config.run_base_dir()).map_err(|e| {
            Error::Other(anyhow::Error::from(e).context("creating base sandbox directory"))
        })?;

        let mut op = op::EnvSetup {
            state_base_dir: &state_base_dir,
            top_levels: &graph.top_levels,
            transitives: &transitive_deps,

            cwd: &wd,
            patches,
            env_vars,
            hostname: state_key.map(|s| s.to_string()),
        };
        let opts = op::Options {
            cache: self.local_cache(),
            graph: &graph,
            exec_base: base.path().to_path_buf(),
        };
        use op::Runnable;
        let mut runnable_env = op.run(&opts).await.map_err(|e| Error::Other(e.into()))?;
        runnable_env.associate_tempdirs(temp_dirs);
        runnable_env.associate_tempdirs([base]);

        Ok(runnable_env)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use op::{Runnable, StandaloneTest};
    use tempfile::tempdir;

    #[test]
    #[ignore] // Do not run in github: does not support nested namespaces
    fn toplevel_layer_init_and_build() {
        let state = tempdir().unwrap();
        let config = ConfigBuilder::new()
            .state_dir(state.path().to_path_buf())
            .repo_dir(
                std::path::Path::new(&std::env::var("CARGO_MANIFEST_DIR").unwrap())
                    .join("testdata")
                    .join("fakepkgs"),
            )
            .stdlib_dir(
                std::path::Path::new(&std::env::var("CARGO_MANIFEST_DIR").unwrap())
                    .join("../graph/minimal-ncl"),
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
            ctx.build_graph(&graph).await.unwrap();

            let temp_dir = ctx.local_cache().temp_dir().unwrap();
            let mut t = StandaloneTest {
                spec: graph.by_name("uroot").unwrap(),
                test_name: "smoke",
            };
            let opts = op::Options {
                cache: ctx.local_cache(),
                exec_base: temp_dir.path().to_path_buf(),
                graph: &graph,
            };

            assert_eq!(t.run(&opts).await.unwrap(), vec![]);

            assert!(std::fs::exists(temp_dir.path().join("tmp/uwu")).unwrap());
            drop(temp_dir);
        });
    }

    #[test]
    fn repo_init() {
        let state = tempdir().unwrap();
        let config = ConfigBuilder::new()
            .state_dir(state.path().to_path_buf())
            .repo_dir(
                std::path::Path::new(&std::env::var("CARGO_MANIFEST_DIR").unwrap())
                    .join("testdata")
                    .join("fakerepo"),
            )
            .stdlib_dir(
                std::path::Path::new(&std::env::var("CARGO_MANIFEST_DIR").unwrap())
                    .join("../graph/minimal-ncl"),
            )
            .build()
            .unwrap();

        let mut ctx = Context::new(config).unwrap();

        let graph = ctx.graph_from_all_packages().unwrap();
        let (_task_smoketest, _graph) = ctx.task(graph, "task-smoketest").unwrap().unwrap();
    }

    #[test]
    #[ignore] // Do not run in github- does not support nested namespaces
    fn task_env() {
        let state = tempdir().unwrap();
        let config = ConfigBuilder::new()
            .state_dir(state.path().to_path_buf())
            .repo_dir(
                std::path::Path::new(&std::env::var("CARGO_MANIFEST_DIR").unwrap())
                    .join("testdata")
                    .join("fakerepo"),
            )
            .stdlib_dir(
                std::path::Path::new(&std::env::var("CARGO_MANIFEST_DIR").unwrap())
                    .join("../graph/minimal-ncl"),
            )
            .build()
            .unwrap();

        let mut ctx = Context::new(config).unwrap();

        let graph = ctx.graph_from_all_packages().unwrap();
        let (task_smoketest, graph) = ctx.task(graph, "task-smoketest").unwrap().unwrap();

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            // Build an environment based on the task
            let env = ctx
                .make_env(
                    graph,
                    None,
                    task_smoketest.state_key.as_ref(),
                    Some(&task_smoketest.patch),
                    Some(&task_smoketest.vars),
                    task_smoketest.packages,
                )
                .await
                .unwrap();

            // Smoketest: date command should succeed, and regardless of the time the output should contain a colon.
            let output = env
                .command("/bbin/date", [""; 0])
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
            let output = env.command("/bbin/pwd", [""; 0]).unwrap().output().unwrap();
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
}
