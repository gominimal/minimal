//! Top-level API for minimal tooling.

use std::{
    collections::{HashMap, HashSet},
    fmt,
    path::{Path, PathBuf},
    sync::Arc,
    time::SystemTime,
};

use anyhow::anyhow;
use checkouts::{Manager as VcsManager, ManagerHandle as VcsManagerHandle};
use common::fetchers::{AnyBackend, AnyRespError, AnyUrl};
use common::{SpecOrigin, Target};
use google_cloud_storage::client::Storage as GcsStorage;
use lcache::CacheBinProvider;
use ot::OpTracker;
use rcache::{Error as RemoteError, RemoteBinProvider, RemoteCache, RemoteCacheWriter};

mod error;
pub use error::Error;
mod config;
pub use config::{Config, ConfigBuilder, ConfigError, DEFAULT_REMOTE_CACHE_BUCKET};
mod env;
use graph::Error as GraphError;
use graph::{BinProvider, BuildSpecRef, Graph, MaskingBinProvider, Transitives};
use mfile::{EnvPatches, EnvVarValue, LinkConfig, Task};
pub use sandbox2::config::Invocation;

mod mfile_search_strategy;
pub use mfile_search_strategy::MFileSearchStrategy;

mod project_setup;
pub use project_setup::ProjectSetup;

pub use env::{Env, interpolate_task_strings};
use tokio::sync::Semaphore;
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

/// Describes where a task came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaskSource {
    MFile,
    Stack(String),
}

/// Daemon-scoped context state that is independent of any particular
/// project's `minimal.toml`. Built once at daemon startup and shared
/// as `Arc<DaemonContext>` across sessions.
///
/// Sessions and other per-invocation callers hold this behind an `Arc`
/// so the daemon-level setup work (dir upsert, VCS init, cache init,
/// standard-library materialization) is amortized across every context
/// that uses it. CLI callers that only build one context per
/// invocation don't share, but pay only the negligible `Arc` overhead.
#[derive(Debug)]
pub struct DaemonContext {
    pub(crate) config: Config,
    pub(crate) stdlib_dir: PathBuf,
    pub(crate) vcs: VcsManagerHandle,
    pub(crate) cache: Cache,
}

/// A top-level context for operations in a minimal-configured repo.
///
/// Internally holds an `Arc<DaemonContext>` — daemon-scoped state that
/// can be shared across many `Context`s — plus a per-project
/// `mfile::File`. Existing `Context::new` callers continue to work
/// unchanged; daemon-side code that wants to build multiple sessions
/// against the same daemon-scoped state should use
/// [`DaemonContext::init`] + [`Context::from_daemon`] instead.
///
/// `Clone` is cheap: an `Arc` bump on the daemon state plus a
/// clone of the parsed mfile (a modest allocation). Callers that
/// need to reuse a fully-built context across repeated operations
/// clone rather than rebuild.
#[derive(Debug, Clone)]
pub struct Context {
    pub(crate) daemon: Arc<DaemonContext>,
    pub(crate) mfile: mfile::File,
}

impl fmt::Display for Context {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "mctx{{")?;
        if let Some(p) = self.mfile.dir_path().map(|p| p.to_path_buf()) {
            write!(f, " mfile repo at {} ", p.display())?;
        } else {
            write!(f, "{:?}", self.daemon.config)?;
        }
        write!(f, "}}")
    }
}

impl DaemonContext {
    /// Initializes daemon-scoped state: upserts working directories,
    /// initializes the VCS manager (respecting `--offline`), initializes
    /// the local cache, and materializes the standard library. Callers
    /// typically wrap the returned value in an `Arc` and share it
    /// across many `Context`s.
    ///
    /// # Errors
    ///
    /// Any I/O or setup failure surfaced from the underlying subsystems.
    pub fn init(config: Config) -> Result<Self, Error> {
        let (vcs, cache, stdlib_dir) = Self::sub_setup(&config)?;
        Ok(Self {
            config,
            stdlib_dir,
            vcs,
            cache,
        })
    }

    /// Returns the daemon's `Config`.
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Returns a path to the standard library.
    pub fn stdlib_dir(&self) -> &PathBuf {
        &self.stdlib_dir
    }

    /// Returns the VCS manager.
    pub fn vcs_manager(&self) -> VcsManagerHandle {
        self.vcs.clone()
    }

    /// Returns a handle to the local cache.
    pub fn local_cache(&self) -> Cache {
        self.cache.clone()
    }

    /// Returns the daemon ID.
    pub fn daemon_id(&self) -> Option<String> {
        self.config().daemon_id()
    }

    /// Releases the local cache's read tracker (its held-open append-log fd).
    /// Called on daemon shutdown before unmounting the filesystem that holds
    /// the cache; harmless otherwise (read tracking is best-effort).
    pub fn release_cache_read_tracker(&self) {
        self.cache.release_read_tracker();
    }

    /// Initializes a bunch of internals and returns them. Use
    /// [`DaemonContext::init`] instead unless you are `minimal init`,
    /// which needs to use these before a full context can be built.
    pub fn sub_setup(config: &Config) -> Result<(VcsManagerHandle, Cache, PathBuf), Error> {
        // Upsert dirs
        use std::fs::create_dir_all;
        create_dir_all(config.downloads_dir())
            .map_err(|e| Error::setup_dirs(e, config.downloads_dir()))?;
        create_dir_all(config.builds_base_dir())
            .map_err(|e| Error::setup_dirs(e, config.builds_base_dir()))?;
        create_dir_all(config.built_cache_dir())
            .map_err(|e| Error::setup_dirs(e, config.built_cache_dir()))?;
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
            // `--offline` flips the VcsManager into offline mode: any clone or fetch
            // surfaces as Error::OfflineCacheMiss instead of attempting the network
            // operation. Pre-populate `vcs_dir()` for the workflow that needs this.
            VcsManager::new_in_dir_with_offline(config.vcs_dir(), config.is_offline())?
        };
        let cache = Cache::at_dir(config.built_cache_dir())
            .map_err(|e| Error::Other(anyhow!("initializing local cache: {}", e)))?;

        // Figure out a path to the standard library. Roughly speaking this is loaded from:
        //  - Any override in the config
        //  - The version embedded in the binary, stamped to disk
        let stdlib_dir = {
            if let Some(dir) = config.stdlib_dir_override() {
                dir.to_path_buf()
            } else {
                stdlib::upsert_stdlib_to_disk(config.stdlib_dir()).map_err(|e| {
                    Error::Other(anyhow!("loading embedded standard library: {}", e))
                })?
            }
        };

        Ok((vcs, cache, stdlib_dir))
    }
}

impl Context {
    /// Initializes a new context using the given configuration.
    pub fn new(config: Config) -> Result<Self, Error> {
        let strategy = {
            match config.repo_dir_override() {
                Some(path) => MFileSearchStrategy::Override(path.to_path_buf()),
                _ => MFileSearchStrategy::CurrentDirRecursive,
            }
        };
        Self::new_with_strategy(config, strategy)
    }

    /// Initializes a new context using the given configuration and `strategy` for finding the mfile
    /// This is useful when a given command needs to override the behaviour for finding the mfile
    pub fn new_with_strategy(config: Config, strategy: MFileSearchStrategy) -> Result<Self, Error> {
        let daemon = Arc::new(DaemonContext::init(config)?);
        let mfile = strategy.find_mfile()?;
        Ok(Self { daemon, mfile })
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
        let daemon = Arc::new(DaemonContext {
            config,
            stdlib_dir,
            vcs,
            cache,
        });
        Self { daemon, mfile }
    }

    /// Constructs a `Context` from a shared `DaemonContext` and an
    /// already-parsed mfile. Used by daemon-side callers to build
    /// per-session contexts against one shared daemon-scoped setup,
    /// without repeating the (moderately expensive)
    /// [`DaemonContext::init`] work per session.
    pub fn from_daemon(daemon: Arc<DaemonContext>, mfile: mfile::File) -> Self {
        Self { daemon, mfile }
    }

    /// Returns a clone of the shared daemon-scoped context. Cheap —
    /// just an `Arc` clone. Useful when a caller needs to hand the
    /// same daemon-scoped state to another `Context` or subsystem
    /// without going through the mfile-loaded superstructure.
    pub fn daemon_context(&self) -> Arc<DaemonContext> {
        Arc::clone(&self.daemon)
    }
}

/// Low-level API
impl Context {
    /// Re-reads the minimal file and returns a fresh `Context` on the
    /// same shared `Arc<DaemonContext>`. Intended for callers that
    /// have mutated the on-disk mfile and want the in-memory copy
    /// refreshed; daemon-scoped state (`Config`, `stdlib_dir`, `vcs`,
    /// `cache`) is preserved and shared, not rebuilt.
    ///
    /// The reload path mirrors [`Self::repo_dir`]'s resolution order:
    /// the currently-loaded mfile's own directory takes precedence
    /// (correct for daemon-side callers whose shared `Config` has no
    /// per-session repo override), then any config-provided override,
    /// then a recursive search from the daemon's cwd as a last-ditch
    /// fallback for CLI-style callers that constructed via
    /// [`Self::new`].
    pub fn cloned_reinit(&self) -> Result<Self, Error> {
        let strategy = if let Some(path) = self.mfile.repo_path() {
            MFileSearchStrategy::Override(path.to_path_buf())
        } else if let Some(path) = self.daemon.config.repo_dir_override() {
            MFileSearchStrategy::Override(path.to_path_buf())
        } else {
            MFileSearchStrategy::CurrentDirRecursive
        };
        let mfile = strategy.find_mfile()?;
        Ok(Self::from_daemon(Arc::clone(&self.daemon), mfile))
    }

    /// Builds a [`ProjectSetup`] from this context, for running project-setup
    /// operations (e.g. [`op::UpdateProject`]) that refresh the `minimal.toml`.
    pub fn project_setup(&self) -> ProjectSetup {
        ProjectSetup::from_parts(
            self.daemon.config.clone(),
            self.daemon.vcs.clone(),
            self.daemon.stdlib_dir.clone(),
            self.mfile.clone(),
            self.repo_dir().to_path_buf(),
        )
    }

    /// Returns a handle to the local cache.
    pub fn local_cache(&self) -> Cache {
        self.daemon.cache.clone()
    }
    /// Returns the vcs manager.
    pub fn vcs_manager(&self) -> VcsManagerHandle {
        self.daemon.vcs.clone()
    }
    /// Returns the daemon ID, if one was configured.
    pub fn daemon_id(&self) -> Option<String> {
        self.daemon.config.daemon_id()
    }

    /// Returns true if the context is configured to use the local cache.
    pub fn use_local_cache(&self) -> bool {
        self.daemon.config.use_local_cache()
    }
    /// Returns true if the context is configured to use a remote cache.
    pub fn use_remote_cache(&self) -> bool {
        self.daemon.config.use_remote_cache()
    }
    /// Returns the base directory for build sandboxes.
    pub fn builds_base_dir(&self) -> PathBuf {
        self.daemon.config.builds_base_dir()
    }
    /// Returns the base directory for task sandboxes.
    pub fn tasks_base_dir(&self) -> PathBuf {
        self.daemon.config.task_base_dir()
    }
    /// Returns the base directory for the artifact/binary cache.
    ///
    /// DO NOT USE unless you really know what you
    /// are doing - prefer [Context::local_cache] instead.
    pub fn cache_base_dir(&self) -> PathBuf {
        self.daemon.config.built_cache_dir()
    }
    /// Returns the base directory where source checkouts are stored.
    pub fn vcs_dir(&self) -> PathBuf {
        self.daemon.config.vcs_dir()
    }
    /// Returns the base directory where the remote index is cached.
    pub fn index_dir(&self) -> PathBuf {
        self.daemon.config.index_dir()
    }
    /// Returns the directory where compiled layers are cached.
    pub fn layer_cache_dir(&self) -> PathBuf {
        self.daemon.config.layer_cache_dir()
    }

    /// Returns the path to the root of the repo.
    pub fn repo_dir(&self) -> &Path {
        self.mfile
            .repo_path()
            .unwrap_or_else(|| self.daemon.config.repo_dir_override().as_ref().unwrap())
    }
    /// Returns a path to the standard library.
    pub fn stdlib_dir(&self) -> &PathBuf {
        &self.daemon.stdlib_dir
    }

    /// Returns the minimal file configuring this context.
    ///
    /// This usually maps to a `minimal.toml` read from disk,
    /// but not always. Methods like [`mfile::File::repo_path`]
    /// return None if not read from disk.
    pub fn minimal_file(&self) -> &mfile::File {
        &self.mfile
    }

    /// Builds and returns a remote cache reader for the configured cache
    /// location. [Config] has already resolved where artifacts come from — a GCS
    /// bucket (the default) or an HTTPS mirror (honouring
    /// `MINIMAL_REMOTE_CACHE_URL`) — and the minimal file resolves *which index
    /// object* to read ([`mfile::File::cache_config`], overridable via
    /// `MINIMAL_INDEX_SOURCE`), so this just wires up the matching backend and
    /// follows those instructions.
    ///
    /// `auth` selects authenticated vs. anonymous GCS access (the buildbot / mip
    /// upload path reads authed; anonymous CI reads use the public path). It's
    /// ignored for an HTTPS mirror, whose objects are fetched with unauthenticated
    /// public GETs.
    pub async fn remote_cache(
        &self,
        auth: bool,
        force_fresh: bool,
    ) -> Result<RemoteCache<AnyBackend>, RemoteError<AnyRespError>> {
        let start = SystemTime::now();
        let index_dir = if force_fresh {
            None
        } else {
            Some(self.daemon.config.index_dir())
        };

        // A GCS location needs a Storage client (authed or anonymous per `auth`);
        // an HTTPS mirror (e.g. a Cloudflare R2 custom domain) needs none —
        // new_any builds a reqwest client internally. Note it's reading from R2
        // that avoids GCS egress cost: an https:// URL still pointed at GCS would
        // egress just the same.
        let url = self.daemon.config.remote_cache_url();
        let gcs_storage = if matches!(url, AnyUrl::Gcs(_)) {
            let backend = if auth {
                GcsStorage::builder().build().await.unwrap()
            } else {
                GcsStorage::builder()
                    .with_credentials(
                        google_cloud_auth::credentials::anonymous::Builder::new().build(),
                    )
                    .build()
                    .await
                    .unwrap()
            };
            Some(backend)
        } else {
            None
        };

        // Rollout lever: overrides the file setting while per-commit reads
        // bed in. Retire (env var first, then likely the file setting) once
        // snapshot reads are the settled default.
        let override_mode = match std::env::var("MINIMAL_INDEX_SOURCE") {
            Ok(v) => Some(
                v.parse::<mfile::IndexSourceMode>()
                    .map_err(|e| RemoteError::Config(format!("MINIMAL_INDEX_SOURCE: {e}")))?,
            ),
            Err(std::env::VarError::NotPresent) => None,
            // A set-but-garbled override must be loud, like any other bad value.
            Err(e) => return Err(RemoteError::Config(format!("MINIMAL_INDEX_SOURCE: {e}"))),
        };
        let config = self
            .mfile
            .cache_config(override_mode)
            .map_err(RemoteError::Config)?;
        let res = RemoteCache::new_any_configured(
            url,
            gcs_storage,
            index_dir,
            self.daemon.config.ot.clone(),
            &config,
        )
        .await;
        let fetch_retries = match std::env::var("MINIMAL_FETCH_RETRIES") {
            Ok(v) => v
                .parse::<u32>()
                .map_err(|e| RemoteError::Config(format!("MINIMAL_FETCH_RETRIES: {e}")))?,
            Err(std::env::VarError::NotPresent) => self
                .mfile
                .cache
                .fetch_retries
                .unwrap_or(rcache::DEFAULT_FETCH_RETRIES),
            // A set-but-garbled override must be loud, like any other bad value.
            Err(e) => return Err(RemoteError::Config(format!("MINIMAL_FETCH_RETRIES: {e}"))),
        };
        let res = res.map(|rc| rc.with_fetch_retries(fetch_retries));
        tracing::trace!("remote cache init took {:?}", start.elapsed());
        res
    }

    /// Builds a writer for the shared cache. Always uses authenticated GCS
    /// access and always fetches the index fresh (no local-cache fast path) —
    /// the writer's compare-and-swap on commit requires the GCS generation
    /// it observed, which a stale local index can't provide.
    ///
    /// Errors if the cache is configured as an HTTPS read mirror: a mirror (e.g.
    /// R2 via a custom domain) has no writable bucket, so there's nowhere to
    /// upload. Writes require a `gs://` bucket location.
    pub async fn remote_cache_writer(&self) -> anyhow::Result<RemoteCacheWriter> {
        let start = SystemTime::now();
        let bucket = self
            .daemon
            .config
            .remote_cache_write_bucket()
            .ok_or_else(|| {
                anyhow!(
                    "remote cache is configured as an HTTPS read mirror; writes \
                 require a gs:// bucket — set the cache location to a gs:// URL \
                 or a bare bucket name"
                )
            })?;
        let backend = GcsStorage::builder().build().await.unwrap();
        let res = RemoteCacheWriter::new(backend, bucket, self.daemon.config.ot.clone()).await?;
        tracing::trace!("remote cache writer init took {:?}", start.elapsed());
        Ok(res)
    }
    pub async fn remote_storage(&self) -> Result<common::RemoteStorage, Error> {
        let start = SystemTime::now();
        // `--offline` flips the underlying FileCache into offline mode so any
        // source-URL cache miss surfaces as FileCacheError::OfflineCacheMiss
        // rather than a silent network fetch.
        let rs = common::RemoteStorage::new_with_offline(
            self.daemon.config.downloads_dir(),
            false,
            self.daemon.config.is_offline(),
        )
        .await
        .map_err(|e| Error::Other(anyhow!("initializing remote storage: {}", e)))?;
        tracing::trace!("remote storage init took {:?}", start.elapsed());
        Ok(rs)
    }

    /// Returns a [SpecOrigin] representing the top-level repository.
    pub fn repo_origin(&self) -> SpecOrigin {
        SpecOrigin::from_dir(self.repo_dir())
    }
    /// Returns the [OpTracker] to be used as the root for tracking long-running operations.
    pub fn op_tracker(&self) -> Option<OpTracker> {
        self.daemon.config.ot.clone()
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
        let start = SystemTime::now();
        let res = Graph::new_from_chain(
            self.vcs_manager(),
            &mut graph::LayerCacheDir(self.daemon.config.layer_cache_dir()),
            LinkConfig::Dir {
                dir: self.repo_dir().to_str().unwrap().to_string(),
            },
            self.daemon.stdlib_dir.clone(),
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
        let rc = if self.daemon.config.use_remote_cache() {
            Some(self.remote_cache(false, false).await.unwrap())
        } else {
            None
        };

        use orchestrator::LocalBackend;
        let orchestrator = LocalBackend::new_orchestrator(
            self.daemon.config.builds_base_dir(),
            rc.clone(),
            self.remote_storage().await?,
            self.daemon.config.num_parallel_builds(),
            graph.clone(),
            cache.clone(),
            self.daemon_id(),
            log_sink,
            self.daemon.config.ot.clone(),
            cancel,
        )?;

        let mut bin_provider: Box<dyn BinProvider> = match (
            self.daemon.config.use_local_cache(),
            self.daemon.config.use_remote_cache(),
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

    pub fn iter_tasks(&self, graph: &Graph) -> Vec<(String, TaskSource)> {
        let mut out: Vec<_> = self
            .mfile
            .iter_tasks()
            .map(|(name, _t)| (name.clone(), TaskSource::MFile))
            .collect();

        if let Some(h_conf) = &self.mfile.stack
            && let Some(stack) = graph.stack(&h_conf.name)
        {
            out.extend(stack.task_names().into_iter().filter_map(|name| {
                if self.mfile.task(&name).is_some() {
                    // Already capture by iter_tasks() above
                    None
                } else {
                    Some((name.to_string(), TaskSource::Stack(h_conf.name.clone())))
                }
            }));
        }

        out
    }

    /// Returns the task of the given name, fully hydrated based on profiles. If no task
    /// is declared in the minimal file with the given name, stack are considered.
    ///
    /// The returned task will not have had any string interpolations applied.
    pub fn task(&mut self, mut graph: Graph, name: &str) -> Result<Option<(Task, Graph)>, Error> {
        let mfile = self.minimal_file();
        let mut task = match mfile.task(name) {
            Some(t) => t,
            None => {
                // Task requested but none defined, lets see if the stack provides an implementation.
                if let Some(h_conf) = &mfile.stack {
                    if let Some(stack) = graph.stack(&h_conf.name) {
                        if let Some(mut task) = stack.task_by_name(name) {
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
        // Apply the specifics (pkgs etc) of the stack & profile
        graph.hydrate_task(mfile.stack.as_ref().map(|h| h.name.as_str()), &mut task)?;

        // TODO: Probably time to retire this top_levels concept
        graph.top_levels = task.packages.as_bsrs(&graph)?;

        Ok(Some((task, graph)))
    }

    /// Constructs an environment from which executions can be run, based on the given parameters.
    #[allow(clippy::too_many_arguments)]
    /// Builds an [`env::Env`] with the default `HostNet` sandbox network. Use
    /// [`make_env_with_network`](Self::make_env_with_network) to run the sandbox
    /// in another [`sandbox2::NetworkMode`] (e.g. a `NoNet`/`OwnIp` PTask).
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
        self.make_env_with_network(
            name,
            graph,
            wd,
            state_key,
            patches,
            env_vars,
            packages,
            sandbox2::NetworkMode::HostNet,
        )
        .await
    }

    /// Like [`make_env`](Self::make_env) but runs the sandbox in the given
    /// [`sandbox2::NetworkMode`], so callers (e.g. the minimald task-exec path)
    /// can give a task the same network isolation as its session rather than
    /// always `HostNet`.
    #[allow(clippy::too_many_arguments)]
    pub async fn make_env_with_network<'a, S: PackageSelection>(
        &'a mut self,
        name: &'a str,
        graph: &'a mut Graph,
        wd: Option<PathBuf>,
        state_key: Option<&String>,
        patches: Option<&'a EnvPatches>,
        env_vars: Option<&'a HashMap<String, EnvVarValue>>,
        packages: S,
        network_mode: sandbox2::NetworkMode,
    ) -> Result<env::Env<'a>, Error> {
        let mfile = self.minimal_file();

        let mut temp_dirs = vec![];
        let wd = if let Some(wd) = wd {
            wd
        } else {
            self.repo_dir().to_path_buf()
        };
        let state_base_dir = match state_key {
            Some(name) if !name.is_empty() => mfile
                .state_dir(name, self.daemon.config.state_base_dir())
                .unwrap(),
            _ => {
                let tmp = self.daemon.cache.temp_dir().map_err(|e| {
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
            self.daemon.config.task_base_dir(),
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
                override_network_mode: Some(network_mode),
                ot: self.daemon.config.ot.clone(),
            },
        )
        .await?;
        env.associate_tempdirs(temp_dirs);
        env.associate_tempdirs([base]);

        Ok(env)
    }

    /// Returns the list of all packages brought in through tasks, profiles and stacks.
    pub fn scaffolding_packages(&mut self) -> Result<Vec<BuildSpecRef>, Error> {
        let mut out = std::collections::HashSet::new();
        let mut graph = self.graph_from_all_packages()?;
        let mfile = self.minimal_file().clone();
        for name in mfile.tasks.keys() {
            let res = self.task(graph, name)?.unwrap();
            let task = res.0;
            graph = res.1;

            out.extend(task.packages);
        }
        if let Some(stack) = &mfile.stack {
            let h = graph.stack(&stack.name).ok_or_else(|| {
                Error::Graph(Box::new(GraphError::NoSuchStack {
                    name: stack.name.clone(),
                }))
            })?;
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
        // The two arms are NOT interchangeable, though they look it.
        // `rcache::Error`'s Display is `write!(f, "{:?}", self)` — it
        // Debug-formats itself — so the fallback arm renders a Config as
        // `Config("MINIMAL_INDEX_SOURCE: unknown index source \"banana\" ...")`,
        // variant name and escaped quotes included. Destructuring Config and
        // formatting the inner `msg` is what yields the clean, user-facing
        // message. Collapsing this to one arm reintroduces the panic-era
        // output this replaced.
        let rc = self.remote_cache(false, true).await.map_err(|e| match e {
            RemoteError::Config(msg) => Error::Other(anyhow::anyhow!("{msg}")),
            other => Error::Other(anyhow::anyhow!("{other}")),
        })?;
        let mut task_set = tokio::task::JoinSet::new();
        let fetch_start = SystemTime::now();
        let semaphore = Arc::new(Semaphore::new(8));
        for (bsr, _depinfo) in Transitives::for_toplevels(graph, pkgs.into_iter().collect(), false)
        {
            let b = graph.get(&bsr).unwrap();
            let name = b.name.clone();
            let origin = b.from.as_ref().clone();
            let spec_hash = graph.spec_hash(&bsr);
            if let Err(lcache::CacheErr::NotFound) = self.daemon.cache.read_dir(&spec_hash)
                && rc.exists(&spec_hash)
            {
                let rc_clone = rc.clone(); // TODO: This is trash
                let cache_clone = self.daemon.cache.clone();
                let semaphore = semaphore.clone();
                task_set.spawn(async move {
                    let sema = semaphore.acquire().await;
                    let res = rc_clone
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
                        });
                    drop(sema);
                    res
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
                if let Some(h) = doc["stack"].as_table_mut() {
                    did_edit |= upsert_toml_packages_list(h, "build_packages", &resolved);
                    println!("Added [{}] to stack.build_packages", resolved.join(","));
                } else {
                    return Err(Error::Other(anyhow!(
                        "could not find [stack] in minimal.toml: needed for update"
                    )));
                }
            }
            AddDepMode::RuntimePackages => {
                if let Some(h) = doc["stack"].as_table_mut() {
                    did_edit |= upsert_toml_packages_list(h, "runtime_packages", &resolved);
                    println!("Added [{}] to stack.runtime_packages", resolved.join(","));
                } else {
                    return Err(Error::Other(anyhow!(
                        "could not find [stack] in minimal.toml: needed for update"
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
            AddDepMode::SessionPackages => {
                if let Some(h) = doc["session"].as_table_mut() {
                    did_edit |= upsert_toml_packages_list(h, "packages", &resolved);
                } else {
                    doc.insert(
                        "session",
                        Item::Table(toml_edit::Table::from_iter([(
                            "packages",
                            Item::Value(Value::Array(Array::from_iter(resolved.iter()))),
                        )])),
                    );
                    did_edit = true;
                }
                println!("Added [{}] to session.packages", resolved.join(","));
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
    /// Add the specified packages to stack.build_packages.
    BuildPackages,
    /// Add the specified packages to stack.runtime_packages.
    RuntimePackages,
    /// Add the specified packages to a task with a given name.
    TaskPackages { name: String },
    /// Add the specified packages to session.packages.
    SessionPackages,
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

    /// `DaemonContext::init` works standalone — no mfile required.
    /// This is the whole point of the daemon/session split: daemon-
    /// scoped state can be built once at startup, before any project
    /// is known.
    #[test]
    fn daemon_context_inits_without_mfile() {
        let state = tempdir().unwrap();
        let cache = tempdir().unwrap();
        let config = ConfigBuilder::new()
            .with_state_dir(state.path().to_path_buf())
            .with_cache_dir(cache.path().to_path_buf())
            // Stdlib override avoids the network hop for embedded-stdlib
            // materialization.
            .with_stdlib_dir(
                std::path::Path::new(&std::env::var("CARGO_MANIFEST_DIR").unwrap())
                    .join("../stdlib/minimal-ncl"),
            )
            .build()
            .unwrap();

        let daemon = DaemonContext::init(config).expect("daemon-scoped init should succeed");
        // Setup upserted the expected dirs.
        assert!(daemon.config().state_base_dir().exists());
        assert!(daemon.config().built_cache_dir().exists());
        assert!(daemon.stdlib_dir().exists());
    }

    /// `Context::from_daemon` reuses a shared `Arc<DaemonContext>`
    /// across multiple `Context`s: two Contexts built against the
    /// same daemon pointer-compare equal on their daemon slice.
    /// Asserts the sharing contract, not any performance property.
    #[test]
    fn context_from_daemon_shares_arc() {
        let state = tempdir().unwrap();
        let cache = tempdir().unwrap();
        let config = ConfigBuilder::new()
            .with_state_dir(state.path().to_path_buf())
            .with_cache_dir(cache.path().to_path_buf())
            .with_stdlib_dir(
                std::path::Path::new(&std::env::var("CARGO_MANIFEST_DIR").unwrap())
                    .join("../stdlib/minimal-ncl"),
            )
            .build()
            .unwrap();
        let daemon = Arc::new(DaemonContext::init(config).unwrap());

        let repo = std::path::Path::new(&std::env::var("CARGO_MANIFEST_DIR").unwrap())
            .join("testdata")
            .join("fakerepo");
        let mfile_a = MFileSearchStrategy::Override(repo.clone())
            .find_mfile()
            .expect("fakerepo has a minimal.toml");
        let mfile_b = MFileSearchStrategy::Override(repo)
            .find_mfile()
            .expect("fakerepo has a minimal.toml");

        let ctx_a = Context::from_daemon(Arc::clone(&daemon), mfile_a);
        let ctx_b = Context::from_daemon(Arc::clone(&daemon), mfile_b);

        assert!(Arc::ptr_eq(
            &ctx_a.daemon_context(),
            &ctx_b.daemon_context()
        ));
    }

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
                cancel: tokio_util::sync::CancellationToken::new(),
            };
            let opts = op::Options {
                cache: ctx.local_cache(),
                exec_base: temp_dir.path().to_path_buf(),
                graph: &graph,
                ot: ctx.daemon.config.ot.clone(),
                daemon_id: ctx.daemon.config.daemon_id(),
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
    fn task_inherits_stack() {
        let state = tempdir().unwrap();
        let config = ConfigBuilder::new()
            .with_state_dir(state.path().to_path_buf())
            .with_repo_dir(
                std::path::Path::new(&std::env::var("CARGO_MANIFEST_DIR").unwrap())
                    .join("testdata")
                    .join("fakerepo-with-stack"),
            )
            .with_stdlib_dir(
                std::path::Path::new(&std::env::var("CARGO_MANIFEST_DIR").unwrap())
                    .join("../stdlib/minimal-ncl"),
            )
            .build()
            .unwrap();

        let mut ctx = Context::new(config).unwrap();

        let graph = ctx.graph_from_all_packages().unwrap();
        let (task, _graph) = ctx.task(graph, "task-inherits-stack").unwrap().unwrap();

        // println!("task = {:#?}", task);
        // task inherited stack build_packages and runtime_packages, as well as any
        // extras defined in the minimal file
        assert_eq!(
            task.packages,
            vec![
                "uroot".to_string(),
                "extra-build-pkg".to_string(),
                "extra-runtime-pkg".to_string(),
                "stack-build-pkg".to_string(),
                "stack-runtime-pkg".to_string(),
            ]
        );
        // task inherited stack build env vars
        assert_eq!(
            task.vars.get("STACK_VAR"),
            Some(&EnvVarValue::Value("set".to_string()))
        );
    }

    #[test]
    #[ignore] // Do not run in github- does not support nested namespaces
    fn task_env() {
        let (cache, state) = (tempdir().unwrap(), tempdir().unwrap());
        let config = ConfigBuilder::new()
            .with_state_dir(state.path().to_path_buf())
            .with_cache_dir(cache.path().to_path_buf())
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

                    [stack]
                    use = \"fake-stack\"

                    [tasks.something]
                    exec = \"./something\"
                    "
                },
                std::path::Path::new(&std::env::var("CARGO_MANIFEST_DIR").unwrap())
                    .join("testdata")
                    .join("fakerepo-with-stack")
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

        // Add a package to the session.
        ctx.add_deps(&graph, ["uroot"], AddDepMode::SessionPackages)
            .unwrap();
        assert!(
            String::from_utf8(std::fs::read(&mfile_path).unwrap())
                .unwrap()
                .contains("[session]\npackages = [\"uroot\"]")
        );
    }

    #[test]
    #[ignore] // Do not run in github- does not support nested namespaces
    fn task_resolve_string_interpolation() {
        let (cache, state) = (tempdir().unwrap(), tempdir().unwrap());
        let config = ConfigBuilder::new()
            .with_state_dir(state.path().to_path_buf())
            .with_cache_dir(cache.path().to_path_buf())
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
                    Some(
                        &std::collections::HashMap::from([(
                            "input".to_string(),
                            args::Arg::Scalar(args::ScalarArg::String("beep".to_string())),
                        )])
                        .into(),
                    ),
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
