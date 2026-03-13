use std::{fmt, path::PathBuf};

use checkouts::ManagerHandle;

/// The errors possible in configuration or building a configuration.
#[derive(Debug)]
pub enum ConfigError {
    IO(&'static str, PathBuf, std::io::Error),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::IO(ctx, path, e) => {
                write!(f, "{} I/O error at path {}: {}", ctx, path.display(), e)
            }
        }
    }
}

impl std::error::Error for ConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ConfigError::IO(_, _, e) => Some(e),
        }
    }
}

/// Builder for [Config].
#[derive(Debug, Default, Clone)]
pub struct ConfigBuilder {
    no_cache: Option<bool>,
    no_fetch: Option<bool>,
    num_parallel_builds: Option<usize>,

    minimal_dir: Option<PathBuf>,
    stdlib_dir: Option<PathBuf>,
    repo_dir: Option<PathBuf>,
    vcs_manager: Option<ManagerHandle>,
}

impl ConfigBuilder {
    /// Creates a new config builder.
    pub fn new() -> Self {
        Self::default()
    }
    /// Configures whether the local cache may be used or not.
    pub fn with_no_cache(mut self, no_cache: bool) -> Self {
        self.no_cache = Some(no_cache);
        self
    }
    /// Configures whether the remote cache may be used or not.
    pub fn with_no_fetch(mut self, no_fetch: bool) -> Self {
        self.no_fetch = Some(no_fetch);
        self
    }
    /// Configures the max number of parallel builds.
    pub fn with_num_parallel_builds(mut self, num_parallel_builds: usize) -> Self {
        self.num_parallel_builds = Some(num_parallel_builds);
        self
    }
    /// Overrides the base directory for system state.
    pub fn with_state_dir(mut self, dir: PathBuf) -> Self {
        self.minimal_dir = Some(dir);
        self
    }
    /// Overrides loading of the standard library, getting it from the given path instead.
    pub fn with_stdlib_dir(mut self, dir: PathBuf) -> Self {
        self.stdlib_dir = Some(dir);
        self
    }
    /// Use the repository rooted at the given directory, instead of inferring it from the cwd.
    pub fn with_repo_dir(mut self, dir: PathBuf) -> Self {
        self.repo_dir = Some(dir);
        self
    }
    /// Use the specified vcs manager instead of initializing one from disk.
    pub fn with_vcs_manager(mut self, manager: ManagerHandle) -> Self {
        self.vcs_manager = Some(manager);
        self
    }
}

impl ConfigBuilder {
    /// Constructs a config object using the given builder.
    pub fn build(self) -> Result<Config, ConfigError> {
        Ok(Config {
            no_cache: self.no_cache.unwrap_or(false),
            no_fetch: self.no_fetch.unwrap_or(false),
            num_parallel_builds: self
                .num_parallel_builds
                .unwrap_or_else(common::default_parallelism),

            minimal_dir: self.minimal_dir.unwrap_or_else(|| {
                dirs::cache_dir()
                    .unwrap_or_else(|| PathBuf::from("~/.cache"))
                    .join("minimal")
            }),
            stdlib_dir: self.stdlib_dir,
            repo_dir: self.repo_dir,
            vcs_manager: self.vcs_manager,
        })
    }
}

/// Configuration for a [super::Context].
#[derive(Debug, Clone)]
pub struct Config {
    /// Assume no entries in the local cache for build planning / orchestration purposes.
    no_cache: bool,
    /// Do not fetch any needed-but-available-remote entries from the remote cache.
    no_fetch: bool,
    /// Maximum number of concurrent builds.
    num_parallel_builds: usize,

    /// Path to the base of the minimal state directory, typically `~/.cache/minimal`.
    pub(crate) minimal_dir: PathBuf,
    /// Overrides where the standard directory is loaded from.
    stdlib_dir: Option<PathBuf>,
    /// Overrides the base/project/repo directory.
    repo_dir: Option<PathBuf>,
    /// Use the specified vcs manager instead of initializing one from disk.
    vcs_manager: Option<ManagerHandle>,
}

impl Config {
    pub(crate) fn stdlib_dir_override(&self) -> &Option<PathBuf> {
        &self.stdlib_dir
    }
    pub(crate) fn vcs_manager_override(&self) -> Option<ManagerHandle> {
        self.vcs_manager.clone()
    }

    /// Returns the path to the repo, if overridden (i.e. via '-C' argument).
    pub fn repo_dir_override(&self) -> &Option<PathBuf> {
        &self.repo_dir
    }

    /// Returns true if objects should be used from the local cache instead of fetched/rebuilt.
    pub fn use_local_cache(&self) -> bool {
        !self.no_cache
    }
    /// Returns true if objects should be downloaded from the remote cache instead of built.
    pub fn use_remote_cache(&self) -> bool {
        !self.no_fetch
    }
    /// Returns the maximum number of parallel builds that may take place at once.
    pub fn num_parallel_builds(&self) -> usize {
        self.num_parallel_builds
    }

    pub(crate) fn cache_dir(&self) -> PathBuf {
        self.minimal_dir.join("built")
    }
    pub(crate) fn downloads_dir(&self) -> PathBuf {
        self.minimal_dir.join("downloads")
    }
    pub(crate) fn builds_base_dir(&self) -> PathBuf {
        self.minimal_dir.join("sandboxes")
    }
    pub(crate) fn state_base_dir(&self) -> PathBuf {
        self.minimal_dir.join("state")
    }
    pub(crate) fn task_base_dir(&self) -> PathBuf {
        self.minimal_dir.join("tasks")
    }
    pub(crate) fn vcs_dir(&self) -> PathBuf {
        self.minimal_dir.join("vcs")
    }
    pub(crate) fn index_dir(&self) -> PathBuf {
        self.minimal_dir.join("idx")
    }
    pub(crate) fn stdlib_dir(&self) -> PathBuf {
        self.minimal_dir.join("stdlib")
    }
    pub(crate) fn layer_cache_dir(&self) -> PathBuf {
        self.minimal_dir.join("lc")
    }
}
