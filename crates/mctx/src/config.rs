use std::{
    fmt,
    path::{Path, PathBuf},
};

use checkouts::ManagerHandle;
use ot::OpTracker;

/// The errors possible in configuration or building a configuration.
#[derive(Debug)]
pub enum ConfigError {
    IO(&'static str, PathBuf, std::io::Error),
    /// Configured remote cache bucket name is empty or whitespace-only.
    /// Carries the offending value for diagnostics.
    InvalidRemoteCacheBucket(String),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::IO(ctx, path, e) => {
                write!(f, "{} I/O error at path {}: {}", ctx, path.display(), e)
            }
            ConfigError::InvalidRemoteCacheBucket(bucket) => {
                write!(f, "invalid remote cache bucket: {:?}", bucket)
            }
        }
    }
}

impl std::error::Error for ConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ConfigError::IO(_, _, e) => Some(e),
            ConfigError::InvalidRemoteCacheBucket(_) => None,
        }
    }
}

/// Default GCS bucket name used when the caller does not configure one
/// via [ConfigBuilder::with_remote_cache_bucket].
pub const DEFAULT_REMOTE_CACHE_BUCKET: &str = "minimal-staging-cache";

/// Resolves the remote-cache reader URL override: a non-empty explicit builder
/// value wins; otherwise a non-empty `MINIMAL_REMOTE_CACHE_URL`; else `None`
/// (reads go through the GCS client). Empty / whitespace-only values in either
/// source are treated as unset. Pure so the precedence is unit-testable without
/// touching process env.
fn resolve_remote_cache_read_url(builder: Option<String>, env: Option<String>) -> Option<String> {
    builder
        .filter(|s| !s.trim().is_empty())
        .or_else(|| env.filter(|s| !s.trim().is_empty()))
}

/// Builder for [Config].
#[derive(Debug, Default, Clone)]
pub struct ConfigBuilder {
    no_cache: Option<bool>,
    no_fetch: Option<bool>,
    offline: Option<bool>,
    num_parallel_builds: Option<usize>,

    minimal_state_dir: Option<PathBuf>,
    minimal_cache_dir: Option<PathBuf>,
    stdlib_dir: Option<PathBuf>,
    repo_dir: Option<PathBuf>,

    vcs_manager: Option<ManagerHandle>,
    ot: Option<OpTracker>,
    remote_cache_bucket: Option<String>,
    remote_cache_read_url: Option<String>,
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
    /// Configures whether minimal runs in offline mode. When set, any source
    /// or VCS cache miss surfaces as a clear error rather than a silent
    /// network call.
    ///
    /// Does NOT imply [Self::with_no_fetch] — the remote artifact cache
    /// is sha-verified on hydrate (see `rcache::RemoteCache::materialize`),
    /// so cached pulls are hermetically clean even when offline mode
    /// forbids source-tarball or VCS fetches. For environments that need
    /// to disable both (e.g. fully air-gapped builds), set them
    /// independently via [Self::with_no_fetch] + [Self::with_offline].
    ///
    /// Hermetic-builder-rs sets offline=true to surface mirror-source
    /// gaps as clear errors while still allowing the signer-attested
    /// build cache to satisfy build_deps.
    pub fn with_offline(mut self, offline: bool) -> Self {
        self.offline = Some(offline);
        self
    }
    /// Configures the max number of parallel builds.
    pub fn with_num_parallel_builds(mut self, num_parallel_builds: usize) -> Self {
        self.num_parallel_builds = Some(num_parallel_builds);
        self
    }
    /// Overrides the base directory for minimal state.
    pub fn with_state_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.minimal_state_dir = Some(dir.into());
        self
    }
    /// Overrides the base directory for minimal cache.
    pub fn with_cache_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.minimal_cache_dir = Some(dir.into());
        self
    }
    /// Overrides loading of the standard library, getting it from the given path instead.
    pub fn with_stdlib_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.stdlib_dir = Some(dir.into());
        self
    }
    /// Use the repository rooted at the given directory, instead of inferring it from the cwd.
    pub fn with_repo_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.repo_dir = Some(dir.into());
        self
    }
    /// Use the specified vcs manager instead of initializing one from disk.
    pub fn with_vcs_manager(mut self, manager: ManagerHandle) -> Self {
        self.vcs_manager = Some(manager);
        self
    }
    /// Use the specified operation tracker instead of the root.
    pub fn with_operation_tracker(mut self, ot: OpTracker) -> Self {
        self.ot = Some(ot);
        self
    }
    /// Override the GCS bucket name used by the remote cache reader and
    /// writer. Defaults to [DEFAULT_REMOTE_CACHE_BUCKET] when unset.
    pub fn with_remote_cache_bucket(mut self, bucket: String) -> Self {
        self.remote_cache_bucket = Some(bucket);
        self
    }
    /// Override the base URL the remote cache *reader* fetches from, bypassing
    /// the GCS client in favour of plain unauthenticated HTTPS GETs. Point this
    /// at an S3-compatible mirror (e.g. a Cloudflare R2 custom domain) to avoid
    /// GCS egress cost. The URL MUST end in `/`. Takes precedence over the
    /// `MINIMAL_REMOTE_CACHE_URL` environment variable; when neither is set,
    /// reads go through the GCS client against the configured bucket. The
    /// *writer* is unaffected (writes always use GCS).
    pub fn with_remote_cache_read_url(mut self, url: String) -> Self {
        self.remote_cache_read_url = Some(url);
        self
    }
}

impl ConfigBuilder {
    /// Constructs a config object using the given builder.
    pub fn build(self) -> Result<Config, ConfigError> {
        let remote_cache_bucket = self
            .remote_cache_bucket
            .unwrap_or_else(|| DEFAULT_REMOTE_CACHE_BUCKET.to_string());
        if remote_cache_bucket.trim().is_empty() {
            return Err(ConfigError::InvalidRemoteCacheBucket(remote_cache_bucket));
        }

        // An explicit builder value wins; otherwise honour the
        // `MINIMAL_REMOTE_CACHE_URL` env var, so CI / deployments can repoint
        // cache reads at an R2 mirror without a code change.
        let remote_cache_read_url = resolve_remote_cache_read_url(
            self.remote_cache_read_url,
            std::env::var("MINIMAL_REMOTE_CACHE_URL").ok(),
        );

        Ok(Config {
            no_cache: self.no_cache.unwrap_or(false),
            no_fetch: self.no_fetch.unwrap_or(false),
            offline: self.offline.unwrap_or(false),
            num_parallel_builds: self
                .num_parallel_builds
                .unwrap_or_else(common::default_parallelism),

            minimal_state_dir: self.minimal_state_dir.unwrap_or_else(|| {
                paths::minimal_state_dir()
                    .as_utf8_path()
                    .as_std_path()
                    .to_path_buf()
            }),
            minimal_cache_dir: self.minimal_cache_dir.unwrap_or_else(|| {
                paths::minimal_cache_dir()
                    .as_utf8_path()
                    .as_std_path()
                    .to_path_buf()
            }),
            stdlib_dir: self.stdlib_dir,
            repo_dir: self.repo_dir,
            vcs_manager: self.vcs_manager,
            ot: self.ot,
            remote_cache_bucket,
            remote_cache_read_url,
        })
    }
}

impl Config {
    /// Converts this config back into a builder, preserving all values.
    /// Useful for layering overrides on top of an existing configuration.
    pub fn into_builder(self) -> ConfigBuilder {
        ConfigBuilder {
            no_cache: Some(self.no_cache),
            no_fetch: Some(self.no_fetch),
            offline: Some(self.offline),
            num_parallel_builds: Some(self.num_parallel_builds),
            minimal_state_dir: Some(self.minimal_state_dir),
            minimal_cache_dir: Some(self.minimal_cache_dir),
            stdlib_dir: self.stdlib_dir,
            repo_dir: self.repo_dir,
            vcs_manager: self.vcs_manager,
            ot: self.ot,
            remote_cache_bucket: Some(self.remote_cache_bucket),
            remote_cache_read_url: self.remote_cache_read_url,
        }
    }
}

/// Configuration for a [super::Context].
#[derive(Debug, Clone)]
pub struct Config {
    /// Assume no entries in the local cache for build planning / orchestration purposes.
    no_cache: bool,
    /// Do not fetch any needed-but-available-remote entries from the remote cache.
    no_fetch: bool,
    /// Run in offline mode: error on source / VCS cache miss instead of attempting
    /// any network call. Implies the artifact-cache-skip half of [Self::no_fetch].
    offline: bool,
    /// Maximum number of concurrent builds.
    num_parallel_builds: usize,

    /// Path to the base of the minimal state directory, typically `$XDG_STATE_DIR/minimal`.
    pub(crate) minimal_state_dir: PathBuf,
    /// Path to the base of the minimal cache directory, typically `$XDG_CACHE_DIR/minimal`.
    pub(crate) minimal_cache_dir: PathBuf,
    /// Overrides where the standard library is loaded from.
    stdlib_dir: Option<PathBuf>,
    /// Overrides the base/project/repo directory.
    repo_dir: Option<PathBuf>,

    /// Use the specified vcs manager instead of initializing one from disk.
    vcs_manager: Option<ManagerHandle>,
    /// The [OpTracker] to use instead of the root.
    pub(crate) ot: Option<OpTracker>,
    /// GCS bucket name for the remote cache reader/writer. Always set —
    /// defaults to [DEFAULT_REMOTE_CACHE_BUCKET] when the builder did
    /// not specify one.
    remote_cache_bucket: String,
    /// Optional base URL for the remote cache *reader* — plain HTTPS instead of
    /// the GCS client (e.g. a Cloudflare R2 mirror). `None` reads via GCS. See
    /// [ConfigBuilder::with_remote_cache_read_url].
    remote_cache_read_url: Option<String>,
}

impl Config {
    pub(crate) fn stdlib_dir_override(&self) -> Option<&Path> {
        self.stdlib_dir.as_deref()
    }
    pub(crate) fn vcs_manager_override(&self) -> Option<ManagerHandle> {
        self.vcs_manager.clone()
    }

    /// Returns the path to the repo, if overridden (i.e. via '-C' argument).
    pub fn repo_dir_override(&self) -> Option<&Path> {
        self.repo_dir.as_deref()
    }

    /// Returns true if objects should be used from the local cache instead of fetched/rebuilt.
    pub fn use_local_cache(&self) -> bool {
        !self.no_cache
    }
    /// Returns true if objects should be downloaded from the remote cache instead of built.
    /// Gated only on [Self::no_fetch] — `offline` controls source-tarball / VCS
    /// fetch policy, not the sha-verified artifact cache. Cached pulls are
    /// hermetically clean (rcache verifies sha256 on hydrate) so they're
    /// allowed in offline mode. Set [Self::with_no_fetch] explicitly to
    /// disable the artifact cache in fully air-gapped configurations.
    pub fn use_remote_cache(&self) -> bool {
        !self.no_fetch
    }
    /// Returns true if minimal is running in offline mode. When true, source-tarball
    /// and VCS cache misses surface as errors rather than silent network fetches.
    pub fn is_offline(&self) -> bool {
        self.offline
    }
    /// Returns the maximum number of parallel builds that may take place at once.
    pub fn num_parallel_builds(&self) -> usize {
        self.num_parallel_builds
    }
    /// Returns the GCS bucket name for the remote cache.
    pub fn remote_cache_bucket(&self) -> &str {
        &self.remote_cache_bucket
    }
    /// Returns the remote-cache *reader* base URL override (plain HTTPS), if set
    /// via the builder or `MINIMAL_REMOTE_CACHE_URL`. `None` reads via the GCS
    /// client against [Self::remote_cache_bucket].
    pub fn remote_cache_read_url(&self) -> Option<&str> {
        self.remote_cache_read_url.as_deref()
    }

    pub(crate) fn built_cache_dir(&self) -> PathBuf {
        self.minimal_cache_dir.join("built")
    }
    pub(crate) fn downloads_dir(&self) -> PathBuf {
        self.minimal_cache_dir.join("downloads")
    }
    pub(crate) fn builds_base_dir(&self) -> PathBuf {
        self.minimal_state_dir.join("sandboxes")
    }
    pub(crate) fn state_base_dir(&self) -> PathBuf {
        self.minimal_state_dir.join("state")
    }
    pub(crate) fn task_base_dir(&self) -> PathBuf {
        self.minimal_state_dir.join("tasks")
    }
    pub(crate) fn vcs_dir(&self) -> PathBuf {
        self.minimal_cache_dir.join("vcs")
    }
    pub(crate) fn index_dir(&self) -> PathBuf {
        self.minimal_cache_dir.join("idx")
    }
    pub(crate) fn stdlib_dir(&self) -> PathBuf {
        self.minimal_cache_dir.join("stdlib")
    }
    pub(crate) fn layer_cache_dir(&self) -> PathBuf {
        self.minimal_cache_dir.join("lc")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_cache_bucket_defaults_when_unset() {
        let cfg = ConfigBuilder::new().build().unwrap();
        assert_eq!(cfg.remote_cache_bucket(), DEFAULT_REMOTE_CACHE_BUCKET);
    }

    #[test]
    fn remote_cache_bucket_honors_override() {
        let cfg = ConfigBuilder::new()
            .with_remote_cache_bucket("my-bucket".into())
            .build()
            .unwrap();
        assert_eq!(cfg.remote_cache_bucket(), "my-bucket");
    }

    #[test]
    fn remote_cache_bucket_rejects_empty() {
        let err = ConfigBuilder::new()
            .with_remote_cache_bucket(String::new())
            .build()
            .unwrap_err();
        assert!(matches!(err, ConfigError::InvalidRemoteCacheBucket(_)));
    }

    #[test]
    fn remote_cache_bucket_rejects_whitespace_only() {
        let err = ConfigBuilder::new()
            .with_remote_cache_bucket("   \t\n".into())
            .build()
            .unwrap_err();
        assert!(matches!(err, ConfigError::InvalidRemoteCacheBucket(_)));
    }

    #[test]
    fn read_url_none_when_neither_set() {
        assert_eq!(resolve_remote_cache_read_url(None, None), None);
    }

    #[test]
    fn read_url_builder_wins_over_env() {
        assert_eq!(
            resolve_remote_cache_read_url(
                Some("https://builder/".into()),
                Some("https://env/".into())
            ),
            Some("https://builder/".to_string())
        );
    }

    #[test]
    fn read_url_falls_back_to_env() {
        assert_eq!(
            resolve_remote_cache_read_url(None, Some("https://env/".into())),
            Some("https://env/".to_string())
        );
    }

    #[test]
    fn read_url_ignores_empty_and_whitespace() {
        // Empty/whitespace builder value falls through to a non-empty env var.
        assert_eq!(
            resolve_remote_cache_read_url(Some("  ".into()), Some("https://env/".into())),
            Some("https://env/".to_string())
        );
        // Empty/whitespace in both -> None (read via GCS).
        assert_eq!(
            resolve_remote_cache_read_url(Some(String::new()), None),
            None
        );
        assert_eq!(
            resolve_remote_cache_read_url(None, Some("\t\n".into())),
            None
        );
        assert_eq!(
            resolve_remote_cache_read_url(Some("".into()), Some(" ".into())),
            None
        );
    }

    #[test]
    fn read_url_builder_round_trips_through_config() {
        // The builder value is non-empty, so it wins regardless of any ambient
        // MINIMAL_REMOTE_CACHE_URL in the test process -> no env flakiness.
        let cfg = ConfigBuilder::new()
            .with_remote_cache_read_url("https://cache.example.com/".into())
            .build()
            .unwrap();
        assert_eq!(
            cfg.remote_cache_read_url(),
            Some("https://cache.example.com/")
        );
    }
}
