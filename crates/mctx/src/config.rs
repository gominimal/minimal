use std::{
    fmt,
    path::{Path, PathBuf},
};

use checkouts::ManagerHandle;
use common::fetchers::{AnyUrl, GcsUrl, ReqwestUrl};
use ot::OpTracker;

/// The errors possible in configuration or building a configuration.
#[derive(Debug)]
pub enum ConfigError {
    IO(&'static str, PathBuf, std::io::Error),
    /// Configured remote cache location (`remote_cache_url`) is empty or unparseable.
    /// Carries the offending value for diagnostics.
    InvalidRemoteCacheUrl(String),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::IO(ctx, path, e) => {
                write!(f, "{} I/O error at path {}: {}", ctx, path.display(), e)
            }
            ConfigError::InvalidRemoteCacheUrl(url) => {
                write!(f, "invalid remote_cache_url: {:?}", url)
            }
        }
    }
}

impl std::error::Error for ConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ConfigError::IO(_, _, e) => Some(e),
            ConfigError::InvalidRemoteCacheUrl(_) => None,
        }
    }
}

/// Default remote cache location when none is configured — the shared GCS
/// bucket. A bare name (no scheme) is treated as a GCS bucket.
pub const DEFAULT_REMOTE_CACHE_BUCKET: &str = "minimal-staging-cache";

/// Default *read* location: the R2 mirror on the product domain. Cache
/// reads are immutable, content-addressed, and sha256-verified
/// client-side, and R2 charges no egress — where the same reads from
/// the GCS bucket are billed internet egress for every consumer
/// outside GCP. Writers never use this (writes require the `gs://`
/// bucket above). An explicitly configured location or the
/// `MINIMAL_REMOTE_CACHE_URL` env var both take precedence: in-cloud
/// readers (res-servers) pin `gs://` explicitly for free same-region
/// reads, and pointing the env var at `gs://minimal-staging-cache` is
/// the escape hatch back to direct GCS.
pub const DEFAULT_REMOTE_CACHE_READ_URL: &str = "https://cache.minimal.dev/";

/// Parses a remote-cache location string into (a) the resolved [`AnyUrl`] a
/// reader fetches from and (b) the GCS bucket name a *writer* would use
/// (`None` for an HTTPS mirror — you can't write to a read mirror). Accepted:
/// `https://…` / `http://…` → an HTTPS mirror; `gs://bucket[/…]` or a bare
/// `bucket` name → the GCS bucket. Pure, so it's unit-testable.
fn parse_remote_cache_url(raw: &str) -> Result<(AnyUrl, Option<String>), ConfigError> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err(ConfigError::InvalidRemoteCacheUrl(raw.to_string()));
    }
    if raw.starts_with("https://") || raw.starts_with("http://") {
        let url = ReqwestUrl::try_from(raw)
            .map_err(|_| ConfigError::InvalidRemoteCacheUrl(raw.to_string()))?;
        return Ok((AnyUrl::Https(url), None));
    }
    // gs://bucket[/path] or a bare bucket name -> GCS.
    let bucket = raw.strip_prefix("gs://").unwrap_or(raw);
    let bucket = bucket.split('/').next().unwrap_or("");
    if bucket.is_empty() {
        return Err(ConfigError::InvalidRemoteCacheUrl(raw.to_string()));
    }
    let any = AnyUrl::Gcs(GcsUrl {
        bucket: format!("projects/_/buckets/{bucket}"),
        object: String::new(),
    });
    Ok((any, Some(bucket.to_string())))
}

/// Builder for [Config].
#[derive(Debug, Default, Clone)]
pub struct ConfigBuilder {
    no_cache: Option<bool>,
    no_fetch: Option<bool>,
    offline: Option<bool>,
    num_parallel_builds: Option<usize>,
    daemon_id: Option<String>,

    minimal_state_dir: Option<PathBuf>,
    minimal_cache_dir: Option<PathBuf>,
    stdlib_dir: Option<PathBuf>,
    repo_dir: Option<PathBuf>,

    vcs_manager: Option<ManagerHandle>,
    ot: Option<OpTracker>,
    remote_cache_url: Option<String>,
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
    /// Use the specified ID to identify this process in temp files.
    pub fn with_daemon_id(mut self, id: String) -> Self {
        self.daemon_id = Some(id);
        self
    }
    /// Override where the remote cache lives. One value serves both reader and
    /// writer: a `gs://bucket` (or bare bucket name) uses the GCS client;
    /// an `https://…` value reads over plain unauthenticated HTTPS (e.g. a
    /// Cloudflare R2 custom domain, to avoid GCS egress cost) — an HTTPS value
    /// is read-only (writes require a `gs://` bucket). Defaults to
    /// [DEFAULT_REMOTE_CACHE_BUCKET]. For read-only consumers, the
    /// `MINIMAL_REMOTE_CACHE_URL` env var overrides the *reader* only (the
    /// writer still uses this value). An HTTPS value MUST end in `/`.
    pub fn with_remote_cache_url(mut self, url: String) -> Self {
        self.remote_cache_url = Some(url);
        self
    }
}

impl ConfigBuilder {
    /// Constructs a config object using the given builder.
    pub fn build(self) -> Result<Config, ConfigError> {
        // The one configured cache location (default: the shared GCS bucket).
        // The raw `Option` is retained on `Config` so `into_builder` can
        // round-trip "unconfigured" faithfully as `None`.
        let configured_cache_url = self.remote_cache_url;
        let explicitly_configured = configured_cache_url.is_some();
        let remote_cache_url = configured_cache_url
            .clone()
            .unwrap_or_else(|| DEFAULT_REMOTE_CACHE_BUCKET.to_string());
        // The writer always uses the configured location's GCS bucket (`None`
        // when it's an HTTPS mirror -> writes error, since you can't write to a
        // read mirror). This also validates the configured value.
        let (_, remote_cache_write_bucket) = parse_remote_cache_url(&remote_cache_url)?;
        // Read-side resolution, in precedence order: the
        // `MINIMAL_REMOTE_CACHE_URL` env override, then an explicitly
        // configured location, then the R2 mirror default. Only callers
        // that configured nothing get the mirror — an explicit
        // `with_remote_cache_url` (e.g. res-servers pinning `gs://` for
        // free same-region reads) is honoured for reads AND writes.
        let env_override = std::env::var("MINIMAL_REMOTE_CACHE_URL")
            .ok()
            .filter(|s| !s.trim().is_empty());
        let (read_raw, read_source) = match (env_override, explicitly_configured) {
            (Some(url), _) => (url, "env-override"),
            (None, true) => (remote_cache_url.clone(), "configured"),
            (None, false) => (
                DEFAULT_REMOTE_CACHE_READ_URL.to_string(),
                "default-r2-mirror",
            ),
        };
        // One line of visibility: which source reads use. Selection was
        // previously silent, which made "is this client actually on the
        // mirror?" unanswerable from logs (it took GCS access-log
        // forensics to attribute egress).
        tracing::info!(url = %read_raw, source = read_source, "remote cache read location");
        let (remote_cache_read, _) = parse_remote_cache_url(&read_raw)?;

        Ok(Config {
            no_cache: self.no_cache.unwrap_or(false),
            no_fetch: self.no_fetch.unwrap_or(false),
            offline: self.offline.unwrap_or(false),
            num_parallel_builds: self
                .num_parallel_builds
                .unwrap_or_else(common::default_parallelism),
            daemon_id: self.daemon_id,

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
            remote_cache_url: configured_cache_url,
            remote_cache_read,
            remote_cache_write_bucket,
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
            daemon_id: self.daemon_id,
            num_parallel_builds: Some(self.num_parallel_builds),
            minimal_state_dir: Some(self.minimal_state_dir),
            minimal_cache_dir: Some(self.minimal_cache_dir),
            stdlib_dir: self.stdlib_dir,
            repo_dir: self.repo_dir,
            vcs_manager: self.vcs_manager,
            ot: self.ot,
            remote_cache_url: self.remote_cache_url,
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
    /// The identifer for this process. Downstream machinery defaults to the PID if not set.
    daemon_id: Option<String>,

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
    /// The one configured cache location (raw), retained for round-tripping via
    /// [Self::into_builder]. `None` when nothing was configured, so the rebuild
    /// re-applies the read default instead of pinning the materialized bucket.
    /// See [ConfigBuilder::with_remote_cache_url].
    remote_cache_url: Option<String>,
    /// The resolved location the *reader* fetches from (GCS bucket or HTTPS
    /// mirror), honouring the `MINIMAL_REMOTE_CACHE_URL` env override.
    remote_cache_read: AnyUrl,
    /// The GCS bucket a *writer* uses; `None` when the configured location is an
    /// HTTPS mirror (writes then error — you can't write to a read mirror).
    remote_cache_write_bucket: Option<String>,
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
    /// The resolved location the remote-cache *reader* fetches artifacts from —
    /// a GCS bucket or an HTTPS mirror — ready to hand to the cache backend.
    /// Honours the `MINIMAL_REMOTE_CACHE_URL` env override.
    pub fn remote_cache_url(&self) -> AnyUrl {
        self.remote_cache_read.clone()
    }
    /// The GCS bucket the remote-cache *writer* uploads to; `None` when the
    /// configured location is an HTTPS read mirror (writes then error).
    pub fn remote_cache_write_bucket(&self) -> Option<&str> {
        self.remote_cache_write_bucket.as_deref()
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

    pub(crate) fn daemon_id(&self) -> Option<String> {
        self.daemon_id.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_bare_bucket_is_gcs() {
        let (url, wb) = parse_remote_cache_url("my-bucket").unwrap();
        assert!(matches!(url, AnyUrl::Gcs(ref g) if g.bucket == "projects/_/buckets/my-bucket"));
        assert_eq!(wb.as_deref(), Some("my-bucket"));
    }

    #[test]
    fn parse_gs_scheme_is_gcs() {
        let (url, wb) = parse_remote_cache_url("gs://b/ignored/path").unwrap();
        assert!(matches!(url, AnyUrl::Gcs(ref g) if g.bucket == "projects/_/buckets/b"));
        assert_eq!(wb.as_deref(), Some("b"));
    }

    #[test]
    fn parse_https_is_mirror_with_no_write_bucket() {
        let (url, wb) = parse_remote_cache_url("https://cache.example.com/").unwrap();
        assert!(matches!(url, AnyUrl::Https(_)));
        assert_eq!(wb, None);
    }

    #[test]
    fn parse_rejects_empty_and_bad_url() {
        for bad in ["", "   ", "https://"] {
            assert!(
                matches!(
                    parse_remote_cache_url(bad).unwrap_err(),
                    ConfigError::InvalidRemoteCacheUrl(_)
                ),
                "expected error for {bad:?}"
            );
        }
    }

    #[test]
    fn default_config_writer_uses_default_bucket() {
        // write bucket is derived from the configured value (not the env
        // override), so this is free of MINIMAL_REMOTE_CACHE_URL flakiness.
        let cfg = ConfigBuilder::new().build().unwrap();
        assert_eq!(
            cfg.remote_cache_write_bucket(),
            Some(DEFAULT_REMOTE_CACHE_BUCKET)
        );
    }

    #[test]
    fn default_reader_is_the_r2_mirror_writer_stays_gcs() {
        // The R2-default flip: an unconfigured builder reads from the
        // mirror but still derives its write bucket from the GCS
        // default — the read default must never leak into the writer.
        let cfg = ConfigBuilder::new().build().unwrap();
        assert_eq!(
            cfg.remote_cache_write_bucket(),
            Some(DEFAULT_REMOTE_CACHE_BUCKET)
        );
        // Same env guard as the sibling tests.
        if std::env::var("MINIMAL_REMOTE_CACHE_URL")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .is_none()
        {
            assert!(
                matches!(cfg.remote_cache_url(), AnyUrl::Https(_)),
                "unconfigured reader should default to the R2 mirror"
            );
        }
    }

    #[test]
    fn round_trip_through_into_builder_preserves_read_default() {
        // An unconfigured config reads from the R2 mirror; round-tripping it
        // through into_builder().build() must not flip reads back to GCS.
        if std::env::var("MINIMAL_REMOTE_CACHE_URL")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .is_some()
        {
            return;
        }
        let fresh = ConfigBuilder::new().build().unwrap();
        assert!(matches!(fresh.remote_cache_url(), AnyUrl::Https(_)));
        let round_tripped = fresh.into_builder().build().unwrap();
        assert!(
            matches!(round_tripped.remote_cache_url(), AnyUrl::Https(_)),
            "round-tripped config should still read from the R2 mirror"
        );
    }

    #[test]
    fn builder_gs_value_sets_reader_and_writer() {
        let cfg = ConfigBuilder::new()
            .with_remote_cache_url("gs://my-bucket".into())
            .build()
            .unwrap();
        assert_eq!(cfg.remote_cache_write_bucket(), Some("my-bucket"));
        // Guard the reader assertion: a non-empty MINIMAL_REMOTE_CACHE_URL in
        // the test process would override the reader.
        if std::env::var("MINIMAL_REMOTE_CACHE_URL")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .is_none()
        {
            assert!(matches!(
                cfg.remote_cache_url(),
                AnyUrl::Gcs(g) if g.bucket == "projects/_/buckets/my-bucket"
            ));
        }
    }

    #[test]
    fn builder_https_value_is_read_only() {
        let cfg = ConfigBuilder::new()
            .with_remote_cache_url("https://cache.example.com/".into())
            .build()
            .unwrap();
        // HTTPS location -> the writer has no bucket (writes will error).
        assert_eq!(cfg.remote_cache_write_bucket(), None);
    }

    #[test]
    fn builder_rejects_empty() {
        let err = ConfigBuilder::new()
            .with_remote_cache_url(String::new())
            .build()
            .unwrap_err();
        assert!(matches!(err, ConfigError::InvalidRemoteCacheUrl(_)));
    }
}
