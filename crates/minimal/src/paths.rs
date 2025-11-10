use std::path::{Path, PathBuf};

/// Centralized configuration for all paths used by the minimal package manager.
/// This provides a single source of truth for directory organization.
#[derive(Debug, Clone)]
pub struct PathConfig {
    /// Root directory for all minimal-related data
    /// Default: ~/.cache/minimal/
    root_dir: PathBuf,

    /// Directory for input-addressed build cache
    /// Default: ~/.cache/minimal/builds/
    cache_dir: PathBuf,
    /// Directory for downloaded sources and prebuilts
    /// Default: ~/.cache/minimal/downloads/
    download_cache_dir: PathBuf,
    /// Base directory for build sandboxes
    /// Default: ~/.cache/minimal/sandboxes/
    sandbox_base_dir: PathBuf,
    /// Base directory for runtime sandboxes
    /// Default: ~/.cache/minimal/runs
    run_base_dir: PathBuf,
    /// Base directory for durable environment state
    /// Default: ~/.cache/minimal/envs
    env_base_dir: PathBuf,
    /// Directory containing VCS checkouts
    /// Default: ~/.cache/minimal/vcs/
    vcs_dir: PathBuf,

    /// Directory containing minimal standard library
    stdlib_dir: Option<PathBuf>,
}

impl Default for PathConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl PathConfig {
    /// Creates a default PathConfig.
    pub fn new() -> Self {
        let root_dir = Self::default_root_dir();
        Self::new_with_base(root_dir)
    }

    /// Create a new PathConfig rooted at a given directory.
    pub fn new_with_base(root_dir: PathBuf) -> Self {
        let stdlib_dir = None;
        Self {
            cache_dir: root_dir.join("builds"),
            download_cache_dir: root_dir.join("downloads"),
            sandbox_base_dir: root_dir.join("sandboxes"),
            env_base_dir: root_dir.join("envs"),
            run_base_dir: root_dir.join("runs"),
            vcs_dir: root_dir.join("vcs"),
            root_dir,
            stdlib_dir,
        }
    }

    /// Create a PathConfig with custom cache directory
    pub fn with_cache_dir(mut self, cache_dir: PathBuf) -> Self {
        self.cache_dir = cache_dir;
        self
    }

    /// Create a PathConfig with custom download cache directory
    pub fn with_download_cache_dir(mut self, download_cache_dir: PathBuf) -> Self {
        self.download_cache_dir = download_cache_dir;
        self
    }

    /// Create a PathConfig with custom sandbox base directory
    pub fn with_sandbox_base_dir(mut self, sandbox_base_dir: PathBuf) -> Self {
        self.sandbox_base_dir = sandbox_base_dir;
        self
    }

    /// Create a PathConfig with custom environment-state base directory
    pub fn with_envs_base_dir(mut self, env_base_dir: PathBuf) -> Self {
        self.env_base_dir = env_base_dir;
        self
    }

    /// Create a PathConfig with custom run sandbox base directory
    pub fn with_run_base_dir(mut self, run_base_dir: PathBuf) -> Self {
        self.run_base_dir = run_base_dir;
        self
    }

    /// Create a PathConfig with custom vcs base directory
    pub fn with_vcs_dir(mut self, vcs_dir: PathBuf) -> Self {
        self.vcs_dir = vcs_dir;
        self
    }

    /// Create a PathConfig with the given stdlib directory
    pub fn with_stdlib_dir(mut self, stdlib_dir: PathBuf) -> Self {
        self.stdlib_dir = Some(stdlib_dir);
        self
    }

    /// Get the default root directory following XDG Base Directory specification
    fn default_root_dir() -> PathBuf {
        dirs::cache_dir()
            .unwrap_or_else(|| PathBuf::from("~/.cache"))
            .join("minimal")
    }

    /// Get the root directory
    pub fn root_dir(&self) -> &Path {
        &self.root_dir
    }

    /// Get the cache directory for builds
    pub fn cache_dir(&self) -> &Path {
        &self.cache_dir
    }

    /// Get the download cache directory
    pub fn download_cache_dir(&self) -> &Path {
        &self.download_cache_dir
    }

    /// Get the sandbox base directory
    pub fn sandbox_base_dir(&self) -> &Path {
        &self.sandbox_base_dir
    }

    /// Get the environment-state base directory
    pub fn env_base_dir(&self) -> &Path {
        &self.env_base_dir
    }

    /// Get the runtime sandbox base directory
    pub fn run_base_dir(&self) -> &Path {
        &self.run_base_dir
    }

    /// Get the vcs directory
    pub fn vcs_dir(&self) -> &Path {
        &self.vcs_dir
    }

    /// Get the stdlib directory
    pub fn stdlib_dir(&self) -> Option<&Path> {
        self.stdlib_dir.as_deref()
    }

    /// Create all necessary directories
    pub fn ensure_directories(&self) -> std::io::Result<()> {
        std::fs::create_dir_all(&self.cache_dir)?;
        std::fs::create_dir_all(&self.download_cache_dir)?;
        std::fs::create_dir_all(&self.sandbox_base_dir)?;
        std::fs::create_dir_all(&self.env_base_dir)?;
        std::fs::create_dir_all(&self.run_base_dir)?;
        std::fs::create_dir_all(&self.vcs_dir)?;
        // Note: packages_dir is expected to exist already
        Ok(())
    }

    /// Display all configured paths for debugging
    pub fn display_paths(&self) {
        println!("Minimal Path Configuration:");
        println!("  Root directory:          {}", self.root_dir.display());
        println!("  Build cache:             {}", self.cache_dir.display());
        println!(
            "  Download cache:          {}",
            self.download_cache_dir.display()
        );
        println!(
            "  Sandbox base:            {}",
            self.sandbox_base_dir.display()
        );
        println!(
            "  Minimal stdlib directory:      {}",
            self.stdlib_dir
                .as_ref()
                .map(|d| d.display().to_string())
                .unwrap_or("<unset>".to_string())
        );
    }
}
