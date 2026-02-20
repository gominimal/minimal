use crate::{Error, Sandbox};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::hash::Hash;
use std::path::{Path, PathBuf};

/// Something in the FS that needs to be mapped into the sandbox.
#[derive(Debug)]
pub enum SandboxMapped {
    File(PathBuf),
    Dir(PathBuf),
    TempDir(tempfile::TempDir),
}

impl PartialEq for SandboxMapped {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::File(f1), Self::File(f2)) => f1.eq(f2),
            (Self::Dir(d1), Self::Dir(d2)) => d1.eq(d2),
            (Self::TempDir(d1), Self::TempDir(d2)) => d1.path().eq(d2.path()),
            _ => false,
        }
    }
}
impl Eq for SandboxMapped {}

impl Hash for SandboxMapped {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        match self {
            Self::File(p) => {
                "f".hash(state);
                p.hash(state);
            }
            Self::Dir(p) => {
                "d".hash(state);
                p.hash(state);
            }
            Self::TempDir(p) => {
                "t".hash(state);
                p.path().hash(state);
            }
        }
    }
}

/// The different ways the working directory in the sandbox is to be setup.
#[derive(Debug)]
pub enum WdSetup {
    /// An empty directory `/build` is created, which is setup according to `working_inputs`.
    Isolated {
        /// The set of files that should be mapped into the working directory of the sandbox.
        working_inputs: Vec<SandboxMapped>,
    },
    /// The host filesystem up to the given path is recreated with empty directories, and
    /// the given path is bind-mounted into the sandbox.
    BoundDir {
        path: PathBuf,
        read_only: bool,
        fs_mappings: Vec<common::FsMapping>,
    },
}

/// Describes the setup of a sandbox.
#[derive(Debug)]
pub struct Config {
    /// A human-readable name for this sandbox, such as the package being built.
    pub name: String,
    /// Whether to delete the sandbox files when dropped.
    pub keep_dirs: bool,

    /// The state directory, if any. An empty one will be created otherwise.
    pub state_dir: Option<PathBuf>,
    /// How the working directory is configured.
    ///
    /// The two main options are:
    ///  * Isolated: cwd is an empty `/build` directory.
    ///  * BoundDir: cwd is a path on the host system. Directories between `/` and the
    ///    given path are created but empty, and the given path is bind-mounted
    ///    into the sandbox.
    pub wd: WdSetup,
    /// The set of files that should be mapped into the root filesystem of the sandbox.
    pub rootfs: HashSet<SandboxMapped>,

    pub disable_networking: bool,
    /// The hostname to set in the environment, if any.
    pub hostname: Option<String>,

    /// Globally/initially-set environment variables.
    pub env_vars: HashMap<String, String>,
}

/// A command to be run in the sandbox.
#[derive(Debug, Clone)]
pub struct Invocation {
    /// The program to exec.
    ///
    /// If executable is not an absolute path, it will be
    /// mutated to `/usr/bin/{executable}` if:
    ///  * `{executable}` is not a file in the cwd
    ///  * `/usr/bin/{executable}` exists
    pub executable: String,
    /// Argv given to the invoked program.
    pub args: Vec<String>,
    /// Environment variables set on this invocation only. This
    /// takes precedence over any env vars set on [Config].
    pub envs: HashMap<String, String>,
}

impl Config {
    /// Initializes an empty config with the given name.
    pub fn new<S: Into<String>>(name: S) -> Self {
        Self {
            name: name.into(),
            disable_networking: false,
            env_vars: HashMap::with_capacity(12),
            hostname: None,
            keep_dirs: false,
            rootfs: HashSet::with_capacity(64),
            state_dir: None,
            wd: WdSetup::Isolated {
                working_inputs: Vec::with_capacity(6),
            },
        }
    }

    /// Configures the sandbox to use the given directory for `/state`.
    pub fn with_state_dir<P: Into<PathBuf>>(mut self, state_dir: P) -> Self {
        self.state_dir = Some(state_dir.into());
        self
    }
    /// Configures the sandbox to map the given directory as the working directory.
    pub fn with_wd<P: Into<PathBuf>>(
        mut self,
        wd: P,
        read_only: bool,
        fs_mappings: Vec<common::FsMapping>,
    ) -> Self {
        self.wd = WdSetup::BoundDir {
            path: wd.into(),
            read_only,
            fs_mappings,
        };
        self
    }
    /// Configures the sandbox to isolate itself from the host, configuring only
    /// the given files as contents of the isolated working directory.
    pub fn with_isolated_wd<I: Iterator<Item = SandboxMapped>>(mut self, inputs: I) -> Self {
        match &mut self.wd {
            WdSetup::BoundDir { .. } => {
                self.wd = WdSetup::Isolated {
                    working_inputs: inputs.into_iter().collect(),
                };
            }
            WdSetup::Isolated { working_inputs } => working_inputs.extend(inputs),
        };
        self
    }

    /// Configures the hostname to use in the sandbox.
    pub fn with_hostname<S: Into<String>>(mut self, hostname: S) -> Self {
        self.hostname = Some(hostname.into());
        self
    }
    /// Adds to the set of environment variables all invocations will see.
    pub fn with_env_vars<I: Iterator<Item = (String, String)>>(
        mut self,
        extra_env_vars: I,
    ) -> Self {
        self.env_vars.extend(extra_env_vars);
        self
    }
    /// Sets the given environment variable, all invocations will see it unless overridden.
    pub fn with_env_var<S1: Into<String>, S2: Into<String>>(mut self, key: S1, val: S2) -> Self {
        self.env_vars.insert(key.into(), val.into());
        self
    }

    /// Adds the set of [SandboxMapped] objects to the root fs.
    pub fn with_rootfs<I: Iterator<Item = SandboxMapped>>(mut self, rootfs: I) -> Self {
        self.rootfs.extend(rootfs);
        self
    }
    /// Adds the given [SandboxMapped] object to the root fs.
    pub fn with_add_rootfs(mut self, file: SandboxMapped) -> Self {
        self.rootfs.insert(file);
        self
    }
    /// Sets whether networking is required.
    pub fn with_disable_networking(mut self, disable_networking: bool) -> Self {
        self.disable_networking = disable_networking;
        self
    }

    /// Extends the list of environment variables with the set generated from given build args.
    pub fn with_build_args<K: AsRef<str>, V: Into<String>, I: Iterator<Item = (K, V)>>(
        mut self,
        build_args: I,
    ) -> Self {
        self.env_vars.extend(build_args.map(|(k, v)| {
            (
                "MINIMAL_ARG_".to_owned()
                    + &k.as_ref()
                        .trim()
                        .replace("=", "")
                        .replace(":", "")
                        .replace("/", "")
                        .replace("\"", "")
                        .replace("'", "")
                        .to_uppercase(),
                v.into(),
            )
        }));
        self
    }

    /// Builds the sandbox using the given configuration, with temporary files and the rootfs
    /// contained within the given directory.
    pub async fn build<P: AsRef<Path>>(self, base_dir: P) -> Result<Sandbox, Error> {
        // Make sure the parent directory exists
        fs::create_dir_all(base_dir.as_ref()).map_err(|e| {
            Error::IO(
                "create sandbox base directory",
                base_dir.as_ref().to_path_buf(),
                e,
            )
        })?;

        // Create a unique directory name using sandbox name, timestamp, and process ID.
        // At this layer its plausible that there might be two packages of the same name
        // built at the same time, so we do an atomic directory creation dance /w an attempt
        // counter to make sure each sandbox gets its own folder.
        use std::time::{SystemTime, UNIX_EPOCH};
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| {
                Error::IO(
                    "get timestamp",
                    Default::default(),
                    std::io::Error::other(e),
                )
            })?
            .as_secs();
        let pid = std::process::id();
        let build_base_dir = {
            let mut attempt = 0u32;
            loop {
                let dir_name = if attempt == 0 {
                    format!("{}-{}-{}", self.name, timestamp, pid)
                } else {
                    format!("{}-{}-{}-{}", self.name, timestamp, pid, attempt)
                };

                let candidate_dir = base_dir.as_ref().join(dir_name);
                match fs::create_dir(&candidate_dir) {
                    Ok(()) => break candidate_dir,
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                        attempt += 1;
                        if attempt > 20 {
                            return Err(Error::IO(
                                "create sandbox directory",
                                candidate_dir,
                                std::io::Error::new(
                                    std::io::ErrorKind::AlreadyExists,
                                    "too many directory creation attempts",
                                ),
                            ));
                        }
                        continue;
                    }
                    Err(e) => {
                        return Err(Error::IO("create sandbox directory", candidate_dir, e));
                    }
                }
            }
        };

        // Validate FS mappings, creating any non-existent files as we go.
        if let WdSetup::BoundDir { fs_mappings, .. } = &self.wd {
            for m in fs_mappings {
                match fs::metadata(&m.host_path) {
                    Ok(stat) => {
                        if stat.is_dir() && m.is_file {
                            return Err(Error::IO(
                                "stat fs mapping",
                                m.host_path.clone().into(),
                                std::io::Error::new(
                                    std::io::ErrorKind::AlreadyExists,
                                    "directory mapped as a file",
                                ),
                            ));
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                        if !m.create_if_missing {
                            return Err(Error::IO("fs mapping", m.host_path.clone().into(), e));
                        }

                        // Missing and needs to be created.
                        if m.is_file {
                            fs::write(
                                &m.host_path,
                                if m.host_path.ends_with(".json") {
                                    "{}"
                                } else {
                                    ""
                                },
                            )
                            .map_err(|e| {
                                Error::IO("create mapped file", m.host_path.clone().into(), e)
                            })?;
                        } else {
                            fs::create_dir_all(&m.host_path).map_err(|e| {
                                Error::IO("create mapped dir", m.host_path.clone().into(), e)
                            })?;
                        }
                    }
                    Err(e) => {
                        return Err(Error::IO("stat fs mapping", m.host_path.clone().into(), e));
                    }
                };
            }
        }

        Sandbox::new(build_base_dir, self)
    }
}
