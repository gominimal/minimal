use crate::network::Network;
use crate::{Error, Sandbox};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::hash::Hash;
use std::path::{Path, PathBuf};

pub use sessions::NetworkMode;

/// Something in the FS that needs to be mapped into the sandbox.
#[derive(Debug)]
pub enum SandboxMapped {
    File(PathBuf),
    Dir(PathBuf),
    TempDir(tempfile::TempDir),
    /// Special case of [`SandboxMapped::File`] where the path is
    /// copied-in + permissions applied, rather than hardlinked.
    FileCopy(PathBuf),
}

impl PartialEq for SandboxMapped {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::File(f1), Self::File(f2)) => f1.eq(f2),
            (Self::Dir(d1), Self::Dir(d2)) => d1.eq(d2),
            (Self::TempDir(d1), Self::TempDir(d2)) => d1.path().eq(d2.path()),
            (Self::FileCopy(f1), Self::FileCopy(f2)) => f1.eq(f2),
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
            Self::FileCopy(p) => {
                "fc".hash(state);
                p.hash(state);
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
    /// The layout used for a minimal session.
    ///
    /// The homedir is at /home, and the working directory is at /workbench (unless overridden).
    Session {
        home: PathBuf,
        working: PathBuf,
        working_name_override: Option<String>,
    },
}

impl WdSetup {
    /// Returns the path within the sandbox of the cwd. The returned path
    /// is always relative.
    ///
    /// SAFETY:
    ///  * This function will panic if the variant is not `BoundDir`.
    pub(crate) fn bound_dir_sandbox_cwd(&self) -> &Path {
        let p = match self {
            Self::BoundDir { path, .. } => match std::env::var("MINIMAL_INTERNAL_PATCH_STRIP") {
                Err(_) => path,
                Ok(prefix) => match path.strip_prefix(&prefix) {
                    Err(_) => path,
                    Ok(stripped) => stripped,
                },
            },
            _ => panic!("sandbox_cwd called for non bound-dir variant {:?}", self),
        };
        if p.is_absolute() {
            return p.strip_prefix("/").unwrap();
        }
        p
    }
}

/// Parameters for an own-IP user-mode (RustSlirp) tap.
///
/// When set on an own-IP sandbox, hakoniwa creates and configures a TAP device
/// *inside* the sandbox's user+network namespace (rootless — no host
/// `CAP_NET_ADMIN`), assigning the address/netmask and a default route via the
/// gateway, and surfaces the tap fd as [`hakoniwa::Child::rustslirp_tapfd`] for
/// the caller to relay to the gvproxy switch. Replaces the privileged
/// open-tap-then-move-into-netns path on the native (DM2) deployment.
#[derive(Debug, Clone, Copy)]
pub struct OwnIpTap {
    /// The PTask's switch address, assigned to the tap in-namespace.
    pub address: std::net::Ipv4Addr,
    /// The switch subnet netmask (e.g. `255.255.0.0` for a `/16`).
    pub netmask: std::net::Ipv4Addr,
    /// The switch gateway, installed as the next-hop default route
    /// (`0.0.0.0/0 via gateway`) — gvproxy answers DNS and routes egress there.
    pub gateway: std::net::Ipv4Addr,
    /// The tap MTU; must match the relay's frame buffer (`DEFAULT_MTU`).
    pub mtu: u16,
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

    /// Synthesize DNS config.
    pub setup_dns_config: bool,
    /// The network isolation mode for this sandbox.
    ///
    /// Used only when [`network`](Self::network) is `None` (the built-in
    /// `HostNet`/`NoNet` path). A custom [`Network`] takes precedence.
    pub network_mode: NetworkMode,
    /// A custom per-sandbox [`Network`], if injected via
    /// [`with_network`](Self::with_network). When set it overrides
    /// [`network_mode`](Self::network_mode), and decides both netns isolation and
    /// any post-spawn wiring (e.g. an own-IP gvproxy switch attach). Keeping the
    /// wiring behind this trait is what lets tasks and sessions share one
    /// networking path instead of it living only in the minimald session host.
    pub network: Option<Box<dyn Network>>,
    /// Own-IP user-mode tap parameters. When `Some` (native/DM2 own-IP), the
    /// sandbox's TAP is created + configured inside its namespace by hakoniwa
    /// (rootless), and the tap fd is surfaced via `Child.rustslirp_tapfd`. `None`
    /// keeps the host/VM behaviour (no in-namespace tap).
    pub own_ip_tap: Option<OwnIpTap>,
    /// The DNS server for an own-IP sandbox's `/etc/resolv.conf`, overriding the
    /// synth rootfs's host stub resolver (unreachable in the fresh netns). Set for
    /// **every** own-IP sandbox — both the native (DM2) tap path (which also sets
    /// [`own_ip_tap`](Self::own_ip_tap)) and the in-VM (DM1/3/4) shuttle path
    /// (which does not) — so DNS is not tied to the presence of tap params.
    /// `None` keeps the host-derived resolver.
    pub own_ip_dns: Option<std::net::Ipv4Addr>,

    /// The hostname to set in the environment, if any.
    pub hostname: Option<String>,
    /// The username to set in the environment, if any. Defaults to `build`.
    pub username: Option<String>,

    /// Globally/initially-set environment variables.
    pub env_vars: HashMap<String, String>,

    /// CPU shares, for partitioning CPU when the system is contended. Maps roughly to
    /// cgroups v2 cpu.weights.
    pub cpu_weight: Option<u64>,
}

/// A command to be run in the sandbox.
#[derive(Debug, Clone, PartialEq, Eq)]
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
            setup_dns_config: true,
            network_mode: NetworkMode::HostNet,
            network: None,
            own_ip_tap: None,
            own_ip_dns: None,
            env_vars: HashMap::with_capacity(12),
            hostname: None,
            username: None,
            keep_dirs: false,
            rootfs: HashSet::with_capacity(64),
            state_dir: None,
            wd: WdSetup::Isolated {
                working_inputs: Vec::with_capacity(6),
            },
            cpu_weight: None,
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
            WdSetup::BoundDir { .. } | WdSetup::Session { .. } => {
                self.wd = WdSetup::Isolated {
                    working_inputs: inputs.into_iter().collect(),
                };
            }
            WdSetup::Isolated { working_inputs } => working_inputs.extend(inputs),
        };
        self
    }
    /// Configures the sandbox following the layout for a session.
    pub fn with_session_dirs(mut self, home: PathBuf, working: PathBuf) -> Self {
        self.wd = WdSetup::Session {
            home,
            working,
            working_name_override: None,
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
    /// Sets the network isolation mode for this sandbox (built-in
    /// `HostNet`/`NoNet` path). Ignored if a custom [`Network`] is set via
    /// [`with_network`](Self::with_network).
    pub fn with_network_mode(mut self, mode: NetworkMode) -> Self {
        self.network_mode = mode;
        self
    }
    /// Sets a custom per-sandbox [`Network`], overriding
    /// [`with_network_mode`](Self::with_network_mode). Use this for modes that
    /// need post-spawn wiring (e.g. own-IP gvproxy switch attach), supplied by
    /// the consumer so the wiring lives behind one abstraction for every sandbox.
    pub fn with_network(mut self, network: Box<dyn Network>) -> Self {
        self.network = Some(network);
        self
    }
    /// Sets the own-IP user-mode tap parameters (native/DM2 own-IP). When set,
    /// hakoniwa builds the tap inside the sandbox namespace (rootless) and the
    /// caller relays `Child.rustslirp_tapfd` to the switch. `None` keeps the
    /// host/VM behaviour.
    pub fn with_own_ip_tap(mut self, tap: Option<OwnIpTap>) -> Self {
        self.own_ip_tap = tap;
        self
    }
    /// Sets the own-IP DNS server for `/etc/resolv.conf` (the switch gateway).
    /// Set for every own-IP sandbox, independent of [`own_ip_tap`](Self::own_ip_tap),
    /// so both the DM2 tap path and the DM1/3/4 shuttle path get a working
    /// resolver. `None` keeps the host-derived resolver.
    pub fn with_own_ip_dns(mut self, dns: Option<std::net::Ipv4Addr>) -> Self {
        self.own_ip_dns = dns;
        self
    }
    /// Sets whether DNS should be configured.
    pub fn with_dns(mut self, dns: bool) -> Self {
        self.setup_dns_config = dns;
        self
    }
    /// Configures the username to use in the sandbox.
    pub fn with_username<S: Into<String>>(mut self, username: S) -> Self {
        self.username = Some(username.into());
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

    /// Sets the CPU weight to the given value.
    pub fn with_cpu_weight(mut self, weight: u64) -> Self {
        self.cpu_weight = Some(weight);
        self
    }

    /// Builds the sandbox using the given configuration, with temporary files and the rootfs
    /// contained within the given directory.
    pub async fn build<P: AsRef<Path>, C: super::Channel>(
        self,
        base_dir: P,
        channel: C,
    ) -> Result<Sandbox<C>, Error> {
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
                let dir_name = format!("{}-{}-{}-{}", self.name, timestamp, attempt, pid);

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

        // Make synthetic configuration
        let sd = build_base_dir.join("synth");
        fs::create_dir_all(&sd)
            .map_err(|e| Error::IO("create synth config directory", sd.clone(), e))?;
        if self.setup_dns_config {
            common::synth_dns_config(&sd)
                .map_err(|e| Error::IO("synthesizing DNS configuration", sd.clone(), e))?;
        }
        let home = match &self.wd {
            WdSetup::Isolated { .. } => "/state/home".to_string(),
            WdSetup::BoundDir { .. } => std::env::home_dir()
                .and_then(|p| p.to_str().map(String::from))
                .unwrap_or_else(|| "/state/home".to_string()),
            WdSetup::Session { .. } => "/home".to_string(),
        };
        match &self.username {
            Some(n) => common::synth_user_group_config(&sd, n, &home),
            None => common::synth_user_group_config(&sd, "build", &home),
        }
        .map_err(|e| Error::IO("synthesizing user/group configuration", sd, e))?;

        Sandbox::new(build_base_dir, self, channel)
    }
}
