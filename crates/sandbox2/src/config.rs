use crate::network::{NetPlan, Network};
use crate::{Error, Sandbox};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::hash::Hash;
use std::path::{Path, PathBuf};

/// The uid every box execs as inside its user namespace.
///
/// `Sandbox::new_container` maps exactly this uid (and [`BOX_GID`]) onto the
/// daemon's own uid and gid, so the process a box execs is not root inside its
/// user namespace and the kernel therefore clears its effective and permitted
/// capability sets at exec. The same uid is the one
/// `common::synth_user_group_config` writes the box's `/etc/passwd` entry for,
/// so the name the box reports and the uid it holds agree. `common` cannot
/// depend on this crate, so no type can hold that agreement;
/// `the_synth_passwd_entry_names_the_box_uid_and_gid` does, reading the entries
/// the function writes and failing when they name another uid.
pub const BOX_UID: u32 = 1000;

/// The gid every box execs as inside its user namespace, mapped onto the
/// daemon's own gid the same way [`BOX_UID`] is mapped onto its uid. The
/// synthesized `group` entry is held to it by the same test.
pub const BOX_GID: u32 = 1000;

/// A capability no box may hold: its kernel number (these are ABI, assigned
/// once and never reused) and its name, for the launch log line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ForbiddenCapability {
    /// The capability's name, `CAP_NET_RAW` and friends.
    pub name: &'static str,
    /// The capability's number in the kernel's capability ABI.
    pub number: u32,
}

/// The capabilities no box may hold, in the order the launch log line names
/// them, `CAP_NET_RAW` first: it is the one that would let a box write packets
/// whose source address is not the address its plan — and the relay's
/// source-address check — say it has, which is the reach the escape bound is
/// about. `CAP_NET_ADMIN` is on the same list for the same reason one layer
/// up: it would let a box re-address its own interface, the address that
/// identifies it.
///
/// The launch path drops these from the box's capability *bounding* set, the
/// one capability set an exec does not clear, so a dropped capability cannot
/// come back even if a file capability or a setuid bit would grant it — both
/// of which the box's `no_new_privs` bit makes the kernel ignore anyway.
pub const BOX_FORBIDDEN_CAPABILITIES: &[ForbiddenCapability] = &[
    ForbiddenCapability {
        name: "CAP_NET_RAW",
        number: 13,
    },
    ForbiddenCapability {
        name: "CAP_NET_ADMIN",
        number: 12,
    },
];

/// The forbidden capabilities as the sandbox launch log line names them, e.g.
/// `CAP_NET_RAW, CAP_NET_ADMIN` — the bounding set every box is launched with.
#[must_use]
pub fn forbidden_capability_names() -> String {
    BOX_FORBIDDEN_CAPABILITIES
        .iter()
        .map(|cap| cap.name)
        .collect::<Vec<_>>()
        .join(", ")
}

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

// Ordered on (variant tag, path), mirroring the `PartialEq`/`Hash` key above,
// so `BTreeSet<SandboxMapped>` iterates — and the rootfs therefore assembles —
// in the same order in every process. Assembly is first-writer-wins
// hardlinking, so an unordered collection let a per-process hash seed decide
// which entry provided a path that two entries both contain.
impl PartialOrd for SandboxMapped {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for SandboxMapped {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        fn key(m: &SandboxMapped) -> (u8, &Path) {
            match m {
                SandboxMapped::File(p) => (0, p),
                SandboxMapped::Dir(p) => (1, p),
                SandboxMapped::TempDir(t) => (2, t.path()),
                SandboxMapped::FileCopy(p) => (3, p),
            }
        }
        key(self).cmp(&key(other))
    }
}

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

/// The classifier leaf a box is placed in: the cgroup its egress verdict is
/// decided on (NET-079, design §4.1), and the one no process of the box may
/// leave or let another box join.
///
/// A *path*, not a kernel handle: the daemon creates the leaf before the spawn
/// and moves the box's processes into it right after, and this option is how
/// the rest of the sandbox learns the box has one — the host's own cgroup2
/// mount is kept out of the box's mount namespace ([`Self::dir`]'s tree is the
/// only hierarchy the box could be told apart in) and the launch log names the
/// leaf.
///
/// The path is resolved in the *daemon's* namespaces. Inside the box it names
/// nothing: the leaf is a sibling of the box's cgroup-namespace root, so the
/// kernel hides it from every cgroup view the box can mount.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassifierLeaf {
    /// The leaf's directory in the daemon's classifier tree, e.g.
    /// `<tree>/boxes/<box-id>`.
    dir: PathBuf,
}

impl ClassifierLeaf {
    /// A leaf at `dir`, e.g. `<tree>/boxes/<box-id>`.
    #[must_use]
    pub fn new<P: Into<PathBuf>>(dir: P) -> Self {
        Self { dir: dir.into() }
    }

    /// The leaf's directory in the daemon's classifier tree.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The leaf's `cgroup.procs`: writing a pid here moves that process into
    /// the leaf. A box is placed by writing the pids of its first processes;
    /// an injected process joins by writing its own before it enters the
    /// box's namespaces, where the path no longer resolves.
    #[must_use]
    pub fn procs(&self) -> PathBuf {
        self.dir.join("cgroup.procs")
    }
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
    ///
    /// `BTreeSet`: iteration order is assembly order (entries are hardlinked
    /// first-writer-wins), so it must be deterministic across processes.
    pub rootfs: BTreeSet<SandboxMapped>,

    /// Synthesize the host's resolver into the sandbox, when no provider
    /// decides the network; a provider's plan names its own.
    pub setup_dns_config: bool,
    /// What this sandbox's network looks like when no provider decides it.
    ///
    /// Used only when [`network`](Self::network) is `None`. A caller that has a
    /// network *mode* turns it into a plan; the sandbox layer does not know what
    /// a mode is.
    pub plan: NetPlan,
    /// A custom per-sandbox [`Network`], if injected via
    /// [`with_network`](Self::with_network). When set its plan overrides
    /// [`plan`](Self::plan), and it decides both netns isolation and any
    /// post-spawn wiring (e.g. an own-IP gvproxy switch attach). Keeping the
    /// wiring behind this trait is what lets tasks and sessions share one
    /// networking path instead of it living only in the minimald session host.
    pub network: Option<std::sync::Arc<dyn Network>>,

    /// The hostname to set in the environment, if any.
    pub hostname: Option<String>,
    /// The username to set in the environment, if any. Defaults to `build`.
    pub username: Option<String>,
    /// The home directory to give the sandboxed process — both `$HOME` and
    /// the synthesized passwd entry — under the [`WdSetup::BoundDir`] layout.
    /// The other two layouts own their home outright (`/state/home` for
    /// `Isolated`, `/home` for `Session`) and ignore this.
    ///
    /// `None` falls back to the ambient `$HOME` of the process building the
    /// sandbox, which is the right answer for `mip` on a developer's host and
    /// the wrong one under `minimald`, where the daemon is pid 1 in the guest
    /// with `HOME=/` and has a real session home to offer instead (#1204).
    pub home: Option<PathBuf>,

    /// Globally/initially-set environment variables.
    pub env_vars: HashMap<String, String>,

    /// CPU shares, for partitioning CPU when the system is contended. Maps roughly to
    /// cgroups v2 cpu.weights.
    pub cpu_weight: Option<u64>,

    /// Suffix marker to identify the process in the names of temp files/directories. Defaults
    /// to the PID when not set.
    pub daemon_id: Option<String>,

    /// The classifier leaf this box is placed in, when the host has one for
    /// it. See [`ClassifierLeaf`]: set by the daemon (which creates the leaf
    /// and moves the box's processes into it), `None` on a host that cannot
    /// decide per box — where the box runs unenforced rather than being
    /// refused (NET-079's exception).
    pub classifier_leaf: Option<ClassifierLeaf>,
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
    /// The home directory a command in this sandbox sees, as an absolute path
    /// inside the sandbox. One definition, used for both `$HOME` and the
    /// synthesized passwd entry so the two can never disagree.
    ///
    /// `Isolated` and `Session` own their home outright. `BoundDir` mirrors
    /// host paths one-for-one, so its home is a host path too: the
    /// caller-supplied [`Config::home`] when there is one, else the ambient
    /// `$HOME`. `/state/home` is the last resort for a process with no `$HOME`
    /// at all.
    #[must_use]
    pub fn sandbox_home(&self) -> String {
        match &self.wd {
            WdSetup::Isolated { .. } => "/state/home".to_string(),
            WdSetup::Session { .. } => format!("/{}", crate::SESSION_HOME),
            WdSetup::BoundDir { .. } => self
                .home
                .as_deref()
                .and_then(Path::to_str)
                .map(String::from)
                .or_else(|| std::env::var("HOME").ok())
                .unwrap_or_else(|| "/state/home".to_string()),
        }
    }

    /// The working directory a command in this sandbox starts in, as an
    /// absolute path inside the sandbox — `/workbench` for a session (unless
    /// the name is overridden), `/build` for a task.
    ///
    /// Fails only for a [`WdSetup::BoundDir`] sandbox whose host path is not
    /// valid UTF-8: the sandbox-side cwd is that path with the host prefix
    /// stripped, so it cannot be rendered as a string.
    pub fn command_cwd(&self) -> Result<String, Error> {
        match &self.wd {
            WdSetup::BoundDir { .. } => {
                let cwd = self.wd.bound_dir_sandbox_cwd();
                let cwd = cwd.to_str().ok_or_else(|| {
                    Error::IO(
                        "sandbox cwd is not valid UTF-8",
                        cwd.to_path_buf(),
                        std::io::Error::new(std::io::ErrorKind::InvalidInput, "non-UTF-8 path"),
                    )
                })?;
                Ok(format!("/{cwd}"))
            }
            WdSetup::Isolated { .. } => Ok("/build".to_string()),
            WdSetup::Session {
                working_name_override,
                ..
            } => Ok(format!(
                "/{}",
                working_name_override
                    .clone()
                    .unwrap_or_else(|| crate::SESSION_DEFAULT_WD.to_string())
            )),
        }
    }

    /// The environment a command in this sandbox is launched with, before any
    /// per-invocation additions.
    ///
    /// The layout defaults come first and the configured
    /// [`env_vars`](Self::env_vars) last, so a composition's variables win on a
    /// key collision — `PS1`, `LANG` and the login-shell identity are floors,
    /// not policy.
    #[must_use]
    pub fn command_env(&self) -> BTreeMap<String, String> {
        let mut env = BTreeMap::new();
        let mut set = |k: &str, v: &str| {
            env.insert(k.to_string(), v.to_string());
        };

        // XDG vars
        if let WdSetup::Session { .. } = &self.wd {
            set("XDG_STATE_HOME", "/home/.local/state");
            set("XDG_CONFIG_HOME", "/home/.config");
            set("XDG_DATA_HOME", "/home/.local/share");
            set("PATH", "/usr/bin:/bin:/usr/sbin:/sbin:/home/.local/bin"); // adds /home/.local/bin
            // A styled default shell prompt for interactive sessions. Set as a
            // plain default here (not forced) so a user's composition var can
            // override it: the composed `env_vars` are applied further down and
            // win on key collision.
            set(
                "PS1",
                r"\[\033[01;32m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ ",
            );
            // Login-shell identity, mirroring what sshd/pam would set from
            // `/etc/passwd`. `USER`/`LOGNAME` track the configured username;
            // `SHELL` points at the session shell (the `bash` package installs
            // to `/usr/bin/bash`). All plain defaults, so composition vars win.
            if let Some(user) = &self.username {
                set("USER", user);
                set("LOGNAME", user);
            }
            set("SHELL", "/usr/bin/bash");
        } else {
            // Both build and BoundWd layouts
            set("XDG_STATE_HOME", "/state/state");
            set("XDG_CONFIG_HOME", "/state/home");
            set("XDG_DATA_HOME", "/state/data");
            set("PATH", "/usr/bin:/bin:/usr/sbin:/sbin");
        }
        set("XDG_CACHE_HOME", "/state/cache");
        set("XDG_RUNTIME_DIR", "/run");

        set("HOME", &self.sandbox_home());

        if let WdSetup::Isolated { .. } = self.wd {
            set("OUTPUT_DIR", "/build/output");
            set("GIT_TERMINAL_PROMPT", "0");
            set("SOURCE_DATE_EPOCH", "0");
            set("PYTHONHASHSEED", "0");
        }

        // Locale. Sessions get a safe, always-present `C.UTF-8` floor: it's
        // built into glibc so it never triggers "cannot set locale" warnings
        // the way `en_US.utf8` does when that locale isn't generated in the
        // rootfs, and setting only `LANG` (the lowest-precedence locale knob,
        // no `LC_ALL`) lets a session's composed `env_vars` or a client's
        // forwarded `LANG`/`LC_*` override it. Build/task sandboxes keep the
        // fixed `en_US.utf8` + `LC_ALL` they always had, for output stability.
        if let WdSetup::Session { .. } = &self.wd {
            set("LANG", "C.UTF-8");
        } else {
            set("LANG", "en_US.utf8");
            set("LC_ALL", "en_US.utf8");
        }
        set("IS_SANDBOX", "1");
        if let WdSetup::BoundDir { .. } = self.wd {
            //  Quality-of-life wiring for task sandboxes
            for var in ["TERM", "COLORTERM", "LS_COLORS"] {
                if let Ok(value) = std::env::var(var) {
                    set(var, &value);
                }
            }
        }

        self.env_vars.iter().for_each(|(var, val)| set(var, val));
        env
    }

    /// Initializes an empty config with the given name.
    pub fn new<S: Into<String>>(name: S) -> Self {
        Self {
            name: name.into(),
            setup_dns_config: true,
            plan: NetPlan::host(),
            network: None,
            env_vars: HashMap::with_capacity(12),
            hostname: None,
            username: None,
            home: None,
            keep_dirs: false,
            rootfs: BTreeSet::new(),
            state_dir: None,
            wd: WdSetup::Isolated {
                working_inputs: Vec::with_capacity(6),
            },
            cpu_weight: None,
            daemon_id: None,
            classifier_leaf: None,
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
    /// Sets what this sandbox's network looks like when no provider decides it.
    /// Ignored if a custom [`Network`] is set via
    /// [`with_network`](Self::with_network), whose own plan wins.
    #[must_use]
    pub fn with_plan(mut self, plan: NetPlan) -> Self {
        self.plan = plan;
        self
    }
    /// Sets a custom per-sandbox [`Network`], overriding
    /// [`with_plan`](Self::with_plan). Use this for modes that
    /// need post-spawn wiring (e.g. own-IP gvproxy switch attach), supplied by
    /// the consumer so the wiring lives behind one abstraction for every sandbox.
    pub fn with_network(mut self, network: std::sync::Arc<dyn Network>) -> Self {
        self.network = Some(network);
        self
    }
    /// Sets whether the host's resolver is synthesized into the sandbox.
    /// Ignored when a [`Network`] is set: its plan names the resolver.
    pub fn with_dns(mut self, dns: bool) -> Self {
        self.setup_dns_config = dns;
        self
    }
    /// Configures the username to use in the sandbox.
    pub fn with_username<S: Into<String>>(mut self, username: S) -> Self {
        self.username = Some(username.into());
        self
    }
    /// Configures the home directory to give the sandboxed process under the
    /// [`WdSetup::BoundDir`] layout, in place of the ambient `$HOME`. See
    /// [`Config::home`]; `None` restores the ambient fallback.
    pub fn with_home<P: Into<PathBuf>>(mut self, home: Option<P>) -> Self {
        self.home = home.map(Into::into);
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

    /// Sets the identifier for the process/daemon doing the build.
    pub fn with_daemon_id(mut self, id: String) -> Self {
        self.daemon_id = Some(id);
        self
    }

    /// Places this box in `leaf`, its classifier leaf: the cgroup its egress
    /// verdict is decided on (NET-079).
    ///
    /// The daemon creates the leaf before the spawn and sets this so the
    /// sandbox layer can keep the host's cgroup mount out of the box's mount
    /// namespace and name the leaf in the launch log. The placement itself —
    /// writing the box's processes into [`ClassifierLeaf::procs`] — stays with
    /// the daemon, which owns the pids to move and the leaf's lifetime.
    pub fn with_classifier_leaf(mut self, leaf: ClassifierLeaf) -> Self {
        self.classifier_leaf = Some(leaf);
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

        // Create a unique directory name using sandbox name, timestamp, and daemon ID.
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
        let id = self
            .daemon_id
            .clone()
            .unwrap_or_else(|| std::process::id().to_string());
        let build_base_dir = {
            let mut attempt = 0u32;
            loop {
                let dir_name = format!("{}-{}-{}-{}", self.name, timestamp, attempt, id);

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

        // Make synthetic configuration. The resolver is the plan's to say, and
        // is written when the container is built.
        let sd = build_base_dir.join("synth");
        fs::create_dir_all(&sd)
            .map_err(|e| Error::IO("create synth config directory", sd.clone(), e))?;
        let home = self.sandbox_home();
        match &self.username {
            Some(n) => common::synth_user_group_config(&sd, n, &home),
            None => common::synth_user_group_config(&sd, "build", &home),
        }
        .map_err(|e| Error::IO("synthesizing user/group configuration", sd, e))?;

        Sandbox::new(build_base_dir, self, channel)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session_config() -> Config {
        let mut config = Config::new("test");
        config.wd = WdSetup::Session {
            home: PathBuf::from("/tmp/home"),
            working: PathBuf::from("/tmp/working"),
            working_name_override: None,
        };
        config.username = Some("dev".to_string());
        config
    }

    /// The pair a session's shell is launched with is the pair anything
    /// injected into that session later has to be given, so both come from
    /// here. `/workbench` is the contract the session layout promises.
    #[test]
    fn a_session_starts_in_workbench_with_its_login_identity() {
        let config = session_config();

        assert_eq!(config.command_cwd().unwrap(), "/workbench");
        let env = config.command_env();
        assert_eq!(env.get("HOME").map(String::as_str), Some("/home"));
        assert_eq!(env.get("USER").map(String::as_str), Some("dev"));
        assert_eq!(env.get("LANG").map(String::as_str), Some("C.UTF-8"));
    }

    /// Composed variables are policy; the layout defaults are only a floor.
    #[test]
    fn configured_vars_override_the_layout_defaults() {
        let mut config = session_config();
        config
            .env_vars
            .insert("LANG".to_string(), "en_GB.UTF-8".to_string());
        config
            .env_vars
            .insert("EDITOR".to_string(), "hx".to_string());

        let env = config.command_env();

        assert_eq!(env.get("LANG").map(String::as_str), Some("en_GB.UTF-8"));
        assert_eq!(env.get("EDITOR").map(String::as_str), Some("hx"));
    }

    /// A build sandbox keeps the layout it always had — the extraction of this
    /// logic out of `command_inner` must not have moved the task plane.
    #[test]
    fn a_build_sandbox_keeps_its_own_layout() {
        let config = Config::new("test");

        assert_eq!(config.command_cwd().unwrap(), "/build");
        let env = config.command_env();
        assert_eq!(env.get("HOME").map(String::as_str), Some("/state/home"));
        assert_eq!(env.get("SOURCE_DATE_EPOCH").map(String::as_str), Some("0"));
        assert_eq!(env.get("LC_ALL").map(String::as_str), Some("en_US.utf8"));
        assert_eq!(env.get("PS1"), None);
    }

    /// A bound-dir sandbox mirrors host paths, so its home is a host path —
    /// the caller's when one is given. `minimald` gives the session's home
    /// here because its own ambient `$HOME` is `/` in the guest, which is not
    /// a directory anything can be patched into (#1204).
    #[test]
    fn a_bound_dir_sandbox_takes_the_home_it_is_given() {
        let config = Config::new("test")
            .with_wd("/workbench", false, Vec::new())
            .with_home(Some("/var/lib/minimal/sessions/s1/home"));

        assert_eq!(config.sandbox_home(), "/var/lib/minimal/sessions/s1/home");
        assert_eq!(
            config.command_env().get("HOME").map(String::as_str),
            Some("/var/lib/minimal/sessions/s1/home"),
        );
    }

    /// The other two layouts own their home outright, so an override is
    /// ignored rather than silently relocating a session's `/home`.
    #[test]
    fn only_the_bound_dir_layout_takes_a_home_override() {
        let session = session_config().with_home(Some("/elsewhere"));
        assert_eq!(session.sandbox_home(), "/home");

        let build = Config::new("test").with_home(Some("/elsewhere"));
        assert_eq!(build.sandbox_home(), "/state/home");
    }

    /// One file of a synthesized `etc`, read back from disk: what these tests
    /// check is what `common::synth_user_group_config` wrote, not what it was
    /// asked to write.
    fn synth_file(dir: &tempfile::TempDir, file: &str) -> String {
        std::fs::read_to_string(dir.path().join("etc").join(file))
            .unwrap_or_else(|e| panic!("reading the synthesized {file}: {e}"))
    }

    /// The `name` entry of a synthesized passwd or group `content`, so a test
    /// can read the entry the box's reported identity comes from.
    fn synth_entry<'a>(content: &'a str, name: &str, file: &str) -> &'a str {
        let not_there = format!("no {name} entry in the synthesized {file}: {content}");
        content
            .lines()
            .find(|line| line.split(':').next() == Some(name))
            .unwrap_or_else(|| panic!("{not_there}"))
    }

    /// The numeric field at `index` of a colon-separated passwd or group
    /// `entry`, named by `what` in the panics a malformed entry raises.
    fn synth_number(entry: &str, index: usize, what: &str) -> u32 {
        let missing = format!("{what} is missing from the entry: {entry}");
        let field = entry
            .split(':')
            .nth(index)
            .unwrap_or_else(|| panic!("{missing}"));
        let not_a_number = format!("{what} is not a number in the entry: {entry}");
        field.parse().unwrap_or_else(|_| panic!("{not_a_number}"))
    }

    /// The agreement `BOX_UID`'s documentation promises: the uid every box
    /// execs as and the uid `common::synth_user_group_config` writes the box's
    /// `/etc/passwd` entry for are the same, and likewise the gids — so the
    /// name a box reports and the id it holds agree.
    ///
    /// `common` cannot depend on this crate, so no type holds the two
    /// constants together; this test does, by reading the files the function
    /// writes. A change to either side fails here, rather than leaving a box
    /// reporting a name that maps to a uid it does not hold.
    #[test]
    fn the_synth_passwd_entry_names_the_box_uid_and_gid() {
        let synth = tempfile::tempdir().expect("a temp dir for the synthesized config");
        common::synth_user_group_config(synth.path(), "dev", "/home")
            .expect("synthesizing the box's user and group configuration");

        let passwd = synth_file(&synth, "passwd");
        let group = synth_file(&synth, "group");

        let user = synth_entry(&passwd, "dev", "passwd");
        assert_eq!(
            synth_number(user, 2, "the passwd entry's uid"),
            BOX_UID,
            "the synthesized passwd entry must name the uid every box execs as, \
             or the box reports a name that maps to a uid it does not hold"
        );
        assert_eq!(
            synth_number(user, 3, "the passwd entry's gid"),
            BOX_GID,
            "the synthesized passwd entry must name the gid every box execs as"
        );

        let own_group = synth_entry(&group, "dev", "group");
        assert_eq!(
            synth_number(own_group, 2, "the group entry's gid"),
            BOX_GID,
            "the synthesized group entry must name the gid every box execs as"
        );
    }

    /// The classifier leaf option carries the leaf's `cgroup.procs` path — the
    /// file a pid is written to, to move it into the leaf — and is off unless
    /// the daemon sets it, so a host that cannot decide per box keeps
    /// launching boxes (NET-079's exception) rather than refusing them.
    #[test]
    fn a_classifier_leaf_names_its_procs_file_and_is_opt_in() {
        assert!(
            session_config().classifier_leaf.is_none(),
            "a box with no leaf configured must launch as it did before the \
             classifier existed"
        );

        let config = session_config().with_classifier_leaf(ClassifierLeaf::new(
            "/sys/fs/cgroup/minimald.slice/boxes/b1",
        ));
        let leaf = config
            .classifier_leaf
            .as_ref()
            .expect("with_classifier_leaf sets the option");

        assert_eq!(
            leaf.dir(),
            Path::new("/sys/fs/cgroup/minimald.slice/boxes/b1"),
            "the leaf's directory is the placement the daemon created"
        );
        assert_eq!(
            leaf.procs(),
            Path::new("/sys/fs/cgroup/minimald.slice/boxes/b1/cgroup.procs"),
            "the leaf's migration target is its own cgroup.procs, so the \
             daemon and an injected process write the same file"
        );
    }
}
