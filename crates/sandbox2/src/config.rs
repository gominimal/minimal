use crate::network::{NetPlan, Network};
use crate::{Error, Sandbox};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::ffi::OsStr;
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

/// The cohort subtree a box whose declaration admits no destination lives
/// in (NET-079): the packet-filter rule that refuses a deny-all box's
/// connections matches this subtree, so a leaf anywhere else — directly
/// under the cohort, or under [`ALLOW_DIR`] — is decided by a rule that does
/// not name it.
pub const DENY_DIR: &str = "deny";

/// The cohort subtree every other box lives in (NET-079): a box that
/// declared nothing, or declared a list, keeps the shipped allow-all — the
/// verdict its leaf is decided on is `allow`, and its traffic is one of the
/// cohort's (NET-078), never the node plane's.
pub const ALLOW_DIR: &str = "allow";

/// Which cohort subtree a box's leaf lives in (NET-079): the classifier's
/// answer to "what does this box's declaration admit?", spelled as the one
/// path component that picks the subtree — `deny` for a declaration that
/// admits no destination, `allow` for every other box, whatever it declared.
///
/// Decided once, from the declaration, at the box's launch: a declaration is
/// fixed at create (tightening is recreate), so the verdict is a property of
/// the leaf the box is placed in rather than something a launch or a stop
/// edits. `sandbox2` knows the *name* of the verdict and nothing about the
/// declarations that map onto it — the mapping lives where the declaration
/// does, in the daemon, so this crate never learns what an egress section is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// The box's declaration admits no destination; its leaf is under
    /// [`DENY_DIR`], and the rule that refuses its connections matches.
    Deny,
    /// Every other box; its leaf is under [`ALLOW_DIR`], and only the
    /// cohort's identity (NET-078) is carried on its traffic.
    Allow,
}

impl Verdict {
    /// The cohort subtree this verdict's leaves live in — the one path
    /// component that places a leaf: `<tree>/boxes/<dir_name>/<box-id>`.
    #[must_use]
    pub fn dir_name(self) -> &'static str {
        match self {
            Self::Deny => DENY_DIR,
            Self::Allow => ALLOW_DIR,
        }
    }
}

/// The classifier leaf a box is placed in: the cgroup its egress verdict is
/// decided on (NET-079, design §4.1), and the one no process of the box may
/// leave or let another box join.
///
/// A *path*, not a kernel handle. The daemon creates the leaf before the
/// spawn; the box's first process joins it in its own pre-exec closure,
/// *before* it unshares the cgroup namespace, so the leaf becomes the
/// namespace's root — the cgroup every view the box can ever mount starts at,
/// and the only one it can reach. This option is how the rest of the sandbox
/// learns the box has one: the launch log names the leaf, and the sandbox
/// binds the leaf's tree into the box so the join has a path to write.
///
/// The path is resolved in the *daemon's* namespaces, where the leaf is
/// created; inside the box it is reached through the tree bound at the
/// conventional cgroup mountpoint — see [`Self::tree_root`] and
/// [`Self::relative_dir`], which name the two halves of that.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassifierLeaf {
    /// The leaf's directory in the daemon's classifier tree, e.g.
    /// `<tree>/boxes/<deny|allow>/<box-id>` — never `<tree>/boxes/<box-id>`:
    /// a leaf directly under the cohort sits outside both subtrees, so the
    /// deny rule's match on [`DENY_DIR`] would silently miss it (NET-079).
    dir: PathBuf,
}

impl ClassifierLeaf {
    /// A leaf at `dir`, e.g. `<tree>/boxes/<deny|allow>/<box-id>`.
    #[must_use]
    pub fn new<P: Into<PathBuf>>(dir: P) -> Self {
        Self { dir: dir.into() }
    }

    /// The leaf for `box_id` under `root`'s cohort, in the subtree `verdict`
    /// picks — the spelling the daemon's own placement creates, so a caller
    /// that knows the verdict can name the leaf without duplicating the
    /// layout: `<root>/boxes/<deny|allow>/<sanitized box-id>`, one level
    /// below the cohort in either subtree, never the cohort itself.
    #[must_use]
    pub fn under(root: &Path, box_id: &str, verdict: Verdict) -> Self {
        Self::new(crate::classifier::box_leaf(root, box_id, verdict))
    }

    /// The leaf's directory in the daemon's classifier tree.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The leaf's `cgroup.procs`: writing a pid here moves that process into
    /// the leaf. A box's first process writes its own in its pre-exec
    /// closure, before it unshares the cgroup namespace; an injected process
    /// writes its own before it joins the box's namespaces, where the root's
    /// own `cgroup.procs` is no longer writable.
    #[must_use]
    pub fn procs(&self) -> PathBuf {
        self.dir.join("cgroup.procs")
    }

    /// The tree this leaf belongs to — `dir`'s parent's parent's parent, since
    /// every leaf is `<tree>/<BOXES_DIR>/<deny|allow>/<box-id>`. The daemon
    /// resolves the leaf through it, and the sandbox binds *it* into the box
    /// at the conventional cgroup mountpoint, so the box's own join goes
    /// through the tree it is a leaf of — which the box then covers, so no
    /// process it runs is left a cgroup path at all.
    #[must_use]
    pub fn tree_root(&self) -> PathBuf {
        self.dir
            .parent()
            .and_then(Path::parent)
            .and_then(Path::parent)
            .map_or_else(|| self.dir.clone(), Path::to_path_buf)
    }

    /// The leaf's path under its [`tree_root`](Self::tree_root) —
    /// `<BOXES_DIR>/<deny|allow>/<box-id>`. The box joins its leaf through
    /// the tree bound at the conventional mountpoint, so this is the one
    /// spelling of the leaf that resolves *inside* the box, before its cgroup
    /// namespace is unshared onto the leaf.
    #[must_use]
    pub fn relative_dir(&self) -> PathBuf {
        self.dir
            .strip_prefix(self.tree_root())
            .map(Path::to_path_buf)
            .unwrap_or_else(|_| self.dir.clone())
    }

    /// Whether this leaf sits in the [`DENY_DIR`] subtree — i.e. whether the
    /// box it places was declared deny-all. A leaf's verdict is a property of
    /// the path the daemon placed it at ([`Verdict::dir_name`]), so this reads
    /// it back off the path rather than being told: the caller that knows a
    /// leaf's *directory* (an argv option, a log line) knows its box's verdict
    /// without a second field to keep in step.
    ///
    /// A path whose parent is neither subtree — a leaf squatted directly
    /// under the cohort, or a directory that is not a leaf at all — answers
    /// `false`: it is not a deny-all box's leaf, so nothing about it warrants
    /// the fatal handling that spelling carries.
    #[must_use]
    pub fn is_deny(&self) -> bool {
        self.dir
            .parent()
            .and_then(Path::file_name)
            .is_some_and(|name| name == OsStr::new(DENY_DIR))
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

    /// Whether the box's classifier cover is forced onto its tmpfs fallback —
    /// the branch the design takes only where the kernel refuses the
    /// read-only cgroup2 mount of the namespace root. A test knob
    /// ([`Self::with_forced_cover_fallback`]), never set in production: on a
    /// host whose kernel does mount cgroup2 inside a box's user namespace, it
    /// is the only way to exercise the recorded-fallback branch
    /// deterministically — the branch every launch takes on a host whose
    /// kernel refuses that mount.
    pub(crate) force_cover_fallback: bool,
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
        // The layout default `PATH`, set below; captured up front so a composed
        // `PATH` can expand `$PATH`/`${PATH}` against it without re-borrowing
        // `env` while the `set` closure holds it mutably.
        let default_path = if let WdSetup::Session { .. } = &self.wd {
            "/usr/bin:/bin:/usr/sbin:/sbin:/home/.local/bin"
        } else {
            "/usr/bin:/bin:/usr/sbin:/sbin"
        };
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

        // A composed `PATH` may extend the layout default by referring to it
        // as `$PATH` or `${PATH}`; expand that reference so the default
        // directories are not lost. Every other variable stays literal.
        self.env_vars.iter().for_each(|(var, val)| {
            if var == "PATH" {
                let expanded = val
                    .replace("${PATH}", default_path)
                    .replace("$PATH", default_path);
                set(var, &expanded);
            } else {
                set(var, val);
            }
        });
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
            force_cover_fallback: false,
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

    /// Forces a leaf-bearing box's cover onto its recorded tmpfs fallback,
    /// skipping the design's read-only cgroup2 mount of the namespace root.
    /// Test-only, so a host whose kernel *does* allow that mount can still
    /// exercise the fallback branch deterministically: the branch the box
    /// tests assert per cover, split by the cover the box reports it took.
    #[cfg(test)]
    pub(crate) fn with_forced_cover_fallback(mut self) -> Self {
        self.force_cover_fallback = true;
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

    /// A composed `PATH` that refers to `$PATH` (or `${PATH}`) extends the
    /// layout default instead of replacing it verbatim; a `PATH` without a
    /// reference, and any other variable, stay literal.
    #[test]
    fn a_composed_path_expands_its_self_reference() {
        let mut config = session_config();
        config
            .env_vars
            .insert("PATH".to_string(), "/opt/bin:$PATH".to_string());
        config
            .env_vars
            .insert("EDITOR".to_string(), "hx:$PATH".to_string());

        let env = config.command_env();

        assert_eq!(
            env.get("PATH").map(String::as_str),
            Some("/opt/bin:/usr/bin:/bin:/usr/sbin:/sbin:/home/.local/bin"),
        );
        // A non-PATH variable containing `$PATH` stays literal.
        assert_eq!(env.get("EDITOR").map(String::as_str), Some("hx:$PATH"));

        let mut braced = session_config();
        braced
            .env_vars
            .insert("PATH".to_string(), "/opt/bin:${PATH}".to_string());
        assert_eq!(
            braced.command_env().get("PATH").map(String::as_str),
            Some("/opt/bin:/usr/bin:/bin:/usr/sbin:/sbin:/home/.local/bin"),
        );

        let mut literal = session_config();
        literal
            .env_vars
            .insert("PATH".to_string(), "/opt/bin".to_string());
        assert_eq!(
            literal.command_env().get("PATH").map(String::as_str),
            Some("/opt/bin"),
        );
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

        // The depth the verdict's subtrees add (NET-079): a leaf is
        // `<tree>/boxes/<deny|allow>/<box-id>`, never `<tree>/boxes/<box-id>`.
        let config = session_config().with_classifier_leaf(ClassifierLeaf::new(
            "/sys/fs/cgroup/minimald.slice/boxes/deny/b1",
        ));
        let leaf = config
            .classifier_leaf
            .as_ref()
            .expect("with_classifier_leaf sets the option");

        assert_eq!(
            leaf.dir(),
            Path::new("/sys/fs/cgroup/minimald.slice/boxes/deny/b1"),
            "the leaf's directory is the placement the daemon created"
        );
        assert_eq!(
            leaf.procs(),
            Path::new("/sys/fs/cgroup/minimald.slice/boxes/deny/b1/cgroup.procs"),
            "the leaf's migration target is its own cgroup.procs, so the \
             daemon and an injected process write the same file"
        );
        assert_eq!(
            leaf.tree_root(),
            Path::new("/sys/fs/cgroup/minimald.slice"),
            "the tree is three levels up from the leaf: cohort, then the \
             verdict's subtree, then the leaf"
        );
        assert_eq!(
            leaf.relative_dir(),
            Path::new("boxes/deny/b1"),
            "the leaf's spelling inside the box names the subtree its verdict \
             picked, so the join the box's own closure makes goes through the \
             one cgroup its verdict is decided on"
        );

        // The per-verdict constructor spells the same leaf from the tree and
        // the session's name, in either subtree — the layout lives in one
        // place, not in every caller that names a leaf. The name goes through
        // the same sanitize as the placement, so its separators are dropped.
        let root = Path::new("/sys/fs/cgroup/minimald.slice");
        for (verdict, dir) in [
            (super::Verdict::Deny, "deny"),
            (super::Verdict::Allow, "allow"),
        ] {
            assert_eq!(
                ClassifierLeaf::under(root, "a session", verdict).dir(),
                &Path::new("/sys/fs/cgroup/minimald.slice")
                    .join("boxes")
                    .join(dir)
                    .join("asession"),
                "a {dir} leaf is one level below the cohort, in its verdict's \
                 subtree: the sanitize the placement performs is the \
                 constructor's, so no caller can spell a leaf the cohort owns"
            );
        }
    }

    /// A leaf's verdict reads back off its path: the caller that knows the
    /// directory knows which subtree its box was placed in — the spelling the
    /// injection shim's fatal join is keyed on (a deny-all box's leaf cannot
    /// be joined non-fatally, NET-079).
    #[test]
    fn a_leaf_is_deny_only_when_its_parent_is_the_deny_subtree() {
        assert!(
            ClassifierLeaf::new("/sys/fs/cgroup/minimald.slice/boxes/deny/b1").is_deny(),
            "a leaf in the deny subtree belongs to a deny-all box"
        );
        assert!(
            !ClassifierLeaf::new("/sys/fs/cgroup/minimald.slice/boxes/allow/b1").is_deny(),
            "a leaf in the allow subtree is every other box"
        );
        assert!(
            !ClassifierLeaf::new("/sys/fs/cgroup/minimald.slice/boxes/b1").is_deny(),
            "a leaf squatted directly under the cohort is in neither subtree, \
             so it is not a deny-all box's leaf however it got there"
        );
    }
}
