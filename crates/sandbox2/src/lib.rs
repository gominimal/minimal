//! The low-level sandbox implementation.
//!
//! Build a [`Config`] and use it to construct a [`Sandbox`].
//!
//! There are two main variants of sandboxes:
//!
//!  * those configured with [`WdSetup::Isolated`], which have no state directory, file mappings to the host system,
//!    or mapped cwd. These are 'cleanroom' sandboxes, for hermetic builds.
//!  * those configured with [`WdSetup::BoundDir`], which map a directory from the host for the cwd, allow additional
//!    filesystem mappings into the sandbox, allows wiring a `/state` directory, and brings across a host of default
//!    environment variables (like TERM) from the host. These are for task sandboxes.

pub mod config;
use config::Config;
pub mod network;
pub use network::{
    AbandonFuture, AttachFuture, HOST_MIN_INTERNAL, HostEntry, HostNet, NetGuard, NetPlan, Network,
    NetworkError, NoNet, PlanFuture, Resolver, SocketSeal, Spawned, TapSpec,
};
use std::fs::{self, Permissions};
#[cfg(target_os = "linux")]
use std::io::Read;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::SystemTime;
pub mod error;
pub mod forker;
#[cfg(target_os = "linux")]
use crate::config::Invocation;
use crate::config::WdSetup;
#[cfg(target_os = "linux")]
use crate::error::ExecutionError;
pub use error::Error;
/// Re-export so downstream crates (e.g. `mctx`) can use the command type
/// without depending on `hakoniwa` directly.
#[cfg(target_os = "linux")]
pub use hakoniwa::Command;

mod listener;

/// Something that handles line-oriented RPCs from within the sandbox.
pub trait Channel: Send {
    // Return true to close the connection.
    fn handle(&mut self, stream: &mut UnixStream, line: &str, rootfs: &Path);
}

impl Channel for () {
    fn handle(&mut self, stream: &mut UnixStream, _line: &str, _rootfs: &Path) {
        writeln!(stream, "error: no handler!").ok();
    }
}

/// The name of the working directory inside a session sandbox: the host
/// directory given to [`Config::with_session_dirs`] is bind-mounted at
/// `/{SESSION_DEFAULT_WD}` unless the config overrides the name.
///
/// Exported so callers that have to translate between a path typed inside the
/// sandbox and the host directory backing it agree with the mount on where it
/// lives.
///
/// [`Config::with_session_dirs`]: config::Config::with_session_dirs
pub const SESSION_DEFAULT_WD: &str = "workbench";

/// The name of the home directory inside a session sandbox: the host directory
/// given to [`Config::with_session_dirs`] is bind-mounted at `/{SESSION_HOME}`.
///
/// Exported for the same reason as [`SESSION_DEFAULT_WD`].
///
/// [`Config::with_session_dirs`]: config::Config::with_session_dirs
pub const SESSION_HOME: &str = "home";

/// An initialized sandbox.
///
/// Sandboxes can have a [`Channel`] wired to the outside world for interactive operations and mutations
/// to the sandbox itself that originate from inside the sandbox. Pass `()` as the channel to have this
/// be effectively disabled.
#[derive(Debug)]
pub struct Sandbox<C: Channel = ()> {
    pub(crate) base_dir: PathBuf,
    #[cfg(target_os = "linux")]
    pub(crate) state_dir: PathBuf,
    pub(crate) config: Config,

    keep_dir: bool,
    stdout: Option<fs::File>,
    stderr: Option<fs::File>,

    listener: Option<listener::Listener<C>>,
}

impl<C: Channel> Drop for Sandbox<C> {
    fn drop(&mut self) {
        drop(self.listener.take()); // drop the listener first to clean up the listening thread

        if let Some(stdout) = self.stdout.take() {
            if let Err(e) = stdout.sync_all() {
                tracing::warn!("Failed fsync of stdout file: {}", e,);
            }
            drop(stdout);
        }
        if let Some(stderr) = self.stderr.take() {
            if let Err(e) = stderr.sync_all() {
                tracing::warn!("Failed fsync of stderr file: {}", e,);
            }
            drop(stderr);
        }

        if !self.keep_dir
            && let Err(e) = common::remove_dir_all(&self.base_dir)
        {
            tracing::warn!(
                "Failed cleanup for sandbox at path {}: {}",
                self.base_dir.display(),
                e,
            );
        }
    }
}

// Sandbox initialization
impl<C: Channel> Sandbox<C> {
    /// The working directory a command in this sandbox starts in, as an
    /// absolute path inside the sandbox.
    ///
    /// Exposed so a caller that runs a process in this sandbox by some route
    /// other than [`Self::command`] — minimald joining a live session's
    /// namespaces — starts it where the sandbox's own process started.
    pub fn command_cwd(&self) -> Result<String, Error> {
        self.config.command_cwd()
    }

    /// The environment a command in this sandbox is launched with, before any
    /// per-invocation additions. Companion to [`Self::command_cwd`].
    #[must_use]
    pub fn command_env(&self) -> std::collections::BTreeMap<String, String> {
        self.config.command_env()
    }

    /// The host-side twin of the report file a leaf-bearing box's pre-exec
    /// closure writes into its `/run` — the same file, through the sandbox's
    /// read-write `/run` bind, named by the leaf ([`classifier::closure_report_name`]).
    ///
    /// For the daemon to read after the spawn: which cover the box took over
    /// its classifier tree (the design's read-only cgroup2 mount of the
    /// namespace root, or the recorded tmpfs fallback, with the errno that
    /// forced it), or the errno the closure died on where the box never
    /// reached its program — the `127` the spawn then reports, whose stderr
    /// is the box's own stdio and reaches no daemon log without this file.
    ///
    /// `leaf` names a leaf this sandbox's box was placed in; the caller that
    /// created the leaf is the caller that reads the report.
    #[must_use]
    pub fn closure_report_path(&self, leaf: &config::ClassifierLeaf) -> PathBuf {
        let name = leaf
            .dir()
            .file_name()
            .and_then(std::ffi::OsStr::to_str)
            .map(classifier::closure_report_name)
            .unwrap_or_else(|| classifier::closure_report_name("unnamed-leaf"));
        self.base_dir.join("run").join(name)
    }

    /// Creates a new sandbox, containing all filesystem state within `base_dir`.
    pub(crate) fn new(base_dir: PathBuf, config: Config, channel: C) -> Result<Self, Error> {
        // Setup the rootfs
        let rootfs = base_dir.join("rootfs");
        fs::create_dir_all(&rootfs)
            .map_err(|e| Error::IO("create rootfs dir", rootfs.clone(), e))?;
        let hardlinking_start = SystemTime::now();
        for i in config.rootfs.iter() {
            match i {
                config::SandboxMapped::Dir(p) => hardlink_dir_contents(p, &rootfs)?,
                config::SandboxMapped::TempDir(td) => hardlink_dir_contents(td.path(), &rootfs)?,
                config::SandboxMapped::File(p) | config::SandboxMapped::FileCopy(p) => {
                    return Err(Error::MappedFile(p.clone()));
                }
            }
        }
        hardlink_dir_contents(&base_dir.join("synth"), &rootfs)?;

        // MINIMAL_INTERNAL_CS_BUILD bundle: when the env var is "1"
        // AND the convention path exists on host, hardlink that
        // directory's contents into the sandbox rootfs root. This is
        // the same mechanism the public `extra_rootfs` field used to
        // provide; it now happens behind the (undocumented) CS flag
        // with a hardcoded convention path, so there's no new public
        // API surface.
        //
        // Convention: minimalmertic's hermetic-builder-rs stages its
        // CS-only cache bundle (cargo-vendor, npm-cache, pnpm-store,
        // bun-cache, pip-wheels, rust-stage0, goproxy) at
        // /root/.cache/minimal/cs-mirror/. Inside the sandbox these
        // appear at /cargo-vendor, /goproxy, etc. — top-level paths
        // matching the existing pkg-build.sh offline-cache idiom.
        //
        // Inert when env var unset or the convention path doesn't
        // exist (tests, dev environments, non-CS callers).
        if std::env::var("MINIMAL_INTERNAL_CS_BUILD").as_deref() == Ok("1") {
            let cs_mirror = Path::new("/root/.cache/minimal/cs-mirror");
            if cs_mirror.exists() {
                hardlink_dir_contents(cs_mirror, &rootfs)?;
            }
        }
        tracing::trace!("rootfs hardlinking took {:?}", hardlinking_start.elapsed());

        // On aarch64, autotools/libtool defaults to installing libraries
        // into lib64/. Create a usr/lib64 → lib symlink in the rootfs so
        // configure scripts detect it and use usr/lib/ instead. Also create
        // the same symlink in the output directory so DESTDIR installs that
        // still target lib64/ land in lib/ transparently.
        let usr_lib64 = rootfs.join("usr").join("lib64");
        if !fs::exists(&usr_lib64).unwrap_or(true) {
            std::os::unix::fs::symlink("lib", &usr_lib64)
                .map_err(|e| Error::IO("create usr/lib64 symlink", usr_lib64, e))?;
        }

        // Setup the working directory
        match &config.wd {
            WdSetup::Isolated { working_inputs } => {
                let b = base_dir.join("build");
                fs::create_dir_all(&b).map_err(|e| Error::IO("create build dir", b.clone(), e))?;

                let hardlinking_start = SystemTime::now();
                for i in working_inputs {
                    match i {
                        config::SandboxMapped::File(p) => {
                            let dest = &b.join(p.file_name().unwrap());
                            match fs::hard_link(p, dest) {
                                Ok(()) => Ok(()),
                                Err(e) => {
                                    if e.kind() == std::io::ErrorKind::AlreadyExists {
                                        tracing::warn!(
                                            "Not linking {} => {}, already exists",
                                            p.display(),
                                            dest.display()
                                        );
                                        Ok(())
                                    } else {
                                        Err(e)
                                    }
                                }
                            }
                            .map_err(|e| Error::IO("hardlinking input file", dest.clone(), e))?;
                        }
                        config::SandboxMapped::FileCopy(p) => {
                            let dest = b.join(p.file_name().unwrap());
                            fs::copy(p, &dest)
                                .map_err(|e| Error::IO("copying input file", dest, e))?;
                        }
                        config::SandboxMapped::Dir(p) => hardlink_dir_contents(p, &b)?,
                        config::SandboxMapped::TempDir(td) => hardlink_dir_contents(td.path(), &b)?,
                    }
                }
                tracing::trace!("input hardlinking took {:?}", hardlinking_start.elapsed());

                let output = b.join("output");
                fs::create_dir_all(&output)
                    .map_err(|e| Error::IO("create output dir", b.clone(), e))?;

                // Mirror the usr/lib64 → lib symlink into the output dir so
                // that DESTDIR installs targeting lib64/ land in lib/.
                let out_usr_lib = output.join("usr").join("lib");
                fs::create_dir_all(&out_usr_lib)
                    .map_err(|e| Error::IO("create output usr/lib", out_usr_lib.clone(), e))?;
                let out_usr_lib64 = output.join("usr").join("lib64");
                std::os::unix::fs::symlink("lib", &out_usr_lib64)
                    .map_err(|e| Error::IO("create output usr/lib64 symlink", out_usr_lib64, e))?;
            }
            WdSetup::BoundDir {
                path: _,
                fs_mappings,
                read_only: _,
            } => {
                let rootfs_cwd = rootfs.join(config.wd.bound_dir_sandbox_cwd());
                fs::create_dir_all(&rootfs_cwd)
                    .map_err(|e| Error::IO("create shadow cwd tree", rootfs_cwd, e))?;

                // Create bind-mount targets
                for m in fs_mappings {
                    let sp = m.path_in_sandbox();
                    let sp = match sp.strip_prefix("/") {
                        Some(stripped) => stripped,
                        None => &sp,
                    };
                    let p = rootfs.join(sp);

                    if m.is_file {
                        fs::create_dir_all(p.parent().unwrap())
                            .map_err(|e| Error::IO("create mapping parent", p, e))?;
                    } else {
                        fs::create_dir_all(&p)
                            .map_err(|e| Error::IO("create mapping target", p, e))?;
                    }
                }
            }
            WdSetup::Session {
                home: _,
                working: _,
                working_name_override,
            } => {
                let rootfs_cwd = rootfs.join(
                    working_name_override
                        .as_ref()
                        .cloned()
                        .unwrap_or_else(|| SESSION_DEFAULT_WD.to_string()),
                );
                fs::create_dir_all(&rootfs_cwd)
                    .map_err(|e| Error::IO("create cwd", rootfs_cwd, e))?;
                let rootfs_home = rootfs.join(SESSION_HOME);
                fs::create_dir_all(&rootfs_home)
                    .map_err(|e| Error::IO("create home", rootfs_home.clone(), e))?;
            }
        }

        // Setup /state
        let state_dir = match &config.state_dir {
            None => base_dir.join("state"),
            Some(s) => s.to_path_buf(),
        };

        if !matches!(&config.wd, WdSetup::Session { .. }) {
            fs::create_dir_all(state_dir.join("home"))
                .map_err(|e| Error::IO("mkdir /state/home", state_dir.join("home"), e))?;
            fs::create_dir_all(state_dir.join("data"))
                .map_err(|e| Error::IO("mkdir /state/data", state_dir.join("data"), e))?;
            fs::create_dir_all(state_dir.join("state"))
                .map_err(|e| Error::IO("mkdir /state/state", state_dir.join("state"), e))?;
        }
        fs::create_dir_all(state_dir.join("cache"))
            .map_err(|e| Error::IO("mkdir /state/cache", state_dir.join("cache"), e))?;

        // Create /run/minenv_sock as the pipe to higher-level functions.
        let run_dir = base_dir.join("run");
        fs::create_dir_all(&run_dir).map_err(|e| Error::IO("mkdir /run", run_dir.clone(), e))?;
        fs::set_permissions(&run_dir, Permissions::from_mode(0o700))
            .map_err(|e| Error::IO("set perms /run", run_dir.clone(), e))?;
        let sock_path = run_dir.join("minenv_sock");
        let listener = listener::Listener::new(&sock_path, &rootfs, channel)
            .map_err(|e| Error::IO("creating env socket", sock_path, e))?;

        let stdout = fs::File::create(base_dir.join("stdout"))
            .map_err(|e| Error::IO("creating stdout", base_dir.join("stdout"), e))?;
        let stderr = fs::File::create(base_dir.join("stderr"))
            .map_err(|e| Error::IO("creating stderr", base_dir.join("stderr"), e))?;

        Ok(Self {
            base_dir,
            #[cfg(target_os = "linux")]
            state_dir,
            config,
            keep_dir: false,
            stdout: Some(stdout),
            stderr: Some(stderr),
            listener: Some(listener),
        })
    }

    #[cfg(target_os = "linux")]
    fn needs_lib64_symlink(&self) -> Result<bool, Error> {
        let lib64_p = self.rootfs().join("lib64");
        Ok(!fs::exists(&lib64_p)
            .map_err(|e| Error::IO("checking for lib64 directory", lib64_p, e))?)
    }
    #[cfg(target_os = "linux")]
    fn needs_lib_symlink(&self) -> Result<bool, Error> {
        let lib_p = self.rootfs().join("lib");
        Ok(!fs::exists(&lib_p).map_err(|e| Error::IO("checking for lib directory", lib_p, e))?)
    }
    #[cfg(target_os = "linux")]
    fn needs_bin_symlink(&self) -> Result<bool, Error> {
        let bin_p = self.rootfs().join("bin");
        Ok(!fs::exists(&bin_p).map_err(|e| Error::IO("checking for bin directory", bin_p, e))?)
    }

    /// Configures the sandbox to not delete itself when dropped.
    pub fn keep_dir(&mut self, keep_dir: bool) {
        self.keep_dir = keep_dir;
    }

    /// Path to the rootfs of the sandbox.
    pub fn rootfs(&self) -> PathBuf {
        self.base_dir.join("rootfs")
    }
}

/// An initialized sandbox environment.
#[cfg(target_os = "linux")]
pub struct Container {
    container: hakoniwa::Container,
    /// The libc-only seccomp-BPF filter installed by this container before
    /// exec. Stored as a `&'static` because a hakoniwa command closure is
    /// `'static` and the filter must live as long as any command spawned from
    /// this container.  The value is one of the process-wide `OnceLock`
    /// builds ([`socket_family_filter_for_none_box`], or the
    /// confined-families one), shared by every container running under that
    /// seal; nothing is leaked per sandbox.
    socket_family_filter: &'static SocketFamilyFilter,
}

#[cfg(target_os = "linux")]
impl AsRef<hakoniwa::Container> for Container {
    fn as_ref(&self) -> &hakoniwa::Container {
        &self.container
    }
}

#[cfg(target_os = "linux")]
impl Container {
    /// Instructs the container to perform the setsid() & associate controlling
    /// terminal dance.
    pub fn set_session_leader(&mut self) {
        self.container.runctl(hakoniwa::Runctl::NewSession);
    }

    fn command_inner<C, I, IE, ArgS, EnvK, EnvV>(
        &self,
        sandbox: &Sandbox<C>,
        program: &str,
        args: I,
        envs: IE,
    ) -> Result<hakoniwa::Command, Error>
    where
        C: Channel,
        I: IntoIterator<Item = ArgS>,
        ArgS: AsRef<str>,
        IE: IntoIterator<Item = (EnvK, EnvV)>,
        EnvK: AsRef<str>,
        EnvV: AsRef<str>,
    {
        let mut command = self.container.command(program);
        command.args(args);
        // Both are derived from the config rather than built here, so that a
        // process injected into a *running* sandbox (minimald's `nsenter`) can
        // reproduce the same working directory and environment without a second
        // definition of them drifting from this one.
        command.current_dir(sandbox.config.command_cwd()?);
        command.envs(sandbox.config.command_env());
        for (k, v) in envs.into_iter() {
            command.env(k.as_ref(), v.as_ref());
        }

        // Every box execs with the same credentials: as the unprivileged box
        // uid inside its user namespace, with no_new_privs set and the
        // capabilities no box may hold dropped from its bounding set — the one
        // capability set an exec does not clear. The closure below runs at the
        // only moment that is possible, while the process still holds
        // CAP_SETPCAP in its user namespace, and installs the box's
        // socket-family seal there at the same moment hakoniwa would load a
        // libseccomp filter. A box with a classifier leaf also joins it in the
        // same closure — the last moment the process still sits in the
        // daemon's cgroup namespace, where the leaf is reachable.
        install_box_credentials(
            &self.container,
            &mut command,
            self.socket_family_filter,
            sandbox.config.classifier_leaf.clone(),
            sandbox.config.force_cover_fallback,
        )?;

        Ok(command)
    }
}

/// The classifier tree each host-address box's egress verdict is decided on
/// (NET-079, design §4.1): one cgroup tree per daemon, holding a leaf for the
/// daemon itself and one leaf per box.
///
/// ```text
/// <TREE_ROOT>/            delegated to the daemon's account — the directory
///                         plus its cgroup.procs, cgroup.threads and
///                         cgroup.subtree_control, the whole v2 delegation
///                         contract. The kernel reads a write to a
///                         cgroup.procs as a migration that needs write on
///                         the *common ancestor* of source and destination,
///                         so the contract is what makes the daemon's own
///                         entry (and each box's) possible at all — and the
///                         mount root above the tree, whose `cgroup.procs`
///                         the contract does not cover, is the one file a
///                         process outside the tree cannot write to get in.
///                         No process ever lives here and no controller is
///                         ever enabled on it (the no-internal-process rule —
///                         a controller on a process-bearing cgroup makes
///                         every child below it `domain invalid`, spike
///                         finding F)
///   daemon/               the daemon and its own helpers; entered at startup
///   boxes/                every box leaf lives under here, and the daemon
///                         never places itself under it (NET-078's two
///                         identities)
///     deny/               the subtree a box whose declaration admits no
///                         destination lives in: the packet-filter rule that
///                         refuses a deny-all box's connections matches this
///                         subtree by cgroup path, so no leaf may sit
///                         directly under `boxes/` — one there would be
///                         decided by no rule at all (NET-079)
///     allow/              every other box, whatever it declared: the shipped
///                         allow-all included, and its traffic is one of the
///                         cohort's (NET-078)
///       <box-id>/         one leaf per box, named by its session id, created
///                         before the spawn and removed after the box is
///                         reaped; an empty one a daemon death left behind is
///                         swept at the next daemon start
/// ```
///
/// Natively the tree is installed by the privileged step
/// (`scripts/install-host-classifier.sh`), which delegates it to the daemon's
/// account and leaves the cgroup2 mount root above it root-owned. Delegation
/// does not move the daemon itself: a process cannot migrate itself into the
/// tree from `user.slice`, where the daemon's first hop's common ancestor is
/// the root-owned mount root, so natively the daemon must be *placed* — the
/// installer's `--pid` step for a running daemon, or a systemd unit with
/// `Delegate=yes` for one it starts — and a daemon that is not inside the
/// tree does not place its boxes either (NET-079's exception: unenforced,
/// never refused, and never a box that dies joining a leaf it cannot join).
/// In a microVM the guest daemon is pid 1 and roots its own tree under the
/// cgroup2 mount the guest boot path makes with namespace delegation.
///
/// **Why a box stays in its leaf.** The box's leaf is the root of its cgroup
/// namespace (architecture, *Box Resources*): the box's first process joins
/// the leaf in its pre-exec closure, *then* unshares the cgroup namespace —
/// `unshare(CLONE_NEWCGROUP)` roots the new namespace at the cgroup the
/// caller stands in, so the namespace is rooted where the box already stands.
/// Any cgroup view the box could mount after that starts at the namespace
/// root — the leaf itself — so a sibling leaf is neither visible nor
/// reachable, and with cgroup2 mounted `nsdelegate` the root's own
/// `cgroup.procs` is not writable from inside the namespace (it is a
/// delegation boundary, and the process running as the delegated account
/// inside it holds no capability over it). The tree the sandbox binds at the
/// conventional mountpoint for the join is *covered* once the join has run —
/// with the design's own cover, a read-only cgroup2 mount of the namespace
/// root, so the host's cgroup mount stays out of the box's mount namespace
/// while the box keeps exactly the view a cgroup-aware runtime expects to
/// find: its own limit readable (`memory.max`) at the conventional place, no
/// cgroup but its own reachable, its own root's `cgroup.procs` not writable.
/// Where the kernel refuses that mount inside the box's user namespace, the
/// bind is covered by an empty read-only tmpfs instead — a *recorded
/// fallback*, never the design's cover: the box still has no cgroup path to
/// write a migration to, but none to read a limit from either, which is why
/// the fallback is reported through the sandbox's `/run` for the daemon to
/// warn, marked in the box's own environment (`MINIMAL_CLASSIFIER_COVER`),
/// and asserted by the tests branch by branch rather than passed off as the
/// design. The barrier against a box is therefore its cgroup-namespace root
/// plus `nsdelegate` plus that cover — not the slice's uid, which the box
/// shares with the daemon. Of those layers, the cover is the one the
/// stand-in-tree tests can assert per branch (nothing resolves under the
/// fallback's tmpfs; under the design's cover the box's own `memory.max`
/// resolves and a sibling's path does not); the namespace root needs the
/// kernel's own bookkeeping to see, which is what the delegated-tree test
/// asserts: the host-side `cgroup.procs` holds the box's pid while the box
/// reads `0::/`.
pub mod classifier {
    use crate::config;
    use std::path::{Path, PathBuf};

    /// The daemon's tree root: where the host's cgroup2 mount carries the
    /// tree — `/sys/fs/cgroup/minimald.slice` natively and in the guest, whose
    /// daemon mounts cgroup2 at the conventional place itself.
    pub const TREE_ROOT: &str = "/sys/fs/cgroup/minimald.slice";

    /// The leaf the daemon itself runs in: a **sibling** of every box leaf,
    /// never the tree root (spike finding F), so the daemon's own fetches are
    /// decided as node-plane traffic (NET-080) and a controller enabled on
    /// the root can never make the box leaves unusable.
    pub const DAEMON_LEAF: &str = "daemon";

    /// The host-address cohort: every box leaf lives under here, and the
    /// daemon never places itself under it (NET-078's two identities).
    pub const BOXES_DIR: &str = "boxes";

    /// The presence marker of the packet-filter table the privileged step
    /// installs (NET-079): a cgroup directory under the tree root — on real
    /// cgroupfs a plain file cannot exist, so the marker is a cgroup that
    /// holds no process, and on the stand-in trees a test rehearses against
    /// it is a directory. The step writes it *after* the one `nft -f`
    /// transaction that loads the table succeeds, so it records "the table
    /// that decides a deny-all box's connections is loaded" — and the daemon
    /// probes it read-only, because listing a table needs the very
    /// capability the step runs with (`nft list table` is CAP_NET_ADMIN).
    /// Nothing else creates it: the guest builds its own tree but no table,
    /// so a guest's marker is honestly absent and its recorded state says
    /// the table is not there.
    pub const TABLE_MARKER: &str = "classifier-table";

    /// The conventional cgroup2 mountpoint: where the box's classifier tree
    /// is bound for the join, and where the cover — the design's read-only
    /// cgroup2 mount of the box's own namespace root, or the recorded empty
    /// read-only tmpfs fallback — is mounted over that bind once the join
    /// has run. It is the one place a cgroup-aware runtime looks, so it is
    /// the one place the cover has to hold: under the design's cover the
    /// box finds its own limit there and no cgroup but its own; under the
    /// fallback it finds no cgroup path at all — none to read a limit
    /// from, and none to write a migration to.
    pub const CONVENTIONAL_CGROUP2_MOUNTPOINT: &str = "/sys/fs/cgroup";

    /// The daemon's own leaf under `root`.
    #[must_use]
    pub fn daemon_leaf(root: &Path) -> PathBuf {
        root.join(DAEMON_LEAF)
    }

    /// The cgroup.v2 names the kernel reserves for its own files: a leaf named
    /// `cgroup.procs` cannot be created and would shadow a migration target.
    const RESERVED_PREFIX: &str = "cgroup.";

    /// The box-id a session's name becomes: a single path component the kernel
    /// will accept, derived rather than trusted, because a session name is
    /// user input and the leaf is a directory in a root-owned tree.
    ///
    /// `[A-Za-z0-9][A-Za-z0-9._-]*`, truncated to the 64 bytes a cgroup name
    /// is expected to fit in: no separator (a `..` or a `/` would escape the
    /// cohort), no leading dot or dash (a hidden name is never the intent),
    /// and never the kernel's own `cgroup.` prefix. A name that sanitizes to
    /// nothing at all still gets a leaf of its own, not the cohort directory
    /// itself.
    #[must_use]
    pub fn sanitize_box_id(name: &str) -> String {
        let mut id = String::new();
        for c in name.chars() {
            let ok = c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-') && !id.is_empty();
            if !ok {
                continue;
            }
            if id.len() + c.len_utf8() >= 64 {
                break;
            }
            id.push(c);
        }
        if id.is_empty() {
            id.push_str("box");
        }
        if id.starts_with(RESERVED_PREFIX) {
            format!("box-{id}")
        } else {
            id
        }
    }

    /// The leaf for `box_id` under `root`, in the cohort subtree `verdict`
    /// picks — `<root>/boxes/<deny|allow>/<box-id>`, never
    /// `<root>/boxes/<box-id>`: both subtrees share one depth, so the
    /// cohort's source-identity match (NET-078) covers a leaf in either
    /// subtree at the same level, and the deny-all refusal (NET-079) matches
    /// the `deny` subtree alone — a leaf directly under the cohort would be
    /// decided by no rule at all, which is why none may sit there. A
    /// directory in the daemon's own namespaces, resolved before any of the
    /// box's namespaces exist.
    #[must_use]
    pub fn box_leaf(root: &Path, box_id: &str, verdict: config::Verdict) -> PathBuf {
        root.join(BOXES_DIR)
            .join(verdict.dir_name())
            .join(sanitize_box_id(box_id))
    }

    /// The name of the report file the box's pre-exec closure writes into
    /// the sandbox's read-write `/run`, named by the leaf the box is placed
    /// in so two sessions never share one. Spelled identically from both
    /// sides of the `/run` bind: by the closure, which knows the leaf only
    /// as the `cgroup.procs` it joined, and by the daemon, which knows the
    /// leaf directory it created — see [`crate::Sandbox::closure_report_path`]
    /// for the host-side twin. The report carries what nothing else can:
    /// which cover the box took over its classifier tree, or the errno the
    /// closure died on before the program ran.
    #[must_use]
    pub fn closure_report_name(box_id: &str) -> String {
        format!("minimal-closure-{box_id}")
    }

    /// Creates the box's leaf under `root`, in the subtree `verdict` picks,
    /// before the box's first process exists. Requires the tree the
    /// privileged step installs (or the guest daemon builds): the cohort's
    /// two subtrees must already exist and be delegated to the daemon's
    /// account, and their absence is the `NotFound` that tells the daemon
    /// this host has no per-box classifier at all — the box then runs
    /// unenforced, never refused (NET-079's exception).
    ///
    /// A leaf that already exists is surfaced, not reused: the leaf is named
    /// by its session's id, so on a fresh launch an existing one is a
    /// collision — another session holds it — and [`sweep_box_leaves`] has
    /// already taken the empty directories a daemon death leaves behind.
    pub fn create_box_leaf(
        root: &Path,
        box_id: &str,
        verdict: config::Verdict,
    ) -> std::io::Result<PathBuf> {
        let leaf = box_leaf(root, box_id, verdict);
        std::fs::create_dir(&leaf).map(|()| leaf)
    }

    /// Moves `pid` into the cgroup whose `cgroup.procs` is `procs` — the one
    /// migration primitive the whole placement rests on. A write is a
    /// migration command, not file content, so the kernel ignores the file's
    /// offset entirely; the pid is therefore *appended*, so that over any
    /// filesystem — cgroup2, where the kernel holds the membership, or the
    /// stand-in tree a test builds — each call places one more process rather
    /// than replacing the last. A process inherits its cgroup at fork, so a
    /// box is placed by moving the processes that were forked before the leaf
    /// existed, and everything they fork later lands in it without help.
    ///
    /// The `cgroup.procs` is never created here: a missing one means the leaf
    /// is not a cgroup at all, and that is the `NotFound` the caller should
    /// see, not a stray file a later write would fill.
    pub fn place_pid(procs: &Path, pid: u32) -> std::io::Result<()> {
        use std::io::Write as _;

        let mut file = std::fs::OpenOptions::new().append(true).open(procs)?;
        file.write_all(format!("{pid}\n").as_bytes())
    }

    /// Removes the box's leaf, once its last process is gone: a cgroup
    /// directory is removed with `rmdir` and refuses while it holds a process
    /// or a child cgroup, which is the failure a still-running box must
    /// produce. A leaf that is already gone is success — removal is owed
    /// once, not exactly once.
    pub fn remove_box_leaf(leaf: &Path) -> std::io::Result<()> {
        match std::fs::remove_dir(leaf) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Removes the empty box leaves a daemon death leaves behind: a box's
    /// leaf is removed when its launch is abandoned and when its process is
    /// reaped, but nothing removes one when the daemon is killed first, and a
    /// leaf named by its session's id must never be mistaken for a leftover
    /// one the next launch of that id could take. Each is removed with the
    /// same `rmdir` [`remove_box_leaf`] uses, and the kernel's refusal while
    /// a cgroup holds a process is the sweep's own test of emptiness: a leaf
    /// that goes was nobody's, and a leaf that stays belongs to a session the
    /// daemon no longer knows — which is the collision its next launch
    /// reports rather than a directory it reuses. A missing cohort is not an
    /// error; it is the host with no tree at all.
    ///
    /// Sweeps *both* subtrees and nothing else: a box's leaf is always under
    /// one of them (NET-079), so the cohort's own direct children — the two
    /// subtrees the step installs — are not the sweep's to test. A leaf left
    /// directly under the cohort by a daemon predating the subtrees is not
    /// swept either: `rmdir` on a direct child would remove the subtrees
    /// themselves the moment both were empty, so the sweep keeps to the
    /// leaves it could own.
    ///
    /// Returns the leaves it removed, so the caller can say what it swept.
    pub fn sweep_box_leaves(root: &Path) -> std::io::Result<Vec<PathBuf>> {
        let mut swept = Vec::new();
        for subtree in [config::DENY_DIR, config::ALLOW_DIR] {
            let entries = match std::fs::read_dir(root.join(BOXES_DIR).join(subtree)) {
                Ok(entries) => entries,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return Err(e),
            };
            for entry in entries {
                let Ok(entry) = entry else { continue };
                let path = entry.path();
                if !path.is_dir() {
                    continue;
                }
                // `rmdir` refuses — `EBUSY` over a real tree, `ENOTEMPTY`
                // over a stand-in holding a `cgroup.procs` — whatever still
                // has a session in it, and that refusal is kept, not an
                // error: the sweep owes a leaf its removal only when the
                // leaf is empty.
                if std::fs::remove_dir(&path).is_ok() {
                    swept.push(path);
                }
            }
        }
        Ok(swept)
    }

    /// Whether this daemon can place a box process in a leaf under `root` —
    /// the daemon-side half of the placement, proved by doing it: a
    /// throwaway child of this process migrates into a throwaway leaf and
    /// back out, and the probe succeeding is the only evidence that the join
    /// the box's own pre-exec closure makes can succeed. The leaf is made in
    /// the subtree `verdict` picks, the same one the launch's own leaf will
    /// live in: the subtrees share one delegation, but the probe answers for
    /// the cgroup the box is actually about to be placed in.
    ///
    /// The kernel gates that migration on write permission to the
    /// `cgroup.procs` of the *common ancestor* of source and destination, so
    /// the probe is exactly the question that matters: a daemon outside the
    /// delegated tree — one systemd starts in `user.slice`, whose first hop's
    /// common ancestor is the root-owned cgroup2 mount root — fails with the
    /// same `EACCES` the box's join would die on, and its daemon then knows
    /// to place no box at all rather than to spawn one that dies taking a
    /// leaf it cannot take (NET-079's exception, decided at the launch
    /// rather than in the box). A daemon inside the tree — placed by the
    /// installer's `--pid` step or a `Delegate=yes` unit, or entered by its
    /// own pid-1 hand in the guest — needs no help, and every launch pays
    /// one throwaway migration for the proof.
    #[cfg(target_os = "linux")]
    pub fn probe_child_placement(root: &Path, verdict: config::Verdict) -> std::io::Result<()> {
        // A throwaway leaf under the cohort, in the verdict's subtree, named
        // by this daemon's pid so two daemons probing one tree never share
        // one, and removed first so a probe that died before its own cleanup
        // cannot wedge the next.
        let leaf = box_leaf(
            root,
            &format!("placement-probe-{}", std::process::id()),
            verdict,
        );
        let _ = std::fs::remove_dir(&leaf);
        std::fs::create_dir(&leaf)?;
        let placed = place_child_in(&leaf.join("cgroup.procs"));
        // The throwaway leaf is owed its removal. The child is gone by now,
        // so over a real tree the kernel allows it; a refusal here is left
        // alone — the probe has its answer, and a stuck probe leaf says so
        // at the next probe, which removes it first.
        let _ = std::fs::remove_dir(&leaf);
        placed
    }

    /// Forks a child that writes its own pid to `procs`, and reports the
    /// child's migration: `Ok(())` when the write placed it, the write's own
    /// errno otherwise. Never called but by [`probe_child_placement`].
    #[cfg(target_os = "linux")]
    fn place_child_in(procs: &Path) -> std::io::Result<()> {
        let path = match std::ffi::CString::new(procs.as_os_str().as_encoded_bytes()) {
            Ok(path) => path,
            Err(_) => return Err(std::io::Error::from_raw_os_error(libc::EINVAL)),
        };
        // SAFETY: `fork(2)` runs in this (possibly multithreaded) process,
        // and the child runs only async-signal-safe calls between the fork
        // and its `_exit` — open, write, close, getpid — so no allocator or
        // lock can be held across the fork by the child itself, in kind
        // with the pre-exec closure this probe models.
        let pid = unsafe { libc::fork() };
        if pid == -1 {
            return Err(std::io::Error::last_os_error());
        }
        if pid == 0 {
            // The child's report is its exit status: 0 for a placement made,
            // the migration's own errno for one refused. `Error::last_os_error`
            // is `Error::Os(RawOsError)` around this thread's errno — no
            // allocation, so it belongs to the async-signal-safe set the
            // child may run.
            let errno = match unsafe { place_self_in(path.as_ptr()) } {
                Some(()) => 0,
                None => std::io::Error::last_os_error().raw_os_error().unwrap_or(1),
            };
            // SAFETY: `_exit(2)` never returns, so the child ends here.
            unsafe { libc::_exit(errno as libc::c_int) };
        }
        let mut status = 0;
        // SAFETY: `waitpid(2)` waits on the child this function forked.
        if unsafe { libc::waitpid(pid, &mut status, 0) } == -1 {
            return Err(std::io::Error::last_os_error());
        }
        if libc::WIFEXITED(status) {
            let errno = libc::WEXITSTATUS(status);
            if errno == 0 {
                Ok(())
            } else {
                Err(std::io::Error::from_raw_os_error(errno))
            }
        } else {
            Err(std::io::Error::other(
                "the placement probe's child did not exit on its own",
            ))
        }
    }

    /// The child half of the placement probe: this process writes its own
    /// pid to `path` with the raw syscalls, the same migration the box's
    /// pre-exec closure makes. `Ok(())` is a placement made; an `Err` carries
    /// the failing syscall's errno for the exit status. No `O_CREAT`: a
    /// missing `cgroup.procs` is a missing leaf and is reported, not made.
    #[cfg(target_os = "linux")]
    unsafe fn place_self_in(path: *const libc::c_char) -> Option<()> {
        // SAFETY: `open(2)` reads its arguments; the flags are the append
        // the migration primitive uses, and `O_CLOEXEC` keeps the descriptor
        // from crossing the exec this child never reaches anyway.
        let fd = unsafe { libc::open(path, libc::O_WRONLY | libc::O_APPEND | libc::O_CLOEXEC) };
        if fd == -1 {
            return None;
        }
        // The pid is formatted by hand into a stack buffer: `format!` would
        // allocate, and this is the pre-exec environment.
        let mut digits = [0u8; 12];
        let mut len = 0;
        let mut pid = unsafe { libc::getpid() };
        if pid == 0 {
            digits[len] = b'0';
            len += 1;
        }
        while pid > 0 && len < digits.len() {
            digits[len] = b'0' + (pid % 10) as u8;
            pid /= 10;
            len += 1;
        }
        digits[..len].reverse();
        digits[len] = b'\n';
        len += 1;
        // SAFETY: `write(2)` reads `digits`, which outlives the call, and the
        // length is the pid and its newline.
        if unsafe { libc::write(fd, digits.as_ptr().cast(), len) } == -1 {
            // SAFETY: `close(2)` consumes the descriptor just opened, even
            // on the failing path.
            unsafe { libc::close(fd) };
            return None;
        }
        // SAFETY: `close(2)` consumes the descriptor just opened.
        unsafe { libc::close(fd) };
        Some(())
    }

    /// This process's cgroup as the kernel names it: the `0::` line of
    /// `/proc/self/cgroup`, without its prefix — the v2 spelling, which a
    /// v1 host does not carry. This is where the *daemon* stands, and what a
    /// placement advisory can name: a daemon outside the delegated tree
    /// reads the cgroup its supervisor put it in, and a daemon inside it
    /// reads the leaf it entered.
    #[must_use]
    pub fn own_cgroup_path() -> Option<String> {
        std::fs::read_to_string("/proc/self/cgroup")
            .ok()?
            .lines()
            .find_map(|line| line.strip_prefix("0::"))
            .map(str::to_string)
    }

    /// The account this daemon runs as: the daemon knows its own uid, and
    /// the *name* is what a person types after the installer's `--user`, so
    /// it is looked up rather than guessed. A uid with no account — a
    /// container running a bare uid — is the `None` the hint below names
    /// its fallback for.
    #[cfg(target_os = "linux")]
    #[must_use]
    pub fn own_account() -> Option<String> {
        nix::unistd::User::from_uid(nix::unistd::getuid())
            .ok()
            .flatten()
            .map(|user| user.name)
    }

    /// The command a person runs on this host to give this daemon a
    /// classifier tree: the installer takes the account the daemon runs as,
    /// and the hint spells the whole command so the advisory that carries it
    /// never has to name a placeholder for the one thing the daemon knows.
    #[cfg(target_os = "linux")]
    #[must_use]
    pub fn install_hint() -> String {
        match own_account() {
            Some(account) => {
                format!("sudo scripts/install-host-classifier.sh --user {account}")
            }
            None => "sudo scripts/install-host-classifier.sh --user \
                 <the account this daemon runs as>"
                .to_string(),
        }
    }

    /// The command a person runs on this host to move *this daemon* into the
    /// tree its boxes are placed in: the installer's `--pid` step is the one
    /// migration the delegated account cannot make itself, so the hint names
    /// this daemon's pid — the one fact the person cannot guess and the
    /// advisory that carries the hint would otherwise have to name a
    /// placeholder for.
    #[cfg(target_os = "linux")]
    #[must_use]
    pub fn place_hint() -> String {
        format!(
            "sudo scripts/install-host-classifier.sh --pid {}",
            std::process::id()
        )
    }

    /// Moves this process into `root`'s [`DAEMON_LEAF`], as the daemon does at
    /// startup: its own traffic then leaves from a leaf of its own (NET-080),
    /// never classed with a box's, and the daemon sits in a *sibling* of every
    /// box leaf — never above them, where a controller it enabled for its own
    /// benefit could make the box leaves `domain invalid` (spike finding F).
    ///
    /// Creates the tree first where this process has the privilege to (the
    /// guest's pid 1). Natively the tree is the privileged step's to install,
    /// and entering it is a migration: the daemon's first hop out of
    /// `user.slice` has the root-owned cgroup2 mount root as its common
    /// ancestor, so a daemon that starts outside the delegated tree cannot
    /// make it itself — the installer's `--pid` step or a `Delegate=yes`
    /// unit places it. A daemon left outside keeps running, with its boxes
    /// unenforced: [`probe_child_placement`] is what tells an installed tree
    /// it can place a box in from one it cannot, and nothing boxes into a
    /// leaf before that.
    ///
    /// Also asks the kernel for the `memory` controller on the cohort and on
    /// both of its subtrees — best-effort, and safe: none of them holds a
    /// process, so enabling a controller on any of them breaks no
    /// internal-process rule. A leaf without it carries no `memory.max` at
    /// all, so no reader — a diagnostics bundle on the host side, or the box
    /// itself under the design's own cover — can name the limit a box's
    /// verdict is decided on.
    pub fn enter_daemon_leaf(root: &Path) -> std::io::Result<()> {
        // The cohort and both of its subtrees: a box leaf is now a grandchild
        // of the cohort, so the subtree its verdict picks must exist before
        // the launch that places it. Already-there is the common case (the
        // installer made them, or a previous daemon did).
        let mut tree = vec![root.join(BOXES_DIR)];
        for subtree in [config::DENY_DIR, config::ALLOW_DIR] {
            let dir = root.join(BOXES_DIR).join(subtree);
            std::fs::create_dir(&dir).or_else(|e| {
                if e.kind() == std::io::ErrorKind::AlreadyExists {
                    Ok(())
                } else {
                    Err(e)
                }
            })?;
            tree.push(dir);
        }
        let daemon = daemon_leaf(root);
        std::fs::create_dir(&daemon).or_else(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                Ok(())
            } else {
                Err(e)
            }
        })?;
        // Over a stand-in tree (a test's) this writes a plain file; over a
        // real tree the kernel takes `+memory` as a subtree_control command
        // and may refuse it — a host without the memory controller, or one
        // that has it threaded off, still gets its boxes placed. The cohort
        // comes first and the subtrees after it: over a real tree a
        // controller reaches a cgroup only once the cgroup above it has
        // enabled it, so the cascade order is the only one that works.
        for dir in &tree {
            if let Err(e) = std::fs::write(dir.join("cgroup.subtree_control"), "+memory\n")
                && e.kind() != std::io::ErrorKind::NotFound
                && e.kind() != std::io::ErrorKind::PermissionDenied
            {
                tracing::warn!(
                    error = %e,
                    "enabling the memory controller on {} ; a box leaf \
                     may carry no memory.max for a reader to name its limit from",
                    dir.display()
                );
            }
        }
        place_pid(&daemon.join("cgroup.procs"), std::process::id())
    }

    /// The cgroup2 mounts named in a `mountinfo`(5) text, with whether each
    /// carries the `nsdelegate` option that makes a cgroup namespace a
    /// delegation boundary — the property a box's confinement rests on.
    ///
    /// Pure over its input so a daemon can report it and a test can read the
    /// mount table a host actually gave it.
    #[must_use]
    pub fn host_cgroup2_mounts(mountinfo: &str) -> Vec<(PathBuf, bool)> {
        mountinfo
            .lines()
            .filter_map(|line| {
                // "ID PARENT MAJ:MIN ROOT MOUNTPOINT OPTIONS … - FSTYPE SOURCE SUPEROPTIONS"
                let (left, right) = line.split_once(" - ")?;
                let mut left = left.split_whitespace();
                left.next()?; // mount ID
                left.next()?; // parent ID
                left.next()?; // device major:minor
                left.next()?; // root of the mount within the filesystem
                let mountpoint = left.next()?;
                let mut right = right.split_whitespace();
                if right.next()? != "cgroup2" {
                    return None;
                }
                right.next()?; // source
                let superoptions = right.next().unwrap_or_default();
                let nsdelegate = superoptions.split(',').any(|option| option == "nsdelegate");
                Some((PathBuf::from(mountpoint), nsdelegate))
            })
            .collect()
    }

    /// The cgroup2 mount that decides where a tree named `root` actually
    /// lives: the deepest one containing it, with whether that mount treats
    /// cgroup namespaces as delegation boundaries (`nsdelegate`). A `root`
    /// under no cgroup2 mount is not a cgroup tree at all — plain
    /// directories, whose `cgroup.procs` moves nothing.
    ///
    /// Pure over its input, so the daemon can refuse exactly the hosts whose
    /// "tree" decides nothing and a test can pin the shape it refuses.
    #[must_use]
    pub fn cgroup2_covering(root: &Path, mountinfo: &str) -> Option<(PathBuf, bool)> {
        host_cgroup2_mounts(mountinfo)
            .into_iter()
            .filter(|(mountpoint, _)| root.starts_with(mountpoint))
            // Two mounts can both contain `root` (a nested overmount); the
            // deeper one is the one the tree actually sits on.
            .max_by_key(|(mountpoint, _)| mountpoint.components().count())
    }

    /// Whether the classifier tree at `root` can decide a box's verdict on
    /// this host: the tree must sit on a cgroup2 mount — a directory tree
    /// anywhere else is plain directories, and a box "placed" there is
    /// unenforced while looking placed — and in a guest, where this daemon is
    /// pid 1 and its own boot path is the only thing that could have mounted
    /// that cgroup2, the mount must carry `nsdelegate`: a guest tree without
    /// namespace delegation is a broken image, not a deployment state
    /// (design §7.1).
    ///
    /// Natively a tree on a cgroup2 mounted without `nsdelegate` still
    /// counts: the privileged step refuses to install one there, so a tree
    /// that exists anyway was built by hand, and the confinement does not
    /// rest on the host's mount options alone — see [`Self`]'s placement
    /// order. Pure over its inputs, so the exact hosts a daemon must run
    /// unenforced on — or refuse, in the guest — are pinned by a test.
    #[must_use]
    pub fn tree_is_real(root: &Path, mountinfo: Option<&str>, guest: bool) -> bool {
        match mountinfo.and_then(|mi| cgroup2_covering(root, mi)) {
            Some((_, true)) => true,
            Some((_, false)) => !guest,
            None => false,
        }
    }

    /// This host's mount table, as [`cgroup2_covering`] and
    /// [`host_cgroup2_mounts`] read it. `None` where it cannot be read — a
    /// host whose mount table cannot be read has no cgroup2 to build a tree
    /// on either.
    #[must_use]
    pub fn own_mountinfo() -> Option<String> {
        std::fs::read_to_string("/proc/self/mountinfo").ok()
    }
}

/// Install the box's classifier placement, credentials — and, for a none box,
/// its seccomp-BPF filter — into a hakoniwa command as a program-closure.
///
/// The closure runs after namespaces and credentials are configured but before
/// the supervised program execs, which is the correct moment for all three.
/// For a box with a classifier leaf it joins the leaf, unshares the cgroup
/// namespace onto it, and covers the tree the join went through — with the
/// design's read-only cgroup2 mount of the namespace root, or the recorded
/// tmpfs fallback where the kernel refuses that mount; it takes the box's
/// credentials, loads the `&'static` seal filter the `Container` holds, and
/// then execs the original program, since
/// `command_from_closure` otherwise replaces the program entirely.
///
/// `command_from_closure` starts a fresh `Command`, so the working directory
/// and environment already set on `command` are carried over to it: hakoniwa
/// `chdir`s and rebuilds the child's `environ` from the command it spawns, and
/// the exec in the closure inherits both.  Whatever a caller sets on the
/// returned command afterwards (`SHELL`, `PS1`, stdio) lands on the closure
/// command and reaches the program the same way.
#[cfg(target_os = "linux")]
fn install_box_credentials(
    container: &hakoniwa::Container,
    command: &mut hakoniwa::Command,
    socket_family_filter: &'static SocketFamilyFilter,
    classifier_leaf: Option<config::ClassifierLeaf>,
    force_cover_fallback: bool,
) -> Result<(), Error> {
    let program = command.get_program().to_string();
    let args = command.get_args();
    let current_dir = command.get_current_dir().map(Path::to_path_buf);
    let envs = command.get_envs();
    // The leaf's `cgroup.procs` as the box itself will spell it: through the
    // tree the sandbox bound at the conventional mountpoint, the only place
    // the leaf is reachable from inside the box. The write happens before the
    // cgroup namespace is unshared, and the cover mounted over the tree
    // afterwards leaves no spelling of another leaf at all — so this is also
    // the last spelling of *this* leaf that ever opens for a migration.
    let classifier_join = classifier_leaf.map(|leaf| {
        Path::new(classifier::CONVENTIONAL_CGROUP2_MOUNTPOINT)
            .join(leaf.relative_dir())
            .join("cgroup.procs")
    });
    // The closure's report file, in the sandbox's read-write `/run`, named by
    // the leaf so two sessions never share one: the closure knows the leaf
    // only as the `cgroup.procs` it joins, so the name is derived from that
    // path here, and the daemon derives the same name from the leaf
    // directory it created — see [`Sandbox::closure_report_path`], the
    // host-side twin.
    let closure_report = classifier_join.as_deref().and_then(|procs| {
        procs
            .parent()
            .and_then(Path::file_name)
            .and_then(std::ffi::OsStr::to_str)
            .map(|box_id| Path::new("/run").join(classifier::closure_report_name(box_id)))
    });
    // SAFETY: `command_from_closure` is unsafe because the closure runs in a
    // forked child.  `socket_family_filter` is `&'static`: it is one of the
    // process-wide `OnceLock` values, owned for the process's whole life, so
    // it outlives every command spawned from the container.  The closure is
    // not async-signal-safe: it allocates after the fork (the argv `CString`s,
    // a failure message), in kind with hakoniwa's own closure path, which
    // `format!`s its panic report at the same point.  The child is
    // single-threaded, so no allocator lock can be held across the fork.  The
    // closure never returns: it execs, or `_exit`s.
    let mut closure = unsafe {
        container.command_from_closure(move || {
            exec_box_program(
                &program,
                &args,
                socket_family_filter,
                classifier_join.as_deref(),
                force_cover_fallback,
                closure_report.as_deref(),
            )
        })
    };
    if let Some(dir) = current_dir {
        closure.current_dir(dir);
    }
    closure.envs(envs);
    *command = closure;
    Ok(())
}

/// Writes the one line the box's pre-exec closure reports into the sandbox's
/// read-write `/run` — the one directory the box and the daemon share — so
/// the daemon can say, after the spawn, what nothing else can carry: which
/// cover the box took over its classifier tree, or the errno that killed the
/// closure before the program ran (the `127` the spawn then reports, whose
/// stderr reaches only the box's own stdio, never a daemon log). Each write
/// replaces the line wholesale, so a closure that covered and then failed
/// leaves the failure — the line worth reading is the one that says the box
/// never reached its program — and the daemon holds the file until the box's
/// fate is known, so a failure that lands after a cover line is still the
/// line it logs.
///
/// The line appears whole or not at all: `fs::write` creates the report
/// empty before it fills it, and a reader that caught that window would log
/// an empty line and take the file away before the real one landed. A temp
/// file beside the report, renamed over it, leaves no such window —
/// `rename(2)` is atomic, and the temp sits in the same directory, the one
/// read-write `/run` both sides share.
///
/// Best-effort by design: a box that cannot say what it did still runs, and
/// the daemon says so when the report never appears.
#[cfg(target_os = "linux")]
fn write_closure_report(report: Option<&Path>, line: &str) {
    let Some(report) = report else { return };
    let name = report
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .unwrap_or("closure-report");
    let temp = report.with_file_name(format!("{name}.tmp{}", std::process::id()));
    let written =
        std::fs::write(&temp, format!("{line}\n")).and_then(|()| std::fs::rename(&temp, report));
    // A rename that failed leaves the line nowhere — the state the daemon's
    // watch already names — so the temp never lingers either.
    if written.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
}

/// Marks the cover the box took in its own environment
/// (`MINIMAL_CLASSIFIER_COVER`: the design's `cgroup2`, or the recorded
/// `tmpfs-fallback`) — the box-visible half of the fallback being recorded
/// at all: a process inside the box can learn which it runs under, which is
/// the question a cgroup-aware runtime in the box would ask first.
///
/// `setenv(3)` mutates this forked child's own `environ`, which the `execv(3)`
/// below hands to the program, so the marker reaches everything the box
/// execs after it.
#[cfg(target_os = "linux")]
fn set_box_cover_marker(cover: &'static str) {
    // A `&str` carries no NUL of its own, so the value is rebuilt as a
    // `CString` first: `setenv(3)` reads to the terminator, and a bare
    // `as_ptr()` would read past the literal into whatever rodata sits
    // behind it.
    let cover = std::ffi::CString::new(cover).expect("the cover name has no NUL in it");
    // SAFETY: `setenv(3)` with NUL-terminated literal name and value; it
    // allocates, which this closure's contract already allows (see
    // `install_box_credentials`).
    unsafe {
        libc::setenv(c"MINIMAL_CLASSIFIER_COVER".as_ptr(), cover.as_ptr(), 1);
    }
}

/// The body of the launch closure in [`install_box_credentials`]: place the
/// box in its classifier leaf, cover the tree the join went through, take
/// the box's credentials, install the box's socket-family seal, then exec
/// the program the caller asked for.  Never returns; a failure is reported
/// on the child's stderr, into the closure's report file, and exits the
/// child with the shell's "cannot run" status.
///
/// Split out of the closure so each unsafe operation sits in its own block
/// rather than inheriting the one around `command_from_closure`.
#[cfg(target_os = "linux")]
fn exec_box_program(
    program: &str,
    args: &[String],
    socket_family_filter: &'static SocketFamilyFilter,
    classifier_join: Option<&Path>,
    force_cover_fallback: bool,
    closure_report: Option<&Path>,
) -> ! {
    // The box's classifier leaf (NET-079), taken in the order the
    // confinement rests on: join first, *then* unshare the cgroup namespace,
    // so its root is the leaf the process just entered — the box's own view
    // of the hierarchy starts at the one cgroup its verdict is decided on.
    // The join is the last act that still runs in the daemon's namespaces,
    // where the tree the sandbox bound resolves; what covers that bind once
    // the join has run is what keeps the host's cgroup mount out of the
    // box's mount namespace — the design's own cgroup2 view of the
    // namespace root, or the recorded tmpfs fallback below. Failures exit
    // the child: a box that cannot take the leaf its verdict is decided on
    // must not run.
    if let Some(procs) = classifier_join {
        if let Err(e) = classifier::place_pid(procs, std::process::id()) {
            exit_child("joining the box's classifier leaf", &e, closure_report);
        }
        // SAFETY: `unshare(2)` with the cgroup-namespace flag only;
        // async-signal-safe.
        if unsafe { libc::unshare(libc::CLONE_NEWCGROUP) } == -1 {
            exit_child(
                "unsharing the cgroup namespace onto the box's leaf",
                &std::io::Error::last_os_error(),
                closure_report,
            );
        }
        let target = std::ffi::CString::new(classifier::CONVENTIONAL_CGROUP2_MOUNTPOINT)
            .expect("the cgroup mountpoint has no NUL in it");
        // The cover the design asks for (architecture, *Box Resources*): a
        // read-only cgroup2 mount of the namespace root — the box's own
        // leaf, the cgroup its verdict is decided on — at the one place a
        // cgroup-aware runtime looks. No data string, and the box's user
        // namespace still holds CAP_SYS_ADMIN over this mount namespace, so
        // the mount is the box's own to make. Inside it the box reads its
        // own limit where a runtime looks for it (`memory.max`) and reaches
        // no cgroup but its own: a sibling leaf is not below the namespace
        // root and its path does not resolve, and the read-only mount (with
        // `nsdelegate` on the host's side) leaves the root's own
        // `cgroup.procs` unwritable, which is what makes leaving the leaf —
        // let alone joining another box's — impossible.
        //
        // Where the kernel refuses that mount, the recorded fallback covers
        // the bind with an empty read-only tmpfs instead: the host's cgroup
        // mount still stays out of the box's mount namespace and no process
        // the box runs is left a cgroup path to write a migration to, at
        // the cost of the box reading no limit of its own either. That
        // trade is why the fallback is *recorded* — reported through
        // `/run` for the daemon to warn, marked in the box's environment —
        // and never passed off as the design's cover. The fallback failing
        // too is fatal, and not only in kind: a leaf-bearing box whose
        // cover never came would keep the tree bind, writable, in its mount
        // namespace.
        let mut refused: Option<String> = None;
        if force_cover_fallback {
            // The test knob: the fallback branch, deterministically.
            refused = Some("forced".to_string());
        } else {
            // SAFETY: `mount(2)` with valid C strings and no data; the
            // cgroup2 view of a namespace root takes no options.
            // Async-signal-safe.
            if unsafe {
                libc::mount(
                    c"cgroup2".as_ptr(),
                    target.as_ptr(),
                    c"cgroup2".as_ptr(),
                    libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
                    std::ptr::null(),
                )
            } == -1
            {
                let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
                refused = Some(format!("errno {errno}"));
            } else {
                write_closure_report(closure_report, "cover cgroup2");
                set_box_cover_marker("cgroup2");
            }
        }
        if let Some(why) = refused {
            write_closure_report(closure_report, &format!("cover tmpfs-fallback {why}"));
            set_box_cover_marker("tmpfs-fallback");
            // SAFETY: `mount(2)` as above, with tmpfs, which takes no
            // options but the flags (an empty one is all the cover needs).
            if unsafe {
                libc::mount(
                    c"minimald-classifier-cover".as_ptr(),
                    target.as_ptr(),
                    c"tmpfs".as_ptr(),
                    libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
                    std::ptr::null(),
                )
            } == -1
            {
                exit_child(
                    "covering the bound classifier tree with the recorded \
                     fallback tmpfs",
                    &std::io::Error::last_os_error(),
                    closure_report,
                );
            }
        }
    }
    // SAFETY: `assume_box_credentials` is async-signal-safe; this is the
    // pre-exec moment it is for, with the namespace built and CAP_SETPCAP in
    // it still held.
    if let Err(e) = unsafe { assume_box_credentials() } {
        exit_child("taking the box credentials", &e, closure_report);
    }
    {
        // SAFETY: `install_socket_family_filter` is async-signal-safe, and
        // `socket_family_filter` is `&'static`, so it stays valid for the call.
        if let Err(e) = unsafe { install_socket_family_filter(socket_family_filter) } {
            exit_child("installing the socket-family filter", &e, closure_report);
        }
    }
    // `command_from_closure` replaces the program with this closure; exec
    // into the real program so the spawn runs what the caller asked for, now
    // with the box's credentials and its socket-family seal in place.
    let e = execv_in_child(program, args);
    exit_child(&format!("exec {program}"), &e, closure_report)
}

/// Takes the credentials every box process execs with: sets `no_new_privs`,
/// drops each capability no box may hold
/// ([`config::BOX_FORBIDDEN_CAPABILITIES`]) from the bounding set, clears the
/// remaining capability sets, and switches to the box uid and gid
/// ([`config::BOX_UID`], [`config::BOX_GID`]).
///
/// The bounding set is the one capability set an exec does not clear, so a
/// capability dropped from it can never be granted back — not by the process
/// once it holds no capabilities, and not by a file capability or a setuid
/// bit, which `no_new_privs` makes the kernel ignore at exec. The other sets
/// are cleared here too, so the program that execs next holds no capability at
/// all whatever the daemon's own credential state was.
///
/// The caller must still hold `CAP_SETPCAP` in the user namespace it is about
/// to exec in — the drops need it — and `CAP_SETUID`/`CAP_SETGID` unless the
/// box ids are already its own. Both hold for the two call sites: the launch
/// path runs this in its pre-exec closure, where the process has just created
/// the box's user namespace and therefore holds every capability in it, and
/// `nsenter` runs it after joining a box's user namespace, which grants the
/// joiner the same.
///
/// # Safety
///
/// Only async-signal-safe syscalls (`prctl`, `capset`, `setgid`, `setuid`) are
/// used, so this is safe to call from a pre-exec closure; it is `unsafe`
/// because it takes over the calling process's credentials.
#[cfg(target_os = "linux")]
pub unsafe fn assume_box_credentials() -> std::io::Result<()> {
    // no_new_privs, first: nothing that follows, and no file the box execs
    // later, can grant a privilege the process does not already hold.
    // SAFETY: prctl with valid arguments; async-signal-safe.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } == -1 {
        return Err(std::io::Error::last_os_error());
    }

    // The bounding set, dropped while CAP_SETPCAP is still held: it survives
    // exec, so it is the only set that has to be dropped rather than cleared.
    for cap in config::BOX_FORBIDDEN_CAPABILITIES {
        // SAFETY: prctl with valid arguments; async-signal-safe.
        if unsafe {
            libc::prctl(
                libc::PR_CAPBSET_DROP,
                libc::c_ulong::from(cap.number),
                0,
                0,
                0,
            )
        } == -1
        {
            return Err(std::io::Error::last_os_error());
        }
    }

    // Every other set, cleared by hand: exec recomputes them empty for a
    // process that is not root in its user namespace and carries no file
    // capabilities, but doing it here makes that hold by construction instead
    // of resting on the uid and the no_new_privs bit staying as they are.
    clear_capability_sets()?;

    // The box uid and gid, last: both resolve through the namespace's map onto
    // the daemon's own ids, so this asserts the identity the box's rootfs and
    // its plan describe, and fails the launch rather than exec a box that is
    // someone else.
    // SAFETY: setgid with a valid id; async-signal-safe.
    if unsafe { libc::setgid(config::BOX_GID) } == -1 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: setuid with a valid id; async-signal-safe.
    if unsafe { libc::setuid(config::BOX_UID) } == -1 {
        return Err(std::io::Error::last_os_error());
    }

    Ok(())
}

/// Clears this process's inheritable, permitted and effective capability sets
/// with one `capset(2)`, and its ambient set with `PR_CAP_AMBIENT_CLEAR_ALL`.
/// Dropping capabilities needs no privilege, so this works for a process that
/// holds none.
///
/// The kernel's `capset` payload is plain `u32` words: an 8-byte header
/// (`version`, `pid`) followed by two 12-byte structs of (`effective`,
/// `permitted`, `inheritable`), the second covering capabilities 32..63. They
/// are spelled here as arrays rather than `repr(C)` structs so the layout is
/// fixed by construction.
#[cfg(target_os = "linux")]
fn clear_capability_sets() -> std::io::Result<()> {
    const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;
    let header = [LINUX_CAPABILITY_VERSION_3, 0];
    let data = [0; 6];
    // SAFETY: capset reads the header and the zeroed data words, both of which
    // outlive the call; it is async-signal-safe.
    if unsafe { libc::syscall(libc::SYS_capset, header.as_ptr(), data.as_ptr()) } == -1 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: prctl with valid arguments; async-signal-safe, and clearing the
    // ambient set needs no privilege either.
    if unsafe {
        libc::prctl(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_CLEAR_ALL,
            0,
            0,
            0,
        )
    } == -1
    {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Exec into `program` with `args` from the forked child of a hakoniwa
/// `command_from_closure` closure; returns only when the exec failed.  The
/// environment is not passed explicitly: `execv` hands the program the
/// `environ` hakoniwa rebuilt from the command's final `envs` just before
/// running the closure.
#[cfg(target_os = "linux")]
fn execv_in_child(program: &str, args: &[String]) -> std::io::Error {
    let argv_c: Result<Vec<std::ffi::CString>, _> = std::iter::once(program)
        .chain(args.iter().map(String::as_str))
        .map(std::ffi::CString::new)
        .collect();
    let argv_c = match argv_c {
        Ok(argv) => argv,
        Err(_) => return std::io::Error::from_raw_os_error(libc::EINVAL),
    };
    let mut argv_ptrs: Vec<*const libc::c_char> = argv_c.iter().map(|s| s.as_ptr()).collect();
    argv_ptrs.push(std::ptr::null());

    // SAFETY: execv only touches the C strings we just built, which `argv_c`
    // keeps alive for the call.
    unsafe { libc::execv(argv_c[0].as_ptr(), argv_ptrs.as_ptr()) };
    // execv returns only on failure.
    std::io::Error::last_os_error()
}

/// Reports a failure of the forked child on its stderr and exits it with 127,
/// the shell's "cannot run" status, so a spawn that never reached the program
/// is distinguishable from the program's own exit codes.  The failure is
/// reported into the closure's report file first, with its errno: the box's
/// stderr is the session's own stdio, so without that line a `127` reaches no
/// daemon log at all.  Called after the fork, so it uses `write(2)` and
/// `_exit(2)` rather than the Rust stdio and exit machinery.
#[cfg(target_os = "linux")]
fn exit_child(what: &str, err: &std::io::Error, report: Option<&Path>) -> ! {
    write_closure_report(
        report,
        &format!("failed {what} errno {}", err.raw_os_error().unwrap_or(0)),
    );
    let msg = format!("minimal: sandbox: {what} failed: {err}\n");
    // SAFETY: `write` and `_exit` are async-signal-safe; `msg` outlives the
    // write, and `_exit` does not return.
    unsafe {
        libc::write(libc::STDERR_FILENO, msg.as_ptr().cast(), msg.len());
        libc::_exit(127)
    }
}

/// Options for [`Sandbox::bind_mount`].
#[derive(Debug, Default, Clone, Copy)]
#[cfg(target_os = "linux")]
struct BindOpts {
    read_only: bool,
    recursive: bool,
}

// Sandbox usage
#[cfg(target_os = "linux")]
impl<C: Channel> Sandbox<C> {
    fn bind_mount(
        path: &Path,
        container_path: &str,
        opts: BindOpts,
        container: &mut hakoniwa::Container,
    ) -> Result<(), Error> {
        let mut flags = hakoniwa::MountOptions::BIND
            | hakoniwa::MountOptions::NOSUID
            | locked_mount_flags(path);
        if opts.recursive {
            flags |= hakoniwa::MountOptions::REC;
        }
        if opts.read_only {
            flags |= hakoniwa::MountOptions::RDONLY;
        }
        container.mount(
            path.to_str().ok_or_else(|| {
                Error::Execution(ExecutionError::MountError {
                    msg: "Unable to convert path to unicode string",
                    path: path.to_path_buf(),
                })
            })?,
            container_path,
            "",
            flags,
        );
        Ok(())
    }

    /// The network plan this sandbox's own configuration implies: its
    /// [`plan`](config::Config::plan), carrying the host resolver when
    /// [`setup_dns_config`](config::Config::setup_dns_config) asks for one.
    #[must_use]
    pub fn built_in_plan(&self) -> network::NetPlan {
        plan_from_config(&self.config)
    }

    /// Step 1 of a launch: ask the provider what this sandbox needs. A sandbox
    /// with no provider is planned by its own configuration, through the same
    /// sequence. From here the plan's release is owed; see [`PlannedLaunch`].
    ///
    /// Not an `async fn`: that would hold `&Sandbox<C>` across the await and
    /// impose `C: Sync` on every caller's future, which the build path does
    /// not satisfy.
    ///
    /// # Errors
    ///
    /// Propagates the provider's planning failure.
    pub fn plan_launch(
        &self,
    ) -> impl Future<Output = Result<PlannedLaunch, Error>> + Send + 'static {
        let network = self
            .config
            .network
            .clone()
            .unwrap_or_else(|| std::sync::Arc::new(self.built_in_plan()));
        PlannedLaunch::begin(network)
    }

    /// Builds the hakoniwa [`Container`] for this sandbox, configured for
    /// `plan`.
    ///
    /// Spawning this container (`Command::spawn`) does a bare in-process `fork()`
    /// on the calling thread and arms `PR_SET_PDEATHSIG(SIGKILL)`, tying the
    /// child's lifetime to that thread. See [`run_with_cancel`](Self::run_with_cancel)
    /// for the thread-affinity constraints this imposes on callers.
    #[cfg(target_os = "linux")]
    pub fn new_container(&self, plan: &network::NetPlan) -> Result<Container, Error> {
        let mut container = hakoniwa::Container::new();
        container
            .rootfs(self.rootfs())
            .unwrap()
            // The box's uid and gid inside its user namespace, mapped onto the
            // daemon's own. Every box execs as this unprivileged uid with
            // no_new_privs set, so the kernel clears its capability sets at
            // exec; see `assume_box_credentials` for what the launch applies
            // on top of the map, and `config::BOX_UID` for why this uid.
            .uidmap(config::BOX_UID)
            .gidmap(config::BOX_GID)
            .devfsmount("/dev")
            .tmpfsmount("/tmp")
            .runctl(hakoniwa::Runctl::IgnoreCgroupSetupFailed);

        // The cgroup namespace, whose root decides what the box can ever
        // reach. A box with no classifier leaf takes it here, in the one
        // `unshare()` every namespace goes through: its root is then the
        // cgroup its forking parent sits in — the daemon's leaf, which has
        // no children, and on a host with no per-box classifier is the
        // whole of the confinement. A box *with* a leaf does not unshare it
        // here: the pre-exec closure joins the leaf first and unshares the
        // namespace second, so the root is the leaf itself (see
        // `exec_box_program`) — and the tree the join writes through has to
        // be bound into the box while the process still sits in the
        // daemon's namespaces, where the tree's paths resolve.
        if self.config.classifier_leaf.is_none() {
            container.unshare(hakoniwa::Namespace::Cgroup);
        }

        // Every box's launch posture (NET-083), applied by the pre-exec
        // closure on every command spawned from this container: exec as the
        // unprivileged box uid with no_new_privs set — so the kernel clears
        // every capability set at exec and ignores any file capability or
        // setuid bit — with the capabilities no box may hold dropped from the
        // bounding set, the one set an exec does not clear, so they cannot
        // come back. Logged once per launch, so a diagnostics bundle's daemon
        // log tail carries the posture the box was launched with.
        tracing::info!(
            uid = config::BOX_UID,
            gid = config::BOX_GID,
            no_new_privs = true,
            cleared_sets = "inheritable,permitted,effective,ambient",
            bounding_set_dropped = %config::forbidden_capability_names(),
            "sandbox launch: box execs as the box uid with no capability a box may not hold"
        );

        // The box's classifier leaf (NET-079): the cgroup its egress verdict
        // is decided on, and the one every process of the box must stay in.
        // The tree the leaf belongs to is bound at the conventional cgroup
        // mountpoint, so the box's own pre-exec closure can write its way
        // into the leaf — the one migration primitive the whole placement
        // rests on — and the closure then covers the bind with a read-only
        // cgroup2 mount of the box's own namespace root, or with an empty
        // read-only tmpfs where the kernel refuses that mount, so the
        // host's cgroup mount stays out of the box's mount namespace either
        // way. The host's own cgroup2 mount is never bound into the box.
        if let Some(leaf) = self.config.classifier_leaf.clone() {
            let mountpoint = classifier::CONVENTIONAL_CGROUP2_MOUNTPOINT;
            let in_rootfs = self.rootfs().join(
                Path::new(mountpoint)
                    .strip_prefix("/")
                    .unwrap_or(Path::new(mountpoint)),
            );
            std::fs::create_dir_all(&in_rootfs).map_err(|e| {
                Error::IO(
                    "creating the cgroup mountpoint in the box rootfs",
                    in_rootfs,
                    e,
                )
            })?;
            Self::bind_mount(
                &leaf.tree_root(),
                mountpoint,
                BindOpts {
                    read_only: false,
                    recursive: true,
                },
                &mut container,
            )?;

            // What the host's mount table says about cgroup2, for the launch
            // log. The line's own claim is the hiding: none of these mounts
            // is the box's to see — the tree bound for the join is the only
            // cgroup2 the box is ever given, and it is covered over once the
            // join has run — and which of them carries `nsdelegate` is what a
            // diagnostics bundle would look for first (the confinement holds
            // without it; its absence is the first thing to rule out).
            //
            // The cover branch is not this line's to name: the line is
            // written before the box's pre-exec closure runs, and which
            // cover the closure took — the design's cgroup2 view of the
            // box's own namespace root, or the recorded tmpfs where the
            // kernel refuses that mount — is the closure's own report into
            // `/run`, which the daemon's watch logs and warns about when no
            // report comes.
            let mountinfo = classifier::own_mountinfo().unwrap_or_default();
            let host_mounts = classifier::host_cgroup2_mounts(&mountinfo);
            let named = if host_mounts.is_empty() {
                "none on this host".to_string()
            } else {
                host_mounts
                    .iter()
                    .map(|(mountpoint, nsdelegate)| {
                        format!(
                            "{}{}",
                            mountpoint.display(),
                            if *nsdelegate { " (nsdelegate)" } else { "" }
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            tracing::info!(
                leaf = %leaf.dir().display(),
                join_procs = %Path::new(mountpoint).join(leaf.relative_dir()).join("cgroup.procs").display(),
                host_cgroup_mount = %format!("hidden from the box: {named}"),
                "sandbox launch: box joins its classifier leaf before its \
                 cgroup namespace is unshared onto it"
            );
        }

        // Network isolation (R1.4/R1.7). An isolating plan gets a fresh network
        // namespace with only a down `lo`; wiring it is the provider's job,
        // after the process exists. Unlike the cgroup-setup fallback above this
        // is a *security* boundary, so it fails closed when the host cannot
        // make the namespace (spec R1.2).
        let isolate = isolation_decision(plan, network_namespaces_available())?;
        if isolate {
            container.unshare(hakoniwa::Namespace::Network);
        }

        // Socket-family seal for every plan. A fresh network namespace blocks
        // IP/UNIX flows, but AF_VSOCK is not subject to the network namespace,
        // so a process in any box could still reach the host over vsock.  The
        // seal is an allowlist: the `none` plan's seal admits AF_UNIX alone,
        // and every other plan's seal admits the families the box's own
        // network namespace confines, so a family that reaches past the
        // namespace is refused in every box.  The filter is installed in the
        // child after hakoniwa has set up namespaces and credentials but
        // before exec, using `prctl` + `seccomp` via libc only.  A caller on a
        // foreign ABI — a 32-bit binary on an x86_64 host, say — dies with
        // SIGSYS on its first syscall in every box; the family list names
        // native-ABI calls only.
        #[cfg(target_os = "linux")]
        let socket_family_filter = {
            let filter = socket_family_filter_for_plan(plan);
            tracing::info!(
                network_plan = %plan,
                socket_seal = %filter.seal,
                refusing = filter.refused_families,
                "sandbox launch: box sealed against the socket families its namespace does not confine"
            );
            filter
        };

        // Have hakoniwa create + configure the TAP inside the sandbox's user+net
        // namespace (rootless). `network()` does not imply the netns unshare,
        // so it must follow the `unshare` above — which a tap-carrying plan
        // guarantees, since `NetPlan` cannot describe a tap without isolation.
        if let Some(tap) = plan.tap() {
            container.network(
                hakoniwa::RustSlirp::default()
                    // L2: the gvproxy relay is HyperKit-framed Ethernet, not L3.
                    .mode(hakoniwa::RustSlirpMode::TAP)
                    .address(tap.address)
                    .netmask(tap.netmask)
                    // Next-hop default route (`0.0.0.0/0 via gateway`); gvproxy is a
                    // real gateway and does not proxy-ARP, so an on-link route fails.
                    .gateway(hakoniwa::RustSlirpGateway::IfaceWithAddr(tap.gateway))
                    .mtu(tap.mtu)
                    .clone(),
            );
        }

        let rec = BindOpts {
            recursive: true,
            read_only: false,
        };
        Self::bind_mount(&self.state_dir, "/state", rec, &mut container)?;
        Self::bind_mount(&self.base_dir.join("run"), "/run", rec, &mut container)?;

        // MINIMAL_INTERNAL_CS_BUILD: undocumented bundle of behaviors
        // needed for running minimal as a library inside a GCP
        // Confidential Space workload. Not for general callers; we
        // expose it as a private "I am the trusted CS builder" flag so
        // it can't accidentally enable non-hermetic behavior in normal
        // `minimal package <pkg>` invocations.
        //
        // What the bundle does:
        //
        // 1. Bind-mount the outer /proc into the sandbox + enable
        //    Runctl::MountFallback. CS workload containers get OCI
        //    MaskedPaths (containerd's default — tmpfs over
        //    /proc/{kcore,scsi,keys,...}). The Linux kernel's
        //    anti-unmask guard then refuses any nested procfsmount
        //    over a masked parent, so hakoniwa's implicit
        //    `Container::new()::procfsmount("/proc")` returns EPERM.
        //    Workaround: bind the outer (already-masked) /proc instead
        //    of trying to mount a fresh procfs. The MountFallback
        //    runctl is required for the same reason — hakoniwa emits
        //    a mandatory MS_REMOUNT after every bind, which also
        //    fails on the masked /proc until we let it retry with the
        //    source mount's existing flags.
        //
        //    Caveat (noted by @twitchyliquid64 on the PR): MountFallback
        //    is a container-global runctl, not per-mount. It applies
        //    to every bind in the sandbox — a sandbox that wanted to
        //    assert e.g. NOEXEC on a target may silently end up with
        //    the source's existing flags instead. Acceptable inside
        //    the CS attested boundary where outer isolation handles
        //    the actual security property; the inner hakoniwa is for
        //    build-script reproducibility, not isolation. Filed
        //    upstream to see if hakoniwa would accept a per-mount
        //    runctl that would let us scope this to /proc only.
        //
        // 2. (Cache delivery for hermetic-builder's ecosystem caches —
        //    cargo-vendor, npm-cache, pnpm-store, bun-cache,
        //    pip-wheels, rust-stage0, goproxy — happens in Sandbox::new
        //    via hardlink_dir_contents from the convention path
        //    /root/.cache/minimal/cs-mirror/. Earlier iteration of
        //    this PR used /state/cs-mirror-pointing symlinks here,
        //    but /state inside each sandbox is per-build state, not
        //    shared with the orchestrator's outer state_dir, so the
        //    symlinks pointed at unreachable paths. The hardlink
        //    mechanism (matching the old extra_rootfs behavior) does
        //    the right thing without expanding public API surface.)
        //
        // Inert when the env var is unset; default `minimal package`
        // invocations see no behavior change.
        if std::env::var("MINIMAL_INTERNAL_CS_BUILD").as_deref() == Ok("1") {
            container.bindmount_rw("/proc", "/proc");
            container.runctl(hakoniwa::Runctl::MountFallback);
            // Cache delivery (cargo-vendor, npm-cache, ...) is handled
            // by the hardlink_dir_contents call in Sandbox::new — see
            // lib.rs near line ~105. Earlier iteration of this PR
            // used /state/<...>-pointing symlinks here, but /state
            // inside each sandbox is per-build state (created via
            // base_dir.join("state") in Sandbox::new), not shared with
            // the orchestrator's outer state_dir, so the symlinks
            // pointed at unreachable paths. The hardlink mechanism
            // replaces them.
        }

        if self.needs_bin_symlink()? {
            container.symlink("/usr/bin", "/bin");
        }
        if self.needs_lib64_symlink()? {
            container.symlink("/usr/lib", "/lib64");
        }
        if self.needs_lib_symlink()? {
            container.symlink("/usr/lib", "/lib");
        }

        // Mount in the working directory
        match &self.config.wd {
            WdSetup::Isolated { .. } => {
                Self::bind_mount(&self.base_dir.join("build"), "/build", rec, &mut container)?;
            }
            WdSetup::BoundDir {
                path, read_only, ..
            } => {
                let sandbox_cwd = self.config.wd.bound_dir_sandbox_cwd();
                let sandbox_cwd = sandbox_cwd.to_str().ok_or_else(|| {
                    Error::IO(
                        "bound-dir cwd is not valid UTF-8",
                        sandbox_cwd.to_path_buf(),
                        std::io::Error::new(std::io::ErrorKind::InvalidInput, "non-UTF-8 path"),
                    )
                })?;
                let container_path = format!("/{sandbox_cwd}");
                let opts = BindOpts {
                    recursive: true,
                    read_only: *read_only,
                };
                Self::bind_mount(path, &container_path, opts, &mut container)?;
            }
            WdSetup::Session {
                home,
                working,
                working_name_override,
            } => {
                // mount the given home path to /{SESSION_HOME}
                Self::bind_mount(
                    home,
                    &format!("/{SESSION_HOME}"),
                    BindOpts {
                        recursive: true,
                        read_only: false,
                    },
                    &mut container,
                )?;
                // mount the given working directory to /{SESSION_DEFAULT_WD} (unless overridden)
                Self::bind_mount(
                    working,
                    &format!(
                        "/{}",
                        working_name_override
                            .as_ref()
                            .cloned()
                            .unwrap_or_else(|| SESSION_DEFAULT_WD.to_string())
                    ),
                    BindOpts {
                        recursive: true,
                        read_only: false,
                    },
                    &mut container,
                )?;
            }
        }
        // Mount in any file mappings
        if let WdSetup::BoundDir { fs_mappings, .. } = &self.config.wd {
            for m in fs_mappings {
                let opts = BindOpts {
                    recursive: !m.is_file,
                    read_only: m.read_only,
                };
                Self::bind_mount(
                    Path::new(&m.host_path),
                    &m.path_in_sandbox(),
                    opts,
                    &mut container,
                )?;
            }
        }

        if let Some(hn) = &self.config.hostname {
            let etc_hostname = self.rootfs().join("etc").join("hostname");
            if !std::fs::exists(&etc_hostname)
                .map_err(|e| Error::IO("checking for /etc/hostname", etc_hostname.clone(), e))?
            {
                std::fs::write(&etc_hostname, format!("{}\n", hn))
                    .map_err(|e| Error::IO("writing /etc/hostname", etc_hostname.clone(), e))?;
            }
            container.unshare(hakoniwa::Namespace::Uts);
            container.hostname(hn);
        }

        // The resolver the plan names, written to the rootfs before spawn like
        // `/etc/hostname` above: hakoniwa binds `/etc` read-only from
        // `<rootfs>/etc`, so an in-sandbox write would hit a read-only fs.
        write_resolv_conf(&self.rootfs(), plan.resolver())?;
        // The plan's static hosts entries, written the same way — a name the
        // box's resolver does not know still answers from `/etc/hosts`.
        write_hosts(&self.rootfs(), plan.hosts())?;

        if let Some(s) = &self.config.cpu_weight
            && booted_with_systemd()
        {
            container.cgroups_resources({
                let mut resources = hakoniwa::cgroups::Resources::default();
                resources.cpu({
                    let mut cpu = hakoniwa::cgroups::Cpu::default();
                    cpu.shares(*s);
                    cpu
                });
                resources
            });
        }

        Ok(Container {
            container,
            socket_family_filter,
        })
    }

    /// Initializes a hakoniwa command structure.
    #[cfg(target_os = "linux")]
    pub fn command<I, ArgS, IE, EnvK, EnvV>(
        &mut self,
        container: &Container,
        program: &str,
        args: I,
        env_vars: IE,
    ) -> Result<hakoniwa::Command, Error>
    where
        I: IntoIterator<Item = ArgS>,
        ArgS: AsRef<str>,
        IE: IntoIterator<Item = (EnvK, EnvV)>,
        EnvK: AsRef<str>,
        EnvV: AsRef<str>,
    {
        let rootfs = self.rootfs();
        let mut program = program.to_string();

        // Add /usr/bin/ for commands that are not absolute, and don't shadow anything in cwd
        if !program.starts_with("/") {
            let cwd = match &self.config.wd {
                WdSetup::Isolated { .. } => self.base_dir.join("build"),
                WdSetup::BoundDir { path, .. } => path.clone(),
                WdSetup::Session { working, .. } => working.clone(),
            };
            let in_cwd = cwd.join(&program);
            let in_usr_bin = rootfs.join("usr/bin").join(&program);
            if !fs::exists(&in_cwd)
                .map_err(|e| Error::IO("checking program in cwd", in_cwd.clone(), e))?
                && fs::exists(&in_usr_bin)
                    .map_err(|e| Error::IO("checking program in usr/bin", in_usr_bin.clone(), e))?
            {
                program = format!("/usr/bin/{program}");
            }
        }

        container.command_inner(self, &program, args, env_vars)
    }

    /// Runs the invocations in the sandbox to completion.
    ///
    /// Delegates to [`run_with_cancel`](Self::run_with_cancel) — see its docs for
    /// the important thread-affinity constraint on the sandbox container.
    #[cfg(target_os = "linux")]
    pub async fn run<W1, W2>(
        &mut self,
        invocations: Vec<Invocation>,
        stdout_writer: Option<W1>,
        stderr_writer: Option<W2>,
    ) -> Result<(), Error>
    where
        W1: tokio::io::AsyncWrite + Unpin + Send,
        W2: tokio::io::AsyncWrite + Unpin + Send,
    {
        self.run_with_cancel(
            invocations,
            stdout_writer,
            stderr_writer,
            tokio_util::sync::CancellationToken::new(),
        )
        .await
    }

    /// Runs the invocations in the sandbox, killing the container if `cancel`
    /// fires.
    ///
    /// # Container lifetime (hakoniwa `PR_SET_PDEATHSIG`)
    ///
    /// The forked container arms `PR_SET_PDEATHSIG(SIGKILL)`, which Linux
    /// delivers when the forking *thread* exits, so every container is forked
    /// on the process-wide fork thread ([`forker::on_fork_thread`]) rather than
    /// on the caller's. That thread is never retired, so this future may be
    /// driven from any runtime thread, worker or blocking-pool; see the
    /// [`forker`] module docs for the failure the fork thread rules out.
    #[cfg(target_os = "linux")]
    pub async fn run_with_cancel<W1, W2>(
        &mut self,
        invocations: Vec<Invocation>,
        mut stdout_writer: Option<W1>,
        mut stderr_writer: Option<W2>,
        cancel: tokio_util::sync::CancellationToken,
    ) -> Result<(), Error>
    where
        W1: tokio::io::AsyncWrite + Unpin + Send,
        W2: tokio::io::AsyncWrite + Unpin + Send,
    {
        for (i, exec) in invocations.iter().enumerate() {
            if cancel.is_cancelled() {
                return Err(Error::Execution(ExecutionError::Cancelled));
            }

            // One launch per invocation: hakoniwa unshares per `spawn()`, so
            // each invocation has its own netns and needs its own plan.
            let planned = self.plan_launch().await?;
            let container = self.new_container(planned.plan())?;

            let mut cmd = self.command(&container, &exec.executable, &exec.args, &exec.envs)?;
            cmd.stderr(hakoniwa::Stdio::MakePipe);
            cmd.stdout(hakoniwa::Stdio::MakePipe);
            tracing::debug!("Executing: {} {}", &exec.executable, exec.args.join(" "));

            let mut child = forker::on_fork_thread(move || cmd.spawn())
                .map_err(|e| Error::Execution(ExecutionError::SpawnFailed(e)))?;

            // Step 3: wire this invocation's netns. Torn down explicitly once
            // the invocation completes (both arms).
            let net_guard = match planned
                .attach(network::Spawned::from_child(&mut child))
                .await
            {
                Ok(guard) => guard,
                Err(e) => {
                    // Attach failed after spawn: kill+reap the child so it
                    // doesn't outlive its sandbox (a `hakoniwa::Child` does
                    // not terminate on drop). `wait` runs regardless of
                    // `kill` (the process may have already exited).
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(e);
                }
            };

            // Take pipes from the child so threads can stream them into the stdout/stderr
            // files, as well as to the caller-provided writers if applicable.
            let child_stdout = child.stdout.take();
            let child_stderr = child.stderr.take();

            // Stdout thread — like stderr, capture a rolling tail of the
            // last ~4 KiB so the caller can include it in InvocationFailed
            // when a build script swallows its stderr (mesa's pip install
            // 2>/dev/null pattern) but emits the real diagnostic to stdout.
            let stdout_file = self.stdout.take();
            let (stdout_tx, mut stdout_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(32);
            let stdout_thread =
                std::thread::spawn(move || -> Result<(Option<fs::File>, Vec<u8>), Error> {
                    let mut file = stdout_file;
                    let mut tail = Vec::new();
                    if let Some(mut pipe) = child_stdout {
                        let mut buf = [0u8; 8192];
                        loop {
                            let n = pipe.read(&mut buf).map_err(|e| {
                                Error::IO("reading stdout pipe", Default::default(), e)
                            })?;
                            if n == 0 {
                                break;
                            }
                            if let Some(f) = file.as_mut() {
                                f.write_all(&buf[..n]).map_err(|e| {
                                    Error::IO("writing stdout", Default::default(), e)
                                })?;
                            }
                            tail.extend_from_slice(&buf[..n]);
                            if tail.len() > 8192 {
                                let start = tail.len() - 4096;
                                tail = tail[start..].to_vec();
                            }
                            // Ignore send errors: the receiver may have been dropped
                            // if the async writer errored, but we still drain the pipe.
                            let _ = stdout_tx.blocking_send(buf[..n].to_vec());
                        }
                        if let Some(f) = file.as_mut() {
                            f.flush()
                                .map_err(|e| Error::IO("flushing stdout", Default::default(), e))?;
                        }
                    }
                    if tail.len() > 4096 {
                        let start = tail.len() - 4096;
                        tail = tail[start..].to_vec();
                    }
                    Ok((file, tail))
                });

            // Stderr thread
            let stderr_file = self.stderr.take();
            let (stderr_tx, mut stderr_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(32);
            let stderr_thread =
                std::thread::spawn(move || -> Result<(Option<fs::File>, Vec<u8>), Error> {
                    let mut file = stderr_file;
                    let mut tail = Vec::new();
                    if let Some(mut pipe) = child_stderr {
                        let mut buf = [0u8; 8192];
                        loop {
                            let n = pipe.read(&mut buf).map_err(|e| {
                                Error::IO("reading stderr pipe", Default::default(), e)
                            })?;
                            if n == 0 {
                                break;
                            }
                            if let Some(f) = file.as_mut() {
                                f.write_all(&buf[..n]).map_err(|e| {
                                    Error::IO("writing stderr", Default::default(), e)
                                })?;
                            }
                            tail.extend_from_slice(&buf[..n]);
                            if tail.len() > 8192 {
                                let start = tail.len() - 4096;
                                tail = tail[start..].to_vec();
                            }
                            let _ = stderr_tx.blocking_send(buf[..n].to_vec());
                        }
                        if let Some(f) = file.as_mut() {
                            f.flush()
                                .map_err(|e| Error::IO("flushing stderr", Default::default(), e))?;
                        }
                    }
                    if tail.len() > 4096 {
                        let start = tail.len() - 4096;
                        tail = tail[start..].to_vec();
                    }
                    Ok((file, tail))
                });

            // Forward chunks from the channels to the optional async writers.
            use tokio::io::AsyncWriteExt;
            let stdout_fwd = async {
                while let Some(chunk) = stdout_rx.recv().await {
                    if let Some(w) = stdout_writer.as_mut() {
                        w.write_all(&chunk).await.map_err(|e| {
                            Error::IO("writing to stdout writer", Default::default(), e)
                        })?;
                    }
                }
                Ok::<(), Error>(())
            };
            let stderr_fwd = async {
                while let Some(chunk) = stderr_rx.recv().await {
                    if let Some(w) = stderr_writer.as_mut() {
                        w.write_all(&chunk).await.map_err(|e| {
                            Error::IO("writing to stderr writer", Default::default(), e)
                        })?;
                    }
                }
                Ok::<(), Error>(())
            };

            // Race the forwarding against cancellation. When cancelled, kill the
            // child process — this closes its pipes, which unblocks the reader
            // threads, which drop the senders, which completes the fwd futures.
            tokio::select! {
                biased;
                _ = cancel.cancelled() => {
                    let _ = child.kill();

                    // Recover stdout/stderr files from the reader threads.
                    // The threads will finish promptly now that pipes are closed.
                    if let Ok(Ok((f, _tail))) = stdout_thread.join() {
                        self.stdout = f;
                    }
                    if let Ok(Ok((f, _tail))) = stderr_thread.join() {
                        self.stderr = f;
                    }

                    // Reap the child process, then tear down its network.
                    let _ = child.wait();
                    net_guard.teardown().await;
                    return Err(Error::Execution(ExecutionError::Cancelled));
                }
                (stdout_fwd_res, stderr_fwd_res) = async { tokio::join!(stdout_fwd, stderr_fwd) } => {
                    // Compute the invocation outcome with a closure so every
                    // failure path (reader-thread error, async writer error, wait
                    // error, non-zero exit) funnels through one point; then tear
                    // the network down unconditionally *before* propagating, so a
                    // switch attachment is never leaked on an error return.
                    let outcome: Result<(), Error> = (|| {
                        let (stdout_file, stdout_tail) = stdout_thread
                            .join()
                            .expect("stdout reader thread panicked")?;
                        let (stderr_file, stderr_tail) = stderr_thread
                            .join()
                            .expect("stderr reader thread panicked")?;

                        self.stdout = stdout_file;
                        self.stderr = stderr_file;

                        // Propagate any async writer errors.
                        stdout_fwd_res?;
                        stderr_fwd_res?;

                        // The pipes are drained, so the child should have exited.
                        let status = child
                            .wait()
                            .map_err(|e| Error::Execution(ExecutionError::SpawnFailed(e)))?;

                        if !status.success() {
                            let stderr_str = String::from_utf8_lossy(&stderr_tail).into_owned();
                            let stdout_str = String::from_utf8_lossy(&stdout_tail).into_owned();
                            return Err(Error::Execution(ExecutionError::InvocationFailed {
                                idx: i,
                                code: status.code,
                                reason: status.reason.clone(),
                                stderr: stderr_str,
                                stdout: stdout_str,
                            }));
                        }
                        Ok(())
                    })();

                    // The invocation's process has exited; tear down its network
                    // before propagating any error.
                    net_guard.teardown().await;
                    outcome?;
                }
            }
        }
        Ok(())
    }
}

// Output collection
impl Sandbox {
    /// Copies all output files into the given destination directory that match the globset.
    ///
    /// Symlinks are copied if they point to a file within the output, otherwise an error is returned.
    pub fn match_outputs_into<P: AsRef<Path>>(
        &self,
        matcher: globset::GlobSet,
        dest_dir: P,
    ) -> Result<(), Error> {
        use error::OutputError;

        let output_dir = self.base_dir.join("build").join("output");
        let dest_dir = dest_dir.as_ref();

        for entry in walkdir::WalkDir::new(&output_dir) {
            let entry =
                entry.map_err(|e| Error::IO("walking outputs", output_dir.clone(), e.into()))?;
            let path = entry.path();
            let file_type = entry.file_type();

            // Skip directories
            if file_type.is_dir() {
                continue;
            }

            // Get relative path from output_dir for glob matching
            let rel_path = path
                .strip_prefix(&output_dir)
                .expect("path should be under output_dir");

            // Check if this entry matches the glob
            if !matcher.is_match(rel_path) {
                continue;
            }

            // Create destination directory structure
            let dest_path = dest_dir.join(rel_path);
            if let Some(parent) = dest_path.parent() {
                fs::create_dir_all(parent)
                    .map_err(|e| Error::IO("creating dest directory", parent.to_path_buf(), e))?;
            }

            if file_type.is_symlink() {
                // Read the symlink target
                let target = fs::read_link(path)
                    .map_err(|e| Error::IO("reading symlink", path.to_path_buf(), e))?;

                let resolved_target = path.parent().unwrap().join(&target);
                let is_internal = if let Ok(canonical_target) = resolved_target.canonicalize() {
                    canonical_target.starts_with(&output_dir)
                } else {
                    false
                };
                if !is_internal {
                    return Err(Error::Output(OutputError::ExternalSymlink {
                        symlink: path.to_path_buf(),
                        target,
                    }));
                }

                // Recreate the symlink with the same target
                std::os::unix::fs::symlink(&target, &dest_path)
                    .map_err(|e| Error::IO("creating symlink", dest_path.clone(), e))?;
            } else if file_type.is_file() {
                // Copy the file
                fs::copy(path, &dest_path)
                    .map_err(|e| Error::IO("copying file", dest_path.clone(), e))?;
            }
        }

        Ok(())
    }
}

// Matches the logic in the libcgroups crate. If we do not conditionally
// set cpu resources, the underlying code in libcgroups will panic :(
#[cfg(target_os = "linux")]
fn booted_with_systemd() -> bool {
    std::fs::symlink_metadata("/run/systemd/system")
        .map(|p| p.is_dir())
        .unwrap_or_default()
}

fn hardlink_dir_contents(src_dir: &Path, dst_parent_dir: &Path) -> Result<(), Error> {
    common::hardlink_dir_contents(src_dir, dst_parent_dir).map_err(Error::HardlinkFailed)
}

/// Returns the kernel-locked mount flags for the mount containing `path`.
///
/// In a user namespace, remounting a bind mount requires preserving all
/// flags that the kernel has locked (CL_UNPRIVILEGED). If the remount
/// omits a locked flag the kernel returns EPERM. By proactively reading
/// these flags and including them in the mount options we hand to
/// hakoniwa, the remount succeeds even in nested sandboxes—without
/// resorting to MountFallback (which can silently drop requested
/// restrictions like RDONLY).
#[cfg(target_os = "linux")]
fn locked_mount_flags(path: &Path) -> hakoniwa::MountOptions {
    use nix::sys::statfs::statfs;
    use nix::sys::statvfs::FsFlags;

    let stat = match statfs(path) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(
                "statfs({}) failed: {e}, not adding locked mount flags",
                path.to_string_lossy()
            );
            return hakoniwa::MountOptions::empty();
        }
    };

    let flags = stat.flags();
    let mut opts = hakoniwa::MountOptions::empty();
    if flags.contains(FsFlags::ST_RDONLY) {
        opts |= hakoniwa::MountOptions::RDONLY;
    }
    if flags.contains(FsFlags::ST_NOSUID) {
        opts |= hakoniwa::MountOptions::NOSUID;
    }
    if flags.contains(FsFlags::ST_NODEV) {
        opts |= hakoniwa::MountOptions::NODEV;
    }
    if flags.contains(FsFlags::ST_NOEXEC) {
        opts |= hakoniwa::MountOptions::NOEXEC;
    }
    opts
}

/// Best-effort probe for whether this host can create network namespaces.
///
/// Reads `/proc/sys/user/max_net_namespaces`: a missing file or a zero limit
/// means network namespaces are unavailable, so [`new_container`](Sandbox::new_container)
/// fails closed for [`NetworkMode::NoNet`] and [`NetworkMode::OwnIp`] rather
/// than silently sharing the host network. The quota is a necessary, not
/// sufficient, signal — a positive quota can still be denied at `unshare` time
/// by capability or seccomp policy — but with the fail-closed contract above a
/// false positive surfaces as a spawn error, never as a silent loss of
/// isolation.
#[cfg(target_os = "linux")]
fn network_namespaces_available() -> bool {
    std::fs::read_to_string("/proc/sys/user/max_net_namespaces")
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .is_some_and(|n| n > 0)
}

/// A host-level obstruction to creating the unprivileged user namespace every
/// sandbox needs, as diagnosed by [`user_namespaces_restriction`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum UsernsRestriction {
    /// User namespaces are unavailable outright: `/proc/sys/user/
    /// max_user_namespaces` is missing (kernel built without
    /// `CONFIG_USER_NS`) or zero (administratively disabled).
    Disabled,
    /// `kernel.apparmor_restrict_unprivileged_userns=1` (stock Ubuntu 24.04+)
    /// and this process is unconfined, so the kernel will deny the unshare.
    /// Loading an AppArmor profile that grants this process `userns` lifts
    /// the restriction for it alone (`packaging/apparmor/minimald`).
    ApparmorUnconfined,
}

impl std::fmt::Display for UsernsRestriction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Disabled => {
                write!(
                    f,
                    "user namespaces are unavailable (user.max_user_namespaces is 0 or missing)"
                )
            }
            Self::ApparmorUnconfined => {
                write!(
                    f,
                    "kernel.apparmor_restrict_unprivileged_userns=1 and this process is unconfined"
                )
            }
        }
    }
}

/// Best-effort probe for whether this host will refuse the unprivileged user
/// namespace every sandbox starts by unsharing — the counterpart of the
/// network probe above, for the namespace that has no fallback.
///
/// Returns the obstruction it finds, or `None` when none is visible. The
/// sandbox child is forked from the calling process with no exec in between,
/// so the caller's own privileges and AppArmor label are exactly what the
/// kernel will check at `unshare`/`uid_map` time — probe from the daemon,
/// not from a helper. Like the network probe this is a necessary-not-
/// sufficient signal (seccomp or LSM policy can still deny at spawn time),
/// but it is advisory: a false `None` surfaces later as the spawn error it
/// always was, never as a loss of isolation.
#[cfg(target_os = "linux")]
#[must_use]
pub fn user_namespaces_restriction() -> Option<UsernsRestriction> {
    userns_restriction_from(
        std::fs::read_to_string("/proc/sys/user/max_user_namespaces").ok(),
        std::fs::read_to_string("/proc/sys/kernel/apparmor_restrict_unprivileged_userns").ok(),
        nix::unistd::geteuid().is_root(),
        apparmor_label().as_deref(),
    )
}

/// This process's AppArmor label, e.g. `unconfined` or `minimald (unconfined)`.
///
/// The `apparmor/` subdir is the modern location; older kernels expose only
/// the shared `attr/current`. Unreadable (AppArmor absent) is `None`.
#[cfg(target_os = "linux")]
fn apparmor_label() -> Option<String> {
    [
        "/proc/self/attr/apparmor/current",
        "/proc/self/attr/current",
    ]
    .iter()
    .find_map(|p| std::fs::read_to_string(p).ok())
}

/// Decision core of [`user_namespaces_restriction`], on pre-read inputs.
#[cfg(target_os = "linux")]
fn userns_restriction_from(
    max_user_namespaces: Option<String>,
    apparmor_restrict: Option<String>,
    euid_is_root: bool,
    apparmor_label: Option<&str>,
) -> Option<UsernsRestriction> {
    if max_user_namespaces
        .and_then(|s| s.trim().parse::<u64>().ok())
        .is_none_or(|n| n == 0)
    {
        return Some(UsernsRestriction::Disabled);
    }
    // The AppArmor restriction below only binds unprivileged processes; a
    // root daemon (e.g. the in-guest microVM pid-1) is exempt from it.
    if euid_is_root {
        return None;
    }
    let restricted = apparmor_restrict
        .and_then(|s| s.trim().parse::<u32>().ok())
        .is_some_and(|v| v != 0);
    // The label reads `unconfined` or `<profile> (<mode>)`, possibly
    // NUL/newline-terminated. An unreadable label on a kernel that has the
    // restriction sysctl means no profile is attached — which the kernel
    // treats as unconfined, so we do too.
    let unconfined =
        apparmor_label.is_none_or(|l| l.trim_end_matches(['\n', '\0']).trim() == "unconfined");
    (restricted && unconfined).then_some(UsernsRestriction::ApparmorUnconfined)
}

/// A launch between its plan and its attach, owing the plan's release.
///
/// A value rather than a closure, because the session path builds its
/// environment asynchronously between the two steps. Every way out releases
/// the plan exactly once: [`attach`](Self::attach) hands the obligation to the
/// returned [`NetGuard`], [`abandon`](Self::abandon) releases it, and `Drop`
/// releases it — which is what catches a cancelled launch.
pub struct PlannedLaunch {
    network: std::sync::Arc<dyn network::Network>,
    plan: network::NetPlan,
    /// Whether the release is still owed. Cleared by `attach` and `abandon`.
    owed: bool,
}

impl std::fmt::Debug for PlannedLaunch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PlannedLaunch")
            .field("plan", &self.plan)
            .field("owed", &self.owed)
            .finish_non_exhaustive()
    }
}

impl PlannedLaunch {
    /// Step 1: ask the provider for its plan, and take on its release. Split
    /// from [`Sandbox::plan_launch`] so the sequence is reachable without a
    /// `Sandbox`.
    ///
    /// # Errors
    ///
    /// Propagates the provider's planning failure; a plan that failed reserved
    /// nothing.
    pub async fn begin(network: std::sync::Arc<dyn network::Network>) -> Result<Self, Error> {
        let plan = network.plan().await.map_err(Error::Network)?;
        Ok(Self {
            network,
            plan,
            owed: true,
        })
    }

    /// What the sandbox needs; the container is built from it.
    #[must_use]
    pub fn plan(&self) -> &network::NetPlan {
        &self.plan
    }

    /// The process exists: wire its namespace. The returned guard owns the
    /// release from here, so no abandon follows.
    ///
    /// # Errors
    ///
    /// Propagates the provider's attach failure; the plan's release stays owed
    /// and the drop of `self` runs it.
    pub async fn attach(mut self, spawned: network::Spawned) -> Result<Box<dyn NetGuard>, Error> {
        let guard = self.network.attach(spawned).await.map_err(Error::Network)?;
        self.owed = false;
        Ok(guard)
    }

    /// Give up before the process exists, releasing the plan.
    pub async fn abandon(mut self) {
        self.owed = false;
        self.network.abandon().await;
    }
}

impl Drop for PlannedLaunch {
    fn drop(&mut self) {
        if !self.owed {
            return;
        }
        let network = std::sync::Arc::clone(&self.network);
        // `Drop` cannot `await`; with no runtime there is nothing to release to.
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move { network.abandon().await });
        }
    }
}

/// The network plan a sandbox's built-in configuration implies. See
/// [`Sandbox::built_in_plan`].
fn plan_from_config(config: &config::Config) -> network::NetPlan {
    // A resolver the plan names wins; `setup_dns_config` fills in the host's
    // only where the plan is silent.
    if config.setup_dns_config && *config.plan.resolver() == network::Resolver::None {
        return config.plan.clone().with_resolver(network::Resolver::Host);
    }
    config.plan.clone()
}

/// Whether to unshare the network namespace, or the error that says we will not
/// hand back host networking instead. Takes what the probe found so 017-011 is
/// provable on any host.
#[cfg(target_os = "linux")]
fn isolation_decision(plan: &network::NetPlan, netns_available: bool) -> Result<bool, Error> {
    if plan.isolates_netns() && !netns_available {
        return Err(Error::Execution(
            ExecutionError::NetworkIsolationUnavailable,
        ));
    }
    Ok(plan.isolates_netns())
}

/// The audit-architecture identifier of the ABI this binary is built for.  A
/// kernel ABI constant (`AUDIT_ARCH_*` in `linux/audit.h`) that the `libc`
/// crate does not expose; chosen at compile time so an unsupported target
/// fails to build rather than panicking at launch.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const AUDIT_ARCH: u32 = 0xc000_003e; // AUDIT_ARCH_X86_64
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
const AUDIT_ARCH: u32 = 0xc000_00b7; // AUDIT_ARCH_AARCH64

/// The x32 ABI shares `AUDIT_ARCH_X86_64` and marks its syscalls by setting
/// this bit in `nr`, so a plain compare against `SYS_socket` would let an x32
/// caller through.  The filter kills any such call instead.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const X32_SYSCALL_BIT: u32 = 0x4000_0000;

/// The socket-family seccomp filter as a classic BPF program.  It is installed
/// via `prctl(PR_SET_NO_NEW_PRIVS, 1)` and `seccomp(SECCOMP_SET_MODE_FILTER, 0,
/// &prog)` by a pre-exec closure so it survives both the sandbox spawn and any
/// later `nsenter` injection into the box.
#[cfg(target_os = "linux")]
#[derive(Clone, Debug)]
pub struct SocketFamilyFilter {
    program: Vec<libc::sock_filter>,
    /// The seal the filter is; the launch and injection logs name it.
    pub seal: network::SocketSeal,
    /// The families the seal refuses, named for the launch log.
    pub refused_families: &'static str,
}

/// Syscall numbers for the socket-family filters.  `libc` exposes these per-arch.
#[cfg(target_os = "linux")]
const SYS_SOCKET: i64 = libc::SYS_socket;
#[cfg(target_os = "linux")]
const SYS_SOCKETPAIR: i64 = libc::SYS_socketpair;

/// Build the socket-family filter for a seal: a classic BPF seccomp program
/// that admits the `socket()`/`socketpair()` calls whose address family the
/// seal lists and refuses the rest with `EAFNOSUPPORT`.  Both seals are
/// allowlists.  The `none` seal admits `AF_UNIX` alone, which stays working
/// so the in-sandbox `min` helper and the minenv socket keep functioning;
/// the confined-families seal admits the families the box's own network
/// namespace confines — `AF_UNIX`, `AF_INET`, `AF_INET6`, `AF_NETLINK`,
/// `AF_PACKET` — so no family that reaches past the namespace survives it.
/// `AF_PACKET` sits on the admitted list because its refusal is the missing
/// `CAP_NET_RAW` no box holds (NET-083), not this filter's.
///
/// This program is the first instalment of the seccomp profile applied
/// inside boxes (architecture.md AT9, open gap 2): the family list is
/// published here, reviewable where the design promised it.
#[cfg(target_os = "linux")]
fn build_socket_family_filter(seal: network::SocketSeal) -> SocketFamilyFilter {
    // Return EAFNOSUPPORT for a socket() or socketpair() the seal refuses.
    let refuse_action = libc::SECCOMP_RET_ERRNO | (libc::EAFNOSUPPORT as u32);
    // Return the default allow action when the syscall is not one we restrict
    // or when the address family is allowed.
    let allow_action = libc::SECCOMP_RET_ALLOW;
    // A caller on a foreign ABI (another audit arch, or x32 on x86_64) dies
    // with SIGSYS on its first syscall in every box, networked ones included:
    // this check sits before the syscall-number dispatch, and the numbers
    // would not mean the same thing on another ABI, so the filter kills
    // rather than guesses.  A 32-bit binary in a host-address or own-address
    // box dies here, where it ran before the seal reached every box.
    let kill_action = libc::SECCOMP_RET_KILL_PROCESS;

    // The families the seal admits, in the order the verdict tail compares
    // them.  The `none` seal admits `AF_UNIX` alone; the confined-families
    // seal admits the namespace-confined set.
    let admitted: &[u32] = match seal {
        network::SocketSeal::Full => &[libc::AF_UNIX as u32],
        network::SocketSeal::ConfinedFamilies => &[
            libc::AF_UNIX as u32,
            libc::AF_INET as u32,
            libc::AF_INET6 as u32,
            libc::AF_NETLINK as u32,
            libc::AF_PACKET as u32,
        ],
    };

    // Offsets into struct seccomp_data in bytes:
    //   int nr;                  // 0
    //   __u32 arch;              // 4
    //   __u64 instruction_pointer; // 8
    //   __u64 args[6];           // 16
    const OFFSET_NR: u32 = 0;
    const OFFSET_ARCH: u32 = 4;
    const OFFSET_ARG0: u32 = 16;

    let load = |offset: u32| libc::sock_filter {
        code: (libc::BPF_LD | libc::BPF_ABS | libc::BPF_W) as u16,
        jt: 0,
        jf: 0,
        k: offset,
    };
    let jeq = |k: u32, jt: u8, jf: u8| libc::sock_filter {
        code: (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
        jt,
        jf,
        k,
    };
    let ret = |action: u32| libc::sock_filter {
        code: (libc::BPF_RET | libc::BPF_K) as u16,
        jt: 0,
        jf: 0,
        k: action,
    };

    // Classic BPF seccomp program.  `jt` and `jf` are the number of
    // instructions to skip after the current one (0 means "fall through to the
    // next instruction").  Indices below are for x86_64; aarch64 has no x32
    // guard, so everything from the `SYS_socket` compare on sits two lower
    // (relative jumps in that tail are unchanged).
    let mut filter: Vec<libc::sock_filter> = vec![
        // 0: load arch.
        load(OFFSET_ARCH),
        // 1: native ABI -> 3; anything else -> 2.
        jeq(AUDIT_ARCH, 1, 0),
        // 2: kill: foreign ABI.
        ret(kill_action),
        // 3: load syscall number.
        load(OFFSET_NR),
    ];
    #[cfg(target_arch = "x86_64")]
    {
        // 4: nr >= X32_SYSCALL_BIT -> 5; else -> 6.
        filter.push(libc::sock_filter {
            code: (libc::BPF_JMP | libc::BPF_JGE | libc::BPF_K) as u16,
            jt: 0,
            jf: 1,
            k: X32_SYSCALL_BIT,
        });
        // 5: kill: x32 ABI.
        filter.push(ret(kill_action));
    }
    // 6: socket() -> 8; else -> 7.
    filter.push(jeq(SYS_SOCKET as u32, 1, 0));
    // 7: socketpair() -> 8; anything else jumps past the whole verdict tail
    // to the default allow — one skip per admitted-family verdict pair plus
    // the refuse and allow returns that end it.
    filter.push(jeq(
        SYS_SOCKETPAIR as u32,
        0,
        (2 * admitted.len() + 2) as u8,
    ));
    // 8: load arg0 (the address family).
    filter.push(load(OFFSET_ARG0));
    // The verdict tail: both seals are allowlists, so each admitted family
    // gets an allow return and whatever is left over is refused.  The `none`
    // seal's one-family list is the tail the `none` box has always run; the
    // confined-families seal's list is the namespace-confined set.  Relative
    // jumps stay correct for either list.
    for family in admitted {
        // family matches -> the allow return; anything else falls through to
        // the next comparison, or to the refuse return past the last one.
        filter.push(jeq(*family, 0, 1));
        filter.push(ret(allow_action));
    }
    // The seal's verdict for every family it does not admit, EAFNOSUPPORT.
    filter.push(ret(refuse_action));
    // The default allow for every syscall that creates no socket, reached
    // both by falling through and by instruction 7's jump.
    filter.push(ret(allow_action));

    SocketFamilyFilter {
        program: filter,
        seal,
        refused_families: match seal {
            network::SocketSeal::Full => "every family but unix",
            network::SocketSeal::ConfinedFamilies => {
                "every family but unix, inet, inet6, netlink, packet"
            }
        },
    }
}

/// Install a seccomp-BPF filter in this process by enabling
/// `PR_SET_NO_NEW_PRIVS` and loading the filter with the kernel.  This must run
/// after the namespace/credential setup and before the supervised program
/// starts, and it must be async-signal-safe (it only calls `prctl(2)` and
/// `syscall(2)`).
///
/// # Safety
///
/// `filter` must remain valid and immutable for the duration of this call.
/// The function is otherwise async-signal-safe and only uses libc syscalls.
#[cfg(target_os = "linux")]
pub unsafe fn install_socket_family_filter(filter: &SocketFamilyFilter) -> std::io::Result<()> {
    // SAFETY: prctl is async-signal-safe and the arguments are valid.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } == -1 {
        return Err(std::io::Error::last_os_error());
    }

    let prog = libc::sock_fprog {
        len: filter.program.len() as u16,
        filter: filter.program.as_ptr().cast_mut(),
    };

    // SAFETY: syscall is async-signal-safe; the seccomp_set_mode_filter
    // arguments point at a valid sock_fprog whose filter bytes are pinned.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_SET_MODE_FILTER as i64,
            0i64,
            &prog as *const libc::sock_fprog as i64,
        )
    };
    if rc == -1 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Returns a pointer to the built-in socket-family filter for a seal — the
/// full `none` seal, or the confined-families seal every other box launches
/// under.  Used both when launching a box and when re-installing the same
/// filter during `nsenter` injection (the filter is inherited by children,
/// not by processes that join the namespaces later).
#[cfg(target_os = "linux")]
#[must_use]
pub fn socket_family_filter_for_none_box() -> &'static SocketFamilyFilter {
    static FILTER: std::sync::OnceLock<SocketFamilyFilter> = std::sync::OnceLock::new();
    FILTER.get_or_init(|| build_socket_family_filter(network::SocketSeal::Full))
}

/// Returns a pointer to the built-in confined-families socket-family filter:
/// it admits the families the box's own network namespace confines — unix,
/// inet, inet6, netlink, packet — and refuses everything else with
/// `EAFNOSUPPORT`, `AF_VSOCK` (the family that reaches the host whatever
/// network namespace the caller sits in) included, so an own-address or
/// host-address box keeps its inet sockets and cannot reach past its
/// namespace.
#[cfg(target_os = "linux")]
#[must_use]
pub fn socket_family_filter_for_confined_families() -> &'static SocketFamilyFilter {
    static FILTER: std::sync::OnceLock<SocketFamilyFilter> = std::sync::OnceLock::new();
    FILTER.get_or_init(|| build_socket_family_filter(network::SocketSeal::ConfinedFamilies))
}

/// The socket-family filter a box runs under, decided by its plan: the full
/// `none` seal for [`NetPlan::none`], the confined-families seal for every
/// other plan.
#[cfg(target_os = "linux")]
fn socket_family_filter_for_plan(plan: &network::NetPlan) -> &'static SocketFamilyFilter {
    match plan.seal() {
        network::SocketSeal::Full => socket_family_filter_for_none_box(),
        network::SocketSeal::ConfinedFamilies => socket_family_filter_for_confined_families(),
    }
}

/// Puts the plan's resolver into `<rootfs>/etc/resolv.conf`. The host's is
/// synthesized only if the rootfs has none; named servers replace whatever is
/// there, unlinking first because the rootfs is a hardlink farm over the
/// package cache.
fn write_resolv_conf(rootfs: &Path, resolver: &network::Resolver) -> Result<(), Error> {
    let etc_resolv = rootfs.join("etc").join("resolv.conf");
    match resolver {
        network::Resolver::None => Ok(()),
        network::Resolver::Host => {
            if fs::exists(&etc_resolv)
                .map_err(|e| Error::IO("checking for /etc/resolv.conf", etc_resolv.clone(), e))?
            {
                return Ok(());
            }
            common::synth_dns_config(rootfs)
                .map_err(|e| Error::IO("synthesizing /etc/resolv.conf", etc_resolv, e))
        }
        network::Resolver::Nameservers(servers) => {
            fs::create_dir_all(rootfs.join("etc"))
                .map_err(|e| Error::IO("creating /etc", rootfs.join("etc"), e))?;
            match fs::remove_file(&etc_resolv) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(Error::IO("replacing /etc/resolv.conf", etc_resolv, e)),
            }
            let body: String = servers
                .iter()
                .map(|s| format!("nameserver {s}\n"))
                .collect();
            fs::write(&etc_resolv, body)
                .map_err(|e| Error::IO("writing /etc/resolv.conf", etc_resolv, e))
        }
    }
}

/// Appends the plan's static entries to `<rootfs>/etc/hosts`, preserving
/// whatever the rootfs ships. The file is replaced rather than appended in
/// place, unlinking first for the same reason [`write_resolv_conf`] does: the
/// rootfs is a hardlink farm over the package cache, and an in-place append
/// would write through the link into the cached package.
///
/// Idempotent: `new_container` runs once per task invocation over the same
/// rootfs, so an entry a previous invocation already wrote is skipped instead
/// of growing the file a line per exec.
fn write_hosts(rootfs: &Path, hosts: &[network::HostEntry]) -> Result<(), Error> {
    if hosts.is_empty() {
        return Ok(());
    }
    let etc_hosts = rootfs.join("etc").join("hosts");
    fs::create_dir_all(rootfs.join("etc"))
        .map_err(|e| Error::IO("creating /etc", rootfs.join("etc"), e))?;
    let shipped = match fs::read(&etc_hosts) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(e) => return Err(Error::IO("reading /etc/hosts", etc_hosts.clone(), e)),
    };
    let mut body = String::from_utf8_lossy(&shipped).into_owned();
    if !body.is_empty() && !body.ends_with('\n') {
        body.push('\n');
    }
    for entry in hosts {
        if hosts_entry_present(&body, entry) {
            continue;
        }
        body.push_str(&format!("{}\t{}\n", entry.address, entry.name));
    }
    match fs::remove_file(&etc_hosts) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(Error::IO("replacing /etc/hosts", etc_hosts.clone(), e)),
    }
    fs::write(&etc_hosts, body).map_err(|e| Error::IO("writing /etc/hosts", etc_hosts, e))
}

/// Whether `body` already answers `entry` — a line whose whitespace-separated
/// fields carry both the address and the name, in tab- or space-separated
/// form, and whether it was written by this function or shipped by the rootfs.
fn hosts_entry_present(body: &str, entry: &network::HostEntry) -> bool {
    let address = entry.address.to_string();
    body.lines().any(|line| {
        let fields: Vec<&str> = line.split_whitespace().collect();
        fields.contains(&address.as_str()) && fields.contains(&entry.name.as_str())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use config::{Config, SandboxMapped};

    // /proc is mounted with nosuid,nodev on essentially every Linux distro;
    // if either stops showing up we've broken the FsFlags → MountOptions
    // mapping and a nested sandbox would silently lose those locked flags
    // again. NOEXEC is also common but skipped here since it's not
    // universal.
    #[cfg(target_os = "linux")]
    #[test]
    fn locked_mount_flags_reads_proc_flags() {
        let opts = locked_mount_flags(Path::new("/proc"));
        assert!(opts.contains(hakoniwa::MountOptions::NOSUID));
        assert!(opts.contains(hakoniwa::MountOptions::NODEV));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn locked_mount_flags_empty_on_statfs_failure() {
        let opts = locked_mount_flags(Path::new("/nonexistent-path-for-statfs-test"));
        assert!(opts.is_empty());
    }

    /// A provider that records which operations ran, in order, so the sequence
    /// itself can be asserted rather than its effects.
    #[derive(Debug, Default)]
    struct Recorder {
        events: std::sync::Mutex<Vec<&'static str>>,
        /// When set, `attach` fails — the path that must still leave the plan's
        /// release owed.
        attach_fails: bool,
    }

    impl Recorder {
        fn events(&self) -> Vec<&'static str> {
            self.events.lock().unwrap().clone()
        }
        fn push(&self, e: &'static str) {
            self.events.lock().unwrap().push(e);
        }
    }

    impl network::Network for Recorder {
        fn plan(&self) -> network::PlanFuture<'_> {
            self.push("plan");
            Box::pin(std::future::ready(Ok(network::NetPlan::isolated())))
        }
        fn attach(&self, spawned: network::Spawned) -> network::AttachFuture<'_> {
            self.push("attach");
            if self.attach_fails {
                return Box::pin(std::future::ready(Err(network::NetworkError::new(
                    std::io::Error::other("attach refused"),
                ))));
            }
            drop(spawned);
            Box::pin(std::future::ready(Ok(network::noop_guard())))
        }
        fn abandon(&self) -> network::AbandonFuture<'_> {
            self.push("abandon");
            Box::pin(std::future::ready(()))
        }
    }

    fn planned_with(rec: &std::sync::Arc<Recorder>) -> PlannedLaunch {
        PlannedLaunch {
            network: rec.clone(),
            plan: network::NetPlan::isolated(),
            owed: true,
        }
    }

    /// 017-001. A full launch records `plan` then `attach`, nothing between.
    /// The order is structural: `new_container` takes a `&NetPlan` and `attach`
    /// takes a [`network::Spawned`], which only a spawned process yields.
    #[tokio::test]
    async fn network_phases_run_in_order() {
        let rec = std::sync::Arc::new(Recorder::default());
        let planned = PlannedLaunch::begin(rec.clone()).await.expect("planning");
        assert_eq!(rec.events(), vec!["plan"]);
        assert!(
            planned.plan().isolates_netns(),
            "the provider's plan is carried forward"
        );

        let guard = planned.attach(network::Spawned::new(4242)).await.unwrap();
        assert_eq!(rec.events(), vec!["plan", "attach"]);
        guard.teardown().await;
    }

    /// 017-002. A launch that gives up between plan and attach releases the
    /// plan exactly once, and a failed attach still leaves the release owed.
    #[tokio::test]
    async fn abandoned_launch_releases_the_plan() {
        let rec = std::sync::Arc::new(Recorder::default());
        rec.push("plan");
        planned_with(&rec).abandon().await;
        // The explicit abandon consumes the launch; its drop must not release again.
        assert_eq!(rec.events(), vec!["plan", "abandon"]);

        let rec = std::sync::Arc::new(Recorder {
            events: std::sync::Mutex::new(vec!["plan"]),
            attach_fails: true,
        });
        assert!(
            planned_with(&rec)
                .attach(network::Spawned::new(1))
                .await
                .is_err()
        );
        tokio::task::yield_now().await;
        assert_eq!(
            rec.events(),
            vec!["plan", "attach", "abandon"],
            "a failed attach must still release the plan"
        );
    }

    /// 017-002 sub-requirement: the launch future going away is the one exit a
    /// caller cannot handle, so the release rides on `Drop`.
    #[tokio::test]
    async fn cancelled_launch_releases_the_plan() {
        let rec = std::sync::Arc::new(Recorder::default());
        rec.push("plan");
        drop(planned_with(&rec));
        tokio::task::yield_now().await;
        assert_eq!(rec.events(), vec!["plan", "abandon"]);
    }

    /// 017-010. The descriptor reaches the provider once: a second take yields
    /// nothing rather than a second owner of the same fd.
    #[test]
    fn the_tap_descriptor_goes_to_the_provider_once() {
        use std::os::fd::AsRawFd as _;
        // A pipe end stands in for the tap; any real fd proves ownership moved.
        let (read_end, _write_end) = std::io::pipe().expect("pipe");
        let fd = std::os::fd::OwnedFd::from(read_end);
        let raw = fd.as_raw_fd();

        let mut spawned = network::Spawned::new(7).with_tap_fd(fd);
        assert_eq!(spawned.take_tap_fd().expect("first take").as_raw_fd(), raw);
        assert!(
            spawned.take_tap_fd().is_none(),
            "a second take gets nothing"
        );
        assert!(network::Spawned::new(7).take_tap_fd().is_none());
    }

    /// 017-004. Both ways a sandbox process starts — the invocation path
    /// ([`Sandbox::plan_launch`]) and the caller-spawn path `minimald` uses
    /// ([`PlannedLaunch::begin`]) — reach the same provider through one
    /// sequence; with no provider, both plan from the sandbox's own config.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn both_spawn_paths_apply_the_network() {
        let recorder = std::sync::Arc::new(Recorder::default());
        let (_tmp, base) = make_base_with_synth();
        let config = Config::new("test-both-paths")
            .with_network(recorder.clone() as std::sync::Arc<dyn network::Network>);
        let sandbox = Sandbox::new(base, config, ()).unwrap();

        let from_invocation = sandbox.plan_launch().await.expect("plan");
        let from_caller = PlannedLaunch::begin(recorder.clone()).await.expect("plan");
        assert_eq!(
            recorder.events(),
            vec!["plan", "plan"],
            "each path asks once"
        );
        assert_eq!(from_invocation.plan(), from_caller.plan());
        from_invocation.abandon().await;
        from_caller.abandon().await;
        assert_eq!(
            recorder.events(),
            vec!["plan", "plan", "abandon", "abandon"]
        );

        let (_tmp, base) = make_base_with_synth();
        let config = Config::new("test-both-paths-bare").with_plan(network::NetPlan::isolated());
        let sandbox = Sandbox::new(base, config, ()).unwrap();
        let from_invocation = sandbox.plan_launch().await.expect("plan");
        let from_caller = PlannedLaunch::begin(std::sync::Arc::new(sandbox.built_in_plan()))
            .await
            .expect("plan");
        assert!(from_invocation.plan().isolates_netns());
        assert_eq!(from_invocation.plan(), from_caller.plan());
    }

    fn tap_spec() -> network::TapSpec {
        network::TapSpec {
            address: std::net::Ipv4Addr::new(100, 64, 0, 2),
            netmask: std::net::Ipv4Addr::new(255, 255, 0, 0),
            gateway: std::net::Ipv4Addr::new(100, 64, 0, 1),
            mtu: 1500,
        }
    }

    /// 017-007. A plan with tap parameters isolates, however it was built:
    /// `NetPlan` has no constructor that pairs a tap with a shared namespace.
    #[test]
    fn a_tap_plan_always_isolates() {
        assert!(network::NetPlan::isolated_with_tap(tap_spec()).isolates_netns());
        assert!(
            network::NetPlan::isolated_with_tap(tap_spec())
                .with_resolver(network::Resolver::Host)
                .isolates_netns()
        );
        assert!(network::NetPlan::host().tap().is_none());
    }

    /// 017-006, for the plans the sandbox layer handles by itself: a shared
    /// namespace gets no tap and the host's resolver only when asked; an
    /// isolated one gets no tap and no resolver; a resolver the plan names is
    /// kept. The mode half is `minimald::net::provider`.
    #[test]
    fn the_mode_bounds_the_network_access() {
        let plan_for = |plan, dns| {
            let mut cfg = Config::new("t").with_plan(plan);
            cfg.setup_dns_config = dns;
            plan_from_config(&cfg)
        };

        let host = plan_for(network::NetPlan::host(), true);
        assert!(!host.isolates_netns() && host.tap().is_none());
        assert_eq!(host.resolver(), &network::Resolver::Host);
        assert_eq!(
            plan_for(network::NetPlan::host(), false).resolver(),
            &network::Resolver::None
        );

        let isolated = plan_for(network::NetPlan::isolated(), false);
        assert!(isolated.isolates_netns() && isolated.tap().is_none());
        assert_eq!(isolated.resolver(), &network::Resolver::None);

        let named = network::Resolver::Nameservers(vec![std::net::Ipv4Addr::new(100, 64, 0, 1)]);
        let own_ip = network::NetPlan::isolated_with_tap(tap_spec()).with_resolver(named.clone());
        assert_eq!(plan_for(own_ip, true).resolver(), &named);
    }

    /// The plan's resolver is what reaches `/etc/resolv.conf`.
    #[test]
    fn the_plan_names_the_resolver_the_rootfs_gets() {
        let tmp = tempfile::TempDir::new().unwrap();
        let rootfs = tmp.path();
        let resolv = rootfs.join("etc").join("resolv.conf");
        fs::create_dir_all(rootfs.join("etc")).unwrap();

        write_resolv_conf(rootfs, &network::Resolver::None).unwrap();
        assert!(!resolv.exists(), "None must write nothing");

        write_resolv_conf(rootfs, &network::Resolver::Host).unwrap();
        assert!(resolv.exists(), "Host must synthesize a resolver");

        fs::write(&resolv, "nameserver 192.0.2.1\n").unwrap();
        write_resolv_conf(rootfs, &network::Resolver::Host).unwrap();
        assert_eq!(
            fs::read_to_string(&resolv).unwrap(),
            "nameserver 192.0.2.1\n",
            "Host must not replace a resolver the rootfs already has"
        );

        let switch = std::net::Ipv4Addr::new(100, 64, 0, 1);
        write_resolv_conf(rootfs, &network::Resolver::Nameservers(vec![switch])).unwrap();
        assert_eq!(
            fs::read_to_string(&resolv).unwrap(),
            "nameserver 100.64.0.1\n",
            "named servers must replace what is there"
        );
    }

    /// NET-003: a host-address box resolves `host.min.internal` through a
    /// static `/etc/hosts` entry — the plan carries it and the container build
    /// writes it, keeping whatever the rootfs ships and leaving the hardlinked
    /// package cache untouched.
    #[test]
    fn hosts_entry_names_host_min_internal() {
        let plan = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(network::HostNet.plan())
            .expect("HostNet plans do not fail");
        let hosts = plan.hosts();
        assert_eq!(
            hosts.len(),
            1,
            "the native host-address plan carries one entry"
        );
        assert_eq!(hosts[0].name, network::HOST_MIN_INTERNAL);
        assert_eq!(hosts[0].address, std::net::Ipv4Addr::LOCALHOST);

        let tmp = tempfile::TempDir::new().unwrap();
        let rootfs = tmp.path();
        let etc_hosts = rootfs.join("etc").join("hosts");
        fs::create_dir_all(rootfs.join("etc")).unwrap();
        // The rootfs's hosts file is hardlinked from the package cache.
        let cache = tmp.path().join("package-etc-hosts");
        fs::write(&cache, "127.0.0.1\tlocalhost\n").unwrap();
        fs::hard_link(&cache, &etc_hosts).unwrap();

        write_hosts(rootfs, hosts).unwrap();
        assert_eq!(
            fs::read_to_string(&etc_hosts).unwrap(),
            "127.0.0.1\tlocalhost\n127.0.0.1\thost.min.internal\n",
            "shipped content kept, entry appended"
        );
        // `new_container` runs once per task invocation on the same rootfs, so
        // a second write over an already-present entry must not duplicate it.
        write_hosts(rootfs, hosts).unwrap();
        assert_eq!(
            fs::read_to_string(&etc_hosts).unwrap(),
            "127.0.0.1\tlocalhost\n127.0.0.1\thost.min.internal\n",
            "a repeat write does not grow the file a line per invocation"
        );
        assert_eq!(
            fs::read_to_string(&cache).unwrap(),
            "127.0.0.1\tlocalhost\n",
            "the package cache file must be untouched"
        );
    }

    /// 017-011. A host that cannot make the namespace the plan needs fails the
    /// launch rather than handing back the host's network.
    #[cfg(target_os = "linux")]
    #[test]
    fn no_namespace_support_fails_closed() {
        let err = isolation_decision(&network::NetPlan::isolated(), false)
            .expect_err("an isolating plan on a host without namespaces must fail");
        assert!(
            matches!(
                err,
                Error::Execution(ExecutionError::NetworkIsolationUnavailable)
            ),
            "expected NetworkIsolationUnavailable, got {err:?}"
        );
        assert!(
            isolation_decision(&network::NetPlan::isolated_with_tap(tap_spec()), false,).is_err()
        );
        assert!(!isolation_decision(&network::NetPlan::host(), false).unwrap());
    }

    /// The Ubuntu 24.04+ default: restriction sysctl on, daemon unconfined —
    /// the one case the AppArmor profile exists to fix.
    #[cfg(target_os = "linux")]
    #[test]
    fn userns_restricted_and_unconfined_is_diagnosed() {
        let got = userns_restriction_from(
            Some("15000\n".into()),
            Some("1\n".into()),
            false,
            Some("unconfined\n"),
        );
        assert_eq!(got, Some(UsernsRestriction::ApparmorUnconfined));
    }

    /// With the minimald profile attached the label is no longer bare
    /// `unconfined`, so the restriction does not bind — no warning.
    #[cfg(target_os = "linux")]
    #[test]
    fn userns_restricted_but_confined_is_clear() {
        let got = userns_restriction_from(
            Some("15000\n".into()),
            Some("1\n".into()),
            false,
            Some("minimald (unconfined)\n"),
        );
        assert_eq!(got, None);
    }

    /// Root is exempt from the AppArmor restriction (the in-guest microVM
    /// daemon runs as root and must stay silent).
    #[cfg(target_os = "linux")]
    #[test]
    fn userns_restricted_but_root_is_clear() {
        let got = userns_restriction_from(
            Some("15000\n".into()),
            Some("1\n".into()),
            true,
            Some("unconfined\n"),
        );
        assert_eq!(got, None);
    }

    /// Most distros: the restriction sysctl reads 0 (or does not exist on
    /// non-AppArmor kernels) — unconfined is fine.
    #[cfg(target_os = "linux")]
    #[test]
    fn userns_unrestricted_is_clear() {
        for sysctl in [Some("0\n".to_string()), None] {
            let got = userns_restriction_from(
                Some("15000\n".into()),
                sysctl,
                false,
                Some("unconfined\n"),
            );
            assert_eq!(got, None);
        }
    }

    /// A zero or missing user-namespace quota means no sandbox can start at
    /// all, root or not, regardless of AppArmor.
    #[cfg(target_os = "linux")]
    #[test]
    fn userns_zero_or_missing_quota_is_disabled() {
        for quota in [Some("0\n".to_string()), None] {
            let got = userns_restriction_from(quota, Some("0\n".into()), true, None);
            assert_eq!(got, Some(UsernsRestriction::Disabled));
        }
    }

    /// An unreadable label on a kernel that enforces the restriction means no
    /// profile is attached: the kernel treats that as unconfined, so the probe
    /// must as well.
    #[cfg(target_os = "linux")]
    #[test]
    fn userns_restricted_with_unreadable_label_is_diagnosed() {
        let got = userns_restriction_from(Some("15000\n".into()), Some("1\n".into()), false, None);
        assert_eq!(got, Some(UsernsRestriction::ApparmorUnconfined));
    }

    /// Creates a tempdir with the `synth/usr/` structure required by
    /// `Sandbox::new`. The `synth/` dir is hardlinked into the rootfs;
    /// `usr/` must be present so the subsequent `usr/lib64 → lib` symlink
    /// step can succeed.
    fn make_base_with_synth() -> (tempfile::TempDir, PathBuf) {
        let tmp = tempfile::TempDir::new().unwrap();
        let base = tmp.path().to_path_buf();
        fs::create_dir_all(base.join("synth").join("usr")).unwrap();
        (tmp, base)
    }

    /// `Sandbox::new` must reject a `SandboxMapped::File` entry in `config.rootfs`
    /// with `Error::MappedFile`. Files cannot be hardlinked at the rootfs level —
    /// only directories are valid rootfs entries.
    #[test]
    fn sandbox_new_rejects_mapped_file_in_rootfs() {
        let tmp = tempfile::TempDir::new().unwrap();
        let base = tmp.path().to_path_buf();
        // A file path that need not exist — the error is returned before it is accessed.
        let phantom = base.join("phantom.txt");
        let config = Config::new("test-reject-file").with_add_rootfs(SandboxMapped::File(phantom));
        let result = Sandbox::new(base, config, ());
        assert!(
            matches!(result, Err(Error::MappedFile(_))),
            "expected MappedFile error, got {result:?}"
        );
    }

    /// When no explicit `state_dir` is configured, `Sandbox::new` derives it
    /// as `base_dir/state`. The caller relies on this to bind-mount `/state`
    /// into the container at the correct host path.
    #[test]
    #[cfg(target_os = "linux")]
    fn sandbox_new_derives_state_dir_from_base() {
        let (_tmp, base) = make_base_with_synth();
        let config = Config::new("test-state-default");
        let sandbox = Sandbox::new(base.clone(), config, ()).unwrap();
        assert_eq!(
            sandbox.state_dir,
            base.join("state"),
            "state_dir should default to base_dir/state"
        );
    }

    /// When an explicit `state_dir` is supplied via `Config::with_state_dir`,
    /// `Sandbox::new` must store that path verbatim so the container bind-mounts
    /// the caller's chosen directory rather than an auto-generated one.
    #[test]
    #[cfg(target_os = "linux")]
    fn sandbox_new_honours_explicit_state_dir() {
        let (_tmp, base) = make_base_with_synth();
        let state_tmp = tempfile::TempDir::new().unwrap();
        let state_path = state_tmp.path().to_path_buf();
        let config = Config::new("test-state-explicit").with_state_dir(state_path.clone());
        let sandbox = Sandbox::new(base, config, ()).unwrap();
        assert_eq!(
            sandbox.state_dir, state_path,
            "state_dir should match the path supplied via with_state_dir"
        );
    }

    /// Runs a classic BPF seccomp program over one synthetic `seccomp_data`
    /// and returns the action it terminates with.  Supports exactly the
    /// opcodes [`build_socket_family_filter`] emits: `LD|W|ABS`, `JMP|JEQ|K`,
    /// `JMP|JGE|K`, and `RET|K`.
    #[cfg(target_os = "linux")]
    fn run_seccomp_program(program: &[libc::sock_filter], nr: u32, arch: u32, arg0: u32) -> u32 {
        let (mut pc, mut acc) = (0usize, 0u32);
        loop {
            let insn = &program[pc];
            pc += 1;
            let code = u32::from(insn.code);
            if code == libc::BPF_LD | libc::BPF_W | libc::BPF_ABS {
                // Offsets into `struct seccomp_data`: nr, arch, args[0] low word.
                acc = match insn.k {
                    0 => nr,
                    4 => arch,
                    16 => arg0,
                    other => panic!("unexpected seccomp_data offset {other}"),
                };
            } else if code == libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K {
                pc += usize::from(if acc == insn.k { insn.jt } else { insn.jf });
            } else if code == libc::BPF_JMP | libc::BPF_JGE | libc::BPF_K {
                pc += usize::from(if acc >= insn.k { insn.jt } else { insn.jf });
            } else if code == libc::BPF_RET | libc::BPF_K {
                return insn.k;
            } else {
                panic!("unexpected BPF opcode {code:#x} at {}", pc - 1);
            }
        }
    }

    /// The socket families the filter's live-kernel behaviour is probed for,
    /// in the order the probe child reports them.
    #[cfg(target_os = "linux")]
    const PROBED_FAMILIES: [(&str, i32); 4] = [
        ("AF_UNIX", libc::AF_UNIX),
        ("AF_INET", libc::AF_INET),
        ("AF_INET6", libc::AF_INET6),
        ("AF_VSOCK", libc::AF_VSOCK),
    ];

    /// Probes [`PROBED_FAMILIES`] in a forked child, installing the given
    /// production filter first when one is supplied, and returns one errno
    /// byte per family: `0` when the child created a socket of that family,
    /// the raw errno otherwise.
    ///
    /// The child runs only async-signal-safe calls between the fork and its
    /// `_exit` (`prctl`, the raw `seccomp` syscall, `socket`, `close`, `write`,
    /// `_exit`), matching the pre-exec environment the production filter is
    /// installed in; the parent owns every assertion, so a failure is reported
    /// with the test's own messages rather than a bare child exit code.
    #[cfg(target_os = "linux")]
    fn probe_socket_families_in_child(
        filter: Option<&'static SocketFamilyFilter>,
    ) -> std::io::Result<[u8; 4]> {
        let mut report = [0u8; 4];
        let mut fds = [0; 2];
        // SAFETY: `pipe(2)` writes two descriptors into `fds` and reads no
        // memory of ours beyond it; the result is checked.
        if unsafe { libc::pipe(fds.as_mut_ptr()) } == -1 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: the fork runs in the test's process, and the child only
        // touches async-signal-safe calls before its `_exit`, so no allocator
        // or lock can be held across the fork by the child itself.
        let pid = unsafe { libc::fork() };
        if pid == -1 {
            return Err(std::io::Error::last_os_error());
        }
        if pid == 0 {
            // Child: the production filter, then one errno byte per family.
            // SAFETY: the descriptors are the pipe's own ends.
            unsafe { libc::close(fds[0]) };
            if let Some(filter) = filter {
                // SAFETY: the filter is the `&'static` the process-wide
                // OnceLock owns, valid and immutable for the child's lifetime.
                if unsafe { install_socket_family_filter(filter) }.is_err() {
                    // Distinguishable in the parent's failure message: no
                    // install, no probe. This host cannot install the seal.
                    unsafe { libc::_exit(127) };
                }
            }
            for (i, &(_, family)) in PROBED_FAMILIES.iter().enumerate() {
                // SAFETY: `socket(2)` reads only its arguments.
                let fd = unsafe { libc::socket(family, libc::SOCK_STREAM, 0) };
                report[i] = if fd >= 0 {
                    // SAFETY: `close(2)` consumes the descriptor just created.
                    unsafe { libc::close(fd) };
                    0
                } else {
                    std::io::Error::last_os_error().raw_os_error().unwrap_or(1) as u8
                };
            }
            // SAFETY: `write(2)` reads `report`, which outlives the call, and
            // `_exit(2)` never returns, so the child ends here.
            unsafe {
                libc::write(fds[1], report.as_ptr().cast(), report.len());
                libc::_exit(0);
            }
        }
        // Parent: drain the report, then reap the child.
        // SAFETY: the write end is the parent's to close.
        unsafe { libc::close(fds[1]) };
        let mut filled = 0;
        while filled < report.len() {
            // SAFETY: `read(2)` writes only into the unfilled tail of
            // `report`, and the length is bounded by the same slice.
            let n = unsafe {
                libc::read(
                    fds[0],
                    report[filled..].as_mut_ptr().cast(),
                    report.len() - filled,
                )
            };
            if n <= 0 {
                break; // The child is gone; its exit status below names it.
            }
            filled += n as usize;
        }
        let mut status = 0;
        // SAFETY: `waitpid(2)` waits on the child this function forked.
        if unsafe { libc::waitpid(pid, &mut status, 0) } == -1 {
            return Err(std::io::Error::last_os_error());
        }
        if !libc::WIFEXITED(status) || libc::WEXITSTATUS(status) != 0 {
            return Err(std::io::Error::other(format!(
                "the socket-family probe child exited with status {status} \
                 (127 means installing the filter failed, so this host cannot \
                 install the seal at all)"
            )));
        }
        if filled != report.len() {
            return Err(std::io::Error::other(format!(
                "the socket-family probe child reported {filled} of {} bytes",
                report.len()
            )));
        }
        Ok(report)
    }

    /// NET-038. The none-box filter refuses `AF_VSOCK` sockets (which bypass the
    /// network namespace) while still allowing the local `AF_UNIX` sockets the
    /// sandbox's own minenv socket depends on, leaves every other syscall alone,
    /// and kills a caller on a foreign ABI rather than letting it through.  The
    /// production runtime effect is proved by
    /// `network_none_blocks_all_outside_sockets` in the minimald root integration
    /// harness; this unit test evaluates the program
    /// [`build_socket_family_filter`] produces and installs the production
    /// filter against the live kernel this test runs on, so the shipped BPF is
    /// exercised by real `socket(2)` calls on every host that runs the suite,
    /// not only where the root harness can.
    /// Every plan carries a seal, and only the none plan's refuses the
    /// families it does not need: every other plan's box is sealed to the
    /// families its own namespace confines, so it keeps the inet sockets an
    /// own-address or host-address box exists to open (see
    /// `every_box_refuses_namespace_bypass_families`). An isolated
    /// plan without a tap is also what an own-address box starts from inside
    /// a microVM, where the daemon moves the tap in after spawn; giving it
    /// the none seal would refuse the `AF_INET` sockets that box needs.
    #[test]
    fn each_plan_carries_its_socket_seal() {
        assert!(network::NetPlan::none().blocks_outside_sockets());
        assert!(!network::NetPlan::isolated().blocks_outside_sockets());
        assert!(!network::NetPlan::host().blocks_outside_sockets());
        assert!(
            !network::NetPlan::isolated_with_tap(network::TapSpec {
                address: std::net::Ipv4Addr::new(10, 0, 0, 2),
                netmask: std::net::Ipv4Addr::new(255, 255, 255, 0),
                gateway: std::net::Ipv4Addr::new(10, 0, 0, 1),
                mtu: 1500,
            })
            .blocks_outside_sockets()
        );
        assert_eq!(network::NetPlan::none().seal(), network::SocketSeal::Full);
        assert_eq!(
            network::NetPlan::isolated().seal(),
            network::SocketSeal::ConfinedFamilies
        );
        assert_eq!(
            network::NetPlan::host().seal(),
            network::SocketSeal::ConfinedFamilies
        );
        assert_eq!(
            network::NetPlan::isolated_with_tap(network::TapSpec {
                address: std::net::Ipv4Addr::new(10, 0, 0, 2),
                netmask: std::net::Ipv4Addr::new(255, 255, 255, 0),
                gateway: std::net::Ipv4Addr::new(10, 0, 0, 1),
                mtu: 1500,
            })
            .seal(),
            network::SocketSeal::ConfinedFamilies
        );
        assert_eq!(network::NetPlan::none().to_string(), "none");
        assert_eq!(network::NetPlan::isolated().to_string(), "isolated");
        assert_eq!(network::NetPlan::host().to_string(), "host_ip");
        assert_eq!(
            network::SocketSeal::Full.to_string(),
            "full",
            "the full seal must not display as the plan name `none`, which reads as no seal"
        );
        assert_eq!(
            network::SocketSeal::ConfinedFamilies.to_string(),
            "confined-families"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn none_plan_refuses_vsock_family() {
        let plan = network::NetPlan::none();
        assert!(
            plan.blocks_outside_sockets(),
            "a none plan must block outside sockets"
        );

        // The provider is the consumer-facing surface: `network_for` maps every
        // no-net consumer — a `--network none` session's interactive box and a
        // no-net task's sandbox alike (`task_network` goes through the same
        // mapping) — to `NoNet`, so pinning that its plan seals is pinning the
        // task path, not just the session path.
        let no_net = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("building a current-thread runtime for the provider pin")
            .block_on(network::NoNet.plan())
            .expect("NoNet plans do not fail");
        assert!(
            no_net.blocks_outside_sockets(),
            "the NoNet provider must yield the sealing plan for every consumer it plans"
        );

        let filter = build_socket_family_filter(network::SocketSeal::Full);
        assert_eq!(filter.seal, network::SocketSeal::Full);
        assert_eq!(
            filter.refused_families, "every family but unix",
            "the launch log must name what the seal refuses"
        );

        let run = |nr: i64, arch: u32, arg0: u32| {
            run_seccomp_program(&filter.program, nr as u32, arch, arg0)
        };
        let refuse = libc::SECCOMP_RET_ERRNO | (libc::EAFNOSUPPORT as u32);
        // AUDIT_ARCH_I386: the compat ABI an x86_64 kernel also answers to.
        const FOREIGN_ARCH: u32 = 0x4000_0003;

        assert_eq!(
            run(libc::SYS_socket, AUDIT_ARCH, libc::AF_VSOCK as u32),
            refuse,
            "socket(AF_VSOCK) must fail with EAFNOSUPPORT"
        );
        assert_eq!(
            run(libc::SYS_socketpair, AUDIT_ARCH, libc::AF_INET as u32),
            refuse,
            "socketpair(AF_INET) must fail with EAFNOSUPPORT"
        );
        assert_eq!(
            run(libc::SYS_socket, AUDIT_ARCH, libc::AF_UNIX as u32),
            libc::SECCOMP_RET_ALLOW,
            "socket(AF_UNIX) must stay allowed"
        );
        assert_eq!(
            run(libc::SYS_read, AUDIT_ARCH, 0),
            libc::SECCOMP_RET_ALLOW,
            "a syscall that creates no socket must stay allowed"
        );
        assert_eq!(
            run(libc::SYS_socket, FOREIGN_ARCH, libc::AF_VSOCK as u32),
            libc::SECCOMP_RET_KILL_PROCESS,
            "a foreign-ABI caller must be killed, not allowed"
        );
        #[cfg(target_arch = "x86_64")]
        assert_eq!(
            run(
                libc::SYS_socket | i64::from(X32_SYSCALL_BIT),
                AUDIT_ARCH,
                libc::AF_VSOCK as u32
            ),
            libc::SECCOMP_RET_KILL_PROCESS,
            "an x32 caller must be killed, not allowed"
        );

        // The program above is what ships; these probes run the shipped
        // filter against the kernel this test executes on, exactly the way a
        // none-box child experiences it: install via `prctl` + `seccomp`,
        // then call `socket(2)` for real.  A control child runs unfiltered,
        // so a family the kernel itself cannot create (no AF_VSOCK driver,
        // say) is told apart from one the filter refused.
        let unfiltered = probe_socket_families_in_child(None)
            .expect("running the unfiltered socket-family probe");
        let filtered = probe_socket_families_in_child(Some(socket_family_filter_for_none_box()))
            .expect("running the none-filtered socket-family probe");
        let [unix, inet, inet6, vsock] = filtered;
        assert_eq!(
            unix, 0,
            "the filter must keep AF_UNIX sockets working (errno {unix})"
        );
        assert_eq!(
            inet,
            libc::EAFNOSUPPORT as u8,
            "the filter must refuse AF_INET with EAFNOSUPPORT"
        );
        assert_eq!(
            inet6,
            libc::EAFNOSUPPORT as u8,
            "the filter must refuse AF_INET6 with EAFNOSUPPORT"
        );
        assert_eq!(
            vsock,
            libc::EAFNOSUPPORT as u8,
            "the filter must refuse AF_VSOCK with EAFNOSUPPORT — the family \
             that bypasses the network namespace is the point of the seal"
        );
        // Where the control child could create the family at all, the filter
        // is what refused it; where the kernel never could, the refusal above
        // matches what the kernel already answers and says so, so a missing
        // driver on the host is never mistaken for the seal working.
        for (i, (name, _)) in PROBED_FAMILIES.iter().enumerate().skip(1) {
            if unfiltered[i] != 0 {
                eprintln!(
                    "note: this kernel creates no {name} sockets (errno {}), \
                     so the filtered refusal matches what it already answers",
                    unfiltered[i]
                );
            }
        }
    }

    /// Every box refuses the socket families its network namespace does not
    /// confine, whatever its network mode.  The plan picks the seal — the
    /// full `none` seal for [`NetPlan::none`], the confined-families seal for
    /// every other plan — and the seal picks the filter.  Both are
    /// allowlists: the none seal admits `AF_UNIX` alone; the
    /// confined-families seal admits the families the box's own network
    /// namespace confines (`AF_UNIX`, `AF_INET`, `AF_INET6`, `AF_NETLINK`,
    /// `AF_PACKET`), so it refuses `AF_VSOCK` — the family that reaches the
    /// host whatever namespace the caller sits in — along with every other
    /// family outside its list, without needing any of them named: the
    /// simulated families below include `AF_BLUETOOTH` and `AF_ALG`, refused
    /// because the allowlist does not carry them.  The confined seal's
    /// program is what ships; these probes run the shipped filter against
    /// the kernel this test executes on, exactly the way a host-address or
    /// own-address box experiences it: install via `prctl` + `seccomp`, then
    /// call `socket(2)` for real.  A control child runs unfiltered, so a
    /// family the kernel itself cannot create (no AF_VSOCK driver, say) is
    /// told apart from one the filter refused.
    #[cfg(target_os = "linux")]
    #[test]
    fn every_box_refuses_namespace_bypass_families() {
        let tap = network::TapSpec {
            address: std::net::Ipv4Addr::new(10, 0, 0, 2),
            netmask: std::net::Ipv4Addr::new(255, 255, 255, 0),
            gateway: std::net::Ipv4Addr::new(10, 0, 0, 1),
            mtu: 1500,
        };
        let plans: [(&str, network::NetPlan, network::SocketSeal, bool); 4] = [
            (
                "host_ip",
                network::NetPlan::host(),
                network::SocketSeal::ConfinedFamilies,
                true,
            ),
            (
                "isolated",
                network::NetPlan::isolated(),
                network::SocketSeal::ConfinedFamilies,
                true,
            ),
            (
                "own_ip",
                network::NetPlan::isolated_with_tap(tap),
                network::SocketSeal::ConfinedFamilies,
                true,
            ),
            (
                "none",
                network::NetPlan::none(),
                network::SocketSeal::Full,
                false,
            ),
        ];
        let refuse = libc::SECCOMP_RET_ERRNO | (libc::EAFNOSUPPORT as u32);
        for (name, plan, seal, admits_inet) in plans {
            assert_eq!(plan.to_string(), name, "the plan under test");
            assert_eq!(plan.seal(), seal, "plan {name} must run under its seal");
            let filter = socket_family_filter_for_plan(&plan);
            assert_eq!(
                filter.seal, seal,
                "plan {name}: the seal selects the filter"
            );
            let run = |nr: i64, arch: u32, arg0: u32| {
                run_seccomp_program(&filter.program, nr as u32, arch, arg0)
            };
            assert_eq!(
                run(libc::SYS_socket, AUDIT_ARCH, libc::AF_VSOCK as u32),
                refuse,
                "{name}: socket(AF_VSOCK) must fail with EAFNOSUPPORT — the \
                 family that bypasses every network namespace is the point of \
                 the seal"
            );
            assert_eq!(
                run(libc::SYS_socketpair, AUDIT_ARCH, libc::AF_VSOCK as u32),
                refuse,
                "{name}: socketpair(AF_VSOCK) must fail with EAFNOSUPPORT"
            );
            assert_eq!(
                run(libc::SYS_read, AUDIT_ARCH, 0),
                libc::SECCOMP_RET_ALLOW,
                "{name}: a syscall that creates no socket must stay allowed"
            );
            // The allowlist is what meets "every family the namespace does
            // not confine" without enumerating it: a family outside the
            // list is refused whatever it is, the bypass families the old
            // denylist named beside AF_VSOCK included.  The family numbers
            // are cast where they are known-positive constants, the same
            // shape the seal's admitted list uses.
            const BYPASSED_FAMILIES: [u32; 2] = [libc::AF_BLUETOOTH as u32, libc::AF_ALG as u32];
            for bypassed in BYPASSED_FAMILIES {
                assert_eq!(
                    run(libc::SYS_socket, AUDIT_ARCH, bypassed),
                    refuse,
                    "{name}: socket({bypassed}) must fail with EAFNOSUPPORT — \
                     no family outside the seal's list may survive it"
                );
            }
            if admits_inet {
                assert_eq!(
                    run(libc::SYS_socket, AUDIT_ARCH, libc::AF_INET as u32),
                    libc::SECCOMP_RET_ALLOW,
                    "{name}: a networked box must keep its inet sockets"
                );
                assert_eq!(
                    run(libc::SYS_socket, AUDIT_ARCH, libc::AF_INET6 as u32),
                    libc::SECCOMP_RET_ALLOW,
                    "{name}: a networked box must keep its inet6 sockets"
                );
                assert_eq!(
                    run(libc::SYS_socket, AUDIT_ARCH, libc::AF_UNIX as u32),
                    libc::SECCOMP_RET_ALLOW,
                    "{name}: a networked box must keep its unix sockets"
                );
                assert_eq!(
                    run(libc::SYS_socket, AUDIT_ARCH, libc::AF_NETLINK as u32),
                    libc::SECCOMP_RET_ALLOW,
                    "{name}: a networked box must keep its netlink sockets — \
                     the namespace confines them"
                );
                assert_eq!(
                    run(libc::SYS_socket, AUDIT_ARCH, libc::AF_PACKET as u32),
                    libc::SECCOMP_RET_ALLOW,
                    "{name}: the packet family must stay admitted by the seal — \
                     its refusal is the missing CAP_NET_RAW (NET-083), not \
                     this filter's"
                );
            } else {
                assert_eq!(
                    run(libc::SYS_socket, AUDIT_ARCH, libc::AF_INET as u32),
                    refuse,
                    "{name}: the none seal must refuse AF_INET with EAFNOSUPPORT"
                );
            }
        }

        // The confined-families seal, against the live kernel: the shipped
        // filter is installed in a forked child and every probed family is
        // asked for for real, with the unfiltered control child from above as
        // the witness for what the kernel could do on its own.
        let unfiltered = probe_socket_families_in_child(None)
            .expect("running the unfiltered socket-family probe");
        let confined =
            probe_socket_families_in_child(Some(socket_family_filter_for_confined_families()))
                .expect("running the confined-families socket-family probe");
        let [unix, inet, inet6, vsock] = confined;
        assert_eq!(
            unix, 0,
            "a confined-families-sealed box keeps AF_UNIX sockets (errno {unix})"
        );
        assert_eq!(
            inet, 0,
            "a confined-families-sealed box keeps AF_INET sockets (errno {inet})"
        );
        assert_eq!(
            inet6, 0,
            "a confined-families-sealed box keeps AF_INET6 sockets (errno {inet6})"
        );
        assert_eq!(
            vsock,
            libc::EAFNOSUPPORT as u8,
            "the confined-families seal must refuse AF_VSOCK with EAFNOSUPPORT \
             — the family that bypasses the network namespace is the point of \
             the seal"
        );
        for (i, (name, _)) in PROBED_FAMILIES.iter().enumerate().skip(1) {
            if unfiltered[i] != 0 {
                eprintln!(
                    "note: this kernel creates no {name} sockets (errno {}), \
                     so the filtered refusal matches what it already answers",
                    unfiltered[i]
                );
            }
        }
    }

    /// After a successful `Sandbox::new`, the minenv Unix socket must be connectable.
    /// This exercises the channel listener thread: if the thread failed to bind or
    /// is not running, the connect call would fail.
    #[test]
    fn sandbox_new_minenv_socket_is_connectable() {
        use std::os::unix::net::UnixStream;
        let (_tmp, base) = make_base_with_synth();
        let config = Config::new("test-socket");
        let sandbox = Sandbox::new(base, config, ()).unwrap();
        let sock = sandbox.base_dir.join("run").join("minenv_sock");
        UnixStream::connect(&sock).expect("minenv_sock should be connectable after Sandbox::new");
    }

    /// A `BoundDir` (task) sandbox configured with a nested working directory
    /// and a mix of file and directory mappings must construct successfully and
    /// come up fully operational. This drives the `WdSetup::BoundDir` arm of
    /// `Sandbox::new` — shadow-cwd creation and the fs-mapping target loop —
    /// which every other constructor test (all `Isolated`) leaves unexercised.
    /// The asserted contract mirrors the `Isolated` socket test: `new` returns
    /// `Ok` and the minenv socket is connectable, proving the constructor ran to
    /// completion for a bound-dir config rather than panicking or erroring in
    /// the bound-dir branch.
    #[test]
    fn sandbox_new_accepts_bound_dir_with_file_and_dir_mappings() {
        use std::os::unix::net::UnixStream;
        let (_tmp, base) = make_base_with_synth();
        let file_mapping = common::FsMapping {
            host_path: "/host/etc/app.conf".to_string(),
            sandbox_path: Some("/etc/app.conf".to_string()),
            is_file: true,
            ..Default::default()
        };
        let dir_mapping = common::FsMapping {
            host_path: "/host/opt/data".to_string(),
            sandbox_path: Some("/opt/data".to_string()),
            is_file: false,
            ..Default::default()
        };
        let config = Config::new("test-bound-dir").with_wd(
            "/work/project",
            false,
            vec![file_mapping, dir_mapping],
        );
        let sandbox = Sandbox::new(base, config, ())
            .expect("bound-dir sandbox with file and dir mappings should construct");
        let sock = sandbox.base_dir.join("run").join("minenv_sock");
        UnixStream::connect(&sock)
            .expect("minenv_sock should be connectable after a bound-dir Sandbox::new");
    }

    // ---------------------------------------------------------------------
    // NET-079: each host-address box in its own classifier leaf, kept there.
    // ---------------------------------------------------------------------

    /// The mount-table half of the confinement: which cgroup2 mounts a host's
    /// `mountinfo` names, which one a classifier tree lives on, and whether
    /// it carries `nsdelegate` — the option that makes a cgroup namespace a
    /// delegation boundary, without which a guest's pid 1 refuses to place
    /// boxes at all (design §7.1). Pure over its input, so the reading a
    /// real host's mount table gives can be asserted against a mount table
    /// this test controls.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_mount_table_names_the_cgroup2_mounts_and_their_nsdelegate() {
        // A real mount table's shape, with the decoys: other filesystems,
        // another cgroup2 mounted elsewhere, and one mounted without
        // `nsdelegate` — the host a box's confinement silently rests on
        // nothing (D3) must be told apart from one mounted with it.
        let mountinfo = concat!(
            "35 30 0:26 / /sys/fs/cgroup rw,relatime shared:2 - cgroup2 cgroup2 rw,nsdelegate\n",
            "32 22 0:25 / /run/other rw - tmpfs tmpfs rw\n",
            "36 30 0:27 / /custom/cgroup rw - cgroup2 cgroup2 rw,memory_recursiveprot\n",
            "33 22 0:24 / /proc rw,nosuid - proc proc rw\n",
        );

        let mounts = classifier::host_cgroup2_mounts(mountinfo);
        assert_eq!(
            mounts,
            vec![
                (PathBuf::from("/sys/fs/cgroup"), true),
                (PathBuf::from("/custom/cgroup"), false),
            ],
            "only cgroup2 rows count, each with its own nsdelegate state"
        );

        let tree = Path::new("/sys/fs/cgroup/minimald.slice");
        assert_eq!(
            classifier::cgroup2_covering(tree, mountinfo),
            Some((PathBuf::from("/sys/fs/cgroup"), true)),
            "the deepest cgroup2 mount containing the tree is the one it lives on"
        );
        assert!(
            classifier::tree_is_real(tree, Some(mountinfo), false)
                && classifier::tree_is_real(tree, Some(mountinfo), true),
            "a tree on a cgroup2 mounted nsdelegate decides boxes, for a \
             native daemon and for the guest's pid 1 alike"
        );

        // A tree on a cgroup2 without `nsdelegate`: natively still a tree —
        // the privileged step refuses to install one there, so whatever is
        // found under it is treated as one, the box's own read-only view
        // being the barrier in front of it either way — but for a guest,
        // whose own boot path is the only thing that could have mounted that
        // cgroup2, it is a broken image, and the guest refuses boxes rather
        // than run them unenforced (design §7.1).
        let undelegated = Path::new("/custom/cgroup/minimald.slice");
        assert_eq!(
            classifier::cgroup2_covering(undelegated, mountinfo),
            Some((PathBuf::from("/custom/cgroup"), false)),
            "the covering mount is found wherever cgroup2 was mounted"
        );
        assert!(
            classifier::tree_is_real(undelegated, Some(mountinfo), false),
            "natively, a tree on a cgroup2 without nsdelegate still places boxes"
        );
        assert!(
            !classifier::tree_is_real(undelegated, Some(mountinfo), true),
            "in a guest, a tree on a cgroup2 without nsdelegate decides nothing"
        );

        // A deeper cgroup2 mount the tree could sit under is the one that
        // decides — a nested mount changes where the tree's files live.
        let nested = concat!(
            "35 30 0:26 / /sys/fs/cgroup rw,relatime shared:2 - cgroup2 cgroup2 rw,nsdelegate\n",
            "37 35 0:26 /minimald.slice /sys/fs/cgroup/minimald.slice rw - cgroup2 cgroup2 rw\n",
        );
        assert_eq!(
            classifier::cgroup2_covering(tree, nested),
            Some((PathBuf::from("/sys/fs/cgroup/minimald.slice"), false)),
            "the deepest mount containing the tree wins over the shallower one"
        );

        // And the states that decide nothing at all: a directory tree under
        // no cgroup2 mount is plain directories — a box "placed" there would
        // run unenforced while looking placed — and a mount table that cannot
        // be read is a host nothing can be checked against.
        let no_cgroup2 = "33 22 0:24 / / rw - ext4 /dev/root rw\n";
        assert!(
            !classifier::tree_is_real(tree, Some(no_cgroup2), false),
            "a tree under no cgroup2 mount moves nothing and decides nothing"
        );
        assert!(
            !classifier::tree_is_real(tree, None, false),
            "a host whose mount table cannot be read has no tree to check"
        );
    }

    /// The files the kernel makes when a cgroup is created, modelled over a
    /// stand-in tree: `cgroup.procs` and `cgroup.threads` — the two migration
    /// files, empty because a fresh cgroup holds no process — and
    /// `cgroup.subtree_control`, which the kernel puts in every cgroup. A real
    /// tree is never asked to have these made for it: the kernel makes them
    /// at `mkdir` time, and their absence over a stand-in is the one gap in
    /// the model.
    #[cfg(target_os = "linux")]
    const CGROUP_KERNEL_FILES: [&str; 3] =
        ["cgroup.procs", "cgroup.threads", "cgroup.subtree_control"];

    /// Stands in for the kernel over a stand-in tree: writes
    /// [`CGROUP_KERNEL_FILES`] into `dir`, empty, as the kernel leaves them
    /// when it makes a cgroup.
    #[cfg(target_os = "linux")]
    fn model_cgroup_files(dir: &Path) {
        for name in CGROUP_KERNEL_FILES {
            std::fs::write(dir.join(name), "")
                .unwrap_or_else(|e| panic!("modeling {name} in {}: {e}", dir.display()));
        }
    }

    /// C source for the probe this proof runs inside a box. It reports its
    /// own pid (the one that wrote itself into its leaf), the box's own
    /// cgroup as the kernel names it, the cover its pre-exec closure took
    /// (`MINIMAL_CLASSIFIER_COVER`: the design's `cgroup2` view of its own
    /// namespace root, or the recorded `tmpfs-fallback`), and then whatever
    /// its argv asks of the mountpoint — what filesystem sits there, what
    /// the box can read there, which migration paths open for writing — and
    /// can hold the box in its leaf until a release file appears, so the
    /// test can read the host's side of the tree while the box is still in
    /// it.
    #[cfg(target_os = "linux")]
    const CGROUP_PROBE_C: &str = r#"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/statfs.h>
#include <time.h>
#include <unistd.h>

int main(int argc, char **argv) {
    /* Unbuffered: every line is through the pipe the moment it is printed,
       so a box held in its leaf reports live — the report does not wait for
       the exit the hold delays, and a lost release file still leaves the
       reader a report it can read. */
    setvbuf(stdout, NULL, _IONBF, 0);

    /* The box's own cgroup as the kernel names it: once the box has joined
       its leaf and unshared its cgroup namespace onto it, this is 0::/ — the
       box stands at the root of its own cgroup namespace, its own leaf. */
    FILE *cg = fopen("/proc/self/cgroup", "r");
    char line[256];
    if (cg && fgets(line, sizeof line, cg)) {
        line[strcspn(line, "\n")] = 0;
        printf("self_cgroup: %s\n", line);
    } else {
        printf("self_cgroup: unreadable\n");
    }
    if (cg) fclose(cg);

    /* The pid that joined the leaf, for the test to find in the leaf's own
       cgroup.procs afterwards. */
    printf("pid: %ld\n", (long)getpid());

    /* The cover the box's pre-exec closure took over its classifier tree,
       marked in the box's own environment: the design's read-only cgroup2
       mount of the namespace root, or the recorded tmpfs fallback where the
       kernel refused that mount. What each branch can reach — its own
       limit, another leaf — is what the test asserts per branch. */
    const char *cover = getenv("MINIMAL_CLASSIFIER_COVER");
    printf("cover: %s\n", cover ? cover : "unset");

    /* argv[i] names an operation on a path:
         STATFS:<path>  what filesystem is mounted there — the cover itself;
         READ:<path>    what the box can read: its own limit
                        (<mountpoint>/memory.max) where a cgroup-aware
                        runtime looks, or nothing at all;
         WRITE:<path>   the migration paths that must not open: the box's
                        own root cgroup.procs (writing a pid there is
                        leaving the leaf, which is what confinement forbids)
                        and a sibling leaf's cgroup.procs (the file a pid is
                        written into to join another box's verdict);
         HOLD:<path>    stay in the leaf until that path appears, so the test
                        can read the host's side of the tree — the leaf's
                        cgroup.procs, which the kernel empties the moment the
                        box's last process exits — while the box is still in
                        it. The hold runs last, when every line of the report
                        is already out. */
    const char *release = NULL;
    for (int i = 1; i < argc; i++) {
        if (strncmp(argv[i], "STATFS:", 7) == 0) {
            const char *path = argv[i] + 7;
            struct statfs st;
            if (statfs(path, &st) == 0)
                printf("fstype %s: magic %lu\n", path, (unsigned long)st.f_type);
            else
                printf("fstype %s: errno %d\n", path, errno);
        } else if (strncmp(argv[i], "READ:", 5) == 0) {
            const char *path = argv[i] + 5;
            int fd = open(path, O_RDONLY | O_CLOEXEC);
            if (fd >= 0) {
                printf("read %s: errno 0\n", path);
                close(fd);
            } else {
                printf("read %s: errno %d\n", path, errno);
            }
        } else if (strncmp(argv[i], "WRITE:", 6) == 0) {
            const char *path = argv[i] + 6;
            int fd = open(path, O_WRONLY | O_CLOEXEC);
            if (fd >= 0) {
                printf("open %s: errno 0\n", path);
                close(fd);
            } else {
                printf("open %s: errno %d\n", path, errno);
            }
        } else if (strncmp(argv[i], "HOLD:", 5) == 0) {
            release = argv[i] + 5;
        }
    }

    /* 10s of waiting — shorter than the reader's deadline, so a lost release
       file is a box the reader still sees out, never a report that times
       out. */
    if (release) {
        for (int tries = 0; tries < 200 && access(release, F_OK) != 0; tries++) {
            struct timespec ts = {0, 50 * 1000 * 1000};
            nanosleep(&ts, 0);
        }
    }
    return 0;
}
"#;

    /// `CGROUP2_SUPER_MAGIC` — what the tree bound for the join reports on a
    /// host with no classifier leaf: the box launched without a placement is
    /// launched exactly as before, and the mountpoint still names the tree
    /// the sandbox would have bound.
    ///
    /// `TMPFS_SUPER_MAGIC` — what the cover mounted over that bind reports
    /// once the join has run: the box is left no cgroup path to resolve at
    /// all, and the host's cgroup mount stays out of the box's mount
    /// namespace.
    #[cfg(target_os = "linux")]
    const CGROUP2_SUPER_MAGIC: u64 = 0x6367_7270;
    #[cfg(target_os = "linux")]
    const TMPFS_SUPER_MAGIC: u64 = 0x0102_1994;

    /// The longest path an `AF_UNIX` socket may take: `sockaddr_un::sun_path`
    /// holds 108 bytes including the terminating NUL.
    #[cfg(target_os = "linux")]
    const SUN_PATH_MAX: usize = 107;

    /// Whether a box can be built under `candidate`, for a box named `name`.
    ///
    /// The box's environment socket lives at
    /// `<candidate>/sandbox/<name>-<timestamp>-<attempt>-<pid>/run/minenv_sock`,
    /// and the bind is refused with `EINVAL` when that path does not fit the
    /// 108 bytes `sun_path` holds. Hakoniwa also re-issues its read-only bind
    /// flags with `MS_REMOUNT` inside the user namespace, which may not
    /// *clear* a flag the underlying mount holds — so a `nodev` tmpfs (an
    /// ordinary `/tmp`) refuses with `EPERM`, and a `noexec` filesystem could
    /// not run the probe either.
    #[cfg(target_os = "linux")]
    fn hosts_a_box(candidate: &Path, name: &str) -> Result<(), String> {
        use nix::sys::statfs::statfs;
        use nix::sys::statvfs::FsFlags;

        let probe = tempfile::tempdir_in(candidate)
            .map_err(|e| format!("cannot create a temp dir here: {e}"))?;
        let flags = statfs(probe.path())
            .map_err(|e| format!("statfs failed: {e}"))?
            .flags();
        if flags.contains(FsFlags::ST_NODEV) {
            return Err("the filesystem is mounted nodev".to_string());
        }
        if flags.contains(FsFlags::ST_NOEXEC) {
            return Err("the filesystem is mounted noexec".to_string());
        }
        // The real name shape: `<name>-<timestamp>-<attempt>-<pid>`, with the
        // timestamp and pid at the sizes they actually reach.
        let below = format!("/sandbox/{name}-1790441721-0-1048576/run/minenv_sock");
        let socket_len = probe.path().as_os_str().len() + below.len();
        if socket_len > SUN_PATH_MAX {
            return Err(format!(
                "the box's socket path under it would be {socket_len} bytes, \
                 past the {SUN_PATH_MAX} an AF_UNIX path may be"
            ));
        }
        Ok(())
    }

    /// The first directory on this host that can host a box: the host's tmp
    /// first, then the conventional scratch and runtime directories, then the
    /// cargo target directory's tmp. A host with nowhere is told what every
    /// candidate was refused for.
    #[cfg(target_os = "linux")]
    fn box_base_dir(name: &str) -> PathBuf {
        let candidates = vec![
            std::env::temp_dir(),
            PathBuf::from("/var/tmp"),
            PathBuf::from("/run"),
            PathBuf::from("/state"),
            std::env::var_os("CARGO_TARGET_DIR")
                .map(|dir| PathBuf::from(dir).join("tmp"))
                .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/tmp")),
        ];
        let mut refusals = Vec::new();
        let chosen = candidates
            .into_iter()
            .find(|candidate| match hosts_a_box(candidate, name) {
                Ok(()) => true,
                Err(reason) => {
                    refusals.push(format!("{}: {}", candidate.display(), reason));
                    false
                }
            })
            .unwrap_or_else(|| {
                panic!(
                    "no directory on this host can host the box this proof needs: {}",
                    refusals.join("; ")
                )
            });
        if refusals.is_empty() {
            eprintln!("box base: {}", chosen.display());
        } else {
            eprintln!(
                "box base: {} (refused: {})",
                chosen.display(),
                refusals.join("; ")
            );
        }
        chosen
    }

    /// Compiles the cgroup probe statically, so it runs in the minimal rootfs
    /// this proof builds for the box. Panics when no C compiler is on `PATH`
    /// rather than skipping: the proof only reaches this on a host whose
    /// user-namespace gate passed, so a missing compiler is a host that
    /// promised to run it and cannot.
    #[cfg(target_os = "linux")]
    fn compile_cgroup_probe(base: &Path) -> PathBuf {
        let src = base.join("cgroup_probe.c");
        let bin = base.join("cgroup_probe");
        std::fs::write(&src, CGROUP_PROBE_C).expect("writing the cgroup probe source");
        let status = std::process::Command::new("gcc")
            .args(["-static", "-o"])
            .arg(&bin)
            .arg(&src)
            .status()
            .expect("spawning gcc to compile the cgroup probe");
        assert!(
            status.success(),
            "gcc failed to compile the cgroup probe: {status:?}"
        );
        bin
    }

    /// A minimal rootfs holding the probe at `/usr/bin/probe`, with the
    /// directories the sandbox layer needs (`usr/lib` for its symlink, `etc`
    /// for hakoniwa's rootfs setup).
    #[cfg(target_os = "linux")]
    fn probe_rootfs(dir: &Path, probe: &Path) {
        std::fs::create_dir_all(dir.join("usr").join("bin"))
            .expect("creating the probe rootfs usr/bin");
        std::fs::copy(probe, dir.join("usr").join("bin").join("probe"))
            .expect("copying the probe into the rootfs");
        std::fs::create_dir_all(dir.join("usr").join("lib"))
            .expect("creating the probe rootfs usr/lib");
        std::fs::create_dir_all(dir.join("etc")).expect("creating the probe rootfs etc");
    }

    /// A probe box this proof launched and is holding in its leaf: the
    /// report is not read yet — the probe's `HOLD:` argument keeps the box
    /// in its leaf until the release file appears — so the test can read the
    /// host's side of the tree while the box is still in it.
    ///
    /// The release handshake and the closure's report both run through the
    /// sandbox's `/run`: it is the one live directory the host and the box
    /// share — the bind is of the same directory, not a copy — where the
    /// rootfs is assembled by hardlink, so a file created in its source
    /// directory after the build never appears inside the box at all.
    #[cfg(target_os = "linux")]
    struct HeldProbe {
        /// The probe's `key: value` report, read to EOF in the background:
        /// the read finishes when the box exits, which the hold delays, and
        /// the probe's stdout is unbuffered, so every line it prints is
        /// already through the pipe while the box is held.
        report: tokio::task::JoinHandle<Result<std::collections::BTreeMap<String, String>, String>>,
        /// Creating this file releases the box's hold: the host-side twin of
        /// the `HOLD:/run/<name>` path the probe polls.
        release: PathBuf,
        /// The box's sandbox base directory, whose `run` is the box's `/run`
        /// — also where the pre-exec closure's cover report lands.
        base: PathBuf,
        /// Keeps the box's sandbox — and with it that base directory —
        /// alive: the sandbox's own `Drop` removes the directory, and a held
        /// probe reads the release and report files out of it. Dropped when
        /// the probe's report is read.
        keep_alive: Box<dyn Send>,
    }

    #[cfg(target_os = "linux")]
    impl HeldProbe {
        /// Ends the box's hold: creates the file the box is polling for.
        fn release_hold(&self) {
            std::fs::write(&self.release, b"released\n")
                .unwrap_or_else(|e| panic!("releasing the held box: {e}"));
        }

        /// The probe's report, once the box has run to its end.
        async fn report(self) -> std::collections::BTreeMap<String, String> {
            // The box's sandbox stays alive until the report is in: the
            // report is read from the child's stdout, and the tests read the
            // base directory's other files — the closure's report, the
            // hold's release — while the box is still held, which is this
            // value's whole purpose.
            let keep_alive = self.keep_alive;
            let report = self.report;
            let placed = report
                .await
                .expect("reading the held probe's report")
                .expect("the probe in the box reported");
            drop(keep_alive);
            placed
        }

        /// Releases the box and reads what it printed, in one step — for the
        /// boxes held only to keep their launch alive for the assertions.
        async fn release_and_report(self) -> std::collections::BTreeMap<String, String> {
            self.release_hold();
            self.report().await
        }
    }

    /// Launches a box — from the production launch path, the same
    /// `Sandbox::new_container` every session runs — named `name`, placed in
    /// `leaf` when there is one, running the probe with `probe_args` — and
    /// hands the box back *held*: the probe holds (`HOLD:/run/<name>` among
    /// its args) until [`HeldProbe::release_hold`] creates that file, and
    /// [`HeldProbe::report`] reads what the probe printed. With
    /// `force_cover_fallback` the box's cover is forced onto its tmpfs
    /// fallback — the branch a host whose kernel allows the design's
    /// cgroup2 mount would otherwise never take.
    #[cfg(target_os = "linux")]
    async fn launch_box_probe(
        name: &str,
        leaf: Option<config::ClassifierLeaf>,
        probe_args: &[String],
        force_cover_fallback: bool,
    ) -> HeldProbe {
        use std::io::Read as _;

        let base_dir = box_base_dir(name);
        let build = tempfile::tempdir_in(&base_dir)
            .unwrap_or_else(|e| panic!("a temp dir under {}: {e}", base_dir.display()));
        let probe = compile_cgroup_probe(build.path());
        let source = build.path().join("rootfs-src");
        probe_rootfs(&source, &probe);

        let mut config = Config::new(name)
            .with_rootfs(std::iter::once(SandboxMapped::Dir(source)))
            .with_dns(false);
        if let Some(leaf) = leaf {
            config = config.with_classifier_leaf(leaf);
        }
        if force_cover_fallback {
            config = config.with_forced_cover_fallback();
        }
        let sandbox_home = tempfile::tempdir_in(&base_dir)
            .unwrap_or_else(|e| panic!("a temp dir under {}: {e}", base_dir.display()));
        let mut sandbox = config
            .build(sandbox_home.path().join("sandbox"), ())
            .await
            .expect("building the box");

        let plan = sandbox.built_in_plan();
        let container = sandbox
            .new_container(&plan)
            .expect("building the box's container");
        let mut command = sandbox
            .command(
                &container,
                "/usr/bin/probe",
                probe_args.iter().cloned(),
                std::iter::empty::<(&str, &str)>(),
            )
            .expect("building the probe command");
        command.stdout(hakoniwa::Stdio::MakePipe);
        let mut child = command.spawn().expect("spawning the probe in the box");

        // The box's own `/run`, host-side: the hold's release file lands
        // here, and so does the report the box's pre-exec closure wrote.
        let run = sandbox.base_dir.join("run");
        let release = probe_args
            .iter()
            .find_map(|arg| arg.strip_prefix("HOLD:/run/"))
            .map_or_else(|| run.join("probe-not-held"), |file| run.join(file));

        let stdout = child.stdout.take().expect("the probe's stdout pipe");
        // The reader runs in the background: its EOF is the box's exit, which
        // the hold delays — this is the handshake's point — and its deadline
        // counts from the spawn. The box's 10s hold is the shorter of the
        // two, so a lost release file is a box that leaves on its own, never
        // a report that times out.
        let report = tokio::task::spawn(async move {
            let report = tokio::time::timeout(
                std::time::Duration::from_secs(30),
                tokio::task::spawn_blocking(move || {
                    let mut buf = Vec::new();
                    std::io::BufReader::new(stdout)
                        .read_to_end(&mut buf)
                        .expect("reading the probe's report");
                    buf
                }),
            )
            .await
            .map_err(|_| "the probe in the box did not report in time".to_string())?
            .expect("spawn_blocking join");
            let status = tokio::time::timeout(
                std::time::Duration::from_secs(10),
                tokio::task::spawn_blocking(move || child.wait()),
            )
            .await
            .map_err(|_| "waiting for the probe in the box timed out".to_string())?
            .expect("spawn_blocking join")
            .expect("waiting for the probe in the box");
            if !status.success() {
                return Err(format!(
                    "the probe in the box failed: {status:?}\nreport: {}",
                    String::from_utf8_lossy(&report)
                ));
            }
            Ok(String::from_utf8_lossy(&report)
                .lines()
                .filter_map(|line| {
                    line.split_once(": ")
                        .map(|(k, v)| (k.to_string(), v.to_string()))
                })
                .collect())
        });

        HeldProbe {
            report,
            release,
            base: sandbox.base_dir.clone(),
            // The box's sandbox stays alive for as long as the probe holds
            // the box: its own `Drop` removes the base directory, and the
            // two files this harness reads out of it — the closure's report
            // and the hold's release — live in that directory's `/run`.
            keep_alive: Box::new((sandbox, sandbox_home)),
        }
    }

    /// Launches a box — from the production launch path, the same
    /// `Sandbox::new_container` every session runs — named `name`, placed in
    /// `leaf` when there is one, running the probe with `probe_args`, and
    /// returns its `key: value` report: released at once, for the probes
    /// that hold nothing.
    #[cfg(target_os = "linux")]
    async fn box_probe_report(
        name: &str,
        leaf: Option<config::ClassifierLeaf>,
        probe_args: &[String],
    ) -> std::collections::BTreeMap<String, String> {
        let held = launch_box_probe(name, leaf, probe_args, false).await;
        held.release_hold();
        held.report().await
    }

    /// The daemon-side probe: a throwaway child of this process migrates
    /// into a throwaway leaf of the tree and back out, and the daemon's
    /// placement decision rests on what it reports — the same migration the
    /// box's own join makes, performed by a child that is gone before the
    /// box is spawned.
    ///
    /// Over a stand-in tree the probe can only be caught failing, and that
    /// failure is the one the design owes: nothing behind the stand-in makes
    /// the kernel's files when the probe makes its leaf, so the child
    /// reports the missing `cgroup.procs` rather than a placement — the probe
    /// never makes what it is looking for, which is what keeps it honest on
    /// a host whose tree is not a tree. The success half runs where the tree
    /// is real: it is the gate of `host_address_box_placed_in_leaf`.
    #[cfg(target_os = "linux")]
    #[test]
    fn probe_reports_a_leaf_it_cannot_place_a_child_in() {
        let tree = tempfile::tempdir().expect("a temp dir standing in for the tree");
        std::fs::create_dir_all(tree.path().join(classifier::BOXES_DIR))
            .expect("creating the cohort directory");

        // The probe asks its question in the subtree the box it is about is
        // declared into: a deny-all box is probed in `deny`, so that is the
        // cohort the stand-in tree needs and the one the throwaway leaf
        // lands in.
        let deny = tree
            .path()
            .join(classifier::BOXES_DIR)
            .join(config::DENY_DIR);
        std::fs::create_dir(&deny).expect("creating the deny subtree");

        let missing = classifier::probe_child_placement(tree.path(), config::Verdict::Deny)
            .expect_err("over a stand-in tree nothing made the probe leaf's cgroup.procs");
        assert_eq!(
            missing.kind(),
            std::io::ErrorKind::NotFound,
            "the probe's child opens the leaf's cgroup.procs without creating \
             it: a missing one is a missing leaf, reported rather than made"
        );

        // The leaf the probe made is not left behind by the failure either:
        // the probe owes the throwaway its removal whatever the answer was.
        assert!(
            !classifier::box_leaf(
                tree.path(),
                &format!("placement-probe-{}", std::process::id()),
                config::Verdict::Deny,
            )
            .exists(),
            "the throwaway leaf the probe made is gone, failure or not"
        );

        // A host with no cohort directory at all says the same thing one step
        // earlier: the probe never made its leaf.
        let bare = classifier::probe_child_placement(
            tree.path().join("no-such-tree").as_path(),
            config::Verdict::Deny,
        )
        .expect_err("the probe cannot make a leaf under a tree that is absent");
        assert_eq!(
            bare.kind(),
            std::io::ErrorKind::NotFound,
            "a missing cohort is a missing tree, not a probe that passes"
        );
    }

    /// NET-079. A box placed in its own classifier leaf can neither see nor
    /// join another box's leaf: the leaf is the root of its cgroup namespace.
    ///
    /// Three parts, each asserting the layer it owns:
    ///
    /// * **placement**, over a stand-in tree: the daemon's half is plain
    ///   filesystem work — the leaf created before the spawn, a process
    ///   moved by writing its pid to the leaf's `cgroup.procs`, the leaf
    ///   removed once the box is gone — asserted exactly, so the
    ///   daemon-side flow that mirrors it cannot drift from the primitive it
    ///   rests on.
    /// * **join order**, in a real box: the box's own first process joins
    ///   its leaf, through the tree the sandbox binds at the conventional
    ///   mountpoint, and *then* unshares its cgroup namespace onto it — so
    ///   the pid the box reports is the one in its leaf's `cgroup.procs`,
    ///   written by itself, and `/proc/self/cgroup` reads `0::/`: the box
    ///   stands at the root of its own cgroup namespace, which on a
    ///   tree-bearing host is its own leaf.
    /// * **visibility**, in the same box, asserted per branch: the box's
    ///   cover over the tree it joined through is the design's read-only
    ///   cgroup2 view of its own namespace root where the kernel allows
    ///   that mount, and the empty read-only tmpfs recorded as a fallback
    ///   where it refuses it — the branch the box reports it took, in its
    ///   environment and in the one-line report its pre-exec closure leaves
    ///   for the daemon in the sandbox's `/run`, is the one whose assertions
    ///   run. On the design's branch the host's cgroup mount stays out of
    ///   the box's mount namespace while the box's own hierarchy is there
    ///   to read, a sibling leaf's path does not resolve, and the root's
    ///   own `cgroup.procs` is readable but not writable (writing a pid
    ///   there is leaving the leaf, which is what confinement forbids); on
    ///   the fallback no cgroup file resolves at all, so no migration
    ///   write has a file to open. The fallback branch is also forced for
    ///   a second box, so it is exercised wherever the tests run rather
    ///   than only on a host the design's mount refuses.
    ///
    /// A box *without* a leaf is launched exactly as before: the placement is
    /// an opt-in per box, not a change to every sandbox (NET-079's exception).
    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn box_cannot_see_or_join_a_sibling_leaf() {
        if let Some(reason) = user_namespaces_restriction() {
            eprintln!(
                "skipping box_cannot_see_or_join_a_sibling_leaf: this host \
                 denies the unprivileged user namespace every sandbox starts \
                 by unsharing: {reason}"
            );
            return;
        }

        // --- placement: the daemon's half, over a stand-in tree -----------
        let tree = tempfile::tempdir().expect("a temp dir standing in for the tree");
        let boxes = tree.path().join(classifier::BOXES_DIR);
        std::fs::create_dir_all(&boxes).expect("creating the cohort directory");
        for subtree in [config::DENY_DIR, config::ALLOW_DIR] {
            std::fs::create_dir(boxes.join(subtree)).expect("creating the cohort's two subtrees");
        }

        // The box-id is derived from the session's name, which is user input.
        // A deny-all session names a leaf in the deny subtree — the one
        // subtree a session's declaration can land it in.
        let hostile = "box ../../cannot --see=or join";
        let leaf = classifier::create_box_leaf(tree.path(), hostile, config::Verdict::Deny)
            .expect("creating the box's leaf before its first process exists");
        assert_eq!(
            leaf,
            boxes
                .join(config::DENY_DIR)
                .join("box....cannot--seeorjoin"),
            "a session name is user input, so the leaf it names must be a \
             single sanitized component: its separators are dropped, so a \
             traversal (`../..`) cannot leave the cohort, and it never starts \
             with the kernel's own `cgroup.` prefix"
        );
        assert!(
            leaf.is_dir(),
            "the leaf exists before the box's first process does"
        );

        // The kernel makes a cgroup's files when it makes the cgroup; over a
        // stand-in tree nothing does, so the model stands in for the kernel
        // before any placement writes into them.
        model_cgroup_files(&leaf);

        // A process is moved by writing its pid to the leaf's cgroup.procs —
        // the one migration primitive the whole placement rests on, the same
        // one the box's own first process and an injected process both use.
        for pid in [1_u32, 4242] {
            classifier::place_pid(&leaf.join("cgroup.procs"), pid)
                .expect("moving a box process into its leaf");
        }
        assert_eq!(
            std::fs::read_to_string(leaf.join("cgroup.procs")).expect("reading the leaf's procs"),
            "1\n4242\n",
            "a process is placed by writing its pid, and a cgroup holds every \
             process that was moved into it"
        );

        // The leaf is removed once the box is gone, and removal is owed once
        // rather than exactly once. On a real tree the kernel holds the
        // membership itself, so nothing but the directory is ever left to
        // remove; over a stand-in tree the procs file the placements went
        // into stands in for them, so the model is dropped to represent
        // their departure.
        for name in CGROUP_KERNEL_FILES {
            std::fs::remove_file(leaf.join(name))
                .unwrap_or_else(|e| panic!("dropping the modelled {name}: {e}"));
        }
        classifier::remove_box_leaf(&leaf).expect("removing the box's leaf");
        assert!(
            !leaf.exists(),
            "a box's leaf does not outlive the box it decided"
        );
        classifier::remove_box_leaf(&leaf).expect("removing an already-removed leaf succeeds");

        // A leaf that already exists is a collision, not a reuse: the leaf is
        // named by the session that holds it, so a fresh launch finding one
        // is told — and the sweep below has already taken what a daemon
        // death left behind. The colliding session here is declared into
        // the allow subtree, so the collision is pinned in the other half of
        // the cohort too.
        classifier::create_box_leaf(
            tree.path(),
            "held by another session",
            config::Verdict::Allow,
        )
        .expect("creating the leaf a second session will collide with");
        let collision = classifier::create_box_leaf(
            tree.path(),
            "held by another session",
            config::Verdict::Allow,
        )
        .expect_err("a leaf another session holds is not taken over");
        assert_eq!(
            collision.kind(),
            std::io::ErrorKind::AlreadyExists,
            "the leaf is named by its session's id, so an existing one on a \
             fresh launch is a collision, never a directory to reuse"
        );
        classifier::remove_box_leaf(&classifier::box_leaf(
            tree.path(),
            "held by another session",
            config::Verdict::Allow,
        ))
        .expect("dropping the collision leaf now that it has done its work");

        // The sweep at daemon start takes the empty leaves a daemon death
        // leaves behind — and only those: a leaf that still holds a session
        // is refused by its `rmdir`, over a real tree because the kernel
        // will not remove a cgroup holding a process, and over this stand-in
        // because the modelled procs file stands in for them. The held leaf
        // and the abandoned one are deliberately in different subtrees, so
        // the sweep is proved to walk both and to refuse the occupied one
        // wherever it sits.
        let held =
            classifier::create_box_leaf(tree.path(), "a live session", config::Verdict::Deny)
                .expect("creating the leaf a live session holds");
        model_cgroup_files(&held);
        let empty =
            classifier::create_box_leaf(tree.path(), "an abandoned launch", config::Verdict::Allow)
                .expect("creating the leaf a daemon death left behind");
        assert_eq!(
            classifier::sweep_box_leaves(tree.path()).expect("sweeping the cohort at daemon start"),
            vec![empty.clone()],
            "the sweep removes the empty leaves and refuses the occupied ones"
        );
        assert!(
            held.is_dir(),
            "a leaf that still holds a session outlives the sweep: its \
             session's next launch reports the collision instead of reusing \
             the directory"
        );
        assert_eq!(
            classifier::sweep_box_leaves(tree.path().join("no-such-tree").as_path())
                .expect("a host with no tree sweeps nothing"),
            Vec::<PathBuf>::new(),
            "a missing cohort directory is a host with no tree at all, not a \
             sweep failure"
        );

        // A host without the tree says so in the error, not in a refusal: the
        // daemon reads this as "no per-box classifier on this host" and runs
        // the box unenforced (NET-079's exception) — or, in the guest, refuses
        // a host-address box rather than run it unenforced (design §7.1).
        let missing = classifier::create_box_leaf(
            tree.path().join("no-such-tree").as_path(),
            "b",
            config::Verdict::Deny,
        )
        .expect_err("a tree that was never installed refuses the leaf");
        assert_eq!(
            missing.kind(),
            std::io::ErrorKind::NotFound,
            "the missing tree is the one failure a launch must survive"
        );

        // --- in a real box: the box's own half -----------------------------
        // A tree with two leaves in it, standing in for the one the
        // privileged step installs: the box's own, and a sibling's it must
        // not be able to reach. Every path the box resolves below goes
        // through the tree bound at the conventional mountpoint — the same
        // spelling on a real tree and on a stand-in (see
        // `ClassifierLeaf::relative_dir`).
        let box_tree = tempfile::tempdir().expect("a temp dir standing in for the box's tree");
        std::fs::create_dir_all(box_tree.path().join(classifier::BOXES_DIR))
            .expect("creating the cohort directory");
        for subtree in [config::DENY_DIR, config::ALLOW_DIR] {
            std::fs::create_dir(box_tree.path().join(classifier::BOXES_DIR).join(subtree))
                .expect("creating the cohort's two subtrees");
        }
        // The box is declared deny-all, so its leaf is in the deny subtree;
        // the sibling it must not reach sits in the allow subtree, the
        // farthest leaf from it the cohort offers.
        let leaf = config::ClassifierLeaf::new(
            classifier::create_box_leaf(box_tree.path(), "cg-probe", config::Verdict::Deny)
                .expect("creating the box's leaf before its first process exists"),
        );
        let _sibling =
            classifier::create_box_leaf(box_tree.path(), "the-other-box", config::Verdict::Allow)
                .expect("creating the sibling's leaf, for the box to fail to reach");
        // The kernel made both leaves' files when it made the leaves; over a
        // stand-in tree nothing did, and the box's own join — the write its
        // pre-exec closure makes through the tree the sandbox bound — is
        // into the modelled procs file.
        model_cgroup_files(leaf.dir());
        model_cgroup_files(&classifier::box_leaf(
            box_tree.path(),
            "the-other-box",
            config::Verdict::Allow,
        ));

        let mountpoint = classifier::CONVENTIONAL_CGROUP2_MOUNTPOINT.to_string();
        let controllers = format!("{mountpoint}/cgroup.controllers");
        let root_procs = format!("{mountpoint}/cgroup.procs");
        let sibling_procs = classifier::box_leaf(
            Path::new(&mountpoint),
            "the-other-box",
            config::Verdict::Allow,
        )
        .join("cgroup.procs")
        .to_string_lossy()
        .into_owned();
        let probe_args = vec![
            format!("STATFS:{mountpoint}"),
            format!("READ:{controllers}"),
            format!("WRITE:{root_procs}"),
            format!("WRITE:{sibling_procs}"),
        ];

        let held = launch_box_probe("cg-probe", Some(leaf.clone()), &probe_args, false).await;
        // The channel the daemon reads, proved end to end: the box's
        // pre-exec closure leaves its one-line report in the sandbox's
        // `/run`, spelled there from the join path and here from the leaf
        // directory, so the daemon can say after the spawn which cover the
        // box took — or why it never reached its program. The closure has
        // written it before the probe it execs runs at all, so it is there
        // while the box is held.
        let report_path = held
            .base
            .join("run")
            .join(classifier::closure_report_name("cg-probe"));
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let closure_report = loop {
            match std::fs::read_to_string(&report_path) {
                Ok(report) => break report,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    assert!(
                        std::time::Instant::now() < deadline,
                        "the box's pre-exec closure wrote no report into {}",
                        report_path.display()
                    );
                    tokio::time::sleep(std::time::Duration::from_millis(25)).await;
                }
                Err(e) => panic!("reading the box's closure report: {e}"),
            }
        };
        held.release_hold();
        let placed = held.report().await;
        eprintln!(
            "a box with a leaf reports its own cgroup as: {}",
            placed
                .get("self_cgroup")
                .cloned()
                .unwrap_or_else(|| "nothing".to_string())
        );

        // The join, in the order the confinement rests on: the pid the box
        // reports is the one pid in its leaf's `cgroup.procs`, written by
        // the box's own first process through the tree the sandbox bound —
        // the daemon no longer places the program, the box places itself,
        // and it does so *before* it unshares its cgroup namespace onto the
        // leaf. Nothing else writes the file: no daemon-side placement runs
        // for this box, and a supervisor that never exec'd never reaches the
        // closure that joins.
        let pid = placed
            .get("pid")
            .cloned()
            .unwrap_or_else(|| "no report".to_string());
        let members =
            std::fs::read_to_string(leaf.procs()).expect("reading the leaf's procs afterwards");
        assert_eq!(
            members.lines().collect::<Vec<_>>(),
            vec![pid.as_str()],
            "the box's own first process wrote itself into its leaf before it \
             unshared its cgroup namespace onto it"
        );

        // The box stands at the root of its own cgroup namespace — `0::/`.
        // Over this stand-in tree that reading is what any process reports
        // after `unshare(CLONE_NEWCGROUP)` and proves the namespace was
        // taken, not where it is rooted: the root is the test runner's own
        // cgroup here. The kernel-held half — the host-side leaf's
        // `cgroup.procs` naming the box while the box reads `0::/` — is what
        // `host_address_box_placed_in_leaf` asserts on a delegated tree, the
        // only place the namespace root is pinned to the leaf by the kernel
        // itself.
        assert_eq!(
            placed.get("self_cgroup").map(String::as_str),
            Some("0::/"),
            "the box reads the root of its own cgroup namespace; that this \
             stand-in tree is not the kernel's own is why the membership, not \
             the reading, is what `host_address_box_placed_in_leaf` proves"
        );

        // The cover over the tree the box just joined through, asserted per
        // branch: the branch the box reports it took — in its environment
        // and in the closure's report — is the one whose assertions run, so
        // neither branch is pinned by claims the other disproves.
        let cover = placed
            .get("cover")
            .cloned()
            .unwrap_or_else(|| "no report".to_string());
        eprintln!("the box took the {cover} cover over its bound classifier tree");
        assert!(
            closure_report.trim().starts_with(&format!("cover {cover}")),
            "the closure's report into the sandbox's /run and its marker in \
             the box's environment name the same cover: the report says \
             {closure_report:?} while the box says {cover:?}"
        );
        match cover.as_str() {
            "cgroup2" => {
                // The design's cover: the host's cgroup mount stays out of
                // the box's mount namespace — the design's own wording of
                // the obligation — while the box keeps the view a
                // cgroup-aware runtime expects of a box: its own hierarchy,
                // rooted at its own leaf, there to read.
                let what_sits_there = placed
                    .get(&format!("fstype {mountpoint}"))
                    .cloned()
                    .unwrap_or_else(|| "no report".to_string());
                assert_eq!(
                    what_sits_there,
                    format!("magic {CGROUP2_SUPER_MAGIC}"),
                    "the box's own cgroup is mounted where a cgroup-aware \
                     runtime looks, read-only — covered, not hidden from \
                     itself"
                );
                assert_eq!(
                    placed
                        .get(&format!("read {controllers}"))
                        .map(String::as_str),
                    Some("errno 0"),
                    "the box's own cgroup resolves: the controllers file a \
                     cgroup-aware runtime starts from is there to read"
                );
                // And the barrier, on this branch asked of a kernel that
                // holds the memberships: the root's own cgroup.procs is
                // there to read but not to write — writing a pid there is
                // leaving the leaf — and which refusal answers depends on
                // who owns the file: the read-only mount answers `EROFS`
                // where the box's uid owns it (a systemd delegation chowns
                // its subtree to the daemon's account, which the box's uid
                // maps onto), and `EACCES` where it does not, the kernel
                // checking permission before the mount's flag. Either way
                // the migration is refused, not granted.
                let wrote_root = placed
                    .get(&format!("open {root_procs}"))
                    .cloned()
                    .unwrap_or_else(|| "no report".to_string());
                assert!(
                    wrote_root == "errno 30" || wrote_root == "errno 13",
                    "the box must not be able to write its own root's \
                     cgroup.procs — writing a pid there is leaving the leaf \
                     its verdict is decided on — but it reports {wrote_root:?}"
                );
                assert_eq!(
                    placed
                        .get(&format!("open {sibling_procs}"))
                        .map(String::as_str),
                    Some("errno 2"),
                    "a sibling leaf is not below the box's cgroup namespace \
                     root, so its path does not resolve at all — invisible, \
                     not merely unwritable"
                );
            }
            "tmpfs-fallback" => {
                // The recorded fallback: the box is left no cgroup hierarchy
                // to see at all, which is why the branch is recorded rather
                // than passed off as the design's cover.
                let what_sits_there = placed
                    .get(&format!("fstype {mountpoint}"))
                    .cloned()
                    .unwrap_or_else(|| "no report".to_string());
                assert_eq!(
                    what_sits_there,
                    format!("magic {TMPFS_SUPER_MAGIC}"),
                    "where the kernel refuses the design's cgroup2 mount, the \
                     tree the join went through is covered by an empty \
                     read-only tmpfs instead"
                );
                assert_eq!(
                    placed
                        .get(&format!("read {controllers}"))
                        .map(String::as_str),
                    Some("errno 2"),
                    "the cover holds on the fallback too: the controllers \
                     file a cgroup-aware runtime starts from is not there to \
                     find, so no cgroup file the box could name resolves at \
                     the mountpoint"
                );
                for (path, whose) in [
                    (&root_procs, "its own root's"),
                    (&sibling_procs, "another box's"),
                ] {
                    assert_eq!(
                        placed.get(&format!("open {path}")).map(String::as_str),
                        Some("errno 2"),
                        "the fallback leaves the box no cgroup path to open \
                         {whose} cgroup.procs through — a migration out of \
                         its leaf has no file to open, let alone permission \
                         to write"
                    );
                }
            }
            other => panic!("the box reported a cover this proof does not know: {other}"),
        }

        // The fallback branch is exercised deterministically wherever the
        // tests run, including on a host whose kernel allows the design's
        // mount: forced there for a second box, so the recorded branch is
        // never the one only a refusing host gets to see.
        let forced = launch_box_probe("cg-probe-fallback", Some(leaf), &probe_args, true)
            .await
            .release_and_report()
            .await;
        assert_eq!(
            forced.get("cover").map(String::as_str),
            Some("tmpfs-fallback"),
            "the forced-fallback box reports the recorded tmpfs cover"
        );
        assert_eq!(
            forced
                .get(&format!("fstype {mountpoint}"))
                .map(String::as_str),
            Some(&format!("magic {TMPFS_SUPER_MAGIC}")[..]),
            "the recorded fallback is the empty read-only tmpfs, deterministically"
        );

        // The placement is an opt-in per box: a box with no classifier leaf
        // is launched exactly as it always was — no tree bound, no cover
        // mounted, no join — so a host that cannot decide per box keeps
        // launching boxes (NET-079's exception).
        let unplaced = box_probe_report("cg-probe-plain", None, &probe_args).await;
        let still_there = unplaced
            .get(&format!("fstype {mountpoint}"))
            .cloned()
            .unwrap_or_else(|| "no report".to_string());
        assert_ne!(
            still_there,
            format!("magic {CGROUP2_SUPER_MAGIC}"),
            "a box with no classifier leaf gets no classifier tree at all: the \
             placement is an opt-in per box, not a change to every sandbox"
        );
    }

    /// NET-079 against the kernel's own bookkeeping: on a host whose
    /// classifier tree is real and delegated to this account, and where this
    /// process is inside it, the box's placement is a migration the kernel
    /// performed — the host-side `cgroup.procs` of the leaf names the box's
    /// process while the box reads `0::/` — which no stand-in tree can prove,
    /// because a stand-in has no kernel to hold the membership.
    ///
    /// The box is held in its leaf by a real release-file handshake through
    /// its own `/run` while the kernel's half is read, and the cover it took
    /// — the design's cgroup2 view of its own namespace root, or the recorded
    /// tmpfs where the kernel refuses that mount — is asserted per branch,
    /// against the branch the box itself reports: on the design's branch the
    /// sibling's path does not resolve while the box's own `memory.max` is
    /// readable, and on the fallback nothing cgroup-shaped is.
    ///
    /// Gated, with the reason printed, on the two halves the kernel needs:
    /// the tree installed and writable by this account, and a child of this
    /// process actually migrating into a leaf of it — the same probe the
    /// daemon's placement decision runs. Any host that never prepared the
    /// tree is told so, and a host that did not place its *daemon* in it is
    /// told that too, so the skip is the deployment's own state, not a
    /// silent pass.
    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn host_address_box_placed_in_leaf() {
        const SKIP: &str = "skipping host_address_box_placed_in_leaf";
        if let Some(reason) = user_namespaces_restriction() {
            eprintln!(
                "{SKIP}: this host denies the unprivileged user namespace \
                       every sandbox starts by unsharing: {reason}"
            );
            return;
        }
        let root = Path::new(classifier::TREE_ROOT);
        let boxes = root.join(classifier::BOXES_DIR);
        let deny = boxes.join(config::DENY_DIR);
        let allow = boxes.join(config::ALLOW_DIR);
        for subtree in [&deny, &allow] {
            if !subtree.is_dir() {
                eprintln!(
                    "{SKIP}: {} is absent — this host has no classifier tree to \
                     place a box in (scripts/install-host-classifier.sh installs one)",
                    subtree.display()
                );
                return;
            }
        }
        if nix::unistd::access(&deny, nix::unistd::AccessFlags::W_OK).is_err() {
            eprintln!(
                "{SKIP}: {} is not writable by this account — the tree is \
                 installed but not delegated to the account this process runs as",
                deny.display()
            );
            return;
        }
        if let Err(e) = classifier::probe_child_placement(root, config::Verdict::Deny) {
            eprintln!(
                "{SKIP}: this process cannot place a child in the tree ({e}; it \
                 runs in {}) — the installer's --pid step or a Delegate=yes unit \
                 has to place the daemon first",
                classifier::own_cgroup_path()
                    .as_deref()
                    .unwrap_or("no v2 cgroup of its own")
            );
            return;
        }

        // Two leaves of the real cohort, this test's own: the box's, and a
        // sibling's the box must not reach. The box is declared deny-all, so
        // its leaf is in the deny subtree; the sibling sits in the allow
        // subtree, the farthest leaf from it the cohort offers.
        let box_id = format!("host-address-{}", std::process::id());
        let sibling_id = format!("sibling-of-{box_id}");
        let leaf = classifier::create_box_leaf(root, &box_id, config::Verdict::Deny)
            .expect("creating the box's leaf in the real tree");
        let sibling = classifier::create_box_leaf(root, &sibling_id, config::Verdict::Allow)
            .expect("creating the sibling's leaf in the real tree");
        let mountpoint = classifier::CONVENTIONAL_CGROUP2_MOUNTPOINT.to_string();
        let controllers = format!("{mountpoint}/cgroup.controllers");
        let memory_max = format!("{mountpoint}/memory.max");
        let root_procs = format!("{mountpoint}/cgroup.procs");
        let sibling_procs =
            classifier::box_leaf(Path::new(&mountpoint), &sibling_id, config::Verdict::Allow)
                .join("cgroup.procs")
                .to_string_lossy()
                .into_owned();

        // The memory controller on the cohort and on both of its subtrees,
        // the same enabling a running daemon performs at its start
        // (`enter_daemon_leaf`): without it a leaf carries no `memory.max` at
        // all, and this proof reads the box's own limit under the design's
        // cover — the assertion that the box's verdict is where a runtime
        // looks. Best-effort and warned, as in the daemon; a host without the
        // controller is one the design's own diagnostics already tell.
        for dir in [&boxes, &deny, &allow] {
            if let Err(e) = std::fs::write(dir.join("cgroup.subtree_control"), "+memory\n")
                && e.kind() != std::io::ErrorKind::NotFound
                && e.kind() != std::io::ErrorKind::PermissionDenied
            {
                panic!("enabling the memory controller on the real cohort: {e}");
            }
        }

        // The probe holds the box in its leaf for a while — the kernel drops
        // the membership the moment the box's last process exits, so the
        // host's side of the tree has to be read while the box is still in
        // it, and the box's build takes its own time to get there. The hold
        // is a real handshake: the probe polls for a release file in its own
        // `/run` — the one live directory the box and the host share — and
        // ends on its own after 10s if no file appears, so a lost handshake
        // costs a slow run, not a hung one.
        let release_name = format!("probe-release-{}", std::process::id());
        let probe_args = vec![
            format!("STATFS:{mountpoint}"),
            format!("READ:{controllers}"),
            format!("READ:{memory_max}"),
            format!("WRITE:{root_procs}"),
            format!("WRITE:{sibling_procs}"),
            format!("HOLD:/run/{release_name}"),
        ];
        let held = launch_box_probe(
            &box_id,
            Some(config::ClassifierLeaf::new(leaf.clone())),
            &probe_args,
            false,
        )
        .await;

        // The kernel's own half of the placement: the leaf's `cgroup.procs`
        // on the host side, holding the box's own first process. The box
        // names its pid as it reads it — inside its own PID namespace, which
        // is not the pid the host side holds — so the member is not matched
        // against the report but asserted to be the leaf's one and only.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(12);
        let members = loop {
            let members = std::fs::read_to_string(leaf.join("cgroup.procs")).unwrap_or_default();
            if !members.is_empty() {
                break members;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the box never joined its leaf: the kernel holds nothing in {}",
                leaf.join("cgroup.procs").display()
            );
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        };
        eprintln!(
            "the kernel holds {} in the box's leaf while the box is alive in it",
            members.trim()
        );
        assert_eq!(
            members.lines().count(),
            1,
            "the leaf the box joined holds the box's own first process and \
             nobody else: {members:?}"
        );
        assert_ne!(
            members.trim(),
            std::process::id().to_string(),
            "the member is the box's process, not this test's"
        );

        // The closure's one-line report, read on the host side while the box
        // is still held: the channel the daemon reads after every launch, on
        // the real tree too — the cover the box took is not something the
        // daemon has to guess from the absence of a 127.
        let report_path = held
            .base
            .join("run")
            .join(classifier::closure_report_name(&box_id));
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let closure_report = loop {
            match std::fs::read_to_string(&report_path) {
                Ok(report) => break report,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    assert!(
                        std::time::Instant::now() < deadline,
                        "the box's pre-exec closure wrote no report into {}",
                        report_path.display()
                    );
                    tokio::time::sleep(std::time::Duration::from_millis(25)).await;
                }
                Err(e) => panic!("reading the box's closure report: {e}"),
            }
        };
        held.release_hold();
        let placed = held.report().await;
        assert_eq!(
            placed.get("self_cgroup").map(String::as_str),
            Some("0::/"),
            "the box reads the root of its own cgroup namespace — and the \
             kernel holds that process in the leaf, so the root is the leaf"
        );

        // The cover, per branch — the branch the box reports it took, in its
        // environment and in the closure's report, is the one asserted, so a
        // host whose kernel refuses the design's cgroup2 mount proves the
        // recorded fallback here rather than failing a claim it was never in
        // a position to make.
        let cover = placed
            .get("cover")
            .cloned()
            .unwrap_or_else(|| "no report".to_string());
        eprintln!("the box on the real tree took the {cover} cover");
        assert!(
            closure_report.trim().starts_with(&format!("cover {cover}")),
            "the closure's report into the sandbox's /run and its marker in \
             the box's environment name the same cover: the report says \
             {closure_report:?} while the box says {cover:?}"
        );
        match cover.as_str() {
            "cgroup2" => {
                assert_eq!(
                    placed
                        .get(&format!("fstype {mountpoint}"))
                        .map(String::as_str),
                    Some(&format!("magic {CGROUP2_SUPER_MAGIC}")[..]),
                    "the box's own cgroup is mounted where a cgroup-aware \
                     runtime looks, read-only"
                );
                assert_eq!(
                    placed
                        .get(&format!("read {memory_max}"))
                        .map(String::as_str),
                    Some("errno 0"),
                    "the box's own memory.max — the limit its verdict is \
                     decided on — is readable under the design's cover, while \
                     the sibling's whole path does not resolve"
                );
                assert_eq!(
                    placed
                        .get(&format!("read {controllers}"))
                        .map(String::as_str),
                    Some("errno 0"),
                    "the controllers file a cgroup-aware runtime starts from \
                     is there to read in the box's own cgroup"
                );
                let wrote_root = placed
                    .get(&format!("open {root_procs}"))
                    .cloned()
                    .unwrap_or_else(|| "no report".to_string());
                assert!(
                    wrote_root == "errno 30" || wrote_root == "errno 13",
                    "the box must not be able to write its own root's \
                     cgroup.procs — writing a pid there is leaving the leaf \
                     the kernel holds it in — but it reports {wrote_root:?} \
                     (either refusal is the barrier: `EROFS` from the \
                     read-only mount where the box's uid owns the file, \
                     `EACCES` where it does not)"
                );
                assert_eq!(
                    placed
                        .get(&format!("open {sibling_procs}"))
                        .map(String::as_str),
                    Some("errno 2"),
                    "the sibling's path does not resolve at all below the \
                     box's cgroup namespace root — invisible, not merely \
                     unwritable, so no pid of the box's can reach another \
                     box's verdict"
                );
            }
            "tmpfs-fallback" => {
                assert_eq!(
                    placed
                        .get(&format!("fstype {mountpoint}"))
                        .map(String::as_str),
                    Some(&format!("magic {TMPFS_SUPER_MAGIC}")[..]),
                    "where the kernel refuses the design's cgroup2 mount, the \
                     box is left the recorded empty read-only tmpfs instead"
                );
                assert_eq!(
                    placed
                        .get(&format!("read {memory_max}"))
                        .map(String::as_str),
                    Some("errno 2"),
                    "the fallback costs the box its own limit too: nothing \
                     cgroup-shaped resolves, which is why the branch is \
                     recorded rather than passed off as the design's cover"
                );
                assert_eq!(
                    placed
                        .get(&format!("read {controllers}"))
                        .map(String::as_str),
                    Some("errno 2"),
                    "the controllers file a cgroup-aware runtime starts from \
                     does not resolve under the fallback either"
                );
                for (path, whose) in [
                    (&root_procs, "its own root's"),
                    (&sibling_procs, "another box's"),
                ] {
                    assert_eq!(
                        placed.get(&format!("open {path}")).map(String::as_str),
                        Some("errno 2"),
                        "the fallback leaves the box no cgroup path through \
                         which to open {whose} cgroup.procs — a migration out \
                         of its leaf has no file to open, let alone \
                         permission to write"
                    );
                }
            }
            other => panic!("the box reported a cover this proof does not know: {other}"),
        }

        // The box is out, so its leaf is empty and removable — and this test
        // owes the real tree both of the leaves it made in it.
        classifier::remove_box_leaf(&leaf).expect("removing the box's leaf");
        classifier::remove_box_leaf(&sibling).expect("removing the sibling's leaf");
    }
}
