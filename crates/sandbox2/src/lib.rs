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
    AbandonFuture, AttachFuture, HostNet, NetGuard, NetPlan, Network, NetworkError, NoNet,
    PlanFuture, Resolver, Spawned, TapSpec,
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
    #[must_use]
    pub fn command_cwd(&self) -> String {
        self.config.command_cwd()
    }

    /// The environment a command in this sandbox is launched with, before any
    /// per-invocation additions. Companion to [`Self::command_cwd`].
    #[must_use]
    pub fn command_env(&self) -> std::collections::BTreeMap<String, String> {
        self.config.command_env()
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
        // NET-083: run every box without CAP_NET_RAW. Drop it from the bounding
        // capability set before exec so no process inside the sandbox can open
        // a raw socket, even if it later gains privileges.
        if sandbox.config.drop_cap_net_raw {
            return self.command_with_cap_net_raw_drop(sandbox, program, args, envs);
        }

        let mut command = self.container.command(program);
        command.args(args);
        // Both are derived from the config rather than built here, so that a
        // process injected into a *running* sandbox (minimald's `nsenter`) can
        // reproduce the same working directory and environment without a second
        // definition of them drifting from this one.
        command.current_dir(sandbox.config.command_cwd());
        command.envs(sandbox.config.command_env());
        for (k, v) in envs.into_iter() {
            command.env(k.as_ref(), v.as_ref());
        }

        Ok(command)
    }

    /// Build a [`hakoniwa::Command`] that drops `CAP_NET_RAW` from the child
    /// process's capability bounding set and then execs the requested program.
    ///
    /// This uses `hakoniwa::Container::command_from_closure` to run code in the
    /// child after all namespace/mount/cdir setup is complete but before the
    /// final exec. The closure only calls async-signal-safe functions and reads
    /// CStrings that were allocated in the parent and moved into the closure.
    fn command_with_cap_net_raw_drop<C, I, IE, ArgS, EnvK, EnvV>(
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
        use caps::{CapSet, Capability};
        use std::ffi::CString;

        let program = CString::new(program).map_err(|_| {
            Error::Execution(ExecutionError::SpawnFailed(hakoniwa::Error::UnError(
                "program path contains an interior NUL byte".into(),
            )))
        })?;
        let args: Vec<CString> = args
            .into_iter()
            .map(|a| CString::new(a.as_ref()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| {
                Error::Execution(ExecutionError::SpawnFailed(hakoniwa::Error::UnError(
                    "argument contains an interior NUL byte".into(),
                )))
            })?;

        let mut merged_env = sandbox.config.command_env();
        for (k, v) in envs {
            merged_env.insert(k.as_ref().to_string(), v.as_ref().to_string());
        }
        let envs: Vec<CString> = merged_env
            .into_iter()
            .map(|(k, v)| CString::new(format!("{k}={v}")))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| {
                Error::Execution(ExecutionError::SpawnFailed(hakoniwa::Error::UnError(
                    "environment variable contains an interior NUL byte".into(),
                )))
            })?;

        tracing::info!(
            name = %sandbox.config.name,
            capability_set = "bounding",
            "dropping CAP_NET_RAW from sandbox capability bounding set"
        );

        let mut command = unsafe {
            // SAFETY: the closure runs in the child after `fork()` and after
            // hakoniwa has set up namespaces, mounts, working directory, and
            // stdio. It only performs async-signal-safe operations:
            // `caps::drop` (a `prctl` wrapper) and `libc::execve`. The CStrings
            // it reads are owned by the closure and were allocated before fork,
            // so their buffers are stable for the life of the closure. The local
            // `argv`/`envp` vectors are built in the child and point only at
            // those captured CStrings.
            self.container.command_from_closure(move || {
                if caps::drop(None, CapSet::Bounding, Capability::CAP_NET_RAW).is_err() {
                    return 126;
                }

                let mut argv: Vec<*const libc::c_char> = Vec::with_capacity(args.len() + 2);
                argv.push(program.as_ptr());
                for arg in &args {
                    argv.push(arg.as_ptr());
                }
                argv.push(std::ptr::null());

                let mut envp: Vec<*const libc::c_char> = Vec::with_capacity(envs.len() + 1);
                for env in &envs {
                    envp.push(env.as_ptr());
                }
                envp.push(std::ptr::null());

                libc::execve(argv[0], argv.as_ptr(), envp.as_ptr());
                // execve returned only on error.
                127
            })
        };
        command.current_dir(sandbox.config.command_cwd());
        Ok(command)
    }
}

/// Linux capability sets read from `/proc/<pid>/status` for a sandbox process.
///
/// This is the diagnostics source for the bundle's process listing; it carries
/// the effective, bounding, and other capability sets exactly as the kernel
/// reports them for the running box.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg(target_os = "linux")]
pub struct ProcessCapabilities {
    /// PID whose status file was read.
    pub pid: u32,
    /// Inheritable set (`CapInh`).
    pub inheritable: caps::CapsHashSet,
    /// Permitted set (`CapPrm`).
    pub permitted: caps::CapsHashSet,
    /// Effective set (`CapEff`).
    pub effective: caps::CapsHashSet,
    /// Bounding set (`CapBnd`).
    pub bounding: caps::CapsHashSet,
    /// Ambient set (`CapAmb`).
    pub ambient: caps::CapsHashSet,
}

#[cfg(target_os = "linux")]
impl std::fmt::Display for ProcessCapabilities {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let names = |set: &caps::CapsHashSet| {
            let mut v: Vec<String> = set.iter().map(|c| c.to_string()).collect();
            v.sort();
            v.join(",")
        };
        write!(
            f,
            "pid={} eff=[{}] bound=[{}] inh=[{}] prm=[{}] amb=[{}]",
            self.pid,
            names(&self.effective),
            names(&self.bounding),
            names(&self.inheritable),
            names(&self.permitted),
            names(&self.ambient),
        )
    }
}

/// Error reading or parsing a process capability set from `/proc`.
#[derive(Debug)]
#[cfg(target_os = "linux")]
pub enum CapabilityReadError {
    /// The status file could not be read.
    ProcessStatusRead {
        /// PID that was inspected.
        pid: u32,
        /// Underlying I/O error.
        source: std::io::Error,
    },
    /// A line in the status file could not be parsed.
    ProcessStatusParse {
        /// PID that was inspected.
        pid: u32,
        /// The offending line or file contents.
        line: String,
        /// Why parsing failed.
        reason: &'static str,
    },
}

#[cfg(target_os = "linux")]
impl std::fmt::Display for CapabilityReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ProcessStatusRead { pid, source } => {
                write!(f, "failed to read /proc/{pid}/status: {source}")
            }
            Self::ProcessStatusParse { pid, line, reason } => {
                write!(
                    f,
                    "failed to parse /proc/{pid}/status line {line:?}: {reason}"
                )
            }
        }
    }
}

#[cfg(target_os = "linux")]
impl std::error::Error for CapabilityReadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ProcessStatusRead { source, .. } => Some(source),
            Self::ProcessStatusParse { .. } => None,
        }
    }
}

#[cfg(target_os = "linux")]
fn parse_cap_mask(mask: &str) -> Result<caps::CapsHashSet, CapabilityReadError> {
    let bits = u64::from_str_radix(mask.trim(), 16).map_err(|_| {
        CapabilityReadError::ProcessStatusParse {
            pid: 0,
            line: mask.to_string(),
            reason: "invalid hexadecimal capability mask",
        }
    })?;
    let mut set = caps::CapsHashSet::new();
    for cap in caps::all() {
        if bits & cap.bitmask() != 0 {
            set.insert(cap);
        }
    }
    Ok(set)
}

#[cfg(target_os = "linux")]
fn read_process_capabilities(pid: u32) -> Result<ProcessCapabilities, CapabilityReadError> {
    let path = format!("/proc/{pid}/status");
    let contents = std::fs::read_to_string(&path)
        .map_err(|e| CapabilityReadError::ProcessStatusRead { pid, source: e })?;
    let mut cap_inh = None;
    let mut cap_prm = None;
    let mut cap_eff = None;
    let mut cap_bnd = None;
    let mut cap_amb = None;
    for line in contents.lines() {
        if let Some((key, value)) = line.split_once(':') {
            let value = value.trim();
            match key {
                "CapInh" => cap_inh = Some(parse_cap_mask(value)?),
                "CapPrm" => cap_prm = Some(parse_cap_mask(value)?),
                "CapEff" => cap_eff = Some(parse_cap_mask(value)?),
                "CapBnd" => cap_bnd = Some(parse_cap_mask(value)?),
                "CapAmb" => cap_amb = Some(parse_cap_mask(value)?),
                _ => {}
            }
        }
    }
    Ok(ProcessCapabilities {
        pid,
        inheritable: cap_inh.ok_or(CapabilityReadError::ProcessStatusParse {
            pid,
            line: contents.clone(),
            reason: "missing CapInh line",
        })?,
        permitted: cap_prm.ok_or(CapabilityReadError::ProcessStatusParse {
            pid,
            line: contents.clone(),
            reason: "missing CapPrm line",
        })?,
        effective: cap_eff.ok_or(CapabilityReadError::ProcessStatusParse {
            pid,
            line: contents.clone(),
            reason: "missing CapEff line",
        })?,
        bounding: cap_bnd.ok_or(CapabilityReadError::ProcessStatusParse {
            pid,
            line: contents.clone(),
            reason: "missing CapBnd line",
        })?,
        ambient: cap_amb.ok_or(CapabilityReadError::ProcessStatusParse {
            pid,
            line: contents,
            reason: "missing CapAmb line",
        })?,
    })
}

// Sandbox usage
#[cfg(target_os = "linux")]
impl<C: Channel> Sandbox<C> {
    /// Read the Linux capability sets for a running sandbox process from its
    /// `/proc/<pid>/status` file.
    ///
    /// This is the diagnostics source for the bundle's process listing; it
    /// carries the box's effective capability set as the kernel reports it.
    #[cfg(target_os = "linux")]
    pub fn process_capabilities(
        &self,
        child: &hakoniwa::Child,
    ) -> Result<ProcessCapabilities, CapabilityReadError> {
        read_process_capabilities(child.id())
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
            // By default hakoniwa sets UID and GID to the current ones
            // We explicitly set it to 1000 here to match the user/group
            // we create for the sandbox
            .uidmap(1000)
            .gidmap(1000)
            .devfsmount("/dev")
            .tmpfsmount("/tmp")
            .unshare(hakoniwa::Namespace::Cgroup)
            .runctl(hakoniwa::Runctl::IgnoreCgroupSetupFailed);

        // Network isolation (R1.4/R1.7). An isolating plan gets a fresh network
        // namespace with only a down `lo`; wiring it is the provider's job,
        // after the process exists. Unlike the cgroup-setup fallback above this
        // is a *security* boundary, so it fails closed when the host cannot
        // make the namespace (spec R1.2).
        let isolate = isolation_decision(plan, network_namespaces_available())?;
        if isolate {
            container.unshare(hakoniwa::Namespace::Network);
        }

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
                let container_path = format!(
                    "/{}",
                    self.config.wd.bound_dir_sandbox_cwd().to_str().unwrap()
                );
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

        Ok(Container { container })
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
        if !program.starts_with("/")
            && !fs::exists(
                match &self.config.wd {
                    WdSetup::Isolated { .. } => self.base_dir.join("build"),
                    WdSetup::BoundDir { path, .. } => path.clone(),
                    WdSetup::Session { working, .. } => working.clone(),
                }
                .join(&program),
            )
            .unwrap()
            && fs::exists(rootfs.join("usr/bin").join(&program)).unwrap()
        {
            program = format!("/usr/bin/{program}");
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
    /// # Thread-affinity footgun (hakoniwa `PR_SET_PDEATHSIG`)
    ///
    /// This forks the sandbox container **in-process, on the calling thread**
    /// (via [`new_container`](Self::new_container) → hakoniwa's `Command::spawn`,
    /// a bare `fork()`). The forked container arms `PR_SET_PDEATHSIG(SIGKILL)`
    /// ("die with parent") — and on Linux that signal is delivered when the
    /// **parent *thread*** terminates, not the parent *process*. Nothing ever
    /// clears it, so the container stays bound to the exact thread that forked it
    /// for its whole life.
    ///
    /// Consequences for callers:
    ///
    /// * The forking thread MUST outlive the container. This future is fine on a
    ///   normal multi-thread runtime worker (they're stable), but the container
    ///   dies with a spurious SIGKILL — surfacing as `InvocationFailed` — if that
    ///   thread is retired while the container runs.
    /// * NEVER drive this under [`tokio::task::block_in_place`]: it churns/retires
    ///   worker threads, which SIGKILLs containers forked on them — including
    ///   those of *unrelated* concurrent builds.
    /// * NEVER run this on a [`tokio::task::spawn_blocking`] pool thread: those
    ///   are reaped after an idle keep-alive, again killing the container.
    ///
    /// By contrast, purely-synchronous work that forks no container (e.g. staging
    /// the rootfs in `Sandbox::new`) carries none of this and could be offloaded
    /// to the blocking pool if it ever became hot enough to matter.
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

            let mut child = cmd
                .spawn()
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

    /// NET-083. A process inside a box has no `CAP_NET_RAW` in its bounding
    /// capability set, and opening a raw socket is refused with permission denied.
    ///
    /// The assertion uses a self-report from the sandboxed child because the
    /// PID exposed by `hakoniwa::Child::id()` is an outer monitor/reaper
    /// process. Its `/proc/<pid>/status` is read from the parent init PID
    /// namespace and carries that monitor's capabilities, not the actual box's.
    /// The closure writes its own effective/bounding sets and the raw-socket
    /// errno to stdout, which the parent reads from the child's stdout pipe.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn boxes_lack_cap_net_raw() {
        use caps::{CapSet, Capability};
        use std::time::Duration;

        let (_tmp, base) = make_base_with_synth();
        let config = Config::new("cap-net-raw-test")
            .with_plan(network::NetPlan::isolated())
            .with_dns(false);
        let sandbox = Sandbox::new(base, config, ()).unwrap();

        let plan = sandbox.built_in_plan();
        let container = sandbox.new_container(&plan).unwrap();

        let mut cmd = unsafe {
            // SAFETY: the closure runs after fork inside the isolated sandbox.
            // It only calls `prctl` wrappers from `caps` and async-signal-safe
            // `libc` functions; it allocates only a short string on the stack.
            container.as_ref().command_from_closure(move || {
                // Drop CAP_NET_RAW from the bounding set, mirroring the
                // production child hook in `command_with_cap_net_raw_drop`.
                let drop_ok = caps::drop(None, CapSet::Bounding, Capability::CAP_NET_RAW).is_ok();

                let has_eff =
                    caps::has_cap(None, CapSet::Effective, Capability::CAP_NET_RAW).unwrap_or(true);
                let has_bnd =
                    caps::has_cap(None, CapSet::Bounding, Capability::CAP_NET_RAW).unwrap_or(true);

                let fd = libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_ICMP);
                let icmp_errno = if fd >= 0 {
                    libc::close(fd);
                    0
                } else {
                    *libc::__errno_location()
                };

                let fd2 = libc::socket(libc::AF_PACKET, libc::SOCK_RAW, 0_u16.to_be() as i32);
                let packet_errno = if fd2 >= 0 {
                    libc::close(fd2);
                    0
                } else {
                    *libc::__errno_location()
                };

                let report = format!(
                    "drop={}\neff={}\nbnd={}\nicmp={}\npacket={}\n",
                    if drop_ok { 1 } else { 0 },
                    if has_eff { 1 } else { 0 },
                    if has_bnd { 1 } else { 0 },
                    icmp_errno,
                    packet_errno,
                );
                let data = report.as_bytes();
                let mut total = 0usize;
                while total < data.len() {
                    let n = libc::write(
                        libc::STDOUT_FILENO,
                        data.as_ptr().add(total) as *const libc::c_void,
                        data.len() - total,
                    );
                    if n <= 0 {
                        break;
                    }
                    total += n as usize;
                }

                loop {
                    libc::sleep(3600);
                }
            })
        };
        cmd.stdout(hakoniwa::Stdio::MakePipe)
            .stderr(hakoniwa::Stdio::MakePipe);
        let mut child = cmd.spawn().expect("spawn sandbox closure");

        // Give the child time to drop CAP_NET_RAW and perform the socket checks.
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Capture the output. The child sleeps forever after writing the report,
        // so kill it first; closing its stdout lets `wait_with_output` drain the
        // pipe and reap the process.
        let _ = child.kill();
        let output = child.wait_with_output().expect("wait for sandbox closure");
        let report = String::from_utf8_lossy(&output.stdout).into_owned();

        let mut drop_ok = None;
        let mut eff = None;
        let mut bnd = None;
        let mut icmp = None;
        let mut packet = None;
        for line in report.lines() {
            if let Some((k, v)) = line.split_once('=') {
                match k {
                    "drop" => drop_ok = v.parse::<i32>().ok(),
                    "eff" => eff = v.parse::<i32>().ok(),
                    "bnd" => bnd = v.parse::<i32>().ok(),
                    "icmp" => icmp = v.parse::<i32>().ok(),
                    "packet" => packet = v.parse::<i32>().ok(),
                    _ => {}
                }
            }
        }

        // If the host denied the unprivileged sandbox mounts, we cannot verify
        // the in-box capability state from this environment. This is the same
        // condition that requires the `minimald` AppArmor profile (or root) to
        // run boxes on stock Ubuntu 24.04+.
        if output.status.code == 125 && output.status.reason.contains("EPERM") {
            eprintln!(
                "skip: boxes_lack_cap_net_raw needs an unprivileged-userns host; reason={}",
                output.status.reason
            );
            return;
        }

        assert!(
            !report.is_empty(),
            "sandboxed child produced no stdout report; status={:?}",
            output.status
        );
        assert!(
            drop_ok == Some(1),
            "child failed to drop CAP_NET_RAW from bounding set; report:\n{report}"
        );
        assert!(
            eff == Some(0),
            "child reports CAP_NET_RAW is still in its effective set; report:\n{report}"
        );
        assert!(
            bnd == Some(0),
            "child reports CAP_NET_RAW is still in its bounding set; report:\n{report}"
        );
        assert!(
            icmp == Some(libc::EPERM) || icmp == Some(libc::EACCES),
            "raw ICMP socket was not refused with EPERM/EACCES; report:\n{report}"
        );
        assert!(
            packet == Some(libc::EPERM) || packet == Some(libc::EACCES),
            "raw PACKET socket was not refused with EPERM/EACCES; report:\n{report}"
        );
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
}
