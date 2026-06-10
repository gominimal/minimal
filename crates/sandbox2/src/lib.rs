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
use std::fs::{self, Permissions};
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::SystemTime;
pub mod error;
use crate::config::{Invocation, WdSetup};
use crate::error::ExecutionError;
pub use error::Error;

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

/// An initialized sandbox.
///
/// Sandboxes can have a [`Channel`] wired to the outside world for interactive operations and mutations
/// to the sandbox itself that originate from inside the sandbox. Pass `()` as the channel to have this
/// be effectively disabled.
#[derive(Debug)]
pub struct Sandbox<C: Channel = ()> {
    pub(crate) base_dir: PathBuf,
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
        }

        // Setup /state
        let state_dir = match &config.state_dir {
            None => base_dir.join("state"),
            Some(s) => s.to_path_buf(),
        };
        fs::create_dir_all(state_dir.join("home"))
            .map_err(|e| Error::IO("mkdir /state/home", state_dir.join("home"), e))?;
        fs::create_dir_all(state_dir.join("data"))
            .map_err(|e| Error::IO("mkdir /state/data", state_dir.join("data"), e))?;
        fs::create_dir_all(state_dir.join("cache"))
            .map_err(|e| Error::IO("mkdir /state/cache", state_dir.join("cache"), e))?;
        fs::create_dir_all(state_dir.join("state"))
            .map_err(|e| Error::IO("mkdir /state/state", state_dir.join("state"), e))?;

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
            state_dir,
            config,
            keep_dir: false,
            stdout: Some(stdout),
            stderr: Some(stderr),
            listener: Some(listener),
        })
    }

    fn needs_lib64_symlink(&self) -> Result<bool, Error> {
        let lib64_p = self.rootfs().join("lib64");
        Ok(!fs::exists(&lib64_p)
            .map_err(|e| Error::IO("checking for lib64 directory", lib64_p, e))?)
    }
    fn needs_lib_symlink(&self) -> Result<bool, Error> {
        let lib_p = self.rootfs().join("lib");
        Ok(!fs::exists(&lib_p).map_err(|e| Error::IO("checking for lib directory", lib_p, e))?)
    }
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
pub struct Container {
    container: hakoniwa::Container,
}

impl AsRef<hakoniwa::Container> for Container {
    fn as_ref(&self) -> &hakoniwa::Container {
        &self.container
    }
}

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
        command.current_dir(match &sandbox.config.wd {
            WdSetup::BoundDir { .. } => format!(
                "/{}",
                sandbox.config.wd.bound_dir_sandbox_cwd().to_str().unwrap()
            ),
            WdSetup::Isolated { .. } => "/build".to_string(),
        });

        command.env("XDG_CONFIG_HOME", "/state/home");
        command.env("XDG_DATA_HOME", "/state/data");
        command.env("XDG_CACHE_HOME", "/state/cache");
        command.env("XDG_STATE_HOME", "/state/state");
        command.env("XDG_RUNTIME_DIR", "/run");
        command.env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin");
        if let WdSetup::Isolated { .. } = sandbox.config.wd {
            command.env("HOME", "/state/home");
        } else if let Ok(h) = std::env::var("HOME") {
            command.env("HOME", &h);
        } else {
            command.env("HOME", "/state/home");
        };
        if let WdSetup::Isolated { .. } = sandbox.config.wd {
            command.env("OUTPUT_DIR", "/build/output");
            command.env("GIT_TERMINAL_PROMPT", "0");
            command.env("SOURCE_DATE_EPOCH", "0");
            command.env("PYTHONHASHSEED", "0");
        }

        command.env("LANG", "en_US.utf8");
        command.env("LC_ALL", "en_US.utf8");
        command.env("IS_SANDBOX", "1");
        if let WdSetup::BoundDir { .. } = sandbox.config.wd {
            //  Quality-of-life wiring for task sandboxes
            if let Ok(term) = std::env::var("TERM") {
                command.env("TERM", &term);
            }
            if let Ok(ct) = std::env::var("COLORTERM") {
                command.env("COLORTERM", &ct);
            }
            if let Ok(lsc) = std::env::var("LS_COLORS") {
                command.env("LS_COLORS", &lsc);
            }
        }

        sandbox.config.env_vars.iter().for_each(|(var, val)| {
            command.env(var, val);
        });
        for (k, v) in envs.into_iter() {
            command.env(k.as_ref(), v.as_ref());
        }

        Ok(command)
    }
}

/// Options for [`Sandbox::bind_mount`].
#[derive(Debug, Default, Clone, Copy)]
struct BindOpts {
    read_only: bool,
    recursive: bool,
}

// Sandbox usage
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

    pub fn new_container(&self) -> Result<Container, Error> {
        let mut container = hakoniwa::Container::new();
        container
            .rootfs(self.rootfs())
            .unwrap()
            .devfsmount("/dev")
            .tmpfsmount("/tmp")
            .unshare(hakoniwa::Namespace::Cgroup)
            .runctl(hakoniwa::Runctl::IgnoreCgroupSetupFailed);

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
                }
                .join(&program),
            )
            .unwrap()
            && fs::exists(rootfs.join("usr/bin").join(&program)).unwrap()
        {
            program = format!("/usr/bin/{}", &program);
        }

        container.command_inner(self, &program, args, env_vars)
    }

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
        let container = self.new_container()?;
        for (i, exec) in invocations.iter().enumerate() {
            if cancel.is_cancelled() {
                return Err(Error::Execution(ExecutionError::Cancelled));
            }

            let mut cmd = self.command(&container, &exec.executable, &exec.args, &exec.envs)?;
            cmd.stderr(hakoniwa::Stdio::MakePipe);
            cmd.stdout(hakoniwa::Stdio::MakePipe);
            tracing::debug!("Executing: {} {}", &exec.executable, exec.args.join(" "));

            let mut child = cmd
                .spawn()
                .map_err(|e| Error::Execution(ExecutionError::SpawnFailed(e)))?;

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

                    // Reap the child process.
                    let _ = child.wait();
                    return Err(Error::Execution(ExecutionError::Cancelled));
                }
                (stdout_fwd_res, stderr_fwd_res) = async { tokio::join!(stdout_fwd, stderr_fwd) } => {
                    // Collect results from the reader threads.
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

#[cfg(test)]
mod tests {
    use super::*;
    use config::{Config, SandboxMapped};

    // /proc is mounted with nosuid,nodev on essentially every Linux distro;
    // if either stops showing up we've broken the FsFlags → MountOptions
    // mapping and a nested sandbox would silently lose those locked flags
    // again. NOEXEC is also common but skipped here since it's not
    // universal.
    #[test]
    fn locked_mount_flags_reads_proc_flags() {
        let opts = locked_mount_flags(Path::new("/proc"));
        assert!(opts.contains(hakoniwa::MountOptions::NOSUID));
        assert!(opts.contains(hakoniwa::MountOptions::NODEV));
    }

    #[test]
    fn locked_mount_flags_empty_on_statfs_failure() {
        let opts = locked_mount_flags(Path::new("/nonexistent-path-for-statfs-test"));
        assert!(opts.is_empty());
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
}
