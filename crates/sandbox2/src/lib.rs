pub mod config;
use config::Config;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::SystemTime;
use tracing::Span;
pub mod error;
use crate::config::{Invocation, WdSetup};
use crate::error::ExecutionError;
use common::FdSynchronizer;
pub use error::Error;

#[derive(Debug)]
pub struct Sandbox {
    pub(crate) base_dir: PathBuf,
    pub(crate) state_dir: PathBuf,
    pub(crate) config: Config,

    keep_dir: bool,
    stdout: Option<fs::File>,
    stderr: Option<fs::File>,
}

impl Drop for Sandbox {
    fn drop(&mut self) {
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

        if !self.keep_dir && fs::remove_dir_all(&self.base_dir).is_err() {
            // remove_dir_all will fail if files are set as non-writeable even
            // if theres a path to delete them. Urgh. Only golang does this.
            //
            // We do the same thing as `go clean -modcache` to fix the horror of their
            // making.
            //
            // https://cs.opensource.google/go/go/+/refs/tags/go1.25.7:src/cmd/go/internal/modfetch/fetch.go;l=426-438
            for entry in walkdir::WalkDir::new(&self.base_dir) {
                if let Ok(entry) = entry
                    && entry.file_type().is_dir()
                {
                    use std::os::unix::fs::PermissionsExt;
                    fs::set_permissions(entry.path(), fs::Permissions::from_mode(0o777)).ok();
                }
            }
            // Try again
            if let Err(e) = fs::remove_dir_all(&self.base_dir) {
                tracing::warn!(
                    "Failed cleanup for sandbox at path {}: {}",
                    self.base_dir.display(),
                    e,
                );
            }
        }
    }
}

// Sandbox initialization
impl Sandbox {
    pub(crate) fn new(base_dir: PathBuf, config: Config) -> Result<Self, Error> {
        // Setup the rootfs
        let rootfs = base_dir.join("rootfs");
        fs::create_dir_all(&rootfs)
            .map_err(|e| Error::IO("create rootfs dir", rootfs.clone(), e))?;
        let hardlinking_start = SystemTime::now();
        for i in config.rootfs.iter() {
            match i {
                config::SandboxMapped::Dir(p) => hardlink_dir_contents(p, &rootfs)?,
                config::SandboxMapped::TempDir(td) => hardlink_dir_contents(td.path(), &rootfs)?,
                config::SandboxMapped::File(_p) => todo!(),
            }
        }
        hardlink_dir_contents(&base_dir.join("synth"), &rootfs)?;
        tracing::trace!("rootfs hardlinking took {:?}", hardlinking_start.elapsed());

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
                        config::SandboxMapped::Dir(p) => hardlink_dir_contents(p, &b)?,
                        config::SandboxMapped::TempDir(td) => hardlink_dir_contents(td.path(), &b)?,
                    }
                }
                tracing::trace!("input hardlinking took {:?}", hardlinking_start.elapsed());

                fs::create_dir_all(b.join("output"))
                    .map_err(|e| Error::IO("create output dir", b.clone(), e))?;
            }
            WdSetup::BoundDir {
                path,
                fs_mappings,
                read_only: _,
            } => {
                let cwd = rootfs.join(path);
                fs::create_dir_all(&cwd)
                    .map_err(|e| Error::IO("create shadow cwd tree", cwd.clone(), e))?;

                // Create bind-mount targets
                for m in fs_mappings {
                    let p = rootfs.join(m.path_in_sandbox());

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
        })
    }

    fn needs_lib64_symlink(&self) -> Result<bool, Error> {
        let lib64_p = self.base_dir.join("rootfs").join("lib64");
        Ok(!fs::exists(&lib64_p)
            .map_err(|e| Error::IO("checking for lib64 directory", lib64_p, e))?)
    }
    fn needs_lib_symlink(&self) -> Result<bool, Error> {
        let lib_p = self.base_dir.join("rootfs").join("lib");
        Ok(!fs::exists(&lib_p).map_err(|e| Error::IO("checking for lib directory", lib_p, e))?)
    }
    fn needs_bin_symlink(&self) -> Result<bool, Error> {
        let bin_p = self.base_dir.join("rootfs").join("bin");
        Ok(!fs::exists(&bin_p).map_err(|e| Error::IO("checking for bin directory", bin_p, e))?)
    }

    /// Configures the sandbox to not delete itself when dropped.
    pub fn keep_dir(&mut self, keep_dir: bool) {
        self.keep_dir = keep_dir;
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
    fn command_inner<I, IE, ArgS, EnvK, EnvV>(
        &self,
        sandbox: &Sandbox,
        program: &str,
        args: I,
        envs: IE,
    ) -> Result<hakoniwa::Command, Error>
    where
        I: IntoIterator<Item = ArgS>,
        ArgS: AsRef<str>,
        IE: IntoIterator<Item = (EnvK, EnvV)>,
        EnvK: AsRef<str>,
        EnvV: AsRef<str>,
    {
        let mut command = self.container.command(program);
        command.args(args);
        command.current_dir(match &sandbox.config.wd {
            WdSetup::BoundDir { path, .. } => path.to_str().unwrap().to_string(),
            WdSetup::Isolated { .. } => "/build".to_string(),
        });

        command.env("XDG_CONFIG_HOME", "/state/home");
        command.env("XDG_DATA_HOME", "/state/data");
        command.env("XDG_CACHE_HOME", "/state/cache");
        command.env("XDG_STATE_HOME", "/state/state");
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
        }

        command.env("LANG", "en_US.utf8");
        command.env("LC_ALL", "en_US.utf8");
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

// Sandbox usage
impl Sandbox {
    pub fn new_container(&self) -> Result<Container, Error> {
        let mut container = hakoniwa::Container::new();
        container
            .rootfs(self.base_dir.join("rootfs"))
            .unwrap()
            .devfsmount("/dev")
            .tmpfsmount("/tmp")
            .bindmount_rw(self.state_dir.to_str().unwrap(), "/state")
            .unshare(hakoniwa::Namespace::Cgroup);

        if self.needs_bin_symlink()? {
            container.symlink("/usr/bin", "/bin");
        }
        if self.needs_lib64_symlink()? {
            container.symlink("/usr/lib", "/lib64");
        }
        // On aarch64, autotools/libtool defaults to installing libraries
        // into lib64/. Symlink /usr/lib64 → /usr/lib so installs land in
        // lib/ transparently (configure and libtool check for this symlink).
        if !fs::exists(self.base_dir.join("rootfs").join("usr").join("lib64"))
            .unwrap_or(false)
        {
            container.symlink("/usr/lib", "/usr/lib64");
        }
        if self.needs_lib_symlink()? {
            container.symlink("/usr/lib", "/lib");
        }

        // Mount in the working directory
        match &self.config.wd {
            WdSetup::Isolated { .. } => {
                container.bindmount_rw(self.base_dir.join("build").to_str().unwrap(), "/build")
            }
            WdSetup::BoundDir {
                path,
                read_only: false,
                fs_mappings: _,
            } => container.bindmount_rw(path.to_str().unwrap(), path.to_str().unwrap()),
            WdSetup::BoundDir {
                path,
                read_only: true,
                fs_mappings: _,
            } => container.bindmount_ro(path.to_str().unwrap(), path.to_str().unwrap()),
        };
        // Mount in any file mappings
        if let WdSetup::BoundDir { fs_mappings, .. } = &self.config.wd {
            for m in fs_mappings {
                if m.is_file {
                    container.mount(
                        &m.host_path,
                        &m.path_in_sandbox(),
                        "",
                        if m.read_only {
                            hakoniwa::MountOptions::BIND | hakoniwa::MountOptions::RDONLY
                        } else {
                            hakoniwa::MountOptions::BIND
                        },
                    );
                } else if m.read_only {
                    container.bindmount_ro(&m.host_path, &m.path_in_sandbox());
                } else {
                    container.bindmount_rw(&m.host_path, &m.path_in_sandbox());
                }
            }
        }

        if let Some(hn) = &self.config.hostname {
            let etc_hostname = self.base_dir.join("rootfs").join("etc").join("hostname");
            if !std::fs::exists(&etc_hostname)
                .map_err(|e| Error::IO("checking for /etc/hostname", etc_hostname.clone(), e))?
            {
                std::fs::write(&etc_hostname, format!("{}\n", hn))
                    .map_err(|e| Error::IO("writing /etc/hostname", etc_hostname.clone(), e))?;
            }
            container.unshare(hakoniwa::Namespace::Uts);
            container.hostname(hn);
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
        let rootfs = self.base_dir.join("rootfs");
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

    pub fn run(&mut self, invocations: Vec<Invocation>) -> Result<(), Error> {
        let container = self.new_container()?;
        for (i, exec) in invocations.iter().enumerate() {
            let span = match &self.config.wd {
                WdSetup::Isolated { .. } => tracing::info_span!(
                    "sandbox_exec",
                    "indicatif.pb_show" = tracing::field::Empty,
                    "cmd" = {
                        let s = if exec.args.is_empty() {
                            exec.executable.clone()
                        } else {
                            format!("{} {}", exec.executable, exec.args.join(" "))
                        };
                        match s.char_indices().nth(30) {
                            Some((idx, _)) => format!("{}...", &s[..idx]),
                            None => s.to_string(),
                        }
                    },
                ),
                _ => Span::none(),
            };
            let _enter = span.enter();

            let mut cmd = self.command(&container, &exec.executable, &exec.args, &exec.envs)?;
            cmd.stderr(hakoniwa::Stdio::MakePipe);
            cmd.stdout(hakoniwa::Stdio::MakePipe);
            tracing::debug!("Executing: {} {}", &exec.executable, exec.args.join(" "));

            // Exclusive section: only one hakoniwa command can be spawned
            // at a time. This prevents races with a file descriptor being held
            // by one forked process while being needed closed in another process.
            //
            // Waiting for spawn lets us wait till exec, at which point all such
            // file descriptors (which have O_CLOEXEC) will have been closed.
            let mut child = {
                let _guard = FdSynchronizer::lock_fork();
                cmd.spawn()
            }
            .map_err(|e| Error::Execution(ExecutionError::SpawnFailed(e)))?;

            let output = child
                .wait_with_output()
                .map_err(|e| Error::Execution(ExecutionError::SpawnFailed(e)))?;
            if let Some(stdout) = self.stdout.as_mut() {
                stdout
                    .write_all(&output.stdout)
                    .map_err(|e| Error::IO("writing stdout", Default::default(), e))?;
                stdout
                    .flush()
                    .map_err(|e| Error::IO("flushing stdout", Default::default(), e))?;
            }
            if let Some(stderr) = self.stderr.as_mut() {
                stderr
                    .write_all(&output.stderr)
                    .map_err(|e| Error::IO("writing stderr", Default::default(), e))?;
                stderr
                    .flush()
                    .map_err(|e| Error::IO("flushing stderr", Default::default(), e))?;
            }

            if !output.status.success() {
                let stderr_tail = {
                    let s = &output.stderr;
                    let tail = if s.len() > 4096 {
                        &s[s.len() - 4096..]
                    } else {
                        s
                    };
                    String::from_utf8_lossy(tail).into_owned()
                };
                return Err(Error::Execution(ExecutionError::InvocationFailed {
                    idx: i,
                    code: output.status.code,
                    reason: output.status.reason.clone(),
                    stderr: stderr_tail,
                }));
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

        let _l = FdSynchronizer::lock_writing_files();

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

fn hardlink_dir_contents(src_dir: &Path, dst_parent_dir: &Path) -> Result<(), Error> {
    common::hardlink_dir_contents(src_dir, dst_parent_dir).map_err(Error::HardlinkFailed)
}
