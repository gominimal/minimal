//! Injecting additional processes into a running session's namespaces.
//!
//! A session shell is launched into a sandbox by [`crate::session_host`], which
//! hands hakoniwa a container and gets back a [`hakoniwa::Child`]. Running a
//! *second* program in that same sandbox means joining the namespaces via
//! `setns(2)`.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::process::{CommandExt as _, ExitStatusExt as _};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

use nix::sched::CloneFlags;

/// `argv[1]` the daemon re-execs itself with to run [`shim_main`].
pub const SUBCOMMAND: &str = "__nsenter";

/// Where this daemon can re-exec itself from. Registered by [`set_shim_exe`].
static SHIM_EXE: OnceLock<PathBuf> = OnceLock::new();

/// Registers `path` as the [`SUBCOMMAND`] shim, overriding `current_exe()` for
/// every later [`Injection`].
///
/// For the microVM's pid-1, whose `current_exe()` is the initramfs `/init` —
/// unreachable once it switches into the rootfs, so every re-exec is an ENOENT
/// (#1175). Its boot path stages a runnable copy and names it here.
///
/// First registration wins: a stale path is worse than the one in use.
pub fn set_shim_exe(path: impl Into<PathBuf>) {
    let path = path.into();
    if let Err(rejected) = SHIM_EXE.set(path) {
        tracing::warn!(
            in_use = %SHIM_EXE.get().expect("set failed, so a value is present").display(),
            rejected = %rejected.display(),
            "the nsenter shim path is already registered; keeping the first one",
        );
    }
}

/// The registered shim executable, if [`set_shim_exe`] has been called.
#[must_use]
pub fn shim_exe() -> Option<&'static Path> {
    SHIM_EXE.get().map(PathBuf::as_path)
}

/// Descriptor number the pidfd is placed on, the shim joins the namespaces
/// associated with this process.
const PIDFD_FD: RawFd = 3;

/// A namespace an injected process can join.
#[derive(Copy, Clone, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum Namespace {
    /// Must be joined in the same `setns` call as any other namespace it owns.
    User,
    Mnt,
    Pid,
    Uts,
    Ipc,
    Cgroup,
    Net,
}

impl Namespace {
    /// Every namespace, in no significant order — a single `setns` call takes
    /// the whole set at once and the kernel sequences it internally.
    const ALL: [Self; 7] = [
        Self::User,
        Self::Mnt,
        Self::Pid,
        Self::Uts,
        Self::Ipc,
        Self::Cgroup,
        Self::Net,
    ];

    /// The entry name under `/proc/<pid>/ns/`.
    fn proc_name(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Mnt => "mnt",
            Self::Pid => "pid",
            Self::Uts => "uts",
            Self::Ipc => "ipc",
            Self::Cgroup => "cgroup",
            Self::Net => "net",
        }
    }

    /// The `clone(2)` flag `setns` selects this namespace with.
    fn clone_flag(self) -> CloneFlags {
        match self {
            Self::User => CloneFlags::CLONE_NEWUSER,
            Self::Mnt => CloneFlags::CLONE_NEWNS,
            Self::Pid => CloneFlags::CLONE_NEWPID,
            Self::Uts => CloneFlags::CLONE_NEWUTS,
            Self::Ipc => CloneFlags::CLONE_NEWIPC,
            Self::Cgroup => CloneFlags::CLONE_NEWCGROUP,
            Self::Net => CloneFlags::CLONE_NEWNET,
        }
    }

    /// The namespace `pid` is in, as the kernel's `ns:[inode]` identity, or
    /// `None` if this kernel has no such namespace type.
    fn identity(self, pid: Option<u32>) -> Result<Option<String>, NsenterError> {
        let who = pid.map_or_else(|| "self".to_string(), |p| p.to_string());
        let path = format!("/proc/{who}/ns/{}", self.proc_name());
        match std::fs::read_link(&path) {
            Ok(target) => Ok(Some(target.to_string_lossy().into_owned())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(source) => Err(NsenterError::ReadNamespace { path, source }),
        }
    }
}

/// The namespaces of `leader_pid` that the caller is not already in.
///
/// The set has to be computed, not hardcoded, and asking for one namespace too
/// many is not free. Once `setns` switches our credentials into the sandbox's
/// user namespace, we hold capabilities *there* and nowhere else — so asking in
/// the same call for a namespace the sandbox never unshared, which is therefore
/// still the host's, is refused with `EPERM` rather than quietly ignored.
/// Measured, joining a sandbox that unshared user/mount/PID/UTS/cgroup but left
/// IPC and (for a `HostNet` session) the network alone:
///
/// ```text
///  setns(pidfd, user|mnt)    = ok        setns(pidfd, user|ipc) = EPERM
///  setns(pidfd, user|pid)    = ok        setns(pidfd, user|net) = EPERM
///  setns(pidfd, user|uts)    = ok
///  setns(pidfd, user|cgroup) = ok
/// ```
///
/// Diffing namespace identities against our own yields exactly the set the
/// sandbox created, which is what makes this work across a `HostNet` session
/// (network shared with the daemon, so not joined) and a `NoNet`/`OwnIp` one
/// (network unshared, so joined) without either being a special case.
///
/// # Errors
///
/// [`NsenterError::ReadNamespace`] if `/proc` cannot be read for either process;
/// a namespace type this kernel does not implement is skipped, not an error.
pub fn namespaces_to_join(leader_pid: u32) -> Result<Vec<Namespace>, NsenterError> {
    Namespace::ALL
        .into_iter()
        .filter_map(|ns| {
            let differs = || {
                Ok(match (ns.identity(Some(leader_pid))?, ns.identity(None)?) {
                    (Some(theirs), Some(ours)) => theirs != ours,
                    // A namespace type the kernel lacks entirely: nothing to join.
                    _ => false,
                })
            };
            match differs() {
                Ok(true) => Some(Ok(ns)),
                Ok(false) => None,
                Err(e) => Some(Err(e)),
            }
        })
        .collect()
}

/// A failure injecting a process into a session's namespaces.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum NsenterError {
    /// The supervisor's `children` file could not be read. Absent on a kernel
    /// built without `CONFIG_PROC_CHILDREN`; `ENOENT` also means the supervisor
    /// itself is gone, i.e. the session has ended.
    #[error("reading /proc/{pid}/task/{pid}/children (is CONFIG_PROC_CHILDREN enabled?)")]
    ReadChildren {
        pid: u32,
        #[source]
        source: std::io::Error,
    },

    /// The supervisor has no children: the session program has exited, and its
    /// namespaces are on their way out with it.
    #[error("sandbox supervisor {pid} has no child process; the session program has exited")]
    NoSessionLeader { pid: u32 },

    /// The supervisor has more than one child, so "the session program" is
    /// ambiguous. hakoniwa forks exactly once, so this means the process
    /// structure this module is written against has changed.
    #[error("sandbox supervisor {pid} has {count} children, expected exactly 1: {children}")]
    AmbiguousSessionLeader {
        pid: u32,
        count: usize,
        children: String,
    },

    /// The `children` file held something that is not a PID.
    #[error("sandbox supervisor {pid} reported an unparseable child pid: {child:?}")]
    MalformedChild { pid: u32, child: String },

    /// A `/proc/<pid>/ns/*` link could not be read while working out which
    /// namespaces the session actually has.
    #[error("reading the namespace link {path}")]
    ReadNamespace {
        path: String,
        #[source]
        source: std::io::Error,
    },

    /// `pidfd_open(2)` failed. `ESRCH` means the session program exited between
    /// resolving its PID and pinning it.
    #[error("pidfd_open({pid})")]
    PidfdOpen {
        pid: u32,
        #[source]
        source: std::io::Error,
    },

    /// The daemon binary could not be located to re-exec.
    #[error("resolving the running executable to re-exec as the {SUBCOMMAND} shim")]
    CurrentExe {
        #[source]
        source: std::io::Error,
    },

    /// The shim path resolved to something that is no longer on disk. The
    /// usual cause is a daemon whose own binary was replaced or deleted while
    /// it was running: `current_exe()` reads `/proc/self/exe`, which the
    /// kernel then reports as a dangling `<path> (deleted)`.
    ///
    /// Checked before the spawn because the `ENOENT` it would otherwise
    /// produce names the *injected* program, sending whoever reads it looking
    /// for a missing `bash` inside the session instead of a missing daemon
    /// outside it.
    #[error(
        "the daemon's own executable is gone from {path:?} — it was replaced or deleted while \
         the daemon was running (a rebuild, typically); restart minimald"
    )]
    ShimMissing { path: PathBuf },

    /// `setns(2)` failed. `EPERM` on an otherwise sound setup means one of: the
    /// caller is multi-threaded (which the user namespace forbids), the set
    /// includes a namespace the sandbox never unshared (see
    /// [`namespaces_to_join`]), or the sandbox's user namespace is not owned by
    /// this user — a daemon can only join sandboxes it owns.
    #[error("setns(2) onto the session's namespaces ({namespaces})")]
    Setns {
        namespaces: String,
        #[source]
        source: nix::Error,
    },

    /// The injected program could not be started. `ENOMEM` from the fork means
    /// the sandbox's PID namespace has no live init left to reparent to — the
    /// session shell exited while we were joining.
    #[error("spawning {program:?} inside the session")]
    Spawn {
        program: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// The shim could not reap the process it started.
    #[error("waiting for {program:?} inside the session")]
    Wait {
        program: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

/// Resolves the PID of the process hakoniwa exec'd, given the PID of its
/// container supervisor — that is, [`hakoniwa::Child::id()`].
///
/// The supervisor's sole child is the exec'd program (see the module docs), and
/// `/proc/<pid>/task/<pid>/children` names it. The read is race-free against a
/// just-returned `spawn()`: hakoniwa's parent only reports setup-success to the
/// caller *after* the second fork, so by the time a `hakoniwa::Child` exists the
/// child entry does too. It is not race-free against the `execve` that follows,
/// which matters only for reads that depend on it — `/proc/<pid>/environ` in
/// that window still holds the daemon's environment, not the session's.
///
/// # Errors
///
/// [`NsenterError::NoSessionLeader`] once the session program has exited, and
/// [`NsenterError::ReadChildren`] if `/proc` cannot answer — including on a
/// kernel without `CONFIG_PROC_CHILDREN`.
pub fn session_leader_pid(container_pid: u32) -> Result<u32, NsenterError> {
    let path = format!("/proc/{container_pid}/task/{container_pid}/children");
    let raw = std::fs::read_to_string(&path).map_err(|source| NsenterError::ReadChildren {
        pid: container_pid,
        source,
    })?;

    let children: Vec<&str> = raw.split_ascii_whitespace().collect();
    match children.as_slice() {
        [] => Err(NsenterError::NoSessionLeader { pid: container_pid }),
        [child] => child.parse().map_err(|_| NsenterError::MalformedChild {
            pid: container_pid,
            child: (*child).to_string(),
        }),
        many => Err(NsenterError::AmbiguousSessionLeader {
            pid: container_pid,
            count: many.len(),
            children: many.join(" "),
        }),
    }
}

/// Pins `pid` as a pidfd, so later use cannot be misdirected by PID reuse.
fn pidfd_open(pid: u32) -> Result<OwnedFd, NsenterError> {
    // SAFETY: `pidfd_open` takes a pid and a flags word and returns a fresh
    // descriptor or -1; it reads no user memory. On success we own the
    // descriptor and hand it straight to `OwnedFd`, which closes it exactly
    // once.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0) };
    if fd < 0 {
        return Err(NsenterError::PidfdOpen {
            pid,
            source: std::io::Error::last_os_error(),
        });
    }
    // SAFETY: `fd` is a positive, freshly-opened descriptor owned by nobody else.
    Ok(unsafe { OwnedFd::from_raw_fd(fd as RawFd) })
}

/// A program to run inside a running session's sandbox.
///
/// Built against the PID of the session process — resolve it with
/// [`session_leader_pid`], never `hakoniwa::Child::id()` — and turned into a
/// [`Command`] by [`Self::command`]. What the namespaces do not carry is set
/// here:
///
/// - **working directory** via [`Self::with_cwd`]. Without it the process
///   starts at the container root, because joining a mount namespace puts both
///   root and cwd there.
/// - **environment** via [`Self::with_env`]. Without it the process inherits the
///   daemon's environment, which describes the host rather than the sandbox.
/// - **stdio** on the returned [`Command`], which the caller owns. For a PTY,
///   open it daemon-side and pass slave descriptors exactly as the session
///   launcher does — descriptors cross namespaces untouched.
///
/// `minimald` gets both of the first two from the session's
/// [`SessionEnvironment`](crate::session_host::SessionEnvironment), which is
/// what the session's own shell was launched with.
#[derive(Debug)]
#[must_use = "an Injection does nothing until `command` is called"]
pub struct Injection {
    leader_pid: u32,
    program: OsString,
    args: Vec<OsString>,
    cwd: Option<PathBuf>,
    env: Option<BTreeMap<String, String>>,
    shim_exe: Option<PathBuf>,
}

impl Injection {
    /// Runs `program` in the namespaces of the session process `leader_pid`.
    pub fn new<I, S>(leader_pid: u32, program: impl AsRef<OsStr>, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        Self {
            leader_pid,
            program: program.as_ref().to_os_string(),
            args: args
                .into_iter()
                .map(|a| a.as_ref().to_os_string())
                .collect(),
            cwd: None,
            env: None,
            shim_exe: None,
        }
    }

    /// Starts the program in `cwd`, a path inside the container (`/workbench`
    /// for a session's workspace).
    ///
    /// Applied by the shim after it joins, since the path only exists there.
    pub fn with_cwd(mut self, cwd: impl Into<PathBuf>) -> Self {
        self.cwd = Some(cwd.into());
        self
    }

    /// Runs the program with exactly `env`, replacing the daemon's environment
    /// rather than adding to it.
    ///
    /// Carried on the shim's own environment and inherited from there, so no
    /// value is ever visible in `ps` output.
    pub fn with_env(mut self, env: impl Into<BTreeMap<String, String>>) -> Self {
        self.env = Some(env.into());
        self
    }

    /// Uses `shim_exe` as the namespace-joining shim instead of the running
    /// executable.
    ///
    /// The daemon always wants the running executable — it re-execs itself.
    /// This is for callers that are not the daemon: an integration test driving
    /// the real shim out of `CARGO_BIN_EXE_minimald`, say. A daemon whose own
    /// path is unrunnable uses [`set_shim_exe`] instead.
    pub fn with_shim(mut self, shim_exe: impl Into<PathBuf>) -> Self {
        self.shim_exe = Some(shim_exe.into());
        self
    }

    /// Builds the command that runs this program in the session.
    ///
    /// The pidfd is owned by the returned command and closed when it drops, so
    /// the pin against PID reuse lasts exactly as long as it is needed. Waiting
    /// on the resulting child waits on the shim, whose exit status is the
    /// injected program's.
    ///
    /// # Errors
    ///
    /// [`NsenterError::PidfdOpen`] if the session program exited before it
    /// could be pinned, [`NsenterError::ReadNamespace`] if its namespaces
    /// cannot be enumerated, [`NsenterError::CurrentExe`] if no shim was named
    /// or registered and this binary cannot be located.
    pub fn command(self) -> Result<Command, NsenterError> {
        // Resolved here rather than in the shim: the daemon holds the session's
        // PID and the shim holds only a pidfd, and naming the namespaces on the
        // command line puts them in `ps` output for whoever is debugging a
        // joined process.
        let namespaces = namespaces_to_join(self.leader_pid)?;
        let pidfd = pidfd_open(self.leader_pid)?;
        // Caller's choice, then the registration, then our own path.
        let shim = match self.shim_exe.or_else(|| shim_exe().map(Path::to_path_buf)) {
            Some(exe) => exe,
            None => {
                std::env::current_exe().map_err(|source| NsenterError::CurrentExe { source })?
            }
        };
        // See [`NsenterError::ShimMissing`]: a path that has gone away since it
        // was resolved is worth its own error, because the spawn's `ENOENT`
        // blames the injected program for the daemon's problem.
        if !shim.exists() {
            return Err(NsenterError::ShimMissing { path: shim });
        }

        let mut cmd = Command::new(shim);
        cmd.arg(SUBCOMMAND).arg("--pidfd").arg(PIDFD_FD.to_string());
        if !namespaces.is_empty() {
            cmd.arg("--join").arg(
                namespaces
                    .iter()
                    .map(|ns| ns.proc_name())
                    .collect::<Vec<_>>()
                    .join(","),
            );
        }
        if let Some(cwd) = &self.cwd {
            cmd.arg("--chdir").arg(cwd);
        }
        if let Some(env) = self.env {
            // The shim needs nothing from the daemon's environment — it holds
            // its pidfd on a descriptor and everything else in argv — so this
            // is the session's environment exactly, passed down by inheritance.
            cmd.env_clear().envs(env);
        }
        cmd.arg("--").arg(&self.program).args(&self.args);

        // SAFETY: the closure runs in the forked child between `fork` and
        // `exec`, where only async-signal-safe calls are legal. `dup2` and
        // `fcntl` are both on that list, and the closure allocates nothing and
        // touches no lock. It borrows only `pidfd`, which it owns.
        //
        // std installs the child's stdio before running pre_exec closures, so
        // fds 0-2 are already final and fd 3 is free to claim.
        unsafe {
            cmd.pre_exec(move || {
                let raw = pidfd.as_raw_fd();
                if raw == PIDFD_FD {
                    // `dup2(fd, fd)` is a no-op that, unlike the copying case,
                    // leaves FD_CLOEXEC set — which would close the pidfd out
                    // from under the exec. Clear it directly instead.
                    if libc::fcntl(raw, libc::F_SETFD, 0) == -1 {
                        return Err(std::io::Error::last_os_error());
                    }
                } else if libc::dup2(raw, PIDFD_FD) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }

        Ok(cmd)
    }
}

/// Arguments for the internal [`SUBCOMMAND`] shim.
#[derive(Debug, clap::Args)]
pub struct ShimArgs {
    /// Descriptor number carrying the pidfd of the session process to join.
    #[arg(long, default_value_t = PIDFD_FD)]
    pidfd: RawFd,

    /// Namespaces to join, as `/proc/<pid>/ns` names.
    ///
    /// Computed by [`namespaces_to_join`] rather than assumed: naming a
    /// namespace the session does not have of its own is an `EPERM`, not a
    /// no-op. Empty means the target shares every namespace with us and there
    /// is nothing to join.
    #[arg(long, value_delimiter = ',')]
    join: Vec<Namespace>,

    /// Directory to enter after joining, resolved inside the container.
    ///
    /// Optional: joining the mount namespace already puts both the root and the
    /// working directory at the container's root.
    #[arg(long)]
    chdir: Option<PathBuf>,

    /// The program to run inside the session, followed by its arguments.
    #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
    argv: Vec<OsString>,
}

/// Joins the session's namespaces and runs the requested program there,
/// returning the exit code to leave with.
///
/// **Must be called before the tokio runtime is built.** `setns(CLONE_NEWUSER)`
/// refuses a multi-threaded caller, and the `fork` this performs is only safe
/// because the process is single-threaded.
///
/// The spawn here is the fork that matters: `setns(CLONE_NEWPID)` placed *this*
/// process's future children in the session's PID namespace without moving this
/// process, so the program lands in the namespace and the shim stays outside it
/// as its parent, able to reap it and report its status.
///
/// # Errors
///
/// [`NsenterError::Setns`] if the namespaces cannot be joined, and
/// [`NsenterError::Spawn`] if the program cannot be started inside them.
pub fn shim_main(args: ShimArgs) -> Result<i32, NsenterError> {
    // SAFETY: `command_in_session` placed a pidfd on this descriptor and it
    // survived the exec; nothing else in this freshly-exec'd process owns it.
    // A wrong `--pidfd` yields a closed or unrelated descriptor, which fails
    // `setns` with EBADF/EINVAL rather than doing damage.
    let pidfd = unsafe { OwnedFd::from_raw_fd(args.pidfd) };
    if !args.join.is_empty() {
        // One call for the whole set: the kernel installs the user namespace
        // first and validates the rest against the credentials that gives us,
        // which is what makes the rest permitted. Joining them one at a time
        // fails — and joining the mount namespace first would repoint `/proc`
        // at the sandbox's procfs, where the remaining `/proc/<host pid>/ns`
        // paths do not exist.
        let flags = args
            .join
            .iter()
            .fold(CloneFlags::empty(), |acc, ns| acc | ns.clone_flag());
        nix::sched::setns(&pidfd, flags).map_err(|source| NsenterError::Setns {
            namespaces: args
                .join
                .iter()
                .map(|ns| ns.proc_name())
                .collect::<Vec<_>>()
                .join(","),
            source,
        })?;
    }
    drop(pidfd);

    let (program, rest) = args
        .argv
        .split_first()
        .expect("clap requires at least one argv entry");

    let mut cmd = Command::new(program);
    cmd.args(rest);
    if let Some(dir) = &args.chdir {
        cmd.current_dir(dir);
    }

    // SAFETY: the closure runs in the forked child between `fork` and `exec`,
    // where only async-signal-safe calls are legal. `prctl` is on that list,
    // and the closure allocates nothing and captures nothing.
    unsafe {
        cmd.pre_exec(|| {
            // Tie the injected process's lifetime to this shim's. Nothing else
            // does: the shim is its parent but sits outside the session's PID
            // namespace, and killing the shim is exactly how the daemon cancels
            // an exec whose client has gone away. Without this the command
            // keeps running in the session, holding stdio pipes nobody reads.
            //
            // The usual `getppid()` race check — did the parent die before this
            // ran? — is not available here: the parent is outside the PID
            // namespace this process was just placed in, so `getppid` reports 0
            // whether or not it is still alive. The window is a few
            // instructions wide, and what escapes through it is bounded by the
            // session: the sandbox's PID namespace dies with its shell, taking
            // anything left in it.
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }

    let program = PathBuf::from(program);
    let mut child = cmd.spawn().map_err(|source| NsenterError::Spawn {
        program: program.clone(),
        source,
    })?;
    let status = child.wait().map_err(|source| NsenterError::Wait {
        program: program.clone(),
        source,
    })?;

    // Mirror the shell's convention for a signalled child so the daemon sees
    // the same code it would from a direct spawn.
    Ok(status
        .code()
        .or_else(|| status.signal().map(|sig| 128 + sig))
        .unwrap_or(1))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A process whose only child is known: `sh` prints the PID of the
    /// background `sleep` it forked, so the expected answer arrives on stdout
    /// after the fork rather than being guessed at.
    fn shell_with_one_child() -> (std::process::Child, u32) {
        use std::io::BufRead as _;

        let mut sh = Command::new("/bin/sh")
            .arg("-c")
            .arg("sleep 30 & echo $!; wait")
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("spawning /bin/sh");
        // One line, not to EOF: `sh` holds the pipe open until the background
        // `sleep` it just forked has finished, which is the state under test.
        let mut out = String::new();
        std::io::BufReader::new(sh.stdout.as_mut().expect("piped stdout"))
            .read_line(&mut out)
            .expect("reading the child pid");
        let child_pid = out.trim().parse().expect("sh printed a pid");
        (sh, child_pid)
    }

    #[test]
    fn resolves_the_grandchild_not_the_forking_process() {
        let (mut sh, expected) = shell_with_one_child();

        let resolved = session_leader_pid(sh.id());

        let _ = sh.kill();
        let _ = sh.wait();
        assert_eq!(resolved.expect("resolving the sole child"), expected);
    }

    /// The production path: no shim is named per injection (only tests do
    /// that), so this resolution order is what keeps #1175 fixed. One test,
    /// because [`SHIM_EXE`] is process-wide and set once.
    ///
    /// Both stand-in shims are real files: a path that doesn't exist is now
    /// [`NsenterError::ShimMissing`], which would mask the ordering under test.
    #[test]
    fn the_registered_shim_overrides_current_exe_and_yields_to_an_explicit_one() {
        let registered_exe = tempfile::NamedTempFile::new().expect("a temp file to stand in");
        let explicit_exe = tempfile::NamedTempFile::new().expect("a temp file to stand in");

        // A plain child shares all our namespaces, so nothing is joined and no
        // privilege is needed.
        let mut sleep = Command::new("/bin/sleep")
            .arg("30")
            .spawn()
            .expect("spawning /bin/sleep");
        let target = sleep.id();
        let injection = || Injection::new(target, "/bin/true", Vec::<&str>::new());

        let unregistered = injection().command().map(|c| c.get_program().to_owned());
        set_shim_exe(registered_exe.path());
        let registered = injection().command().map(|c| c.get_program().to_owned());
        let explicit = injection()
            .with_shim(explicit_exe.path())
            .command()
            .map(|c| c.get_program().to_owned());

        let _ = sleep.kill();
        let _ = sleep.wait();
        assert_eq!(
            PathBuf::from(unregistered.expect("building the command")),
            std::env::current_exe().expect("locating the test binary"),
            "with nothing registered the daemon re-execs itself",
        );
        assert_eq!(
            PathBuf::from(registered.expect("building the command")),
            registered_exe.path(),
            "the registered shim replaces current_exe()",
        );
        assert_eq!(
            PathBuf::from(explicit.expect("building the command")),
            explicit_exe.path(),
            "a per-injection shim still wins over the registration",
        );
    }

    /// A shim path that has gone away — the shape `current_exe()` takes after
    /// the daemon's binary is replaced under it, which any rebuild of a running
    /// daemon does — is reported as the daemon's problem. Spawning it instead
    /// yields an `ENOENT` naming the injected program, which reads as a broken
    /// session rather than a stale daemon.
    #[test]
    fn a_shim_that_is_no_longer_on_disk_is_named_as_the_failure() {
        let missing = tempfile::NamedTempFile::new().expect("a temp file to stand in");
        let path = missing.path().to_path_buf();
        drop(missing); // Now a path that resolved a moment ago and no longer does.

        let mut sleep = Command::new("/bin/sleep")
            .arg("30")
            .spawn()
            .expect("spawning /bin/sleep");
        let built = Injection::new(sleep.id(), "/bin/true", Vec::<&str>::new())
            .with_shim(&path)
            .command();

        let _ = sleep.kill();
        let _ = sleep.wait();
        let Err(NsenterError::ShimMissing { path: reported }) = built else {
            panic!("expected ShimMissing, got {:?}", built.map(|_| "a command"));
        };
        assert_eq!(reported, path);
    }

    #[test]
    fn a_process_without_children_is_not_a_container_supervisor() {
        let mut sleep = Command::new("/bin/sleep")
            .arg("30")
            .spawn()
            .expect("spawning /bin/sleep");

        let resolved = session_leader_pid(sleep.id());

        let _ = sleep.kill();
        let _ = sleep.wait();
        assert!(
            matches!(resolved, Err(NsenterError::NoSessionLeader { .. })),
            "expected NoSessionLeader, got {resolved:?}"
        );
    }
}
