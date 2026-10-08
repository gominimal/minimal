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
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::time::Duration;

use nix::sched::CloneFlags;

/// `argv[1]` the daemon re-execs itself with to run [`shim_main`].
pub const SUBCOMMAND: &str = "__nsenter";

/// Where this daemon can re-exec itself from. Registered by [`set_shim_exe`].
static SHIM_EXE: OnceLock<PathBuf> = OnceLock::new();

/// How long the shim gives the injected process group between the SIGTERM it
/// forwards and the SIGKILL that ends the group. Ending an exec is SIGTERM, a
/// grace period, then SIGKILL, so a member that traps SIGTERM can clean up.
///
/// This and [`SHIM_ESCALATION`] are two halves of one timeline and are defined
/// together on purpose: the daemon's SIGKILL of the shim must come after the
/// shim's own group SIGKILL plus [`ESCALATION_MARGIN`]. A shim SIGKILLed first
/// cannot kill the group (`PR_SET_PDEATHSIG` takes the group leader only), so
/// the daemon's SIGKILL is a fallback for a wedged shim, never the normal way
/// an exec ends. Whole seconds, because `alarm(2)` arms whole seconds.
pub const GROUP_GRACE: Duration = Duration::from_secs(2);

/// How long the daemon waits for a SIGTERMed shim to exit before it SIGKILLs
/// it. Longer than [`GROUP_GRACE`] plus [`ESCALATION_MARGIN`], which the const
/// assertion below enforces; [`GROUP_GRACE`] says why.
pub const SHIM_ESCALATION: Duration = Duration::from_secs(5);

/// The slack between the shim's group SIGKILL and the daemon's SIGKILL of the
/// shim: time for the shim to finish its last group scan, reap, and exit.
const ESCALATION_MARGIN: Duration = Duration::from_secs(2);

const _: () = {
    assert!(
        SHIM_ESCALATION.as_secs() > GROUP_GRACE.as_secs() + ESCALATION_MARGIN.as_secs(),
        "the daemon must SIGKILL the shim only after the shim's own group SIGKILL"
    );
    assert!(
        GROUP_GRACE.subsec_nanos() == 0 && GROUP_GRACE.as_secs() > 0,
        "alarm(2) arms whole seconds"
    );
};

/// [`GROUP_GRACE`] as the `alarm(2)` argument the SIGTERM handler arms.
#[allow(clippy::cast_possible_truncation)]
const GROUP_GRACE_ALARM: libc::c_uint = GROUP_GRACE.as_secs() as libc::c_uint;

/// How often the shim's main flow checks, during the grace period, whether the
/// group still has a live member.
const GROUP_POLL: Duration = Duration::from_millis(25);

/// The process-group id (== pid, see `setpgid(0, 0)` in [`shim_main`]) of the
/// process this shim injected into the session, published after spawn so the
/// signal handlers can reach the whole group — the injected program and every
/// descendant it forked — rather than leaving grandchildren reparented to
/// PID 1. `0` before the spawn and again just before the leader is reaped, so
/// a handler can never target a recycled pid.
static CHILD_PGID: AtomicI32 = AtomicI32::new(0);

/// The first SIGTERM or SIGHUP the shim received, `0` until one arrives. The
/// handler claims it with a compare-exchange, so a second signal neither
/// re-sends the group SIGTERM nor re-arms or extends the grace period.
static TERM_SIGNAL: AtomicI32 = AtomicI32::new(0);

/// Whether the group has been sent its SIGTERM. Claimed with a swap by
/// whichever of the handler and the main flow first sees both a termination
/// request and a published [`CHILD_PGID`], so the group gets exactly one.
static GROUP_TERMED: AtomicBool = AtomicBool::new(false);

/// Set by the SIGALRM handler once [`GROUP_GRACE`] has run out.
static GRACE_EXPIRED: AtomicBool = AtomicBool::new(false);

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

    /// The shim could not move itself into a deny-all box's classifier leaf
    /// before joining its namespaces. The join is the one write that must
    /// precede `setns` (see [`shim_main`]), and for a deny-all box it is also
    /// the one placement a verdict cannot survive failing: a process left
    /// outside the leaf runs where nothing refuses its connections, so the
    /// injected run stops rather than silently run unenforced. For any other
    /// leaf the same failure is advisory (NET-079's exception) and never
    /// yields this error.
    #[error("joining the deny-all box's classifier leaf {}", leaf.display())]
    JoinDenyLeaf {
        leaf: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// The injected program could not be started for a reason a shell would
    /// not report as its own (those are exit codes 127/126). `ENOMEM` from the
    /// fork means the sandbox's PID namespace has no live init left to
    /// reparent to — the session shell exited while we were joining.
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
    seal_none_box: bool,
    /// The box's classifier leaf (NET-079), joined before the namespaces.
    /// `None` on a host that places no box.
    leaf: Option<sandbox2::config::ClassifierLeaf>,
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
            seal_none_box: false,
            leaf: None,
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

    /// Mark this injection as entering a none box, so the shim reinstalls the
    /// none plan's full socket-family seal — every family but the ones the
    /// box's own network namespace confines (`AF_UNIX`, `AF_INET`,
    /// `AF_INET6`, `AF_NETLINK` with `NETLINK_ROUTE` only) — after joining
    /// the namespaces.  That seal applies only when the injection joins the
    /// box's own network namespace; one that does not falls back to `AF_UNIX`
    /// alone
    /// ([`injection_socket_filter`]).
    ///
    /// Every injection is sealed: without this marker the shim reinstalls the
    /// confined-families seal, the one every networked box launches under,
    /// which admits the families the box's own network namespace confines
    /// and refuses the rest.  Either way the filter installed at launch is
    /// inherited by children of the filtered process only, and an injected
    /// process joins the namespaces later.
    pub fn seal_none_box(mut self) -> Self {
        self.seal_none_box = true;
        self
    }

    /// Joins the box's classifier leaf before joining its namespaces.
    ///
    /// The leaf is the cgroup the box's egress verdict is decided on, and the
    /// one the injected process must share with the box it joins. The join is
    /// the shim's own — and it happens *before* `setns`, the only place it
    /// can: the box's cgroup namespace is rooted at its own leaf, and from
    /// inside it that root is not writable — with `nsdelegate` mounted the
    /// root's `cgroup.procs` is a delegation boundary, and the empty tmpfs
    /// the box mounts over the tree it joined through leaves no path to
    /// write a migration to at all. Writing the shim's pid from the daemon's
    /// namespaces puts it, and the program it forks, in the leaf.
    pub fn with_classifier_leaf(mut self, leaf: sandbox2::config::ClassifierLeaf) -> Self {
        self.leaf = Some(leaf);
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
        if self.seal_none_box {
            cmd.arg("--seal-none-box");
        }
        if let Some(leaf) = &self.leaf {
            cmd.arg("--classifier-leaf").arg(leaf.dir());
        }
        // One debug line per injection naming the seal the joined process will
        // run under (observability). Resolved through the filters rather than
        // restated here, so the log names exactly what the shim installs; the
        // shim itself has no tracing subscriber — it is the daemon re-exec'd
        // before its runtime is built.
        let seal = injection_socket_filter(self.seal_none_box, &namespaces).seal;
        tracing::debug!(
            leader_pid = self.leader_pid,
            program = %self.program.to_string_lossy(),
            socket_seal = %seal,
            "nsenter injection: joining the box under its socket-family seal"
        );
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

    /// When present, the target session is a none box and the shim must
    /// re-install its full socket-family seal after joining the namespaces —
    /// unix, inet, inet6 and netlink route admitted when the join enters the box's
    /// own network namespace, `AF_UNIX` alone when it does not. When absent the shim re-installs the
    /// confined-families seal, the one every other box launches under, which
    /// admits the families the box's namespace confines and refuses the
    /// rest.  Either way the filter is inherited by children of the filtered
    /// process, but an injected process joins the namespaces later and must
    /// load it itself.
    #[arg(long)]
    seal_none_box: bool,

    /// The classifier leaf of the box being joined, so the shim can move
    /// itself into it **before** `setns` — the write has to happen from the
    /// daemon's namespaces, where the leaf is reachable; see
    /// [`Injection::with_classifier_leaf`]. Absent on a host that places no
    /// box, whose injections join nothing but the namespaces.
    #[arg(long)]
    classifier_leaf: Option<PathBuf>,

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
/// [`NsenterError::JoinDenyLeaf`] if the box is deny-all and its classifier
/// leaf cannot be joined, [`NsenterError::Setns`] if the namespaces cannot be
/// joined, [`NsenterError::Spawn`] if the program cannot be started for a
/// reason a shell would not report, and [`NsenterError::Wait`] if the started
/// program cannot be reaped. A program that is missing, not executable, or not
/// an executable format is reported on stderr and returned as the shell's exit
/// code (127/126) rather than as an error.
pub fn shim_main(args: ShimArgs) -> Result<i32, NsenterError> {
    // SAFETY: `command_in_session` placed a pidfd on this descriptor and it
    // survived the exec; nothing else in this freshly-exec'd process owns it.
    // A wrong `--pidfd` yields a closed or unrelated descriptor, which fails
    // `setns` with EBADF/EINVAL rather than doing damage.
    let pidfd = unsafe { OwnedFd::from_raw_fd(args.pidfd) };

    // NET-079: join the box's classifier leaf before its namespaces. This is
    // the one write that has to happen *before* `setns`: the box's cgroup
    // namespace is rooted at its own leaf, and from inside it that root is
    // not writable — with `nsdelegate` mounted the root's `cgroup.procs` is
    // a delegation boundary, and the empty tmpfs the box mounts over the
    // tree it joined through leaves no path to write a migration to. Writing
    // our pid here, from the daemon's own namespaces, moves this shim into
    // the leaf, and the program forked below inherits it with everything
    // else.
    //
    // Fatal for a deny leaf, advisory for any other: a process that stays
    // out of a deny-all box's leaf is a process of a box whose declaration
    // admits nothing running where nothing refuses its connections — the
    // one placement failure a verdict cannot survive, so the injected run
    // stops rather than silently run unenforced. Any other leaf is the
    // cohort's identity alone, and a host that cannot place an injected
    // process does not refuse it on that ground (NET-079's exception): it
    // runs in the daemon's leaf instead, and the box's own processes are
    // placed either way. This shim has no logger (it runs before any
    // runtime is built), so the failure goes to the inherited stderr, which
    // is the daemon's.
    if let Some(leaf) = &args.classifier_leaf {
        let leaf = sandbox2::config::ClassifierLeaf::new(leaf);
        if let Err(source) = sandbox2::classifier::place_pid(&leaf.procs(), std::process::id()) {
            if leaf.is_deny() {
                eprintln!(
                    "minimald: joining the deny-all box's classifier leaf {}: {source}",
                    leaf.dir().display()
                );
                return Err(NsenterError::JoinDenyLeaf {
                    leaf: leaf.dir().to_path_buf(),
                    source,
                });
            }
            eprintln!(
                "minimald: joining the session's classifier leaf {}: {source}",
                leaf.dir().display()
            );
        }
    }

    // The daemon's procfs, opened before the join: the grace period below scans
    // it for live members of the injected group, by the pids and group ids this
    // shim sees. After `setns(CLONE_NEWNS)` the path `/proc` names the box's
    // procfs, whose pids belong to the box's PID namespace rather than this
    // shim's. `None` (no procfs) only costs the early exit: the grace period
    // then always runs to its end.
    let proc_dir = std::fs::File::open("/proc").ok();

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

    // Resolved here, before the fork: building the filter allocates, and the
    // first `OnceLock` access is what builds it. Only the `&'static` result
    // crosses into the child. Every injection is sealed — the none box's
    // full seal (unix-only unless the join entered the box's own network
    // namespace), or the confined-families seal every other box launches
    // under.
    let socket_family_filter = injection_socket_filter(args.seal_none_box, &args.join);

    // SAFETY: the closures run in the forked child between `fork` and `exec`,
    // where only async-signal-safe calls are legal. `signal`, `alarm`,
    // `setpgid`, `prctl` and the raw `seccomp` syscall are on that list, and
    // the closures allocate nothing
    // and capture only a static reference.
    unsafe {
        cmd.pre_exec(|| {
            // Undo what the shim's own termination handling (installed before
            // the spawn) left in this forked copy: the handlers, and an alarm
            // a handler running here before this point could have armed, which
            // `exec` would otherwise carry into the program. Dispositions first,
            // so a signal from here on takes its default action.
            for signum in [libc::SIGTERM, libc::SIGHUP, libc::SIGALRM] {
                if libc::signal(signum, libc::SIG_DFL) == libc::SIG_ERR {
                    return Err(std::io::Error::last_os_error());
                }
            }
            libc::alarm(0);
            // Make the injected process the leader of a new process group
            // (pid == pgid). Nothing else does: the shim sits outside the
            // session's PID namespace, so the group ids the session's shell
            // already assigned do not help it name "the shim's child and its
            // descendants" for a later group kill.
            if libc::setpgid(0, 0) == -1 {
                return Err(std::io::Error::last_os_error());
            }
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

        // The injected process takes the box's credentials — no_new_privs, the
        // capabilities no box may hold dropped from the bounding set, every
        // capability set cleared, and the box uid and gid — the same state the
        // box's own processes exec with, so a process that joins a running box
        // cannot be the hole that state was for. Joining the user namespace
        // above granted this process a full capability set in it, which is
        // what the drops run on; without them, a file capability or a setuid
        // bit on a program in the box could hand the injected process a
        // capability no box process may hold.
        cmd.pre_exec(|| {
            // SAFETY: `assume_box_credentials` only makes async-signal-safe
            // syscalls and owns no state; this is the pre-exec moment it is
            // for, in the box's user namespace with the capabilities joining
            // it granted.
            sandbox2::assume_box_credentials()
        });

        cmd.pre_exec(move || {
            // Re-install the box's socket-family seal — the none box's full
            // seal, or the confined-families seal every other box launches
            // under.  The filter installed at sandbox launch is inherited by
            // children of the filtered process, but this injected process
            // joins the namespaces later and must load it itself.
            // SAFETY: `filter` is a `&'static` owned by the process-wide
            // OnceLock, valid and immutable for the program's lifetime.
            sandbox2::install_socket_family_filter(socket_family_filter)?;
            Ok(())
        });
    }

    // The handlers go in before the spawn, so a SIGTERM or SIGHUP that arrives
    // before the child exists is recorded (and its grace period armed) rather
    // than taking the default action, which would leave the child to
    // `PR_SET_PDEATHSIG` and its descendants to run on. The forked copy resets
    // them in its first pre-exec closure.
    // SAFETY: shim_main runs before any runtime is built (see its doc), so this
    // process is single-threaded and no handler can interrupt half-initialised
    // state.
    unsafe {
        install_termination_handlers();
    }

    let program = PathBuf::from(program);
    let mut child = match cmd.spawn() {
        Ok(child) => child,
        Err(source) => {
            // The child's `chdir` fails with the same `ENOENT` as a missing
            // program; a missing working directory is not "command not found".
            let chdir_missing = spawn_failed_on_missing_chdir(&source, args.chdir.as_deref());
            let mapped = if chdir_missing {
                None
            } else {
                spawn_failure_code_and_message(&source)
            };
            let Some((code, msg)) = mapped else {
                return Err(NsenterError::Spawn { program, source });
            };
            eprintln!("{program}: {msg}", program = program.display());
            return Ok(code);
        }
    };

    // Publish the child's group lead (its own pid, from `setpgid(0, 0)` above)
    // for the handlers. A termination that arrived before this store found no
    // group to signal, so it is forwarded here; `GROUP_TERMED` makes sure the
    // group gets one SIGTERM whichever side gets there first.
    let pgid = libc::pid_t::try_from(child.id()).expect("a pid fits a pid_t");
    CHILD_PGID.store(pgid, Ordering::SeqCst);
    if TERM_SIGNAL.load(Ordering::SeqCst) != 0 {
        term_group_once();
    }

    // Wait for the leader to exit without reaping it: until it is reaped its
    // pid stays allocated and still names the group, so neither a handler nor
    // the grace period below can target a recycled group. The handlers return
    // (they only record and signal), so an interrupted wait is resumed.
    loop {
        // SAFETY: `waitid` writes only into `info`, a zeroed `siginfo_t` we own.
        let observed = unsafe {
            let mut info: libc::siginfo_t = std::mem::zeroed();
            libc::waitid(
                libc::P_PID,
                child.id(),
                &raw mut info,
                libc::WEXITED | libc::WNOWAIT,
            )
        };
        if observed == 0 {
            break;
        }
        let source = std::io::Error::last_os_error();
        if source.kind() != std::io::ErrorKind::Interrupted {
            return Err(NsenterError::Wait { program, source });
        }
    }

    // The leader has exited. Decide once whether the exec was ended or ended
    // by itself, after blocking SIGTERM and SIGHUP so the answer cannot change
    // once read. One that arrived before the block started the grace period;
    // one that arrives after it is never delivered, and the exec ends as the
    // leader did, killing nothing: a normal exit leaves the group's other
    // members (a `nohup`'d job) alone.
    block_termination_signals();
    let terminated_by = TERM_SIGNAL.load(Ordering::SeqCst);
    if terminated_by != 0 {
        // The usual shape: the leader died of the SIGTERM while a member it
        // forked traps or ignores it. Hold the leader as a zombie, so the pgid
        // stays allocated, until the grace period runs out (the SIGALRM
        // handler sets the flag and has already SIGKILLed the group) or the
        // group has no live member left. Then SIGKILL whatever remains.
        while !GRACE_EXPIRED.load(Ordering::SeqCst)
            && proc_dir
                .as_ref()
                .is_none_or(|proc_dir| group_has_live_member(proc_dir, pgid))
        {
            std::thread::sleep(GROUP_POLL);
        }
        // SAFETY: `pgid` names the group this shim spawned, which its unreaped
        // leader keeps from being recycled.
        unsafe { kill_group(pgid) };
    }

    // Disarm: no alarm left to fire, and from here the handlers are no-ops so
    // a straggler signal cannot target the pid the reap below frees for reuse.
    // SAFETY: `alarm(0)` only cancels this process's pending alarm.
    unsafe { libc::alarm(0) };
    CHILD_PGID.store(0, Ordering::SeqCst);

    let status = child.wait().map_err(|source| NsenterError::Wait {
        program: program.clone(),
        source,
    })?;

    // An exec that was ended reports the signal that ended it, the way the
    // shell reports a command it killed, whatever the leader's own status.
    if terminated_by != 0 {
        return Ok(128 + terminated_by);
    }
    // Mirror the shell's convention for a signalled child so the daemon sees
    // the same code it would from a direct spawn.
    Ok(status
        .code()
        .or_else(|| status.signal().map(|sig| 128 + sig))
        .unwrap_or(1))
}

/// Kill every process in the process group led by `pgid` — the injected program
/// and every descendant that has not left the group.
///
/// The daemon cancels a `min session exec` by signalling the shim, which
/// SIGTERMs this group and, once [`GROUP_GRACE`] is over, calls this with the
/// group lead captured at spawn. Without the group kill, only the shim's direct
/// child dies and its grandchildren are reparented to PID 1 to run on
/// indefinitely (#948).
///
/// A descendant that calls `setsid(2)` leaves the group and escapes this kill
/// (and the shim's `wait`); it is bounded by the sandbox's PID namespace dying
/// with its session shell, the same bound the pre-fix race already relied on.
///
/// # Safety
///
/// The caller must pass the group-lead of a live group it is entitled to
/// signal, or `0` (a no-op, so a handler that fires after the child was reaped
/// cannot hit a recycled pid). Any `pgid <= 1` is a no-op: `kill(0, …)` would
/// signal the shim's own group and `kill(-1, …)` every process it may signal,
/// so neither can ever be the target.
unsafe fn kill_group(pgid: i32) {
    if pgid <= 1 {
        return;
    }
    // SAFETY: only async-signal-safe calls follow, so this is legal from a
    // signal handler. SIGKILL is uncatchable, so nothing in the group can
    // survive it; ESRCH means the group is already gone.
    unsafe {
        libc::kill(-pgid, libc::SIGKILL);
    }
}

/// Send the injected group its one SIGTERM, if the group is published and no
/// one has sent it yet. Async-signal-safe (atomics and `kill` only), so both
/// the SIGTERM/SIGHUP handler and the main flow call it.
fn term_group_once() {
    let pgid = CHILD_PGID.load(Ordering::SeqCst);
    // The same guard as `kill_group`: `0` is "no group yet" (or "already
    // reaped"), and nothing at or below 1 names a child group.
    if pgid > 1 && !GROUP_TERMED.swap(true, Ordering::SeqCst) {
        // SAFETY: `pgid` is the group lead this shim spawned, unreaped while
        // published; `kill(2)` is async-signal-safe.
        unsafe { libc::kill(-pgid, libc::SIGTERM) };
    }
}

/// SIGTERM and SIGHUP: the daemon ending an exec whose client went away. The
/// first one records itself, arms [`GROUP_GRACE`] and forwards SIGTERM to the
/// group; any later one does nothing, so the grace period is never re-armed or
/// extended. The waiting happens in [`shim_main`]'s main flow, not here.
extern "C" fn on_term_or_hup(signum: libc::c_int) {
    // The main flow reads errno after the `waitid` this may have interrupted.
    // SAFETY: `__errno_location` is this thread's errno slot, live for the call.
    let saved = unsafe { *libc::__errno_location() };
    if TERM_SIGNAL
        .compare_exchange(0, signum, Ordering::SeqCst, Ordering::SeqCst)
        .is_ok()
    {
        // SAFETY: `alarm(2)` is async-signal-safe and arms only this process's
        // timer.
        unsafe { libc::alarm(GROUP_GRACE_ALARM) };
        term_group_once();
    }
    // SAFETY: as above.
    unsafe { *libc::__errno_location() = saved };
}

/// SIGALRM: [`GROUP_GRACE`] has run out. SIGKILL the group and tell the main
/// flow. Once the shim is about to reap its child, [`CHILD_PGID`] is `0` and the
/// kill is a no-op, so an alarm that fires late does nothing.
extern "C" fn on_grace_expired(_signum: libc::c_int) {
    // SAFETY: `__errno_location` is this thread's errno slot, live for the call.
    let saved = unsafe { *libc::__errno_location() };
    GRACE_EXPIRED.store(true, Ordering::SeqCst);
    // SAFETY: the published pgid is the group this shim spawned, or `0`.
    unsafe { kill_group(CHILD_PGID.load(Ordering::SeqCst)) };
    // SAFETY: as above.
    unsafe { *libc::__errno_location() = saved };
}

/// Install [`on_term_or_hup`] for SIGTERM and SIGHUP — the two the daemon uses
/// to cancel a shim whose client died — and [`on_grace_expired`] for SIGALRM.
///
/// # Safety
///
/// Must run while the process is single-threaded (before the tokio runtime is
/// built, which [`shim_main`] guarantees) so a handler cannot interrupt a
/// half-initialised data structure.
unsafe fn install_termination_handlers() {
    let handlers: [(libc::c_int, extern "C" fn(libc::c_int)); 3] = [
        (libc::SIGTERM, on_term_or_hup),
        (libc::SIGHUP, on_term_or_hup),
        (libc::SIGALRM, on_grace_expired),
    ];
    for (signum, handler) in handlers {
        // SAFETY: an all-zero `sigaction` is a valid disposition (empty mask,
        // SIG_DFL); `sigemptyset` writes only the mask; `sigaction` installs a
        // handler whose body is limited to atomics, `kill`, `alarm` and errno.
        // No SA_RESTART: the main flow's waits retry on EINTR themselves.
        let installed = unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = handler as usize;
            libc::sigemptyset(&raw mut action.sa_mask);
            libc::sigaction(signum, &raw const action, std::ptr::null_mut())
        };
        debug_assert_eq!(
            installed, 0,
            "installing the termination handler for signal {signum}"
        );
    }
}

/// Block SIGTERM and SIGHUP for the rest of the shim's life: once the shim has
/// decided whether the exec was ended, a later request must not change that.
fn block_termination_signals() {
    // SAFETY: an all-zero `sigset_t` is valid storage for `sigemptyset` to
    // initialise; `sigprocmask` only changes this single-threaded process's
    // mask.
    let blocked = unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&raw mut set);
        libc::sigaddset(&raw mut set, libc::SIGTERM);
        libc::sigaddset(&raw mut set, libc::SIGHUP);
        libc::sigprocmask(libc::SIG_BLOCK, &raw const set, std::ptr::null_mut())
    };
    debug_assert_eq!(blocked, 0, "blocking SIGTERM and SIGHUP");
}

/// Whether the process group `pgid` has a member that is still running: any
/// member that is not a zombie (the shim's own unreaped leader is one). Read
/// from the `pgrp` and state fields of every `<pid>/stat` under `proc_dir`,
/// the shim's own procfs. `kill(-pgid, 0)` cannot answer this: the zombie
/// leader the shim holds is still a member, so it never reports `ESRCH`. A
/// scan that cannot be made answers `true`, which only costs the early exit:
/// the grace period then runs to its end.
fn group_has_live_member(proc_dir: &std::fs::File, pgid: libc::pid_t) -> bool {
    // A fresh open file description for every scan: a `dup` would share the
    // directory offset the previous scan left at the end.
    // SAFETY: `openat` on a directory fd this function borrows, with a static
    // NUL-terminated path; the result is checked before use.
    let fd = unsafe {
        libc::openat(
            proc_dir.as_raw_fd(),
            c".".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return true;
    }
    // SAFETY: `fd` is an open directory this function owns; on success
    // `fdopendir` takes it over and `closedir` below closes it.
    let dir = unsafe { libc::fdopendir(fd) };
    if dir.is_null() {
        // SAFETY: `fdopendir` failed, so `fd` is still ours to close.
        unsafe { libc::close(fd) };
        return true;
    }
    let mut live = false;
    loop {
        // SAFETY: `dir` is the open stream above, used by this thread only.
        let entry = unsafe { libc::readdir(dir) };
        if entry.is_null() {
            break;
        }
        // SAFETY: `readdir` returned a valid entry whose `d_name` is
        // NUL-terminated and live until the next `readdir` on `dir`.
        let name = unsafe { std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()) };
        let Some(pid) = name.to_str().ok().and_then(|n| n.parse::<u32>().ok()) else {
            continue;
        };
        if is_live_member(proc_dir, pid, pgid) {
            live = true;
            break;
        }
    }
    // SAFETY: `dir` came from `fdopendir` above and is closed exactly once.
    unsafe { libc::closedir(dir) };
    live
}

/// Whether `pid` (under `proc_dir`) is in group `pgid` and not a zombie. A
/// process that is gone, or whose `stat` cannot be read, is not.
fn is_live_member(proc_dir: &std::fs::File, pid: u32, pgid: libc::pid_t) -> bool {
    let Ok(path) = std::ffi::CString::new(format!("{pid}/stat")) else {
        return false;
    };
    // SAFETY: `openat` on a directory fd this function borrows and a
    // NUL-terminated path it owns; the result is checked before use.
    let fd = unsafe {
        libc::openat(
            proc_dir.as_raw_fd(),
            path.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return false;
    }
    // SAFETY: `fd` was just opened and nothing else owns it.
    let mut file = std::fs::File::from(unsafe { OwnedFd::from_raw_fd(fd) });
    let mut stat = String::new();
    if std::io::Read::read_to_string(&mut file, &mut stat).is_err() {
        return false;
    }
    stat_is_live_member(&stat, pgid)
}

/// Whether a `/proc/<pid>/stat` line names a process in group `pgid` that is
/// not a zombie. The fields after the parenthesised comm, which may itself
/// contain `)`, start: state ppid pgrp.
fn stat_is_live_member(stat: &str, pgid: libc::pid_t) -> bool {
    let Some((_, after_comm)) = stat.rsplit_once(')') else {
        return false;
    };
    let mut fields = after_comm.split_whitespace();
    let (Some(state), Some(_ppid), Some(pgrp)) = (fields.next(), fields.next(), fields.next())
    else {
        return false;
    };
    pgrp.parse::<libc::pid_t>() == Ok(pgid) && !matches!(state, "Z" | "X")
}

/// Maps a failed `spawn` to the shell's exit-code and message conventions:
/// `ENOENT` is "command not found" (127), `EACCES` is "permission denied"
/// (126), and `ENOEXEC` is "cannot execute" (126). Any other failure — a
/// fork's `ENOMEM`, or an `EPERM` from a `pre_exec` hook, included — is not the
/// program's to report, so it is `None` and stays a [`NsenterError::Spawn`].
/// `EACCES` is matched by errno rather than [`std::io::ErrorKind::PermissionDenied`],
/// which also covers `EPERM`.
///
/// The message is the plain text a shell would print, without the debug
/// wrapper `main` adds to [`NsenterError`] — a script must be able to tell
/// "not found" from the command's own failure.
fn spawn_failure_code_and_message(source: &std::io::Error) -> Option<(i32, String)> {
    match source.raw_os_error()? {
        libc::ENOENT => Some((127, "command not found".to_string())),
        libc::EACCES => Some((126, "permission denied".to_string())),
        libc::ENOEXEC => Some((126, format!("cannot execute: {source}"))),
        _ => None,
    }
}

/// Whether a failed `spawn` is the child's `chdir` failing on a missing
/// working directory rather than the program itself being missing. Only
/// `ENOENT` is ambiguous between the two — `EACCES` and `ENOEXEC` are the
/// program's own failure whichever syscall raised them, so they map
/// unconditionally and never route through this discriminator.
fn spawn_failed_on_missing_chdir(source: &std::io::Error, chdir: Option<&Path>) -> bool {
    source.raw_os_error() == Some(libc::ENOENT) && chdir.is_some_and(|dir| !dir.is_dir())
}

/// The socket-family filter an injected process installs after joining a
/// box.  A none box's relaxed seal admits inet and netlink route only because the
/// box's own network namespace confines them, so it applies only when the
/// join enters that namespace (`join` names `Net`); an injection that stays
/// in the daemon's namespace gets the unix-only seal instead, fail closed
/// ([`sandbox2::SocketSeal::in_netns`]).
fn injection_socket_filter(
    seal_none_box: bool,
    join: &[Namespace],
) -> &'static sandbox2::SocketFamilyFilter {
    if seal_none_box {
        let joins_box_netns = join.contains(&Namespace::Net);
        sandbox2::socket_family_filter_for_seal(
            sandbox2::SocketSeal::Full.in_netns(joins_box_netns),
        )
    } else {
        sandbox2::socket_family_filter_for_confined_families()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A failed spawn maps to the shell's exit-code and message conventions:
    /// `ENOENT` is "command not found" (127), `EACCES` is "permission denied"
    /// (126), and `ENOEXEC` is "cannot execute" (126). Anything else, such as
    /// the fork's `ENOMEM` or a `pre_exec` hook's `EPERM`, is left to
    /// [`NsenterError::Spawn`].
    #[test]
    fn spawn_failures_map_to_shell_exit_codes_and_messages() {
        let not_found = std::io::Error::from_raw_os_error(libc::ENOENT);
        let (code, msg) = spawn_failure_code_and_message(&not_found).unwrap();
        assert_eq!(code, 127);
        assert_eq!(msg, "command not found");

        let denied = std::io::Error::from_raw_os_error(libc::EACCES);
        let (code, msg) = spawn_failure_code_and_message(&denied).unwrap();
        assert_eq!(code, 126);
        assert_eq!(msg, "permission denied");

        let no_exec = std::io::Error::from_raw_os_error(libc::ENOEXEC);
        let (code, msg) = spawn_failure_code_and_message(&no_exec).unwrap();
        assert_eq!(code, 126);
        assert!(msg.starts_with("cannot execute: "), "got {msg:?}");

        let fork_failed = std::io::Error::from_raw_os_error(libc::ENOMEM);
        assert_eq!(spawn_failure_code_and_message(&fork_failed), None);

        let hook_refused = std::io::Error::from_raw_os_error(libc::EPERM);
        assert_eq!(spawn_failure_code_and_message(&hook_refused), None);
    }

    /// Only `ENOENT` is ambiguous between a missing program and a missing
    /// working directory. An `EACCES` from `chdir` (an inaccessible cwd) is
    /// the program's own failure and must not be swallowed by the
    /// missing-chdir discriminator, so it still maps to 126.
    #[test]
    fn missing_chdir_discriminator_only_swallows_enoent() {
        let missing = std::io::Error::from_raw_os_error(libc::ENOENT);
        let denied = std::io::Error::from_raw_os_error(libc::EACCES);
        let no_exec = std::io::Error::from_raw_os_error(libc::ENOEXEC);
        let chdir = Some(Path::new("/definitely/not/here"));

        assert!(spawn_failed_on_missing_chdir(&missing, chdir));
        assert!(!spawn_failed_on_missing_chdir(&missing, None));
        assert!(!spawn_failed_on_missing_chdir(&denied, chdir));
        assert!(!spawn_failed_on_missing_chdir(&no_exec, chdir));
    }

    /// The fail-closed gate on the injection path: a none-box injection
    /// gets the relaxed none seal only when it joins the box's network
    /// namespace, and the unix-only seal when the join set leaves `Net` out.
    #[test]
    fn none_injection_relaxes_only_when_joining_the_box_netns() {
        use sandbox2::SocketSeal;
        let with_net = [Namespace::User, Namespace::Mnt, Namespace::Net];
        let without_net = [Namespace::User, Namespace::Mnt];
        assert_eq!(
            injection_socket_filter(true, &with_net).seal,
            SocketSeal::Full
        );
        assert_eq!(
            injection_socket_filter(true, &without_net).seal,
            SocketSeal::UnixOnly,
            "a none-box injection outside the box's netns must keep the unix-only seal"
        );
        for join in [&with_net[..], &without_net[..]] {
            assert_eq!(
                injection_socket_filter(false, join).seal,
                SocketSeal::ConfinedFamilies
            );
        }
    }

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

    /// Every box unshares its own IPC namespace, so a process injected into a
    /// box has to be able to join it: the joinable set includes IPC, and
    /// [`namespaces_to_join`] picks it up wherever the box's differs from ours.
    #[test]
    fn the_ipc_namespace_is_one_an_injected_process_joins() {
        assert!(
            Namespace::ALL.contains(&Namespace::Ipc),
            "an injected process must join its box's IPC namespace"
        );
        assert_eq!(Namespace::Ipc.proc_name(), "ipc");
        assert_eq!(Namespace::Ipc.clone_flag(), CloneFlags::CLONE_NEWIPC);
    }

    #[test]
    fn resolves_the_grandchild_not_the_forking_process() {
        let (mut sh, expected) = shell_with_one_child();

        let resolved = session_leader_pid(sh.id());

        let _ = sh.kill();
        let _ = sh.wait();
        assert_eq!(resolved.expect("resolving the sole child"), expected);
    }

    /// The group kill reaches a descendant, not just the direct child: `sh`
    /// puts its background `sleep` in the group, and after [`kill_group`] on the
    /// group lead, `kill(grandchild, 0)` reports `ESRCH` — the descendant is
    /// gone, not reparented and left running.
    #[test]
    fn kill_group_reaches_the_grandchild() {
        use std::io::BufRead as _;
        use std::os::unix::process::CommandExt as _;
        use std::time::Instant;

        let mut sh = Command::new("/bin/sh");
        sh.arg("-c")
            .arg("sleep 600 & echo $!; wait")
            .stdout(std::process::Stdio::piped());
        // SAFETY: the closure only calls `setpgid(2)`, which is
        // async-signal-safe, in the forked pre-exec child.
        unsafe {
            sh.pre_exec(|| {
                if libc::setpgid(0, 0) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut sh = sh.spawn().expect("spawning /bin/sh");

        let mut out = String::new();
        std::io::BufReader::new(sh.stdout.as_mut().expect("piped stdout"))
            .read_line(&mut out)
            .expect("reading the grandchild pid");
        let grandchild: i32 = out.trim().parse().expect("sh printed a pid");

        // SAFETY: `sh.id()` is the group lead the pre_exec created; it is the
        // group this test spawned and owns.
        unsafe { kill_group(sh.id() as i32) };
        let _ = sh.wait();

        // The descendant must disappear quickly rather than linger under PID 1.
        let deadline = Instant::now() + std::time::Duration::from_secs(2);
        loop {
            // SAFETY: `kill(pid, 0)` only probes existence; `grandchild` names a
            // process this test forked.
            let exists = unsafe { libc::kill(grandchild, 0) } == 0;
            if !exists {
                assert_eq!(
                    std::io::Error::last_os_error().raw_os_error(),
                    Some(libc::ESRCH),
                    "the grandchild must be gone, not just invisible"
                );
                break;
            }
            // Killed but not yet reaped: a container's PID 1 need not reap
            // the orphans reparented to it, so a zombie counts as dead.
            if is_zombie(grandchild) {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "grandchild {grandchild} survived the group kill"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }

    /// Whether `pid` is a zombie, per the state field of `/proc/<pid>/stat`
    /// (the first field after the parenthesised comm).
    fn is_zombie(pid: i32) -> bool {
        std::fs::read_to_string(format!("/proc/{pid}/stat"))
            .ok()
            .and_then(|stat| {
                let (_, after_comm) = stat.rsplit_once(')')?;
                after_comm
                    .split_whitespace()
                    .next()
                    .map(|state| state == "Z")
            })
            .unwrap_or(false)
    }

    /// The handler's guard: `kill_group` never signals the shim's own group
    /// (`0`) or every process it may signal (`-1`, from a `pgid` of `1`), nor
    /// a negative id. Reaching any `kill` here would take the test runner down.
    #[test]
    fn kill_group_ignores_pgids_that_name_no_child_group() {
        for pgid in [i32::MIN, -1, 0, 1] {
            // SAFETY: every value is below the guard, so no signal is sent.
            unsafe { kill_group(pgid) };
        }
    }

    /// The grace period's group probe reads state and pgrp past the last `)`,
    /// so a comm holding `) ` cannot shift the fields, and a zombie member is
    /// not a live one.
    #[test]
    fn stat_is_live_member_reads_state_and_pgrp() {
        assert!(stat_is_live_member("42 (sh) S 1 42 42 0 -1", 42));
        assert!(stat_is_live_member("43 (a) b) R 42 42 42 0 -1", 42));
        assert!(!stat_is_live_member("42 (sh) Z 1 42 42 0 -1", 42));
        assert!(!stat_is_live_member("44 (sh) S 1 44 44 0 -1", 42));
        assert!(!stat_is_live_member("garbage", 42));
    }

    /// The probe the grace period polls: a running group has a live member,
    /// and a group whose only member is its unreaped zombie leader — the
    /// state the shim holds the group in — has none, so the shim stops
    /// waiting as soon as the last real member is gone.
    #[test]
    fn group_has_live_member_ignores_the_zombie_leader() {
        use std::os::unix::process::CommandExt as _;

        let proc_dir = std::fs::File::open("/proc").expect("opening /proc");
        let mut sleep = Command::new("sleep");
        sleep.arg("600");
        // SAFETY: the closure only calls `setpgid(2)`, which is
        // async-signal-safe, in the forked pre-exec child.
        unsafe {
            sleep.pre_exec(|| {
                if libc::setpgid(0, 0) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut sleep = sleep.spawn().expect("spawning sleep");
        let pgid = libc::pid_t::try_from(sleep.id()).expect("a pid fits a pid_t");
        assert!(
            group_has_live_member(&proc_dir, pgid),
            "the running leader is a live member"
        );

        // SAFETY: `pgid` is the group this test spawned and owns.
        unsafe { kill_group(pgid) };
        // SAFETY: `waitid` writes only into `info`, a zeroed `siginfo_t`.
        let observed = unsafe {
            let mut info: libc::siginfo_t = std::mem::zeroed();
            libc::waitid(
                libc::P_PID,
                sleep.id(),
                &raw mut info,
                libc::WEXITED | libc::WNOWAIT,
            )
        };
        assert_eq!(observed, 0, "waiting for the leader to die");
        assert!(
            !group_has_live_member(&proc_dir, pgid),
            "a zombie leader alone is not a live member"
        );
        let _ = sleep.wait();
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

    /// The leaf an injection joins travels on the shim's argv, so the one
    /// process that can write it — the shim, before it joins the namespaces
    /// — knows where to go. Opt-in: a host that places no box sends no flag,
    /// and the injection joins nothing but the namespaces.
    #[test]
    fn the_classifier_leaf_travels_on_the_shims_argv_when_one_is_set() {
        let leaf =
            sandbox2::config::ClassifierLeaf::new("/sys/fs/cgroup/minimald.slice/boxes/allow/b");
        let shim = tempfile::NamedTempFile::new().expect("a temp file to stand in for the shim");

        let mut sleep = Command::new("/bin/sleep")
            .arg("30")
            .spawn()
            .expect("spawning /bin/sleep");
        let target = sleep.id();
        let unplaced = Injection::new(target, "/bin/true", Vec::<&str>::new())
            .with_shim(shim.path())
            .command();
        let placed = Injection::new(target, "/bin/true", Vec::<&str>::new())
            .with_shim(shim.path())
            .with_classifier_leaf(leaf.clone())
            .command();

        let _ = sleep.kill();
        let _ = sleep.wait();

        let argv = |cmd: std::process::Command| -> Vec<OsString> {
            cmd.get_args().map(OsString::from).collect()
        };
        let bare = argv(unplaced.expect("building the command without a leaf"));
        assert!(
            !bare.contains(&OsString::from("--classifier-leaf")),
            "a host that places no box sends no flag: {bare:?}"
        );
        let joined = argv(placed.expect("building the command with a leaf"));
        let at = joined
            .iter()
            .position(|arg| arg == "--classifier-leaf")
            .expect("the leaf is named on the shim's argv");
        assert_eq!(
            joined[at + 1],
            OsString::from(leaf.dir().as_os_str()),
            "the flag carries the leaf's directory, whose cgroup.procs the \
             shim writes its pid to"
        );
    }
}
