//! A session-owned runtime environment.
//!
//! [`Env`] is the minimald-specific counterpart to [`mctx::Env`]. The crucial
//! difference is ownership: this `Env` *owns* the [`mctx::Context`] and
//! [`graph::Graph`] (they are moved into the in-sandbox command actor) instead
//! of borrowing them like `mctx::Env<'a>` does. That makes it `Send + 'static`,
//! so the long-lived session host can hold it directly — no self-referential
//! lifetimes, no leaking the context/graph to fabricate `'static` borrows.
//!
//! ## The in-sandbox `min` command channel
//!
//! Packages, tasks and checks can be driven from *inside* a running session via
//! the `min` helper, which talks to `/run/minenv_sock`. [`sandbox2`]'s listener
//! is synchronous — a blocking `accept()` loop on its own OS thread — which is
//! why the equivalent handler in `mctx` has to spin up a fresh tokio runtime per
//! command. Here we bridge that synchronous world to the daemon's async runtime
//! with an actor:
//!
//! - [`BridgeChannel`] is the trivial synchronous [`sandbox2::Channel`]. For each
//!   request it clones the connection and forwards it (with the request line)
//!   down an mpsc to the actor, then returns immediately.
//! - [`SessionChannel`] is the actor: it owns the context and graph and processes
//!   requests one at a time on the runtime, so every handler is a plain
//!   `async fn` that `.await`s — no nested runtimes, no sync/async bridge writers.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::Permissions;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::Poll;

use camino::{Utf8Path, Utf8PathBuf};
use graph::{BuildSpecRef, Graph, SetupForPackages, Transitives};
use mctx::{AddDepMode, Context, Error};
use mfile::{EnvPatches, EnvVarValue};
use op::Runnable;
use ot::OpTracker;
use paths::{DaemonAbsPath, DaemonRelPath, SandboxAbsPath};
use sandbox2::config::{Config, SandboxMapped};
use sandbox2::{Container, Sandbox};
use sessions::NetworkMode;
use tempfile::TempDir;
use tokio::sync::mpsc;
use tokio::task::{JoinHandle, spawn_blocking};

/// The min helper script installed at `/usr/bin/min` inside the sandbox.
const MIN_SCRIPT: &str = include_str!("env_min_helper.sh");

/// Where the session's workspace appears *inside* the sandbox. The daemon sees
/// the same directory at [`SessionChannel::working`], so this is the prefix
/// that translates a path typed in the sandbox into one the daemon can write.
pub(crate) const WORKSPACE_ROOT: &str = constcat::concat!("/", sandbox2::SESSION_DEFAULT_WD);

/// Where the session's home directory appears inside the sandbox, backed by
/// [`SessionChannel::home`]. The second of the two directories a sandbox path
/// can name on the daemon's side.
pub(crate) const HOME_ROOT: &str = constcat::concat!("/", sandbox2::SESSION_HOME);

/// The parameters used to construct an [`Env`].
///
/// Built with [`EnvArgs::new`] plus the `with_*` setters. `state_base_dir` is the
/// host directory backing the session's `/state`; the caller is responsible for
/// its lifetime (e.g. a persistent state dir or a `TempDir` handed to
/// [`Env::with_temp_dirs`]).
#[derive(Debug, Clone)]
pub struct EnvArgs {
    name: String,
    username: Option<String>,

    cwd: DaemonAbsPath,
    home: DaemonAbsPath,
    state_base_dir: DaemonAbsPath,

    packages: Vec<String>,
    patches: Option<EnvPatches>,
    env_vars: Option<HashMap<String, EnvVarValue>>,
    ot: Option<OpTracker>,
    network_mode: NetworkMode,
    own_ip_tap: Option<sandbox2::config::OwnIpTap>,
    own_ip_dns: Option<std::net::Ipv4Addr>,
    /// Weak handle to the owning session actor, wired into the command channel
    /// so in-sandbox `min` commands can drive session side-ops (e.g. builds).
    /// Every session env has one — this `Env` is always session-scoped.
    session: crate::session::WeakSessionHandle,
    /// When true (default), [`Env::build`] consumes package
    /// [`SetupForPackages`] output for `env_vars`/`fs_mappings`.
    /// When false, the caller supplies both via `env_vars` /
    /// `patches` and `state_dirs` is derived from resolved values
    /// shaped `/state/<prefix>`.
    ///
    /// [`SetupForPackages`]: graph::SetupForPackages
    include_package_attr_wiring: bool,
}

impl EnvArgs {
    /// Creates args for an environment named `name`, with working directory
    /// `cwd` and `/state` backed by `state_base_dir`. `session` is a weak
    /// handle to the owning session actor.
    pub fn new(
        name: impl Into<String>,
        cwd: impl Into<DaemonAbsPath>,
        home: impl Into<DaemonAbsPath>,
        state_base_dir: impl Into<DaemonAbsPath>,
        session: crate::session::WeakSessionHandle,
    ) -> Self {
        Self {
            name: name.into(),
            username: None,
            cwd: cwd.into(),
            home: home.into(),
            state_base_dir: state_base_dir.into(),
            packages: Vec::new(),
            patches: None,
            env_vars: None,
            ot: None,
            network_mode: NetworkMode::HostNet,
            own_ip_tap: None,
            own_ip_dns: None,
            session,
            include_package_attr_wiring: true,
        }
    }

    /// Opts out of consuming `env_vars` / `fs_mappings` from
    /// `SetupForPackages`. Callers on this path must funnel package
    /// contributions through `.with_resolved_env_vars` /
    /// `.with_patches` themselves.
    #[must_use]
    pub fn without_package_attr_wiring(mut self) -> Self {
        self.include_package_attr_wiring = false;
        self
    }

    /// Sets the packages (by name) that should be available in the environment.
    #[must_use]
    pub fn with_packages<I, S>(mut self, packages: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.packages = packages.into_iter().map(Into::into).collect();
        self
    }

    /// Adds caller-supplied filesystem patches (pinhole mounts) on top of the
    /// ones contributed by packages.
    #[must_use]
    pub fn with_patches(mut self, patches: EnvPatches) -> Self {
        self.patches = Some(patches);
        self
    }

    /// Sets environment variables to apply on top of the package-derived ones.
    #[must_use]
    pub fn with_env_vars(mut self, env_vars: HashMap<String, EnvVarValue>) -> Self {
        self.env_vars = Some(env_vars);
        self
    }

    /// Set environment variables from already-resolved values,
    /// wrapping each as [`EnvVarValue::Value`]. Ergonomic shortcut
    /// over `.with_env_vars` for callers with post-gate values.
    #[must_use]
    pub fn with_resolved_env_vars(mut self, env_vars: HashMap<String, String>) -> Self {
        self.env_vars = Some(
            env_vars
                .into_iter()
                .map(|(k, v)| (k, EnvVarValue::Value(v)))
                .collect(),
        );
        self
    }

    /// Sets the operation tracker propagated to downstream operations.
    #[must_use]
    pub fn with_op_tracker(mut self, ot: OpTracker) -> Self {
        self.ot = Some(ot);
        self
    }

    /// Sets the username.
    #[must_use]
    pub fn with_username(mut self, username: String) -> Self {
        self.username = Some(username);
        self
    }

    /// Sets the network isolation mode for the session sandbox.
    #[must_use]
    pub fn with_network_mode(mut self, mode: NetworkMode) -> Self {
        self.network_mode = mode;
        self
    }

    /// Sets the own-IP user-mode tap parameters (native/DM2 own-IP). When set,
    /// the sandbox's TAP is created + configured in-namespace by hakoniwa
    /// (rootless) and the caller relays its fd to the switch. `None` keeps the
    /// host/VM behaviour.
    #[must_use]
    pub fn with_own_ip_tap(mut self, tap: Option<sandbox2::config::OwnIpTap>) -> Self {
        self.own_ip_tap = tap;
        self
    }

    /// Sets the own-IP DNS server for the sandbox's `/etc/resolv.conf` (the
    /// switch gateway). Set for every own-IP sandbox, independent of the tap
    /// params, so both the DM2 and DM1/3/4 own-IP paths get a working resolver.
    #[must_use]
    pub fn with_own_ip_dns(mut self, dns: Option<std::net::Ipv4Addr>) -> Self {
        self.own_ip_dns = dns;
        self
    }
}

/// A fully-owned, session-scoped runtime environment.
///
/// Owns the sandbox and the command-channel actor (which in turn owns the
/// context and graph), so the whole environment can be moved and held for the
/// life of a session. Dropping it tears down the actor and the sandbox (and
/// thus the sandbox's backing files).
pub struct Env {
    sandbox: Sandbox<BridgeChannel>,
    /// The command-channel actor task. `Some` until [`Drop`] aborts it.
    actor: Option<JoinHandle<()>>,
    /// Variables the channel actor has added since launch; see
    /// [`SessionChannel::runtime_env`].
    runtime_env: RuntimeEnv,
    /// Extra directories kept alive for the environment's lifetime (e.g. a
    /// temporary `/state` directory). Dropped after the sandbox.
    _temp_dirs: Vec<TempDir>,
}

/// Environment variables a *running* session has acquired, on top of the ones
/// it was launched with. Usually happens due to `min add`.
///
/// Shared between [`Env`] and the [`SessionChannel`] actor that learns of them.
#[derive(Clone, Default)]
pub(crate) struct RuntimeEnv(Arc<Mutex<BTreeMap<String, String>>>);

impl RuntimeEnv {
    /// Records a variable the session has just acquired. Last write wins, as it
    /// does in the shell, where a later `export` overrides an earlier one.
    fn record(&self, key: &str, value: &str) {
        self.0
            .lock()
            .expect("runtime env lock is never held across a panic")
            .insert(key.to_string(), value.to_string());
    }

    /// Everything recorded so far.
    fn snapshot(&self) -> BTreeMap<String, String> {
        self.0
            .lock()
            .expect("runtime env lock is never held across a panic")
            .clone()
    }
}

/// Derive the composition-path state-dir set by picking up any
/// resolved env-var value shaped `/state/<single-component>`.
/// Multi-component and empty prefixes are dropped — they can't be
/// distinguished from coincidental `/state/`-prefixed values.
fn state_dirs_from_env_vars(
    env_vars: &HashMap<String, String>,
) -> std::collections::HashSet<String> {
    env_vars
        .values()
        .filter_map(|v| v.strip_prefix("/state/"))
        .filter(|p| !p.is_empty() && !p.contains('/'))
        .map(str::to_owned)
        .collect()
}

impl Env {
    /// Build a runtime environment. Resolves and locally builds the
    /// requested packages (plus `bash`/`socat` for the `min`
    /// helper), assembles the rootfs, and spawns the command
    /// channel actor.
    pub async fn build(mut ctx: Context, mut graph: Graph, args: EnvArgs) -> std::io::Result<Self> {
        // Resolve the requested package names to top-levels, then ensure the
        // helper's dependencies (`bash`, `socat`) are present.
        graph.top_levels = args
            .packages
            .iter()
            .map(|n| {
                graph
                    .by_name(n)
                    .copied()
                    .ok_or_else(|| std::io::Error::other(format!("no such package: {n}")))
            })
            .collect::<Result<_, _>>()?;
        for helper_dep in ["bash", "socat"] {
            if let Some(bsr) = graph.by_name(helper_dep).copied()
                && !graph.top_levels.contains(&bsr)
            {
                graph.top_levels.push(bsr);
            }
        }

        // Ensure all transitive runtime deps are built and present locally.
        let cache = ctx.local_cache();
        let transitives = Transitives::for_toplevels(&graph, graph.top_levels.clone(), false);
        let all_built = transitives
            .keys()
            .all(|bsr| cache.read_dir(&graph.spec_hash(bsr)).is_ok());
        if !all_built {
            tracing::trace!("missing local packages, building session env");
            ctx.build_graph(&graph, false, None)
                .await
                .map_err(err_to_io)?;
        }

        // Collect the package-derived wiring and merge caller-supplied
        // overrides. On the composition path the caller funnels
        // `env_state_wiring` and fs mappings through their own args,
        // so we skip `SetupForPackages`'s output for those fields.
        // `needs_dns` / `needs_internet` are ignored on either
        // branch — they aren't user-gate-able, so if we add a new
        // `SetupForPackages` field make sure to route it through
        // the same branch as `env_vars`/`fs_mappings`, not with these.
        let (legacy_state_dirs, mut pkg_env_vars) = if args.include_package_attr_wiring {
            let SetupForPackages {
                fs_mappings: _,
                needs_dns: _,
                needs_internet: _,
                dropped_credentials: _,
                state_dirs,
                env_vars,
            } = SetupForPackages::build(&graph, transitives.keys())
                .map_err(std::io::Error::other)?;
            (state_dirs, env_vars)
        } else {
            (std::collections::HashSet::<String>::new(), HashMap::new())
        };

        if let Some(vars) = &args.env_vars {
            for (k, v) in vars {
                let value = match v {
                    EnvVarValue::Value(v) => v.clone(),
                    EnvVarValue::Inherit => std::env::var(k).map_err(|e| {
                        std::io::Error::other(format!("inheriting environment variable '{k}': {e}"))
                    })?,
                };
                pkg_env_vars.insert(k.clone(), value);
            }
        }

        // Composition path: state_dirs come from the resolved
        // env-var values shaped `/state/<prefix>`. Matches what
        // `SetupForPackages` produces for `env_state_wiring` and
        // means a session that has been correctly gated (e.g. a
        // `deny` policy on some GOCACHE env var) also skips creating
        // its state dir — no orphaned `/state` slot for a var the
        // session doesn't actually have.
        let state_dirs: std::collections::HashSet<String> = if args.include_package_attr_wiring {
            legacy_state_dirs
        } else {
            state_dirs_from_env_vars(&pkg_env_vars)
        };

        let rootfs_dirs = transitives
            .keys()
            .map(|bsr| cache.read_dir(&graph.spec_hash(bsr)))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| std::io::Error::other(format!("loading dependency: {e}")))?;

        let config = Config::new(args.name.clone())
            .with_session_dirs(
                args.home.as_utf8_path().as_std_path().to_path_buf(),
                args.cwd.as_utf8_path().as_std_path().to_path_buf(),
            )
            //.with_wd(args.cwd.as_utf8_path(), false, patch.into())
            .with_rootfs(
                rootfs_dirs
                    .into_iter()
                    .map(|ce| SandboxMapped::Dir(ce.path().to_path_buf())),
            )
            .with_state_dir(args.state_base_dir.as_utf8_path())
            .with_env_vars(pkg_env_vars.into_iter())
            .with_network_mode(args.network_mode)
            // Own-IP tap params are `None` for host/VM modes and the
            // vsock-shuttle path. DNS is set on every own-IP sandbox.
            .with_own_ip_tap(args.own_ip_tap)
            .with_own_ip_dns(args.own_ip_dns)
            .with_hostname(args.name.clone())
            .with_daemon_id(ctx.daemon_id().unwrap()) // Always set under minimald
            .with_username(args.username.unwrap_or_else(|| "user".to_string()));

        // Wire up the channel actor and build the sandbox around the bridge.
        let (tx, rx) = mpsc::channel(8);
        let base_dir = ctx.tasks_base_dir();
        let mut sandbox = config
            .build(base_dir, BridgeChannel { tx })
            .await
            .map_err(sandbox_err_to_io)?;

        for want_dir in &state_dirs {
            std::fs::create_dir_all(args.state_base_dir.as_utf8_path().join(want_dir))
                .map_err(std::io::Error::other)?;
        }
        install_min_helpers(&sandbox.rootfs()).map_err(std::io::Error::other)?;
        sandbox.keep_dir(false);

        let runtime_env = RuntimeEnv::default();
        let channel = SessionChannel {
            rootfs: DaemonAbsPath::try_new(
                Utf8PathBuf::try_from(sandbox.rootfs().to_path_buf()).unwrap(),
            )
            .unwrap(),
            runtime_env: runtime_env.clone(),
            state_dir: args.state_base_dir.clone(),
            working: args.cwd.clone(),
            home: args.home.clone(),
            has_packages: transitives.keys().copied().collect(),
            ot: args.ot.clone(),
            session: args.session.clone(),
            ctx,
            graph,
            rx,
        };
        let actor = tokio::spawn(channel.run());

        Ok(Self {
            sandbox,
            actor: Some(actor),
            runtime_env,
            _temp_dirs: Vec::new(),
        })
    }

    /// Gives ownership of additional temporary directories to this environment,
    /// so they are cleaned up when the environment is dropped (e.g. a temporary
    /// `/state` directory).
    pub fn with_temp_dirs<I: IntoIterator<Item = TempDir>>(mut self, dirs: I) -> Self {
        self._temp_dirs.extend(dirs);
        self
    }

    /// Creates a fresh container in this environment's sandbox.
    pub fn container(&mut self) -> std::io::Result<Container> {
        self.sandbox.new_container().map_err(sandbox_err_to_io)
    }

    /// Builds a command to run `program` inside the given container.
    pub fn command<I, S>(
        &mut self,
        container: &Container,
        program: &str,
        args: I,
    ) -> std::io::Result<hakoniwa::Command>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.sandbox
            .command(container, program, args, [("", ""); 0])
            .map_err(sandbox_err_to_io)
    }

    /// The working directory and environment a command should run with in this
    /// session **as it stands now** — `/workbench`, the composed session
    /// variables, and anything `min add` has installed since launch.
    #[cfg_attr(test, allow(dead_code))]
    pub(crate) fn command_environment(&self) -> crate::session_host::SessionEnvironment {
        let mut vars = self.sandbox.command_env();
        vars.extend(self.runtime_env.snapshot());
        crate::session_host::SessionEnvironment {
            cwd: self.sandbox.command_cwd(),
            vars,
        }
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        // Abort the actor first: any in-flight handler is cancelled and the
        // owned context/graph dropped, so nothing keeps reading from the sandbox
        // files that the sandbox's own `Drop` (run when `sandbox` is dropped
        // after this) is about to remove.
        if let Some(actor) = self.actor.take() {
            actor.abort();
        }
    }
}

/// Converts an [`mctx::Error`] into an [`std::io::Error`], preserving its
/// (richly-formatted) `Display` message.
fn err_to_io(e: Error) -> std::io::Error {
    std::io::Error::other(e.to_string())
}

/// Converts a [`sandbox2::Error`] into an [`std::io::Error`].
fn sandbox_err_to_io(e: sandbox2::Error) -> std::io::Error {
    std::io::Error::other(e.to_string())
}

/// Installs the `min` helper script and the `etc` directory into a rootfs.
fn install_min_helpers(rootfs: &Path) -> std::io::Result<()> {
    let usr_bin = rootfs.join("usr").join("bin");
    std::fs::create_dir_all(&usr_bin)?;
    std::fs::write(usr_bin.join("min"), MIN_SCRIPT)?;
    std::fs::set_permissions(usr_bin.join("min"), Permissions::from_mode(0o0755))?;
    std::fs::create_dir_all(rootfs.join("etc"))?;
    Ok(())
}

/// A request forwarded from the synchronous listener to the async actor.
struct ChannelRequest {
    /// The single request line read by the listener (`method%data`).
    line: String,
    /// An owned clone of the client connection, written to by the handler.
    stream: UnixStream,
}

/// The synchronous [`sandbox2::Channel`] that bridges the listener thread to the
/// async [`SessionChannel`] actor. It does no work itself beyond handing each
/// request off; the connection clone stays open in the actor until the handler
/// finishes, at which point dropping it closes the connection and the client's
/// `socat` sees EOF.
struct BridgeChannel {
    tx: mpsc::Sender<ChannelRequest>,
}

impl sandbox2::Channel for BridgeChannel {
    fn handle(&mut self, stream: &mut UnixStream, line: &str, _rootfs: &Path) {
        let stream = match stream.try_clone() {
            Ok(s) => s,
            Err(e) => {
                let _ = writeln!(stream, "error: internal: cloning connection failed: {e}");
                return;
            }
        };
        // `blocking_send` is correct here: the listener runs on its own OS
        // thread, not a runtime worker. It only blocks if the actor is many
        // commands behind, which doesn't happen for interactive `min` use.
        if let Err(e) = self.tx.blocking_send(ChannelRequest {
            line: line.to_string(),
            stream,
        }) {
            let mut stream = e.0.stream;
            let _ = writeln!(stream, "error: session command handler unavailable");
        }
    }
}

/// The async command-channel actor.
///
/// Owns the session's [`Context`] and [`Graph`] and processes one request at a
/// time, so all of its handlers can be plain `async fn`s.
struct SessionChannel {
    ctx: Context,
    graph: Graph,
    /// The sandbox rootfs, into which freshly-installed packages are hardlinked.
    rootfs: DaemonAbsPath,
    /// The host directory backing `/state`.
    state_dir: DaemonAbsPath,
    /// The host directory backing `/workbench`.
    working: DaemonAbsPath,
    /// The host directory backing `/home`.
    home: DaemonAbsPath,

    /// Packages already materialized into the rootfs.
    has_packages: HashSet<BuildSpecRef>,
    ot: Option<OpTracker>,
    /// Weak handle to the owning session actor, used by session-scoped commands
    /// (e.g. `min build`) to drive side-ops.
    session: crate::session::WeakSessionHandle,
    /// Accumulates env vars of newly-installed packages, shared with the owning [`Env`].
    runtime_env: RuntimeEnv,
    rx: mpsc::Receiver<ChannelRequest>,
}

impl SessionChannel {
    /// Drives the actor until the bridge (and thus all senders) is dropped.
    async fn run(mut self) {
        while let Some(ChannelRequest { line, mut stream }) = self.rx.recv().await {
            tracing::trace!("session channel handling: {line}");
            self.handle(&line, &mut stream).await;
            // `stream` is dropped here, closing the connection so the client's
            // `socat` reads EOF and the `min` helper's read loop terminates.
        }
    }

    /// Dispatches a single `method%data` request line.
    async fn handle(&mut self, line: &str, stream: &mut UnixStream) {
        let add_dep = match line.split_once('%') {
            Some(("add-transient", pkgs)) => match self.parse_pkgs_line(pkgs) {
                Err(n) => {
                    let _ = writeln!(stream, "error: no such package '{n}'");
                    None
                }
                Ok(pkgs) => {
                    self.install(&pkgs, stream).await;
                    None
                }
            },
            Some(("add-build", pkgs)) => match self.parse_pkgs_line(pkgs) {
                Err(n) => {
                    let _ = writeln!(stream, "error: no such package '{n}'");
                    None
                }
                Ok(pkgs) => {
                    self.install(&pkgs, stream).await;
                    Some((AddDepMode::BuildPackages, pkgs))
                }
            },
            Some(("add-runtime", pkgs)) => match self.parse_pkgs_line(pkgs) {
                Err(n) => {
                    let _ = writeln!(stream, "error: no such package '{n}'");
                    None
                }
                Ok(pkgs) => {
                    self.install(&pkgs, stream).await;
                    Some((AddDepMode::RuntimePackages, pkgs))
                }
            },
            Some(("add-session", pkgs)) => match self.parse_pkgs_line(pkgs) {
                Err(n) => {
                    let _ = writeln!(stream, "error: no such package '{n}'");
                    None
                }
                Ok(pkgs) => {
                    self.install(&pkgs, stream).await;
                    Some((AddDepMode::SessionPackages, pkgs))
                }
            },
            Some(("search", term)) => {
                self.search(term, stream);
                None
            }
            Some(("check", args)) => {
                self.run_check(stream, args).await;
                None
            }
            Some(("patched-pkg", name)) => {
                self.run_patched_pkg(stream, name).await;
                None
            }
            Some(("run", args)) => {
                let (name, rest) = args.split_once(' ').unwrap_or((args, ""));
                self.run_task(stream, name, rest).await;
                None
            }
            Some(("build", args)) => {
                self.run_build(stream, args).await;
                None
            }
            // `<cwd>%<args>`: the helper's sandbox working directory, so a
            // relative `--output` resolves where the user typed it.
            Some(("materialize", request)) => {
                self.run_materialize(stream, request).await;
                None
            }
            _ => {
                let _ = writeln!(stream, "error: unhandled input '{line}'");
                None
            }
        };

        if let Some((mode, pkgs)) = add_dep {
            let bsrs: Vec<BuildSpecRef> = pkgs.into_iter().map(|(_n, bsr)| bsr).collect();
            if let Err(e) = self.ctx.add_deps(&self.graph, bsrs, mode) {
                let _ = writeln!(stream, "error: {e}");
            }
        }
    }

    /// Record and transmit a newly-acquired variable to the session shell.
    fn announce_env(&self, stream: &mut UnixStream, key: &str, value: &str) {
        self.runtime_env.record(key, value);
        let _ = writeln!(stream, "set_env:{key}:{value}");
    }

    /// Resolves a space-separated list of package names to `(name, ref)` pairs,
    /// returning the first unknown name as `Err`.
    fn parse_pkgs_line<'a>(&self, pkgs: &'a str) -> Result<Vec<(&'a str, BuildSpecRef)>, &'a str> {
        pkgs.split(' ')
            .map(|n| match self.graph.by_name(n) {
                None => Err(n),
                Some(bsr) => Ok((n, *bsr)),
            })
            .collect()
    }

    /// Installs packages into the running environment, building them if needed
    /// and hardlinking their files into the live rootfs.
    async fn install(&mut self, pkgs: &[(&str, BuildSpecRef)], stream: &mut UnixStream) {
        if pkgs
            .iter()
            .all(|(_n, bsr)| self.graph.top_levels.contains(bsr))
        {
            // Already installed. Say so rather than returning silently: this
            // path is indistinguishable from a successful injection on the
            // wire, so a stale `top_levels` would otherwise read as success.
            let _ = writeln!(
                stream,
                "msg:Already installed: {}",
                pkgs.iter().map(|t| t.0).collect::<Vec<_>>().join(", ")
            );
            return;
        }

        let mut new_graph = self.graph.clone();
        for (_n, bsr) in pkgs {
            if !new_graph.top_levels.contains(bsr) {
                new_graph.top_levels.push(*bsr);
            }
        }
        if let Err(e) = self.ctx.build_graph(&new_graph, false, None).await {
            let _ = writeln!(stream, "error: {e}");
            return;
        }

        let transitives = Transitives::for_toplevels(
            &new_graph,
            pkgs.iter().map(|(_n, bsr)| *bsr).collect(),
            false,
        );
        match SetupForPackages::build(
            &new_graph,
            transitives
                .keys()
                .filter(|bsr| !self.has_packages.contains(bsr)),
        ) {
            Ok(setup) => {
                for want_dir in setup.state_dirs {
                    if let Err(e) =
                        std::fs::create_dir_all(self.state_dir.as_utf8_path().join(want_dir))
                    {
                        let _ = writeln!(stream, "error: {e}");
                        return;
                    }
                }
                for (k, v) in &setup.env_vars {
                    self.announce_env(stream, k, v);
                }
            }
            Err(e) => {
                let _ = writeln!(stream, "error: {e}");
                return;
            }
        }

        let cache = self.ctx.local_cache();

        // Resolve the newly-needed packages to their cache directories,
        // then hardlink them in within a blocking thread.
        let mut pkg_dirs = Vec::new();
        for bsr in transitives.keys() {
            if self.has_packages.insert(*bsr) {
                match cache.read_dir(&new_graph.spec_hash(bsr)) {
                    Ok(entry) => pkg_dirs.push(entry.path().to_path_buf()),
                    Err(e) => {
                        let _ = writeln!(stream, "error: {e}");
                        return;
                    }
                }
            }
        }
        let rootfs = self.rootfs.as_utf8_path().as_std_path().to_path_buf();
        let hardlink = spawn_blocking(move || {
            pkg_dirs
                .iter()
                .try_for_each(|src| common::hardlink_dir_contents(src, &rootfs))
        })
        .await;
        match hardlink {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                let _ = writeln!(stream, "error: hardlinking: {e}");
                return;
            }
            Err(e) => {
                let _ = writeln!(stream, "error: spawn: {e}");
                return;
            }
        }

        let _ = writeln!(
            stream,
            "msg:Installed {}",
            pkgs.iter().map(|t| t.0).collect::<Vec<_>>().join(", ")
        );
        self.graph = new_graph;
    }

    /// Implements `min search <term>`.
    fn search(&self, term: &str, stream: &mut UnixStream) {
        for (bsr, m) in self.graph.fuzzy_name_search(term, 8).iter() {
            let b = self.graph.get(bsr).unwrap();
            let name = &b.name;
            if name.ends_with(" (prebuilt)") {
                continue;
            }

            let _ = write!(stream, "msg: * {name}");
            if let Some(v) = b.upstream_version() {
                let _ = write!(stream, " (version {v})");
            }
            if !m.outputs.is_empty() {
                let _ = write!(
                    stream,
                    " [provides {}]",
                    m.outputs.keys().cloned().collect::<Vec<_>>().join(",")
                );
            }
            let _ = writeln!(stream);
        }
    }

    /// Implements `min check [--packages] [--stacks] [--profiles] [--fix] [names...]`:
    /// kicks off a session side-op check run and streams each object's results
    /// back to the client until the run completes.
    async fn run_check(&mut self, stream: &mut UnixStream, args: &str) {
        use crate::session_sop::{CheckOpts, CheckOutcome, CheckUpdate};

        let Some(session) = self.session.upgrade() else {
            let _ = writeln!(stream, "error: session is gone");
            return;
        };

        let opts = match CheckOpts::from_args(args) {
            Ok(opts) => opts,
            Err(msg) => {
                let _ = writeln!(stream, "error: {msg}");
                return;
            }
        };

        let mut updates = match session.start_check(opts).await {
            Ok(rx) => rx,
            Err(e) => {
                let _ = writeln!(stream, "error: {e}");
                return;
            }
        };

        let mut outcome = None;
        while let Some(update) = updates.recv().await {
            if let CheckUpdate::Finished(o) = &update {
                outcome = Some(o.clone());
            }
            for line in update.render() {
                let _ = writeln!(stream, "msg:{line}");
            }
        }

        // Report the propagated outcome; only a clean run claims success.
        let (status, message) = CheckOutcome::summarize(outcome.as_ref());
        if status == 0 {
            let _ = writeln!(stream, "msg:{message}");
        } else {
            let _ = writeln!(stream, "error: {message}");
        }
    }

    /// Implements `min patched-pkg <pkgname>`.
    async fn run_patched_pkg(&mut self, stream: &mut UnixStream, pkg_name: &str) {
        let (ctx, graph, new_has_packages) = if let Ok(v) = self.refresh(stream).await {
            v
        } else {
            return;
        };

        let bsr = match graph.by_name(pkg_name) {
            None => {
                Self::write_error(
                    &Error::Graph(Box::new(graph::Error::NoSuchPkg {
                        name: pkg_name.to_string(),
                    })),
                    stream,
                );
                return;
            }
            Some(bsr) => *bsr,
        };

        // Scope the build to the requested package on a throwaway clone. The
        // session graph's own `top_levels` is its record of what is installed;
        // narrowing that to `[bsr]` would make the next `min add <pkg>` take
        // `install`'s already-installed path and silently inject nothing.
        let mut build_graph = graph.clone();
        build_graph.top_levels = vec![bsr];

        let result: std::io::Result<()> = async {
            let remote_storage = ctx.remote_storage().await.map_err(err_to_io)?;
            let output_base = ctx.builds_base_dir();
            let _ = std::fs::create_dir_all(&output_base);

            let cache = ctx.local_cache();
            let (stdout_writer, stderr_writer) = StreamWriter::pair(stream)?;
            let res = op::PatchedBuild {
                spec: &bsr,
                remote_fetcher: &remote_storage,
                stdout_writer: Some(Box::new(stdout_writer)),
                stderr_writer: Some(Box::new(stderr_writer)),
            }
            .run(&op::Options {
                cache,
                graph: &build_graph,
                exec_base: output_base,
                ot: self.ot.clone(),
                daemon_id: ctx.daemon_id(),
            })
            .await
            .map_err(std::io::Error::other)?;

            res.outputs
                .finalize(res.meta)
                .map_err(std::io::Error::other)?;
            Ok(())
        }
        .await;

        if let Err(e) = result {
            let _ = writeln!(stream, "error: {e}");
            return;
        }
        let _ = writeln!(
            stream,
            "msg:Written to cache with hash {}",
            graph.spec_hash(&bsr).0
        );

        self.ctx = ctx;
        self.graph = graph;
        self.has_packages = new_has_packages;
    }

    /// Implements `min run <task>`.
    async fn run_task(&mut self, stream: &mut UnixStream, task_name: &str, args: &str) {
        let (mut ctx, graph, _) = if let Ok(v) = self.refresh(stream).await {
            v
        } else {
            return;
        };

        let (task, mut graph) = match ctx.task(graph, task_name) {
            Err(e) => return Self::write_error(&e, stream),
            Ok(None) => {
                let _ = writeln!(stream, "error: no such task '{task_name}'");
                return;
            }
            Ok(Some(v)) => v,
        };

        let parsed_args = if !task.args.is_empty() {
            match task.args.parse(args) {
                Err(e) => {
                    for line in format!("{}", e.render().ansi()).lines() {
                        let _ = writeln!(stream, "msg:{line}");
                    }
                    let _ = writeln!(stream, "error: failed parsing arguments for task");
                    return;
                }
                Ok(args) => Some(args),
            }
        } else {
            None
        };

        let result: Result<(), Error> = async {
            let mut env = ctx
                .make_env(
                    task_name,
                    &mut graph,
                    task.inherit_cwd
                        .then(|| self.working.as_utf8_path().as_std_path().to_path_buf()),
                    task.state_key.as_ref(),
                    Some(&task.patch),
                    Some(&task.vars),
                    task.packages.clone(),
                )
                .await?;

            let (interactive, invocations) =
                env.task_invocations(&task, parsed_args.as_ref()).await?;
            if interactive {
                let _ = writeln!(
                    stream,
                    "error: cannot run interactive tasks from within an environment"
                );
                return Ok(());
            }

            let (stdout_writer, stderr_writer) = StreamWriter::pair(stream)
                .map_err(|e| Error::IO("creating writers", Default::default(), e))?;
            env.run(invocations, Some(stdout_writer), Some(stderr_writer))
                .await
        }
        .await;

        if let Err(e) = result {
            Self::write_error(&e, stream);
        }
    }

    /// Implements `min build [--verbose] [--rebuild] pkgs...`: kicks off
    /// a session side-op build and streams its progress back to the client
    /// until the build completes.
    async fn run_build(&mut self, stream: &mut UnixStream, args: &str) {
        let mut flag_verbose = false;
        let mut flag_rebuild = false;
        let mut pkgs: Vec<String> = Vec::new();

        for token in args.split_whitespace() {
            match token {
                "--verbose" => flag_verbose = true,
                "--rebuild" => flag_rebuild = true,
                _ => pkgs.push(token.to_string()),
            }
        }

        let Some(session) = self.session.upgrade() else {
            let _ = writeln!(stream, "error: session is gone");
            return;
        };

        let mut events = match session.start_build(flag_rebuild, pkgs).await {
            Ok(rx) => rx,
            Err(e) => {
                let _ = writeln!(stream, "error: {e}");
                return;
            }
        };

        use crate::session_sop::{BuildOutcome, BuildUpdate};
        let mut renderer = orchestrator::BuildRenderer::new(flag_verbose);
        let mut outcome = None;
        while let Some(update) = events.recv().await {
            match update {
                BuildUpdate::Event(event) => {
                    if let Some(line) = renderer.render(event) {
                        let _ = writeln!(stream, "msg:{}", line.text);
                    }
                }
                BuildUpdate::Finished(o) => outcome = Some(o),
            }
        }

        // Report the propagated outcome; only success claims completion.
        match outcome {
            Some(BuildOutcome::Success) => {
                let _ = writeln!(stream, "msg:build finished");
            }
            Some(BuildOutcome::Failed(e)) => {
                let _ = writeln!(stream, "error: build failed: {e}");
            }
            Some(BuildOutcome::Cancelled) => {
                let _ = writeln!(stream, "error: build cancelled");
            }
            // The channel closed without a terminal update — the side-op died
            // before reporting (e.g. the actor was torn down mid-build).
            None => {
                let _ = writeln!(stream, "error: build ended without reporting an outcome");
            }
        }
    }

    /// Implements `min materialize --output <path> [--arch <arch>] <name>`.
    ///
    /// The side-op streams the artifact's bytes rather than writing a file, so
    /// landing it is this transport's job. `request` carries the helper's
    /// sandbox working directory ahead of the arguments, so `--output` resolves
    /// where the user typed it and stays inside the workspace — the one
    /// directory the daemon and the sandbox share.
    async fn run_materialize(&mut self, stream: &mut UnixStream, request: &str) {
        use crate::session_sop::{MaterializeOutcome, MaterializeUpdate};
        use tokio::io::AsyncWriteExt as _;

        let prepared: Result<_, String> = async {
            let MaterializeArgs { opts, output } = MaterializeArgs::from_request(request)?;
            let session = self.session.upgrade().ok_or("session is gone")?;
            let file = create_artifact(&self.working, &self.home, &output)
                .await
                .map_err(|e| format!("creating {output}: {e}"))?;
            let updates = session
                .start_materialize(opts)
                .await
                .map_err(|e| e.to_string())?;
            Ok((output, file, updates))
        }
        .await;
        let (output, mut file, mut updates) = match prepared {
            Ok(prepared) => prepared,
            Err(msg) => {
                let _ = writeln!(stream, "error: {msg}");
                return;
            }
        };

        let mut outcome = None;
        let mut write_err = None;
        while let Some(update) = updates.recv().await {
            match &update {
                MaterializeUpdate::Chunk(bytes) => {
                    if let Err(e) = file.write_all(bytes).await {
                        // Returning drops the receiver, which poisons the
                        // assembly's writer — no point building the rest of an
                        // artifact that has nowhere to land.
                        write_err = Some(e.to_string());
                        break;
                    }
                }
                MaterializeUpdate::Finished(o) => outcome = Some(o.clone()),
                MaterializeUpdate::Event(_) => {}
            }
            for line in update.render() {
                let _ = writeln!(stream, "msg:{line}");
            }
        }

        if let Some(msg) = write_err {
            let _ = writeln!(stream, "error: writing {output}: {msg}");
            return;
        }
        let (status, message) = MaterializeOutcome::summarize(outcome.as_ref());
        if status != 0 {
            let _ = writeln!(stream, "error: {message}");
            return;
        }

        // A `tokio::fs::File` completes its writes in the background; dropping
        // one unflushed truncates the artifact silently.
        if let Err(e) = file.flush().await {
            let _ = writeln!(stream, "error: writing {output}: {e}");
            return;
        }
        // The byte stream carries no mode, so a raw-file output needs the
        // source's back or an extracted binary arrives without its executable
        // bit. On the fd, so it cannot land on a path swapped underneath us.
        if let Some(MaterializeOutcome::Completed {
            mode: Some(mode), ..
        }) = outcome
            && let Err(e) = file
                .set_permissions(Permissions::from_mode(mode & 0o777))
                .await
        {
            let _ = writeln!(stream, "error: setting mode on {output}: {e}");
            return;
        }

        let _ = writeln!(stream, "msg:{message} to {output}");
    }

    /// Writes an [`mctx::Error`] to the client as `msg:` lines (preserving its
    /// multi-line, richly-formatted report) followed by an `error:` terminator.
    fn write_error(e: &Error, stream: &mut UnixStream) {
        for line in e.to_string().split('\n') {
            let _ = writeln!(stream, "msg:{line}");
        }
        let _ = writeln!(stream, "error: sandbox command failed.");
    }

    /// Refreshes and returns internals by re-reading the minimal.toml.
    ///
    /// The returned graph carries the session's own top-levels, not the ones a
    /// fresh parse hands out: [`Self::install`] reads `top_levels` as the set
    /// of packages already injected into the live rootfs, so a refresh that
    /// reset it would either re-inject everything or (worse) claim packages are
    /// present that never were.
    async fn refresh(
        &mut self,
        stream: &mut UnixStream,
    ) -> Result<(Context, Graph, HashSet<BuildSpecRef>), ()> {
        let error = |e: &Error, stream: &mut UnixStream| {
            Self::write_error(e, stream);
            Err(())
        };

        let mut ctx = match self.ctx.cloned_reinit() {
            Err(e) => return error(&e, stream),
            Ok(ctx) => ctx,
        };
        let mut graph = match ctx.graph_from_all_packages() {
            Err(e) => return error(&e, stream),
            Ok(g) => g,
        };

        // Recompute BuildSpecRefs for the new graph.
        let no_such = |name: String| Error::Graph(Box::new(graph::Error::NoSuchPkg { name }));
        let new_top_levels: Vec<BuildSpecRef> =
            match Self::remap_refs(&self.graph, &graph, &self.graph.top_levels) {
                Err(name) => return error(&no_such(name), stream),
                Ok(v) => v,
            };
        let new_has_packages: HashSet<BuildSpecRef> =
            match Self::remap_refs(&self.graph, &graph, &self.has_packages) {
                Err(name) => return error(&no_such(name), stream),
                Ok(v) => v,
            };
        graph.top_levels = new_top_levels;

        Ok((ctx, graph, new_has_packages))
    }

    /// Re-resolves refs taken against `from` into refs against `to`. Refs are
    /// graph-local, so the only identity that survives a re-parse is the
    /// package name; a name `to` no longer declares comes back as `Err`.
    fn remap_refs<'a, C: FromIterator<BuildSpecRef>>(
        from: &Graph,
        to: &Graph,
        bsrs: impl IntoIterator<Item = &'a BuildSpecRef>,
    ) -> Result<C, String> {
        bsrs.into_iter()
            .map(|bsr| {
                let name = &from.get(bsr).expect("bsrs always exist").name;
                to.by_name(name).copied().ok_or_else(|| name.clone())
            })
            .collect()
    }
}

/// A parsed `min materialize` invocation: what to materialize, plus where in
/// the session to put it.
#[derive(Debug, PartialEq)]
struct MaterializeArgs {
    opts: crate::session_sop::MaterializeOpts,
    /// Where the artifact lands, as an absolute path in the *sandbox* —
    /// resolved against the sandbox cwd, and not yet tied to a daemon
    /// directory. [`sandbox_to_daemon`] decides which one it names.
    output: SandboxAbsPath,
}

impl MaterializeArgs {
    /// Parses a `materialize%<cwd>%<args>` request line. The cwd is its own
    /// field rather than a flag so no user argument can be mistaken for it.
    fn from_request(request: &str) -> Result<Self, String> {
        let Some((cwd, args)) = request.split_once('%') else {
            return Err("malformed materialize request: no working directory".to_string());
        };
        Self::from_args(Utf8Path::new(cwd), args)
    }

    /// Mirrors the clap interface of `mip materialize`: a required
    /// `-o`/`--output <PATH>`, an optional `--arch <ARCH>`, and exactly one
    /// bare `<OUTPUT_NAME>`, with both `--flag value` and `--flag=value`
    /// accepted. `--output` departs from `mip`'s: it resolves against `cwd`
    /// and must land in the workspace (see [`resolve_output`]).
    fn from_args(cwd: &Utf8Path, args: &str) -> Result<Self, String> {
        let mut output: Option<String> = None;
        let mut arch: Option<String> = None;
        let mut names: Vec<String> = Vec::new();

        let mut tokens = args.split_whitespace();
        while let Some(token) = tokens.next() {
            let (flag, inline) = match token.split_once('=') {
                Some((flag, value)) => (flag, Some(value)),
                None => (token, None),
            };
            // Takes the flag's value from `=` when it was attached, otherwise
            // from the next token.
            let mut value = |flag: &str| match inline {
                Some(v) => Ok(v.to_string()),
                None => tokens
                    .next()
                    .map(str::to_string)
                    .ok_or_else(|| format!("`{flag}` requires a value")),
            };

            match flag {
                "-o" | "--output" => output = Some(value(flag)?),
                "--arch" => arch = Some(value(flag)?),
                // Any leading dash, as `min check` does. A typo falling
                // through to the positional would read as a second output
                // name, and the error has to name the typo, not the count.
                flag if flag.starts_with('-') => {
                    return Err(format!(
                        "unknown flag `{flag}` (expected --output or --arch)"
                    ));
                }
                _ => names.push(token.to_string()),
            }
        }

        let output = output.ok_or("`min materialize` requires --output <PATH>")?;
        let output = resolve_output(cwd, Utf8Path::new(output.as_str()))?;

        let output_name = match names.len() {
            1 => names.remove(0),
            0 => return Err("`min materialize` requires the name of an output".to_string()),
            _ => {
                return Err(format!(
                    "expected one output name, got {}",
                    names.join(", ")
                ));
            }
        };

        Ok(Self {
            opts: crate::session_sop::MaterializeOpts { output_name, arch },
            output,
        })
    }
}

/// Resolves a `--output` path typed inside the sandbox — absolute, or relative
/// to `cwd`, the directory the user typed it in — to an absolute path in the
/// sandbox's mount namespace.
///
/// Which daemon directory it lands in is [`sandbox_to_daemon`]'s decision, so
/// nothing is stripped here.
fn resolve_output(cwd: &Utf8Path, output: &Utf8Path) -> Result<SandboxAbsPath, String> {
    let absolute = if output.is_absolute() {
        output.to_path_buf()
    } else {
        if output.as_str().is_empty() {
            return Err("`--output` is empty".to_string());
        }
        if !cwd.is_absolute() {
            return Err(format!(
                "cannot resolve `--output {output}`: \
                 the working directory `{cwd}` is not an absolute path"
            ));
        }
        cwd.join(output)
    };
    // Normalize here so `sandbox_to_daemon`'s prefix match is sound:
    // `/workbench/../etc/passwd` must not pass on its first component.
    // Lexical, not `canonicalize` — this is a sandbox path, and the artifact
    // does not exist yet. `create_under` makes the on-disk check.
    SandboxAbsPath::try_new(normalize_absolute(&absolute))
        .map_err(|e| format!("`--output` is not a usable path: {e}"))
}

/// Resolves `.` and `..` textually. A `..` at the root stays there, so an
/// escape can only show up as a path failing the workspace prefix check.
pub(crate) fn normalize_absolute(path: &Utf8Path) -> Utf8PathBuf {
    let mut out = Utf8PathBuf::new();
    for component in path.components() {
        match component {
            camino::Utf8Component::CurDir => {}
            camino::Utf8Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_str()),
        }
    }
    out
}

/// Creates the file an artifact named by `path` should be written to.
///
/// Picks the session directory `path` falls under — [`WORKSPACE_ROOT`] maps to
/// `working`, [`HOME_ROOT`] to `home` — and creates the directories leading to
/// the destination. These two are the only directories a sandbox path and the
/// daemon share, so anything else is refused rather than redirected:
/// `/tmp/x.tar` names a file in the *sandbox*, which the daemon cannot write.
///
/// This is the one realm crossing a destination makes, and it is where the
/// result is checked to really be inside the directory it named.
/// [`resolve_output`] rules out escapes spelled with `..`, but it reasons about
/// the sandbox's namespace and cannot see symlinks: the parent is canonicalized
/// and checked, and the file opened `O_NOFOLLOW` so a link at the destination
/// itself is refused at open time. The daemon is not confined to the sandbox,
/// so either would otherwise have it writing wherever the link leads.
///
/// The bytes are written straight into the returned file: it is the artifact,
/// not a staging copy, so a run that fails partway leaves a partial file.
async fn create_artifact(
    working: &DaemonAbsPath,
    home: &DaemonAbsPath,
    path: &SandboxAbsPath,
) -> std::io::Result<tokio::fs::File> {
    let invalid = |msg: String| std::io::Error::new(std::io::ErrorKind::InvalidInput, msg);

    let (base, rel) = [(WORKSPACE_ROOT, working), (HOME_ROOT, home)]
        .into_iter()
        .find_map(|(root, base)| Some((base, path.as_utf8_path().strip_prefix(root).ok()?)))
        .ok_or_else(|| {
            invalid(format!(
                "`{path}` is outside the session's {WORKSPACE_ROOT} and {HOME_ROOT}"
            ))
        })?;
    // Stripping a root off itself leaves nothing to name a file with.
    if rel.as_str().is_empty() {
        return Err(invalid(format!(
            "`{path}` is a session directory, not a file"
        )));
    }
    // The typed join keeps the destination anchored: `DaemonAbsPath::join`
    // takes a `DaemonRelPath`, where joining a raw string could replace the
    // root outright. `try_new` re-checks that the remainder is relative and
    // `..`-free — `resolve_output` normalized it, and this is the proof.
    let rel = DaemonRelPath::try_new(rel)
        .map_err(|e| invalid(format!("`{path}` cannot be resolved on the daemon: {e}")))?;
    let dest = base.join(&rel);

    let (parent, file_name) = match (
        dest.as_utf8_path().parent(),
        dest.as_utf8_path().file_name(),
    ) {
        (Some(parent), Some(file_name)) => (parent, file_name),
        _ => return Err(invalid(format!("`{path}` does not name a file"))),
    };
    // `base` is canonicalized too: it may itself be reached through a symlink
    // (`/var` -> `/private/var`), which would fail a textual comparison.
    let real_base = canonicalize_utf8(base.as_utf8_path())?;
    let contained = |dir: &Utf8Path| -> std::io::Result<Utf8PathBuf> {
        let real = canonicalize_utf8(dir)?;
        if !real.starts_with(&real_base) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("`{path}` resolves to `{real}`, outside `{base}`"),
            ));
        }
        Ok(real)
    };

    // Check the deepest directory that already exists *before* creating
    // anything: `create_dir_all` through a symlinked parent would otherwise
    // materialize directories outside the session before the check refused.
    let existing = parent
        .ancestors()
        .find(|dir| dir.exists())
        .ok_or_else(|| invalid(format!("`{path}` has no existing parent directory")))?;
    contained(existing)?;

    tokio::fs::create_dir_all(parent).await?;
    // Re-checked after creating: `create_dir_all` only makes real directories,
    // but the check above and this are not one atomic step.
    let real_parent = contained(parent)?;

    tokio::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(real_parent.join(file_name))
        .await
}

/// [`std::fs::canonicalize`] keeping the path UTF-8.
fn canonicalize_utf8(path: &Utf8Path) -> std::io::Result<Utf8PathBuf> {
    let canonical = std::fs::canonicalize(path.as_std_path())?;
    Utf8PathBuf::from_path_buf(canonical)
        .map_err(|p| std::io::Error::other(format!("path is not utf-8: {}", p.display())))
}

/// An [`tokio::io::AsyncWrite`] that frames whatever is written to it into
/// newline-delimited `msg:` lines on a shared [`UnixStream`].
///
/// Used to stream a sandboxed build's stdout/stderr back to the `min` client.
/// Two writers can share one connection (via `Arc<Mutex<_>>`) so stdout and
/// stderr don't interleave mid-line.
struct StreamWriter {
    stream: Arc<Mutex<UnixStream>>,
    buf: Vec<u8>,
}

impl StreamWriter {
    fn pair(stream: &UnixStream) -> Result<(Self, Self), std::io::Error> {
        let shared = Arc::new(Mutex::new(stream.try_clone()?));
        Ok((
            Self {
                stream: shared.clone(),
                buf: Vec::new(),
            },
            Self {
                stream: shared,
                buf: Vec::new(),
            },
        ))
    }

    fn emit_lines(&mut self) {
        while let Some(pos) = self.buf.iter().position(|&b| b == b'\n') {
            let line = String::from_utf8_lossy(&self.buf[..pos]);
            let _ = writeln!(self.stream.lock().unwrap(), "msg:{line}");
            self.buf.drain(..=pos);
        }
    }
}

impl tokio::io::AsyncWrite for StreamWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        self.buf.extend_from_slice(buf);
        self.emit_lines();
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use camino::Utf8PathBuf;
    use mctx::ConfigBuilder;
    use std::io::{BufRead, BufReader};
    use tempfile::tempdir;

    /// Builds a `Context` and `Graph` from mctx's fakerepo fixture, plus a
    /// `SessionChannel` wired to them with a dummy receiver so handlers can be
    /// driven directly.
    fn setup_channel() -> (TempDir, TempDir, TempDir, SessionChannel) {
        let cwd = tempdir().unwrap();
        let state = tempdir().unwrap();
        let home = tempdir().unwrap();
        let rootfs = tempdir().unwrap();
        let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
        let config = ConfigBuilder::new()
            .with_state_dir(state.path().to_path_buf())
            .with_repo_dir(manifest_dir.join("../mctx/testdata/fakerepo"))
            .with_stdlib_dir(manifest_dir.join("../stdlib/minimal-ncl"))
            .with_no_fetch(true)
            .build()
            .unwrap();

        let mut ctx = Context::new(config).unwrap();
        let mut graph = ctx.graph_from_all_packages().unwrap();
        graph.top_levels = vec![];

        let (_tx, rx) = mpsc::channel(1);
        let channel = SessionChannel {
            rootfs: DaemonAbsPath::try_new(
                Utf8PathBuf::try_from(rootfs.path().to_path_buf()).unwrap(),
            )
            .unwrap(),
            state_dir: DaemonAbsPath::try_new(
                Utf8PathBuf::try_from(state.path().to_path_buf()).unwrap(),
            )
            .unwrap(),
            working: DaemonAbsPath::try_new(
                Utf8PathBuf::try_from(cwd.path().to_path_buf()).unwrap(),
            )
            .unwrap(),
            home: DaemonAbsPath::try_new(Utf8PathBuf::try_from(home.path().to_path_buf()).unwrap())
                .unwrap(),
            has_packages: HashSet::new(),
            ot: None,
            session: crate::session::WeakSessionHandle::dangling(),
            runtime_env: RuntimeEnv::default(),
            ctx,
            graph,
            rx,
        };
        (state, rootfs, cwd, channel)
    }

    /// Reads all currently-available lines from a `UnixStream`.
    fn read_lines(stream: &UnixStream) -> Vec<String> {
        stream.set_nonblocking(true).unwrap();
        BufReader::new(stream)
            .lines()
            .map_while(Result::ok)
            .collect()
    }

    #[tokio::test]
    async fn errs_on_unknown_command() {
        let (_state, _rootfs, _cwd, mut chan) = setup_channel();
        let (mut ours, theirs) = UnixStream::pair().unwrap();

        chan.handle("garbage-input", &mut ours).await;
        drop(ours);

        let lines = read_lines(&theirs);
        assert_eq!(lines.len(), 1);
        assert!(
            lines[0].contains("error: unhandled input 'garbage-input'"),
            "unexpected output: {lines:?}"
        );
    }

    /// A variable a running session acquires has to reach two places: the shell,
    /// which exports it, and the daemon, which hands it to anything injected
    /// into the session later. `min add` is the source in production; this
    /// drives the announcement directly, since installing a package would mean
    /// building one.
    #[tokio::test]
    async fn an_acquired_var_reaches_both_the_shell_and_the_daemon() {
        let (_state, _rootfs, _cwd, chan) = setup_channel();
        let (mut ours, theirs) = UnixStream::pair().unwrap();

        chan.announce_env(&mut ours, "GOCACHE", "/state/gocache");
        drop(ours);

        assert_eq!(read_lines(&theirs), vec!["set_env:GOCACHE:/state/gocache"]);
        assert_eq!(
            chan.runtime_env
                .snapshot()
                .get("GOCACHE")
                .map(String::as_str),
            Some("/state/gocache"),
            "the daemon's view is missing a variable the shell was given"
        );
    }

    /// Installing over an earlier install replaces the value, as the shell's
    /// second `export` does.
    #[tokio::test]
    async fn a_reannounced_var_takes_the_newer_value() {
        let (_state, _rootfs, _cwd, chan) = setup_channel();
        let (mut ours, _theirs) = UnixStream::pair().unwrap();

        chan.announce_env(&mut ours, "PYTHONPATH", "/first");
        chan.announce_env(&mut ours, "PYTHONPATH", "/second");

        assert_eq!(
            chan.runtime_env
                .snapshot()
                .get("PYTHONPATH")
                .map(String::as_str),
            Some("/second")
        );
    }

    #[tokio::test]
    async fn search_finds_known_package() {
        let (_state, _rootfs, _cwd, mut chan) = setup_channel();
        let (mut ours, theirs) = UnixStream::pair().unwrap();

        // "uroot" is a known package in the fakerepo fixture.
        chan.handle("search%uroot", &mut ours).await;
        drop(ours);

        let lines = read_lines(&theirs);
        assert!(
            lines.iter().any(|l| l.contains("uroot")),
            "expected 'uroot' in search results, got: {lines:?}"
        );
    }

    /// Names the packages `bsrs` refers to, sorted, for comparing sets across
    /// two parses of the same repo (refs are graph-local; names are not).
    fn names<'a>(graph: &Graph, bsrs: impl IntoIterator<Item = &'a BuildSpecRef>) -> Vec<String> {
        let mut out: Vec<String> = bsrs
            .into_iter()
            .map(|bsr| graph.get(bsr).expect("bsr in graph").name.clone())
            .collect();
        out.sort();
        out
    }

    /// A refresh re-parses the mfile, so its graph's `top_levels` are the
    /// packages the *repo* declares. The session means something else by that
    /// field — the packages it has injected into its rootfs — and `install`
    /// reads it to decide whether `min add` has any work to do. A refresh that
    /// let the repo's answer through would make `min add <declared-pkg>` take
    /// the already-installed path and inject nothing.
    #[tokio::test]
    async fn refresh_does_not_adopt_the_repos_top_levels() {
        let (_state, _rootfs, _cwd, mut chan) = setup_channel();
        let (mut ours, _theirs) = UnixStream::pair().unwrap();

        // The fixture declares `uroot`; this session has installed nothing.
        assert!(
            chan.graph.by_name("uroot").is_some(),
            "fixture no longer declares uroot"
        );
        chan.graph.top_levels = vec![];
        chan.has_packages = HashSet::new();

        let (_ctx, graph, has_packages) = chan
            .refresh(&mut ours)
            .await
            .expect("refresh should succeed");

        assert!(
            graph.top_levels.is_empty(),
            "refresh adopted the repo's top-levels as the installed set: {:?}",
            names(&graph, &graph.top_levels)
        );
        assert!(has_packages.is_empty());
    }

    /// The other half: refs are graph-local, so what the session *has*
    /// installed has to be re-resolved by name onto the reparsed graph rather
    /// than carried over or dropped.
    #[tokio::test]
    async fn refresh_remaps_the_installed_set_onto_the_new_graph() {
        let (_state, _rootfs, _cwd, mut chan) = setup_channel();
        let (mut ours, _theirs) = UnixStream::pair().unwrap();

        let uroot = *chan.graph.by_name("uroot").expect("fakerepo has uroot");
        chan.graph.top_levels = vec![uroot];
        chan.has_packages = HashSet::from([uroot]);

        let (_ctx, graph, has_packages) = chan
            .refresh(&mut ours)
            .await
            .expect("refresh should succeed");

        assert_eq!(
            names(&graph, &graph.top_levels),
            vec!["uroot".to_string()],
            "refresh dropped the session's top-levels"
        );
        assert_eq!(names(&graph, &has_packages), vec!["uroot".to_string()]);
        for bsr in graph.top_levels.iter().chain(has_packages.iter()) {
            assert!(
                graph.get(bsr).is_some(),
                "a ref from the old graph leaked into the new one"
            );
        }
    }

    /// Adding a package the session already has is a no-op, but it must be a
    /// *visible* one: the wire carries no other signal, so a silent return is
    /// indistinguishable from a successful injection.
    #[tokio::test]
    async fn installing_an_already_installed_package_reports_it() {
        let (_state, _rootfs, _cwd, mut chan) = setup_channel();
        let (mut ours, theirs) = UnixStream::pair().unwrap();

        let uroot = *chan.graph.by_name("uroot").expect("fakerepo has uroot");
        chan.graph.top_levels = vec![uroot];

        // Driven directly rather than through `handle`, which would also
        // record the dependency in the fixture's checked-in minimal.toml.
        chan.install(&[("uroot", uroot)], &mut ours).await;
        drop(ours);

        let lines = read_lines(&theirs);
        assert_eq!(
            lines,
            vec!["msg:Already installed: uroot".to_string()],
            "unexpected output: {lines:?}"
        );
    }

    /// A resolved env var shaped `/state/<prefix>` seeds a state
    /// dir named `<prefix>`; non-`/state/` values are ignored. This
    /// is the isolated composition-branch derivation the parity
    /// test does not exercise via `Env::build` (which requires a
    /// full graph + built packages), pulled out into a helper so
    /// it can be unit-tested directly.
    #[test]
    fn state_dirs_from_env_vars_extracts_single_component_prefixes() {
        let env = HashMap::from([
            ("GOCACHE".to_string(), "/state/gocache".to_string()),
            ("GOMODCACHE".to_string(), "/state/gomodcache".to_string()),
            ("HOME".to_string(), "/home/user".to_string()),
            ("PS1".to_string(), r"\u@\h $ ".to_string()),
        ]);
        let out = state_dirs_from_env_vars(&env);
        assert_eq!(out.len(), 2);
        assert!(out.contains("gocache"));
        assert!(out.contains("gomodcache"));
    }

    /// A value that's literally `/state/` (no prefix component) is
    /// ignored — creating `state_base_dir/` itself is nonsense.
    #[test]
    fn state_dirs_from_env_vars_ignores_bare_state() {
        let env = HashMap::from([("WEIRD".to_string(), "/state/".to_string())]);
        assert!(state_dirs_from_env_vars(&env).is_empty());
    }

    /// The sandbox working directory the helper sends, for tests that don't
    /// care which subdirectory of the workspace the command was typed in.
    fn wd(sub: &str) -> Utf8PathBuf {
        Utf8Path::new(WORKSPACE_ROOT).join(sub)
    }

    /// A session's two daemon directories, `work` and `home`, under `dir`.
    fn session_dirs(dir: &TempDir) -> (DaemonAbsPath, DaemonAbsPath) {
        let root = Utf8PathBuf::try_from(dir.path().to_path_buf()).unwrap();
        let dirs = (root.join("work"), root.join("home"));
        std::fs::create_dir_all(&dirs.0).unwrap();
        std::fs::create_dir_all(&dirs.1).unwrap();
        (
            DaemonAbsPath::try_new(dirs.0).unwrap(),
            DaemonAbsPath::try_new(dirs.1).unwrap(),
        )
    }

    /// An absolute sandbox path, as `resolve_output` produces.
    fn sbx(path: &str) -> SandboxAbsPath {
        SandboxAbsPath::try_new(path).unwrap()
    }

    /// The parse mirrors `mip materialize`'s clap interface, including the
    /// `--flag=value` form clap accepts alongside `--flag value`.
    #[test]
    fn materialize_args_parse_both_flag_forms() {
        let expected = MaterializeArgs {
            opts: crate::session_sop::MaterializeOpts {
                output_name: "image".to_string(),
                arch: Some("arm64".to_string()),
            },
            output: SandboxAbsPath::try_new("/workbench/dist/image.tar").unwrap(),
        };

        let cwd = wd("");
        assert_eq!(
            MaterializeArgs::from_args(&cwd, "--output dist/image.tar --arch arm64 image").unwrap(),
            expected
        );
        assert_eq!(
            MaterializeArgs::from_args(&cwd, "-o=dist/image.tar --arch=arm64 image").unwrap(),
            expected
        );
        // The positional is recognised wherever it lands.
        assert_eq!(
            MaterializeArgs::from_args(&cwd, "image -o dist/image.tar --arch arm64").unwrap(),
            expected
        );
    }

    /// The request line carries the helper's working directory ahead of the
    /// arguments; without it there is nothing to resolve `--output` against,
    /// which must be an error rather than a guess at the workspace root.
    #[test]
    fn materialize_request_carries_the_working_directory() {
        let args = MaterializeArgs::from_request(&format!("{}%-o out.tar image", wd("sub")))
            .expect("a well-formed request");
        assert_eq!(args.output.as_str(), "/workbench/sub/out.tar");

        let err = MaterializeArgs::from_request("-o out.tar image")
            .expect_err("a request without a working directory is malformed");
        assert!(
            err.contains("working directory"),
            "the error must say what is missing, got {err:?}",
        );
    }

    /// The point of sending the cwd: `min materialize -o out.tar` run from a
    /// subdirectory resolves *there*, not at the workspace root. Resolution
    /// stops at an absolute sandbox path — which session directory it names is
    /// `sandbox_to_daemon`'s decision, so `/home` resolves as readily as
    /// `/workbench` and neither is checked here.
    #[test]
    fn materialize_output_resolves_against_the_working_directory() {
        for (cwd, output, want) in [
            // A bare name lands beside the user, wherever they are.
            (
                "/workbench/sub/deep",
                "out.tar",
                "/workbench/sub/deep/out.tar",
            ),
            ("/workbench", "out.tar", "/workbench/out.tar"),
            ("/home/nested", "out.tar", "/home/nested/out.tar"),
            // `..` and `.` are resolved away.
            (
                "/workbench/sub/deep",
                "../out.tar",
                "/workbench/sub/out.tar",
            ),
            (
                "/workbench/sub",
                "./dist/out.tar",
                "/workbench/sub/dist/out.tar",
            ),
            // An absolute path is already a sandbox path: the cwd doesn't
            // enter into it, so it resolves the same way from anywhere.
            (
                "/workbench/sub",
                "/workbench/dist/out.tar",
                "/workbench/dist/out.tar",
            ),
            ("/workbench", "/home/somefile", "/home/somefile"),
            ("/home", "/workbench/somefile", "/workbench/somefile"),
        ] {
            let resolved = resolve_output(Utf8Path::new(cwd), Utf8Path::new(output))
                .unwrap_or_else(|e| panic!("resolving {output:?} from {cwd:?}: {e}"));
            assert_eq!(resolved.as_str(), want, "`-o {output}` from {cwd}");
        }
    }

    /// Each of the two directories a sandbox path can name maps to its own
    /// daemon directory — `/workbench` to the workspace, `/home` to the home.
    #[tokio::test]
    async fn sandbox_paths_land_in_the_session_directory_they_name() {
        let tmp = tempdir().unwrap();
        let (working, home) = session_dirs(&tmp);

        for (path, want) in [
            (
                "/workbench/dist/out.tar",
                working.as_utf8_path().join("dist/out.tar"),
            ),
            (
                "/home/.cache/out.tar",
                home.as_utf8_path().join(".cache/out.tar"),
            ),
        ] {
            create_artifact(&working, &home, &sbx(path))
                .await
                .unwrap_or_else(|e| panic!("creating {path}: {e}"));
            assert!(want.is_file(), "`{path}` should have landed at {want}");
        }
    }

    /// Anything under neither directory is refused rather than redirected:
    /// `/tmp/x.tar` names a file in the *sandbox*, which the daemon cannot
    /// write, and a root names a directory, not an artifact.
    #[tokio::test]
    async fn sandbox_paths_outside_the_session_directories_are_refused() {
        let tmp = tempdir().unwrap();
        let (working, home) = session_dirs(&tmp);

        for (path, want) in [
            ("/tmp/x.tar", "outside the session's"),
            ("/etc/passwd", "outside the session's"),
            ("/", "outside the session's"),
            // A prefix match must be by component, or this would resolve.
            ("/workbenchx/out.tar", "outside the session's"),
            ("/workbench", "is a session directory"),
            ("/home", "is a session directory"),
        ] {
            let err = create_artifact(&working, &home, &sbx(path))
                .await
                .expect_err("a path outside the session directories");
            assert!(
                err.to_string().contains(want),
                "expected {want:?} for {path}, got {err}",
            );
            assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        }
    }

    /// A `..` that climbs out shows up as a path under neither directory —
    /// `resolve_output` normalizes first precisely so the prefix match cannot
    /// be fooled by a leading component.
    #[tokio::test]
    async fn traversals_out_of_the_session_directories_are_refused() {
        let tmp = tempdir().unwrap();
        let (working, home) = session_dirs(&tmp);

        for (cwd, output) in [
            ("/workbench", "/etc/passwd"),
            ("/workbench", "../out.tar"),
            ("/workbench/sub", "../../out.tar"),
            ("/home", "../../../../etc/passwd"),
            ("/workbench", "/workbench/../etc/passwd"),
        ] {
            let resolved = resolve_output(Utf8Path::new(cwd), Utf8Path::new(output))
                .expect("resolution itself does not judge the destination");
            let err = create_artifact(&working, &home, &resolved)
                .await
                .expect_err("a path leaving the session directories must be refused");
            assert!(
                err.to_string().contains("outside the session's"),
                "expected a containment error for `-o {output}` from {cwd}, got {err}",
            );
        }
    }

    /// The directories leading to the artifact are created, and the bytes go
    /// straight into it — there is no staging copy to publish.
    #[tokio::test]
    async fn create_artifact_creates_the_file_and_its_parents() {
        use tokio::io::AsyncWriteExt as _;

        let tmp = tempdir().unwrap();
        let (working, home) = session_dirs(&tmp);

        let mut file = create_artifact(&working, &home, &sbx("/workbench/dist/image.tar"))
            .await
            .expect("the parent directories are created");
        file.write_all(b"tarball").await.unwrap();
        file.flush().await.unwrap();
        drop(file);

        let dest = working.as_utf8_path().join("dist/image.tar");
        assert_eq!(std::fs::read(&dest).unwrap(), b"tarball");
    }

    /// `resolve_output` reasons about a path in the sandbox's namespace, so it
    /// cannot see a symlink in the workspace pointing out of it. The daemon is
    /// not confined to the sandbox, so the check has to happen on disk or
    /// `-o escape/x.tar` writes wherever the link leads.
    #[tokio::test]
    async fn create_artifact_refuses_a_parent_symlinked_out_of_the_session() {
        let tmp = tempdir().unwrap();
        let (working, home) = session_dirs(&tmp);
        let outside = Utf8PathBuf::try_from(tmp.path().join("outside")).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, working.as_utf8_path().join("escape")).unwrap();

        let err = create_artifact(&working, &home, &sbx("/workbench/escape/x.tar"))
            .await
            .expect_err("a symlinked parent leaving the session must be refused");
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(
            !outside.join("x.tar").exists(),
            "nothing may be created outside the session directory"
        );
    }

    /// The parent check cannot catch a symlink at the *destination itself*, so
    /// the open refuses to follow one. Otherwise `-o out.tar`, with `out.tar`
    /// linked to `/etc/passwd`, would have the daemon write through it.
    #[tokio::test]
    async fn create_artifact_refuses_a_symlinked_destination() {
        let tmp = tempdir().unwrap();
        let (working, home) = session_dirs(&tmp);
        let outside = Utf8PathBuf::try_from(tmp.path().join("outside.tar")).unwrap();
        std::os::unix::fs::symlink(&outside, working.as_utf8_path().join("out.tar")).unwrap();

        create_artifact(&working, &home, &sbx("/workbench/out.tar"))
            .await
            .expect_err("a symlinked destination must not be followed");
        assert!(
            !outside.exists(),
            "the link's target must not be created, let alone written"
        );
    }

    /// The containment check has to run *before* any directory is created, or
    /// `create_dir_all` walks through the link and materializes directories
    /// outside the session on its way to a destination that is then refused.
    #[tokio::test]
    async fn create_artifact_creates_nothing_through_a_symlinked_parent() {
        let tmp = tempdir().unwrap();
        let (working, home) = session_dirs(&tmp);
        let outside = Utf8PathBuf::try_from(tmp.path().join("outside")).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, working.as_utf8_path().join("escape")).unwrap();

        let err = create_artifact(&working, &home, &sbx("/workbench/escape/deep/x.tar"))
            .await
            .expect_err("a destination below a symlinked parent must be refused");
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(
            !outside.join("deep").exists(),
            "no directory may be created outside the session"
        );
    }

    /// A symlinked *directory* that stays inside the session directory is
    /// ordinary content and keeps working — the check is containment, not a
    /// ban on links.
    #[tokio::test]
    async fn create_artifact_allows_a_symlink_within_the_session() {
        let tmp = tempdir().unwrap();
        let (working, home) = session_dirs(&tmp);
        std::fs::create_dir_all(working.as_utf8_path().join("real")).unwrap();
        std::os::unix::fs::symlink(
            working.as_utf8_path().join("real"),
            working.as_utf8_path().join("link"),
        )
        .unwrap();

        create_artifact(&working, &home, &sbx("/workbench/link/x.tar"))
            .await
            .expect("a link inside the session directory is fine");
        assert!(
            working.as_utf8_path().join("real/x.tar").exists(),
            "the file lands in the directory the link points at"
        );
    }

    /// `--arch` is optional (the output's own arch, else the host's, applies);
    /// `--output` and the name are not.
    #[test]
    fn materialize_args_require_an_output_path_and_a_name() {
        let cwd = wd("");
        let args = MaterializeArgs::from_args(&cwd, "-o image.tar image").unwrap();
        assert_eq!(args.opts.arch, None);

        for (args, want) in [
            ("image", "--output"),
            ("-o image.tar", "requires the name"),
            ("-o", "requires a value"),
            ("-o image.tar image other", "expected one output name"),
        ] {
            let err = MaterializeArgs::from_args(&cwd, args).expect_err("incomplete invocation");
            assert!(
                err.contains(want),
                "expected {want:?} in the error for {args:?}, got {err:?}",
            );
        }
    }

    /// A mistyped flag must be an error, never a positional: read as one it
    /// would be a second output name, and the report would complain about the
    /// count instead of naming the typo.
    #[test]
    fn materialize_args_reject_unknown_flags() {
        let err = MaterializeArgs::from_args(&wd(""), "--ouput image.tar image")
            .expect_err("a mistyped flag must not parse as an output name");
        assert!(
            err.contains("unknown flag") && err.contains("--ouput"),
            "the error must name the offending flag, got {err:?}",
        );
    }

    /// A multi-component prefix that leaked past the extractor
    /// (which should have already rejected it) is silently dropped
    /// here — the extractor is the layer that surfaces the error
    /// to the client. This helper is the last line of defense but
    /// its concern is producing a valid single-component set, not
    /// diagnosing bad ones.
    #[test]
    fn state_dirs_from_env_vars_silently_drops_multi_component() {
        let env = HashMap::from([("WEIRD".to_string(), "/state/foo/bar".to_string())]);
        assert!(state_dirs_from_env_vars(&env).is_empty());
    }
}
