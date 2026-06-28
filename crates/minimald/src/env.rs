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

use std::collections::{HashMap, HashSet};
use std::fs::Permissions;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::Poll;

use camino::Utf8PathBuf;
use futures::StreamExt;
use graph::{BuildSpecRef, Graph, SetupForPackages, Transitives};
use mctx::{AddDepMode, Context, Error};
use mfile::{EnvPatches, EnvVarValue};
use op::Runnable;
use ot::OpTracker;
use paths::DaemonAbsPath;
use sandbox2::config::{Config, SandboxMapped};
use sandbox2::{Container, Sandbox};
use sessions::NetworkMode;
use tempfile::TempDir;
use tokio::sync::mpsc;
use tokio::task::{JoinHandle, spawn_blocking};

/// The min helper script installed at `/usr/bin/min` inside the sandbox.
const MIN_SCRIPT: &str = include_str!("env_min_helper.sh");

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
}

impl EnvArgs {
    /// Creates args for an environment named `name`, with working directory
    /// `cwd` and `/state` backed by `state_base_dir`.
    pub fn new(
        name: impl Into<String>,
        cwd: impl Into<DaemonAbsPath>,
        home: impl Into<DaemonAbsPath>,
        state_base_dir: impl Into<DaemonAbsPath>,
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
        }
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
    /// Extra directories kept alive for the environment's lifetime (e.g. a
    /// temporary `/state` directory). Dropped after the sandbox.
    _temp_dirs: Vec<TempDir>,
}

impl Env {
    /// Builds a runtime environment, consuming the context and graph.
    ///
    /// This resolves the requested packages (always pulling in `bash` and
    /// `socat` for the `min` helper), ensures they are built locally, assembles
    /// the sandbox rootfs, installs the `min` helper, and spawns the command
    /// channel actor with the context and graph moved into it.
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

        // Collect the package-derived wiring and merge caller-supplied overrides.
        let SetupForPackages {
            fs_mappings: mut patch,
            needs_dns: _,
            needs_internet: _,
            state_dirs,
            env_vars: mut pkg_env_vars,
        } = SetupForPackages::build(&graph, transitives.keys()).map_err(std::io::Error::other)?;

        if let Some(p) = &args.patches {
            patch.union(p);
        }
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
            // An own-IP sandbox runs in its own netns, where the synthesized
            // `/etc/resolv.conf` (the host's `127.0.0.53` systemd-resolved stub)
            // is unreachable. Point it at gvproxy's switch gateway, which serves
            // DNS for the subnet and is already the PTask's default route. Other
            // modes share the host netns and keep the host-derived resolver.
            .with_dns_nameserver(match args.network_mode {
                NetworkMode::OwnIp => Some(crate::net::DEFAULT_SUBNET.gateway()),
                _ => None,
            })
            .with_hostname(args.name.clone())
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

        let channel = SessionChannel {
            rootfs: DaemonAbsPath::try_new(
                Utf8PathBuf::try_from(sandbox.rootfs().to_path_buf()).unwrap(),
            )
            .unwrap(),
            state_dir: args.state_base_dir.clone(),
            working: args.cwd.clone(),
            task_name: args.name.clone(),
            has_packages: transitives.keys().copied().collect(),
            ot: args.ot.clone(),
            ctx,
            graph,
            rx,
        };
        let actor = tokio::spawn(channel.run());

        Ok(Self {
            sandbox,
            actor: Some(actor),
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
    /// The host directory the working directory.
    working: DaemonAbsPath,

    /// The environment name, used when adding task packages.
    task_name: String,
    /// Packages already materialized into the rootfs.
    has_packages: HashSet<BuildSpecRef>,
    ot: Option<OpTracker>,
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
            Some(("add-session", pkgs)) => match self.parse_pkgs_line(pkgs) {
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
            Some(("add-task", pkgs)) => match self.parse_pkgs_line(pkgs) {
                Err(n) => {
                    let _ = writeln!(stream, "error: no such package '{n}'");
                    None
                }
                Ok(pkgs) => {
                    self.install(&pkgs, stream).await;
                    Some((
                        AddDepMode::TaskPackages {
                            name: self.task_name.clone(),
                        },
                        pkgs,
                    ))
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
            return; // Already installed.
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
                if !setup.fs_mappings.dir.is_empty() || !setup.fs_mappings.file.is_empty() {
                    let _ = writeln!(
                        stream,
                        "msg:Error: A package needed for this install requires files from your host to be patched in,"
                    );
                    let _ = writeln!(
                        stream,
                        "msg:which cannot be performed within an existing session."
                    );
                    let _ = writeln!(stream, "msg:");
                    let _ = writeln!(
                        stream,
                        "msg:Exit the session, add the package yourself, and then restart your session to work around this."
                    );
                    let _ = writeln!(stream, "error: Failed installation.");
                    return;
                }

                for want_dir in setup.state_dirs {
                    if let Err(e) =
                        std::fs::create_dir_all(self.state_dir.as_utf8_path().join(want_dir))
                    {
                        let _ = writeln!(stream, "error: {e}");
                        return;
                    }
                }
                for (k, v) in &setup.env_vars {
                    let _ = writeln!(stream, "set_env:{k}:{v}");
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

    /// Implements `min check`.
    async fn run_check(&mut self, stream: &mut UnixStream, args: &str) {
        let mut flag_packages = false;
        let mut flag_stacks = false;
        let mut flag_profiles = false;
        let mut fix = false;
        let mut filter_names: Vec<String> = Vec::new();

        for token in args.split_whitespace() {
            match token {
                "--packages" => flag_packages = true,
                "--stacks" => flag_stacks = true,
                "--profiles" => flag_profiles = true,
                "--fix" => fix = true,
                _ => filter_names.push(token.to_string()),
            }
        }

        // If no kind flags specified, check everything.
        let check_all = !flag_packages && !flag_stacks && !flag_profiles;

        let mut check_ctx = match self.ctx.cloned_reinit() {
            Err(e) => return Self::write_error(&e, stream),
            Ok(ctx) => ctx,
        };
        let graph = match check_ctx.graph_from_all_packages() {
            Err(e) => return Self::write_error(&e, stream),
            Ok(g) => g,
        };

        let upstream_dir = check_ctx.minimal_file().dir_path().unwrap().to_path_buf();

        let mut checks_stream = match check::run_checks(
            (check_all || flag_packages).then(|| upstream_dir.join("packages")),
            (check_all || flag_profiles).then(|| upstream_dir.join("profiles")),
            (check_all || flag_stacks).then(|| upstream_dir.join("stacks")),
            check::CheckCtx::new(
                filter_names,
                vec![],
                fix,
                Some(Arc::new(tokio::sync::RwLock::new(graph))),
                check_ctx.stdlib_dir().to_path_buf(),
                check_ctx.local_cache(),
                self.ot.clone(),
            ),
        ) {
            Err(e) => return Self::write_error(&Error::from(e), stream),
            Ok(res_stream) => res_stream,
        };

        while let Some((heading, result)) = checks_stream.next().await {
            let checks = match result {
                Ok(checks) => checks,
                Err(e) => {
                    let _ = writeln!(stream, "error: {e}");
                    return;
                }
            };
            let _ = writeln!(stream, "msg:");
            let _ = writeln!(stream, "msg:{heading}");
            for check in checks {
                let _ = writeln!(stream, "msg:{}...{}", check.check, check.verdict);
                for err in check.err {
                    let _ = writeln!(stream, "msg:\t{err}");
                }
            }
        }
    }

    /// Implements `min patched-pkg <pkgname>`.
    async fn run_patched_pkg(&mut self, stream: &mut UnixStream, pkg_name: &str) {
        let mut build_ctx = match self.ctx.cloned_reinit() {
            Err(e) => return Self::write_error(&e, stream),
            Ok(ctx) => ctx,
        };
        let graph = match build_ctx.graph_from_package_names([pkg_name]) {
            Err(e) => return Self::write_error(&e, stream),
            Ok(g) => g,
        };

        let bsr = graph.top_levels[0];
        let result: std::io::Result<()> = async {
            let remote_storage = build_ctx.remote_storage().await.map_err(err_to_io)?;
            let output_base = build_ctx.builds_base_dir();
            let _ = std::fs::create_dir_all(&output_base);

            let cache = build_ctx.local_cache();
            let (stdout_writer, stderr_writer) = StreamWriter::pair(stream)?;
            let res = op::PatchedBuild {
                spec: &bsr,
                remote_fetcher: &remote_storage,
                stdout_writer: Some(Box::new(stdout_writer)),
                stderr_writer: Some(Box::new(stderr_writer)),
            }
            .run(&op::Options {
                cache,
                graph: &graph,
                exec_base: output_base,
                ot: self.ot.clone(),
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
    }

    /// Implements `min run <task>`.
    async fn run_task(&mut self, stream: &mut UnixStream, task_name: &str, args: &str) {
        let mut build_ctx = match self.ctx.cloned_reinit() {
            Err(e) => return Self::write_error(&e, stream),
            Ok(ctx) => ctx,
        };
        let graph = match build_ctx.graph_from_all_packages() {
            Err(e) => return Self::write_error(&e, stream),
            Ok(g) => g,
        };
        let (task, mut graph) = match build_ctx.task(graph, task_name) {
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
            let mut env = build_ctx
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

    /// Writes an [`mctx::Error`] to the client as `msg:` lines (preserving its
    /// multi-line, richly-formatted report) followed by an `error:` terminator.
    fn write_error(e: &Error, stream: &mut UnixStream) {
        for line in e.to_string().split('\n') {
            let _ = writeln!(stream, "msg:{line}");
        }
        let _ = writeln!(stream, "error: sandbox command failed.");
    }
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
            task_name: "test-task".to_string(),
            has_packages: HashSet::new(),
            ot: None,
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
}
