use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fs::Permissions,
    io::Write,
    os::unix::{fs::PermissionsExt, net::UnixStream},
    path::{Path, PathBuf},
};

use crate::{AddDepMode, Context, Error};
use futures::stream::StreamExt;
use graph::{BuildSpecRef, Graph, SetupForPackages, Transitives, TransitivesDep};
use mfile::{EnvPatches, EnvVarValue};
use op::Runnable;
use ot::OpTracker;
#[cfg(target_os = "linux")]
use sandbox2::Container;
use sandbox2::config::{Invocation, SandboxMapped};
use tempfile::TempDir;

#[allow(dead_code)]
struct EnvChannel<'a> {
    graph: &'a mut Graph,
    ctx: &'a mut Context,

    task_name: String,
    state_dir: PathBuf,
    has_packages: HashSet<BuildSpecRef>,

    daemon_id: Option<String>,
    ot: Option<OpTracker>,
}

impl EnvChannel<'_> {
    /// Helper for installing packages into the environment.
    fn install(
        &mut self,
        pkgs: &Vec<(&str, BuildSpecRef)>,
        stream: &mut UnixStream,
        rootfs: &Path,
    ) {
        if pkgs
            .iter()
            .all(|(_n, bsr)| self.graph.top_levels.contains(bsr))
        {
            return; // Already installed.
        }

        let mut new_graph = self.graph.clone();
        pkgs.iter().for_each(|(_n, bsr)| {
            if !new_graph.top_levels.contains(bsr) {
                new_graph.top_levels.push(*bsr);
            }
        });
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        if let Err(e) = rt.block_on(self.ctx.build_graph(&new_graph, false, None)) {
            writeln!(stream, "error: {}", e).ok();
            return;
        };

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
                    writeln!(stream, "msg:Error: A package needed for this install requires files from your host to be patched in,").ok();
                    writeln!(
                        stream,
                        "msg:which cannot be performed within an existing session."
                    )
                    .ok();
                    writeln!(stream, "msg:").ok();
                    writeln!(stream, "msg:Exit the session, add the package yourself, and then restart your session to work around this.").ok();
                    writeln!(stream, "error: Failed installation.").ok();
                    return;
                }

                for want_dir in setup.state_dirs {
                    std::fs::create_dir_all(self.state_dir.join(want_dir)).unwrap();
                }
                setup.env_vars.iter().for_each(|(k, v)| {
                    writeln!(stream, "set_env:{}:{}", k, v).ok();
                });
            }
            Err(e) => {
                writeln!(stream, "error: {}", e).ok();
                return;
            }
        }
        for bsr in transitives.keys() {
            if self.has_packages.insert(*bsr)
                && let Err(e) = common::hardlink_dir_contents(
                    self.ctx
                        .daemon
                        .cache
                        .read_dir(&new_graph.spec_hash(bsr))
                        .unwrap()
                        .path(),
                    rootfs,
                )
            {
                writeln!(stream, "error: {}", e).ok();
                return;
            }
        }
        writeln!(
            stream,
            "msg:Installed {}",
            pkgs.iter().map(|t| t.0).collect::<Vec<_>>().join(", ")
        )
        .ok();
        *self.graph = new_graph;
    }

    fn parse_pkgs_line<'a>(&self, pkgs: &'a str) -> Result<Vec<(&'a str, BuildSpecRef)>, &'a str> {
        pkgs.split(" ")
            .map(|n| match self.graph.by_name(n) {
                None => Err(n),
                Some(bsr) => Ok((n, *bsr)),
            })
            .collect()
    }

    /// Helper for writing an [Error] back to the user
    fn write_error(e: Error, stream: &mut UnixStream) {
        let mut buf = codespan_reporting::term::termcolor::NoColor::new(Vec::with_capacity(512));
        e.report_to(&mut buf);
        for line in buf.into_inner().split(|c| *c == b'\n') {
            stream.write_all(b"msg:").ok();
            stream.write_all(line).ok();
            stream.write_all(b"\n").ok();
        }
        writeln!(stream, "error: sandbox command failed.").ok();
    }

    /// Implementation of `min check`
    fn run_check(&mut self, stream: &mut UnixStream, _rootfs: &Path, args: &str) {
        let mut flag_packages = false;
        let mut flag_stacks = false;
        let mut fix = false;
        let mut filter_names: Vec<String> = Vec::new();

        for token in args.split_whitespace() {
            match token {
                "--packages" => flag_packages = true,
                "--stacks" => flag_stacks = true,
                "--fix" => fix = true,
                _ => filter_names.push(token.to_string()),
            }
        }

        // If no kind flags specified, check everything (same as cmd_check default).
        let check_all = !flag_packages && !flag_stacks;

        let mut check_ctx = match self.ctx.cloned_reinit() {
            Err(e) => return EnvChannel::write_error(e, stream),
            Ok(ctx) => ctx,
        };
        let graph = match check_ctx.graph_from_all_packages() {
            Err(e) => return EnvChannel::write_error(e, stream),
            Ok(g) => g,
        };

        let upstream_dir = check_ctx.minimal_file().dir_path().unwrap().to_path_buf();

        let mut checks_stream = match check::run_checks(
            if check_all || flag_packages {
                Some(upstream_dir.join("packages"))
            } else {
                None
            },
            if check_all || flag_stacks {
                Some(upstream_dir.join("stacks"))
            } else {
                None
            },
            check::CheckCtx::new(
                filter_names,
                vec![],
                fix,
                Some(std::sync::Arc::new(tokio::sync::RwLock::new(graph))),
                check_ctx.stdlib_dir().to_path_buf(),
                check_ctx.local_cache(),
                self.ot.clone(),
                self.daemon_id.clone(),
            ),
        ) {
            Err(e) => return EnvChannel::write_error(e.into(), stream),
            Ok(res_stream) => res_stream,
        };
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        if let Err(e) = rt.block_on(async {
            while let Some((heading, result)) = checks_stream.next().await {
                let checks = result?;
                writeln!(stream, "msg:").ok();
                writeln!(stream, "msg:{}", heading).ok();
                for check in checks {
                    writeln!(stream, "msg:{}...{}", check.check, check.verdict).ok();
                    for err in check.err {
                        writeln!(stream, "msg:\t{}", err).ok();
                    }
                }
            }
            Ok::<(), check::Error>(())
        }) {
            writeln!(stream, "error: {}", e).ok();
        }
    }

    /// Implementation of `min patched-pkg <pkgname>`
    fn run_patched_pkg(&mut self, stream: &mut UnixStream, _rootfs: &Path, pkg_name: &str) {
        let mut build_ctx = match self.ctx.cloned_reinit() {
            Err(e) => return EnvChannel::write_error(e, stream),
            Ok(ctx) => ctx,
        };
        let graph = match build_ctx.graph_from_package_names([pkg_name]) {
            Err(e) => return EnvChannel::write_error(e, stream),
            Ok(g) => g,
        };

        let bsr = graph.top_levels[0];
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        if let Err(e) = rt.block_on(async {
            let remote_storage = build_ctx
                .remote_storage()
                .await
                .map_err(|e| anyhow::anyhow!("{}", e))?;

            let output_base = build_ctx.builds_base_dir();
            std::fs::create_dir_all(&output_base).ok();

            let cache = build_ctx.local_cache();
            let (stdout_writer, stderr_writer) = StreamWriter::pair(stream);
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
                daemon_id: self.daemon_id.clone(),
            })
            .await
            .map_err(|e| anyhow::anyhow!("{}", e))?;

            res.outputs
                .finalize(res.meta)
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            Ok::<(), anyhow::Error>(())
        }) {
            writeln!(stream, "error: {}", e).ok();
            return;
        };
        writeln!(
            stream,
            "msg:Written to cache with hash {}",
            graph.spec_hash(&bsr).0
        )
        .ok();
    }

    /// Implementation of `min run <task>`
    fn run_task(&mut self, stream: &mut UnixStream, _rootfs: &Path, task_name: &str, args: &str) {
        let mut build_ctx = match self.ctx.cloned_reinit() {
            Err(e) => return EnvChannel::write_error(e, stream),
            Ok(ctx) => ctx,
        };

        // An `echo` task carries its whole output in its declaration, so it
        // needs no package graph or sandbox — service it straight from the
        // mfile. Only mfile-local tasks are matched here; a stack-provided
        // echo task falls through to the normal (sandboxed) path below.
        if let Some(task) = build_ctx.minimal_file().task(task_name)
            && task.action.as_echo().is_some()
        {
            let parsed_args = if task.args.is_empty() {
                None
            } else {
                match task.args.parse(args) {
                    Err(e) => {
                        for line in format!("{}", e.render().ansi()).lines() {
                            writeln!(stream, "msg:{}", line).ok();
                        }
                        writeln!(stream, "error: failed parsing arguments for task").ok();
                        return;
                    }
                    Ok(args) => Some(args),
                }
            };
            match crate::interpolate_task_strings(&task, parsed_args.as_ref()) {
                Err(e) => return EnvChannel::write_error(e, stream),
                // `msg:` framing matches how task stdout lines reach the client.
                Ok(t) => writeln!(stream, "msg:{}", t.action.as_echo().unwrap_or_default()).ok(),
            };
            return;
        }

        let graph = match build_ctx.graph_from_all_packages() {
            Err(e) => return EnvChannel::write_error(e, stream),
            Ok(g) => g,
        };
        let task = match build_ctx.task(graph, task_name) {
            Err(e) => return EnvChannel::write_error(e, stream),
            Ok(v) => v,
        };
        let (task, mut graph) = match task {
            None => {
                writeln!(stream, "error: no such task '{}'", task_name).ok();
                return;
            }
            Some((t, g)) => (t, g),
        };
        let parsed_args = if !task.args.is_empty() {
            Some(match task.args.parse(args) {
                Err(e) => {
                    for line in format!("{}", e.render().ansi()).lines() {
                        writeln!(stream, "msg:{}", line).ok();
                    }
                    writeln!(stream, "error: failed parsing arguments for task").ok();
                    return;
                }
                Ok(args) => args,
            })
        } else {
            None
        };

        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        let result: Result<(), Error> = rt.block_on(async {
            let mut env = build_ctx
                .make_env(
                    task_name,
                    &mut graph,
                    if task.inherit_cwd {
                        Some(std::env::current_dir().unwrap())
                    } else {
                        None
                    },
                    task.state_key.as_ref(),
                    Some(&task.patch),
                    Some(&task.vars),
                    task.packages.clone(),
                    // A nested `min task` inside a bound-dir sandbox: paths
                    // are mirrored one-for-one and sandbox2 gave this process
                    // the outer environment's `HOME`, so the ambient home is
                    // the outer home, which is the one `~/` meant all along.
                    PatchHome::Ambient,
                )
                .await?;

            let (interactive, invocations) =
                env.task_invocations(&task, parsed_args.as_ref()).await?;
            if interactive {
                return Err(Error::Other(anyhow::anyhow!(
                    "cannot run interactive tasks from within an environment"
                )));
            }

            let (stdout_writer, stderr_writer) = StreamWriter::pair(stream);
            env.run(invocations, Some(stdout_writer), Some(stderr_writer))
                .await
        });

        if let Err(e) = result {
            EnvChannel::write_error(e, stream)
        }
    }
}

impl sandbox2::Channel for EnvChannel<'_> {
    fn handle(&mut self, stream: &mut UnixStream, line: &str, rootfs: &Path) {
        // handle, eg: echo 'add-ephemeral%mermaid-ascii' | socat -,ignoreeof UNIX-CONNECT:/run/minenv_sock

        let add_dep = match line.split_once("%") {
            Some(("add-session", pkgs)) => match self.parse_pkgs_line(pkgs) {
                Err(n) => {
                    writeln!(stream, "error: no such package '{}'", n).ok();
                    None
                }
                Ok(pkgs) => {
                    self.install(&pkgs, stream, rootfs);
                    None
                }
            },
            Some(("add-build", pkgs)) => match self.parse_pkgs_line(pkgs) {
                Err(n) => {
                    writeln!(stream, "error: no such package '{}'", n).ok();
                    None
                }
                Ok(pkgs) => {
                    self.install(&pkgs, stream, rootfs);
                    Some((AddDepMode::BuildPackages, pkgs))
                }
            },
            Some(("add-runtime", pkgs)) => match self.parse_pkgs_line(pkgs) {
                Err(n) => {
                    writeln!(stream, "error: no such package '{}'", n).ok();
                    None
                }
                Ok(pkgs) => {
                    self.install(&pkgs, stream, rootfs);
                    Some((AddDepMode::RuntimePackages, pkgs))
                }
            },
            Some(("add-task", pkgs)) => match self.parse_pkgs_line(pkgs) {
                Err(n) => {
                    writeln!(stream, "error: no such package '{}'", n).ok();
                    None
                }
                Ok(pkgs) => {
                    self.install(&pkgs, stream, rootfs);
                    Some((
                        AddDepMode::TaskPackages {
                            name: self.task_name.clone(),
                        },
                        pkgs,
                    ))
                }
            },
            Some(("search", term)) => {
                self.graph
                    .fuzzy_name_search(term, 8)
                    .iter()
                    .for_each(|(bsr, m)| {
                        let b = self.graph.get(bsr).unwrap();
                        let name = &b.name;
                        if name.ends_with(" (prebuilt)") {
                            return;
                        }

                        write!(stream, "msg: * {}", name).ok();
                        if let Some(v) = b.upstream_version() {
                            write!(stream, " (version {})", v).ok();
                        }
                        if !m.outputs.is_empty() {
                            write!(
                                stream,
                                " [provides {}]",
                                m.outputs.keys().cloned().collect::<Vec<_>>().join(",")
                            )
                            .ok();
                        }
                        writeln!(stream).ok();
                    });
                None
            }
            Some(("check", args)) => {
                self.run_check(stream, rootfs, args);

                None
            }
            Some(("patched-pkg", name)) => {
                self.run_patched_pkg(stream, rootfs, name);

                None
            }
            Some(("run", args)) => {
                let (name, rest) = match args.split_once(" ") {
                    Some(v) => v,
                    None => (args, ""),
                };
                self.run_task(stream, rootfs, name, rest);

                None
            }
            _ => {
                writeln!(stream, "error: unhandled input '{}'", line).ok();
                None
            }
        };

        if let Some((add_mode, pkgs)) = add_dep
            && let Err(e) = self.ctx.add_deps(
                self.graph,
                pkgs.into_iter().map(|a| a.1).collect::<Vec<_>>(),
                add_mode,
            )
        {
            writeln!(stream, "error: {}", e).ok();
        }
    }
}

/// The arguments used to construct a runtime environment.
pub struct EnvArgs<'a> {
    /// A symbolic name for the environment. For tasks, this is the task name.
    pub name: &'a str,
    /// The exhaustive set of packages needed in the environment, aka transitive dependencies.
    pub transitives: HashMap<BuildSpecRef, TransitivesDep>,

    /// The path to the directory which will back /state.
    pub state_base_dir: PathBuf,
    /// The working directory to map.
    pub cwd: PathBuf,
    /// Any additional pinhole bind mounts / file mappings.
    pub patches: Option<&'a EnvPatches>,
    /// The home directory `~/`-rooted patch paths expand against, and that
    /// the sandbox reports as `$HOME`.
    pub home: PatchHome,

    /// Environment variables to set.
    pub env_vars: Option<&'a BTreeMap<String, EnvVarValue>>,
    /// The hostname to set, if any.
    pub hostname: Option<String>,

    /// If set, overrides the network isolation mode for the sandbox.
    pub override_network_mode: Option<sandbox2::NetworkMode>,
    /// The operation tracker to use downstream, if applicable.
    pub ot: Option<OpTracker>,
}

/// Returns a clone of `task` with every action string interpolated against
/// the task's parameters — `task_packages` plus any `parsed_args` — so that
/// `%{name}`-style placeholders are resolved.
///
/// Shared by the invocation path ([`Env::task_invocations`]) and the
/// sandbox-free `echo` short-circuits, so an echoed string is interpolated
/// the same way an `exec`/`bash` action would be.
pub fn interpolate_task_strings(
    task: &mfile::Task,
    parsed_args: Option<&args::ArgsSet>,
) -> Result<mfile::Task, Error> {
    let base = [(
        "task_packages",
        args::Arg::Array(
            task.packages
                .iter()
                .map(|s| args::ScalarArg::String(s.clone()))
                .collect(),
        ),
    )]
    .into_iter();
    let var_ctx = if let Some(args) = parsed_args {
        common::ncl_eval::VarCtx::from_iter(
            base.chain(args.iter().map(|(k, v)| (k.as_str(), v.clone()))),
        )
    } else {
        common::ncl_eval::VarCtx::from_iter(base)
    };
    task.map_exec_strings(|s| {
        var_ctx
            .eval_string(s)
            .map_err(|_| anyhow::anyhow!("nickel eval failed for string: {}", s))
    })
    .map_err(Error::Other)
}

/// Names whoever put a patch path into the environment: the package that
/// declared it, or — for a path that arrived through the task's own `patch`
/// table rather than a package attribute — the task itself.
fn declared_by(packages: &BTreeMap<String, String>, declared: &str, task: &str) -> String {
    match packages.get(declared) {
        Some(p) => format!("package `{p}`"),
        None => format!("task `{task}`"),
    }
}

/// The home directory this environment's `~/`-rooted patch paths expand
/// against, and that its sandbox reports as `$HOME`.
///
/// A patch path such as `~/.claude.json` has to name a real directory on the
/// filesystem the sandbox is assembled on. Reading the *ambient* home is
/// right in exactly one of the two situations this type distinguishes, so the
/// choice is made at the call site rather than silently deep in the
/// conversion: `minimald` is pid 1 inside the guest with `HOME=/`, and
/// expanding against that put package-declared files at the root of a
/// read-only rootfs, failing with `EROFS` (#1204).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum PatchHome {
    /// The home of the process building the environment (`$HOME`).
    ///
    /// The right answer for `mip` run by a developer: the sandbox mirrors
    /// host paths one-for-one (`WdSetup::BoundDir`), so the home a package
    /// means by `~` *is* the invoking user's, and sandbox2 synthesizes the
    /// same home into the sandbox's passwd. An unset `HOME` leaves no home at
    /// all, which is an error for a `~/`-rooted mapping and fine for anything
    /// else.
    #[default]
    Ambient,
    /// The home directory of the `minimald` session this environment belongs
    /// to, in the daemon's filesystem view.
    ///
    /// [`Daemon`]-realm because that is the filesystem the daemon assembles
    /// the sandbox on, and because it is the realm the session already tracks
    /// its home in (`SessionPaths::home`, `minimald::env::EnvArgs::home`) —
    /// so it arrives here without a conversion that could launder the realm.
    ///
    /// [`Daemon`]: paths::Daemon
    Session(paths::DaemonAbsPath),
}

impl PatchHome {
    /// The directory to expand `~/` against, or `None` when there is no home
    /// to be had (an [`Ambient`](Self::Ambient) home with `HOME` unset).
    #[must_use]
    pub fn resolve(&self) -> Option<PathBuf> {
        match self {
            Self::Ambient => std::env::home_dir(),
            Self::Session(home) => Some(home.as_utf8_path().as_std_path().to_path_buf()),
        }
    }
}

/// A successfully-configured runtime environment.
pub struct Env<'a> {
    sandbox: sandbox2::Sandbox<EnvChannel<'a>>,
    temp_dirs: Vec<TempDir>,
}

impl<'a> Env<'a> {
    /// Builds a runtime environment from the given parameters.
    ///
    /// This collects the wiring needed by packages (fs mappings, DNS, env vars),
    /// merges any caller-supplied patches and env vars, then constructs and
    /// returns the sandbox.
    pub async fn build(
        ctx: &'a mut Context,
        graph: &'a mut Graph,
        args: EnvArgs<'a>,
    ) -> Result<Self, Error> {
        let base_dir = ctx.daemon.config.task_base_dir();

        let SetupForPackages {
            fs_mappings: mut patch,
            fs_mapping_packages,
            needs_dns,
            needs_internet,
            state_dirs,
            env_vars: mut pkg_env_vars,
        } = SetupForPackages::build(graph, args.transitives.keys())
            .map_err(|e| Error::IO("package setup", "".into(), e))?;

        if let Some(p) = args.patches {
            patch.union(p);
        }
        if let Some(vars) = args.env_vars {
            pkg_env_vars.extend(
                vars.iter()
                    .map(|(k, v)| match v {
                        EnvVarValue::Value(v) => Ok::<_, Error>((k.clone(), v.clone())),
                        EnvVarValue::Inherit => Ok((
                            k.clone(),
                            std::env::var(k).map_err(|e| {
                                Error::Other(anyhow::anyhow!(
                                    "inheriting environment variable '{}': {}",
                                    k,
                                    e
                                ))
                            })?,
                        )),
                    })
                    .collect::<Result<Vec<_>, _>>()?,
            );
        }

        // `~/`-rooted patch paths expand against the home the caller named
        // (see [`PatchHome`]), and the same home goes on to the sandbox as
        // `$HOME` so a mapped-in `~/.claude.json` lands where the process
        // will look for it. A home that can't hold the file — notably `/`,
        // which is what `minimald` sees as pid 1 in the guest with no session
        // to borrow a home from — is refused with the package named, rather
        // than landing the file at the root of a read-only rootfs (#1204).
        let home = args.home.resolve();
        let fs_mappings = patch.to_fs_mappings(home.as_deref()).map_err(|e| {
            Error::Other(anyhow::anyhow!(
                "{e} (declared by {})",
                declared_by(&fs_mapping_packages, &e.declared, args.name)
            ))
        })?;
        // Expanded path → the declaration behind it. sandbox2 only ever sees
        // the expanded form, so its "create mapped file" failures name a path
        // nobody wrote down; this puts the package and its `~/`-rooted
        // declaration back into the message.
        let declarations: BTreeMap<String, &String> = fs_mapping_packages
            .keys()
            .filter_map(|declared| {
                Some((
                    EnvPatches::expand_home(declared, home.as_deref()).ok()?,
                    declared,
                ))
            })
            .collect();

        let mut config = sandbox2::config::Config::new(args.name)
            .with_wd(args.cwd.clone(), false, fs_mappings)
            .with_home(home.clone())
            .with_rootfs(
                args.transitives
                    .keys()
                    .map(|bsr| ctx.daemon.cache.read_dir(&graph.spec_hash(bsr)))
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|e| Error::Other(anyhow::anyhow!("loading dependency: {}", e)))?
                    .into_iter()
                    .map(|ce| SandboxMapped::Dir(ce.path().to_path_buf())),
            )
            .with_state_dir(&args.state_base_dir)
            .with_dns(
                args.override_network_mode
                    .map(|m| !matches!(m, sandbox2::NetworkMode::NoNet))
                    .unwrap_or(needs_dns),
            )
            .with_network_mode(args.override_network_mode.unwrap_or(
                if !needs_dns && !needs_internet {
                    sandbox2::NetworkMode::NoNet
                } else {
                    sandbox2::NetworkMode::HostNet
                },
            ))
            .with_env_vars(pkg_env_vars.into_iter());
        if let Some(id) = ctx.daemon_id() {
            config = config.with_daemon_id(id);
        }
        if let Some(hn) = &args.hostname {
            config = config.with_hostname(hn);
        }
        if let Ok(username) = std::env::var("USER") {
            config = config.with_username(username);
        }

        let daemon_id = ctx.daemon_id();
        let mut sandbox = config
            .build(
                base_dir,
                EnvChannel {
                    ctx,
                    graph,
                    task_name: args.name.to_string(),
                    state_dir: args.state_base_dir.clone(),
                    has_packages: args.transitives.keys().cloned().collect(),
                    ot: args.ot.clone(),
                    daemon_id,
                },
            )
            .await
            .map_err(|e| {
                // Sandbox setup creates every mapped file it doesn't find. If
                // that failed on a path we mapped in, say whose declaration it
                // was — "create mapped file /.claude.json: EROFS" on its own
                // sends nobody anywhere useful (#1204).
                let sandbox2::Error::IO(_, path, _) = &e else {
                    return e.into();
                };
                match path.to_str().and_then(|p| declarations.get(p)) {
                    Some(declared) => Error::Other(anyhow::anyhow!(
                        "{e}; mapped in by {}, which declares it as `{declared}`",
                        declared_by(&fs_mapping_packages, declared, args.name)
                    )),
                    None => e.into(),
                }
            })?;
        for want_dir in state_dirs {
            std::fs::create_dir_all(args.state_base_dir.join(&want_dir)).map_err(|e| {
                Error::IO("creating state dir", args.state_base_dir.join(want_dir), e)
            })?;
        }
        install_min_helpers(sandbox.rootfs())
            .map_err(|e| Error::IO("installing min helpers", sandbox.rootfs(), e))?;

        sandbox.keep_dir(false);

        Ok(Env {
            sandbox,
            temp_dirs: vec![],
        })
    }

    /// Gives temporary directories into the ownership of this env. Use this
    /// if you created a temporary directory for `state_base_dir` and want it to be
    /// cleaned up along with this environment.
    pub(crate) fn associate_tempdirs<I: IntoIterator<Item = TempDir>>(&mut self, dirs: I) {
        self.temp_dirs.extend(dirs);
    }

    /// Resolves the invocations to run for the given task using [`op::TaskEnv`], as well
    /// as whether they need to be in an interactive environment or not.
    ///
    /// The environment is used to resolve any meta commands (i.e. `TaskAction::CmdCmd`),
    /// and any string interpolations declared in the task are resolved.
    pub async fn task_invocations(
        &mut self,
        task: &mfile::Task,
        parsed_args: Option<&args::ArgsSet>,
    ) -> Result<(bool, Vec<Invocation>), Error> {
        let mapped_task = interpolate_task_strings(task, parsed_args)?;

        Ok((
            task.interactive,
            op::TaskEnv {
                task: &mapped_task,
                sandbox: &mut self.sandbox,
            }
            .resolve()
            .await
            .map_err(|e| Error::Other(anyhow::anyhow!("{}", e)))?,
        ))
    }

    #[cfg(target_os = "linux")]
    pub fn container(&mut self) -> Result<Container, Error> {
        self.sandbox
            .new_container()
            .map_err(|e| Error::Other(anyhow::anyhow!("{}", e)))
    }

    #[cfg(target_os = "linux")]
    pub fn command<I, S>(
        &mut self,
        container: &Container,
        program: &str,
        args: I,
    ) -> Result<sandbox2::Command, Error>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.sandbox
            .command(container, program, args, [("", ""); 0])
            .map_err(|e| Error::Other(anyhow::anyhow!("{}", e)))
    }

    /// Runs a sequence of invocations inside the sandbox, optionally streaming
    /// stdout and stderr to the provided async writers.
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
        #[cfg(target_os = "linux")]
        {
            self.sandbox
                .run(invocations, stdout_writer, stderr_writer)
                .await
                .map_err(Error::from)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (invocations, stdout_writer, stderr_writer);
            Err(op::sandbox_unsupported().into())
        }
    }
}

fn install_min_helpers(rootfs: PathBuf) -> Result<(), std::io::Error> {
    let usr_bin = rootfs.join("usr").join("bin");
    std::fs::create_dir_all(&usr_bin)?;

    std::fs::write(usr_bin.join("min"), MIN_SCRIPT)?;
    std::fs::set_permissions(
        rootfs.join("usr").join("bin").join("min"),
        Permissions::from_mode(0o0755),
    )?;

    let etc = rootfs.join("etc");
    std::fs::create_dir_all(&etc)?;

    Ok(())
}

const MIN_SCRIPT: &str = include_str!("min_helper.sh");

/// An [`tokio::io::AsyncWrite`] implementation that writes complete lines
/// as `msg:` prefixed messages to a [`UnixStream`].
///
/// Multiple `StreamWriter` instances can share the same underlying stream
/// via an `Arc<Mutex<_>>`, preventing interleaved writes from stdout/stderr.
struct StreamWriter {
    stream: std::sync::Arc<std::sync::Mutex<UnixStream>>,
    buf: Vec<u8>,
}

impl StreamWriter {
    fn pair(stream: &UnixStream) -> (Self, Self) {
        let shared = std::sync::Arc::new(std::sync::Mutex::new(stream.try_clone().unwrap()));
        (
            Self {
                stream: shared.clone(),
                buf: Vec::new(),
            },
            Self {
                stream: shared,
                buf: Vec::new(),
            },
        )
    }

    fn emit_lines(&mut self) {
        while let Some(pos) = self.buf.iter().position(|&b| b == b'\n') {
            let line = String::from_utf8_lossy(&self.buf[..pos]);
            writeln!(self.stream.lock().unwrap(), "msg:{}", line).ok();
            self.buf.drain(..=pos);
        }
    }
}

impl tokio::io::AsyncWrite for StreamWriter {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        self.buf.extend_from_slice(buf);
        self.emit_lines();
        std::task::Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        std::task::Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ConfigBuilder;
    use sandbox2::Channel;
    use std::io::{BufRead, BufReader};
    use tempfile::tempdir;

    /// The guest case (#1204). A task running in a `minimald` session
    /// expands `~/` against the session's own home — a real, writable
    /// directory — where the daemon's ambient home is `/` (it is pid 1 in the
    /// guest) and expanding against that produced `/.claude.json` on a
    /// read-only rootfs. Both halves are asserted here: the session home
    /// resolves and expands, and `/` is still refused for the case where
    /// there is no session home to borrow.
    #[test]
    fn a_session_home_expands_where_the_ambient_one_is_refused() {
        let patches = EnvPatches {
            file: [("~/.claude.json".to_string(), mfile::PatchSetting::ReadWrite)].into(),
            ..Default::default()
        };

        let session = PatchHome::Session(
            paths::DaemonAbsPath::try_new("/var/lib/minimal/sessions/s1/home").unwrap(),
        );
        let home = session.resolve().expect("a session always has a home");
        assert_eq!(
            patches.to_fs_mappings(Some(&home)).unwrap()[0].host_path,
            "/var/lib/minimal/sessions/s1/home/.claude.json",
        );

        assert!(
            patches.to_fs_mappings(Some(Path::new("/"))).is_err(),
            "a pid-1 daemon with no session home to offer must still refuse `/`"
        );
    }

    /// A patch path a package declared is attributed to that package; one
    /// that only the task's own `patch` table names falls back to the task.
    /// The attribution is what makes a failure to map `~/.claude.json`
    /// actionable — the path alone doesn't say who asked for it (#1204).
    #[test]
    fn declared_by_names_the_package_then_the_task() {
        let packages =
            BTreeMap::from_iter([("~/.claude.json".to_string(), "claude-code".to_string())]);
        assert_eq!(
            declared_by(&packages, "~/.claude.json", "test"),
            "package `claude-code`"
        );
        assert_eq!(
            declared_by(&packages, "~/.npmrc", "test"),
            "task `test`",
            "a path no package declared came from the task's own patch table"
        );
    }

    /// Helper: build a Context and Graph from the fakerepo test data,
    /// matching the pattern used in lib.rs tests.
    fn setup_ctx_and_graph() -> (TempDir, Context, Graph) {
        let state = tempdir().unwrap();
        let manifest_dir =
            std::path::Path::new(&std::env::var("CARGO_MANIFEST_DIR").unwrap()).to_path_buf();
        let config = ConfigBuilder::new()
            .with_state_dir(state.path().to_path_buf())
            .with_repo_dir(manifest_dir.join("testdata").join("fakerepo"))
            .with_stdlib_dir(manifest_dir.join("../stdlib/minimal-ncl"))
            .with_no_fetch(true)
            .build()
            .unwrap();

        let mut ctx = Context::new(config).unwrap();
        let mut graph = ctx.graph_from_all_packages().unwrap();
        graph.top_levels = vec![];
        (state, ctx, graph)
    }

    /// Helper: read all available lines from a UnixStream reader.
    fn read_lines(stream: &std::os::unix::net::UnixStream) -> Vec<String> {
        stream
            .set_nonblocking(true)
            .expect("set_nonblocking failed");
        let reader = BufReader::new(stream);
        reader.lines().map_while(|l| l.ok()).collect()
    }

    #[test]
    fn env_channel_errs_unknown_command() {
        let (state_dir, mut ctx, mut graph) = setup_ctx_and_graph();
        let mut chan = EnvChannel {
            graph: &mut graph,
            ctx: &mut ctx,
            task_name: "test-task".to_string(),
            state_dir: state_dir.path().to_path_buf(),
            has_packages: HashSet::new(),
            ot: None,
            daemon_id: None,
        };

        let (mut ours, theirs) = std::os::unix::net::UnixStream::pair().unwrap();
        let rootfs = tempdir().unwrap();
        chan.handle(&mut ours, "garbage-input", rootfs.path());
        drop(ours);

        let lines = read_lines(&theirs);
        assert_eq!(lines.len(), 1);
        assert!(
            lines[0].contains("error: unhandled input 'garbage-input'"),
            "unexpected output: {:?}",
            lines
        );
    }

    #[test]
    fn env_channel_search() {
        let (state_dir, mut ctx, mut graph) = setup_ctx_and_graph();
        let mut chan = EnvChannel {
            graph: &mut graph,
            ctx: &mut ctx,
            task_name: "test-task".to_string(),
            state_dir: state_dir.path().to_path_buf(),
            has_packages: HashSet::new(),
            ot: None,
            daemon_id: None,
        };

        let (mut ours, theirs) = std::os::unix::net::UnixStream::pair().unwrap();
        let rootfs = tempdir().unwrap();
        // "uroot" is a known package in the fakerepo fixture
        chan.handle(&mut ours, "search%uroot", rootfs.path());
        drop(ours);

        let lines = read_lines(&theirs);
        assert!(
            lines.iter().any(|l| l.contains("uroot")),
            "expected 'uroot' in search results, got: {:?}",
            lines
        );
    }

    #[test]
    fn env_channel_add_session_errs_unknown_pkg() {
        let (state_dir, mut ctx, mut graph) = setup_ctx_and_graph();
        let mut chan = EnvChannel {
            graph: &mut graph,
            ctx: &mut ctx,
            task_name: "test-task".to_string(),
            state_dir: state_dir.path().to_path_buf(),
            has_packages: HashSet::new(),
            ot: None,
            daemon_id: None,
        };

        let (mut ours, theirs) = std::os::unix::net::UnixStream::pair().unwrap();
        let rootfs = tempdir().unwrap();
        chan.handle(&mut ours, "add-session%nonexistent-pkg-xyz", rootfs.path());
        drop(ours);

        let lines = read_lines(&theirs);
        assert_eq!(lines.len(), 1);
        assert!(
            lines[0].contains("error: no such package"),
            "unexpected output: {:?}",
            lines
        );
    }

    #[test]
    fn env_channel_add_session() {
        let (state_dir, mut ctx, mut graph) = setup_ctx_and_graph();
        let rootfs = ctx.daemon.cache.temp_dir().unwrap();
        let mut chan = EnvChannel {
            graph: &mut graph,
            ctx: &mut ctx,
            task_name: "test-task".to_string(),
            state_dir: state_dir.path().to_path_buf(),
            has_packages: HashSet::new(),
            ot: None,
            daemon_id: None,
        };

        assert!(!std::fs::exists(rootfs.path().join("bin")).unwrap());

        let (mut ours, theirs) = std::os::unix::net::UnixStream::pair().unwrap();
        chan.handle(&mut ours, "add-session%uroot", rootfs.path());
        drop(ours);

        let lines = read_lines(&theirs);
        assert_eq!(lines.len(), 1);
        assert!(
            lines[0].contains("msg:Installed uroot"),
            "unexpected output: {:?}",
            lines
        );
        assert_eq!(
            chan.has_packages,
            HashSet::from_iter([*chan.graph.by_name("uroot").unwrap()])
        );
        assert!(std::fs::exists(rootfs.path().join("bin")).unwrap());
    }
}
