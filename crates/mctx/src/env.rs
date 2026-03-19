use std::{
    collections::{HashMap, HashSet},
    fs::Permissions,
    io::Write,
    os::unix::{fs::PermissionsExt, net::UnixStream},
    path::{Path, PathBuf},
};

use crate::{AddDepMode, Context, Error};
use common::FsMapping;
use futures::stream::StreamExt;
use graph::{BuildSpecRef, Graph, SetupForPackages, Transitives, TransitivesDep};
use mfile::{EnvPatches, EnvVarValue};
use op::Runnable;
use sandbox2::{
    Container,
    config::{Invocation, SandboxMapped},
};
use tempfile::TempDir;

#[allow(dead_code)]
struct EnvChannel<'a> {
    graph: &'a mut Graph,
    ctx: &'a mut Context,

    task_name: String,
    state_dir: PathBuf,
    has_packages: HashSet<BuildSpecRef>,
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

        pkgs.iter().for_each(|(_n, bsr)| {
            if !self.graph.top_levels.contains(bsr) {
                self.graph.top_levels.push(*bsr);
            }
        });
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        if let Err(e) = rt.block_on(self.ctx.build_graph(self.graph, None)) {
            writeln!(stream, "error: {}", e).ok();
            return;
        };

        let transitives = Transitives::for_toplevels(
            self.graph,
            pkgs.iter().map(|(_n, bsr)| *bsr).collect(),
            false,
        );
        match SetupForPackages::build(
            self.graph,
            transitives
                .keys()
                .filter(|bsr| !self.has_packages.contains(bsr)),
        ) {
            Ok(setup) => {
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
            if self.has_packages.insert(*bsr) {
                if let Err(e) = common::hardlink_dir_contents(
                    self.ctx
                        .cache
                        .read_dir(&self.graph.spec_hash(bsr))
                        .unwrap()
                        .path(),
                    rootfs,
                ) {
                    writeln!(stream, "error: {}", e).ok();
                    return;
                }
            }
        }
        writeln!(
            stream,
            "msg:Installed {}",
            pkgs.iter().map(|t| t.0).collect::<Vec<_>>().join(", ")
        )
        .ok();
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
        let mut flag_harnesses = false;
        let mut flag_profiles = false;
        let mut fix = false;
        let mut filter_names: Vec<String> = Vec::new();

        for token in args.split_whitespace() {
            match token {
                "--packages" => flag_packages = true,
                "--harnesses" => flag_harnesses = true,
                "--profiles" => flag_profiles = true,
                "--fix" => fix = true,
                _ => filter_names.push(token.to_string()),
            }
        }

        // If no kind flags specified, check everything (same as cmd_check default).
        let check_all = !flag_packages && !flag_harnesses && !flag_profiles;

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
            if check_all || flag_profiles {
                Some(upstream_dir.join("profiles"))
            } else {
                None
            },
            if check_all || flag_harnesses {
                Some(upstream_dir.join("harnesses"))
            } else {
                None
            },
            check_ctx.stdlib_dir().to_path_buf(),
            &filter_names,
            Some(graph),
            check_ctx.local_cache(),
            fix,
            &[],
        ) {
            Err(e) => return EnvChannel::write_error(e.into(), stream),
            Ok(res_stream) => res_stream,
        };
        let rt = tokio::runtime::Builder::new_current_thread()
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
        let rt = tokio::runtime::Builder::new_current_thread()
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

        let rt = tokio::runtime::Builder::new_current_thread()
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
                    .for_each(|(bsr, n)| {
                        if *n < 8 {
                            return;
                        }
                        let name = &self.graph.get(bsr).unwrap().name;
                        if name.ends_with(" (prebuilt)") {
                            return;
                        }

                        writeln!(stream, "msg: * {}", name).ok();
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

        if let Some((add_mode, pkgs)) = add_dep {
            if let Err(e) = self.ctx.add_deps(
                self.graph,
                pkgs.into_iter().map(|a| a.1).collect::<Vec<_>>(),
                add_mode,
            ) {
                writeln!(stream, "error: {}", e).ok();
            }
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

    /// Environment variables to set.
    pub env_vars: Option<&'a HashMap<String, EnvVarValue>>,
    /// The hostname to set, if any.
    pub hostname: Option<String>,

    /// If set, enables or disables networking.
    pub override_disable_networking: Option<bool>,
}

/// A successfully-configured runtime environment.
pub struct Env<'a> {
    cwd: PathBuf,
    claude_md_already_exists: bool,
    sandbox: sandbox2::Sandbox<EnvChannel<'a>>,
    temp_dirs: Vec<TempDir>,
}

impl<'a> Drop for Env<'a> {
    fn drop(&mut self) {
        // Because we bind-mount in a mutated or new CLAUDE.md file, we always leave behind
        // such a file on the filesystem when we exit. We detect if the file is empty, and if so
        // yeet it, to avoid polluting the users' repository.
        if !self.claude_md_already_exists {
            let claude_md = self.cwd.join("CLAUDE.md");
            match std::fs::metadata(&claude_md) {
                Err(_) => {}
                Ok(stat) => {
                    if stat.len() == 0 {
                        let _ = std::fs::remove_file(claude_md);
                    }
                }
            }
        }
    }
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
        let base_dir = ctx.config.task_base_dir();

        let SetupForPackages {
            fs_mappings: mut patch,
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
        let mut fs_mappings: Vec<FsMapping> = patch.into();

        let claude_md_already_exists = args.cwd.join("CLAUDE.md").exists();
        let llm_inject_dir = ctx
            .local_cache()
            .temp_dir()
            .map_err(|e| Error::Other(anyhow::anyhow!("making temp dir: {}", e)))?;
        {
            // Create or upsert the CLAUDE.md.
            let claude_md = llm_inject_dir.path().join("CLAUDE.md");
            let mut f = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&claude_md)
                .map_err(|e| Error::IO("open CLAUDE.md", claude_md.clone(), e))?;
            if let Ok(data) = std::fs::read(args.cwd.join("CLAUDE.md")) {
                f.write_all(&data)
                    .map_err(|e| Error::IO("prefill CLAUDE.md", claude_md.clone(), e))?;
            }
            f.write_all(LLM_APPEND_INSTRUCTIONS.as_bytes())
                .map_err(|e| Error::IO("write CLAUDE.md", claude_md.clone(), e))?;

            let sandbox_path = args.cwd.join("CLAUDE.md");
            let already_patched_by_user = fs_mappings
                .iter()
                .any(|m| m.host_path == sandbox_path.to_str().unwrap());
            if !already_patched_by_user {
                fs_mappings.push(FsMapping {
                    host_path: claude_md.to_str().unwrap().to_string(),
                    is_file: true,
                    read_only: true,
                    create_if_missing: false,
                    sandbox_path: Some(sandbox_path.to_str().unwrap().to_string()),
                });
            }
        }

        let mut config = sandbox2::config::Config::new(args.name)
            .with_wd(args.cwd.clone(), false, fs_mappings)
            .with_rootfs(
                args.transitives
                    .keys()
                    .map(|bsr| ctx.cache.read_dir(&graph.spec_hash(bsr)))
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|e| Error::Other(anyhow::anyhow!("loading dependency: {}", e)))?
                    .into_iter()
                    .map(|ce| SandboxMapped::Dir(ce.path().to_path_buf())),
            )
            .with_state_dir(&args.state_base_dir)
            .with_dns(
                args.override_disable_networking
                    .map(|v| !v)
                    .unwrap_or(needs_dns),
            )
            .with_disable_networking(
                args.override_disable_networking
                    .unwrap_or(!needs_dns && !needs_internet),
            )
            .with_env_vars(pkg_env_vars.into_iter());
        if let Some(hn) = &args.hostname {
            config = config.with_hostname(hn);
        }
        if let Ok(username) = std::env::var("USER") {
            config = config.with_username(username);
        }

        let mut sandbox = config
            .build(
                base_dir,
                EnvChannel {
                    ctx,
                    graph,
                    task_name: args.name.to_string(),
                    state_dir: args.state_base_dir.clone(),
                    has_packages: args.transitives.keys().cloned().collect(),
                },
            )
            .await?;
        for want_dir in state_dirs {
            std::fs::create_dir_all(args.state_base_dir.join(&want_dir)).map_err(|e| {
                Error::IO("creating state dir", args.state_base_dir.join(want_dir), e)
            })?;
        }
        install_min_helpers(sandbox.rootfs())
            .map_err(|e| Error::IO("installing min helpers", sandbox.rootfs(), e))?;

        sandbox.keep_dir(false);

        Ok(Env {
            cwd: args.cwd,
            sandbox,
            claude_md_already_exists: claude_md_already_exists,
            temp_dirs: vec![llm_inject_dir],
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
        parsed_args: Option<&toml::Value>,
    ) -> Result<(bool, Vec<Invocation>), Error> {
        let base = [("task_packages", task.packages.clone().into())].into_iter();
        let var_ctx = if let Some(args) = parsed_args {
            let table = args
                .as_table()
                .ok_or_else(|| Error::Other(anyhow::anyhow!("parsed_args is not a table")))?;
            common::ncl_eval::VarCtx::new(
                base.chain(table.iter().map(|(k, v)| (k.as_str(), v.clone()))),
            )
        } else {
            common::ncl_eval::VarCtx::new(base)
        };

        Ok((
            task.interactive,
            op::TaskEnv {
                task: &task
                    .map_exec_strings(|s| {
                        var_ctx
                            .eval_string(s)
                            .map_err(|_| anyhow::anyhow!("nickel eval failed for string: {}", s))
                    })
                    .map_err(Error::Other)?,
                sandbox: &mut self.sandbox,
            }
            .resolve()
            .await
            .map_err(|e| Error::Other(anyhow::anyhow!("{}", e)))?,
        ))
    }

    pub fn container(&mut self) -> Result<Container, Error> {
        self.sandbox
            .new_container()
            .map_err(|e| Error::Other(anyhow::anyhow!("{}", e)))
    }

    pub fn command<I, S>(
        &mut self,
        container: &Container,
        program: &str,
        args: I,
    ) -> Result<hakoniwa::Command, Error>
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
        self.sandbox
            .run(invocations, stdout_writer, stderr_writer)
            .await
            .map_err(Error::from)
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

const LLM_APPEND_INSTRUCTIONS: &str = include_str!("llm_append_instructions.txt");

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
        let mut chan = EnvChannel {
            graph: &mut graph,
            ctx: &mut ctx,
            task_name: "test-task".to_string(),
            state_dir: state_dir.path().to_path_buf(),
            has_packages: HashSet::new(),
        };

        let rootfs = tempdir().unwrap();
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
