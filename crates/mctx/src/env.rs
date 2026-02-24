use std::{
    collections::{HashMap, HashSet},
    io::Write,
    path::{Path, PathBuf},
};

use graph::{BuildSpecRef, DepGraph, SetupForPackages, Transitives, TransitivesDep};
use mfile::EnvPatches;
use sandbox2::{Container, config::SandboxMapped};
use tempfile::TempDir;

use crate::{AddDepMode, Context, Error};

#[allow(dead_code)]
struct EnvChannel<'a> {
    graph: &'a mut DepGraph,
    ctx: &'a mut Context,

    has_packages: HashSet<BuildSpecRef>,
}

impl EnvChannel<'_> {
    fn install(
        &mut self,
        pkgs: &Vec<(&str, BuildSpecRef)>,
        stream: &mut std::os::unix::net::UnixStream,
        rootfs: &Path,
    ) {
        pkgs.iter().for_each(|(_n, bsr)| {
            if !self.graph.top_levels.contains(bsr) {
                self.graph.top_levels.push(*bsr);
            }
        });
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        if let Err(e) = rt.block_on(self.ctx.build_graph(self.graph)) {
            writeln!(stream, "error: {}", e).ok();
            return;
        };

        let transitives = Transitives::for_toplevels(
            self.graph,
            pkgs.iter().map(|(_n, bsr)| *bsr).collect(),
            false,
        );
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
            "msg: installed {}",
            pkgs.iter().map(|t| t.0).collect::<Vec<_>>().join(", ")
        )
        .ok();
    }

    fn parse_pkgs_line<'a>(
        &self,
        comma_separated_pkgs: &'a str,
    ) -> Result<Vec<(&'a str, BuildSpecRef)>, &'a str> {
        comma_separated_pkgs
            .split(",")
            .map(|n| match self.graph.by_name(n) {
                None => Err(n),
                Some(bsr) => Ok((n, *bsr)),
            })
            .collect()
    }
}

impl sandbox2::Channel for EnvChannel<'_> {
    fn handle(&mut self, stream: &mut std::os::unix::net::UnixStream, line: &str, rootfs: &Path) {
        // handle, eg: echo 'add-ephemeral%mermaid-ascii' | socat -,ignoreeof UNIX-CONNECT:/run/minenv_sock

        let add_dep = match line.split_once("%") {
            Some(("add-ephemeral", pkgs)) => match self.parse_pkgs_line(pkgs) {
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
            Some(("add-tool", pkgs)) => match self.parse_pkgs_line(pkgs) {
                Err(n) => {
                    writeln!(stream, "error: no such package '{}'", n).ok();
                    None
                }
                Ok(pkgs) => {
                    self.install(&pkgs, stream, rootfs);
                    Some((AddDepMode::ToolPackages, pkgs))
                }
            },
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
    /// A symbolic name for the environment.
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
    pub env_vars: Option<&'a HashMap<String, String>>,
    /// The hostname to set, if any.
    pub hostname: Option<String>,
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
        graph: &'a mut DepGraph,
        args: EnvArgs<'a>,
    ) -> Result<Self, Error> {
        let base_dir = ctx.config.task_base_dir();

        let SetupForPackages {
            fs_mappings: mut patch,
            needs_dns,
            needs_internet,
            state_dirs,
            env_vars: mut pkg_env_vars,
        } = graph
            .env_config_for_packages(args.transitives.keys())
            .map_err(|e| Error::Other(anyhow::anyhow!("{}", e)))?;

        if let Some(p) = args.patches {
            patch.union(p);
        }
        if let Some(vars) = args.env_vars {
            pkg_env_vars.extend(vars.clone());
        }

        let mut config = sandbox2::config::Config::new(args.name)
            .with_wd(args.cwd, false, patch.into())
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
            .with_dns(needs_dns)
            .with_disable_networking(!needs_dns && !needs_internet)
            .with_env_vars(pkg_env_vars.into_iter());
        if let Some(hn) = &args.hostname {
            config = config.with_hostname(hn);
        }

        let mut sandbox = config
            .build(
                base_dir,
                EnvChannel {
                    ctx,
                    graph,
                    has_packages: args.transitives.keys().cloned().collect(),
                },
            )
            .await
            .map_err(|e| Error::Other(anyhow::anyhow!("{}", e)))?;
        for want_dir in state_dirs {
            std::fs::create_dir_all(args.state_base_dir.join(want_dir))
                .map_err(anyhow::Error::from)
                .map_err(Error::Other)?;
        }
        sandbox.keep_dir(false);

        Ok(Env {
            sandbox,
            temp_dirs: vec![],
        })
    }

    /// Gives temporary directories into the ownership of this env. Use this
    /// if you created a temporary directory for `state_base_dir` and want it to be
    /// cleaned up along with this environment.
    pub fn associate_tempdirs<I: IntoIterator<Item = TempDir>>(&mut self, dirs: I) {
        self.temp_dirs.extend(dirs);
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
}
