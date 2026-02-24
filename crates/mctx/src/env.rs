use std::{collections::HashMap, path::Path};

use graph::{BuildSpecRef, DepGraph, SetupForPackages, TransitivesDep};
use mfile::EnvPatches;
use sandbox2::{Container, config::SandboxMapped};
use tempfile::TempDir;

use crate::{Context, Error};

#[allow(dead_code)]
struct EnvChannel<'a> {
    graph: &'a DepGraph,
    ctx: &'a mut Context,
}

impl sandbox2::Channel for EnvChannel<'_> {
    fn handle(
        &self,
        stream: &mut std::os::unix::net::UnixStream,
        line: &str,
        _rootfs: &Path,
    ) -> bool {
        use std::io::Write;
        writeln!(stream, "error: unhandled input '{}'", line).unwrap();
        // TODO: do stuff with self.graph, self.cache, self.mfile
        false
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
    #[allow(clippy::too_many_arguments)]
    pub async fn build(
        ctx: &'a mut Context,
        name: &str,
        state_base_dir: &Path,
        transitives: &HashMap<BuildSpecRef, TransitivesDep>,
        cwd: &Path,
        patches: Option<&EnvPatches>,
        env_vars: Option<&HashMap<String, String>>,
        hostname: Option<String>,
        graph: &'a DepGraph,
        exec_base: std::path::PathBuf,
    ) -> Result<Self, Error> {
        let SetupForPackages {
            fs_mappings: mut patch,
            needs_dns,
            needs_internet,
            state_dirs,
            env_vars: mut pkg_env_vars,
        } = graph
            .env_config_for_packages(transitives.keys())
            .map_err(|e| Error::Other(anyhow::anyhow!("{}", e)))?;

        if let Some(p) = patches {
            patch.union(p);
        }
        if let Some(vars) = env_vars {
            pkg_env_vars.extend(vars.clone());
        }

        let mut config = sandbox2::config::Config::new(name)
            .with_wd(cwd, false, patch.into())
            .with_rootfs(
                transitives
                    .keys()
                    .map(|bsr| ctx.cache.read_dir(&graph.spec_hash(bsr)))
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|e| Error::Other(anyhow::anyhow!("loading dependency: {}", e)))?
                    .into_iter()
                    .map(|ce| SandboxMapped::Dir(ce.path().to_path_buf())),
            )
            .with_state_dir(state_base_dir)
            .with_dns(needs_dns)
            .with_disable_networking(!needs_dns && !needs_internet)
            .with_env_vars(pkg_env_vars.into_iter());
        if let Some(hn) = &hostname {
            config = config.with_hostname(hn);
        }

        let mut sandbox = config
            .build(&exec_base, EnvChannel { graph, ctx })
            .await
            .map_err(|e| Error::Other(anyhow::anyhow!("{}", e)))?;
        for want_dir in state_dirs {
            std::fs::create_dir_all(state_base_dir.join(want_dir))
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
