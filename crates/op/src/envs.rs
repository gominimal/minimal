use std::{collections::HashMap, path::Path};

use crate::{Error, Options, Runnable};
use graph::{BuildSpecRef, SetupForPackages, TransitivesDep};
use mfile::EnvPatches;
use sandbox2::{Container, config::SandboxMapped};
use tempfile::TempDir;

/// Considers the transitive deps & toplevels which are going into the a runnable environment, and constructs
/// scaffolding as necessary.
///
/// Necessary dependencies are mapped into the given `opts.exec_base`, along with state wiring in `state_base_dir`.
pub struct EnvSetup<'a> {
    /// A human-readable name for this sandbox.
    pub name: &'a str,

    /// The `/state` dir that should live between invocations.
    ///
    /// Call `mfile::File::env_state_dir` to get this value for a minimalfile environment.
    pub state_base_dir: &'a Path,

    /// The 'top level' packages that were called for in this environment.
    pub top_levels: &'a Vec<BuildSpecRef>,
    /// All packages that will be called for in this environment (transitive dependencies).
    ///
    /// Call `Transitives::for_toplevels` to get this list.
    pub transitives: &'a HashMap<BuildSpecRef, TransitivesDep>,

    /// The working directory to use for this environment.
    pub cwd: &'a Path,
    /// File/directory mounts in the environment, if any.
    pub patches: Option<&'a EnvPatches>,
    /// Environment variables, if any.
    pub env_vars: Option<&'a HashMap<String, String>>,
    /// The hostname to set in the environment, if any.
    pub hostname: Option<String>,
}

impl<'a> Runnable for EnvSetup<'a> {
    type Result = RunnableEnv;

    async fn run<'b>(&mut self, opts: &Options<'b>) -> Result<Self::Result, Error> {
        // Collect wiring needed by packages, then apply any config at our level (i.e. env vars)
        // to these settings.
        let SetupForPackages {
            fs_mappings: mut patch,
            needs_dns,
            needs_internet,
            state_dirs,
            mut env_vars,
        } = opts
            .graph
            .env_config_for_packages(self.transitives.keys())
            .map_err(anyhow::Error::from)?;

        if let Some(patches) = self.patches {
            patch.union(patches); // patches set on [EnvSetup] take precedence
        }
        if let Some(vars) = self.env_vars {
            env_vars.extend(vars.clone()); // env vars set on [EnvSetup] take precedence
        }

        let config = sandbox2::config::Config::new(self.name)
            .with_wd(self.cwd, false, patch.into())
            .with_rootfs(
                self.transitives
                    .keys()
                    .map(|bsr| opts.cache.read_dir(&opts.graph.spec_hash(bsr)))
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|e| Error::Other(anyhow::anyhow!("loading dependency: {}", e)))?
                    .into_iter()
                    .map(|ce| SandboxMapped::Dir(ce.path().to_path_buf())),
            )
            .with_state_dir(self.state_base_dir)
            .with_dns(needs_dns)
            .with_disable_networking(!needs_dns && !needs_internet)
            .with_env_vars(env_vars.into_iter());

        let sandbox = config.build(&opts.exec_base).await?;
        for want_dir in state_dirs {
            std::fs::create_dir_all(self.state_base_dir.join(want_dir))
                .map_err(anyhow::Error::from)?;
        }

        Ok(RunnableEnv {
            sandbox,
            temp_dirs: vec![],
        })
    }
}

/// Describes a successfully-configured runtime environment.
pub struct RunnableEnv {
    sandbox: sandbox2::Sandbox,
    temp_dirs: Vec<TempDir>,
}

impl RunnableEnv {
    /// Gives temporary directories into the ownership of the runnable env. Use this
    /// if you created a temporary directory for `state_base_dir` and want it to be
    /// cleaned up along with this environment.
    pub fn associate_tempdirs<I: IntoIterator<Item = TempDir>>(&mut self, dirs: I) {
        self.temp_dirs.extend(dirs);
    }

    pub fn container(&mut self) -> Result<sandbox2::Container, Error> {
        self.sandbox.new_container().map_err(|e| e.into())
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
            .map_err(|e| e.into())
    }
}
