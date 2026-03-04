use std::collections::HashSet;

use anyhow::anyhow;
use graph::{BuildSpec, BuildSpecRef, SpecTest, SubsetInput, Transitives};
use lcache::{CacheErr, MetaInner};
use sandbox2::config::SandboxMapped;

use crate::{Error, Options, Runnable, SubsetBuild};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StandaloneTestError {
    pub program: String,
    pub args: Vec<String>,
    pub exit_code: i32,
}

/// Runs the standalone spec test with the given name, returning an error if it fails.
pub struct StandaloneTest<'a> {
    pub spec: &'a BuildSpecRef,
    pub test_name: &'a str,
    /// Optional async writer that receives a copy of the sandbox's stdout stream.
    pub stdout_writer: Option<Box<dyn tokio::io::AsyncWrite + Unpin + Send + Sync>>,
    /// Optional async writer that receives a copy of the sandbox's stderr stream.
    pub stderr_writer: Option<Box<dyn tokio::io::AsyncWrite + Unpin + Send + Sync>>,
}

impl<'a> StandaloneTest<'a> {
    async fn dependencies(
        &self,
        build: &BuildSpec,
        test: &SpecTest,
        opts: &Options<'a>,
    ) -> Result<(HashSet<SandboxMapped>, bool, bool), Error> {
        let transitives = Transitives::for_toplevels(
            opts.graph,
            {
                let mut toplevels = test.deps.clone().unwrap_or_default().to_vec();
                toplevels.push(*self.spec);
                toplevels
            },
            false,
        );

        let mut dependencies = HashSet::new();
        let (mut needs_dns, mut need_internet) = (false, false);

        let build_deps: Vec<_> = transitives.into_iter().collect();
        for (bsr, dep_info) in build_deps.into_iter() {
            match dep_info.outputs {
                // Regular build
                None => {
                    let cache_dir = opts.cache.read_dir(&opts.graph.spec_hash(&bsr))?;
                    dependencies.insert(SandboxMapped::Dir(cache_dir.path().to_path_buf()));
                }
                // Subset
                Some(outputs) => {
                    let subset = SubsetInput {
                        from: bsr,
                        outputs: outputs.into_iter().collect(),
                    };
                    let subset_hash = opts.graph.subset_hash(&subset);

                    // If the subset exists use it, otherwise build it
                    dependencies.insert(SandboxMapped::Dir(
                        match opts.cache.read_dir(&subset_hash) {
                            Ok(cache_dir) => cache_dir,
                            Err(CacheErr::NotFound) => {
                                let mut sb = SubsetBuild {
                                    subset: &subset,
                                    from_dir: None,
                                };
                                let pending_dir = sb.run(opts).await?;
                                pending_dir.finalize(lcache::EntryMeta {
                                    inner: MetaInner::Subset(subset.as_spec(opts.graph)),
                                    fetched: false,
                                    origin: Some(build.from.as_ref().clone()),
                                    ..Default::default()
                                })?;

                                opts.cache.read_dir(&subset_hash)?
                            }
                            Err(e) => {
                                return Err(e.into());
                            }
                        }
                        .path()
                        .to_path_buf(),
                    ));
                }
            }

            needs_dns |= opts
                .graph
                .get(&bsr)
                .unwrap()
                .abstract_deps
                .get("dns")
                .is_some();
            need_internet |= opts
                .graph
                .get(&bsr)
                .unwrap()
                .abstract_deps
                .get("internet")
                .is_some();
        }
        Ok((dependencies, needs_dns, need_internet))
    }

    fn invocations(&self, test: &SpecTest) -> Result<Vec<sandbox2::config::Invocation>, Error> {
        if test.cmds.is_empty() || test.cmds[0].is_empty() {
            return Err(Error::Other(anyhow!(
                "cannot test spec: no test command specified"
            )));
        }

        Ok(test
            .cmds
            .iter()
            .filter_map(|e| e.split_at_checked(1))
            .map(|(exec, args)| sandbox2::config::Invocation {
                executable: exec[0].clone(),
                args: args.to_vec(),
                envs: Default::default(),
            })
            .collect())
    }
}

impl<'a> Runnable for StandaloneTest<'a> {
    type Result = Vec<StandaloneTestError>;

    async fn run<'b>(&mut self, opts: &Options<'b>) -> Result<Self::Result, Error> {
        let build = opts.graph.get(self.spec).unwrap();
        let test = match build
            .tests
            .as_ref()
            .and_then(|tests| tests.get(self.test_name))
        {
            None => {
                return Err(Error::Other(anyhow!("no such test: {}", self.test_name)));
            }
            Some(t) => t,
        };
        if test.build_test {
            return Err(Error::Other(anyhow!(
                "test {} is not a standalone test",
                self.test_name
            )));
        }

        let (deps, needs_dns, needs_internet) = self.dependencies(build, test, opts).await?;

        let config = sandbox2::config::Config::new("test")
            .with_rootfs(deps.into_iter())
            .with_dns(needs_dns)
            .with_disable_networking(!needs_dns && !needs_internet)
            .with_hostname("test")
            .with_env_var("HOME", "/tmp");
        let mut sandbox = config.build(&opts.exec_base, ()).await?;

        let invocations = self.invocations(test)?;
        match sandbox
            .run(
                invocations.clone(),
                self.stdout_writer.take(),
                self.stderr_writer.take(),
            )
            .await
        {
            Ok(()) => Ok(vec![]),
            Err(sandbox2::Error::Execution(
                sandbox2::error::ExecutionError::InvocationFailed { idx, code, .. },
            )) => {
                let inv = &invocations[idx];
                Ok(vec![StandaloneTestError {
                    program: inv.executable.clone(),
                    args: inv.args.clone(),
                    exit_code: code,
                }])
            }
            Err(e) => Err(e.into()),
        }
    }
}
