use std::{collections::HashSet, path::PathBuf};

use anyhow::anyhow;
use cache::{CacheErr, MetaInner};
use graph::{BuildSpec, BuildSpecRef, SubsetInput, Transitives, dep_graph::SpecTest};

use crate::{Error, Options, Runnable, SubsetBuild};

pub struct StandaloneTestError {
    pub program: String,
    pub args: Vec<String>,
    pub exit_code: i32,
}

/// Runs the standalone spec test with the given name, returning an error if it fails.
pub struct StandaloneTest<'a> {
    pub spec: &'a BuildSpecRef,
    pub test_name: &'a str,
}

impl<'a> StandaloneTest<'a> {
    async fn dependencies(
        &self,
        build: &BuildSpec,
        test: &SpecTest,
        opts: &Options<'a>,
    ) -> Result<(HashSet<PathBuf>, bool, bool), Error> {
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
                    dependencies.insert(cache_dir.path().to_path_buf());
                }
                // Subset
                Some(outputs) => {
                    let subset = SubsetInput {
                        from: bsr,
                        outputs: outputs.into_iter().collect(),
                    };
                    let subset_hash = opts.graph.subset_hash(&subset);

                    // If the subset exists use it, otherwise build it
                    dependencies.insert(
                        match opts.cache.read_dir(&subset_hash) {
                            Ok(cache_dir) => cache_dir,
                            Err(CacheErr::NotFound) => {
                                let mut sb = SubsetBuild {
                                    subset: &subset,
                                    from_dir: None,
                                };
                                let pending_dir = sb.run(opts).await?;
                                pending_dir.finalize(cache::EntryMeta {
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
                    );
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

    fn invocations(&self, test: &SpecTest) -> Result<Vec<(String, Vec<String>)>, Error> {
        if test.cmds.is_empty() || test.cmds[0].is_empty() {
            return Err(Error::Other(anyhow!(
                "cannot test spec: no test command specified"
            )));
        }

        Ok(test
            .cmds
            .iter()
            .filter_map(|e| e.split_at_checked(1))
            .map(|(exec, args)| (exec[0].clone(), args.to_vec()))
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

        let (mut dep_paths, needs_dns, needs_internet) =
            self.dependencies(build, test, opts).await?;
        let synth_files = opts.cache.temp_dir()?;
        if needs_dns {
            common::synth_dns_config(synth_files.path()).map_err(anyhow::Error::from)?;
        }
        dep_paths.insert(synth_files.path().to_path_buf());

        // Hardlink in the files which represent each dependency.
        for dep in dep_paths {
            common::hardlink_dir_contents(&dep, &opts.exec_base).map_err(anyhow::Error::from)?;
        }

        let mut container = hakoniwa::Container::new();
        container
            .rootfs(&opts.exec_base)
            .map_err(anyhow::Error::from)?
            .devfsmount("/dev")
            .symlink("/usr/bin", "/bin")
            .symlink("/usr/lib", "/lib64");

        std::fs::create_dir_all(opts.exec_base.join("tmp"))?;
        container.bindmount_rw(opts.exec_base.join("tmp").to_str().unwrap(), "/tmp");

        std::fs::create_dir_all(opts.exec_base.join("etc"))?;
        std::fs::write(opts.exec_base.join("etc").join("hostname"), "test\n")?;
        container.unshare(hakoniwa::Namespace::Uts);
        container.hostname("test");
        if !needs_dns && !needs_internet {
            container.unshare(hakoniwa::Namespace::Network);
        }

        let mut out = Vec::new();
        for (program, args) in self.invocations(test)? {
            let mut command = container.command(&program);
            command
                .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
                .env("LANG", "en_US.utf8")
                .env("LC_ALL", "en_US.utf8")
                .env("HOME", "/tmp");
            command.args(args.clone());
            command.current_dir("/tmp");
            command.stdin(hakoniwa::Stdio::Inherit);
            command.stdout(hakoniwa::Stdio::Inherit);
            command.stderr(hakoniwa::Stdio::Inherit);

            let exec_result = command.status().map_err(anyhow::Error::from)?;
            if exec_result.code != 0 {
                out.push(StandaloneTestError {
                    program,
                    args,
                    exit_code: exec_result.code,
                });
            }
        }
        Ok(out)
    }
}
