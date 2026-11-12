use std::{
    collections::{BTreeSet, HashSet},
    path::PathBuf,
    time::Instant,
};

use crate::{Error, Materialized, Options, Runnable, SubsetBuild};
use anyhow::anyhow;
use common::Target;
use globset::GlobSet;
use graph::{BuildDep, BuildSpec, BuildSpecRef, SubsetInput, Transitives};
use lcache::{CacheErr, MetaInner, PendingDir};
use ot::{OpTracker, Operation};
use sandbox::config::SandboxMapped;
use tracing::info;

/// The return value of a successful build of a build-spec.
pub struct SpecBuildResult {
    pub outputs: PendingDir,
    pub build_ms: usize,
}

/// Builds a spec, storing the resulting outputs in the cache.
pub struct SpecBuild<'a, SF: crate::SourceFetcher> {
    /// The spec to be built.
    pub spec: &'a BuildSpecRef,
    /// A fetcher which can be used to fetch sources.
    pub remote_fetcher: &'a SF,

    /// If set, overrides the set of dependencies injected into the build.
    /// If unset, the necessary dependencies are computed automatically.
    ///
    /// Does not override `Local` or `Source` variant build_deps - those will
    /// always be made present automatically.
    ///
    /// Ordered: `rootfs_mapped` passes these to the sandbox, which hardlinks
    /// them first-writer-wins, so iteration order must be deterministic.
    pub override_deps: Option<BTreeSet<PathBuf>>,

    /// Optional async writer that receives a copy of the sandbox's stdout stream.
    pub stdout_writer: Option<Box<dyn tokio::io::AsyncWrite + Unpin + Send + Sync>>,
    /// Optional async writer that receives a copy of the sandbox's stderr stream.
    pub stderr_writer: Option<Box<dyn tokio::io::AsyncWrite + Unpin + Send + Sync>>,

    /// Cancellation token to stop the build.
    pub cancel: tokio_util::sync::CancellationToken,

    /// CPU shares, for partitioning CPU when the system is contended. Maps roughly to
    /// cgroups v2 cpu.weights.
    pub cpu_weight: Option<u64>,

    /// The build box this build runs in, if it runs for a box (NET-155).
    /// `None` is a build outside any box: `mip`'s, which keeps the plan below.
    pub build_box: Option<crate::BuildBox>,

    /// A patched build (`override_deps` that a person chose): it always gets
    /// the network, and it counts as workspace (NET-169).
    pub patched: bool,
}

impl<'a, SF: crate::SourceFetcher> SpecBuild<'a, SF> {
    async fn build_deps_mapped<'b>(
        &mut self,
        build: &BuildSpec,
        opts: &Options<'b>,
        op: &OpTracker,
    ) -> Result<Vec<SandboxMapped>, Error> {
        let mut build_deps = Vec::new();

        for input in build.build_deps.iter() {
            match input {
                BuildDep::Local { full_path, .. } => {
                    build_deps.push(SandboxMapped::FileCopy(full_path.to_path_buf()))
                }
                BuildDep::Source(source) => {
                    let resolved_src = crate::SourceLoad {
                        source,
                        remote_fetcher: self.remote_fetcher,
                        into: None,
                        build_box: self.build_box.as_ref(),
                        package: &build.name,
                    }
                    .run(&Options {
                        ot: Some(op.to_owned()),
                        cache: opts.cache.clone(),
                        graph: opts.graph,
                        exec_base: opts.exec_base.clone(),
                        daemon_id: opts.daemon_id.clone(),
                    })
                    .await;
                    let resolved_src = match resolved_src {
                        Ok(resolved) => resolved,
                        Err(e) => {
                            self.report_failed_fetch(source, &e).await;
                            return Err(e);
                        }
                    };
                    match resolved_src {
                        Materialized::Given(_) => unreachable!(),
                        // A copy, not a hardlink: the path is the download cache's own file,
                        // and /build is writable, so a hardlink would let a build rewrite the
                        // cached source under a concurrent build of the same source
                        // (build-servers#231). The cache re-hashes on every hit, so only a
                        // reader already past that check could see the change.
                        Materialized::File(path) => build_deps.push(SandboxMapped::FileCopy(path)),
                        Materialized::TempDir(td) => build_deps.push(SandboxMapped::TempDir(td)),
                    }
                }
                BuildDep::Build(_) => {} // Handled by Transitives
                _ => todo!("input: {:?}", input),
            }
        }
        Ok(build_deps)
    }

    async fn rootfs_mapped(
        &self,
        build: &BuildSpec,
        opts: &Options<'a>,
    ) -> Result<(HashSet<SandboxMapped>, bool, bool), Error> {
        if let Some(deps) = &self.override_deps {
            // Outside a box, a build with overridden dependencies has always
            // had the network. In a box only a patched build does: any other
            // build's own `needs` decide (NET-155).
            let (needs_dns, needs_internet) = if self.build_box.is_none() || self.patched {
                (true, true)
            } else {
                crate::build_box::declared_needs(opts.graph, self.spec)
            };
            return Ok((
                deps.iter().map(|p| SandboxMapped::Dir(p.clone())).collect(),
                needs_dns,
                needs_internet,
            ));
        }

        let mut dependencies = HashSet::new();
        let transitives = Transitives::new(opts.graph, self.spec, true);

        let build_deps: Vec<_> = transitives.transitive_runtime_deps.into_iter().collect();
        for (bsr, dep_info) in build_deps.into_iter() {
            match dep_info.outputs {
                // Regular build
                None => {
                    let cache_dir = opts.cache.read_dir(&opts.graph.spec_hash(&bsr)).unwrap();
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
        }

        let (needs_dns, need_internet) = crate::build_box::declared_needs(opts.graph, self.spec);

        Ok((dependencies, needs_dns, need_internet))
    }

    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    fn invocations(&self, build: &BuildSpec) -> Result<Vec<(String, Vec<String>)>, Error> {
        if build.cmds.is_empty() || build.cmds[0].is_empty() {
            return Err(Error::Other(anyhow!(
                "cannot build spec: no build command specified"
            )));
        }

        Ok(build
            .cmds
            .iter()
            .filter_map(|e| e.split_at_checked(1))
            .map(|(exec, args)| (exec[0].clone(), args.to_vec()))
            .collect())
    }

    /// Runs the build invocations in the sandbox.
    #[cfg(target_os = "linux")]
    async fn execute_in_sandbox(
        &mut self,
        sandbox: &mut sandbox::Sandbox<()>,
        build: &BuildSpec,
    ) -> Result<(), Error> {
        sandbox
            .run_with_cancel(
                self.invocations(build)?
                    .into_iter()
                    .map(|(program, args)| sandbox::config::Invocation {
                        executable: program,
                        args,
                        envs: Default::default(),
                    })
                    .collect(),
                self.stdout_writer.take(),
                self.stderr_writer.take(),
                self.cancel.clone(),
            )
            .await
            .map_err(Error::from)
    }

    /// Sandbox execution is only available on Linux (hakoniwa).
    #[cfg(not(target_os = "linux"))]
    async fn execute_in_sandbox(
        &mut self,
        _sandbox: &mut sandbox::Sandbox<()>,
        _build: &BuildSpec,
    ) -> Result<(), Error> {
        Err(crate::sandbox_unsupported())
    }

    async fn materialize_prebuilt<'b>(
        &mut self,
        opts: &Options<'b>,
        build: &BuildSpec,
    ) -> Result<SpecBuildResult, Error> {
        if let BuildDep::Source(source) = &build.build_deps[0] {
            let start = Instant::now();
            let out_dir = opts
                .cache
                .write_dir(&opts.graph.spec_hash(self.spec))
                .unwrap();
            let resolved_src = crate::SourceLoad {
                source,
                remote_fetcher: self.remote_fetcher,
                into: Some(out_dir),
                build_box: self.build_box.as_ref(),
                package: &build.name,
            }
            .run(opts)
            .await;
            let resolved_src = match resolved_src {
                Ok(resolved) => resolved,
                Err(e) => {
                    self.report_failed_fetch(source, &e).await;
                    return Err(e);
                }
            };

            if let Materialized::Given(d) = resolved_src {
                let build_ms = Instant::now().duration_since(start).as_millis() as usize;
                Ok(SpecBuildResult {
                    outputs: d,
                    build_ms,
                })
            } else {
                panic!(
                    "prebuilt source materialized as non-tempdir: {:?}",
                    resolved_src
                );
            }
        } else {
            panic!("prebuilt input was not source: {:?}", build.build_deps[0]);
        }
    }
}

/// `url` without its credentials, its query and its fragment, or `None`
/// when it is not a URL.
pub(crate) fn stripped_url(url: &str) -> Option<String> {
    let mut parsed = url::Url::parse(url).ok()?;
    let _ = parsed.set_username("");
    let _ = parsed.set_password(None);
    parsed.set_query(None);
    parsed.set_fragment(None);
    Some(parsed.to_string())
}

/// `text` with each URL in it stripped as `stripped_url` strips one. A URL
/// runs from its scheme to the next space, quote, bracket or parenthesis.
/// One that does not parse is replaced whole, so no credential in it stays.
pub(crate) fn strip_urls(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find("://") {
        let start = rest[..at]
            .rfind(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.')))
            .map_or(0, |i| i + 1);
        let end = rest[at..]
            .find(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | '<' | '>' | '(' | ')'))
            .map_or(rest.len(), |i| at + i);
        out.push_str(&rest[..start]);
        if start == at {
            // No scheme before the `://`: not a URL.
            out.push_str(&rest[start..end]);
        } else {
            match stripped_url(&rest[start..end]) {
                Some(url) => out.push_str(&url),
                None => out.push_str("<url>"),
            }
        }
        rest = &rest[end..];
    }
    out.push_str(rest);
    out
}

impl<'a, SF: crate::SourceFetcher> SpecBuild<'a, SF> {
    /// Writes a web source this build could not fetch to the build's stderr
    /// (NET-155), so the output of a build placed for a box names the source
    /// and its host. A daemon that reads the output can then say which
    /// destination the box's egress rules refused. The URL is written without
    /// its credentials and its query.
    async fn report_failed_fetch(&mut self, source: &graph::SourceInput, e: &Error) {
        use tokio::io::AsyncWriteExt;
        let graph::SourceFetch::Web { url, .. } = &source.from else {
            return;
        };
        let Some(writer) = self.stderr_writer.as_mut() else {
            return;
        };
        let Some(shown) = stripped_url(url) else {
            return;
        };
        // The error can quote a URL too: reqwest's names the request's.
        let line = format!(
            "could not fetch the source {shown}: {}\n",
            strip_urls(&e.to_string())
        );
        let _ = writer.write_all(line.as_bytes()).await;
        let _ = writer.flush().await;
    }

    /// The sandbox configuration this build runs in. A build for a box runs
    /// in its build box (NET-155): an empty network namespace when it needs
    /// no network, and the build box's own network when it does, never the
    /// host's. Only a build outside any box gets the host plan.
    ///
    /// # Errors
    ///
    /// The refusal of a build that needs the network its build box does not
    /// have, before anything of the build runs.
    fn sandbox_config(
        &self,
        build: &BuildSpec,
        inputs: Vec<SandboxMapped>,
        rootfs: HashSet<SandboxMapped>,
        needs_dns: bool,
        needs_internet: bool,
        daemon_id: Option<&String>,
    ) -> Result<sandbox::config::Config, Error> {
        let needs_network = needs_dns || needs_internet;
        let mut config = sandbox::config::Config::new(&build.name)
            .with_isolated_wd(inputs.into_iter())
            .with_rootfs(rootfs.into_iter())
            .with_dns(needs_dns)
            // A build that needs neither DNS nor the internet runs in an empty
            // network namespace. Said as a plan rather than as a mode: a build
            // is not a PTask and has never had one, and the sandbox layer acts
            // on plans.
            .with_plan(if needs_network && self.build_box.is_none() {
                sandbox::NetPlan::host()
            } else {
                sandbox::NetPlan::isolated()
            });
        if let Some(a) = &build.build_args {
            config = config.with_build_args(a.iter());
        }
        if let Some(w) = self.cpu_weight {
            config = config.with_cpu_weight(w);
        }
        if let Some(id) = daemon_id {
            config = config.with_daemon_id(id.clone());
        }
        if let Some(build_box) = &self.build_box
            && needs_network
        {
            let Some(network) = build_box.opened() else {
                return Err(build_box.needs_network());
            };
            config = config.with_network(network.network());
        }
        Ok(config)
    }
}

impl<'a, SF: crate::SourceFetcher> Runnable for SpecBuild<'a, SF> {
    type Result = SpecBuildResult;

    async fn run<'b>(&mut self, opts: &Options<'b>) -> Result<Self::Result, Error> {
        let build = opts.graph.get(self.spec).unwrap();

        let build_op = OpTracker::new_with_root(&opts.ot).with_op(Operation::PackageBuild {
            name: build.name.clone(),
        });

        // Special case: prebuilts
        if build.is_pure_prebuilt() {
            return self.materialize_prebuilt(opts, build).await;
        }
        if build.is_pure_collection() {
            // A collection is an empty package that only has runtime deps, so lets just commit an empty package
            return Ok(SpecBuildResult {
                outputs: opts.cache.write_dir(&opts.graph.spec_hash(self.spec))?,
                build_ms: 0,
            });
        }
        if build.target != Target::host() {
            return Err(Error::Other(anyhow!(
                "cannot build spec with target {} on {}",
                build.target.as_ref(),
                Target::host().as_ref()
            )));
        }

        let inputs = self.build_deps_mapped(build, opts, &build_op).await?;
        let (rootfs, needs_dns, needs_internet) = self.rootfs_mapped(build, opts).await?;

        // A build that declares no network has fetched all it will: its
        // grant ends here, and its steps run with no address (NET-167). A
        // process on the build box's network waits for room on it.
        let _network_slot = match &self.build_box {
            Some(build_box) if needs_dns || needs_internet => match build_box.network().await {
                Some(network) => Some(network.slot().await),
                None => None,
            },
            Some(build_box) => {
                build_box.close().await;
                None
            }
            None => None,
        };

        let channel = ();

        let config = self.sandbox_config(
            build,
            inputs,
            rootfs,
            needs_dns,
            needs_internet,
            opts.daemon_id.as_ref(),
        )?;
        let mut sandbox = config.build(&opts.exec_base, channel).await?;
        sandbox.keep_dir(true);

        info!("Building package: {}", build.name);
        let start = Instant::now();
        self.execute_in_sandbox(&mut sandbox, build).await?;
        let build_ms = Instant::now().duration_since(start).as_millis() as usize;

        let out_dir = opts
            .cache
            .write_dir(&opts.graph.spec_hash(self.spec))
            .unwrap();

        build_op.set_op(Operation::CollectOutputs {
            name: build.name.clone(),
            outputs: build.outputs.iter().map(|(n, _)| n.clone()).collect(),
        });

        // Build individual globs for each output so we can verify each one matched
        let output_globs: Vec<(String, globset::Glob)> = build
            .outputs
            .iter()
            .map(|(name, o)| {
                globset::GlobBuilder::new(o.glob())
                    .literal_separator(true)
                    .empty_alternates(true)
                    .build()
                    .map(|g| (name.clone(), g))
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| Error::Other(anyhow!(e)))?;

        {
            // Match the outputs into their final destination
            sandbox.match_outputs_into(
                GlobSet::new(output_globs.iter().map(|(_, g)| g.clone())).unwrap(),
                out_dir.path(),
            )?;

            // Verify each glob matched at least one file
            let mut unmatched: Vec<&str> =
                output_globs.iter().map(|(name, _)| name.as_str()).collect();
            for entry in walkdir::WalkDir::new(out_dir.path()) {
                let entry = entry
                    .map_err(|e| Error::Other(anyhow!("failed to walk output directory: {}", e)))?;
                if entry.file_type().is_dir() {
                    continue;
                }
                let rel_path = entry
                    .path()
                    .strip_prefix(out_dir.path())
                    .expect("path should be under out_dir");
                for (name, glob) in &output_globs {
                    if glob.compile_matcher().is_match(rel_path) {
                        unmatched.retain(|n| n != name);
                    }
                }
                if unmatched.is_empty() {
                    break;
                }
            }
            if !unmatched.is_empty() {
                return Err(Error::Other(anyhow!(
                    "output globs did not match any files: {}",
                    unmatched.join(", ")
                )));
            }
        }

        sandbox.keep_dir(false);
        build_op.set_done();
        Ok(SpecBuildResult {
            outputs: out_dir,
            build_ms,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SourceFetcher;
    use decode::Layer;
    use graph::{BuildSpecRef, Graph};
    use indoc::indoc;
    use lcache::Cache;
    use tempfile::TempDir;
    use tokio_util::sync::CancellationToken;

    /// NET-155: the line a failed web-source fetch writes to the build's
    /// stderr keeps no credential and no query of any URL its error quotes.
    #[test]
    fn failed_fetch_line_strips_urls() {
        assert_eq!(
            strip_urls(
                "error sending request for url \
                 (https://user:secret@downloads.example.org/a.tar.gz?token=t0k#f): \
                 could not connect to downloads.example.org:443: refused"
            ),
            "error sending request for url \
             (https://downloads.example.org/a.tar.gz): \
             could not connect to downloads.example.org:443: refused"
        );
        assert_eq!(strip_urls("no scheme ://here"), "no scheme ://here");
        assert_eq!(strip_urls("bad http://user:pw@[::1 end"), "bad <url> end");
        assert_eq!(
            stripped_url("http://u:p@example.org/x?y=1").as_deref(),
            Some("http://example.org/x")
        );
    }

    /// A [`SourceFetcher`] that must never be called. The build paths exercised
    /// here short-circuit before any source is fetched, so reaching either
    /// method indicates the function (or the test) took an unexpected branch.
    #[derive(Debug)]
    struct UnusedFetcher;

    impl SourceFetcher for UnusedFetcher {
        async fn download_web(
            &self,
            _url: &str,
            _sha256: &str,
            _op: &OpTracker,
        ) -> anyhow::Result<PathBuf> {
            unreachable!("source fetch must not happen on these build paths")
        }

        async fn download_gcs(
            &self,
            _bucket_id: String,
            _file: &str,
            _sha256: &str,
            _op: &OpTracker,
        ) -> anyhow::Result<PathBuf> {
            unreachable!("source fetch must not happen on these build paths")
        }
    }

    /// Serves the same file for every source, as the download cache does on a hit.
    #[derive(Debug)]
    struct OneFileFetcher(PathBuf);

    impl SourceFetcher for OneFileFetcher {
        async fn download_web(
            &self,
            _url: &str,
            _sha256: &str,
            _op: &OpTracker,
        ) -> anyhow::Result<PathBuf> {
            Ok(self.0.clone())
        }

        async fn download_gcs(
            &self,
            _bucket_id: String,
            _file: &str,
            _sha256: &str,
            _op: &OpTracker,
        ) -> anyhow::Result<PathBuf> {
            Ok(self.0.clone())
        }
    }

    fn graph_from(ncl: &str) -> Graph {
        Graph::new()
            .ingest(Layer::new_for_test(ncl.to_string()).unwrap())
            .unwrap()
    }

    fn spec_build<'a>(
        spec: &'a BuildSpecRef,
        fetcher: &'a UnusedFetcher,
    ) -> SpecBuild<'a, UnusedFetcher> {
        SpecBuild {
            spec,
            remote_fetcher: fetcher,
            override_deps: None,
            stdout_writer: None,
            stderr_writer: None,
            cancel: CancellationToken::new(),
            cpu_weight: None,
            build_box: None,
            patched: false,
        }
    }

    /// A spec with no build deps and an empty command is a "pure collection":
    /// running it does no build work and commits an empty output directory.
    #[test]
    fn run_pure_collection_commits_empty_outputs_with_zero_build_time() {
        let tmp = TempDir::new().unwrap();
        let cache = Cache::at_dir(tmp.path()).unwrap();
        let dg = graph_from(indoc! {r#"
            let {BuildSpec, ..} = import "minimal.ncl" in
            {
                name = "collection",
                build_deps = [],
                cmd = "",
            } | BuildSpec
        "#});
        let bsr = *dg.by_name("collection").unwrap();
        let fetcher = UnusedFetcher;
        let mut sb = spec_build(&bsr, &fetcher);
        let opts = Options {
            cache: cache.clone(),
            graph: &dg,
            exec_base: "/not-exists".into(),
            ot: None,
            daemon_id: None,
        };

        let result = futures::executor::block_on(sb.run(&opts)).unwrap();

        // No build is executed for a collection, so no time is spent building...
        assert_eq!(result.build_ms, 0);
        // ...and the caller is handed a real, usable output directory.
        assert!(
            result.outputs.path().is_dir(),
            "a committed collection must yield an existing output directory"
        );
    }

    /// A spec whose declared target is not the host cannot be built, and the
    /// error must name the offending target so the caller understands why.
    #[test]
    fn run_rejects_spec_targeting_a_non_host_system() {
        let tmp = TempDir::new().unwrap();
        let cache = Cache::at_dir(tmp.path()).unwrap();
        // amd64/macos is never a supported host (macOS hosts are arm64 only),
        // so this spec is unbuildable on whatever host runs the test suite.
        let dg = graph_from(indoc! {r#"
            let {BuildSpec, ..} = import "minimal.ncl" in
            {
                name = "cross",
                build_deps = [],
                cmd = "echo hi",
                target = "amd64/macos",
            } | BuildSpec
        "#});
        let bsr = *dg.by_name("cross").unwrap();
        let fetcher = UnusedFetcher;
        let mut sb = spec_build(&bsr, &fetcher);
        let opts = Options {
            cache: cache.clone(),
            graph: &dg,
            exec_base: "/not-exists".into(),
            ot: None,
            daemon_id: None,
        };

        let err = futures::executor::block_on(sb.run(&opts))
            .err()
            .expect("SpecBuild::run should fail for an unbuildable target");

        let msg = format!("{err}");
        assert!(
            msg.contains("amd64/macos"),
            "error should name the unbuildable target, got: {msg}"
        );
    }

    /// A non-extracted source reaches the sandbox's writable /build as a private
    /// copy of the cached file. A hardlink there would be the download cache's own
    /// inode, so a build appending to its input changed the cached source for any
    /// concurrent build of it (build-servers#231, reproduced from inside a real
    /// build sandbox).
    #[test]
    fn a_non_extracted_source_is_mapped_as_a_private_copy() {
        let tmp = TempDir::new().unwrap();
        let cache = Cache::at_dir(tmp.path()).unwrap();
        let cached = tmp.path().join("payload.tar.gz");
        std::fs::write(&cached, b"payload").unwrap();
        let dg = graph_from(indoc! {r#"
            let {BuildSpec, Source, ..} = import "minimal.ncl" in
            {
                name = "uses-raw-source",
                build_deps = [
                    {
                        url = "https://example.invalid/payload.tar.gz",
                        sha256 = "0000000000000000000000000000000000000000000000000000000000000000",
                        extract = false,
                    } | Source,
                ],
                cmd = "true",
            } | BuildSpec
        "#});
        let bsr = *dg.by_name("uses-raw-source").unwrap();
        let fetcher = OneFileFetcher(cached.clone());
        let mut sb = SpecBuild {
            spec: &bsr,
            remote_fetcher: &fetcher,
            override_deps: None,
            stdout_writer: None,
            stderr_writer: None,
            cancel: CancellationToken::new(),
            cpu_weight: None,
            build_box: None,
            patched: false,
        };
        let opts = Options {
            cache: cache.clone(),
            graph: &dg,
            exec_base: "/not-exists".into(),
            ot: None,
            daemon_id: None,
        };
        let build = dg.get(&bsr).unwrap();
        let op = OpTracker::new_root();
        let deps = futures::executor::block_on(sb.build_deps_mapped(build, &opts, &op)).unwrap();
        assert_eq!(deps, vec![SandboxMapped::FileCopy(cached)]);
    }

    fn network_build() -> Graph {
        graph_from(indoc! {r#"
            let {BuildSpec, ..} = import "minimal.ncl" in
            {
                name = "downloads-at-build",
                build_deps = [],
                cmd = "curl https://example.invalid/",
            } | BuildSpec
        "#})
    }

    fn build_box(network: Option<crate::BuildNetwork>) -> crate::BuildBox {
        crate::BuildBox::on_network("/nonexistent".into(), network)
    }

    fn some_network() -> crate::BuildNetwork {
        crate::BuildNetwork::new(|| {
            std::sync::Arc::new(sandbox::NoNet) as std::sync::Arc<dyn sandbox::Network>
        })
    }

    /// NET-155: a build for a box runs on its build box's network and never
    /// gets the host plan. Only a build outside any box does.
    #[test]
    fn box_build_never_gets_the_host_plan() {
        let dg = network_build();
        let bsr = *dg.by_name("downloads-at-build").unwrap();
        let build = dg.get(&bsr).unwrap();
        let fetcher = UnusedFetcher;

        let mut in_a_box = spec_build(&bsr, &fetcher);
        in_a_box.build_box = Some(build_box(Some(some_network())));
        let config = in_a_box
            .sandbox_config(build, Vec::new(), HashSet::new(), true, true, None)
            .unwrap();
        assert!(config.network.is_some());
        assert_ne!(config.plan, sandbox::NetPlan::host());

        let outside = spec_build(&bsr, &fetcher);
        let config = outside
            .sandbox_config(build, Vec::new(), HashSet::new(), true, true, None)
            .unwrap();
        assert!(config.network.is_none());
        assert_eq!(config.plan, sandbox::NetPlan::host());
    }

    /// NET-155: a build that needs no network stays in an empty namespace,
    /// whichever network its build box has.
    #[test]
    fn build_that_needs_no_network_stays_in_an_empty_namespace() {
        let dg = network_build();
        let bsr = *dg.by_name("downloads-at-build").unwrap();
        let build = dg.get(&bsr).unwrap();
        let fetcher = UnusedFetcher;

        for network in [Some(some_network()), None] {
            let mut in_a_box = spec_build(&bsr, &fetcher);
            in_a_box.build_box = Some(build_box(network));
            let config = in_a_box
                .sandbox_config(build, Vec::new(), HashSet::new(), false, false, None)
                .unwrap();
            assert!(config.network.is_none());
            assert_eq!(config.plan, sandbox::NetPlan::isolated());
        }
    }

    /// NET-155: a build that needs the network its build box does not have
    /// is refused before its sandbox exists, so no packet leaves.
    #[test]
    fn build_box_with_no_network_refuses_before_any_packet() {
        let dg = network_build();
        let bsr = *dg.by_name("downloads-at-build").unwrap();
        let build = dg.get(&bsr).unwrap();
        let fetcher = UnusedFetcher;

        let mut in_a_box = spec_build(&bsr, &fetcher);
        in_a_box.build_box = Some(build_box(None));
        let refused = in_a_box
            .sandbox_config(build, Vec::new(), HashSet::new(), true, false, None)
            .expect_err("the build needs a network its build box does not have");
        assert_eq!(
            refused.to_string(),
            format!("other: {}", crate::NEEDS_NETWORK_RULES)
        );
    }

    /// NET-155: in a box, a build's own `needs` decide its network even when
    /// its dependencies come ready-made. Only a patched build keeps the
    /// network, and outside a box every such build keeps it.
    #[tokio::test]
    async fn override_deps_needs_follow_the_spec_in_a_box() {
        let dg = network_build();
        let bsr = *dg.by_name("downloads-at-build").unwrap();
        let fetcher = UnusedFetcher;
        let tmp = tempfile::TempDir::new().unwrap();
        std::fs::create_dir(tmp.path().join("cache")).unwrap();
        let opts = crate::Options {
            cache: lcache::Cache::at_dir(tmp.path().join("cache")).unwrap(),
            graph: &dg,
            exec_base: tmp.path().to_path_buf(),
            ot: None,
            daemon_id: None,
        };
        let build = dg.get(&bsr).unwrap();

        let mut sb = spec_build(&bsr, &fetcher);
        sb.override_deps = Some(Default::default());
        let (_, dns, internet) = sb.rootfs_mapped(build, &opts).await.unwrap();
        assert!(dns && internet, "outside a box nothing changes");

        sb.build_box = Some(build_box(Some(some_network())));
        let (_, dns, internet) = sb.rootfs_mapped(build, &opts).await.unwrap();
        assert!(!dns && !internet, "in a box the spec's needs decide");

        sb.patched = true;
        let (_, dns, internet) = sb.rootfs_mapped(build, &opts).await.unwrap();
        assert!(dns && internet, "a patched build keeps the network");
    }
}
