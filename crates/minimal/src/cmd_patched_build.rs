use crate::{Context, Error};
use anyhow::anyhow;
use graph::{BuildSpecRef, Graph, Transitives};
use lcache::{Cache, LocalDir};
use op::{PatchedBuild, Runnable};
use std::collections::HashSet;
use std::path::PathBuf;

#[derive(Debug, clap::Args)]
pub struct PatchedBuildArgs {
    #[arg(long)]
    remote_addr: Option<String>,
    package: String,
}

pub async fn cmd_patched_build(args: PatchedBuildArgs, ctx: &mut Context) -> Result<(), Error> {
    crate::enforce_science_mode()?;

    let graph = ctx.graph_from_package_names([args.package])?;
    let cache = ctx.local_cache();

    let remote_storage = ctx.remote_storage().await.unwrap();

    let bsr = graph.top_levels[0];

    // Handle the remote-build case.
    if let Some(addr) = args.remote_addr {
        let transitives = Transitives::new(&graph, &bsr, true);
        let deps = transitives
            .transitive_runtime_deps
            .into_iter()
            .map(|(dep_bsr, dep)| {
                let build = graph.get(&dep_bsr).unwrap();
                let cache_dir = cache.unsafe_get_build_by_name(&build.name).unwrap();
                (dep_bsr, dep.outputs, cache_dir.path().to_path_buf())
            })
            .collect();
        return remote_patched_build(addr, &bsr, &graph, cache, deps).await;
    }

    let output_base = ctx.builds_base_dir();
    std::fs::create_dir_all(&output_base).ok();
    let res = PatchedBuild {
        spec: &bsr,
        remote_fetcher: &remote_storage,
        stdout_writer: Some(Box::new(common::TracingWriter::stdout())),
        stderr_writer: Some(Box::new(common::TracingWriter::stderr())),
    }
    .run(&op::Options {
        cache,
        graph: &graph,
        exec_base: output_base,
    })
    .await
    .map_err(|e| Error::Other(anyhow!("build failed: {}", e)))?;

    res.outputs.finalize(res.meta).unwrap();
    println!("Written to cache with hash {}", graph.spec_hash(&bsr).0);

    Ok(())
}

pub async fn remote_patched_build(
    addr: String,
    spec: &BuildSpecRef,
    graph: &Graph,
    cache: Cache<LocalDir>,
    deps: Vec<(BuildSpecRef, Option<HashSet<String>>, PathBuf)>,
) -> Result<(), Error> {
    use op::remote_build::*;

    let client =
        remote_proto::remote_execution_service_client::RemoteExecutionServiceClient::connect(addr)
            .await
            .map_err(|e| Error::Other(anyhow!(e)))?;

    let mut b = RemoteSpecBuild {
        client,
        spec,
        deps: deps
            .into_iter()
            .map(|(bsr, outputs, dir)| Dep {
                bsr,
                inner: DepInner::Local(bsr, dir),
                outputs,
            })
            .collect(),
    };
    b.run(&op::Options {
        cache,
        graph,
        exec_base: "/non-existent".into(),
    })
    .await
    .map_err(|e| Error::Other(anyhow!(e)))?;

    Ok(())
}
