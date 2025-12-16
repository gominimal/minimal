use crate::{Context, Error, remote_storage::RemoteStorage};
use anyhow::anyhow;
use cache::{Cache, EntryMeta, LocalDir, MetaInner};
use graph::{BuildSpecRef, DepGraph, Transitives};
use op::{Runnable, SpecBuild};
use std::{collections::HashSet, path::PathBuf};

#[derive(Debug, clap::Args)]
pub struct PatchedBuildArgs {
    #[arg(long)]
    remote_addr: Option<String>,
    package: String,
}

pub async fn cmd_patched_build(args: PatchedBuildArgs, ctx: &mut Context) -> Result<(), Error> {
    crate::enforce_science_mode()?;

    let graph = ctx.graph_from_package_names(&[args.package])?;
    let cache = ctx.local_cache();
    let remote_storage = RemoteStorage::new(ctx.paths().download_cache_dir().to_path_buf(), false)
        .await
        .unwrap();

    let bsr = graph.top_levels[0];
    let build = graph.get(&bsr).unwrap();

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

    // Select dependencies by name to be used in the build.
    let mut dependencies = HashSet::new();
    let transitives = Transitives::new(&graph, &bsr, true);
    let build_deps: Vec<_> = transitives
        .transitive_runtime_deps
        .keys()
        .to_owned()
        .collect();

    for bsr in build_deps.iter() {
        let build = graph.get(bsr).unwrap();
        let cache_dir = cache.unsafe_get_build_by_name(&build.name).unwrap();
        dependencies.insert(cache_dir.path().to_path_buf());
    }

    let output_base = ctx.paths().sandbox_base_dir().to_path_buf();
    std::fs::create_dir_all(&output_base).ok();
    let res = SpecBuild {
        spec: &bsr,
        override_deps: Some(dependencies),
        remote_fetcher: &remote_storage,
    }
    .run(&op::Options {
        cache,
        graph: &graph,
        exec_base: output_base,
    })
    .await
    .map_err(anyhow::Error::from)?;

    res.outputs
        .finalize(EntryMeta {
            inner: MetaInner::Spec(build.name.clone()),
            breaker_build: true,
            build_ms: Some(res.build_ms),
            origin: Some(build.from.as_ref().clone()),
            ..Default::default()
        })
        .unwrap();
    println!("Written to cache with hash {}", graph.spec_hash(&bsr).0);

    Ok(())
}

pub async fn remote_patched_build(
    addr: String,
    spec: &BuildSpecRef,
    graph: &DepGraph,
    cache: Cache<LocalDir>,
    deps: Vec<(BuildSpecRef, Option<HashSet<String>>, PathBuf)>,
) -> Result<(), Error> {
    use op::remote_build::*;

    let client =
        res_proto::remote_execution_service_client::RemoteExecutionServiceClient::connect(addr)
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
