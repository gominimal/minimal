use crate::{Context, Error, remote_storage::RemoteStorage};
use cache::{EntryMeta, MetaInner};
use graph::Transitives;
use op::{Runnable, SpecBuild};
use std::collections::HashSet;

#[derive(Debug, clap::Args)]
pub struct PatchedBuildArgs {
    package: String,
}

pub async fn cmd_patched_build(args: PatchedBuildArgs, ctx: &mut Context) -> Result<(), Error> {
    crate::enforce_science_mode()?;

    let graph = ctx.graph_from_package_name(&args.package)?;
    let cache = ctx.local_cache();
    let remote_storage = RemoteStorage::new(ctx.paths().download_cache_dir().to_path_buf())
        .await
        .unwrap();

    let bsr = graph.top_levels[0];
    let build = graph.get(&bsr).unwrap();

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
    let out_dir = SpecBuild {
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

    out_dir
        .finalize(EntryMeta {
            inner: MetaInner::Spec(build.name.clone()),
            breaker_build: true,
            origin: Some(build.from.as_ref().clone()),
            ..Default::default()
        })
        .unwrap();
    println!("Written to cache with hash {}", graph.spec_hash(&bsr).0);

    Ok(())
}
