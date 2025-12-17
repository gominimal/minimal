use crate::{Context, Error, PackagesArg, run::Run};
use anyhow::Context as _;
use build_events::events::{
    BuildEvent, BuildFinished, BuildMetadata, BuildStarted, build_event, current_millis,
};
use cache::{Cache, CacheBinProvider, LocalDir, RemoteBinProvider};
use common::RemoteStorage;
use graph::{DepGraph, ExecPlan, Transitives};
use std::collections::HashMap;
use std::process::Command;
use tracing::info;

#[derive(Debug, clap::Args)]
pub struct BuildArgs {
    #[command(flatten)]
    packages: PackagesArg,
}

pub async fn cmd_build(args: BuildArgs, ctx: &mut Context) -> Result<(), Error> {
    let graph = args.packages.graph(ctx)?;
    let cache = ctx.local_cache();

    cmd_build_impl(&graph, ctx, cache, ctx.num_parallel_builds).await?;

    Ok(())
}

pub async fn cmd_build_impl(
    graph: &DepGraph,
    ctx: &mut Context,
    cache: Cache<LocalDir>,
    num_parallel_builds: usize,
) -> anyhow::Result<()> {
    rayon::ThreadPoolBuilder::new()
        .num_threads(num_parallel_builds)
        .build_global()
        .unwrap();

    let output_base = ctx.paths().sandbox_base_dir().to_path_buf();
    std::fs::create_dir_all(&output_base).ok();

    let mut run = Run::new(
        graph,
        cache.clone(),
        RemoteStorage::new(ctx.paths().download_cache_dir().to_path_buf(), false)
            .await
            .unwrap(),
        output_base,
    );

    // Get command for BuildStarted event (skip binary path at index 0)
    let args: Vec<String> = std::env::args().collect();
    let command = if args.len() > 1 {
        args[1..].join(" ")
    } else {
        args.first().cloned().unwrap_or_default()
    };

    let working_directory = std::env::current_dir()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();

    // Emit BuildStarted event using global event bus
    build_events::event_bus().emit(BuildEvent {
        event: Some(build_event::Event::BuildStarted(BuildStarted {
            invocation_id: build_events::invocation_id().to_string(),
            command,
            timestamp_millis: current_millis(),
            working_directory,
        })),
    });

    // Collect and emit git metadata
    let mut metadata = HashMap::new();

    // Get git user
    if let Ok(output) = Command::new("git").args(["config", "user.name"]).output()
        && output.status.success()
        && let Ok(user) = String::from_utf8(output.stdout)
    {
        metadata.insert("user".to_string(), user.trim().to_string());
    }

    // Get git branch
    if let Ok(output) = Command::new("git")
        .args(["rev-parse", "--abbrev-ref", "HEAD"])
        .output()
        && output.status.success()
        && let Ok(branch) = String::from_utf8(output.stdout)
    {
        metadata.insert("branch".to_string(), branch.trim().to_string());
    }

    // Get git commit SHA
    if let Ok(output) = Command::new("git").args(["rev-parse", "HEAD"]).output()
        && output.status.success()
        && let Ok(commit) = String::from_utf8(output.stdout)
    {
        metadata.insert("commit".to_string(), commit.trim().to_string());
    }

    // Get git remote URL
    if let Ok(output) = Command::new("git")
        .args(["config", "remote.origin.url"])
        .output()
        && output.status.success()
        && let Ok(repo_url) = String::from_utf8(output.stdout)
    {
        metadata.insert("repo_url".to_string(), repo_url.trim().to_string());
    }

    // Emit BuildMetadata event if we collected any metadata (using global event bus)
    if !metadata.is_empty() {
        build_events::event_bus().emit(BuildEvent {
            event: Some(build_event::Event::BuildMetadata(BuildMetadata {
                metadata,
            })),
        });
    }

    let build_success = match (ctx.no_cache, ctx.no_fetch) {
        // No local or remote cache
        (true, true) => run.execute(ExecPlan::new(graph), None).await,
        // Both caches
        (false, false) => {
            let local_adapter = CacheBinProvider::new(graph, cache.clone());
            let remote_cache = ctx.remote_cache(false).await.unwrap();
            let remote_adapter = RemoteBinProvider::new(graph, &remote_cache);
            run.execute(
                ExecPlan::new_with_bin_provider(graph, (local_adapter, remote_adapter)),
                Some(&remote_cache),
            )
            .await
        }
        // Only remote cache
        (true, false) => {
            let remote_cache = ctx.remote_cache(false).await.unwrap();
            let remote_adapter = RemoteBinProvider::new(graph, &remote_cache);
            run.execute(
                ExecPlan::new_with_bin_provider(graph, remote_adapter),
                Some(&remote_cache),
            )
            .await
        }
        // Only local cache
        (false, true) => {
            let local_adapter = CacheBinProvider::new(graph, cache.clone());
            run.execute(ExecPlan::new_with_bin_provider(graph, local_adapter), None)
                .await
        }
    };

    // Determine if build was successful
    let build_succeeded = build_success.is_ok();
    let error_message = build_success.as_ref().err().map(|e| e.to_string());

    // Emit BuildFinished event using global event bus
    build_events::event_bus().emit(BuildEvent {
        event: Some(build_event::Event::BuildFinished(BuildFinished {
            success: build_succeeded,
            timestamp_millis: current_millis(),
            error_message,
        })),
    });

    // Propagate error if build failed
    build_success.context("Failed to execute build")?;

    // If we got this far, everything we need is either fetchable or built.
    //
    // There could still be stuff thats fetchable but not in the local cache. We
    // can materialize that locally now.
    if !ctx.no_fetch {
        let mut needs_materialize: Vec<_> =
            Transitives::for_toplevels(graph, graph.top_levels.to_vec(), false)
                .into_keys()
                .filter_map(|bsr| {
                    // Filter runtime_deps that are in the local cache
                    cache
                        .read_dir(&graph.spec_hash(&bsr))
                        .map(|_| None)
                        .unwrap_or(Some(bsr))
                })
                .collect();
        needs_materialize.sort();
        needs_materialize.dedup();

        if !needs_materialize.is_empty() {
            let remote_cache = ctx.remote_cache(false).await.unwrap();
            let tokio_runtime = tokio::runtime::Handle::current();
            rayon::scope(|s| {
                let remote_cache = &remote_cache;
                let cache = &cache;
                for bsr in needs_materialize.into_iter() {
                    let tokio_runtime = tokio_runtime.clone();

                    s.spawn(move |_| {
                        let _rt = tokio_runtime.enter();
                        let build = graph.get(&bsr).unwrap();
                        let (name, origin) = (&build.name, &build.from);

                        let (fetch_time, pending_dir) = futures::executor::block_on(
                            remote_cache.materialize(&graph.spec_hash(&bsr), cache, name.as_str()),
                        )
                        .unwrap();
                        pending_dir
                            .finalize(cache::EntryMeta {
                                inner: cache::MetaInner::Spec(name.clone()),
                                origin: Some(origin.as_ref().clone()),
                                fetched: true,
                                fetch_ms: Some(fetch_time.as_millis() as usize),
                                ..Default::default()
                            })
                            .unwrap();
                    });
                }
            });
        }
    }

    // Display build summary
    display_build_summary(graph, &cache, ctx, &run);

    Ok(())
}

/// Display a summary of what was built and where outputs can be found
fn display_build_summary(
    graph: &DepGraph,
    cache: &Cache<LocalDir>,
    _ctx: &mut Context,
    _run: &Run,
) {
    info!("Build completed successfully!");

    // Show target packages and their cache locations
    if !graph.top_levels.is_empty() {
        info!("Target packages:");
        for bsr in &graph.top_levels {
            let build = graph.get(bsr).unwrap();
            let spec_hash = graph.spec_hash(bsr);

            // Check if the package exists in cache
            if let Ok(e) = cache.read_dir(&spec_hash) {
                let suffix = if let Ok(meta) = cache.read_meta(&spec_hash) {
                    if let Some(fetch_ms) = meta.fetch_ms
                        && meta.fetched
                    {
                        if fetch_ms > 1000 {
                            format!("(fetched in {:.1}s)", fetch_ms as f32 / 1000.0)
                        } else {
                            format!("(fetched in {}ms)", fetch_ms)
                        }
                    } else if let Some(build_ms) = meta.build_ms {
                        if build_ms > 1000 {
                            format!("(built in {:.1}s)", build_ms as f32 / 1000.0)
                        } else {
                            format!("(built in {}ms)", build_ms)
                        }
                    } else {
                        "".to_string()
                    }
                } else {
                    "".to_string()
                };
                info!("  {} -> {} {}", build.name, e.path().display(), suffix);
            }
        }
    }
}
