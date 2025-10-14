use crate::{Error, lockfile::PrebuiltsLock, remote_storage::RemoteStorage, run::Run};
use crate::{GlobalArgs, PackagesArg};
use anyhow::Context;
use build_events::events::{BuildEvent, BuildFinished, BuildMetadata, BuildStarted, current_millis};
use build_events::{BuildEventBus, BuildEventDispatcher};
use build_events_proto::SpongeBobSubscriberV2;
use cache::{Cache, CacheBinProvider, LocalDir, RemoteBinProvider};
use graph::{DepGraph, ExecPlan, Transitives};
use std::collections::HashMap;
use std::path::Path;
use std::process::Command;
use tracing::info;

#[derive(Debug, clap::Args)]
pub struct BuildArgs {
    #[command(flatten)]
    packages: PackagesArg,
}

pub async fn cmd_build(args: BuildArgs, globals: &GlobalArgs) -> Result<(), Error> {
    let graph = args.packages.graph(globals)?;
    let cache = globals.cache().map_err(anyhow::Error::from)?;

    cmd_build_impl(&graph, globals, cache, globals.num_parallel_builds).await?;

    Ok(())
}

pub async fn cmd_build_impl(
    graph: &DepGraph,
    globals: &GlobalArgs,
    cache: Cache<LocalDir>,
    num_parallel_builds: usize,
) -> anyhow::Result<()> {
    // Create SpongeBob invocation for this build command
    let mut spongebob_client = spongebob::SpongeBob::new()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create SpongeBob client: {}", e))?;

    let mut spongebob_invocation = Some(spongebob_client.create_invocation());

    rayon::ThreadPoolBuilder::new()
        .num_threads(num_parallel_builds)
        .build_global()
        .unwrap();

    let output_base = globals.path_config().sandbox_base_dir().to_path_buf();
    std::fs::create_dir_all(&output_base).ok();

    let mut run = Run::new(
        graph,
        cache.clone(),
        RemoteStorage::new(globals.path_config().download_cache_dir().to_path_buf())
            .await
            .unwrap(),
        PrebuiltsLock::load(Path::new("prebuilts.lock")).unwrap(),
        output_base,
    );

    // Setup build events system
    let event_bus = BuildEventBus::new(10000);

    // Create dispatcher with SpongeBobSubscriberV2 if we have an invocation
    if let Some(ref invocation) = spongebob_invocation {
        let mut dispatcher = BuildEventDispatcher::new(event_bus.subscribe());
        let subscriber = SpongeBobSubscriberV2::from_invocation(invocation.clone());
        dispatcher.add_subscriber(Box::new(subscriber));

        // Spawn dispatcher in background
        tokio::spawn(async move {
            dispatcher.run().await;
        });
    }

    // Get invocation_id for events
    let invocation_id = spongebob_invocation
        .as_ref()
        .map(|inv| inv.invocation_id().to_string())
        .unwrap_or_else(|| "local".to_string());

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

    // Emit BuildStarted event
    event_bus.emit(BuildEvent::BuildStarted(BuildStarted {
        invocation_id: invocation_id.clone(),
        command,
        timestamp_millis: current_millis(),
        working_directory,
    }));

    // Collect and emit git metadata
    let mut metadata = HashMap::new();

    // Get git user
    if let Ok(output) = Command::new("git").args(["config", "user.name"]).output() {
        if output.status.success() {
            if let Ok(user) = String::from_utf8(output.stdout) {
                metadata.insert("user".to_string(), user.trim().to_string());
            }
        }
    }

    // Get git branch
    if let Ok(output) = Command::new("git").args(["rev-parse", "--abbrev-ref", "HEAD"]).output() {
        if output.status.success() {
            if let Ok(branch) = String::from_utf8(output.stdout) {
                metadata.insert("branch".to_string(), branch.trim().to_string());
            }
        }
    }

    // Get git commit SHA
    if let Ok(output) = Command::new("git").args(["rev-parse", "HEAD"]).output() {
        if output.status.success() {
            if let Ok(commit) = String::from_utf8(output.stdout) {
                metadata.insert("commit".to_string(), commit.trim().to_string());
            }
        }
    }

    // Get git remote URL
    if let Ok(output) = Command::new("git").args(["config", "remote.origin.url"]).output() {
        if output.status.success() {
            if let Ok(repo_url) = String::from_utf8(output.stdout) {
                metadata.insert("repo_url".to_string(), repo_url.trim().to_string());
            }
        }
    }

    // Emit BuildMetadata event if we collected any metadata
    if !metadata.is_empty() {
        event_bus.emit(BuildEvent::BuildMetadata(BuildMetadata { metadata }));
    }

    let build_success = match (globals.no_cache, globals.no_fetch) {
        // No local or remote cache
        (true, true) => {
            run.execute(ExecPlan::new(graph), None, &mut spongebob_invocation)
                .await
        }
        // Both caches
        (false, false) => {
            let local_adapter = CacheBinProvider::new(graph, cache.clone());
            let remote_cache = globals.remote_cache().await.unwrap();
            let remote_adapter = RemoteBinProvider::new(graph, &remote_cache);
            run.execute(
                ExecPlan::new_with_bin_provider(graph, (local_adapter, remote_adapter)),
                Some(&remote_cache),
                &mut spongebob_invocation,
            )
            .await
        }
        // Only remote cache
        (true, false) => {
            let remote_cache = globals.remote_cache().await.unwrap();
            let remote_adapter = RemoteBinProvider::new(graph, &remote_cache);
            run.execute(
                ExecPlan::new_with_bin_provider(graph, remote_adapter),
                Some(&remote_cache),
                &mut spongebob_invocation,
            )
            .await
        }
        // Only local cache
        (false, true) => {
            let local_adapter = CacheBinProvider::new(graph, cache.clone());
            run.execute(
                ExecPlan::new_with_bin_provider(graph, local_adapter),
                None,
                &mut spongebob_invocation,
            )
            .await
        }
    };

    // Determine if build was successful
    let build_succeeded = build_success.is_ok();
    let error_message = build_success.as_ref().err().map(|e| e.to_string());

    // Emit BuildFinished event
    event_bus.emit(BuildEvent::BuildFinished(BuildFinished {
        invocation_id: invocation_id.clone(),
        success: build_succeeded,
        timestamp_millis: current_millis(),
        error_message,
    }));

    // Propagate error if build failed
    build_success.context("Failed to execute build")?;

    // If we got this far, everything we need is either fetchable or built.
    //
    // There could still be stuff thats fetchable but not in the local cache. We
    // can materialize that locally now.
    if !globals.no_fetch {
        let mut needs_materialize: Vec<_> =
            Transitives::for_toplevels(graph, graph.top_levels.to_vec(), false)
                .into_iter()
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
            let remote_cache = globals.remote_cache().await.unwrap();
            let tokio_runtime = tokio::runtime::Handle::current();
            rayon::scope(|s| {
                let remote_cache = &remote_cache;
                let cache = &cache;
                for bsr in needs_materialize.into_iter() {
                    let tokio_runtime = tokio_runtime.clone();

                    s.spawn(move |_| {
                        let _rt = tokio_runtime.enter();
                        let name = &graph.get(&bsr).unwrap().name;
                        let span = tracing::info_span!(
                            "download_cached",
                            "indicatif.pb_show" = tracing::field::Empty,
                            "build" = name,
                        );
                        let _enter = span.enter();

                        futures::executor::block_on(remote_cache.materialize(
                            &graph.spec_hash(&bsr),
                            name,
                            cache,
                        ))
                        .unwrap();
                    });
                }
            });
        }
    }

    // Log build results to SpongeBob
    if let Some(ref mut invocation) = spongebob_invocation {
        log_build_results_to_spongebob(invocation, graph, build_succeeded).await?;
    }

    let spongebob_url = spongebob_invocation
        .as_ref()
        .map(|inv| inv.url().to_string());

    // Display build summary
    display_build_summary(graph, &cache, globals, &run, spongebob_url.as_deref());

    Ok(())
}

/// Log build command results to SpongeBob
async fn log_build_results_to_spongebob(
    spongebob_invocation: &mut spongebob::SpongeBobInvocation,
    graph: &DepGraph,
    success: bool,
) -> anyhow::Result<()> {
    let packages_list = graph
        .top_levels
        .iter()
        .map(|bsr| graph.get(bsr).unwrap().name.as_str())
        .collect::<Vec<_>>()
        .join(", ");

    let _build_summary = if success {
        format!(
            "Build completed successfully for packages: {}",
            packages_list
        )
    } else {
        format!("Build failed for packages: {}", packages_list)
    };

    let build_log = format!(
        "Build Command Summary\n\
         Packages: {}\n\
         Status: {}\n\
         Total packages: {}\n",
        packages_list,
        if success { "SUCCESS" } else { "FAILED" },
        graph.top_levels.len()
    );

    // Use a semantic target ID for the build command summary
    let build_command_target_id = "build-summary".to_string();

    // Upload build summary to the synthetic target
    info!("Uploading build summary to SpongeBob invocation");
    spongebob_invocation
        .upload_file(
            &build_command_target_id,
            "build-summary.txt",
            build_log.into_bytes(),
        )
        .await
        .map_err(|e| anyhow::anyhow!("Failed to upload build summary to SpongeBob: {}", e))?;

    Ok(())
}

/// Display a summary of what was built and where outputs can be found
fn display_build_summary(
    graph: &DepGraph,
    cache: &Cache<LocalDir>,
    _globals: &GlobalArgs,
    _run: &Run,
    command_spongebob_url: Option<&str>,
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
                info!("  {} -> {}", build.name, e.path().display());
            } else {
                info!("  {} -> (not in cache)", build.name);
            }
        }
    }
    if let Some(url) = command_spongebob_url {
        info!("{}", url);
    };
}
