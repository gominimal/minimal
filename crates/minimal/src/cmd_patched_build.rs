use crate::run::Materialized;
use crate::{Context, Error, remote_storage::RemoteStorage};
use build_sandbox::{BuildConfig, Input as SandboxInput, config::BuildScript, run_build};
use cache::{EntryMeta, MetaInner};
use graph::{BuildOutput, BuildSpecInput, Transitives};
use std::collections::HashSet;
use tracing::info;

#[derive(Debug, clap::Args)]
pub struct PatchedBuildArgs {
    package: String,
}

pub async fn cmd_patched_build(args: PatchedBuildArgs, ctx: &mut Context) -> Result<(), Error> {
    crate::enforce_science_mode()?;
    let mut temp_dirs = Vec::new();

    let graph = ctx.graph_from_package_name(&args.package)?;
    let cache = ctx.local_cache();
    let remote_storage = RemoteStorage::new(ctx.paths().download_cache_dir().to_path_buf())
        .await
        .unwrap();

    let mut inputs = Vec::new();
    let mut dependencies = HashSet::new();
    let transitives = Transitives::new(&graph, &graph.top_levels[0], true);
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

    let build = graph.get(&graph.top_levels[0]).unwrap();
    for input in build.inputs.iter() {
        match input {
            BuildSpecInput::Local { full_path, .. } => {
                inputs.push(SandboxInput::File(full_path.to_path_buf()))
            }
            BuildSpecInput::Source(source) => {
                match crate::run::materialize_source(
                    build.name.as_str(),
                    source,
                    &remote_storage,
                    &cache,
                )
                .await?
                {
                    Materialized::File(path) => inputs.push(SandboxInput::File(path)),
                    Materialized::TempDir(td) => {
                        inputs.push(SandboxInput::Dir(td.path().to_path_buf()));
                        temp_dirs.push(td);
                    }
                }
            }
            BuildSpecInput::Build(_) => {} // Handled by Transitives above
            _ => todo!("input: {:?}", input),
        }
    }

    let cmd_parts: Vec<String> =
        shlex::split(&build.cmd).unwrap_or_else(|| vec![build.cmd.clone()]);
    let (executable, args) = if !cmd_parts.is_empty() {
        let exe = cmd_parts[0].clone();
        let args = cmd_parts[1..].to_vec();
        (exe, args)
    } else {
        (build.cmd.clone(), vec![])
    };

    let config = BuildConfig {
        name: build.name.clone(),
        dependencies,
        inputs,
        build_script: BuildScript {
            executable: executable.into(),
            args,
            build_args: build.build_args.clone(),
        },
        outputs: build
            .outputs
            .values()
            .map(|output| match output {
                BuildOutput::Library { glob } => glob.clone(),
                BuildOutput::Data { glob } => glob.clone(),
                BuildOutput::Binary { glob } => glob.clone(),
            })
            .collect(),
    };

    let output_base = ctx.paths().sandbox_base_dir().to_path_buf();
    std::fs::create_dir_all(&output_base).ok();
    let out_dir = cache
        .write_dir(&graph.spec_hash(&graph.top_levels[0]))
        .unwrap();

    info!("Building package: {}", build.name);

    // Use package name as target ID for semantic meaning
    let target_id = build.name.clone();

    run_build(&config, out_dir.path(), output_base.clone(), &target_id)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to build {}: {}", build.name, e))?;

    out_dir
        .finalize(EntryMeta {
            inner: MetaInner::Spec(build.name.clone()),
            breaker_build: true,
            origin: Some(build.from.as_ref().clone()),
            ..Default::default()
        })
        .unwrap();
    println!(
        "Written to cache with hash {}",
        graph.spec_hash(&graph.top_levels[0]).0
    );

    for tempdir in temp_dirs.into_iter() {
        drop(tempdir);
    }
    Ok(())
}
