use crate::GlobalArgs;
use crate::{Error, remote_storage::RemoteStorage};
use build_sandbox::{BuildConfig, config::BuildScript, run_build};
use cache::EntryMeta;
use graph::{BuildOutput, BuildSpecInput, Transitives};
use std::collections::HashSet;
use tracing::info;

#[derive(Debug, clap::Args)]
pub struct PatchedBuildArgs {
    package: String,
}

pub async fn cmd_patched_build(args: PatchedBuildArgs, globals: &GlobalArgs) -> Result<(), Error> {
    crate::enforce_science_mode()?;

    let graph = globals.graph_from_package_name(&args.package)?;
    let cache = globals.cache().map_err(anyhow::Error::from)?;
    let remote_storage =
        RemoteStorage::new(globals.path_config().download_cache_dir().to_path_buf())
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
        let cache_dir = cache.unsafe_get_by_name(&build.name).unwrap();
        dependencies.insert(cache_dir.path().to_path_buf());
    }

    let build = graph.get(&graph.top_levels[0]).unwrap();
    for input in build.inputs.iter() {
        match input {
            BuildSpecInput::Local((path, _hash)) => inputs.push(path.to_path_buf()),
            BuildSpecInput::Source(source) => inputs.push(
                crate::run::materialize_source(build.name.as_str(), source, &remote_storage)
                    .await?,
            ),
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

    let output_base = globals.path_config().sandbox_base_dir().to_path_buf();
    std::fs::create_dir_all(&output_base).ok();
    let out_dir = cache
        .write_dir(&graph.spec_hash(&graph.top_levels[0]))
        .unwrap();

    info!("Building package: {}", build.name);
    let command_info = format!("unsafe-patched-build {}", build.name);
    let mut spongebob_client = spongebob::SpongeBob::new()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create SpongeBob client: {}", e))?;
    let mut spongebob_invocation = match spongebob_client.create_invocation(&command_info).await {
        Ok(inv) => Some(inv),
        Err(e) => {
            tracing::warn!("Failed to create SpongeBob invocation: {}", e);
            None
        }
    };

    run_build(
        &config,
        out_dir.path(),
        &mut spongebob_invocation,
        output_base.clone(),
    )
    .await
    .map_err(|e| anyhow::anyhow!("Failed to build {}: {}", build.name, e))?;

    out_dir
        .finalize(EntryMeta {
            spec_name: build.name.clone(),
            ..Default::default()
        })
        .unwrap();

    Ok(())
}
