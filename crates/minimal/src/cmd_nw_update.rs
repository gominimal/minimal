use crate::{lockfile::PrebuiltsLock, remote_storage::RemoteStorage, run::Run};
use anyhow::{Context, Result};
use graph::BuildSpecInput;
use graph::planner2::ExecPlan;
use std::path::PathBuf;

#[derive(clap::Args)]
pub struct NWUpdateArgs {
    /// Package name to build
    #[arg(short, long)]
    package: String,

    /// Path to a directory to cache build outputs in
    #[arg(long)]
    cache_dir: Option<PathBuf>,
}

pub async fn cmd_new_world_update(args: NWUpdateArgs) -> Result<()> {
    let graph = super::graph_from_package_name(&args.package, false);
    let cache = super::load_cache(args.cache_dir).unwrap();
    let remote_storage = RemoteStorage::new().await.unwrap();

    // Load the lockfile
    let lockfile_path = std::path::Path::new("prebuilts.lock");
    let mut lockfile = PrebuiltsLock::load(lockfile_path).unwrap_or_else(|e| {
        eprintln!(
            "Warning: Failed to load lockfile {}: {}",
            lockfile_path.display(),
            e
        );
        eprintln!("Using empty lockfile...");
        PrebuiltsLock::default()
    });

    let mut run = Run::new(
        &graph,
        cache.clone(),
        remote_storage.clone(),
        lockfile.clone(),
    );
    run.execute(ExecPlan::new(&graph), None)
        .await
        .context("Failed to execute build")?;

    // Work out the name of the prebuilt by looking at replace_by_cycle and then the first input
    let prebuilt_name = {
        let replace_spec = graph
            .get(
                &graph
                    .get(&graph.top_levels[0])
                    .unwrap()
                    .replace_on_cycle
                    .unwrap(),
            )
            .unwrap();
        if let BuildSpecInput::Prebuilt(name, _) = &replace_spec.inputs[0] {
            name.clone()
        } else {
            unreachable!()
        }
    };

    // Build the archive
    let package_hash = graph.spec_hash(&graph.top_levels[0]);
    let cache_handle = cache.read_dir(&package_hash).unwrap();
    let cache_dir = cache_handle.path();
    let archive_name = format!("{}.tar.zst", package_hash.0.to_hex());
    let temp_archive_path = std::env::temp_dir().join(&archive_name);
    crate::run::create_prebuilt_archive(&cache_dir.to_path_buf(), &temp_archive_path)?;

    // Upload
    let bucket_id = "minimal-staging-archives";
    let gcs_path = format!("prebuilts/{}/{}", prebuilt_name, archive_name);
    let archive_data = std::fs::read(&temp_archive_path)?;
    remote_storage
        .upload(bucket_id.to_string(), &gcs_path, &archive_data)
        .await?;
    std::fs::remove_file(&temp_archive_path)?;
    eprintln!(
        "Automatically uploaded prebuilt to gs://{}/{}",
        bucket_id, gcs_path
    );

    // Update the prebuilts lockfile
    lockfile.update_hash(prebuilt_name.clone(), package_hash.0.to_hex().to_string());
    let lockfile_path = std::path::Path::new("prebuilts.lock");
    lockfile.save(lockfile_path)?;
    eprintln!("Updated prebuilts.lock with new hash for {}", prebuilt_name);

    Ok(())
}
