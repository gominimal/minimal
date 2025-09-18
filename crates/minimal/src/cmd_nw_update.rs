use crate::{
    Error, GlobalArgs, PackagesArg, lockfile::PrebuiltsLock, remote_storage::RemoteStorage,
};
use graph::BuildSpecInput;
use std::path::Path;
use tracing::{info, warn};

static BUCKET_ID: &str = "minimal-staging-archives";

#[derive(clap::Args)]
pub struct NWUpdateArgs {
    #[command(flatten)]
    packages: PackagesArg,
}

pub async fn cmd_new_world_update(args: NWUpdateArgs, globals: &GlobalArgs) -> Result<(), Error> {
    let graph = args.packages.graph(globals)?;
    let cache = globals.cache().map_err(anyhow::Error::from)?;

    crate::cmd_build::cmd_build_impl(
        &graph,
        globals.no_cache,
        cache.clone(),
        globals.num_parallel_builds,
    )
    .await?;

    let remote_storage = RemoteStorage::new().await.unwrap();

    let mut lockfile = PrebuiltsLock::load(Path::new("prebuilts.lock")).unwrap();

    for bsr in &graph.top_levels {
        // Work out the name of the prebuilt by looking at replace_by_cycle and then the first input
        let (prebuilt_name, prebuilt_sha256) = {
            let replace_spec = graph
                .get(
                    &graph
                        .get(bsr)
                        .unwrap()
                        .replace_on_cycle
                        .expect("expected a cycle breaker on each named package"),
                )
                .unwrap();
            if let BuildSpecInput::Prebuilt(name, sha256) = &replace_spec.inputs[0] {
                (name.clone(), sha256.clone())
            } else {
                unreachable!("first input was not a prebuilt")
            }
        };

        // Build the archive
        let package_hash = graph.spec_hash(bsr);
        let cache_handle = cache.read_dir(&package_hash).unwrap();
        let cache_dir = cache_handle.path();
        let archive_name = format!("{}.tar.zst", package_hash.0.to_hex());

        let encoder = zstd::stream::Encoder::new(Vec::new(), 3).map_err(anyhow::Error::from)?;
        let mut tar_builder = tar::Builder::new(encoder);
        tar_builder
            .append_dir_all(".", cache_dir)
            .map_err(anyhow::Error::from)?;
        let archive_data = tar_builder
            .into_inner()
            .map_err(anyhow::Error::from)?
            .finish()
            .map_err(anyhow::Error::from)?;

        // Compute sha256 hash
        let hash_hex = {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(&archive_data);
            let computed_hash = hasher.finalize();
            hex::encode(computed_hash)
        };
        info!("sha256({}) = {}", prebuilt_name, hash_hex);

        // Upload
        let gcs_path = format!("prebuilts/{}/{}", prebuilt_name, archive_name);
        remote_storage
            .upload(BUCKET_ID, &gcs_path, &archive_data)
            .await?;
        info!(
            "Automatically uploaded prebuilt to gs://{}/{}",
            BUCKET_ID, gcs_path
        );

        // Update the prebuilts lockfile
        lockfile.update_hash(prebuilt_name.clone(), package_hash.0.to_hex().to_string());
        info!("Updated prebuilts.lock with new hash for {}", prebuilt_name);

        if let Some(old_hash_hex) = prebuilt_sha256 {
            info!(
                "updating hardcoded sha256 value: {} => {}",
                old_hash_hex, hash_hex
            );
            use std::process::Command;

            let status = Command::new("find")
                .args([
                    "packages/",
                    "-type",
                    "f",
                    "-exec",
                    "sed",
                    "-i",
                    &format!("s/{}/{}/g", old_hash_hex, hash_hex),
                    "{}",
                    "+",
                ])
                .status()
                .map_err(anyhow::Error::from)?;
            if !status.success() {
                warn!(
                    "find/replace for hardcoded hash failed with exit code: {:?}",
                    status.code()
                );
            }
        }
    }
    let lockfile_path = std::path::Path::new("prebuilts.lock");
    lockfile.save(lockfile_path)?;

    Ok(())
}
