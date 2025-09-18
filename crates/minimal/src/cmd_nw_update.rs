use crate::{lockfile::PrebuiltsLock, remote_storage::RemoteStorage};
use anyhow::Result;
use graph::BuildSpecInput;
use std::path::PathBuf;

static BUCKET_ID: &str = "minimal-staging-archives";

#[derive(clap::Args)]
pub struct NWUpdateArgs {
    /// Package names to build & update
    #[arg(short, long, alias="package", value_delimiter=',', num_args=0..)]
    packages: Vec<String>,

    /// Path to a directory to cache build outputs in
    #[arg(long)]
    cache_dir: Option<PathBuf>,

    /// Whether to ignore the local cache
    #[arg(long, default_value_t = false)]
    no_cache: bool,

    /// Number of parallel builds
    #[arg(short, long, default_value_t = 4)]
    num_parallel_builds: usize,
}

pub async fn cmd_new_world_update(args: NWUpdateArgs) -> Result<()> {
    let graph = match args.packages.len() {
        1 => super::graph_from_package_name(&args.packages[0]),
        _ => super::graph_from_package_names(&args.packages),
    };

    let cache = super::load_cache(args.cache_dir).unwrap();

    crate::cmd_build::cmd_build_impl(
        &graph,
        args.no_cache,
        cache.clone(),
        None,
        args.num_parallel_builds,
    )
    .await?;

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

        let encoder = zstd::stream::Encoder::new(Vec::new(), 3)?;
        let mut tar_builder = tar::Builder::new(encoder);
        tar_builder.append_dir_all(".", cache_dir)?;
        let archive_data = tar_builder.into_inner()?.finish()?;

        // Compute sha256 hash
        let hash_hex = {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(&archive_data);
            let computed_hash = hasher.finalize();
            hex::encode(computed_hash)
        };
        eprintln!("sha256({}) = {}", prebuilt_name, hash_hex);

        // Upload
        let gcs_path = format!("prebuilts/{}/{}", prebuilt_name, archive_name);
        remote_storage
            .upload(BUCKET_ID, &gcs_path, &archive_data)
            .await?;
        eprintln!(
            "Automatically uploaded prebuilt to gs://{}/{}",
            BUCKET_ID, gcs_path
        );

        // Update the prebuilts lockfile
        lockfile.update_hash(prebuilt_name.clone(), package_hash.0.to_hex().to_string());
        eprintln!("Updated prebuilts.lock with new hash for {}", prebuilt_name);

        if let Some(old_hash_hex) = prebuilt_sha256 {
            eprintln!(
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
                .status()?;
            if !status.success() {
                eprintln!(
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
