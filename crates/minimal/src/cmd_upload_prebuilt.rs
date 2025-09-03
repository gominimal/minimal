use crate::remote_storage::RemoteStorage;
use std::path::PathBuf;

#[derive(clap::Args)]
pub struct UploadPrebuiltArgs {
    /// Package name to upload prebuilt for
    #[arg(short, long)]
    package: String,

    /// Path to a directory to cache build outputs in
    #[arg(long)]
    cache_dir: Option<PathBuf>,
}

pub async fn cmd_upload_prebuilt(
    args: UploadPrebuiltArgs,
) -> Result<(), Box<dyn std::error::Error>> {
    let package_name = &args.package;

    // Load the package spec to compute its hash
    let spec_file = format!("packages/{}/build.ncl", package_name);
    let spec_path = std::path::Path::new(&spec_file);

    if !spec_path.exists() {
        return Err(format!("Package spec file not found: {}", spec_file).into());
    }

    // Load the SOURCE dependency graph for this package to get the correct hash
    let dp = super::graph_from_package_name(package_name, true);

    // Get the spec hash for the package
    let package_ref = dp
        .iter()
        .find(|(_, spec)| spec.name == *package_name)
        .map(|(bsr, _spec)| bsr)
        .ok_or_else(|| format!("Package '{}' not found in dependency graph", package_name))?;

    let spec_hash = dp.spec_hash(&package_ref);

    println!("Package: {}", package_name);
    println!("Spec hash: {}", spec_hash.0.to_hex());

    // Check if prebuilt directory exists
    let prebuilt_dir = PathBuf::from("packages")
        .join(package_name)
        .join("prebuilt");
    if !prebuilt_dir.exists() {
        return Err(format!("Prebuilt directory not found: {}", prebuilt_dir.display()).into());
    }

    println!("Creating archive from: {}", prebuilt_dir.display());

    // Create temporary archive file
    let temp_dir = std::env::temp_dir();
    let archive_name = format!("{}.tar.zst", spec_hash.0.to_hex());
    let temp_archive_path = temp_dir.join(&archive_name);

    // Create the tar.zst archive
    create_prebuilt_archive(&prebuilt_dir, &temp_archive_path)?;

    println!("Created archive: {}", temp_archive_path.display());

    // Upload to GCS
    let remote_storage = RemoteStorage::new().await?;
    let bucket_id = "minimal-staging-archives";
    let gcs_path = format!("prebuilts/{}/{}", package_name, archive_name);

    let archive_data = std::fs::read(&temp_archive_path)?;
    remote_storage
        .upload(bucket_id.to_string(), &gcs_path, &archive_data)
        .await?;

    println!("Uploaded to: gs://{}/{}", bucket_id, gcs_path);

    // Clean up temp file
    std::fs::remove_file(&temp_archive_path)?;

    println!("\nTo use this prebuilt archive, update your .ncl file to use:");
    println!("{{package = \"{}\"}} | Prebuilt,", package_name);
    println!("instead of Local file references.");

    Ok(())
}

fn create_prebuilt_archive(prebuilt_dir: &PathBuf, archive_path: &PathBuf) -> std::io::Result<()> {
    let file = std::fs::File::create(archive_path)?;
    let encoder = zstd::stream::Encoder::new(file, 3)?; // Compression level 3
    let mut tar_builder = tar::Builder::new(encoder);

    // Add all files from the prebuilt directory to the archive
    tar_builder.append_dir_all(".", prebuilt_dir)?;

    let encoder = tar_builder.into_inner()?;
    encoder.finish()?;

    Ok(())
}
