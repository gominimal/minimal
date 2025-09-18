//! OCI image generation for minimal packages.
//!
//! This module provides functionality to create and push OCI-compliant container images
//! from minimal packages. It generates multi-layer images where each runtime dependency
//! becomes a separate layer,.

use anyhow::Result;
use cache::{Cache, CacheBinProvider, LocalDir};
use docker_credential::{CredentialRetrievalError, DockerCredential, get_credential};
use flate2::{Compression, write::GzEncoder};
use graph::{BuildSpecRef, DepGraph, ExecPlan, SpecHash, Transitives};
use oci_client::{Client, Reference, client::ClientConfig};
use oci_spec::image::{
    Descriptor, DescriptorBuilder, ImageConfiguration, ImageConfigurationBuilder, ImageManifest,
    ImageManifestBuilder, MediaType, RootFsBuilder, SCHEMA_VERSION, Sha256Digest,
};
use sha2::Digest;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use tracing::{debug, info};

use crate::{load_cache, lockfile::PrebuiltsLock, remote_storage::RemoteStorage, run::Run};

#[derive(clap::Args)]
pub struct OciImageArgs {
    /// Package name to create OCI image for
    #[arg(short, long)]
    package: String,

    /// Registry URL (e.g., ghcr.io/user/repo)
    #[arg(short, long)]
    registry: String,

    /// Image tag (defaults to package spec hash)
    #[arg(short, long)]
    tag: Option<String>,

    /// Path to a directory to cache build outputs in
    #[arg(long)]
    cache_dir: Option<PathBuf>,
}

pub async fn cmd_oci_image(args: OciImageArgs) -> Result<()> {
    let graph = crate::graph_from_package_name(&args.package);
    let cache = load_cache(args.cache_dir)?;

    let package_ref = graph
        .top_levels
        .first()
        .ok_or_else(|| anyhow::anyhow!("No package found for name: {}", args.package))?;

    ensure_package_built(&graph, *package_ref, &cache).await?;

    let transitives = Transitives::new(&graph, package_ref, false);
    let mut all_deps: Vec<BuildSpecRef> = transitives
        .transitive_runtime_deps
        .keys()
        .cloned()
        .collect();
    all_deps.sort_by_key(|bsr| graph.get(bsr).unwrap().name.clone());

    all_deps.push(*package_ref);

    info!("Creating OCI image for package: {}", args.package);
    info!(
        "Will create {} layers: base layer + {} dependencies + main package",
        all_deps.len() + 1,
        all_deps.len() - 1
    );

    let mut layers = Vec::new();
    let mut layer_diff_ids = Vec::new();
    let mut layer_data = Vec::new();

    // Create base layer with /lib64 symlink
    let (base_layer_descriptor, base_diff_id, base_layer_bytes, base_layer_digest) =
        create_base_layer().await?;
    layers.push(base_layer_descriptor);
    layer_diff_ids.push(base_diff_id);
    layer_data.push((base_layer_bytes, base_layer_digest));

    for dep_ref in &all_deps {
        let dep_spec = graph.get(dep_ref).unwrap();
        let dep_hash = graph.spec_hash(dep_ref);

        info!("Creating layer for: {}", dep_spec.name);

        let (layer_descriptor, diff_id, layer_bytes, layer_digest) =
            create_layer_from_cache(&cache, &dep_hash, &dep_spec.name).await?;
        layers.push(layer_descriptor);
        layer_diff_ids.push(diff_id);
        layer_data.push((layer_bytes, layer_digest));
    }

    let config = create_image_config(layer_diff_ids)?;
    let config_bytes = serde_json::to_vec(&config)?;
    let config_digest_hex = format!("{:x}", sha2::Sha256::digest(&config_bytes));
    let config_digest = format!("sha256:{}", config_digest_hex);
    let config_descriptor = create_config_descriptor(config_bytes.len() as u64, &config_digest)?;

    let manifest = ImageManifestBuilder::default()
        .schema_version(SCHEMA_VERSION)
        .config(config_descriptor)
        .layers(layers)
        .build()?;

    let tag = args
        .tag
        .unwrap_or_else(|| graph.spec_hash(package_ref).0.to_hex()[..12].to_string());

    push_to_registry(
        &args.registry,
        &args.package,
        &tag,
        manifest,
        config_bytes,
        layer_data,
    )
    .await?;

    info!(
        "Successfully pushed OCI image to {}/{}:{}",
        args.registry, args.package, tag
    );

    Ok(())
}

async fn ensure_package_built(
    graph: &DepGraph,
    package_ref: BuildSpecRef,
    cache: &Cache<LocalDir>,
) -> Result<()> {
    let package_hash = graph.spec_hash(&package_ref);

    if cache.read_dir(&package_hash).is_ok() {
        debug!("Package already built and cached");
        return Ok(());
    }

    info!("Package not in cache, building...");

    let remote_storage = RemoteStorage::new().await?;
    let lockfile_path = std::path::Path::new("prebuilts.lock");
    let lockfile = PrebuiltsLock::load(lockfile_path).unwrap_or_else(|e| {
        debug!(
            "Warning: Failed to load lockfile {}: {}",
            lockfile_path.display(),
            e
        );
        debug!("Using empty lockfile...");
        PrebuiltsLock::default()
    });
    let mut runner = Run::new(graph, cache.clone(), remote_storage, lockfile);
    runner
        .execute(
            ExecPlan::new_with_bin_provider(graph, CacheBinProvider::new(graph, cache.clone())),
            None,
        )
        .await?;

    Ok(())
}

async fn create_base_layer() -> Result<(Descriptor, String, Vec<u8>, String)> {
    let enc = GzEncoder::new(Vec::new(), Compression::default());
    let mut tar = tar::Builder::new(enc);

    let mut header = tar::Header::new_gnu();
    header.set_path("lib64")?;
    header.set_link_name("usr/lib")?;
    header.set_entry_type(tar::EntryType::Symlink);
    header.set_size(0);
    header.set_cksum();
    tar.append(&header, std::io::empty())?;

    tar.finish()?;
    let compressed_bytes = tar.into_inner()?.finish()?;

    let compressed_digest_hex = format!("{:x}", sha2::Sha256::digest(&compressed_bytes));
    let compressed_digest = format!("sha256:{}", compressed_digest_hex);

    let uncompressed_digest = {
        let dec = flate2::read::GzDecoder::new(&compressed_bytes[..]);
        let mut hasher = sha2::Sha256::new();
        let mut reader = std::io::BufReader::new(dec);
        std::io::copy(&mut reader, &mut hasher)?;
        format!("sha256:{:x}", hasher.finalize())
    };

    let descriptor = DescriptorBuilder::default()
        .media_type(MediaType::ImageLayerGzip)
        .size(compressed_bytes.len() as u64)
        .digest(Sha256Digest::from_str(&compressed_digest_hex)?)
        .build()?;

    info!(
        "Created base layer with /lib64 symlink: {} bytes",
        compressed_bytes.len()
    );

    Ok((
        descriptor,
        uncompressed_digest,
        compressed_bytes,
        compressed_digest,
    ))
}

async fn create_layer_from_cache(
    cache: &Cache<LocalDir>,
    spec_hash: &SpecHash,
    package_name: &str,
) -> Result<(Descriptor, String, Vec<u8>, String)> {
    let cache_entry = cache
        .read_dir(spec_hash)
        .map_err(|_| anyhow::anyhow!("Package {} not found in cache", package_name))?;

    let cache_dir = cache_entry.path();

    // Create tar.gz in memory
    let enc = GzEncoder::new(Vec::new(), Compression::default());
    let mut tar = tar::Builder::new(enc);

    add_dir_to_tar(&mut tar, cache_dir, ".")?;

    tar.finish()?;
    let compressed_bytes = tar.into_inner()?.finish()?;

    // Calculate digests
    let compressed_digest_hex = format!("{:x}", sha2::Sha256::digest(&compressed_bytes));
    let compressed_digest = format!("sha256:{}", compressed_digest_hex);

    let uncompressed_digest = {
        let dec = flate2::read::GzDecoder::new(&compressed_bytes[..]);
        let mut hasher = sha2::Sha256::new();
        let mut reader = std::io::BufReader::new(dec);
        std::io::copy(&mut reader, &mut hasher)?;
        format!("sha256:{:x}", hasher.finalize())
    };

    let descriptor = DescriptorBuilder::default()
        .media_type(MediaType::ImageLayerGzip)
        .size(compressed_bytes.len() as u64)
        .digest(Sha256Digest::from_str(&compressed_digest_hex)?)
        .build()?;

    info!(
        "Created layer for {}: {} bytes",
        package_name,
        compressed_bytes.len()
    );

    Ok((
        descriptor,
        uncompressed_digest,
        compressed_bytes,
        compressed_digest,
    ))
}

fn add_dir_to_tar<W: Write>(
    tar: &mut tar::Builder<W>,
    src_dir: &Path,
    tar_prefix: &str,
) -> Result<()> {
    for entry in std::fs::read_dir(src_dir)? {
        let entry = entry?;
        let path = entry.path();
        let name = entry.file_name();
        let tar_path = if tar_prefix == "." {
            PathBuf::from(name)
        } else {
            PathBuf::from(tar_prefix).join(name)
        };

        if path.is_dir() {
            tar.append_dir(&tar_path, &path)?;
            add_dir_to_tar(tar, &path, &tar_path.to_string_lossy())?;
        } else {
            tar.append_path_with_name(&path, &tar_path)?;
        }
    }
    Ok(())
}

fn create_image_config(layer_diff_ids: Vec<String>) -> Result<ImageConfiguration> {
    let rootfs = RootFsBuilder::default()
        .typ("layers")
        .diff_ids(layer_diff_ids)
        .build()?;

    let config = ImageConfigurationBuilder::default()
        .architecture("amd64")
        .os("linux")
        .rootfs(rootfs)
        .build()?;

    Ok(config)
}

fn create_config_descriptor(size: u64, digest: &str) -> Result<Descriptor> {
    let digest_hex = digest.strip_prefix("sha256:").unwrap_or(digest);

    let descriptor = DescriptorBuilder::default()
        .media_type(MediaType::ImageConfig)
        .size(size)
        .digest(Sha256Digest::from_str(digest_hex)?)
        .build()?;

    Ok(descriptor)
}

fn build_auth(reference: &Reference) -> oci_client::secrets::RegistryAuth {
    let server = reference.resolve_registry();
    debug!(
        "Attempting to load Docker credentials for registry: {}",
        server
    );

    match get_credential(server) {
        Err(CredentialRetrievalError::ConfigNotFound) => {
            debug!("No Docker config found, using anonymous authentication");
            oci_client::secrets::RegistryAuth::Anonymous
        }
        Err(CredentialRetrievalError::NoCredentialConfigured) => {
            debug!(
                "No credentials configured for registry {}, using anonymous authentication",
                server
            );
            oci_client::secrets::RegistryAuth::Anonymous
        }
        Err(CredentialRetrievalError::ConfigReadError) => {
            debug!("Failed to read Docker config, using anonymous authentication");
            oci_client::secrets::RegistryAuth::Anonymous
        }
        Err(CredentialRetrievalError::HelperFailure {
            helper,
            stdout,
            stderr,
        }) => {
            debug!(
                "Credential helper '{}' failed (stdout: {}, stderr: {}), using anonymous authentication",
                helper, stdout, stderr
            );
            oci_client::secrets::RegistryAuth::Anonymous
        }
        Err(e) => {
            debug!(
                "Credential retrieval failed: {:?}, using anonymous authentication",
                e
            );
            oci_client::secrets::RegistryAuth::Anonymous
        }
        Ok(DockerCredential::UsernamePassword(username, password)) => {
            info!(
                "Successfully loaded Docker credentials for registry: {}",
                server
            );
            oci_client::secrets::RegistryAuth::Basic(username, password)
        }
        Ok(DockerCredential::IdentityToken(_)) => {
            debug!("Identity token found but not supported, using anonymous authentication");
            oci_client::secrets::RegistryAuth::Anonymous
        }
    }
}

async fn push_to_registry(
    registry: &str,
    package_name: &str,
    tag: &str,
    manifest: ImageManifest,
    config_bytes: Vec<u8>,
    layer_data: Vec<(Vec<u8>, String)>,
) -> Result<()> {
    let reference_string = format!("{}/{}:{}", registry, package_name, tag);
    let reference = Reference::try_from(reference_string.as_str())?;

    let client = Client::new(ClientConfig {
        use_monolithic_push: true,
        ..Default::default()
    });

    info!("Authenticating with registry: {}", registry);
    let auth = build_auth(&reference);
    client
        .auth(&reference, &auth, oci_client::RegistryOperation::Push)
        .await?;

    info!("Pushing config blob...");
    let config_digest = format!("sha256:{:x}", sha2::Sha256::digest(&config_bytes));
    client
        .push_blob(&reference, &config_bytes, &config_digest)
        .await?;

    for (i, (layer_bytes, digest)) in layer_data.iter().enumerate() {
        info!("Pushing layer {} of {}...", i + 1, layer_data.len());
        client.push_blob(&reference, layer_bytes, digest).await?;
    }

    info!("Pushing manifest...");
    let manifest_bytes = serde_json::to_vec(&manifest)?;
    client
        .push_manifest_raw(
            &reference,
            manifest_bytes,
            "application/vnd.oci.image.manifest.v1+json".parse()?,
        )
        .await?;

    Ok(())
}
