//! OCI image generation for minimal packages.
//!
//! This module provides functionality to create and push OCI-compliant container images
//! from minimal packages. It generates multi-layer images where each runtime dependency
//! becomes a separate layer,.

use cache::{Cache, LocalDir};
use common::SpecHash;
use docker_credential::{CredentialRetrievalError, DockerCredential, get_credential};
use flate2::{Compression, write::GzEncoder};
use graph::{BuildSpecRef, Transitives};
use oci_client::{Client, Reference, client::ClientConfig};
use oci_spec::image::{
    Descriptor, DescriptorBuilder, ImageConfiguration, ImageConfigurationBuilder, ImageManifest,
    ImageManifestBuilder, MediaType, RootFsBuilder, SCHEMA_VERSION, Sha256Digest,
};
use sha2::Digest;
use std::io::{Seek, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use tracing::{debug, info};

use crate::{Error, GlobalArgs, PackagesArg};

#[derive(clap::Args)]
pub struct OciImageArgs {
    /// Package names to materialize to the OCI image
    #[command(flatten)]
    packages: PackagesArg,

    /// Registry URL (e.g., ghcr.io/user/repo)
    #[arg(short, long)]
    registry: String,

    /// Image name
    #[arg(short, long)]
    name: String,

    /// Image tag
    #[arg(short, long)]
    tag: String,
}

pub async fn cmd_oci_image(args: OciImageArgs, globals: &GlobalArgs) -> Result<(), Error> {
    let graph = args.packages.graph(globals)?;
    let cache = globals.cache().map_err(anyhow::Error::from)?;

    // Make sure the packages are built
    crate::cmd_build::cmd_build_impl(
        &graph,
        globals,
        cache.clone(),
        globals.num_parallel_builds,
    )
    .await?;

    let mut all_deps: Vec<BuildSpecRef> =
        Transitives::for_toplevels(&graph, graph.top_levels.to_vec(), false)
            .into_iter()
            .collect();
    all_deps.sort_by_key(|bsr| graph.get(bsr).unwrap().name.clone());

    info!("Creating OCI image for packages: {}", args.packages);
    info!(
        "Will create {} layers: base layer + {} packages",
        all_deps.len() + 1,
        all_deps.len() - 1
    );

    let mut layers = Vec::new();
    let mut layer_diff_ids = Vec::new();
    let mut layer_data = Vec::new();

    // Create base layer with /lib64 symlink
    let (base_layer_descriptor, base_diff_id, base_layer_file, base_layer_digest) =
        create_base_layer().await?;
    layers.push(base_layer_descriptor);
    layer_diff_ids.push(base_diff_id);
    layer_data.push((base_layer_file, base_layer_digest));

    let tokio_runtime = tokio::runtime::Handle::current();
    let results = std::sync::Arc::new(std::sync::Mutex::new(Vec::with_capacity(all_deps.len())));
    rayon::scope(|s| {
        for dep_ref in &all_deps {
            let tokio_runtime = tokio_runtime.clone();
            let results = results.clone();
            let cache = cache.clone();

            let dep_spec = graph.get(dep_ref).unwrap();
            let dep_hash = graph.spec_hash(dep_ref);

            info!("Creating layer for: {}", dep_spec.name);

            s.spawn(move |_| {
                let _rt = tokio_runtime.enter();
                let result = futures::executor::block_on(create_layer_from_cache(
                    &cache,
                    &dep_hash,
                    &dep_spec.name,
                ));
                results.lock().unwrap().push(result);
            });
        }
    });

    let results = std::sync::Arc::into_inner(results)
        .unwrap()
        .into_inner()
        .unwrap()
        .into_iter()
        .collect::<Result<Vec<_>, _>>();

    for (layer_descriptor, diff_id, layer_file, layer_digest) in results? {
        layers.push(layer_descriptor);
        layer_diff_ids.push(diff_id);
        layer_data.push((layer_file, layer_digest));
    }

    let config = create_image_config(layer_diff_ids)?;
    let config_bytes = serde_json::to_vec(&config).map_err(anyhow::Error::from)?;
    let config_digest_hex = format!("{:x}", sha2::Sha256::digest(&config_bytes));
    let config_digest = format!("sha256:{}", config_digest_hex);
    let config_descriptor = create_config_descriptor(config_bytes.len() as u64, &config_digest)?;

    let manifest = ImageManifestBuilder::default()
        .schema_version(SCHEMA_VERSION)
        .config(config_descriptor)
        .layers(layers)
        .build()
        .map_err(anyhow::Error::from)?;

    push_to_registry(
        &args.registry,
        &args.name,
        &args.tag,
        manifest,
        config_bytes,
        layer_data,
    )
    .await?;

    info!(
        "Successfully pushed OCI image to {}/{}:{}",
        args.registry, args.name, args.tag
    );

    Ok(())
}

async fn create_base_layer() -> anyhow::Result<(Descriptor, String, std::fs::File, String)> {
    let enc = GzEncoder::new(tempfile::tempfile()?, Compression::best());
    let mut tar = tar::Builder::new(enc);

    let mut header = tar::Header::new_gnu();
    header.set_path("lib64")?;
    header.set_link_name("usr/lib")?;
    header.set_entry_type(tar::EntryType::Symlink);
    header.set_size(0);
    header.set_cksum();
    tar.append(&header, std::io::empty())?;

    tar.finish()?;
    let mut tar_file = tar.into_inner()?.finish()?;

    // Calculate digests
    let (sha256, compressed_len) = {
        let mut hasher = sha2::Sha256::new();
        tar_file.seek(std::io::SeekFrom::Start(0))?;
        let len = std::io::copy(&mut tar_file, &mut hasher)?;
        (hasher.finalize(), len)
    };
    let compressed_digest_hex = format!("{:x}", sha256);
    let compressed_digest = format!("sha256:{}", compressed_digest_hex);

    let uncompressed_digest = {
        tar_file.seek(std::io::SeekFrom::Start(0))?;
        let dec = flate2::read::GzDecoder::new(&tar_file);
        let mut hasher = sha2::Sha256::new();
        let mut reader = std::io::BufReader::new(dec);
        std::io::copy(&mut reader, &mut hasher)?;
        format!("sha256:{:x}", hasher.finalize())
    };

    let descriptor = DescriptorBuilder::default()
        .media_type(MediaType::ImageLayerGzip)
        .size(compressed_len)
        .digest(Sha256Digest::from_str(&compressed_digest_hex)?)
        .build()?;

    info!(
        "Created base layer with /lib64 symlink: {}",
        size::Size::from_bytes(compressed_len)
    );

    tar_file.seek(std::io::SeekFrom::Start(0))?;
    Ok((descriptor, uncompressed_digest, tar_file, compressed_digest))
}

async fn create_layer_from_cache(
    cache: &Cache<LocalDir>,
    spec_hash: &SpecHash,
    package_name: &str,
) -> anyhow::Result<(Descriptor, String, std::fs::File, String)> {
    let cache_entry = cache
        .read_dir(spec_hash)
        .map_err(|_| anyhow::anyhow!("Package {} not found in cache", package_name))?;

    let cache_dir = cache_entry.path();

    // Create tar.gz backed by temporary file
    let enc = GzEncoder::new(tempfile::tempfile()?, Compression::best());
    let mut tar = tar::Builder::new(enc);
    add_dir_to_tar(&mut tar, cache_dir, ".")?;
    tar.finish()?;
    let mut tar_file = tar.into_inner()?.finish()?;

    // Calculate digests
    let (sha256, compressed_len) = {
        let mut hasher = sha2::Sha256::new();
        tar_file.seek(std::io::SeekFrom::Start(0))?;
        let len = std::io::copy(&mut tar_file, &mut hasher)?;
        (hasher.finalize(), len)
    };
    let compressed_digest_hex = format!("{:x}", sha256);
    let compressed_digest = format!("sha256:{}", compressed_digest_hex);

    let uncompressed_digest = {
        tar_file.seek(std::io::SeekFrom::Start(0))?;
        let dec = flate2::read::GzDecoder::new(&tar_file);
        let mut hasher = sha2::Sha256::new();
        let mut reader = std::io::BufReader::new(dec);
        std::io::copy(&mut reader, &mut hasher)?;
        format!("sha256:{:x}", hasher.finalize())
    };

    let descriptor = DescriptorBuilder::default()
        .media_type(MediaType::ImageLayerGzip)
        .size(compressed_len)
        .digest(Sha256Digest::from_str(&compressed_digest_hex)?)
        .build()?;

    info!(
        "Created layer for {}: {}",
        package_name,
        size::Size::from_bytes(compressed_len)
    );

    tar_file.seek(std::io::SeekFrom::Start(0))?;
    Ok((descriptor, uncompressed_digest, tar_file, compressed_digest))
}

fn add_dir_to_tar<W: Write>(
    tar: &mut tar::Builder<W>,
    src_dir: &Path,
    tar_prefix: &str,
) -> anyhow::Result<()> {
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

fn create_image_config(layer_diff_ids: Vec<String>) -> anyhow::Result<ImageConfiguration> {
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

fn create_config_descriptor(size: u64, digest: &str) -> anyhow::Result<Descriptor> {
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
    name: &str,
    tag: &str,
    manifest: ImageManifest,
    config_bytes: Vec<u8>,
    layer_data: Vec<(std::fs::File, String)>,
) -> anyhow::Result<()> {
    let reference_string = format!("{}/{}:{}", registry, name, tag);
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

    let num_layers = layer_data.len();
    for (i, (mut layer_file, digest)) in layer_data.into_iter().enumerate() {
        layer_file.seek(std::io::SeekFrom::Start(0))?;
        let mut layer_bytes: Vec<u8> = Vec::with_capacity(1024 * 1024);
        std::io::copy(&mut layer_file, &mut layer_bytes)?;

        info!("Pushing layer {} of {}...", i + 1, num_layers);
        client.push_blob(&reference, &layer_bytes, &digest).await?;
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
