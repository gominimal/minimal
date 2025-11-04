//! OCI image generation for minimal packages.
//!
//! This module provides functionality to create and push OCI-compliant container images
//! from minimal packages. It generates multi-layer images where each runtime dependency
//! becomes a separate layer,.

use cache::{Cache, LocalDir};
use common::SpecHash;
use flate2::{Compression, write::GzEncoder};
use graph::{BuildSpecRef, Transitives};
use oci_spec::image::{
    Descriptor, DescriptorBuilder, ImageConfigurationBuilder, ImageIndexBuilder, MediaType,
    PlatformBuilder, RootFsBuilder, SCHEMA_VERSION, Sha256Digest,
};
use sha2::digest::OutputSizeUser;
#[allow(deprecated)]
use sha2::digest::generic_array::GenericArray;
use sha2::{Digest, Sha256};
use std::io::{Seek, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use tracing::info;

use crate::{Context, Error, PackagesArg};

#[derive(clap::Args)]
pub struct OciImageArgs {
    /// Package names to materialize to the OCI image
    #[command(flatten)]
    packages: PackagesArg,

    /// The tarfile to write
    #[arg(short, long)]
    output: PathBuf,
}

pub async fn cmd_oci_image(args: OciImageArgs, ctx: &mut Context) -> Result<(), Error> {
    let graph = args.packages.graph(ctx)?;
    let cache = ctx.local_cache();

    // Make sure the packages are built
    crate::cmd_build::cmd_build_impl(&graph, ctx, cache.clone(), ctx.num_parallel_builds).await?;

    let mut all_deps: Vec<BuildSpecRef> =
        Transitives::for_toplevels(&graph, graph.top_levels.to_vec(), false)
            .into_iter()
            .collect();
    all_deps.sort_by_key(|bsr| graph.get(bsr).unwrap().name.clone());

    info!("Creating OCI image for packages: {}", args.packages);
    info!(
        "Will create {} layers: base layer + {} packages",
        all_deps.len() + 1,
        all_deps.len()
    );

    let mut layers = Vec::new();

    // Create base layer with /lib64 symlink
    layers.push(create_base_layer().await?);

    // Build all layers in parallel
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
    layers.extend(
        std::sync::Arc::into_inner(results)
            .unwrap()
            .into_inner()
            .unwrap()
            .into_iter()
            .collect::<Result<Vec<_>, _>>()?
            .into_iter(),
    );

    let w = std::fs::File::create(args.output).map_err(anyhow::Error::from)?;
    let mut tb = tar::Builder::new(w);

    // ImageConfig - written as blob object by hash
    let image_config_bytes = serde_json::to_vec(
        &ImageConfigurationBuilder::default()
            .architecture("amd64")
            .os("linux")
            .rootfs(
                RootFsBuilder::default()
                    .typ("layers")
                    .diff_ids(
                        layers
                            .iter()
                            .map(|l| l.uncompressed_digest())
                            .collect::<Vec<_>>(),
                    )
                    .build()
                    .map_err(anyhow::Error::from)?,
            )
            .build()
            .map_err(anyhow::Error::from)?,
    )
    .map_err(anyhow::Error::from)?;
    let mut th = tar::Header::new_gnu();
    th.set_mode(0o444);
    th.set_path(format!(
        "blobs/sha256/{:x}",
        Sha256::digest(&image_config_bytes)
    ))
    .map_err(anyhow::Error::from)?;
    th.set_size(image_config_bytes.len() as u64);
    th.set_cksum();
    tb.append(&th, image_config_bytes.as_slice())
        .map_err(anyhow::Error::from)?;

    // Image index - index.json
    let image_index = ImageIndexBuilder::default()
        .schema_version(SCHEMA_VERSION)
        .media_type(MediaType::ImageIndex)
        .manifests(vec![
            DescriptorBuilder::default()
                .media_type(MediaType::ImageConfig)
                .size(image_config_bytes.len() as u64)
                .digest(
                    Sha256Digest::from_str(&format!(
                        "{:x}",
                        sha2::Sha256::digest(&image_config_bytes)
                    ))
                    .map_err(anyhow::Error::from)?,
                )
                .platform(
                    PlatformBuilder::default()
                        .os("linux")
                        .architecture("amd64")
                        .build()
                        .unwrap(),
                )
                .build()
                .map_err(anyhow::Error::from)?,
        ])
        .build()
        .map_err(anyhow::Error::from)?;
    let image_index_str = image_index.to_string().unwrap();
    let image_index_b = image_index_str.as_bytes();
    let mut th = tar::Header::new_gnu();
    th.set_path("index.json").unwrap();
    th.set_size(image_index_b.len() as u64);
    th.set_mode(0o644);
    th.set_cksum();
    tb.append(&th, image_index_b).map_err(anyhow::Error::from)?;

    // OCI Layout description - oci-layout
    let layout_b = "{\"imageLayoutVersion\": \"1.0.0\"}".as_bytes();
    let mut th = tar::Header::new_gnu();
    th.set_path("oci-layout").unwrap();
    th.set_size(layout_b.len() as u64);
    th.set_mode(0o644);
    th.set_cksum();
    tb.append(&th, layout_b).map_err(anyhow::Error::from)?;

    // Finally we write out each layer at "blobs/sha256/<sha256-hex>"
    for layer in layers {
        let mut th = tar::Header::new_gnu();
        th.set_mode(0o444);
        th.set_path(format!("blobs/sha256/{:x}", layer.compressed_sha256))
            .map_err(anyhow::Error::from)?;
        th.set_size(layer.descriptor.size());
        th.set_cksum();
        tb.append(&th, layer.targz).map_err(anyhow::Error::from)?;
    }

    tb.finish().map_err(anyhow::Error::from)?;
    Ok(())
}

#[allow(deprecated)]
struct BuiltLayer {
    descriptor: Descriptor,
    uncompressed_sha256: GenericArray<u8, <Sha256 as OutputSizeUser>::OutputSize>,
    compressed_sha256: GenericArray<u8, <Sha256 as OutputSizeUser>::OutputSize>,
    targz: std::fs::File,
}

impl BuiltLayer {
    fn uncompressed_digest(&self) -> String {
        format!("sha256:{:x}", self.uncompressed_sha256)
    }
}

async fn create_base_layer() -> anyhow::Result<BuiltLayer> {
    let enc = GzEncoder::new(tempfile::tempfile()?, Compression::none()); // TODO: Back to reasonable setting
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

    let uncompressed_sha256 = {
        tar_file.seek(std::io::SeekFrom::Start(0))?;
        let dec = flate2::read::GzDecoder::new(&tar_file);
        let mut hasher = sha2::Sha256::new();
        let mut reader = std::io::BufReader::new(dec);
        std::io::copy(&mut reader, &mut hasher)?;
        hasher.finalize()
    };

    let descriptor = DescriptorBuilder::default()
        .media_type(MediaType::ImageLayerGzip)
        .size(compressed_len)
        .digest(Sha256Digest::from_str(&format!("{:x}", sha256))?)
        .build()?;

    tar_file.seek(std::io::SeekFrom::Start(0))?;
    Ok(BuiltLayer {
        descriptor,
        uncompressed_sha256,
        compressed_sha256: sha256,
        targz: tar_file,
    })
}

async fn create_layer_from_cache(
    cache: &Cache<LocalDir>,
    spec_hash: &SpecHash,
    package_name: &str,
) -> anyhow::Result<BuiltLayer> {
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

    let uncompressed_sha256 = {
        tar_file.seek(std::io::SeekFrom::Start(0))?;
        let dec = flate2::read::GzDecoder::new(&tar_file);
        let mut hasher = sha2::Sha256::new();
        let mut reader = std::io::BufReader::new(dec);
        std::io::copy(&mut reader, &mut hasher)?;
        hasher.finalize()
    };

    let descriptor = DescriptorBuilder::default()
        .media_type(MediaType::ImageLayerGzip)
        .size(compressed_len)
        .digest(Sha256Digest::from_str(&format!("{:x}", sha256))?)
        .build()?;

    info!(
        "Created layer for {}: {}",
        package_name,
        size::Size::from_bytes(compressed_len)
    );

    tar_file.seek(std::io::SeekFrom::Start(0))?;
    Ok(BuiltLayer {
        descriptor,
        uncompressed_sha256,
        compressed_sha256: sha256,
        targz: tar_file,
    })
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
