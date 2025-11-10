//! OCI image generation for minimal packages.
//!
//! This module provides functionality to create OCI-compliant container images
//! from minimal packages. It generates multi-layer images where each runtime dependency
//! becomes a separate layer.

use crate::{Error, Options, Runnable};
use common::SpecHash;
use flate2::{Compression, write::GzEncoder};
use globset::{Glob, GlobSet};
use graph::{BuildSpecRef, Transitives, TransitivesDep};
use oci_spec::image::{
    ANNOTATION_REF_NAME, ConfigBuilder, Descriptor, DescriptorBuilder, ImageConfigurationBuilder,
    ImageIndexBuilder, ImageManifestBuilder, MediaType, PlatformBuilder, RootFsBuilder,
    SCHEMA_VERSION, Sha256Digest,
};
use sha2::digest::OutputSizeUser;
#[allow(deprecated)]
use sha2::digest::generic_array::GenericArray;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::{Seek, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use tracing::info;

/// Creates an OCI image from a set of packages.
pub struct OciImageCreate {
    /// The packages to include in the image (used for logging)
    pub packages: Vec<String>,
    /// The output file path to write the OCI image tarball
    pub output_file: PathBuf,

    pub name: Option<String>,
    pub entrypoint: Option<String>,
    pub vars: HashMap<String, String>,
}

impl Runnable for OciImageCreate {
    type Result = ();

    async fn run<'b>(&mut self, opts: &Options<'b>) -> Result<Self::Result, Error> {
        let mut all_deps: Vec<(BuildSpecRef, TransitivesDep)> =
            Transitives::for_toplevels(opts.graph, opts.graph.top_levels.to_vec(), false)
                .into_iter()
                .collect();
        all_deps.sort_by_key(|(bsr, _)| opts.graph.get(bsr).unwrap().name.clone());

        info!("Creating OCI image for packages: {:?}", self.packages);
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
        let results =
            std::sync::Arc::new(std::sync::Mutex::new(Vec::with_capacity(all_deps.len())));
        rayon::scope(|s| {
            for (bsr, dep) in &all_deps {
                let tokio_runtime = tokio_runtime.clone();
                let results = results.clone();
                let cache = opts.cache.clone();

                let dep_spec = opts.graph.get(bsr).unwrap();
                let dep_hash = opts.graph.spec_hash(bsr);
                let match_globs = dep.outputs.as_ref().map(|set| {
                    GlobSet::new(set.iter().map(|output_name| {
                        Glob::new(dep_spec.outputs.get(output_name).unwrap().glob()).unwrap()
                    }))
                    .unwrap()
                });

                info!(
                    "Creating layer for: {}",
                    if match_globs.is_some() {
                        format!("{} (subset)", dep_spec.name)
                    } else {
                        dep_spec.name.to_string()
                    }
                );

                s.spawn(move |_| {
                    let _rt = tokio_runtime.enter();
                    let result = futures::executor::block_on(create_layer_from_cache(
                        &cache,
                        &dep_hash,
                        &dep_spec.name,
                        &match_globs,
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

        // Required reading: https://github.com/opencontainers/image-spec/blob/main/spec.md
        // index.json - entrypoint that points to a manifest descriptor
        // blobs/sha256/<manifest-digest> - image manifest, points to a image config and also all the layers in order
        // blobs/sha256/<image-config-digest> - image config, metadata about the image
        // blobs/sha256/<layer-gzip-digest> - the tar.gz of a filesystem layer
        let w = std::fs::File::create(&self.output_file)?;
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
                        .build()?,
                )
                .config({
                    let mut cb = ConfigBuilder::default();
                    if let Some(entrypoint) = &self.entrypoint {
                        cb = cb.entrypoint(shlex::split(entrypoint).unwrap());
                    };
                    if !self.vars.is_empty() {
                        cb = cb.env(
                            self.vars
                                .iter()
                                .map(|(k, v)| String::from_iter([k, "=", v]))
                                .collect::<Vec<_>>(),
                        );
                    }
                    cb.build().unwrap()
                })
                .build()?,
        )?;
        let mut th = tar::Header::new_gnu();
        th.set_mode(0o444);
        th.set_path(format!(
            "blobs/sha256/{:x}",
            Sha256::digest(&image_config_bytes)
        ))?;
        th.set_size(image_config_bytes.len() as u64);
        th.set_cksum();
        tb.append(&th, image_config_bytes.as_slice())?;

        // Image manifest - written out as blob object by hash
        let image_manifest_bytes = serde_json::to_vec(
            &ImageManifestBuilder::default()
                .schema_version(SCHEMA_VERSION)
                .config(
                    DescriptorBuilder::default()
                        .media_type(MediaType::ImageConfig)
                        .size(image_config_bytes.len() as u64)
                        .digest(Sha256Digest::from_str(&format!(
                            "{:x}",
                            sha2::Sha256::digest(&image_config_bytes)
                        ))?)
                        .build()?,
                )
                .layers(
                    layers
                        .iter()
                        .map(|l| l.descriptor.clone())
                        .collect::<Vec<_>>(),
                )
                .build()?,
        )?;
        let mut th = tar::Header::new_gnu();
        th.set_mode(0o444);
        th.set_path(format!(
            "blobs/sha256/{:x}",
            Sha256::digest(&image_manifest_bytes)
        ))?;
        th.set_size(image_manifest_bytes.len() as u64);
        th.set_cksum();
        tb.append(&th, image_manifest_bytes.as_slice())?;

        // Image index - index.json
        let image_index = ImageIndexBuilder::default()
            .schema_version(SCHEMA_VERSION)
            .media_type(MediaType::ImageIndex)
            .manifests(vec![
                DescriptorBuilder::default()
                    .media_type(MediaType::ImageManifest)
                    .size(image_manifest_bytes.len() as u64)
                    .digest(Sha256Digest::from_str(&format!(
                        "{:x}",
                        sha2::Sha256::digest(&image_manifest_bytes)
                    ))?)
                    .platform(
                        PlatformBuilder::default()
                            .os("linux")
                            .architecture("amd64")
                            .build()
                            .unwrap(),
                    )
                    .annotations({
                        let mut annotations = HashMap::new();
                        if let Some(name) = &self.name {
                            annotations.insert(ANNOTATION_REF_NAME.to_string(), name.clone());
                        }
                        annotations
                    })
                    .build()?,
            ])
            .build()?;
        let image_index_str = image_index.to_string().unwrap();
        let image_index_b = image_index_str.as_bytes();
        let mut th = tar::Header::new_gnu();
        th.set_path("index.json").unwrap();
        th.set_size(image_index_b.len() as u64);
        th.set_mode(0o644);
        th.set_cksum();
        tb.append(&th, image_index_b)?;

        // OCI Layout description - oci-layout
        let layout_b = "{\"imageLayoutVersion\": \"1.0.0\"}".as_bytes();
        let mut th = tar::Header::new_gnu();
        th.set_path("oci-layout").unwrap();
        th.set_size(layout_b.len() as u64);
        th.set_mode(0o644);
        th.set_cksum();
        tb.append(&th, layout_b)?;

        // Finally we write out each layer at "blobs/sha256/<sha256-hex>"
        for layer in layers {
            let mut th = tar::Header::new_gnu();
            th.set_mode(0o444);
            th.set_path(format!("blobs/sha256/{:x}", layer.compressed_sha256))?;
            th.set_size(layer.descriptor.size());
            th.set_cksum();
            tb.append(&th, layer.targz)?;
        }

        tb.finish()?;
        Ok(())
    }
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
    cache: &cache::Cache<cache::LocalDir>,
    spec_hash: &SpecHash,
    package_name: &str,
    match_globs: &Option<globset::GlobSet>,
) -> anyhow::Result<BuiltLayer> {
    let cache_entry = cache
        .read_dir(spec_hash)
        .map_err(|_| anyhow::anyhow!("Package {} not found in cache", package_name))?;

    let cache_dir = cache_entry.path();

    // Create tar.gz backed by temporary file
    let enc = GzEncoder::new(tempfile::tempfile()?, Compression::best());
    let mut tar = tar::Builder::new(enc);
    add_dir_to_tar(&mut tar, cache_dir, ".", match_globs)?;
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
        if match_globs.is_some() {
            format!("{} (subset)", package_name)
        } else {
            package_name.to_string()
        },
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
    match_globs: &Option<globset::GlobSet>,
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
            add_dir_to_tar(tar, &path, &tar_path.to_string_lossy(), match_globs)?;
        } else {
            // For files, only include them if there were no specified matchers,
            // or something matched.
            let matched = match_globs
                .as_ref()
                .map(|gs| gs.is_match(&tar_path))
                .unwrap_or(true);
            if matched {
                tar.append_path_with_name(&path, &tar_path)?;
            }
        }
    }
    Ok(())
}
