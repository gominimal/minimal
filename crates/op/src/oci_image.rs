//! OCI image generation for minimal packages.
//!
//! This module provides functionality to create OCI-compliant container images
//! from minimal packages. It generates multi-layer images where each runtime dependency
//! becomes a separate layer.

use crate::materialize::{Emitter, MaterializeEvent};
use crate::{Error, Options};
use common::SpecHash;
use flate2::{Compression, write::GzEncoder};
use globset::{Glob, GlobSet};
use graph::{BuildSpecRef, Transitives, TransitivesDep};
use oci_spec::image::{
    ANNOTATION_REF_NAME, ConfigBuilder, Descriptor, DescriptorBuilder, ImageConfigurationBuilder,
    ImageIndexBuilder, ImageManifestBuilder, MediaType, PlatformBuilder, RootFsBuilder,
    SCHEMA_VERSION, Sha256Digest,
};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::Seek;
use std::str::FromStr;

/// An OCI image assembled from the built top levels of [`Options::graph`] and
/// their transitive runtime dependencies, one layer per package. The target
/// architecture comes from the graph.
pub(crate) struct OciImage<'a> {
    /// The image's `org.opencontainers.image.ref.name` annotation.
    pub name: &'a str,
    pub entrypoint: Option<&'a [String]>,
    pub cmd: Option<&'a [String]>,
    pub vars: &'a HashMap<String, String>,
}

impl OciImage<'_> {
    /// Writes the image tarball to `w` and returns it, so a caller that
    /// wrapped its sink can recover the wrapper.
    #[tracing::instrument(skip_all, err)]
    pub(crate) async fn write<W: std::io::Write>(
        &self,
        opts: &Options<'_>,
        w: W,
        events: &Emitter,
    ) -> Result<W, Error> {
        let mut all_deps: Vec<(BuildSpecRef, TransitivesDep)> =
            Transitives::for_toplevels(opts.graph, opts.graph.top_levels.to_vec(), false)
                .into_iter()
                .collect();
        all_deps.sort_by_key(|(bsr, _)| opts.graph.get(bsr).unwrap().name.clone());

        // Plus the base layer holding the /lib64 symlink.
        events.send(MaterializeEvent::Layers {
            total: all_deps.len() + 1,
        });

        let mut layers = Vec::new();

        // Create base layer with /lib64 symlink
        layers.push(create_base_layer().await?);

        // Build all layers in parallel
        let tokio_runtime = tokio::runtime::Handle::current();
        let results =
            std::sync::Arc::new(std::sync::Mutex::new(Vec::with_capacity(all_deps.len())));
        rayon::scope(|s| {
            for (dep_idx, (bsr, dep)) in all_deps.iter().enumerate() {
                let tokio_runtime = tokio_runtime.clone();
                let results = results.clone();
                let cache = opts.cache.clone();
                let events = events.clone();

                let dep_spec = opts.graph.get(bsr).unwrap();
                let dep_hash = opts.graph.spec_hash(bsr);
                let match_globs = dep.outputs.as_ref().map(|set| {
                    GlobSet::new(set.iter().map(|output_name| {
                        Glob::new(dep_spec.outputs.get(output_name).unwrap().glob()).unwrap()
                    }))
                    .unwrap()
                });

                events.send(MaterializeEvent::LayerStarted {
                    package: dep_spec.name.clone(),
                    subset: match_globs.is_some(),
                });

                s.spawn(move |_| {
                    let _rt = tokio_runtime.enter();
                    let result = futures::executor::block_on(create_layer_from_cache(
                        &cache,
                        &dep_hash,
                        &dep_spec.name,
                        &match_globs,
                        &events,
                    ));
                    results.lock().unwrap().push((dep_idx, result));
                });
            }
        });
        // Threads finish in scheduler order; layer order is part of the
        // manifest and therefore the image digest. Restore dep order.
        let mut results = std::sync::Arc::into_inner(results)
            .unwrap()
            .into_inner()
            .unwrap();
        results.sort_by_key(|(dep_idx, _)| *dep_idx);
        layers.extend(
            results
                .into_iter()
                .map(|(_, result)| result)
                .collect::<Result<Vec<_>, _>>()?,
        );

        // Required reading: https://github.com/opencontainers/image-spec/blob/main/spec.md
        // index.json - entrypoint that points to a manifest descriptor
        // blobs/sha256/<manifest-digest> - image manifest, points to a image config and also all the layers in order
        // blobs/sha256/<image-config-digest> - image config, metadata about the image
        // blobs/sha256/<layer-gzip-digest> - the tar.gz of a filesystem layer
        let mut tb = tar::Builder::new(w);

        // ImageConfig - written as blob object by hash
        let target = opts.graph.target();
        let arch = match target.arch() {
            common::target::Arch::Arm64 => "arm64",
            common::target::Arch::Amd64 => "amd64",
        };
        events.send(MaterializeEvent::Architecture {
            arch: arch.to_string(),
        });

        let image_config_bytes = serde_json_lenient::to_vec(
            &ImageConfigurationBuilder::default()
                .architecture(arch)
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
                    if let Some(entrypoint) = self.entrypoint {
                        cb = cb.entrypoint(entrypoint.to_vec());
                    };
                    if let Some(cmd) = self.cmd {
                        cb = cb.cmd(cmd.to_vec());
                    };
                    if !self.vars.is_empty() {
                        // HashMap iteration order is random per process; env
                        // order is part of the config blob and therefore the
                        // image digest. Sort by key.
                        let mut vars: Vec<_> = self.vars.iter().collect();
                        vars.sort_by_key(|(k, _)| k.as_str());
                        cb = cb.env(
                            vars.into_iter()
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
            "blobs/sha256/{}",
            hex::encode(Sha256::digest(&image_config_bytes))
        ))?;
        th.set_size(image_config_bytes.len() as u64);
        th.set_cksum();
        tb.append(&th, image_config_bytes.as_slice())?;

        // Image manifest - written out as blob object by hash
        let image_manifest_bytes = serde_json_lenient::to_vec(
            &ImageManifestBuilder::default()
                .schema_version(SCHEMA_VERSION)
                .config(
                    DescriptorBuilder::default()
                        .media_type(MediaType::ImageConfig)
                        .size(image_config_bytes.len() as u64)
                        .digest(Sha256Digest::from_str(&hex::encode(sha2::Sha256::digest(
                            &image_config_bytes,
                        )))?)
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
            "blobs/sha256/{}",
            hex::encode(Sha256::digest(&image_manifest_bytes))
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
                    .digest(Sha256Digest::from_str(&hex::encode(sha2::Sha256::digest(
                        &image_manifest_bytes,
                    )))?)
                    .platform(
                        PlatformBuilder::default()
                            .os("linux")
                            .architecture(arch)
                            .build()
                            .unwrap(),
                    )
                    .annotations(HashMap::from([(
                        ANNOTATION_REF_NAME.to_string(),
                        self.name.to_string(),
                    )]))
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
            th.set_path(format!(
                "blobs/sha256/{}",
                hex::encode(layer.compressed_sha256)
            ))?;
            th.set_size(layer.descriptor.size());
            th.set_cksum();
            tb.append(&th, layer.targz)?;
        }

        // `into_inner` finishes the archive and hands the sink back.
        Ok(tb.into_inner()?)
    }
}

struct BuiltLayer {
    descriptor: Descriptor,
    uncompressed_sha256: [u8; 32],
    compressed_sha256: [u8; 32],
    targz: std::fs::File,
}

impl BuiltLayer {
    fn uncompressed_digest(&self) -> String {
        format!("sha256:{}", hex::encode(self.uncompressed_sha256))
    }
}

#[tracing::instrument(err)]
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
    let (sha256, compressed_len): ([u8; 32], _) = {
        let mut hasher = common::HashWriter(sha2::Sha256::new());
        tar_file.seek(std::io::SeekFrom::Start(0))?;
        let len = std::io::copy(&mut tar_file, &mut hasher)?;
        (hasher.0.finalize().into(), len)
    };

    let uncompressed_sha256: [u8; 32] = {
        tar_file.seek(std::io::SeekFrom::Start(0))?;
        let dec = flate2::read::GzDecoder::new(&tar_file);
        let mut hasher = common::HashWriter(sha2::Sha256::new());
        let mut reader = std::io::BufReader::new(dec);
        std::io::copy(&mut reader, &mut hasher)?;
        hasher.0.finalize().into()
    };

    let descriptor = DescriptorBuilder::default()
        .media_type(MediaType::ImageLayerGzip)
        .size(compressed_len)
        .digest(Sha256Digest::from_str(&hex::encode(sha256))?)
        .build()?;

    tar_file.seek(std::io::SeekFrom::Start(0))?;
    Ok(BuiltLayer {
        descriptor,
        uncompressed_sha256,
        compressed_sha256: sha256,
        targz: tar_file,
    })
}

#[tracing::instrument(skip_all, fields(package_name = %package_name), err)]
async fn create_layer_from_cache(
    cache: &lcache::Cache<lcache::LocalDir>,
    spec_hash: &SpecHash,
    package_name: &str,
    match_globs: &Option<globset::GlobSet>,
    events: &Emitter,
) -> anyhow::Result<BuiltLayer> {
    let cache_entry = cache
        .read_dir(spec_hash)
        .map_err(|_| anyhow::anyhow!("Package {} not found in cache", package_name))?;

    let cache_dir = cache_entry.path();

    // Create tar.gz backed by temporary file
    let enc = GzEncoder::new(tempfile::tempfile()?, Compression::best());
    let mut tar = tar::Builder::new(enc);
    common::archive::add_dir_to_tar(&mut tar, cache_dir, ".", match_globs)?;
    tar.finish()?;
    let mut tar_file = tar.into_inner()?.finish()?;

    // Calculate digests
    let (sha256, compressed_len): ([u8; 32], _) = {
        let mut hasher = common::HashWriter(sha2::Sha256::new());
        tar_file.seek(std::io::SeekFrom::Start(0))?;
        let len = std::io::copy(&mut tar_file, &mut hasher)?;
        (hasher.0.finalize().into(), len)
    };

    let uncompressed_sha256: [u8; 32] = {
        tar_file.seek(std::io::SeekFrom::Start(0))?;
        let dec = flate2::read::GzDecoder::new(&tar_file);
        let mut hasher = common::HashWriter(sha2::Sha256::new());
        let mut reader = std::io::BufReader::new(dec);
        std::io::copy(&mut reader, &mut hasher)?;
        hasher.0.finalize().into()
    };

    let descriptor = DescriptorBuilder::default()
        .media_type(MediaType::ImageLayerGzip)
        .size(compressed_len)
        .digest(Sha256Digest::from_str(&hex::encode(sha256))?)
        .build()?;

    events.send(MaterializeEvent::LayerFinished {
        package: package_name.to_string(),
        subset: match_globs.is_some(),
        bytes: compressed_len,
    });

    tar_file.seek(std::io::SeekFrom::Start(0))?;
    Ok(BuiltLayer {
        descriptor,
        uncompressed_sha256,
        compressed_sha256: sha256,
        targz: tar_file,
    })
}
