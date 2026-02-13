//! OCI image generation for minimal packages.
//!
//! This module provides functionality to create OCI-compliant container images
//! from minimal packages. It generates multi-layer images where each runtime dependency
//! becomes a separate layer.

use crate::{Error, Options, Runnable};
use common::{SpecHash, Tee};
use flate2::{Compression, write::GzEncoder};
use globset::{Glob, GlobSet};
use graph::{BuildSpecRef, Transitives, TransitivesDep};
use mfile::StrOrList;
use oci_spec::image::{
    ANNOTATION_REF_NAME, ConfigBuilder, Descriptor, DescriptorBuilder, ImageConfigurationBuilder,
    ImageIndexBuilder, ImageManifestBuilder, MediaType, PlatformBuilder, RootFsBuilder,
    SCHEMA_VERSION, Sha256Digest,
};
use sha2::digest::OutputSizeUser;
#[allow(deprecated)]
use sha2::digest::generic_array::GenericArray;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::io::{Seek, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use tracing::info;

#[derive(serde::Serialize, serde::Deserialize)]
struct LayerMeta {
    compressed_sha256: String,
    uncompressed_sha256: String,
    compressed_len: u64,
}

fn layer_cache_key(spec_hash: &SpecHash, output_names: &Option<&HashSet<String>>) -> blake3::Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"oci-layer-v1\0");
    hasher.update(spec_hash.as_bytes());
    if let Some(names) = output_names {
        let mut sorted: Vec<&String> = names.iter().collect();
        sorted.sort();
        for name in sorted {
            hasher.update(b"\0");
            hasher.update(name.as_bytes());
        }
    }
    hasher.finalize()
}

/// Creates an OCI image from a set of packages.
pub struct OciImageCreate {
    /// The packages to include in the image (used for logging)
    pub packages: Vec<String>,
    /// The output file path to write the OCI image tarball
    pub output_file: PathBuf,

    pub name: Option<String>,
    pub entrypoint: Option<mfile::StrOrList>,
    pub cmd: Option<mfile::StrOrList>,
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

        let layers_dir = opts.cache.root_path().join("layers");
        std::fs::create_dir_all(&layers_dir)?;

        let mut layers = Vec::new();

        // Create base layer with /lib64 symlink
        layers.push(create_base_layer(&layers_dir).await?);

        // Build all layers in parallel
        let tokio_runtime = tokio::runtime::Handle::current();
        let results =
            std::sync::Arc::new(std::sync::Mutex::new(Vec::with_capacity(all_deps.len())));
        rayon::scope(|s| {
            for (bsr, dep) in &all_deps {
                let tokio_runtime = tokio_runtime.clone();
                let results = results.clone();
                let cache = opts.cache.clone();
                let layers_dir = layers_dir.clone();

                let dep_spec = opts.graph.get(bsr).unwrap();
                let dep_hash = opts.graph.spec_hash(bsr);
                let match_globs = dep.outputs.as_ref().map(|set| {
                    GlobSet::new(set.iter().map(|output_name| {
                        Glob::new(dep_spec.outputs.get(output_name).unwrap().glob()).unwrap()
                    }))
                    .unwrap()
                });
                let output_names = dep.outputs.clone();

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
                        output_names.as_ref(),
                        &layers_dir,
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
                        cb = cb.entrypoint(match entrypoint {
                            StrOrList::Single(s) => shlex::split(s).unwrap(),
                            StrOrList::Multiple(v) => v.clone(),
                        });
                    };
                    if let Some(cmd) = &self.cmd {
                        cb = cb.cmd(match cmd {
                            StrOrList::Single(s) => shlex::split(s).unwrap(),
                            StrOrList::Multiple(v) => v.clone(),
                        });
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

/// Builds a layer by tar-ing + gzip-compressing, using a Tee to hash the uncompressed
/// tar stream inline (avoiding a separate decompression pass).
/// Returns (compressed_file, compressed_sha256, uncompressed_sha256, compressed_len).
#[allow(deprecated)]
fn build_layer_tee<F>(
    write_tar: F,
) -> anyhow::Result<(
    std::fs::File,
    GenericArray<u8, <Sha256 as OutputSizeUser>::OutputSize>,
    GenericArray<u8, <Sha256 as OutputSizeUser>::OutputSize>,
    u64,
)>
where
    F: FnOnce(&mut tar::Builder<Tee<GzEncoder<std::fs::File>, Sha256>>) -> anyhow::Result<()>,
{
    let compressed_file = tempfile::tempfile()?;
    let enc = GzEncoder::new(compressed_file, Compression::fast());
    let uncompressed_hasher = Sha256::new();
    let tee = Tee::new(enc, uncompressed_hasher);

    let mut tar = tar::Builder::new(tee);
    write_tar(&mut tar)?;
    tar.finish()?;

    let tee = tar.into_inner()?;
    let (enc, uncompressed_hasher) = tee.into_inner();
    let uncompressed_sha256 = uncompressed_hasher.finalize();

    let mut compressed_file = enc.finish()?;

    // Hash the compressed data
    let (compressed_sha256, compressed_len) = {
        let mut hasher = Sha256::new();
        compressed_file.seek(std::io::SeekFrom::Start(0))?;
        let len = std::io::copy(&mut compressed_file, &mut hasher)?;
        (hasher.finalize(), len)
    };

    compressed_file.seek(std::io::SeekFrom::Start(0))?;
    Ok((
        compressed_file,
        compressed_sha256,
        uncompressed_sha256,
        compressed_len,
    ))
}

fn load_cached_layer(layers_dir: &Path, key_hex: &str) -> anyhow::Result<Option<BuiltLayer>> {
    let meta_path = layers_dir.join(format!("{}.meta.json", key_hex));
    let targz_path = layers_dir.join(format!("{}.tar.gz", key_hex));

    let meta_bytes = match std::fs::read(&meta_path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let meta: LayerMeta = serde_json::from_slice(&meta_bytes)?;

    let targz = match std::fs::File::open(&targz_path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };

    let compressed_sha256 = hex_to_sha256_array(&meta.compressed_sha256)?;
    let uncompressed_sha256 = hex_to_sha256_array(&meta.uncompressed_sha256)?;

    let descriptor = DescriptorBuilder::default()
        .media_type(MediaType::ImageLayerGzip)
        .size(meta.compressed_len)
        .digest(Sha256Digest::from_str(&meta.compressed_sha256)?)
        .build()?;

    Ok(Some(BuiltLayer {
        descriptor,
        uncompressed_sha256,
        compressed_sha256,
        targz,
    }))
}

#[allow(deprecated)]
fn hex_to_sha256_array(
    hex: &str,
) -> anyhow::Result<GenericArray<u8, <Sha256 as OutputSizeUser>::OutputSize>> {
    let bytes = hex::decode(hex)?;
    if bytes.len() != 32 {
        anyhow::bail!("expected 32 bytes for sha256 hex, got {}", bytes.len());
    }
    Ok(GenericArray::clone_from_slice(&bytes))
}

fn save_layer_cache(
    layers_dir: &Path,
    key_hex: &str,
    compressed_file: &mut std::fs::File,
    meta: &LayerMeta,
) -> anyhow::Result<()> {
    // Write tar.gz to cache via temp file for atomicity
    let targz_path = layers_dir.join(format!("{}.tar.gz", key_hex));
    let tmp_targz = tempfile::NamedTempFile::new_in(layers_dir)?;
    compressed_file.seek(std::io::SeekFrom::Start(0))?;
    let mut tmp_writer = std::io::BufWriter::new(&tmp_targz);
    std::io::copy(compressed_file, &mut tmp_writer)?;
    tmp_writer.flush()?;
    drop(tmp_writer);
    tmp_targz.persist(&targz_path)?;

    // Write metadata
    let meta_path = layers_dir.join(format!("{}.meta.json", key_hex));
    let tmp_meta = tempfile::NamedTempFile::new_in(layers_dir)?;
    serde_json::to_writer(&tmp_meta, meta)?;
    tmp_meta.persist(&meta_path)?;

    compressed_file.seek(std::io::SeekFrom::Start(0))?;
    Ok(())
}

async fn create_base_layer(layers_dir: &Path) -> anyhow::Result<BuiltLayer> {
    let key = blake3::hash(b"oci-base-layer-v1");
    let key_hex = key.to_hex();

    if let Some(layer) = load_cached_layer(layers_dir, &key_hex)? {
        info!("Using cached base layer");
        return Ok(layer);
    }

    let (mut compressed_file, compressed_sha256, uncompressed_sha256, compressed_len) =
        build_layer_tee(|tar| {
            let mut header = tar::Header::new_gnu();
            header.set_path("lib64")?;
            header.set_link_name("usr/lib")?;
            header.set_entry_type(tar::EntryType::Symlink);
            header.set_size(0);
            header.set_cksum();
            tar.append(&header, std::io::empty())?;
            Ok(())
        })?;

    let meta = LayerMeta {
        compressed_sha256: format!("{:x}", compressed_sha256),
        uncompressed_sha256: format!("{:x}", uncompressed_sha256),
        compressed_len,
    };
    save_layer_cache(layers_dir, &key_hex, &mut compressed_file, &meta)?;

    let descriptor = DescriptorBuilder::default()
        .media_type(MediaType::ImageLayerGzip)
        .size(compressed_len)
        .digest(Sha256Digest::from_str(&format!("{:x}", compressed_sha256))?)
        .build()?;

    Ok(BuiltLayer {
        descriptor,
        uncompressed_sha256,
        compressed_sha256,
        targz: compressed_file,
    })
}

async fn create_layer_from_cache(
    cache: &cache::Cache<cache::LocalDir>,
    spec_hash: &SpecHash,
    package_name: &str,
    match_globs: &Option<globset::GlobSet>,
    output_names: Option<&HashSet<String>>,
    layers_dir: &Path,
) -> anyhow::Result<BuiltLayer> {
    let key = layer_cache_key(spec_hash, &output_names);
    let key_hex = key.to_hex();

    if let Some(layer) = load_cached_layer(layers_dir, &key_hex)? {
        info!(
            "Using cached layer for {}",
            if match_globs.is_some() {
                format!("{} (subset)", package_name)
            } else {
                package_name.to_string()
            }
        );
        return Ok(layer);
    }

    let cache_entry = cache
        .read_dir(spec_hash)
        .map_err(|_| anyhow::anyhow!("Package {} not found in cache", package_name))?;

    let cache_dir = cache_entry.path().to_path_buf();

    let (mut compressed_file, compressed_sha256, uncompressed_sha256, compressed_len) =
        build_layer_tee(|tar| {
            common::archive::add_dir_to_tar(tar, &cache_dir, ".", match_globs)?;
            Ok(())
        })?;

    let meta = LayerMeta {
        compressed_sha256: format!("{:x}", compressed_sha256),
        uncompressed_sha256: format!("{:x}", uncompressed_sha256),
        compressed_len,
    };
    save_layer_cache(layers_dir, &key_hex, &mut compressed_file, &meta)?;

    let descriptor = DescriptorBuilder::default()
        .media_type(MediaType::ImageLayerGzip)
        .size(compressed_len)
        .digest(Sha256Digest::from_str(&format!("{:x}", compressed_sha256))?)
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

    Ok(BuiltLayer {
        descriptor,
        uncompressed_sha256,
        compressed_sha256,
        targz: compressed_file,
    })
}
