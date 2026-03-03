use std::{
    collections::{HashMap, HashSet},
    io::SeekFrom,
    os::unix::fs::MetadataExt,
    path::PathBuf,
};

use crate::{Error, Options, Runnable};
use graph::{BuildDep, BuildSpec, BuildSpecRef, SourceFetch, SourceInput};
use res_proto::{
    BuildStatus, CommandParameters, CreateBuildRequest, DownloadRequest, InjectedFiles, Invocation,
    OutputArtifact, PollBuildRequest, TarballCompression, TarballFormat, UploadMessage,
    UploadRequest,
    injected_files::{FilesUpload, InjectedVariant, UnpackDest},
    remote_execution_service_client::RemoteExecutionServiceClient,
};
use tempfile::tempfile;
use tokio_stream::StreamExt;
use tonic::transport::Channel;

/// The return value of a successful remote build of a build-spec.
pub struct RemoteSpecBuildResult {
    pub build_ms: usize,
}

/// Something in a remote cache.
///
/// TODO: This interface is gonna need work. For starters, we need a type that describes a remote
/// cache rather than duplicating the details into here.
#[derive(Debug)]
pub struct RemoteDep {}

/// Details about where a dependency for a remote build is sourced.
#[derive(Debug)]
pub enum DepInner {
    /// Stream from the local cache.
    Local(BuildSpecRef, PathBuf),
    /// The executor should fetch.
    Remote(RemoteDep),
}

/// Describes a dependency for a build that will occur remotely.
pub struct Dep {
    /// The build-spec that this build satisfies.
    ///
    /// If a cycle-breaker is used, this field differs from the one
    /// described by inner.
    pub bsr: BuildSpecRef,
    /// Specific outputs to use instead of the whole build.
    pub outputs: Option<HashSet<String>>,
    /// Details about where the dependency is sourced.
    pub inner: DepInner,
}

/// Builds a spec on something implementing RES.
pub struct RemoteSpecBuild<'a> {
    /// The spec to be built.
    pub spec: &'a BuildSpecRef,
    /// The dependencies to be wired.
    pub deps: Vec<Dep>,

    pub client: RemoteExecutionServiceClient<Channel>,
}

impl<'a> RemoteSpecBuild<'a> {
    // Construct the array of layers which will form the execution environment.
    // self.deps[i] corresponds to layers[i], and any extra layers beyond the len
    // of self.deps corresponds to Local or Source build_deps.
    fn layers(&self, build: &BuildSpec) -> Vec<InjectedFiles> {
        self.deps
            .iter()
            .map(|d| match &d.inner {
                DepInner::Local(_bsr, _path) => InjectedFiles {
                    unpack_to: UnpackDest::DestRootfs.into(),
                    injected_variant: Some(InjectedVariant::FilesUpload(
                        res_proto::injected_files::FilesUpload {
                            upload_id: common::random_alphanumeric(8),
                            format: Some(TarballFormat {
                                compression: TarballCompression::TarZst.into(),
                            }),
                        },
                    )),
                },
                DepInner::Remote(remote) => todo!("remote dep: {:?}", remote),
            })
            .chain(build.build_deps.iter().filter_map(|i| match i {
                // Should be represented in the deps array
                BuildDep::Build(_) | BuildDep::Subset(_) => None,
                // Handle local files as additional uploads
                BuildDep::Local {
                    full_path,
                    filename,
                    file_hash: _,
                } => Some(InjectedFiles {
                    unpack_to: UnpackDest::DestBuilddir.into(),
                    injected_variant: Some(InjectedVariant::InlineFile(
                        res_proto::injected_files::InlineFile {
                            path: filename.clone(),
                            mode: std::fs::metadata(full_path).unwrap().mode(),
                            data: std::fs::read(full_path).unwrap(),
                        },
                    )),
                }),
                // Source entries map 1:1 to a Source proto
                BuildDep::Source(SourceInput {
                    extract,
                    from:
                        SourceFetch::Web {
                            url,
                            sha256,
                            url_pos: _,
                            sha256_pos: _,
                        },
                    strip_prefix,
                }) => Some(InjectedFiles {
                    unpack_to: UnpackDest::DestBuilddir.into(),
                    injected_variant: Some(InjectedVariant::Source(
                        res_proto::injected_files::Source {
                            url: url.clone(),
                            sha256: sha256.clone(),
                            extract: *extract,
                            strip_prefix: strip_prefix.to_owned().unwrap_or_default(),
                        },
                    )),
                }),
                BuildDep::Source(SourceInput {
                    extract: _,
                    from: SourceFetch::Local { filename, .. },
                    strip_prefix: _,
                }) => todo!("supporting local sources, i.e. {}", filename),

                BuildDep::HostPath(_) => todo!(),
            }))
            .collect()
    }

    /// Constructs the sub-proto describing the invocations in the execution environment.
    fn command_parameters(&self, build: &BuildSpec) -> Result<CommandParameters, Error> {
        if build.cmds.is_empty() || build.cmds[0].is_empty() {
            return Err(Error::Other(anyhow::anyhow!(
                "cannot build spec: no build command specified"
            )));
        }

        Ok(CommandParameters {
            invocations: build
                .cmds
                .iter()
                .map(|argv| Invocation {
                    argv: argv.clone(),
                    build_args: build
                        .build_args
                        .as_ref()
                        .map(|a| HashMap::from_iter(a.clone()))
                        .unwrap_or_default(),
                })
                .collect(),
            disable_networking: false, // TODO: set this properly
        })
    }
}

impl<'a> Runnable for RemoteSpecBuild<'a> {
    type Result = RemoteSpecBuildResult;

    async fn run<'b>(&mut self, opts: &Options<'b>) -> Result<Self::Result, Error> {
        let build = opts.graph.get(self.spec).unwrap();
        let client_id = format!("{}-{}", common::random_alphanumeric(8), build.name);

        let layers = self.layers(build);
        let _server_id = self
            .client
            .create_build(CreateBuildRequest {
                client_id: client_id.clone(),
                files: layers.clone(),
                command_parameters: Some(self.command_parameters(build)?),
                build_outputs: vec![OutputArtifact {
                    capture_globs: build
                        .outputs
                        .values()
                        .map(|output| match output {
                            graph::BuildOutput::Library {
                                glob,
                                allow_data: _,
                            } => glob.clone(),
                            graph::BuildOutput::Data {
                                glob,
                                allow_executable: _,
                            } => glob.clone(),
                            graph::BuildOutput::Binary { glob } => glob.clone(),
                        })
                        .collect(),
                    ..Default::default()
                }],
            })
            .await
            .map_err(|e| Error::Other(anyhow::Error::from(e)))?
            .into_inner()
            .server_id;

        // Build was accepted, lets upload everything that needs to be uploaded next, namely:
        // Layers which correspond to a [DepInner::Local]
        //
        // Layers which correspond to a Local input or Source input are not uploads, so we never
        // have to look at layers[i] where i exceeds self.deps.len().
        let uploads: Vec<_> = layers
            .iter()
            .zip(self.deps.iter())
            // Iterate layers and generate futures for uploading the local dep
            .filter_map(|(layer, dep)| {
                if let (
                    Some(InjectedVariant::FilesUpload(FilesUpload { upload_id, .. })),
                    DepInner::Local(_bsr, dir),
                ) = (&layer.injected_variant, &dep.inner)
                {
                    let upload_id = upload_id.clone();
                    let dir = dir.clone();
                    let client_id = client_id.clone();
                    let mut client = self.client.clone();

                    Some(async move {
                        let file =
                            tokio::task::spawn_blocking(move || -> Result<std::fs::File, Error> {
                                let (mut file, _hash) =
                                    common::archive::compress_dir(&dir, Some(1))
                                        .map_err(|e| Error::Other(e.into()))?;
                                std::io::Seek::rewind(&mut file)
                                    .map_err(|e| Error::Other(e.into()))?;
                                Ok(file)
                            })
                            .await
                            .map_err(|e| Error::Other(e.into()))??;

                        let data_stream = tokio_util::io::ReaderStream::new(
                            tokio::fs::File::from_std(file),
                        )
                        .map(|chunk| UploadMessage {
                            msg: Some(res_proto::upload_message::Msg::Chunk(
                                res_proto::UploadChunk {
                                    data: chunk.unwrap().to_vec(),
                                },
                            )),
                        });

                        client
                            .upload(
                                tokio_stream::once(UploadMessage {
                                    msg: Some(res_proto::upload_message::Msg::Request(
                                        UploadRequest {
                                            id: Some(res_proto::upload_request::Id {
                                                id: Some(
                                                    res_proto::upload_request::id::Id::ClientId(
                                                        client_id,
                                                    ),
                                                ),
                                            }),
                                            upload_id,
                                        },
                                    )),
                                })
                                .chain(data_stream),
                            )
                            .await
                            .map_err(|e| Error::Other(e.into()))?;

                        Ok::<(), Error>(())
                    })
                } else {
                    None
                }
            })
            .collect();

        // Await all uploads concurrently, failing fast if any error occurs
        futures::future::try_join_all(uploads).await?;

        // Now we poll the build until its done!
        let start_time = std::time::Instant::now();
        let timeout = std::time::Duration::from_secs(60 * 30);

        loop {
            // Check if we've exceeded the timeout
            if start_time.elapsed() > timeout {
                return Err(Error::Other(anyhow::anyhow!(
                    "Remote build timed out after 30 minutes"
                )));
            }

            let status = self
                .client
                .poll_build(PollBuildRequest {
                    id: Some(res_proto::poll_build_request::Id {
                        id: Some(res_proto::poll_build_request::id::Id::ClientId(
                            client_id.clone(),
                        )),
                    }),
                })
                .await
                .map_err(|e| Error::Other(e.into()))?;

            if status.get_ref().status() == BuildStatus::StatusDone {
                let mut output_stream = self
                    .client
                    .download(DownloadRequest {
                        id: Some(res_proto::download_request::Id {
                            id: Some(res_proto::download_request::id::Id::ClientId(
                                client_id.clone(),
                            )),
                        }),
                    })
                    .await
                    .map_err(|e| Error::Other(e.into()))?
                    .into_inner();

                let mut temp_file =
                    tokio::fs::File::from_std(tempfile().map_err(|e| Error::Other(e.into()))?);
                // Stream the download data and write to the temporary file
                while let Some(download_data) = output_stream.next().await {
                    let download_data = download_data.map_err(|e| Error::Other(e.into()))?;
                    tokio::io::AsyncWriteExt::write_all(&mut temp_file, &download_data.data)
                        .await
                        .map_err(|e| Error::Other(e.into()))?;
                }
                // Decompress the data into the local cache.
                let into_dir = opts.cache.write_dir(&opts.graph.spec_hash(self.spec))?;
                tokio::io::AsyncSeekExt::seek(&mut temp_file, SeekFrom::Start(0))
                    .await
                    .unwrap();
                common::archive::extract_compressed_tar(
                    &mut temp_file.into_std().await,
                    common::archive::Compression::Zstd,
                    into_dir.path(),
                    None,
                )
                .map_err(|e| Error::Other(e.into()))?;

                into_dir.finalize(lcache::EntryMeta {
                    inner: lcache::MetaInner::Spec(build.name.clone()),
                    origin: Some(build.from.as_ref().clone()),
                    ..Default::default()
                })?;

                return Ok(RemoteSpecBuildResult { build_ms: 67 });
            }

            // Sleep for a bit before polling again
            tokio::time::sleep(tokio::time::Duration::from_millis(250)).await;
        }
    }
}
