use std::path::Path;
use std::pin::Pin;
use std::{borrow::Cow, collections::HashMap};

use anyhow::anyhow;
use common::SpecHash;
use futures::StreamExt;
use futures::channel::mpsc;
use graph::Graph;
use orchestrator::{BuildEvent, BuildEventInner};
use remote_execution_service_client::RemoteExecutionServiceClient as RESClient;
use remote_proto::{res::*, *};
use tempfile::NamedTempFile;
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tonic::transport::{Channel, Error as TransportError};

type CreateEnvStream = Pin<Box<dyn futures::Stream<Item = CreateEnvMessage> + Send>>;
type CreateBuildStream = Pin<Box<dyn futures::Stream<Item = OrchestrateBuildMessage> + Send>>;

/// Errors that can occur when driving a remote client.
#[derive(Debug)]
pub enum Error {
    Transport(TransportError),
    Other(Box<dyn std::error::Error + Send + Sync>),
}

/// Describes files that an environment can operate on or with.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum Worktree<'a> {
    /// Create a new empty cwd for this environment.
    #[default]
    Ephemeral,
    /// Stream across a copy of the given directory.
    Dir(Cow<'a, Path>),
}

/// A connection to a server providing the remote execution service.
pub struct Client<'a, T = Channel> {
    c: RESClient<T>,
    g: &'a Graph,
}

impl<'a> Client<'a, Channel> {
    /// Connects to the given gRPC endpoint.
    pub async fn connect<S: Into<String>>(addr: S, g: &'a Graph) -> Result<Self, TransportError> {
        Ok(Self {
            c: RESClient::connect(addr.into()).await?,
            g,
        })
    }
}

impl<'a, T> Client<'a, T> {
    /// Creates a new [Client] from an existing grpc client structure.
    pub fn new(c: RESClient<T>, g: &'a Graph) -> Self {
        Self { c, g }
    }
}

impl<'a, T: Clone> Clone for Client<'a, T> {
    fn clone(&self) -> Self {
        Self {
            c: self.c.clone(),
            g: self.g,
        }
    }
}

impl<'a, T> Client<'a, T>
where
    T: tonic::client::GrpcService<tonic::body::Body>,
    T::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    T::ResponseBody: http_body::Body<Data = bytes::Bytes> + Send + 'static,
    <T::ResponseBody as http_body::Body>::Error:
        Into<Box<dyn std::error::Error + Send + Sync>> + Send,
{
    pub async fn make_env<'b>(&mut self, cwd: Worktree<'b>) -> Result<Env<'b>, Error> {
        use create_env_message::*;
        let client_id = format!(
            "{}-{}",
            common::random_alphanumeric(8),
            common::random_alphanumeric(8)
        );

        // Stream the graph using the async wire writer through a duplex pipe.
        use stream_config::*;
        let (graph_writer, graph_reader) = tokio::io::duplex(8 * 1024);
        let graph_clone = self.g.clone();
        tokio::spawn(async move {
            graph::wire::AsyncGraphWriter::new(graph_writer)
                .write_graph(&graph_clone)
                .await
                .expect("graph wire serialization failed");
        });
        let graph_stream: (StreamConfig, CreateEnvStream) = (
            StreamConfig {
                format: Some(Format::Graph(GraphFormat::GfStreamingV1.into())),
                kind: StreamKind::SkGraph.into(),
            },
            Box::pin(
                tokio_util::io::ReaderStream::new(graph_reader)
                    .filter_map(|result| async { result.ok() })
                    .map(|bytes| CreateEnvMessage {
                        msg: Some(Msg::Chunk(StreamChunk {
                            idx: 0,
                            data: bytes.to_vec(),
                        })),
                    }),
            ),
        );

        let worktree_stream: Option<(StreamConfig, CreateEnvStream)> = match cwd {
            Worktree::Ephemeral => None,
            Worktree::Dir(ref d) => {
                let dir = d.clone().into_owned();
                let chunk_stream: CreateEnvStream = Box::pin(
                    futures::stream::once(async move {
                        let file =
                            tokio::task::spawn_blocking(move || -> Result<std::fs::File, Error> {
                                let (mut file, _hash) =
                                    common::archive::compress_dir(&dir, Some(-5), &None)
                                        .map_err(|e| Error::Other(e.into()))?;
                                std::io::Seek::rewind(&mut file)
                                    .map_err(|e| Error::Other(e.into()))?;
                                Ok(file)
                            })
                            .await
                            .map_err(|e| Error::Other(e.into()))
                            .and_then(|r| r)
                            .unwrap(); // TODO: propagate error

                        tokio_util::io::ReaderStream::new(tokio::fs::File::from_std(file))
                            .filter_map(|result| async { result.ok() })
                            .map(|bytes| CreateEnvMessage {
                                msg: Some(Msg::Chunk(StreamChunk {
                                    idx: 0,
                                    data: bytes.to_vec(),
                                })),
                            })
                    })
                    .flatten(),
                );

                Some((
                    StreamConfig {
                        format: Some(Format::Files(FilesFormat {
                            tarball: Some(TarballFormat {
                                compression: TarballCompression::TarZst.into(),
                            }),
                        })),
                        kind: StreamKind::SkWorktree.into(),
                    },
                    chunk_stream,
                ))
            }
        };

        let stream_configs: Vec<StreamConfig> = [Some(&graph_stream), worktree_stream.as_ref()]
            .into_iter()
            .filter_map(|s| s.as_ref().map(|(sc, _)| *sc))
            .collect();
        let request_msg = tokio_stream::once({
            let client_id = client_id.clone();

            CreateEnvMessage {
                msg: Some(Msg::Request(CreateEnvRequest {
                    client_id,
                    streams: stream_configs,
                    expiry_minutes: 6 * 60,
                })),
            }
        });

        let streams: CreateEnvStream = Box::pin(
            futures::stream::iter(
                vec![Some(graph_stream), worktree_stream]
                    .into_iter()
                    .flatten()
                    .enumerate()
                    .map(|(idx, (_, chunks))| {
                        let idx = idx as u32;
                        chunks.map(move |mut msg| {
                            if let Some(Msg::Chunk(ref mut chunk)) = msg.msg {
                                chunk.idx = idx;
                            }
                            msg
                        })
                    }),
            )
            .flatten(),
        );
        let tx_result = self
            .c
            .create_env(request_msg.chain(streams))
            .await
            .map_err(|e| Error::Other(e.into()))?
            .into_inner();

        Ok(Env {
            client_id,
            cwd,
            server_id: tx_result.server_id,
        })
    }

    pub async fn exec<'b>(
        &mut self,
        env: &Env<'b>,
        args: &ExecArgs,
        mut stdout: Option<&mut (dyn AsyncWrite + Unpin + Send)>,
        mut stderr: Option<&mut (dyn AsyncWrite + Unpin + Send)>,
    ) -> Result<u32, Error> {
        let mut stream = self
            .c
            .exec(CreateTaskRequest {
                client_id: env.client_id.clone(),
                args: args.args.clone(),
                env_vars: args.env_vars.clone(),
                packages: args.packages.clone(),
            })
            .await
            .map_err(|e| Error::Other(e.into()))?
            .into_inner();

        let mut exit_code = 0;
        while let Some(resp) = stream.next().await {
            let resp = resp.map_err(|e| Error::Other(e.into()))?;
            match resp.msg {
                Some(create_task_response::Msg::Data(data)) => {
                    match task_data::Channel::try_from(data.kind) {
                        Ok(task_data::Channel::ChStdout) => {
                            if let Some(w) = stdout.as_mut() {
                                w.write_all(&data.data)
                                    .await
                                    .map_err(|e| Error::Other(e.into()))?;
                            }
                        }
                        Ok(task_data::Channel::ChStderr) => {
                            if let Some(w) = stderr.as_mut() {
                                w.write_all(&data.data)
                                    .await
                                    .map_err(|e| Error::Other(e.into()))?;
                            }
                        }
                        _ => {}
                    }
                }
                Some(create_task_response::Msg::Status(status)) => {
                    exit_code = status.exit_code;
                }
                None => {}
            }
        }

        Ok(exit_code)
    }

    pub async fn build(
        &mut self,
        verbose: bool,
        commit_results: bool,
        rebuild_top_levels: bool,
        remote_cache_bucket: Option<String>,
        log_sink: Option<mpsc::UnboundedSender<BuildEvent>>,
    ) -> Result<(), Error> {
        use orchestrate_build_message::*;
        let client_id = format!(
            "{}-{}",
            common::random_alphanumeric(8),
            common::random_alphanumeric(8)
        );

        // Stream the graph using the async wire writer through a duplex pipe.
        use stream_config::*;
        let (graph_writer, graph_reader) = tokio::io::duplex(8 * 1024);
        let graph_clone = self.g.clone();
        tokio::spawn(async move {
            graph::wire::AsyncGraphWriter::new(graph_writer)
                .write_graph(&graph_clone)
                .await
                .expect("graph wire serialization failed");
        });
        let (graph_config, graph_stream): (StreamConfig, CreateBuildStream) = (
            StreamConfig {
                format: Some(Format::Graph(GraphFormat::GfStreamingV1.into())),
                kind: StreamKind::SkGraph.into(),
            },
            Box::pin(
                tokio_util::io::ReaderStream::new(graph_reader)
                    .filter_map(|result| async { result.ok() })
                    .map(|bytes| OrchestrateBuildMessage {
                        msg: Some(Msg::Chunk(StreamChunk {
                            idx: 0,
                            data: bytes.to_vec(),
                        })),
                    }),
            ),
        );

        let request_msg = tokio_stream::once({
            let client_id = client_id.clone();
            OrchestrateBuildMessage {
                msg: Some(Msg::Request(OrchestrateBuildRequest {
                    client_id,
                    graph_stream: Some(graph_config),
                    verbose,
                    commit: commit_results,
                    rebuild_top_levels,
                    remote_cache_gcs_bucket: remote_cache_bucket,
                })),
            }
        });
        let mut rpc = self
            .c
            .orchestrate_build(request_msg.chain(graph_stream))
            .await
            .map_err(|e| Error::Other(e.into()))?
            .into_inner();

        // Read the setup status
        match rpc.next().await {
            Some(Ok(OrchestrateBuildResponse {
                msg: Some(orchestrate_build_response::Msg::Resp(_)),
            })) => Ok(()),
            Some(Err(e)) => Err(Error::Other(e.into())),
            _ => Err(Error::Other(
                anyhow!("expected orchestrate_build setup status").into(),
            )),
        }?;

        while let Some(msg) = rpc.next().await {
            let msg = msg.map_err(|e| Error::Other(e.into()))?;

            match msg.msg {
                Some(orchestrate_build_response::Msg::Start(s)) => {
                    if let Some(ref sink) = log_sink {
                        let _ = sink.unbounded_send(BuildEvent {
                            idx: s.build_id as usize,
                            inner: BuildEventInner::Start {
                                name: s.name,
                                full_build: s.full_build,
                                spec_hash: s.spec_hash,
                            },
                        });
                    }
                }
                Some(orchestrate_build_response::Msg::Stop(s)) => {
                    if let Some(ref sink) = log_sink {
                        let _ = sink.unbounded_send(BuildEvent {
                            idx: s.build_id as usize,
                            inner: BuildEventInner::Stop,
                        });
                    }
                }
                Some(orchestrate_build_response::Msg::Line(log_line)) => {
                    if let Some(ref sink) = log_sink {
                        let _ = sink.unbounded_send(BuildEvent {
                            idx: log_line.build_id as usize,
                            inner: BuildEventInner::Log {
                                is_stderr: log_line.stderr,
                                line: log_line.line,
                            },
                        });
                    }
                }
                Some(orchestrate_build_response::Msg::Hydrate(h)) => {
                    if let Some(ref sink) = log_sink {
                        let _ = sink.unbounded_send(BuildEvent {
                            idx: h.build_id as usize,
                            inner: BuildEventInner::Hydrate {
                                name: h.name,
                                spec_hash: h.spec_hash,
                            },
                        });
                    }
                }
                Some(orchestrate_build_response::Msg::Err(e)) => {
                    return Err(Error::Other(
                        anyhow!("orchestration failed: {}", e.msg).into(),
                    ));
                }
                Some(orchestrate_build_response::Msg::Resp(_)) => unreachable!(),
                None => {}
            }
        }

        Ok(())
    }

    pub async fn download(
        &mut self,
        spec_hash: &SpecHash,
        compression_level: i32,
    ) -> Result<NamedTempFile, Error> {
        let mut rpc = self
            .c
            .download(DownloadRequest {
                spec_hash: spec_hash.as_bytes().to_vec(),
                format: Some(TarballFormat {
                    compression: compression_level,
                }),
            })
            .await
            .map_err(|e| Error::Other(e.into()))?
            .into_inner();

        let tempfile = NamedTempFile::new().map_err(|e| Error::Other(e.into()))?;
        let mut temp_file = tokio::fs::File::from(
            tempfile
                .as_file()
                .try_clone()
                .map_err(|e| Error::Other(e.into()))?,
        );
        // Stream the download data and write to the temporary file
        while let Some(download_data) = rpc.next().await {
            let download_data = download_data.map_err(|e| Error::Other(e.into()))?;
            tokio::io::AsyncWriteExt::write_all(&mut temp_file, &download_data.chunk)
                .await
                .map_err(|e| Error::Other(e.into()))?;
        }
        tokio::io::AsyncWriteExt::shutdown(&mut temp_file)
            .await
            .map_err(|e| Error::Other(e.into()))?;

        Ok(tempfile)
    }
}

/// The configuration describing an execution in a remote environment.
pub struct ExecArgs {
    pub packages: Vec<String>,
    pub args: Vec<String>,
    pub env_vars: HashMap<String, String>,
}

/// An initialized remote environment.
#[allow(dead_code)]
pub struct Env<'a> {
    client_id: String,
    cwd: Worktree<'a>,

    /// The ID of the server backing this environment.
    server_id: String,
}

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use super::*;
    use create_env_message::Msg;
    use remote_execution_service_server::{RemoteExecutionService, RemoteExecutionServiceServer};
    use tokio_stream::StreamExt;

    struct MockServer {
        tx: tokio::sync::mpsc::UnboundedSender<CreateEnvMessage>,
    }

    #[tonic::async_trait]
    impl RemoteExecutionService for MockServer {
        async fn create_env(
            &self,
            request: tonic::Request<tonic::Streaming<CreateEnvMessage>>,
        ) -> Result<tonic::Response<CreateEnvResponse>, tonic::Status> {
            let mut stream = request.into_inner();
            while let Some(msg) = stream.next().await {
                self.tx.send(msg.unwrap()).unwrap();
            }
            Ok(tonic::Response::new(CreateEnvResponse {
                server_id: "test".into(),
                expires_at: Some(SystemTime::now().into()),
            }))
        }

        type ExecStream = tokio_stream::Empty<Result<CreateTaskResponse, tonic::Status>>;
        async fn exec(
            &self,
            _request: tonic::Request<CreateTaskRequest>,
        ) -> Result<tonic::Response<Self::ExecStream>, tonic::Status> {
            unimplemented!()
        }

        type OrchestrateBuildStream =
            tokio_stream::Empty<Result<OrchestrateBuildResponse, tonic::Status>>;
        async fn orchestrate_build(
            &self,
            _request: tonic::Request<tonic::Streaming<OrchestrateBuildMessage>>,
        ) -> Result<tonic::Response<Self::OrchestrateBuildStream>, tonic::Status> {
            unimplemented!()
        }

        type DownloadStream = tokio_stream::Empty<Result<DownloadResponse, tonic::Status>>;
        async fn download(
            &self,
            _request: tonic::Request<DownloadRequest>,
        ) -> Result<tonic::Response<Self::DownloadStream>, tonic::Status> {
            unimplemented!()
        }
    }

    #[tokio::test]
    async fn make_env_ephemeral() {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();

        let svc = RemoteExecutionServiceServer::new(MockServer { tx });
        let graph = Graph::new();
        let mut client = Client::new(RESClient::new(svc), &graph);
        client.make_env(Worktree::Ephemeral).await.unwrap();

        // First message must be the Request with exactly one stream config (graph).
        let first = rx.recv().await.unwrap();
        let Msg::Request(req) = first.msg.unwrap() else {
            panic!("expected Request as first message");
        };
        assert_eq!(
            req.streams.len(),
            1,
            "ephemeral should have graph stream only"
        );
        assert_eq!(
            req.streams[0].kind,
            i32::from(stream_config::StreamKind::SkGraph)
        );

        // Remaining messages are graph data chunks. Reassemble and deserialize.
        let mut graph_data = Vec::new();
        while let Ok(msg) = rx.try_recv() {
            let Msg::Chunk(chunk) = msg.msg.unwrap() else {
                panic!("expected Chunk message");
            };
            assert_eq!(chunk.idx, 0, "graph stream index should be 0");
            graph_data.extend_from_slice(&chunk.data);
        }
        assert!(!graph_data.is_empty(), "should have received graph data");

        let restored = Graph::from_bytes(&graph_data).expect("graph should deserialize");
        // A default graph round-trips successfully.
        assert_eq!(
            restored.to_bytes().unwrap(),
            graph.to_bytes().unwrap(),
            "round-tripped graph should match original"
        );
    }

    #[tokio::test]
    async fn make_env_send_dir() {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();

        // Create a temp directory with a test file.
        let src_dir = tempfile::tempdir().unwrap();
        std::fs::write(src_dir.path().join("hello.txt"), b"hello world").unwrap();

        let svc = RemoteExecutionServiceServer::new(MockServer { tx });
        let graph = Graph::new();
        let mut client = Client::new(RESClient::new(svc), &graph);
        client
            .make_env(Worktree::Dir(Cow::Borrowed(src_dir.path())))
            .await
            .unwrap();

        // First message is the Request with two stream configs (graph + worktree).
        let first = rx.recv().await.unwrap();
        let Msg::Request(req) = first.msg.unwrap() else {
            panic!("expected Request as first message");
        };
        assert_eq!(req.streams.len(), 2);
        assert_eq!(
            req.streams[0].kind,
            i32::from(stream_config::StreamKind::SkGraph)
        );
        assert_eq!(
            req.streams[1].kind,
            i32::from(stream_config::StreamKind::SkWorktree)
        );

        // Collect chunks by stream index.
        let mut graph_data = Vec::new();
        let mut worktree_data = Vec::new();
        while let Ok(msg) = rx.try_recv() {
            let Msg::Chunk(chunk) = msg.msg.unwrap() else {
                panic!("expected Chunk message");
            };
            match chunk.idx {
                0 => graph_data.extend_from_slice(&chunk.data),
                1 => worktree_data.extend_from_slice(&chunk.data),
                other => panic!("unexpected stream index {other}"),
            }
        }

        // Graph should round-trip.
        Graph::from_bytes(&graph_data).expect("graph should deserialize");

        // Worktree is a zstd-compressed tarball. Decompress and verify contents.
        assert!(
            !worktree_data.is_empty(),
            "should have received worktree data"
        );
        let dst_dir = tempfile::tempdir().unwrap();
        common::archive::extract_compressed_tar(
            std::io::Cursor::new(&worktree_data),
            common::archive::Compression::Zstd,
            dst_dir.path(),
            None,
        )
        .unwrap();

        let extracted = std::fs::read_to_string(dst_dir.path().join("hello.txt")).unwrap();
        assert_eq!(extracted, "hello world");
    }

    struct DownloadMockServer {
        chunks: Vec<Vec<u8>>,
    }

    #[tonic::async_trait]
    impl RemoteExecutionService for DownloadMockServer {
        async fn create_env(
            &self,
            _request: tonic::Request<tonic::Streaming<CreateEnvMessage>>,
        ) -> Result<tonic::Response<CreateEnvResponse>, tonic::Status> {
            unimplemented!()
        }

        type ExecStream = tokio_stream::Empty<Result<CreateTaskResponse, tonic::Status>>;
        async fn exec(
            &self,
            _request: tonic::Request<CreateTaskRequest>,
        ) -> Result<tonic::Response<Self::ExecStream>, tonic::Status> {
            unimplemented!()
        }

        type OrchestrateBuildStream =
            tokio_stream::Empty<Result<OrchestrateBuildResponse, tonic::Status>>;
        async fn orchestrate_build(
            &self,
            _request: tonic::Request<tonic::Streaming<OrchestrateBuildMessage>>,
        ) -> Result<tonic::Response<Self::OrchestrateBuildStream>, tonic::Status> {
            unimplemented!()
        }

        type DownloadStream =
            tokio_stream::Iter<std::vec::IntoIter<Result<DownloadResponse, tonic::Status>>>;
        async fn download(
            &self,
            request: tonic::Request<DownloadRequest>,
        ) -> Result<tonic::Response<Self::DownloadStream>, tonic::Status> {
            let req = request.into_inner();
            assert_eq!(req.spec_hash.len(), 32, "spec_hash must be 32 bytes");
            assert_eq!(req.spec_hash, vec![0x11; 32]);
            let responses: Vec<_> = self
                .chunks
                .iter()
                .map(|c| Ok(DownloadResponse { chunk: c.clone() }))
                .collect();
            Ok(tonic::Response::new(tokio_stream::iter(responses)))
        }
    }

    #[tokio::test]
    async fn download_streams_tarball() {
        // Create a temp directory with a test file and compress it into a tarball.
        let src_dir = tempfile::tempdir().unwrap();
        std::fs::write(src_dir.path().join("data.txt"), b"hello download").unwrap();
        let (mut tarball, _hash) =
            common::archive::compress_dir(src_dir.path(), Some(-5), &None).unwrap();
        std::io::Seek::rewind(&mut tarball).unwrap();

        // Read the tarball bytes and split into small chunks to simulate streaming.
        use std::io::Read as _;
        let mut tarball_bytes = Vec::new();
        tarball.read_to_end(&mut tarball_bytes).unwrap();
        let chunks: Vec<Vec<u8>> = tarball_bytes.chunks(64).map(|c| c.to_vec()).collect();

        let svc = RemoteExecutionServiceServer::new(DownloadMockServer { chunks });
        let graph = Graph::new();
        let mut client = Client::new(RESClient::new(svc), &graph);

        let spec_hash = SpecHash::from_bytes([0x11; 32]);
        let result_file = client.download(&spec_hash, -5).await.unwrap();

        // The returned NamedTempFile should contain the reassembled tarball.
        // Rewind since the write via the cloned fd advanced the shared file offset.
        use std::io::Seek as _;
        let mut result_file = result_file;
        result_file.as_file_mut().rewind().unwrap();

        let dst_dir = tempfile::tempdir().unwrap();
        common::archive::extract_compressed_tar(
            result_file.as_file(),
            common::archive::Compression::Zstd,
            dst_dir.path(),
            None,
        )
        .unwrap();
        let extracted = std::fs::read_to_string(dst_dir.path().join("data.txt")).unwrap();
        assert_eq!(extracted, "hello download");
    }

    struct ExecMockServer;

    #[tonic::async_trait]
    impl RemoteExecutionService for ExecMockServer {
        async fn create_env(
            &self,
            _request: tonic::Request<tonic::Streaming<CreateEnvMessage>>,
        ) -> Result<tonic::Response<CreateEnvResponse>, tonic::Status> {
            unimplemented!()
        }

        type ExecStream =
            tokio_stream::Iter<std::vec::IntoIter<Result<CreateTaskResponse, tonic::Status>>>;

        async fn exec(
            &self,
            request: tonic::Request<CreateTaskRequest>,
        ) -> Result<tonic::Response<Self::ExecStream>, tonic::Status> {
            let req = request.into_inner();
            assert_eq!(req.packages, vec!["base", "bash"]);

            let responses = vec![
                Ok(CreateTaskResponse {
                    msg: Some(create_task_response::Msg::Data(TaskData {
                        kind: task_data::Channel::ChStdout.into(),
                        eof: false,
                        data: b"success\n".to_vec(),
                    })),
                }),
                Ok(CreateTaskResponse {
                    msg: Some(create_task_response::Msg::Status(TaskStatus {
                        exit_code: 0,
                    })),
                }),
            ];

            Ok(tonic::Response::new(tokio_stream::iter(responses)))
        }

        type OrchestrateBuildStream =
            tokio_stream::Empty<Result<OrchestrateBuildResponse, tonic::Status>>;
        async fn orchestrate_build(
            &self,
            _request: tonic::Request<tonic::Streaming<OrchestrateBuildMessage>>,
        ) -> Result<tonic::Response<Self::OrchestrateBuildStream>, tonic::Status> {
            unimplemented!()
        }

        type DownloadStream = tokio_stream::Empty<Result<DownloadResponse, tonic::Status>>;
        async fn download(
            &self,
            _request: tonic::Request<DownloadRequest>,
        ) -> Result<tonic::Response<Self::DownloadStream>, tonic::Status> {
            unimplemented!()
        }
    }

    #[tokio::test]
    async fn env_exec_simple() {
        let svc = RemoteExecutionServiceServer::new(ExecMockServer);
        let graph = Graph::new();
        let mut client = Client::new(RESClient::new(svc), &graph);

        let env = Env {
            client_id: "test-client".into(),
            cwd: Worktree::Ephemeral,
            server_id: "test-server".into(),
        };
        let args = ExecArgs {
            packages: vec!["base".into(), "bash".into()],
            args: vec![],
            env_vars: HashMap::new(),
        };

        let mut stdout_buf = Vec::new();
        let exit_code = client
            .exec(&env, &args, Some(&mut stdout_buf), None)
            .await
            .unwrap();

        assert_eq!(exit_code, 0, "expected exit code 0");
        let output = String::from_utf8(stdout_buf).unwrap();
        assert!(
            output.contains("success"),
            "expected 'success' in stdout, got: {output}"
        );
    }
}
