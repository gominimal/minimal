use std::borrow::Cow;
use std::path::Path;
use std::pin::Pin;

use futures::StreamExt;
use graph::Graph;
use remote_execution_service_client::RemoteExecutionServiceClient as RESClient;
use remote_proto::{res::*, *};
use tonic::transport::{Channel, Error as TransportError};

type ChunkStream = Pin<Box<dyn futures::Stream<Item = CreateEnvMessage> + Send>>;

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

        // Work out the streams
        use stream_config::*;
        let graph_bytes = self.g.to_bytes().unwrap(); // TODO: Can we do a better job of streaming
        let graph_stream: (StreamConfig, ChunkStream) = {
            (
                StreamConfig {
                    format: Some(Format::Graph(GraphFormat::GfJsonSerdeV1.into())),
                    kind: StreamKind::SkGraph.into(),
                },
                Box::pin(
                    futures::stream::once(async move {
                        tokio_util::io::ReaderStream::new(std::io::Cursor::new(graph_bytes))
                            .filter_map(|result| async { result.ok() })
                            .map(|bytes| CreateEnvMessage {
                                msg: Some(Msg::Chunk(CreateChunk {
                                    idx: 0,
                                    data: bytes.to_vec(),
                                })),
                            })
                    })
                    .flatten(),
                ),
            )
        };

        let worktree_stream: Option<(StreamConfig, ChunkStream)> = match cwd {
            Worktree::Ephemeral => None,
            Worktree::Dir(ref d) => {
                let dir = d.clone().into_owned();
                let chunk_stream: ChunkStream = Box::pin(
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
                                msg: Some(Msg::Chunk(CreateChunk {
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

        let streams: ChunkStream = Box::pin(
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
            cwd,
            server_id: tx_result.server_id,
        })
    }
}

/// An initialized remote environment.
#[allow(dead_code)]
pub struct Env<'a> {
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
}
