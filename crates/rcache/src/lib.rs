//! Remote cache implementation for fetching/uploading build artifacts over the network.

mod remote;
pub use remote::{Error, INDEX_FILENAME, RemoteCache};

mod remote_index;

/// An adapter that lets you use a [RemoteCache] as a [graph::BinProvider].
#[derive(Debug, Clone)]
pub struct RemoteBinProvider<'a, B: common::fetchers::FetchBackend> {
    graph: &'a graph::Graph,
    remote: &'a RemoteCache<B>,
}

impl<'a, B: common::fetchers::FetchBackend> RemoteBinProvider<'a, B> {
    pub fn new(graph: &'a graph::Graph, remote: &'a RemoteCache<B>) -> Self {
        Self { graph, remote }
    }
}

impl<'a, B: common::fetchers::FetchBackend + Sync> graph::BinProvider for RemoteBinProvider<'a, B>
where
    B::Url: Sync + Send,
{
    fn exists(&self, bsr: &graph::BuildSpecRef) -> bool {
        self.remote.exists(&self.graph.spec_hash(bsr))
    }
}
