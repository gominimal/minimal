use std::path::PathBuf;

use crate::{
    Backend, Deliverable, DeliverableInner, DeliverableRef, DeliverableState, Orchestrator,
    SharedHandle, StateHandle,
};
use common::SpecHash;
use either::Either;
use futures::channel::mpsc;
use google_cloud_storage::client::Storage as GcsStorage;
use graph::{BinProvider, BuildSpecRef, Graph, SubsetInput};
use lcache::{Cache, CacheErr, DirCacheEntry, EntryMeta, LocalDir, MetaInner, PendingDir};
use op::{Runnable, SourceFetcher};
use ot::OpTracker;
use rcache::RemoteCache;
use tokio::sync::Semaphore;
use tokio::task::spawn_blocking;

use crate::Error;

/// The specific event described by a [BuildEvent].
#[derive(Debug, Clone)]
pub enum BuildEventInner {
    /// A line of text on stdout or stderr. You can identify the build by correlating
    /// the `idx` field in the containing structure with that of an earlier
    /// [BuildEventInner::Start] message.
    Log { is_stderr: bool, line: String },
    /// An indication that a package is being fetched to the local cache.
    Hydrate { name: String, spec_hash: String },
    /// A build of the described package has started.
    Start {
        name: String,
        full_build: bool,
        spec_hash: String,
    },
    /// The build has finished. You can identify the build by correlating
    /// the `idx` field in the containing structure with that of an earlier
    /// [BuildEventInner::Start] message.
    Stop,
}

/// Something that happens during a build run. The `idx` field identifies the build in question.
#[derive(Debug, Clone)]
pub struct BuildEvent {
    pub idx: usize,
    pub inner: BuildEventInner,
}

/// An [`tokio::io::AsyncWrite`] adapter that buffers bytes and sends complete
/// lines as [`BuildLogLine`] items through an [`mpsc::UnboundedSender`].
struct SinkWriter {
    sender: mpsc::UnboundedSender<BuildEvent>,
    idx: usize,
    is_stderr: bool,
    buf: Vec<u8>,
}

impl SinkWriter {
    fn new(sender: mpsc::UnboundedSender<BuildEvent>, idx: usize, is_stderr: bool) -> Self {
        Self {
            sender,
            idx,
            is_stderr,
            buf: Vec::new(),
        }
    }

    fn emit_lines(&mut self) {
        while let Some(pos) = self.buf.iter().position(|&b| b == b'\n') {
            let line = String::from_utf8_lossy(&self.buf[..pos]).into_owned();
            let _ = self.sender.unbounded_send(BuildEvent {
                idx: self.idx,
                inner: BuildEventInner::Log {
                    is_stderr: self.is_stderr,
                    line,
                },
            });
            self.buf.drain(..=pos);
        }
    }

    fn emit_remaining(&mut self) {
        if !self.buf.is_empty() {
            let line = String::from_utf8_lossy(&self.buf).into_owned();
            let _ = self.sender.unbounded_send(BuildEvent {
                idx: self.idx,
                inner: BuildEventInner::Log {
                    is_stderr: self.is_stderr,
                    line,
                },
            });
            self.buf.clear();
        }
    }
}

impl tokio::io::AsyncWrite for SinkWriter {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        self.buf.extend_from_slice(buf);
        self.emit_lines();
        std::task::Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        self.emit_remaining();
        std::task::Poll::Ready(Ok(()))
    }
}

impl Drop for SinkWriter {
    fn drop(&mut self) {
        self.emit_remaining();
    }
}

/// A type which implements [Backend] by building everything locally.
#[derive(Debug)]
pub struct LocalBackend<SF: SourceFetcher + 'static> {
    pub(crate) sf: SF,
    pub(crate) output_base: PathBuf,
    pub(crate) remote_cache: Option<RemoteCache<GcsStorage>>,
    pub(crate) build_semaphore: Semaphore,
    pub(crate) num_concurrent_builds: usize,
    pub(crate) log_sink: Option<mpsc::UnboundedSender<BuildEvent>>,
    pub(crate) ot: Option<OpTracker>,
    pub(crate) cancel: tokio_util::sync::CancellationToken,
}

impl<SF: SourceFetcher> Backend for LocalBackend<SF> {
    type Artifact = Either<(PendingDir, EntryMeta), DirCacheEntry<LocalDir>>;

    async fn build(
        dr: DeliverableRef,
        bsr: BuildSpecRef,
        spec_hash: SpecHash,
        dependencies: Vec<DeliverableRef>,
        shared_hnd: &mut SharedHandle<Self>,
        state_hnd: &mut StateHandle<Self>,
    ) -> Result<Self::Artifact, Error> {
        let (dep_paths, breaker_build, cost, depended_on_by) = {
            let s = state_hnd.lock().await;
            let dep_paths: Vec<PathBuf> = dependencies
                .into_iter()
                .map(|dr| match s.get(&dr).unwrap() {
                    Deliverable {
                        inner: _,
                        depended_on_by: _,
                        state: DeliverableState::Complete(a),
                    } => match a {
                        Either::Left((pd, _meta)) => pd.path().to_path_buf(),
                        Either::Right(c) => c.path().to_path_buf(),
                    },
                    _ => unreachable!(),
                })
                .collect();
            let d = s.get(&dr).unwrap();
            let (breaker_build, cost, depended_on_by) =
                if let DeliverableInner::Build {
                    full_build, cost, ..
                } = d.inner
                {
                    (!full_build, cost, d.depended_on_by)
                } else {
                    unreachable!()
                };
            drop(s);

            (dep_paths, breaker_build, cost, depended_on_by)
        };

        let shared_hnd2 = shared_hnd.clone();
        let artifact = spawn_blocking(async move || {
            let shared = shared_hnd2.inner().read().await;
            let permit = shared
                .backend
                .build_semaphore
                .acquire_many(cost.min(shared.backend.num_concurrent_builds) as u32)
                .await
                .unwrap();
            let log_sink = shared.backend.log_sink.clone();
            let name = shared.graph.get(&bsr).unwrap().name.clone();
            log_sink.as_ref().iter().for_each(|s| {
                s.unbounded_send(BuildEvent {
                    idx: dr.inner_idx(),
                    inner: BuildEventInner::Start {
                        name: name.clone(),
                        full_build: !breaker_build,
                        spec_hash: spec_hash.0.to_hex().to_string(),
                    },
                })
                .ok();
            });
            let mut b = op::SpecBuild {
                override_deps: Some(dep_paths.into_iter().collect()),
                spec: &bsr,
                remote_fetcher: &shared.backend.sf,
                stdout_writer: log_sink.as_ref().map(
                    |s| -> Box<dyn tokio::io::AsyncWrite + Unpin + Send + Sync> {
                        Box::new(SinkWriter::new(s.clone(), dr.inner_idx(), false))
                    },
                ),
                stderr_writer: log_sink.as_ref().map(
                    |s| -> Box<dyn tokio::io::AsyncWrite + Unpin + Send + Sync> {
                        Box::new(SinkWriter::new(s.clone(), dr.inner_idx(), true))
                    },
                ),
                cancel: shared.backend.cancel.clone(),
                cpu_weight: Some(
                    ((3 * cost + 60 + depended_on_by * cost.max(1) * 25) as u64).min(10000),
                ),
            };

            let res = b
                .run(&op::Options {
                    cache: shared.cache.clone(),
                    graph: &shared.graph,
                    ot: shared.backend.ot.clone(),
                    exec_base: shared.backend.output_base.clone(),
                })
                .await;
            log_sink.as_ref().iter().for_each(|s| {
                s.unbounded_send(BuildEvent {
                    idx: dr.inner_idx(),
                    inner: BuildEventInner::Stop,
                })
                .ok();
            });
            drop(permit);
            drop(shared);
            res
        })
        .await
        .unwrap()
        .await?;

        {
            let shared = shared_hnd.inner().read().await;
            let build = shared.graph.get(&bsr).unwrap();
            Ok(Either::Left((
                artifact.outputs,
                EntryMeta {
                    breaker_build,
                    inner: MetaInner::Spec(build.name.clone()),
                    origin: Some(build.from.as_ref().clone()),
                    build_ms: Some(artifact.build_ms),
                    ..Default::default()
                },
            )))
        }
    }

    async fn cache_hydrate(
        dr: DeliverableRef,
        bsr: BuildSpecRef,
        spec_hash: SpecHash,
        shared_hnd: &mut SharedHandle<Self>,
        _state_hnd: &mut StateHandle<Self>,
    ) -> Result<Self::Artifact, Error> {
        // Check local cache
        {
            let s = shared_hnd.inner().read().await;
            let cache_res = s.cache.read_dir(&spec_hash);
            drop(s);
            if let Ok(cd) = cache_res {
                return Ok(Either::Right(cd));
            }
        }

        let shared_hnd2 = shared_hnd.clone();
        spawn_blocking(async move || {
            let shared = shared_hnd2.inner().read().await;
            let sema = shared.fetch_semaphore.acquire().await;
            let res = if let Some(remote_cache) = shared.backend.remote_cache.as_ref() {
                let build = shared.graph.get(&bsr).unwrap();

                let log_sink = shared.backend.log_sink.clone();
                log_sink.as_ref().iter().for_each(|s| {
                    s.unbounded_send(BuildEvent {
                        idx: dr.inner_idx(),
                        inner: BuildEventInner::Hydrate {
                            name: build.name.clone(),
                            spec_hash: spec_hash.0.to_hex().to_string(),
                        },
                    })
                    .ok();
                });

                let (fetch_time, pending_dir) = remote_cache
                    .materialize(&spec_hash, &shared.cache, build.name.as_str())
                    .await
                    .map_err(|e| Error::Other(e.into()))?;

                Ok(Either::Left((
                    pending_dir,
                    EntryMeta {
                        inner: MetaInner::Spec(build.name.clone()),
                        fetched: true,
                        fetch_ms: Some(fetch_time.as_millis() as usize),
                        origin: Some(build.from.as_ref().clone()),
                        ..Default::default()
                    },
                )))
            } else {
                Err(Error::Cache(CacheErr::NotFound))
            };
            drop(sema);
            drop(shared);
            res
        })
        .await
        .unwrap()
        .await
    }

    async fn materialize_subset(
        _dr: DeliverableRef,
        subset: SubsetInput,
        build: DeliverableRef,
        _spec_hash: SpecHash,
        shared_hnd: &mut SharedHandle<Self>,
        state_hnd: &mut StateHandle<Self>,
    ) -> Result<Self::Artifact, Error> {
        let (build_dir, build_bsr) = {
            let deliverable = state_hnd.lock_for_deliverable(&build).await;
            (
                if let DeliverableState::Complete(ref a) = deliverable.state {
                    match a {
                        Either::Left((pd, _meta)) => pd.path().to_path_buf(),
                        Either::Right(cd) => cd.path().to_path_buf(),
                    }
                } else {
                    return Err(Error::Cache(CacheErr::NotFound));
                },
                match deliverable.inner {
                    DeliverableInner::Build { bsr, .. } => bsr,
                    DeliverableInner::CacheFill { bsr, .. } => bsr,
                    _ => unreachable!(),
                },
            )
        };

        let shared_hnd2 = shared_hnd.clone();
        let subset2 = subset.clone();
        let pending_dir = spawn_blocking(async move || {
            let shared = shared_hnd2.inner().read().await;
            let res = op::SubsetBuild {
                from_dir: Some(build_dir),
                subset: &subset2,
            }
            .run(&op::Options {
                cache: shared.cache.clone(),
                graph: &shared.graph,
                ot: shared.backend.ot.clone(),
                exec_base: shared.backend.output_base.clone(),
            })
            .await;
            drop(shared);
            res
        })
        .await
        .unwrap()
        .await?;

        let shared = shared_hnd.inner().read().await;
        let build_origin = shared.graph.get(&build_bsr).unwrap().from.clone();
        let subset_spec = subset.as_spec(&shared.graph);
        drop(shared);

        Ok(Either::Left((
            pending_dir,
            EntryMeta {
                inner: MetaInner::Subset(subset_spec),
                origin: Some(build_origin.as_ref().clone()),
                ..Default::default()
            },
        )))
    }
}

impl<SF: SourceFetcher> LocalBackend<SF> {
    /// Creates a new orchestrator for local builds.
    #[allow(clippy::too_many_arguments)]
    pub fn new_orchestrator(
        top_levels: Vec<BuildSpecRef>,
        output_base: PathBuf,
        remote_cache: Option<RemoteCache<GcsStorage>>,
        sf: SF,
        num_concurrent_builds: usize,
        graph: Graph,
        cache: Cache<LocalDir>,
        log_sink: Option<mpsc::UnboundedSender<BuildEvent>>,
        ot: Option<OpTracker>,
        cancel: tokio_util::sync::CancellationToken,
    ) -> Result<Orchestrator<Self>, Error> {
        Ok(Orchestrator {
            top_levels,
            backend: LocalBackend::<SF> {
                output_base,
                remote_cache,
                sf,
                log_sink,
                build_semaphore: Semaphore::new(num_concurrent_builds),
                num_concurrent_builds,
                ot,
                cancel,
            },
            graph,
            cache,
        })
    }

    /// Executes a local build with the orchestrator.
    pub async fn run_local_build<BP: BinProvider>(
        orch: Orchestrator<Self>,
        bp: BP,
    ) -> (Vec<(PendingDir, EntryMeta)>, Result<(), Error>) {
        let unsafe_skip_double_builds = std::env::var("MINIMAL_SCIENCE_MODE")
            .is_ok_and(|v| v.eq("yeppers"))
            && std::env::var("UNSAFE_SKIP_DOUBLE_BUILDS").is_ok_and(|v| v.eq("1") || v.eq("true"));

        let (built, result) = orch.run(bp).await;
        (
            built
                .into_iter()
                .filter_map(|a| match (unsafe_skip_double_builds, a) {
                    // We don't actually want to store breaker builds, they are just a stepping stone.
                    (
                        false,
                        Either::Left((
                            _pd,
                            EntryMeta {
                                breaker_build: true,
                                ..
                            },
                        )),
                    ) => None,
                    (_, Either::Left((pd, meta))) => Some((pd, meta)),
                    (_, Either::Right(_cache_dir)) => None,
                })
                .collect(),
            result,
        )
    }
}
