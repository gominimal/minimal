//! Session side-operations - operations run non-interactively in the context of a session.

use std::sync::Arc;

use futures::StreamExt as _;
use mctx::{Context, PackageSelection};
use orchestrator::BuildEvent;
use tokio::{
    sync::{
        Mutex,
        mpsc::{self, error::TrySendError},
    },
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;

use crate::session::WeakSessionHandle;

/// The terminal result of a build side-op, delivered as the final
/// [`BuildUpdate`] before the build's channel closes.
#[derive(Debug, Clone)]
pub enum BuildOutcome {
    /// The build finished and every top-level is available.
    Success,
    /// The build errored; the string is the (rendered) failure.
    Failed(String),
    /// The build was cancelled before completing (e.g. the session tore down).
    Cancelled,
}

/// An update from a running build side-op: incremental progress
/// ([`BuildUpdate::Event`]), then exactly one terminal
/// [`BuildUpdate::Finished`] as the last item before the channel closes.
#[derive(Debug, Clone)]
pub enum BuildUpdate {
    Event(BuildEvent),
    Finished(BuildOutcome),
}

/// A registration to recieve updates about the progress of a build.
#[derive(Debug)]
pub(crate) enum BuildSink {
    Structured(mpsc::Sender<BuildUpdate>),
}

impl BuildSink {
    /// Best-effort progress delivery: a full or disconnected sink drops the
    /// update rather than blocking the build.
    pub fn try_send(&self, u: BuildUpdate) -> Result<(), TrySendError<BuildUpdate>> {
        match self {
            Self::Structured(s) => s.try_send(u),
        }
    }

    /// Reliable delivery for the terminal outcome: awaits channel capacity so
    /// the `Finished` update isn't dropped under backpressure. Errors only if
    /// the subscriber has already gone away.
    pub async fn send(&self, u: BuildUpdate) -> Result<(), mpsc::error::SendError<BuildUpdate>> {
        match self {
            Self::Structured(s) => s.send(u).await,
        }
    }
}

#[derive(Debug)]
struct BuildInner {
    sinks: Vec<BuildSink>,
}

#[derive(Debug)]
#[allow(dead_code)]
enum Op {
    Build {
        /// Packages which were requested to be built
        packages: Vec<String>,
        /// Interior mutability. Users MUST NEVER block while holding
        /// the lock: get in, read/update data, get out.
        inner: Arc<Mutex<BuildInner>>,
    },
}

/// Session side-operation.
#[derive(Debug)]
#[allow(dead_code)]
pub struct SideOp {
    id: uuid::Uuid,
    session: WeakSessionHandle,

    op: Op,

    cancel: CancellationToken,
    handle: JoinHandle<()>,
}

/// How long to wait to hand a subscriber the terminal [`BuildUpdate::Finished`]
/// before giving up. A subscriber that stopped draining but hasn't dropped its
/// receiver would otherwise block the build task's reliable send forever — and
/// [`SideOp::shutdown`] awaits that task, so this bound keeps teardown from
/// wedging on a wedged consumer. Responsive consumers deliver far inside it.
const FINISH_SEND_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

impl SideOp {
    /// UUID of this operation.
    pub fn id(&self) -> &uuid::Uuid {
        &self.id
    }

    /// Called by the session when it is being shut down.
    pub(crate) async fn shutdown(self) {
        self.cancel.cancel();
        if let Err(e) = self.handle.await {
            tracing::warn!(error = %e, "sop shutdown unexpected error on join");
        }
    }

    /// Kicks off a build side-op wired to a single structured sink, returning
    /// the op alongside the receiver end that streams its [`BuildEvent`]s until
    /// the build completes (at which point the sender is dropped and the
    /// receiver closes). The session actor stores the op and hands the receiver
    /// to whoever requested the build so it can render progress.
    pub(crate) async fn spawn_build(
        session: WeakSessionHandle,
        rebuild: bool,
        pkgs: Vec<String>,
        ctx: Context,
        buffer: usize,
    ) -> Result<(Self, mpsc::Receiver<BuildUpdate>), std::io::Error> {
        let (tx, rx) = mpsc::channel(buffer);
        let sop =
            Self::new_build(session, rebuild, pkgs, ctx, vec![BuildSink::Structured(tx)]).await?;
        Ok((sop, rx))
    }

    /// Called to kick off a new build with the specified parameters.
    ///
    /// Should only be called from the session actor.
    pub(crate) async fn new_build(
        session: WeakSessionHandle,
        rebuild: bool,
        pkgs: Vec<String>,
        ctx: Context,
        sinks: Vec<BuildSink>,
    ) -> Result<Self, std::io::Error> {
        // `graph_from_all_packages` is CPU-heavy, run on blocking pool.
        let (ctx, graph_result) = tokio::task::spawn_blocking(move || {
            let mut ctx = ctx;
            let r = ctx.graph_from_all_packages().map_err(|e| e.to_string());

            (ctx, r)
        })
        .await
        .map_err(std::io::Error::other)?;
        let mut graph = graph_result.map_err(std::io::Error::other)?;
        graph.top_levels = pkgs
            .as_bsrs(&graph)
            .map_err(|e| std::io::Error::other(e.to_string()))?;

        let cancel = CancellationToken::new();
        let inner = Arc::new(Mutex::new(BuildInner { sinks }));

        let handle = {
            // Two clones for the task (the original `cancel` stays on the
            // `SideOp` so `shutdown` can trigger it): one drives the build,
            // one classifies the outcome after it returns. All clones share
            // the same cancellation state.
            let build_cancel = cancel.clone();
            let cancel_flag = cancel.clone();
            let pump_inner = inner.clone();
            let build_inner = inner.clone();
            tokio::task::spawn(async move {
                let mut ctx = ctx;
                let (log_tx, mut log_rx) = futures::channel::mpsc::unbounded::<BuildEvent>();

                // Pump task: drain the log channel until the build drops its
                // sender (on completion or cancellation).
                let pump = tokio::task::spawn(async move {
                    while let Some(event) = log_rx.next().await {
                        let inner = pump_inner.lock().await;
                        for sink in &inner.sinks {
                            let _ = sink.try_send(BuildUpdate::Event(event.clone()));
                        }
                    }
                });

                // Do the build. Reduce its `!Send` error (`mctx::Error` holds
                // nickel `Rc`s) to an owned string right away, so nothing
                // non-`Send` is held across the `pump.await` below.
                let build_err = match ctx
                    .build_graph_with_cancel(&graph, rebuild, Some(log_tx), build_cancel)
                    .await
                {
                    Ok(()) => None,
                    Err(e) => {
                        tracing::warn!("session build failed: {e}");
                        Some(e.to_string())
                    }
                };
                let _ = pump.await;

                // Classify the terminal outcome. A build that returned `Ok` is
                // a success even if the token was cancelled afterwards (e.g. a
                // `shutdown` racing the `pump.await` drain) — the work is done.
                // Cancellation only reclassifies an *errored* build, whose error
                // is just fallout from tearing the build down.
                let outcome = match build_err {
                    None => BuildOutcome::Success,
                    Some(_) if cancel_flag.is_cancelled() => BuildOutcome::Cancelled,
                    Some(msg) => BuildOutcome::Failed(msg),
                };

                // Deliver the outcome to every subscriber, then drop the sinks
                // so their receivers close. Take the sinks out *under* the lock
                // (never awaiting while holding it), then send outside it.
                let sinks = {
                    let mut inner = build_inner.lock().await;
                    std::mem::take(&mut inner.sinks)
                };
                for sink in &sinks {
                    // Bound the reliable delivery so a stuck-but-undropped
                    // receiver can't stall this task (and thus `shutdown`); a
                    // consumer that has fallen behind just misses the final
                    // update, then sees the channel close below.
                    let _ = tokio::time::timeout(
                        FINISH_SEND_TIMEOUT,
                        sink.send(BuildUpdate::Finished(outcome.clone())),
                    )
                    .await;
                }
                // `sinks` dropped here → each receiver observes the close.
            })
        };

        Ok(Self {
            id: uuid::Uuid::now_v7(),
            cancel,
            session,
            op: Op::Build {
                packages: pkgs,
                inner,
            },
            handle,
        })
    }
}
