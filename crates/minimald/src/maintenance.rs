//! Housekeeping the daemon runs on its own clock, with no client asking.
//!
//! The job is reclaiming the local cache. A long-lived daemon accumulates
//! build artifacts nothing reads any more, plus the sandbox, task and temp
//! directories of executions whose process is long gone. `mip cache clean`
//! does this on demand for a project; here the same [`op::CleanCache`] runs
//! for the daemon, with every live session's packages held back.
//!
//! In the microVM there is a second half to it. Unlinking files inside the
//! guest returns blocks to ext4 and nothing else: the data volume is mounted
//! without `discard`, so the host's backing image only ever grows, and a clean
//! that reclaims gigabytes inside the VM reclaims nothing the user can see on
//! their disk. So every clean that ran is followed by an `FITRIM`
//! ([`guest::trim_state_volume`](crate::guest::trim_state_volume)), which is
//! what actually punches the freed extents out of the image.
//!
//! Cleaning is an actor, not a bare timer, because there is more than one way
//! to ask for one: the periodic tick, and anything that wants a clean *now*.
//! Both arrive at [`Maintenance::mainloop`], which runs them one at a time —
//! two cleans racing over the same cache would have one unlinking entries the
//! other is walking. [`MaintenanceHandle::clean_now`] is the only way in from
//! outside, and it queues rather than overlaps.
//!
//! [`spawn`] is called once by [`Server::run`](crate::server::Server::run);
//! the actor lives as long as the daemon does.

use std::io::ErrorKind;
use std::time::Duration;

use futures::StreamExt;
use futures::channel::mpsc as event_chan;
use op::{CleanCache, CleanEvent, CleanReport, StaleKind};
use tokio::sync::mpsc;
use tokio::task::AbortHandle;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use crate::server::ServerStateHandle;
use crate::sessions::Responder;

/// How long after startup the first clean runs. Late enough to stay out of the
/// way of a daemon that is still coming up (and of the session a user is
/// probably waiting on), early enough that a machine whose daemon restarts
/// often still gets cleaned.
const STARTUP_DELAY: Duration = Duration::from_secs(5 * 60);

/// How long after a clean the next one is due. Measured from the end of the
/// last clean whatever asked for it, so an explicit
/// [`clean_now`](MaintenanceHandle::clean_now) pushes the tick out rather than
/// being followed by a redundant one.
const CLEAN_INTERVAL: Duration = Duration::from_secs(6 * 60 * 60);

/// How long a cache entry must have gone unread before it is reclaimed. Packages
/// needed by sessions are retained separately.
const UNUSED_FOR: Duration = Duration::from_secs(5 * 24 * 60 * 60);

/// What the maintenance actor accepts.
#[derive(Debug)]
enum MaintenanceMessage {
    /// Run a cache clean and report what it removed.
    CleanNow {
        /// Reclaim entries unread for at least this long; `None` for
        /// [`UNUSED_FOR`].
        older_than: Option<Duration>,
        /// Where to mirror the clean's events, for a caller streaming them
        /// somewhere (the `CleanCache` RPC streams them to its client). The
        /// daemon log gets them either way.
        events: Option<event_chan::UnboundedSender<CleanEvent>>,
        responder: Responder<CleanReport>,
    },
}

/// The daemon's housekeeping actor.
///
/// Follows the actor pattern, like [`crate::sessions::Manager`]. Here the
/// pattern is load-bearing rather than incidental: being the single owner of
/// cache cleaning is what keeps a requested clean from colliding with the
/// periodic one.
struct Maintenance {
    state: ServerStateHandle,
    receiver: mpsc::Receiver<MaintenanceMessage>,
    /// The server shutdown token; ends the loop between cleans.
    shutdown: CancellationToken,
}

impl Maintenance {
    /// Runs cleans — one at a time — until shutdown.
    ///
    /// Each clean is awaited inline, so while one runs the next request simply
    /// waits its turn in the channel. That is the whole serialization; nothing
    /// here needs a lock.
    async fn mainloop(mut self) {
        let mut next_tick = Instant::now() + STARTUP_DELAY;
        loop {
            // A pending shutdown wins over a due clean (`biased`), so the loop
            // never starts one it would have to be aborted out of.
            tokio::select! {
                biased;
                () = self.shutdown.cancelled() => break,
                msg = self.receiver.recv() => match msg {
                    // Every handle is gone, so nothing can ask for a clean
                    // again. Only reachable if the server state was dropped
                    // without cancelling the token.
                    None => break,
                    Some(MaintenanceMessage::CleanNow { older_than, events, responder }) => {
                        let older_than = older_than.unwrap_or(UNUSED_FOR);
                        let report = clean(&self.state, older_than, events).await;
                        // The trim finishes before the caller is answered: a
                        // reply means the whole reclaim is done, on the host's
                        // disk as well as inside the guest. Answering early
                        // would have `mip cache clean` return while the space
                        // it reported is still not back, which is the one
                        // question the caller is asking.
                        if report.is_ok() {
                            trim_state_volume_if_mounted(&self.state).await;
                        }
                        responder.handle(std::future::ready(report)).await;
                        next_tick = Instant::now() + CLEAN_INTERVAL;
                    }
                },
                () = tokio::time::sleep_until(next_tick) => {
                    // Nobody is waiting on this one; `clean` logged the outcome.
                    if clean(&self.state, UNUSED_FOR, None).await.is_ok() {
                        trim_state_volume_if_mounted(&self.state).await;
                    }
                    next_tick = Instant::now() + CLEAN_INTERVAL;
                }
            }
        }
        tracing::debug!("maintenance actor stopped");
    }
}

/// A handle to the maintenance actor.
///
/// Cloning is cheap and every clone reaches the same actor — which is the
/// point: however many callers ask, cleans still happen one at a time.
#[derive(Clone, Debug)]
pub(crate) struct MaintenanceHandle {
    sender: mpsc::Sender<MaintenanceMessage>,
    abort: AbortHandle,
}

impl MaintenanceHandle {
    /// Runs a cache clean, returning what it removed. `older_than` overrides
    /// [`UNUSED_FOR`]; `events` receives the clean's progress as it happens,
    /// for a caller relaying it (the `CleanCache` RPC streams it to its
    /// client).
    ///
    /// Returns only once the reclaim is complete end to end — including, in
    /// the microVM, the `FITRIM` that returns the freed blocks to the host
    /// image. Queues behind a clean already in progress rather than starting a
    /// second one, so this can take as long as a full clean-and-trim plus the
    /// one ahead of it, and `events` stays silent until this request's turn
    /// comes (the trim reports to the log, not through `events`).
    /// `NotConnected` once the actor has stopped (shutdown).
    pub(crate) async fn clean_now(
        &self,
        older_than: Option<Duration>,
        events: Option<event_chan::UnboundedSender<CleanEvent>>,
    ) -> Result<CleanReport, std::io::Error> {
        let (send, recv) = Responder::channel();
        // Ignore send errors - the recv will also fail.
        let _ = self
            .sender
            .send(MaintenanceMessage::CleanNow {
                older_than,
                events,
                responder: send,
            })
            .await;
        recv.await.unwrap_or_else(|_| {
            Err(std::io::Error::new(
                ErrorKind::NotConnected,
                "maintenance actor is gone",
            ))
        })
    }

    /// Stops the actor, including a clean in flight. The shutdown token
    /// already ends it between cleans; this covers the mid-clean case.
    pub(crate) fn abort(&self) {
        self.abort.abort();
    }
}

/// Spawns the maintenance actor: a clean [`STARTUP_DELAY`] after boot, then one
/// every [`CLEAN_INTERVAL`], plus whatever [`MaintenanceHandle::clean_now`]
/// asks for, until `shutdown` fires.
///
/// A clean that fails is logged and the actor carries on; housekeeping never
/// takes the daemon down with it.
pub(crate) fn spawn(state: ServerStateHandle, shutdown: CancellationToken) -> MaintenanceHandle {
    let (sender, receiver) = mpsc::channel(8);
    let actor = Maintenance {
        state,
        receiver,
        shutdown,
    };
    let abort = tokio::spawn(actor.mainloop()).abort_handle();

    MaintenanceHandle { sender, abort }
}

/// One clean: work out what every session still needs, then reclaim everything
/// else that has gone cold. Private to the actor — every caller arrives through
/// [`MaintenanceHandle`], which is what keeps this from running twice at once.
///
/// Note the ordering hazard this deliberately does not solve: the `Shutdown`
/// RPC quiesces the state volume *before* cancelling the token, so a clean that
/// starts in the moment before a shutdown arrives can still be deleting under
/// the mountpoint as it is synced. The window is small, the deletes are
/// individually journalled, and the mainloop's `biased` select keeps it from
/// starting a new one once the token is cancelled.
async fn clean(
    state: &ServerStateHandle,
    older_than: Duration,
    relay: Option<event_chan::UnboundedSender<CleanEvent>>,
) -> Result<CleanReport, std::io::Error> {
    let sessions = state.sessions_manager().await;

    // The keep set is the whole safety story: everything not in it is a
    // deletion candidate. A partial answer is therefore unusable — if any
    // session can't say what it needs, skip the clean rather than reclaim
    // something it was still using.
    let keep = match sessions.needed_packages().await {
        Ok(keep) => keep,
        Err(error) => {
            tracing::warn!(
                %error,
                "skipping cache clean: could not determine what the sessions need",
            );
            return Err(error);
        }
    };

    let daemon_ctx = state.daemon_context().await;
    let cache = daemon_ctx.local_cache();
    let (tx, rx) = event_chan::unbounded();
    let renderer = tokio::spawn(log_events(rx, relay));

    let op = CleanCache {
        older_than,
        keep,
        sweep: vec![
            (StaleKind::Sandbox, daemon_ctx.builds_base_dir()),
            (StaleKind::Task, daemon_ctx.tasks_base_dir()),
            (StaleKind::TempDir, daemon_ctx.cache_base_dir().join("temp")),
        ],
        // Never sweep this daemon's own live sandboxes and task dirs: they
        // carry its id where another process's would carry a pid.
        daemon_id: daemon_ctx.daemon_id(),
        events: Some(tx),
    };

    // Walking the cache and unlinking trees is blocking work; it has no
    // business on the runtime's async threads. Dropping `op` at the end of the
    // closure closes the event stream, so the renderer finishes with it. The
    // error is rendered in there too — `op::Error` is a large enum, and only
    // its message crosses back.
    let result =
        tokio::task::spawn_blocking(move || op.run(&cache).map_err(|e| e.to_string())).await;
    let _ = renderer.await;

    match result {
        Ok(Ok(report)) => {
            tracing::info!(
                entries = report.entries,
                dirs = report.dirs,
                "cache clean complete",
            );
            Ok(report)
        }
        Ok(Err(error)) => {
            tracing::warn!(%error, "cache clean failed");
            Err(std::io::Error::other(error))
        }
        Err(error) => {
            tracing::error!(%error, "cache clean panicked");
            Err(std::io::Error::other(error))
        }
    }
}

/// Hand the blocks the clean just freed back to the host image — the trim half
/// of the module doc. No-op unless the boot path actually mounted a data volume
/// at the state dir, which in practice means the microVM: a native daemon's
/// state dir is a directory on the user's own filesystem, not this daemon's to
/// discard against.
///
/// Every failure is logged and swallowed. A trim reclaims space; it never
/// affects correctness, and a daemon whose housekeeping cannot punch holes
/// still has a correct cache. `Unsupported` is the ordinary case for a
/// filesystem or block driver without discard (a native-Linux `minimald` run
/// with a state volume, a virtio-blk without `discard` negotiated), and would
/// otherwise warn every [`CLEAN_INTERVAL`] forever, so it logs at debug.
///
/// Deliberately unbounded, unlike the shutdown quiesce's 10 s ceiling. A
/// requesting client does wait on this — [`MaintenanceHandle::clean_now`]
/// replies only once the trim is done — but so does it wait on the clean
/// itself, which is equally unbounded; a reclaim takes as long as the
/// filesystem makes it take, and a deadline here would only report success
/// over extents still undiscarded. It shares the shutdown hazard documented on
/// [`clean`] — a trim in flight when the `Shutdown` RPC quiesces the volume is
/// walking a filesystem being synced and unmounted — bounded the same way, by
/// [`MaintenanceHandle::abort`] and the ext4 journal.
#[cfg(target_os = "linux")]
async fn trim_state_volume_if_mounted(state: &ServerStateHandle) {
    if !state.state_volume_mounted().await {
        return;
    }
    let mountpoint = state.minimal_state_dir().await;
    // `FITRIM` walks the whole filesystem's block groups; like the clean
    // itself, that belongs on the blocking pool.
    let trim = tokio::task::spawn_blocking(move || {
        crate::guest::trim_state_volume(mountpoint.as_utf8_path().as_str())
    });
    match trim.await {
        Ok(Ok(discarded)) => {
            tracing::info!(discarded_bytes = discarded, "state volume trimmed")
        }
        Ok(Err(error)) if error.kind() == ErrorKind::Unsupported => {
            tracing::debug!(%error, "state volume does not support discard; not trimming")
        }
        Ok(Err(error)) => tracing::warn!(%error, "state volume trim failed; space not reclaimed"),
        Err(error) => tracing::warn!(%error, "state volume trim panicked"),
    }
}

/// Nothing to trim off a host that has no guest data volume — `minimald` only
/// mounts one as the microVM's pid-1, and its `FITRIM` is Linux-only.
#[cfg(not(target_os = "linux"))]
async fn trim_state_volume_if_mounted(_state: &ServerStateHandle) {}

/// Logs what the clean removed, one line per entry, until the sender drops,
/// mirroring each event to `relay` if a caller asked for one. Best-effort on
/// that half: a client that hung up mid-clean must not stop the clean, nor cost
/// the daemon its own record of what was removed.
async fn log_events(
    mut rx: event_chan::UnboundedReceiver<CleanEvent>,
    relay: Option<event_chan::UnboundedSender<CleanEvent>>,
) {
    while let Some(event) = rx.next().await {
        tracing::info!("{}", event.render());
        if let Some(relay) = &relay {
            let _ = relay.unbounded_send(event);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use common::SpecHash;
    use lcache::{EntryMeta, FileSystem, MetaInner};
    use tempfile::TempDir;

    use super::*;
    use crate::server::ServerStateHandle;

    /// A daemon rooted at a fresh tempdir, with its maintenance actor running.
    async fn daemon() -> (TempDir, ServerStateHandle, MaintenanceHandle) {
        let dir = TempDir::new().unwrap();
        let state = ServerStateHandle::new(crate::server::test_config(dir.path()), None)
            .await
            .unwrap();
        let maintenance = spawn(state.clone(), CancellationToken::new());
        (dir, state, maintenance)
    }

    /// Writes an entry into the daemon's local cache under `hash`. No read is
    /// ever recorded against it, so a clean sees it as cold.
    fn write_entry(cache: &mctx::Cache, hash: &SpecHash) {
        let w = cache.write_dir(hash).unwrap();
        w.open_write("f").unwrap().write_all(b"x").unwrap();
        w.finalize(EntryMeta {
            inner: MetaInner::Spec("test".to_string()),
            fetched: false,
            ..Default::default()
        })
        .unwrap();
    }

    /// A clean reclaims cold cache entries but not the ones a live session
    /// still needs — the whole point of routing the keep set through the
    /// sessions manager.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn clean_keeps_what_a_session_needs_and_drops_the_rest() {
        let (_dir, state, maintenance) = daemon().await;

        // A session that needs exactly one package, and the hash it resolves.
        let mngr = state.sessions_manager().await;
        let _id = crate::sessions::tests::active_session_needing(&mngr, "sess", "pkg-a").await;
        let needed: Vec<SpecHash> = mngr.needed_packages().await.unwrap().into_iter().collect();
        assert_eq!(needed.len(), 1, "the session needs its one package");

        // Both go into the cache with no recorded read: only the keep set
        // separates them.
        let cache = state.daemon_context().await.local_cache();
        let cold = SpecHash::from_bytes([9; 32]);
        write_entry(&cache, &needed[0]);
        write_entry(&cache, &cold);

        let report = maintenance.clean_now(None, None).await.unwrap();

        assert_eq!(
            report,
            CleanReport {
                entries: 1,
                dirs: 0
            }
        );
        let left: Vec<SpecHash> = cache.iter_entries().collect();
        assert_eq!(left, vec![needed[0].clone()], "the cold entry should go");
    }

    /// With no sessions at all the keep set is empty, so a cold entry goes —
    /// and the clean still completes cleanly (the sweep dirs exist, the temp
    /// dir included).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn clean_runs_with_no_sessions() {
        let (_dir, state, maintenance) = daemon().await;
        let cache = state.daemon_context().await.local_cache();
        write_entry(&cache, &SpecHash::from_bytes([1; 32]));

        assert_eq!(
            maintenance.clean_now(None, None).await.unwrap(),
            CleanReport {
                entries: 1,
                dirs: 0
            },
        );
        assert_eq!(cache.iter_entries().count(), 0);
    }

    /// Two requests in flight at once don't overlap: the actor takes them in
    /// turn, so one reclaims both entries and the other finds nothing left. If
    /// they ran together they would be walking and unlinking the same cache
    /// tree, and the counts would not add up to exactly what was there.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_requests_are_serialized() {
        let (_dir, state, maintenance) = daemon().await;
        let cache = state.daemon_context().await.local_cache();
        write_entry(&cache, &SpecHash::from_bytes([1; 32]));
        write_entry(&cache, &SpecHash::from_bytes([2; 32]));

        let other = maintenance.clone();
        let (first, second) = tokio::join!(
            maintenance.clean_now(None, None),
            other.clean_now(None, None)
        );

        let mut counts = [first.unwrap().entries, second.unwrap().entries];
        counts.sort();
        assert_eq!(
            counts,
            [0, 2],
            "one clean took both entries, the other none"
        );
        assert_eq!(cache.iter_entries().count(), 0);
    }
}
