//! Session side-operations - operations run non-interactively in the context of a session.

use std::{io::ErrorKind::NotFound, sync::Arc};

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

/// The terminal result of a check side-op, delivered as the final
/// [`CheckUpdate`] before the check's channel closes.
#[derive(Debug, Clone)]
pub enum CheckOutcome {
    /// Every selected object was checked. `failed` is set when any checker
    /// returned [`CheckVerdict::Fail`](check::CheckVerdict::Fail) — the run
    /// itself completed either way.
    Completed { failed: bool },
    /// The run errored before checking everything; the string is the failure.
    Failed(String),
    /// The run was cancelled before completing (e.g. the session tore down).
    Cancelled,
}

/// An update from a running check side-op: one [`CheckUpdate::Checked`] per
/// object as its checks complete, then exactly one terminal
/// [`CheckUpdate::Finished`] as the last item before the channel closes.
///
/// `Checked` delivery is best-effort (see [`Sink::try_send`]), so a subscriber
/// that falls far enough behind can miss one. The `failed` flag on
/// [`CheckOutcome::Completed`] is tallied from *every* result regardless of
/// delivery, so a dropped update can cost a rendered line but never turns a
/// failing run into a passing one.
#[derive(Debug, Clone)]
pub enum CheckUpdate {
    /// Every checker for one object (a package, profile, or stack) finished.
    Checked {
        object: check::CheckObj,
        results: Vec<check::CheckResult>,
    },
    Finished(CheckOutcome),
}

impl CheckUpdate {
    /// The display lines for this update, in order and already formatted.
    /// Framing is the caller's job: the env socket prefixes each with `msg:`,
    /// the SSH exec path writes them to the channel's data stream.
    ///
    /// [`CheckUpdate::Finished`] renders nothing — the terminal outcome goes
    /// through [`CheckOutcome::summarize`] instead, which also carries the
    /// exit status each transport needs.
    pub fn render(&self) -> Vec<String> {
        let Self::Checked { object, results } = self else {
            return vec![];
        };
        // A blank line separates objects, then the heading ("package: foo").
        let mut lines = vec![String::new(), object.to_string()];
        for check in results {
            lines.push(format!("{}...{}", check.check, check.verdict));
            lines.extend(check.err.iter().map(|err| format!("\t{err}")));
        }
        lines
    }
}

impl CheckOutcome {
    /// The exit status and message to report once a run's channel has closed.
    /// `None` is a channel that closed without a terminal update — the side-op
    /// died before reporting (e.g. the actor was torn down mid-run).
    ///
    /// A zero status is the only success: callers render it as ordinary output
    /// and anything else as an error. Statuses match the build path — 1 for a
    /// failure, 130 for a cancellation.
    pub fn summarize(outcome: Option<&Self>) -> (u32, String) {
        match outcome {
            Some(Self::Completed { failed: false }) => (0, "check finished".to_string()),
            Some(Self::Completed { failed: true }) => (1, "some checks failed".to_string()),
            Some(Self::Failed(e)) => (1, format!("check failed: {e}")),
            Some(Self::Cancelled) => (130, "check cancelled".to_string()),
            None => (1, "check ended without reporting an outcome".to_string()),
        }
    }
}

/// A registration to recieve updates about the progress of a side-op.
///
/// See the [`BuildSink`] and [`CheckSink`] aliases: the delivery discipline is
/// the same for both, only the update type differs.
#[derive(Debug)]
pub(crate) enum Sink<T> {
    Structured(mpsc::Sender<T>),
}

impl<T> Sink<T> {
    /// Best-effort progress delivery: a full or disconnected sink drops the
    /// update rather than blocking the op.
    pub fn try_send(&self, u: T) -> Result<(), TrySendError<T>> {
        match self {
            Self::Structured(s) => s.try_send(u),
        }
    }

    /// Reliable delivery for the terminal outcome: awaits channel capacity so
    /// the `Finished` update isn't dropped under backpressure. Errors only if
    /// the subscriber has already gone away.
    pub async fn send(&self, u: T) -> Result<(), mpsc::error::SendError<T>> {
        match self {
            Self::Structured(s) => s.send(u).await,
        }
    }
}

/// A registration to recieve updates about the progress of a build.
pub(crate) type BuildSink = Sink<BuildUpdate>;
/// A registration to recieve updates about the progress of a check run.
pub(crate) type CheckSink = Sink<CheckUpdate>;

/// The subscribers of one side-op, behind the op's lock.
#[derive(Debug)]
struct Inner<T> {
    sinks: Vec<Sink<T>>,
}

/// Which objects to check and how, as parsed from the `min check` invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CheckOpts {
    pub packages: bool,
    pub profiles: bool,
    pub stacks: bool,
    pub fix: bool,
    pub filter_names: Vec<String>,
    pub skip_checkers: Vec<String>,
}

impl CheckOpts {
    /// Parses a `min check` argument string: the `--packages`, `--profiles`,
    /// and `--stacks` kind flags, `--fix`, and every bare word as an
    /// object-name filter. With no kind flag at all, every kind is checked.
    ///
    /// Shared by the two transports that accept the command (the in-sandbox
    /// env socket and the SSH exec path) so they can't drift on what a flag
    /// means.
    ///
    /// Returns the message to report if any token looks like a flag but isn't
    /// one. Such a token must never fall through to `filter_names`: it would
    /// filter for a name nothing matches, so zero objects get checked and the
    /// run reports success — turning `min check --packags` into a silent pass
    /// for anything scripting the exit status.
    pub fn from_args(args: &str) -> Result<Self, String> {
        let (mut packages, mut profiles, mut stacks, mut fix) = (false, false, false, false);
        let mut filter_names = Vec::new();

        for token in args.split_whitespace() {
            match token {
                "--packages" => packages = true,
                "--profiles" => profiles = true,
                "--stacks" => stacks = true,
                "--fix" => fix = true,
                // Anything leading with a dash, not just `--`: `mip check`
                // carries an explicit guard for people typing `-p`, and no
                // real package/profile/stack directory is named that way.
                flag if flag.starts_with('-') => {
                    return Err(format!(
                        "unknown flag `{flag}` \
                         (expected --packages, --profiles, --stacks, or --fix)"
                    ));
                }
                name => filter_names.push(name.to_string()),
            }
        }

        // No kind flag specified means check everything.
        if !packages && !profiles && !stacks {
            (packages, profiles, stacks) = (true, true, true);
        }

        Ok(Self {
            packages,
            profiles,
            stacks,
            fix,
            filter_names,
            // No flag exposes this yet; checkers are skipped by name only from
            // `mip check --skip`.
            skip_checkers: vec![],
        })
    }
}

#[derive(Debug)]
#[allow(dead_code)]
enum Op {
    Build {
        /// Packages which were requested to be built
        packages: Vec<String>,
        /// Whether named packages must be built even if cached
        rebuild: bool,
        /// Interior mutability. Users MUST NEVER block while holding
        /// the lock: get in, read/update data, get out.
        inner: Arc<Mutex<Inner<BuildUpdate>>>,
    },
    Check {
        /// What the check run was asked to cover
        opts: CheckOpts,
        /// Interior mutability. Users MUST NEVER block while holding
        /// the lock: get in, read/update data, get out.
        inner: Arc<Mutex<Inner<CheckUpdate>>>,
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

/// How long to wait to hand a subscriber a side-op's terminal update before
/// giving up - without a timeout shutdown may hang forever.
const FINISH_SEND_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Delivers the terminal `update` to every subscriber, then drops the sinks so
/// their receivers close.
async fn finish<T: Clone>(inner: &Mutex<Inner<T>>, update: T) {
    let sinks = {
        let mut inner = inner.lock().await;
        std::mem::take(&mut inner.sinks)
    };
    for sink in &sinks {
        let _ = tokio::time::timeout(FINISH_SEND_TIMEOUT, sink.send(update.clone())).await;
    }
    // `sinks` dropped here → each receiver observes the close.
}

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
    ///
    /// Should only be called from the session actor.
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
    async fn new_build(
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
        let inner = Arc::new(Mutex::new(Inner { sinks }));

        let handle = {
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

                finish(&build_inner, BuildUpdate::Finished(outcome)).await;
            })
        };

        Ok(Self {
            id: uuid::Uuid::now_v7(),
            cancel,
            session,
            op: Op::Build {
                packages: pkgs,
                rebuild,
                inner,
            },
            handle,
        })
    }

    /// Kicks off a check side-op wired to a single structured sink, returning
    /// the op alongside the receiver end that streams a [`CheckUpdate`] per
    /// checked object until the run completes (at which point the sender is
    /// dropped and the receiver closes). The session actor stores the op and
    /// hands the receiver to whoever requested the run so it can render results.
    ///
    /// Should only be called from the session actor.
    pub(crate) async fn spawn_check(
        session: WeakSessionHandle,
        opts: CheckOpts,
        ctx: Context,
        buffer: usize,
    ) -> Result<(Self, mpsc::Receiver<CheckUpdate>), std::io::Error> {
        let (tx, rx) = mpsc::channel(buffer);
        let sop = Self::new_check(session, opts, ctx, vec![CheckSink::Structured(tx)]).await?;
        Ok((sop, rx))
    }

    /// Called to kick off a new check run with the specified parameters.
    async fn new_check(
        session: WeakSessionHandle,
        opts: CheckOpts,
        ctx: Context,
        sinks: Vec<CheckSink>,
    ) -> Result<Self, std::io::Error> {
        let dir = ctx
            .minimal_file()
            .dir_path()
            .ok_or(std::io::Error::new(
                NotFound,
                "no minimal.toml in workbench",
            ))?
            .to_path_buf();

        // `graph_from_all_packages` is CPU-heavy, run on blocking pool.
        let (ctx, graph_result) = tokio::task::spawn_blocking(move || {
            let mut ctx = ctx;
            let r = ctx.graph_from_all_packages().map_err(|e| e.to_string());

            (ctx, r)
        })
        .await
        .map_err(std::io::Error::other)?;
        let graph = graph_result.map_err(std::io::Error::other)?;

        let cancel = CancellationToken::new();
        let inner = Arc::new(Mutex::new(Inner { sinks }));

        let handle = {
            let check_cancel = cancel.clone();
            let cancel_flag = cancel.clone();
            let check_opts = opts.clone();
            let check_inner = inner.clone();
            tokio::task::spawn(async move {
                let stream = check::run_checks(
                    (check_opts.packages).then(|| dir.join("packages")),
                    (check_opts.profiles).then(|| dir.join("profiles")),
                    (check_opts.stacks).then(|| dir.join("stacks")),
                    check::CheckCtx::new(
                        check_opts.filter_names,
                        check_opts.skip_checkers,
                        check_opts.fix,
                        Some(Arc::new(tokio::sync::RwLock::new(graph))),
                        ctx.stdlib_dir().to_path_buf(),
                        ctx.local_cache(),
                        ctx.op_tracker(),
                    )
                    .with_cancel(check_cancel),
                );

                let mut stream = match stream.map_err(|e| e.to_string()) {
                    Ok(s) => s,
                    Err(msg) => {
                        tracing::warn!("session check failed to start: {msg}");
                        finish(
                            &check_inner,
                            CheckUpdate::Finished(CheckOutcome::Failed(msg)),
                        )
                        .await;
                        return;
                    }
                };

                // Drain the checks, forwarding results as they land; the first
                // error ends the run.
                let mut failed = false;
                let outcome = loop {
                    let Some((object, result)) = stream.next().await else {
                        break CheckOutcome::Completed { failed };
                    };
                    // `check::Error` is `!Send` (nickel `Rc`s), so it must not
                    // outlive this match.
                    let results = match result.map_err(|e| match e {
                        check::Error::Cancelled => None,
                        e => Some(e.to_string()),
                    }) {
                        Ok(results) => results,
                        Err(None) => break CheckOutcome::Cancelled,
                        Err(Some(msg)) => {
                            tracing::warn!("session check failed: {msg}");
                            break CheckOutcome::Failed(msg);
                        }
                    };
                    failed |= results
                        .iter()
                        .any(|r| matches!(r.verdict, check::CheckVerdict::Fail));
                    let inner = check_inner.lock().await;
                    for sink in &inner.sinks {
                        let _ = sink.try_send(CheckUpdate::Checked {
                            object: object.clone(),
                            results: results.clone(),
                        });
                    }
                };
                drop(stream);

                // Classify first: cancelling below would make every `Failed`
                // look like teardown fallout.
                let outcome = match outcome {
                    CheckOutcome::Failed(_) if cancel_flag.is_cancelled() => {
                        CheckOutcome::Cancelled
                    }
                    o => o,
                };

                // Dropping the stream can't reach `StandaloneTestCheck`'s
                // detached task or in-flight blocking checkers; the token can.
                // A `Completed` run has nothing left to stop.
                if !matches!(outcome, CheckOutcome::Completed { .. }) {
                    cancel_flag.cancel();
                }

                finish(&check_inner, CheckUpdate::Finished(outcome)).await;
            })
        };

        Ok(Self {
            id: uuid::Uuid::now_v7(),
            cancel,
            session,
            op: Op::Check { opts, inner },
            handle,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use check::{CheckObj, CheckResult, CheckVerdict};

    /// A bare `min check` checks every kind, with no filters and no fixing.
    #[test]
    fn check_opts_default_to_every_kind() {
        assert_eq!(
            CheckOpts::from_args("").unwrap(),
            CheckOpts {
                packages: true,
                profiles: true,
                stacks: true,
                fix: false,
                filter_names: vec![],
                skip_checkers: vec![],
            }
        );
    }

    /// Naming a kind narrows the run to exactly that kind — the "check
    /// everything" default must not leak back in alongside an explicit flag.
    #[test]
    fn check_opts_kind_flag_excludes_the_others() {
        let opts = CheckOpts::from_args("--packages").unwrap();
        assert!(opts.packages);
        assert!(!opts.profiles, "an explicit --packages excludes profiles");
        assert!(!opts.stacks, "an explicit --packages excludes stacks");
    }

    /// Flags are recognised anywhere in the argument string, and every bare
    /// word is an object-name filter (never silently dropped).
    #[test]
    fn check_opts_collect_flags_and_filters() {
        let opts = CheckOpts::from_args("uroot --fix  busybox --stacks").unwrap();
        assert_eq!(opts.filter_names, vec!["uroot", "busybox"]);
        assert!(opts.fix);
        assert!(opts.stacks && !opts.packages && !opts.profiles);
    }

    /// A mistyped flag must be an error, never a name filter. Treated as a
    /// filter it would match no object, so the run would check nothing and
    /// report success — a silent pass for anything scripting the exit status.
    #[test]
    fn check_opts_reject_unknown_flags() {
        for args in ["--packags", "--fix --stacsk", "-p uroot", "uroot --verbose"] {
            let err = CheckOpts::from_args(args)
                .expect_err("an unrecognized flag must not parse as a filter");
            assert!(
                err.contains("unknown flag"),
                "expected an unknown-flag error for {args:?}, got {err:?}",
            );
        }
    }

    /// The rejection keys on the leading dash, not on the token being unknown
    /// in general: bare words are legitimate object names and stay filters.
    #[test]
    fn check_opts_keep_bare_words_as_filters() {
        let opts = CheckOpts::from_args("some-pkg other.pkg under_score")
            .expect("dashes inside a name are fine");
        assert_eq!(
            opts.filter_names,
            vec!["some-pkg", "other.pkg", "under_score"]
        );
    }

    /// The rendered form is what both transports print, so pin its shape: a
    /// blank separator, the object heading, then one line per check with its
    /// errors indented beneath.
    #[test]
    fn checked_update_renders_heading_then_indented_errors() {
        let lines = CheckUpdate::Checked {
            object: CheckObj::Package("uroot".to_string()),
            results: vec![
                CheckResult {
                    check: "fmt".into(),
                    verdict: CheckVerdict::Pass,
                    err: vec![],
                },
                CheckResult {
                    check: "parse".into(),
                    verdict: CheckVerdict::Fail,
                    err: vec!["build.ncl: bad".to_string()],
                },
            ],
        }
        .render();

        assert_eq!(
            lines,
            vec![
                "".to_string(),
                "package: uroot".to_string(),
                "fmt...Pass".to_string(),
                "parse...Fail".to_string(),
                "\tbuild.ncl: bad".to_string(),
            ]
        );
    }

    /// `Finished` carries no display lines of its own — it is reported via
    /// `summarize`, and a transport that rendered both would print twice.
    #[test]
    fn finished_update_renders_nothing() {
        assert!(
            CheckUpdate::Finished(CheckOutcome::Completed { failed: false })
                .render()
                .is_empty()
        );
    }

    /// Only a clean completion exits 0. Every other terminal state — including
    /// a run that completed with failing checks — has to be distinguishable by
    /// exit status, since that is all a scripted `min check` sees.
    #[test]
    fn only_a_clean_run_summarizes_as_success() {
        let status = |o: CheckOutcome| CheckOutcome::summarize(Some(&o)).0;

        assert_eq!(status(CheckOutcome::Completed { failed: false }), 0);
        assert_eq!(status(CheckOutcome::Completed { failed: true }), 1);
        assert_eq!(status(CheckOutcome::Failed("boom".into())), 1);
        assert_eq!(status(CheckOutcome::Cancelled), 130);
        // A channel that closed without a terminal update is a failure, never
        // a silent pass.
        assert_eq!(CheckOutcome::summarize(None).0, 1);
    }
}
