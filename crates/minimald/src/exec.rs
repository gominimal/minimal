//! SSH `exec` request handling: Launching tasks defined in the session,
//! git recieve-pack, and launching side ops.
//!
//! Process spawning is abstracted via the [`Exec`] / [`Process`] traits
//! so the bridge logic can be exercised with a mock in tests without
//! going through `tokio::process` or russh.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Display;
use std::io;
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use boxes::SessionId;
use futures::{
    StreamExt,
    stream::{self, BoxStream, Stream},
};
use paths::DaemonAbsPath;
use russh::{
    Channel, ChannelId,
    server::{Msg, Session},
};
use std::collections::VecDeque;
use tempfile::TempDir;
use tokio::net::unix::pipe;

use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    process::{Child, ChildStderr, ChildStdin, ChildStdout, Command},
};
use tokio_util::sync::CancellationToken;
use tracing::Instrument as _;

// Every task this module spawns carries the caller's span (TEL-022): the
// clippy `disallowed-methods` for the crate names tokio's own spawn.
use crate::traced::spawn;

use diagnostics::redact::scrub_secrets;

use crate::{
    ChannelConfig, MINIMAL_SESSION_ID_ENV,
    box_actor::BoxHandle,
    box_manager::BoxKeyPredicate,
    connection::{ConnectionError, ConnectionHandle},
    server::ServerStateHandle,
};

mod bridge;
mod git;
mod process;
mod run;

pub(crate) use bridge::*;
use git::*;
pub use process::*;
use run::*;

/// "What to run." Turns into a [`Stream`] of one or more process
/// spawns, run back-to-back.
///
/// Modelling as a `Stream` rather than a two-trait `IntoIter`/`Iter`
/// split is a deliberate choice: some impls (notably [`TaskExec`]) need
/// stateful resources to outlive every spawned process — that state has
/// no honest home in a separate "resolution" step, so we let it live on
/// the stack frame of the impl's producer (or on the stream's state
/// directly). Trivial impls like [`TokioExec`] use [`stream::once`].
///
/// Setup errors and per-spawn errors both surface as `Err` items in the
/// stream; the bridge handles them uniformly.
pub trait Exec: Send + 'static {
    /// What the bridge does with input arriving after the current command
    /// closed its stdin: dropped for a single program, kept for the next in
    /// a sequence (the default).
    fn unread_stdin(&self) -> UnreadStdin {
        UnreadStdin::Keep
    }

    type Process: Process;

    /// Whether a destroy of the box ends this exec's process. True for a
    /// process inside the box, which the destroy's host teardown stops.
    /// False for a process outside the box — on the daemon's host, or in a
    /// task's own sandbox — which outlives it.
    const ENDED_BY_BOX_DESTROY: bool = true;

    fn exec(self, session: BoxHandle) -> BoxStream<'static, io::Result<Self::Process>>;
}

/// A handle to one spawned process: stdio plus lifecycle controls.
///
/// `wait` MUST be cancel-safe — callers poll it inside `tokio::select!`,
/// so the future may be dropped and re-awaited across loop iterations.
pub trait Process: Send + 'static {
    type Stdin: AsyncWrite + Unpin + Send + 'static;
    type Stdout: AsyncRead + Unpin + Send + 'static;
    type Stderr: AsyncRead + Unpin + Send + 'static;

    /// Returns all three stdio handles the first time it's called,
    /// `None` thereafter (per-handle `Option::take` semantics, matching
    /// `tokio::process::Child`).
    fn take_stdio(&mut self) -> Option<(Self::Stdin, Self::Stdout, Self::Stderr)>;

    /// Resolves when the process exits. `Ok(None)` means the process
    /// was terminated by a signal rather than exiting with a numeric
    /// code.
    async fn wait(&mut self) -> io::Result<Option<i32>>;

    /// Request termination. Idempotent. Returns immediately — the
    /// caller is expected to follow up with `wait` for the actual exit.
    fn start_kill(&mut self) -> io::Result<()>;
}

/// Handles a request to run a program on an SSH channel.
///
/// Looks up the target session via the `MINIMAL_SESSION_ID` env var the
/// client previously set on this channel, fetches its workspace, accepts the
/// request, and spawns an async task to take over the
/// channel for the lifetime of the conversation.
///
/// Accepted forms are:
///  * `git-receive-pack min://<session ID>` - handles a git receive-pack, routing
///    with the trailing session ID. Matched before the vocabulary below, and
///    not part of it: git speaks the pack protocol, not exec requests.
///  * `git-upload-pack min://<session ID>` - handles a git upload-pack, routing
///    with the trailing session ID the same way.
///  * a [`minimald_rpc::exec::ExecRequest`], which is where the rest of the
///    vocabulary is defined. The daemon-serviced forms — `min://task/run`,
///    `min://package/build` and `min://check` — are each routed via a
///    `MINIMAL_SESSION_ID` env var that must be set on the channel by the
///    client. `min://shell` and `min://argv` are handed to the session.
///  * anything else: a shell command for the session. Nothing about a
///    command's text routes it, so a session command can never be mistaken
///    for one of the daemon's own (gominimal/inbox#558).
pub(crate) async fn handle_exec(
    argv: &[u8],
    serv: ServerStateHandle,
    conn: ConnectionHandle,
    id: ChannelId,
    session: &mut Session,
) -> Result<(), ConnectionError> {
    let argv = match String::from_utf8(argv.to_vec()) {
        Ok(argv) => argv,
        Err(e) => {
            tracing::warn!("channel {id}: argv was not utf8: {e}");
            session.channel_failure(id)?;
            return Ok(());
        }
    };

    let mut conn_lock = conn.lock().await;
    let Some((channel, config)) = conn_lock.take(id) else {
        session.channel_failure(id)?;
        return Ok(());
    };
    let conn_username = conn_lock.ssh_username.clone().unwrap_or_default();
    drop(conn_lock);

    if let Some(ident) = argv.strip_prefix("git-receive-pack min://") {
        return handle_git_receive(ident, serv, conn, id, session, channel, config).await;
    }

    if let Some(ident) = argv.strip_prefix("git-upload-pack min://") {
        return handle_git_upload(ident, serv, conn, id, session, channel, config).await;
    }

    if config.pty.is_some() {
        tracing::warn!("channel {id}: pty requested but not yet supported",);
        session.channel_failure(id)?;
        return Ok(());
    }

    let Some(session_id_str) = config.env_vars.get(MINIMAL_SESSION_ID_ENV) else {
        tracing::warn!(
            "execution request rejected on channel {id}: missing {MINIMAL_SESSION_ID_ENV}",
        );
        session.channel_failure(id)?;
        return Ok(());
    };
    let Ok(session_id) = SessionId::parse_str(session_id_str) else {
        tracing::warn!(
            value = %session_id_str,
            "execution request rejected on channel {id}: {MINIMAL_SESSION_ID_ENV} is not a uuid",
        );
        session.channel_failure(id)?;
        return Ok(());
    };

    // The exec span (which adopts the client's TRACEPARENT) is opened before
    // the session lookup, so the manager's GetSession is a child of the
    // caller's trace instead of a root of its own.
    let (span, traceparent) = exec_span(&config, session_id, &argv);
    let trace_env = minimald_rpc::taskenv::trace_env(
        mlog::otel::exporting(),
        traceparent,
        minimald_rpc::trace::opted_out(&config.env_vars),
    );
    let mngr = serv.sessions_manager().await;
    let session_handle = match mngr
        .get_session(BoxKeyPredicate::Id(session_id))
        .instrument(span.clone())
        .await
    {
        Ok(Some(h)) => h,
        Ok(None) => {
            tracing::warn!(%session_id, "execution request rejected: unknown session");
            session.channel_failure(id)?;
            return Ok(());
        }
        Err(e) => {
            tracing::warn!(%session_id, error = %e, "execution request rejected: lookup failed");
            session.channel_failure(id)?;
            return Ok(());
        }
    };

    // Logged for every accepted form, before the dispatch that decides which
    // one it is: an operator reading the log should see what a client asked to
    // run, whether it was serviced by the daemon, handed to the session, or
    // refused below. The command is scrubbed so a credential passed as an
    // argument never lands in the log verbatim. For a client that opted out
    // of telemetry the line says so and carries no command at all: the log
    // exporter would otherwise ship the one record of what it ran.
    if minimald_rpc::trace::opted_out(&config.env_vars) {
        tracing::info!(%session_id, telemetry = OPT_OUT, "exec request (command not recorded)");
    } else {
        tracing::info!(%session_id, command = %scrub_secrets(&argv), "exec request");
    }

    // Parsed, never sniffed. The vocabulary in `minimald_rpc::exec` is the only
    // way to ask for one of the daemon's own forms, so a session command can no
    // longer be mistaken for one — `min --version` names the session's `min`
    // and reaches it, where the old `strip_prefix("min ")` claimed and refused
    // it (gominimal/inbox#558).
    let request = match minimald_rpc::exec::ExecRequest::parse(&argv) {
        Ok(request) => request,
        Err(e) => {
            tracing::warn!(%session_id, error = %e, "execution request rejected");
            // Accept-then-report, as the bad-flag path does: a bare
            // `channel_failure` would reach the client as an opaque "exec
            // request failed" with none of the detail the error carries.
            session.channel_success(id)?;
            spawn(async move {
                reject_unsupported_exec(channel, e.to_string()).await;
            });
            return Ok(());
        }
    };

    use minimald_rpc::exec::ExecRequest;
    match request {
        ExecRequest::Shell(_) | ExecRequest::Argv(_) => {
            let program = match request {
                ExecRequest::Shell(cmd) => BoxProgram::Shell(cmd),
                ExecRequest::Argv(words) => BoxProgram::Argv(words),
                _ => unreachable!("the match arm admits only Shell and Argv"),
            };
            let span = span.clone();
            session.channel_success(id)?;
            spawn(
                run_in_session(
                    serv,
                    conn,
                    session_handle,
                    id,
                    channel,
                    program,
                    conn_username,
                    trace_env,
                )
                .instrument(span),
            );
        }
        ExecRequest::TaskRun {
            task,
            owns_box,
            args,
            cwd,
        } => {
            let task = task.trim().to_string();
            if task.is_empty() {
                tracing::warn!(%session_id, "execution request rejected: task/run names no task");
                session.channel_failure(id)?;
                return Ok(());
            }
            // A task's `env_vars`, resolved by the client against the invoking
            // shell and carried on the channel environment (#585). Empty from a
            // client that predates it — in which case the task path resolves
            // them the old way, daemon-side.
            // Plus the exec span's TRACEPARENT on opt-in (TEL-023):
            // a `min` the task runs joins the caller's trace.
            let task_env = minimald_rpc::taskenv::with_trace(
                minimald_rpc::taskenv::from_channel_env(&config.env_vars),
                trace_env.clone(),
            );
            let drop_env = minimald_rpc::taskenv::drops_from_channel_env(&config.env_vars);
            let span = span.clone();
            session.channel_success(id)?;
            spawn(tracing::Instrument::instrument(
                async move {
                    // `ExecTask::run` consumes the server handle; the box's end
                    // needs one after the bridge returns.
                    let end_serv = serv.clone();
                    let exec_task = ExecTask {
                        conn,
                        serv,
                        session: session_handle,
                        channel_id: id,
                        exec: TaskExec {
                            args,
                            // The name stays behind for the run-box-end log line.
                            task: task.clone(),
                            env: task_env,
                            drop_env,
                            cwd,
                        },
                    };
                    let exit_status = exec_task.run(channel).await;
                    // The exit status is on the wire and the channel closed: the
                    // run is over whether or not its client is still here, so a
                    // box created for it ends now (NET-131).
                    if owns_box {
                        end_run_box(&end_serv, session_id, &task, exit_status).await;
                    }
                },
                span,
            ));
        }
        ExecRequest::PackageBuild(args) => {
            let span = span.clone();
            session.channel_success(id)?;
            let build_args = args.trim().to_string();
            spawn(tracing::Instrument::instrument(
                async move {
                    run_build_exec(session_handle, id, channel, build_args).await;
                },
                span,
            ));
        }
        ExecRequest::Check(args) => {
            session.channel_success(id)?;
            let check_args = args.trim().to_string();
            spawn(tracing::Instrument::instrument(
                async move {
                    run_check_exec(session_handle, id, channel, check_args).await;
                },
                span,
            ));
        }
    }

    Ok(())
}

/// Accepts the channel and reports an exec request the daemon cannot serve on
/// the SSH stderr stream, then exits non-zero. A bare `channel_failure` would
/// reach the client only as an opaque "exec request failed", so — mirroring the
/// accept-then-report shape `run_check_exec` uses for a bad flag — this relays
/// the parse error, which already names the form asked for and lists the ones
/// this daemon serves. The command is still refused; nothing is spawned.
async fn reject_unsupported_exec(channel: Channel<Msg>, reason: String) {
    let (_rs, ws) = channel.split();
    let mut e = ws.make_writer_ext(Some(1));
    let _ = e
        .write_all(unsupported_command_message(&reason).as_bytes())
        .await;
    let _ = e.flush().await;
    let _ = ws.eof().await;
    let _ = ws.exit_status(1).await; // otherwise considered -1
    let _ = ws.close().await; // needed to release the remote
}

/// The stderr copy for an exec request the daemon cannot serve. The reason
/// comes from [`minimald_rpc::exec::ExecParseError`], which already names the
/// form that was asked for and the ones this daemon serves.
fn unsupported_command_message(reason: &str) -> String {
    format!("minimald: {reason}\n")
}

/// The tracing span an in-session exec runs under, mirroring the `rpc` span in
/// [`crate::rpc::handle_ssh_rpc`].
///
/// The client's propagated trace context is adopted — same trace id, fresh span
/// id, the client's span as parent — so one `trace_id` grep joins the CLI's log
/// with the daemon's. A missing or malformed value mints a fresh context:
/// propagation is a diagnostic aid and must never fail a request. The command
/// rides on the span, so every record the exec emits names what was asked for.
/// The exec span, and its context as a `TRACEPARENT` (what a box gets on
/// opt-in, so a `min` run inside joins this trace) — `None` unless the span
/// is actually recorded (see [`box_traceparent`]).
fn exec_span(
    config: &ChannelConfig,
    session_id: SessionId,
    argv: &str,
) -> (tracing::Span, Option<String>) {
    // Two callsites, not one span with a recorded field: the opted-out
    // request's span never carries the command, not even in the file log's
    // span fields, and the recorded one is what the exec-span tests read
    // at creation.
    let span = if minimald_rpc::trace::opted_out(&config.env_vars) {
        tracing::info_span!(
            "exec",
            %session_id,
            command = tracing::field::Empty,
            telemetry = OPT_OUT,
            trace_id = tracing::field::Empty,
            span_id = tracing::field::Empty,
            parent_span_id = tracing::field::Empty,
        )
    } else {
        tracing::info_span!(
            "exec",
            %session_id,
            command = %scrub_secrets(argv),
            telemetry = tracing::field::Empty,
            trace_id = tracing::field::Empty,
            span_id = tracing::field::Empty,
            parent_span_id = tracing::field::Empty,
        )
    };
    let adopted = adopt_client_trace(&span, config);
    let tp = box_traceparent(&adopted);
    (span, tp)
}

/// The value of a request span's `telemetry` field when its client opted
/// out: the one mark the file log keeps of such a request (the span is
/// recorded nowhere else).
pub(crate) const OPT_OUT: &str = "opt-out";

/// A span's trace context, and whether that span is recorded by the export
/// (its ids are the exported span's ids).
pub(crate) struct AdoptedTrace {
    ctx: minimald_rpc::trace::TraceContext,
    /// False with export off, and with the export filter not admitting the
    /// span (`MINIMAL_OTEL_FILTER=warn` against an info-level span): the ids
    /// were minted for the file log only, and no exporter or spool ever sees
    /// a span with them.
    recorded: bool,
}

/// The `TRACEPARENT` a box may be given for `adopted`: only one that names a
/// recorded span. Under `MINIMAL_OTEL_FILTER=warn`
/// the daemon handed the box a `TRACEPARENT` whose span id was spooled and
/// exported nowhere, so a `min` run inside parented itself to an orphan. A
/// trace nobody can follow is worse than a fresh one: hand the box nothing.
fn box_traceparent(adopted: &AdoptedTrace) -> Option<String> {
    adopted.recorded.then(|| adopted.ctx.traceparent())
}

/// Makes `span` a child of the client's `TRACEPARENT` (channel env) and
/// records its ids. With OTel export on and the span admitted, the exported
/// span's ids are the ids; otherwise adopt-or-mint exactly as before. The
/// span must declare the `trace_id`, `span_id` and `parent_span_id` fields.
pub(crate) fn adopt_client_trace(span: &tracing::Span, config: &ChannelConfig) -> AdoptedTrace {
    use minimald_rpc::trace::{TRACEPARENT_ENV, TraceContext};

    if minimald_rpc::trace::opted_out(&config.env_vars) {
        return adopt_opt_out(span);
    }
    let client_ctx = config
        .env_vars
        .get(TRACEPARENT_ENV)
        .and_then(|v| TraceContext::parse_traceparent(v));
    adopt_trace(span, client_ctx)
}

/// The client opted out of telemetry (`MINIMAL_OTEL=off` on the channel,
/// or in a forward's originator field): make `span`, and every span under
/// it, non-recording ([`mlog::otel::opt_out`]), mark it `telemetry =
/// opt-out`, and give it ids for the file log only. Nothing is adopted: an
/// opted-out client sends no `TRACEPARENT`, and one that did would still
/// get no span in its trace. The result is never `recorded`, so the box
/// gets no `TRACEPARENT` either ([`box_traceparent`]). The span must
/// declare the `trace_id`, `span_id`, `parent_span_id` and `telemetry`
/// fields.
pub(crate) fn adopt_opt_out(span: &tracing::Span) -> AdoptedTrace {
    use minimald_rpc::trace::TraceContext;

    // `record` drops a field the span did not declare without a word, and
    // the opt-out mark would be lost (the `git_receive`/`git_upload` spans
    // once lacked it): fail loudly in tests instead.
    debug_assert!(
        span.metadata()
            .is_none_or(|m| m.fields().field("telemetry").is_some()),
        "span {:?} must declare `telemetry` to be opted out",
        span.metadata().map(tracing::Metadata::name)
    );
    let ctx = mlog::otel::opt_out(span)
        .map(|(t, s, f)| TraceContext::from_parts(t, s, f))
        .unwrap_or_else(|| TraceContext::mint().unsampled());
    span.record("telemetry", OPT_OUT);
    span.record("trace_id", tracing::field::display(ctx.trace_id_hex()));
    span.record("span_id", tracing::field::display(ctx.span_id_hex()));
    // The mailbox messages sent from inside carry these unsampled ids, so
    // the `*.message` spans they open are opted out too (`adopt_trace`
    // aligns them under a flags-00 parent).
    crate::traced::remember(span, ctx);
    AdoptedTrace {
        ctx,
        recorded: false,
    }
}

/// Makes `span` a child of `client_ctx` — the client's context however it
/// travelled (the channel env for session channels and RPCs, the open
/// request's originator field for a direct-tcpip forward) — and records its
/// ids. With OTel export on and the span admitted, the exported span's ids
/// are the ids; otherwise adopt-or-mint exactly as before. The span must
/// declare the `trace_id`, `span_id` and `parent_span_id` fields.
pub(crate) fn adopt_trace(
    span: &tracing::Span,
    client_ctx: Option<minimald_rpc::trace::TraceContext>,
) -> AdoptedTrace {
    use minimald_rpc::trace::TraceContext;

    let aligned = mlog::otel::align(span, client_ctx.as_ref().map(TraceContext::parts))
        .map(|(t, s, f)| TraceContext::from_parts(t, s, f));
    let recorded = aligned.is_some();
    let ctx = aligned.unwrap_or_else(|| {
        client_ctx
            .as_ref()
            .map(TraceContext::child)
            .unwrap_or_else(TraceContext::mint)
    });
    span.record("trace_id", tracing::field::display(ctx.trace_id_hex()));
    span.record("span_id", tracing::field::display(ctx.span_id_hex()));
    if let Some(client_ctx) = &client_ctx {
        span.record(
            "parent_span_id",
            tracing::field::display(client_ctx.span_id_hex()),
        );
    }
    // For a mailbox message sent from inside this span (or anything it
    // encloses) to carry these ids: see `traced::caller_context`.
    crate::traced::remember(span, ctx);
    AdoptedTrace { ctx, recorded }
}

#[cfg(test)]
mod box_traceparent_tests {
    use super::{AdoptedTrace, box_traceparent};

    /// A box gets a `TRACEPARENT` only for a recorded span: with export off,
    /// or the export filter not admitting the exec span, the context exists
    /// (the file log uses it) but names a span no exporter or spool sees.
    #[test]
    fn an_unrecorded_exec_span_gives_the_box_no_traceparent() {
        let ctx = minimald_rpc::trace::TraceContext::mint();
        assert_eq!(
            box_traceparent(&AdoptedTrace {
                ctx,
                recorded: false
            }),
            None
        );
        assert_eq!(
            box_traceparent(&AdoptedTrace {
                ctx,
                recorded: true
            }),
            Some(ctx.traceparent())
        );
    }

    /// Without an exporter installed (this test process), `align` admits
    /// nothing, so the adopted trace is never marked recorded.
    #[test]
    fn without_an_exporter_nothing_is_recorded() {
        assert!(!mlog::otel::exporting());
        let span = tracing::info_span!("exec");
        assert!(mlog::otel::align(&span, None).is_none());
    }
}

#[cfg(test)]
pub(crate) mod testing {
    //! Mock `Process` for testing the exec bridge without spawning a
    //! real subprocess. The test side holds a [`MockController`] for
    //! driving exit and observing `start_kill`, plus duplex endpoints
    //! mirroring each stdio stream.

    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    use futures::stream::{self, BoxStream, StreamExt};
    use tokio::io::{DuplexStream, duplex};
    use tokio::sync::{Mutex, Notify};

    use super::Process;

    /// Stdio buffer size. Chosen well above the bridge's 8 KiB read
    /// buffer so a single test write never blocks on backpressure.
    const PIPE_CAPACITY: usize = 64 * 1024;

    #[derive(Default)]
    struct MockInner {
        exit: Mutex<Option<i32>>,
        notify: Notify,
        kill_requested: AtomicBool,
        exit_on_kill: Mutex<Option<i32>>,
    }

    /// Test-side handle for driving and observing a [`MockProcess`].
    /// Cheaply cloneable — both sides share the same `Arc`.
    #[derive(Clone, Default)]
    pub struct MockController {
        inner: Arc<MockInner>,
    }

    impl MockController {
        /// Signal that the mock process has exited with this code. Wakes
        /// any pending `wait` future.
        pub async fn signal_exit(&self, code: i32) {
            *self.inner.exit.lock().await = Some(code);
            // notify_one stores a permit if no waiter is parked yet,
            // which sidesteps the "set exit before bridge polls wait"
            // race that would otherwise leave the bridge hanging.
            self.inner.notify.notify_one();
        }

        /// Set the code the mock process reports once `start_kill` is
        /// called. Without it a killed mock reports no numeric code.
        pub async fn exit_on_kill(&self, code: i32) {
            *self.inner.exit_on_kill.lock().await = Some(code);
        }

        /// Whether the bridge has called `start_kill` on the process.
        pub fn was_killed(&self) -> bool {
            self.inner.kill_requested.load(Ordering::SeqCst)
        }
    }

    /// Test-side endpoints — counterparts to the streams the bridge
    /// owns after `take_stdio`.
    pub struct MockEndpoints {
        /// Reads bytes the bridge wrote to "child stdin".
        pub stdin_reader: DuplexStream,
        /// Writes bytes the bridge will read as "child stdout".
        pub stdout_writer: DuplexStream,
        /// Writes bytes the bridge will read as "child stderr".
        pub stderr_writer: DuplexStream,
        pub ctrl: MockController,
    }

    /// Bridge-side `Process` impl. The bridge calls `take_stdio` to
    /// grab the inner halves, then drives them like any other stdio.
    pub struct MockProcess {
        stdin: Option<DuplexStream>,
        stdout: Option<DuplexStream>,
        stderr: Option<DuplexStream>,
        ctrl: MockController,
    }

    /// A single bridge-side mock paired with its test-side endpoint.
    fn build_mock_pair() -> (MockProcess, MockEndpoints) {
        let (stdin_bridge, stdin_test) = duplex(PIPE_CAPACITY);
        let (stdout_bridge, stdout_test) = duplex(PIPE_CAPACITY);
        let (stderr_bridge, stderr_test) = duplex(PIPE_CAPACITY);
        let ctrl = MockController::default();
        (
            MockProcess {
                stdin: Some(stdin_bridge),
                stdout: Some(stdout_bridge),
                stderr: Some(stderr_bridge),
                ctrl: ctrl.clone(),
            },
            MockEndpoints {
                stdin_reader: stdin_test,
                stdout_writer: stdout_test,
                stderr_writer: stderr_test,
                ctrl,
            },
        )
    }

    /// A boxed stream of mock processes, shaped to match the trait
    /// surface (`io::Result` items so test fixtures can inject failures
    /// alongside successes).
    pub type MockStream = BoxStream<'static, std::io::Result<MockProcess>>;

    /// Build a single-process mock stream and its test-side endpoints.
    /// Convenience for the common case where a test only needs one
    /// process in the sequence.
    pub fn build_mock() -> (MockStream, MockEndpoints) {
        let (proc, endpoints) = build_mock_pair();
        (stream::iter(vec![Ok(proc)]).boxed(), endpoints)
    }

    /// Build a multi-process mock stream and the corresponding ordered
    /// endpoints. `endpoints[i]` drives the i-th process the bridge
    /// pulls from the stream.
    pub fn build_mock_seq(n: usize) -> (MockStream, Vec<MockEndpoints>) {
        let (procs, endpoints): (Vec<_>, Vec<_>) = (0..n).map(|_| build_mock_pair()).unzip();
        (stream::iter(procs.into_iter().map(Ok)).boxed(), endpoints)
    }

    impl Process for MockProcess {
        type Stdin = DuplexStream;
        type Stdout = DuplexStream;
        type Stderr = DuplexStream;

        fn take_stdio(&mut self) -> Option<(Self::Stdin, Self::Stdout, Self::Stderr)> {
            Some((self.stdin.take()?, self.stdout.take()?, self.stderr.take()?))
        }

        async fn wait(&mut self) -> std::io::Result<Option<i32>> {
            loop {
                if let Some(code) = *self.ctrl.inner.exit.lock().await {
                    return Ok(Some(code));
                }
                // A killed process winds down with no numeric code (the
                // shell would report it as signal termination). Model
                // that as `Ok(None)` so the bridge maps it to exit 1.
                if self.ctrl.inner.kill_requested.load(Ordering::SeqCst) {
                    return Ok(*self.ctrl.inner.exit_on_kill.lock().await);
                }
                self.ctrl.inner.notify.notified().await;
            }
        }

        fn start_kill(&mut self) -> std::io::Result<()> {
            self.ctrl.inner.kill_requested.store(true, Ordering::SeqCst);
            self.ctrl.inner.notify.notify_one();
            Ok(())
        }
    }
}

#[cfg(test)]
#[expect(
    clippy::disallowed_methods,
    reason = "upstream's tests spawn plain tokio tasks; the traced-spawn rule is for request handling"
)]
mod tests;

/// The exec channel's spans (OTel TEL-021, TEL-022, TEL-043): the client's
/// `TRACEPARENT` reaches the `exec` and `git_*` spans, and the session
/// lookup those channels make runs inside them. Export is off here, so the
/// ids are the ones `adopt_trace` records for the file log; with export on
/// they are the exported ids (the same code path, see `adopt_trace`).
#[cfg(test)]
mod trace_tests {
    use crate::test_harness::{ExecRejected, SpanLog, TestServer};
    use tracing_subscriber::layer::SubscriberExt as _;

    const TRACE: &str = "0af7651916cd43dd8448eb211c80319c";
    const PARENT: &str = "b7ad6b7169203331";
    /// A session id no fresh server knows.
    const UNKNOWN: &str = "6f1c1f9e-5a1b-4c2d-8e3f-000000000001";

    fn traceparent() -> String {
        format!("00-{TRACE}-{PARENT}-01")
    }

    /// `command` on `argv`'s channel of a fresh server, with the client's
    /// `TRACEPARENT` and `MINIMAL_SESSION_ID` naming no session: the request
    /// is refused after the lookup. Returns what the spans looked like.
    async fn exec_unknown_session(command: &str) -> SpanLog {
        let log = SpanLog::default();
        let _g = tracing::subscriber::set_default(tracing_subscriber::registry().with(log.clone()));
        let server = TestServer::new().await;
        let mut client = server.connect().await;
        let session = UNKNOWN.to_owned();
        let tp = traceparent();
        let env = [
            (crate::MINIMAL_SESSION_ID_ENV, session.as_str()),
            (minimald_rpc::trace::TRACEPARENT_ENV, tp.as_str()),
        ];
        let outcome = client.exec(&env, false, command, b"").await;
        assert_eq!(outcome.err(), Some(ExecRejected), "an unknown session");
        log
    }

    /// `verb min://<session>` on a channel of a fresh server's configured
    /// session, with the client's `TRACEPARENT`: the lookup succeeds and the
    /// pack task runs (to whatever end; its outcome is not the point).
    /// Returns what the spans looked like.
    async fn exec_known_session(verb: &str) -> SpanLog {
        let log = SpanLog::default();
        let _g = tracing::subscriber::set_default(tracing_subscriber::registry().with(log.clone()));
        let server = TestServer::new().await;
        let mut client = server.connect().await;
        let session =
            crate::test_harness::create_configured_session(&mut client, "git-trace", "/tmp")
                .await
                .to_string();
        let tp = traceparent();
        let env = [
            (crate::MINIMAL_SESSION_ID_ENV, session.as_str()),
            (minimald_rpc::trace::TRACEPARENT_ENV, tp.as_str()),
        ];
        let command = format!("{verb} min://{session}");
        let run = client.exec(&env, false, &command, b"");
        let outcome = tokio::time::timeout(std::time::Duration::from_secs(60), run)
            .await
            .expect("the pack task ends with its channel");
        assert!(outcome.is_ok(), "a known session is accepted");
        log
    }

    /// The span `name`, in the client's trace, is the parent of the pack
    /// task's `GetPaths` session message: the task runs in it.
    fn assert_task_in(log: &SpanLog, name: &str) {
        let span = log.one(name, "trace_id", TRACE);
        let paths: Vec<_> = log
            .find("session.message", "kind", "GetPaths")
            .into_iter()
            .filter(|m| m.field("trace_id") == Some(TRACE))
            .collect();
        assert_eq!(
            paths.len(),
            1,
            "one GetPaths in the client's trace: {paths:#?}"
        );
        assert_eq!(
            paths[0].field("parent_span_id"),
            span.field("span_id"),
            "the pack task runs in {name}: {paths:?}"
        );
    }

    /// The span `name` is the client's span's child, and the manager's
    /// `GetSession` message (the session lookup) is that span's child, all
    /// in the client's trace.
    fn assert_lookup_in(log: &SpanLog, name: &str) -> crate::test_harness::LoggedSpan {
        let span = log.one(name, "trace_id", TRACE);
        assert_eq!(span.field("parent_span_id"), Some(PARENT), "{span:?}");
        let lookup = log.one("sessions.manager.message", "kind", "GetSession");
        assert_eq!(lookup.field("trace_id"), Some(TRACE), "{lookup:?}");
        assert_eq!(
            lookup.field("parent_span_id"),
            span.field("span_id"),
            "the lookup is a child of {name}: {lookup:?}"
        );
        span
    }

    /// TEL-021, TEL-022: an exec adopts the client's `TRACEPARENT`,
    /// and its session lookup is a child of the exec span. TEL-043: the command
    /// line on the span is scrubbed of secrets.
    #[tokio::test]
    async fn an_exec_session_lookup_runs_in_the_exec_span() {
        let log =
            exec_unknown_session("curl -H 'Authorization: Bearer abc123def456' https://x/").await;
        let exec = assert_lookup_in(&log, "exec");
        let command = exec.field("command").unwrap_or_default();
        assert!(!command.contains("abc123def456"), "{command}");
        assert!(
            command.contains("Authorization: Bearer <redacted"),
            "{command}"
        );
    }

    /// An exec whose client opted out of telemetry
    /// (`MINIMAL_OTEL=off` on the channel, no `TRACEPARENT`) leaves no
    /// span in the daemon's export: a tracer under the daemon's subscriber
    /// sees nothing of it or of what ran in it, while the same exec from a
    /// client that did not opt out exports its `exec` span. The file log
    /// still has the span, marked `telemetry=opt-out`, with unsampled ids
    /// its session lookup shares, and no command line.
    ///
    /// The lookup's own `sessions.manager.message` span is a root that
    /// adopts the request's ids through `mlog::otel::align`, which asks the
    /// process-wide tracer and so cannot be driven by this test's; the
    /// flags-00 ids it adopts are the mechanism TEL-024 proves.
    #[tokio::test]
    async fn an_opted_out_request_leaves_no_daemon_span() {
        use opentelemetry::trace::TracerProvider as _;
        use opentelemetry_sdk::trace::{InMemorySpanExporter, SdkTracerProvider};

        let exporter = InMemorySpanExporter::default();
        let provider = SdkTracerProvider::builder()
            .with_simple_exporter(exporter.clone())
            .build();
        let log = SpanLog::default();
        let _g = tracing::subscriber::set_default(
            tracing_subscriber::registry()
                .with(tracing_opentelemetry::layer().with_tracer(provider.tracer("t")))
                .with(log.clone()),
        );
        let exported = || -> Vec<(String, String)> {
            exporter
                .get_finished_spans()
                .unwrap()
                .iter()
                .map(|s| (s.name.to_string(), s.span_context.trace_id().to_string()))
                .collect()
        };
        let server = TestServer::new().await;
        let mut client = server.connect().await;
        let session = UNKNOWN.to_owned();
        let command = "curl -H 'Authorization: Bearer abc123def456' https://x/";

        let off = [
            (crate::MINIMAL_SESSION_ID_ENV, session.as_str()),
            (minimald_rpc::trace::OTEL_ENV, minimald_rpc::trace::OTEL_OFF),
        ];
        let outcome = client.exec(&off, false, command, b"").await;
        assert_eq!(outcome.err(), Some(ExecRejected), "an unknown session");
        let exec = log.one("exec", "telemetry", super::OPT_OUT);
        assert_eq!(exec.field("command"), None, "no command line: {exec:?}");
        assert_eq!(exec.field("parent_span_id"), None, "{exec:?}");
        let trace_id = exec
            .field("trace_id")
            .expect("ids for the file log")
            .to_owned();
        let lookup = log.one("sessions.manager.message", "kind", "GetSession");
        assert_eq!(
            lookup.field("trace_id"),
            Some(trace_id.as_str()),
            "the lookup joins the request in the file log: {lookup:?}"
        );
        let sent = exporter
            .get_finished_spans()
            .unwrap()
            .iter()
            .filter(|s| s.name == "exec" || s.span_context.trace_id().to_string() == trace_id)
            .count();
        assert_eq!(
            sent,
            0,
            "nothing of the request was exported: {:?}",
            exported()
        );

        let tp = traceparent();
        let on = [
            (crate::MINIMAL_SESSION_ID_ENV, session.as_str()),
            (minimald_rpc::trace::TRACEPARENT_ENV, tp.as_str()),
        ];
        let outcome = client.exec(&on, false, command, b"").await;
        assert_eq!(outcome.err(), Some(ExecRejected), "an unknown session");
        assert!(
            exported().iter().any(|(name, _)| name == "exec"),
            "a client that did not opt out is exported: {:?}",
            exported()
        );
        assert!(
            log.one("exec", "trace_id", TRACE)
                .field("command")
                .is_some_and(|c| c.contains("<redacted")),
            "and its span carries the scrubbed command"
        );
    }

    /// TEL-022: a push's session lookup runs in the
    /// `git_receive` span, in the client's trace.
    #[tokio::test]
    async fn a_git_receive_lookup_runs_in_its_span() {
        let log = exec_unknown_session(&format!("git-receive-pack min://{UNKNOWN}")).await;
        assert_lookup_in(&log, "git_receive");
    }

    /// TEL-022: a fetch's session lookup runs in the
    /// `git_upload` span, in the client's trace.
    #[tokio::test]
    async fn a_git_upload_lookup_runs_in_its_span() {
        let log = exec_unknown_session(&format!("git-upload-pack min://{UNKNOWN}")).await;
        assert_lookup_in(&log, "git_upload");
    }

    /// TEL-022: a push's receive-pack task runs in `git_receive`,
    /// so its session messages join the client's trace instead of rooting
    /// their own.
    #[tokio::test]
    async fn a_git_receive_task_runs_in_its_span() {
        let log = exec_known_session("git-receive-pack").await;
        assert_task_in(&log, "git_receive");
    }

    /// TEL-022: a fetch's upload-pack task runs in `git_upload`
    /// (here it refuses a session with no repository, after `GetPaths`).
    #[tokio::test]
    async fn a_git_upload_task_runs_in_its_span() {
        let log = exec_known_session("git-upload-pack").await;
        assert_task_in(&log, "git_upload");
    }

    /// A push or a fetch from a client that opted out
    /// (`MINIMAL_OTEL=off` on the channel) marks its git span
    /// `telemetry=opt-out`, with ids for the file log and no parent. This
    /// runs `adopt_opt_out` on both git spans, so its debug assertion that
    /// the span declares `telemetry` fails here if either span loses it.
    #[tokio::test]
    async fn an_opted_out_git_span_is_marked_opt_out() {
        for (verb, name) in [
            ("git-receive-pack", "git_receive"),
            ("git-upload-pack", "git_upload"),
        ] {
            let log = SpanLog::default();
            let _g =
                tracing::subscriber::set_default(tracing_subscriber::registry().with(log.clone()));
            let server = TestServer::new().await;
            let mut client = server.connect().await;
            let env = [
                (crate::MINIMAL_SESSION_ID_ENV, UNKNOWN),
                (minimald_rpc::trace::OTEL_ENV, minimald_rpc::trace::OTEL_OFF),
            ];
            let outcome = client
                .exec(&env, false, &format!("{verb} min://{UNKNOWN}"), b"")
                .await;
            assert_eq!(
                outcome.err(),
                Some(ExecRejected),
                "{verb}: an unknown session"
            );
            let span = log.one(name, "telemetry", super::OPT_OUT);
            assert_eq!(span.field("parent_span_id"), None, "{span:?}");
            assert!(span.field("trace_id").is_some(), "file-log ids: {span:?}");
        }
    }
}
