//! The exec forms the daemon runs against a session: a command in the
//! session sandbox, `min://package/build` and `min://check`.

use super::*;

/// Runs `argv` inside the session's sandbox, streamed over the SSH channel.
///
/// The fallback for every exec request the daemon does not service itself. It
/// needs the session's sandbox up, which [`BoxExec`] arranges — launching a
/// host for an idle session if there isn't one.
// Left positional: a single call site that immediately packs the arguments into
// an `ExecTask`, so a struct would be single-use ceremony.
#[allow(clippy::too_many_arguments)]
pub(super) async fn run_in_session(
    serv: ServerStateHandle,
    conn: ConnectionHandle,
    session: BoxHandle,
    channel_id: ChannelId,
    channel: Channel<Msg>,
    program: BoxProgram,
    conn_username: String,
    extra_env: BTreeMap<String, String>,
) {
    let exec_task = ExecTask {
        conn,
        serv,
        session,
        channel_id,
        exec: BoxExec {
            program,
            conn_username,
            extra_env,
        },
    };
    exec_task.run(channel).await;
}

/// Ends the box a task run owns, from the daemon's side of the exec's exit
/// (NET-131). The destroy used to be the client's, issued after a normal
/// run; left there, a client killed mid-run would strand its session — the
/// abandoned-launch reap covers only un-finalized sessions and there is no
/// idle stop to catch one. The teardown is the `DestroySession` RPC's own
/// path, so the box ends exactly as a client-issued destroy ends it.
///
/// The one info line this emits on success is what a diagnostic bundle's
/// daemon-log tail reads the end of a run box from: it names the session,
/// the run and the exit code.
pub(super) async fn end_run_box(
    serv: &ServerStateHandle,
    session_id: SessionId,
    task: &str,
    exit_status: u32,
) {
    let mngr = serv.sessions_manager().await;
    // The name for the log line, resolved before the delete for the same
    // reason `serve_destroy_session` resolves it there: once the record is
    // gone there is nothing left to resolve it against.
    let session_name = mngr
        .get_record(BoxKeyPredicate::Id(session_id))
        .await
        .ok()
        .flatten()
        .and_then(|record| record.name);
    match mngr.delete_session(session_id).await {
        Ok(_) => tracing::info!(
            session_id = %session_id,
            session_name = session_name.as_deref().unwrap_or("<anonymous>"),
            task = %task,
            exit = exit_status,
            "run box ended",
        ),
        // Most plausibly the interrupt path's own destroy won the race; the
        // error names what actually blocked the teardown.
        Err(e) => tracing::warn!(
            session_id = %session_id,
            task = %task,
            exit = exit_status,
            error = %e,
            "ending the run's box failed",
        ),
    }
}

/// Streams a `min package build [--verbose] [--rebuild] [pkgs...]` exec over the SSH
/// channel. Kicks off a session side-op build based on an existing session.
pub(super) async fn run_build_exec(
    session: BoxHandle,
    channel_id: ChannelId,
    channel: Channel<Msg>,
    args: String,
) {
    use orchestrator::{BuildLineKind, BuildRenderer};

    let mut verbose = false;
    let mut rebuild = false;
    let mut pkgs: Vec<String> = Vec::new();
    for token in args.split_whitespace() {
        match token {
            "--verbose" => verbose = true,
            "--rebuild" => rebuild = true,
            _ => pkgs.push(token.to_string()),
        }
    }

    // Same channel-half handling as `ExecTask::run`: stdout on the data
    // stream, stderr on SSH extended-data type 1.
    let (_rs, ws) = channel.split();
    let mut w = ws.make_writer();
    let mut e = ws.make_writer_ext(Some(1));

    let exit_status = match session.start_build(rebuild, pkgs).await {
        Ok(mut events) => {
            use crate::box_ops::{BuildOutcome, BuildUpdate};
            let mut renderer = BuildRenderer::new(verbose);
            let mut outcome = None;
            while let Some(update) = events.recv().await {
                let event = match update {
                    BuildUpdate::Event(event) => event,
                    BuildUpdate::Finished(o) => {
                        outcome = Some(o);
                        continue;
                    }
                };
                let Some(line) = renderer.render(event) else {
                    continue;
                };
                let out: &mut (dyn AsyncWrite + Unpin + Send) = match line.kind {
                    BuildLineKind::Stderr => &mut e,
                    BuildLineKind::Status => &mut w,
                };
                if let Err(err) = out.write_all(format!("{}\n", line.text).as_bytes()).await {
                    // No reader on the channel — the client went away. Stop
                    // streaming; the side-op keeps running independently.
                    tracing::warn!(%channel_id, error = %err, "min package build: channel write failed");
                    break;
                }
            }
            // Map the propagated outcome to an exit code, reporting a
            // failure/cancellation on the SSH stderr stream. Only success
            // exits 0.
            match outcome {
                Some(BuildOutcome::Success) => 0,
                Some(BuildOutcome::Failed(msg)) => {
                    let _ = e
                        .write_all(format!("build failed: {msg}\n").as_bytes())
                        .await;
                    1
                }
                Some(BuildOutcome::Cancelled) => {
                    let _ = e.write_all(b"build cancelled\n").await;
                    130
                }
                None => {
                    let _ = e
                        .write_all(b"build ended without reporting an outcome\n")
                        .await;
                    1
                }
            }
        }
        Err(err) => {
            let _ = e
                .write_all(format!("minimald: failed to start build: {err}\n").as_bytes())
                .await;
            1
        }
    };

    let _ = w.flush().await;
    let _ = e.flush().await;
    let _ = ws.eof().await;
    let _ = ws.exit_status(exit_status).await; // otherwise considered -1
    let _ = ws.close().await; // needed to release the remote
}

/// Streams a `min check [--packages] [--profiles] [--stacks] [--fix] [names...]`
/// exec over the SSH channel. Kicks off a session side-op check run based on an
/// existing session.
pub(super) async fn run_check_exec(
    session: BoxHandle,
    channel_id: ChannelId,
    channel: Channel<Msg>,
    args: String,
) {
    use crate::box_ops::{CheckOpts, CheckOutcome, CheckUpdate};

    let (_rs, ws) = channel.split();
    let mut w = ws.make_writer();
    let mut e = ws.make_writer_ext(Some(1));

    // A bad flag is reported here rather than refused at the request layer:
    // a `channel_failure` would only tell the client "rejected", where this
    // path gets the message across and still exits non-zero.
    let opts = match CheckOpts::from_args(&args) {
        Ok(opts) => opts,
        Err(msg) => {
            let _ = e.write_all(format!("minimald: {msg}\n").as_bytes()).await;
            let _ = e.flush().await;
            let _ = ws.eof().await;
            let _ = ws.exit_status(1).await;
            let _ = ws.close().await;
            return;
        }
    };

    let exit_status = match session.start_check(opts).await {
        Ok(mut updates) => {
            let mut outcome = None;
            'drain: while let Some(update) = updates.recv().await {
                if let CheckUpdate::Finished(o) = &update {
                    outcome = Some(o.clone());
                }
                for line in update.render() {
                    if let Err(err) = w.write_all(format!("{line}\n").as_bytes()).await {
                        // No reader on the channel — the client went away. Stop
                        // streaming; the side-op keeps running independently.
                        tracing::warn!(%channel_id, error = %err, "min check: channel write failed");
                        break 'drain;
                    }
                }
            }

            // Only a clean run exits 0; everything else reports on stderr.
            let (status, message) = CheckOutcome::summarize(outcome.as_ref());
            let out: &mut (dyn AsyncWrite + Unpin + Send) = match status {
                0 => &mut w,
                _ => &mut e,
            };
            let _ = out.write_all(format!("{message}\n").as_bytes()).await;
            status
        }
        Err(err) => {
            let _ = e
                .write_all(format!("minimald: failed to start check: {err}\n").as_bytes())
                .await;
            1
        }
    };

    let _ = w.flush().await;
    let _ = e.flush().await;
    let _ = ws.eof().await;
    let _ = ws.exit_status(exit_status).await; // otherwise considered -1
    let _ = ws.close().await; // needed to release the remote
}
