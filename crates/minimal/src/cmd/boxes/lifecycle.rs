//! `min session destroy`, `stop` and `rename`: the box lifecycle helpers.
//! `min box stop` (BOX-013, BCLI-059), `min box rm` (BOX-019, BCLI-060,
//! BCLI-004), `min box rename` (BOX-010, BCLI-058) and `min box prune`
//! (BOX-021, BCLI-061, BCLI-005) live here too.

use super::*;

/// What the daemon's at-risk report means for the destroy gate.
///
/// The three-way split is deliberate: proven-clean destroys without a word,
/// proven-dirty gates with the listing, and unknowable gates without one —
/// an unreadable tree (stopped session, RPC failure) cannot prove dirt, but
/// it cannot prove cleanliness either, so the gate stays conservative.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum AtRiskState {
    /// Proven clean: everything committed and pushed, or nothing changed
    /// since activation. Destroy proceeds without a prompt.
    Clean,
    /// At-risk work, with the rendered listing lines to print above the
    /// confirm.
    Dirty(Vec<String>),
    /// The state could not be determined: gate, but without a listing.
    Unknowable,
}

/// Classifies the daemon's [`minimald_rpc::SessionDeltaResponse`] (or its
/// absence, on RPC failure/timeout) into the destroy gate's three-way
/// state, rendering the listing lines for the dirty arm.
pub(crate) fn assess_at_risk(resp: Option<minimald_rpc::SessionDeltaResponse>) -> AtRiskState {
    use minimald_rpc::SessionDeltaResponse as R;
    /// Cap on listing rows, matching the shell-exit prompt's.
    const ROWS_SHOWN: usize = 10;
    fn push_capped(rows: &[String], out: &mut Vec<String>) {
        for row in rows.iter().take(ROWS_SHOWN) {
            out.push(format!("  {row}"));
        }
        if rows.len() > ROWS_SHOWN {
            out.push(format!("  ... and {} more", rows.len() - ROWS_SHOWN));
        }
    }
    match resp {
        None | Some(R::Unavailable) => AtRiskState::Unknowable,
        Some(R::Vcs {
            uncommitted,
            unpushed_commits,
        }) => {
            if uncommitted.is_empty() && unpushed_commits == 0 {
                return AtRiskState::Clean;
            }
            let mut lines = Vec::new();
            if !uncommitted.is_empty() {
                let n = uncommitted.len();
                let s = if n == 1 { "" } else { "s" };
                lines.push(format!("{n} file{s} with uncommitted changes:"));
                push_capped(&uncommitted, &mut lines);
            }
            if unpushed_commits > 0 {
                let s = if unpushed_commits == 1 { "" } else { "s" };
                lines.push(format!(
                    "{unpushed_commits} commit{s} not pushed to any remote"
                ));
            }
            AtRiskState::Dirty(lines)
        }
        Some(R::ChangedSinceActivation { rows }) => {
            if rows.is_empty() {
                return AtRiskState::Clean;
            }
            let n = rows.len();
            // Honest wording for the non-VCS fallback: the activation
            // baseline cannot tell committed work from unsaved work.
            let (noun, verb) = if n == 1 {
                ("file", "differs")
            } else {
                ("files", "differ")
            };
            let mut lines = vec![format!(
                "{n} {noun} {verb} from activation (may include committed work):"
            )];
            push_capped(&rows, &mut lines);
            AtRiskState::Dirty(lines)
        }
    }
}

/// How a single-session destroy proceeds past its confirmation gate.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum DestroyGate {
    /// Destroy without prompting: `--force`, or the session is proven
    /// clean.
    Proceed,
    /// Prompt interactively (default No) before destroying.
    Confirm,
}

/// Decides whether a single-session destroy proceeds promptless, may
/// prompt, or must refuse — one match over (force, at-risk state,
/// interactivity).
pub(crate) fn destroy_gate(
    force: bool,
    at_risk: &AtRiskState,
    no_input: bool,
    stdin_is_terminal: bool,
) -> Result<DestroyGate, anyhow::Error> {
    let interactive = !no_input && stdin_is_terminal;
    match (force, at_risk, interactive) {
        // --force bypasses the gate; a proven-clean session has nothing to
        // lose, so no friction either — including headless.
        (true, _, _) | (false, AtRiskState::Clean, _) => Ok(DestroyGate::Proceed),
        // At-risk (or unknowable) work with a human present: ask.
        (false, _, true) => Ok(DestroyGate::Confirm),
        // The `--all` headless precedent: EOF must never read as consent.
        (false, _, false) => {
            bail!("refusing to destroy the session without confirmation; pass --force")
        }
    }
}

/// Best-effort fetch of the session's at-risk report for the destroy
/// confirm. Any failure — RPC error, timeout, a daemon predating the RPC —
/// reads as `None` (unknowable), and the confirm renders without a listing.
pub(crate) async fn box_delta(
    client: &mut client::Client,
    id: boxes::SessionId,
) -> Option<minimald_rpc::SessionDeltaResponse> {
    /// Client-side ceiling on the fetch. The daemon bounds each of its
    /// computations at 5 s; this sits just above so a slow-but-healthy
    /// answer still lands while a wedged daemon cannot stall the confirm.
    const BOX_DELTA_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(6);
    use minimald_rpc::{SessionDelta, SessionDeltaRequest};
    tokio::time::timeout(
        BOX_DELTA_TIMEOUT,
        client.oneshot_rpc::<SessionDelta>(SessionDeltaRequest { id }),
    )
    .await
    .ok()?
    .ok()
}

pub(crate) async fn destroy_all_boxes(
    global: &GlobalArgs,
    client: &mut client::Client,
    force: bool,
) -> Result<(), anyhow::Error> {
    use minimald_rpc::ListSessions;

    let sessions = client
        .oneshot_rpc::<ListSessions>(())
        .await
        .context("ListSessions RPC failed")?
        .sessions;

    if sessions.is_empty() {
        println!("No active sessions.");
        return Ok(());
    }

    if !force {
        if !std::io::stdin().is_terminal() {
            bail!("refusing to destroy all sessions without confirmation; pass --force")
        }
        if !confirm(&format!("Destroy all {} sessions?", sessions.len()), false)? {
            println!("Aborted.");
            return Ok(());
        }
    }

    let session_count = sessions.len();
    let mut failures = 0;
    for session in sessions {
        // The record carries the pair the box's registration handed back
        // (T66), and the box id beside it, which the destroy-side withdrawal
        // presents; a session that registered no box holds none, and the
        // withdrawal stays silent for it. A record the daemon cannot answer
        // destroys the session all the same — nothing is left on this path
        // to withdraw the row by.
        let record = get_session_record(client, &session.id.to_string())
            .await
            .ok()
            .and_then(|resp| resp.record);
        let box_addresses = record.as_ref().and_then(|record| record.box_addresses);
        let box_id = record.as_ref().and_then(|record| record.box_id);
        if let Err(error) = destroy_box(
            client,
            global,
            session.id,
            session.name.as_deref(),
            box_addresses,
            box_id,
            force,
        )
        .await
        {
            failures += 1;
            eprintln!(
                "Failed to destroy session {} ({}): {error:#}",
                session.id,
                session.name.as_deref().unwrap_or("-")
            );
        }
    }

    if failures > 0 {
        bail!("failed to destroy {failures} of {session_count} sessions")
    }

    Ok(())
}

pub(crate) async fn destroy_box(
    client: &mut client::Client,
    global: &GlobalArgs,
    id: boxes::SessionId,
    name: Option<&str>,
    box_addresses: Option<boxes::BoxAddresses>,
    box_id: Option<boxes::BoxId>,
    force: bool,
) -> Result<(), anyhow::Error> {
    use minimald_rpc::{DestroySession, DestroySessionRequest};

    let resp = client
        .oneshot_rpc::<DestroySession>(DestroySessionRequest {
            id,
            only_if_unfinalized: false,
        })
        .await
        .context("DestroySession RPC failed")?;

    match resp {
        minimald_rpc::Errorable::Ok(resp) => {
            println!("Destroyed session {} ({})", id, name.unwrap_or("-"));
            // A failed `on_destroy` hook does not stop the destroy, so it is a
            // warning rather than an error: the session is gone either way.
            for failure in &resp.hook_failures {
                let (head, output) = failure.split_once('\n').unwrap_or((failure, ""));
                eprintln!("warning: on_destroy hook {head}; the session was destroyed anyway");
                if !output.is_empty() {
                    eprintln!("{output}");
                }
            }
            // The session is gone; the row its activation bought outlives it on
            // the VM host daemon, and its creator withdraws it here (T66) —
            // presenting the pair the registration handed back and the box id
            // beside it. The id is what proves a session renamed since its
            // registration: the host keeps the row under the name it was
            // registered by (#1116). The id goes only with a pair: a box with
            // no row withdraws nothing here. Best-effort: a withdrawal that
            // cannot be made leaves the row published and warns rather than
            // failing a destroy that already succeeded.
            // A box that registered no row held its name in the zone instead
            // (`host_ip`); the same destroy releases it, best-effort the same
            // way.
            let control_sock =
                vm_host_control_sock(daemon_host_kind(global), global.minimal_dir.as_deref());
            let row_id = box_addresses.and(box_id);
            withdraw_box_row(control_sock.clone(), name, box_addresses, row_id).await;
            release_held_box_name(control_sock, id, name, box_addresses).await;
        }
        minimald_rpc::Errorable::Err { error } => {
            // Two concurrent destroys race inside the daemon, and the loser
            // is told the session is already gone (UNKNOWN_SESSION_ID_LEAD).
            // Under `--force` that is the goal state, so it is reported as
            // success. Without it, the destroy fails naming the session
            // instead of forwarding the daemon's text. Any other error is
            // forwarded unchanged.
            if error.starts_with(minimald_rpc::UNKNOWN_SESSION_ID_LEAD) {
                let label = match name {
                    Some(name) => name.to_string(),
                    None => id.to_string(),
                };
                if force {
                    println!("Session {label} is already destroyed");
                    return Ok(());
                }
                bail!("session {label} is already destroyed")
            }
            bail!("the daemon reported an error destroying the session: {error}")
        }
    }

    Ok(())
}

/// Stop a VM whose guest cannot be asked to shut down: the in-guest daemon
/// did not answer, so the host stops the VMM itself. This is `minvmd stop`'s
/// own path — best-effort guest Shutdown over the bridge socket (5 s connect
/// deadline, so a wedged guest cannot stall this recovery), then SIGTERM to
/// the VMM, SIGKILL after the 5 s grace, then `Stopped` — run against the
/// host dir the CLI resolved for *this* VM, then waited on until minvmd
/// has released the VM's alive lock.
///
/// The lifecycle file cannot be that wait: the stop writes `Stopped` itself,
/// before the supervisor has reaped the VMM and exited, and a `min start` in
/// that window finds the alive lock still held and refuses to boot.
///
/// Worst case, after the CLI's own attempt on the guest has given up: the
/// 5 s grace plus the [`HOST_STOP_RELEASE_WAIT`] when the guest is not asked
/// again, about 25 s; and when it is asked, the 5 s connect deadline on top,
/// about 30 s — or, for a guest that completes the handshake and then hangs,
/// the 120 s Shutdown deadline on top of that, about 150 s.
///
/// The CLI's own attempt comes first. A guest that accepts the connection and
/// then never acknowledges holds `min stop --force` for the 120 s drain
/// budget, then the 20 s wait for the VM to stop on its own, then the 25 s
/// above: about 165 s from start to finish.
///
/// Only reached on a minvmd backend with `--force`, once the guest is proven
/// unreachable; a native minimald is not a VM and keeps its own error.
/// `quiesce_guest` is false when the CLI's own Shutdown RPC has just failed,
/// so the guest is not asked a second time.
///
/// A VM that is still booting has no VMM pid the host could signal, and its
/// supervisor would write `Running` over a `Stopped` this wrote, so that case
/// is refused rather than reported as a host-side stop.
pub(crate) async fn stop_wedged_vm_from_host(
    minimal_dir: Option<PathBuf>,
    quiesce_guest: bool,
) -> Result<(), anyhow::Error> {
    let host_dir = client::resolve_host_dir(minimal_dir.as_deref(), true)
        .context("resolving the VM's provider dir for a host-side stop")?;
    let outcome = stop_vm_from_host_at(host_dir, quiesce_guest, stop_command()).await?;

    // stderr, so it survives the `>/dev/null` every scripted caller wraps
    // `stop` in. The loss caveat is only true of a guest that was killed: one
    // that acknowledged Shutdown drained its sessions and quiesced its volume
    // first.
    use minvmd::cmd::stop::HostStop;
    match outcome {
        HostStop::NothingSignalled => println!("Daemon is not running."),
        HostStop::GuestAcknowledged => {
            eprintln!("the VM was stopped from the host after its guest shut down cleanly");
        }
        HostStop::GuestUnacknowledged => eprintln!("{UNACKNOWLEDGED_STOP_CAVEAT}"),
    }
    Ok(())
}

/// Stop the VM whose state directory is `host_dir` from this machine, as
/// `minvmd stop` does, then wait until minvmd releases the VM's alive lock.
/// `retry` is the command a VM that is still booting is told to run again.
/// [`stop_wedged_vm_from_host`] and `min host stop --force` share it.
pub(crate) async fn stop_vm_from_host_at(
    host_dir: PathBuf,
    quiesce_guest: bool,
    retry: String,
) -> Result<minvmd::cmd::stop::HostStop, anyhow::Error> {
    // The stop sleep-polls the VMM's exit and the wait polls the alive lock,
    // so both go on the blocking pool rather than stalling an async worker
    // (rust-coding-standards: no blocking in an async context).
    tokio::task::spawn_blocking(move || {
        let state_dir = minvmd::state::StateDir::new(host_dir.clone())
            .context("opening the VM's state dir for a host-side stop")?;
        let state = state_dir
            .effective_state()
            .context("reading the VM's state for a host-side stop")?;
        // Checked first: the VM going down on its own (or a dead supervisor's
        // stale state being repaired by the read above) since the caller's
        // liveness probe is the goal state, not a boot to wait out.
        if !state.lifecycle.is_active() {
            return Ok(minvmd::cmd::stop::HostStop::NothingSignalled);
        }
        if state.lifecycle == minvmd::lifecycle::Lifecycle::Starting || state.vmm_pid.is_none() {
            anyhow::bail!("the VM is still booting; retry `{retry}` once it is up");
        }
        let outcome = minvmd::cmd::stop::stop_at(host_dir, quiesce_guest)
            .context("stopping the VM from the host")?;
        wait_for_alive_lock_released(&state_dir, HOST_STOP_RELEASE_WAIT)?;
        Ok(outcome)
    })
    .await
    .context("the host-side stop of the VM panicked")?
}

/// What `min stop --force` says after killing a VM whose guest did not
/// acknowledge Shutdown. The volume's journal keeps its filesystem metadata
/// consistent across the kill; it does not keep the data.
const UNACKNOWLEDGED_STOP_CAVEAT: &str = "The VM did not respond to shutdown, so it was killed from this machine. \
     Running sessions were killed without their shutdown steps, and recently written files \
     may be empty or cut short. The VM disk's filesystem itself stays consistent.";

/// What `min host stop --force` says after killing a VM whose guest did not
/// acknowledge Shutdown. The same caveat as [`UNACKNOWLEDGED_STOP_CAVEAT`],
/// for a command that names boxes, not sessions.
const HOST_UNACKNOWLEDGED_STOP_CAVEAT: &str = "The VM did not respond to shutdown, so it was killed from this machine. \
     Running boxes were killed without their stop steps, and recently written files \
     may be empty or cut short. The VM disk's filesystem itself stays consistent.";

/// How long a host-side stop waits for minvmd to release the VM's alive lock
/// once the VMM has been signalled: the supervisor has to reap the VMM child
/// and exit. The same ceiling an acknowledged shutdown is given to reach
/// `Stopped`.
const HOST_STOP_RELEASE_WAIT: std::time::Duration = std::time::Duration::from_secs(20);

/// Wait until no minvmd (supervisor or VMM child) holds `state_dir`'s alive
/// lock, so the next `min start` can take it.
pub(crate) fn wait_for_alive_lock_released(
    state_dir: &minvmd::state::StateDir,
    timeout: std::time::Duration,
) -> Result<(), anyhow::Error> {
    let deadline = std::time::Instant::now() + timeout;
    while state_dir
        .daemon_alive()
        .context("probing the VM's alive lock after a host-side stop")?
    {
        if std::time::Instant::now() >= deadline {
            bail!(
                "the VM host daemon (minvmd) is still running {timeout:?} after the stop; \
                 the VM cannot be started again until that process exits"
            );
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    Ok(())
}

/// `min stop` for the VM this command drives: a bare `min stop` targets the
/// default VM, so a named one must carry its `--vm` (NET-052).
fn stop_command() -> String {
    match client::vm_name() {
        paths::DEFAULT_VM_NAME => "min stop".to_owned(),
        vm => format!("min --vm {vm} stop"),
    }
}

/// The failure `min stop` ends with when the VM's guest does not answer and
/// `--force` was not given: `cause` under the recovery, typed so the run exits
/// with the reserved host-unreachable code (7) rather than the unspecified 1.
///
/// A VM that is still booting is not answering either, but `--force` refuses
/// it, so the hint names the retry instead of a recovery that would not work.
pub(crate) fn wedged_vm_unreachable(
    cause: anyhow::Error,
    minimal_dir: Option<&std::path::Path>,
) -> anyhow::Error {
    // Same cheap state-file read as `cmd_stop`'s liveness probe; a state that
    // cannot be read leaves the `--force` hint.
    let booting = client::resolve_host_dir(minimal_dir, true)
        .ok()
        .and_then(|dir| minvmd::state::StateDir::new(dir).ok())
        .and_then(|state_dir| state_dir.read_state().ok())
        .is_some_and(|state| state.lifecycle == minvmd::lifecycle::Lifecycle::Starting);
    let hint = if booting {
        format!(
            "the VM is still booting; retry `{}` once it is up",
            stop_command()
        )
    } else {
        format!(
            "the VM is not answering; `{} --force` stops it from the host",
            stop_command()
        )
    };
    client::box_registration::HostUnreachable::over(cause, hint)
}

/// Whether the daemon can be *observed* to have stopped — the question the
/// failed-RPC arm of [`stop_outcome`] turns on.
///
/// The shutdown wait, then the liveness probe this command opened with. On a VM
/// backend the wait IS the observation — it polls the lifecycle state — but a
/// native minimald has no lifecycle file and its wait returns at once, saying
/// nothing, so only the probe can answer for that backend. Anything we cannot
/// read is not a confirmed stop.
///
/// Which makes the recovery a VM-backend one in practice: the native probe fires
/// once, immediately, and minimald keeps its listener bound through the 5s drain
/// grace it takes after its accept loop exits (minimald's `SHUTDOWN_GRACE`), so
/// a connect in that window still succeeds and reports "running". Native
/// therefore keeps today's fail-on-RPC-error behaviour — which is right for it:
/// a native daemon is not pid-1 and does not take the transport down with it, so
/// the lost reply this recovers from is not a failure mode it has.
pub(crate) async fn daemon_confirmed_stopped(
    use_minvmd: bool,
    minimal_dir: Option<PathBuf>,
) -> bool {
    // Both calls can sleep-poll, so they go on the blocking pool rather than
    // stalling an async worker (rust-coding-standards: no blocking in an async
    // context). A panicked probe observed nothing, which is not a confirmation.
    tokio::task::spawn_blocking(move || {
        autospawn::wait_for_daemon_stopped(use_minvmd, minimal_dir.as_deref()).is_ok()
            && !autospawn::is_daemon_running(use_minvmd, minimal_dir.as_deref()).unwrap_or(true)
    })
    .await
    .unwrap_or(false)
}

/// Decide what `min stop` reports, given how the `Shutdown` RPC ended, the wait
/// an accepted shutdown runs out, and — only when the RPC itself failed —
/// whether the daemon can nevertheless be confirmed down.
///
/// What `stop` promises is observable: the daemon is down. On a VM target the
/// daemon IS the guest's pid-1, so an accepted shutdown takes the SSH transport
/// down with it — as a *consequence of succeeding* — and the reply can be lost
/// before the client decodes it. Gating on the transport would report failure
/// for a stop that did exactly what was asked, so a failed RPC over a daemon
/// that did stop is a success. A daemon still there afterwards is a real
/// failure, and the RPC error — the one that explains what went wrong — is what
/// the user sees.
///
/// Only that failure arm probes. An accepted shutdown is judged by its wait
/// alone: the daemon acknowledges before it has finished going down, so asking
/// again there would race its own teardown and fail stops that worked.
///
/// `SessionsLive` is not a lost reply but an answer: the daemon refused, and is
/// going nowhere, so there is nothing to observe.
pub(crate) async fn stop_outcome<W, C>(
    resp: Result<minimald_rpc::ShutdownResponse, anyhow::Error>,
    wait_for_stopped: W,
    confirm_stopped: C,
) -> Result<(), anyhow::Error>
where
    W: AsyncFnOnce() -> Result<(), anyhow::Error>,
    C: AsyncFnOnce() -> bool,
{
    use minimald_rpc::ShutdownResponse;
    match resp {
        Ok(ShutdownResponse::ShuttingDown) => {
            println!("Daemon is shutting down.");
            wait_for_stopped().await
        }
        Ok(ShutdownResponse::SessionsLive) => {
            bail!("daemon has active sessions; pass --force to shut down anyway")
        }
        Err(rpc_err) => {
            if confirm_stopped().await {
                // Say what was suppressed. Exiting 0 over a failed RPC is only
                // sound because the daemon is observably down, and a silent
                // recovery would leave nothing — in a terminal or in a soak
                // log — to check that reading against. stderr, so it survives
                // the `>/dev/null` every scripted caller wraps `stop` in.
                eprintln!("warning: the shutdown RPC failed, but the daemon stopped: {rpc_err:#}");
                println!("Daemon is shutting down.");
                Ok(())
            } else {
                Err(rpc_err)
            }
        }
    }
}

/// The line `min task run` prints when its task returns (T43). The task
/// box ended with its task and keeps its record, so the line names the box
/// and the command that removes it.
pub(crate) fn kept_box_line(name: &str) -> String {
    format!("Kept box {name}. Remove it with min box rm {name}.")
}

/// Stop the daemon of the host named `host`, over `client`, for
/// `min host stop` (BCLI-049). `vm_dir` is the VM's state directory when
/// the host is a VM host, and `None` for a native daemon.
///
/// Without `force`, the daemon gets the clean `Shutdown` that `min stop`
/// sends, with the same drain budget on a VM. The call then waits until
/// the VM is down. With `force`, the `Shutdown` skips the busy-box check and
/// the drain budget. A VM is then stopped from this machine without a wait
/// for its own shutdown. A guest that acknowledged has already drained its
/// boxes and quiesced its volume, so it is not asked again.
pub(crate) async fn shut_down_host_daemon(
    mut client: client::Client,
    host: &str,
    vm_dir: Option<PathBuf>,
    force: bool,
) -> Result<(), anyhow::Error> {
    use minimald_rpc::{Shutdown, ShutdownRequest, ShutdownResponse};
    let force_command = format!("min host stop {host} --force");
    let drain_budget = if vm_dir.is_some() && !force {
        minvmd::cmd::stop::GUEST_SHUTDOWN_TIMEOUT.saturating_sub(client::RPC_TIMEOUT)
    } else {
        std::time::Duration::ZERO
    };
    let resp = client
        .oneshot_rpc_with_hook_budget::<Shutdown>(ShutdownRequest { force }, drain_budget)
        .await
        .context("Shutdown RPC failed");
    // The daemon holds its shutdown open for a drain grace while a client is
    // still attached, and this is that client.
    drop(client);
    tracing::debug!(host, force, answer = ?resp.as_ref().ok(), "host daemon Shutdown answered");
    let busy = || {
        anyhow::anyhow!(
            "the daemon on {host} did not stop, because a box on it is still busy. \
             Run `{force_command}` to stop it anyway."
        )
    };
    let Some(vm_dir) = vm_dir else {
        return match resp? {
            ShutdownResponse::ShuttingDown => Ok(()),
            ShutdownResponse::SessionsLive => Err(busy()),
        };
    };
    if force {
        let acknowledged = matches!(resp, Ok(ShutdownResponse::ShuttingDown));
        if let Err(e) = &resp {
            tracing::debug!(
                host,
                "forced Shutdown failed, stopping the VM from this machine: {e:#}"
            );
        }
        let outcome = stop_vm_from_host_at(vm_dir, false, force_command).await?;
        if !acknowledged && outcome == minvmd::cmd::stop::HostStop::GuestUnacknowledged {
            eprintln!("{HOST_UNACKNOWLEDGED_STOP_CAVEAT}");
        }
        return Ok(());
    }
    let stopped = || async {
        let dir = vm_dir.clone();
        tokio::task::spawn_blocking(move || wait_for_vm_stopped_at(&dir, HOST_STOP_RELEASE_WAIT))
            .await
            .unwrap_or(false)
    };
    match resp {
        Ok(ShutdownResponse::ShuttingDown) => {
            if stopped().await {
                Ok(())
            } else {
                bail!(
                    "the VM of {host} is still shutting down after {}s. \
                     Run `{force_command}` to stop it from this machine.",
                    HOST_STOP_RELEASE_WAIT.as_secs()
                )
            }
        }
        Ok(ShutdownResponse::SessionsLive) => Err(busy()),
        // On a VM the daemon is the guest's pid-1, so a shutdown that worked
        // can take the reply down with it. A VM that is down is the goal.
        // Only a lost reply earns the wait. An error the daemon reported is
        // an answer, and its VM stays up.
        Err(rpc_err) if rpc_unanswered(&rpc_err) && stopped().await => {
            tracing::debug!(
                host,
                "the Shutdown reply was lost, but the VM stopped: {rpc_err:#}"
            );
            Ok(())
        }
        Err(rpc_err) => Err(rpc_err.context(format!(
            "the daemon on {host} did not stop. \
             Run `{force_command}` to stop its VM from this machine."
        ))),
    }
}

/// Whether the VM whose state directory is `dir` is down within `timeout`.
/// A state that cannot be read is no proof that it stopped.
fn wait_for_vm_stopped_at(dir: &std::path::Path, timeout: std::time::Duration) -> bool {
    let Ok(state_dir) = minvmd::state::StateDir::new(dir.to_path_buf()) else {
        return false;
    };
    let deadline = std::time::Instant::now() + timeout;
    loop {
        match state_dir.effective_state() {
            Ok(state) if !state.lifecycle.is_active() => return true,
            Ok(_) => {}
            Err(e) => {
                tracing::debug!(dir = %dir.display(), "VM state not read: {e:#}");
                return false;
            }
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

/// The refusal of `min box rm` for a running box without `--force`
/// (BCLI-004, BOX-019). `target` is the box as the user named it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoxRunningRefusal {
    pub(crate) target: String,
}

impl BoxRunningRefusal {
    /// The exit code `min box rm` ends with on this refusal.
    pub const EXIT_CODE: u8 = 2;

    /// The refusal for the box the user named `target`.
    pub fn new(target: impl Into<String>) -> Self {
        Self {
            target: target.into(),
        }
    }
}

impl std::fmt::Display for BoxRunningRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let target = &self.target;
        write!(
            f,
            "{target} is running. Stop it with min box stop {target}, \
             or remove it now with min box rm {target} --force."
        )
    }
}

impl std::error::Error for BoxRunningRefusal {}

/// The daemon's text when a reap that is not forced finds the box running
/// (`box_manager`'s reap gate). The client checks the state from the
/// listing first, so this answer arrives only when the box started in
/// between.
const DAEMON_RUNNING_REAP: &str = "is running, so it was not removed.";

/// Whether a `ReapBox` error is the daemon's answer that the box is running,
/// which `min box rm` without `--force` maps to [`BoxRunningRefusal`].
fn reap_error_is_running(force: bool, error: &str) -> bool {
    !force && error.contains(DAEMON_RUNNING_REAP)
}

/// The `StopBox` request for `min box stop`: the graceful stop of BOX-013,
/// or its forced stop under `--force`.
pub(crate) fn box_stop_request(id: boxes::SessionId, force: bool) -> minimald_rpc::StopBoxRequest {
    minimald_rpc::StopBoxRequest { id, force }
}

/// The `ReapBox` request for `min box rm`: the reap of BOX-019, or its
/// forced reap under `--force`.
pub(crate) fn box_rm_request(id: boxes::SessionId, force: bool) -> minimald_rpc::ReapBoxRequest {
    minimald_rpc::ReapBoxRequest { id, force }
}

/// The error for a daemon answer to a verb on the box `target` names. A
/// box removed after its address resolved is the not-found refusal.
fn box_rpc_error(target: &str, error: String) -> anyhow::Error {
    if error.starts_with(minimald_rpc::UNKNOWN_SESSION_ID_LEAD) {
        BoxAddressRefusal::NotFound {
            address: target.to_owned(),
        }
        .into()
    } else {
        anyhow::anyhow!("{error}")
    }
}

/// Whether `e`, the error of a oneshot RPC, means the daemon did not
/// answer: the call timed out, or the connection was lost before a reply.
/// A refusal or a failure the daemon reported is an answer, and so is a
/// reply that did not decode, unless the reply was empty.
pub(crate) fn rpc_unanswered(e: &anyhow::Error) -> bool {
    e.chain().any(|cause| {
        if cause.downcast_ref::<russh::Error>().is_some() {
            return true;
        }
        let text = cause.to_string();
        // The client's deadline, and a channel that closed without a byte.
        text.contains(" RPC timed out after ") || text.ends_with("(daemon replied: )")
    })
}

/// `min box stop <box> [--force]`: stops the box and keeps its record.
/// `<box>` is a box address, looked up on every local host.
pub async fn cmd_box_stop(global: &GlobalArgs, args: BoxStopArgs) -> Result<(), anyhow::Error> {
    ensure_daemon(global)?;
    let hosts = crate::cmd::list::local_hosts(global)?;
    let mut out = std::io::stdout().lock();
    let stopped = stop_box_on_hosts(hosts, &mut out, &args.target, args.force).await?;
    // A stopped box is not live, so the VM host daemon retires its
    // `host_ip` egress rules. The row and the name hold stay until the box
    // is removed. An attach admits the rules again. Best-effort: a box of
    // another mode has no rules, and no VM host daemon means nothing to do.
    // The retire goes to the VM that keeps the box, which need not be the
    // selected one.
    let control_sock = box_host_control_sock(&stopped.host);
    retire_stopped_box_with_vm_host(control_sock, stopped.box_id).await;
    Ok(())
}

/// Resolves the address `target` over `hosts` and stops that box on the
/// host that keeps it, forced under `force`. Returns the box and its host.
pub(crate) async fn stop_box_on_hosts(
    hosts: Vec<crate::cmd::list::LocalHost>,
    out: &mut impl std::io::Write,
    target: &str,
    force: bool,
) -> Result<ResolvedBox, anyhow::Error> {
    let resolved = resolve_box_on_hosts(hosts, target, "box stop").await?;
    let mut client = gated_box_host_client(&resolved.host).await?;
    stop_listed_box(&mut client, out, resolved.box_id, target, force).await?;
    Ok(resolved)
}

/// The control socket of the VM host daemon that serves `host`, for the
/// cleanup after a stop or a removal. A native host has none.
pub(crate) fn box_host_control_sock(
    host: &crate::cmd::list::LocalHost,
) -> Option<std::path::PathBuf> {
    if host.provider == crate::cmd::list::LOCAL_MINVMD_PROVIDER {
        control_sock_beside(&host.sock)
    } else {
        None
    }
}

/// Stops the box `id`, which the address `target` resolved to, as BOX-013
/// defines, forced under `force`. Writes one line to `out`. Returns true
/// when this stop stopped the box, and false when the box had already
/// exited.
pub(crate) async fn stop_listed_box(
    client: &mut client::Client,
    out: &mut impl std::io::Write,
    id: boxes::SessionId,
    target: &str,
    force: bool,
) -> Result<bool, anyhow::Error> {
    use minimald_rpc::{Errorable, StopBox};

    crate::output::record_box_id(&id.to_string());
    let stopped = match client
        .oneshot_rpc::<StopBox>(box_stop_request(id, force))
        .await
        .context("StopBox RPC failed")?
    {
        Errorable::Ok(stopped) => stopped,
        Errorable::Err { error } => return Err(box_rpc_error(target, error)),
    };
    write_stop_line(out, target, &stopped)?;
    Ok(!stopped.already_exited)
}

/// The one line `min box stop` prints for the daemon's answer `stopped`.
fn write_stop_line(
    out: &mut impl std::io::Write,
    target: &str,
    stopped: &minimald_rpc::StopBoxResponse,
) -> std::io::Result<()> {
    if stopped.already_exited {
        tracing::info!(r#box = target, "the box exited before the stop");
        writeln!(
            out,
            "{target} exited before the stop, so the stop changed nothing."
        )
    } else {
        writeln!(out, "Stopped {target}.")
    }
}

/// `min box rm <box> [--force]`: removes the box. A running box without
/// `--force` is refused on stderr with exit 2 (BCLI-004): the refusal
/// returns as a [`BoxRunningRefusal`], and the process maps it to its exit
/// code.
pub async fn cmd_box_rm(global: &GlobalArgs, args: BoxRmArgs) -> Result<(), anyhow::Error> {
    ensure_daemon(global)?;
    let hosts = crate::cmd::list::local_hosts(global)?;
    let (host, removed) = rm_box_on_hosts(hosts, &args.target, args.force).await?;
    // The box is gone. Its creator withdraws the row on the VM host
    // daemon, or releases the name the zone held, as `destroy_box` does.
    // Both are best-effort and warn on failure. Both go to the VM that
    // kept the box, which need not be the selected one.
    let control_sock = box_host_control_sock(&host);
    let name = removed.name.as_deref();
    let row_id = removed.box_addresses.and(removed.box_id);
    withdraw_box_row(control_sock.clone(), name, removed.box_addresses, row_id).await;
    release_held_box_name(control_sock, removed.id, name, removed.box_addresses).await;
    // The line goes last, so a closed stdout cannot skip the cleanup above.
    writeln!(std::io::stdout().lock(), "Removed {}.", args.target)?;
    Ok(())
}

/// A box that `rm_listed_box` reaped: what its creator needs to retire
/// the row or the name hold the box leaves on the VM host daemon.
#[derive(Debug)]
pub(crate) struct RemovedBox {
    pub(crate) id: boxes::SessionId,
    pub(crate) name: Option<String>,
    pub(crate) box_addresses: Option<boxes::BoxAddresses>,
    /// The id the box's registration handed back beside the pair, which
    /// the withdrawal presents so a renamed box's row is still its own.
    pub(crate) box_id: Option<boxes::BoxId>,
}

/// Resolves the address `target` over `hosts` and reaps that box on the
/// host that keeps it, as [`rm_listed_box`] does. Returns that host and
/// the box it reaped.
pub(crate) async fn rm_box_on_hosts(
    hosts: Vec<crate::cmd::list::LocalHost>,
    target: &str,
    force: bool,
) -> Result<(crate::cmd::list::LocalHost, RemovedBox), anyhow::Error> {
    let ResolvedBox { host, box_id } = resolve_box_on_hosts(hosts, target, "box rm").await?;
    let mut client = gated_box_host_client(&host).await?;
    let removed = rm_listed_box(&mut client, box_id, target, force).await?;
    Ok((host, removed))
}

/// Reaps the box `id`, which the address `target` resolved to, as BOX-019
/// defines, forced under `force`. Without `force`, a running box is
/// refused with [`BoxRunningRefusal`]. Prints nothing on stdout: the
/// caller prints the line after its cleanup.
pub(crate) async fn rm_listed_box(
    client: &mut client::Client,
    id: boxes::SessionId,
    target: &str,
    force: bool,
) -> Result<RemovedBox, anyhow::Error> {
    use minimald_rpc::{Errorable, ReapBox};

    // The host's listing gives the running check and the box's name.
    let listing = list_box_records(client, None).await?;
    crate::output::record_box_id(&id.to_string());
    let running = listing
        .iter()
        .any(|entry| entry.box_id == id && entry.state == "running");
    let refusal = || anyhow::Error::new(BoxRunningRefusal::new(target));
    if running && !force {
        return Err(refusal());
    }
    // The record carries the pair the box's registration handed back,
    // and the box id beside it, which the withdrawal after the reap
    // presents. A record the daemon cannot answer reaps the box all the
    // same.
    let record = get_session_record(client, &id.to_string())
        .await
        .ok()
        .and_then(|resp| resp.record);
    let box_addresses = record.as_ref().and_then(|record| record.box_addresses);
    let box_id = record.as_ref().and_then(|record| record.box_id);
    let name = listing
        .iter()
        .find(|entry| entry.box_id == id)
        .and_then(|entry| entry.name.clone());
    let reaped = match client
        .oneshot_rpc::<ReapBox>(box_rm_request(id, force))
        .await
        .context("ReapBox RPC failed")?
    {
        Errorable::Ok(reaped) => reaped,
        Errorable::Err { error } if reap_error_is_running(force, &error) => {
            return Err(refusal());
        }
        Errorable::Err { error } => return Err(box_rpc_error(target, error)),
    };
    // A failed `on_destroy` hook does not stop the reap, so it is a
    // warning: the box is gone either way.
    for failure in &reaped.hook_failures {
        let (head, output) = failure.split_once('\n').unwrap_or((failure, ""));
        eprintln!("warning: on_destroy hook {head}. The box was removed anyway.");
        if !output.is_empty() {
            eprintln!("{output}");
        }
    }
    Ok(RemovedBox {
        id,
        name,
        box_addresses,
        box_id,
    })
}

/// The daemon's refusal of a rename (BOX-010): a running box on the host
/// holds the name, the name is reserved, or the name is not a valid box
/// name. The text is the daemon's, and
/// names the holder. `min box rename` ends with exit 2 on it (BCLI-058).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoxRenameRefusal {
    pub(crate) message: String,
}

impl BoxRenameRefusal {
    /// The exit code `min box rename` ends with on this refusal.
    pub const EXIT_CODE: u8 = 2;

    /// The lead of the daemon's text when a running box holds the name, as
    /// `boxes::box_name::RenameRefusal::HeldByRunning` spells it.
    const HELD_LEAD: &'static str = "The running session `";

    /// The lead of the daemon's text when the name is not a valid box name,
    /// as `boxes::store`'s name check spells it.
    const INVALID_LEAD: &'static str = "invalid box name: ";

    /// The refusal a `RenameSession` error carries, or `None` when the
    /// error is any other failure.
    pub(crate) fn from_error(error: &str) -> Option<Self> {
        let reserved = boxes::box_name::RenameRefusal::Reserved.to_string();
        let held = error.starts_with(Self::HELD_LEAD) && error.contains(" holds the name `");
        // BCLI-058: a name the store refuses is a usage error too.
        let invalid = error.starts_with(Self::INVALID_LEAD);
        (held || invalid || error == reserved).then(|| Self {
            message: error.to_owned(),
        })
    }
}

impl std::fmt::Display for BoxRenameRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for BoxRenameRefusal {}

/// `min box rename <box> <name>`: renames the box as BOX-010 defines.
/// `<box>` is a box address, looked up on every local host.
pub async fn cmd_box_rename(global: &GlobalArgs, args: BoxRenameArgs) -> Result<(), anyhow::Error> {
    ensure_daemon(global)?;
    let hosts = crate::cmd::list::local_hosts(global)?;
    let resolved = resolve_box_on_hosts(hosts, &args.target, "box rename").await?;
    let mut client = gated_box_host_client(&resolved.host).await?;
    // The record says how the box holds its name on the VM host (a zone
    // hold or a host row), which then moves to the new name (#1116).
    let record = get_session_record(&mut client, &resolved.box_id.to_string())
        .await
        .ok()
        .and_then(|resp| resp.record);
    let mut out = std::io::stdout().lock();
    rename_listed_box(
        &mut client,
        &mut out,
        resolved.box_id,
        &args.target,
        &args.new_name,
    )
    .await?;
    if let Some(record) = record {
        let control_sock = box_host_control_sock(&resolved.host);
        rename_box_with_vm_host(control_sock, &record, &args.new_name).await;
    }
    Ok(())
}

/// Renames the box `id`, which the address `target` resolved to, to
/// `new_name`, as BOX-010 defines. Writes one line to `out`. The daemon's
/// refusal returns as a [`BoxRenameRefusal`].
pub(crate) async fn rename_listed_box(
    client: &mut client::Client,
    out: &mut impl std::io::Write,
    id: boxes::SessionId,
    target: &str,
    new_name: &str,
) -> Result<(), anyhow::Error> {
    use minimald_rpc::{Errorable, RenameSession, RenameSessionRequest};

    crate::output::record_box_id(&id.to_string());
    let answer = client
        .oneshot_rpc::<RenameSession>(RenameSessionRequest {
            id,
            new_name: new_name.to_owned(),
        })
        .await
        .context("RenameSession RPC failed")?;
    match answer {
        Errorable::Ok(_) => {
            tracing::info!(verb = "box rename", box_id = %id, outcome = "renamed");
            writeln!(out, "Renamed {target} to {new_name}.")?;
            Ok(())
        }
        Errorable::Err { error } => {
            tracing::info!(verb = "box rename", box_id = %id, outcome = "refused", "{error}");
            match BoxRenameRefusal::from_error(&error) {
                Some(refusal) => Err(refusal.into()),
                None => Err(box_rpc_error(target, error)),
            }
        }
    }
}

/// `min box restart <box>`: stops a box whose spec sets
/// `lifetime = "until_stopped"`, if it runs, and starts it again from its
/// stored spec under the same id and name (BCLI-074, BOX-176). A refusal
/// returns as a [`minimald_rpc::RestartRefusal`], and the process exits
/// with the code it carries.
pub async fn cmd_box_restart(
    global: &GlobalArgs,
    args: BoxRestartArgs,
) -> Result<(), anyhow::Error> {
    ensure_daemon(global)?;
    let hosts = crate::cmd::list::local_hosts(global)?;
    let mut out = std::io::stdout().lock();
    restart_box_on_hosts(hosts, &mut out, &args.target).await?;
    Ok(())
}

/// Resolves the address `target` over `hosts` and restarts that box on
/// the host that keeps it, as BOX-176 defines. Returns the box
/// and its host.
pub(crate) async fn restart_box_on_hosts(
    hosts: Vec<crate::cmd::list::LocalHost>,
    out: &mut impl std::io::Write,
    target: &str,
) -> Result<ResolvedBox, anyhow::Error> {
    restart_box_on_hosts_with(hosts, out, target, async |client, request| {
        client
            .oneshot_rpc::<minimald_rpc::RestartBox>(request)
            .await
    })
    .await
}

/// [`restart_box_on_hosts`], with `send` to put the `RestartBox` request
/// to the host that keeps the box.
pub(crate) async fn restart_box_on_hosts_with(
    hosts: Vec<crate::cmd::list::LocalHost>,
    out: &mut impl std::io::Write,
    target: &str,
    send: impl AsyncFnOnce(
        &mut client::Client,
        minimald_rpc::RestartBoxRequest,
    ) -> Result<RestartBoxAnswer, anyhow::Error>,
) -> Result<ResolvedBox, anyhow::Error> {
    let resolved = resolve_box_on_hosts(hosts, target, "box restart").await?;
    let mut client = gated_box_host_client(&resolved.host).await?;
    crate::output::record_box_id(&resolved.box_id.to_string());
    let request = minimald_rpc::RestartBoxRequest {
        id: resolved.box_id,
    };
    let answer = send(&mut client, request)
        .await
        .context("RestartBox RPC failed")?;
    finish_restart(out, resolved.box_id, target, answer)?;
    Ok(resolved)
}

/// The daemon's answer to a `RestartBox` request.
pub(crate) type RestartBoxAnswer = minimald_rpc::Errorable<minimald_rpc::RestartBoxResponse>;

/// The refusal `min box restart` prints when the daemon answers
/// `Lifetime` (BCLI-074): the box's stored spec does not set
/// `lifetime = "until_stopped"`. That includes a box with no stored spec,
/// so the text claims no more than that. It names `min box run`, the hint
/// BCLI-009 chooses by `lifetime`.
pub(crate) fn restart_lifetime_refusal(target: &str) -> minimald_rpc::RestartRefusal {
    minimald_rpc::RestartRefusal {
        kind: minimald_rpc::RestartRefusalKind::Lifetime,
        exit_code: 2,
        message: format!(
            "The spec of {target} does not set lifetime = \"until_stopped\", \
             so min box restart cannot restart it. \
             Run it again with min box run <entry>."
        ),
    }
}

/// Ends a restart of the box `id`, which the address `target` resolved
/// to, on the daemon's `answer` (BOX-176). Writes one line to `out` when
/// the box runs again. A refusal returns as a
/// [`minimald_rpc::RestartRefusal`]: the lifetime refusal with the
/// client's hint, any other refusal as the daemon wrote it.
fn finish_restart(
    out: &mut impl std::io::Write,
    id: boxes::SessionId,
    target: &str,
    answer: RestartBoxAnswer,
) -> Result<(), anyhow::Error> {
    use minimald_rpc::{Errorable, RestartBoxResponse};

    match answer {
        Errorable::Ok(RestartBoxResponse::Restarted { was_running }) => {
            tracing::info!(verb = "box restart", box_id = %id, was_running, outcome = "restarted");
            writeln!(out, "Restarted {target}.")?;
            Ok(())
        }
        Errorable::Ok(RestartBoxResponse::Refused(refusal)) => {
            tracing::info!(
                verb = "box restart",
                box_id = %id,
                outcome = "refused",
                refusal = refusal.kind.name(),
                "{refusal}"
            );
            match refusal.kind {
                minimald_rpc::RestartRefusalKind::Lifetime => {
                    Err(restart_lifetime_refusal(target).into())
                }
                _ => Err(refusal.into()),
            }
        }
        Errorable::Err { error } => {
            tracing::info!(verb = "box restart", box_id = %id, outcome = "failed", "{error}");
            Err(box_rpc_error(target, error))
        }
    }
}

/// The refusal of `min box prune` off a terminal without `--yes`
/// (BCLI-005). It ends the command with exit 2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PruneNeedsYes;

impl PruneNeedsYes {
    /// The exit code `min box prune` ends with on this refusal.
    pub const EXIT_CODE: u8 = 2;
}

impl std::fmt::Display for PruneNeedsYes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(
            "Prune removes boxes. Pass --yes to confirm, or --dry-run to see what it would remove.",
        )
    }
}

impl std::error::Error for PruneNeedsYes {}

/// How `min box prune` proceeds past its confirmation gate.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum PruneGate {
    /// Prune without asking: `--yes`.
    Proceed,
    /// Ask on the terminal first, default No.
    Confirm,
}

/// Decides whether `min box prune` prunes, asks, or refuses with
/// [`PruneNeedsYes`]. Off a terminal, or under `--no-input`, nothing can
/// answer the question, so only `--yes` prunes.
pub(crate) fn prune_gate(
    yes: bool,
    no_input: bool,
    stdin_is_terminal: bool,
) -> Result<PruneGate, PruneNeedsYes> {
    match (yes, !no_input && stdin_is_terminal) {
        (true, _) => Ok(PruneGate::Proceed),
        (false, true) => Ok(PruneGate::Confirm),
        (false, false) => Err(PruneNeedsYes),
    }
}

/// The `PruneBoxes` request for `min box prune`: BOX-021's `older-than`
/// selector for `--older-than`, and its `parent` selector for `--parent`,
/// which the caller resolved to the box `parent`.
pub(crate) fn box_prune_request(
    older_than: Option<std::time::Duration>,
    parent: Option<boxes::SessionId>,
) -> minimald_rpc::PruneBoxesRequest {
    minimald_rpc::PruneBoxesRequest {
        older_than_secs: older_than.map(|age| age.as_secs()),
        parent,
    }
}

/// The question `min box prune` asks on a terminal. It names each
/// selector the person passed, so it never claims more than the prune
/// removes. The age prints in the largest whole unit `--older-than` takes.
pub(crate) fn prune_question(
    older_than: Option<std::time::Duration>,
    parent: Option<&str>,
) -> String {
    let what = match parent {
        Some(parent) => format!("child box of {parent}"),
        None => "box".to_owned(),
    };
    match older_than {
        Some(age) => {
            let secs = age.as_secs();
            let (n, unit) = [(86_400, 'd'), (3_600, 'h'), (60, 'm')]
                .into_iter()
                .find(|(size, _)| secs > 0 && secs % size == 0)
                .map_or((secs, 's'), |(size, unit)| (secs / size, unit));
            format!("Remove every {what} that stopped or exited at least {n}{unit} ago?")
        }
        None => format!("Remove every stopped or exited {what}?"),
    }
}

/// `min box prune [--older-than <d>] [--parent <box>] [--yes] [--dry-run]`:
/// removes the stopped and exited boxes that match, as BOX-021 defines.
/// With `--parent`, only the host that keeps that box is pruned. Without
/// it, every local host that is running is pruned. With `--dry-run`, it
/// lists the boxes that match with the disk each holds, and removes none
/// (BCLI-006). A dry run removes nothing, so it asks nothing.
pub async fn cmd_box_prune(global: &GlobalArgs, args: BoxPruneArgs) -> Result<(), anyhow::Error> {
    let mode = if args.dry_run {
        PruneMode::DryRun
    } else {
        PruneMode::Remove
    };
    let gate = if mode == PruneMode::DryRun {
        PruneGate::Proceed
    } else {
        prune_gate(args.yes, global.no_input, std::io::stdin().is_terminal())
            .inspect_err(|_| tracing::info!(verb = "box prune", outcome = "refused", "no --yes"))?
    };
    if gate == PruneGate::Confirm {
        let question = prune_question(args.older_than, args.parent.as_deref());
        if !confirm(&question, false)? {
            tracing::info!(verb = "box prune", outcome = "declined");
            println!("Nothing was removed.");
            return Ok(());
        }
    }
    ensure_daemon(global)?;
    let hosts = crate::cmd::list::local_hosts(global)?;
    let (hosts, parent) = match &args.parent {
        Some(parent) => {
            let resolved = resolve_box_on_hosts(hosts, parent, "box prune").await?;
            (vec![resolved.host], Some(resolved.box_id))
        }
        None => (hosts, None),
    };
    let request = box_prune_request(args.older_than, parent);
    let mut out = std::io::stdout().lock();
    let tally = prune_hosts(hosts, parent.is_some(), request, mode, &mut out).await?;
    let mut err = std::io::stderr().lock();
    if mode == PruneMode::DryRun {
        tracing::info!(
            verb = "box prune",
            parent = ?parent,
            matched = tally.reaped,
            disk_bytes = tally.disk_bytes,
            unmeasured = tally.unmeasured,
            failed_hosts = tally.failed_hosts.len(),
            outcome = "dry run"
        );
        return finish_prune_dry_run(&tally, &mut out, &mut err);
    }
    tracing::info!(
        verb = "box prune",
        parent = ?parent,
        reaped = tally.reaped,
        failed = tally.failed,
        failed_hosts = tally.failed_hosts.len(),
        outcome = "pruned"
    );
    finish_prune(&tally, &mut out, &mut err)
}

/// Whether `min box prune` removes the boxes that match or, under
/// `--dry-run`, only lists them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PruneMode {
    /// Remove the boxes that match.
    Remove,
    /// List the boxes that match with the disk each holds, and remove none.
    DryRun,
}

/// What `min box prune` did across its hosts: how many boxes it removed and
/// did not, how many hosts it pruned, and each host it could not prune with
/// the reason. Under `--dry-run`, `reaped` counts the boxes that matched,
/// `disk_bytes` sums the disk they hold, and `unmeasured` counts the ones
/// whose disk the daemon did not measure.
#[derive(Debug, Default)]
pub(crate) struct PruneTally {
    pub reaped: usize,
    pub disk_bytes: u64,
    pub unmeasured: usize,
    pub failed: usize,
    pub pruned_hosts: usize,
    pub failed_hosts: Vec<(String, anyhow::Error)>,
}

/// Prunes each host in `hosts` with `request`. A host that fails does not
/// stop the prune: its error goes in the tally and the next host is pruned.
/// A host that is not selected is probed first, and one that is not running
/// is skipped. Only a write to `out` that fails ends the walk.
pub(crate) async fn prune_hosts(
    hosts: Vec<crate::cmd::list::LocalHost>,
    by_parent: bool,
    request: minimald_rpc::PruneBoxesRequest,
    mode: PruneMode,
    out: &mut impl std::io::Write,
) -> Result<PruneTally, anyhow::Error> {
    let mut tally = PruneTally::default();
    for host in hosts {
        let client = if host.selected || by_parent {
            gated_box_host_client(&host).await.map(Some)
        } else {
            match client::Client::probe(&host.sock).await {
                Ok(mut client) => client::ensure_version_match(&mut client)
                    .await
                    .map(|()| Some(client)),
                Err(client::ProbeRefusal::NotRunning) => Ok(None),
                Err(client::ProbeRefusal::Unreachable(e)) => Err(e),
            }
        };
        let pruned = match (client, mode) {
            (Ok(None), _) => continue,
            (Ok(Some(mut client)), PruneMode::Remove) => {
                prune_host(&mut client, &host, out, request.clone()).await
            }
            (Ok(Some(mut client)), PruneMode::DryRun) => {
                preview_prune_host(&mut client, out, request.clone())
                    .await
                    .map(|matched| {
                        for entry in &matched {
                            match entry.disk_bytes {
                                Some(bytes) => tally.disk_bytes += bytes,
                                None => tally.unmeasured += 1,
                            }
                        }
                        (matched.len(), 0)
                    })
            }
            (Err(e), _) => Err(e),
        };
        match pruned {
            Ok((reaped, failed)) => {
                tally.reaped += reaped;
                tally.failed += failed;
                tally.pruned_hosts += 1;
            }
            Err(e) => {
                tracing::warn!(verb = "box prune", host = %host.host, error = %format!("{e:#}"), "host prune failed");
                tally.failed_hosts.push((host.host, e));
            }
        }
    }
    Ok(tally)
}

/// Ends `min box prune` from its `tally`: one line on `err` for each host it
/// could not prune, then an error that counts the boxes and the hosts that
/// failed. With no failure and nothing removed, it says so on `out`.
pub(crate) fn finish_prune(
    tally: &PruneTally,
    out: &mut impl std::io::Write,
    err: &mut impl std::io::Write,
) -> Result<(), anyhow::Error> {
    for (host, e) in &tally.failed_hosts {
        writeln!(err, "Could not prune host {host}: {e:#}")?;
    }
    let plural =
        |n: usize, one: &str, many: &str| format!("{n} {}", if n == 1 { one } else { many });
    let mut summary = Vec::new();
    if tally.failed > 0 {
        summary.push(format!(
            "Prune could not remove {} of {}.",
            tally.failed,
            plural(tally.reaped + tally.failed, "box", "boxes")
        ));
    }
    if !tally.failed_hosts.is_empty() {
        summary.push(format!(
            "Prune failed on {} of {}.",
            tally.failed_hosts.len(),
            plural(
                tally.pruned_hosts + tally.failed_hosts.len(),
                "host",
                "hosts"
            )
        ));
    }
    if !summary.is_empty() {
        bail!("{}", summary.join(" "));
    }
    if tally.reaped == 0 {
        writeln!(
            out,
            "No stopped or exited box matched, so nothing was removed."
        )?;
    }
    Ok(())
}

/// Ends `min box prune --dry-run` from its `tally`: one line on `err` for
/// each host it could not ask, the sum of the disk the matched boxes hold,
/// and how many of them the sum leaves out. With nothing matched and no
/// host failed, it says so. A host that failed ends it with an error.
pub(crate) fn finish_prune_dry_run(
    tally: &PruneTally,
    out: &mut impl std::io::Write,
    err: &mut impl std::io::Write,
) -> Result<(), anyhow::Error> {
    for (host, e) in &tally.failed_hosts {
        writeln!(err, "Could not check host {host}: {e:#}")?;
    }
    if tally.reaped == 0 {
        // A host that failed was not checked and can hold boxes that
        // match, so the no-match line prints only when every host answered.
        if tally.failed_hosts.is_empty() {
            writeln!(
                out,
                "No stopped or exited box matched, so prune would remove nothing."
            )?;
        }
    } else {
        writeln!(out, "Total: {}", format_disk(tally.disk_bytes))?;
        match tally.unmeasured {
            0 => {}
            1 => writeln!(out, "The total leaves out 1 box whose disk is unknown.")?,
            n => writeln!(out, "The total leaves out {n} boxes whose disk is unknown.")?,
        }
        writeln!(out, "Nothing was removed.")?;
    }
    if !tally.failed_hosts.is_empty() {
        let hosts = tally.pruned_hosts + tally.failed_hosts.len();
        bail!(
            "The dry run failed on {} of {hosts} {}.",
            tally.failed_hosts.len(),
            if hosts == 1 { "host" } else { "hosts" }
        );
    }
    Ok(())
}

/// Asks the host `client` serves which boxes a prune with `request`
/// removes, and writes one line for each to `out` with the disk it holds.
/// Removes nothing. Returns the boxes that matched.
pub(crate) async fn preview_prune_host(
    client: &mut client::Client,
    out: &mut impl std::io::Write,
    request: minimald_rpc::PruneBoxesRequest,
) -> Result<Vec<minimald_rpc::PrunePreviewEntry>, anyhow::Error> {
    use minimald_rpc::{Errorable, PreviewPrune};

    let preview = match client
        .oneshot_rpc::<PreviewPrune>(request)
        .await
        .context("PreviewPrune RPC failed")?
    {
        Errorable::Ok(preview) => preview,
        Errorable::Err { error } => bail!("{error}"),
    };
    for entry in &preview.matched {
        let disk = entry
            .disk_bytes
            .map_or_else(|| "disk unknown".to_owned(), format_disk);
        let record = &entry.record;
        match &record.name {
            Some(name) => writeln!(out, "Would remove {name} ({}): {disk}", record.box_id)?,
            None => writeln!(out, "Would remove {}: {disk}", record.box_id)?,
        }
    }
    Ok(preview.matched)
}

/// Prunes the host `client` serves with `request`, writes one line for each
/// box it removed to `out` and one line for each it did not to stderr, and
/// retires the row or the name hold each removed box leaves on the VM host
/// daemon. Returns how many boxes it removed and how many it did not.
pub(crate) async fn prune_host(
    client: &mut client::Client,
    host: &crate::cmd::list::LocalHost,
    out: &mut impl std::io::Write,
    request: minimald_rpc::PruneBoxesRequest,
) -> Result<(usize, usize), anyhow::Error> {
    use minimald_rpc::{Errorable, PruneBoxes};

    // The records of the boxes a prune can remove carry the pair each box's
    // registration handed back, which the withdrawal after the prune
    // presents. The prune reaps the boxes all the same without them.
    let mut addresses = std::collections::HashMap::new();
    if host.provider == crate::cmd::list::LOCAL_MINVMD_PROVIDER {
        for entry in list_box_records(client, None).await.unwrap_or_default() {
            if entry.state == "stopped" || entry.state == "exited" {
                let record = get_session_record(client, &entry.box_id.to_string())
                    .await
                    .ok()
                    .and_then(|resp| resp.record);
                addresses.insert(
                    entry.box_id,
                    (
                        record.as_ref().and_then(|r| r.box_addresses),
                        record.as_ref().and_then(|r| r.box_id),
                    ),
                );
            }
        }
    }
    let pruned = match client
        .oneshot_rpc::<PruneBoxes>(request)
        .await
        .context("PruneBoxes RPC failed")?
    {
        Errorable::Ok(pruned) => pruned,
        Errorable::Err { error } => bail!("{error}"),
    };
    let control_sock = box_host_control_sock(host);
    for entry in &pruned.reaped {
        let name = entry.name.as_deref();
        let (box_addresses, box_id) = addresses.get(&entry.box_id).copied().unwrap_or_default();
        let row_id = box_addresses.and(box_id);
        withdraw_box_row(control_sock.clone(), name, box_addresses, row_id).await;
        release_held_box_name(control_sock.clone(), entry.box_id, name, box_addresses).await;
    }
    write_prune_lines(out, &pruned)?;
    Ok((pruned.reaped.len(), pruned.failed.len()))
}

/// The lines `min box prune` prints for one host's answer `pruned`: one on
/// `out` for each box it removed, and one on stderr for each it did not.
fn write_prune_lines(
    out: &mut impl std::io::Write,
    pruned: &minimald_rpc::PruneBoxesResponse,
) -> std::io::Result<()> {
    for entry in &pruned.reaped {
        match &entry.name {
            Some(name) => writeln!(out, "Removed {name} ({}).", entry.box_id)?,
            None => writeln!(out, "Removed {}.", entry.box_id)?,
        }
    }
    for failure in &pruned.failed {
        eprintln!("Could not remove {}: {}", failure.box_id, failure.error);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The destroy race's loser: a second destroy of an already-destroyed
    /// session is told so by the daemon ("no session with ID ...") — the
    /// goal state, not a failure. Under `--force` the destroy reports it and
    /// succeeds; without, it fails naming the session.
    #[tokio::test]
    async fn a_destroy_of_an_already_destroyed_session_reports_it() {
        let dir = tempfile::TempDir::new().unwrap();
        let ssh_sock = dir.path().join("ssh.sock");
        let server = minimald::test_harness::TestServer::new().await;
        server.listen_on_uds(&ssh_sock).await;
        let project = tempfile::TempDir::new().unwrap();
        let mut daemon = server.connect().await;
        let id = minimald::test_harness::create_configured_session(
            &mut daemon,
            "web",
            project.path().to_str().unwrap(),
        )
        .await;
        let mut client = client::Client::connect(&ssh_sock).await.unwrap();
        let global = GlobalArgs::default();

        // The first destroy wins the race.
        destroy_box(&mut client, &global, id, Some("web"), None, None, false)
            .await
            .expect("the first destroy succeeds");

        // The loser is told the session is already gone: under `--force`
        // that is the goal state, reported and not a failure.
        destroy_box(&mut client, &global, id, Some("web"), None, None, true)
            .await
            .expect("a forced destroy of a destroyed session succeeds");

        // Without `--force` the same answer is an error — one that names
        // the session rather than forwarding the daemon's internals.
        let err = destroy_box(&mut client, &global, id, Some("web"), None, None, false)
            .await
            .expect_err("an unforced destroy of a destroyed session fails");
        assert!(
            err.to_string().contains("web is already destroyed"),
            "the error names the session: {err}"
        );
    }

    /// The id of the box the host lists under `name`.
    async fn listed_id(client: &mut client::Client, name: &str) -> boxes::SessionId {
        list_box_records(client, None)
            .await
            .unwrap()
            .into_iter()
            .find(|entry| entry.name.as_deref() == Some(name))
            .expect("the box is listed")
            .box_id
    }

    /// A daemon on a fresh socket, with a client connected to it, and a
    /// configured box for each name in `names`.
    async fn daemon_with_boxes(
        names: &[&str],
    ) -> (
        minimald::test_harness::TestServer,
        tempfile::TempDir,
        tempfile::TempDir,
        client::Client,
    ) {
        let dir = tempfile::TempDir::new().unwrap();
        let ssh_sock = dir.path().join("ssh.sock");
        let server = minimald::test_harness::TestServer::new().await;
        server.listen_on_uds(&ssh_sock).await;
        let project = tempfile::TempDir::new().unwrap();
        let mut daemon = server.connect().await;
        for name in names {
            minimald::test_harness::create_configured_session(
                &mut daemon,
                name,
                project.path().to_str().unwrap(),
            )
            .await;
        }
        let client = client::Client::connect(&ssh_sock).await.unwrap();
        (server, dir, project, client)
    }

    /// The state the host lists for the box named `name`, or `None` when
    /// the host keeps no box of that name.
    async fn listed_state(client: &mut client::Client, name: &str) -> Option<String> {
        list_box_records(client, None)
            .await
            .unwrap()
            .into_iter()
            .find(|entry| entry.name.as_deref() == Some(name))
            .map(|entry| entry.state)
    }

    /// The daemon's log lines for the stop it served of box `id` with
    /// `force`. The daemon logs each stop it served with its `force` flag.
    fn served_stops(log: &str, id: boxes::SessionId, force: bool) -> usize {
        log.lines()
            .filter(|line| {
                line.contains("session stopped")
                    && line.contains(&format!("session_id={id}"))
                    && line.contains(&format!("force={force}"))
            })
            .count()
    }

    // BCLI-059: `min box stop` stops the box as BOX-013 defines, and asks
    // for the forced stop under `--force`.
    #[tokio::test]
    async fn box_stop_stops_as_box_013_force_forces() {
        let log = minimald::test_harness::captured_log();
        let (_server, _dir, _project, mut client) = daemon_with_boxes(&["web", "api"]).await;
        assert_eq!(
            listed_state(&mut client, "web").await.as_deref(),
            Some("running")
        );

        let mut out = Vec::new();
        let web = listed_id(&mut client, "web").await;
        stop_listed_box(&mut client, &mut out, web, "web", false)
            .await
            .expect("the graceful stop succeeds");
        assert_eq!(String::from_utf8(out).unwrap(), "Stopped web.\n");
        assert_eq!(
            listed_state(&mut client, "web").await.as_deref(),
            Some("stopped")
        );

        let mut out = Vec::new();
        let api = listed_id(&mut client, "api").await;
        stop_listed_box(&mut client, &mut out, api, "api", true)
            .await
            .expect("the forced stop succeeds");
        assert_eq!(String::from_utf8(out).unwrap(), "Stopped api.\n");
        // A stopped box keeps its record until it is removed.
        assert_eq!(
            listed_state(&mut client, "api").await.as_deref(),
            Some("stopped")
        );

        // The daemon served a graceful stop of `web` and a forced stop of
        // `api`, and no other stop of either.
        let log = log.contents();
        assert_eq!(served_stops(&log, web, false), 1, "{log}");
        assert_eq!(served_stops(&log, web, true), 0, "{log}");
        assert_eq!(served_stops(&log, api, true), 1, "{log}");
        assert_eq!(served_stops(&log, api, false), 0, "{log}");

        // A box that exited before the stop reached it: the daemon answers
        // `already_exited`, and the line says the stop changed nothing.
        let mut out = Vec::new();
        write_stop_line(
            &mut out,
            "web",
            &minimald_rpc::StopBoxResponse {
                exit_code: Some(0),
                signal: None,
                already_exited: true,
            },
        )
        .unwrap();
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "web exited before the stop, so the stop changed nothing.\n"
        );
    }

    // BCLI-060: `min box rm` reaps the box as BOX-019 defines, and asks for
    // the forced reap under `--force`.
    #[tokio::test]
    async fn box_rm_reaps_as_box_019_force_forces() {
        let (_server, _dir, _project, mut client) = daemon_with_boxes(&["web", "api"]).await;

        // A stopped box is removed without `--force`.
        let web = listed_id(&mut client, "web").await;
        stop_listed_box(&mut client, &mut Vec::new(), web, "web", false)
            .await
            .expect("the stop succeeds");
        let removed = rm_listed_box(&mut client, web, "web", false)
            .await
            .expect("a stopped box is removed");
        // The caller retires the row or name hold by this name.
        assert_eq!(removed.name.as_deref(), Some("web"));
        assert_eq!(listed_state(&mut client, "web").await, None);

        // A running box is removed under `--force`.
        assert_eq!(
            listed_state(&mut client, "api").await.as_deref(),
            Some("running")
        );
        let api = listed_id(&mut client, "api").await;
        let removed = rm_listed_box(&mut client, api, "api", true)
            .await
            .expect("a forced removal of a running box succeeds");
        assert_eq!(removed.name.as_deref(), Some("api"));
        assert_eq!(listed_state(&mut client, "api").await, None);
    }

    // BCLI-004: `min box rm` of a running box without `--force` is refused
    // with exit 2, naming `--force`, and the box keeps running.
    #[tokio::test]
    async fn rm_running_box_refuses_naming_force() {
        let (_server, _dir, _project, mut client) = daemon_with_boxes(&["web"]).await;

        let id = listed_id(&mut client, "web").await;
        let err = rm_listed_box(&mut client, id, "web", false)
            .await
            .expect_err("a running box is refused without --force");
        let refusal = err
            .downcast_ref::<BoxRunningRefusal>()
            .expect("the refusal is typed");
        assert_eq!(
            refusal.to_string(),
            "web is running. Stop it with min box stop web, \
             or remove it now with min box rm web --force."
        );
        assert_eq!(
            listed_state(&mut client, "web").await.as_deref(),
            Some("running")
        );

        // A box that starts between the listing and the reap gets the
        // daemon's own answer. Send the unforced reap straight to the daemon
        // and check that the client maps that answer to the same refusal.
        let answer = client
            .oneshot_rpc::<minimald_rpc::ReapBox>(box_rm_request(id, false))
            .await
            .expect("the ReapBox RPC answers");
        let minimald_rpc::Errorable::Err { error } = answer else {
            panic!("the daemon refuses an unforced reap of a running box");
        };
        assert!(
            reap_error_is_running(false, &error),
            "the daemon's running-box answer maps to the refusal: {error}"
        );
        assert!(!reap_error_is_running(true, &error));
        assert_eq!(
            listed_state(&mut client, "web").await.as_deref(),
            Some("running")
        );
    }

    // BCLI-058: `min box rename` renames the box as BOX-010 defines. A name
    // a running box holds is refused with exit 2, and the refusal names the
    // holder. The reserved name `self` is refused too.
    #[tokio::test]
    async fn box_rename_renames_as_box_010() {
        let log = minimald::test_harness::captured_log();
        let (_server, _dir, _project, mut client) = daemon_with_boxes(&["web", "api"]).await;

        let web = listed_id(&mut client, "web").await;
        let mut out = Vec::new();
        rename_listed_box(&mut client, &mut out, web, "web", "front")
            .await
            .expect("the rename succeeds");
        assert_eq!(String::from_utf8(out).unwrap(), "Renamed web to front.\n");
        assert_eq!(listed_state(&mut client, "web").await, None);
        assert_eq!(listed_id(&mut client, "front").await, web);
        assert!(
            log.contents().contains("renamed a box"),
            "{}",
            log.contents()
        );

        // The running box `front` holds the name, so `api` cannot take it.
        let api = listed_id(&mut client, "api").await;
        let mut out = Vec::new();
        let err = rename_listed_box(&mut client, &mut out, api, "api", "front")
            .await
            .expect_err("a held name is refused");
        let refusal = err
            .downcast_ref::<BoxRenameRefusal>()
            .unwrap_or_else(|| panic!("the refusal is typed: {err:#}"));
        assert_eq!(BoxRenameRefusal::EXIT_CODE, 2);
        let text = refusal.to_string();
        assert!(text.contains(&web.to_string()), "names the holder: {text}");
        assert!(text.contains("`front`"), "names the holder: {text}");
        assert!(out.is_empty());
        assert_eq!(listed_id(&mut client, "api").await, api);

        // `self` is reserved.
        let err = rename_listed_box(&mut client, &mut Vec::new(), api, "api", "self")
            .await
            .expect_err("`self` is refused");
        assert!(err.downcast_ref::<BoxRenameRefusal>().is_some(), "{err:#}");

        // Any other daemon error is not the refusal.
        assert_eq!(
            BoxRenameRefusal::from_error("session is already named `api`"),
            None
        );
    }

    // BCLI-061: `min box prune` asks for BOX-021's prune, with the
    // `older-than` selector for `--older-than` and the `parent` selector for
    // `--parent`. A running box is never removed.
    #[tokio::test]
    async fn box_prune_flags_map_to_box_021_selectors() {
        // The flags map to the selectors.
        let parent = boxes::SessionId::from_bytes([7; 16]);
        let age = crate::cli::parse_box_age("7d").unwrap();
        assert_eq!(age.as_secs(), 7 * 86_400);
        assert_eq!(
            box_prune_request(Some(age), Some(parent)),
            minimald_rpc::PruneBoxesRequest {
                older_than_secs: Some(7 * 86_400),
                parent: Some(parent),
            }
        );
        assert_eq!(
            box_prune_request(None, None),
            minimald_rpc::PruneBoxesRequest::default()
        );
        // The terminal question names every selector it was given.
        assert_eq!(
            prune_question(None, None),
            "Remove every stopped or exited box?"
        );
        assert_eq!(
            prune_question(None, Some("api")),
            "Remove every stopped or exited child box of api?"
        );
        assert_eq!(
            prune_question(Some(age), None),
            "Remove every box that stopped or exited at least 7d ago?"
        );
        assert_eq!(
            prune_question(crate::cli::parse_box_age("90s").ok(), Some("api")),
            "Remove every child box of api that stopped or exited at least 90s ago?"
        );
        for (arg, secs) in [("12h", 43_200), ("30m", 1_800), ("90s", 90), ("0d", 0)] {
            assert_eq!(crate::cli::parse_box_age(arg).unwrap().as_secs(), secs);
        }
        for bad in ["", "7", "d", "7y", "-1d", "1.5h"] {
            let err = crate::cli::parse_box_age(bad).expect_err(bad);
            assert!(err.contains("such as 7d, 12h, 30m or 90s"), "{err}");
        }

        let (_server, dir, _project, mut client) = daemon_with_boxes(&["web", "api", "db"]).await;
        let host = crate::cmd::list::LocalHost {
            provider: crate::cmd::list::LOCAL_PROVIDER,
            host: "local0".to_owned(),
            sock: dir.path().join("ssh.sock"),
            selected: true,
        };
        let web = listed_id(&mut client, "web").await;
        let api = listed_id(&mut client, "api").await;
        for id in [web, api] {
            stop_listed_box(&mut client, &mut Vec::new(), id, "box", false)
                .await
                .expect("the stop succeeds");
        }

        // The boxes stopped just now, so an hour's age matches none.
        let mut out = Vec::new();
        let pruned = prune_host(
            &mut client,
            &host,
            &mut out,
            box_prune_request(Some(std::time::Duration::from_secs(3_600)), None),
        )
        .await
        .expect("the prune succeeds");
        assert_eq!(pruned, (0, 0));
        assert!(out.is_empty());

        // No box is a child of `db`, so its parent selector matches none.
        let db = listed_id(&mut client, "db").await;
        let pruned = prune_host(
            &mut client,
            &host,
            &mut Vec::new(),
            box_prune_request(None, Some(db)),
        )
        .await
        .expect("the prune succeeds");
        assert_eq!(pruned, (0, 0));
        assert_eq!(
            listed_state(&mut client, "web").await.as_deref(),
            Some("stopped")
        );

        // With no selector, every stopped box goes, and the running one stays.
        let mut out = Vec::new();
        let pruned = prune_host(&mut client, &host, &mut out, box_prune_request(None, None))
            .await
            .expect("the prune succeeds");
        assert_eq!(pruned, (2, 0));
        let mut lines: Vec<String> = String::from_utf8(out)
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect();
        lines.sort();
        let mut want = vec![
            format!("Removed api ({api})."),
            format!("Removed web ({web})."),
        ];
        want.sort();
        assert_eq!(lines, want);
        assert_eq!(listed_state(&mut client, "web").await, None);
        assert_eq!(listed_state(&mut client, "api").await, None);
        assert_eq!(
            listed_state(&mut client, "db").await.as_deref(),
            Some("running")
        );
    }

    // BCLI-061: a host that `min box prune` cannot prune does not stop the
    // prune. The other hosts are still pruned, the failed host is named with
    // its reason, and the command ends with an error that counts it.
    #[tokio::test]
    async fn box_prune_goes_on_past_a_failed_host() {
        let (_server, dir, _project, mut client) = daemon_with_boxes(&["web", "db"]).await;
        let web = listed_id(&mut client, "web").await;
        stop_listed_box(&mut client, &mut Vec::new(), web, "box", false)
            .await
            .expect("the stop succeeds");

        // A host whose socket accepts and then closes: its probe fails.
        let broken_sock = dir.path().join("broken.sock");
        let listener = tokio::net::UnixListener::bind(&broken_sock).unwrap();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                drop(stream);
            }
        });
        let hosts = vec![
            crate::cmd::list::LocalHost {
                provider: crate::cmd::list::LOCAL_PROVIDER,
                host: "broken0".to_owned(),
                sock: broken_sock,
                selected: false,
            },
            crate::cmd::list::LocalHost {
                provider: crate::cmd::list::LOCAL_PROVIDER,
                host: "local0".to_owned(),
                sock: dir.path().join("ssh.sock"),
                selected: true,
            },
        ];

        let mut out = Vec::new();
        let tally = prune_hosts(
            hosts,
            false,
            box_prune_request(None, None),
            PruneMode::Remove,
            &mut out,
        )
        .await
        .expect("only a write to out can end the walk");
        assert_eq!((tally.reaped, tally.failed, tally.pruned_hosts), (1, 0, 1));
        assert_eq!(tally.failed_hosts.len(), 1);
        assert_eq!(tally.failed_hosts[0].0, "broken0");
        assert_eq!(
            String::from_utf8(out.clone()).unwrap(),
            format!("Removed web ({web}).\n")
        );
        assert_eq!(listed_state(&mut client, "web").await, None);
        assert_eq!(
            listed_state(&mut client, "db").await.as_deref(),
            Some("running")
        );

        let mut err = Vec::new();
        let summary = finish_prune(&tally, &mut out, &mut err).expect_err("a host failed");
        let err = String::from_utf8(err).unwrap();
        assert!(err.starts_with("Could not prune host broken0: "), "{err}");
        assert_eq!(err.lines().count(), 1, "{err}");
        assert_eq!(summary.to_string(), "Prune failed on 1 of 2 hosts.");

        // The box count says "box" for one.
        let one_failed = PruneTally {
            failed: 1,
            pruned_hosts: 1,
            ..PruneTally::default()
        };
        let summary =
            finish_prune(&one_failed, &mut Vec::new(), &mut Vec::new()).expect_err("a box failed");
        assert_eq!(summary.to_string(), "Prune could not remove 1 of 1 box.");
    }

    // BCLI-005: off a terminal, or under `--no-input`, `min box prune`
    // without `--yes` is refused with exit 2, naming `--yes`. On a terminal
    // it asks, and `--yes` prunes without asking.
    #[test]
    fn prune_off_tty_needs_yes() {
        assert_eq!(prune_gate(false, false, false), Err(PruneNeedsYes));
        assert_eq!(prune_gate(false, true, true), Err(PruneNeedsYes));
        assert_eq!(prune_gate(false, false, true), Ok(PruneGate::Confirm));
        assert_eq!(prune_gate(true, false, false), Ok(PruneGate::Proceed));
        assert_eq!(prune_gate(true, true, true), Ok(PruneGate::Proceed));
        assert_eq!(PruneNeedsYes::EXIT_CODE, 2);
        assert_eq!(
            PruneNeedsYes.to_string(),
            "Prune removes boxes. Pass --yes to confirm, or --dry-run to see what it would remove."
        );
    }
}
