//! `min session destroy`, `stop` and `rename`: the box lifecycle helpers.
//! `min box stop` (BOX-013, BCLI-059) and `min box rm` (BOX-019, BCLI-060,
//! BCLI-004) live here too.

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
        // (T66), which the destroy-side withdrawal presents; a session that
        // registered no box holds none, and the withdrawal stays silent for
        // it. A record the daemon cannot answer destroys the session all the
        // same — nothing is left on this path to withdraw the row by.
        let box_addresses = get_session_record(client, &session.id.to_string())
            .await
            .ok()
            .and_then(|resp| resp.record)
            .and_then(|record| record.box_addresses);
        if let Err(error) = destroy_box(
            client,
            global,
            session.id,
            session.name.as_deref(),
            box_addresses,
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
            // presenting the pair the registration handed back. Best-effort: a
            // withdrawal that cannot be made leaves the row published and warns
            // rather than failing a destroy that already succeeded.
            // A box that registered no row held its name in the zone instead
            // (`host_ip`); the same destroy releases it, best-effort the same
            // way.
            let control_sock =
                vm_host_control_sock(daemon_host_kind(global), global.minimal_dir.as_deref());
            withdraw_box_row(control_sock.clone(), name, box_addresses, None).await;
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
        Err(rpc_err) if stopped().await => {
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
    host_ip_box_with_vm_host(control_sock, stopped.box_id, None, false).await;
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
    withdraw_box_row(control_sock.clone(), name, removed.box_addresses, None).await;
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
    // which the withdrawal after the reap presents. A record the daemon
    // cannot answer reaps the box all the same.
    let box_addresses = get_session_record(client, &id.to_string())
        .await
        .ok()
        .and_then(|resp| resp.record)
        .and_then(|record| record.box_addresses);
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
    })
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
        destroy_box(&mut client, &global, id, Some("web"), None, false)
            .await
            .expect("the first destroy succeeds");

        // The loser is told the session is already gone: under `--force`
        // that is the goal state, reported and not a failure.
        destroy_box(&mut client, &global, id, Some("web"), None, true)
            .await
            .expect("a forced destroy of a destroyed session succeeds");

        // Without `--force` the same answer is an error — one that names
        // the session rather than forwarding the daemon's internals.
        let err = destroy_box(&mut client, &global, id, Some("web"), None, false)
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
}
