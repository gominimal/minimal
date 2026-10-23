//! `min session destroy`, `stop` and `rename`: the box lifecycle helpers.

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
                vm_host_control_sock(daemon_provider_kind(global), global.minimal_dir.as_deref());
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
/// provider dir the CLI resolved for *this* VM, then waited on until minvmd
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
    let provider_dir = client::resolve_provider_dir(minimal_dir.as_deref(), true)
        .context("resolving the VM's provider dir for a host-side stop")?;

    // The stop sleep-polls the VMM's exit and the wait polls the alive lock,
    // so both go on the blocking pool rather than stalling an async worker
    // (rust-coding-standards: no blocking in an async context).
    let outcome = tokio::task::spawn_blocking(move || {
        let state_dir = minvmd::state::StateDir::new(provider_dir.clone())
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
            anyhow::bail!(
                "the VM is still booting; retry `{}` once it is up",
                stop_command()
            );
        }
        let outcome = minvmd::cmd::stop::stop_at(provider_dir, quiesce_guest)
            .context("stopping the VM from the host")?;
        wait_for_alive_lock_released(&state_dir, HOST_STOP_RELEASE_WAIT)?;
        Ok(outcome)
    })
    .await
    .context("the host-side stop of the VM panicked")??;

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

/// What `min stop --force` says after killing a VM whose guest did not
/// acknowledge Shutdown. The volume's journal keeps its filesystem metadata
/// consistent across the kill; it does not keep the data.
const UNACKNOWLEDGED_STOP_CAVEAT: &str = "The VM did not respond to shutdown, so it was killed from this machine. \
     Running sessions were killed without their shutdown steps, and recently written files \
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
    let booting = client::resolve_provider_dir(minimal_dir, true)
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
}
