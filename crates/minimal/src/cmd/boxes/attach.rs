//! `min session attach` and `min box attach`: resolving the target, the
//! ssh hand-off, the host asks the attach answers, and how the attach
//! ended.

use super::*;
use minimal_client::box_registration::resume_box_row;

/// Whether to announce the resolved or freshly created session on stderr
/// before handing off to the interactive shell. Suppressed under `--no-input`
/// and when stderr is not a terminal, so scripted and CI callers — which read
/// the session id from stdout — see nothing extra.
pub(crate) fn should_announce_box(global: &GlobalArgs) -> bool {
    !global.no_input && std::io::stderr().is_terminal()
}

/// A one-line identity for a session in an attach/create confirmation: the
/// session name plus a short id in parentheses, or just the short id when the
/// session is unnamed. The short id is the leading block of the UUID — enough
/// to tell two same-named sessions built from the same directory apart without
/// the full 36-character id.
pub(crate) fn box_announce_label(id: &boxes::SessionId, name: Option<&str>) -> String {
    let id = id.to_string();
    let short = id.split('-').next().unwrap_or(&id);
    match name {
        Some(name) => format!("{name} ({short})"),
        None => short.to_string(),
    }
}

/// Resolve a named box to its record and the socket the hand-off runs over:
/// the target `min session attach`, `min session exec`, `min session run` and
/// `min net forward` land in when the name alone decides where to look
/// (NET-058). `verb` leads the one line that says which VM the box was found
/// on ("Attaching to", "Running in", ...).
///
/// The selected VM's daemon is asked first (`client`, reached over `sock`),
/// and its answer is gated on the reply that lookup was already making. On a
/// host with several VMs and no `--vm`, a hit there is checked against every
/// VM, and a name a second VM also holds is an ambiguity
/// ([`ensure_selected_holds_box_alone`]). When that daemon does
/// not know the name, [`crate::attach::resolve_box_vm`] resolves the VM that owns it
/// across every VM's socket, so no global flag is needed to reach a box on
/// another VM — the resolution gates the owning daemon on the very reply that
/// named the box, so a skewed VM cannot be reached through it. Nothing found
/// anywhere returns the selected VM's own error — the "no session found" it
/// computed, or its skew — as the more useful of the two answers.
pub(crate) async fn resolve_named_box_version_gated(
    global: &GlobalArgs,
    client: &mut client::Client,
    sock: std::path::PathBuf,
    name: &str,
    verb: &str,
    example: &str,
) -> Result<(boxes::Record, std::path::PathBuf), anyhow::Error> {
    match resolve_session_version_gated(client, name).await {
        Ok(record) => {
            // A second VM that holds the name makes it ambiguous. The check
            // runs before the attach touches the terminal.
            ensure_selected_holds_box_alone(global, name, &record).await?;
            Ok((record, sock))
        }
        Err(selected) => {
            // Every refusal here — the miss, a box on a stopped VM, an
            // ambiguous name — is made before the attach touches the
            // terminal, so it prints on the terminal as the user left it.
            let resolved = resolve_box_on_another_vm(global, name, example, selected).await?;
            // The operator never chose the VM the way they chose the
            // session, so tell them which one they're landing in.
            if should_announce_box(global) {
                eprintln!(
                    "{verb} session {} on VM {}",
                    box_announce_label(&resolved.record.id, resolved.record.name.as_deref()),
                    resolved.vm
                );
            }
            Ok((resolved.record, resolved.sock))
        }
    }
}

/// Resolve a session to attach to when the user supplied no explicit session
/// reference. Matches an already-fetched session list against the current
/// working directory, and either attaches directly (unambiguous), opens the
/// interactive picker (ambiguous), or errors (ambiguous but non-interactive).
///
/// Takes the list rather than fetching it so its caller can assert the
/// daemon's build off the `ListSessions` reply — before the picker blocks on a
/// human, not after.
///
/// Returns [`SmartAttach::NoSessions`] when no sessions exist at all.
pub(crate) fn resolve_smart_attach(
    sessions: &[minimald_rpc::ListSessionsEntry],
    global: &GlobalArgs,
) -> Result<SmartAttach, anyhow::Error> {
    let cwd = crate::attach::cwd_host_path(global)?;
    match crate::attach::resolve_for_attach(sessions, &cwd) {
        crate::attach::SmartResolve::NoSessions => Ok(SmartAttach::NoSessions),
        crate::attach::SmartResolve::Attach(entry) => {
            // Unambiguous auto-resolve: the operator never chose this session,
            // so tell them which one they're landing in. The picker path below
            // needs no such line — the selection is its own confirmation.
            if should_announce_box(global) {
                eprintln!(
                    "Attaching to session {}{}",
                    box_announce_label(&entry.id, entry.name.as_deref()),
                    crate::attach::created_from_suffix(&entry, &cwd)
                );
            }
            Ok(SmartAttach::Attach(Box::new(entry)))
        }
        crate::attach::SmartResolve::Pick(cands) => {
            if global.no_input || !crate::attach::can_pick_interactively() {
                bail!(crate::attach::ambiguous_no_input_message(&cands, &cwd));
            }
            match crate::attach::pick_session(&cands, &cwd)? {
                Some(crate::attach::Picked::Session(entry)) => Ok(SmartAttach::Attach(entry)),
                Some(crate::attach::Picked::CreateNew) => Ok(SmartAttach::CreateForCwd),
                None => bail!("session selection cancelled"),
            }
        }
    }
}

/// Outcome of smart attach resolution when the user gave no explicit session.
pub(crate) enum SmartAttach {
    /// Attach to this resolved or picked session. Boxed: the entry is far
    /// larger than the other arms, which carry nothing.
    Attach(Box<minimald_rpc::ListSessionsEntry>),
    /// The picker's create row was chosen: activate a fresh session for the
    /// cwd and attach, exactly as `min session activate --attach .` would.
    CreateForCwd,
    /// No sessions exist at all.
    NoSessions,
}

/// Guard for the interactive attach path: the PTY-backed session shell must be
/// driven from a real terminal. When stdin is not a TTY there is nothing to
/// drive the remote shell and no EOF ever reaches it through the forced `-tt`
/// PTY, so ssh blocks indefinitely (#953). Fail fast with an actionable message
/// instead of hanging.
///
/// Pure in its `stdin_is_tty` input so both branches are unit-testable without
/// a controlled terminal.
pub(crate) fn ensure_interactive_attach_tty(stdin_is_tty: bool) -> Result<(), anyhow::Error> {
    if stdin_is_tty {
        Ok(())
    } else {
        bail!(
            "`min session attach` needs an interactive terminal, but stdin is not a TTY. \
             Run it from a terminal."
        )
    }
}

/// Shell out to `ssh` to attach to `id` or run a command.
///
/// Split from [`cmd_attach`] so the activate-then-attach chain and the
/// smart-resolution picker can attach without re-resolving an entry they
/// already hold.
///
/// The interactive path (no `wire`) negotiates the configurable session
/// keys from `config_dir` so the daemon adopts the user's detach/forward
/// chord for that channel; the exec path (`wire` set) has no detach
/// and sends none.
///
/// `host_asks_for` names the box whose pending asks the interactive attach
/// answers on a VM-backed host (NET-045): the attach subscribes on the VM
/// host daemon's control socket beside `sock` and renders each ask's dialog
/// while the relay is suspended. `None` on a native host, where the
/// session's own binding asks, and for every exec channel. The subscription
/// is made for a box whose record carries an address pair, and for one whose
/// record could not be read ([`host_asks_target`]).
///
/// Neither path returns normally: on success the error is a [`Handoff`]
/// (exec ssh, or exit with the attach's status) that [`run`] finishes once
/// the command's `cmd` span has ended, so callers return it untouched.
pub(crate) async fn box_via_ssh(
    kind: paths::HostKind,
    sock: &std::path::Path,
    id: boxes::SessionId,
    wire: Option<String>,
    config_dir: Option<&std::path::Path>,
    host_asks_for: Option<&str>,
) -> Result<(), anyhow::Error> {
    box_via_ssh_with(kind, sock, id, wire, config_dir, host_asks_for, None).await
}

/// [`box_via_ssh`] for `min session run`: the exec `wire` of a task, with
/// the task's `env_vars` resolved by this client
/// ([`minimal_client::attach::task_run_command`]) (inbox#778).
pub(crate) async fn task_via_ssh(
    kind: paths::HostKind,
    sock: &std::path::Path,
    id: boxes::SessionId,
    wire: String,
    task_env: &minimald_rpc::taskenv::TaskEnv,
) -> Result<(), anyhow::Error> {
    box_via_ssh_with(kind, sock, id, Some(wire), None, None, Some(task_env)).await
}

async fn box_via_ssh_with(
    kind: paths::HostKind,
    sock: &std::path::Path,
    id: boxes::SessionId,
    wire: Option<String>,
    config_dir: Option<&std::path::Path>,
    host_asks_for: Option<&str>,
    task_env: Option<&minimald_rpc::taskenv::TaskEnv>,
) -> Result<(), anyhow::Error> {
    // The command itself lives in minimal-client, shared with the dash TUI's
    // suspend-attach-resume flow. The interactive path resolves the
    // session-key config from `config_dir` and forwards it per channel; the
    // exec path has no detach and passes `None`.
    let session_keys = if wire.is_none() {
        Some(minimal_client::attach::resolve_session_keys(config_dir)?)
    } else {
        None
    };
    let mut ssh = match (task_env, wire.as_deref()) {
        (Some(task_env), Some(wire)) => {
            minimal_client::attach::task_run_command(sock, id, wire, task_env)?
        }
        _ => minimal_client::attach::attach_command(
            sock,
            id,
            wire.as_deref(),
            session_keys.as_ref(),
        )?,
    };

    // The session's record, read before the attach or the exec on a
    // VM-backed host — one with a VM host daemon's control socket beside
    // `sock` — for the pair its box's row was registered with. A lookup
    // that fails reads as no row, and says so: the row is then not asked
    // back, and the in-VM daemon's own row check decides the launch.
    let mut record_unreadable = false;
    let record = match control_sock_beside(sock).filter(|control| control.exists()) {
        Some(_) => match attached_box_record(sock, id).await {
            Ok(record) => record,
            Err(error) => {
                tracing::warn!(
                    "could not read the session's record ({error:#}); its box row \
                     is not asked back first"
                );
                record_unreadable = true;
                None
            }
        },
        None => None,
    };
    // A VM host that cannot be reached fails the attach or the exec
    // closed (#1790); one that answers late or refuses is a warn line, and
    // the attach or the exec goes on (NET-138).
    resume_box_row(sock, record.as_ref()).await?;
    // The name hold a `host_ip` session without a row depends on may not
    // have survived a VM host daemon restart; re-make it before the
    // attach or the exec, idempotently.
    rehold_held_name_before_attach(kind, sock, id, record.as_ref()).await;

    if wire.is_none() {
        let stdin_is_tty = std::io::stdin().is_terminal();
        // The pair the box's row was registered with, and the box id beside
        // it, read before the attach: an attach that ends in a daemon-side
        // destroy leaves no record to read them from, and the row is still
        // this client's to withdraw. The id proves a box renamed since its
        // registration (#1116); it goes only with a pair.
        let box_row = match host_asks_for {
            Some(_) => {
                record.and_then(|record| record.box_addresses.map(|pair| (pair, record.box_id)))
            }
            None => None,
        };
        let box_addresses = box_row.map(|(pair, _)| pair);
        let host_asks = host_asks_target(
            control_sock_beside(sock),
            host_asks_for,
            box_addresses,
            record_unreadable,
        );
        // The relay blocks its thread until ssh exits, so it runs off the
        // runtime's workers.
        let code = tokio::task::spawn_blocking(move || {
            interactive_attach(
                ssh,
                stdin_is_tty,
                crate::attach::TerminalUnwind::arm,
                |ssh| {
                    // A terminal the relay could not take was never changed,
                    // so a failure here owes it nothing; the marker tells
                    // `interactive_attach` so.
                    let real = minimal_client::tty_relay::RealTty::acquire()
                        .context(crate::attach::TerminalNotTaken)?;
                    mark_relay_not_started(
                        subscribe_host_asks(host_asks)
                            .map(minimal_client::attach::HostAsks::into_hook),
                        |hook| {
                            minimal_client::attach::run_interactive_attach_on(ssh, real, Some(hook))
                        },
                    )
                },
            )
        })
        .await
        .context("the interactive attach's thread failed")??;
        // The attach may have ended in the shell-exit prompt's Delete, a
        // destroy made daemon-side: withdraw the row an own-address box
        // registered, or release the name a `host_ip` box held.
        if let Some(name) = host_asks_for {
            release_held_name_after_attach(sock, id, name, box_row).await;
        }
        // Terminate with ssh's own status, exactly as the `exec()` this
        // replaced did: `min` has nothing of its own left to say after an
        // attach, and the unwind guard has already run. `run` exits once the
        // command's `cmd` span has ended and been flushed.
        return Err(Handoff::Exit(code).into());
    }

    // The exec path spawns ssh with stdout piped so this process can relay
    // it. When the local reader closes (e.g. `head -1`), the write to
    // stdout fails with BrokenPipe; we kill ssh and exit 141 (128+SIGPIPE)
    // rather than leaving the remote process running indefinitely (#815).
    //
    // Unlike the `exec()` this replaced, `min` is now ssh's parent, so a
    // signal sent only to this PID (`kill <pid>`, a supervisor reaping its
    // direct child) would orphan ssh with its stdout closed and the remote
    // command running on. Catch the termination signals and take ssh down
    // with us. The handlers go in before the spawn so there is no window.
    use tokio::signal::unix::{SignalKind, signal};
    let mut sigterm = signal(SignalKind::terminate()).context("installing SIGTERM handler")?;
    let mut sighup = signal(SignalKind::hangup()).context("installing SIGHUP handler")?;
    let mut sigint = signal(SignalKind::interrupt()).context("installing SIGINT handler")?;
    // `min` stays ssh's parent, so the `cmd` span covers the command: every
    // way out below is a [`Handoff::Exit`], which `run` finishes once the
    // span has ended and been flushed. The ssh command carries this
    // process's TRACEPARENT (`attach_command`), which the daemon's `exec`
    // span parents to.
    ssh.stdout(std::process::Stdio::piped());
    let mut child = tokio::process::Command::from(ssh)
        .spawn()
        .context("failed to spawn ssh")?;
    let ssh_stdout = child.stdout.take().context("ssh stdout not piped")?;
    let mut local_stdout = tokio::io::stdout();
    let signo = tokio::select! {
        relayed = relay_exec_stdout(ssh_stdout, &mut local_stdout) => match relayed {
            Ok(()) => {
                // ssh stdout closed cleanly; wait for the child and propagate
                // its exit status.
                let status = child.wait().await.context("ssh exited")?;
                return Err(Handoff::Exit(exit_code_of(status)).into());
            }
            Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => {
                // Local reader closed; kill ssh and exit 141.
                kill_ssh(&mut child).await;
                return Err(Handoff::Exit(141).into());
            }
            Err(e) => {
                // Any other relay failure leaves ssh with nobody reading its
                // output; stop it so the remote command does not outlive us.
                kill_ssh(&mut child).await;
                return Err(e).context("relaying ssh stdout");
            }
        },
        _ = sigterm.recv() => SignalKind::terminate().as_raw_value(),
        _ = sighup.recv() => SignalKind::hangup().as_raw_value(),
        _ = sigint.recv() => SignalKind::interrupt().as_raw_value(),
    };
    kill_ssh(&mut child).await;
    Err(Handoff::Exit(128 + signo).into())
}

/// Where an interactive attach subscribes to its box's pending asks
/// (NET-045): the VM host daemon's control socket and the box's name, for a
/// box whose record carries an address pair. Only such a box registered a
/// row with the VM host daemon, and the subscription reads that row; a
/// `host_ip` or `none` box has none, so no subscription is attempted and
/// nothing is said. A record that could not be read (`record_unreadable`)
/// says neither: the subscription is then attempted by name, so a box that
/// did register a row still gets its port prompts, and a failed attempt is
/// said by [`subscribe_host_asks`].
fn host_asks_target(
    control: Option<std::path::PathBuf>,
    host_asks_for: Option<&str>,
    box_addresses: Option<boxes::BoxAddresses>,
    record_unreadable: bool,
) -> Option<(std::path::PathBuf, String)> {
    if box_addresses.is_none() && !record_unreadable {
        return None;
    }
    Some((control?, host_asks_for?.to_string()))
}

/// Subscribe an interactive attach to its box's pending asks on the VM host
/// daemon (NET-045), from the target [`host_asks_target`] chose; `None`
/// attempts nothing. A subscription that was attempted and cannot be made
/// leaves the attach as it is: the box's asks are then refused at the host
/// for want of an attached client, and the reason is said here, once.
fn subscribe_host_asks(
    target: Option<(std::path::PathBuf, String)>,
) -> Option<minimal_client::attach::HostAsks> {
    let (control, name) = target?;
    match minimal_client::attach::HostAsks::subscribe(&control, &name) {
        Ok(asks) => Some(asks),
        Err(error) => {
            tracing::debug!(box = %name, error = %format!("{error:#}"), "could not subscribe to the box's asks");
            eprintln!(
                "warning: this terminal will not show port prompts for box '{name}': \
                 {error:#}. Run `min session attach {name}` again to retry."
            );
            None
        }
    }
}

/// The box an interactive attach answers asks for (NET-045): its name, on a
/// VM-backed host only. Whether the attach subscribes for it is decided
/// from its record ([`host_asks_target`]).
pub(crate) fn host_asks_box(global: &GlobalArgs, name: Option<&str>) -> Option<String> {
    (daemon_host_kind(global) == paths::HostKind::Minvmd)
        .then_some(name)
        .flatten()
        .map(str::to_string)
}

/// Kill the exec path's ssh child and reap it.
async fn kill_ssh(child: &mut tokio::process::Child) {
    // A failed kill means ssh has already exited, so there is nothing left
    // to stop; record it and carry on to this process's own exit.
    if let Err(e) = child.kill().await {
        tracing::debug!(error = %e, "ssh kill failed; it had already exited");
    }
}

/// Run the relay with a suspend hook that records that the relay started,
/// and mark a failure that came before it with
/// [`crate::attach::RelayNotStarted`].
///
/// The relay calls its suspend hook only once `Relay::start` returned: ssh
/// runs on the pty and the real terminal is in raw mode. Every failure of
/// `Relay::start` comes before ssh's output can reach the real terminal, and
/// the relay put back what it changed, so the attach owes the terminal no
/// unwind. `inner` is the caller's own hook, if any, and runs as before.
///
/// The hook runs on a thread of its own, so a relay that started and then
/// failed at once can return before the hook records it. Then the guard
/// stands down, though the relay restored the termios. The only such
/// failure is the wait on ssh's exit.
pub(crate) fn mark_relay_not_started(
    inner: Option<minimal_client::tty_relay::SuspendHook>,
    run: impl FnOnce(
        minimal_client::tty_relay::SuspendHook,
    ) -> Result<std::process::ExitStatus, anyhow::Error>,
) -> Result<std::process::ExitStatus, anyhow::Error> {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    let started = Arc::new(AtomicBool::new(false));
    let hook_started = Arc::clone(&started);
    let hook: minimal_client::tty_relay::SuspendHook = Box::new(move |handle| {
        hook_started.store(true, Ordering::Release);
        if let Some(inner) = inner {
            inner(handle);
        }
    });
    run(hook).map_err(|e| {
        if started.load(Ordering::Acquire) {
            e
        } else {
            anyhow::Error::new(crate::attach::RelayNotStarted(e))
        }
    })
}

/// The interactive attach, from the terminal check to ssh's exit code.
///
/// `-tt` over a *non-terminal* stdin is a trap: ssh still forces the remote
/// PTY, yet the interactive shell reading it never sees an EOF from a
/// redirected local stdin (`< /dev/null`, a pipe), so the command blocks
/// forever (#953). So the refusal comes first, before the relay opens any
/// pty or touches the terminal.
///
/// Then `relay` runs ssh through the client-owned terminal relay
/// ([`minimal_client::attach::run_interactive_attach`]), which has put the
/// terminal's termios back by the time it returns. Only then does the
/// unwind guard get its say, so its codes reach the real terminal (never
/// the relay's pty) in the termios the user started with. `minimald` sends
/// unwind codes with every teardown it initiates, but a transport that
/// drops mid-session sends nothing at all, and once ssh is gone this is the
/// only process left that can still reach the tty. So the guard stays
/// armed for the duration and is stood down only once ssh's exit proves
/// the daemon was alive and speaking: see `crate::attach::client_must_unwind`.
///
/// A relay that fails once it holds the terminal ends `min session attach`
/// with an error, which `main` prints after this returns. The relay put the
/// attach-start termios back before it returned, and the guard writes its
/// unwind as it drops here, so the error lands on a restored terminal and
/// stays on screen after the exit. Only a relay that never took the
/// terminal ([`crate::attach::TerminalNotTaken`]) or never started ssh's
/// session on it ([`crate::attach::RelayNotStarted`]) stands the guard
/// down, because nothing of the session reached the terminal.
pub(crate) fn interactive_attach<W: std::io::Write>(
    ssh: std::process::Command,
    stdin_is_tty: bool,
    arm_unwind: impl FnOnce() -> crate::attach::TerminalUnwind<W>,
    relay: impl FnOnce(std::process::Command) -> Result<std::process::ExitStatus, anyhow::Error>,
) -> Result<i32, anyhow::Error> {
    ensure_interactive_attach_tty(stdin_is_tty)?;
    let mut unwind = arm_unwind();
    let status = match relay(ssh) {
        Ok(status) => status,
        Err(e) => {
            // The relay never took the terminal, or never started ssh's
            // session on it, so nothing of the session reached it and there
            // is nothing to put back. Any other failure came after the
            // session started, and the session may have left its modes set:
            // the guard writes the unwind as it drops, before the error is
            // printed.
            if e.downcast_ref::<crate::attach::TerminalNotTaken>()
                .is_some()
                || e.downcast_ref::<crate::attach::RelayNotStarted>().is_some()
            {
                unwind.disarm();
            }
            drop(unwind);
            return Err(e).context("failed to run ssh");
        }
    };
    if !crate::attach::client_must_unwind(&status) {
        unwind.disarm();
    }
    let code = exit_code_of(status);
    drop(unwind);
    Ok(code)
}

// `min box attach [<box>]` (BCLI-068): find the box, refuse what cannot be
// attached, hand the terminal to the box over ssh, and end with a code a
// script can read.

/// The exit status a daemon reports for an attach it ended: the box went
/// away, another client took its terminal, or the daemon shut down. The
/// daemon's binding sends it as `DAEMON_ENDED_EXIT_STATUS`.
pub(crate) const DAEMON_ENDED_ATTACH: i32 = 254;

/// The exit status ssh gives when its connection fails.
pub(crate) const SSH_CONNECTION_FAILED: i32 = 255;

/// Why `min box attach` attached to nothing, or how its attach failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BoxAttachRefusal {
    /// stdin is not a terminal. Exit 2.
    NoTerminal,
    /// The named box is running and has no terminal. Exit 2.
    NoTerminalInBox {
        /// The box as the caller named it.
        address: String,
    },
    /// With no box named, more than one of the project's boxes can be
    /// attached. Exit 2.
    Ambiguous {
        /// Each box that can be attached.
        candidates: Vec<AddressCandidate>,
    },
    /// With no box named, no box of the project has a terminal. Exit 4.
    NoCandidate,
    /// The named box is stopped or exited and has no terminal, so it
    /// cannot resume. Exit 2.
    NoTerminalToResume {
        /// The box as the caller named it.
        address: String,
        /// Whether the box's spec sets `lifetime = "until_stopped"`, so
        /// `min box restart` starts it again. Else `min box run` does.
        until_stopped: bool,
    },
    /// `min box resume` named a box that is not stopped or exited. Exit 2.
    NotResumable {
        /// The box as the caller named it.
        address: String,
        /// The box's state.
        state: String,
        /// Whether the box has a terminal, so `min box attach` can attach
        /// a running box. Else `min box logs` shows its output.
        pty_enabled: bool,
    },
    /// A running box on the same host holds the name of the stopped or
    /// exited box to resume. Exit 2.
    NameHeld {
        /// The box as the caller named it.
        address: String,
        /// The name both boxes have.
        name: String,
        /// The id of the running box that holds the name.
        holder: boxes::SessionId,
        /// The id of the box to resume.
        box_id: boxes::SessionId,
    },
    /// With no session named, more than one of the project's session boxes
    /// can be attached. Exit 2.
    AmbiguousSessions {
        /// Each session box that can be attached.
        candidates: Vec<AddressCandidate>,
    },
    /// With no session named, no session box of the project has a
    /// terminal. Exit 4.
    NoSessionCandidate,
    /// With no box named, a host did not answer the lookup. Exit 7.
    Unreachable {
        /// Each host that did not answer.
        hosts: Vec<String>,
    },
    /// With `--exec`, the box has no exec of that id, live or ended. Exit 4.
    NoSuchExec {
        /// The box as the caller named it.
        address: String,
        /// The exec id as the caller gave it.
        exec_id: String,
    },
    /// With `--exec`, the exec ended. Exit 4.
    ExecEnded {
        /// The box as the caller named it.
        address: String,
        /// The exec's id.
        exec_id: String,
    },
    /// With `--exec`, the exec runs without a terminal. Exit 2.
    NoTerminalInExec {
        /// The box as the caller named it.
        address: String,
        /// The exec's id.
        exec_id: String,
    },
    /// The connection to the box's host failed during the attach. Exit 7.
    ConnectionLost {
        /// The host of the box.
        host: String,
        /// The box, as the messages name it.
        address: String,
    },
}

impl BoxAttachRefusal {
    /// The exit code the command ends with, from the architecture's
    /// reserved codes: 2 for a usage error, 4 for not found, 7 for an
    /// unreachable host.
    pub fn exit_code(&self) -> u8 {
        match self {
            Self::NoTerminal
            | Self::NoTerminalInBox { .. }
            | Self::NoTerminalInExec { .. }
            | Self::NoTerminalToResume { .. }
            | Self::NotResumable { .. }
            | Self::NameHeld { .. }
            | Self::Ambiguous { .. }
            | Self::AmbiguousSessions { .. } => 2,
            Self::NoCandidate
            | Self::NoSessionCandidate
            | Self::NoSuchExec { .. }
            | Self::ExecEnded { .. } => 4,
            Self::Unreachable { .. } | Self::ConnectionLost { .. } => 7,
        }
    }

    /// The outcome the command's tracing event records.
    fn outcome(&self) -> &'static str {
        match self {
            Self::NoTerminal => "no client terminal",
            Self::NoTerminalInBox { .. } => "box has no terminal",
            Self::NoTerminalToResume { .. } => "box has no terminal to resume",
            Self::NotResumable { .. } => "box not stopped",
            Self::NameHeld { .. } => "name held by a running box",
            Self::Ambiguous { .. } | Self::AmbiguousSessions { .. } => "ambiguous",
            Self::NoCandidate | Self::NoSessionCandidate => "no candidate",
            Self::NoSuchExec { .. } => "exec not found",
            Self::ExecEnded { .. } => "exec ended",
            Self::NoTerminalInExec { .. } => "exec has no terminal",
            Self::Unreachable { .. } => "host unreachable",
            Self::ConnectionLost { .. } => "connection lost",
        }
    }
}

impl std::fmt::Display for BoxAttachRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoTerminal => write!(
                f,
                "Cannot attach: stdin is not a terminal. Run `min box attach` from a terminal."
            ),
            Self::NoTerminalInBox { address } => write!(
                f,
                "Box {address} has no terminal to attach to. \
                 Run `min box logs {address}` to see its output."
            ),
            Self::Ambiguous { candidates } => {
                writeln!(f, "More than one box in this project has a terminal:")?;
                write_candidates(f, candidates)?;
                write!(f, "Name one with `min box attach <box>`.")
            }
            Self::AmbiguousSessions { candidates } => {
                writeln!(
                    f,
                    "More than one session box in this project has a terminal:"
                )?;
                write_candidates(f, candidates)?;
                write!(f, "Name one with `min session attach <box>`.")
            }
            Self::NoCandidate => write!(
                f,
                "No box with a terminal in this project. Start one with min box start."
            ),
            Self::NoSessionCandidate => write!(
                f,
                "No session box with a terminal in this project. \
                 Start one with min session start."
            ),
            // BCLI-009: the exact wording the plan task fixes.
            Self::NoTerminalToResume {
                address,
                until_stopped,
            } => {
                writeln!(f, "{address} has no terminal to resume.")?;
                if *until_stopped {
                    write!(f, "Restart it with min box restart {address}.")
                } else {
                    write!(f, "Run it again with min box run <entry>.")
                }
            }
            Self::NotResumable {
                address,
                state,
                pty_enabled,
            } => {
                writeln!(f, "Cannot resume {address}: the box is {state}.")?;
                if state == "running" && *pty_enabled {
                    write!(f, "Attach to it with min box attach {address}.")
                } else if state == "running" {
                    // The same next step as `NoTerminalInBox`: an attach
                    // to a running box with no terminal is refused.
                    write!(f, "Run min box logs {address} to see its output.")
                } else {
                    write!(f, "Only a stopped or exited box can resume.")
                }
            }
            // BCLI-007: names the running box, and the renames that free
            // the name.
            Self::NameHeld {
                address,
                name,
                holder,
                box_id,
            } => {
                writeln!(
                    f,
                    "Cannot resume {address}: the running box {holder} has the name {name}."
                )?;
                writeln!(
                    f,
                    "Rename the running box with min box rename {holder} <new-name>, \
                     or rename this box with min box rename {box_id} <new-name>."
                )?;
                writeln!(f, "Then resume this box with min box resume {box_id}.")?;
                write!(
                    f,
                    "A resume is also refused when another box holds a volume that this box declares."
                )
            }
            // BCLI-068: the exact wording the plan task fixes.
            Self::NoSuchExec { address, exec_id } => {
                write!(f, "{address} has no exec {exec_id}.")
            }
            Self::ExecEnded { address, exec_id } => write!(
                f,
                "Exec {exec_id} has ended. \
                 Read its output with min box logs {address} --exec {exec_id}, \
                 or its exit code with min box wait {address} --exec {exec_id}."
            ),
            Self::NoTerminalInExec { address, exec_id } => write!(
                f,
                "Exec {exec_id} in {address} has no terminal to attach to. \
                 Run `min box logs {address} --exec {exec_id}` to see its output."
            ),
            Self::Unreachable { hosts } => {
                let (noun, verb) = if hosts.len() == 1 {
                    ("host", "answers")
                } else {
                    ("hosts", "answer")
                };
                write!(
                    f,
                    "Could not reach {noun} {}, so no box was chosen. \
                     Run the command again when the {noun} {verb}, \
                     or name the box as provider/host/name.",
                    hosts.join(", ")
                )
            }
            Self::ConnectionLost { host, address } => write!(
                f,
                "The connection to host {host} failed during the attach. \
                 Run `min box attach {address}` to attach again."
            ),
        }
    }
}

impl std::error::Error for BoxAttachRefusal {}

/// One line for each candidate of an ambiguous bare attach.
fn write_candidates(
    f: &mut std::fmt::Formatter<'_>,
    candidates: &[AddressCandidate],
) -> std::fmt::Result {
    for c in candidates {
        let name = if c.name.is_empty() {
            c.box_id.to_string()
        } else {
            c.name.clone()
        };
        writeln!(
            f,
            "  {}/{}/{}  {}  {}",
            c.provider, c.host, name, c.state, c.box_id
        )?;
    }
    Ok(())
}

/// The verb that attaches: `min box attach`, `min box resume`, or
/// `min session attach`, which sees only boxes of type session (BCLI-032).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AttachVerb {
    /// `min box attach`.
    BoxAttach,
    /// `min box resume`.
    BoxResume,
    /// `min session attach`.
    SessionAttach,
}

impl AttachVerb {
    /// The verb as the tracing events record it.
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::BoxAttach => "box attach",
            Self::BoxResume => "box resume",
            Self::SessionAttach => "session attach",
        }
    }

    /// The only Box Type the verb sees, or `None` for every type.
    fn box_type(self) -> Option<&'static str> {
        match self {
            Self::SessionAttach => Some(boxes::SESSION_BOX_TYPE),
            Self::BoxAttach | Self::BoxResume => None,
        }
    }

    /// `listing` with the boxes this verb does not see dropped.
    fn visible(self, listing: &HostListing) -> HostListing {
        let Some(box_type) = self.box_type() else {
            return listing.clone();
        };
        HostListing {
            host: listing.host.clone(),
            boxes: listing.boxes.clone().map(|boxes| {
                boxes
                    .into_iter()
                    .filter(|entry| entry.box_type.as_deref() == Some(box_type))
                    .collect()
            }),
        }
    }
}

/// The box `min box attach` attaches to, and the host that keeps it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BoxAttachTarget {
    /// The host that keeps the box.
    pub host: crate::cmd::list::LocalHost,
    /// The box's id.
    pub box_id: boxes::SessionId,
    /// The box's name, when it has one.
    pub name: Option<String>,
    /// The box as the messages name it: the address the caller gave, else
    /// the box's name, else its id.
    pub label: String,
}

/// How an attach ended: the code the command exits with, and the one
/// stderr line that names why the daemon ended it, if it did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AttachEnding {
    /// The exit code.
    pub code: i32,
    /// The line printed before the exit.
    pub notice: Option<String>,
}

/// What the box's host said of the box once the attach ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum BoxAfterAttach {
    /// The host keeps the box, in this state.
    Listed(minimald_rpc::BoxListingEntry),
    /// The host keeps no such box.
    Gone,
    /// The host did not answer.
    HostSilent,
    /// The host answered with an error, or nobody asked it.
    Unread,
}

/// Refuses an attach from a caller with no terminal on stdin. It runs
/// before any lookup, so the box is not resumed and its state and events
/// do not change.
pub(crate) fn ensure_box_attach_tty(stdin_is_tty: bool) -> Result<(), BoxAttachRefusal> {
    if stdin_is_tty {
        Ok(())
    } else {
        tracing::info!(verb = "box attach", outcome = "no client terminal");
        Err(BoxAttachRefusal::NoTerminal)
    }
}

/// Attaches this terminal to a box: the box `args.target` names, else the
/// current project's box with a terminal (BCLI-068). Ends with the code
/// the attach ended with: 0 for a detach or an entrypoint that exited, 254
/// after one line that names why the daemon ended the attach.
pub async fn cmd_box_attach(global: &GlobalArgs, args: BoxAttachArgs) -> Result<(), anyhow::Error> {
    let stdin_is_tty = std::io::stdin().is_terminal();
    ensure_box_attach_tty(stdin_is_tty)?;
    if let Some(exec_id) = args.exec.as_deref() {
        // clap refuses `--exec` without a box (BCLI-068), so this holds.
        let address = args
            .target
            .as_deref()
            .context("min box attach --exec needs a box")?;
        ensure_daemon(global)?;
        let hosts = crate::cmd::list::local_hosts(global)?;
        let kind = daemon_host_kind(global);
        let ending = box_attach_exec_on_hosts(
            hosts,
            address,
            exec_id,
            stdin_is_tty,
            async |target: &BoxAttachTarget, exec_id: &minimald_rpc::exec::ExecId| {
                attach_exec_by_id(kind, &target.host.sock, target.box_id, exec_id).await
            },
        )
        .await?;
        if let Some(notice) = &ending.notice {
            eprintln!("{notice}");
        }
        return Err(Handoff::Exit(ending.code).into());
    }
    attach_command(global, AttachVerb::BoxAttach, args.target.as_deref()).await
}

/// `min box resume <box>`: attaches this terminal to the box, which
/// resumes a stopped or exited box that has a terminal (BCLI-007). A box
/// in any other state is refused.
pub async fn cmd_box_resume(global: &GlobalArgs, args: BoxResumeArgs) -> Result<(), anyhow::Error> {
    attach_command(global, AttachVerb::BoxResume, Some(&args.target)).await
}

/// `min session attach [<box>]`: `min box attach` that sees only boxes of
/// type session (BCLI-032).
pub async fn cmd_session_attach(
    global: &GlobalArgs,
    target: Option<&str>,
) -> Result<(), anyhow::Error> {
    attach_command(global, AttachVerb::SessionAttach, target).await
}

/// The attach of `verb` to the box `target` names, else to the current
/// project's box with a terminal. A stopped or exited box resumes.
async fn attach_command(
    global: &GlobalArgs,
    verb: AttachVerb,
    target: Option<&str>,
) -> Result<(), anyhow::Error> {
    let stdin_is_tty = std::io::stdin().is_terminal();
    ensure_box_attach_tty(stdin_is_tty)?;
    let scope = match target {
        Some(_) => None,
        None => {
            let cwd = crate::attach::cwd_host_path(global)?;
            Some(box_list_scope(cwd.as_ref())?)
        }
    };
    ensure_daemon(global)?;
    let hosts = crate::cmd::list::local_hosts(global)?;
    let hosts = match target {
        Some(address) => named_attach_hosts(global, hosts, verb, address).await?,
        None => hosts,
    };
    let kind = daemon_host_kind(global);
    let ending = attach_on_hosts(
        verb,
        hosts,
        target,
        scope.as_ref(),
        stdin_is_tty,
        async |target: &BoxAttachTarget| {
            let host_asks = host_asks_box(global, target.name.as_deref());
            ssh_exit_code(
                box_via_ssh(
                    kind,
                    &target.host.sock,
                    target.box_id,
                    None,
                    global.config_dir.as_deref(),
                    host_asks.as_deref(),
                )
                .await,
            )
        },
    )
    .await?;
    if let Some(notice) = &ending.notice {
        eprintln!("{notice}");
    }
    Err(Handoff::Exit(ending.code).into())
}

/// The hosts a named attach of `verb` looks on (NET-058). For a name or an
/// id with no `--vm`, the selected VM's daemon is asked first, and its
/// answer is gated on the daemon's build. A name that a second VM also
/// holds is refused as ambiguous. When the selected VM does not know the
/// name, [`crate::attach::resolve_box_vm`] finds the VM that owns it. The
/// process then acts on that VM, as `--vm` makes it, and the attach
/// announces the VM. A box only a stopped VM holds is refused with the
/// command that starts that VM. The attach then looks only on the host
/// that holds the box. When no VM knows the name, every host stays, and
/// [`attach_target`] refuses the address. A `provider/host/name` address
/// names its host, so it keeps every host.
pub(crate) async fn named_attach_hosts(
    global: &GlobalArgs,
    hosts: Vec<crate::cmd::list::LocalHost>,
    verb: AttachVerb,
    address: &str,
) -> Result<Vec<crate::cmd::list::LocalHost>, anyhow::Error> {
    let BoxAddress::Unqualified(name) = parse_box_address(address) else {
        return Ok(hosts);
    };
    if global.vm.is_some() {
        return Ok(hosts);
    }
    let Some(selected) = hosts.iter().find(|h| h.selected).cloned() else {
        return Ok(hosts);
    };
    let mut client = client::Client::connect(&selected.sock)
        .await
        .context("Failed to connect to minimald")?;
    let sock = match resolve_session_version_gated(&mut client, name).await {
        Ok(record) => {
            // A second VM that holds the name makes it ambiguous.
            ensure_selected_holds_box_alone(global, name, &record).await?;
            selected.sock
        }
        Err(missed) => match crate::attach::resolve_box_vm(global, name).await? {
            Some(resolved) => {
                // From here the process acts on the owning VM, as `--vm`
                // makes it. A second set is a no-op.
                let _ = client::set_vm_name(&resolved.vm);
                tracing::info!(
                    verb = verb.name(),
                    box_id = %resolved.record.id,
                    vm = %resolved.vm,
                    outcome = "resolved on another VM"
                );
                // The user did not choose the VM, so say which one it is.
                if should_announce_box(global) {
                    let noun = match verb {
                        AttachVerb::SessionAttach => "session",
                        AttachVerb::BoxAttach | AttachVerb::BoxResume => "box",
                    };
                    eprintln!(
                        "Attaching to {noun} {} on VM {}",
                        box_announce_label(&resolved.record.id, resolved.record.name.as_deref()),
                        resolved.vm
                    );
                }
                resolved.sock
            }
            // No VM knows the name: the address refusal of every host is
            // the answer.
            None if missed.downcast_ref::<crate::cmd::BoxNotFound>().is_some() => {
                return Ok(hosts);
            }
            // The selected daemon's own failure, such as a version skew.
            None => return Err(missed),
        },
    };
    if hosts.iter().any(|h| h.sock == sock) {
        Ok(hosts.into_iter().filter(|h| h.sock == sock).collect())
    } else {
        Ok(hosts)
    }
}

/// What the box's records say of an exec id that `min box attach --exec`
/// names, in the order its refusals are checked (BCLI-068).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExecFound {
    /// The box has no exec of that id, live or ended.
    Unknown,
    /// The exec ended.
    Ended,
    /// The exec runs without a terminal.
    NoTerminal,
    /// The exec runs with a terminal.
    Terminal,
}

/// Classifies the exec `exec_id` of a box. The host's `live_execs`
/// (BOX-159) decide whether the exec runs and whether it holds a PTY. For
/// an id the host does not list, `events` is read only when the caller
/// passes it. A started exec has then ended, and an id with no start was
/// never an exec of this box.
pub(crate) fn exec_found(
    live_execs: &[minimald_rpc::LiveExec],
    events: Option<&[boxes::events::BoxEvent]>,
    exec_id: &str,
) -> ExecFound {
    use boxes::events::{BoxEventType, exec_data};

    if let Some(live) = live_execs.iter().find(|exec| exec.id == exec_id) {
        return if live.mode == minimald_rpc::exec::ExecMode::Tty {
            ExecFound::Terminal
        } else {
            ExecFound::NoTerminal
        };
    }
    let started = events.is_some_and(|events| {
        events.iter().any(|event| {
            event.kind == BoxEventType::ExecStarted
                && event.data.get(exec_data::EXEC_ID).and_then(|v| v.as_str()) == Some(exec_id)
        })
    });
    if started {
        ExecFound::Ended
    } else {
        ExecFound::Unknown
    }
}

/// Every event the box `box_id` kept, read once. `address` names the box
/// in the errors.
async fn read_kept_events(
    client: &mut client::Client,
    box_id: boxes::SessionId,
    address: &str,
) -> Result<Vec<boxes::events::BoxEvent>, anyhow::Error> {
    use minimald_rpc::ReadEventsUpdate;

    let unreadable = || {
        anyhow::anyhow!(
            "Could not read the events of box {address}, so the exec was not found. \
             Run `min box show {address}` to check that the box still exists."
        )
    };
    let mut lines = client.read_box_events(box_id, false).await.map_err(|e| {
        tracing::warn!(verb = "box attach", box_id = %box_id, "open the events read: {e:#}");
        unreadable()
    })?;
    let mut events = Vec::new();
    loop {
        let line = match lines.next_line().await {
            Ok(Some(line)) => line,
            Ok(None) => {
                tracing::warn!(verb = "box attach", box_id = %box_id, "the events read ended early");
                return Err(unreadable());
            }
            Err(e) => {
                tracing::warn!(verb = "box attach", box_id = %box_id, "read an events line: {e:#}");
                return Err(unreadable());
            }
        };
        match serde_json_lenient::from_str::<ReadEventsUpdate>(&line) {
            Ok(ReadEventsUpdate::Event { event }) => events.push(event),
            Ok(ReadEventsUpdate::Done | ReadEventsUpdate::Reaped) => return Ok(events),
            Ok(ReadEventsUpdate::Failed { error }) => {
                tracing::warn!(verb = "box attach", box_id = %box_id, "the events read failed: {error}");
                return Err(unreadable());
            }
            Err(e) => {
                tracing::warn!(verb = "box attach", box_id = %box_id, line, "decode an events line: {e}");
                return Err(unreadable());
            }
        }
    }
}

/// The box and the exec `min box attach <box> --exec <id>` attaches to.
/// The box resolves as every `min box` verb resolves an address. The exec
/// is refused when the box has no exec of that id, then when it ended,
/// then when it has no terminal (BCLI-068).
pub(crate) async fn box_attach_exec_target(
    hosts: Vec<crate::cmd::list::LocalHost>,
    address: &str,
    exec_id: &str,
) -> Result<(BoxAttachTarget, minimald_rpc::exec::ExecId), anyhow::Error> {
    use minimald_rpc::{Errorable, ShowBox, ShowBoxRequest};

    let ResolvedBox { host, box_id } = resolve_box_on_hosts(hosts, address, "box attach").await?;
    let mut client = box_host_client(&host).await?;
    let shown = match client
        .oneshot_rpc::<ShowBox>(ShowBoxRequest { id: box_id })
        .await
        .context("ShowBox RPC failed")?
    {
        Errorable::Ok(shown) => shown,
        Errorable::Err { error } if error.starts_with(minimald_rpc::UNKNOWN_SESSION_ID_LEAD) => {
            tracing::info!(verb = "box attach", box_id = %box_id, outcome = "not found");
            return Err(BoxAddressRefusal::NotFound {
                address: address.to_owned(),
            }
            .into());
        }
        Errorable::Err { error } => bail!("{error}"),
    };
    let parsed = minimald_rpc::exec::ExecId::parse(exec_id).ok();
    let found = match &parsed {
        Some(id) if shown.live_execs.iter().any(|exec| exec.id == id.as_str()) => {
            exec_found(&shown.live_execs, None, id.as_str())
        }
        Some(id) => {
            let events = read_kept_events(&mut client, box_id, address).await?;
            exec_found(&shown.live_execs, Some(&events), id.as_str())
        }
        None => ExecFound::Unknown,
    };
    let refusal = match found {
        ExecFound::Unknown => Some(BoxAttachRefusal::NoSuchExec {
            address: address.to_owned(),
            exec_id: exec_id.to_owned(),
        }),
        ExecFound::Ended => Some(BoxAttachRefusal::ExecEnded {
            address: address.to_owned(),
            exec_id: exec_id.to_owned(),
        }),
        ExecFound::NoTerminal => Some(BoxAttachRefusal::NoTerminalInExec {
            address: address.to_owned(),
            exec_id: exec_id.to_owned(),
        }),
        ExecFound::Terminal => None,
    };
    if let Some(refusal) = refusal {
        tracing::info!(
            verb = "box attach",
            box_id = %box_id,
            exec_id,
            outcome = refusal.outcome()
        );
        return Err(refusal.into());
    }
    let exec_id = parsed.expect("only a parsed id names a terminal exec");
    Ok((
        BoxAttachTarget {
            host,
            box_id,
            name: shown.record.name,
            label: address.to_owned(),
        },
        exec_id,
    ))
}

/// `min box attach <box> --exec <id>` over the local `hosts`: refuses a
/// caller with no terminal, finds the box and the exec
/// ([`box_attach_exec_target`]), runs `attach` on them, and reads how the
/// attach ended ([`exec_attach_ending`]).
pub(crate) async fn box_attach_exec_on_hosts<A>(
    hosts: Vec<crate::cmd::list::LocalHost>,
    address: &str,
    exec_id: &str,
    stdin_is_tty: bool,
    attach: A,
) -> Result<AttachEnding, anyhow::Error>
where
    A: AsyncFnOnce(&BoxAttachTarget, &minimald_rpc::exec::ExecId) -> Result<i32, anyhow::Error>,
{
    ensure_box_attach_tty(stdin_is_tty)?;
    let (target, exec_id) = box_attach_exec_target(hosts, address, exec_id).await?;
    tracing::info!(
        verb = "box attach",
        box_id = %target.box_id,
        host = %target.host.host,
        exec_id = %exec_id,
        outcome = "attaching"
    );
    let code = attach(&target, &exec_id).await.inspect_err(|err| {
        tracing::info!(verb = "box attach", box_id = %target.box_id, exec_id = %exec_id, outcome = "error", "{err:#}");
    })?;
    if code == SSH_CONNECTION_FAILED {
        let refusal = BoxAttachRefusal::ConnectionLost {
            host: target.host.host.clone(),
            address: format!("{} --exec {exec_id}", target.label),
        };
        tracing::info!(
            verb = "box attach",
            box_id = %target.box_id,
            exec_id = %exec_id,
            outcome = refusal.outcome(),
            "{refusal}"
        );
        return Err(refusal.into());
    }
    // A stop ends the exec, by its signal or with its own code, before the
    // daemon writes the stopped record, so every code reads the box again.
    let settle = if code == DAEMON_ENDED_ATTACH {
        DAEMON_END_SETTLE
    } else {
        ENTRYPOINT_END_SETTLE
    };
    let after = box_after_attach_settled(&target.host, target.box_id, settle).await;
    let ending = exec_attach_ending(&target, &exec_id, code, &after)?;
    tracing::info!(
        verb = "box attach",
        box_id = %target.box_id,
        exec_id = %exec_id,
        exec_exit = code,
        exit = ending.code,
        outcome = if ending.code == DAEMON_ENDED_ATTACH { "ended by the host" } else { "ended" },
        "attach ended"
    );
    Ok(ending)
}

/// How an exec attach that ended with ssh's `code` ends the command, from
/// what the host said of the box afterwards. It follows [`attach_ending`]:
/// a stop, a removal or another terminal's attach ends with 254 and its
/// line. A detach or the exec's own end is 0, whatever code the exec ended
/// with. `min box wait <box> --exec <id>` reads that code. ssh's own 255 is
/// a lost connection, and its retry names `--exec <id>`.
pub(crate) fn exec_attach_ending(
    target: &BoxAttachTarget,
    exec_id: &minimald_rpc::exec::ExecId,
    code: i32,
    after: &BoxAfterAttach,
) -> Result<AttachEnding, BoxAttachRefusal> {
    match (code, after) {
        (SSH_CONNECTION_FAILED, _) => Err(BoxAttachRefusal::ConnectionLost {
            host: target.host.host.clone(),
            address: format!("{} --exec {exec_id}", target.label),
        }),
        (DAEMON_ENDED_ATTACH, _) => attach_ending(target, code, after),
        (_, BoxAfterAttach::Gone) => Ok(AttachEnding {
            code: DAEMON_ENDED_ATTACH,
            notice: Some(format!("Detached: {} was removed.", target.label)),
        }),
        // A stopped box ends with 254 and its line. Any other box ends
        // with 0: the exec ended by itself or the caller detached.
        _ => attach_ending(target, 0, after),
    }
}

/// Connects this terminal to the terminal exec `exec_id` in box `id` on
/// the daemon at `sock`, through `ssh -tt`, as `min box exec -t` does after
/// it starts one. Returns ssh's exit status, which is the exec's.
async fn attach_exec_by_id(
    kind: paths::HostKind,
    sock: &std::path::Path,
    id: boxes::SessionId,
    exec_id: &minimald_rpc::exec::ExecId,
) -> Result<i32, anyhow::Error> {
    // A VM-backed box gets its row and its name hold back first, as
    // `min box exec` does.
    let record = match control_sock_beside(sock).filter(|control| control.exists()) {
        Some(_) => attached_box_record(sock, id).await.unwrap_or_else(|error| {
            tracing::warn!(
                "could not read the box's record ({error:#}); its box row is not asked back first"
            );
            None
        }),
        None => None,
    };
    resume_box_row(sock, record.as_ref()).await?;
    rehold_held_name_before_attach(kind, sock, id, record.as_ref()).await;

    let wire = minimald_rpc::exec::ExecRequest::ExecAttach(exec_id.clone()).encode();
    let ssh = minimal_client::attach::attach_command(sock, id, Some(&wire), None)?;
    // `-tt` before the other arguments, so ssh asks for a terminal.
    let mut forced = std::process::Command::new(ssh.get_program());
    forced.arg("-tt").args(ssh.get_args());
    for (name, value) in ssh.get_envs() {
        match value {
            Some(value) => forced.env(name, value),
            None => forced.env_remove(name),
        };
    }
    tokio::task::spawn_blocking(move || {
        interactive_attach(forced, true, crate::attach::TerminalUnwind::arm, |ssh| {
            let real = minimal_client::tty_relay::RealTty::acquire()
                .context(crate::attach::TerminalNotTaken)?;
            minimal_client::attach::run_interactive_attach_on(ssh, real, None)
        })
    })
    .await
    .context("the terminal attach's thread failed")?
}

/// The exit code an attach through [`box_via_ssh`] ended with: the code of
/// its exit hand-off. Any other error is the error.
pub(crate) fn ssh_exit_code(attached: Result<(), anyhow::Error>) -> Result<i32, anyhow::Error> {
    match attached {
        Ok(()) => Ok(0),
        Err(e) => match e.downcast_ref::<Handoff>() {
            Some(Handoff::Exit(code)) => Ok(*code),
            _ => Err(e),
        },
    }
}

/// An attach of `verb` over the local `hosts`: `min box attach`,
/// `min box resume` or `min session attach`. It refuses a caller with no
/// terminal, finds the box ([`attach_target`]), runs `attach` on it, and
/// reads how the attach ended ([`attach_ending`]). `scope` is the current
/// project's root, which the bare form reads.
pub(crate) async fn attach_on_hosts<A>(
    verb: AttachVerb,
    hosts: Vec<crate::cmd::list::LocalHost>,
    address: Option<&str>,
    scope: Option<&paths::HostAbsPath>,
    stdin_is_tty: bool,
    attach: A,
) -> Result<AttachEnding, anyhow::Error>
where
    A: AsyncFnOnce(&BoxAttachTarget) -> Result<i32, anyhow::Error>,
{
    let name = verb.name();
    ensure_box_attach_tty(stdin_is_tty)?;
    let target = attach_target(verb, hosts, address, scope).await?;
    tracing::info!(
        verb = name,
        box_id = %target.box_id,
        host = %target.host.host,
        outcome = "attaching"
    );
    let code = attach(&target).await.inspect_err(|err| {
        tracing::info!(verb = name, box_id = %target.box_id, outcome = "error", "{err:#}");
    })?;
    let after = match code {
        0 => box_after_attach_settled(&target.host, target.box_id, ENTRYPOINT_END_SETTLE).await,
        DAEMON_ENDED_ATTACH => {
            box_after_attach_settled(&target.host, target.box_id, DAEMON_END_SETTLE).await
        }
        _ => BoxAfterAttach::Unread,
    };
    match attach_ending(&target, code, &after) {
        Ok(ending) => {
            tracing::info!(
                verb = name,
                box_id = %target.box_id,
                exit = ending.code,
                outcome = if ending.code == DAEMON_ENDED_ATTACH { "ended by the host" } else { "ended" },
                "attach ended"
            );
            Ok(ending)
        }
        Err(refusal) => {
            tracing::info!(
                verb = name,
                box_id = %target.box_id,
                outcome = refusal.outcome(),
                "{refusal}"
            );
            Err(refusal.into())
        }
    }
}

/// The box an attach of `verb` goes to, among the boxes the verb sees. A
/// named box is resolved as every `min box` verb resolves an address. A
/// running box with no terminal is refused, and so is a stopped or exited
/// one, with the command that starts it again (BCLI-009). With no box
/// named, the current project's running box with a terminal is the one,
/// else its only stopped or exited box with a terminal. Every host must
/// answer that lookup. `min box resume` of a named box that is not stopped
/// or exited is refused before the box's terminal checks. A stopped or
/// exited box with a terminal resumes in the attach, so it is refused here
/// when a running box on its host holds its name (BCLI-007). That check
/// comes after the box's terminal checks, as the host checks. The caller's
/// terminal is checked before this lookup ([`attach_on_hosts`]).
pub(crate) async fn attach_target(
    verb: AttachVerb,
    mut hosts: Vec<crate::cmd::list::LocalHost>,
    address: Option<&str>,
    scope: Option<&paths::HostAbsPath>,
) -> Result<BoxAttachTarget, anyhow::Error> {
    use minimald_rpc::{Errorable, ShowBox, ShowBoxRequest};

    let name = verb.name();
    let refuse = |refusal: BoxAttachRefusal, box_id: Option<boxes::SessionId>| {
        match box_id {
            Some(box_id) => {
                tracing::info!(verb = name, box_id = %box_id, outcome = refusal.outcome(), "{refusal}");
            }
            None => tracing::info!(verb = name, outcome = refusal.outcome(), "{refusal}"),
        }
        anyhow::Error::from(refusal)
    };
    if let Some(BoxAddress::Qualified { provider, host, .. }) = address.map(parse_box_address) {
        hosts.retain(|h| h.provider == provider && h.host == host);
    }
    let mut listings = Vec::with_capacity(hosts.len());
    for host in hosts {
        let boxes = read_host_boxes(&host).await.inspect_err(|err| {
            tracing::info!(verb = name, outcome = "error", host = %host.host, "{err:#}");
        })?;
        listings.push(HostListing { host, boxes });
    }
    let visible: Vec<HostListing> = listings.iter().map(|l| verb.visible(l)).collect();

    let Some(address) = address else {
        let target = project_attach_target(&visible, scope).map_err(|refusal| {
            let refusal = match (verb, refusal) {
                (AttachVerb::SessionAttach, BoxAttachRefusal::NoCandidate) => {
                    BoxAttachRefusal::NoSessionCandidate
                }
                (AttachVerb::SessionAttach, BoxAttachRefusal::Ambiguous { candidates }) => {
                    BoxAttachRefusal::AmbiguousSessions { candidates }
                }
                (_, refusal) => refusal,
            };
            refuse(refusal, None)
        })?;
        let state = visible
            .iter()
            .filter(|l| l.host == target.host)
            .filter_map(|l| l.boxes.as_ref().ok())
            .flatten()
            .find(|e| e.box_id == target.box_id)
            .map(|e| e.state.clone())
            .unwrap_or_default();
        if let Some(refusal) = name_held(&listings, &target, &state) {
            return Err(refuse(refusal, Some(target.box_id)));
        }
        return Ok(target);
    };
    let ResolvedBox { host, box_id } = match resolve_box_address(address, &visible) {
        Ok(resolved) => {
            tracing::info!(
                verb = name,
                box_id = %resolved.box_id,
                host = %resolved.host.host,
                outcome = "resolved"
            );
            resolved
        }
        Err(refusal) => {
            for listing in &listings {
                if let Err(why) = &listing.boxes {
                    tracing::info!(verb = name, host = %listing.host.host, "host did not answer: {why}");
                }
            }
            tracing::info!(verb = name, address, outcome = "refused", "{refusal}");
            return Err(refusal.into());
        }
    };
    let mut client = box_host_client(&host).await?;
    let shown = match client
        .oneshot_rpc::<ShowBox>(ShowBoxRequest { id: box_id })
        .await
        .context("ShowBox RPC failed")?
    {
        Errorable::Ok(shown) => shown,
        Errorable::Err { error } if error.starts_with(minimald_rpc::UNKNOWN_SESSION_ID_LEAD) => {
            // The box was removed after the address resolved.
            tracing::info!(verb = name, box_id = %box_id, outcome = "not found");
            return Err(BoxAddressRefusal::NotFound {
                address: address.to_owned(),
            }
            .into());
        }
        Errorable::Err { error } => bail!("{error}"),
    };
    let record = shown.record;
    let retained = matches!(record.state.as_str(), "stopped" | "exited");
    // Only a stopped or exited box resumes. This check comes before the
    // box's terminal checks, so a running box is sent to `min box attach`.
    if verb == AttachVerb::BoxResume && !retained {
        let refusal = BoxAttachRefusal::NotResumable {
            address: address.to_owned(),
            state: record.state.clone(),
            pty_enabled: record.pty_enabled,
        };
        return Err(refuse(refusal, Some(box_id)));
    }
    if !record.pty_enabled && record.state == "running" {
        let refusal = BoxAttachRefusal::NoTerminalInBox {
            address: address.to_owned(),
        };
        return Err(refuse(refusal, Some(box_id)));
    }
    // BCLI-009: a stopped or exited box with no terminal cannot resume.
    // The hint follows the spec's lifetime, not the Box Type.
    if !record.pty_enabled && retained {
        let refusal = BoxAttachRefusal::NoTerminalToResume {
            address: address.to_owned(),
            until_stopped: record.lifetime.as_deref() == Some("until_stopped"),
        };
        return Err(refuse(refusal, Some(box_id)));
    }
    let target = BoxAttachTarget {
        host,
        box_id,
        name: record.name,
        label: address.to_owned(),
    };
    if let Some(refusal) = name_held(&listings, &target, &record.state) {
        return Err(refuse(refusal, Some(box_id)));
    }
    Ok(target)
}

/// The refusal for a resume of `target`, in `state`, whose name a running
/// box on the same host holds (BCLI-007). Boxes of every type hold names,
/// so `listings` is every box each host listed. `None` for a box that is
/// not stopped or exited, a box with no name, and a name nobody holds.
fn name_held(
    listings: &[HostListing],
    target: &BoxAttachTarget,
    state: &str,
) -> Option<BoxAttachRefusal> {
    if !matches!(state, "stopped" | "exited") {
        return None;
    }
    let name = target.name.as_deref().filter(|name| !name.is_empty())?;
    let holder = listings
        .iter()
        .filter(|l| l.host == target.host)
        .filter_map(|l| l.boxes.as_ref().ok())
        .flatten()
        .find(|e| {
            e.state == "running" && e.box_id != target.box_id && e.name.as_deref() == Some(name)
        })?;
    Some(BoxAttachRefusal::NameHeld {
        address: target.label.clone(),
        name: name.to_owned(),
        holder: holder.box_id,
        box_id: target.box_id,
    })
}

/// The bare form's choice over what each host answered: of the boxes of
/// the project at `scope` that have a terminal, the one running box, else
/// the one stopped or exited box. A host that did not answer chooses
/// nothing, because the box can be on that host.
pub(crate) fn project_attach_target(
    listings: &[HostListing],
    scope: Option<&paths::HostAbsPath>,
) -> Result<BoxAttachTarget, BoxAttachRefusal> {
    let silent: Vec<String> = listings
        .iter()
        .filter(|l| l.boxes.is_err())
        .map(|l| l.host.host.clone())
        .collect();
    if !silent.is_empty() {
        return Err(BoxAttachRefusal::Unreachable { hosts: silent });
    }
    let candidates: Vec<(&HostListing, &minimald_rpc::BoxListingEntry)> = listings
        .iter()
        .filter_map(|l| l.boxes.as_ref().ok().map(|boxes| (l, boxes)))
        .flat_map(|(l, boxes)| boxes.iter().map(move |e| (l, e)))
        .filter(|(_, e)| e.pty_enabled && e.project_root.as_ref() == scope)
        .collect();
    let in_state = |states: &[&str]| -> Vec<_> {
        candidates
            .iter()
            .filter(|(_, e)| states.contains(&e.state.as_str()))
            .copied()
            .collect()
    };
    let running = in_state(&["running"]);
    let chosen = if running.is_empty() {
        in_state(&["stopped", "exited"])
    } else {
        running
    };
    match chosen.as_slice() {
        [] => Err(BoxAttachRefusal::NoCandidate),
        [(listing, entry)] => Ok(BoxAttachTarget {
            host: listing.host.clone(),
            box_id: entry.box_id,
            name: entry.name.clone(),
            label: entry
                .name
                .clone()
                .unwrap_or_else(|| entry.box_id.to_string()),
        }),
        several => Err(BoxAttachRefusal::Ambiguous {
            candidates: several
                .iter()
                .map(|(l, e)| AddressCandidate {
                    provider: l.host.provider.to_owned(),
                    host: l.host.host.clone(),
                    name: e.name.clone().unwrap_or_default(),
                    state: box_state_label(e),
                    box_id: e.box_id,
                })
                .collect(),
        }),
    }
}

/// What `host` says of box `id` once an attach to it ended. The host is
/// probed once, under the probe bound, so a host that went down does not
/// hold the exit.
pub(crate) async fn box_after_attach(
    host: &crate::cmd::list::LocalHost,
    id: boxes::SessionId,
) -> BoxAfterAttach {
    use minimald_rpc::{Errorable, ShowBox, ShowBoxRequest};

    let read = tokio::time::timeout(client::PROBE_TIMEOUT, async {
        let mut client = match client::Client::probe(&host.sock).await {
            Ok(client) => client,
            Err(client::ProbeRefusal::NotRunning) => return BoxAfterAttach::HostSilent,
            Err(client::ProbeRefusal::Unreachable(e)) => {
                tracing::debug!(host = %host.host, "the host did not answer after the attach: {e:#}");
                return BoxAfterAttach::HostSilent;
            }
        };
        match client.oneshot_rpc::<ShowBox>(ShowBoxRequest { id }).await {
            Ok(Errorable::Ok(shown)) => BoxAfterAttach::Listed(shown.record),
            Ok(Errorable::Err { error })
                if error.starts_with(minimald_rpc::UNKNOWN_SESSION_ID_LEAD) =>
            {
                BoxAfterAttach::Gone
            }
            Ok(Errorable::Err { error }) => {
                tracing::debug!(host = %host.host, "could not read the box after the attach: {error}");
                BoxAfterAttach::Unread
            }
            Err(e) => {
                tracing::debug!(host = %host.host, "the host did not answer after the attach: {e:#}");
                BoxAfterAttach::HostSilent
            }
        }
    })
    .await;
    read.unwrap_or(BoxAfterAttach::HostSilent)
}

/// How long the read after an attach that ended with 0 waits for a box
/// that still reads `running` to leave it. A stop can end the entrypoint,
/// and the attach with it, before the daemon writes the stopped record: it
/// writes the record once it reaps the entrypoint. A detach leaves the box
/// running, so this bound is also what every detach waits.
pub(crate) const ENTRYPOINT_END_SETTLE: std::time::Duration = std::time::Duration::from_millis(500);

/// How long the read after an attach the daemon ended (254) waits for a box
/// that still reads `running` to leave it. A stop or a removal closes the
/// channel before the daemon writes the record. A stop writes it only once
/// the entrypoint and every process in the box ended, or after its grace
/// period and one more probe bound. A box that still runs at the bound lost
/// its terminal to another attach. A takeover waits the whole bound.
pub(crate) const DAEMON_END_SETTLE: std::time::Duration =
    minimald_rpc::STOP_GRACE.saturating_add(minimald_rpc::HOST_PROBE_TIMEOUT);

/// How often the settled read asks the host again.
const SETTLE_POLL: std::time::Duration = std::time::Duration::from_millis(50);

/// What `host` says of box `id` once an attach to it ended, read again
/// until the box no longer reads `running` or `settle` is over. The channel
/// of an attach can close before the record says why (see
/// [`DAEMON_END_SETTLE`]), so one read straight after the attach can see a
/// box that a stop is about to record as stopped.
pub(crate) async fn box_after_attach_settled(
    host: &crate::cmd::list::LocalHost,
    id: boxes::SessionId,
    settle: std::time::Duration,
) -> BoxAfterAttach {
    let deadline = tokio::time::Instant::now() + settle;
    let mut reads = 0u32;
    loop {
        let after = box_after_attach(host, id).await;
        reads += 1;
        let running = matches!(&after, BoxAfterAttach::Listed(entry) if entry.state == "running");
        if !running || tokio::time::Instant::now() >= deadline {
            tracing::debug!(
                box_id = %id,
                reads,
                still_running = running,
                "read the box after the attach"
            );
            return after;
        }
        tokio::time::sleep(SETTLE_POLL).await;
    }
}

/// How an attach that ended with ssh's `code` ends the command, from what
/// the host said of the box afterwards.
///
/// A daemon that ended the attach reports 254, and the line names why: the
/// box was stopped or removed, another terminal attached to it, or its host
/// shut down or stopped answering. A stop can also end the entrypoint, which
/// the daemon reports as 0, so a box that is `stopped` ends with 254 too,
/// whatever exit code its entrypoint recorded. A 254 against a box that
/// reads `exited` ends with 0 and its line, since the entrypoint ended by
/// itself. ssh's own 255 is a lost connection, exit 7, whatever the host
/// says afterwards. Every other code is the code: 0 for a detach or an
/// entrypoint that exited.
pub(crate) fn attach_ending(
    target: &BoxAttachTarget,
    code: i32,
    after: &BoxAfterAttach,
) -> Result<AttachEnding, BoxAttachRefusal> {
    let label = &target.label;
    let ended = |line: String| {
        Ok(AttachEnding {
            code: DAEMON_ENDED_ATTACH,
            notice: Some(line),
        })
    };
    let stopped = |entry: &minimald_rpc::BoxListingEntry| entry.state == "stopped";
    match (code, after) {
        (SSH_CONNECTION_FAILED, _) => {
            // ssh's own failure is a lost connection whether or not the
            // host answers the read afterwards.
            Err(BoxAttachRefusal::ConnectionLost {
                host: target.host.host.clone(),
                address: label.clone(),
            })
        }
        (DAEMON_ENDED_ATTACH, BoxAfterAttach::Listed(entry)) if stopped(entry) => {
            ended(format!("Detached: {label} was stopped."))
        }
        (DAEMON_ENDED_ATTACH, BoxAfterAttach::Listed(entry)) if entry.state == "running" => {
            ended(format!("Detached: another terminal attached to {label}."))
        }
        (DAEMON_ENDED_ATTACH, BoxAfterAttach::Listed(entry)) if entry.state == "exited" => {
            // The box's entrypoint ended by itself, so the attach ended
            // normally. The line still says how the box ended.
            Ok(AttachEnding {
                code: 0,
                notice: Some(ended_box_line(label, entry)),
            })
        }
        (DAEMON_ENDED_ATTACH, BoxAfterAttach::Listed(entry)) => ended(ended_box_line(label, entry)),
        (DAEMON_ENDED_ATTACH, BoxAfterAttach::Gone) => {
            ended(format!("Detached: {label} was removed."))
        }
        (DAEMON_ENDED_ATTACH, BoxAfterAttach::HostSilent) => {
            // The host did not answer the read: it shut down, its daemon
            // stopped, or it cannot be reached.
            ended(format!(
                "Detached: host {} shut down or stopped answering.",
                target.host.host
            ))
        }
        (DAEMON_ENDED_ATTACH, BoxAfterAttach::Unread) => {
            // The host answered the read with an error, so the record does
            // not say why the attach ended.
            ended(format!(
                "Detached: host {} ended the attach to {label}.",
                target.host.host
            ))
        }
        (0, BoxAfterAttach::Listed(entry)) if stopped(entry) => {
            ended(format!("Detached: {label} was stopped."))
        }
        _ => Ok(AttachEnding { code, notice: None }),
    }
}

/// The line for a box the daemon ended the attach of that is neither
/// running nor stopped.
fn ended_box_line(label: &str, entry: &minimald_rpc::BoxListingEntry) -> String {
    // An OOM record also stores an exit code (`OOM_EXIT_CODE`, 137), so
    // the reason is matched before the code.
    match (entry.exit_code, entry.reason.as_deref()) {
        (_, Some("oom")) => format!("Detached: {label} ran out of memory and ended."),
        (Some(code), _) => format!("Detached: {label} exited with code {code}."),
        (None, Some("timeout")) => format!("Detached: {label} ran past its timeout and ended."),
        _ => format!("Detached: {label} is {}.", box_state_label(entry)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use boxes::{DynamicIngress, IngressPolicy, NetworkMode};
    use minimal_client::box_registration::{RegisteredWithVmHost, register_box_for_activation};

    /// A box whose record was read and carries no address pair registered no
    /// row with the VM host daemon: the attach gets no subscription target,
    /// so no control-socket request is made. That covers a `host_ip` or
    /// `none` box.
    #[test]
    fn host_asks_target_is_none_for_a_box_with_no_address_pair() {
        let control = std::path::PathBuf::from("/run/vm/control.sock");
        assert_eq!(
            host_asks_target(Some(control), Some("web"), None, false),
            None
        );
    }

    /// A record that could not be read does not say the box has no row: the
    /// subscription is still attempted, at the control socket and under the
    /// box's name, so an `own_ip` box keeps its port prompts. A native host
    /// (no box named) or a missing control socket still yields none.
    #[test]
    fn host_asks_target_names_the_box_when_its_record_is_unreadable() {
        let control = std::path::PathBuf::from("/run/vm/control.sock");
        assert_eq!(
            host_asks_target(Some(control.clone()), Some("web"), None, true),
            Some((control.clone(), "web".to_string()))
        );
        assert_eq!(host_asks_target(Some(control), None, None, true), None);
        assert_eq!(host_asks_target(None, Some("web"), None, true), None);
    }

    /// A box whose record carries its address pair on a VM-backed host is
    /// subscribed for, at the control socket and under its name; a native
    /// host (no box named) or a missing control socket still yields none.
    #[test]
    fn host_asks_target_names_the_control_socket_and_box_with_an_address_pair() {
        let control = std::path::PathBuf::from("/run/vm/control.sock");
        let addresses = boxes::BoxAddresses {
            switch_address: std::net::Ipv4Addr::new(100, 64, 0, 2),
            loopback_address: std::net::Ipv4Addr::new(127, 0, 64, 0),
        };
        assert_eq!(
            host_asks_target(Some(control.clone()), Some("web"), Some(addresses), false),
            Some((control.clone(), "web".to_string()))
        );
        assert_eq!(
            host_asks_target(Some(control), None, Some(addresses), false),
            None
        );
        assert_eq!(
            host_asks_target(None, Some("web"), Some(addresses), false),
            None
        );
    }

    /// A host-side ask stand: the real VM host daemon's control server and
    /// guest door over a real registry, in a host dir the CLI resolves
    /// the control socket in (NET-045).
    struct AskStand {
        _dir: tempfile::TempDir,
        global: GlobalArgs,
        control: std::path::PathBuf,
        guest: std::path::PathBuf,
        registry: minvmd::box_registry::BoxRegistry,
    }

    impl AskStand {
        fn start() -> Self {
            let dir = tempfile::TempDir::new().unwrap();
            let host_dir = dir.path().join("providers").join("local-minvmd0");
            std::fs::create_dir_all(&host_dir).unwrap();
            let control = host_dir.join("control.sock");
            let registry = minvmd::box_registry::BoxRegistry::new(switch::SwitchSubnet::default());
            let answerer =
                minvmd::net::answerer::AnswererStatus::allocating_for_tests("ask-test-node");
            let _server = minvmd::control::spawn(
                control.clone(),
                registry.clone(),
                answerer.clone(),
                minvmd::control::ProxyPublishStatus::default(),
            )
            .expect("the control server binds its socket");
            let guest = minvmd::control::spawn_guest_reports_door(
                &control,
                registry.clone(),
                answerer,
                minvmd::control::ProxyPublishStatus::default(),
            )
            .expect("the guest door binds its socket");
            let global = GlobalArgs {
                provider: Some(Provider::LocalMinvmd),
                minimal_dir: Some(dir.path().to_path_buf()),
                ..Default::default()
            };
            Self {
                _dir: dir,
                global,
                control,
                guest,
                registry,
            }
        }

        /// Register `name` the way the activation does, with `stance` over
        /// 3000-3999.
        async fn register(&self, name: &str, stance: DynamicIngress) -> RegisteredWithVmHost {
            let policy = boxes::BoxPolicy {
                egress: None,
                ingress: Some(IngressPolicy {
                    port_mappings: vec![],
                    dynamic_allowed_range: Some((3000, 3999)),
                    dynamic_ingress: Some(stance),
                }),
                credentialed_upstream: None,
                quic443: None,
            };
            register_box_for_activation(
                paths::HostKind::Minvmd,
                self.global.minimal_dir.as_deref(),
                NetworkMode::OwnIp,
                name,
                &policy,
            )
            .await
            .expect("the real control server answers the registration")
            .expect("an own-address box on a VM-backed host registers")
        }

        /// The guest's ask for `port`, its reply read on a thread.
        fn guest_ask(
            &self,
            web: &RegisteredWithVmHost,
            port: u16,
        ) -> std::sync::mpsc::Receiver<minimald_rpc::BoxControlReply> {
            use std::io::{BufRead as _, Write as _};
            let mut stream = std::os::unix::net::UnixStream::connect(&self.guest).unwrap();
            let mut line = serde_json_lenient::to_string(
                &minimald_rpc::BoxControlRequest::AdmitAsk(minimald_rpc::AdmitAskRequest {
                    switch_address: web.addresses.switch_address,
                    port,
                    proto: boxes::IpProto::Tcp,
                }),
            )
            .unwrap();
            line.push('\n');
            stream.write_all(line.as_bytes()).unwrap();
            let (tx, rx) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                let mut reader = std::io::BufReader::new(stream);
                let mut reply = String::new();
                if reader.read_line(&mut reply).is_ok() && !reply.trim().is_empty() {
                    let _ = tx.send(serde_json_lenient::from_str(reply.trim()).unwrap());
                }
            });
            rx
        }
    }

    /// The relay as the ask loop sees it: every suspend and resume, in
    /// order, reported on a channel.
    struct RecordingTerminal(std::sync::mpsc::Sender<&'static str>);

    impl minimal_client::attach::AskTerminal for RecordingTerminal {
        fn suspend_for_ask(&self) -> Result<(), anyhow::Error> {
            let _ = self.0.send("suspend");
            Ok(())
        }

        fn resume_after_ask(&self) {
            let _ = self.0.send("resume");
        }

        fn ask_cancelled(&self) -> bool {
            false
        }
    }

    /// Serve `asks` on a thread with `dialog`, reporting the terminal's
    /// suspend and resume, and the offer each dialog was built from.
    fn serve_asks(
        asks: minimal_client::attach::HostAsks,
        dialog: fn(&minimald_rpc::PendingAskOffer) -> minimald_rpc::AskAnswer,
    ) -> (
        std::sync::mpsc::Receiver<&'static str>,
        std::sync::mpsc::Receiver<minimald_rpc::PendingAskOffer>,
    ) {
        let (events, events_rx) = std::sync::mpsc::channel();
        let (offers, offers_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            asks.serve(&RecordingTerminal(events), |offer, _| {
                let _ = offers.send(offer.clone());
                minimal_client::ask_dialog::AskDialogEnd::Answered(dialog(offer))
            });
        });
        (events_rx, offers_rx)
    }

    const ASK_WAIT: std::time::Duration = std::time::Duration::from_secs(10);

    /// An ask create stands on a VM-backed host (NET-045): T94's refusal is
    /// gone, and the registration hands the host row the ask stance — as it
    /// does allow and deny — so the host holds the stance the human is
    /// asked under.
    #[tokio::test]
    async fn vm_backed_dynamic_ask_create_accepted() {
        let stand = AskStand::start();
        for (name, stance) in [
            ("asker", DynamicIngress::Ask),
            ("allower", DynamicIngress::Allow),
            ("denier", DynamicIngress::Deny),
        ] {
            let _held = stand.register(name, stance).await;
            let row = stand
                .registry
                .row_by_name(name)
                .expect("the registration published the row");
            assert_eq!(
                row.dynamic_ingress(),
                stance,
                "{name}'s row holds its stance"
            );
            assert_eq!(row.dynamic_range(), Some((3000, 3999)));
        }
        refuse_dynamic_ingress_off_own_ip(
            crate::cli::CliNetworkMode::OwnIp,
            Some(DynamicIngress::Ask),
            Some((3000, 3999)),
        )
        .expect("an own-IP ask create is not refused");
        assert_eq!(
            minimal_client::attach::VM_HOST_CONTROL_SOCK_FILE,
            minvmd::control::CONTROL_SOCK_FILE,
            "the dash finds the control socket the VM host daemon binds"
        );
    }

    /// The attached client renders the offer the host pushed — built from
    /// the host row — suspends the relay for it, records the yes through
    /// the host door, and resumes; the guest's held ask is admitted.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn client_records_ask_yes_through_host_door() {
        let stand = AskStand::start();
        let web = stand.register("web", DynamicIngress::Ask).await;
        let asks = tokio::task::spawn_blocking({
            let control = stand.control.clone();
            move || minimal_client::attach::HostAsks::subscribe(&control, "web")
        })
        .await
        .unwrap()
        .expect("the attach subscribes by the row's box id");
        let (events, offers) = serve_asks(asks, |_| minimald_rpc::AskAnswer::Yes);

        let reply = stand.guest_ask(&web, 3000);
        let offer = offers.recv_timeout(ASK_WAIT).expect("the dialog is shown");
        assert_eq!(offer.name, "web");
        assert_eq!(Some(offer.box_id), web.box_id);
        assert_eq!(
            minimal_client::ask_dialog::ask_dialog_lead_in(&offer),
            "web asks to publish port 3000/tcp."
        );
        let minimald_rpc::BoxControlReply::AskAdmit(outcome) =
            reply.recv_timeout(ASK_WAIT).unwrap()
        else {
            panic!("the guest's ask is answered with its end");
        };
        assert!(
            matches!(
                outcome,
                minimald_rpc::AskAdmitOutcome::Admitted { port: 3000, .. }
            ),
            "the recorded yes admits the ask: {outcome:?}"
        );
        assert_eq!(events.recv_timeout(ASK_WAIT).unwrap(), "suspend");
        assert_eq!(events.recv_timeout(ASK_WAIT).unwrap(), "resume");
        let row = stand.registry.row_by_name("web").unwrap();
        assert_eq!(row.runtime_port_numbers(), vec![3000]);
    }

    /// Two attaches are offered one ask; the first records a no while the
    /// second's dialog is still up. The second's late yes is told the ask
    /// was already denied, and admits nothing.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn late_attach_answer_admits_nothing() {
        let stand = AskStand::start();
        let web = stand.register("web", DynamicIngress::Ask).await;
        let subscribe = || {
            let control = stand.control.clone();
            tokio::task::spawn_blocking(move || {
                minimal_client::attach::HostAsks::subscribe(&control, "web")
            })
        };
        let first = subscribe()
            .await
            .unwrap()
            .expect("the first attach subscribes");
        let second = subscribe()
            .await
            .unwrap()
            .expect("the second attach subscribes");
        // The second dialog is up before the first answers, and answers
        // only once the first's no is recorded.
        let (shown, shown_rx) = std::sync::mpsc::channel::<()>();
        let (first_done, first_done_rx) = std::sync::mpsc::channel::<()>();
        let (first_offers, first_offers_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let (events, _) = std::sync::mpsc::channel();
            first.serve(&RecordingTerminal(events), |offer, _| {
                let _ = shown_rx.recv();
                let _ = first_offers.send(offer.clone());
                minimal_client::ask_dialog::AskDialogEnd::Answered(minimald_rpc::AskAnswer::No)
            });
        });
        let (events, events_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            second.serve(&RecordingTerminal(events), |_, _| {
                let _ = shown.send(());
                let _ = first_done_rx.recv();
                minimal_client::ask_dialog::AskDialogEnd::Answered(minimald_rpc::AskAnswer::Yes)
            });
        });
        let reply = stand.guest_ask(&web, 3000);
        first_offers_rx
            .recv_timeout(ASK_WAIT)
            .expect("the first dialog is shown");
        let minimald_rpc::BoxControlReply::AskAdmit(outcome) =
            reply.recv_timeout(ASK_WAIT).unwrap()
        else {
            panic!("the guest's ask is answered with its end");
        };
        assert!(matches!(
            outcome,
            minimald_rpc::AskAdmitOutcome::Refused {
                reason: minimald_rpc::AskRefused::Denied,
                ..
            }
        ));
        first_done.send(()).unwrap();
        assert_eq!(events_rx.recv_timeout(ASK_WAIT).unwrap(), "suspend");
        assert_eq!(
            events_rx.recv_timeout(ASK_WAIT).unwrap(),
            "resume",
            "the late dialog resumes the relay"
        );
        assert!(
            stand
                .registry
                .row_by_name("web")
                .unwrap()
                .runtime_port_numbers()
                .is_empty(),
            "the late yes admitted nothing"
        );
    }

    /// Two attaches are offered one ask; the first answers yes while the
    /// second's dialog is still up and unanswered. The host's dismissal takes
    /// the second dialog down by itself: it records nothing, and its relay
    /// resumes without anyone pressing a key.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn overtaken_dialog_is_dismissed_and_relay_resumes() {
        let stand = AskStand::start();
        let web = stand.register("web", DynamicIngress::Ask).await;
        let subscribe = || {
            let control = stand.control.clone();
            tokio::task::spawn_blocking(move || {
                minimal_client::attach::HostAsks::subscribe(&control, "web")
            })
        };
        let first = subscribe()
            .await
            .unwrap()
            .expect("the first attach subscribes");
        let second = subscribe()
            .await
            .unwrap()
            .expect("the second attach subscribes");
        // The first answers only once the second's dialog is up.
        let (shown, shown_rx) = std::sync::mpsc::channel::<()>();
        std::thread::spawn(move || {
            let (events, _) = std::sync::mpsc::channel();
            first.serve(&RecordingTerminal(events), |_, _| {
                let _ = shown_rx.recv();
                minimal_client::ask_dialog::AskDialogEnd::Answered(minimald_rpc::AskAnswer::Yes)
            });
        });
        let (ends, ends_rx) = std::sync::mpsc::channel();
        let (events, events_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            second.serve(&RecordingTerminal(events), |_, watch| {
                let _ = shown.send(());
                watch.wait_dismissed();
                let _ = ends.send(());
                minimal_client::ask_dialog::AskDialogEnd::Dismissed
            });
        });
        let reply = stand.guest_ask(&web, 3000);
        let minimald_rpc::BoxControlReply::AskAdmit(outcome) =
            reply.recv_timeout(ASK_WAIT).unwrap()
        else {
            panic!("the guest's ask is answered with its end");
        };
        assert!(
            matches!(
                outcome,
                minimald_rpc::AskAdmitOutcome::Admitted { port: 3000, .. }
            ),
            "the first attach's yes admits the ask: {outcome:?}"
        );
        ends_rx
            .recv_timeout(ASK_WAIT)
            .expect("the overtaken dialog is dismissed without an answer");
        assert_eq!(events_rx.recv_timeout(ASK_WAIT).unwrap(), "suspend");
        assert_eq!(
            events_rx.recv_timeout(ASK_WAIT).unwrap(),
            "resume",
            "the dismissed dialog resumes the relay"
        );
        assert_eq!(
            stand
                .registry
                .row_by_name("web")
                .unwrap()
                .runtime_port_numbers(),
            vec![3000],
            "the one yes admitted the port once"
        );
    }

    /// Ctrl-C at the dialog is a no: the client records no through the host
    /// door, nothing is admitted, and the relay resumes. Escape and a closed
    /// input are a no the same way.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ctrl_c_at_ask_dialog_records_no_and_relay_resumes() {
        let keys = |keys: &[u8]| minimal_client::ask_dialog::AskSelector::default().feed(keys);
        assert_eq!(keys(b"\x03"), Some(minimald_rpc::AskAnswer::No));
        assert_eq!(keys(b"\x1b"), Some(minimald_rpc::AskAnswer::No));
        assert_eq!(keys(b"\x04"), Some(minimald_rpc::AskAnswer::No));
        assert_eq!(keys(b"\x1b[B\r"), Some(minimald_rpc::AskAnswer::Yes));

        let stand = AskStand::start();
        let web = stand.register("web", DynamicIngress::Ask).await;
        let asks = tokio::task::spawn_blocking({
            let control = stand.control.clone();
            move || minimal_client::attach::HostAsks::subscribe(&control, "web")
        })
        .await
        .unwrap()
        .expect("the attach subscribes");
        let (events, offers) = serve_asks(asks, |_| {
            minimal_client::ask_dialog::AskSelector::default()
                .feed(b"\x03")
                .expect("Ctrl-C ends the dialog")
        });
        let reply = stand.guest_ask(&web, 3000);
        offers.recv_timeout(ASK_WAIT).expect("the dialog is shown");
        let minimald_rpc::BoxControlReply::AskAdmit(outcome) =
            reply.recv_timeout(ASK_WAIT).unwrap()
        else {
            panic!("the guest's ask is answered with its end");
        };
        assert_eq!(
            outcome,
            minimald_rpc::AskAdmitOutcome::Refused {
                ask_id: match outcome {
                    minimald_rpc::AskAdmitOutcome::Refused { ask_id, .. }
                    | minimald_rpc::AskAdmitOutcome::Admitted { ask_id, .. } => ask_id,
                },
                reason: minimald_rpc::AskRefused::Denied,
                cause: None,
            },
            "Ctrl-C records a no"
        );
        assert_eq!(events.recv_timeout(ASK_WAIT).unwrap(), "suspend");
        assert_eq!(
            events.recv_timeout(ASK_WAIT).unwrap(),
            "resume",
            "the relay resumes after the dialog"
        );
        assert!(
            stand
                .registry
                .row_by_name("web")
                .unwrap()
                .runtime_port_numbers()
                .is_empty()
        );
    }
}
