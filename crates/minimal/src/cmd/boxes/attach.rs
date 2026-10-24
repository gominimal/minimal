//! `min session attach`: resolving the target, the ssh hand-off and the
//! host asks the attach answers.

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

/// Resolve a named attach target to its record and the socket the hand-off
/// runs over — the target `min session attach` lands in when the name alone
/// decides where to look (NET-058).
///
/// The selected VM's daemon is asked first (`client`, reached over `sock`):
/// the common case — a box on the VM the operator is already on — costs
/// nothing beyond the one lookup the command always made, and its answer is
/// gated on the reply that lookup was already making. When that daemon does
/// not know the name, [`crate::attach::resolve_box_vm`] resolves the VM that owns it
/// across every VM's socket, so no global flag is needed to reach a box on
/// another VM — the resolution gates the owning daemon on the very reply that
/// named the box, so a skewed VM cannot be reached through it. Nothing found
/// anywhere returns the selected VM's own error — the "no session found" it
/// computed, or its skew — as the more useful of the two answers.
pub(crate) async fn resolve_attach_target_version_gated(
    global: &GlobalArgs,
    client: &mut client::Client,
    sock: std::path::PathBuf,
    name: &str,
) -> Result<(boxes::Record, std::path::PathBuf), anyhow::Error> {
    match resolve_session_version_gated(client, name).await {
        Ok(record) => Ok((record, sock)),
        Err(selected) => match crate::attach::resolve_box_vm(global, name).await? {
            Some(resolved) => {
                // The operator never chose the VM the way they chose the
                // session, so tell them which one they're landing in.
                if should_announce_box(global) {
                    eprintln!(
                        "Attaching to session {} on VM {}",
                        box_announce_label(&resolved.record.id, resolved.record.name.as_deref()),
                        resolved.vm
                    );
                }
                Ok((resolved.record, resolved.sock))
            }
            None => Err(selected),
        },
    }
}

/// Resolve a session to attach to when the user supplied no explicit session
/// reference. Matches an already-fetched session list against the current
/// working directory, and either attaches directly (unambiguous), opens the
/// interactive picker (ambiguous), or errors (ambiguous but non-interactive).
///
/// Takes the list rather than fetching it so its two callers can assert the
/// daemon's build off the `ListSessions` reply — before the picker blocks on a
/// human, not after.
///
/// Returns [`SmartAttach::NoSessions`] when no sessions exist at all, which
/// `min session attach` reports as an error pointing at `min session activate`.
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

/// The picker's `+ Create a new session` arm: activate a fresh session for the
/// cwd and attach. A thin wrapper over [`cmd_activate`] with an autogen name
/// and default sync, so the create-then-attach path stays the one that
/// `min session activate --attach .` runs.
pub(crate) async fn activate_new_for_attach(global: &GlobalArgs) -> Result<(), anyhow::Error> {
    // `Box::pin` breaks the async recursion cycle: `cmd_activate` chains into
    // `cmd_attach` (on `--attach`), which reaches back here — an unboxed cycle
    // is an infinitely sized future (E0733).
    Box::pin(cmd_activate(
        global,
        ActivateArgs {
            name: None,
            path: None,
            sync: None,
            network: CliNetworkMode::HostNet,
            ingress: Vec::new(),
            dynamic_ingress: None,
            dynamic_range: None,
            allow_subnets: Vec::new(),
            allow_dns_hosts: Vec::new(),
            allow_protocols: Vec::new(),
            deny_subnets: Vec::new(),
            deny_all_egress: false,
            credentialed_upstream: false,
            loadout: Vec::new(),
            no_loadouts: false,
            no_hooks: false,
            no_prompt: false,
            attach: true,
        },
    ))
    .await
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
    sock: &std::path::Path,
    id: boxes::SessionId,
    wire: Option<String>,
    config_dir: Option<&std::path::Path>,
    host_asks_for: Option<&str>,
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
    let mut ssh =
        minimal_client::attach::attach_command(sock, id, wire.as_deref(), session_keys.as_ref())?;

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
    rehold_held_name_before_attach(sock, id, record.as_ref()).await;

    if wire.is_none() {
        let stdin_is_tty = std::io::stdin().is_terminal();
        // The pair the box's row was registered with, read before the
        // attach: an attach that ends in a daemon-side destroy leaves no
        // record to read it from, and the row is still this client's to
        // withdraw.
        let box_addresses = match host_asks_for {
            Some(_) => record.and_then(|record| record.box_addresses),
            None => None,
        };
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
                    minimal_client::attach::run_interactive_attach(
                        ssh,
                        subscribe_host_asks(host_asks)
                            .map(minimal_client::attach::HostAsks::into_hook),
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
            release_held_name_after_attach(sock, id, name, box_addresses).await;
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
    (daemon_provider_kind(global) == paths::ProviderKind::Minvmd)
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
            // ssh never ran (or the relay never took the terminal), so
            // nothing of the session reached the terminal and there is
            // nothing to put back.
            unwind.disarm();
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
    /// guest door over a real registry, in a provider dir the CLI resolves
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
            let provider_dir = dir.path().join("providers").join("local-minvmd0");
            std::fs::create_dir_all(&provider_dir).unwrap();
            let control = provider_dir.join("control.sock");
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
                paths::ProviderKind::Minvmd,
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
