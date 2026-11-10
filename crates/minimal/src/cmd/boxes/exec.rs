//! `min box exec`: runs a command in a running box, and relays the
//! command's output and exit code.

use super::*;

/// A child's exit status as this process's exit code, following the shell's
/// `128 + signal` convention for a signalled child. Reproduces what `exec()`
/// gave for free: the client's status *is* ssh's.
pub(crate) fn exit_code_of(status: std::process::ExitStatus) -> i32 {
    use std::os::unix::process::ExitStatusExt as _;
    status
        .code()
        .or_else(|| status.signal().map(|s| 128 + s))
        .unwrap_or(1)
}

/// Relay a reader's bytes to a writer until the reader reaches EOF. Returns
/// `BrokenPipe` when the writer's far end closes first, so the caller can
/// kill the child whose output it was relaying (#815).
pub(crate) async fn relay_exec_stdout<R, W>(mut from: R, to: &mut W) -> Result<(), std::io::Error>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let mut buf = [0u8; 8192];
    loop {
        let n = from.read(&mut buf).await?;
        if n == 0 {
            return Ok(());
        }
        to.write_all(&buf[..n]).await?;
        to.flush().await?;
    }
}

/// What `min box exec` asks of the box `target` names (BOX-149, BCLI-053):
/// the argv, how the command meets this client, and its own timeout.
#[derive(Debug, Clone)]
pub(crate) struct BoxExecRequest {
    /// The box as the user named it.
    pub(crate) target: String,
    /// The command's words, run with no shell.
    pub(crate) argv: Vec<String>,
    /// Attached by default, a terminal under `-t`, detached under
    /// `--detach`.
    pub(crate) mode: minimald_rpc::exec::ExecMode,
    /// The command's own timeout in whole seconds, from `--timeout`.
    pub(crate) timeout_secs: Option<u64>,
}

impl BoxExecRequest {
    /// The request the flags in `args` ask for.
    pub(crate) fn from_args(args: BoxExecArgs) -> Self {
        use minimald_rpc::exec::ExecMode;
        let mode = if args.tty {
            ExecMode::Tty
        } else if args.detach {
            ExecMode::Detached
        } else {
            ExecMode::Attached
        };
        Self {
            target: args.target,
            argv: args.command,
            mode,
            timeout_secs: args.timeout,
        }
    }

    /// The exec form the daemon reads off the channel.
    pub(crate) fn wire(&self) -> String {
        minimald_rpc::exec::ExecRequest::Exec(minimald_rpc::exec::ExecSpec {
            argv: self.argv.clone(),
            mode: self.mode,
            timeout_secs: self.timeout_secs,
        })
        .encode()
    }
}

/// How a tty exec's terminal reaches this client once the exec started.
pub(crate) enum TtyAttach {
    /// Through `ssh -tt` on this process's terminal, with the terminal relay
    /// `min session attach` uses, to the box `id` on the daemon at `sock`.
    Terminal {
        sock: std::path::PathBuf,
        id: boxes::SessionId,
    },
    /// Through an exec channel, with the caller's stdio as pipes. Only the
    /// scripted tests take it: `min box exec -t` refuses a stdin that is not
    /// a terminal.
    #[cfg(test)]
    Pipes,
}

/// The bytes a caller sends to the command's stdin. `None` closes the
/// command's stdin at once.
pub(crate) type ExecInput = Option<tokio::sync::mpsc::Receiver<Vec<u8>>>;

/// One exec channel to a box, as the relay reads and writes it.
pub(crate) trait ExecChannel {
    /// The next message from the daemon, or `None` once the channel closed.
    async fn wait(&mut self) -> Option<russh::ChannelMsg>;
    /// Ends the command's stdin.
    async fn eof(&mut self) -> Result<(), anyhow::Error>;
    /// A writer to the command's stdin.
    fn input(&self) -> std::pin::Pin<Box<dyn tokio::io::AsyncWrite + Send>>;
}

impl ExecChannel for russh::Channel<russh::client::Msg> {
    async fn wait(&mut self) -> Option<russh::ChannelMsg> {
        russh::Channel::wait(self).await
    }

    async fn eof(&mut self) -> Result<(), anyhow::Error> {
        russh::Channel::eof(self)
            .await
            .context("close the command's stdin")
    }

    fn input(&self) -> std::pin::Pin<Box<dyn tokio::io::AsyncWrite + Send>> {
        Box::pin(self.make_writer())
    }
}

/// Opens the exec channels of one box.
pub(crate) trait ExecChannels {
    /// The channel type.
    type Channel: ExecChannel;
    /// Opens a channel that carries the exec form `wire` to the box.
    async fn open(&mut self, wire: &str) -> Result<Self::Channel, anyhow::Error>;
}

/// The exec channels of the box `id` on the daemon `client` reaches.
/// `target` is the box as the user named it.
pub(crate) struct HostChannels<'a> {
    client: client::Client,
    id: boxes::SessionId,
    target: &'a str,
}

impl ExecChannels for HostChannels<'_> {
    type Channel = russh::Channel<russh::client::Msg>;

    async fn open(&mut self, wire: &str) -> Result<Self::Channel, anyhow::Error> {
        let (id, target) = (self.id, self.target);
        self.client
            .open_session_exec_channel(id, wire, &minimald_rpc::taskenv::TaskEnv::default())
            .await
            .map_err(|error| {
                // The open fails when the daemon refuses the channel, and
                // when the connection to it fails. The text says only that
                // the channel did not open.
                tracing::warn!(%id, "the exec channel did not open: {error:#}");
                anyhow::anyhow!(
                    "Could not open a channel to {target} to run the command. \
                     Run `min box show {target}` to see the box."
                )
            })
    }
}

/// `min box exec <box> [-t|--detach] [--timeout <d>] -- <cmd>`: runs the
/// command in the box and exits with the command's exit code (BCLI-053).
pub async fn cmd_box_exec(global: &GlobalArgs, args: BoxExecArgs) -> Result<(), anyhow::Error> {
    use minimald_rpc::exec::ExecMode;

    let request = BoxExecRequest::from_args(args);
    let stdin_is_tty = std::io::stdin().is_terminal();
    // `-t` without a terminal starts nothing: no daemon, no lookup.
    refuse_tty_without_terminal(&request, stdin_is_tty)?;
    ensure_daemon(global)?;
    let hosts = crate::cmd::list::local_hosts(global)?;
    // A terminal on stdin is never pumped. An attached command does not
    // read it, as `min task run` does not: a read from a background job
    // would stop this process with SIGTTOU's sibling, SIGTTIN. With `-t`
    // the terminal attach reads it itself, and a pump thread started
    // before it would keep a blocking read and take the first keystroke.
    let input = match request.mode {
        ExecMode::Detached | ExecMode::Tty => None,
        ExecMode::Attached if stdin_is_tty => None,
        ExecMode::Attached => Some(stdin_pump()),
    };
    let mut stdout = tokio::io::stdout();
    let mut stderr = tokio::io::stderr();
    let code = box_exec_on_hosts(
        hosts,
        daemon_host_kind(global),
        &request,
        stdin_is_tty,
        input,
        &mut stdout,
        &mut stderr,
    )
    .await?;
    if code == 0 {
        Ok(())
    } else {
        Err(Handoff::Exit(code).into())
    }
}

/// Refuses `min box exec -t` when stdin is not a terminal (exit 2). The
/// refusal comes before the box resolves, so nothing resumes or starts.
fn refuse_tty_without_terminal(
    request: &BoxExecRequest,
    terminal: bool,
) -> Result<(), anyhow::Error> {
    if request.mode != minimald_rpc::exec::ExecMode::Tty || terminal {
        return Ok(());
    }
    let refusal = BoxExecRefusal::NoTerminal {
        target: request.target.clone(),
    };
    tracing::info!(
        verb = "box exec",
        mode = request.mode.name(),
        outcome = refusal.outcome(),
        "{refusal}"
    );
    Err(refusal.into())
}

/// This process's stdin as chunks, read on a detached thread as `min task
/// run` reads it: a thread is abandoned at exit, where a read on tokio's
/// blocking pool holds the runtime open.
fn stdin_pump() -> tokio::sync::mpsc::Receiver<Vec<u8>> {
    let (tx, rx) = tokio::sync::mpsc::channel::<Vec<u8>>(1);
    std::thread::spawn(move || {
        use std::io::Read as _;
        let mut stdin = std::io::stdin();
        let mut buf = [0u8; 8192];
        loop {
            match stdin.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if tx.blocking_send(buf[..n].to_vec()).is_err() {
                        break;
                    }
                }
            }
        }
    });
    rx
}

/// Resolves the box `request` names over `hosts`, runs the command there as
/// BOX-149 defines, and returns the exit code to end with. The command's
/// output goes to `out` and `err`. A tty exec attaches this process's
/// terminal, and is refused before the box resolves when `terminal` is
/// not set. A refusal returns as a
/// [`BoxExecRefusal`], and an exec that its own timeout ended as a
/// [`BoxExecTimedOut`]. The verb, the box id and the outcome go on the
/// command's span.
pub(crate) async fn box_exec_on_hosts<O, E>(
    hosts: Vec<crate::cmd::list::LocalHost>,
    kind: paths::HostKind,
    request: &BoxExecRequest,
    terminal: bool,
    input: ExecInput,
    out: &mut O,
    err: &mut E,
) -> Result<i32, anyhow::Error>
where
    O: tokio::io::AsyncWrite + Unpin,
    E: tokio::io::AsyncWrite + Unpin,
{
    refuse_tty_without_terminal(request, terminal)?;
    let resolved = resolve_box_on_hosts(hosts, &request.target, "box exec").await?;
    crate::output::record_box_id(&resolved.box_id.to_string());
    let ran = exec_in_resolved_box(&resolved, kind, request, input, out, err).await;
    record_exec_outcome(resolved.box_id, request, &ran);
    ran
}

/// The event that records how `min box exec` ended in the box `box_id`.
pub(crate) fn record_exec_outcome(
    box_id: boxes::SessionId,
    request: &BoxExecRequest,
    ran: &Result<i32, anyhow::Error>,
) {
    let mode = request.mode.name();
    match ran {
        Ok(code) => tracing::info!(
            verb = "box exec",
            box_id = %box_id,
            mode,
            exit_code = code,
            outcome = "ran",
        ),
        Err(error) => {
            let outcome = if let Some(refusal) = error.downcast_ref::<BoxExecRefusal>() {
                refusal.outcome()
            } else if error.downcast_ref::<BoxExecTimedOut>().is_some() {
                "timeout"
            } else {
                "error"
            };
            tracing::info!(verb = "box exec", box_id = %box_id, mode, outcome, "{error:#}");
        }
    }
}

/// [`box_exec_on_hosts`] once the address resolved to `resolved`.
async fn exec_in_resolved_box<O, E>(
    resolved: &ResolvedBox,
    kind: paths::HostKind,
    request: &BoxExecRequest,
    input: ExecInput,
    out: &mut O,
    err: &mut E,
) -> Result<i32, anyhow::Error>
where
    O: tokio::io::AsyncWrite + Unpin,
    E: tokio::io::AsyncWrite + Unpin,
{
    let sock = resolved.host.sock.as_path();
    let id = resolved.box_id;
    // A VM-backed box gets its row and its name hold back before the
    // command runs, as `min session exec` does before its ssh exec.
    let record = match control_sock_beside(sock).filter(|control| control.exists()) {
        Some(_) => attached_box_record(sock, id).await.unwrap_or_else(|error| {
            tracing::warn!(
                "could not read the box's record ({error:#}); its box row is not asked back first"
            );
            None
        }),
        None => None,
    };
    minimal_client::box_registration::resume_box_row(sock, record.as_ref()).await?;
    rehold_held_name_before_attach(kind, sock, id, record.as_ref()).await;

    let client = gated_box_host_client(&resolved.host).await?;
    let mut channels = HostChannels {
        client,
        id,
        target: &request.target,
    };
    // A tty exec reached here only with a terminal on stdin.
    let attach = TtyAttach::Terminal {
        sock: sock.to_path_buf(),
        id,
    };
    exec_over(&mut channels, request, attach, input, out, err).await
}

/// Runs `request` over the exec `channels` of its box (BOX-149): attached,
/// with the command's stdio relayed; detached, with only the exec id on
/// `out`; or with a terminal, the exec id on `err` and then the command's
/// output on `out`. Returns the exit code to end with.
pub(crate) async fn exec_over<C, O, E>(
    channels: &mut C,
    request: &BoxExecRequest,
    attach: TtyAttach,
    input: ExecInput,
    out: &mut O,
    err: &mut E,
) -> Result<i32, anyhow::Error>
where
    C: ExecChannels,
    O: tokio::io::AsyncWrite + Unpin,
    E: tokio::io::AsyncWrite + Unpin,
{
    use minimald_rpc::exec::ExecMode;

    let target = request.target.as_str();
    let started = std::time::Instant::now();
    let channel = channels.open(&request.wire()).await?;
    match request.mode {
        ExecMode::Attached => {
            let relayed = relay_box_channel(channel, input, out, err, true).await?;
            let status = relayed_status(target, relayed, err).await?;
            // The daemon ends an attached exec at its timeout with 124 and
            // says nothing more. Only a run that asked for a timeout, and
            // lasted that long, ended at it. An attached exec cannot learn
            // its exec id, so it cannot ask the daemon as the tty path does:
            // a command that itself exits 124 after `--timeout` reads as a
            // timeout.
            if let Some(secs) = request.timeout_secs
                && status == i32::from(BoxExecTimedOut::EXIT_CODE)
                && started.elapsed() >= std::time::Duration::from_secs(secs)
            {
                return Err(BoxExecTimedOut::exec(target, secs).into());
            }
            Ok(status)
        }
        ExecMode::Detached => match started_exec_id(target, channel, err).await? {
            Ok(exec_id) => {
                out.write_all(format!("{exec_id}\n").as_bytes()).await?;
                out.flush().await?;
                Ok(0)
            }
            Err(status) => Ok(status),
        },
        ExecMode::Tty => {
            let exec_id = match started_exec_id(target, channel, err).await? {
                Ok(exec_id) => exec_id,
                Err(status) => return Ok(status),
            };
            err.write_all(format!("{exec_id}\n").as_bytes()).await?;
            err.flush().await?;
            let attach_wire = minimald_rpc::exec::ExecRequest::ExecAttach(exec_id.clone()).encode();
            let status = match attach {
                #[cfg(test)]
                TtyAttach::Pipes => {
                    let channel = channels.open(&attach_wire).await?;
                    let relayed = relay_box_channel(channel, input, out, err, false).await?;
                    relayed_status(target, relayed, err).await?
                }
                TtyAttach::Terminal { sock, id } => {
                    drop(input);
                    attach_exec_terminal(&sock, id, &attach_wire).await?
                }
            };
            // The attach ends with 124 for an exec that its timeout ended,
            // and for a command that exited 124. The exec's stored end
            // tells them apart.
            if request.timeout_secs.is_some() && status == i32::from(BoxExecTimedOut::EXIT_CODE) {
                return wait_exec_over(channels, target, &exec_id, err).await;
            }
            Ok(status)
        }
    }
}

/// What a channel relay saw: the exit status, and the stderr it held back
/// because it read as the daemon's refusal.
pub(crate) struct Relayed {
    status: Option<u32>,
    held: Vec<u8>,
}

/// Relays the exec on `channel`: `input` to the command's stdin, its stdout
/// to `out`, its stderr to `err`. With `hold_refusal`, a first stderr chunk
/// that reads as the daemon's refusal is held back, so the caller can print
/// the refusal in its own words. Any later output releases it.
async fn relay_box_channel<C, O, E>(
    mut channel: C,
    input: ExecInput,
    out: &mut O,
    err: &mut E,
    hold_refusal: bool,
) -> Result<Relayed, anyhow::Error>
where
    C: ExecChannel,
    O: tokio::io::AsyncWrite + Unpin,
    E: tokio::io::AsyncWrite + Unpin,
{
    let pump = match input {
        None => {
            channel.eof().await?;
            None
        }
        Some(mut rx) => {
            let mut to_channel = channel.input();
            // Both results are dropped: the command can end before it reads
            // all of its input, and the channel loop below sees that.
            Some(AbortOnDrop(tokio::spawn(async move {
                while let Some(chunk) = rx.recv().await {
                    if to_channel.write_all(&chunk).await.is_err() {
                        break;
                    }
                }
                let _ = to_channel.shutdown().await;
            })))
        }
    };
    let mut held = Vec::new();
    let mut seen_output = false;
    let mut status = None;
    while let Some(msg) = channel.wait().await {
        match msg {
            russh::ChannelMsg::Data { data } => {
                release_held(&mut held, err).await?;
                seen_output = true;
                out.write_all(&data)
                    .await
                    .context("write the command's stdout")?;
                out.flush().await.context("write the command's stdout")?;
            }
            russh::ChannelMsg::ExtendedData { data, ext: 1 } => {
                if hold_refusal && !seen_output && held.is_empty() && reads_as_refusal(&data) {
                    held.extend_from_slice(&data);
                } else {
                    release_held(&mut held, err).await?;
                    err.write_all(&data)
                        .await
                        .context("write the command's stderr")?;
                    err.flush().await.context("write the command's stderr")?;
                }
                seen_output = true;
            }
            russh::ChannelMsg::ExitStatus { exit_status } => status = Some(exit_status),
            _ => {}
        }
    }
    drop(pump);
    Ok(Relayed { status, held })
}

/// Aborts the stdin task when the relay returns, on every path out of it.
struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Writes the held stderr to `err`, and empties it.
async fn release_held<E>(held: &mut Vec<u8>, err: &mut E) -> Result<(), anyhow::Error>
where
    E: tokio::io::AsyncWrite + Unpin,
{
    if !held.is_empty() {
        err.write_all(held)
            .await
            .context("write the command's stderr")?;
        err.flush().await.context("write the command's stderr")?;
        held.clear();
    }
    Ok(())
}

// The daemon's refusal texts (`not_running_message`,
// `exec_disabled_message` and `exec_spec_unreadable_message` in
// `minimald`'s exec module). The harness tests of `min box exec` pin them:
// a change on the daemon side fails those tests.
const NOT_RUNNING_TAIL: &str = "Only a running box can run a command.\n";
const EXEC_DISABLED_MARK: &str = "does not run commands: its spec sets [io] exec_enabled = false.";
const SPEC_UNREADABLE_MARK: &str = "does not run commands: its stored spec cannot be read";

/// Whether a stderr chunk reads as one of the daemon's refusals.
fn reads_as_refusal(chunk: &[u8]) -> bool {
    let text = String::from_utf8_lossy(chunk);
    text.starts_with("box ")
        && (text.ends_with(NOT_RUNNING_TAIL)
            || text.contains(EXEC_DISABLED_MARK)
            || text.contains(SPEC_UNREADABLE_MARK))
}

/// The state word in the daemon's text `box <label> is <state>. Only a
/// running box can run a command.`, or `None` when it cannot be read. Then
/// the daemon's text goes to stderr unchanged.
fn not_running_state(text: &str) -> Option<String> {
    let head = text.strip_prefix("box ")?.strip_suffix(NOT_RUNNING_TAIL)?;
    let (_, state) = head.trim_end().strip_suffix('.')?.rsplit_once(" is ")?;
    let word = !state.is_empty() && state.chars().all(|c| c.is_ascii_alphabetic() || c == '-');
    word.then(|| state.to_owned())
}

/// The refusal that the daemon's exit `status` and its held stderr `held`
/// make, for the box the user named `target`. `None` for anything else.
fn exec_refusal(target: &str, status: u32, held: &[u8]) -> Option<BoxExecRefusal> {
    let text = String::from_utf8_lossy(held);
    let target = target.to_owned();
    match status {
        2 if text.ends_with(NOT_RUNNING_TAIL) => {
            not_running_state(&text).map(|state| BoxExecRefusal::NotRunning { target, state })
        }
        5 if text.contains(EXEC_DISABLED_MARK) => Some(BoxExecRefusal::ExecDisabled { target }),
        5 if text.contains(SPEC_UNREADABLE_MARK) => Some(BoxExecRefusal::SpecUnreadable { target }),
        _ => None,
    }
}

/// The exit code a relayed channel ends with, or the refusal its held
/// stderr makes. Held stderr that makes no refusal is the command's own,
/// and goes to `err`. A channel that closed with no status ends with 1.
async fn relayed_status<E>(
    target: &str,
    relayed: Relayed,
    err: &mut E,
) -> Result<i32, anyhow::Error>
where
    E: tokio::io::AsyncWrite + Unpin,
{
    let Relayed { status, mut held } = relayed;
    let Some(status) = status else {
        release_held(&mut held, err).await?;
        tracing::warn!("the exec channel closed with no exit status");
        return Ok(1);
    };
    if let Some(refusal) = exec_refusal(target, status, &held) {
        return Err(refusal.into());
    }
    release_held(&mut held, err).await?;
    Ok(i32::try_from(status).unwrap_or(1))
}

/// The exec id a tty or a detached exec start answered on `channel`, or
/// the exit code of a start that ran nothing. The daemon's own words for
/// a failed start go to `err`.
async fn started_exec_id<C, E>(
    target: &str,
    channel: C,
    err: &mut E,
) -> Result<Result<minimald_rpc::exec::ExecId, i32>, anyhow::Error>
where
    C: ExecChannel,
    E: tokio::io::AsyncWrite + Unpin,
{
    let mut answer = Vec::new();
    let relayed = relay_box_channel(channel, None, &mut answer, err, true).await?;
    let status = relayed_status(target, relayed, err).await?;
    if status != 0 {
        return Ok(Err(status));
    }
    let text = String::from_utf8_lossy(&answer);
    let exec_id = minimald_rpc::exec::ExecId::parse(text.trim())
        .with_context(|| format!("the host of {target} did not answer with an exec id"))?;
    Ok(Ok(exec_id))
}

/// Waits for the exec `exec_id` in the box of `channels` to end and returns
/// its exit code, as BOX-149's wait gives it: the wait that `min box exec
/// -t` makes for a 124, and that `min box wait <box> --exec <id>` makes. An
/// exec that its own timeout ended returns as a [`BoxExecTimedOut`]. The
/// daemon's other words go to `err`.
pub(crate) async fn wait_exec_over<C, E>(
    channels: &mut C,
    target: &str,
    exec_id: &minimald_rpc::exec::ExecId,
    err: &mut E,
) -> Result<i32, anyhow::Error>
where
    C: ExecChannels,
    E: tokio::io::AsyncWrite + Unpin,
{
    let wire = minimald_rpc::exec::ExecRequest::ExecWait(exec_id.clone()).encode();
    let channel = channels.open(&wire).await?;
    let mut said = Vec::new();
    let relayed =
        relay_box_channel(channel, None, &mut tokio::io::sink(), &mut said, false).await?;
    let status = relayed_status(target, relayed, &mut said).await?;
    // The daemon's `timeout_message` says why a wait ended with 124.
    if status == i32::from(BoxExecTimedOut::EXIT_CODE)
        && String::from_utf8_lossy(&said).contains("ran past its timeout")
    {
        return Err(BoxExecTimedOut::waited(target, exec_id.as_str()).into());
    }
    // BCLI-057: the daemon has no running exec of this id and no stored end
    // for one.
    if status != 0 && String::from_utf8_lossy(&said).contains(NO_EXIT_MARK) {
        return Err(BoxExecIdRefusal::NoExitCode {
            target: target.to_owned(),
            exec_id: exec_id.to_string(),
        }
        .into());
    }
    err.write_all(&said).await?;
    err.flush().await?;
    Ok(status)
}

/// Connects this process's terminal to the tty exec that `attach_wire`
/// resumes, through `ssh -tt` and the terminal relay `min session attach`
/// uses. Returns ssh's exit status, which is the exec's.
async fn attach_exec_terminal(
    sock: &std::path::Path,
    id: boxes::SessionId,
    attach_wire: &str,
) -> Result<i32, anyhow::Error> {
    let ssh = minimal_client::attach::attach_command(sock, id, Some(attach_wire), None)?;
    let ssh = with_forced_tty(&ssh);
    tokio::task::spawn_blocking(move || {
        interactive_attach(ssh, true, crate::attach::TerminalUnwind::arm, |ssh| {
            let real = minimal_client::tty_relay::RealTty::acquire()
                .context(crate::attach::TerminalNotTaken)?;
            minimal_client::attach::run_interactive_attach_on(ssh, real, None)
        })
    })
    .await
    .context("the terminal attach's thread failed")?
}

/// `ssh` with `-tt` before its other arguments, so ssh asks for a terminal
/// for the command that `attach_command` gave it.
fn with_forced_tty(ssh: &std::process::Command) -> std::process::Command {
    let mut forced = std::process::Command::new(ssh.get_program());
    forced.arg("-tt").args(ssh.get_args());
    for (name, value) in ssh.get_envs() {
        match value {
            Some(value) => forced.env(name, value),
            None => forced.env_remove(name),
        };
    }
    forced
}

// The daemon's texts for an exec id it has no exec of (`no_exec_message`,
// `unknown_exit_message` and the `StopExec` refusal in `minimald`). The
// `--exec` tests of `min box stop`, `logs` and `wait` pin them: a change on
// the daemon side fails those tests.
const NO_EXEC_MARK: &str = "has no exec ";
const NO_EXIT_MARK: &str = "so it has no exit code or terminal for it.";

/// The exec id `text` that `--exec` gave for the box `target`
/// (BCLI-055, BCLI-056, BCLI-057). Text that is not an exec id is a
/// [`BoxExecIdRefusal::NotAnId`].
pub(crate) fn exec_id_arg(
    target: &str,
    text: &str,
) -> Result<minimald_rpc::exec::ExecId, BoxExecIdRefusal> {
    minimald_rpc::exec::ExecId::parse(text).map_err(|_| BoxExecIdRefusal::NotAnId {
        target: target.to_owned(),
        exec_id: text.trim().to_owned(),
    })
}

/// The exec channels of the box `resolved`, which the address `target`
/// named, on a client gated as `min box exec` gates it.
pub(crate) async fn exec_channels_of<'a>(
    resolved: &ResolvedBox,
    target: &'a str,
) -> Result<HostChannels<'a>, anyhow::Error> {
    Ok(HostChannels {
        client: gated_box_host_client(&resolved.host).await?,
        id: resolved.box_id,
        target,
    })
}

/// Records the verb `verb` with `--exec`, the box id `box_id` it resolved,
/// the exec id and the outcome of `result` on the log.
pub(crate) fn record_exec_id_outcome<T>(
    verb: &'static str,
    box_id: Option<boxes::SessionId>,
    exec_id: &str,
    result: &Result<T, anyhow::Error>,
) {
    let box_id = box_id.map(|id| id.to_string()).unwrap_or_default();
    match result {
        Ok(_) => tracing::info!(verb, box_id, exec_id, outcome = "ok"),
        Err(error) => {
            let outcome = if let Some(refusal) = error.downcast_ref::<BoxExecIdRefusal>() {
                refusal.outcome()
            } else if error.downcast_ref::<BoxExecTimedOut>().is_some() {
                "exec timeout"
            } else if error.downcast_ref::<BoxTimedOut>().is_some() {
                "wait timeout"
            } else if error.downcast_ref::<BoxAddressRefusal>().is_some() {
                "not found"
            } else {
                "error"
            };
            tracing::info!(verb, box_id, exec_id, outcome, "{error:#}");
        }
    }
}

/// Writes the output that the exec `exec_id` in the box of `channels`
/// captured to `out`, as BOX-149's output read gives it (BCLI-056). An
/// exec id the box has no exec of is a [`BoxExecIdRefusal::Unknown`]. The
/// daemon's other words go to `err`. Returns the exit code to end with.
pub(crate) async fn exec_output_over<C, O, E>(
    channels: &mut C,
    target: &str,
    exec_id: &minimald_rpc::exec::ExecId,
    out: &mut O,
    err: &mut E,
) -> Result<i32, anyhow::Error>
where
    C: ExecChannels,
    O: tokio::io::AsyncWrite + Unpin,
    E: tokio::io::AsyncWrite + Unpin,
{
    let wire = minimald_rpc::exec::ExecRequest::ExecOutput(exec_id.clone()).encode();
    let channel = channels.open(&wire).await?;
    let mut said = Vec::new();
    let relayed = relay_box_channel(channel, None, out, &mut said, false).await?;
    let status = relayed_status(target, relayed, &mut said).await?;
    if status != 0 && String::from_utf8_lossy(&said).contains(NO_EXEC_MARK) {
        return Err(BoxExecIdRefusal::Unknown {
            target: target.to_owned(),
            exec_id: exec_id.to_string(),
        }
        .into());
    }
    err.write_all(&said).await?;
    err.flush().await?;
    Ok(status)
}

/// `min box logs <box> --exec <id>` over the local `hosts`: resolves the
/// box, then writes the exec's captured output to `out` (BCLI-056).
/// Returns the exit code to end with.
pub(crate) async fn box_logs_exec_on_hosts<O, E>(
    hosts: Vec<crate::cmd::list::LocalHost>,
    target: &str,
    exec_text: &str,
    out: &mut O,
    err: &mut E,
) -> Result<i32, anyhow::Error>
where
    O: tokio::io::AsyncWrite + Unpin,
    E: tokio::io::AsyncWrite + Unpin,
{
    const VERB: &str = "box logs";
    let mut box_id = None;
    let result = async {
        let exec_id = exec_id_arg(target, exec_text)?;
        let resolved = resolve_box_on_hosts(hosts, target, VERB).await?;
        box_id = Some(resolved.box_id);
        crate::output::record_box_id(&resolved.box_id.to_string());
        let mut channels = exec_channels_of(&resolved, target).await?;
        exec_output_over(&mut channels, target, &exec_id, out, err).await
    }
    .await;
    record_exec_id_outcome(VERB, box_id, exec_text, &result);
    result
}

/// `min box logs <box> --exec <id>`: prints what one exec printed, and
/// exits with 0 when the whole output was read (BCLI-056).
pub async fn cmd_box_logs_exec(
    global: &GlobalArgs,
    target: &str,
    exec_text: &str,
) -> Result<(), anyhow::Error> {
    ensure_daemon(global)?;
    let hosts = crate::cmd::list::local_hosts(global)?;
    let mut out = tokio::io::stdout();
    let mut err = tokio::io::stderr();
    let code = box_logs_exec_on_hosts(hosts, target, exec_text, &mut out, &mut err).await?;
    if code == 0 {
        Ok(())
    } else {
        Err(Handoff::Exit(code).into())
    }
}

/// An RPC to stop one exec in a running box (BOX-151). The client's half of
/// `minimald`'s `StopExec`: the same name and the same wire fields.
struct StopExec;

/// The request for a [`StopExec`] RPC.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct StopExecRequest {
    /// The box the exec runs in.
    #[serde(rename = "box")]
    box_id: boxes::SessionId,
    /// The exec's id.
    exec_id: String,
}

/// The response for a [`StopExec`] RPC: how the exec ended.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct StopExecResponse {
    /// Why the exec ended, as its `exec_exited` event spells it. Required,
    /// so the untagged `Errorable` never reads a refusal as this answer.
    reason: String,
    /// Set when the exec had already ended before the stop, so the stop
    /// sent no signal.
    #[serde(default)]
    already_ended: bool,
}

impl minimald_rpc::OneshotSshRpc for StopExec {
    const NAME: &'static str = "minimald-v1-StopExec";
    type Request<'a> = StopExecRequest;
    type Response = minimald_rpc::Errorable<StopExecResponse>;
}

/// `min box stop <box> --exec <id>` over the local `hosts`: resolves the
/// box, stops that exec as BOX-151 defines, and writes one line to `out`
/// (BCLI-055). The box and its other execs keep running.
pub(crate) async fn box_stop_exec_on_hosts(
    hosts: Vec<crate::cmd::list::LocalHost>,
    out: &mut impl std::io::Write,
    target: &str,
    exec_text: &str,
) -> Result<(), anyhow::Error> {
    const VERB: &str = "box stop";
    let mut box_id = None;
    let result = async {
        let exec_id = exec_id_arg(target, exec_text)?;
        let resolved = resolve_box_on_hosts(hosts, target, VERB).await?;
        box_id = Some(resolved.box_id);
        crate::output::record_box_id(&resolved.box_id.to_string());
        let mut client = gated_box_host_client(&resolved.host).await?;
        let request = StopExecRequest {
            box_id: resolved.box_id,
            exec_id: exec_id.to_string(),
        };
        let stopped = match client
            .oneshot_rpc::<StopExec>(request)
            .await
            .context("StopExec RPC failed")?
        {
            minimald_rpc::Errorable::Ok(stopped) => stopped,
            minimald_rpc::Errorable::Err { error } => {
                return Err(if error.contains(NO_EXEC_MARK) {
                    BoxExecIdRefusal::Unknown {
                        target: target.to_owned(),
                        exec_id: exec_id.to_string(),
                    }
                    .into()
                } else if error.starts_with(minimald_rpc::UNKNOWN_SESSION_ID_LEAD) {
                    BoxAddressRefusal::NotFound {
                        address: target.to_owned(),
                    }
                    .into()
                } else {
                    anyhow::anyhow!("{error}")
                });
            }
        };
        write_exec_stop_line(out, target, exec_id.as_str(), stopped.already_ended)?;
        Ok(())
    }
    .await;
    record_exec_id_outcome(VERB, box_id, exec_text, &result);
    result
}

/// `min box stop <box> --exec <id>`: stops one exec and leaves the box
/// running (BCLI-055).
pub async fn cmd_box_stop_exec(
    global: &GlobalArgs,
    target: &str,
    exec_text: &str,
) -> Result<(), anyhow::Error> {
    ensure_daemon(global)?;
    let hosts = crate::cmd::list::local_hosts(global)?;
    let mut out = std::io::stdout().lock();
    box_stop_exec_on_hosts(hosts, &mut out, target, exec_text).await
}

/// The one line `min box stop <box> --exec <id>` prints: the exec stopped,
/// or it had already ended when the stop came (BCLI-055).
pub(crate) fn write_exec_stop_line(
    out: &mut impl std::io::Write,
    target: &str,
    exec_id: &str,
    already_ended: bool,
) -> std::io::Result<()> {
    if already_ended {
        writeln!(
            out,
            "Exec {exec_id} in {target} ended before the stop, so the stop changed nothing."
        )
    } else {
        writeln!(out, "Stopped exec {exec_id} in {target}.")
    }
}
