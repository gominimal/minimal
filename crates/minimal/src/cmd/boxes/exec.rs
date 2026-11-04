//! `min session exec` and `min session run`: relaying the remote command's
//! output and exit code.

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
    fn wire(&self) -> String {
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
    /// `min session attach` uses.
    Terminal,
    /// Through the daemon channel, with this process's stdio as pipes: the
    /// path for a stdin that is not a terminal.
    Pipes,
}

/// The bytes a caller sends to the command's stdin. `None` closes the
/// command's stdin at once.
pub(crate) type ExecInput = Option<tokio::sync::mpsc::Receiver<Vec<u8>>>;

/// `min box exec <box> [-t|--detach] [--timeout <d>] -- <cmd>`: runs the
/// command in the box and exits with the command's exit code (BCLI-053).
pub async fn cmd_box_exec(global: &GlobalArgs, args: BoxExecArgs) -> Result<(), anyhow::Error> {
    use minimald_rpc::exec::ExecMode;

    ensure_daemon(global)?;
    let hosts = crate::cmd::list::local_hosts(global)?;
    let request = BoxExecRequest::from_args(args);
    let stdin_is_tty = std::io::stdin().is_terminal();
    // A terminal on stdin is not read for an attached command, as `min task
    // run` does not read it: a read from a background job would stop this
    // process with SIGTTOU's sibling, SIGTTIN. `-t` is the way to type to
    // the command.
    let input = match request.mode {
        ExecMode::Detached => None,
        ExecMode::Attached if stdin_is_tty => None,
        ExecMode::Attached | ExecMode::Tty => Some(stdin_pump()),
    };
    let attach = if stdin_is_tty {
        TtyAttach::Terminal
    } else {
        TtyAttach::Pipes
    };
    let mut stdout = tokio::io::stdout();
    let mut stderr = tokio::io::stderr();
    let code = box_exec_on_hosts(
        hosts,
        daemon_host_kind(global),
        &request,
        attach,
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
/// output goes to `out` and `err`. A detached exec writes only its exec id
/// to `out`, and a tty exec writes its exec id to `err` first. A refusal
/// returns as a [`BoxExecRefusal`], and an exec that its own timeout ended
/// as a [`BoxExecTimedOut`]. The verb, the box id and the outcome go on
/// the command's span.
pub(crate) async fn box_exec_on_hosts<O, E>(
    hosts: Vec<crate::cmd::list::LocalHost>,
    kind: paths::HostKind,
    request: &BoxExecRequest,
    attach: TtyAttach,
    input: ExecInput,
    out: &mut O,
    err: &mut E,
) -> Result<i32, anyhow::Error>
where
    O: tokio::io::AsyncWrite + Unpin,
    E: tokio::io::AsyncWrite + Unpin,
{
    let resolved = resolve_box_on_hosts(hosts, &request.target, "box exec").await?;
    crate::output::record_box_id(&resolved.box_id.to_string());
    let ran = exec_in_resolved_box(&resolved, kind, request, attach, input, out, err).await;
    let mode = request.mode.name();
    match &ran {
        Ok(code) => tracing::info!(
            verb = "box exec",
            box_id = %resolved.box_id,
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
            tracing::info!(
                verb = "box exec",
                box_id = %resolved.box_id,
                mode,
                outcome,
                "{error:#}"
            );
        }
    }
    ran
}

/// [`box_exec_on_hosts`] once the address resolved to `resolved`.
async fn exec_in_resolved_box<O, E>(
    resolved: &ResolvedBox,
    kind: paths::HostKind,
    request: &BoxExecRequest,
    attach: TtyAttach,
    input: ExecInput,
    out: &mut O,
    err: &mut E,
) -> Result<i32, anyhow::Error>
where
    O: tokio::io::AsyncWrite + Unpin,
    E: tokio::io::AsyncWrite + Unpin,
{
    use minimald_rpc::exec::ExecMode;

    let sock = resolved.host.sock.as_path();
    let id = resolved.box_id;
    // A VM-backed box gets its row and its name hold back before the
    // command runs, as `min session exec` does before its ssh exec.
    let record = match control_sock_beside(sock).filter(|control| control.exists()) {
        Some(_) => attached_box_record(sock, id).await.unwrap_or_else(|error| {
            tracing::warn!("could not read the box's record ({error:#}); its box row is not asked back first");
            None
        }),
        None => None,
    };
    minimal_client::box_registration::resume_box_row(sock, record.as_ref()).await?;
    rehold_held_name_before_attach(kind, sock, id, record.as_ref()).await;

    let mut client = gated_box_host_client(&resolved.host).await?;
    let started = std::time::Instant::now();
    let channel = open_box_channel(&mut client, id, &request.target, &request.wire()).await?;
    match request.mode {
        ExecMode::Attached => {
            let relayed = relay_box_channel(channel, input, out, err, true).await?;
            let status = relayed_status(&request.target, relayed, err).await?;
            // The daemon ends an attached exec at its timeout with 124 and
            // says nothing more. Only a run that asked for a timeout, and
            // lasted that long, ended at it.
            if let Some(secs) = request.timeout_secs
                && status == i32::from(BoxExecTimedOut::EXIT_CODE)
                && started.elapsed() >= std::time::Duration::from_secs(secs)
            {
                return Err(BoxExecTimedOut::exec(&request.target, secs).into());
            }
            Ok(status)
        }
        ExecMode::Detached => {
            let exec_id = started_exec_id(&request.target, channel, err).await?;
            match exec_id {
                Ok(exec_id) => {
                    out.write_all(format!("{exec_id}\n").as_bytes()).await?;
                    out.flush().await?;
                    Ok(0)
                }
                Err(status) => Ok(status),
            }
        }
        ExecMode::Tty => {
            let exec_id = match started_exec_id(&request.target, channel, err).await? {
                Ok(exec_id) => exec_id,
                Err(status) => return Ok(status),
            };
            err.write_all(format!("{exec_id}\n").as_bytes()).await?;
            err.flush().await?;
            let attach_wire = minimald_rpc::exec::ExecRequest::ExecAttach(exec_id.clone()).encode();
            let status = match attach {
                TtyAttach::Pipes => {
                    let channel =
                        open_box_channel(&mut client, id, &request.target, &attach_wire).await?;
                    let relayed = relay_box_channel(channel, input, out, err, false).await?;
                    relayed_status(&request.target, relayed, err).await?
                }
                TtyAttach::Terminal => {
                    drop(input);
                    attach_exec_terminal(sock, id, &attach_wire).await?
                }
            };
            // The attach ends with 124 for an exec that its timeout ended,
            // or for a command that exited 124. The exec's stored end tells
            // them apart.
            if request.timeout_secs.is_some() && status == i32::from(BoxExecTimedOut::EXIT_CODE) {
                return wait_box_exec(&mut client, id, &request.target, &exec_id, err).await;
            }
            Ok(status)
        }
    }
}

/// Opens the channel that carries `wire` to the box `id`. A daemon that
/// refuses the channel no longer has the box, or cannot run in it.
async fn open_box_channel(
    client: &mut client::Client,
    id: boxes::SessionId,
    target: &str,
    wire: &str,
) -> Result<russh::Channel<russh::client::Msg>, anyhow::Error> {
    client
        .open_session_exec_channel(id, wire, &minimald_rpc::taskenv::TaskEnv::default())
        .await
        .map_err(|error| {
            tracing::warn!(%id, "the host refused the exec channel: {error:#}");
            anyhow::anyhow!(
                "The host of {target} refused to run the command. \
                 Run `min box show {target}` to see the box."
            )
        })
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
pub(crate) async fn relay_box_channel<O, E>(
    mut channel: russh::Channel<russh::client::Msg>,
    input: ExecInput,
    out: &mut O,
    err: &mut E,
    hold_refusal: bool,
) -> Result<Relayed, anyhow::Error>
where
    O: tokio::io::AsyncWrite + Unpin,
    E: tokio::io::AsyncWrite + Unpin,
{
    let pump = match input {
        None => {
            channel.eof().await.context("close the command's stdin")?;
            None
        }
        Some(mut rx) => {
            let mut to_channel = channel.make_writer();
            // Both results are dropped: the command can end before it reads
            // all of its input, and the channel loop below sees that.
            Some(tokio::spawn(async move {
                while let Some(chunk) = rx.recv().await {
                    if to_channel.write_all(&chunk).await.is_err() {
                        break;
                    }
                }
                let _ = to_channel.shutdown().await;
            }))
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
                out.write_all(&data).await.context("write the command's stdout")?;
                out.flush().await.context("write the command's stdout")?;
            }
            russh::ChannelMsg::ExtendedData { data, ext: 1 } => {
                if hold_refusal && !seen_output && held.is_empty() && reads_as_refusal(&data) {
                    held.extend_from_slice(&data);
                } else {
                    release_held(&mut held, err).await?;
                    err.write_all(&data).await.context("write the command's stderr")?;
                    err.flush().await.context("write the command's stderr")?;
                }
                seen_output = true;
            }
            russh::ChannelMsg::ExitStatus { exit_status } => status = Some(exit_status),
            _ => {}
        }
    }
    if let Some(pump) = pump {
        pump.abort();
    }
    Ok(Relayed { status, held })
}

/// Writes the held stderr to `err`, and empties it.
async fn release_held<E>(held: &mut Vec<u8>, err: &mut E) -> Result<(), anyhow::Error>
where
    E: tokio::io::AsyncWrite + Unpin,
{
    if !held.is_empty() {
        err.write_all(held).await.context("write the command's stderr")?;
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

/// The refusal that the daemon's exit `status` and its held stderr `held`
/// make, for the box the user named `target`. `None` for anything else.
fn exec_refusal(target: &str, status: u32, held: &[u8]) -> Option<BoxExecRefusal> {
    let text = String::from_utf8_lossy(held);
    let target = target.to_owned();
    match status {
        2 if text.ends_with(NOT_RUNNING_TAIL) => Some(BoxExecRefusal::NotRunning { target }),
        5 if text.contains(EXEC_DISABLED_MARK) => Some(BoxExecRefusal::ExecDisabled { target }),
        5 if text.contains(SPEC_UNREADABLE_MARK) => Some(BoxExecRefusal::SpecUnreadable { target }),
        _ => None,
    }
}

/// The exit code a relayed channel ends with, or the refusal its held
/// stderr makes. Held stderr that makes no refusal is the command's own,
/// and goes to `err`. A channel that closed with no status ends with 1.
async fn relayed_status<E>(target: &str, relayed: Relayed, err: &mut E) -> Result<i32, anyhow::Error>
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
async fn started_exec_id<E>(
    target: &str,
    channel: russh::Channel<russh::client::Msg>,
    err: &mut E,
) -> Result<Result<minimald_rpc::exec::ExecId, i32>, anyhow::Error>
where
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

/// Waits for the exec `exec_id` in the box `id` to end and returns its exit
/// code, as BOX-149's wait gives it. An exec that its own timeout ended
/// returns as a [`BoxExecTimedOut`]. The daemon's other words go to `err`.
pub(crate) async fn wait_box_exec<E>(
    client: &mut client::Client,
    id: boxes::SessionId,
    target: &str,
    exec_id: &minimald_rpc::exec::ExecId,
    err: &mut E,
) -> Result<i32, anyhow::Error>
where
    E: tokio::io::AsyncWrite + Unpin,
{
    let wire = minimald_rpc::exec::ExecRequest::ExecWait(exec_id.clone()).encode();
    let channel = open_box_channel(client, id, target, &wire).await?;
    let mut said = Vec::new();
    let relayed = relay_box_channel(channel, None, &mut tokio::io::sink(), &mut said, false).await?;
    let status = relayed_status(target, relayed, &mut said).await?;
    // The daemon's `timeout_message` says why a wait ended with 124.
    if status == i32::from(BoxExecTimedOut::EXIT_CODE)
        && String::from_utf8_lossy(&said).contains("ran past its timeout")
    {
        return Err(BoxExecTimedOut::waited(target, exec_id.as_str()).into());
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
