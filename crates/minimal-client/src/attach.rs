//! Building the `ssh` invocation for attaching to a session.
//!
//! Shared between the `min session attach` CLI path and the `min dash` TUI
//! (which suspends itself around the attach). Both run the interactive
//! attach through the client-owned terminal relay
//! ([`run_interactive_attach`]); the CLI's exec path runs the command
//! itself, with no pty of its own.

use std::path::Path;

use crate::tty_relay;
use anyhow::Context as _;

/// Read and validate the session-key config, returning the resolved
/// [`sessions::keys::SessionKeys`] to negotiate at attach. A missing config
/// file yields the shipped defaults; a present-but-invalid one (e.g. a
/// termios-special leader) surfaces its error loudly so the user fixes the
/// config rather than silently attaching with the wrong chord.
///
/// Only the interactive attach path needs the keys (non-interactive exec
/// channels have no detach); callers pass `None` to [`attach_command`] for
/// those.
pub fn resolve_session_keys(
    config_dir: Option<&Path>,
) -> Result<sessions::keys::SessionKeys, anyhow::Error> {
    let cfg_path = paths::minimal_config_dir_with_override(config_dir).join("config.toml");
    let cfg = sessions::client::config::read_config_or_default(&cfg_path)
        .map_err(|e| anyhow::anyhow!("reading session-keys config {cfg_path:?}: {e}"))?;
    cfg.session_keys
        .to_session_keys()
        .map_err(|e| anyhow::anyhow!("invalid session-keys config: {e}"))
}

/// Shell-quote a string for safe interpolation into `sh -c`.
pub fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\"'\"'"))
}

/// Quote a path for use as an `ssh -o` option value.
///
/// ssh re-parses the value as a config line, splitting on whitespace to allow a
/// file list and honouring `\` escapes inside quotes. So the quotes carry a path
/// with spaces, and `\`/`"` must be escaped within them — unescaped, a `"`
/// resolves the option to the wrong file and a trailing `\` swallows the closing
/// quote, both of which make ssh reject the line outright.
pub fn ssh_opt_quote(path: &Path) -> String {
    // Backslashes first: escaping quotes introduces backslashes of its own.
    let escaped = path
        .display()
        .to_string()
        .replace('\\', r"\\")
        .replace('"', "\\\"");
    format!("\"{escaped}\"")
}

/// The `ssh` host-key options for attaching, given the `known_hosts` sitting
/// next to the daemon socket.
///
/// minvmd records the guest's host key there from the boot beacon, so when the
/// file is present we pin against it. A native minimald also writes this.
pub fn host_key_opts(known_hosts: &Path) -> [String; 2] {
    if known_hosts.is_file() {
        [
            "StrictHostKeyChecking=yes".to_string(),
            format!("UserKnownHostsFile={}", ssh_opt_quote(known_hosts)),
        ]
    } else {
        [
            "StrictHostKeyChecking=no".to_string(),
            "UserKnownHostsFile=/dev/null".to_string(),
        ]
    }
}

/// Build the `ssh` command that attaches to session `id` via the daemon
/// socket at `sock`.
///
/// `wire` is an already-encoded [`minimald_rpc::exec`] request, or `None` for
/// the interactive shell. Callers name their own form — [`remote_command`] for
/// a user's argv, [`minimald_rpc::exec::ExecRequest::TaskRun`] for a task — so
/// this function never has to guess what a caller meant.
///
/// The interactive path (`wire: None`) forces a PTY with `-tt` — the
/// daemon's shell_request handler mints the PTY-backed session shell. Its
/// callers run the command through [`run_interactive_attach`], which owns
/// the user's terminal and relays it to ssh over a local pty.
///
/// `session_keys` negotiates the configurable detach/forward chord per
/// channel: when `Some`, each resolved key is sent as an env var (with a
/// matching `SendEnv` option) the daemon reads back alongside
/// `MINIMAL_SESSION_ID` and re-validates as a silent backstop. Pass `None`
/// for non-interactive exec channels, which have no detach.
pub fn attach_command(
    sock: &Path,
    id: sessions::SessionId,
    wire: Option<&str>,
    session_keys: Option<&sessions::keys::SessionKeys>,
) -> Result<std::process::Command, anyhow::Error> {
    // ProxyCommand points at our own `proxy` subcommand so we don't
    // depend on socat or nc being installed.
    let exe = std::env::current_exe().context("cannot determine current exe")?;
    let proxy_cmd = format!(
        "{} proxy --socket {}",
        shell_quote(&exe.display().to_string()),
        shell_quote(&sock.display().to_string()),
    );

    let [strict, known_hosts_file] = host_key_opts(&sock.with_file_name(paths::KNOWN_HOSTS_FILE));

    let mut ssh = std::process::Command::new("ssh");
    // Pin the shell ssh uses to run the ProxyCommand. ssh launches a
    // ProxyCommand via `$SHELL -c` and execs `$SHELL` with no PATH lookup, so a
    // caller whose `$SHELL` is a bare name (`fish`) or points at a shell absent
    // from this context fails with "<shell>: No such file or directory" and the
    // transport dies at "banner exchange … Broken pipe". Our ProxyCommand is a
    // full-path `min proxy …` that needs nothing but a POSIX `sh`, so force the
    // always-present `/bin/sh` rather than inherit the user's interactive shell.
    ssh.env("SHELL", "/bin/sh");
    ssh.env("MINIMAL_SESSION_ID", id.to_string());
    ssh.args([
        "-o",
        "SendEnv=MINIMAL_SESSION_ID",
        // Forward the user's locale and timezone into the session, mirroring a
        // conventional `SendEnv LANG LC_* TZ`. The daemon accepts only these
        // (its `AcceptEnv` allowlist) and folds them in below any loadout.
        // `TERM` needs no `SendEnv`: ssh always carries it in the PTY request.
        "-o",
        "SendEnv=LANG",
        "-o",
        "SendEnv=LC_*",
        "-o",
        "SendEnv=TZ",
        "-o",
        &format!("ProxyCommand={proxy_cmd}"),
        "-o",
        &strict,
        "-o",
        &known_hosts_file,
    ]);
    // Negotiate the session-key config per channel: send each resolved key
    // as an env var the daemon reads back (alongside MINIMAL_SESSION_ID) and
    // re-validates as a silent backstop. ssh's `SendEnv` forwards a var only
    // when it's present in the child environment, so each `SendEnv` option is
    // paired with its `env` set above. Only the interactive attach path sends
    // these — exec/task channels pass `None`.
    if let Some(keys) = session_keys {
        ssh.env(sessions::keys::LEADER_ENV, keys.leader.as_config_str())
            .env(
                sessions::keys::DETACH_KEY_ENV,
                keys.detach_key.as_config_str(),
            )
            .env(
                sessions::keys::FORWARD_KEY_ENV,
                keys.forward_key.as_config_str(),
            )
            .env(
                sessions::keys::BELL_ENV,
                if keys.bell_on_leader { "1" } else { "0" },
            )
            .args([
                "-o",
                &format!("SendEnv={}", sessions::keys::LEADER_ENV),
                "-o",
                &format!("SendEnv={}", sessions::keys::DETACH_KEY_ENV),
                "-o",
                &format!("SendEnv={}", sessions::keys::FORWARD_KEY_ENV),
                "-o",
                &format!("SendEnv={}", sessions::keys::BELL_ENV),
            ]);
    }

    // The interactive path opens the in-sandbox session shell via the daemon's
    // `shell_request`, which requires a PTY. Force one with `-tt` so ssh
    // allocates it even when our stdin is a pty driven programmatically rather
    // than the controlling terminal. The `--command` path is a non-interactive
    // exec and needs no PTY.
    //
    // Note: `-tt` over a *non-terminal* stdin is a trap — ssh still forces the
    // remote PTY, yet the interactive shell reading it never sees an EOF from a
    // redirected local stdin (`< /dev/null`, a pipe), so the command blocks
    // forever (#953). Callers must guarantee a terminal on stdin.
    if wire.is_none() {
        ssh.arg("-tt");
    }

    // The SSH host identity must match the known_hosts entry the daemon wrote,
    // which it keys on [`paths::ssh_host_alias`] (`local-minimald<N>` /
    // `local-minvmd<N>` for the default VM, `<vm>.local-minvmd<N>` for a named
    // VM).
    // Derive it from the socket path so the client and daemon can never
    // disagree on the name.
    let host_alias = sock
        .parent()
        .and_then(paths::ssh_host_alias)
        .context("daemon socket path has no provider-dir parent")?;
    ssh.arg(host_alias);

    // If a command was provided, pass it to ssh (non-interactive exec).
    // Otherwise, ssh opens an interactive shell via shell_request.
    if let Some(wire) = wire {
        ssh.arg(wire);
    }

    Ok(ssh)
}

/// Run an interactive attach (`wire: None`) through the client-owned
/// [relay](tty_relay) on the real terminal ([`tty_relay::RealTty::acquire`]):
/// ssh goes on the slave end of a pty pair, the relay keeps the real
/// terminal in ssh's own raw set, restores its attach-start termios on every
/// exit path, and returns ssh's exit status unchanged, death by a signal
/// included. The termios is restored by the time this returns, so any
/// unwind codes the caller still owes the terminal land on a cooked tty.
///
/// `suspend` is the hook a prompt uses to borrow the real terminal
/// mid-attach (the dynamic-ingress `ask` flow, NET-045): it runs on its
/// own thread for the duration of the attach with a
/// [`tty_relay::RelayHandle`], whose `suspend` hands the terminal over
/// (attach-start termios, session output buffered) and whose `resume`
/// takes it back. The hook thread is not joined: an attach that ends
/// while a prompt is up still exits with ssh's status, and every handle
/// call after that is a no-op or an error. The VM-backed attach hands
/// [`HostAsks::into_hook`]; `None` for callers that just attach.
///
/// The exec path (`wire: Some`) never comes here: the caller runs ssh
/// itself, with no relay and no pty.
pub fn run_interactive_attach(
    ssh: std::process::Command,
    suspend: Option<tty_relay::SuspendHook>,
) -> Result<std::process::ExitStatus, anyhow::Error> {
    let real = tty_relay::RealTty::acquire()
        .context("the interactive attach needs a terminal, but none could be taken")?;
    run_interactive_attach_on(ssh, real, suspend)
}

/// [`run_interactive_attach`] on a terminal the caller already holds.
pub fn run_interactive_attach_on(
    ssh: std::process::Command,
    real: tty_relay::RealTty,
    suspend: Option<tty_relay::SuspendHook>,
) -> Result<std::process::ExitStatus, anyhow::Error> {
    let relay = tty_relay::Relay::start(ssh, real)?;
    if let Some(hook) = suspend {
        let handle = relay.handle();
        // A hook that cannot get a thread just never prompts; the attach
        // itself is unaffected.
        if let Err(e) = std::thread::Builder::new()
            .name("tty-relay-suspend-hook".into())
            .spawn(move || hook(&handle))
        {
            tracing::warn!("tty relay: could not start the suspend hook: {e}");
        }
    }
    relay.join(None)
}

// ---------------------------------------------------------------------------
// Host-side asks (NET-045)
// ---------------------------------------------------------------------------

/// The VM host daemon's control socket's file name beside its ssh socket:
/// `minvmd::control::CONTROL_SOCK_FILE`, spelled here because this crate
/// does not depend on the VM host daemon; the CLI's tests pin the two equal.
pub const VM_HOST_CONTROL_SOCK_FILE: &str = "control.sock";

/// How long one exchange with the VM host daemon's control socket may take:
/// the row read, the subscription's acknowledgement, and a recorded answer.
/// The subscription itself is held for the whole attach, with no bound.
const HOST_ASK_CONTROL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// An interactive attach's subscription to its box's pending asks on a
/// VM-backed host (NET-045): the VM host daemon offers each ask the in-VM
/// daemon raises to every interactive attach subscribed to the box's row,
/// and this side renders the dialog on the real terminal and records the
/// human's answer through the host door. Only an interactive relay attach
/// subscribes: an exec channel, a task and `min dash`'s list view never do,
/// so none of them counts as attached.
///
/// Opened before the attach starts, so the subscription is in place by the
/// time the human could expose a port; served for the attach's duration
/// by the relay's suspend hook ([`Self::into_hook`]).
pub struct HostAsks {
    control_sock: std::path::PathBuf,
    subscription: std::io::BufReader<std::os::unix::net::UnixStream>,
}

/// The terminal side of the ask dialog: the relay's suspend and resume, as
/// a trait so the serving loop is testable without a pty.
pub trait AskTerminal {
    /// Hand the real terminal to the dialog: the relay stops forwarding and
    /// puts the attach-start termios back. Errors once the attach ended.
    fn suspend_for_ask(&self) -> Result<(), anyhow::Error>;
    /// Take the terminal back and resume relaying.
    fn resume_after_ask(&self);
    /// Whether the session ended while the dialog held the terminal: a
    /// cancelled dialog records nothing.
    fn ask_cancelled(&self) -> bool;
}

impl AskTerminal for tty_relay::RelayHandle {
    fn suspend_for_ask(&self) -> Result<(), anyhow::Error> {
        // The lease is not held: the handle's resume ends the suspension.
        self.suspend().map(drop)
    }

    fn resume_after_ask(&self) {
        self.resume();
    }

    fn ask_cancelled(&self) -> bool {
        self.is_cancelled()
    }
}

/// One request line to the VM host daemon's control socket, one reply line
/// back, both bounded by [`HOST_ASK_CONTROL_TIMEOUT`]; the connection is
/// handed back for a caller that keeps it.
fn host_control(
    control_sock: &Path,
    request: &minimald_rpc::BoxControlRequest,
) -> Result<
    (
        minimald_rpc::BoxControlReply,
        std::io::BufReader<std::os::unix::net::UnixStream>,
    ),
    anyhow::Error,
> {
    use std::io::{BufRead as _, Write as _};
    let mut stream = std::os::unix::net::UnixStream::connect(control_sock).with_context(|| {
        format!(
            "connecting to the VM host daemon's control socket at {}",
            control_sock.display()
        )
    })?;
    stream.set_read_timeout(Some(HOST_ASK_CONTROL_TIMEOUT))?;
    stream.set_write_timeout(Some(HOST_ASK_CONTROL_TIMEOUT))?;
    let mut line = serde_json_lenient::to_string(request).context("serializing the request")?;
    line.push('\n');
    stream.write_all(line.as_bytes())?;
    let mut reader = std::io::BufReader::new(stream);
    let mut reply = String::new();
    reader.read_line(&mut reply)?;
    if reply.trim().is_empty() {
        anyhow::bail!("the VM host daemon closed its control socket without answering");
    }
    let reply = serde_json_lenient::from_str(reply.trim())
        .with_context(|| format!("the VM host daemon's reply did not parse: {reply}"))?;
    Ok((reply, reader))
}

impl HostAsks {
    /// Subscribe to the pending asks of the box whose row is named
    /// `box_name` on the VM host daemon at `control_sock`: the row read
    /// answers the row's host-minted box id, and the subscription is keyed
    /// by that id, never by a name a guest could report.
    ///
    /// # Errors
    ///
    /// The socket did not answer, no live row carries the name, or the
    /// daemon refused the subscription.
    pub fn subscribe(control_sock: &Path, box_name: &str) -> Result<Self, anyhow::Error> {
        let (row, _) = host_control(
            control_sock,
            &minimald_rpc::BoxControlRequest::ReadRow(minimald_rpc::ReadRowRequest {
                name: box_name.to_string(),
            }),
        )?;
        let box_id = match row {
            minimald_rpc::BoxControlReply::Row(row) => row.box_id,
            minimald_rpc::BoxControlReply::NoRow { .. } => {
                anyhow::bail!("the VM host daemon holds no row for box {box_name:?}")
            }
            other => anyhow::bail!("the VM host daemon answered the row read with {other:?}"),
        };
        let (ack, subscription) = host_control(
            control_sock,
            &minimald_rpc::BoxControlRequest::SubscribeAsks(minimald_rpc::SubscribeAsksRequest {
                box_id,
            }),
        )?;
        match ack {
            minimald_rpc::BoxControlReply::AsksSubscribed { .. } => {}
            minimald_rpc::BoxControlReply::Error { error } => {
                anyhow::bail!("the VM host daemon refused the ask subscription: {error}")
            }
            other => anyhow::bail!("the VM host daemon answered the subscription with {other:?}"),
        }
        // Held for the attach's whole life: offers arrive whenever the box
        // asks, so the read has no bound.
        subscription.get_ref().set_read_timeout(None)?;
        tracing::info!(box = %box_name, "subscribed to the box's pending asks on the VM host");
        Ok(Self {
            control_sock: control_sock.to_path_buf(),
            subscription,
        })
    }

    /// [`Self::subscribe`] on the VM host daemon's control socket beside
    /// the daemon's ssh socket `ssh_sock`, for a caller that does not know
    /// whether the daemon is VM-backed: anything but a subscription — no
    /// such socket, a native daemon's socket that serves no rows, no row
    /// for the box — is `None`, said at debug.
    pub fn subscribe_beside(ssh_sock: &Path, box_name: &str) -> Option<Self> {
        let control_sock = ssh_sock.parent()?.join(VM_HOST_CONTROL_SOCK_FILE);
        if !control_sock.exists() {
            return None;
        }
        Self::subscribe(&control_sock, box_name)
            .inspect_err(|error| {
                tracing::debug!(box = %box_name, error = %format!("{error:#}"), "no host-side ask subscription");
            })
            .ok()
    }

    /// The relay's suspend hook: serve the subscription for the attach's
    /// duration, rendering each offer with [`render_ask_dialog`].
    pub fn into_hook(self) -> tty_relay::SuspendHook {
        Box::new(move |handle| self.serve(handle, render_ask_dialog))
    }

    /// Serve offers until the subscription ends: for each, suspend the
    /// relay, render the dialog with `dialog`, record its answer through
    /// the host door, and resume. An offer the daemon already dismissed is
    /// skipped; an attach that ended under the dialog records nothing.
    pub fn serve<T: AskTerminal>(
        mut self,
        terminal: &T,
        mut dialog: impl FnMut(&minimald_rpc::PendingAskOffer) -> minimald_rpc::AskAnswer,
    ) {
        use std::io::BufRead as _;
        loop {
            let mut line = String::new();
            match self.subscription.read_line(&mut line) {
                Ok(0) | Err(_) => return,
                Ok(_) => {}
            }
            let offer = match serde_json_lenient::from_str(line.trim()) {
                Ok(minimald_rpc::BoxControlReply::PendingAskOffer(offer)) => offer,
                Ok(_) | Err(_) => continue,
            };
            if self.dismissed_already(offer.ask_id) {
                continue;
            }
            if terminal.suspend_for_ask().is_err() {
                return;
            }
            tracing::info!(
                ask_id = %offer.ask_id,
                box = %offer.name,
                port = offer.port,
                "showing the host-side ask dialog"
            );
            let answer = dialog(&offer);
            if terminal.ask_cancelled() {
                return;
            }
            tracing::info!(ask_id = %offer.ask_id, answer = ?answer, "the ask dialog was answered");
            if let Err(error) = self.record(offer.ask_id, answer) {
                tracing::warn!(ask_id = %offer.ask_id, %error, "the ask answer was not recorded");
                eprintln!("The answer was not recorded: {error:#}");
            }
            terminal.resume_after_ask();
        }
    }

    /// Whether a dismissal for `ask_id` is already buffered behind its
    /// offer: another attach answered first, so there is no dialog to show.
    fn dismissed_already(&self, ask_id: minimald_rpc::AskId) -> bool {
        String::from_utf8_lossy(self.subscription.buffer())
            .lines()
            .filter_map(|line| serde_json_lenient::from_str(line.trim()).ok())
            .any(|reply| {
                matches!(
                    reply,
                    minimald_rpc::BoxControlReply::PendingAskDismissed { ask_id: id, .. }
                        if id == ask_id
                )
            })
    }

    /// Record `answer` for `ask_id` through the host door.
    fn record(
        &self,
        ask_id: minimald_rpc::AskId,
        answer: minimald_rpc::AskAnswer,
    ) -> Result<(), anyhow::Error> {
        let (reply, _) = host_control(
            &self.control_sock,
            &minimald_rpc::BoxControlRequest::RecordAskAnswer(
                minimald_rpc::RecordAskAnswerRequest { ask_id, answer },
            ),
        )?;
        match reply {
            minimald_rpc::BoxControlReply::AskAnswerRecorded { .. } => Ok(()),
            minimald_rpc::BoxControlReply::Error { error } => {
                anyhow::bail!(
                    "the VM host daemon refused it ({error}); another attach may have answered first"
                )
            }
            other => anyhow::bail!("the VM host daemon answered with {other:?}"),
        }
    }
}

/// The dialog's question, built from the offer's host-row fields alone: the
/// box's name as the host row holds it, the protocol and the port. Control
/// characters are dropped so nothing in a name can drive the terminal.
#[must_use]
pub fn ask_dialog_text(offer: &minimald_rpc::PendingAskOffer) -> String {
    let name: String = offer.name.chars().filter(|c| !c.is_control()).collect();
    format!(
        "Box '{name}' asks to publish {} port {} to the host. Allow?",
        offer.proto, offer.port
    )
}

/// The dialog's end as the answer recorded for it: a yes only for an
/// explicit yes; a no for a no, Ctrl-C, Escape and a closed or failed
/// input; and no-tty when there was no terminal to render on.
#[must_use]
pub fn ask_answer_from(result: Result<bool, inquire::InquireError>) -> minimald_rpc::AskAnswer {
    match result {
        Ok(true) => minimald_rpc::AskAnswer::Yes,
        Err(inquire::InquireError::NotTTY) => minimald_rpc::AskAnswer::NoTty,
        Ok(false) | Err(_) => minimald_rpc::AskAnswer::No,
    }
}

/// Render the ask dialog with `inquire` on the real terminal, in the
/// attach-start termios the suspended relay put back, defaulting to no.
#[must_use]
pub fn render_ask_dialog(offer: &minimald_rpc::PendingAskOffer) -> minimald_rpc::AskAnswer {
    ask_answer_from(
        inquire::Confirm::new(&ask_dialog_text(offer))
            .with_default(false)
            .with_help_message("y allows the publish; n, Esc or Ctrl-C refuses it")
            .prompt(),
    )
}

/// The single command string to hand `ssh`, or `None` for the interactive
/// shell.
///
/// ssh has no argv on the wire: it joins its trailing arguments with single
/// spaces and the far side runs the result through a shell — so an argv passed
/// through word by word is re-split by that shell, and every quote the *local*
/// shell already removed is gone for good. `min session exec s sh -c 'echo A B'`
/// arrived as `sh -c echo A B`, where `A` became `sh`'s `$0` and vanished from
/// the output (gominimal/inbox#558 — fully qualified because the bare `#NNN`
/// refs elsewhere in this tree point at this repo, and that one does not).
///
/// So the request is tagged instead ([`minimald_rpc::exec`]), and the arity
/// picks the tag:
///
/// * One argument is a shell command, carried as-is — the `ssh host '...'` form
///   the session e2e and the docs use (`min session exec s 'echo $PWD'`), where
///   pipes, globs and `$PWD` are the point and must reach the session's shell.
/// * Several arguments are an argv, carried as data. No shell reassembles them,
///   so a word keeps its spaces and its metacharacters stay literal.
///
/// Arity is a default, not a limitation: both forms are nameable on the wire,
/// so an explicit `--shell` / `--argv` flag could select one without changing
/// the protocol.
pub fn remote_command(command: &[String]) -> Option<String> {
    use minimald_rpc::exec::ExecRequest;
    match command {
        [] => None,
        [one] => Some(ExecRequest::Shell(one.clone()).encode()),
        words => Some(ExecRequest::Argv(words.to_vec()).encode()),
    }
}

/// The largest encoded exec command `min session exec` will hand to ssh.
///
/// Linux caps a single argument at `MAX_ARG_STRLEN` (128 KiB), so a command
/// that large already fails with `E2BIG` on the box; larger still, the exec
/// request exceeds the SSH transport's packet limit and tears the connection
/// down instead of erroring, leaving the client with ssh's rc 255 — the same
/// status a command's own `exit 255` produces. Refusing here, before ssh is
/// contacted, keeps the failure a clear client-side error.
///
/// The limit applies to the whole encoded wire for both forms on purpose. A
/// multi-word argv is stricter than it needs to be for `E2BIG` alone, since
/// each word is its own `execve` argument, but the whole wire still rides in
/// one SSH exec request and must fit the transport's packet limit. Do not
/// relax this into a per-word check without also bounding the packet.
pub const MAX_EXEC_COMMAND_BYTES: usize = 128 * 1024;

/// Encode a command for the wire, refusing one that exceeds
/// [`MAX_EXEC_COMMAND_BYTES`].
///
/// Returns the encoded command when it fits, or an error naming the size and
/// pointing large data at stdin or a file under `/workbench`.
pub fn checked_remote_command(command: &[String]) -> anyhow::Result<Option<String>> {
    let wire = remote_command(command);
    if let Some(wire) = wire.as_deref()
        && wire.len() >= MAX_EXEC_COMMAND_BYTES
    {
        anyhow::bail!(
            "the command is {} bytes once encoded; min session exec needs it under {} KiB once encoded; pass large data on stdin or in a file under /workbench",
            wire.len(),
            MAX_EXEC_COMMAND_BYTES / 1024,
        );
    }
    Ok(wire)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn attach_command_targets_the_provider_alias() {
        let sock = PathBuf::from("/tmp/x/providers/local-minimald0/ssh.sock");
        let cmd = attach_command(&sock, sessions::SessionId::nil(), None, None).unwrap();
        let args: Vec<_> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert!(args.iter().any(|a| a == "-tt"));
        assert_eq!(args.last().map(String::as_str), Some("local-minimald0"));
        assert!(
            args.iter()
                .any(|a| a.starts_with("ProxyCommand=") && a.contains("proxy --socket"))
        );
    }

    /// The exec path (`wire: Some`) is not the relay's: its command carries
    /// no stdio of its own (ssh inherits whatever the caller does not
    /// override) and no `-tt` forces a pty.
    #[test]
    fn exec_path_keeps_inherited_stdio() {
        let sock = PathBuf::from("/tmp/x/providers/local-minimald0/ssh.sock");
        let cmd = attach_command(&sock, sessions::SessionId::nil(), Some("wire"), None).unwrap();
        let args: Vec<_> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert!(!args.iter().any(|a| a == "-tt"));
        assert_eq!(args.last().map(String::as_str), Some("wire"));
        // `Command`'s alternate Debug names every stdio override set on it.
        let debug = format!("{cmd:#?}");
        for stdio in ["stdin", "stdout", "stderr"] {
            assert!(!debug.contains(stdio), "{stdio} overridden: {debug}");
        }
    }

    /// A named VM's socket nests under a per-name subdirectory, so the ssh
    /// host is the VM name namespaced under the provider-instance name.
    #[test]
    fn attach_command_targets_a_named_vm_alias() {
        let sock = PathBuf::from("/tmp/x/providers/local-minvmd0/alpha/ssh.sock");
        let cmd = attach_command(&sock, sessions::SessionId::nil(), None, None).unwrap();
        let args: Vec<_> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(args.last().map(String::as_str), Some("alpha.local-minvmd0"));
        assert!(
            args.iter()
                .any(|a| a.starts_with("ProxyCommand=") && a.contains("proxy --socket"))
        );
    }

    #[test]
    fn attach_command_with_exec_has_no_forced_pty() {
        let sock = PathBuf::from("/tmp/x/providers/local-minvmd0/ssh.sock");
        let wire = remote_command(&["min".to_string(), "run".to_string(), "test".to_string()]);
        let cmd = attach_command(&sock, sessions::SessionId::nil(), wire.as_deref(), None).unwrap();
        let args: Vec<_> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert!(!args.iter().any(|a| a == "-tt"));
        // One trailing argument, not three: ssh would join a word-per-arg argv
        // with spaces and let the far shell re-split it.
        assert_eq!(
            args.last().map(String::as_str),
            Some(r#"min://argv ["min","run","test"]"#)
        );
    }

    /// No command is the interactive shell: ssh gets no trailing argument at
    /// all, and the daemon opens the session shell via `shell_request`.
    #[test]
    fn no_command_is_the_interactive_shell() {
        assert_eq!(remote_command(&[]), None);
    }

    /// The `ssh host '...'` form the e2e and docs use: a lone argument is a
    /// shell command, so `$PWD`, pipes and `;` still mean what they say when
    /// the session's shell sees them.
    #[test]
    fn a_lone_argument_is_carried_as_a_shell_command() {
        let wire = remote_command(&["echo EXEC_OK $PWD".to_string()]).unwrap();
        assert_eq!(
            minimald_rpc::exec::ExecRequest::parse(&wire),
            Ok(minimald_rpc::exec::ExecRequest::Shell(
                "echo EXEC_OK $PWD".to_string()
            ))
        );
    }

    /// The bug: `min session exec s sh -c 'echo A B C'`. ssh's join let the far
    /// shell re-split the `-c` argument, so `A` was eaten as `sh`'s `$0` and
    /// only `B C` printed. Carried as an argv, the words arrive as data and
    /// `echo A B C` stays one argument.
    #[test]
    fn a_multi_word_argv_survives_as_data() {
        let wire = remote_command(&["sh".to_string(), "-c".to_string(), "echo A B C".to_string()])
            .unwrap();
        assert_eq!(
            minimald_rpc::exec::ExecRequest::parse(&wire),
            Ok(minimald_rpc::exec::ExecRequest::Argv(vec![
                "sh".to_string(),
                "-c".to_string(),
                "echo A B C".to_string(),
            ]))
        );
    }

    /// A session command that merely looks like one of the daemon's own is the
    /// session's: nothing about `min ...` is special on the wire any more, so
    /// the session's `min` binary is reachable (gominimal/inbox#558).
    #[test]
    fn a_min_command_still_belongs_to_the_session() {
        let wire = remote_command(&["min --version".to_string()]).unwrap();
        assert_eq!(
            minimald_rpc::exec::ExecRequest::parse(&wire),
            Ok(minimald_rpc::exec::ExecRequest::Shell(
                "min --version".to_string()
            ))
        );
    }

    /// A command just under the limit encodes and passes the guard; one byte
    /// over is refused with the size in the message, before any ssh command is
    /// built.
    #[test]
    fn checked_remote_command_refuses_an_oversized_command() {
        // A lone argument encodes as `min://shell <cmd>`; size the payload so
        // the wire lands exactly on the boundary.
        let prefix_len = "min://shell ".len();
        let under = "x".repeat(MAX_EXEC_COMMAND_BYTES - prefix_len - 1);
        let wire = checked_remote_command(&[under]).unwrap().unwrap();
        assert_eq!(wire.len(), MAX_EXEC_COMMAND_BYTES - 1);

        // The per-argument limit includes the terminating NUL, so a wire of
        // exactly the limit still fails with E2BIG once ssh execs it. Refuse
        // the boundary too, not just lengths above it.
        let at_limit = "x".repeat(MAX_EXEC_COMMAND_BYTES - prefix_len);
        let boundary_wire = remote_command(std::slice::from_ref(&at_limit)).unwrap();
        assert_eq!(boundary_wire.len(), MAX_EXEC_COMMAND_BYTES);
        assert!(checked_remote_command(&[at_limit]).is_err());

        let over = "x".repeat(MAX_EXEC_COMMAND_BYTES - prefix_len + 1);
        let err = checked_remote_command(&[over]).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("needs it under 128 KiB once encoded"));
        assert!(msg.contains(&format!("{} bytes", MAX_EXEC_COMMAND_BYTES + 1)));
    }

    /// The interactive attach path negotiates the session-key config: each
    /// resolved key is set on the child env with a matching `SendEnv` option
    /// so the daemon adopts the user's chord for that channel.
    #[test]
    fn attach_command_negotiates_session_keys_when_given() {
        let sock = PathBuf::from("/tmp/x/providers/local-minimald0/ssh.sock");
        let keys = sessions::keys::SessionKeys::default();
        let cmd = attach_command(&sock, sessions::SessionId::nil(), None, Some(&keys)).unwrap();

        let env: std::collections::HashMap<String, String> = cmd
            .get_envs()
            .filter_map(|(k, v)| {
                v.map(|v| {
                    (
                        k.to_string_lossy().into_owned(),
                        v.to_string_lossy().into_owned(),
                    )
                })
            })
            .collect();
        assert_eq!(
            env.get(sessions::keys::LEADER_ENV).map(String::as_str),
            Some("ctrl-]")
        );
        assert_eq!(
            env.get(sessions::keys::DETACH_KEY_ENV).map(String::as_str),
            Some("d")
        );
        assert_eq!(
            env.get(sessions::keys::FORWARD_KEY_ENV).map(String::as_str),
            Some("ctrl-]")
        );
        assert_eq!(
            env.get(sessions::keys::BELL_ENV).map(String::as_str),
            Some("0")
        );

        let args: Vec<String> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        for name in [
            sessions::keys::LEADER_ENV,
            sessions::keys::DETACH_KEY_ENV,
            sessions::keys::FORWARD_KEY_ENV,
            sessions::keys::BELL_ENV,
        ] {
            assert!(
                args.iter().any(|a| a == format!("SendEnv={name}").as_str()),
                "missing SendEnv={name} in {args:?}",
            );
        }
    }

    /// Passing no session keys (`None`) sets no session-key env vars and asks
    /// ssh to forward none: exec channels have no detach chord.
    #[test]
    fn attach_command_omits_session_keys_when_none() {
        let sock = PathBuf::from("/tmp/x/providers/local-minimald0/ssh.sock");
        let cmd = attach_command(&sock, sessions::SessionId::nil(), None, None).unwrap();

        let env: std::collections::HashMap<String, String> = cmd
            .get_envs()
            .filter_map(|(k, v)| {
                v.map(|v| {
                    (
                        k.to_string_lossy().into_owned(),
                        v.to_string_lossy().into_owned(),
                    )
                })
            })
            .collect();
        for name in [
            sessions::keys::LEADER_ENV,
            sessions::keys::DETACH_KEY_ENV,
            sessions::keys::FORWARD_KEY_ENV,
            sessions::keys::BELL_ENV,
        ] {
            assert!(!env.contains_key(name), "{name} should not be set for exec");
        }

        let args: Vec<String> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        for name in [
            sessions::keys::LEADER_ENV,
            sessions::keys::DETACH_KEY_ENV,
            sessions::keys::FORWARD_KEY_ENV,
            sessions::keys::BELL_ENV,
        ] {
            assert!(
                !args.iter().any(|a| a == format!("SendEnv={name}").as_str()),
                "SendEnv={name} should not appear for exec in {args:?}",
            );
        }
    }

    /// A VM-backed provider dir carries the guest's recorded host key, so
    /// attach must verify against it rather than waive the check.
    #[test]
    fn host_key_opts_pin_to_an_adjacent_known_hosts() {
        let tmp = tempfile::tempdir().unwrap();
        let known_hosts = tmp.path().join(paths::KNOWN_HOSTS_FILE);
        std::fs::write(&known_hosts, "local-minimald0 ssh-ed25519 AAAA...\n").unwrap();

        let [strict, hosts_file] = host_key_opts(&known_hosts);
        assert_eq!(strict, "StrictHostKeyChecking=yes");
        assert_eq!(
            hosts_file,
            format!("UserKnownHostsFile=\"{}\"", known_hosts.display())
        );
    }

    /// No recorded host key yet (first boot): the check is waived rather
    /// than failing the attach, and nothing is written to a real known_hosts.
    #[test]
    fn host_key_opts_waive_when_no_known_hosts() {
        let tmp = tempfile::tempdir().unwrap();
        let [strict, hosts_file] = host_key_opts(&tmp.path().join(paths::KNOWN_HOSTS_FILE));
        assert_eq!(strict, "StrictHostKeyChecking=no");
        assert_eq!(hosts_file, "UserKnownHostsFile=/dev/null");
    }

    /// ssh re-parses the option value as a config line, so the path must survive
    /// its quote and backslash handling intact. These expectations were checked
    /// against OpenSSH's own parser with `ssh -G`.
    #[test]
    fn ssh_opt_quote_escapes_backslashes_and_quotes() {
        let q = |s: &str| ssh_opt_quote(std::path::Path::new(s));

        assert_eq!(q("/state/known_hosts"), r#""/state/known_hosts""#);
        // A space is why we quote at all: ssh would otherwise read a file list.
        assert_eq!(q("/st ate/known_hosts"), r#""/st ate/known_hosts""#);
        assert_eq!(q(r#"/st"ate/known_hosts"#), r#""/st\"ate/known_hosts""#);
        assert_eq!(q(r"/st\ate/known_hosts"), r#""/st\\ate/known_hosts""#);
        // A trailing backslash must not escape the closing quote.
        assert_eq!(q(r"/state\"), r#""/state\\""#);
    }

    /// The assembled option for a state dir carrying every character ssh's
    /// parser treats specially.
    #[test]
    fn host_key_opts_pin_to_a_path_needing_escapes() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join(r#"sp ace q"uote back\slash"#);
        std::fs::create_dir_all(&dir).unwrap();
        let known_hosts = dir.join(paths::KNOWN_HOSTS_FILE);
        std::fs::write(&known_hosts, "local-minimald0 ssh-ed25519 AAAA...\n").unwrap();

        let [strict, hosts_file] = host_key_opts(&known_hosts);
        assert_eq!(strict, "StrictHostKeyChecking=yes");
        assert!(
            hosts_file.contains(r#"q\"uote"#) && hosts_file.contains(r"back\\slash"),
            "path must reach ssh escaped, got: {hosts_file}"
        );
    }
}
