//! Building the `ssh` invocation for attaching to a session.
//!
//! Shared between the `min session attach` CLI path and the `min dash` TUI
//! (which suspends itself around the attach). Both run the interactive
//! attach through the client-owned terminal relay
//! ([`run_interactive_attach`]); the CLI's exec path runs the command
//! itself, with no pty of its own.

use std::path::Path;

use crate::HANDSHAKE_TIMEOUT;
use crate::ask_dialog::{AskDialogEnd, render_ask_dialog};
use crate::tty_relay;
use anyhow::Context as _;

/// Seconds between ssh keepalive probes on a non-interactive exec channel.
/// With [`EXEC_SERVER_ALIVE_COUNT_MAX`], a peer that stops answering ends the
/// exec after about 60 s instead of hanging it.
const EXEC_SERVER_ALIVE_INTERVAL_SECS: u32 = 15;
/// Unanswered keepalive probes ssh tolerates before it drops an exec channel.
const EXEC_SERVER_ALIVE_COUNT_MAX: u32 = 4;

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
        // Bound the connect and the initial protocol handshake/key exchange so
        // a bridge that accepts but never serves fails instead of hanging ssh.
        "-o",
        &format!("ConnectTimeout={}", HANDSHAKE_TIMEOUT.as_secs()),
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

    // A non-interactive exec channel must not hang forever on a peer that
    // accepted the connection but stopped answering after the handshake:
    // keepalives end it with exit 255 within about a minute. The interactive
    // path is left without them so a laptop sleep does not kill the attach.
    if wire.is_some() {
        ssh.args([
            "-o",
            &format!("ServerAliveInterval={EXEC_SERVER_ALIVE_INTERVAL_SECS}"),
            "-o",
            &format!("ServerAliveCountMax={EXEC_SERVER_ALIVE_COUNT_MAX}"),
        ]);
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
    /// Lines a dialog read off the subscription while it watched for its
    /// own dismissal, kept in order for the serving loop.
    held: std::collections::VecDeque<String>,
}

/// A dialog's view of the subscription while it is up: whether the host
/// has taken its ask away. Every other line read here is held, in order,
/// for the serving loop.
pub struct AskWatch<'a> {
    ask_id: minimald_rpc::AskId,
    subscription: &'a mut std::io::BufReader<std::os::unix::net::UnixStream>,
    held: &'a mut std::collections::VecDeque<String>,
}

impl<'a> AskWatch<'a> {
    pub(crate) fn new(
        ask_id: minimald_rpc::AskId,
        subscription: &'a mut std::io::BufReader<std::os::unix::net::UnixStream>,
        held: &'a mut std::collections::VecDeque<String>,
    ) -> Self {
        Self {
            ask_id,
            subscription,
            held,
        }
    }

    /// The subscription's socket, for a poll beside the terminal.
    pub(crate) fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        use std::os::fd::AsFd as _;
        self.subscription.get_ref().as_fd()
    }

    /// Whether bytes already read off the socket are waiting: a poll of
    /// the socket would not see them.
    pub(crate) fn has_buffered(&self) -> bool {
        !self.subscription.buffer().is_empty()
    }

    /// Read one line. `true` when it ends this dialog: the dismissal of
    /// this ask, or the subscription ending, after which nothing this
    /// attach records could count. Any other line is held.
    pub(crate) fn take_line(&mut self) -> bool {
        use std::io::BufRead as _;
        let mut line = String::new();
        match self.subscription.read_line(&mut line) {
            Ok(0) | Err(_) => return true,
            Ok(_) => {}
        }
        if is_dismissal_of(&line, self.ask_id) {
            return true;
        }
        self.held.push_back(line);
        false
    }

    /// Block until the host dismisses this ask or the subscription ends:
    /// a dialog that never answers.
    pub fn wait_dismissed(&mut self) {
        while !self.take_line() {}
    }
}

/// Whether `line` is the host's dismissal of `ask_id`.
fn is_dismissal_of(line: &str, ask_id: minimald_rpc::AskId) -> bool {
    matches!(
        serde_json_lenient::from_str(line.trim()),
        Ok(minimald_rpc::BoxControlReply::PendingAskDismissed { ask_id: id, .. }) if id == ask_id
    )
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
    host_control_within(control_sock, request, HOST_ASK_CONTROL_TIMEOUT)
}

/// The bound on a box row exchange the async front-ends run on a blocking
/// thread under [`crate::box_registration::BOX_CONTROL_TIMEOUT`]: one second
/// past it, so the caller's own deadline is the one that answers, and the
/// thread ends soon after the caller gives up on it rather than holding the
/// runtime's shutdown — and the process's exit — for the ask bound.
const BOX_CONTROL_THREAD_BOUND: std::time::Duration =
    std::time::Duration::from_secs(crate::box_registration::BOX_CONTROL_TIMEOUT.as_secs() + 1);

/// [`host_control`] bounded by `timeout` instead ([`BOX_CONTROL_THREAD_BOUND`]).
fn host_control_within(
    control_sock: &Path,
    request: &minimald_rpc::BoxControlRequest,
    timeout: std::time::Duration,
) -> Result<
    (
        minimald_rpc::BoxControlReply,
        std::io::BufReader<std::os::unix::net::UnixStream>,
    ),
    anyhow::Error,
> {
    use std::io::{BufRead as _, Write as _};

    use crate::box_registration::HostUnreachable;
    // Every failure short of a reply is the host unreached
    // ([`HostUnreachable`]); a reply that does not parse is a host that
    // answered.
    let mut stream = std::os::unix::net::UnixStream::connect(control_sock).map_err(|error| {
        HostUnreachable::over(
            error,
            format!(
                "connecting to the VM host daemon's control socket at {}",
                control_sock.display()
            ),
        )
    })?;
    stream
        .set_read_timeout(Some(timeout))
        .and_then(|()| stream.set_write_timeout(Some(timeout)))
        .map_err(|error| HostUnreachable::over(error, "bounding the control exchange"))?;
    let mut line = serde_json_lenient::to_string(request).context("serializing the request")?;
    line.push('\n');
    stream
        .write_all(line.as_bytes())
        .map_err(|error| HostUnreachable::over(error, "writing the control request"))?;
    let mut reader = std::io::BufReader::new(stream);
    let mut reply = String::new();
    reader
        .read_line(&mut reply)
        .map_err(|error| HostUnreachable::over(error, "reading the control reply"))?;
    if reply.trim().is_empty() {
        return Err(HostUnreachable::error(
            "the VM host daemon closed its control socket without answering",
        ));
    }
    let reply = serde_json_lenient::from_str(reply.trim())
        .with_context(|| format!("the VM host daemon's reply did not parse: {reply}"))?;
    Ok((reply, reader))
}

/// Holds (`hold`) or releases a `host_ip` box's name in the zone of the VM
/// host daemon beside the daemon's ssh socket `ssh_sock`: the \[proposed\]
/// pre-alias interim (deployment-and-egress-gateway ruling §7.1) that
/// answers a held name NODATA where an unheld one answers NXDOMAIN.
/// Best-effort for a caller that does not know whether the daemon is
/// VM-backed: no control socket beside it is nothing to do, and a refusal
/// or a failed exchange warns and leaves the name answering as it did.
/// `session_id` is the session the hold is for: a release that names it
/// frees only that session's hold.
pub fn hold_box_name_beside(
    ssh_sock: &Path,
    box_name: &str,
    session_id: Option<sessions::SessionId>,
    hold: bool,
) {
    let Some(control_sock) = ssh_sock
        .parent()
        .map(|dir| dir.join(VM_HOST_CONTROL_SOCK_FILE))
    else {
        return;
    };
    if !control_sock.exists() {
        return;
    }
    let request = minimald_rpc::HoldBoxNameRequest {
        name: box_name.to_string(),
        session_id,
    };
    let (verb, operation) = if hold {
        (
            minimald_rpc::BoxControlRequest::HoldBoxName(request),
            "hold",
        )
    } else {
        (
            minimald_rpc::BoxControlRequest::ReleaseBoxName(request),
            "release",
        )
    };
    let failure = match host_control(&control_sock, &verb) {
        Ok((minimald_rpc::BoxControlReply::NameHeld { .. }, _)) => return,
        Ok((other, _)) => format!("another verb's reply: {other:?}"),
        Err(error) => format!("{error:#}"),
    };
    tracing::warn!(
        box = %box_name,
        operation,
        "the box name {operation} could not be made ({failure}); the name answers as it did before"
    );
}

/// Withdraws a box's host row (T66) on the VM host daemon whose control
/// socket is `control_sock`, once the session that registered it is gone:
/// the creator presents the name and the pair the registration handed back,
/// and the daemon stops the pair's addresses admitting anything and returns
/// them to its hand-out books. `box_id` is the id the registration handed
/// back beside the pair, where the caller still holds it: the daemon then
/// withdraws only that box, never a newer one handed the same name and pair
/// after the quarantine. `None` — a session record carries no id — is the
/// pair proof alone.
///
/// Best-effort and blocking: a withdrawal that cannot be made — the socket
/// unreachable, a daemon that refuses the line, no answer in time — leaves
/// the row published and warns rather than failing the destroy or the
/// activation error it rides on. A daemon answering with a pair that is not
/// the pair asked is answering something else, and says the row stays too.
pub fn withdraw_box_row_at(
    control_sock: &Path,
    box_name: &str,
    addresses: sessions::BoxAddresses,
    box_id: Option<minimald_rpc::BoxId>,
) {
    let request = minimald_rpc::BoxControlRequest::Withdraw(minimald_rpc::WithdrawBoxRequest {
        name: box_name.to_string(),
        switch_address: addresses.switch_address,
        loopback_address: addresses.loopback_address,
        box_id,
    });
    let failure = match host_control_within(control_sock, &request, BOX_CONTROL_THREAD_BOUND) {
        Ok((minimald_rpc::BoxControlReply::Addresses(handed), _)) if handed == addresses => {
            tracing::info!(
                box = %box_name,
                switch_address = %handed.switch_address,
                loopback_address = %handed.loopback_address,
                "withdrew the box's host row; its addresses admit nothing"
            );
            return;
        }
        Ok((minimald_rpc::BoxControlReply::Addresses(handed), _)) => format!(
            "the daemon answered with a different address pair, switch address {}",
            handed.switch_address
        ),
        Ok((minimald_rpc::BoxControlReply::Error { error }, _)) => {
            format!("the daemon refused it: {error}")
        }
        Ok((other, _)) => format!("another verb's reply: {other:?}"),
        Err(error) => format!("{error:#}"),
    };
    tracing::warn!(
        box = %box_name,
        "the box row withdrawal could not be made ({failure}); the row stays published"
    );
}

/// [`withdraw_box_row_at`] on the control socket beside the daemon's ssh
/// socket `ssh_sock`, for a caller that does not know whether the daemon is
/// VM-backed: no control socket beside it is a native host, which holds no
/// rows, and nothing to do.
pub fn withdraw_box_row_beside(
    ssh_sock: &Path,
    box_name: &str,
    addresses: sessions::BoxAddresses,
    box_id: Option<minimald_rpc::BoxId>,
) {
    let Some(control_sock) = ssh_sock
        .parent()
        .map(|dir| dir.join(VM_HOST_CONTROL_SOCK_FILE))
    else {
        return;
    };
    if !control_sock.exists() {
        return;
    }
    withdraw_box_row_at(&control_sock, box_name, addresses, box_id);
}

/// Asks the VM host daemon whose control socket is `control_sock` for box
/// `box_name`'s host row back (NET-138), before an attach or an exec runs
/// in a box whose row may have been withdrawn while nothing carried its
/// frames — its host ended and stayed down past the daemon's detach grace,
/// or the daemon restarted under it. The creator presents the name and the
/// pair its registration handed back, the proof a withdrawal presents; the
/// daemon reinstates the row from its own record of the registration, or
/// keeps the one that stands. `box_id` narrows the proof to one creation,
/// where the caller holds it.
///
/// Blocking. A resume the daemon answers without the row — a daemon that
/// predates the verb or holds no registration of the box — is a warn
/// line, and the attach goes ahead: the in-VM daemon still refuses to
/// relaunch a box whose row is gone. Returns whether the daemon answered
/// with the row.
///
/// # Errors
///
/// [`crate::box_registration::HostUnreachable`] when the daemon cannot be
/// reached at all (#1790): the caller fails closed on it.
pub fn resume_box_row_at(
    control_sock: &Path,
    box_name: &str,
    addresses: sessions::BoxAddresses,
    box_id: Option<minimald_rpc::BoxId>,
) -> anyhow::Result<bool> {
    let request = minimald_rpc::BoxControlRequest::ResumeBox(minimald_rpc::ResumeBoxRequest {
        name: box_name.to_string(),
        switch_address: addresses.switch_address,
        loopback_address: addresses.loopback_address,
        box_id,
    });
    let failure = match host_control_within(control_sock, &request, BOX_CONTROL_THREAD_BOUND) {
        Ok((minimald_rpc::BoxControlReply::Registered(row), _))
            if row.switch_address == addresses.switch_address
                && row.loopback_address == addresses.loopback_address =>
        {
            tracing::debug!(
                box = %box_name,
                switch_address = %row.switch_address,
                "the box's host row stands"
            );
            return Ok(true);
        }
        Ok((minimald_rpc::BoxControlReply::Registered(row), _)) => format!(
            "the daemon answered with a different address pair, switch address {}",
            row.switch_address
        ),
        Ok((minimald_rpc::BoxControlReply::Error { error }, _)) => {
            format!("the daemon refused it: {error}")
        }
        Ok((other, _)) => format!("another verb's reply: {other:?}"),
        Err(error)
            if error
                .downcast_ref::<crate::box_registration::HostUnreachable>()
                .is_some() =>
        {
            return Err(error);
        }
        Err(error) => format!("{error:#}"),
    };
    tracing::warn!(
        box = %box_name,
        "the box's host row could not be resumed ({failure})"
    );
    Ok(false)
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
            held: std::collections::VecDeque::new(),
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

    /// The next subscription line: a held one first, then the socket.
    /// `None` once the subscription ended.
    fn next_line(&mut self) -> Option<String> {
        use std::io::BufRead as _;
        self.held.pop_front().or_else(|| {
            let mut line = String::new();
            match self.subscription.read_line(&mut line) {
                Ok(0) | Err(_) => None,
                Ok(_) => Some(line),
            }
        })
    }

    /// Serve offers until the subscription ends: for each, suspend the
    /// relay, render the dialog with `dialog`, record its answer through
    /// the host door, and resume. The dialog watches the subscription
    /// through its [`AskWatch`]: one the host dismisses comes down unanswered
    /// and records nothing. An offer the daemon already dismissed is
    /// skipped; an attach that ended under the dialog records nothing.
    pub fn serve<T: AskTerminal>(
        mut self,
        terminal: &T,
        mut dialog: impl FnMut(&minimald_rpc::PendingAskOffer, &mut AskWatch<'_>) -> AskDialogEnd,
    ) {
        loop {
            let Some(line) = self.next_line() else {
                return;
            };
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
            let end = dialog(
                &offer,
                &mut AskWatch::new(offer.ask_id, &mut self.subscription, &mut self.held),
            );
            if terminal.ask_cancelled() {
                return;
            }
            let answer = match end {
                AskDialogEnd::Answered(answer) => answer,
                AskDialogEnd::Dismissed => {
                    tracing::info!(ask_id = %offer.ask_id, "the ask was dismissed; its dialog came down unanswered");
                    terminal.resume_after_ask();
                    continue;
                }
            };
            tracing::info!(ask_id = %offer.ask_id, answer = ?answer, "the ask dialog was answered");
            match self.record(offer.ask_id, answer) {
                Ok(None) => {}
                // Another attach ended the ask first: say how it really
                // ended, not what this dialog chose.
                Ok(Some(late)) => {
                    tracing::info!(ask_id = %offer.ask_id, %late, "the ask had already ended");
                    eprintln!("{late}");
                }
                Err(error) => {
                    tracing::warn!(ask_id = %offer.ask_id, %error, "the ask answer was not recorded");
                    eprintln!("The answer was not recorded: {error:#}");
                }
            }
            terminal.resume_after_ask();
        }
    }

    /// Whether a dismissal for `ask_id` is already buffered behind its
    /// offer: another attach answered first, so there is no dialog to show.
    fn dismissed_already(&self, ask_id: minimald_rpc::AskId) -> bool {
        let buffered = String::from_utf8_lossy(self.subscription.buffer());
        self.held
            .iter()
            .map(String::as_str)
            .chain(buffered.lines())
            .any(|line| is_dismissal_of(line, ask_id))
    }

    /// Record `answer` for `ask_id` through the host door. `Ok(Some)` is
    /// the line saying how the ask had already ended when the answer came
    /// late; nothing was recorded then.
    fn record(
        &self,
        ask_id: minimald_rpc::AskId,
        answer: minimald_rpc::AskAnswer,
    ) -> Result<Option<String>, anyhow::Error> {
        let (reply, _) = host_control(
            &self.control_sock,
            &minimald_rpc::BoxControlRequest::RecordAskAnswer(
                minimald_rpc::RecordAskAnswerRequest { ask_id, answer },
            ),
        )?;
        match reply {
            minimald_rpc::BoxControlReply::AskAnswerRecorded { .. } => Ok(None),
            minimald_rpc::BoxControlReply::AskAlreadyEnded {
                port,
                proto,
                already_ended,
                ..
            } => Ok(Some(late_answer_line(port, proto, already_ended))),
            minimald_rpc::BoxControlReply::Error { error } => {
                anyhow::bail!("the VM host daemon refused it: {error}")
            }
            other => anyhow::bail!("the VM host daemon answered with {other:?}"),
        }
    }
}

/// The one line a late answer prints: how the ask it answered had already
/// ended, as the VM host daemon recorded it.
#[must_use]
pub fn late_answer_line(
    port: u16,
    proto: sessions::IpProto,
    end: minimald_rpc::AskLateEnd,
) -> String {
    match end {
        minimald_rpc::AskLateEnd::Allowed => {
            format!("ask {port}/{proto} was already allowed by another attach")
        }
        minimald_rpc::AskLateEnd::Denied => {
            format!("ask {port}/{proto} was already denied by another attach")
        }
        minimald_rpc::AskLateEnd::Cancelled { cause } => {
            format!("ask {port}/{proto} was cancelled ({cause})")
        }
    }
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

    /// The dashboard's hold verbs: a release is one release line naming the
    /// box on the control socket beside the ssh socket, a hold one hold
    /// line, and a daemon with no control socket beside it (a native host)
    /// is sent nothing.
    #[test]
    fn hold_box_name_beside_speaks_the_hold_verbs_on_the_control_socket() {
        use std::io::{BufRead as _, Write as _};
        let dir = tempfile::TempDir::new().unwrap();
        let ssh_sock = dir.path().join("ssh.sock");

        // No control socket: nothing to connect to, nothing happens.
        hold_box_name_beside(&ssh_sock, "web", None, false);

        let listener =
            std::os::unix::net::UnixListener::bind(dir.path().join(VM_HOST_CONTROL_SOCK_FILE))
                .unwrap();
        let server = std::thread::spawn(move || {
            let mut seen = Vec::new();
            for _ in 0..2 {
                let (stream, _) = listener.accept().unwrap();
                let mut reader = std::io::BufReader::new(stream);
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                reader
                    .get_mut()
                    .write_all(b"{\"name\":\"web\",\"held\":false}\n")
                    .unwrap();
                seen.push(line);
            }
            seen
        });
        let id = sessions::SessionId::nil();
        hold_box_name_beside(&ssh_sock, "web", Some(id), false);
        hold_box_name_beside(&ssh_sock, "api", Some(id), true);
        let seen = server.join().unwrap();
        let decode = |line: &str| -> minimald_rpc::BoxControlRequest {
            serde_json_lenient::from_str(line.trim()).expect("the request is the wire type")
        };
        let minimald_rpc::BoxControlRequest::ReleaseBoxName(release) = decode(&seen[0]) else {
            panic!("a release is carried by the release verb");
        };
        assert_eq!(release.name, "web");
        assert_eq!(release.session_id, Some(id));
        let minimald_rpc::BoxControlRequest::HoldBoxName(hold) = decode(&seen[1]) else {
            panic!("a hold is carried by the hold verb");
        };
        assert_eq!(hold.name, "api");
    }

    /// A late answer prints exactly how the ask had already ended.
    #[test]
    fn late_answer_line_names_the_real_end() {
        use minimald_rpc::{AskCancelCause, AskLateEnd};
        let tcp = sessions::IpProto::Tcp;
        assert_eq!(
            late_answer_line(3000, tcp, AskLateEnd::Allowed),
            "ask 3000/tcp was already allowed by another attach"
        );
        assert_eq!(
            late_answer_line(3000, tcp, AskLateEnd::Denied),
            "ask 3000/tcp was already denied by another attach"
        );
        assert_eq!(
            late_answer_line(
                3000,
                tcp,
                AskLateEnd::Cancelled {
                    cause: AskCancelCause::GuestClosed
                }
            ),
            "ask 3000/tcp was cancelled (the guest connection closed)"
        );
    }

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

    /// Every attach bounds its connect and handshake with the shared deadline;
    /// only the non-interactive exec path adds keepalives, so a peer that
    /// stops answering ends the exec instead of hanging it.
    #[test]
    fn attach_command_bounds_the_handshake() {
        let sock = PathBuf::from("/tmp/x/providers/local-minimald0/ssh.sock");
        let interactive = attach_command(&sock, sessions::SessionId::nil(), None, None).unwrap();
        let exec = attach_command(&sock, sessions::SessionId::nil(), Some("wire"), None).unwrap();

        let args = |cmd: &std::process::Command| -> Vec<String> {
            cmd.get_args()
                .map(|a| a.to_string_lossy().into_owned())
                .collect()
        };

        let connect_timeout = format!("ConnectTimeout={}", HANDSHAKE_TIMEOUT.as_secs());
        for cmd in [&interactive, &exec] {
            let args = args(cmd);
            assert!(
                args.iter().any(|a| a == &connect_timeout),
                "missing {connect_timeout} in {args:?}",
            );
        }

        let interactive_args = args(&interactive);
        assert!(
            !interactive_args
                .iter()
                .any(|a| a.starts_with("ServerAlive")),
            "interactive attach must not carry keepalives: {interactive_args:?}",
        );

        let exec_args = args(&exec);
        for opt in [
            format!("ServerAliveInterval={EXEC_SERVER_ALIVE_INTERVAL_SECS}"),
            format!("ServerAliveCountMax={EXEC_SERVER_ALIVE_COUNT_MAX}"),
        ] {
            assert!(
                exec_args.iter().any(|a| a == &opt),
                "missing {opt} in {exec_args:?}",
            );
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
