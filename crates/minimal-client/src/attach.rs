//! Building the `ssh` invocation for attaching to a session.
//!
//! Shared between the `min session attach` CLI path (which `exec()`s the
//! command, replacing itself) and the `min dash` TUI (which spawns it as a
//! child while the TUI is suspended and resumes when ssh exits).

use std::path::Path;

use anyhow::Context as _;

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
/// The interactive path (`command: None`) forces a PTY with `-tt` — the
/// daemon's shell_request handler mints the PTY-backed session shell, and
/// ssh handles termios/PTY management. The caller decides how to run the
/// command: `min session attach` `exec()`s it, `min dash` spawns it as a
/// child while suspended.
pub fn attach_command(
    sock: &Path,
    id: sessions::SessionId,
    command: Option<&str>,
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
    ssh.env("MINIMAL_SESSION_ID", id.to_string()).args([
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
    if command.is_none() {
        ssh.arg("-tt");
    }

    // The SSH host identity must match the known_hosts entry the daemon wrote,
    // which it keys on the provider-instance name — the provider dir's basename
    // (`local-minimald<N>` / `local-minvmd<N>`). Derive it from the socket path
    // so the client and daemon can never disagree on the name.
    let host_alias = sock
        .parent()
        .and_then(std::path::Path::file_name)
        .and_then(|n| n.to_str())
        .context("daemon socket path has no provider-dir parent")?;
    ssh.arg(host_alias);

    // If a command was provided, pass it to ssh (non-interactive exec).
    // Otherwise, ssh opens an interactive shell via shell_request.
    if let Some(cmd) = command {
        ssh.arg(cmd);
    }

    Ok(ssh)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn attach_command_targets_the_provider_alias() {
        let sock = PathBuf::from("/tmp/x/providers/local-minimald0/ssh.sock");
        let cmd = attach_command(&sock, sessions::SessionId::nil(), None).unwrap();
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

    #[test]
    fn attach_command_with_exec_has_no_forced_pty() {
        let sock = PathBuf::from("/tmp/x/providers/local-minvmd0/ssh.sock");
        let cmd = attach_command(&sock, sessions::SessionId::nil(), Some("min run test")).unwrap();
        let args: Vec<_> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert!(!args.iter().any(|a| a == "-tt"));
        assert_eq!(args.last().map(String::as_str), Some("min run test"));
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
