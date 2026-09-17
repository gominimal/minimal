//! Building the `ssh` invocation for attaching to a session.
//!
//! Shared between the `min session attach` CLI path (which `exec()`s the
//! command, replacing itself) and the `min dash` TUI (which spawns it as a
//! child while the TUI is suspended and resumes when ssh exits).

use std::path::Path;

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
/// daemon's shell_request handler mints the PTY-backed session shell, and
/// ssh handles termios/PTY management. The caller decides how to run the
/// command: `min session attach` `exec()`s it, `min dash` spawns it as a
/// child while suspended.
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
    if let Some(wire) = wire {
        ssh.arg(wire);
    }

    Ok(ssh)
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
