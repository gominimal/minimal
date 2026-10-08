use super::*;

/// Interactive attach over a non-terminal stdin must fail fast rather than
/// force `ssh -tt` into an indefinite block (#953). A real terminal (or a
/// pty driver) passes the guard so the shell can open.
#[test]
fn interactive_attach_requires_a_tty_on_stdin() {
    let err = ensure_interactive_attach_tty(false)
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("not a TTY"),
        "expected an actionable non-TTY error, got: {err}"
    );
    ensure_interactive_attach_tty(true).expect("a real terminal must pass the guard");
}

/// The #953 refusal still comes first: a non-terminal stdin is turned away
/// before the unwind guard arms or the relay opens a pty or touches the
/// terminal.
#[test]
fn non_terminal_stdin_still_refused_before_relay() {
    let armed = std::cell::Cell::new(false);
    let relayed = std::cell::Cell::new(false);
    let err = interactive_attach(
        std::process::Command::new("ssh"),
        false,
        || {
            armed.set(true);
            attach::TerminalUnwind::arm_on(Vec::new(), true)
        },
        |_| {
            relayed.set(true);
            unreachable!("the relay must not run over a non-terminal stdin")
        },
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("not a TTY"), "{err}");
    assert!(!armed.get(), "the unwind guard armed before the refusal");
    assert!(!relayed.get(), "the relay ran before the refusal");
}

/// The termios the relay put back must be in force before the blind unwind
/// writes a byte, and the unwind goes to the real terminal (what the user
/// sees), not to the session's pty. Driven over a pty that stands in for
/// the user's terminal, through the real relay, with a session that ends
/// the way a dropped transport does (255) so the guard fires.
#[test]
fn relay_restores_termios_before_unwind_codes() {
    use nix::sys::termios::{LocalFlags, Termios, tcgetattr};
    use std::io::Read as _;
    use std::os::fd::OwnedFd;
    use std::sync::{Arc, Mutex};

    fn mode(t: &Termios) -> String {
        // PENDIN is kernel bookkeeping on macOS, not a mode anyone set; and
        // only the named control characters count (Linux's kernel keeps
        // fewer than libc's `NCCS`, so the array's tail is stack garbage).
        use nix::sys::termios::SpecialCharacterIndices as C;
        let cc: Vec<u8> = [
            C::VEOF,
            C::VEOL,
            C::VERASE,
            C::VINTR,
            C::VKILL,
            C::VMIN,
            C::VQUIT,
            C::VSTART,
            C::VSTOP,
            C::VSUSP,
            C::VTIME,
        ]
        .iter()
        .map(|&i| t.control_chars[i as usize])
        .collect();
        format!(
            "{:?} {:?} {:?} {:?} {cc:?}",
            t.input_flags,
            t.output_flags,
            t.control_flags,
            t.local_flags - LocalFlags::PENDIN,
        )
    }

    /// Writes to the user's terminal, noting the termios it found there
    /// at the moment of the first write.
    struct RealTerminal {
        tty: std::fs::File,
        termios_at_write: Arc<Mutex<Option<String>>>,
    }
    impl std::io::Write for RealTerminal {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            let mut seen = self.termios_at_write.lock().unwrap();
            if seen.is_none() {
                *seen = Some(mode(&tcgetattr(&self.tty).unwrap()));
            }
            self.tty.write(buf)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            self.tty.flush()
        }
    }

    let pty = nix::pty::openpty(None, None).unwrap();
    let start = mode(&tcgetattr(&pty.slave).unwrap());
    let mut master = std::fs::File::from(pty.master);
    let screen = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&screen);
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        loop {
            match master.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => sink.lock().unwrap().extend_from_slice(&buf[..n]),
                // A signal can interrupt the read on some targets.
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) => break,
            }
        }
    });
    let dup = |fd: &OwnedFd| fd.try_clone().unwrap();
    let termios_at_write = Arc::new(Mutex::new(None));

    let mut session = std::process::Command::new("/bin/sh");
    session
        .arg("-c")
        .arg("stty raw -echo -iexten; printf R; exit 255");
    let code = interactive_attach(
        session,
        true,
        || {
            attach::TerminalUnwind::arm_on(
                RealTerminal {
                    tty: std::fs::File::from(dup(&pty.slave)),
                    termios_at_write: Arc::clone(&termios_at_write),
                },
                true,
            )
        },
        |ssh| {
            let real = client::tty_relay::RealTty::from_fds(dup(&pty.slave), dup(&pty.slave));
            client::attach::run_interactive_attach_on(ssh, real, None)
        },
    )
    .unwrap();
    assert_eq!(code, 255);

    let at_write = termios_at_write
        .lock()
        .unwrap()
        .clone()
        .expect("a transport drop arms the blind unwind");
    assert_eq!(
        at_write, start,
        "the unwind wrote before the termios was restored"
    );
    let until = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let seen = screen.lock().unwrap().clone();
        // The session's output, then the unwind's codes, on the user's
        // terminal.
        if seen.starts_with(b"R") && seen.ends_with(b"\x1b[?1004l") {
            break;
        }
        assert!(
            std::time::Instant::now() < until,
            "the unwind codes never reached the terminal: {:?}",
            String::from_utf8_lossy(&seen)
        );
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}

/// The interactive attach no longer `exec()`s ssh — it waits on it so the
/// terminal can be put back afterwards (#1210) — so the status ssh reports
/// has to become this process's own, signalled children included.
#[test]
fn ssh_status_becomes_the_clients_exit_code() {
    use std::os::unix::process::ExitStatusExt as _;

    assert_eq!(exit_code_of(std::process::ExitStatus::from_raw(0)), 0);
    // wait(2) encoding: the exit code sits in the high byte.
    assert_eq!(exit_code_of(std::process::ExitStatus::from_raw(3 << 8)), 3);
    // A signalled child reports no code of its own; the shell's 128 + n.
    // 9 is SIGKILL, in the low bits where wait(2) puts the signal.
    assert_eq!(exit_code_of(std::process::ExitStatus::from_raw(9)), 137);
}

/// The exec-path stdout relay copies data from a reader to a writer and
/// returns `BrokenPipe` when the writer's far end closes (#815).
#[tokio::test]
async fn exec_stdout_relay_copies_and_detects_broken_pipe() {
    use tokio::io::AsyncWriteExt as _;

    // Clean EOF: write "hello\n" then drop the write half, so the read half
    // yields the bytes and then EOF. The relay should copy and return Ok.
    let (mut src, mut rx) = tokio::io::duplex(64);
    src.write_all(b"hello\n").await.unwrap();
    drop(src);
    let mut sink = tokio::io::sink();
    relay_exec_stdout(&mut rx, &mut sink)
        .await
        .expect("relay should succeed on clean EOF");

    // BrokenPipe: the writer's far end is closed, so the first write fails.
    let (mut src, mut rx) = tokio::io::duplex(64);
    src.write_all(b"world\n").await.unwrap();
    drop(src);
    let (mut writer, reader) = tokio::io::duplex(64);
    drop(reader); // close the read half of the duplex
    let err = relay_exec_stdout(&mut rx, &mut writer)
        .await
        .expect_err("relay should fail when the writer's far end is closed");
    assert_eq!(
        err.kind(),
        std::io::ErrorKind::BrokenPipe,
        "relay should return BrokenPipe when writer's far end closes"
    );
}

/// A CLI upgraded past its daemon must be refused up front, naming both
/// builds and the recovery. Before #1251 the skew surfaced only at
/// `FinalizeSession`, by which point the activation's cleanup had already
/// destroyed the session it had just created.
#[test]
fn version_skew_is_reported_with_both_builds_and_a_recovery() {
    let msg = client::version_skew_message("0.6.0", "0.5.0-dev.12.g86ce5c3a")
        .expect("differing builds are a skew");
    assert!(msg.contains("0.6.0"), "missing the CLI version: {msg}");
    assert!(
        msg.contains("0.5.0-dev.12.g86ce5c3a"),
        "missing the daemon version: {msg}"
    );
    assert!(msg.contains("min stop"), "missing the recovery: {msg}");
    assert!(
        msg.contains(client::SKEW_OVERRIDE_VAR),
        "missing the override: {msg}"
    );
}

/// Every direct daemon connection in this crate is either version-gated or
/// deliberately not, and this test is where that decision is recorded.
///
/// #1251 shipped the gate but wired it to two call sites; the rest reached
/// activations and live-session hand-offs ungated. A new connection is easy
/// to add and easy to forget, so the inventory is asserted rather than
/// documented: adding, removing, or un-gating one fails here and forces the
/// same judgement — can this path leave daemon state half-built (gate it),
/// or must it work *because* the pair is skewed (leave it, with a comment
/// saying why)?
#[test]
fn every_daemon_connection_is_classified() {
    assert_eq!(
        connect_site_inventory(env!("CARGO_MANIFEST_DIR")),
        [
            // A box-name resolution probe: ungated while it finds nothing, but
            // the VM that owns the name is gated on the reply that named it —
            // the same ride-along shape `resolve_session_version_gated` uses.
            "attach.rs::box_record_on = gated",
            "cmd/admin.rs::cmd_version = ungated",
            "cmd/list.rs::cmd_bare = gated",
            // `min ls` reaches past the selected VM, and the two halves carry
            // the gate differently (see `ls_listings`): the selected VM is the
            // one this process ensured and drives, so it keeps the gate; the
            // others are probed ungated, for the same reason the dashboard
            // lists a skewed VM ungated — its boxes are exactly what an
            // operator still needs to see.
            "cmd/list.rs::list_other_vm = ungated",
            "cmd/list.rs::list_selected_vm = gated",
            "cmd/mod.rs::arm_activation_interrupt = ungated",
            "cmd/mod.rs::connect_daemon_unchecked = ungated",
            "cmd/net.rs::cmd_net_forward = gated",
            "cmd/session.rs::cmd_attach = gated",
            "cmd/session.rs::cmd_exec = gated",
            "cmd/session.rs::cmd_session_run = gated",
            "cmd/session.rs::cmd_session_setup_zed = gated",
            "diag/net.rs::probe_socket = ungated",
            "task.rs::arm_task_run_interrupt = ungated",
            // Not a product path: the fall-through tests' own connections to
            // the selected daemon — but connections all the same, and the
            // paths they drive are the gated ones above, so the label records
            // what the tests assert rather than a decision they make.
            "tests.rs::attach_fall_through_hands_off_the_owning_vm = gated",
            "tests.rs::attach_refuses_a_box_name_two_vms_know = gated",
        ]
    );
}

/// Every `CreateSession` this crate sends states, in the request itself,
/// whether it asserts the daemon's build.
///
/// The struct field makes omitting the decision a compile error; this
/// makes answering it "no" a visible one. Both session-creating paths
/// assert — they are the ones #1251 is about — and the inventory is what
/// stops a third from quietly passing `None`.
#[test]
fn every_create_session_asserts_the_daemon_build() {
    assert_eq!(
        create_site_inventory(env!("CARGO_MANIFEST_DIR")),
        [
            "cmd/session.rs::activate_session = asserts",
            "task.rs::cmd_task_run = asserts",
            // Not a client path: the two-VM fixture's own create. It asserts
            // like the real ones, so the inventory stays "every site asserts".
            "tests.rs::create_box_on = asserts",
        ]
    );
}

/// The activation path must not spend a round trip on the version.
///
/// That was the cost of #1251's first fix: a `GetVersion` ahead of the
/// create, on the one path where an extra RTT is felt. The check now rides
/// on the `CreateSession` the path was already sending, so the marks of
/// the old mechanism — `GetVersion`, `ensure_version_match`, or the
/// `connect_daemon` that issues it — must be absent from both creators,
/// and the marks of the new one present.
#[test]
fn the_activation_path_makes_no_version_round_trip() {
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    for (file, func) in [
        ("src/cmd/session.rs", "activate_session"),
        ("src/task.rs", "cmd_task_run"),
    ] {
        let text = std::fs::read_to_string(manifest.join(file)).expect("readable source");
        let body =
            function_body(&text, func).unwrap_or_else(|| panic!("{file} no longer defines {func}"));
        for round_trip in ["GetVersion", "ensure_version_match", "connect_daemon("] {
            assert!(
                !body.contains(round_trip),
                "{func} reintroduced a version round trip ({round_trip})"
            );
        }
        assert!(
            body.contains("must_match_version"),
            "{func} no longer asserts its build on the create"
        );
        assert!(
            body.contains("ensure_version_reported"),
            "{func} no longer checks the build the create echoed back"
        );
    }
}

/// The code of the named free function, from its `fn` line to the next
/// one, with comment lines dropped — the prose here talks *about* the
/// mechanisms the caller is scanning for, and a rationale comment naming
/// `GetVersion` must not read as a call to it.
fn function_body(text: &str, name: &str) -> Option<String> {
    let lines: Vec<&str> = text.lines().collect();
    let decls = fn_decl_lines(&lines);
    let start = decls.iter().position(|(_, n)| n == name)?;
    let from = decls[start].0;
    let to = decls.get(start + 1).map_or(lines.len(), |(d, _)| *d);
    Some(
        lines[from..to]
            .iter()
            .filter(|l| !l.trim_start().starts_with("//"))
            .copied()
            .collect::<Vec<_>>()
            .join("\n"),
    )
}

/// Every free-function declaration in `lines`, as `(line index, name)`.
fn fn_decl_lines(lines: &[&str]) -> Vec<(usize, String)> {
    lines
        .iter()
        .enumerate()
        .filter_map(|(i, l)| {
            let t = l.trim_start();
            let t = t
                .strip_prefix("pub(crate) ")
                .or_else(|| t.strip_prefix("pub "))
                .unwrap_or(t);
            let t = t.strip_prefix("async ").unwrap_or(t);
            t.strip_prefix("fn ")
                .map(|rest| (i, rest.split(['(', '<']).next().unwrap_or("").to_string()))
        })
        .collect()
}

/// Every `.rs` file under `<crate>/src`, sorted.
fn crate_sources(manifest_dir: &str) -> (std::path::PathBuf, Vec<std::path::PathBuf>) {
    let src = std::path::Path::new(manifest_dir).join("src");
    let mut files = Vec::new();
    let mut stack = vec![src.clone()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).expect("crate src must be readable") {
            let path = entry.expect("readable dir entry").path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "rs") {
                files.push(path);
            }
        }
    }
    files.sort();
    (src, files)
}

/// Attributes every line matching one of `needles` under `<crate>/src` to the
/// function containing it, labelling that function by whether its body
/// carries one of `markers`.
fn source_inventory(
    manifest_dir: &str,
    needles: &[&str],
    markers: &[&str],
    labels: (&str, &str),
) -> Vec<String> {
    let (src, files) = crate_sources(manifest_dir);
    let mut sites = Vec::new();
    for path in files {
        let text = std::fs::read_to_string(&path).expect("source file must be readable");
        let lines: Vec<&str> = text.lines().collect();
        let decls = fn_decl_lines(&lines);
        let rel = path
            .strip_prefix(&src)
            .expect("scanned under src")
            .to_string_lossy()
            .into_owned();
        for (i, line) in lines.iter().enumerate() {
            if !needles.iter().any(|needle| line.contains(needle)) {
                continue;
            }
            let (start, name) = decls
                .iter()
                .rev()
                .find(|(d, _)| *d < i)
                .cloned()
                .unwrap_or((0, "<top level>".to_string()));
            let end = decls
                .iter()
                .find(|(d, _)| *d > start)
                .map_or(lines.len(), |(d, _)| *d);
            let marked = lines[start..end]
                .iter()
                .any(|l| markers.iter().any(|m| l.contains(m)));
            sites.push(format!(
                "{rel}::{name} = {}",
                if marked { labels.0 } else { labels.1 }
            ));
        }
    }
    sites.sort();
    sites
}

/// Attributes every `CreateSessionRequest` construction under
/// `<crate>/src` to its function, and reports whether it asserts this
/// build.
fn create_site_inventory(manifest_dir: &str) -> Vec<String> {
    // Built by concatenation so this scanner does not match itself.
    const NEEDLE: &str = concat!("CreateSession", "Request {");
    source_inventory(
        manifest_dir,
        &[NEEDLE],
        &[
            "must_match_version: version_assertion()",
            "must_match_version: minimal_client::version_assertion()",
        ],
        ("asserts", "asserts nothing"),
    )
}

/// Attributes every direct `Client` connection under `<crate>/src` to the
/// function that opens it, and reports whether that function also applies
/// the version gate. Source-level on purpose: the alternative is a live
/// daemon per call site.
///
/// A path counts as gated whichever way it gets its answer: the
/// `GetVersion` round trip (`ensure_version_match`), a build a reply it was
/// already making carried (`ensure_version_reported`, directly or through a
/// `*_version_gated` lookup helper), or the assertion it puts on its own
/// `CreateSession`. What the inventory records is that the decision was
/// made, not which mechanism made it.
///
/// A probe is a connection too — one attempt at a VM this process did not
/// select — so both verbs the client opens are needles. That is what keeps
/// a probe path from carrying a gate (or not) without this test noticing:
/// the judgement is the same one, and the inventory is where it is recorded.
fn connect_site_inventory(manifest_dir: &str) -> Vec<String> {
    // Both built by concatenation so this scanner does not match itself.
    const CONNECT_NEEDLE: &str = concat!("Client", "::connect(");
    const PROBE_NEEDLE: &str = concat!("Client", "::probe(");
    source_inventory(
        manifest_dir,
        &[CONNECT_NEEDLE, PROBE_NEEDLE],
        &[
            "ensure_version_match",
            "ensure_version_reported",
            "_version_gated(",
            "must_match_version",
        ],
        ("gated", "ungated"),
    )
}

/// Matching builds are the overwhelmingly common case and must cost the
/// operator nothing.
#[test]
fn matching_versions_are_not_a_skew() {
    assert!(client::version_skew_message(version::VERSION, version::VERSION).is_none());
}

/// The host-cache warm-up is gated on the session provider: a VM-backed
/// provider caches on its own guest volume and never reads the host cache,
/// so `--provider local-minvmd` (and macOS, always minvmd-backed) skip the
/// warm-up, while the native daemon shares the host cache and downloads.
#[test]
fn host_cache_warmup_skips_vm_backed_providers() {
    assert!(
        !should_warm_host_cache(true),
        "a VM-backed provider must not warm the host cache"
    );
    // macOS is always minvmd-backed regardless of the flag; elsewhere the
    // native daemon shares the host cache, so the warm-up runs.
    assert_eq!(should_warm_host_cache(false), !cfg!(target_os = "macos"));
}

/// The `Cli` command tree must stay well-formed: a malformed clap
/// definition panics in `debug_assert`/render, not at parse time, so
/// `min --help` (which bare `min` no longer prints, but which must keep
/// working unchanged) stays renderable.
#[test]
fn cli_command_tree_stays_renderable() {
    use clap::CommandFactory as _;
    Cli::command().debug_assert();
}

/// `min login` mints nothing (NET-109): the verb runs without a daemon and
/// writes no key or certificate to the config directory, where the reverse
/// proxy's files used to land, and it prints the one line saying there is
/// nothing to mint. The `--cert-dir` flag that steered the old writes is
/// refused by the parser.
#[tokio::test]
async fn login_mints_no_certificate() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config");
    let global = GlobalArgs {
        repo_dir: None,
        minimal_dir: Some(dir.path().join("state")),
        config_dir: Some(config.clone()),
        provider: None,
        no_input: true,
        vm: None,
    };

    // No daemon is running and none may be spawned: with the certificate
    // RPC gone the verb has nothing to ask one for. The notice is captured
    // from the verb itself, so the assertions below hold what it emits.
    let mut out = Vec::new();
    cmd_login(&global, LoginArgs {}, &mut out)
        .await
        .expect("a verb with nothing to mint succeeds without a daemon");

    // The config directory is where the key and CA used to be written.
    for file in ["client.pem", "client.key", "ca.pem"] {
        assert!(
            !config.join("minimal").join(file).exists(),
            "login wrote {file}; it must write no key or certificate"
        );
    }

    // The one line it prints, read back out of what the verb wrote: a
    // handler that stopped emitting it, printed something else, or printed
    // it twice fails here rather than passing on the helper's own text.
    let printed = String::from_utf8(out).expect("stdout is UTF-8");
    assert!(
        printed.contains("Nothing to mint"),
        "the line must say there is nothing to mint, got: {printed}"
    );
    assert_eq!(
        printed,
        format!("{}\n", login_nothing_to_mint_line()),
        "the verb prints exactly the one required line"
    );

    // And the minting is gone from the verb's body, asserted on the source
    // the way `the_activation_path_makes_no_version_round_trip` is: the
    // certificate RPC, the write sites, the cert paths, and the daemon
    // spawn must all be absent.
    let text = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/cmd/admin.rs"),
    )
    .expect("readable source");
    let body = function_body(&text, "cmd_login").expect("admin.rs no longer defines cmd_login");
    for minted_again in [
        "IssueClientCert",
        "client.pem",
        "client.key",
        "ca.pem",
        "fs::write",
        "ensure_daemon",
    ] {
        assert!(
            !body.contains(minted_again),
            "cmd_login mints again ({minted_again})"
        );
    }

    // The flag that directed the writes is retired with them.
    use clap::Parser as _;
    let Err(err) = Cli::try_parse_from(["min", "login", "--cert-dir", "/tmp/certs"]) else {
        panic!("--cert-dir is retired and must not parse");
    };
    assert!(
        err.to_string().contains("--cert-dir"),
        "the refusal must name the retired flag, got: {err}"
    );
}

/// The CLI reference documents no retired command (NET-111): the reference
/// is the page a person reads to learn what the CLI offers, so a command
/// the tree no longer parses must not survive there. `min login` survives
/// as a verb, so the guard is on what it must never document again — the
/// minted key and CA — not on the verb's name. And the tree agrees with
/// the page: the retired verb is refused by the argument parser, with its
/// usage, rather than parsing into nothing.
#[test]
fn cli_reference_has_no_retired_commands() {
    let reference = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/reference/cli-min.md"),
    )
    .expect("the min CLI reference must be readable at docs/reference/cli-min.md");
    for (retired, why) in [
        ("ssh-forward", "the SSH LocalForward verb is retired"),
        ("client.pem", "the retired client certificate"),
        ("client.key", "the retired client key"),
        ("ca.pem", "the retired CA certificate"),
        ("cert-dir", "login's retired --cert-dir flag"),
    ] {
        assert!(
            !reference.contains(retired),
            "the CLI reference documents a retired surface ({retired}): {why}"
        );
    }

    let Err(err) = Cli::try_parse_from(["min", "ssh-forward", "dev", "18080:127.0.0.1:80"]) else {
        panic!("ssh-forward is retired and must not parse");
    };
    let rendered = err.to_string();
    assert!(
        rendered.contains("unrecognized subcommand 'ssh-forward'"),
        "the refusal must name the verb, got: {rendered}"
    );
    assert!(
        rendered.contains("Usage:"),
        "the refusal must carry the usage, got: {rendered}"
    );
}

/// Entry constructor for the bare-`min` state-report tests.
fn twin_entry(
    id: &str,
    name: Option<&str>,
    path: Option<&str>,
    status: sessions::SessionStatus,
) -> minimald_rpc::ListSessionsEntry {
    minimald_rpc::ListSessionsEntry {
        id: sessions::SessionId::parse_str(id).unwrap(),
        name: name.map(str::to_owned),
        project_path: path.map(|p| paths::HostAbsPath::try_new(p).unwrap()),
        status,
        git: None,
        host_ip_enforcement: None,
        attrs: None,
    }
}

/// One cwd-matching session: the report names it with its status, and the
/// `Next:` attach line carries its real name — every line verbatim.
#[test]
fn bare_status_renders_a_cwd_session_verbatim() {
    let entries = vec![twin_entry(
        "019f5d0f-0a99-78b1-9165-0809440f0052",
        Some("web"),
        Some("/w"),
        sessions::SessionStatus::Active,
    )];
    let cwd = paths::HostAbsPath::try_new("/w").unwrap();
    assert_eq!(
        render_bare_status("~/w", &entries, &cwd, true),
        "No terminal: not attaching. State for ~/w:\n\
             \x20 sessions: 1 (web, active)\n\
             \x20 blueprint: minimal.toml present\n\
             Next:\n\
             \x20 min session attach --command 'min task run <task>' web\n\
             \x20 min ls --json\n"
    );
}

/// A session already tracked for the target path warns with that
/// session's handle and the `attach` reuse hint; a path with no session
/// stays silent.
#[test]
fn duplicate_session_warning_flags_only_a_matching_path() {
    let entries = vec![twin_entry(
        "019f5d0f-0a99-78b1-9165-0809440f0052",
        Some("web"),
        Some("/w"),
        sessions::SessionStatus::Active,
    )];

    let taken = paths::HostAbsPath::try_new("/w").unwrap();
    let warning = duplicate_session_warning(&entries, &taken)
        .expect("a session on the target path must warn");
    assert!(warning.contains("web"), "warning names the existing handle");
    assert!(
        warning.contains("min session attach web"),
        "warning points at attach for reuse"
    );

    let free = paths::HostAbsPath::try_new("/elsewhere").unwrap();
    assert!(
        duplicate_session_warning(&entries, &free).is_none(),
        "an untaken path does not warn"
    );
}

/// An unnamed existing session must still be reusable: the reuse hint must
/// carry the full id, which `SessionLookup::parse` resolves back to an id.
/// The short unnamed handle would parse as a nonexistent name, so the attach
/// lookup would miss.
#[test]
fn duplicate_session_warning_reuses_unnamed_session_by_id() {
    let id = "019f5d0f-0a99-78b1-9165-0809440f0052";
    let entries = vec![twin_entry(
        id,
        None,
        Some("/w"),
        sessions::SessionStatus::Active,
    )];

    let taken = paths::HostAbsPath::try_new("/w").unwrap();
    let warning = duplicate_session_warning(&entries, &taken)
        .expect("a session on the target path must warn");
    assert!(
        warning.contains(&format!("min session attach {id}")),
        "unnamed reuse hint carries the full id, got: {warning}"
    );
    // The id the hint prints must resolve through the attach lookup path.
    assert!(
        matches!(SessionLookup::parse(id), SessionLookup::Id(_)),
        "the full id resolves as an id, not a name"
    );
}

/// Attach refuses a `Materializing` session, so the warning must not point
/// at it; the duplicate is still flagged, just without an attach hint.
#[test]
fn duplicate_session_warning_skips_attach_for_materializing() {
    let entries = vec![twin_entry(
        "019f5d0f-0a99-78b1-9165-0809440f0052",
        Some("web"),
        Some("/w"),
        sessions::SessionStatus::Materializing,
    )];

    let taken = paths::HostAbsPath::try_new("/w").unwrap();
    let warning = duplicate_session_warning(&entries, &taken)
        .expect("a session on the target path must warn");
    assert!(
        !warning.contains("min session attach"),
        "no attach hint for a non-attachable session, got: {warning}"
    );
}

/// When several sessions track the target path with mixed statuses, the
/// warning must recommend the `Active` one — the only status `attach`
/// accepts — even when a non-active match sorts first in the listing.
#[test]
fn duplicate_session_warning_prefers_active_over_pending_match() {
    let pending_id = "019f5d0f-0a99-78b1-9165-0809440f0052";
    let active_id = "019f5d0f-0a99-78b1-9165-0809440f0053";
    let entries = vec![
        twin_entry(
            pending_id,
            Some("mzing"),
            Some("/w"),
            sessions::SessionStatus::Materializing,
        ),
        twin_entry(
            active_id,
            Some("live"),
            Some("/w"),
            sessions::SessionStatus::Active,
        ),
    ];

    let taken = paths::HostAbsPath::try_new("/w").unwrap();
    let warning = duplicate_session_warning(&entries, &taken)
        .expect("a session on the target path must warn");
    assert!(
        warning.contains("min session attach live"),
        "warning points at the active match for reuse, got: {warning}"
    );
    assert!(
        !warning.contains("still being created"),
        "an attachable active match must not print the wait guidance, got: {warning}"
    );
}

/// No sessions anywhere and no blueprint: the report says so and the
/// `Next:` lines become the create-and-attach pair — every line verbatim.
#[test]
fn bare_status_renders_the_empty_state_verbatim() {
    let cwd = paths::HostAbsPath::try_new("/w").unwrap();
    assert_eq!(
        render_bare_status("/w", &[], &cwd, false),
        "No terminal: not attaching. State for /w:\n\
             \x20 sessions: none\n\
             \x20 blueprint: none (min init to create one)\n\
             Next:\n\
             \x20 min session activate --attach .\n\
             \x20 min ls --json\n"
    );
}

/// Sessions exist but none for this cwd: counted as elsewhere, and the
/// `Next:` lines still offer create-and-attach (attaching to another
/// project's session is not the suggestion).
#[test]
fn bare_status_counts_elsewhere_sessions() {
    let entries = vec![
        twin_entry(
            "019f5d0f-0a99-78b1-9165-0809440f0052",
            Some("api"),
            Some("/other"),
            sessions::SessionStatus::Active,
        ),
        twin_entry(
            "019f5d0f-0a99-78b1-9165-0809440f0066",
            None,
            Some("/third"),
            sessions::SessionStatus::Pending,
        ),
    ];
    let cwd = paths::HostAbsPath::try_new("/w").unwrap();
    let out = render_bare_status("/w", &entries, &cwd, true);
    assert!(
        out.contains("  sessions: 0 here (2 elsewhere)\n"),
        "elsewhere count: {out}"
    );
    assert!(
        out.contains("  min session activate --attach .\n"),
        "no cwd session must suggest activate: {out}"
    );
    assert!(
        !out.contains("session attach --command"),
        "must not suggest attaching elsewhere: {out}"
    );
}

/// More than two cwd matches: the count is the full total, the listing
/// stops at two, and an unnamed session shows its short id — which is
/// also what the attach suggestion substitutes for the first match.
#[test]
fn bare_status_lists_at_most_two_cwd_sessions() {
    let entries = vec![
        twin_entry(
            "019f5d0f-0a99-78b1-9165-0809440f0052",
            None,
            Some("/w"),
            sessions::SessionStatus::Pending,
        ),
        twin_entry(
            "019f5d0f-0a99-78b1-9165-0809440f0066",
            Some("web"),
            Some("/w"),
            sessions::SessionStatus::Materializing,
        ),
        twin_entry(
            "019f5d0f-0a99-78b1-9165-0809440f0077",
            Some("spare"),
            Some("/w"),
            sessions::SessionStatus::Active,
        ),
    ];
    let cwd = paths::HostAbsPath::try_new("/w").unwrap();
    let out = render_bare_status("/w", &entries, &cwd, true);
    assert!(
        out.contains("  sessions: 3 (019f5d0f, pending), (web, materializing)\n"),
        "count-then-two listing: {out}"
    );
    assert!(
        !out.contains("spare"),
        "third session must not be listed: {out}"
    );
    assert!(
        out.contains("  min session attach --command 'min task run <task>' 019f5d0f\n"),
        "attach suggestion uses the first match's handle: {out}"
    );
}

/// `~` abbreviation: exactly under home, home itself, and a path outside
/// home (which renders absolute, untouched).
#[test]
fn display_with_home_tilde_abbreviates_only_under_home() {
    fn p(s: &str) -> &camino::Utf8Path {
        camino::Utf8Path::new(s)
    }
    assert_eq!(
        display_with_home_tilde(p("/home/u/code/app"), Some(p("/home/u"))),
        "~/code/app"
    );
    assert_eq!(
        display_with_home_tilde(p("/home/u"), Some(p("/home/u"))),
        "~"
    );
    assert_eq!(
        display_with_home_tilde(p("/srv/app"), Some(p("/home/u"))),
        "/srv/app"
    );
    assert_eq!(display_with_home_tilde(p("/srv/app"), None), "/srv/app");
}

/// The attach/create confirmation prefers the session name and appends a
/// short id so two same-named sessions built from the same directory are
/// still distinguishable; an unnamed session falls back to the short id
/// alone rather than the full 36-character UUID.
#[test]
fn session_announce_label_prefers_name_with_short_id() {
    let id = sessions::SessionId::parse_str("a1b2c3d4-0000-0000-0000-000000000000").unwrap();
    assert_eq!(session_announce_label(&id, Some("api")), "api (a1b2c3d4)");
    assert_eq!(session_announce_label(&id, None), "a1b2c3d4");
}

/// A session created without `--name` gets a typable `<dir>-<hex>` handle:
/// the basename is lowercased and stripped to the name alphabet, and the
/// caller-supplied hex tails it.
#[test]
fn autogen_session_name_slugs_the_basename() {
    assert_eq!(
        autogen_session_name(camino::Utf8Path::new("/home/u/code/foo"), "9c1e"),
        "foo-9c1e"
    );
    // Disallowed characters are dropped and the rest lowercased.
    assert_eq!(
        autogen_session_name(camino::Utf8Path::new("/tmp/My Project!"), "4f2a"),
        "myproject-4f2a"
    );
    // A basename that sanitizes to nothing falls back to `session`.
    assert_eq!(
        autogen_session_name(camino::Utf8Path::new("/"), "0001"),
        "session-0001"
    );
}

/// Sanitization drops out-of-alphabet characters, trims leading/trailing
/// separators, and falls back to `session` for an all-symbol basename, so
/// the minted name always clears `validate_session_name`.
#[test]
fn sanitize_name_component_trims_and_falls_back() {
    assert_eq!(sanitize_name_component("--foo--"), "foo");
    assert_eq!(sanitize_name_component("café"), "caf");
    assert_eq!(sanitize_name_component("...."), "session");
    assert_eq!(sanitize_name_component("a\tb"), "ab");
    // `_` and `.` map to `-`, so the minted name stays a single DNS label.
    assert_eq!(sanitize_name_component("my_app.dev"), "my-app-dev");
    assert_eq!(sanitize_name_component("mnlh.Ab12_"), "mnlh-ab12");
    // An over-long basename is capped and re-trimmed.
    assert_eq!(sanitize_name_component(&"a".repeat(100)).len(), 48);
    assert_eq!(
        sanitize_name_component(&format!("{}-tail", "b".repeat(47))),
        "b".repeat(47)
    );
}

/// The minted suffix is exactly four lowercase hex digits.
#[test]
fn random_hex4_is_four_lowercase_hex_digits() {
    let h = random_hex4();
    assert_eq!(h.len(), 4);
    assert!(
        h.chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
        "expected four lowercase hex digits, got {h:?}"
    );
}

/// Only an autogen name retries on collision, and only within the bounded
/// budget; a user-supplied name never retries, so its collision passes
/// through, and a non-collision failure is never retried.
#[test]
fn autogen_collision_retry_is_bounded_and_skips_user_names() {
    let collision = "A session with that name already exists";
    assert!(should_retry_autogen(true, 0, collision));
    assert!(should_retry_autogen(
        true,
        AUTOGEN_NAME_RETRIES - 1,
        collision
    ));
    // Budget spent: stop retrying.
    assert!(!should_retry_autogen(true, AUTOGEN_NAME_RETRIES, collision));
    // A user-supplied name never retries — its collision surfaces verbatim.
    assert!(!should_retry_autogen(false, 0, collision));
    // A non-collision failure is never retried.
    assert!(!should_retry_autogen(true, 0, "CreateSession failed: boom"));
}

#[test]
fn provider_local_minvmd_selects_the_vm_backend() {
    use clap::Parser as _;
    let cli = Cli::try_parse_from(["min", "--provider", "local-minvmd", "ls"]).unwrap();
    assert!(cli.global_args.use_minvmd());
}

#[test]
fn provider_local_minimald_is_the_host_backend() {
    use clap::Parser as _;
    let cli = Cli::try_parse_from(["min", "--provider", "local-minimald", "ls"]).unwrap();
    assert!(!cli.global_args.use_minvmd());
}

#[test]
fn no_provider_defaults_to_the_host_backend() {
    use clap::Parser as _;
    let cli = Cli::try_parse_from(["min", "ls"]).unwrap();
    assert!(!cli.global_args.use_minvmd());
}

/// `min session list` is the canonical `<noun> list` spelling of the
/// flagship list command; `min ls` (top-level) and `min session ls`
/// (noun-level) are visible aliases. All three parse to the same `LsArgs`,
/// so `--raw`/`--json` reach the one `cmd_ls` implementation identically.
#[test]
fn session_list_spellings_all_reach_ls() {
    use clap::Parser as _;
    let ls_args = |args: &[&str]| -> LsArgs {
        match Cli::try_parse_from(args).unwrap().command {
            Some(Command::Ls(a))
            | Some(Command::Session(SessionArgs {
                command: SessionCommand::List(a),
            })) => a,
            _ => panic!("expected an ls command for {args:?}"),
        }
    };

    for spelling in [
        ["min", "session", "list"].as_slice(),
        ["min", "session", "ls"].as_slice(),
        ["min", "ls"].as_slice(),
    ] {
        let a = ls_args(spelling);
        assert!(
            !a.raw && !a.json,
            "{spelling:?} must default both flags off"
        );
    }

    // `--raw`/`--json` are accepted on the canonical and the bare form alike.
    let canonical = ls_args(&["min", "session", "list", "--raw"]);
    assert!(canonical.raw && !canonical.json);
    let bare = ls_args(&["min", "ls", "--json"]);
    assert!(bare.json && !bare.raw);
}

/// `setup-zed` takes the session the way every other session verb does —
/// `min session <verb> <session>`. The project path is not an option: it is
/// always the in-box workspace root.
#[test]
fn setup_zed_parses_as_a_session_verb() {
    use clap::Parser as _;
    let setup_zed_args = |args: &[&str]| -> SetupZedArgs {
        match Cli::try_parse_from(args).unwrap().command {
            Some(Command::Session(SessionArgs {
                command: SessionCommand::SetupZed(a),
            })) => a,
            _ => panic!("expected a setup-zed command for {args:?}"),
        }
    };

    let args = setup_zed_args(&["min", "session", "setup-zed", "my-box"]);
    assert_eq!(args.session, "my-box");
    assert!(!args.print);
    assert!(args.settings.is_none());

    let printing = setup_zed_args(&["min", "session", "setup-zed", "my-box", "--print"]);
    assert!(printing.print);

    // The project path is fixed, so there is no flag to set it.
    assert!(
        Cli::try_parse_from([
            "min",
            "session",
            "setup-zed",
            "my-box",
            "--path",
            "/elsewhere"
        ])
        .is_err(),
        "--path must not be accepted"
    );
}

/// Hidden for now: absent from `min session --help` and from the
/// completions clap generates, while still parsing and running.
#[test]
fn setup_zed_is_hidden() {
    use clap::CommandFactory as _;
    let cli = Cli::command();
    let session = cli.find_subcommand("session").expect("session subcommand");
    let setup_zed = session
        .find_subcommand("setup-zed")
        .expect("setup-zed subcommand");
    assert!(setup_zed.is_hide_set(), "setup-zed must stay hidden");
    // The visible siblings are unaffected.
    assert!(!session.find_subcommand("attach").unwrap().is_hide_set());
}

/// `--raw` and `--json` select mutually exclusive output formats, so
/// passing both must be rejected rather than silently letting one win.
#[test]
fn ls_raw_and_json_conflict() {
    use clap::Parser as _;
    assert!(Cli::try_parse_from(["min", "ls", "--raw", "--json"]).is_err());
}

/// `repo_dir` and `minimal_dir` are global, so they must be accepted after
/// the subcommand — not just before it (#1039).
#[test]
fn repo_and_minimal_dir_are_accepted_after_the_subcommand() {
    use clap::Parser as _;
    let cli =
        Cli::try_parse_from(["min", "ls", "-C", "/tmp/x", "--minimal-dir", "/tmp/y"]).unwrap();
    let p = std::path::Path::new;
    assert_eq!(cli.global_args.repo_dir.as_deref(), Some(p("/tmp/x")));
    assert_eq!(cli.global_args.minimal_dir.as_deref(), Some(p("/tmp/y")));
}

/// `session destroy` must present `[SESSION]` and `--all` as mutually
/// exclusive alternatives, one required. Regression for #1038: the error
/// path used to hide `--all` and demand a session outright, yielding a
/// usage line that could never parse.
#[test]
fn destroy_models_session_and_all_as_required_alternatives() {
    use clap::Parser as _;
    let parse = |args: &[&str]| Cli::try_parse_from(args);

    // Exactly one of a session or --all is required; both together conflict.
    assert!(parse(&["min", "session", "destroy", "web"]).is_ok());
    assert!(parse(&["min", "session", "destroy", "--all"]).is_ok());
    assert!(parse(&["min", "session", "destroy"]).is_err());
    assert!(parse(&["min", "session", "destroy", "--all", "web"]).is_err());

    // --force skips the confirm on either target: --all, or — since the
    // single-session confirm landed — a bare session too.
    assert!(parse(&["min", "session", "destroy", "--all", "--force"]).is_ok());
    assert!(parse(&["min", "session", "destroy", "web", "--force"]).is_ok());
    assert!(parse(&["min", "session", "destroy", "web", "-f"]).is_ok());
    // ... but never stands in for the required target.
    assert!(parse(&["min", "session", "destroy", "-f"]).is_err());
}

/// The single-session destroy gate is dirty-only: `--force` and a
/// proven-clean session proceed promptless in every mode (including
/// headless); dirty and unknowable states prompt interactively and
/// refuse headless, naming `--force` — EOF must never read as consent.
#[test]
fn destroy_gate_fires_only_for_dirty_or_unknowable_state() {
    let dirty = || AtRiskState::Dirty(vec!["1 file with uncommitted changes:".to_string()]);

    // --force proceeds promptless regardless of state or mode.
    for state in [AtRiskState::Clean, dirty(), AtRiskState::Unknowable] {
        assert_eq!(
            destroy_gate(true, &state, true, false).unwrap(),
            DestroyGate::Proceed
        );
    }

    // Proven clean proceeds without --force — even headless.
    for (no_input, tty) in [(false, true), (true, true), (false, false)] {
        assert_eq!(
            destroy_gate(false, &AtRiskState::Clean, no_input, tty).unwrap(),
            DestroyGate::Proceed
        );
    }

    // Dirty and unknowable prompt interactively...
    assert_eq!(
        destroy_gate(false, &dirty(), false, true).unwrap(),
        DestroyGate::Confirm
    );
    assert_eq!(
        destroy_gate(false, &AtRiskState::Unknowable, false, true).unwrap(),
        DestroyGate::Confirm
    );

    // ...and refuse headless (no tty, or --no-input), naming --force.
    for state in [dirty(), AtRiskState::Unknowable] {
        for (no_input, tty) in [(true, true), (false, false), (true, false)] {
            let err = destroy_gate(false, &state, no_input, tty)
                .expect_err("headless without --force must refuse")
                .to_string();
            assert!(err.contains("--force"), "error must name --force: {err}");
        }
    }
}

/// Classification of the daemon's at-risk report: proven-clean VCS
/// state and an empty activation delta are `Clean`; uncommitted or
/// unpushed work is `Dirty` with truthful headers; the fallback header
/// admits it may include committed work; absent or `Unavailable`
/// responses are `Unknowable`.
#[test]
fn assess_at_risk_classifies_clean_dirty_and_unknowable() {
    use minimald_rpc::SessionDeltaResponse as R;

    assert_eq!(assess_at_risk(None), AtRiskState::Unknowable);
    assert_eq!(
        assess_at_risk(Some(R::Unavailable)),
        AtRiskState::Unknowable
    );

    // Committed and pushed: proven clean.
    assert_eq!(
        assess_at_risk(Some(R::Vcs {
            uncommitted: vec![],
            unpushed_commits: 0
        })),
        AtRiskState::Clean
    );
    // Nothing changed since activation: clean in fallback mode too.
    assert_eq!(
        assess_at_risk(Some(R::ChangedSinceActivation { rows: vec![] })),
        AtRiskState::Clean
    );

    // Uncommitted files and unpushed commits both render.
    let lines = match assess_at_risk(Some(R::Vcs {
        uncommitted: vec!["M src/main.rs".to_string(), "A notes.md".to_string()],
        unpushed_commits: 2,
    })) {
        AtRiskState::Dirty(lines) => lines,
        other => panic!("expected Dirty, got {other:?}"),
    };
    assert_eq!(lines[0], "2 files with uncommitted changes:");
    assert!(lines.contains(&"  M src/main.rs".to_string()), "{lines:?}");
    assert_eq!(
        lines.last().unwrap(),
        "2 commits not pushed to any remote",
        "{lines:?}"
    );

    // Unpushed commits alone still gate, without a files header.
    let lines = match assess_at_risk(Some(R::Vcs {
        uncommitted: vec![],
        unpushed_commits: 1,
    })) {
        AtRiskState::Dirty(lines) => lines,
        other => panic!("expected Dirty, got {other:?}"),
    };
    assert_eq!(lines, vec!["1 commit not pushed to any remote".to_string()]);

    // The fallback header must not over-claim.
    let lines = match assess_at_risk(Some(R::ChangedSinceActivation {
        rows: vec!["A scratch.txt".to_string()],
    })) {
        AtRiskState::Dirty(lines) => lines,
        other => panic!("expected Dirty, got {other:?}"),
    };
    assert_eq!(
        lines,
        vec![
            "1 file differs from activation (may include committed work):".to_string(),
            "  A scratch.txt".to_string(),
        ]
    );
}

/// `min session run <session> <task>` names both the session to run in and
/// the task to run, in that order — the session-scoped counterpart to
/// `min task run <task>`, which composes a session of its own.
#[test]
fn session_run_takes_a_session_then_a_task() {
    let cli = Cli::try_parse_from(["min", "session", "run", "web", "build"]).unwrap();
    let Some(Command::Session(SessionArgs {
        command: SessionCommand::Run(a),
    })) = cli.command
    else {
        panic!("expected a session run command");
    };
    assert_eq!(a.session, "web");
    assert_eq!(a.task, "build");

    // Both operands are required: a lone session names no task.
    assert!(Cli::try_parse_from(["min", "session", "run", "web"]).is_err());
    assert!(Cli::try_parse_from(["min", "session", "run"]).is_err());
}

/// The task reaches the daemon as a named form, so a task whose name
/// collides with a program on the session's `PATH` is still a task —
/// nothing is inferred from the text (gominimal/inbox#558). `min session
/// run` sends no owns-box flag (NET-131): the task runs in a session
/// someone else keeps.
#[test]
fn session_run_encodes_a_task_form_not_a_command() {
    let request = minimald_rpc::exec::ExecRequest::TaskRun {
        task: "check".to_string(),
        owns_box: false,
        args: vec![],
        cwd: String::new(),
    };
    let wire = request.encode();
    assert_eq!(
        minimald_rpc::exec::ExecRequest::parse(&wire),
        Ok(minimald_rpc::exec::ExecRequest::TaskRun {
            task: "check".to_string(),
            owns_box: false,
            args: vec![],
            cwd: String::new(),
        })
    );
}

/// `min task run <task>` parses with `--keep` off by default; the `--path`
/// option and the `--keep` flag are accepted in any order, and every
/// positional after the task name is a task argument, never a project path.
#[test]
fn task_run_parses_task_keep_and_path() {
    use clap::Parser as _;
    let run_args = |args: &[&str]| -> TaskRunArgs {
        match Cli::try_parse_from(args).unwrap().command {
            Some(Command::Task(TaskArgs {
                command: TaskCommand::Run(a),
            })) => a,
            _ => panic!("expected `task run` for {args:?}"),
        }
    };

    let a = run_args(&["min", "task", "run", "build"]);
    assert_eq!(a.task, "build");
    assert!(!a.keep);
    assert!(a.path.is_none());
    assert!(a.args.is_empty());

    let a = run_args(&["min", "task", "run", "build", "--keep"]);
    assert!(a.keep);

    let a = run_args(&["min", "task", "run", "--keep", "build", "--path", "sub/dir"]);
    assert_eq!(a.task, "build");
    assert_eq!(a.path.as_deref(), Some("sub/dir"));
    assert!(a.keep);

    // A positional after the task name is a task argument, not a path.
    let a = run_args(&["min", "task", "run", "greet", "Alice"]);
    assert_eq!(a.task, "greet");
    assert!(a.path.is_none());
    assert_eq!(a.args, ["Alice"]);

    // `--path` may precede the task name.
    let a = run_args(&["min", "task", "run", "--path", "sub/dir", "build"]);
    assert_eq!(a.task, "build");
    assert_eq!(a.path.as_deref(), Some("sub/dir"));

    // A declared task arg is a `--<name>` flag; it passes through as-is.
    let a = run_args(&["min", "task", "run", "greet", "--name", "Alice"]);
    assert_eq!(a.task, "greet");
    assert_eq!(a.args, ["--name", "Alice"]);

    // A task arg whose name collides with a `min task run` option (`path`,
    // `keep`) goes after `--`, which ends `min`'s own options.
    let a = run_args(&["min", "task", "run", "deploy", "--", "--path", "prod"]);
    assert_eq!(a.task, "deploy");
    assert!(a.path.is_none());
    assert_eq!(a.args, ["--path", "prod"]);

    // The task name is required.
    assert!(Cli::try_parse_from(["min", "task", "run"]).is_err());
    assert!(Cli::try_parse_from(["min", "task"]).is_err());
}

/// The hidden top-level `run` swallows any spelling — flags included —
/// so every muscle-memory invocation reaches the redirect error rather
/// than a clap parse error; and it stays hidden from help.
#[test]
fn hidden_run_swallows_any_spelling_and_stays_hidden() {
    use clap::CommandFactory as _;
    use clap::Parser as _;

    match Cli::try_parse_from(["min", "run", "build", "--keep"])
        .unwrap()
        .command
    {
        Some(Command::Run(a)) => assert_eq!(a.rest, ["build", "--keep"]),
        _ => panic!("expected the hidden run catch"),
    }
    // A bare `min run` parses too; the redirect copy handles it.
    match Cli::try_parse_from(["min", "run"]).unwrap().command {
        Some(Command::Run(a)) => assert!(a.rest.is_empty()),
        _ => panic!("expected the hidden run catch"),
    }

    let cmd = Cli::command();
    let run = cmd
        .find_subcommand("run")
        .expect("the run subcommand must exist");
    assert!(run.is_hide_set(), "`min run` must stay hidden from help");
}

#[test]
fn ingress_spec_defaults_to_tcp() {
    let m = parse_ingress_mapping("18080:80").unwrap();
    assert_eq!(m.external_port, 18080);
    assert_eq!(m.internal_port, 80);
    assert_eq!(m.proto, sessions::IpProto::Tcp);
}

#[test]
fn ingress_spec_parses_explicit_proto() {
    let m = parse_ingress_mapping("5353:53/udp").unwrap();
    assert_eq!(m.external_port, 5353);
    assert_eq!(m.internal_port, 53);
    assert_eq!(m.proto, sessions::IpProto::Udp);
}

#[test]
fn ingress_spec_rejects_malformed_and_bad_proto() {
    assert!(parse_ingress_mapping("18080").is_err());
    assert!(parse_ingress_mapping("notaport:80").is_err());
    assert!(parse_ingress_mapping("18080:80/icmp").is_err());
}

#[test]
fn forward_spec_accepts_ephemeral_local_port() {
    let (local, box_port) = parse_forward_spec("0:80").unwrap();
    assert_eq!(local, 0);
    assert_eq!(box_port, 80);
}

#[test]
fn forward_spec_rejects_zero_box_port() {
    let err = parse_forward_spec("8080:0").unwrap_err().to_string();
    assert!(
        err.contains("box port must be 1-65535"),
        "expected the box-port message, got: {err}"
    );
}

#[test]
fn forward_spec_rejects_out_of_range_and_malformed() {
    assert!(parse_forward_spec("8080:99999").is_err());
    let err = parse_forward_spec("x:80").unwrap_err().to_string();
    assert!(
        err.contains("invalid local port"),
        "expected the local-port message, got: {err}"
    );
}

#[test]
fn ingress_spec_rejects_box_port_zero() {
    let err = parse_ingress_mapping("8080:0").unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("port 0 is reserved"),
        "box port 0 must be rejected: {msg}"
    );
}

/// Regression: a config in the `.minimal/` layout must be detected so
/// `activate` returns without prompting and never scaffolds over it.
/// The old naive `join(MFILE_NAME)` check missed this path.
#[test]
fn project_has_mfile_detects_dot_minimal_layout() {
    let dir = tempfile::tempdir().unwrap();
    let mfile_dir = dir.path().join(".minimal");
    std::fs::create_dir(&mfile_dir).unwrap();
    std::fs::write(
        mfile_dir.join(mfile::MFILE_NAME),
        "[upstream]\nrepo = \"https://github.com/gominimal/pkgs\"\n",
    )
    .unwrap();

    let path = camino::Utf8Path::from_path(dir.path()).expect("temp path is UTF-8");
    assert!(
        project_has_mfile(path),
        "config under .minimal/ must be detected",
    );
}

/// A project with no config in either layout is genuinely missing an
/// mfile, so detection reports false and the caller falls through to
/// the (tty-gated) prompt.
#[test]
fn project_has_mfile_false_when_absent() {
    let dir = tempfile::tempdir().unwrap();
    let path = camino::Utf8Path::from_path(dir.path()).expect("temp path is UTF-8");
    assert!(!project_has_mfile(path));
}

/// `--sync none` drops a config only when one exists up the tree: a
/// `minimal.toml` at the project root is detected from a nested subdir,
/// so the notice fires for the case that would otherwise silently lose
/// the project's packages, vars, patches and hooks.
#[test]
fn sync_none_drops_project_config_true_when_mfile_up_tree() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join(mfile::MFILE_NAME),
        "[upstream]\nrepo = \"https://github.com/gominimal/pkgs\"\n",
    )
    .unwrap();
    let root = camino::Utf8Path::from_path(dir.path()).expect("temp path is UTF-8");
    let subdir = root.join("nested/deep");
    std::fs::create_dir_all(&subdir).unwrap();

    assert!(sync_none_drops_project_config(&subdir));
    let notice = sync_none_notice(&subdir).expect("a config to drop gets a notice");
    assert!(notice.contains("minimal.toml is not sent"), "{notice}");
}

/// With no mfile anywhere up the tree, `--sync none` has nothing to
/// drop, so the notice stays silent. Anchored in `$HOME` for the same
/// reason as [`resolve_upload_root_returns_input_when_no_mfile`]: the
/// upward walk stops there, so "no mfile up the tree" is guaranteed.
#[test]
fn sync_none_drops_project_config_false_when_no_mfile() {
    let Some(home) = std::env::home_dir() else {
        return; // no HOME: no walk boundary to anchor the test to
    };
    let Ok(dir) = tempfile::tempdir_in(&home) else {
        return; // can't create temp dir in HOME, such as on a read only file system
    };
    let path = camino::Utf8Path::from_path(dir.path()).expect("temp path is UTF-8");
    assert!(!sync_none_drops_project_config(path));
    assert_eq!(sync_none_notice(path), None);
}

/// With no mfile anywhere up the tree, `resolve_upload_root` returns the
/// input directory unchanged — the original activate behaviour.
///
/// The temp dir is rooted directly in `$HOME` rather than `$TMPDIR`: the
/// upward walk stops at `$HOME`, so this is the only placement where "no
/// mfile up the tree" is guaranteed. Under `$TMPDIR` the walk escapes to
/// whatever encloses it — with `TMPDIR` inside a checkout of this repo it
/// finds the repo's own `minimal.toml` and the test fails.
#[test]
fn resolve_upload_root_returns_input_when_no_mfile() {
    let Some(home) = std::env::home_dir() else {
        return; // no HOME: no walk boundary to anchor the test to
    };
    let Ok(dir) = tempfile::tempdir_in(&home) else {
        return; // can't create temp dir in HOME, such as on a read only file system  
    };
    let path = camino::Utf8Path::from_path(dir.path()).expect("temp path is UTF-8");
    assert_eq!(resolve_upload_root(path).unwrap(), path);
}

/// `resolve_upload_root` walks up to the nearest mfile and returns its
/// repo root, so activating from a subdir still uploads the whole
/// project. Covers both the root (`./minimal.toml`) and `.minimal/`
/// layouts.
#[test]
fn resolve_upload_root_walks_up_to_mfile_root_layout() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join(mfile::MFILE_NAME),
        "[upstream]\nrepo = \"https://github.com/gominimal/pkgs\"\n",
    )
    .unwrap();
    let root = camino::Utf8Path::from_path(dir.path()).expect("temp path is UTF-8");
    let subdir = root.join("nested/deep");
    std::fs::create_dir_all(&subdir).unwrap();

    assert_eq!(resolve_upload_root(&subdir).unwrap(), root);
}

#[test]
fn resolve_upload_root_walks_up_to_mfile_dot_minimal_layout() {
    let dir = tempfile::tempdir().unwrap();
    let mfile_dir = dir.path().join(".minimal");
    std::fs::create_dir(&mfile_dir).unwrap();
    std::fs::write(
        mfile_dir.join(mfile::MFILE_NAME),
        "[upstream]\nrepo = \"https://github.com/gominimal/pkgs\"\n",
    )
    .unwrap();
    let root = camino::Utf8Path::from_path(dir.path()).expect("temp path is UTF-8");
    let subdir = root.join("nested");
    std::fs::create_dir_all(&subdir).unwrap();

    assert_eq!(resolve_upload_root(&subdir).unwrap(), root);
}

/// A malformed mfile is a real error, not a "not found": propagate it
/// so the user sees the parse failure instead of silently uploading a
/// subdir with no config and letting the daemon fabricate a default.
#[test]
fn resolve_upload_root_errors_on_malformed_mfile() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join(mfile::MFILE_NAME), "not valid toml = =").unwrap();
    let path = camino::Utf8Path::from_path(dir.path()).expect("temp path is UTF-8");
    assert!(resolve_upload_root(path).is_err());
}

/// A refused composition is reported in the user's terms — the
/// directory the activation ran from — with the daemon's own text kept
/// as subordinate detail rather than as the headline (#581).
///
/// The daemon error below is the one from the report: it names an
/// internal package server the caller never asked for and cannot reach.
#[test]
fn composition_failure_leads_with_the_directory_not_the_daemon_step() {
    let daemon_error = "init of minimal context: other: git command 'fetch' failed \
                            (exit status: 128): fatal: unable to access \
                            'http://:8898/pkgs-local.git/': Failed to connect to server";
    let msg =
        composition_failure_message(camino::Utf8Path::new("/home/dev/myproject"), daemon_error);

    let headline = msg.lines().next().expect("a first line");
    assert!(
        headline.contains("/home/dev/myproject"),
        "the headline must name the directory: {msg}"
    );
    assert!(
        !headline.contains("pkgs-local.git") && !headline.contains("ConfigureLoadout"),
        "the headline must not lead with the internal step: {msg}"
    );
    assert!(
        msg.contains(daemon_error),
        "the daemon's error is the only diagnostic and must survive: {msg}"
    );
}

/// A transient git failure — the concurrent `min session activate`
/// `index.lock` race — is not the user's configuration, so the message must
/// not instruct them to fix "the configuration there". The remedy is to
/// re-run, and the directory still leads.
#[test]
fn composition_failure_does_not_blame_config_for_git_lock() {
    let daemon_error = "init of minimal context: other: git command 'checkout' failed \
                            (exit status: 128): fatal: Unable to create \
                            '.../.git/index.lock': File exists.";
    let msg =
        composition_failure_message(camino::Utf8Path::new("/home/dev/myproject"), daemon_error);

    let headline = msg.lines().next().expect("a first line");
    assert!(
        headline.contains("/home/dev/myproject"),
        "the headline must name the directory: {msg}"
    );
    assert!(
        !msg.contains("Fix the configuration there"),
        "a git lock is transient, not a config fault: {msg}"
    );
    assert!(
        msg.contains(daemon_error),
        "the daemon's error must survive: {msg}"
    );
}

/// Every site that reports an uncomposable session goes through the one
/// helper: the refused `ConfigureLoadout` and the headless gating bail in
/// each creator, plus the interactive gating bail they share via
/// [`drive_pending_to_active`]. Asserted rather than documented — the
/// wording was already duplicated across the creators once, and the
/// interactive site was missed the first time precisely because it lives
/// in a third function.
#[test]
fn both_creators_share_the_composition_failure_message() {
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    for (file, func, uses) in [
        ("src/cmd/session.rs", "activate_session", 2),
        ("src/task.rs", "cmd_task_run", 2),
        ("src/cmd/mod.rs", "drive_pending_to_active", 1),
    ] {
        let text = std::fs::read_to_string(manifest.join(file)).expect("readable source");
        let body =
            function_body(&text, func).unwrap_or_else(|| panic!("{file} no longer defines {func}"));
        assert_eq!(
            body.matches("composition_failure_message").count(),
            uses,
            "{func} must route its composition failures through the shared message"
        );
        for bare in ["ConfigureLoadout failed", "Composition gating failed"] {
            assert!(
                !body.contains(bare),
                "{func} still names the internal step instead of the directory ({bare})"
            );
        }
    }
}

/// A project outside a VCS root that declares lifecycle hooks must be
/// detected as hook-carrying, so the headless activation path refuses
/// rather than silently dropping the hooks with the skipped tree
/// upload. A project with no `[session]` hooks reports zero and keeps
/// the quiet skip-and-warn behaviour.
#[test]
fn project_lifecycle_hook_count_detects_declared_hooks() {
    let with_hook = tempfile::tempdir().unwrap();
    std::fs::write(
        with_hook.path().join(mfile::MFILE_NAME),
        "[[session.lifecycle_hooks]]\n\
             on_activate = { type = \"inline\", value = \"echo hi\" }\n",
    )
    .unwrap();
    let root = camino::Utf8Path::from_path(with_hook.path()).expect("temp path is UTF-8");
    assert_eq!(project_lifecycle_hook_count(root), 1);

    let no_hook = tempfile::tempdir().unwrap();
    std::fs::write(
        no_hook.path().join(mfile::MFILE_NAME),
        "[upstream]\nrepo = \"https://github.com/gominimal/pkgs\"\n",
    )
    .unwrap();
    let root = camino::Utf8Path::from_path(no_hook.path()).expect("temp path is UTF-8");
    assert_eq!(project_lifecycle_hook_count(root), 0);
}

/// On a VM target the daemon is the guest's pid-1, so an accepted shutdown
/// takes the SSH transport down with it and the reply can be lost on the
/// way out. `stop` gates on the observable goal, not on the transport: a
/// daemon that reached the stopped state is a stop that worked.
#[tokio::test]
async fn stop_succeeds_when_a_lost_reply_still_stopped_the_daemon() {
    stop_outcome(
        Err(anyhow::anyhow!("EOF while parsing a value")
            .context("decode response for shutdown")
            .context("Shutdown RPC failed")),
        async || Ok(()),
        async || true,
    )
    .await
    .expect("a daemon that reached the stopped state is a successful stop");
}

/// The other half of that judgement: a failed RPC over a daemon that is
/// still there is a real failure, and the RPC's own error — context and all
/// — is what the user needs.
#[tokio::test]
async fn stop_reports_the_rpc_error_when_the_daemon_is_still_running() {
    let err = stop_outcome(
        Err(anyhow::anyhow!("connection reset").context("Shutdown RPC failed")),
        async || Ok(()),
        async || false,
    )
    .await
    .unwrap_err();

    let chain = format!("{err:#}");
    assert!(
        chain.contains("Shutdown RPC failed") && chain.contains("connection reset"),
        "expected the original RPC error chain, got: {chain}"
    );
}

/// A refusal is an answer, not a lost reply: it keeps its own message and
/// its non-zero exit, and observes nothing — the daemon it names is staying
/// up on purpose.
#[tokio::test]
async fn stop_with_live_sessions_bails_without_waiting() {
    let observed = std::cell::Cell::new(false);
    let err = stop_outcome(
        Ok(minimald_rpc::ShutdownResponse::SessionsLive),
        async || {
            observed.set(true);
            Ok(())
        },
        async || {
            observed.set(true);
            true
        },
    )
    .await
    .unwrap_err();

    assert_eq!(
        err.to_string(),
        "daemon has active sessions; pass --force to shut down anyway"
    );
    assert!(
        !observed.get(),
        "a refused shutdown has nothing to wait for"
    );
}

/// An acknowledged shutdown still has to finish, and its wait is the whole
/// judgement: a daemon that never reaches a stopped state fails with the
/// wait's own error, and the extra liveness probe — which exists only to
/// judge a *failed* RPC — never races a teardown the daemon acknowledged.
#[tokio::test]
async fn stop_fails_when_an_accepted_shutdown_never_completes() {
    stop_outcome(
        Ok(minimald_rpc::ShutdownResponse::ShuttingDown),
        async || Ok(()),
        async || false,
    )
    .await
    .expect("an acknowledged shutdown that completes is a successful stop");

    let probed = std::cell::Cell::new(false);
    let err = stop_outcome(
        Ok(minimald_rpc::ShutdownResponse::ShuttingDown),
        async || Err(anyhow::anyhow!("the VM is still shutting down after 20s")),
        async || {
            probed.set(true);
            true
        },
    )
    .await
    .unwrap_err();
    assert!(
        err.to_string().contains("still shutting down"),
        "expected the wait's error, got: {err}"
    );
    assert!(
        !probed.get(),
        "an accepted shutdown is judged by its wait alone"
    );
}

/// The recovery's actual observation, not a stand-in for it: the real
/// probe `cmd_stop` hands `stop_outcome`, run against a state dir no daemon
/// ever ran in. Nothing is listening and no lifecycle is active, which is
/// exactly the post-shutdown reading a lost reply has to be judged on, so
/// it must confirm the stop.
#[tokio::test]
async fn the_real_probe_confirms_a_daemon_that_is_not_there() {
    let dir = tempfile::tempdir().unwrap();
    assert!(
        daemon_confirmed_stopped(true, Some(dir.path().to_path_buf())).await,
        "a state dir with no live daemon is a confirmed stop"
    );
}

/// The already-down fast path: against a state dir no daemon ever ran in,
/// `stop` reports the goal state and exits 0 without connecting or
/// spawning anything.
#[tokio::test]
async fn stop_is_a_no_op_when_the_daemon_is_already_down() {
    let dir = tempfile::tempdir().unwrap();
    let global = GlobalArgs {
        repo_dir: None,
        minimal_dir: Some(dir.path().to_path_buf()),
        config_dir: None,
        provider: None,
        no_input: true,
        vm: None,
    };

    cmd_stop(&global, StopArgs { force: false })
        .await
        .expect("an already-stopped daemon is the goal state, not an error");
}

/// A `min proxy` bridge must not outlive the daemon socket: when the daemon
/// tears the connection down, the proxy exits even though its stdin — held
/// open by the driving `ssh` — never closes. Otherwise the proxy, and the
/// `ssh` process feeding it, orphan against a dead socket.
#[tokio::test]
async fn proxy_exits_when_the_daemon_closes_the_socket() {
    use std::time::Duration;

    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("proxy.sock");
    let listener = tokio::net::UnixListener::bind(&sock).unwrap();

    // Stand in for the daemon: accept the proxy's connection, then drop it,
    // the way `min stop` tears the socket down under a live proxy.
    tokio::spawn(async move {
        let (conn, _) = listener.accept().await.unwrap();
        drop(conn);
    });

    let stream = tokio::net::UnixStream::connect(&sock).await.unwrap();

    // Stdin that stays open with no data, the way `ssh` holds it; the other
    // duplex half must outlive the bridge so the reader never sees EOF.
    let (client_stdin, _ssh_stdin) = tokio::io::duplex(64);

    tokio::time::timeout(
        Duration::from_secs(5),
        proxy_bridge(stream, client_stdin, tokio::io::sink()),
    )
    .await
    .expect("proxy must exit once the socket closes, not hang on open stdin")
    .expect("a bridge that ends on a closed socket is not an error");
}

/// `--network` and `--ingress` are visible in `min session activate --help`
/// (NET-035), with the `--network` value advertising the current
/// `none|host_ip|own_ip` spellings.
#[test]
fn activate_help_shows_network_flags() {
    use clap::CommandFactory as _;

    let mut cmd = Cli::command();
    let activate = cmd
        .find_subcommand_mut("session")
        .expect("`session` stays a subcommand")
        .find_subcommand_mut("activate")
        .expect("`session activate` stays a subcommand");
    let help = activate.render_help().to_string();
    assert!(
        help.contains("--network <none|host_ip|own_ip>"),
        "--help must advertise the network modes and their spellings: {help}"
    );
    assert!(
        help.contains("--ingress <EXT:INT[/PROTO]>"),
        "--help must show the ingress flag: {help}"
    );
}

/// Runs `f` with the process's stderr redirected into a pipe and returns
/// what it wrote alongside `f`'s result.
///
/// The capture watches the real fd 2, so it observes what `eprintln!` prints
/// while it prints — a dropped or rerouted diagnostic fails the caller's
/// assertion instead of only going missing for users.
///
/// Serialized by a process-wide lock: plain `cargo test` shares fd 2 across
/// test threads, so two captures must never overlap. Under nextest — the lane
/// this crate's tests run in — every test owns its process to begin with.
fn capture_stderr<T>(f: impl FnOnce() -> T) -> (String, T) {
    use std::io::Read as _;

    static STDERR_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    let _lock = STDERR_LOCK.lock().expect("stderr capture lock");

    let (read_fd, write_fd) = nix::unistd::pipe().expect("pipe to capture stderr");
    // Save the current stderr first: the guard restores it even when `f`
    // panics with fd 2 still pointed at the pipe.
    struct RestoreStderr(std::os::fd::OwnedFd);
    impl Drop for RestoreStderr {
        fn drop(&mut self) {
            nix::unistd::dup2_stderr(&self.0).expect("restore stderr after capture");
        }
    }
    let restore =
        RestoreStderr(nix::unistd::dup(std::io::stderr()).expect("dup stderr for capture"));
    nix::unistd::dup2_stderr(&write_fd).expect("redirect stderr into the capture pipe");
    // fd 2 now holds a copy of the write end; close the original so the read
    // below reaches EOF once the restore has taken fd 2 back.
    drop(write_fd);

    let result = f();

    drop(restore);
    let mut captured = String::new();
    std::fs::File::from(read_fd)
        .read_to_string(&mut captured)
        .expect("read captured stderr");
    (captured, result)
}

/// Every legacy `--network` spelling still parses to the mode its current
/// spelling names (NET-037), and the parser prints the hint to the process's
/// stderr — exactly one line naming both spellings, captured around the real
/// clap parse so the print itself is under test. The current spellings and
/// the default print nothing, and anything else is refused.
#[test]
fn legacy_network_spellings_parse_with_hint() {
    use clap::Parser as _;

    let activate_args = |args: &[&str]| -> ActivateArgs {
        match Cli::try_parse_from(args).unwrap().command {
            Some(Command::Session(SessionArgs {
                command: SessionCommand::Activate(a),
            })) => a,
            _ => panic!("expected an activate command for {args:?}"),
        }
    };

    for (legacy, current, mode) in [
        ("no-net", "none", CliNetworkMode::NoNet),
        ("host-net", "host_ip", CliNetworkMode::HostNet),
        ("own-ip", "own_ip", CliNetworkMode::OwnIp),
    ] {
        let hint = legacy_network_hint(legacy).expect("a legacy spelling carries a hint");
        let (stderr, args) =
            capture_stderr(|| activate_args(&["min", "session", "activate", "--network", legacy]));
        assert_eq!(
            args.network, mode,
            "--network {legacy} must parse to {current}'s mode"
        );
        assert_eq!(
            stderr,
            format!("{hint}\n"),
            "--network {legacy} must print exactly the hint line to stderr"
        );
        assert!(
            hint.contains(legacy),
            "the hint must name the spelling typed: {hint}"
        );
        assert!(
            hint.contains(current),
            "the hint must name the current spelling: {hint}"
        );
    }

    for (current, mode) in [
        ("none", CliNetworkMode::NoNet),
        ("host_ip", CliNetworkMode::HostNet),
        ("own_ip", CliNetworkMode::OwnIp),
    ] {
        let (stderr, args) =
            capture_stderr(|| activate_args(&["min", "session", "activate", "--network", current]));
        assert_eq!(args.network, mode);
        assert!(
            stderr.is_empty(),
            "a current spelling must print nothing to stderr: {stderr:?}"
        );
    }

    let (stderr, args) = capture_stderr(|| activate_args(&["min", "session", "activate"]));
    assert_eq!(args.network, CliNetworkMode::HostNet);
    assert!(
        stderr.is_empty(),
        "the default network mode must print nothing to stderr: {stderr:?}"
    );

    let err = Cli::try_parse_from(["min", "session", "activate", "--network", "bogus"])
        .map(|_| ())
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("none, host_ip, own_ip"),
        "the error must name the accepted spellings: {err}"
    );
}

/// The `--network` parser accepts every [`sessions::NetworkMode::word`] and
/// maps it back to the same mode, so the word the daemon logs and the
/// refusals print is always one a person can type.
#[test]
fn network_parser_round_trips_every_mode_word() {
    for mode in [
        sessions::NetworkMode::NoNet,
        sessions::NetworkMode::HostNet,
        sessions::NetworkMode::OwnIp,
    ] {
        let parsed = parse_network_mode(mode.word()).expect("a mode word must parse");
        assert_eq!(sessions::NetworkMode::from(parsed), mode, "{}", mode.word());
    }
}

/// `--deny-all-egress` conflicts with every egress rule flag at parse
/// (NET-075's CLI half): a deny-all declaration admits no exceptions, so
/// combining it with any `--allow-*`/`--deny-*` rule is refused before the
/// activation runs, naming both flags — and the refusal is the parser's
/// conflict, not a later validation, so nothing is half-declared. The one
/// egress-shaped flag it must combine with is `--credentialed-upstream`
/// (NET-134): the proxy listener is infrastructure, the machine-internal
/// analogue of the fabric pin's infrastructure set, so a deny-all box may
/// still declare the lane — the proxy's own checks govern what the lane
/// grants, and this flag's conflict is with rules, never with
/// infrastructure.
#[test]
fn deny_all_egress_conflicts_with_every_egress_flag() {
    use clap::Parser as _;

    for (rule, value) in [
        ("--allow-subnets", "10.0.0.0/8"),
        ("--allow-dns-hosts", "github.com"),
        ("--allow-protocols", "tcp"),
        ("--deny-subnets", "0.0.0.0/0"),
    ] {
        let err = Cli::try_parse_from([
            "min",
            "session",
            "activate",
            "--deny-all-egress",
            rule,
            value,
        ])
        .map(|_| ())
        .expect_err("--deny-all-egress must conflict with every egress rule flag");
        assert_eq!(
            err.kind(),
            clap::error::ErrorKind::ArgumentConflict,
            "the combination must be refused as a parse conflict, not a later \
             validation: {err}"
        );
        let rendered = err.to_string();
        assert!(
            rendered.contains("--deny-all-egress"),
            "the refusal must name the deny-all flag: {rendered}"
        );
        assert!(
            rendered.contains(rule),
            "the refusal must name the rule flag it conflicts with: {rendered}"
        );
    }

    // The flag on its own parses, and it carries one meaning wherever the
    // egress flags appear: a boolean declaration with no value to validate.
    let args = Cli::try_parse_from(["min", "session", "activate", "--deny-all-egress"])
        .expect("--deny-all-egress alone must parse");
    match args.command {
        Some(Command::Session(SessionArgs {
            command: SessionCommand::Activate(a),
        })) => assert!(a.deny_all_egress, "the flag must land on the args"),
        _ => panic!("expected an activate command"),
    }

    // The proxy lane is not a rule (NET-134): the two combine.
    Cli::try_parse_from([
        "min",
        "session",
        "activate",
        "--deny-all-egress",
        "--credentialed-upstream",
    ])
    .expect("--deny-all-egress must combine with --credentialed-upstream");
}

/// The dynamic ingress flags parse at the flag (NET-043): a mode with a
/// range lands as both, a mode alone lands with no range, an unknown mode
/// is refused by the mode's parser, and a privileged range is refused by
/// the range's parser in the launch check's own words.
#[test]
fn dynamic_ingress_flags_parse() {
    use clap::Parser as _;

    let activate = |argv: &[&str]| -> ActivateArgs {
        let args = Cli::try_parse_from(argv)
            .unwrap_or_else(|error| panic!("{argv:?} must parse: {error}"));
        match args.command {
            Some(Command::Session(SessionArgs {
                command: SessionCommand::Activate(a),
            })) => a,
            _ => panic!("expected an activate command"),
        }
    };

    let a = activate(&[
        "min",
        "session",
        "activate",
        "--dynamic-ingress",
        "allow",
        "--dynamic-range",
        "8000-8443",
    ]);
    assert_eq!(a.dynamic_ingress, Some(sessions::DynamicIngress::Allow));
    assert_eq!(a.dynamic_range, Some((8000, 8443)));

    let a = activate(&["min", "session", "activate", "--dynamic-ingress", "ask"]);
    assert_eq!(a.dynamic_ingress, Some(sessions::DynamicIngress::Ask));
    assert_eq!(a.dynamic_range, None, "a mode alone carries no range");

    let Err(err) =
        Cli::try_parse_from(["min", "session", "activate", "--dynamic-ingress", "maybe"])
    else {
        panic!("an unknown dynamic ingress mode must not parse");
    };
    let rendered = err.to_string();
    assert!(
        rendered.contains("unknown mode 'maybe'"),
        "the refusal must name the mode, got: {rendered}"
    );

    let Err(err) = Cli::try_parse_from([
        "min",
        "session",
        "activate",
        "--dynamic-ingress",
        "allow",
        "--dynamic-range",
        "80-90",
    ]) else {
        panic!("a privileged dynamic range must not parse");
    };
    let rendered = err.to_string();
    assert!(
        rendered.contains(&sessions::PolicyError::PrivilegedDynamicRange { lo: 80 }.to_string()),
        "the refusal must use the launch check's words, got: {rendered}"
    );
}

/// The CLI reference documents the network flags on `session activate`
/// (NET-036), read from the real file so a docs edit cannot silently drop
/// either row.
#[test]
fn cli_reference_documents_network_flags() {
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/reference/cli-min.md");
    let doc = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    let section = doc
        .split_once("### `session activate`")
        .expect("a `session activate` section in the CLI reference")
        .1;
    let section = section.split("### ").next().unwrap();
    // Table cells escape their pipes as `\|`; compare against the rendered
    // form.
    let section = section.replace("\\|", "|");
    for row in [
        "--network <none|host_ip|own_ip>",
        "--ingress <EXT:INT[/PROTO]>",
        "--dynamic-ingress <allow|ask|deny>",
        "--dynamic-range <LO-HI>",
    ] {
        assert!(
            section.contains(row),
            "the CLI reference's `session activate` rows must document `{row}`"
        );
    }
}

/// Stand up the two-VM shape the named-VM tests below need (NET-057/NET-058):
/// a minimal state dir laid out as the minvmd provider nests a named VM
/// (NET-052) — the default VM serving `providers/local-minvmd0/ssh.sock`,
/// `alpha` serving `providers/local-minvmd0/alpha/ssh.sock` — with a real
/// daemon behind each socket. Real daemons, not stub sockets, because both
/// tests drive the real client transport: the listing connects to each VM to
/// take its `ListSessions`, and the box-name resolution looks the name up on
/// each VM's daemon.
async fn two_vms() -> (
    tempfile::TempDir,
    minimald::test_harness::TestServer,
    minimald::test_harness::TestServer,
) {
    let state = tempfile::tempdir().expect("a temp minimal state dir for two VMs");
    let alpha_dir = state.path().join("providers/local-minvmd0/alpha");
    std::fs::create_dir_all(&alpha_dir).expect("the named VM's provider subdir");
    let default_sock =
        client::resolve_socket_path_named(Some(state.path()), true, paths::DEFAULT_VM_NAME)
            .expect("the default VM's socket path");
    let default_vm = minimald::test_harness::TestServer::new().await;
    default_vm.listen_on_uds(&default_sock).await;
    let alpha = minimald::test_harness::TestServer::new().await;
    alpha.listen_on_uds(&alpha_dir.join("ssh.sock")).await;
    (state, default_vm, alpha)
}

/// Create a named box on one VM's daemon — the CLI's own
/// create/configure/finalize sequence, so the record is durable (an
/// unfinalized one is reaped when the connection that created it drops) and
/// therefore listed under the name given. The create asserts this build the
/// way every other `CreateSession` in the crate does: the harness daemon is
/// the same build, so the assertion holds, and the inventory test that stops
/// a third client path from quietly passing `None` keeps reading "asserts".
async fn create_box_on(
    server: &minimald::test_harness::TestServer,
    name: &str,
) -> sessions::SessionId {
    use minimald_rpc::{
        ConfigureLoadout, ConfigureLoadoutRequest, CreateSession, CreateSessionRequest, Errorable,
        FinalizeSession, FinalizeSessionRequest, SessionConfig,
    };

    let mut client = server.connect().await;
    let project_path =
        camino::Utf8PathBuf::from_path_buf(std::env::current_dir().expect("the test cwd"))
            .expect("UTF-8");
    let id = match client
        .call::<CreateSession>(&CreateSessionRequest {
            config: SessionConfig {
                name: Some(name.to_string()),
                project_path: paths::HostAbsPath::try_new(project_path)
                    .expect("the test cwd as a host path"),
                network: sessions::NetworkMode::NoNet,
                policy: sessions::SessionPolicy::default(),
                box_addresses: None,
                hooks_enabled: true,
                attrs: Default::default(),
            },
            must_match_version: minimal_client::version_assertion(),
        })
        .await
    {
        Errorable::Ok(created) => created.id,
        Errorable::Err { error } => panic!("CreateSession failed: {error}"),
    };
    // The empty composition needs no workspace and no gating, so both steps
    // take their happy paths and leave an `Active`, durable record.
    match client
        .call::<ConfigureLoadout>(&ConfigureLoadoutRequest {
            session_id: id,
            contribution: Default::default(),
        })
        .await
    {
        Errorable::Ok(_) => {}
        Errorable::Err { error } => panic!("ConfigureLoadout failed: {error}"),
    }
    match client
        .call::<FinalizeSession>(&FinalizeSessionRequest {
            session_id: id,
            report_shared_port_collisions: false,
        })
        .await
    {
        Errorable::Ok(_) => id,
        Errorable::Err { error } => panic!("FinalizeSession failed: {error}"),
    }
}

/// The `GlobalArgs` that select the minvmd backend for `state`, pinning `vm`
/// when given: what a `min --provider local-minvmd [--vm NAME] …` invocation
/// resolves to. (Published `--vm` names are not set here: the process-global
/// is first-call-wins, and these tests must not perturb it for others.)
fn vm_globals(state: &std::path::Path, vm: Option<String>) -> GlobalArgs {
    GlobalArgs {
        repo_dir: None,
        minimal_dir: Some(state.to_path_buf()),
        config_dir: None,
        provider: Some(Provider::LocalMinvmd),
        no_input: true,
        vm,
    }
}

/// The box names a listing's VM carries, `-`-free and in order.
fn listed_names(listing: &VmListing) -> Vec<&str> {
    listing
        .resp
        .sessions
        .iter()
        .map(|entry| entry.name.as_deref().expect("the test boxes are named"))
        .collect()
}

/// NET-057: with two VMs running, `min ls` lists every VM's boxes and shows
/// the VM each box lives on — one listing spanning both daemons, the VM per
/// box filled in client-side (each daemon knows only its own).
#[tokio::test]
async fn ls_shows_vm_per_box() {
    let (state, default_vm, alpha) = two_vms().await;
    let api = create_box_on(&default_vm, "api").await;
    let web = create_box_on(&alpha, "web").await;

    let listings = cmd::ls_listings(&vm_globals(state.path(), None))
        .await
        .expect("listing a two-VM host succeeds");
    assert_eq!(listings.len(), 2, "a two-VM host lists both VMs");
    assert_eq!(listings[0].vm, "default", "the default VM lists first");
    assert_eq!(listings[1].vm, "alpha");
    assert_eq!(listed_names(&listings[0]), ["api"], "the default VM's box");
    assert_eq!(listed_names(&listings[1]), ["web"], "the named VM's box");

    // The VM is a column, and each box's row carries its own. NET-018's
    // verdict is per VM for the same reason: the host's resolver hook
    // routes the zone to one VM's answerer (NET-059), so each VM's fact
    // line says which surface its own names answer through — here fed
    // straight to the formatter, the way the verdict a configured host's
    // reads decide arrives at it, with the host daemon answering through
    // its proxy and the named VM through native DNS. NET-138's answerer row
    // is per VM for the same reason's host half: each VM's own control
    // socket read decides its own row, so a VM whose minvmd holds the
    // machine's port says so while a sibling registered with another
    // daemon names that holder instead — one `Holder` and one `Registered`
    // here, fed the same way.
    let surfaces = vec![
        Some(crate::resolver::LiveSurface::Proxy),
        Some(crate::resolver::LiveSurface::Native),
    ];
    let answerers = vec![
        Some(minimald_rpc::ZoneAnswererStatus::Holder { port: 7_656 }),
        Some(minimald_rpc::ZoneAnswererStatus::Registered { port: 7_656 }),
    ];
    let mut out = Vec::new();
    format_ls_across_vms(
        &mut out,
        &LsArgs {
            raw: false,
            json: false,
        },
        &listings,
        &surfaces,
        &answerers,
    )
    .expect("rendering the two-VM listing");
    let table = String::from_utf8(out).expect("the listing is UTF-8");
    let row_of = |id: &sessions::SessionId| {
        table
            .lines()
            .find(|l| l.contains(&id.to_string()))
            .unwrap_or_else(|| panic!("a row for {id} in:\n{table}"))
            .to_string()
    };
    assert!(
        table.contains("VM  "),
        "the table must carry a VM column:\n{table}"
    );
    assert!(row_of(&api).starts_with("default "), "got:\n{table}");
    assert!(row_of(&web).starts_with("alpha "), "got:\n{table}");
    let surface_line_of = |vm: &str| {
        table
            .lines()
            .find(|l| l.starts_with("NAME SURFACE:") && l.contains(vm))
            .unwrap_or_else(|| panic!("a NAME SURFACE line for {vm} in:\n{table}"))
            .to_string()
    };
    assert!(
        surface_line_of("default").contains("the hostname proxy is the live name surface"),
        "the VM the hook does not route to keeps its proxy line:\n{table}"
    );
    assert!(
        surface_line_of("alpha").contains("native DNS is the live name surface"),
        "the VM the hook routes to is named native:\n{table}"
    );
    let answerer_row_of = |vm: &str| {
        table
            .lines()
            .find(|l| l.starts_with("ZONE ANSWERER:") && l.contains(vm))
            .unwrap_or_else(|| panic!("a ZONE ANSWERER line for {vm} in:\n{table}"))
            .to_string()
    };
    assert!(
        answerer_row_of("default").contains("this VM's minvmd holds it on 127.0.0.1:7656"),
        "the VM whose minvmd holds the port says so, in its own row:\n{table}"
    );
    assert!(
        answerer_row_of("alpha").contains("another VM host daemon holds it on 127.0.0.1:7656"),
        "the registered VM names the holder, in its own row:\n{table}"
    );
    assert!(
        !answerer_row_of("alpha").contains("this VM's minvmd holds it"),
        "a VM registered with another daemon must not claim its own minvmd \
         holds the port:\n{table}"
    );
    assert!(
        !answerer_row_of("default").contains("another VM host daemon"),
        "a holder must not be named as a sibling's registration:\n{table}"
    );

    // One VM listed renders exactly the single-VM listing `min ls` has always
    // printed — the surface line included, verdict and all, and the VM's own
    // answerer row with it: the column is a fact about a multi-VM host, not a
    // new format.
    let single = &listings[1..];
    let mut delegated = Vec::new();
    format_ls_across_vms(
        &mut delegated,
        &LsArgs {
            raw: false,
            json: false,
        },
        single,
        &surfaces[1..],
        &answerers[1..],
    )
    .expect("rendering the single-VM listing");
    let mut direct = Vec::new();
    format_ls(
        &mut direct,
        &LsArgs {
            raw: false,
            json: false,
        },
        &single[0].resp,
        surfaces[1].clone(),
        answerers[1].clone(),
    )
    .expect("format_ls on the same listing");
    assert_eq!(
        String::from_utf8_lossy(&delegated),
        String::from_utf8_lossy(&direct),
        "one VM listed must render as the single-VM listing"
    );

    // `--json` stays one object on a multi-VM host — the shape every
    // consumer of `min ls --json` parses — with the VM inside each entry of
    // the one `sessions` array, where a pipeline reads it: `.sessions` keeps
    // working across VMs instead of breaking on a per-VM array. The
    // machine modes never print the verdict, so they carry none.
    let mut out = Vec::new();
    format_ls_across_vms(
        &mut out,
        &LsArgs {
            raw: false,
            json: true,
        },
        &listings,
        &[],
        &[],
    )
    .expect("rendering the two-VM listing as JSON");
    let listing: serde_json_lenient::Value =
        serde_json_lenient::from_str(std::str::from_utf8(&out).expect("UTF-8"))
            .expect("the multi-VM JSON listing is one object");
    assert!(
        !matches!(listing, serde_json_lenient::Value::Array(_)),
        "the top level must stay an object, not one per VM: {listing}"
    );
    let sessions = listing["sessions"]
        .as_array()
        .unwrap_or_else(|| panic!("one sessions array spanning the VMs: {listing}"));
    assert_eq!(
        sessions.len(),
        2,
        "both VMs' boxes in the one array: {listing}"
    );
    let by_vm = |value: &serde_json_lenient::Value| -> (String, String) {
        (
            value["vm"]
                .as_str()
                .expect("each entry carries its VM")
                .to_owned(),
            value["name"]
                .as_str()
                .expect("each entry is a box")
                .to_owned(),
        )
    };
    assert_eq!(
        by_vm(&sessions[0]),
        ("default".to_owned(), "api".to_owned()),
        "the first box carries its VM: {listing}"
    );
    assert_eq!(
        by_vm(&sessions[1]),
        ("alpha".to_owned(), "web".to_owned()),
        "the second box carries its VM: {listing}"
    );
    // The facts the single-VM object carried per daemon cannot sit at the
    // top level once there are several VMs, so each VM keeps its own object
    // under `vms`, named the same way.
    let vms = listing["vms"]
        .as_array()
        .unwrap_or_else(|| panic!("one vms array naming each VM's own facts: {listing}"));
    assert_eq!(
        (
            vms[0]["vm"].as_str(),
            vms[0]["resource_pool"].is_object(),
            vms.len()
        ),
        (Some("default"), true, 2),
        "each VM's facts stay reachable per VM: {listing}"
    );
    assert!(
        vms.iter().all(|vm| vm.get("sessions").is_none()),
        "the sessions live in the one array, not duplicated per VM: {listing}"
    );
}

/// The selected VM's socket can appear a beat after the listing starts: on
/// the VM backend the bridge UDS shows up slightly after the `vm-up` line —
/// the race [`client::Client::connect`]'s retry window exists to absorb — so
/// the not-running skip must exempt the selected VM. It is up
/// ([`cmd::ensure_daemon`] saw to that before the listing ran); skipping it on
/// a path that was merely late would drop the operator's own boxes and print
/// another VM's as the whole picture.
#[tokio::test]
async fn ls_keeps_the_selected_vm_when_its_socket_appears_late() {
    let state = tempfile::tempdir().expect("a temp minimal state dir for two VMs");
    let provider = state.path().join("providers/local-minvmd0");
    std::fs::create_dir_all(provider.join("alpha")).expect("the named VM's provider subdir");
    let default_sock =
        client::resolve_socket_path_named(Some(state.path()), true, paths::DEFAULT_VM_NAME)
            .expect("the default VM's socket path");
    // Both daemons are real. The selected VM's socket is not bound yet — its
    // box is created over the harness's in-memory pair, the way a booting
    // VM's daemon is up before its bridge socket exists.
    let default_vm = minimald::test_harness::TestServer::new().await;
    create_box_on(&default_vm, "api").await;
    let alpha = minimald::test_harness::TestServer::new().await;
    alpha.listen_on_uds(&provider.join("alpha/ssh.sock")).await;
    create_box_on(&alpha, "web").await;

    let global = vm_globals(state.path(), None);
    let listing = tokio::spawn(async move { cmd::ls_listings(&global).await });
    // The listing is now watching the selected VM's not-yet-bound path; the
    // socket lands mid-retry — later than the listing started, earlier than
    // the retry window closes. (The current-thread test runtime only polls
    // the spawned listing where this sleep yields, so the socket is bound
    // while the listing is provably inside that window.)
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    default_vm.listen_on_uds(&default_sock).await;

    let listings = listing
        .await
        .expect("the listing task must not panic")
        .expect("listing a two-VM host whose selected VM bound late succeeds");
    assert_eq!(
        listings.len(),
        2,
        "the selected VM must not be dropped for a socket that was late"
    );
    assert_eq!(listings[0].vm, "default", "the selected VM lists first");
    assert_eq!(listed_names(&listings[0]), ["api"], "the selected VM's box");
    assert_eq!(listings[1].vm, "alpha");
    assert_eq!(listed_names(&listings[1]), ["web"]);
}

/// The VMs a listing reaches past must not be waited on: a stopped VM's
/// stale `ssh.sock` — the path a dead listener left behind — is "not
/// running", one probe attempt with no retry and no warning, and a wedged
/// one — the socket accepts, the daemon never speaks SSH — is bounded by the
/// probe's short leash rather than the stacked connect, handshake and RPC
/// deadlines that held a listing for ~72 s per wedged VM before the probe
/// existed.
#[tokio::test]
async fn ls_leashes_the_vms_it_did_not_select() {
    let state = tempfile::tempdir().expect("a temp minimal state dir");
    let provider = state.path().join("providers/local-minvmd0");
    std::fs::create_dir_all(provider.join("alpha")).expect("the wedged VM's dir");
    std::fs::create_dir_all(provider.join("beta")).expect("the stopped VM's dir");

    // The selected VM, running, with its box.
    let default_sock =
        client::resolve_socket_path_named(Some(state.path()), true, paths::DEFAULT_VM_NAME)
            .expect("the default VM's socket path");
    let default_vm = minimald::test_harness::TestServer::new().await;
    default_vm.listen_on_uds(&default_sock).await;
    create_box_on(&default_vm, "api").await;

    // A wedged VM: the socket accepts and never speaks SSH — the shape a
    // suspended microVM presents behind an always-accepting bridge.
    let wedged = tokio::net::UnixListener::bind(provider.join("alpha/ssh.sock"))
        .expect("the wedged VM's socket binds");
    tokio::spawn(async move {
        // Accepted connections are held, never read, never closed: the
        // handshake on the other end must be the one that gives up.
        let mut held = Vec::new();
        while let Ok((conn, _)) = wedged.accept().await {
            held.push(conn);
        }
    });

    // A stopped VM: the listener died and left its socket path behind.
    let stale = std::os::unix::net::UnixListener::bind(provider.join("beta/ssh.sock"))
        .expect("the stopped VM's socket path binds");
    drop(stale);

    let started = std::time::Instant::now();
    let listings = tokio::time::timeout(
        std::time::Duration::from_secs(20),
        cmd::ls_listings(&vm_globals(state.path(), None)),
    )
    .await
    .expect("a listing that reaches past other VMs must not be held by any of them")
    .expect("listing past a wedged and a stopped VM succeeds");
    assert_eq!(listings.len(), 1, "only the running VM lists");
    assert_eq!(listings[0].vm, "default");
    assert_eq!(listed_names(&listings[0]), ["api"]);
    let elapsed = started.elapsed();
    assert!(
        elapsed < std::time::Duration::from_secs(8),
        "a wedged VM may hold the listing only for the probe's leash, \
         not the handshake's own deadline ({elapsed:?})"
    );
}

/// The stopped-VM half of [`ls_leashes_the_vms_it_did_not_select`] on its own,
/// under the bound that proves the ask: with no wedged VM in the picture, a
/// stopped VM's stale `ssh.sock` is ECONNREFUSED on one probe attempt —
/// "not running" ([`client::ProbeRefusal::NotRunning`]), no ~2 s connect
/// retry, no warning — so a listing that passes it costs the VMs that are
/// up, not the stopped ones' retry windows. The wedged test's 8 s bound is
/// for the wedge's leash and cannot tell a 2 s retry from none; this one
/// can. Mirrors `a_stopped_vm_does_not_hold_a_box_name_resolution`, the
/// resolution path's own proof of the same treatment.
#[tokio::test]
async fn a_stopped_vm_does_not_hold_a_listing() {
    let state = tempfile::tempdir().expect("a temp minimal state dir");
    let provider = state.path().join("providers/local-minvmd0");
    std::fs::create_dir_all(provider.join("beta")).expect("the stopped VM's dir");

    // The selected VM, running, with its box.
    let default_sock =
        client::resolve_socket_path_named(Some(state.path()), true, paths::DEFAULT_VM_NAME)
            .expect("the default VM's socket path");
    let default_vm = minimald::test_harness::TestServer::new().await;
    default_vm.listen_on_uds(&default_sock).await;
    create_box_on(&default_vm, "api").await;

    // The stopped VM: the listener died and left its socket path behind.
    let stale = std::os::unix::net::UnixListener::bind(provider.join("beta/ssh.sock"))
        .expect("the stopped VM's socket path binds");
    drop(stale);

    let started = std::time::Instant::now();
    let listings = cmd::ls_listings(&vm_globals(state.path(), None))
        .await
        .expect("listing past a stopped VM succeeds");
    let elapsed = started.elapsed();
    assert_eq!(listings.len(), 1, "only the running VM lists");
    assert_eq!(listings[0].vm, "default");
    assert_eq!(listed_names(&listings[0]), ["api"]);
    assert!(
        elapsed < std::time::Duration::from_secs(1),
        "a stopped VM's stale socket must not charge the listing its \
         connect-retry window ({elapsed:?})"
    );
}

/// The fallback listing's control-sock gate keys on the backend the daemon
/// connection resolves through, never on `use_minvmd()` — the same rule every
/// other VM-backed gate keys on: the flag is how Linux asks for the VM host,
/// while macOS reaches it with no flag at all, so a gate keyed on the flag
/// would find no control socket for exactly the host whose every invocation
/// is VM-backed, and the one entry `min ls` falls back to there would carry
/// no answerer state to read.
#[test]
fn fallback_listing_control_sock_keys_on_provider_kind() {
    let state = tempfile::tempdir().expect("a temp minimal state dir");
    let sock = state.path().join("ssh.sock");
    // The unflagged invocation resolves through the platform's default
    // backend, so the expectation is that backend's — `client_provider_kind`'s
    // own reading, whatever host this runs on: on Linux the native backend
    // hosts no VM host daemon, while macOS has no native backend at all and
    // every invocation is minvmd-backed, flag or no flag.
    let unflagged = GlobalArgs {
        repo_dir: None,
        minimal_dir: Some(state.path().to_path_buf()),
        config_dir: None,
        provider: None,
        no_input: true,
        vm: None,
    };
    assert_eq!(
        fallback_control_sock(&unflagged, &sock).is_some(),
        client::client_provider_kind(false) == paths::ProviderKind::Minvmd,
        "an unflagged fallback carries a control socket exactly when the \
         backend it resolves through is minvmd"
    );
    // `--provider local-minvmd` asks for the VM host whatever the platform's
    // default backend is, so the fallback always resolves the control socket
    // beside the daemon socket it just listed through.
    let control = fallback_control_sock(&vm_globals(state.path(), None), &sock)
        .expect("`--provider local-minvmd` always resolves a control socket");
    assert_eq!(
        control,
        sock.parent()
            .unwrap()
            .join(minvmd::control::CONTROL_SOCK_FILE),
        "the control socket sits beside the daemon socket the listing resolved"
    );
}

/// NET-058: a box name resolves to the VM that owns it with no global flag —
/// across every VM's socket, since the selected VM's daemon has just said it
/// does not know the name. The resolution covers the selected VM too (a
/// caller that asks once gets one answer), refuses nothing but an ambiguous
/// name, and stays out of the way of an explicit `--vm`.
#[tokio::test]
async fn box_name_resolves_vm_without_flag() {
    let (state, default_vm, alpha) = two_vms().await;
    create_box_on(&default_vm, "api").await;
    let web = create_box_on(&alpha, "web").await;
    let global = vm_globals(state.path(), None);

    let resolved = attach::resolve_box_vm(&global, "web")
        .await
        .expect("resolving across a two-VM host succeeds")
        .expect("'web' lives on alpha, so the name must resolve");
    assert_eq!(resolved.vm, "alpha", "the VM that owns the name");
    assert_eq!(
        resolved.record.id, web,
        "the record that VM's daemon resolved the name to"
    );
    assert_eq!(resolved.record.name.as_deref(), Some("web"));
    assert_eq!(
        resolved.sock,
        state.path().join("providers/local-minvmd0/alpha/ssh.sock"),
        "the owning VM's socket, ready for the hand-off"
    );

    // A box on the selected VM resolves to it: the resolution spans every
    // VM's socket, so one ask has one answer wherever the box lives.
    let on_selected = attach::resolve_box_vm(&global, "api")
        .await
        .expect("resolving a name the default VM owns succeeds")
        .expect("'api' lives on the default VM");
    assert_eq!(on_selected.vm, "default");

    // A name no VM owns resolves to nothing — the caller reports its own
    // original error.
    assert!(
        attach::resolve_box_vm(&global, "no-such-box")
            .await
            .expect("an unowned name is not an error")
            .is_none()
    );

    // An explicit `--vm` pins where to look; the resolution must not override
    // the operator's choice by looking elsewhere.
    let pinned = vm_globals(state.path(), Some("alpha".to_string()));
    assert!(
        attach::resolve_box_vm(&pinned, "web")
            .await
            .expect("a pinned run is not an error")
            .is_none(),
        "a pinned run resolves nothing on its own"
    );

    // Two VMs owning the same name is a tie the name cannot settle: refuse
    // it, name both, and point at the flag that disambiguates.
    create_box_on(&alpha, "shared").await;
    create_box_on(&default_vm, "shared").await;
    let err = attach::resolve_box_vm(&global, "shared")
        .await
        .expect_err("an ambiguous name must be refused, not guessed")
        .to_string();
    assert!(
        err.contains("default") && err.contains("alpha"),
        "the refusal must name every VM that owns it: {err}"
    );
    assert!(
        err.contains("--vm"),
        "the refusal must point at the disambiguator: {err}"
    );
}

/// NET-058's attach half: `min session attach <box>` asks the selected VM's
/// daemon first and, when that daemon does not know the name, falls through
/// to the VM that owns it — the record *and* the socket the SSH hand-off runs
/// over are the owning VM's, not the selected one's. The helper is driven
/// directly, without the live session shell behind the hand-off: what the
/// hand-off consumes is exactly what it returns.
#[tokio::test]
async fn attach_fall_through_hands_off_the_owning_vm() {
    let (state, default_vm, alpha) = two_vms().await;
    let api = create_box_on(&default_vm, "api").await;
    let web = create_box_on(&alpha, "web").await;
    let global = vm_globals(state.path(), None);
    let selected =
        client::resolve_socket_path_named(Some(state.path()), true, paths::DEFAULT_VM_NAME)
            .expect("the selected VM's socket path");
    let mut client = client::Client::connect(&selected)
        .await
        .expect("connect to the selected VM's daemon");

    // A name only alpha knows: the selected VM's daemon has just said so, so
    // the target is alpha's record over alpha's socket.
    let (record, handed_off) =
        cmd::resolve_attach_target_version_gated(&global, &mut client, selected.clone(), "web")
            .await
            .expect("a name alpha owns resolves through the selected VM's miss");
    assert_eq!(
        record.id, web,
        "the owning VM's record, not the selected one's"
    );
    assert_eq!(record.name.as_deref(), Some("web"));
    assert_eq!(
        handed_off,
        state.path().join("providers/local-minvmd0/alpha/ssh.sock"),
        "the hand-off runs over the owning VM's socket"
    );

    // A name the selected VM itself knows never leaves it.
    let (on_selected, its_sock) =
        cmd::resolve_attach_target_version_gated(&global, &mut client, selected.clone(), "api")
            .await
            .expect("a name the selected VM owns resolves on the selected VM");
    assert_eq!(on_selected.id, api);
    assert_eq!(its_sock, selected, "the selected VM's own socket");

    // A name nothing owns reports the selected VM's own miss: it is the
    // more useful of the two answers.
    let err =
        cmd::resolve_attach_target_version_gated(&global, &mut client, selected, "no-such-box")
            .await
            .expect_err("an unowned name is the selected VM's error");
    assert!(
        err.to_string().contains("no-such-box"),
        "the miss names what was asked for: {err}"
    );
}

/// The resolution path gets the same treatment as the listing: a stopped
/// VM's stale `ssh.sock` is probed once — "not running", not a fault to retry
/// for — so a name resolution across every VM costs the VMs that are up, not
/// the stopped ones' retry windows.
#[tokio::test]
async fn a_stopped_vm_does_not_hold_a_box_name_resolution() {
    let state = tempfile::tempdir().expect("a temp minimal state dir");
    let provider = state.path().join("providers/local-minvmd0");
    std::fs::create_dir_all(provider.join("beta")).expect("the stopped VM's dir");

    let default_sock =
        client::resolve_socket_path_named(Some(state.path()), true, paths::DEFAULT_VM_NAME)
            .expect("the default VM's socket path");
    let default_vm = minimald::test_harness::TestServer::new().await;
    default_vm.listen_on_uds(&default_sock).await;
    create_box_on(&default_vm, "api").await;

    // The stopped VM: a dead listener's socket path, still enumerable.
    let stale = std::os::unix::net::UnixListener::bind(provider.join("beta/ssh.sock"))
        .expect("the stopped VM's socket path binds");
    drop(stale);

    let global = vm_globals(state.path(), None);
    let started = std::time::Instant::now();
    let resolved = attach::resolve_box_vm(&global, "api")
        .await
        .expect("resolving past a stopped VM succeeds")
        .expect("'api' lives on the running VM");
    let elapsed = started.elapsed();
    assert_eq!(resolved.vm, "default", "the VM that owns the name");
    assert_eq!(resolved.record.name.as_deref(), Some("api"));
    assert!(
        elapsed < std::time::Duration::from_secs(1),
        "a stopped VM's stale socket must not charge the resolution its \
         connect-retry window ({elapsed:?})"
    );
}

/// NET-058's ambiguous half, on the path attach itself runs: when the
/// selected VM does not know the name and the fall-through finds it on two
/// VMs, the attach must refuse rather than take the first VM that answers —
/// an attach that lands in a project the operator did not choose is worse
/// than one that asks. The refusal names every VM that knows the name and
/// points at the flag that disambiguates, and it stops the hand-off: the
/// resolution itself fails, so no record and no socket come back for ssh to
/// run over.
///
/// The selected VM has to be a third VM that does *not* know the name — that
/// is what sends attach through the fall-through. A name the selected VM
/// knows is its fast path, never ambiguous, and an explicit `--vm` is the
/// operator's own answer. The share this pins is the exposed verb's too: the
/// resolution the two verbs share carries the refusal for both.
#[tokio::test]
async fn attach_refuses_a_box_name_two_vms_know() {
    // Three VMs: the selected one, plus alpha and beta, which both own the
    // ambiguous name.
    let state = tempfile::tempdir().expect("a temp minimal state dir for three VMs");
    let provider = state.path().join("providers/local-minvmd0");
    for vm in ["alpha", "beta"] {
        std::fs::create_dir_all(provider.join(vm)).expect("the named VM's provider subdir");
    }
    let selected_sock =
        client::resolve_socket_path_named(Some(state.path()), true, paths::DEFAULT_VM_NAME)
            .expect("the selected VM's socket path");
    let selected_vm = minimald::test_harness::TestServer::new().await;
    selected_vm.listen_on_uds(&selected_sock).await;
    let alpha = minimald::test_harness::TestServer::new().await;
    alpha.listen_on_uds(&provider.join("alpha/ssh.sock")).await;
    let beta = minimald::test_harness::TestServer::new().await;
    beta.listen_on_uds(&provider.join("beta/ssh.sock")).await;

    // The selected VM knows a box of its own — so the connection, and the
    // version gate the lookup carries, are real — but not this name.
    create_box_on(&selected_vm, "api").await;
    create_box_on(&alpha, "shared").await;
    create_box_on(&beta, "shared").await;

    let global = vm_globals(state.path(), None);
    let mut client = client::Client::connect(&selected_sock)
        .await
        .expect("connect to the selected VM's daemon");
    let err =
        cmd::resolve_attach_target_version_gated(&global, &mut client, selected_sock, "shared")
            .await
            .expect_err("a name two VMs own must be refused, not guessed")
            .to_string();
    assert!(
        err.contains("alpha") && err.contains("beta"),
        "the refusal must name every VM that knows the name: {err}"
    );
    assert!(
        err.contains("shared"),
        "the refusal must name the box it refused: {err}"
    );
    assert!(
        err.contains("--vm"),
        "the refusal must point at the flag that disambiguates: {err}"
    );
    assert!(
        !err.contains(paths::DEFAULT_VM_NAME),
        "a VM that does not know the name is not an owner to choose \
         between: {err}"
    );
}

/// NET-059's report, and NET-025's: a proxy that is *not* where the recipes
/// assume — a VM whose proposed host port the host already held, publishing on
/// a host port of its own; a native daemon whose default was busy, asking the
/// OS for a free one — must tell the operator the port it is reachable on, on
/// the two surfaces the operator points a PAC file or an `HTTP(S)_PROXY`
/// export at. A log line alone is not the report.
///
/// Both surfaces render the daemon's *reported* port, the one its
/// `ListSessions`/`CreateSession` replies carry — which is what makes the walk
/// visible client-side at all. The daemon-side half — a publication refused on
/// the proposed port walking to the next rung, and that rung landing in the
/// reported field the replies read — is pinned by
/// `two_vms_hostnames_route_concurrently` in minimald, whose second VM's rung
/// is the port this test puts in alpha's reply. Here the fact under test is the
/// rendering: each VM's routing line names the VM and the real port, the two
/// surfaces agree on the address, and the port the recipes assume appears
/// nowhere on the walked VM.
#[tokio::test]
async fn walked_proxy_port_reported_at_start_and_in_ls() {
    use minimald_rpc::ListSessions;

    // A real listing reply for the shape, so the lines render beside the facts
    // they render beside in production; the proxy port is the only thing that
    // differs per VM here.
    let server = minimald::test_harness::TestServer::new().await;
    let mut reply_client = server.connect().await;
    let reply = reply_client.call::<ListSessions>(&()).await;
    let listing_for = |vm: &str, port: u16| {
        let mut resp = reply.clone();
        resp.hostname_proxy_port = Some(port);
        VmListing {
            vm: vm.to_owned(),
            resp,
            // A synthetic listing: no VM host daemon sits behind it, so
            // there is no control socket to read a state from — the shape
            // this render is fed, same as a listing that read none.
            control_sock: None,
        }
    };

    // The walked shape: the first VM holds the port the recipes name; the
    // second's publication took the next rung — one stride up, the daemon's
    // own walk when a host port is refused.
    const RECIPES_PORT: u16 = 7654;
    const NEXT_RUNG: u16 = RECIPES_PORT + 1_000;
    let listings = vec![
        listing_for("default", RECIPES_PORT),
        listing_for("alpha", NEXT_RUNG),
    ];

    // `min ls`: alpha's routing line names alpha and the port the host
    // reaches it on — the real port, not the one the recipes assume. The
    // surface verdict is not this test's fact, so none is fed.
    let mut out = Vec::new();
    format_ls_across_vms(
        &mut out,
        &LsArgs {
            raw: false,
            json: false,
        },
        &listings,
        &[],
        &[],
    )
    .expect("rendering the two-VM listing");
    let ls = String::from_utf8(out).expect("the listing is UTF-8");
    let routing = |vm: &str| {
        ls.lines()
            .find(|l| l.starts_with("HOSTNAME PROXY:") && l.contains(vm))
            .unwrap_or_else(|| panic!("a HOSTNAME PROXY line for {vm} in:\n{ls}"))
            .to_string()
    };
    assert!(
        routing("alpha").contains(&format!("127.0.0.1:{NEXT_RUNG}")),
        "a walked port must be the port on the routing line, not a log \
         line: {}",
        routing("alpha")
    );
    assert!(
        !routing("alpha").contains(&RECIPES_PORT.to_string()),
        "the walked VM's line must not name the port the recipes assume: {}",
        routing("alpha")
    );
    assert!(
        routing("default").contains(&format!("127.0.0.1:{RECIPES_PORT}")),
        "the VM that kept the port the recipes name still prints it: {}",
        routing("default")
    );

    // Session start: one line naming the VM the session landed on and the
    // same port, so the two surfaces agree on the address to point at.
    let start = hostname_proxy_start_line(Some("alpha"), NEXT_RUNG);
    let address = format!("127.0.0.1:{NEXT_RUNG}");
    assert!(
        routing("alpha").contains(&address) && start.contains(&address),
        "the routing line and the session-start line must agree on the \
         address: ls={} start={start}",
        routing("alpha")
    );
    assert!(
        start.contains("VM alpha"),
        "on a two-VM host the start line must say whose port it is: {start}"
    );

    // And the wiring: the start line names a VM exactly when the backend hosts
    // them — the selected VM on the VM backend, nothing on the native one,
    // whose single daemon has no VM to name. This test process never publishes
    // a `--vm` name, so the selected VM is the default one.
    let state = tempfile::tempdir().expect("a temp minimal state dir");
    assert_eq!(
        hostname_proxy_start_vm(&vm_globals(state.path(), None)),
        Some(paths::DEFAULT_VM_NAME),
        "the VM backend names the selected VM"
    );
    let native = GlobalArgs {
        repo_dir: None,
        minimal_dir: Some(state.path().to_path_buf()),
        config_dir: None,
        provider: Some(Provider::LocalMinimald),
        no_input: true,
        vm: None,
    };
    // Which backend `--provider local-minimald` selects is the platform's
    // call: on Linux it is the native one, while macOS has no native backend
    // at all, so `client_provider_kind` folds the flag's reading onto minvmd
    // there — the same rule every VM-backed gate keys on, flag or no flag.
    // The expectation is therefore the kind's, not a constant.
    let native_names_a_vm = cfg!(target_os = "macos");
    assert_eq!(
        hostname_proxy_start_vm(&native),
        native_names_a_vm.then_some(paths::DEFAULT_VM_NAME),
        "the backend the flag selects names a VM exactly where that backend \
         is the VM one"
    );

    // The native line is the single-VM routing line word for word — the same
    // address in the same words, so the two surfaces read as one. A fact
    // about the native backend, so it is asserted only where that backend
    // exists: a host whose every backend is minvmd renders its routing lines
    // through the VM listing, which names the VM the start line names above.
    if !native_names_a_vm {
        let native_start = hostname_proxy_start_line(hostname_proxy_start_vm(&native), NEXT_RUNG);
        let mut single = Vec::new();
        let mut native_resp = reply.clone();
        native_resp.hostname_proxy_port = Some(NEXT_RUNG);
        format_ls(
            &mut single,
            &LsArgs {
                raw: false,
                json: false,
            },
            &native_resp,
            None,
            None,
        )
        .expect("rendering the single-VM listing");
        let single = String::from_utf8(single).expect("the listing is UTF-8");
        assert_eq!(
            single
                .lines()
                .find(|l| l.starts_with("HOSTNAME PROXY:"))
                .expect("the single-VM listing prints a routing line"),
            native_start.as_str(),
            "the native start line and `min ls`'s routing line must be the same \
             line"
        );
    }
}

/// Two listed sessions for the id-prefix tests: an unnamed `01a0fe9d…` and
/// `a1b2c3d4…` named `web`.
fn prefix_entries() -> Vec<minimald_rpc::ListSessionsEntry> {
    use sessions::SessionStatus::Active;
    vec![
        twin_entry("01a0fe9d-0a99-78b1-9165-0809440f0052", None, None, Active),
        twin_entry(
            "a1b2c3d4-0a99-78b1-9165-0809440f0052",
            Some("web"),
            None,
            Active,
        ),
    ]
}

/// The short id `min ls` prints resolves as a unique id prefix, with or
/// without dashes and in either case; a prefix nothing matches resolves to
/// nothing, leaving the caller's "no session found".
#[test]
fn a_unique_id_prefix_resolves_to_its_session() {
    let entries = prefix_entries();
    for prefix in ["01a0fe9d", "01A0", "01a0fe9d-0a", "01a0fe9d0a99"] {
        assert_eq!(
            match_id_prefix(&entries, prefix).unwrap(),
            Some(entries[0].id),
            "`{prefix}` resolves"
        );
    }
    assert_eq!(match_id_prefix(&entries, "ffff").unwrap(), None);
}

/// A prefix several sessions share is refused, naming each candidate by its
/// short id and its session name; one more character that tells them apart
/// resolves.
#[test]
fn an_ambiguous_id_prefix_names_the_candidates() {
    use sessions::SessionStatus::Active;
    let entries = vec![
        twin_entry(
            "a1b2c3d4-0a99-78b1-9165-0809440f0052",
            Some("web"),
            None,
            Active,
        ),
        twin_entry(
            "a1b29e8f-0a99-78b1-9165-0809440f0052",
            Some("db"),
            None,
            Active,
        ),
    ];
    let err = match_id_prefix(&entries, "a1b2").unwrap_err();
    assert!(err.downcast_ref::<AmbiguousIdPrefix>().is_some());
    assert_eq!(
        err.to_string(),
        "'a1b2' matches sessions a1b2c3d4… (web), a1b29e8f… (db); use more characters"
    );
    assert_eq!(
        match_id_prefix(&entries, "a1b29").unwrap(),
        Some(entries[1].id)
    );
}

/// Candidates that share more than eight hex digits are cut only as far as
/// needed to be told apart: each rendered id is distinct and exactly as long
/// as the first differing digit.
#[test]
fn an_ambiguous_id_prefix_cuts_at_the_first_differing_digit() {
    use sessions::SessionStatus::Active;
    let entries = vec![
        twin_entry("a1b2c3d4-e50f-78b1-9165-0809440f0052", None, None, Active),
        twin_entry("a1b2c3d4-e51f-78b1-9165-0809440f0052", None, None, Active),
    ];
    // The two ids share their first ten hex digits; the eleventh diverges.
    let err = match_id_prefix(&entries, "a1b2c3d4e5").unwrap_err();
    assert!(err.downcast_ref::<AmbiguousIdPrefix>().is_some());
    assert_eq!(
        err.to_string(),
        "'a1b2c3d4e5' matches sessions a1b2c3d4e50…, a1b2c3d4e51…; use more characters"
    );
    // Each rendered candidate resolves back to exactly its own session.
    assert_eq!(
        match_id_prefix(&entries, "a1b2c3d4e50").unwrap(),
        Some(entries[0].id)
    );
    assert_eq!(
        match_id_prefix(&entries, "a1b2c3d4e51").unwrap(),
        Some(entries[1].id)
    );
}

/// Only 4 to 32 hex digits (dashes allowed) are tried as a prefix: anything
/// else stays a plain name, so a miss is the usual "no session found".
#[test]
fn a_non_hex_or_short_input_is_not_an_id_prefix() {
    let (max, over) = ("0".repeat(32), "0".repeat(33));
    for not_prefix in ["01a", "01a0fe9z", "web-01a0", "", "----", over.as_str()] {
        assert!(!is_id_prefix(not_prefix), "`{not_prefix}` is not a prefix");
    }
    for prefix in ["01a0", "01A0FE9D", "01a0fe9d-0a99", max.as_str()] {
        assert!(is_id_prefix(prefix), "`{prefix}` is a prefix");
    }
    // `01a0fe9z` would match the first session's id were it read as hex.
    assert_eq!(
        match_id_prefix(&prefix_entries(), "01a0fe9z").unwrap(),
        None
    );
}

/// A session named with a string that is also another session's id prefix
/// resolves by its name: an exact name wins over a prefix.
#[test]
fn an_exact_name_wins_over_an_id_prefix() {
    use sessions::SessionStatus::Active;
    let mut entries = prefix_entries();
    entries.push(twin_entry(
        "ffffffff-0a99-78b1-9165-0809440f0052",
        Some("01a0fe9d"),
        None,
        Active,
    ));
    assert_eq!(
        match_id_prefix(&entries, "01a0fe9d").unwrap(),
        Some(entries[2].id)
    );
}

/// A name resolves in any casing, matching how names are made unique: a
/// session named `Beef-Cafe` is found by `beef-cafe` (and vice versa). The
/// names are hex-shaped, because only those reach this match on a name miss,
/// and a folded name wins over a session whose id starts with the same hex.
#[test]
fn a_name_resolves_case_insensitively() {
    use sessions::SessionStatus::Active;
    let entries = vec![
        twin_entry(
            "ffffffff-0a99-78b1-9165-0809440f0052",
            Some("Beef-Cafe"),
            None,
            Active,
        ),
        twin_entry("beefcafe-0a99-78b1-9165-0809440f0054", None, None, Active),
    ];
    assert_eq!(
        match_id_prefix(&entries, "beef-cafe").unwrap(),
        Some(entries[0].id)
    );
    assert_eq!(
        match_id_prefix(&entries, "BEEF-CAFE").unwrap(),
        Some(entries[0].id)
    );
}

/// An exact name wins over a case-folded one, and a casing that folds to two
/// sessions (case-only duplicates written before names were made unique
/// under case folding) resolves to neither rather than picking one, nor
/// falls through to a session whose id starts with that prefix.
#[test]
fn an_exact_name_wins_and_an_ambiguous_fold_resolves_to_none() {
    use sessions::SessionStatus::Active;
    let entries = vec![
        twin_entry(
            "ffffffff-0a99-78b1-9165-0809440f0052",
            Some("Beef-Cafe"),
            None,
            Active,
        ),
        twin_entry(
            "eeeeeeee-0a99-78b1-9165-0809440f0053",
            Some("beef-cafe"),
            None,
            Active,
        ),
        twin_entry("beefcafe-0a99-78b1-9165-0809440f0054", None, None, Active),
    ];
    assert_eq!(
        match_id_prefix(&entries, "beef-cafe").unwrap(),
        Some(entries[1].id)
    );
    assert_eq!(
        match_id_prefix(&entries, "Beef-Cafe").unwrap(),
        Some(entries[0].id)
    );
    assert_eq!(match_id_prefix(&entries, "BEEF-CAFE").unwrap(), None);
    // The id prefix alone, with no name folding to it, still resolves.
    assert_eq!(
        match_id_prefix(&entries, "beefcafe").unwrap(),
        Some(entries[2].id)
    );
}
