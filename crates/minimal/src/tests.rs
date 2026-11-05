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
            // A box address reaches every local host, split as `min box
            // list` splits it: the selected host is the one this process
            // ensured, so it keeps the gate. The others are probed ungated,
            // so a skewed host still answers which boxes it holds.
            "cmd/boxes/address.rs::connect_box_host = gated",
            "cmd/boxes/address.rs::probe_other_host = ungated",
            "cmd/boxes/address.rs::read_host_boxes = ungated",
            // A read-only look at a box after `min box attach` ended, to say
            // why the host ended it. The attach itself went through the
            // address resolution above, and the read builds nothing.
            "cmd/boxes/attach.rs::box_after_attach = ungated",
            // Test-only: the BEP-032 store mint test registers a box with a
            // proxy control socket it serves itself, so no daemon is involved.
            "cmd/boxes/create.rs::box_creation_seals_a_store_member_per_accepted_rule = ungated",
            // Not a daemon connection: `min` registers a GitHub grant box
            // with the Box Egress Proxy over its control socket. The proxy is
            // not the daemon, and the daemon's build is not in question here.
            "cmd/boxes/create.rs::mint_grants = ungated",
            // Not a product path: the destroy-race test's own connection to
            // the harness daemon. The destroy it drives sends no gated RPC —
            // the race's loser just reports what the daemon said — so the
            // harness connection carries no gate to record.
            "cmd/boxes/lifecycle.rs::a_destroy_of_an_already_destroyed_session_reports_it = ungated",
            // `min box prune` probes each host it did not select and checks
            // its build before the prune, so a daemon outside the supported
            // window removes nothing.
            // Not a product path: the stop and remove tests' own connection
            // to the harness daemon, the same as the destroy-race test.
            "cmd/boxes/lifecycle.rs::daemon_with_boxes = ungated",
            "cmd/boxes/lifecycle.rs::prune_hosts = gated",
            // A read-only lookup around an attach the gated `cmd_attach`
            // already made: it reads the box's pair before, and asks whether
            // the session is gone after, to withdraw its row or release a
            // `host_ip` name hold, and which live session holds a name a
            // re-hold took over; it builds nothing a skew could half-make.
            // `min box list` reaches every local host, split as `min ls`
            // splits it: the selected host is the one this process ensured,
            // so it keeps the gate. The others are probed ungated, so a
            // skewed host still lists the boxes an operator needs to see.
            "cmd/boxes/list.rs::list_other_host = ungated",
            "cmd/boxes/list.rs::list_selected_host = gated",
            "cmd/boxes/vm_host.rs::box_record_by = ungated",
            // `min host list|show` probes each local host for its state and
            // daemon version. It only reads, and it must show a skewed
            // daemon's version, so it must work when the pair is skewed.
            // `min host stop` stops the daemon, as `min stop` does: the
            // remedy the version check names, so it is never gated by it.
            "cmd/hosts.rs::cmd_host_stop = ungated",
            "cmd/hosts.rs::probe_host = ungated",
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
            // `min session policy` and `min session destroy` on a box another
            // VM owns: the connection to that VM, gated as `connect_daemon`
            // gates the selected one.
            "cmd/mod.rs::resolve_box_on_any_vm = gated",
            "cmd/net.rs::cmd_net_forward = gated",
            // `min net forward` on a box another VM holds: the session poll's
            // connection to that VM, gated before the loop (NET-058).
            "cmd/net.rs::poll_client_for = gated",
            // `min secret set` asks the egress proxy on its control socket to
            // re-certify its root (#2746). The proxy is not the daemon, and
            // the rule is already saved before the ask, so a skew can
            // half-build nothing here, the same as the mint path's sites.
            "cmd/secret.rs::recertify = ungated",
            "cmd/session.rs::cmd_attach = gated",
            "cmd/session.rs::cmd_exec = gated",
            "cmd/session.rs::cmd_session_run = gated",
            "cmd/session.rs::cmd_session_setup_zed = gated",
            // The dashboard's activation is the same multi-step mutation as
            // `cmd_session`'s, so it carries the same gate on its own create.
            // Its two discovery connections are gated too: the dashboard opens
            // on the same terms `min ls` does (see `dash::rpc`).
            "dash/rpc.rs::activate = gated",
            "dash/rpc.rs::connect_missing = gated",
            "dash/rpc.rs::discover = gated",
            "diag/net.rs::probe_socket = ungated",
            // Test-only: the BEP-063 mint tests register keys with a proxy
            // control socket they serve themselves, so no daemon is involved.
            "mint.rs::a_refused_client_key_is_replaced_and_registered_before_the_mint = ungated",
            "mint.rs::a_replaced_client_key_is_revoked_at_the_proxy_after_a_failed_revoke = ungated",
            "mint.rs::a_replaced_client_key_is_revoked_at_the_proxy_once_for_two_creations = ungated",
            "mint.rs::a_replaced_client_key_keeps_verifying_until_its_boxes_end = ungated",
            "mint.rs::a_replaced_client_key_keeps_verifying_until_its_boxes_end = ungated",
            "mint.rs::a_replaced_client_key_keeps_verifying_until_its_boxes_end = ungated",
            "mint.rs::a_replacement_past_a_bound_of_keys_in_use_fails_the_creation = ungated",
            "mint.rs::a_replacement_the_store_does_not_keep_revokes_no_key = ungated",
            "mint.rs::create = ungated",
            // The proxy's control socket, not the daemon: a replaced client
            // key is revoked there, and no daemon version applies to it.
            "mint.rs::local_client_key_at = ungated",
            "mint.rs::revoke_others = ungated",
            "mint.rs::store_handle_signed_and_key_registered = ungated",
            "mint.rs::store_handle_signed_and_key_registered = ungated",
            "task.rs::arm_task_run_interrupt = ungated",
            // Not a product path: the fall-through tests' own connections to
            // the selected daemon — but connections all the same, and the
            // paths they drive are the gated ones above, so the label records
            // what the tests assert rather than a decision they make.
            // Not a product path, and not the daemon: the mint tests' own
            // connections to a test Box Egress Proxy's control socket.
            "tests.rs::a_failed_box_reply_forgets_the_box_again = ungated",
            "tests.rs::a_refused_client_key_forgets_the_box_again = ungated",
            // Test-only: the box address tests read a box's state straight
            // from an in-process daemon of the same build.
            "tests.rs::address_state = ungated",
            "tests.rs::an_identity_with_no_root_validity_mints_nothing = ungated",
            "tests.rs::attach_fall_through_hands_off_the_owning_vm = gated",
            "tests.rs::attach_refuses_a_box_name_two_vms_know = gated",
            "tests.rs::exec_fall_through_hands_off_the_owning_vm = gated",
            "tests.rs::grant_box_registers_its_declared_egress_with_the_proxy = ungated",
            "tests.rs::grant_box_registers_its_declared_egress_with_the_proxy = ungated",
            "tests.rs::grant_box_registers_its_declared_egress_with_the_proxy_until_the_creation_fails = ungated",
            // Not a product path: the host show test's own connection to
            // the harness daemon, to read the version it expects.
            "tests.rs::host_show_socket_and_version = ungated",
            // Not a product path: the host stop test's own connection to the
            // harness daemon, to list the boxes it expects stopped.
            "tests.rs::host_stop_force_forces_boxes_and_daemon = ungated",
            // Not a product path: the end-to-end test's own connection to
            // the harness daemon, to read the version it expects.
            "tests.rs::hosts_and_providers_end_to_end = ungated",
            "tests.rs::local_member_is_a_sign_in_reference_expiring_with_the_root = ungated",
            // Not a product path, and not the daemon: the audit test submits
            // a revocation to a test Box Egress Proxy's control socket.
            "tests.rs::mint_and_destroy_append_audit_records = ungated",
            // Test-only: the NET-058 and NET-152 tests' client on the selected
            // harness daemon, which is this build.
            "tests.rs::selected_client = ungated",
        ]
    );
}

/// Every `CreateSession` this crate sends states, in the request itself,
/// whether it asserts the daemon's build.
///
/// The constructor leaves the assertion off, so each site sets
/// `must_match_version` itself; this makes a site that does not set it a
/// visible one. Every session-creating path
/// asserts — they are the ones #1251 is about — and the inventory is what
/// stops another from quietly passing `None`.
#[test]
fn every_create_session_asserts_the_daemon_build() {
    assert_eq!(
        create_site_inventory(env!("CARGO_MANIFEST_DIR")),
        [
            "cmd/boxes/create.rs::activate_box = asserts",
            // A unit test's request, never sent: it checks the box spec.
            "cmd/boxes/create.rs::activation_puts_the_spec_on_the_create_request = asserts nothing",
            // A unit test's request, never sent: it checks the project root.
            "cmd/boxes/create.rs::create_from_a_subdirectory_sends_the_project_root = asserts nothing",
            // A unit test's request, never sent: it checks the row withdrawal.
            "cmd/boxes/create.rs::unnamed_activation_withdraws_its_row_when_the_grant_mint_fails = asserts nothing",
            // A unit test's request, never sent: it checks the list's scope.
            "cmd/boxes/list.rs::box_list_and_show_render_retained_records = asserts nothing",
            // A unit test's config, never sent: it checks that the create
            // relays no box id (BOX-002).
            "cmd/boxes/vm_host.rs::activation_relays_no_box_id = asserts nothing",
            // The dashboard's activation: the same create, the same assertion.
            "dash/rpc.rs::activate = asserts",
            // A unit test's request, never sent: it checks the project root.
            "dash/rpc.rs::dashboard_create_from_a_subdirectory_sends_the_project_root = asserts nothing",
            // Not a create the dashboard sends: the unit tests' own-address
            // config, which only a fake create closure receives.
            "dash/rpc.rs::own_ip_config = asserts nothing",
            "task.rs::cmd_task_run = asserts",
            // Not a client path: the two-VM fixture's own create. It asserts
            // like the real ones, so the inventory stays "every site asserts".
            "tests.rs::create_box_on = asserts",
            // Not a client path: the mint unit tests' create-request fixture.
            "tests.rs::create_request = asserts",
            // A unit test's request, never sent: it checks the box's name.
            "tests.rs::created_box_name_is_the_entry_without_a_typed_name = asserts nothing",
            // A unit test's request, never sent: it checks the cleaned entry name.
            "tests.rs::entry_name_registers_and_creates_under_one_cleaned_name = asserts nothing",
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
        ("src/cmd/boxes/create.rs", "activate_box"),
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
    const NEEDLE: &str = concat!("CreateSession", "Request::new(");
    source_inventory(
        manifest_dir,
        &[NEEDLE],
        &[
            ".must_match_version = version_assertion()",
            ".must_match_version = minimal_client::version_assertion()",
        ],
        ("asserts", "asserts nothing"),
    )
}

/// Every line under `<crate>/src` and `<crate>/tests` that spells a create
/// request, or its box config, as a struct literal. A function's return
/// type (`-> BoxConfig {`) is not a literal and does not count.
fn create_literal_sites(manifest_dir: &str) -> Vec<String> {
    // Built by concatenation so this scanner does not match itself.
    const NEEDLES: [&str; 2] = [
        concat!("CreateSession", "Request {"),
        concat!("Box", "Config {"),
    ];
    let root = std::path::Path::new(manifest_dir);
    let mut files = crate_sources(manifest_dir).1;
    let mut stack = vec![root.join("tests")];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries {
            let path = entry.expect("readable dir entry").path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "rs") {
                files.push(path);
            }
        }
    }
    files.sort();
    let mut sites = Vec::new();
    for path in files {
        let text = std::fs::read_to_string(&path).expect("source file must be readable");
        let rel = path
            .strip_prefix(root)
            .expect("scanned under the crate")
            .to_string_lossy()
            .into_owned();
        for (i, line) in text.lines().enumerate() {
            for needle in NEEDLES {
                let literal = line
                    .match_indices(needle)
                    .any(|(at, _)| !line[..at].trim_end().ends_with("->"));
                if literal {
                    sites.push(format!("{rel}:{}: {}", i + 1, line.trim()));
                }
            }
        }
    }
    sites
}

/// Every create request this crate builds, product path or test, goes
/// through `CreateSessionRequest::new`. A literal spells out every field the
/// constructor already fills, so a new field means editing each copy; the
/// constructor keeps that to one place.
#[test]
fn cli_create_requests_use_the_constructor() {
    assert_eq!(
        create_literal_sites(env!("CARGO_MANIFEST_DIR")),
        Vec::<String>::new(),
        "build these with CreateSessionRequest::new and set the fields that differ"
    );
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

/// The host-cache warm-up is gated on the session host: a VM-backed
/// host caches on its own guest volume and never reads the host cache,
/// so `--provider local-minvmd` (and macOS, always minvmd-backed) skip the
/// warm-up, while the native daemon shares the host cache and downloads.
#[test]
fn host_cache_warmup_skips_vm_backed_hosts() {
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

    // The refusal `min` prints names the verb that replaced the retired one.
    let rendered = with_retired_command_hint(err).to_string();
    assert!(
        rendered.contains("unrecognized subcommand 'ssh-forward'")
            && rendered.contains("min net forward <SESSION> <LOCAL>:<PORT>"),
        "the refusal must name the replacement, got: {rendered}"
    );
}

/// Entry constructor for the bare-`min` state-report tests.
fn twin_entry(
    id: &str,
    name: Option<&str>,
    path: Option<&str>,
    status: boxes::BoxState,
) -> minimald_rpc::ListSessionsEntry {
    minimald_rpc::ListSessionsEntry {
        id: boxes::SessionId::parse_str(id).unwrap(),
        name: name.map(str::to_owned),
        project_path: path.map(|p| paths::HostAbsPath::try_new(p).unwrap()),
        status,
        git: None,
        host_ip_enforcement: None,
        shared_port_collisions: Vec::new(),
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
        boxes::BoxState::Active,
    )];
    let cwd = paths::HostAbsPath::try_new("/w").unwrap();
    assert_eq!(
        render_bare_status("~/w", &entries, &cwd, true),
        "No terminal: not attaching. State for ~/w:\n\
             \x20 sessions: 1 (web, running)\n\
             \x20 blueprint: minimal.toml present\n\
             Next:\n\
             \x20 min session run web <task>\n\
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
        boxes::BoxState::Active,
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
    let entries = vec![twin_entry(id, None, Some("/w"), boxes::BoxState::Active)];

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

/// Attach refuses a `Materializing` session, so the warning's reuse step
/// must not point at it yet: the guidance says to wait for `min ls` to
/// report the session active and only then attach. The attach command shows
/// its argument as a placeholder, so no printed command names the session
/// attach would refuse right now.
#[test]
fn duplicate_session_warning_waits_before_attach_for_materializing() {
    let entries = vec![twin_entry(
        "019f5d0f-0a99-78b1-9165-0809440f0052",
        Some("web"),
        Some("/w"),
        boxes::BoxState::Materializing,
    )];

    let taken = paths::HostAbsPath::try_new("/w").unwrap();
    let warning = duplicate_session_warning(&entries, &taken)
        .expect("a session on the target path must warn");
    assert!(
        warning.contains("run `min ls` until its status is running"),
        "the wait guidance names the command to watch, got: {warning}"
    );
    assert!(
        warning.contains("then attach to it with `min session attach <session>`"),
        "attach is the step after the wait and shows its argument, got: {warning}"
    );
    assert!(
        !warning.contains("min session attach web"),
        "no command names a session attach would refuse, got: {warning}"
    );
    assert!(
        !warning.contains("To reuse it instead"),
        "no attach hint to take now for a non-attachable session, got: {warning}"
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
            boxes::BoxState::Materializing,
        ),
        twin_entry(active_id, Some("live"), Some("/w"), boxes::BoxState::Active),
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
            boxes::BoxState::Active,
        ),
        twin_entry(
            "019f5d0f-0a99-78b1-9165-0809440f0066",
            None,
            Some("/third"),
            boxes::BoxState::Pending,
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
        !out.contains("min session run"),
        "must not suggest running in a session elsewhere: {out}"
    );
}

/// More than two cwd matches: the count is the full total, the listing
/// stops at two and counts the rest, sessions elsewhere are counted too,
/// and an unnamed session shows its short id — which is also what the run
/// suggestion substitutes for the first match.
#[test]
fn bare_status_lists_at_most_two_cwd_sessions() {
    let entries = vec![
        twin_entry(
            "019f5d0f-0a99-78b1-9165-0809440f0052",
            None,
            Some("/w"),
            boxes::BoxState::Pending,
        ),
        twin_entry(
            "019f5d0f-0a99-78b1-9165-0809440f0066",
            Some("web"),
            Some("/w"),
            boxes::BoxState::Materializing,
        ),
        twin_entry(
            "019f5d0f-0a99-78b1-9165-0809440f0077",
            Some("spare"),
            Some("/w"),
            boxes::BoxState::Active,
        ),
        twin_entry(
            "019f5d0f-0a99-78b1-9165-0809440f0088",
            Some("api"),
            Some("/other"),
            boxes::BoxState::Active,
        ),
    ];
    let cwd = paths::HostAbsPath::try_new("/w").unwrap();
    let out = render_bare_status("/w", &entries, &cwd, true);
    assert!(
        out.contains(
            "  sessions: 3 (019f5d0f, pending), (web, materializing) and 1 more \
             (1 elsewhere)\n"
        ),
        "count-then-two listing, the rest counted: {out}"
    );
    assert!(
        !out.contains("spare"),
        "third session must not be listed: {out}"
    );
    assert!(
        out.contains("  min session run 019f5d0f <task>\n"),
        "run suggestion uses the first match's handle: {out}"
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
fn box_announce_label_prefers_name_with_short_id() {
    let id = boxes::SessionId::parse_str("a1b2c3d4-0000-0000-0000-000000000000").unwrap();
    assert_eq!(box_announce_label(&id, Some("api")), "api (a1b2c3d4)");
    assert_eq!(box_announce_label(&id, None), "a1b2c3d4");
}

/// BOX-163: a create refused because a running box holds its name ends
/// `min` with exit 2, and the error names the holder and the next step.
/// Any other refusal keeps the daemon's text and is not exit 2.
#[test]
fn held_name_refusal_exits_2_and_names_the_holder() {
    let holder = boxes::SessionId::parse_str("0192f3c4-5d6e-7f80-9a1b-2c3d4e5f6a7b").unwrap();
    let reply = minimald_rpc::HeldNameRefusal {
        name: "default".to_string(),
        holder: Some(holder),
        holder_name: "Default".to_string(),
    }
    .to_string();

    let error = create_refusal(reply);
    let refusal = error
        .downcast_ref::<minimald_rpc::HeldNameRefusal>()
        .expect("main.rs maps this error to its exit code");
    assert_eq!(minimald_rpc::HeldNameRefusal::EXIT_CODE, 2);
    assert_eq!(refusal.holder, Some(holder));
    assert_eq!(refusal.holder_name, "Default");
    let printed = format!("{error:#}");
    assert_eq!(
        printed,
        "Cannot create a session named `default`: the running session `Default` \
         (0192f3c4-5d6e-7f80-9a1b-2c3d4e5f6a7b) holds that name. Rename that session \
         with `min session rename 0192f3c4-5d6e-7f80-9a1b-2c3d4e5f6a7b <new-name>`, \
         or choose another name."
    );

    let other = create_refusal("the project path is not a directory".to_string());
    assert!(
        other
            .downcast_ref::<minimald_rpc::HeldNameRefusal>()
            .is_none()
    );
    assert_eq!(format!("{other:#}"), "the project path is not a directory");
}

/// BOX-163: an own-address create whose VM host registration is refused
/// because a live row holds the name ends `min` with exit 2. The error names
/// the holder's id, read from the daemon. When the holder cannot be read,
/// it is still exit 2 and names the held spelling.
#[test]
fn own_address_held_name_refusal_exits_2_and_names_the_holder() {
    let holder = boxes::SessionId::parse_str("0192f3c4-5d6e-7f80-9a1b-2c3d4e5f6a7b").unwrap();
    let error =
        registration_held_name_refusal("dev", "Dev", Some((holder, Some("Dev".to_string()))));
    let refusal = error
        .downcast_ref::<minimald_rpc::HeldNameRefusal>()
        .expect("main.rs maps this error to exit 2");
    assert_eq!(minimald_rpc::HeldNameRefusal::EXIT_CODE, 2);
    assert_eq!(refusal.holder, Some(holder));
    assert_eq!(
        format!("{error:#}"),
        "Cannot create a session named `dev`: the running session `Dev` \
         (0192f3c4-5d6e-7f80-9a1b-2c3d4e5f6a7b) holds that name. Rename that session \
         with `min session rename 0192f3c4-5d6e-7f80-9a1b-2c3d4e5f6a7b <new-name>`, \
         or choose another name."
    );

    let unread = registration_held_name_refusal("dev", "Dev", None);
    let refusal = unread
        .downcast_ref::<minimald_rpc::HeldNameRefusal>()
        .expect("an unread holder is still exit 2");
    assert_eq!(refusal.holder, None);
    assert_eq!(
        format!("{unread:#}"),
        "Cannot create a session named `dev`: the running session `Dev` holds that name. \
         Choose another name."
    );
    assert_eq!(
        minimald_rpc::HeldNameRefusal::from_error(&unread.to_string()).as_ref(),
        Some(refusal),
        "the text without an id parses back"
    );
}

/// BOX-163: with no `--name`, the create carries no name and the box takes
/// its entry's name. Nothing mints `<dir>-<hex>`. A `[box] name` in the
/// spec comes first, then `--name`.
#[test]
fn created_box_name_is_the_entry_without_a_typed_name() {
    let mut request = minimald_rpc::CreateSessionRequest::new(
        String::new(),
        paths::HostAbsPath::try_new("/home/u/code/foo").unwrap(),
        boxes::NetworkMode::HostNet,
        boxes::BoxPolicy::default(),
    );
    request.config.name = minimal_client::box_name::request_name(None);
    assert_eq!(created_box_name(&request), None, "no spec, no name");

    let mut spec = mfile::spec::BoxSpec::for_session(None, spec_flags(&request));
    put_spec(&mut request, &spec).unwrap();
    assert_eq!(
        created_box_name(&request).as_deref(),
        Some(mfile::spec::DEFAULT_SESSION_ENTRY)
    );

    request.config.name = minimal_client::box_name::request_name(Some("api"));
    assert_eq!(created_box_name(&request).as_deref(), Some("api"));

    spec.name = Some("web".to_string());
    put_spec(&mut request, &spec).unwrap();
    assert_eq!(created_box_name(&request).as_deref(), Some("web"));
}

/// BOX-163: the VM host row and the box carry one name. For an entry such
/// as `My App`, the client registers the row under the name the daemon
/// gives the box, because both sides clean the entry with one function.
#[test]
fn entry_name_registers_and_creates_under_one_cleaned_name() {
    let mut request = minimald_rpc::CreateSessionRequest::new(
        String::new(),
        paths::HostAbsPath::try_new("/home/u/code/foo").unwrap(),
        boxes::NetworkMode::HostNet,
        boxes::BoxPolicy::default(),
    );
    request.config.name = minimal_client::box_name::request_name(None);
    let mut spec = mfile::spec::BoxSpec::for_session(None, spec_flags(&request));
    spec.entry = "My App".to_string();
    put_spec(&mut request, &spec).unwrap();
    assert_eq!(created_box_name(&request).as_deref(), Some("myapp"));
    assert_eq!(
        created_box_name(&request).as_deref(),
        Some(boxes::box_name::entry_box_name(&spec.entry).as_str()),
        "the row's name is the daemon's name for the entry"
    );
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
fn finalize_install_parses_its_flags() {
    use clap::Parser as _;
    let cli = Cli::try_parse_from(["min", "finalize-install"]).unwrap();
    assert!(matches!(
        cli.command,
        Some(Command::FinalizeInstall(FinalizeInstallArgs {
            show: false,
            script: false,
            json: false,
            undo: false,
            ct_mark_mask: None
        }))
    ));
    let cli = Cli::try_parse_from(["min", "finalize-install", "--show", "--script"]).unwrap();
    assert!(matches!(
        cli.command,
        Some(Command::FinalizeInstall(FinalizeInstallArgs {
            show: true,
            script: true,
            json: false,
            undo: false,
            ct_mark_mask: None
        }))
    ));
    let cli = Cli::try_parse_from(["min", "finalize-install", "--show", "--json"]).unwrap();
    assert!(matches!(
        cli.command,
        Some(Command::FinalizeInstall(FinalizeInstallArgs {
            show: true,
            script: false,
            json: true,
            undo: false,
            ct_mark_mask: None
        }))
    ));
    let cli =
        Cli::try_parse_from(["min", "finalize-install", "--undo", "--show", "--script"]).unwrap();
    assert!(matches!(
        cli.command,
        Some(Command::FinalizeInstall(FinalizeInstallArgs {
            show: true,
            script: true,
            json: false,
            undo: true,
            ct_mark_mask: None
        }))
    ));
    // `--script` and `--json` need `--show`; `--json` describes an install,
    // not a removal; the two outputs exclude each other.
    for args in [
        &["min", "finalize-install", "--script"][..],
        &["min", "finalize-install", "--json"],
        &["min", "finalize-install", "--show", "--json", "--undo"],
        &["min", "finalize-install", "--undo", "--show", "--json"],
        &["min", "finalize-install", "--show", "--json", "--script"],
        &["min", "net", "setup"],
    ] {
        assert!(Cli::try_parse_from(args).is_err(), "{args:?}");
    }
}

/// `--ct-mark-mask` takes two contiguous bits in 0x-prefixed hex, the
/// shape the install step requires, and is refused with `--undo`.
#[test]
fn finalize_install_parses_ct_mark_mask() {
    use clap::Parser as _;
    let cli =
        Cli::try_parse_from(["min", "finalize-install", "--ct-mark-mask", "0x0c000000"]).unwrap();
    assert!(matches!(
        cli.command,
        Some(Command::FinalizeInstall(FinalizeInstallArgs {
            ct_mark_mask: Some(0x0c00_0000),
            undo: false,
            ..
        }))
    ));
    let cli = Cli::try_parse_from(["min", "finalize-install", "--show", "--ct-mark-mask", "0x3"])
        .unwrap();
    assert!(matches!(
        cli.command,
        Some(Command::FinalizeInstall(FinalizeInstallArgs {
            ct_mark_mask: Some(0x3),
            show: true,
            ..
        }))
    ));
    for bad in [
        "0x10000000",
        "0x50000000",
        "0x70000000",
        "0x0",
        "0x100000000",
        "30000000",
        "0x",
        "0xzz",
    ] {
        assert!(
            Cli::try_parse_from(["min", "finalize-install", "--ct-mark-mask", bad]).is_err(),
            "{bad}"
        );
    }
    assert!(
        Cli::try_parse_from([
            "min",
            "finalize-install",
            "--undo",
            "--ct-mark-mask",
            "0x0c000000"
        ])
        .is_err()
    );
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

/// The `spin` demo exists only in debug builds: clap's typo tips draw
/// candidates from hidden subcommands too, so hiding it is not enough
/// to keep it out of release output.
#[cfg(not(debug_assertions))]
#[test]
fn spin_absent_in_release() {
    use clap::CommandFactory as _;
    let cli = Cli::command();
    assert!(
        cli.find_subcommand("spin").is_none(),
        "spin must not exist in release builds"
    );
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
    assert_eq!(m.proto, boxes::IpProto::Tcp);
}

#[test]
fn ingress_spec_parses_explicit_proto() {
    let m = parse_ingress_mapping("5353:53/udp").unwrap();
    assert_eq!(m.external_port, 5353);
    assert_eq!(m.internal_port, 53);
    assert_eq!(m.proto, boxes::IpProto::Udp);
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

/// The pure upload decision over its whole domain: the empty/`$HOME`
/// carve-out, the explicit-sync escape hatch, and the VCS / blueprint /
/// headless gate, with no TTY and no daemon in sight.
#[test]
fn decide_workspace_upload_covers_empty_vcs_blueprint_and_headless() {
    // An empty directory skips silently — unless the caller passed an
    // explicit `--sync tarball`, which uploads it anyway.
    let empty = tempfile::tempdir().unwrap();
    let empty = camino::Utf8Path::from_path(empty.path()).expect("temp path is UTF-8");
    assert_eq!(
        decide_workspace_upload(empty, false, false, None),
        UploadDecision::SkipEmptyOrHome
    );
    assert_eq!(
        decide_workspace_upload(empty, true, false, None),
        UploadDecision::Upload
    );

    // A non-empty, undeclared, non-VCS root: a headless caller skips with
    // the shared warning, an interactive one is asked first.
    let plain = tempfile::tempdir().unwrap();
    std::fs::write(plain.path().join("notes.txt"), "x").unwrap();
    let plain = camino::Utf8Path::from_path(plain.path()).expect("temp path is UTF-8");
    assert_eq!(
        decide_workspace_upload(plain, false, true, None),
        UploadDecision::SkipUndeclared
    );
    assert_eq!(
        decide_workspace_upload(plain, false, false, None),
        UploadDecision::Confirm
    );

    // A VCS root or a declared project uploads unconditionally.
    let repo = tempfile::tempdir().unwrap();
    std::fs::write(repo.path().join("notes.txt"), "x").unwrap();
    std::fs::create_dir(repo.path().join(".git")).unwrap();
    let repo = camino::Utf8Path::from_path(repo.path()).expect("temp path is UTF-8");
    assert_eq!(
        decide_workspace_upload(repo, false, true, None),
        UploadDecision::Upload
    );

    let declared = tempfile::tempdir().unwrap();
    std::fs::write(declared.path().join("notes.txt"), "x").unwrap();
    std::fs::write(declared.path().join(mfile::MFILE_NAME), "[upstream]\n").unwrap();
    let declared = camino::Utf8Path::from_path(declared.path()).expect("temp path is UTF-8");
    assert_eq!(
        decide_workspace_upload(declared, false, true, None),
        UploadDecision::Upload
    );

    // A declared project that is `$HOME` keeps the carve-out — home is never
    // bulk-uploaded on a stray activation — so its hooks are the count the
    // gate below refuses over. This is the one state a skip can drop hooks
    // from: an undeclared root has no `minimal.toml` to lose (the case above).
    let home = tempfile::tempdir().unwrap();
    std::fs::write(
        home.path().join(mfile::MFILE_NAME),
        "[[session.lifecycle_hooks]]\n\
         on_activate = { type = \"inline\", value = \"echo hi\" }\n",
    )
    .unwrap();
    let home = camino::Utf8Path::from_path(home.path()).expect("temp path is UTF-8");
    assert_eq!(
        decide_workspace_upload(home, false, false, Some(home.as_std_path())),
        UploadDecision::SkipEmptyOrHome
    );
    assert_eq!(project_lifecycle_hook_count(home), 1);
    assert!(
        refuse_dropped_hooks(
            &WorkspaceUpload::SkippedEmptyOrHome {
                dropped_hooks: project_lifecycle_hook_count(home),
            },
            home,
            CLI_DROPPED_HOOKS_REMEDY,
        )
        .is_err(),
        "a skipped home that declares hooks must be refused, not created silently"
    );
}

/// The refusal a hook-dropping skip raises names the root, the count, and the
/// `--sync` escape hatch. It is shared by both CLI callers and by the
/// dashboard's own gate, so the wording cannot drift between them; the remedy
/// clause is the caller's, and each caller's names what it can do.
#[test]
fn dropped_hooks_error_names_root_count_and_escape_hatch() {
    let err = dropped_hooks_error(
        camino::Utf8Path::new("/srv/data/run42"),
        3,
        CLI_DROPPED_HOOKS_REMEDY,
    );
    let text = err.to_string();
    assert!(text.contains("/srv/data/run42"), "{text}");
    assert!(text.contains("is your home directory"), "{text}");
    assert!(text.contains("3 lifecycle hook(s)"), "{text}");
    assert!(text.contains("--sync tarball"), "{text}");
    assert!(text.contains("--sync none"), "{text}");

    // The dashboard owns neither flag, so its refusal names the command that
    // does rather than advice no key on the screen can follow.
    let dashboard = dropped_hooks_error(
        camino::Utf8Path::new("/home/dev"),
        2,
        DASH_DROPPED_HOOKS_REMEDY,
    )
    .to_string();
    assert!(
        dashboard.contains("min session activate --sync tarball"),
        "{dashboard}"
    );
    assert!(
        !dashboard.contains("`--sync none`"),
        "the dashboard cannot pass --sync none, so it must not be told to: {dashboard}"
    );
}

/// The resolved-root notice appears only when the upload walked above the
/// invocation directory, so `min activate` from inside a project says which
/// root it used while a root at the invocation directory stays quiet.
#[test]
fn resolved_upload_root_notice_only_when_they_differ() {
    let root = camino::Utf8Path::new("/proj");
    let subdir = camino::Utf8Path::new("/proj/sub");
    assert!(resolved_upload_root_notice(root, root).is_none());
    let notice = resolved_upload_root_notice(subdir, root).expect("a notice when they differ");
    assert!(
        notice.contains("/proj (resolved from /proj/sub)"),
        "{notice}"
    );
}

/// A skip that would drop lifecycle hooks is the caller's call: the refusing
/// caller gets an error, and one with no hooks dropped never does. The skip
/// that costs them is the `$HOME` that is itself a declared project — an
/// undeclared root has no `minimal.toml` to lose — and the user's own decline
/// is never refused, whatever it costs: it is an answer, not an accident.
#[test]
fn report_upload_outcome_refuses_dropped_hooks_only() {
    let root = camino::Utf8Path::new("/srv/data/run42");
    assert!(
        report_upload_outcome(
            Ok(WorkspaceUpload::SkippedEmptyOrHome { dropped_hooks: 2 }),
            root,
            DroppedHooksPolicy::Refuse,
            &mut Vec::new(),
        )
        .is_err(),
        "a skipped home that declares hooks is refused"
    );
    for kept in [
        WorkspaceUpload::SkippedEmptyOrHome { dropped_hooks: 0 },
        WorkspaceUpload::SkippedUndeclared,
        WorkspaceUpload::Declined,
    ] {
        assert!(
            report_upload_outcome(Ok(kept), root, DroppedHooksPolicy::Refuse, &mut Vec::new())
                .is_ok(),
            "{kept:?}"
        );
    }
}

/// The non-refusing caller (`min task run`) proceeds, but its warning names
/// the hooks the skipped upload loses: the empty-box line alone would read as
/// a healthy start.
#[test]
fn report_upload_outcome_warns_when_a_home_skip_drops_hooks() {
    let root = camino::Utf8Path::new("/srv/data/run42");
    let mut err = Vec::new();
    let result = report_upload_outcome(
        Ok(WorkspaceUpload::SkippedEmptyOrHome { dropped_hooks: 2 }),
        root,
        DroppedHooksPolicy::Warn,
        &mut err,
    );
    let err = String::from_utf8(err).expect("the sink holds UTF-8");
    assert!(result.is_ok(), "{result:?}");
    assert!(err.contains("Starting with an empty box"), "{err:?}");
    assert!(
        err.contains("2 lifecycle hook(s) declared in /srv/data/run42/minimal.toml"),
        "{err:?}"
    );
}

/// `--no-hooks` already disabled the project's hooks, so the activation
/// proceeds without a hook warning: only the empty-box line remains.
#[test]
fn report_upload_outcome_ignores_hooks_the_caller_disabled() {
    let root = camino::Utf8Path::new("/srv/data/run42");
    let mut err = Vec::new();
    let result = report_upload_outcome(
        Ok(WorkspaceUpload::SkippedEmptyOrHome { dropped_hooks: 2 }),
        root,
        DroppedHooksPolicy::Ignore,
        &mut err,
    );
    let err = String::from_utf8(err).expect("the sink holds UTF-8");
    assert!(result.is_ok(), "{result:?}");
    assert!(err.contains("Starting with an empty box"), "{err:?}");
    assert!(!err.contains("lifecycle hook"), "{err:?}");
}

/// The rule `min dash` applies in place of the stderr wording refuses exactly
/// the skip that would drop hooks: the skips that cost nothing, and the user's
/// own decline, still create their box.
#[test]
fn refuse_dropped_hooks_gates_only_the_hook_dropping_skip() {
    let root = camino::Utf8Path::new("/srv/data/run42");
    for allowed in [
        WorkspaceUpload::Uploaded,
        WorkspaceUpload::SkippedEmptyOrHome { dropped_hooks: 0 },
        WorkspaceUpload::SkippedUndeclared,
        WorkspaceUpload::Declined,
    ] {
        assert!(
            refuse_dropped_hooks(&allowed, root, CLI_DROPPED_HOOKS_REMEDY).is_ok(),
            "{allowed:?}"
        );
    }
    let err = refuse_dropped_hooks(
        &WorkspaceUpload::SkippedEmptyOrHome { dropped_hooks: 2 },
        root,
        CLI_DROPPED_HOOKS_REMEDY,
    )
    .expect_err("a home skip that drops lifecycle hooks is refused");
    assert!(err.to_string().contains("2 lifecycle hook(s)"), "{err}");
}

/// A create that plans its upload refuses the hook-dropping `$HOME` skip
/// from the decision alone, before the daemon holds a session or a row: only
/// the empty/`$HOME` skip can cost hooks, and only when the root declares
/// some.
#[test]
fn refuse_dropped_hooks_before_create_refuses_the_home_skip() {
    let home = tempfile::tempdir().unwrap();
    std::fs::write(
        home.path().join(mfile::MFILE_NAME),
        "[[session.lifecycle_hooks]]\n\
         on_activate = { type = \"inline\", value = \"echo hi\" }\n",
    )
    .unwrap();
    let home = camino::Utf8Path::from_path(home.path()).expect("temp path is UTF-8");
    for allowed in [
        UploadDecision::Upload,
        UploadDecision::SkipUndeclared,
        UploadDecision::Confirm,
        UploadDecision::Declined,
    ] {
        assert!(
            refuse_dropped_hooks_before_create(allowed, home, CLI_DROPPED_HOOKS_REMEDY).is_ok(),
            "{allowed:?}"
        );
    }
    let err = refuse_dropped_hooks_before_create(
        UploadDecision::SkipEmptyOrHome,
        home,
        CLI_DROPPED_HOOKS_REMEDY,
    )
    .expect_err("the home skip that drops hooks is refused before the create");
    assert!(err.to_string().contains("1 lifecycle hook(s)"), "{err}");
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
        ("src/cmd/boxes/create.rs", "activate_box", 2),
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

/// A daemon refusal is printed in the daemon's own words. The RPC's name
/// is the wire's vocabulary, not the person's, so no creator, verdict
/// submitter, finalizer or renamer may prefix the daemon's error with
/// it. Asserted over the function bodies, the way the composition
/// message is, because the prefix had crept into five sites across three
/// files before anyone noticed it on a terminal.
#[test]
fn daemon_refusals_print_without_rpc_names() {
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    for (file, func) in [
        ("src/cmd/boxes/create.rs", "activate_box"),
        ("src/cmd/session.rs", "cmd_rename"),
        ("src/task.rs", "cmd_task_run"),
        ("src/cmd/mod.rs", "submit_verdict_and_wait"),
        ("src/cmd/mod.rs", "upload_and_finalize"),
    ] {
        let text = std::fs::read_to_string(manifest.join(file)).expect("readable source");
        let body =
            function_body(&text, func).unwrap_or_else(|| panic!("{file} no longer defines {func}"));
        for bare in [
            "CreateSession failed",
            "RenameSession failed",
            "SubmitVerdict failed",
            "SubmitVerdict faulted",
            "FinalizeSession failed",
        ] {
            assert!(
                !body.contains(bare),
                "{func} still prefixes the daemon's refusal with an RPC name ({bare})"
            );
        }
    }

    // The daemon's side of the same surface: its refusals are printed
    // verbatim, at finalize through `upload_and_finalize` and at attach,
    // so none of them may name the RPC a person would have to retry. The
    // scan is over the string literals of the daemon's session module,
    // which covers the refusals and the log lines alike; the module has
    // no log-only RPC name left to exempt. The RPC names stay legitimate
    // in type paths and comments, which the scan does not read. A literal
    // is tracked across lines — the refusals are wrapped with `\` — so a
    // continuation line with no quote of its own is still read. The
    // module is `box_actor.rs` and its `box_actor/` files. `kind.rs` holds
    // span names, not refusals, and `tests.rs` is the module's tests.
    let actor_dir = manifest.join("../minimald/src/box_actor");
    let mut sources = vec![manifest.join("../minimald/src/box_actor.rs")];
    for entry in std::fs::read_dir(&actor_dir).expect("readable daemon module dir") {
        let path = entry.expect("readable dir entry").path();
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        if name.ends_with(".rs") && name != "kind.rs" && name != "tests.rs" {
            sources.push(path);
        }
    }
    assert!(
        sources.len() > 1,
        "the daemon's session module files moved; update this scan"
    );
    for source in sources {
        let shown = source
            .strip_prefix(manifest.join(".."))
            .unwrap_or(&source)
            .display()
            .to_string();
        let daemon = std::fs::read_to_string(&source).expect("readable daemon source");
        let mut in_literal = false;
        for (number, line) in daemon.lines().enumerate() {
            if !in_literal && line.trim_start().starts_with("//") {
                continue;
            }
            let in_string = in_literal || line.contains('"');
            // Toggle on every unescaped quote, so the state at the line's end
            // says whether the next line continues a literal.
            let mut chars = line.chars();
            while let Some(c) = chars.next() {
                match c {
                    '\\' => {
                        chars.next();
                    }
                    '"' => in_literal = !in_literal,
                    _ => {}
                }
            }
            if !in_string {
                continue;
            }
            for rpc in [
                "CreateSession",
                "ConfigureLoadout",
                "SubmitVerdict",
                "FinalizeSession",
                "RenameSession",
                "WorkspacePatchesTarZst",
            ] {
                assert!(
                    !line.contains(rpc),
                    "{shown}:{}: a string names the {rpc} RPC: {line}",
                    number + 1
                );
            }
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

/// The wedged-VM recovery: with a VM backend whose state says Running under a
/// live alive-lock but no bridge socket to answer, `min stop --force` must
/// stop the VM from the host — signal the VMM the state names, write
/// `Stopped` — and exit 0, rather than failing on the refused connect and
/// leaving the only recovery a hand-killed VMM.
#[tokio::test]
async fn stop_force_stops_a_wedged_vm_from_the_host() {
    let dir = tempfile::tempdir().unwrap();
    let host_dir = client::resolve_host_dir(Some(dir.path()), true).expect("resolve provider dir");
    let state_dir = minvmd::state::StateDir::new(host_dir).expect("open state dir");
    // The alive lock is held the way a real VM holds it: by the VMM process,
    // through the inherited fd, so it is released when that process dies and
    // not before.
    let lock = state_dir
        .try_acquire_alive_lock()
        .unwrap()
        .expect("acquire alive lock");
    let mut vmm_cmd = std::process::Command::new("sleep");
    vmm_cmd.arg("30");
    lock.inherit_into(&mut vmm_cmd);
    let mut vmm = vmm_cmd.spawn().expect("spawn sleep");
    drop(lock);
    state_dir
        .write_state(&minvmd::state::State {
            lifecycle: minvmd::lifecycle::Lifecycle::Running,
            vmm_pid: Some(vmm.id()),
            started_at: None,
            ..minvmd::state::State::stopped()
        })
        .unwrap();
    assert!(
        state_dir.daemon_alive().unwrap(),
        "the stand-in VMM must hold the alive lock"
    );

    let global = GlobalArgs {
        repo_dir: None,
        minimal_dir: Some(dir.path().to_path_buf()),
        config_dir: None,
        provider: Some(Provider::LocalMinvmd),
        no_input: true,
        vm: None,
    };
    cmd_stop(&global, StopArgs { force: true })
        .await
        .expect("a wedged VM stopped from the host is the goal state");

    assert_eq!(
        state_dir.read_state().unwrap().lifecycle,
        minvmd::lifecycle::Lifecycle::Stopped
    );
    assert!(
        !state_dir.daemon_alive().unwrap(),
        "the stop must not return while the alive lock is held: a `min start` would refuse"
    );
    // SIGTERM'd by the host-side stop; reaped here so the test leaves no stray.
    let status = vmm.wait().unwrap();
    assert!(
        status.code().is_none(),
        "expected a signalled VMM child, got {status:?}"
    );
}

/// A VM that is still booting has no VMM pid to signal, so `min stop --force`
/// must not report a host-side stop it did not make: it refuses with the
/// retry, and leaves the boot's `Starting` state for the supervisor to finish.
#[tokio::test]
async fn stop_force_refuses_a_booting_vm() {
    let dir = tempfile::tempdir().unwrap();
    let host_dir = client::resolve_host_dir(Some(dir.path()), true).expect("resolve provider dir");
    let state_dir = minvmd::state::StateDir::new(host_dir).expect("open state dir");
    state_dir
        .write_state(&minvmd::state::State {
            lifecycle: minvmd::lifecycle::Lifecycle::Starting,
            vmm_pid: None,
            started_at: None,
            ..minvmd::state::State::stopped()
        })
        .unwrap();
    let _lock = state_dir
        .try_acquire_alive_lock()
        .unwrap()
        .expect("acquire alive lock");

    let global = GlobalArgs {
        repo_dir: None,
        minimal_dir: Some(dir.path().to_path_buf()),
        config_dir: None,
        provider: Some(Provider::LocalMinvmd),
        no_input: true,
        vm: None,
    };
    let err = cmd_stop(&global, StopArgs { force: true })
        .await
        .expect_err("a booting VM was not stopped from the host");

    let chain = format!("{err:#}");
    assert!(
        chain.contains("still booting") && chain.contains("`min stop`"),
        "expected the retry hint, got: {chain}"
    );
    assert_eq!(
        state_dir.read_state().unwrap().lifecycle,
        minvmd::lifecycle::Lifecycle::Starting
    );
}

/// Without `--force`, a VM that is still booting is not told to use `--force`,
/// which refuses a booting VM: the hint names the retry, and the failure stays
/// the typed host-unreachable one.
#[tokio::test]
async fn stop_without_force_on_a_booting_vm_names_the_retry() {
    let dir = tempfile::tempdir().unwrap();
    let host_dir = client::resolve_host_dir(Some(dir.path()), true).expect("resolve provider dir");
    let state_dir = minvmd::state::StateDir::new(host_dir).expect("open state dir");
    state_dir
        .write_state(&minvmd::state::State {
            lifecycle: minvmd::lifecycle::Lifecycle::Starting,
            vmm_pid: None,
            started_at: None,
            ..minvmd::state::State::stopped()
        })
        .unwrap();
    let _lock = state_dir
        .try_acquire_alive_lock()
        .unwrap()
        .expect("acquire alive lock");

    let global = GlobalArgs {
        repo_dir: None,
        minimal_dir: Some(dir.path().to_path_buf()),
        config_dir: None,
        provider: Some(Provider::LocalMinvmd),
        no_input: true,
        vm: None,
    };
    let err = cmd_stop(&global, StopArgs { force: false })
        .await
        .expect_err("a booting VM that does not answer keeps failing");

    let chain = format!("{err:#}");
    assert!(
        chain.contains("still booting") && !chain.contains("--force"),
        "expected the retry hint and no --force, got: {chain}"
    );
    assert!(
        err.downcast_ref::<client::box_registration::HostUnreachable>()
            .is_some(),
        "the refusal must carry the type `main` maps to exit 7, got: {chain}"
    );
}

/// The wait a host-side stop ends on is the alive lock, not the lifecycle
/// file: it fails while a minvmd still holds the lock, even over a `Stopped`
/// state, and passes once the lock is released.
#[test]
fn host_stop_waits_for_the_alive_lock_not_the_lifecycle() {
    let dir = tempfile::tempdir().unwrap();
    let state_dir = minvmd::state::StateDir::new(dir.path().to_path_buf()).expect("open state dir");
    state_dir
        .write_state(&minvmd::state::State::stopped())
        .unwrap();
    let lock = state_dir
        .try_acquire_alive_lock()
        .unwrap()
        .expect("acquire alive lock");

    let err = wait_for_alive_lock_released(&state_dir, std::time::Duration::from_millis(300))
        .expect_err("a held alive lock is not a finished stop");
    assert!(
        format!("{err:#}").contains("the VM host daemon (minvmd) is still running"),
        "got: {err:#}"
    );

    drop(lock);
    wait_for_alive_lock_released(&state_dir, std::time::Duration::from_millis(300))
        .expect("a released alive lock is a finished stop");
}

/// Without `--force` the wedged VM keeps its non-zero exit — force-stopping a
/// VM that may still be draining is not the default behaviour — but the error
/// names the recovery instead of a bare connect failure, and is the typed
/// host-unreachable failure the binary exits 7 on.
#[tokio::test]
async fn stop_without_force_on_a_wedged_vm_names_the_recovery() {
    let dir = tempfile::tempdir().unwrap();
    let host_dir = client::resolve_host_dir(Some(dir.path()), true).expect("resolve provider dir");
    let state_dir = minvmd::state::StateDir::new(host_dir).expect("open state dir");
    state_dir
        .write_state(&minvmd::state::State {
            lifecycle: minvmd::lifecycle::Lifecycle::Running,
            vmm_pid: Some(std::process::id()),
            started_at: None,
            ..minvmd::state::State::stopped()
        })
        .unwrap();
    let _lock = state_dir
        .try_acquire_alive_lock()
        .unwrap()
        .expect("acquire alive lock");

    let global = GlobalArgs {
        repo_dir: None,
        minimal_dir: Some(dir.path().to_path_buf()),
        config_dir: None,
        provider: Some(Provider::LocalMinvmd),
        no_input: true,
        vm: None,
    };
    let err = cmd_stop(&global, StopArgs { force: false })
        .await
        .expect_err("a wedged VM without --force must keep failing");

    let chain = format!("{err:#}");
    assert!(
        chain.contains("the VM is not answering") && chain.contains("--force"),
        "expected the recovery hint, got: {chain}"
    );
    assert!(
        err.downcast_ref::<client::box_registration::HostUnreachable>()
            .is_some(),
        "the refusal must carry the type `main` maps to exit 7, got: {chain}"
    );
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

/// The `--network` parser accepts every [`boxes::NetworkMode::word`] and
/// maps it back to the same mode, so the word the daemon logs and the
/// refusals print is always one a person can type.
#[test]
fn network_parser_round_trips_every_mode_word() {
    for mode in [
        boxes::NetworkMode::NoNet,
        boxes::NetworkMode::HostNet,
        boxes::NetworkMode::OwnIp,
    ] {
        let parsed = parse_network_mode(mode.word()).expect("a mode word must parse");
        assert_eq!(boxes::NetworkMode::from(parsed), mode, "{}", mode.word());
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
    assert_eq!(a.dynamic_ingress, Some(boxes::DynamicIngress::Allow));
    assert_eq!(a.dynamic_range, Some((8000, 8443)));

    let a = activate(&["min", "session", "activate", "--dynamic-ingress", "ask"]);
    assert_eq!(a.dynamic_ingress, Some(boxes::DynamicIngress::Ask));
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
        rendered.contains(&boxes::PolicyError::PrivilegedDynamicRange { lo: 80 }.to_string()),
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
/// a minimal state dir laid out as the minvmd host nests a named VM
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
) -> boxes::SessionId {
    use minimald_rpc::{
        ConfigureLoadout, ConfigureLoadoutRequest, CreateSession, CreateSessionRequest, Errorable,
        FinalizeSession, FinalizeSessionRequest,
    };

    let mut client = server.connect().await;
    let project_path =
        camino::Utf8PathBuf::from_path_buf(std::env::current_dir().expect("the test cwd"))
            .expect("UTF-8");
    let mut request = CreateSessionRequest::new(
        name,
        paths::HostAbsPath::try_new(project_path).expect("the test cwd as a host path"),
        boxes::NetworkMode::NoNet,
        boxes::BoxPolicy::default(),
    );
    request.must_match_version = minimal_client::version_assertion();
    let id = match client.call::<CreateSession>(&request).await {
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

    let mut listings = cmd::ls_listings(&vm_globals(state.path(), None))
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
    // The named VM's box reports its own range address, as a published box
    // does (T110), so its BOX NAMES row can read the own-address form.
    listings[1].resp.box_networks.insert(
        web,
        minimald_rpc::BoxNetworkFacts {
            loopback_address: Some(std::net::Ipv4Addr::new(127, 0, 64, 2)),
            egress_posture: None,
            at_fallback: Some(false),
        },
    );
    let surfaces = vec![
        Some(crate::resolver::LiveSurface::Proxy),
        Some(crate::resolver::LiveSurface::Native),
    ];
    let answerers = vec![
        Some(minimald_rpc::AnswererStatusReply {
            answerer: minimald_rpc::ZoneAnswererStatus::Holder { port: 7_656 },
            proxy_down: None,
        }),
        Some(minimald_rpc::AnswererStatusReply {
            answerer: minimald_rpc::ZoneAnswererStatus::Registered { port: 7_656 },
            proxy_down: None,
        }),
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
    let row_of = |id: &boxes::SessionId| {
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
            .find(|l| l.starts_with("BOX NAMES:") && l.contains(vm))
            .unwrap_or_else(|| panic!("a BOX NAMES line for {vm} in:\n{table}"))
            .to_string()
    };
    assert!(
        surface_line_of("default")
            .contains("<box>.min.internal opens through the HTTP proxy at 127.0.0.1:")
            || surface_line_of("default")
                .contains("<box>.min.internal: the hostname proxy is not serving"),
        "the VM the hook does not route to keeps its proxy line:\n{table}"
    );
    assert!(
        surface_line_of("alpha").contains("<box>.min.internal opens at its name on this machine"),
        "the VM the hook routes to is named native:\n{table}"
    );
    let answerer_row_of = |vm: &str| {
        table
            .lines()
            .find(|l| l.starts_with("DNS SERVICE:") && l.contains(vm))
            .unwrap_or_else(|| panic!("a DNS SERVICE line for {vm} in:\n{table}"))
            .to_string()
    };
    assert!(
        answerer_row_of("default")
            .contains("this VM's host daemon answers its box names on 127.0.0.1:7656"),
        "the VM whose minvmd holds the port says so, in its own row:\n{table}"
    );
    assert!(
        answerer_row_of("alpha")
            .contains("another VM host daemon answers this VM's box names on 127.0.0.1:7656"),
        "the registered VM names the holder, in its own row:\n{table}"
    );
    assert!(
        !answerer_row_of("alpha").contains("this VM's host daemon answers"),
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
    let host_dir = state.path().join("providers/local-minvmd0");
    std::fs::create_dir_all(host_dir.join("alpha")).expect("the named VM's provider subdir");
    let default_sock =
        client::resolve_socket_path_named(Some(state.path()), true, paths::DEFAULT_VM_NAME)
            .expect("the default VM's socket path");
    // Both daemons are real. The selected VM's socket is not bound yet — its
    // box is created over the harness's in-memory pair, the way a booting
    // VM's daemon is up before its bridge socket exists.
    let default_vm = minimald::test_harness::TestServer::new().await;
    create_box_on(&default_vm, "api").await;
    let alpha = minimald::test_harness::TestServer::new().await;
    alpha.listen_on_uds(&host_dir.join("alpha/ssh.sock")).await;
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
    let host_dir = state.path().join("providers/local-minvmd0");
    std::fs::create_dir_all(host_dir.join("alpha")).expect("the wedged VM's dir");
    std::fs::create_dir_all(host_dir.join("beta")).expect("the stopped VM's dir");

    // The selected VM, running, with its box.
    let default_sock =
        client::resolve_socket_path_named(Some(state.path()), true, paths::DEFAULT_VM_NAME)
            .expect("the default VM's socket path");
    let default_vm = minimald::test_harness::TestServer::new().await;
    default_vm.listen_on_uds(&default_sock).await;
    create_box_on(&default_vm, "api").await;

    // A wedged VM: the socket accepts and never speaks SSH — the shape a
    // suspended microVM presents behind an always-accepting bridge.
    let wedged = tokio::net::UnixListener::bind(host_dir.join("alpha/ssh.sock"))
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
    let stale = std::os::unix::net::UnixListener::bind(host_dir.join("beta/ssh.sock"))
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
    let host_dir = state.path().join("providers/local-minvmd0");
    std::fs::create_dir_all(host_dir.join("beta")).expect("the stopped VM's dir");

    // The selected VM, running, with its box.
    let default_sock =
        client::resolve_socket_path_named(Some(state.path()), true, paths::DEFAULT_VM_NAME)
            .expect("the default VM's socket path");
    let default_vm = minimald::test_harness::TestServer::new().await;
    default_vm.listen_on_uds(&default_sock).await;
    create_box_on(&default_vm, "api").await;

    // The stopped VM: the listener died and left its socket path behind.
    let stale = std::os::unix::net::UnixListener::bind(host_dir.join("beta/ssh.sock"))
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

/// NET-058's exec half, and `session run` and `net forward` with it: the
/// three go through the same resolution attach does, so a box activated with
/// `--vm` is reached by name alone, over the owning VM's socket. Before this,
/// `min ls` and attach found such a box and `min session exec` answered "No
/// session found" (lab scenario 720).
#[tokio::test]
async fn exec_fall_through_hands_off_the_owning_vm() {
    let (state, default_vm, alpha) = two_vms().await;
    create_box_on(&default_vm, "api").await;
    let web = create_box_on(&alpha, "web").await;
    let global = vm_globals(state.path(), None);
    let selected =
        client::resolve_socket_path_named(Some(state.path()), true, paths::DEFAULT_VM_NAME)
            .expect("the selected VM's socket path");
    let mut client = client::Client::connect(&selected)
        .await
        .expect("connect to the selected VM's daemon");

    for verb in ["Running in", "Running the task in", "Forwarding to"] {
        let (record, handed_off) = cmd::resolve_named_box_version_gated(
            &global,
            &mut client,
            selected.clone(),
            "web",
            verb,
            "session exec web <command>",
        )
        .await
        .expect("a name alpha owns resolves through the selected VM's miss");
        assert_eq!(record.id, web, "{verb}: the owning VM's record");
        assert_eq!(
            handed_off,
            state.path().join("providers/local-minvmd0/alpha/ssh.sock"),
            "{verb}: the hand-off runs over the owning VM's socket"
        );
    }
}

/// NET-058's forward half: `min net forward` on a box another VM holds polls
/// that VM for its session, not the selected one. The selected VM does not
/// hold the box, so a poll there closed the forward on its first tick.
#[tokio::test]
async fn forward_polls_owning_vm() {
    let (state, default_vm, alpha) = two_vms().await;
    let api = create_box_on(&default_vm, "api").await;
    let web = create_box_on(&alpha, "web").await;
    let (client, selected) = selected_client(state.path()).await;
    let owning = state.path().join("providers/local-minvmd0/alpha/ssh.sock");

    let mut poll = cmd::poll_client_for(client, &selected, &owning)
        .await
        .expect("the owning VM's daemon answers");
    let listed = cmd::list_sessions_version_gated(&mut poll)
        .await
        .expect("the poll's list succeeds");
    assert!(
        listed.sessions.iter().any(|s| s.id == web),
        "the poll reaches alpha, which holds 'web'"
    );
    assert!(
        !listed.sessions.iter().any(|s| s.id == api),
        "the poll does not ask the selected VM"
    );

    // A box on the selected VM keeps the selected VM's connection.
    let (client, selected) = selected_client(state.path()).await;
    let mut poll = cmd::poll_client_for(client, &selected, &selected)
        .await
        .expect("the selected VM keeps its connection");
    let listed = cmd::list_sessions_version_gated(&mut poll)
        .await
        .expect("the poll's list succeeds");
    assert!(listed.sessions.iter().any(|s| s.id == api));
}

/// The resolution path gets the same treatment as the listing: a stopped
/// VM's stale `ssh.sock` is probed once — "not running", not a fault to retry
/// for — so a name resolution across every VM costs the VMs that are up, not
/// the stopped ones' retry windows.
#[tokio::test]
async fn a_stopped_vm_does_not_hold_a_box_name_resolution() {
    let state = tempfile::tempdir().expect("a temp minimal state dir");
    let host_dir = state.path().join("providers/local-minvmd0");
    std::fs::create_dir_all(host_dir.join("beta")).expect("the stopped VM's dir");

    let default_sock =
        client::resolve_socket_path_named(Some(state.path()), true, paths::DEFAULT_VM_NAME)
            .expect("the default VM's socket path");
    let default_vm = minimald::test_harness::TestServer::new().await;
    default_vm.listen_on_uds(&default_sock).await;
    create_box_on(&default_vm, "api").await;

    // The stopped VM: a dead listener's socket path, still enumerable.
    let stale = std::os::unix::net::UnixListener::bind(host_dir.join("beta/ssh.sock"))
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
    let host_dir = state.path().join("providers/local-minvmd0");
    for vm in ["alpha", "beta"] {
        std::fs::create_dir_all(host_dir.join(vm)).expect("the named VM's provider subdir");
    }
    let selected_sock =
        client::resolve_socket_path_named(Some(state.path()), true, paths::DEFAULT_VM_NAME)
            .expect("the selected VM's socket path");
    let selected_vm = minimald::test_harness::TestServer::new().await;
    selected_vm.listen_on_uds(&selected_sock).await;
    let alpha = minimald::test_harness::TestServer::new().await;
    alpha.listen_on_uds(&host_dir.join("alpha/ssh.sock")).await;
    let beta = minimald::test_harness::TestServer::new().await;
    beta.listen_on_uds(&host_dir.join("beta/ssh.sock")).await;

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
            running: true,
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

    // Session start: the one host line names the same port as the routing
    // line's `via 127.0.0.1:<port>`, so the two surfaces agree on the
    // address to point at (NET-026 on the activate surface).
    let start = crate::resolver::host_line(
        "web",
        &crate::resolver::LiveSurface::Proxy,
        Some(NEXT_RUNG),
        crate::resolver::HostInstall::default(),
    );
    let address = format!("127.0.0.1:{NEXT_RUNG}");
    assert!(
        routing("alpha").contains(&address) && start.contains(&address),
        "the routing line and the session-start line must agree on the \
         address: ls={} start={start}",
        routing("alpha")
    );
    assert!(
        !start.contains(&RECIPES_PORT.to_string()),
        "the start line must not name the port the recipes assume: {start}"
    );
}

/// Two listed sessions for the id-prefix tests: an unnamed `01a0fe9d…` and
/// `a1b2c3d4…` named `web`.
fn prefix_entries() -> Vec<minimald_rpc::ListSessionsEntry> {
    use boxes::BoxState::Active;
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
    use boxes::BoxState::Active;
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
    use boxes::BoxState::Active;
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
    use boxes::BoxState::Active;
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
    use boxes::BoxState::Active;
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
    use boxes::BoxState::Active;
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

/// The GitHub grant mint and the box's registration with the proxy
/// (BEP-003, BEP-005).
mod mint_tests {
    use std::sync::Arc;

    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use bep::boxes::{BoxRegistry, Stance};
    use bep::control::{Control, Registry};
    use bep::module::GITHUB;
    use bep::publish::{Identity, PublishedKey};
    use bep::seal::{Binding, Breadth, MemberKind, Mode, ProxyKey, ProxyPublicKey};
    use bep::signin::{Completed, Flow, Keychain as _, Material, MemoryKeychain, store_sign_in};
    use minimald_rpc::CreateSessionRequest;

    use crate::mint::{ClientKey, ControlClient, GrantBox, MintError, mint_and_register};

    const BOX_ID: &str = "0192f0c1-7a2b-7c3d-8e4f-a0b1c2d3e4f5";
    const BOX_HEX: &str = "0192f0c17a2b7c3d8e4fa0b1c2d3e4f5";
    const NOW: u64 = 1_800_000_000;
    const ROOT_END: u64 = 2_000_000_000;

    fn published(key: &ProxyPublicKey) -> PublishedKey {
        PublishedKey {
            public: URL_SAFE_NO_PAD.encode(key.to_sec1_bytes()),
            kid: key.kid(),
        }
    }

    /// A proxy's sealing key and the identity it publishes.
    fn proxy() -> (ProxyKey, Identity) {
        let sealing = ProxyKey::generate().unwrap();
        let root = ProxyKey::generate().unwrap();
        let identity = Identity {
            sealing: Some(published(&sealing.public())),
            root: Some(published(&root.public())),
            signing: Some(published(&ProxyKey::generate().unwrap().public())),
            root_not_after: Some(ROOT_END),
            root_certificate: None,
        };
        (sealing, identity)
    }

    fn signed_in() -> MemoryKeychain {
        let keychain = MemoryKeychain::default();
        store_sign_in(
            &keychain,
            &Completed {
                account: "octocat".into(),
                flow: Flow::Device,
                material: Material {
                    instance: String::new(),
                    access_token: "ghu_secret_token_value".into(),
                    refresh_token: "ghr_secret_refresh_value".into(),
                },
                token_expires_at: NOW + 3_600,
                refresh_expires_at: NOW + 86_400,
            },
        )
        .unwrap();
        keychain
    }

    fn grant_box(stance: Stance) -> GrantBox {
        GrantBox {
            box_id: BOX_ID.into(),
            grants: vec!["GH_TOKEN".into()],
            egress: vec![
                "github.com".into(),
                "api.github.com".into(),
                "uploads.github.com".into(),
                "codeload.github.com".into(),
            ],
            stance,
        }
    }

    /// A control socket served on its own runtime, with its registries.
    struct Served {
        _dir: tempfile::TempDir,
        path: std::path::PathBuf,
        clients: Registry,
        boxes: BoxRegistry,
        _runtime: tokio::runtime::Runtime,
    }

    fn serve() -> Served {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bep/control.sock");
        let clients = Registry::default();
        let boxes = BoxRegistry::default();
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        let control = runtime
            .block_on(async { Control::bind(&path, Arc::clone(&clients), Arc::clone(&boxes)) })
            .unwrap();
        runtime.spawn(control.run());
        Served {
            _dir: dir,
            path,
            clients,
            boxes,
            _runtime: runtime,
        }
    }

    // BEP-072, BEP-011: a grant box's create request carries the root
    // certificate the proxy published, beside each grant's sealed value. A
    // grant box whose proxy publishes none is refused with a message that
    // names `bep`, and a box with no grant carries no root.
    #[test]
    fn grant_box_create_request_carries_the_published_root_certificate() {
        use crate::cmd::{grant_root_certificate, hand_grants};

        let (_, identity) = proxy();
        let root_key = identity.key(bep::keys::Role::Root).unwrap();
        let pem = bep::publish::certificate_pem(&certificate_der(&root_key.to_sec1_bytes()));
        let identity = Identity {
            root_certificate: Some(pem.clone()),
            ..identity
        };
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.json");
        identity.publish(&path).unwrap();
        let published = Identity::read(&path).unwrap();

        let root = grant_root_certificate(&published).unwrap();
        assert_eq!(root, pem);
        let grants = vec!["GH_TOKEN".to_string()];
        let minted = vec![crate::mint::Minted {
            grant: "GH_TOKEN".into(),
            sealed: zeroize::Zeroizing::new("sealed-value".into()),
            expiry: ROOT_END,
        }];
        let mut request = create_request();
        hand_grants(&mut request, &grants, &minted, Some(root)).unwrap();
        assert_eq!(
            request.config.root_certificate.as_deref(),
            Some(pem.as_str())
        );
        assert_eq!(request.config.sealed_deliveries.len(), 1);
        assert_eq!(request.config.sealed_deliveries[0].variable, "GH_TOKEN");

        // An identity that an older `bep` published has no certificate, one
        // with a broken certificate has none that the box can trust, and a
        // certificate under another key is not the published root's.
        let foreign = ProxyKey::generate().unwrap().public().to_sec1_bytes();
        let foreign = bep::publish::certificate_pem(&certificate_der(&foreign));
        for root_certificate in [None, Some("not a certificate".to_string()), Some(foreign)] {
            let identity = Identity {
                root_certificate,
                ..published.clone()
            };
            let error = grant_root_certificate(&identity).unwrap_err().to_string();
            assert!(error.contains("no root certificate"), "{error}");
            assert!(error.contains("Run `bep`"), "{error}");
        }
        let mut refused = create_request();
        let error = hand_grants(&mut refused, &grants, &minted, None)
            .unwrap_err()
            .to_string();
        assert!(error.contains("Run `bep`"), "{error}");
        assert_eq!(refused.config.root_certificate, None);
        assert!(refused.config.sealed_deliveries.is_empty());

        // A box with no GitHub grant carries no root.
        let mut plain = create_request();
        hand_grants(&mut plain, &[], &[], None).unwrap();
        assert_eq!(plain.config.root_certificate, None);
    }

    /// A certificate's DER, in the shape of the one `bep` issues, whose
    /// subject public key is `point`, an uncompressed P-256 point. Only the
    /// structure up to the subject key is real.
    fn certificate_der(point: &[u8]) -> Vec<u8> {
        fn element(tag: u8, parts: &[&[u8]]) -> Vec<u8> {
            let content = parts.concat();
            let mut out = vec![tag];
            match u16::try_from(content.len()).unwrap() {
                len @ 0..0x80 => out.push(u8::try_from(len).unwrap()),
                len @ 0x80..0x100 => out.extend([0x81, u8::try_from(len).unwrap()]),
                len => {
                    out.push(0x82);
                    out.extend(len.to_be_bytes());
                }
            }
            out.extend(content);
            out
        }
        const P256: &[u8] = &[
            0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48,
            0xce, 0x3d, 0x03, 0x01, 0x07,
        ];
        let algorithm = element(0x30, &[P256]);
        let key = element(0x03, &[&[0], point]);
        let spki = element(0x30, &[&algorithm, &key]);
        let name = element(0x30, &[&element(0x31, &[])]);
        let tbs = element(
            0x30,
            &[
                &element(0xa0, &[&element(0x02, &[&[2]])]),
                &element(0x02, &[&[1]]),
                &element(0x30, &[]),
                &name,
                &element(0x30, &[]),
                &name,
                &spki,
                &element(0xa3, &[&[0; 200]]),
            ],
        );
        element(0x30, &[&tbs, &element(0x30, &[]), &element(0x03, &[&[0]])])
    }

    fn create_request() -> CreateSessionRequest {
        let mut request = CreateSessionRequest::new(
            "grant-box",
            paths::HostAbsPath::try_new(camino::Utf8PathBuf::from("/tmp/project")).unwrap(),
            boxes::NetworkMode::OwnIp,
            boxes::BoxPolicy::default(),
        );
        request.must_match_version = minimal_client::version_assertion();
        request
    }

    // BEP-005: the member is a sign-in reference under the client's key,
    // with no token, the module's authorities, no injection form, and the
    // root's validity end as its expiry.
    #[test]
    fn local_member_is_a_sign_in_reference_expiring_with_the_root() {
        let (sealing, identity) = proxy();
        let keychain = signed_in();
        let instance = keychain.metadata().unwrap().unwrap().instance;
        let served = serve();
        let mut control = ControlClient::connect(&served.path).unwrap();
        let key = ClientKey::generate().unwrap();

        let minted = mint_and_register(
            &keychain,
            &identity,
            std::path::Path::new("identity.json"),
            &mut control,
            &key,
            &grant_box(Stance::OwnIp),
            NOW,
        )
        .unwrap();
        assert_eq!(minted.len(), 1);
        assert_eq!(minted[0].grant, "GH_TOKEN");
        assert_eq!(minted[0].expiry, ROOT_END);
        // The sealed value carries no token, in any part.
        assert!(!minted[0].sealed.contains("ghu_"));
        assert!(!minted[0].sealed.contains("ghr_"));

        // The value opens for this box on the proxy that publishes the key.
        let node = sealing.public().kid();
        let opened = bep::seal::open(
            &sealing,
            &minted[0].sealed,
            &Binding {
                box_id: BOX_HEX.into(),
                host: node.clone(),
                module: GITHUB.id.into(),
                now: NOW + 1,
            },
        )
        .unwrap();
        assert_eq!(opened.context.box_id, BOX_HEX);
        assert_eq!(opened.context.host, node);
        assert_eq!(opened.context.module, "github");
        assert_eq!(opened.context.host_set_version, GITHUB.host_set_version);
        assert_eq!(opened.context.mode, Mode::User);
        assert_eq!(opened.context.iat, NOW);
        assert_eq!(opened.context.expiry, ROOT_END);
        assert_eq!(opened.member.kind, MemberKind::SignIn);
        assert_eq!(opened.member.breadth, Breadth::Full);
        assert_eq!(opened.member.exp, Some(ROOT_END));

        // The handle verifies under the client key the mint registered.
        let registered = served.clients.read().unwrap().clone();
        assert!(registered.contains(&key.kid()));
        let claims = bep::handle::verify(&opened.member.jws, &registered).unwrap();
        assert_eq!(claims.sub, BOX_HEX);
        assert_eq!(claims.node_id, node);
        assert_eq!(claims.store, "github");
        assert_eq!(claims.id, instance);
        let upstream: Vec<String> = GITHUB.hosts.iter().map(|a| a.host.to_owned()).collect();
        assert_eq!(claims.upstream, upstream);
        assert_eq!(claims.inject, None);
        assert_eq!(claims.iat, NOW);
        assert_eq!(claims.exp, ROOT_END);
        assert_eq!(claims.jti.len(), 32);
        assert!(!opened.member.jws.contains("ghu_"));

        // A handle signed under a key the proxy never registered does not
        // verify.
        let other = bep::handle::ClientKeys::new();
        assert!(bep::handle::verify(&opened.member.jws, &other).is_err());
    }

    // BEP-005: an identity with no root validity end mints nothing, and
    // registers nothing.
    #[test]
    fn an_identity_with_no_root_validity_mints_nothing() {
        let (_, identity) = proxy();
        let identity = Identity {
            root_not_after: None,
            ..identity
        };
        let served = serve();
        let mut control = ControlClient::connect(&served.path).unwrap();
        let err = mint_and_register(
            &signed_in(),
            &identity,
            std::path::Path::new("identity.json"),
            &mut control,
            &ClientKey::generate().unwrap(),
            &grant_box(Stance::OwnIp),
            NOW,
        )
        .unwrap_err();
        assert!(matches!(err, MintError::Identity { .. }), "{err}");
        assert!(served.boxes.get(BOX_HEX).is_none());
    }

    // BEP-003: the proxy holds the box's declared egress and its stance
    // after the mint. With no sign-in held, nothing is registered.
    #[test]
    fn grant_box_registers_its_declared_egress_with_the_proxy() {
        let (_, identity) = proxy();
        let served = serve();
        let mut control = ControlClient::connect(&served.path).unwrap();

        mint_and_register(
            &signed_in(),
            &identity,
            std::path::Path::new("identity.json"),
            &mut control,
            &ClientKey::generate().unwrap(),
            &grant_box(Stance::HostIp),
            NOW,
        )
        .unwrap();
        let held = served.boxes.get(BOX_HEX).expect("the proxy holds the box");
        let egress: Vec<(String, u16)> = held
            .egress
            .iter()
            .map(|authority| (authority.host.clone(), authority.port))
            .collect();
        assert_eq!(
            egress,
            [
                ("github.com".to_owned(), 443),
                ("api.github.com".to_owned(), 443),
                ("uploads.github.com".to_owned(), 443),
                ("codeload.github.com".to_owned(), 443),
            ]
        );
        assert_eq!(held.stance, Stance::HostIp);

        // With no sign-in held the creation fails with the defined error's
        // text, and the proxy gets no registration.
        let other = "0192f0c17a2b7c3d8e4fa0b1c2d3e4f6";
        let err = mint_and_register(
            &MemoryKeychain::default(),
            &identity,
            std::path::Path::new("identity.json"),
            &mut control,
            &ClientKey::generate().unwrap(),
            &GrantBox {
                box_id: other.into(),
                ..grant_box(Stance::OwnIp)
            },
            NOW,
        )
        .unwrap_err();
        assert!(matches!(err, MintError::NoSignIn));
        assert!(err.to_string().contains("Run `min auth login`"), "{err}");
        assert!(served.boxes.get(other).is_none());

        // A box registration the proxy refuses leaves no client key
        // registered.
        let refused_key = ClientKey::generate().unwrap();
        let err = mint_and_register(
            &signed_in(),
            &identity,
            std::path::Path::new("identity.json"),
            &mut control,
            &refused_key,
            &GrantBox {
                box_id: other.into(),
                egress: vec![".".into()],
                ..grant_box(Stance::OwnIp)
            },
            NOW,
        )
        .unwrap_err();
        assert!(matches!(err, MintError::Refused { .. }), "{err}");
        assert!(served.boxes.get(other).is_none());
        assert!(!served.clients.read().unwrap().contains(&refused_key.kid()));

        // Nothing answers on a socket no proxy serves.
        let gone = served.path.with_file_name("none.sock");
        let err = ControlClient::connect(&gone).err().unwrap();
        assert!(matches!(err, MintError::NotRunning { .. }), "{err}");
    }

    // BEP-003: a creation that fails after the mint leaves no declared
    // egress at the proxy. A creation that finishes keeps it.
    #[test]
    fn grant_box_registers_its_declared_egress_with_the_proxy_until_the_creation_fails() {
        use crate::mint::ProxyRegistration;
        let (_, identity) = proxy();
        let served = serve();
        let mut control = ControlClient::connect(&served.path).unwrap();
        let mut mint = |box_id: &str| {
            mint_and_register(
                &signed_in(),
                &identity,
                std::path::Path::new("identity.json"),
                &mut control,
                &ClientKey::generate().unwrap(),
                &GrantBox {
                    box_id: box_id.into(),
                    ..grant_box(Stance::OwnIp)
                },
                NOW,
            )
            .unwrap();
        };

        // A failed creation drops its registration, and the proxy forgets
        // the box.
        mint(BOX_HEX);
        assert!(served.boxes.get(BOX_HEX).is_some());
        drop(ProxyRegistration::new(served.path.clone(), BOX_HEX).unwrap());
        assert!(served.boxes.get(BOX_HEX).is_none());

        // A finished creation keeps its registration.
        let kept = "0192f0c17a2b7c3d8e4fa0b1c2d3e4f7";
        mint(kept);
        ProxyRegistration::new(served.path.clone(), kept)
            .unwrap()
            .keep();
        assert!(served.boxes.get(kept).is_some());

        // A drop inside a runtime forgets the box on a blocking thread, and
        // the runtime waits for it before it shuts down.
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            drop(ProxyRegistration::new(served.path.clone(), kept).unwrap());
        });
        drop(runtime);
        assert!(served.boxes.get(kept).is_none());

        // A drop with no proxy to tell does not panic.
        let gone = served.path.with_file_name("none.sock");
        drop(ProxyRegistration::new(gone, kept).unwrap());
    }

    // BEP-067, BEP-043: a mint appends one `mint` record per member, and a
    // live box's destroy appends one `revocation` record, to the one audit
    // log, through the proxy's control socket. The records chain, and the
    // revocation is in force for the box id alone.
    #[test]
    fn mint_and_destroy_append_audit_records() {
        use bep::audit::{AuditLog, Kind, LogReader, Outcome, line_hash, segment_name};
        use bep::redeemer::Revocations;

        let (_, identity) = proxy();
        let keychain = signed_in();
        let instance = keychain.metadata().unwrap().unwrap().instance;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bep/control.sock");
        let logs = dir.path().join("audit");
        let log = AuditLog::open(logs.join(segment_name(0))).unwrap();
        let revocations = Revocations::default();
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        let control = runtime
            .block_on(async {
                Control::bind(&path, Registry::default(), BoxRegistry::default()).map(|control| {
                    control
                        .with_revocations(Arc::clone(&revocations))
                        .with_audit(Arc::new(std::sync::Mutex::new(log)))
                })
            })
            .unwrap();
        runtime.spawn(control.run());

        let mut client = ControlClient::connect(&path).unwrap();
        let two_grants = GrantBox {
            grants: vec!["GH_TOKEN".into(), "GITHUB_TOKEN".into()],
            ..grant_box(Stance::OwnIp)
        };
        let minted = mint_and_register(
            &keychain,
            &identity,
            std::path::Path::new("identity.json"),
            &mut client,
            &ClientKey::generate().unwrap(),
            &two_grants,
            NOW,
        )
        .unwrap();
        assert_eq!(minted.len(), 2);

        let mut reader = LogReader::new(&logs);
        let mints = reader.read_new().unwrap().entries;
        assert_eq!(mints.len(), 2, "one mint record per member: {mints:?}");
        for entry in &mints {
            assert_eq!(entry.record.kind, Kind::Mint);
            assert_eq!(entry.record.subject, BOX_HEX);
            assert_eq!(entry.record.identifier, format!("github:{instance}"));
            assert_eq!(entry.record.decision, Outcome::Admit);
            assert!(!entry.line.contains("ghu_") && !entry.line.contains("ghr_"));
        }
        assert!(revocations.read().unwrap().is_empty());

        // The destroy of the live box, as `minvmd` sends it: the revocation,
        // then the forget. The hyphenated id names the same box.
        client.revoke_box(BOX_ID).unwrap();
        client.forget_box(BOX_ID).unwrap();
        // A second revocation of the box records nothing new.
        client.revoke_box(BOX_HEX).unwrap();
        let revoked = reader.read_new().unwrap().entries;
        assert_eq!(revoked.len(), 1, "one revocation record: {revoked:?}");
        assert_eq!(revoked[0].record.kind, Kind::Revocation);
        assert_eq!(revoked[0].record.subject, BOX_HEX);
        assert_eq!(revoked[0].record.identifier, bep::audit::NONE);
        // One chain: the revocation follows the client's mints.
        assert_eq!(revoked[0].record.previous_hash, line_hash(&mints[1].line));
        assert_eq!(mints[1].record.previous_hash, line_hash(&mints[0].line));
        assert_eq!(revocations.read().unwrap().as_slice(), [BOX_HEX.to_owned()]);

        // A request with no box id is refused, and records nothing.
        assert!(client.revoke_box("web").is_err());
        assert!(client.record_mint(BOX_HEX, " ").is_err());
        assert!(reader.read_new().unwrap().entries.is_empty());
    }

    /// A control socket that registers and forgets boxes as the proxy does,
    /// and refuses every client key. Gives the socket and its boxes.
    fn serve_refusing_keys() -> (
        tempfile::TempDir,
        std::path::PathBuf,
        BoxRegistry,
        Arc<std::sync::Mutex<Vec<String>>>,
    ) {
        use std::io::{BufRead as _, Write as _};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("control.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let boxes = BoxRegistry::default();
        let ops = Arc::new(std::sync::Mutex::new(Vec::new()));
        let (served_boxes, served_ops) = (Arc::clone(&boxes), Arc::clone(&ops));
        std::thread::spawn(move || {
            let clients = Arc::new(std::sync::RwLock::new(bep::handle::ClientKeys::new()));
            for stream in listener.incoming() {
                let Ok(stream) = stream else {
                    return;
                };
                served_ops.lock().unwrap().push("connect".to_owned());
                // The proxy serves each connection on its own task.
                let (clients, served_boxes, served_ops) = (
                    Arc::clone(&clients),
                    Arc::clone(&served_boxes),
                    Arc::clone(&served_ops),
                );
                std::thread::spawn(move || {
                    let mut reader = std::io::BufReader::new(stream.try_clone().unwrap());
                    let mut writer = stream;
                    let mut line = String::new();
                    while reader.read_line(&mut line).unwrap_or(0) > 0 {
                        let request: bep::control::Request =
                            serde_json_lenient::from_str(&line).unwrap();
                        let op = match request {
                            bep::control::Request::RegisterClientKey { .. } => {
                                "register_client_key"
                            }
                            bep::control::Request::RegisterBox { .. } => "register_box",
                            bep::control::Request::ForgetBox { .. } => "forget_box",
                            bep::control::Request::RevokeClientKey { .. } => "revoke_client_key",
                            bep::control::Request::ReplaceClientKey { .. } => "replace_client_key",
                            bep::control::Request::RecordMint { .. } => "record_mint",
                            bep::control::Request::RevokeBox { .. } => "revoke_box",
                        };
                        served_ops.lock().unwrap().push(op.to_owned());
                        let reply = if op == "register_client_key" {
                            bep::control::Reply {
                                ok: false,
                                kid: None,
                                revoked: Vec::new(),
                                error: Some("the key is not a P-256 public key".into()),
                            }
                        } else if op == "record_mint" || op == "revoke_box" {
                            // `handle_line` keeps no record, so the stub
                            // answers these two itself.
                            bep::control::Reply {
                                ok: true,
                                kid: None,
                                revoked: Vec::new(),
                                error: None,
                            }
                        } else {
                            bep::control::handle_line(&line, &clients, &served_boxes)
                        };
                        let mut answer = serde_json_lenient::to_string(&reply).unwrap();
                        answer.push('\n');
                        writer.write_all(answer.as_bytes()).unwrap();
                        line.clear();
                    }
                });
            }
        });
        (dir, path, boxes, ops)
    }

    // BEP-063: a client key the proxy refuses leaves no box registered
    // either. The box is registered first and forgotten again, over a new
    // connection.
    #[test]
    fn a_refused_client_key_forgets_the_box_again() {
        let (_, identity) = proxy();
        let (_dir, path, boxes, ops) = serve_refusing_keys();
        let mut control = ControlClient::connect(&path).unwrap();
        let err = mint_and_register(
            &signed_in(),
            &identity,
            std::path::Path::new("identity.json"),
            &mut control,
            &ClientKey::generate().unwrap(),
            &grant_box(Stance::OwnIp),
            NOW,
        )
        .unwrap_err();
        assert!(matches!(err, MintError::Refused { .. }), "{err}");
        assert_eq!(
            *ops.lock().unwrap(),
            [
                "connect",
                "register_box",
                "register_client_key",
                "connect",
                "forget_box"
            ]
        );
        assert!(boxes.get(BOX_HEX).is_none());
    }

    /// A control socket that stores each box it is asked to register and
    /// then closes the connection with no reply. Every other request gets
    /// the proxy's answer. Gives the socket, its boxes and the requests.
    fn serve_dropping_box_replies() -> (
        tempfile::TempDir,
        std::path::PathBuf,
        BoxRegistry,
        Arc<std::sync::Mutex<Vec<String>>>,
    ) {
        use std::io::{BufRead as _, Write as _};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("control.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let boxes = BoxRegistry::default();
        let ops = Arc::new(std::sync::Mutex::new(Vec::new()));
        let (served_boxes, served_ops) = (Arc::clone(&boxes), Arc::clone(&ops));
        std::thread::spawn(move || {
            let clients = std::sync::RwLock::new(bep::handle::ClientKeys::new());
            for stream in listener.incoming() {
                let Ok(stream) = stream else {
                    return;
                };
                let mut reader = std::io::BufReader::new(stream.try_clone().unwrap());
                let mut writer = stream;
                let mut line = String::new();
                while reader.read_line(&mut line).unwrap_or(0) > 0 {
                    let request: bep::control::Request =
                        serde_json_lenient::from_str(&line).unwrap();
                    let op = match request {
                        bep::control::Request::RegisterClientKey { .. } => "register_client_key",
                        bep::control::Request::RegisterBox { .. } => "register_box",
                        bep::control::Request::ForgetBox { .. } => "forget_box",
                        bep::control::Request::RevokeClientKey { .. } => "revoke_client_key",
                        bep::control::Request::ReplaceClientKey { .. } => "replace_client_key",
                        bep::control::Request::RecordMint { .. } => "record_mint",
                        bep::control::Request::RevokeBox { .. } => "revoke_box",
                    };
                    served_ops.lock().unwrap().push(op.to_owned());
                    let reply = if op == "record_mint" || op == "revoke_box" {
                        // `handle_line` keeps no record, so the stub
                        // answers these two itself.
                        bep::control::Reply {
                            ok: true,
                            kid: None,
                            revoked: Vec::new(),
                            error: None,
                        }
                    } else {
                        bep::control::handle_line(&line, &clients, &served_boxes)
                    };
                    if op == "register_box" {
                        // The box is stored, and the reply never comes.
                        break;
                    }
                    let mut answer = serde_json_lenient::to_string(&reply).unwrap();
                    answer.push('\n');
                    writer.write_all(answer.as_bytes()).unwrap();
                    line.clear();
                }
            }
        });
        (dir, path, boxes, ops)
    }

    // BEP-003: a registration whose reply fails can still leave the box
    // stored at the proxy. The mint forgets it again over a new connection,
    // and registers no client key.
    #[test]
    fn a_failed_box_reply_forgets_the_box_again() {
        let (_, identity) = proxy();
        let (_dir, path, boxes, ops) = serve_dropping_box_replies();
        let mut control = ControlClient::connect(&path).unwrap();
        let err = mint_and_register(
            &signed_in(),
            &identity,
            std::path::Path::new("identity.json"),
            &mut control,
            &ClientKey::generate().unwrap(),
            &grant_box(Stance::OwnIp),
            NOW,
        )
        .unwrap_err();
        assert!(matches!(err, MintError::Control(_)), "{err}");
        assert_eq!(*ops.lock().unwrap(), ["register_box", "forget_box"]);
        assert!(boxes.get(BOX_HEX).is_none());
    }

    fn github_secrets() -> boxes::core::bep::SecretGrants {
        std::collections::BTreeMap::from([(
            "GH_TOKEN".to_owned(),
            boxes::core::bep::SecretGrant {
                source: boxes::core::bep::GrantSource::Broker,
                scopes: vec!["github:user-token".into()],
                mode: None,
            },
        )])
    }

    fn refusal(err: &anyhow::Error) -> &boxes::core::bep::ActivationRefused {
        err.downcast_ref::<boxes::core::bep::ActivationRefused>()
            .unwrap_or_else(|| panic!("not a refused box spec: {err}"))
    }

    // Gatehouse §6.2: where no node-local proxy exists, a GitHub grant is
    // refused with `gatehouse_unenrolled_node` and exit 5, even with a
    // sign-in held. `github_sign_in_required` is only for a host that has a
    // proxy.
    #[test]
    fn a_grant_box_with_no_proxy_is_refused_as_an_unenrolled_node() {
        use boxes::core::bep::ProxyAbsence;
        let dir = tempfile::tempdir().unwrap();
        let identity = dir.path().join("identity.json");
        let control = dir.path().join("control.sock");
        let binary = dir.path().join("bep");
        let log = dir.path().join("bep.log");
        assert!(!crate::cmd::proxy_present(Some(&identity), Some(&control)));
        assert!(!crate::cmd::proxy_present(None, None));

        // No `bep` program: the proxy is not installed.
        let absence = crate::cmd::proxy_absence(
            Some(&identity),
            Some(&control),
            Ok(binary.clone()),
            Some(log.clone()),
        );
        assert_eq!(
            absence,
            Some(ProxyAbsence::NotInstalled {
                path: Some(binary.clone())
            })
        );
        let err =
            crate::cmd::check_github_grants(&github_secrets(), absence, &signed_in()).unwrap_err();
        let refused = refusal(&err);
        assert_eq!(
            refused.refusals[0].code(),
            Some(boxes::core::bep::GATEHOUSE_UNENROLLED_NODE)
        );
        assert_eq!(
            boxes::core::bep::GATEHOUSE_UNENROLLED_NODE,
            "gatehouse_unenrolled_node"
        );
        assert_eq!(refused.exit_code(), 5);
        assert_eq!(
            refused.to_string(),
            format!(
                "Cannot create the box: it declares the GitHub grant GH_TOKEN, and `bep`, the \
                 Box Egress Proxy, is not installed at {}, so no proxy serves boxes on this \
                 machine. To create the box without the grant, remove GH_TOKEN from \
                 [session.secrets] in minimal.toml.",
                binary.display()
            )
        );
        // No path resolved for the program: the text names none.
        let err = crate::cmd::check_github_grants(
            &github_secrets(),
            crate::cmd::proxy_absence(
                None,
                None,
                Err(bep::store::ProxyLookupError::NoMinvmd),
                None,
            ),
            &signed_in(),
        )
        .unwrap_err();
        assert_eq!(
            err.to_string(),
            "Cannot create the box: it declares the GitHub grant GH_TOKEN, and `bep`, the Box \
             Egress Proxy, is not installed, so no proxy serves boxes on this machine. To \
             create the box without the grant, remove GH_TOKEN from [session.secrets] in \
             minimal.toml."
        );

        // A relative MINVMD_BEP_BIN: the text names the variable and its
        // value, not a missing program.
        let absence = crate::cmd::proxy_absence(
            Some(&identity),
            Some(&control),
            Err(bep::store::ProxyLookupError::RelativeEnv("bin/bep".into())),
            Some(log.clone()),
        );
        assert_eq!(
            absence,
            Some(ProxyAbsence::RelativePath {
                path: "bin/bep".into()
            })
        );
        let err =
            crate::cmd::check_github_grants(&github_secrets(), absence, &signed_in()).unwrap_err();
        let refused = refusal(&err);
        assert_eq!(refused.exit_code(), 5);
        assert_eq!(
            refused.to_string(),
            "Cannot create the box: it declares the GitHub grant GH_TOKEN, and MINVMD_BEP_BIN \
             sets `bep`, the Box Egress Proxy, to the relative path bin/bep, and no proxy \
             serves boxes on this machine. Set MINVMD_BEP_BIN to an absolute path. To create \
             the box without the grant, remove GH_TOKEN from [session.secrets] in \
             minimal.toml."
        );

        // A `bep` program that published nothing: installed, and not
        // answering. With no log file written, the text names no log.
        std::fs::write(&binary, "").unwrap();
        let absence = crate::cmd::proxy_absence(
            Some(&identity),
            Some(&control),
            Ok(binary.clone()),
            Some(log.clone()),
        );
        assert_eq!(
            absence,
            Some(ProxyAbsence::NotAnswering {
                path: binary.clone(),
                log: None
            })
        );
        let err =
            crate::cmd::check_github_grants(&github_secrets(), absence, &signed_in()).unwrap_err();
        let refused = refusal(&err);
        assert_eq!(refused.exit_code(), 5);
        assert_eq!(
            refused.to_string(),
            format!(
                "Cannot create the box: it declares the GitHub grant GH_TOKEN, and `bep`, the \
                 Box Egress Proxy, is installed at {}, but it does not answer, so no proxy \
                 serves boxes on this machine. To create the box without the grant, remove \
                 GH_TOKEN from [session.secrets] in minimal.toml.",
                binary.display()
            )
        );
        // With the log file written, the text names it.
        std::fs::write(&log, "").unwrap();
        let absence = crate::cmd::proxy_absence(
            Some(&identity),
            Some(&control),
            Ok(binary.clone()),
            Some(log.clone()),
        );
        assert_eq!(
            absence,
            Some(ProxyAbsence::NotAnswering {
                path: binary.clone(),
                log: Some(log.clone())
            })
        );
        let err =
            crate::cmd::check_github_grants(&github_secrets(), absence, &signed_in()).unwrap_err();
        let refused = refusal(&err);
        assert_eq!(refused.exit_code(), 5);
        assert_eq!(
            refused.to_string(),
            format!(
                "Cannot create the box: it declares the GitHub grant GH_TOKEN, and `bep`, the \
                 Box Egress Proxy, is installed at {}, but it does not answer, so no proxy \
                 serves boxes on this machine. The proxy's log is at {}. To create the box \
                 without the grant, remove GH_TOKEN from [session.secrets] in minimal.toml.",
                binary.display(),
                log.display()
            )
        );
        // With no sign-in held either, the missing proxy is what is refused.
        let err = crate::cmd::check_github_grants(
            &github_secrets(),
            Some(ProxyAbsence::NotInstalled { path: None }),
            &MemoryKeychain::default(),
        )
        .unwrap_err();
        assert_eq!(
            refusal(&err).refusals[0].code(),
            Some(boxes::core::bep::GATEHOUSE_UNENROLLED_NODE)
        );

        // With a proxy, no sign-in held is refused with its own error.
        std::fs::write(&identity, "{}").unwrap();
        std::fs::write(&control, "").unwrap();
        assert!(crate::cmd::proxy_present(Some(&identity), Some(&control)));
        assert_eq!(
            crate::cmd::proxy_absence(Some(&identity), Some(&control), Ok(binary), Some(log)),
            None
        );
        let err =
            crate::cmd::check_github_grants(&github_secrets(), None, &MemoryKeychain::default())
                .unwrap_err();
        let refused = refusal(&err);
        assert_eq!(
            refused.refusals[0].code(),
            Some(boxes::core::bep::GITHUB_SIGN_IN_REQUIRED)
        );
        assert_eq!(refused.exit_code(), 3);
        // With a proxy and a sign-in, the grants pass. A box with no GitHub
        // grant is never refused.
        assert_eq!(
            crate::cmd::check_github_grants(&github_secrets(), None, &signed_in()).unwrap(),
            ["GH_TOKEN"]
        );
        assert!(
            crate::cmd::check_github_grants(
                &Default::default(),
                Some(ProxyAbsence::NotServed),
                &MemoryKeychain::default()
            )
            .unwrap()
            .is_empty()
        );
    }

    // Gatehouse §6.2: a grant box with no box id or no stance is refused
    // with `gatehouse_unenrolled_node`, and does not start with a grant that
    // resolves to nothing.
    #[test]
    fn a_grant_box_with_no_box_id_or_stance_is_refused_as_an_unenrolled_node() {
        let grants = vec!["GH_TOKEN".to_owned()];
        let refused =
            crate::cmd::grant_box_facts(&grants, None, boxes::NetworkMode::OwnIp).unwrap_err();
        assert_eq!(
            refused.refusals[0].code(),
            Some(boxes::core::bep::GATEHOUSE_UNENROLLED_NODE)
        );
        assert_eq!(refused.exit_code(), 5);
        let refused =
            crate::cmd::grant_box_facts(&grants, Some(BOX_ID.into()), boxes::NetworkMode::NoNet)
                .unwrap_err();
        assert_eq!(refused.exit_code(), 5);

        assert_eq!(
            crate::cmd::grant_box_facts(&grants, Some(BOX_ID.into()), boxes::NetworkMode::HostNet)
                .unwrap(),
            Some((BOX_ID.to_owned(), Stance::HostIp))
        );
        // A box with no GitHub grant needs neither.
        assert_eq!(
            crate::cmd::grant_box_facts(&[], None, boxes::NetworkMode::NoNet).unwrap(),
            None
        );
    }
}

/// BEP-070: on a host that is not enrolled, each box creation gets a box id
/// that the host-side creator mints outside the VM: a UUIDv7 whose timestamp
/// comes from the clock and whose random fields come from the OS CSPRNG.
/// The test drives the CLI's own registration against the real VM host
/// tables and control server, and creates the box again and again under one
/// name. Each creation gets a new id. The CLI presents no id, so the id the
/// reply returns is the one the host's row holds. A friendly name is an
/// alias, so a re-created box never inherits the id of its predecessor.
#[tokio::test]
async fn box_id_is_a_csprng_uuidv7_per_creation() {
    use minimal_client::box_registration::{register_box_for_activation, withdraw_box_row};

    const CREATIONS: usize = 8;

    fn now_ms() -> u64 {
        u64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("the clock is past the epoch")
                .as_millis(),
        )
        .expect("the time in milliseconds fits in 64 bits")
    }

    let policy = boxes::BoxPolicy {
        egress: None,
        ingress: None,
        credentialed_upstream: None,
        quic443: None,
    };
    let dir = tempfile::TempDir::new().unwrap();
    let host_dir = dir.path().join("providers").join("local-minvmd0");
    std::fs::create_dir_all(&host_dir).unwrap();
    let sock_path = host_dir.join("control.sock");
    let attachments = minvmd::bep_attach::Attachments::new();
    let registry = minvmd::box_registry::BoxRegistry::new(switch::SwitchSubnet::default())
        .feeding_proxy_attachments(attachments.clone());
    let _server = minvmd::control::spawn(
        sock_path.clone(),
        registry.clone(),
        minvmd::net::answerer::AnswererStatus::allocating_for_tests("box-id-test-node"),
        minvmd::control::ProxyPublishStatus::default(),
    )
    .expect("the control server binds its socket");

    let mut ids: Vec<[u8; 16]> = Vec::with_capacity(CREATIONS);
    for creation in 0..CREATIONS {
        let before = now_ms();
        let mut registered = register_box_for_activation(
            paths::HostKind::Minvmd,
            Some(dir.path()),
            boxes::NetworkMode::OwnIp,
            "web",
            &policy,
        )
        .await
        .unwrap_or_else(|error| {
            panic!(
                "creation {creation}: the real control server answers the registration, \
                 after ids {ids:02x?}: {error:#}"
            )
        })
        .expect("an own-address box on a VM-backed host registers");
        let after = now_ms();
        // Commit the lease, as an activation does once its session is
        // active. A lease dropped uncommitted makes the host withdraw the
        // row on its own thread, later. That late withdrawal can land
        // while the next creation of "web" is being assigned its address,
        // and the host then refuses that creation as withdrawn.
        if let Some(lease) = registered.lease.take() {
            lease.commit().await;
        }
        let id = registered
            .box_id
            .expect("the reply returns the id the host minted for this creation");
        let bytes = id.to_bytes();

        // The host minted it: the row and the attachment that the
        // registration published hold the id that the reply returned.
        let row = registry
            .table()
            .by_source(registered.addresses.switch_address.octets())
            .expect("the registration published the box's row");
        assert_eq!(
            row.box_id(),
            bytes,
            "creation {creation}: the CLI holds the id the host's row holds"
        );
        let attachment = attachments
            .by_source(registered.addresses.switch_address.octets())
            .expect("the registration issued the box's attachment");
        assert_eq!(
            attachment.box_id(),
            bytes,
            "creation {creation}: the CLI holds the id the host's attachment holds"
        );

        // A UUIDv7: version 7 and the RFC 9562 variant.
        assert_eq!(
            bytes[6] >> 4,
            7,
            "creation {creation}: the id is a UUIDv7, got {id}"
        );
        assert_eq!(
            bytes[8] >> 6,
            0b10,
            "creation {creation}: the id carries the RFC 9562 variant, got {id}"
        );
        // Its 48-bit timestamp is the clock at the mint, not a counter.
        // The mint can take the millisecond after the process's last mint
        // when that is ahead of the clock, so the upper bound allows one
        // second of lead over the clock after the registration.
        let mut stamp = [0u8; 8];
        stamp[2..].copy_from_slice(&bytes[..6]);
        let stamp = u64::from_be_bytes(stamp);
        let latest = after + 1_000;
        assert!(
            (before..=latest).contains(&stamp),
            "creation {creation}: the timestamp {stamp} of id {id} is the clock at the \
             mint, between {before} and {latest}"
        );

        ids.push(bytes);
        withdraw_box_row(
            Some(sock_path.clone()),
            Some("web"),
            Some(registered.addresses),
            Some(id),
        )
        .await;
        assert!(
            !attachments.holds_id(bytes),
            "creation {creation}: the destroyed box's id is held by no attachment"
        );
    }

    // One id per creation: no id returns under the name it was minted for.
    let distinct: std::collections::BTreeSet<[u8; 16]> = ids.iter().copied().collect();
    assert_eq!(
        distinct.len(),
        CREATIONS,
        "each creation under one name gets an id of its own, got {ids:02x?}"
    );
    // The ids sort in creation order: each mint takes a later millisecond
    // than the one before it.
    assert!(
        ids.windows(2).all(|pair| pair[0] < pair[1]),
        "the ids sort in creation order, got {ids:02x?}"
    );
    // The random fields are random fills, never a counter: all 74 bits
    // after the version and the variant. `rand_a` is the 12 bits after the
    // version, and `rand_b` is the 62 bits after the variant. Eight draws of
    // 62 random bits are all distinct, and no two consecutive draws differ
    // by one: either chance is below 2^-55. `rand_a` holds 12 bits only, so
    // two of eight draws match about once in 150 runs. The test asserts
    // only that `rand_a` does not step by one on every creation, the shape
    // a counter gives it: a chance of 2^-84 for random fills.
    let rand_a: Vec<u16> = ids
        .iter()
        .map(|bytes| u16::from_be_bytes([bytes[6] & 0x0f, bytes[7]]))
        .collect();
    let rand_b: Vec<u64> = ids
        .iter()
        .map(|bytes| {
            let mut field = [0u8; 8];
            field.copy_from_slice(&bytes[8..16]);
            field[0] &= 0x3f;
            u64::from_be_bytes(field)
        })
        .collect();
    let distinct_b: std::collections::BTreeSet<u64> = rand_b.iter().copied().collect();
    assert_eq!(
        distinct_b.len(),
        CREATIONS,
        "rand_b differs on every creation, got {rand_b:016x?} from ids {ids:02x?}"
    );
    assert!(
        rand_b
            .windows(2)
            .all(|pair| pair[1].wrapping_sub(pair[0]) & 0x3fff_ffff_ffff_ffff != 1),
        "rand_b is not a counter, got {rand_b:016x?} from ids {ids:02x?}"
    );
    assert!(
        !rand_a
            .windows(2)
            .all(|pair| pair[1].wrapping_sub(pair[0]) & 0x0fff == 1),
        "rand_a is not a counter, got {rand_a:03x?} from ids {ids:02x?}"
    );
}

/// BEP-070: a minted box id that a retained record already names refuses
/// the creation. This test proves the CLI half only: when the host refuses
/// a registration for a colliding id, the CLI refuses the creation. It does
/// not prove that the host detects a collision. The host half — the
/// registry refuses the colliding mint before it spends an address — is
/// `minvmd`'s `colliding_box_id_refused`, which the spec names as a second
/// verify line. A real mint does not collide, and no public door fixes the
/// id the host mints. So this test stands in for the host on the control
/// socket and answers the CLI's registration with the exact refusal the
/// host sends for a collision. The activation fails with the refusal, which
/// names the colliding id, and no box id comes back.
#[tokio::test]
async fn colliding_box_id_refuses_creation() {
    use minimal_client::box_registration::register_box_for_activation;
    use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _};

    let policy = boxes::BoxPolicy {
        egress: None,
        ingress: None,
        credentialed_upstream: None,
        quic443: None,
    };
    let dir = tempfile::TempDir::new().unwrap();
    let host_dir = dir.path().join("providers").join("local-minvmd0");
    std::fs::create_dir_all(&host_dir).unwrap();
    let listener = tokio::net::UnixListener::bind(host_dir.join("control.sock")).unwrap();

    // The id a retained record already holds, and the refusal the host's
    // control server replies with when a mint lands on it.
    let held = minvmd::bep_attach::mint_box_id();
    let refusal = minvmd::box_registry::AllocationError::CollidingBoxId { id: held }.to_string();
    let held_text = minimald_rpc::BoxId::from_bytes(held).to_string();
    assert!(
        refusal.contains(&held_text),
        "the host's refusal names the colliding id {held_text}, got {refusal:?}"
    );

    let host = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("the CLI connects");
        let mut stream = tokio::io::BufReader::new(stream);
        let mut line = String::new();
        stream.read_line(&mut line).await.unwrap();
        let request: minimald_rpc::BoxControlRequest =
            serde_json_lenient::from_str(line.trim()).expect("the CLI sends a control request");
        assert!(
            matches!(request, minimald_rpc::BoxControlRequest::Register(_)),
            "the CLI asks the host to register the box, got {request:?}"
        );
        let mut reply =
            serde_json_lenient::to_string(&minimald_rpc::BoxControlReply::Error { error: refusal })
                .unwrap();
        reply.push('\n');
        stream.get_mut().write_all(reply.as_bytes()).await.unwrap();
    });

    let err = register_box_for_activation(
        paths::HostKind::Minvmd,
        Some(dir.path()),
        boxes::NetworkMode::OwnIp,
        "web",
        &policy,
    )
    .await
    .expect_err("a colliding box id refuses the creation; the box gets no id");
    host.await.expect("the stand-in host answered");
    let chain = format!("{err:#}");
    assert!(
        chain.contains(&held_text),
        "the refusal names the colliding id {held_text}, got {chain:?}"
    );
    assert!(
        chain.contains("does not start"),
        "the activation ends on the refusal, so no box is created, got {chain:?}"
    );
}

/// The cell under `column` in the `min ls` row that contains `row_key`,
/// read by the header's positions up to `next`, the column after it. A
/// cell can hold spaces, so the row is not split on whitespace.
fn ls_cell_at(text: &str, row_key: &str, column: &str, next: &str) -> String {
    let header = text
        .lines()
        .find(|l| l.contains("SESSION ID"))
        .unwrap_or_else(|| panic!("a header in:\n{text}"));
    let start = header.find(column).expect("the column in the header");
    let end = header.find(next).expect("the next column in the header");
    let row = text
        .lines()
        .find(|l| l.contains(row_key) && !l.contains("SESSION ID"))
        .unwrap_or_else(|| panic!("a row for {row_key} in:\n{text}"));
    row[start..end].trim().to_string()
}

/// A listing of one box per entry in `boxes`: its name, its network facts
/// and its per-box enforcement.
fn listing_of(
    boxes: &[(
        &str,
        Option<minimald_rpc::BoxNetworkFacts>,
        Option<boxes::HostIpEnforcement>,
    )],
) -> minimald_rpc::ListSessionsResponse {
    let id = |n: usize| {
        boxes::SessionId::parse_str(&format!("00000000-0000-0000-0000-{n:012}")).unwrap()
    };
    minimald_rpc::ListSessionsResponse {
        resource_pool: None,
        sessions: boxes
            .iter()
            .enumerate()
            .map(|(n, (name, _, enforcement))| {
                let mut entry = twin_entry(
                    &id(n + 1).to_string(),
                    Some(name),
                    Some("/work/proj"),
                    boxes::BoxState::Active,
                );
                entry.host_ip_enforcement = *enforcement;
                entry
            })
            .collect(),
        daemon_version: None,
        hostname_routing_unavailable: None,
        hostname_proxy_port: None,
        zone_answerer_port: None,
        answerer_bound: false,
        box_networks: boxes
            .iter()
            .enumerate()
            .filter_map(|(n, (_, facts, _))| facts.clone().map(|facts| (id(n + 1), facts)))
            .collect(),
    }
}

/// T110: the BOX NAMES row speaks for every listed box, so it reads the
/// `127.0.0.1` fallback form as soon as one box reports the fallback, even
/// beside a box at its own address. A host-address box at the node address
/// `127.0.0.1` is not at the fallback, so it keeps the own-address form.
#[test]
fn ls_shows_box_loopback_address_names_row_follows_any_fallback_box() {
    let at = |address: std::net::Ipv4Addr, at_fallback: bool| {
        Some(minimald_rpc::BoxNetworkFacts {
            loopback_address: Some(address),
            egress_posture: None,
            at_fallback: Some(at_fallback),
        })
    };
    let own = std::net::Ipv4Addr::new(127, 0, 64, 2);
    let localhost = std::net::Ipv4Addr::LOCALHOST;
    let row = |boxes: &[(
        &str,
        Option<minimald_rpc::BoxNetworkFacts>,
        Option<boxes::HostIpEnforcement>,
    )]| {
        let mut resp = listing_of(boxes);
        resp.hostname_proxy_port = Some(7654);
        resp.answerer_bound = true;
        let mut out = Vec::new();
        format_ls(
            &mut out,
            &LsArgs {
                raw: false,
                json: false,
            },
            &resp,
            Some(crate::resolver::LiveSurface::Native),
            None,
        )
        .expect("rendering the listing");
        let table = String::from_utf8(out).expect("the listing is UTF-8");
        table
            .lines()
            .find(|l| l.starts_with("BOX NAMES:"))
            .unwrap_or_else(|| panic!("a BOX NAMES row in:\n{table}"))
            .to_string()
    };
    let opens = "<box>.min.internal opens at its name on this machine; the HTTP proxy at \
                 127.0.0.1:7654 opens it too";
    let resolves = "<box>.min.internal resolves on this machine; open it through the HTTP \
                    proxy at 127.0.0.1:7654";
    assert_eq!(
        row(&[
            ("own", at(own, false), None),
            ("fallback", at(localhost, true), None)
        ]),
        format!("BOX NAMES:       {resolves}"),
        "a mixed listing reads the fallback form"
    );
    assert_eq!(
        row(&[("host", at(localhost, false), None)]),
        format!("BOX NAMES:       {opens}"),
        "a host-address box at 127.0.0.1 is not at the fallback"
    );
    assert_eq!(
        row(&[("own", at(own, false), None)]),
        format!("BOX NAMES:       {opens}")
    );
    assert_eq!(
        row(&[("unreported", None, None)]),
        format!("BOX NAMES:       {resolves}"),
        "a listing that proves no box off the fallback reads the fallback form"
    );
    assert_eq!(
        row(&[]),
        format!("BOX NAMES:       {resolves}"),
        "a listing with no box reads the fallback form"
    );
}

/// T110: `min ls` shows each box's address in an ADDRESS column after NAME
/// — its own address, the `127.0.0.1` fallback, or `-` when the daemon
/// did not report one — and `--json` carries it per session as
/// `loopback_address`, with no key for a box that reported none.
#[test]
fn ls_shows_box_loopback_address() {
    let at = |address: std::net::Ipv4Addr| {
        Some(minimald_rpc::BoxNetworkFacts {
            loopback_address: Some(address),
            egress_posture: None,
            at_fallback: Some(address == std::net::Ipv4Addr::LOCALHOST),
        })
    };
    let resp = listing_of(&[
        ("own", at(std::net::Ipv4Addr::new(127, 0, 64, 2)), None),
        ("fallback", at(std::net::Ipv4Addr::LOCALHOST), None),
        ("unreported", None, None),
    ]);
    let render = |json: bool, listings: &[cmd::VmListing]| {
        let mut out = Vec::new();
        format_ls_across_vms(&mut out, &LsArgs { raw: false, json }, listings, &[], &[])
            .expect("rendering the listing");
        String::from_utf8(out).expect("the listing is UTF-8")
    };
    let one = [cmd::VmListing {
        vm: "default".to_string(),
        resp: resp.clone(),
        control_sock: None,
        running: true,
    }];

    let table = render(false, &one);
    let header = table
        .lines()
        .find(|l| l.contains("SESSION ID"))
        .expect("a header");
    assert!(
        header.find("NAME") < header.find("ADDRESS")
            && header.find("ADDRESS") < header.find("STATUS"),
        "ADDRESS sits after NAME: {header}"
    );
    let address = |name: &str| ls_cell_at(&table, name, "ADDRESS", "STATUS");
    assert_eq!(address("own"), "127.0.64.2", "got:\n{table}");
    assert_eq!(address("fallback"), "127.0.0.1", "got:\n{table}");
    assert_eq!(address("unreported"), "-", "got:\n{table}");

    let document: serde_json_lenient::Value =
        serde_json_lenient::from_str(&render(true, &one)).expect("the listing is JSON");
    let sessions = document["sessions"].as_array().expect("a sessions array");
    assert_eq!(sessions[0]["loopback_address"], "127.0.64.2");
    assert_eq!(sessions[1]["loopback_address"], "127.0.0.1");
    assert!(
        sessions[2].get("loopback_address").is_none(),
        "an unreported address is no key, never an invented value: {document}"
    );
    assert!(
        document.get("box_networks").is_none(),
        "the facts ride on each session, not beside them: {document}"
    );

    // The multi-VM document carries the same field on each session.
    let two = [
        cmd::VmListing {
            vm: "default".to_string(),
            resp: resp.clone(),
            control_sock: None,
            running: true,
        },
        cmd::VmListing {
            vm: "alpha".to_string(),
            resp: listing_of(&[("other", at(std::net::Ipv4Addr::new(127, 0, 64, 9)), None)]),
            control_sock: None,
            running: true,
        },
    ];
    let document: serde_json_lenient::Value =
        serde_json_lenient::from_str(&render(true, &two)).expect("the listing is JSON");
    let other = document["sessions"]
        .as_array()
        .expect("a sessions array")
        .iter()
        .find(|s| s["name"] == "other")
        .expect("the alpha VM's box");
    assert_eq!(other["loopback_address"], "127.0.64.9", "{document}");
    assert_eq!(other["vm"], "alpha", "{document}");
}

/// T110: the EGRESS cell `min ls` prints for a box is the posture `min
/// session policy` prints for the same box, in the same words: the named
/// verdict, `declared rules` for a section listed as rows, and the per-box
/// enforcement note for a host-address box this host cannot decide per
/// box.
#[test]
fn ls_egress_matches_session_policy() {
    use boxes::{EffectiveEgress, EgressPolicy, HostIpEnforcement, NetworkMode};
    let rules = EgressPolicy {
        allow_subnets: Some(vec!["10.0.0.0/8".to_string()]),
        allow_dns_hosts: Some(Vec::new()),
        ..EgressPolicy::default()
    };
    let cases = [
        (
            "own-default",
            EffectiveEgress::DenyAll,
            NetworkMode::OwnIp,
            None,
            "deny-all (default)",
        ),
        (
            "host-default",
            EffectiveEgress::AllowAll,
            NetworkMode::HostNet,
            Some(HostIpEnforcement::PerBox),
            "allow-all (default)",
        ),
        (
            "host-unenforced",
            EffectiveEgress::Declared(EgressPolicy::deny_all()),
            NetworkMode::HostNet,
            Some(HostIpEnforcement::None),
            "deny-all; per-box enforcement none",
        ),
        (
            "own-rules",
            EffectiveEgress::Declared(rules),
            NetworkMode::OwnIp,
            None,
            "declared rules",
        ),
    ];
    let resp = listing_of(
        &cases
            .iter()
            .map(|(name, egress, network, enforcement, _)| {
                (
                    *name,
                    Some(minimald_rpc::BoxNetworkFacts {
                        loopback_address: None,
                        egress_posture: Some(minimald_rpc::EgressPosture::of(egress, *network)),
                        at_fallback: None,
                    }),
                    *enforcement,
                )
            })
            .collect::<Vec<_>>(),
    );
    let mut out = Vec::new();
    format_ls(
        &mut out,
        &LsArgs {
            raw: false,
            json: false,
        },
        &resp,
        None,
        None,
    )
    .expect("rendering the listing");
    let table = String::from_utf8(out).expect("the listing is UTF-8");

    for (name, egress, network, enforcement, words) in cases {
        let cell = ls_cell_at(&table, name, "EGRESS", "TITLE");
        assert_eq!(cell, words, "{name}:\n{table}");
        let mut policy = Vec::new();
        format_policy(
            &mut policy,
            &boxes::EffectiveBoxPolicy {
                egress,
                ..Default::default()
            },
            network,
            enforcement,
            &[],
            None,
        )
        .expect("rendering the policy");
        let policy = String::from_utf8(policy).expect("the policy is UTF-8");
        let (posture, note) = match cell.split_once("; ") {
            Some((posture, note)) => (posture, Some(note)),
            None => (cell.as_str(), None),
        };
        if posture == "declared rules" {
            assert!(
                policy.contains("egress\n  subnets  "),
                "a declared-rules box lists its rows in the policy view:\n{policy}"
            );
        } else {
            assert!(
                policy.contains(&format!("egress\n  {posture}\n")),
                "{name}: the policy view names the same posture:\n{policy}"
            );
        }
        match note {
            Some(note) => assert_eq!(note, "per-box enforcement none"),
            None => assert!(
                !policy.contains("per-box enforcement  none"),
                "{name}: only an unenforced box carries the note:\n{policy}"
            ),
        }
        if note.is_some() {
            assert!(
                policy.contains("  per-box enforcement  none\n"),
                "{name}: the policy view states the same enforcement:\n{policy}"
            );
        }
    }
    assert!(!table.contains("per_box"), "got:\n{table}");
}

/// A stopped VM `vm` under `state`: its state dir with the persisted box
/// records `boxes` (name, id), as its VM host daemon wrote them before it
/// stopped, and a stale `ssh.sock` that no daemon listens on.
fn stopped_vm_with_boxes(state: &std::path::Path, vm: &str, boxes: &[(&str, boxes::SessionId)]) {
    let dir = state.join("providers/local-minvmd0").join(vm);
    std::fs::create_dir_all(&dir).expect("the stopped VM's dir");
    let records: Vec<serde_json_lenient::Value> = boxes
        .iter()
        .enumerate()
        .map(|(index, (name, id))| {
            serde_json_lenient::json!({
                "name": name,
                "box_id": id.to_string(),
                "switch_address": format!("100.64.0.{}", index + 9),
                "loopback_address": format!("127.0.64.{}", index + 2),
                "ingress_ports": [],
                "standing": true,
            })
        })
        .collect();
    std::fs::write(
        dir.join(minvmd::box_registry::REGISTRY_FILE),
        serde_json_lenient::to_vec(&serde_json_lenient::json!({
            "version": 1,
            "boxes": records,
        }))
        .expect("the records serialize"),
    )
    .expect("write the stopped VM's box records");
    let stale = std::os::unix::net::UnixListener::bind(dir.join("ssh.sock"))
        .expect("the stopped VM's socket path binds");
    drop(stale);
}

/// The default VM, running, under a fresh state dir: the selected VM of
/// every test below that pairs it with a stopped one.
async fn running_default_vm() -> (tempfile::TempDir, minimald::test_harness::TestServer) {
    let state = tempfile::tempdir().expect("a temp minimal state dir");
    std::fs::create_dir_all(state.path().join("providers/local-minvmd0")).expect("the host dir");
    let default_sock =
        client::resolve_socket_path_named(Some(state.path()), true, paths::DEFAULT_VM_NAME)
            .expect("the default VM's socket path");
    let default_vm = minimald::test_harness::TestServer::new().await;
    default_vm.listen_on_uds(&default_sock).await;
    (state, default_vm)
}

/// A client on the selected (default) VM's daemon under `state`.
async fn selected_client(state: &std::path::Path) -> (client::Client, std::path::PathBuf) {
    let selected = client::resolve_socket_path_named(Some(state), true, paths::DEFAULT_VM_NAME)
        .expect("the selected VM's socket path");
    let client = client::Client::connect(&selected)
        .await
        .expect("connect to the selected VM's daemon");
    (client, selected)
}

/// NET-058 for the commands that act on a named box over the daemon's RPCs:
/// `min session policy` and `min session destroy` find a box on another VM
/// by its name alone, and the client they get back is that VM's.
#[tokio::test]
async fn box_name_resolves_vm_without_flag_for_policy_and_destroy() {
    let (state, default_vm, alpha) = two_vms().await;
    create_box_on(&default_vm, "api").await;
    let beta = create_box_on(&alpha, "beta").await;
    let global = vm_globals(state.path(), None);

    for example in ["session policy beta", "session destroy beta"] {
        let (client, _) = selected_client(state.path()).await;
        let (mut owner, record) = cmd::resolve_box_on_any_vm(&global, client, "beta", example)
            .await
            .expect("a name alpha owns resolves without --vm");
        assert_eq!(record.id, beta, "{example}: alpha's record");
        let again = cmd::resolve_session(&mut owner, "beta")
            .await
            .expect("the client returned is connected to alpha");
        assert_eq!(again.id, beta, "{example}: the follow-up RPCs reach alpha");
    }
}

/// NET-058: a box name no running VM holds, on a host with two VMs, is
/// refused with the flag that names a box on another VM, shown on the
/// command the user ran. With `--vm`, the selected VM's own miss stands.
#[tokio::test]
async fn unknown_box_names_vm_flag() {
    let (state, _default_vm, _alpha) = two_vms().await;
    let global = vm_globals(state.path(), None);

    let (client, _) = selected_client(state.path()).await;
    let err = cmd::resolve_box_on_any_vm(&global, client, "beta", "session policy beta")
        .await
        .map(|(_, record)| record)
        .expect_err("no VM holds 'beta'");
    assert_eq!(
        format!("error: {err:#}"),
        "error: no running VM has a box named 'beta'. A box on another VM is named with --vm, \
         for example: min --vm <vm> session policy beta",
        "the refusal as main prints it"
    );

    // The hand-off verbs say the same, on their own command.
    let (mut client, sock) = selected_client(state.path()).await;
    let err = cmd::resolve_named_box_version_gated(
        &global,
        &mut client,
        sock,
        "beta",
        "Forwarding to",
        "net forward beta 8080:3000",
    )
    .await
    .expect_err("no VM holds 'beta'");
    assert_eq!(
        err.to_string(),
        "no running VM has a box named 'beta'. A box on another VM is named with --vm, \
         for example: min --vm <vm> net forward beta 8080:3000"
    );

    // An explicit --vm is the operator's choice: the selected VM's miss.
    let pinned = vm_globals(state.path(), Some(paths::DEFAULT_VM_NAME.to_string()));
    let (client, _) = selected_client(state.path()).await;
    let err = cmd::resolve_box_on_any_vm(&pinned, client, "beta", "session policy beta")
        .await
        .map(|(_, record)| record)
        .expect_err("no VM holds 'beta'");
    assert_eq!(err.to_string(), "No session found matching 'beta'");
}

/// NET-152: a box only a stopped VM holds is named with that VM and the
/// command that starts it, on every verb that resolves a box by name. A
/// running VM's box of the same name and the stopped VM's record are an
/// ambiguity that names both VMs.
#[tokio::test]
async fn box_on_stopped_vm_names_start_command() {
    let (state, default_vm) = running_default_vm().await;
    create_box_on(&default_vm, "api").await;
    let beta = boxes::SessionId::mint();
    stopped_vm_with_boxes(state.path(), "alpha", &[("beta", beta)]);
    let global = vm_globals(state.path(), None);
    let expected = "box 'beta' is on VM 'alpha', which is stopped. \
                    Start it with: min --vm alpha session attach beta";

    let err = attach::resolve_box_vm(&global, "beta")
        .await
        .expect_err("a box on a stopped VM is refused");
    assert_eq!(format!("error: {err:#}"), format!("error: {expected}"));

    // The attach path itself: the selected VM's miss falls through to the
    // stopped VM's records.
    let (mut client, sock) = selected_client(state.path()).await;
    let err = cmd::resolve_attach_target_version_gated(&global, &mut client, sock, "beta")
        .await
        .expect_err("attach refuses a box on a stopped VM");
    assert_eq!(err.to_string(), expected);

    // And the RPC verbs, with the policy's machine reading still a miss.
    let (client, _) = selected_client(state.path()).await;
    let err = cmd::resolve_box_on_any_vm(&global, client, "beta", "session policy beta")
        .await
        .map(|(_, record)| record)
        .expect_err("policy refuses a box on a stopped VM");
    assert_eq!(err.to_string(), expected);
    assert!(err.downcast_ref::<cmd::BoxNotFound>().is_some());

    // A name two stopped VMs hold is ambiguous, and typed so the policy's
    // machine reading reports a miss, not an unreachable daemon.
    stopped_vm_with_boxes(state.path(), "delta", &[("dup", boxes::SessionId::mint())]);
    stopped_vm_with_boxes(
        state.path(),
        "epsilon",
        &[("dup", boxes::SessionId::mint())],
    );
    let (client, _) = selected_client(state.path()).await;
    let err = cmd::resolve_box_on_any_vm(&global, client, "dup", "session policy dup")
        .await
        .map(|(_, record)| record)
        .expect_err("a name two stopped VMs hold is ambiguous");
    assert_eq!(
        err.to_string(),
        "box name 'dup' exists on more than one stopped VM (delta, epsilon); \
         name the one you mean with --vm"
    );
    assert!(err.downcast_ref::<cmd::AmbiguousBoxName>().is_some());

    // A name a running VM owns and a stopped VM's records hold is ambiguous,
    // though the running box is active: the error lists both VMs, marks the
    // stopped one, and names --vm.
    stopped_vm_with_boxes(state.path(), "gamma", &[("api", boxes::SessionId::mint())]);
    let err = attach::resolve_box_vm(&global, "api")
        .await
        .expect_err("a running owner and a stopped holder are ambiguous");
    assert_eq!(
        err.to_string(),
        "box name 'api' exists on more than one VM (default, gamma (stopped)); \
         name the one you mean with --vm"
    );
    assert!(err.downcast_ref::<cmd::AmbiguousBoxName>().is_some());

    // A stopped record on the running VM and a stopped VM that holds the
    // name are ambiguous: the error lists both VMs, marks the stopped one,
    // and names --vm.
    let web = create_box_on(&default_vm, "web").await;
    stopped_vm_with_boxes(state.path(), "zeta", &[("web", boxes::SessionId::mint())]);
    let mut rpc = default_vm.connect().await;
    match rpc
        .call::<minimald_rpc::StopBox>(&minimald_rpc::StopBoxRequest {
            id: web,
            force: true,
        })
        .await
    {
        minimald_rpc::Errorable::Ok(_) => {}
        minimald_rpc::Errorable::Err { error } => panic!("StopBox failed: {error}"),
    }
    let err = attach::resolve_box_vm(&global, "web")
        .await
        .expect_err("a stopped owner and a stopped holder are ambiguous");
    assert_eq!(
        err.to_string(),
        "box name 'web' exists on more than one VM (default, zeta (stopped)); \
         name the one you mean with --vm"
    );
    assert!(err.downcast_ref::<cmd::AmbiguousBoxName>().is_some());

    // The selected VM is the only holder: it resolves there.
    create_box_on(&default_vm, "solo").await;
    let (client, _) = selected_client(state.path()).await;
    let (_, record) = cmd::resolve_box_on_any_vm(&global, client, "solo", "session policy solo")
        .await
        .expect("the selected VM's own box resolves");
    assert_eq!(record.name.as_deref(), Some("solo"));

    // A hit on the selected VM is ambiguous when a stopped VM also holds the
    // name.
    let (client, _) = selected_client(state.path()).await;
    let err = cmd::resolve_box_on_any_vm(&global, client, "api", "session policy api")
        .await
        .map(|(_, record)| record)
        .expect_err("the selected VM and a stopped VM both hold 'api'");
    assert_eq!(
        err.to_string(),
        "box name 'api' exists on more than one VM (default, gamma (stopped)); \
         name the one you mean with --vm"
    );

    // A name wins over an id prefix across VMs, as on one daemon: a running
    // box named 'cafe' resolves though a stopped VM holds a box whose id
    // starts with 'cafe'.
    create_box_on(&default_vm, "cafe").await;
    let mut cafe_id = [0x11; 16];
    cafe_id[0] = 0xca;
    cafe_id[1] = 0xfe;
    stopped_vm_with_boxes(
        state.path(),
        "eta",
        &[("other", boxes::SessionId::from_bytes(cafe_id))],
    );
    let resolved = attach::resolve_box_vm(&global, "cafe")
        .await
        .expect("a name match is not ambiguous with an id prefix")
        .expect("the running VM owns 'cafe'");
    assert_eq!(resolved.vm, "default");
    assert_eq!(resolved.record.name.as_deref(), Some("cafe"));
}

/// NET-058: a name the selected VM holds is ambiguous when a second running
/// VM holds it too. `min session destroy` and `min session attach` refuse it,
/// name both VMs and `--vm`, and do not act on the selected VM's box. With
/// `--vm`, the selected VM's box resolves.
#[tokio::test]
async fn box_name_resolves_vm_without_flag_refuses_a_name_two_vms_hold() {
    let (state, default_vm, alpha) = two_vms().await;
    let shared = create_box_on(&default_vm, "shared").await;
    create_box_on(&alpha, "shared").await;
    let global = vm_globals(state.path(), None);
    let expected = "box name 'shared' exists on more than one VM (default, alpha); \
                    name the one you mean with --vm";

    let (client, _) = selected_client(state.path()).await;
    let err = cmd::resolve_box_on_any_vm(&global, client, "shared", "session destroy shared")
        .await
        .map(|(_, record)| record)
        .expect_err("destroy refuses a name two VMs hold");
    assert_eq!(err.to_string(), expected);
    assert!(err.downcast_ref::<cmd::AmbiguousBoxName>().is_some());

    let (mut client, sock) = selected_client(state.path()).await;
    let err = cmd::resolve_attach_target_version_gated(&global, &mut client, sock, "shared")
        .await
        .expect_err("attach refuses a name two VMs hold");
    assert_eq!(err.to_string(), expected);
    assert!(err.downcast_ref::<cmd::AmbiguousBoxName>().is_some());

    // The selected VM's box is still there: nothing acted on it.
    let (mut client, _) = selected_client(state.path()).await;
    let record = cmd::resolve_session(&mut client, "shared")
        .await
        .expect("the selected VM still holds 'shared'");
    assert_eq!(record.id, shared);

    // With --vm, the operator chose: the selected VM's box resolves.
    let pinned = vm_globals(state.path(), Some(paths::DEFAULT_VM_NAME.to_string()));
    let (client, _) = selected_client(state.path()).await;
    let (_, record) =
        cmd::resolve_box_on_any_vm(&pinned, client, "shared", "session destroy shared")
            .await
            .expect("--vm picks the selected VM's box");
    assert_eq!(record.id, shared);
}

/// NET-152: `min ls` lists a stopped VM's boxes from its persisted records:
/// each row's STATUS reads `stopped` and its VM cell `alpha (stopped)`, the
/// table rule runs under the VM column, and `--json` carries the boxes with
/// `"status": "stopped"` and `"vm_running": false`.
#[tokio::test]
async fn ls_lists_boxes_on_stopped_vm() {
    let (state, default_vm) = running_default_vm().await;
    let api = create_box_on(&default_vm, "api").await;
    let beta = boxes::SessionId::mint();
    stopped_vm_with_boxes(state.path(), "alpha", &[("beta", beta)]);
    // A stopped VM with no boxes adds no listing.
    stopped_vm_with_boxes(state.path(), "empty", &[]);
    let global = vm_globals(state.path(), None);

    let listings = cmd::ls_listings(&global)
        .await
        .expect("listing past a stopped VM succeeds");
    assert_eq!(listings.len(), 2, "the running VM and the stopped one");
    assert_eq!(listings[0].vm, "default");
    assert!(listings[0].running);
    assert_eq!(listed_names(&listings[0]), ["api"]);
    assert_eq!(listings[1].vm, "alpha");
    assert!(!listings[1].running, "alpha is stopped");
    assert_eq!(listed_names(&listings[1]), ["beta"]);
    assert_eq!(listings[1].resp.sessions[0].id, beta);
    assert_eq!(
        listings[1].resp.sessions[0].status,
        boxes::BoxState::Stopped
    );

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
    .expect("the table renders");
    let table = String::from_utf8(out).expect("UTF-8");
    let lines: Vec<&str> = table.lines().collect();
    let header = lines
        .iter()
        .position(|line| line.starts_with("VM "))
        .expect("the table header");
    assert!(
        lines[header + 1].starts_with("---------------  "),
        "the rule runs under the VM column, as wide as its widest cell:\n{table}"
    );
    let beta_row = lines
        .iter()
        .find(|line| line.contains(&beta.to_string()))
        .expect("alpha's box has a row");
    assert!(
        beta_row.starts_with("alpha (stopped)  "),
        "the VM cell says the VM is stopped: {beta_row:?}"
    );
    assert!(
        beta_row.split_whitespace().any(|cell| cell == "stopped"),
        "STATUS reads stopped: {beta_row:?}"
    );
    let api_row = lines
        .iter()
        .find(|line| line.contains(&api.to_string()))
        .expect("the running VM's box has a row");
    assert!(
        api_row.starts_with("default          "),
        "a running VM's cell is its name alone, padded to the column: {api_row:?}"
    );

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
    .expect("the JSON renders");
    let document: serde_json_lenient::Value =
        serde_json_lenient::from_slice(&out).expect("one JSON document");
    let sessions = document["sessions"].as_array().expect("a sessions array");
    let beta_entry = sessions
        .iter()
        .find(|entry| entry["name"] == "beta")
        .expect("alpha's box is in the document");
    assert_eq!(beta_entry["status"], "stopped");
    assert_eq!(beta_entry["vm"], "alpha");
    assert_eq!(beta_entry["vm_running"], false);
    let api_entry = sessions
        .iter()
        .find(|entry| entry["name"] == "api")
        .expect("the running VM's box is in the document");
    assert_eq!(api_entry["vm_running"], true);
}

/// NET-152: an attach that fails once the relay holds the terminal ends
/// `min session attach` with an error that `main` prints after the attach
/// returns. By then the relay put the attach-start termios back and the
/// unwind codes are on the terminal, so the error prints after them and
/// stays on screen. A relay that never took the terminal writes nothing.
#[test]
fn attach_error_printed_after_terminal_restore() {
    use std::cell::RefCell;
    use std::rc::Rc;

    /// The user's terminal: everything written to it, in order.
    #[derive(Clone, Default)]
    struct Screen(Rc<RefCell<Vec<u8>>>);
    impl std::io::Write for Screen {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.borrow_mut().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let screen = Screen::default();
    let err = interactive_attach(
        std::process::Command::new("ssh"),
        true,
        || attach::TerminalUnwind::arm_on(screen.clone(), true),
        |_| Err(anyhow::anyhow!("the relay lost the terminal mid-session")),
    )
    .expect_err("a failed relay ends the attach with an error");
    assert!(
        screen.0.borrow().ends_with(b"\x1b[?1004l"),
        "the unwind is on the terminal before the attach returns"
    );
    // What main prints for the error, on the same terminal.
    let printed = format!("error: {err:#}\n");
    std::io::Write::write_all(&mut screen.clone(), printed.as_bytes()).expect("print");
    let seen = screen.0.borrow().clone();
    let at = seen
        .windows(printed.len())
        .position(|window| window == printed.as_bytes())
        .expect("the error is on the terminal");
    assert!(
        seen[..at].ends_with(b"\x1b[?1004l"),
        "the error prints after the restore sequence: {:?}",
        String::from_utf8_lossy(&seen)
    );
    assert_eq!(at + printed.len(), seen.len(), "nothing writes after it");

    // A relay that never took the terminal never changed it.
    let untouched = Screen::default();
    interactive_attach(
        std::process::Command::new("ssh"),
        true,
        || attach::TerminalUnwind::arm_on(untouched.clone(), true),
        |_| {
            Err(anyhow::Error::new(std::io::Error::other("no tty"))
                .context(attach::TerminalNotTaken))
        },
    )
    .expect_err("an attach with no terminal fails");
    assert!(
        untouched.0.borrow().is_empty(),
        "no unwind for a terminal the attach never took"
    );

    // A relay that took the terminal and then failed to start ssh's session
    // on it (ssh does not spawn) never let the session reach the terminal.
    // The relay drops its suspend hook unrun, so the failure is marked, and
    // the guard writes nothing. The error prints as the relay wrote it.
    let not_started = Screen::default();
    let err = interactive_attach(
        std::process::Command::new("ssh"),
        true,
        || attach::TerminalUnwind::arm_on(not_started.clone(), true),
        |_| {
            mark_relay_not_started(None, |_hook| {
                Err(
                    anyhow::Error::new(std::io::Error::other("No such file or directory"))
                        .context("spawning the ssh attach"),
                )
            })
        },
    )
    .expect_err("an attach whose ssh does not spawn fails");
    assert!(
        not_started.0.borrow().is_empty(),
        "no unwind for a relay that never started the session: {:?}",
        String::from_utf8_lossy(&not_started.0.borrow())
    );
    assert_eq!(
        format!("{err:#}"),
        "failed to run ssh: spawning the ssh attach: No such file or directory"
    );
}

/// NET-154: the HOSTNAME PROXY row names every host port the VM's proxy
/// serves on, the preferred first, and `--json` carries them as
/// `hostname_proxy_ports`. One served port prints the row it always did.
#[tokio::test]
async fn ls_reports_every_proxy_port() {
    let mut resp = listing_of(&[("web", None, None)]);
    resp.hostname_proxy_port = Some(65264);
    let render = |json: bool, ports: &[u16]| {
        let mut out = Vec::new();
        cmd::format_ls_with_proxy_ports_on(
            &mut out,
            &LsArgs { raw: false, json },
            &resp,
            None,
            None,
            ports,
            crate::resolver::HostInstall::default(),
        )
        .expect("rendering the listing");
        String::from_utf8(out).expect("the listing is UTF-8")
    };
    let proxy_rows = |text: &str| {
        text.lines()
            .filter(|line| line.starts_with("HOSTNAME PROXY:"))
            .map(str::to_string)
            .collect::<Vec<_>>()
    };

    // One port: the row as it always was, read or not.
    let one = "HOSTNAME PROXY:  listening on 127.0.0.1:65264 as the HTTP proxy for \
               <box>.min.internal names";
    assert_eq!(proxy_rows(&render(false, &[65264])), vec![one]);
    assert_eq!(proxy_rows(&render(false, &[])), vec![one]);

    // Both ports serve: one row names both, the preferred first.
    assert_eq!(
        proxy_rows(&render(false, &[7654, 65264])),
        vec![
            "HOSTNAME PROXY:  listening on 127.0.0.1:7654 and 127.0.0.1:65264 as the HTTP \
             proxy for <box>.min.internal names"
        ]
    );

    // The JSON field.
    let json = |ports: &[u16]| -> serde_json_lenient::Value {
        serde_json_lenient::from_str(&render(true, ports)).expect("the listing is JSON")
    };
    assert_eq!(
        json(&[7654, 65264])["hostname_proxy_ports"],
        serde_json_lenient::json!([7654, 65264])
    );
    assert_eq!(
        json(&[65264])["hostname_proxy_ports"],
        serde_json_lenient::json!([65264])
    );
    assert!(json(&[]).get("hostname_proxy_ports").is_none());

    // The VM host daemon reports no ports while the proxy is down, so a
    // down proxy reaches `--json` as an empty served list and names no port.
    let down = json(&[]);
    assert!(down.get("hostname_proxy_ports").is_none());

    // Two VMs: each VM's row names its own ports.
    let listing = |vm: &str, port: u16| cmd::VmListing {
        vm: vm.to_string(),
        resp: {
            let mut resp = resp.clone();
            resp.hostname_proxy_port = Some(port);
            resp
        },
        control_sock: None,
        running: true,
    };
    let listings = [listing("default", 65264), listing("other", 7700)];
    let across = |json: bool| {
        let mut out = Vec::new();
        cmd::format_ls_across_vms_with_proxy_ports_on(
            &mut out,
            &LsArgs { raw: false, json },
            &listings,
            &[],
            &[],
            &[vec![7654, 65264], vec![7700]],
            crate::resolver::HostInstall::default(),
        )
        .expect("rendering the listing");
        String::from_utf8(out).expect("the listing is UTF-8")
    };
    assert_eq!(
        proxy_rows(&across(false)),
        vec![
            "HOSTNAME PROXY:  default  listening on 127.0.0.1:7654 and 127.0.0.1:65264 as \
             the HTTP proxy for <box>.min.internal names",
            "HOSTNAME PROXY:  other    listening on 127.0.0.1:7700 as the HTTP proxy for \
             <box>.min.internal names",
        ]
    );
    let doc: serde_json_lenient::Value =
        serde_json_lenient::from_str(&across(true)).expect("the listing is JSON");
    assert_eq!(
        doc["vms"][0]["hostname_proxy_ports"],
        serde_json_lenient::json!([7654, 65264])
    );
    assert_eq!(
        doc["vms"][1]["hostname_proxy_ports"],
        serde_json_lenient::json!([7700])
    );

    // The read over the VM host daemon's control socket.
    let dir = tempfile::tempdir().expect("tempdir");
    let sock = dir.path().join("control.sock");
    let listener = tokio::net::UnixListener::bind(&sock).expect("bind the control socket");
    let server = tokio::spawn(async move {
        use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _};
        let (mut stream, _) = listener.accept().await.expect("accept");
        let mut line = String::new();
        tokio::io::BufReader::new(&mut stream)
            .read_line(&mut line)
            .await
            .expect("read the request");
        stream
            .write_all(b"{\"proxy_ports\":[7654,65264]}\n")
            .await
            .expect("write the reply");
        line
    });
    assert_eq!(
        cmd::vm_host_proxy_ports_at(Some(sock)).await,
        vec![7654, 65264]
    );
    let request = server.await.expect("the server ends");
    assert_eq!(request.trim(), r#"{"verb":"proxy_ports"}"#);
    assert!(cmd::vm_host_proxy_ports_at(None).await.is_empty());
}

/// A state dir with the given `providers/<dir>` host directories.
fn state_with_host_dirs(dirs: &[&str]) -> tempfile::TempDir {
    let state = tempfile::tempdir().expect("a temp minimal state dir");
    for dir in dirs {
        std::fs::create_dir_all(state.path().join("providers").join(dir)).expect("the host dir");
    }
    state
}

/// Globals that resolve every path under `state`.
fn host_globals(state: &std::path::Path) -> GlobalArgs {
    GlobalArgs {
        minimal_dir: Some(state.to_path_buf()),
        ..GlobalArgs::default()
    }
}

/// A stale socket file at `sock`, with nothing listening on it: what a
/// stopped daemon leaves behind.
fn stale_socket(sock: &std::path::Path) {
    let listener = std::os::unix::net::UnixListener::bind(sock).expect("the socket path binds");
    drop(listener);
}

/// BCLI-046: the well-known local providers are `local`, `local-minvmd` and
/// `local-box`, and each host is named after its daemon instance. A named
/// VM nested in a VM host is a host of its own, named by its ssh host alias.
/// A directory that is no daemon instance, or no valid VM name, is no host.
#[test]
fn local_provider_and_host_names() {
    use cmd::hosts::{LocalProvider, local_hosts};
    assert_eq!(
        LocalProvider::ALL.map(LocalProvider::name),
        ["local", "local-minvmd", "local-box"]
    );
    let state = state_with_host_dirs(&[
        "local-minimald1",
        "local-minimald01",
        "local-minimald0",
        "local-minvmd0",
        "local-minvmd00",
        "local-minvmd0/alpha",
        "local-minvmd0/Not_A_VM",
        "local-minvmd0/guest",
        "local-minvmd0/default",
        "local-minimald0/beta",
        "remote-x",
        "local-minimald",
    ]);
    let hosts = local_hosts(Some(state.path())).expect("the hosts read");
    let named: Vec<_> = hosts
        .iter()
        .map(|h| (h.name.as_str(), h.provider.name()))
        .collect();
    assert_eq!(
        named,
        [
            ("local0", "local"),
            ("local1", "local"),
            ("local-minvmd0", "local-minvmd"),
            ("alpha.local-minvmd0", "local-minvmd"),
        ]
    );
    assert_eq!(
        hosts[0].socket(),
        state.path().join("providers/local-minimald0/ssh.sock")
    );
    assert_eq!(
        hosts[3].socket(),
        state.path().join("providers/local-minvmd0/alpha/ssh.sock")
    );

    use clap::Parser as _;
    let cli = Cli::try_parse_from(["min", "--provider", "local", "ls"]).unwrap();
    assert_eq!(cli.global_args.provider, Some(Provider::Local));
    assert!(!cli.global_args.use_minvmd());
}

/// BCLI-046: `--provider local-minimald` reads as `local`, prints its hint,
/// and no longer shows among the values `--provider` offers.
#[test]
fn local_minimald_alias_reads_as_local() {
    use clap::Parser as _;
    use clap::ValueEnum as _;
    let mut cli = Cli::try_parse_from(["min", "--provider", "local-minimald", "ls"]).unwrap();
    let hint = cmd::hosts::read_provider_alias(&mut cli.global_args);
    assert_eq!(hint, Some("local-minimald is now called local."));
    assert_eq!(cli.global_args.provider, Some(Provider::Local));
    assert!(!cli.global_args.use_minvmd());

    for provider in ["local", "local-minvmd"] {
        let mut cli = Cli::try_parse_from(["min", "--provider", provider, "ls"]).unwrap();
        assert_eq!(
            cmd::hosts::read_provider_alias(&mut cli.global_args),
            None,
            "{provider} is no alias"
        );
    }
    let mut cli = Cli::try_parse_from(["min", "ls"]).unwrap();
    assert_eq!(cmd::hosts::read_provider_alias(&mut cli.global_args), None);

    let shown: Vec<String> = Provider::value_variants()
        .iter()
        .filter_map(Provider::to_possible_value)
        .filter(|v| !v.is_hide_set())
        .map(|v| v.get_name().to_owned())
        .collect();
    assert_eq!(shown, ["local", "local-minvmd"]);

    // A failed run in a machine output mode carries the hint in the error
    // object's `hint` field, after any hint the failure has.
    let hint = "local-minimald is now called local.";
    let failure = MachineModeFailure::new("not_found", "no box 'x'".into(), String::new());
    assert_eq!(failure.with_alias_hint(hint).hint(), hint);
    let failure = MachineModeFailure::new("not_found", "no box 'x'".into(), "run `min ls`".into());
    assert_eq!(
        failure.with_alias_hint(hint).hint(),
        "run `min ls`. local-minimald is now called local."
    );
}

/// BCLI-047: `min host list` renders each local host with its name and
/// state: a daemon that answers is running, a stale socket is stopped.
#[tokio::test]
async fn host_list_name_and_state() {
    let state = state_with_host_dirs(&["local-minimald0", "local-minvmd0"]);
    let server = minimald::test_harness::TestServer::new().await;
    server
        .listen_on_uds(&state.path().join("providers/local-minimald0/ssh.sock"))
        .await;
    stale_socket(&state.path().join("providers/local-minvmd0/ssh.sock"));

    let mut out = Vec::new();
    cmd::hosts::cmd_host_list(&host_globals(state.path()), &mut out)
        .await
        .expect("host list runs");
    let text = String::from_utf8(out).unwrap();
    assert_eq!(
        text,
        "HOST             PROVIDER       STATE\n\
         local0           local          running\n\
         local-minvmd0    local-minvmd   stopped\n"
    );

    let empty = tempfile::tempdir().unwrap();
    let mut out = Vec::new();
    cmd::hosts::cmd_host_list(&host_globals(empty.path()), &mut out)
        .await
        .expect("host list runs with no host");
    assert_eq!(
        String::from_utf8(out).unwrap(),
        "No local host on this machine yet.\n"
    );
}

/// BCLI-047: a VM host directory that cannot be read keeps its host in
/// `min host list`, and the list and `min host show` say its named VMs
/// were not read, in place of hiding them.
#[tokio::test]
async fn host_list_name_and_state_notes_unread_vms() {
    use std::os::unix::fs::PermissionsExt as _;
    let state = state_with_host_dirs(&["local-minvmd0/alpha"]);
    let vm_host = state.path().join("providers/local-minvmd0");
    let note = format!(
        "The named VMs of local-minvmd0 are not listed, because {} cannot be read: denied.",
        vm_host.display()
    );
    let host = cmd::hosts::LocalHost {
        name: "local-minvmd0".into(),
        provider: cmd::hosts::LocalProvider::LocalMinvmd,
        instance: 0,
        vm: None,
        dir: vm_host.clone(),
        unread_vms: Some("denied".into()),
    };
    assert_eq!(cmd::hosts::unread_vm_notes(&[host]), [note]);

    std::fs::set_permissions(&vm_host, std::fs::Permissions::from_mode(0o000)).unwrap();
    let readable = std::fs::read_dir(&vm_host).is_ok();
    let restore =
        || std::fs::set_permissions(&vm_host, std::fs::Permissions::from_mode(0o755)).unwrap();
    if readable {
        // Root reads the directory whatever its mode, so nothing fails here.
        restore();
        return;
    }
    let mut out = Vec::new();
    let listed = cmd::hosts::cmd_host_list(&host_globals(state.path()), &mut out).await;
    let shown = cmd::hosts::cmd_host_show(
        &host_globals(state.path()),
        &crate::cli::HostShowArgs {
            host: "alpha.local-minvmd0".into(),
        },
        &mut Vec::new(),
    )
    .await;
    restore();
    listed.expect("host list runs");
    let text = String::from_utf8(out).unwrap();
    assert!(
        text.contains("\nlocal-minvmd0    local-minvmd   "),
        "{text}"
    );
    assert!(
        text.contains("The named VMs of local-minvmd0 are not listed, because"),
        "{text}"
    );
    let err = format!("{:#}", shown.expect_err("an unread VM is no host"));
    assert!(
        err.contains("The named VMs of local-minvmd0 are not listed"),
        "{err}"
    );
}

/// BCLI-048: `min host show <host>` adds the host-side socket path and the
/// daemon version. A stopped host has no version to show, and a name no
/// host has is refused with the command that lists them.
#[tokio::test]
async fn host_show_socket_and_version() {
    let state = state_with_host_dirs(&["local-minimald0", "local-minvmd0"]);
    let sock = state.path().join("providers/local-minimald0/ssh.sock");
    let server = minimald::test_harness::TestServer::new().await;
    server.listen_on_uds(&sock).await;
    let version = {
        let mut client = client::Client::connect(&sock).await.expect("connect");
        client
            .oneshot_rpc::<minimald_rpc::GetVersion>(())
            .await
            .expect("GetVersion")
            .long_version
    };
    let stopped_sock = state.path().join("providers/local-minvmd0/ssh.sock");
    stale_socket(&stopped_sock);
    let global = host_globals(state.path());

    let mut out = Vec::new();
    let args = HostShowArgs {
        host: "local0".to_owned(),
    };
    cmd::hosts::cmd_host_show(&global, &args, &mut out)
        .await
        .expect("host show runs");
    assert_eq!(
        String::from_utf8(out).unwrap(),
        format!(
            "Host:            local0\n\
             Provider:        local\n\
             State:           running\n\
             Socket:          {}\n\
             Daemon version:  {version}\n",
            sock.display()
        )
    );

    let mut out = Vec::new();
    let args = HostShowArgs {
        host: "local-minvmd0".to_owned(),
    };
    cmd::hosts::cmd_host_show(&global, &args, &mut out)
        .await
        .expect("host show runs on a stopped host");
    let text = String::from_utf8(out).unwrap();
    assert!(text.contains("State:           stopped\n"), "{text}");
    assert!(
        text.contains(&format!("Socket:          {}\n", stopped_sock.display())),
        "{text}"
    );
    assert!(
        text.contains("Daemon version:  unknown, because the daemon is not running\n"),
        "{text}"
    );

    // A daemon that does not answer can still run, so the text does not say
    // that it is not running.
    let unanswered = cmd::hosts::HostDetail {
        name: "local-minvmd0".to_owned(),
        provider: "local-minvmd",
        state: cmd::hosts::HostState::Unreachable,
        socket: stopped_sock.clone(),
        daemon_version: None,
    };
    let mut out = Vec::new();
    cmd::output::Rendered::text(&unanswered, &mut out).unwrap();
    let text = String::from_utf8(out).unwrap();
    assert!(text.contains("State:           not responding\n"), "{text}");
    assert!(
        text.contains("Daemon version:  unknown, because the daemon did not answer\n"),
        "{text}"
    );

    let args = HostShowArgs {
        host: "local-minimald0".to_owned(),
    };
    let err = cmd::hosts::cmd_host_show(&global, &args, &mut Vec::new())
        .await
        .expect_err("the state dir name is no host name");
    assert_eq!(
        err.to_string(),
        "no local host is named 'local-minimald0'. Run `min host list` to see the local hosts."
    );
}

/// BCLI-049: `min host stop --force` force-stops each running box on the
/// host, then stops its daemon. Each box gets the forced stop, and none the
/// graceful one. The daemon then refuses box work, because it is shutting
/// down. The last line says what stopped.
#[tokio::test]
async fn host_stop_force_forces_boxes_and_daemon() {
    let log = minimald::test_harness::captured_log();
    let state = state_with_host_dirs(&["local-minimald0"]);
    let sock = state.path().join("providers/local-minimald0/ssh.sock");
    let server = minimald::test_harness::TestServer::new().await;
    server.listen_on_uds(&sock).await;
    let project = tempfile::TempDir::new().unwrap();
    let mut daemon = server.connect().await;
    for name in ["web", "api"] {
        minimald::test_harness::create_configured_session(
            &mut daemon,
            name,
            project.path().to_str().unwrap(),
        )
        .await;
    }
    let ids: Vec<(String, boxes::SessionId)> = {
        let mut client = client::Client::connect(&sock).await.expect("connect");
        list_box_records(&mut client, None)
            .await
            .unwrap()
            .into_iter()
            .map(|entry| (entry.name.unwrap_or_default(), entry.box_id))
            .collect()
    };
    assert_eq!(ids.len(), 2, "{ids:?}");
    assert!(!server.state.sessions_manager().await.is_shutting_down());

    let mut out = Vec::new();
    let args = HostStopArgs {
        host: "local0".to_owned(),
        force: true,
    };
    cmd::hosts::cmd_host_stop(&host_globals(state.path()), &args, &mut out)
        .await
        .expect("host stop --force runs");
    let text = String::from_utf8(out).unwrap();
    let mut lines: Vec<&str> = text.lines().collect();
    assert_eq!(
        lines.pop(),
        Some("Stopped 2 boxes and the daemon on local0."),
        "{text}"
    );
    lines.sort_unstable();
    assert_eq!(lines, ["Stopped api.", "Stopped web."], "{text}");

    // Each box got the forced stop of BOX-013, and no graceful one.
    let log = log.contents();
    let served = |id: boxes::SessionId, force: bool| {
        log.lines()
            .filter(|line| {
                line.contains("session stopped")
                    && line.contains(&format!("session_id={id}"))
                    && line.contains(&format!("force={force}"))
            })
            .count()
    };
    for (name, id) in &ids {
        assert_eq!(served(*id, true), 1, "{name}: {log}");
        assert_eq!(served(*id, false), 0, "{name}: {log}");
    }

    // The daemon is shutting down.
    assert!(
        server.state.sessions_manager().await.is_shutting_down(),
        "the daemon is shutting down after host stop"
    );

    // A VM host's line names its VM too, and one box is one box.
    assert_eq!(
        cmd::hosts::host_stop_summary(1, "local-minvmd0", true),
        "Stopped 1 box, the daemon and its VM on local-minvmd0."
    );
    assert_eq!(
        cmd::hosts::host_stop_summary(3, "local-minvmd0", true),
        "Stopped 3 boxes, the daemon and its VM on local-minvmd0."
    );
}

/// BCLI-049: `min host stop --force` on a VM host whose daemon connects but
/// never answers stops the VM from this machine. It does not wait on a box
/// listing first, and it exits 0. Without `--force` the command refuses with
/// exit 7, as `min stop` does for a host that does not answer, and names
/// `--force`.
#[tokio::test]
async fn host_stop_force_forces_boxes_and_daemon_when_daemon_does_not_answer() {
    let state = state_with_host_dirs(&["local-minvmd0"]);
    let sock = state.path().join("providers/local-minvmd0/ssh.sock");
    // Accepts each connection and holds it open, and never writes a byte.
    let listener = tokio::net::UnixListener::bind(&sock).expect("the socket binds");
    let holder = tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((stream, _)) = listener.accept().await {
            held.push(stream);
        }
    });

    let started = std::time::Instant::now();
    let mut out = Vec::new();
    let args = HostStopArgs {
        host: "local-minvmd0".to_owned(),
        force: true,
    };
    cmd::hosts::cmd_host_stop(&host_globals(state.path()), &args, &mut out)
        .await
        .expect("host stop --force stops the VM of a daemon that does not answer");
    // The VM dir has no running VM, so the host-side stop signals nothing.
    assert_eq!(
        String::from_utf8(out).unwrap(),
        "local-minvmd0 is not running.\n"
    );
    // The probe's budget, and no RPC timeout on a listing after it.
    assert!(
        started.elapsed() < client::RPC_TIMEOUT,
        "took {:?}",
        started.elapsed()
    );

    let args = HostStopArgs {
        host: "local-minvmd0".to_owned(),
        force: false,
    };
    let err = cmd::hosts::cmd_host_stop(&host_globals(state.path()), &args, &mut Vec::new())
        .await
        .expect_err("host stop without --force refuses a daemon that does not answer");
    assert!(
        err.downcast_ref::<client::box_registration::HostUnreachable>()
            .is_some(),
        "{err:#}"
    );
    assert!(
        format!("{err:#}").contains("Run `min host stop local-minvmd0 --force`"),
        "{err:#}"
    );
    holder.abort();
}

/// BCLI-049: only a timeout or a lost connection is a daemon that did not
/// answer. A refusal the daemon sent, a failure it reported and a failed
/// write of the output are not.
#[test]
fn host_stop_force_forces_boxes_and_daemon_tells_no_answer_from_an_answer() {
    let timed_out =
        anyhow::anyhow!("StopBox RPC timed out after 60s").context("StopBox RPC failed");
    assert!(cmd::rpc_unanswered(&timed_out));
    let lost = anyhow::Error::new(russh::Error::Disconnect)
        .context("open channel for StopBox")
        .context("StopBox RPC failed");
    assert!(cmd::rpc_unanswered(&lost));
    let closed = anyhow::anyhow!("decode response for ListBoxes (daemon replied: )");
    assert!(cmd::rpc_unanswered(&closed));

    let refused = anyhow::anyhow!("the box is still starting");
    assert!(!cmd::rpc_unanswered(&refused));
    let gone = anyhow::Error::new(BoxAddressRefusal::NotFound {
        address: "web".to_owned(),
    });
    assert!(!cmd::rpc_unanswered(&gone));
    let daemon_side = anyhow::anyhow!("StopBox RPC failed on the daemon side: boom")
        .context("StopBox RPC failed");
    assert!(!cmd::rpc_unanswered(&daemon_side));
    let write = anyhow::Error::new(std::io::Error::from(std::io::ErrorKind::BrokenPipe));
    assert!(!cmd::rpc_unanswered(&write));
}

/// BCLI-049: the lines `min host stop --force` prints for a box it did not
/// stop. A box ended with its VM only when it got no answer or was skipped,
/// and only when the VM stop worked.
#[test]
fn host_stop_force_forces_boxes_and_daemon_names_each_box_it_did_not_stop() {
    use cmd::hosts::{BoxNotStopped, box_not_stopped_line};
    let host = "local-minvmd0";
    assert_eq!(
        box_not_stopped_line("web", host, &BoxNotStopped::Unanswered, true),
        "web did not answer the stop. It ended when its VM stopped."
    );
    assert_eq!(
        box_not_stopped_line("web", host, &BoxNotStopped::Unanswered, false),
        "web did not answer the stop."
    );
    let skipped = BoxNotStopped::Skipped {
        after: "web".to_owned(),
    };
    assert_eq!(
        box_not_stopped_line("api", host, &skipped, true),
        "api was not asked to stop, because web did not answer the stop. \
         It ended when its VM stopped."
    );
    assert_eq!(
        box_not_stopped_line("api", host, &skipped, false),
        "api was not asked to stop, because web did not answer the stop."
    );
    assert_eq!(
        box_not_stopped_line("web", host, &BoxNotStopped::Gone, true),
        "web was not stopped, because it is no longer on local-minvmd0."
    );
    let refused = BoxNotStopped::Refused("the box is still starting".to_owned());
    assert_eq!(
        box_not_stopped_line("web", host, &refused, true),
        "web was not stopped. The daemon on local-minvmd0 answered: the box is still starting"
    );
}

/// BCLI-052: `min provider list --all` lists every well-known local provider
/// present on the machine: a provider with a host, and `local-box` only in a
/// box. Without `--all` it lists the provider the command selects.
#[test]
fn provider_list_all_shows_local_providers() {
    let state = state_with_host_dirs(&["local-minimald0", "local-minvmd0", "local-minvmd1"]);
    let global = host_globals(state.path());

    let mut out = Vec::new();
    cmd::hosts::provider_list(&global, true, false, &mut out).expect("provider list runs");
    assert_eq!(
        String::from_utf8(out).unwrap(),
        "PROVIDER       HOSTS\n\
         local          local0\n\
         local-minvmd   local-minvmd0, local-minvmd1\n"
    );

    let mut out = Vec::new();
    cmd::hosts::provider_list(&global, true, true, &mut out).expect("provider list runs");
    assert!(
        String::from_utf8(out)
            .unwrap()
            .ends_with("local-box      -\n"),
        "local-box is present in a box"
    );

    let vm_only = state_with_host_dirs(&["local-minvmd0"]);
    let mut out = Vec::new();
    cmd::hosts::provider_list(&host_globals(vm_only.path()), true, false, &mut out)
        .expect("provider list runs");
    assert_eq!(
        String::from_utf8(out).unwrap(),
        "PROVIDER       HOSTS\n\
         local-minvmd   local-minvmd0\n"
    );

    let mut vm_global = host_globals(state.path());
    vm_global.provider = Some(Provider::LocalMinvmd);
    let mut out = Vec::new();
    cmd::hosts::provider_list(&vm_global, false, false, &mut out).expect("provider list runs");
    assert_eq!(
        String::from_utf8(out).unwrap(),
        "PROVIDER       HOSTS\n\
         local-minvmd   local-minvmd0, local-minvmd1\n"
    );

    let empty = tempfile::tempdir().unwrap();
    let mut out = Vec::new();
    cmd::hosts::provider_list(&host_globals(empty.path()), true, false, &mut out)
        .expect("provider list runs");
    assert_eq!(
        String::from_utf8(out).unwrap(),
        "No local provider on this machine yet.\n"
    );
}

/// Runs one `min host` or `min provider` step of the end-to-end test below,
/// and records the command with its output in `runs`. The caller's span
/// covers the step, and the step logs one `ran` event in it.
async fn run_host_command<F>(runs: &mut Vec<BoxCommandRun>, command: &str, step: F) -> u8
where
    F: AsyncFnOnce(&mut Vec<u8>) -> Result<(), anyhow::Error>,
{
    let mut stdout = Vec::new();
    let result = step(&mut stdout).await;
    let (stderr, exit) = box_command_ending(&result);
    tracing::info!(command, exit, "host command ran");
    runs.push(BoxCommandRun {
        command: command.to_owned(),
        stdout: String::from_utf8_lossy(&stdout).into_owned(),
        stderr,
        exit,
    });
    exit
}

// The local hosts and providers slice end to end (BCLI-046, BCLI-047,
// BCLI-048, BCLI-049, BCLI-052): `min provider list --all`, `min host
// list`, `min host show` and `min host stop` over harness daemons that a
// native host's socket and a VM host's socket serve. The VM host has no
// VM process, so its VM state reads as not running once the daemon stops.
// A failed step prints every command run so far, with its stdout, stderr
// and exit code. One `hosts_and_providers` span covers the host listing
// and the host stop.
#[tokio::test]
async fn hosts_and_providers_end_to_end() {
    use tracing::Instrument as _;

    let log = minimald::test_harness::captured_log();
    let state = state_with_host_dirs(&["local-minimald0", "local-minvmd0"]);
    let global = host_globals(state.path());
    let native_sock = state.path().join("providers/local-minimald0/ssh.sock");
    let vm_dir = state.path().join("providers/local-minvmd0");
    let vm_sock = vm_dir.join("ssh.sock");
    let native = minimald::test_harness::TestServer::new().await;
    native.listen_on_uds(&native_sock).await;
    let vm_host = minimald::test_harness::TestServer::new().await;
    vm_host.listen_on_uds(&vm_sock).await;
    let project = tempfile::tempdir().expect("a temp project dir");
    let mut daemon = vm_host.connect().await;
    for name in ["web", "api"] {
        minimald::test_harness::create_configured_session(
            &mut daemon,
            name,
            project.path().to_str().expect("a UTF-8 project path"),
        )
        .await;
    }
    drop(daemon);
    let version = {
        let mut client = client::Client::connect(&vm_sock).await.expect("connect");
        client
            .oneshot_rpc::<minimald_rpc::GetVersion>(())
            .await
            .expect("GetVersion")
            .long_version
    };
    // The state dir path keeps this run's span apart from other tests'
    // spans in a shared log.
    let run = state.path().display().to_string();
    let span = tracing::info_span!("hosts_and_providers", run = %run);
    let mut runs = Vec::new();

    async {
        // `min provider list --all`: each local provider with its hosts.
        let providers = async |out: &mut Vec<u8>| {
            cmd::hosts::provider_list(&global, true, false, out)?;
            Ok(())
        };
        let exit = run_host_command(&mut runs, "min provider list --all", providers).await;
        let transcript = box_transcript(&runs);
        assert_eq!(exit, 0, "{transcript}");
        assert_eq!(
            runs[0].stdout,
            "PROVIDER       HOSTS\n\
             local          local0\n\
             local-minvmd   local-minvmd0\n",
            "{transcript}"
        );

        // `min host list`: both hosts run.
        let list = async |out: &mut Vec<u8>| cmd::hosts::cmd_host_list(&global, out).await;
        let exit = run_host_command(&mut runs, "min host list", list).await;
        let transcript = box_transcript(&runs);
        assert_eq!(exit, 0, "{transcript}");
        assert_eq!(
            runs[1].stdout,
            "HOST             PROVIDER       STATE\n\
             local0           local          running\n\
             local-minvmd0    local-minvmd   running\n",
            "{transcript}"
        );

        // `min host show local-minvmd0`: its socket and its daemon version.
        let show = async |out: &mut Vec<u8>| {
            let args = HostShowArgs {
                host: "local-minvmd0".to_owned(),
            };
            cmd::hosts::cmd_host_show(&global, &args, out).await
        };
        let exit = run_host_command(&mut runs, "min host show local-minvmd0", show).await;
        let transcript = box_transcript(&runs);
        assert_eq!(exit, 0, "{transcript}");
        assert_eq!(
            runs[2].stdout,
            format!(
                "Host:            local-minvmd0\n\
                 Provider:        local-minvmd\n\
                 State:           running\n\
                 Socket:          {}\n\
                 Daemon version:  {version}\n",
                vm_sock.display()
            ),
            "{transcript}"
        );

        // `min host stop local-minvmd0`: each box, then the daemon and the
        // VM.
        let stop = async |out: &mut Vec<u8>| {
            let args = HostStopArgs {
                host: "local-minvmd0".to_owned(),
                force: false,
            };
            cmd::hosts::cmd_host_stop(&global, &args, out).await
        };
        let exit = run_host_command(&mut runs, "min host stop local-minvmd0", stop).await;
        let transcript = box_transcript(&runs);
        assert_eq!(exit, 0, "{transcript}");
        let mut lines: Vec<&str> = runs[3].stdout.lines().collect();
        assert_eq!(
            lines.pop(),
            Some("Stopped 2 boxes, the daemon and its VM on local-minvmd0."),
            "{transcript}"
        );
        lines.sort_unstable();
        assert_eq!(lines, ["Stopped api.", "Stopped web."], "{transcript}");
    }
    .instrument(span)
    .await;
    let transcript = box_transcript(&runs);

    // The VM host's daemon shuts down, its VM state reads as not running,
    // and the native host's daemon keeps running.
    assert!(
        vm_host.state.sessions_manager().await.is_shutting_down(),
        "the VM host's daemon is shutting down\n{transcript}"
    );
    let vm_state = minvmd::state::StateDir::new(vm_dir)
        .and_then(|dir| dir.effective_state())
        .expect("the VM state reads");
    assert!(
        !vm_state.lifecycle.is_active(),
        "the VM is down: {:?}\n{transcript}",
        vm_state.lifecycle
    );
    assert!(
        !native.state.sessions_manager().await.is_shutting_down(),
        "the native host's daemon keeps running\n{transcript}"
    );

    // One `hosts_and_providers` span holds each step's `ran` event.
    let log = log.contents();
    let span = format!("hosts_and_providers{{run={run}}}");
    for run in &runs {
        let event = format!("command=\"{}\"", run.command);
        let held = log
            .lines()
            .filter(|line| line.contains(&span) && line.contains(&event))
            .count();
        assert_eq!(held, 1, "{event} in {span}\n{transcript}\n{log}");
    }
}

/// One local host for the box address tests.
fn address_host(provider: &'static str, host: &str, selected: bool) -> LocalHost {
    LocalHost {
        provider,
        host: host.to_owned(),
        sock: std::path::PathBuf::from(format!("/nonexistent/{host}/ssh.sock")),
        selected,
    }
}

/// One box record for the box address tests.
fn address_entry(id: &str, name: &str, state: &str) -> minimald_rpc::BoxListingEntry {
    minimald_rpc::BoxListingEntry {
        box_id: boxes::SessionId::parse_str(id).expect("a valid box id"),
        name: Some(name.to_owned()),
        box_type: Some("session".to_owned()),
        parent: None,
        project_root: None,
        state: state.to_owned(),
        reason: None,
        exit_code: None,
        signal: None,
        pty_enabled: true,
    }
}

/// A host that answered with `boxes`.
fn answered(host: LocalHost, boxes: Vec<minimald_rpc::BoxListingEntry>) -> HostListing {
    HostListing {
        host,
        boxes: Ok(boxes),
    }
}

/// The refusal an address resolves to, as the command prints it, with the
/// exit code the binary ends with.
fn refused(address: &str, listings: &[HostListing]) -> (String, u8) {
    let refusal = resolve_box_address(address, listings).expect_err("the address must be refused");
    let code = refusal.exit_code();
    // The binary finds the refusal through the error chain it travels in.
    let err = anyhow::Error::from(refusal).context("looking up the box");
    let found = err
        .downcast_ref::<BoxAddressRefusal>()
        .expect("the refusal stays findable under context");
    (found.to_string(), code)
}

/// BCLI-002: a box address is an id, a name, or `provider/host/name`, and
/// each form finds the box on whichever local host keeps it.
#[test]
fn box_address_accepts_id_name_and_qualified() {
    let alpha = address_host(LOCAL_MINVMD_PROVIDER, "alpha.local-minvmd0", true);
    let beta = address_host(LOCAL_MINVMD_PROVIDER, "beta.local-minvmd0", false);
    let web = address_entry("0199f000-0000-7000-8000-000000000001", "web", "running");
    let db = address_entry("0199f100-0000-7000-8000-000000000002", "db", "exited");
    let web_beta = address_entry("0199f200-0000-7000-8000-000000000003", "web", "stopped");
    let listings = [
        answered(alpha.clone(), vec![web.clone()]),
        answered(beta.clone(), vec![db.clone(), web_beta.clone()]),
    ];
    let resolve = |address: &str| resolve_box_address(address, &listings).expect(address);

    // A full id finds its box on the host that lists it.
    let by_id = resolve(&db.box_id.to_string());
    assert_eq!((by_id.box_id, by_id.host), (db.box_id, beta.clone()));
    // A unique start of an id does too.
    assert_eq!(resolve("0199f1").box_id, db.box_id);
    // A name finds the box on another host, compared without case.
    let by_name = resolve("DB");
    assert_eq!((by_name.box_id, by_name.host), (db.box_id, beta.clone()));
    // A name a running box holds on one host and a stopped box holds on
    // another resolves to the running box.
    assert_eq!(resolve("web").box_id, web.box_id);
    // `provider/host/name` picks the box on that host.
    let qualified = resolve("local-minvmd/beta.local-minvmd0/web");
    assert_eq!(
        (qualified.box_id, qualified.host),
        (web_beta.box_id, beta.clone())
    );
    // The last part of a qualified address can be an id.
    assert_eq!(
        resolve(&format!("local-minvmd/alpha.local-minvmd0/{}", web.box_id)).box_id,
        web.box_id
    );
    // A qualified address reads only its own host, so an unreachable host
    // elsewhere does not stop it.
    let partial = [
        answered(alpha, vec![web.clone()]),
        HostListing {
            host: beta,
            boxes: Err("connection refused".to_owned()),
        },
    ];
    assert_eq!(
        resolve_box_address("local-minvmd/alpha.local-minvmd0/web", &partial)
            .expect("the qualified address resolves")
            .box_id,
        web.box_id
    );
    // A name with a slash in the wrong place is not a qualified address.
    assert_eq!(
        parse_box_address("a/b"),
        BoxAddress::Unqualified("a/b"),
        "two parts are not provider/host/name"
    );
}

/// BCLI-002, BOX-005: a name that running boxes on two hosts hold is
/// refused with exit 2, and the refusal lists each box with its host.
#[test]
fn ambiguous_name_across_hosts_exit2_lists_candidates() {
    let listings = [
        answered(
            address_host(LOCAL_MINVMD_PROVIDER, "alpha.local-minvmd0", true),
            vec![address_entry(
                "0199f000-0000-7000-8000-000000000001",
                "web",
                "running",
            )],
        ),
        answered(
            address_host(LOCAL_MINVMD_PROVIDER, "beta.local-minvmd0", false),
            vec![address_entry(
                "0199f200-0000-7000-8000-000000000003",
                "web",
                "running",
            )],
        ),
    ];
    let (message, code) = refused("web", &listings);
    assert_eq!(code, 2);
    assert_eq!(
        message,
        "web matches boxes on more than one host:\n\
         \x20 local-minvmd/alpha.local-minvmd0/web  running  0199f000-0000-7000-8000-000000000001\n\
         \x20 local-minvmd/beta.local-minvmd0/web  running  0199f200-0000-7000-8000-000000000003\n\
         Name one as provider/host/name."
    );
}

/// BCLI-002, BOX-005: a name that only stopped or exited boxes on two
/// hosts hold is refused with exit 2, and the refusal lists each box with
/// its host and state.
#[test]
fn retained_name_across_hosts_exit2_lists_host_and_state() {
    let mut exited = address_entry("0199f000-0000-7000-8000-000000000001", "web", "exited");
    exited.exit_code = Some(0);
    let listings = [
        answered(address_host(LOCAL_PROVIDER, "local0", true), vec![exited]),
        answered(
            address_host(LOCAL_PROVIDER, "local1", false),
            vec![address_entry(
                "0199f200-0000-7000-8000-000000000003",
                "web",
                "stopped",
            )],
        ),
    ];
    let (message, code) = refused("web", &listings);
    assert_eq!(code, 2);
    assert_eq!(
        message,
        "web matches boxes on more than one host:\n\
         \x20 local/local0/web  exited (exit 0)  0199f000-0000-7000-8000-000000000001\n\
         \x20 local/local1/web  stopped  0199f200-0000-7000-8000-000000000003\n\
         Name one as provider/host/name."
    );
}

/// BCLI-002: a host that does not answer while an unqualified name
/// resolves fails the lookup with exit 7 and names each such host. A
/// match on a host that answered is not chosen.
#[tokio::test]
async fn unqualified_name_with_unreachable_host_exit7_names_host() {
    let silent = |host: &str| HostListing {
        host: address_host(LOCAL_MINVMD_PROVIDER, host, false),
        boxes: Err("did not answer".to_owned()),
    };
    let listings = [
        answered(
            address_host(LOCAL_MINVMD_PROVIDER, "alpha.local-minvmd0", true),
            vec![address_entry(
                "0199f000-0000-7000-8000-000000000001",
                "web",
                "running",
            )],
        ),
        silent("beta.local-minvmd0"),
    ];
    let (message, code) = refused("web", &listings);
    assert_eq!(code, 7);
    assert_eq!(
        message,
        "Could not reach host beta.local-minvmd0. Box web can be on that host, \
         so no box was chosen. Run the command again when the host answers, \
         or name the box as provider/host/name."
    );

    // Two hosts that do not answer are both named.
    let two = [
        listings[0].clone(),
        silent("beta.local-minvmd0"),
        silent("gamma.local-minvmd0"),
    ];
    let (message, code) = refused("web", &two);
    assert_eq!(code, 7);
    assert!(
        message.starts_with(
            "Could not reach hosts beta.local-minvmd0, gamma.local-minvmd0. \
             Box web can be on one of them"
        ),
        "{message}"
    );
    assert!(
        message.ends_with(
            "Run the command again when the hosts answer, \
             or name the box as provider/host/name."
        ),
        "{message}"
    );
    // A qualified address on a host that does not answer names that host.
    // Its host is named, so the next step is only to ask that host again.
    let (message, code) = refused("local-minvmd/beta.local-minvmd0/web", &listings);
    assert_eq!(code, 7);
    assert_eq!(
        message,
        "Could not reach host beta.local-minvmd0. \
         Box local-minvmd/beta.local-minvmd0/web is on that host if it exists. \
         Run the command again when the host answers."
    );

    // The selected host that does not connect is named the same way, and
    // only a version skew there ends the command with its own error.
    let selected = address_host(LOCAL_MINVMD_PROVIDER, "alpha.local-minvmd0", true);
    let boxes = read_host_boxes(&selected)
        .await
        .expect("a connect failure is not the outer error");
    assert!(boxes.is_err(), "the selected host has no daemon to answer");
    let down = [HostListing {
        host: selected,
        boxes,
    }];
    for address in ["web", "local-minvmd/alpha.local-minvmd0/web"] {
        let (message, code) = refused(address, &down);
        assert_eq!(code, 7, "{address}");
        assert!(
            message.starts_with("Could not reach host alpha.local-minvmd0."),
            "{message}"
        );
    }
}

/// A daemon on a fresh socket with a configured box for each name in
/// `names`, and the unselected local host `host` that it serves.
async fn address_daemon(
    host: &str,
    names: &[&str],
) -> (
    minimald::test_harness::TestServer,
    tempfile::TempDir,
    tempfile::TempDir,
    LocalHost,
) {
    let dir = tempfile::TempDir::new().unwrap();
    let sock = dir.path().join("ssh.sock");
    let server = minimald::test_harness::TestServer::new().await;
    server.listen_on_uds(&sock).await;
    let project = tempfile::TempDir::new().unwrap();
    let mut daemon = server.connect().await;
    for name in names {
        minimald::test_harness::create_configured_session(
            &mut daemon,
            name,
            project.path().to_str().unwrap(),
        )
        .await;
    }
    let mut local = address_host(LOCAL_MINVMD_PROVIDER, host, false);
    local.sock = sock;
    (server, dir, project, local)
}

/// The box address refusal in `err`, as the command prints it, with the
/// exit code the binary ends with.
fn address_refusal(err: &anyhow::Error) -> (String, u8) {
    let refusal = err
        .downcast_ref::<BoxAddressRefusal>()
        .unwrap_or_else(|| panic!("a box address refusal: {err:#}"));
    (refusal.to_string(), refusal.exit_code())
}

/// The state `host` lists for its box named `name`.
async fn address_state(host: &LocalHost, name: &str) -> String {
    let mut client = client::Client::connect(&host.sock).await.unwrap();
    list_box_records(&mut client, None)
        .await
        .unwrap()
        .into_iter()
        .find(|entry| entry.name.as_deref() == Some(name))
        .expect("the box is listed")
        .state
}

/// BCLI-002: `min box stop` and `min box rm` refuse a name that boxes on
/// two hosts hold with exit 2, list each box, and change neither box.
#[tokio::test]
async fn ambiguous_name_across_hosts_exit2_lists_candidates_for_stop_and_rm() {
    let (_a, _ad, _ap, alpha) = address_daemon("alpha.local-minvmd0", &["web"]).await;
    let (_b, _bd, _bp, beta) = address_daemon("beta.local-minvmd0", &["web"]).await;
    let hosts = vec![alpha.clone(), beta.clone()];

    let mut out = Vec::new();
    let stop = cmd::stop_box_on_hosts(hosts.clone(), &mut out, "web", false)
        .await
        .expect_err("stop refuses the name");
    let rm = cmd::rm_box_on_hosts(hosts, "web", true)
        .await
        .expect_err("rm refuses the name");
    for err in [stop, rm] {
        let (message, code) = address_refusal(&err);
        assert_eq!(code, 2, "{message}");
        assert!(
            message.starts_with("web matches boxes on more than one host:\n"),
            "{message}"
        );
        assert!(
            message.contains("local-minvmd/alpha.local-minvmd0/web  running")
                && message.contains("local-minvmd/beta.local-minvmd0/web  running"),
            "{message}"
        );
        assert!(
            message.ends_with("Name one as provider/host/name."),
            "{message}"
        );
    }
    assert!(out.is_empty(), "a refused stop prints nothing on stdout");
    assert_eq!(address_state(&alpha, "web").await, "running");
    assert_eq!(address_state(&beta, "web").await, "running");

    // A qualified address picks the box on its host.
    let mut out = Vec::new();
    cmd::stop_box_on_hosts(
        vec![alpha.clone(), beta.clone()],
        &mut out,
        "local-minvmd/beta.local-minvmd0/web",
        false,
    )
    .await
    .expect("the qualified stop succeeds");
    assert_eq!(address_state(&beta, "web").await, "stopped");
    assert_eq!(address_state(&alpha, "web").await, "running");
}

/// BCLI-002: `min box stop` and `min box rm` refuse an unqualified name
/// with exit 7 while a host does not answer, and name that host.
#[tokio::test]
async fn unqualified_name_with_unreachable_host_exit7_names_host_for_stop_and_rm() {
    let (_a, _ad, _ap, alpha) = address_daemon("alpha.local-minvmd0", &["web"]).await;
    // The selected host has no daemon at its socket, so it does not connect.
    let down = address_host(LOCAL_MINVMD_PROVIDER, "beta.local-minvmd0", true);
    let hosts = vec![alpha.clone(), down];

    let stop = cmd::stop_box_on_hosts(hosts.clone(), &mut Vec::new(), "web", false)
        .await
        .expect_err("stop refuses the name");
    let rm = cmd::rm_box_on_hosts(hosts, "web", true)
        .await
        .expect_err("rm refuses the name");
    for err in [stop, rm] {
        let (message, code) = address_refusal(&err);
        assert_eq!(code, 7, "{message}");
        assert_eq!(
            message,
            "Could not reach host beta.local-minvmd0. Box web can be on that host, \
             so no box was chosen. Run the command again when the host answers, \
             or name the box as provider/host/name."
        );
    }
    assert_eq!(address_state(&alpha, "web").await, "running");
}

/// BCLI-064: an address that names no box fails with exit 4 and names
/// the address, in every form.
#[test]
fn unknown_box_address_exit4_names_address() {
    let listings = [
        answered(
            address_host(LOCAL_MINVMD_PROVIDER, "alpha.local-minvmd0", true),
            vec![address_entry(
                "0199f000-0000-7000-8000-000000000001",
                "web",
                "running",
            )],
        ),
        answered(
            address_host(LOCAL_MINVMD_PROVIDER, "beta.local-minvmd0", false),
            vec![],
        ),
    ];
    for address in [
        "no-such-box",
        "0199ffff-0000-7000-8000-000000000009",
        "local-minvmd/beta.local-minvmd0/web",
        "local-minvmd/no-such-host/web",
        "local/alpha.local-minvmd0/web",
    ] {
        let (message, code) = refused(address, &listings);
        assert_eq!(code, 4, "{address}");
        assert_eq!(
            message,
            format!(
                "No box named {address}. \
                 Run `min box list --all` to see the boxes on every host."
            )
        );
    }
}

/// NET-020: a native daemon whose reply carries the routing cause gets it on
/// the `HOSTNAME PROXY` row of `min ls`, on stdout, once. The cause names
/// the recovery and the command to re-run, and no `warning:` prefix rides
/// on it: `min ls` writes nothing to stderr for it any more.
#[test]
fn ls_native_routing_cause_on_proxy_row() {
    let reason = "the daemon could not bind 127.0.0.1:7654: Address in use (os error 98). \
                  Remedy: free the listen address";
    let mut resp = listing_of(&[("web", None, None)]);
    resp.hostname_routing_unavailable = Some(reason.to_string());
    resp.answerer_bound = true;
    let render = |resp: &minimald_rpc::ListSessionsResponse,
                  surface: Option<crate::resolver::LiveSurface>| {
        let mut out = Vec::new();
        cmd::format_ls_with_proxy_ports_on(
            &mut out,
            &LsArgs {
                raw: false,
                json: false,
            },
            resp,
            surface,
            None,
            &[],
            crate::resolver::HostInstall::default(),
        )
        .expect("rendering the listing");
        String::from_utf8(out).expect("the listing is UTF-8")
    };
    let expected = format!(
        "HOSTNAME PROXY:  the hostname proxy is not serving: {reason}. Minimal retries on \
         its own. Run `min ls` again to check."
    );
    for surface in [
        None,
        Some(crate::resolver::LiveSurface::Proxy),
        Some(crate::resolver::LiveSurface::Native),
    ] {
        let text = render(&resp, surface.clone());
        let rows: Vec<&str> = text
            .lines()
            .filter(|line| line.starts_with("HOSTNAME PROXY:"))
            .collect();
        assert_eq!(
            rows,
            vec![expected.as_str()],
            "surface {surface:?}:\n{text}"
        );
        assert_eq!(
            text.matches(reason).count(),
            1,
            "the cause prints once:\n{text}"
        );
        assert!(!text.contains("warning:"), "no warning prefix:\n{text}");
    }

    // A healthy daemon prints no cause row.
    resp.hostname_routing_unavailable = None;
    assert!(!render(&resp, None).contains("not serving"));

    // `--json` and `--raw` carry no cause row.
    resp.hostname_routing_unavailable = Some(reason.to_string());
    for (raw, json) in [(true, false), (false, true)] {
        let mut out = Vec::new();
        cmd::format_ls_with_proxy_ports_on(
            &mut out,
            &LsArgs { raw, json },
            &resp,
            None,
            None,
            &[],
            crate::resolver::HostInstall::default(),
        )
        .expect("rendering the listing");
        let text = String::from_utf8(out).expect("the listing is UTF-8");
        assert!(!text.contains("HOSTNAME PROXY:"), "machine output:\n{text}");
    }
}

/// NET-020: at activate the daemon's cause rides the one `names:` line, in
/// place of how to open the box, and no warning line of its own prints
/// beside it. The line is the only text the activation prints for it, so
/// the cause appears once.
#[test]
fn activate_prints_routing_cause_once() {
    let reason = "the daemon could not bind 127.0.0.1:7654: Address in use (os error 98). \
                  Remedy: free the listen address";
    let cause = crate::resolver::host_line_proxy_cause(None, Some(reason));
    for surface in [
        crate::resolver::LiveSurface::Proxy,
        crate::resolver::LiveSurface::Native,
    ] {
        let line = crate::resolver::host_line_beside(
            "web",
            &surface,
            None,
            crate::resolver::HostInstall::default(),
            cause.as_deref(),
            true,
        );
        assert!(
            line.contains(&format!(
                "names: web.min.internal: the hostname proxy is not serving: {reason}"
            )),
            "the cause replaces the resolution clause, got: {line}"
        );
        assert_eq!(line.matches(reason).count(), 1, "once, got: {line}");
        assert!(!line.contains("warning:"), "no warning prefix, got: {line}");
        assert!(
            !line.contains("opens through the HTTP proxy at"),
            "a down proxy is never the route, got: {line}"
        );
    }
    // The activation path no longer prints a standalone warning: the
    // function that wrote it is gone, so no stderr line can repeat it.
    let source = include_str!("cmd/boxes/create.rs");
    assert!(
        !source.contains("warn_if_hostname_routing_down("),
        "activate prints the cause only on its names: line"
    );
}

/// One `min box` command the end-to-end test below ran: its spelling, and
/// the stdout, stderr and exit code the command ends with.
struct BoxCommandRun {
    command: String,
    stdout: String,
    stderr: String,
    exit: u8,
}

impl std::fmt::Display for BoxCommandRun {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "$ {}", self.command)?;
        writeln!(f, "exit: {}", self.exit)?;
        writeln!(f, "stdout:\n{}", self.stdout)?;
        writeln!(f, "stderr:\n{}", self.stderr)
    }
}

/// The transcript of every command the end-to-end test ran so far, for its
/// failure messages.
fn box_transcript(runs: &[BoxCommandRun]) -> String {
    runs.iter().map(ToString::to_string).collect()
}

/// The stderr and the exit code a `min box` command ends with for
/// `result`: nothing and 0 on success, else the error and the code
/// `main` maps it to (2 for the running-box refusal, the refusal's own
/// code for a box address refusal, 1 for the rest).
fn box_command_ending(result: &Result<(), anyhow::Error>) -> (String, u8) {
    match result {
        Ok(()) => (String::new(), 0),
        Err(err) if err.downcast_ref::<BoxRunningRefusal>().is_some() => {
            (format!("{err:#}"), BoxRunningRefusal::EXIT_CODE)
        }
        // BCLI-002, BCLI-064: the code `main` gives a box address refusal.
        Err(err) => {
            let exit = err
                .downcast_ref::<BoxAddressRefusal>()
                .map_or(1, BoxAddressRefusal::exit_code);
            (format!("{err:#}"), exit)
        }
    }
}

/// Runs one `min box <verb>` step inside its own `box_verb` span, and
/// records the command with its output in `runs`.
async fn run_box_command<F>(
    runs: &mut Vec<BoxCommandRun>,
    verb: &'static str,
    command: String,
    box_id: &str,
    step: F,
) -> u8
where
    F: AsyncFnOnce(&mut Vec<u8>) -> Result<(), anyhow::Error>,
{
    use tracing::Instrument as _;

    let span = tracing::info_span!("box_verb", verb, box_id);
    let mut stdout = Vec::new();
    let result = async {
        let result = step(&mut stdout).await;
        let (_, exit) = box_command_ending(&result);
        tracing::info!(exit, "min box {verb} ran");
        result
    }
    .instrument(span)
    .await;
    let (stderr, exit) = box_command_ending(&result);
    runs.push(BoxCommandRun {
        command,
        stdout: String::from_utf8_lossy(&stdout).into_owned(),
        stderr,
        exit,
    });
    exit
}

// The first slice end to end (BCLI-001, BCLI-003, BCLI-004, BCLI-051,
// BCLI-059, BCLI-060): `min box list|show|stop|rm` of one box over a
// harness daemon that the native host's socket serves. Each step resolves
// the host and connects as the command does, and renders what the command
// prints. A failed step prints every command run so far, with its stdout,
// stderr and exit code.
#[tokio::test]
async fn box_first_slice_list_show_stop_rm_end_to_end() {
    use minimald_rpc::{Errorable, ShowBox, ShowBoxRequest};

    let log = minimald::test_harness::captured_log();
    let state = tempfile::tempdir().expect("a temp minimal state dir");
    let global = GlobalArgs {
        repo_dir: None,
        minimal_dir: Some(state.path().to_path_buf()),
        config_dir: None,
        provider: Some(Provider::LocalMinimald),
        no_input: true,
        vm: None,
    };
    let sock = client::resolve_socket_path(global.minimal_dir.as_deref(), global.use_minvmd())
        .expect("the native daemon's socket path");
    std::fs::create_dir_all(sock.parent().expect("the socket has a dir"))
        .expect("the native daemon's state dir");
    let server = minimald::test_harness::TestServer::new().await;
    server.listen_on_uds(&sock).await;
    let project = tempfile::tempdir().expect("a temp project dir");
    let mut daemon = server.connect().await;
    let id = minimald::test_harness::create_configured_session(
        &mut daemon,
        "web",
        project.path().to_str().expect("a UTF-8 project path"),
    )
    .await
    .to_string();

    let host = local_hosts(&global)
        .expect("the local hosts")
        .into_iter()
        .find(|host| host.selected)
        .expect("the native host is selected");
    let mut runs = Vec::new();

    // `min box list --all`: the box's id, name, type, state, provider
    // and host.
    let list = async |out: &mut Vec<u8>| {
        let mut client = connect_daemon(&global).await?;
        let listed: Vec<ListedBox> = list_box_records(&mut client, None)
            .await?
            .into_iter()
            .map(|record| ListedBox {
                provider: host.provider.to_string(),
                host: host.host.clone(),
                record,
            })
            .collect();
        render_box_list(out, &listed, false)?;
        Ok(())
    };
    let exit = run_box_command(&mut runs, "list", "min box list --all".into(), &id, list).await;
    let transcript = box_transcript(&runs);
    assert_eq!(exit, 0, "{transcript}");
    let listing = &runs[0].stdout;
    let mut lines = listing.lines();
    let header: Vec<&str> = lines
        .next()
        .unwrap_or_default()
        .split_whitespace()
        .collect();
    for column in ["ID", "NAME", "TYPE", "STATE", "PROVIDER", "HOST"] {
        assert!(header.contains(&column), "no {column} column\n{transcript}");
    }
    let row: Vec<&str> = lines
        .next()
        .unwrap_or_default()
        .split_whitespace()
        .collect();
    assert_eq!(row.first(), Some(&id.as_str()), "{transcript}");
    assert_eq!(row.get(1), Some(&"web"), "{transcript}");
    let type_column = header.iter().position(|column| *column == "TYPE");
    assert_eq!(
        type_column.and_then(|column| row.get(column)),
        Some(&boxes::SESSION_BOX_TYPE),
        "the TYPE cell\n{transcript}"
    );
    assert!(row.contains(&"running"), "{transcript}");
    assert_eq!(
        row.get(row.len().wrapping_sub(2)),
        Some(&"local"),
        "{transcript}"
    );
    assert_eq!(row.last(), Some(&host.host.as_str()), "{transcript}");
    assert_eq!(lines.next(), None, "one box, one row\n{transcript}");

    // `min box show web`: the record with its state and identity, and the
    // provider and host.
    let show = async |out: &mut Vec<u8>| {
        let hosts = local_hosts(&global)?;
        let ResolvedBox { host, box_id: id } =
            resolve_box_on_hosts(hosts, "web", "box show").await?;
        let mut client = box_host_client(&host).await?;
        let shown = match client.oneshot_rpc::<ShowBox>(ShowBoxRequest { id }).await? {
            Errorable::Ok(shown) => shown,
            Errorable::Err { error } => anyhow::bail!("{error}"),
        };
        render_box_show(out, &shown, host.provider, &host.host)?;
        Ok(())
    };
    let shown_running = run_box_command(&mut runs, "show", "min box show web".into(), &id, show);
    let exit = shown_running.await;
    let transcript = box_transcript(&runs);
    assert_eq!(exit, 0, "{transcript}");
    let shown = &runs[1].stdout;
    for line in [
        format!("ID: {id}"),
        "Name: web".to_owned(),
        format!("Type: {}", boxes::SESSION_BOX_TYPE),
        "State: running".to_owned(),
        "Provider: local".to_owned(),
        format!("Host: {}", host.host),
    ] {
        assert!(
            shown
                .lines()
                .any(|shown| shown.split_whitespace().eq(line.split_whitespace())),
            "no `{line}` line\n{transcript}"
        );
    }
    assert!(shown.contains("Identity"), "{transcript}");

    // `min box rm web` of the running box: refused with exit 2, naming
    // `--force`, and the box keeps running.
    let rm = async |out: &mut Vec<u8>| {
        let _ = out;
        rm_box_on_hosts(local_hosts(&global)?, "web", false).await?;
        Ok(())
    };
    let exit = run_box_command(&mut runs, "rm", "min box rm web".into(), &id, rm).await;
    let transcript = box_transcript(&runs);
    assert_eq!(exit, 2, "{transcript}");
    assert!(runs[2].stderr.contains("--force"), "{transcript}");
    assert_eq!(runs[2].stdout, "", "{transcript}");

    // `min box stop web`: the box stops and keeps its record.
    let stop = async |out: &mut Vec<u8>| {
        stop_box_on_hosts(local_hosts(&global)?, out, "web", false).await?;
        Ok(())
    };
    let exit = run_box_command(&mut runs, "stop", "min box stop web".into(), &id, stop).await;
    let transcript = box_transcript(&runs);
    assert_eq!(exit, 0, "{transcript}");
    assert_eq!(runs[3].stdout, "Stopped web.\n", "{transcript}");
    let exit = run_box_command(&mut runs, "show", "min box show web".into(), &id, show).await;
    let transcript = box_transcript(&runs);
    assert_eq!(exit, 0, "{transcript}");
    assert!(
        runs[4]
            .stdout
            .lines()
            .any(|line| line.split_whitespace().take(2).eq(["State:", "stopped"])),
        "the stopped box keeps its record\n{transcript}"
    );

    // `min box rm web` of the stopped box: removed without `--force`, and
    // the listing no longer has it. The `Removed web.` line is not checked
    // here: `cmd_box_rm` writes it to the process's stdout after its
    // cleanup, and `rm_box_on_hosts`, which this step runs, prints nothing.
    let exit = run_box_command(&mut runs, "rm", "min box rm web".into(), &id, rm).await;
    let transcript = box_transcript(&runs);
    assert_eq!(exit, 0, "{transcript}");
    assert_eq!(runs[5].stdout, "", "{transcript}");
    let exit = run_box_command(&mut runs, "list", "min box list --all".into(), &id, list).await;
    let transcript = box_transcript(&runs);
    assert_eq!(exit, 0, "{transcript}");
    assert_eq!(
        runs[6].stdout,
        format!("{EMPTY_HOST_LIST}\n"),
        "{transcript}"
    );

    // Each run of a verb has its own `box_verb` span over the same box:
    // one `ran` event inside the span for each run. The box id in the
    // span keeps other tests' spans in the shared log out of the count.
    let log = log.contents();
    for verb in ["list", "show", "stop", "rm"] {
        let span = format!("box_verb{{verb=\"{verb}\" box_id=\"{id}\"}}");
        let event = format!("min box {verb} ran");
        let spans = log
            .lines()
            .filter(|line| line.contains(&span) && line.contains(&event))
            .count();
        let ran = runs
            .iter()
            .filter(|run| run.command.starts_with(&format!("min box {verb} ")))
            .count();
        assert_eq!(spans, ran, "{span} spans\n{transcript}\n{log}");
    }
}

/// Creates a running box named `name` from `project` on the harness
/// daemon, through the whole create flow, with a stored spec whose
/// `io.pty_enabled` is `pty`. `None` stores no spec, as the harness's own
/// create does, and a session filed that way has a terminal.
async fn create_attach_box(
    daemon: &mut minimald::test_harness::TestClient,
    name: &str,
    project: &std::path::Path,
    pty: Option<bool>,
) -> boxes::SessionId {
    use minimald_rpc::{
        ConfigureLoadout, ConfigureLoadoutRequest, CreateSession, Errorable, FinalizeSession,
        FinalizeSessionRequest,
    };
    let mut request = minimald::test_harness::create_session_req(
        name,
        project.to_str().expect("a UTF-8 project path"),
    );
    request.spec = pty.map(|pty| serde_json_lenient::json!({"v": 1, "io": {"pty_enabled": pty}}));
    let id = daemon.call::<CreateSession>(&request).await.unwrap().id;
    minimald::test_harness::unwrap_ready(
        daemon
            .call::<ConfigureLoadout>(&ConfigureLoadoutRequest {
                session_id: id,
                contribution: Default::default(),
            })
            .await
            .unwrap(),
    );
    match daemon
        .call::<FinalizeSession>(&FinalizeSessionRequest {
            session_id: id,
            report_shared_port_collisions: false,
        })
        .await
    {
        Errorable::Ok(_) => {}
        Errorable::Err { error } => panic!("FinalizeSession failed: {error}"),
    }
    id
}

/// One harness daemon on a fresh socket for the `min box attach` tests,
/// served as the unselected local host `host`, with a project directory
/// its boxes come from.
struct AttachHost {
    server: minimald::test_harness::TestServer,
    _dir: tempfile::TempDir,
    project: tempfile::TempDir,
    host: LocalHost,
}

impl AttachHost {
    async fn start(host: &str) -> Self {
        let (server, dir, project, host) = address_daemon(host, &[]).await;
        Self {
            server,
            _dir: dir,
            project,
            host,
        }
    }

    /// Creates a running box from this host's project.
    async fn create(&self, name: &str, pty: Option<bool>) -> boxes::SessionId {
        let mut daemon = self.server.connect().await;
        create_attach_box(&mut daemon, name, self.project.path(), pty).await
    }

    /// The project root the bare form reads for this host's project.
    fn scope(&self) -> paths::HostAbsPath {
        paths::HostAbsPath::try_new(self.project.path().to_str().expect("a UTF-8 path"))
            .expect("an absolute project path")
    }

    /// Stops the box `name` as `min box stop` does.
    async fn stop(&self, name: &str) {
        cmd::stop_box_on_hosts(vec![self.host.clone()], &mut Vec::new(), name, false)
            .await
            .expect("the stop succeeds");
    }
}

/// The `min box attach` refusal in `err`, as the command prints it, with
/// the exit code the binary ends with.
fn attach_refusal(err: &anyhow::Error) -> (String, u8) {
    let refusal = err
        .downcast_ref::<BoxAttachRefusal>()
        .unwrap_or_else(|| panic!("a box attach refusal: {err:#}"));
    (refusal.to_string(), refusal.exit_code())
}

/// An attach that must not run: the command refused before it.
async fn no_attach(target: &BoxAttachTarget) -> Result<i32, anyhow::Error> {
    panic!("the attach must not run, it ran on {target:?}")
}

/// A target on `host` for the ending tests.
fn ending_target(host: &str) -> BoxAttachTarget {
    BoxAttachTarget {
        host: address_host(LOCAL_PROVIDER, host, true),
        box_id: boxes::SessionId::parse_str("0199f000-0000-7000-8000-000000000001").unwrap(),
        name: Some("web".to_owned()),
        label: "web".to_owned(),
    }
}

/// A listed box for the ending tests, in `state`.
fn ending_entry(state: &str) -> minimald_rpc::BoxListingEntry {
    address_entry("0199f000-0000-7000-8000-000000000001", "web", state)
}

/// BCLI-068: `min box attach <box>` hands the caller's terminal to the box
/// that has a terminal, on the host that keeps it, by every address form.
#[tokio::test]
async fn box_attach_reattaches_pty_box() {
    let alpha = AttachHost::start("alpha.local-minvmd0").await;
    let web = alpha.create("web", Some(true)).await;
    let session = alpha.create("dev", None).await;

    for (address, id) in [
        ("web", web),
        ("local-minvmd/alpha.local-minvmd0/web", web),
        (&*web.to_string(), web),
        ("dev", session),
    ] {
        let mut attached = None;
        let ending = box_attach_on_hosts(
            vec![alpha.host.clone()],
            Some(address),
            None,
            true,
            async |target: &BoxAttachTarget| {
                attached = Some(target.clone());
                Ok(0)
            },
        )
        .await
        .unwrap_or_else(|err| panic!("{address}: {err:#}"));
        let target = attached.expect("the attach ran");
        assert_eq!(target.box_id, id, "{address}");
        assert_eq!(
            target.host.sock, alpha.host.sock,
            "{address}: the box's host"
        );
        assert_eq!(target.label, address);
        assert_eq!(
            ending,
            AttachEnding {
                code: 0,
                notice: None
            },
            "{address}: a detach ends with 0"
        );
    }
}

/// BCLI-068: without a terminal on stdin the attach fails with exit 2
/// before any lookup, so a stopped box is not resumed and stays stopped.
#[tokio::test]
async fn box_attach_without_tty_exit2() {
    let alpha = AttachHost::start("alpha.local-minvmd0").await;
    alpha.create("web", Some(true)).await;
    alpha.stop("web").await;

    for address in [Some("web"), None] {
        let err = box_attach_on_hosts(
            vec![alpha.host.clone()],
            address,
            Some(&alpha.scope()),
            false,
            no_attach,
        )
        .await
        .expect_err("no terminal, no attach");
        let (message, code) = attach_refusal(&err);
        assert_eq!(code, 2, "{message}");
        assert_eq!(
            message,
            "Cannot attach: stdin is not a terminal. Run `min box attach` from a terminal."
        );
    }
    assert_eq!(address_state(&alpha.host, "web").await, "stopped");
    // The check needs no host at all.
    assert!(ensure_box_attach_tty(true).is_ok());
}

/// BCLI-068: a running box whose spec sets no terminal is refused with
/// exit 2, and the refusal names `min box logs <box>`.
#[tokio::test]
async fn box_attach_running_non_pty_box_exit2_names_logs() {
    let alpha = AttachHost::start("alpha.local-minvmd0").await;
    alpha.create("worker", Some(false)).await;

    let err = box_attach_on_hosts(
        vec![alpha.host.clone()],
        Some("worker"),
        None,
        true,
        no_attach,
    )
    .await
    .expect_err("a box with no terminal is refused");
    let (message, code) = attach_refusal(&err);
    assert_eq!(code, 2, "{message}");
    assert_eq!(
        message,
        "Box worker has no terminal to attach to. \
         Run `min box logs worker` to see its output."
    );
    assert_eq!(address_state(&alpha.host, "worker").await, "running");
}

/// An [`AttachHost`] whose daemon keeps its state in a directory the test
/// can reach, so the test can write the exec events the daemon writes when
/// it runs an exec. The harness daemon never starts a sandbox, so it runs
/// no exec itself.
async fn exec_attach_host(host: &str) -> (AttachHost, std::path::PathBuf) {
    let dir = tempfile::TempDir::new().unwrap();
    let sock = dir.path().join("ssh.sock");
    let state = tempfile::TempDir::new().unwrap();
    let state_path = state.path().to_path_buf();
    let server = minimald::test_harness::TestServer::new_in(state).await;
    server.listen_on_uds(&sock).await;
    let project = tempfile::TempDir::new().unwrap();
    let mut local = address_host(LOCAL_MINVMD_PROVIDER, host, false);
    local.sock = sock;
    (
        AttachHost {
            server,
            _dir: dir,
            project,
            host: local,
        },
        state_path,
    )
}

/// Appends the exec event `kind` for `exec_id` to the events of box `id`
/// under the daemon state dir `state`, with the fields the daemon writes.
fn write_exec_event(
    state: &std::path::Path,
    id: boxes::SessionId,
    kind: boxes::events::BoxEventType,
    exec_id: &str,
    pty: bool,
) {
    use boxes::events::exec_data;

    let box_dir = std::fs::read_dir(state.join("sessions"))
        .expect("the daemon's sessions dir")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find(|dir| {
            std::fs::read_to_string(dir.join("record.json"))
                .is_ok_and(|record| record.contains(&id.to_string()))
        })
        .expect("the box's state dir");
    let record: boxes::Record =
        serde_json_lenient::from_slice(&std::fs::read(box_dir.join("record.json")).unwrap())
            .expect("the box's record");
    let mut event = boxes::events::BoxEvent::for_record(&record, kind);
    event.data.insert(exec_data::EXEC_ID.into(), exec_id.into());
    let mode = if pty { "tty" } else { "detached" };
    event.data.insert(exec_data::MODE.into(), mode.into());
    event.data.insert(exec_data::PTY.into(), pty.into());
    event.data.insert(
        exec_data::ARGV.into(),
        serde_json_lenient::json!(["sleep", "600"]),
    );
    if kind == boxes::events::BoxEventType::ExecExited {
        event
            .data
            .insert(exec_data::EXIT_CODE.into(), serde_json_lenient::json!(0));
        event.data.insert(exec_data::REASON.into(), "exited".into());
    }
    let events = camino::Utf8PathBuf::from_path_buf(box_dir.join(boxes::events::EVENTS_FILE))
        .expect("a UTF-8 path");
    boxes::store::append_event_at(&events, &event).expect("the event is written");
}

/// An exec attach that must not run: the command refused before it.
async fn no_exec_attach(
    target: &BoxAttachTarget,
    exec_id: &minimald_rpc::exec::ExecId,
) -> Result<i32, anyhow::Error> {
    panic!("the attach must not run, it ran on {target:?} for {exec_id}")
}

/// Another exec id as the daemon mints one.
const OTHER_EXEC_ID: &str = "01928a3b-4c5d-7e6f-8a9b-0c1d2e3f4a5c";

/// BCLI-068: `min box attach <box> --exec <id>` hands the caller's terminal
/// to the live terminal exec of that id, in the box on the host that keeps
/// it, by every address form.
#[tokio::test]
async fn box_attach_exec_reattaches_live_pty_exec() {
    use clap::Parser as _;

    let (alpha, state) = exec_attach_host("alpha.local-minvmd0").await;
    let web = alpha.create("web", Some(false)).await;
    write_exec_event(
        &state,
        web,
        boxes::events::BoxEventType::ExecStarted,
        AN_EXEC_ID,
        true,
    );

    for address in [
        "web",
        "local-minvmd/alpha.local-minvmd0/web",
        &*web.to_string(),
    ] {
        let mut attached = None;
        let ending = box_attach_exec_on_hosts(
            vec![alpha.host.clone()],
            address,
            AN_EXEC_ID,
            true,
            async |target: &BoxAttachTarget, exec_id: &minimald_rpc::exec::ExecId| {
                attached = Some((target.clone(), exec_id.clone()));
                Ok(3)
            },
        )
        .await
        .unwrap_or_else(|err| panic!("{address}: {err:#}"));
        let (target, exec_id) = attached.expect("the attach ran");
        assert_eq!(target.box_id, web, "{address}");
        assert_eq!(target.host.sock, alpha.host.sock, "{address}");
        assert_eq!(target.label, address);
        assert_eq!(exec_id.as_str(), AN_EXEC_ID, "{address}");
        assert_eq!(
            ending,
            AttachEnding {
                code: 0,
                notice: None
            },
            "{address}: the exec's own end is 0"
        );
    }

    let cli = Cli::try_parse_from(["min", "box", "attach", "web", "--exec", AN_EXEC_ID])
        .expect("`--exec` with a box parses");
    match cli.command {
        Some(Command::Box(BoxArgs {
            command: BoxCommand::Attach(args),
        })) => {
            assert_eq!(args.target.as_deref(), Some("web"));
            assert_eq!(args.exec.as_deref(), Some(AN_EXEC_ID));
        }
        _ => panic!("not `min box attach`"),
    }
}

/// BCLI-068: an exec that ends by itself ends `min box attach --exec` with
/// 0 and no line, whatever code the exec ended with. `min box wait <box>
/// --exec <id>` reads that code.
#[tokio::test]
async fn box_attach_exec_own_end_code7_exits_0() {
    let (alpha, state) = exec_attach_host("alpha.local-minvmd0").await;
    let web = alpha.create("web", Some(true)).await;
    write_exec_event(
        &state,
        web,
        boxes::events::BoxEventType::ExecStarted,
        AN_EXEC_ID,
        true,
    );
    let ending = box_attach_exec_on_hosts(
        vec![alpha.host.clone()],
        "web",
        AN_EXEC_ID,
        true,
        async |_: &BoxAttachTarget, _: &minimald_rpc::exec::ExecId| Ok(7),
    )
    .await
    .expect("the attach ends");
    assert_eq!(
        ending,
        AttachEnding {
            code: 0,
            notice: None
        }
    );
}

/// BCLI-068: `min box stop` ends the attached exec by its signal, which the
/// daemon reports as 1, before it writes the stopped record. The command
/// reads the box again, and ends with 254 and the stop's line. A removed
/// box ends with 254 and the removal's line.
#[tokio::test]
async fn box_attach_exec_box_stopped_exit254_names_stop() {
    let (alpha, state) = exec_attach_host("alpha.local-minvmd0").await;
    let web = alpha.create("web", Some(true)).await;
    write_exec_event(
        &state,
        web,
        boxes::events::BoxEventType::ExecStarted,
        AN_EXEC_ID,
        true,
    );
    let (closed_tx, closed_rx) = tokio::sync::oneshot::channel::<()>();
    let attach = box_attach_exec_on_hosts(
        vec![alpha.host.clone()],
        "web",
        AN_EXEC_ID,
        true,
        async move |_: &BoxAttachTarget, _: &minimald_rpc::exec::ExecId| {
            let _ = closed_tx.send(());
            Ok(1)
        },
    );
    let stop = async {
        closed_rx.await.expect("the attach ran");
        // Let the command's first read see the box running.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        alpha.stop("web").await;
    };
    let (ending, ()) = tokio::join!(attach, stop);
    assert_eq!(
        ending.expect("the attach ends"),
        AttachEnding {
            code: 254,
            notice: Some("Detached: web was stopped.".to_owned())
        }
    );

    let target = ending_target("local0");
    let exec_id = minimald_rpc::exec::ExecId::parse(AN_EXEC_ID).unwrap();
    assert_eq!(
        exec_attach_ending(&target, &exec_id, 1, &BoxAfterAttach::Gone),
        Ok(AttachEnding {
            code: 254,
            notice: Some("Detached: web was removed.".to_owned())
        })
    );
    assert_eq!(
        exec_attach_ending(
            &target,
            &exec_id,
            254,
            &BoxAfterAttach::Listed(ending_entry("running"))
        ),
        Ok(AttachEnding {
            code: 254,
            notice: Some("Detached: another terminal attached to web.".to_owned())
        })
    );
    assert_eq!(
        exec_attach_ending(
            &target,
            &exec_id,
            7,
            &BoxAfterAttach::Listed(ending_entry("running"))
        ),
        Ok(AttachEnding {
            code: 0,
            notice: None
        })
    );
    // ssh's own 255 is a lost connection. The retry names the exec.
    let lost = exec_attach_ending(
        &target,
        &exec_id,
        255,
        &BoxAfterAttach::Listed(ending_entry("running")),
    )
    .expect_err("a lost connection is refused");
    assert_eq!(
        lost.to_string(),
        format!(
            "The connection to host local0 failed during the attach. \
             Run `min box attach web --exec {AN_EXEC_ID}` to attach again."
        )
    );
}

/// BCLI-068: a stop whose entrypoint outlives SIGTERM writes the stopped
/// record only at the end of its grace period, long after the daemon ended
/// the attached exec's channel with 254. The command waits for the record,
/// and ends with 254 and the stop's line.
#[tokio::test]
async fn box_attach_exec_late_stop_record_exit254_names_stop() {
    let (alpha, state) = exec_attach_host("alpha.local-minvmd0").await;
    let web = alpha.create("web", Some(true)).await;
    write_exec_event(
        &state,
        web,
        boxes::events::BoxEventType::ExecStarted,
        AN_EXEC_ID,
        true,
    );
    let (closed_tx, closed_rx) = tokio::sync::oneshot::channel::<()>();
    let attach = box_attach_exec_on_hosts(
        vec![alpha.host.clone()],
        "web",
        AN_EXEC_ID,
        true,
        async move |_: &BoxAttachTarget, _: &minimald_rpc::exec::ExecId| {
            let _ = closed_tx.send(());
            Ok(254)
        },
    );
    let stop = async {
        closed_rx.await.expect("the attach ran");
        // Past the 500 ms the command waits after an exec's own end.
        tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
        assert_eq!(address_state(&alpha.host, "web").await, "running");
        alpha.stop("web").await;
    };
    let (ending, ()) = tokio::join!(attach, stop);
    assert_eq!(
        ending.expect("the attach ends"),
        AttachEnding {
            code: 254,
            notice: Some("Detached: web was stopped.".to_owned())
        }
    );
}

/// BCLI-068: an exec id the box never ran is refused with exit 4, naming
/// the id. The check comes before the ended and the no-terminal checks, so
/// an id of another box is refused the same way.
#[tokio::test]
async fn box_attach_exec_unknown_id_exit4_names_id() {
    let (alpha, state) = exec_attach_host("alpha.local-minvmd0").await;
    let web = alpha.create("web", Some(true)).await;
    let other = alpha.create("other", Some(true)).await;
    write_exec_event(
        &state,
        other,
        boxes::events::BoxEventType::ExecStarted,
        OTHER_EXEC_ID,
        false,
    );
    write_exec_event(
        &state,
        web,
        boxes::events::BoxEventType::ExecStarted,
        AN_EXEC_ID,
        true,
    );

    for exec_id in [OTHER_EXEC_ID, "not-an-exec-id"] {
        let err = box_attach_exec_on_hosts(
            vec![alpha.host.clone()],
            "web",
            exec_id,
            true,
            no_exec_attach,
        )
        .await
        .expect_err("an exec the box never ran is refused");
        let (message, code) = attach_refusal(&err);
        assert_eq!(code, 4, "{message}");
        assert_eq!(message, format!("web has no exec {exec_id}."));
    }
}

/// BCLI-068: a live exec that did not ask for a terminal is refused with
/// exit 2, naming `min box logs <box> --exec <id>`.
#[tokio::test]
async fn box_attach_exec_non_pty_exit2_names_logs() {
    let (alpha, state) = exec_attach_host("alpha.local-minvmd0").await;
    let web = alpha.create("web", Some(true)).await;
    write_exec_event(
        &state,
        web,
        boxes::events::BoxEventType::ExecStarted,
        AN_EXEC_ID,
        false,
    );

    let err = box_attach_exec_on_hosts(
        vec![alpha.host.clone()],
        "web",
        AN_EXEC_ID,
        true,
        no_exec_attach,
    )
    .await
    .expect_err("an exec with no terminal is refused");
    let (message, code) = attach_refusal(&err);
    assert_eq!(code, 2, "{message}");
    assert_eq!(
        message,
        format!(
            "Exec {AN_EXEC_ID} in web has no terminal to attach to. \
             Run `min box logs web --exec {AN_EXEC_ID}` to see its output."
        )
    );

    // A start event that says nothing of a terminal proves no refusal: the
    // command leaves the terminal check to the host.
    let mut silent = boxes::events::BoxEvent {
        box_id: web,
        parent: None,
        ts: 0,
        kind: boxes::events::BoxEventType::ExecStarted,
        data: Default::default(),
    };
    silent
        .data
        .insert(boxes::events::exec_data::EXEC_ID.into(), AN_EXEC_ID.into());
    assert_eq!(
        crate::exec_found(&[silent], &[], true, AN_EXEC_ID),
        crate::ExecFound::Terminal,
    );
}

/// BCLI-068: an exec that ended, with or without a terminal, is refused
/// with exit 4, naming `min box logs` and `min box wait` with `--exec`.
/// The ended check comes before the no-terminal check. An exec of a box
/// that stopped has ended too.
#[tokio::test]
async fn box_attach_exec_ended_exit4_names_logs_and_wait() {
    use boxes::events::BoxEventType;

    let (alpha, state) = exec_attach_host("alpha.local-minvmd0").await;
    let web = alpha.create("web", Some(true)).await;
    let stopped = alpha.create("stopped", Some(true)).await;
    for (exec_id, pty) in [(AN_EXEC_ID, true), (OTHER_EXEC_ID, false)] {
        write_exec_event(&state, web, BoxEventType::ExecStarted, exec_id, pty);
        write_exec_event(&state, web, BoxEventType::ExecExited, exec_id, pty);
    }
    write_exec_event(&state, stopped, BoxEventType::ExecStarted, AN_EXEC_ID, true);
    alpha.stop("stopped").await;

    for (address, exec_id) in [
        ("web", AN_EXEC_ID),
        ("web", OTHER_EXEC_ID),
        ("stopped", AN_EXEC_ID),
    ] {
        let err = box_attach_exec_on_hosts(
            vec![alpha.host.clone()],
            address,
            exec_id,
            true,
            no_exec_attach,
        )
        .await
        .expect_err("an exec that ended is refused");
        let (message, code) = attach_refusal(&err);
        assert_eq!(code, 4, "{address} {exec_id}: {message}");
        assert_eq!(
            message,
            format!(
                "Exec {exec_id} has ended. \
                 Read its output with min box logs {address} --exec {exec_id}, \
                 or its exit code with min box wait {address} --exec {exec_id}."
            )
        );
    }
}

/// BCLI-068: `min box attach --exec <id>` with no box fails with exit 2,
/// before any lookup.
#[tokio::test]
async fn box_attach_exec_without_box_exit2() {
    use clap::Parser as _;

    let Err(err) = Cli::try_parse_from(["min", "box", "attach", "--exec", AN_EXEC_ID]) else {
        panic!("`--exec` needs a box");
    };
    assert_eq!(
        err.kind(),
        clap::error::ErrorKind::MissingRequiredArgument,
        "{err}"
    );
    assert_eq!(err.exit_code(), 2, "{err}");
    assert!(err.to_string().contains("<TARGET>"), "{err}");
}

/// BCLI-068: with no box named, the attach goes to the project's running
/// box with a terminal. With none running, it goes to the project's only
/// stopped or exited box with a terminal. A box with no terminal and a box
/// of another project are never a candidate.
#[tokio::test]
async fn box_attach_without_address_picks_running_else_sole_retained() {
    let alpha = AttachHost::start("alpha.local-minvmd0").await;
    let other = AttachHost::start("beta.local-minvmd0").await;
    let web = alpha.create("web", Some(true)).await;
    alpha.create("worker", Some(false)).await;
    // Another project's running box with a terminal, on another host.
    other.create("elsewhere", Some(true)).await;
    let hosts = vec![alpha.host.clone(), other.host.clone()];

    let attach_bare = async || {
        let mut attached = None;
        box_attach_on_hosts(
            hosts.clone(),
            None,
            Some(&alpha.scope()),
            true,
            async |target: &BoxAttachTarget| {
                attached = Some(target.clone());
                Ok(0)
            },
        )
        .await
        .expect("the bare form finds the box");
        attached.expect("the attach ran")
    };

    let running = attach_bare().await;
    assert_eq!(running.box_id, web, "the running box with a terminal");
    assert_eq!(running.host.sock, alpha.host.sock);
    assert_eq!(running.label, "web");

    // Stopped, the box is still the project's only one with a terminal.
    alpha.stop("web").await;
    let retained = attach_bare().await;
    assert_eq!(
        retained.box_id, web,
        "the only retained box with a terminal"
    );

    // A running box with a terminal wins over the retained one.
    let fresh = alpha.create("api", Some(true)).await;
    assert_eq!(attach_bare().await.box_id, fresh);
}

/// BCLI-068: with no box named, two candidates fail the attach with exit 2
/// and the refusal lists them both.
#[tokio::test]
async fn box_attach_without_address_ambiguous_exit2_lists() {
    let alpha = AttachHost::start("alpha.local-minvmd0").await;
    let web = alpha.create("web", Some(true)).await;
    let api = alpha.create("api", None).await;

    let refusal = async || {
        let err = box_attach_on_hosts(
            vec![alpha.host.clone()],
            None,
            Some(&alpha.scope()),
            true,
            no_attach,
        )
        .await
        .expect_err("two candidates, no attach");
        attach_refusal(&err)
    };
    let (message, code) = refusal().await;
    assert_eq!(code, 2, "{message}");
    assert!(
        message.starts_with("More than one box in this project has a terminal:\n"),
        "{message}"
    );
    for line in [
        format!("  local-minvmd/alpha.local-minvmd0/web  running  {web}"),
        format!("  local-minvmd/alpha.local-minvmd0/api  running  {api}"),
    ] {
        assert!(
            message.lines().any(|l| l == line),
            "no `{line}`:\n{message}"
        );
    }
    assert!(
        message.ends_with("Name one with `min box attach <box>`."),
        "{message}"
    );

    // Two retained boxes are as ambiguous as two running ones.
    alpha.stop("web").await;
    alpha.stop("api").await;
    let (message, code) = refusal().await;
    assert_eq!(code, 2, "{message}");
    assert!(message.contains("web  stopped"), "{message}");
    assert!(message.contains("api  stopped"), "{message}");
    assert_eq!(address_state(&alpha.host, "web").await, "stopped");
}

/// BCLI-068: with no box named and no candidate, the attach fails with
/// exit 4 and a hint that names `min box start`.
#[tokio::test]
async fn box_attach_without_address_none_exit4_hints_start() {
    let alpha = AttachHost::start("alpha.local-minvmd0").await;
    let empty = tempfile::TempDir::new().unwrap();
    let empty_scope = paths::HostAbsPath::try_new(empty.path().to_str().unwrap()).unwrap();

    // A project with no box, and a project whose only box has no terminal.
    alpha.create("worker", Some(false)).await;
    for scope in [empty_scope, alpha.scope()] {
        let err = box_attach_on_hosts(
            vec![alpha.host.clone()],
            None,
            Some(&scope),
            true,
            no_attach,
        )
        .await
        .expect_err("no candidate, no attach");
        let (message, code) = attach_refusal(&err);
        assert_eq!(code, 4, "{message}");
        assert_eq!(
            message,
            "No box with a terminal in this project. Start one with min box start."
        );
    }
}

/// BCLI-068: with no box named, a host that does not answer the lookup
/// fails the attach with exit 7, names the host, and attaches to nothing,
/// though another host has a candidate.
#[tokio::test]
async fn box_attach_without_address_unreachable_host_exit7() {
    let alpha = AttachHost::start("alpha.local-minvmd0").await;
    alpha.create("web", Some(true)).await;
    // The selected host has no daemon at its socket, so it does not connect.
    let down = address_host(LOCAL_MINVMD_PROVIDER, "beta.local-minvmd0", true);

    let err = box_attach_on_hosts(
        vec![alpha.host.clone(), down],
        None,
        Some(&alpha.scope()),
        true,
        no_attach,
    )
    .await
    .expect_err("a silent host, no attach");
    let (message, code) = attach_refusal(&err);
    assert_eq!(code, 7, "{message}");
    assert_eq!(
        message,
        "Could not reach host beta.local-minvmd0, so no box was chosen. \
         Run the command again when the host answers, \
         or name the box as provider/host/name."
    );
    let two = BoxAttachRefusal::Unreachable {
        hosts: vec![
            "beta.local-minvmd0".to_owned(),
            "gamma.local-minvmd0".to_owned(),
        ],
    };
    assert!(
        two.to_string()
            .starts_with("Could not reach hosts beta.local-minvmd0, gamma.local-minvmd0, so"),
        "{two}"
    );
    assert_eq!(two.exit_code(), 7);
}

/// BCLI-068: a detach, or a box's entrypoint that exits on its own, ends
/// the attach with exit 0 and no line of its own.
#[tokio::test]
async fn attach_detach_or_entrypoint_exit_returns_0() {
    let target = ending_target("local0");
    let quiet = AttachEnding {
        code: 0,
        notice: None,
    };
    let mut exited = ending_entry("exited");
    exited.reason = Some("exit".to_owned());
    exited.exit_code = Some(0);
    for after in [
        BoxAfterAttach::Listed(ending_entry("running")),
        BoxAfterAttach::Listed(exited),
        // The shell-exit prompt can delete the box the user chose to.
        BoxAfterAttach::Gone,
        BoxAfterAttach::HostSilent,
        BoxAfterAttach::Unread,
    ] {
        assert_eq!(
            attach_ending(&target, 0, &after),
            Ok(quiet.clone()),
            "{after:?}"
        );
    }

    // A detach from a running box over a live host ends with 0.
    let alpha = AttachHost::start("alpha.local-minvmd0").await;
    alpha.create("web", Some(true)).await;
    let ending = box_attach_on_hosts(
        vec![alpha.host.clone()],
        Some("web"),
        None,
        true,
        async |_: &BoxAttachTarget| Ok(0),
    )
    .await
    .expect("the detach ends the attach");
    assert_eq!(ending, quiet);
}

/// BCLI-068: an attach the daemon ends from the other side exits with 254
/// after one line that names the cause: a stop, a removal, another
/// terminal that took the box, or a host that shut down. A stop gives 254
/// although it also ends the entrypoint. A box that reads `exited` ended by
/// itself, so its 254 ends with 0 and keeps its line.
#[tokio::test]
async fn attach_ended_from_other_side_notice_exit254() {
    let alpha = AttachHost::start("alpha.local-minvmd0").await;
    alpha.create("web", Some(true)).await;
    let hosts = vec![alpha.host.clone()];

    // The box is stopped while attached: the daemon reports 254, or 0 as
    // for an entrypoint that ended.
    for reported in [254, 0] {
        let ending = box_attach_on_hosts(
            hosts.clone(),
            Some("web"),
            None,
            true,
            async |_: &BoxAttachTarget| {
                alpha.stop("web").await;
                Ok(reported)
            },
        )
        .await
        .expect("the attach ends");
        assert_eq!(
            ending,
            AttachEnding {
                code: 254,
                notice: Some("Detached: web was stopped.".to_owned())
            },
            "reported {reported}"
        );
        let mut daemon = alpha.server.connect().await;
        resume_for_attach_test(&mut daemon, &alpha.host).await;
    }

    // The box is removed while attached.
    let ending = box_attach_on_hosts(
        hosts.clone(),
        Some("web"),
        None,
        true,
        async |_: &BoxAttachTarget| {
            cmd::rm_box_on_hosts(hosts.clone(), "web", true)
                .await
                .expect("the removal succeeds");
            Ok(254)
        },
    )
    .await
    .expect("the attach ends");
    assert_eq!(
        ending,
        AttachEnding {
            code: 254,
            notice: Some("Detached: web was removed.".to_owned())
        }
    );

    // Another terminal took the box, or the host shut down.
    let target = ending_target("local0");
    let line = |after: BoxAfterAttach| {
        attach_ending(&target, 254, &after)
            .expect("an ending")
            .notice
            .expect("a line")
    };
    assert_eq!(
        line(BoxAfterAttach::Listed(ending_entry("running"))),
        "Detached: another terminal attached to web."
    );
    assert_eq!(
        line(BoxAfterAttach::HostSilent),
        "Detached: host local0 shut down or stopped answering."
    );
    // A box that reads `exited` ended by itself: the attach ends with 0,
    // and the line says how the box ended.
    let exited_ending = |reason: &str, exit_code: Option<i32>| {
        let mut entry = ending_entry("exited");
        entry.reason = Some(reason.to_owned());
        entry.exit_code = exit_code;
        attach_ending(&target, 254, &BoxAfterAttach::Listed(entry)).expect("an ending")
    };
    assert_eq!(
        exited_ending("exit", Some(3)),
        AttachEnding {
            code: 0,
            notice: Some("Detached: web exited with code 3.".to_owned())
        }
    );
    assert_eq!(
        exited_ending("timeout", None),
        AttachEnding {
            code: 0,
            notice: Some("Detached: web ran past its timeout and ended.".to_owned())
        }
    );
    // An OOM record stores exit code 137 too. The line names the OOM.
    assert_eq!(
        exited_ending("oom", Some(137)),
        AttachEnding {
            code: 0,
            notice: Some("Detached: web ran out of memory and ended.".to_owned())
        }
    );
    // A stop whose entrypoint exited on its SIGTERM records the
    // entrypoint's own code. The daemon reports 0 for it, and it is still
    // a stop.
    let mut stopped = ending_entry("stopped");
    stopped.reason = Some("stopped".to_owned());
    stopped.exit_code = Some(0);
    assert_eq!(
        attach_ending(&target, 0, &BoxAfterAttach::Listed(stopped)),
        Ok(AttachEnding {
            code: 254,
            notice: Some("Detached: web was stopped.".to_owned())
        })
    );
    assert_eq!(
        attach_ending(&target, 254, &BoxAfterAttach::Unread),
        Ok(AttachEnding {
            code: 254,
            notice: Some("Detached: host local0 ended the attach to web.".to_owned())
        }),
        "a host that answered with an error proves no cause, so the line names the host"
    );
}

/// BCLI-068: the daemon closes the attach's channel before it writes the
/// stopped record, so the first read after the attach still sees the box
/// running. The command reads again until the record says why, and a stop
/// still ends with 254 and its line, whether the daemon reported 254 or 0.
#[tokio::test]
async fn attach_ended_from_other_side_notice_exit254_before_the_record() {
    let alpha = AttachHost::start("alpha.local-minvmd0").await;
    alpha.create("web", Some(true)).await;
    let hosts = vec![alpha.host.clone()];

    for reported in [254, 0] {
        let (closed_tx, closed_rx) = tokio::sync::oneshot::channel::<()>();
        let attach = box_attach_on_hosts(
            hosts.clone(),
            Some("web"),
            None,
            true,
            async move |_: &BoxAttachTarget| {
                // The channel closed: the stop has not written the record.
                let _ = closed_tx.send(());
                Ok(reported)
            },
        );
        let stop = async {
            closed_rx.await.expect("the attach ran");
            // Let the command's first read see the box running.
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            alpha.stop("web").await;
        };
        let (ending, ()) = tokio::join!(attach, stop);
        assert_eq!(
            ending.expect("the attach ends"),
            AttachEnding {
                code: 254,
                notice: Some("Detached: web was stopped.".to_owned())
            },
            "reported {reported}"
        );
        let mut daemon = alpha.server.connect().await;
        resume_for_attach_test(&mut daemon, &alpha.host).await;
    }

    // A stop waits for a process that ignores SIGTERM until its grace
    // period ends, so after a 254 the record can still read `running`
    // more than 2 s after the channel closed. It is still a stop.
    let (closed_tx, closed_rx) = tokio::sync::oneshot::channel::<()>();
    let attach = box_attach_on_hosts(
        hosts.clone(),
        Some("web"),
        None,
        true,
        async move |_: &BoxAttachTarget| {
            let _ = closed_tx.send(());
            Ok(254)
        },
    );
    let stop = async {
        closed_rx.await.expect("the attach ran");
        tokio::time::sleep(std::time::Duration::from_millis(2500)).await;
        alpha.stop("web").await;
    };
    let (ending, ()) = tokio::join!(attach, stop);
    assert_eq!(
        ending.expect("the attach ends"),
        AttachEnding {
            code: 254,
            notice: Some("Detached: web was stopped.".to_owned())
        },
        "a stop recorded after 2 s"
    );
}

/// Starts the stopped box `web` on `host` again by its resume, so the
/// next round of a test attaches to a running box. A harness box resumes
/// through the same create flow, so this creates it afresh under the name.
async fn resume_for_attach_test(daemon: &mut minimald::test_harness::TestClient, host: &LocalHost) {
    cmd::rm_box_on_hosts(vec![host.clone()], "web", true)
        .await
        .expect("the stopped box is removed");
    let project = tempfile::TempDir::new().unwrap();
    create_attach_box(daemon, "web", project.path(), Some(true)).await;
}

/// BCLI-068: a connection to the box's host that fails during the attach
/// fails the command with exit 7 and names the host, whether or not the
/// host still answers.
#[tokio::test]
async fn attach_connection_failure_exit7() {
    let target = ending_target("alpha.local-minvmd0");
    let refusal = attach_ending(&target, 255, &BoxAfterAttach::HostSilent)
        .expect_err("a silent host after ssh failed is a lost connection");
    assert_eq!(refusal.exit_code(), 7);
    assert_eq!(
        refusal.to_string(),
        "The connection to host alpha.local-minvmd0 failed during the attach. \
         Run `min box attach web` to attach again."
    );
    // The binary finds the refusal through the error chain it travels in.
    let err = anyhow::Error::from(refusal).context("attaching");
    assert_eq!(attach_refusal(&err).1, 7);

    for after in [
        BoxAfterAttach::Listed(ending_entry("running")),
        BoxAfterAttach::Gone,
        BoxAfterAttach::Unread,
    ] {
        assert_eq!(
            attach_ending(&target, 255, &after).map_err(|refusal| refusal.exit_code()),
            Err(7),
            "{after:?}"
        );
    }

    // A host with no daemon at its socket is read as silent.
    let down = address_host(LOCAL_MINVMD_PROVIDER, "alpha.local-minvmd0", false);
    assert_eq!(
        box_after_attach(&down, target.box_id).await,
        BoxAfterAttach::HostSilent
    );

    // ssh's 255 over a host that still answers is a lost connection too.
    let alpha = AttachHost::start("alpha.local-minvmd0").await;
    alpha.create("web", Some(true)).await;
    let err = box_attach_on_hosts(
        vec![alpha.host.clone()],
        Some("web"),
        None,
        true,
        async |_: &BoxAttachTarget| Ok(255),
    )
    .await
    .expect_err("ssh failed");
    assert_eq!(attach_refusal(&err).1, 7);
}

/// Runs one step of the address end-to-end test below inside its own
/// `box_address_step` span, and records the command with its output in
/// `runs`. The step number keeps each run's span apart in the log.
async fn run_address_step<F>(
    runs: &mut Vec<BoxCommandRun>,
    box_id: &str,
    command: String,
    step: F,
) -> u8
where
    F: AsyncFnOnce(&mut Vec<u8>) -> Result<(), anyhow::Error>,
{
    use tracing::Instrument as _;

    let span = tracing::info_span!("box_address_step", step = runs.len(), box_id);
    let mut stdout = Vec::new();
    let result = step(&mut stdout).instrument(span).await;
    let (stderr, exit) = box_command_ending(&result);
    runs.push(BoxCommandRun {
        command,
        stdout: String::from_utf8_lossy(&stdout).into_owned(),
        stderr,
        exit,
    });
    exit
}

// The address and machine-output slice end to end (BCLI-002, BCLI-033,
// BCLI-063, BCLI-064): one box over a harness daemon on the native host's
// socket. `min box show|stop|rm` take its id, its name and
// provider/host/name. An address that names no box ends with exit 4, and
// an unqualified name while a host does not answer ends with exit 7. Each
// `-o json` box object carries its `min/v1/box` schema, and a secret
// renders only as its reference. A failed step prints every command run so
// far, with its stdout, stderr and exit code.
#[tokio::test]
async fn box_address_and_json_output_end_to_end() {
    use crate::output::{ObjectType, OutputMode, Rendered, Secret};
    use minimald_rpc::{Errorable, ShowBox, ShowBoxRequest};

    let log = minimald::test_harness::captured_log();
    let state = tempfile::tempdir().expect("a temp minimal state dir");
    let global = GlobalArgs {
        repo_dir: None,
        minimal_dir: Some(state.path().to_path_buf()),
        config_dir: None,
        provider: Some(Provider::LocalMinimald),
        no_input: true,
        vm: None,
    };
    let sock = client::resolve_socket_path(global.minimal_dir.as_deref(), global.use_minvmd())
        .expect("the native daemon's socket path");
    std::fs::create_dir_all(sock.parent().expect("the socket has a dir"))
        .expect("the native daemon's state dir");
    let server = minimald::test_harness::TestServer::new().await;
    server.listen_on_uds(&sock).await;
    let project = tempfile::tempdir().expect("a temp project dir");
    let mut daemon = server.connect().await;
    let id = minimald::test_harness::create_configured_session(
        &mut daemon,
        "web",
        project.path().to_str().expect("a UTF-8 project path"),
    )
    .await
    .to_string();

    let host = local_hosts(&global)
        .expect("the local hosts")
        .into_iter()
        .find(|host| host.selected)
        .expect("the native host is selected");
    let qualified = format!("{}/{}/web", host.provider, host.host);
    let mut runs = Vec::new();

    // `min box show <address>`: the record of the box the address names.
    let show = async |address: &str, out: &mut Vec<u8>| {
        let hosts = local_hosts(&global)?;
        let ResolvedBox { host, box_id } = resolve_box_on_hosts(hosts, address, "box show").await?;
        let mut client = box_host_client(&host).await?;
        let shown = match client
            .oneshot_rpc::<ShowBox>(ShowBoxRequest { id: box_id })
            .await?
        {
            Errorable::Ok(shown) => shown,
            Errorable::Err { error } => anyhow::bail!("{error}"),
        };
        render_box_show(out, &shown, host.provider, &host.host)?;
        Ok(())
    };

    // The id, the name and provider/host/name each show the same box.
    for address in [id.as_str(), "web", qualified.as_str()] {
        let step = async |out: &mut Vec<u8>| show(address, out).await;
        let command = format!("min box show {address}");
        let exit = run_address_step(&mut runs, &id, command, step).await;
        let transcript = box_transcript(&runs);
        assert_eq!(exit, 0, "{transcript}");
        let shown = &runs.last().expect("the step ran").stdout;
        for line in [format!("ID: {id}"), "Name: web".to_owned()] {
            assert!(
                shown
                    .lines()
                    .any(|shown| shown.split_whitespace().eq(line.split_whitespace())),
                "no `{line}` line\n{transcript}"
            );
        }
    }

    // `min box show no-such-box`: exit 4, and the refusal names the
    // address.
    let missing = async |out: &mut Vec<u8>| show("no-such-box", out).await;
    let command = "min box show no-such-box".to_owned();
    let exit = run_address_step(&mut runs, &id, command, missing).await;
    let transcript = box_transcript(&runs);
    assert_eq!(exit, 4, "{transcript}");
    let run = runs.last().expect("the step ran");
    assert!(
        run.stderr.contains("No box named no-such-box."),
        "{transcript}"
    );
    assert_eq!(run.stdout, "", "{transcript}");

    // `min box show web` while the selected VM host does not answer: exit
    // 7, the refusal names that host, and no box is chosen although the
    // native host has one named web.
    let mut native = host.clone();
    native.selected = false;
    let down = LocalHost {
        provider: LOCAL_MINVMD_PROVIDER,
        host: "beta.local-minvmd0".to_owned(),
        sock: state.path().join("no-vm").join("ssh.sock"),
        selected: true,
    };
    let unreachable = async |out: &mut Vec<u8>| {
        let _ = out;
        resolve_box_on_hosts(vec![native.clone(), down.clone()], "web", "box show").await?;
        Ok(())
    };
    let command = "min box show web --vm beta".to_owned();
    let exit = run_address_step(&mut runs, &id, command, unreachable).await;
    let transcript = box_transcript(&runs);
    assert_eq!(exit, 7, "{transcript}");
    let run = runs.last().expect("the step ran");
    assert!(
        run.stderr
            .contains("Could not reach host beta.local-minvmd0. Box web can be on that host"),
        "{transcript}"
    );
    assert_eq!(run.stdout, "", "{transcript}");

    // `min box list -o json`: every object carries the `min/v1/box`
    // schema, with the box's id, name, provider and host.
    let list_json = async |out: &mut Vec<u8>| {
        let mut client = connect_daemon(&global).await?;
        let listed: Vec<ListedBox> = list_box_records(&mut client, None)
            .await?
            .into_iter()
            .map(|record| ListedBox {
                provider: host.provider.to_string(),
                host: host.host.clone(),
                record,
            })
            .collect();
        render_box_list_json(out, &listed)?;
        Ok(())
    };
    let command = "min box list --all -o json".to_owned();
    let exit = run_address_step(&mut runs, &id, command, list_json).await;
    let transcript = box_transcript(&runs);
    assert_eq!(exit, 0, "{transcript}");
    let objects: Vec<serde_json_lenient::Value> =
        serde_json_lenient::from_str(&runs.last().expect("the step ran").stdout)
            .unwrap_or_else(|e| panic!("one JSON array: {e}\n{transcript}"));
    assert_eq!(objects.len(), 1, "{transcript}");
    for object in &objects {
        assert_eq!(
            object["schema"],
            ObjectType::Box.schema(),
            "the schema stamp\n{transcript}"
        );
    }
    assert_eq!(objects[0]["id"], id.as_str(), "{transcript}");
    assert_eq!(objects[0]["name"], "web", "{transcript}");
    assert_eq!(objects[0]["provider"], host.provider, "{transcript}");
    assert_eq!(objects[0]["host"], host.host.as_str(), "{transcript}");

    // A secret renders only as its reference, in every output mode.
    #[derive(serde::Serialize)]
    struct BoxSecret {
        name: &'static str,
        secret: Secret,
    }
    impl Rendered for BoxSecret {
        const TYPE: ObjectType = ObjectType::Box;
        fn text(&self, out: &mut dyn std::io::Write) -> std::io::Result<()> {
            writeln!(out, "{}: {}", self.name, self.secret)
        }
    }
    let object = BoxSecret {
        name: "web",
        secret: Secret::with_value("env:API_TOKEN", "s3cr3t-value"),
    };
    for mode in OutputMode::ALL {
        let mut out = Vec::new();
        crate::output::write_object(&mut out, mode, &object).expect("the object renders");
        let text = String::from_utf8(out).expect("the output is UTF-8");
        assert!(!text.contains("s3cr3t-value"), "{mode:?}: {text}");
        assert!(text.contains("env:API_TOKEN"), "{mode:?}: {text}");
        if mode.is_machine() {
            let value: serde_json_lenient::Value =
                serde_json_lenient::from_str(&text).expect("one JSON object");
            assert_eq!(value["schema"], ObjectType::Box.schema(), "{text}");
            assert_eq!(value["secret"]["ref"], "env:API_TOKEN", "{text}");
        }
    }

    // `min box stop <id>` and `min box rm provider/host/name`: the
    // changing verbs take the same addresses.
    let stop = async |out: &mut Vec<u8>| {
        stop_box_on_hosts(local_hosts(&global)?, out, &id, false).await?;
        Ok(())
    };
    let command = format!("min box stop {id}");
    let exit = run_address_step(&mut runs, &id, command, stop).await;
    let transcript = box_transcript(&runs);
    assert_eq!(exit, 0, "{transcript}");
    let rm = async |out: &mut Vec<u8>| {
        let _ = out;
        rm_box_on_hosts(local_hosts(&global)?, &qualified, false).await?;
        Ok(())
    };
    let command = format!("min box rm {qualified}");
    let exit = run_address_step(&mut runs, &id, command, rm).await;
    let transcript = box_transcript(&runs);
    assert_eq!(exit, 0, "{transcript}");

    // The removed box is not found by its id any more.
    let gone = async |out: &mut Vec<u8>| show(&id, out).await;
    let command = format!("min box show {id}");
    let exit = run_address_step(&mut runs, &id, command, gone).await;
    let transcript = box_transcript(&runs);
    assert_eq!(exit, 4, "{transcript}");

    // Each command that resolves an address logs one resolution inside
    // its step's span: the host it reached for a resolved address, or the
    // outcome of a refused one.
    let log = log.contents();
    let resolutions = |step: usize, outcome: &str| {
        let span = format!("box_address_step{{step={step} box_id=\"{id}\"}}");
        log.lines()
            .filter(|line| line.contains(&span) && line.contains(outcome))
            .collect::<Vec<_>>()
    };
    let expected = [
        (0, "outcome=\"resolved\""),
        (1, "outcome=\"resolved\""),
        (2, "outcome=\"resolved\""),
        (3, "outcome=\"not found\""),
        (4, "outcome=\"host unreachable\""),
        (6, "outcome=\"resolved\""),
        (7, "outcome=\"resolved\""),
        (8, "outcome=\"not found\""),
    ];
    for (step, outcome) in expected {
        let lines = resolutions(step, outcome);
        assert_eq!(
            lines.len(),
            1,
            "step {step} ({}): one `{outcome}` resolution\n{transcript}\n{log}",
            runs[step].command
        );
        if outcome.contains("resolved") {
            assert!(
                lines[0].contains(&format!("host={}", host.host)),
                "step {step}: the host it reached\n{log}"
            );
        }
    }
}

/// A native host whose socket a harness daemon serves, with a running box
/// named `web` and a running box named `locked` whose spec sets `[io]
/// exec_enabled = false`. Holds the state dir, the daemon and the project
/// dir.
struct ExecHost {
    _state: tempfile::TempDir,
    _server: minimald::test_harness::TestServer,
    _project: tempfile::TempDir,
    global: GlobalArgs,
    web: boxes::SessionId,
    locked: boxes::SessionId,
}

async fn exec_host() -> ExecHost {
    use minimald_rpc::{
        ConfigureLoadout, ConfigureLoadoutRequest, CreateSession, Errorable, FinalizeSession,
        FinalizeSessionRequest,
    };

    let state = tempfile::tempdir().expect("a temp minimal state dir");
    let global = GlobalArgs {
        repo_dir: None,
        minimal_dir: Some(state.path().to_path_buf()),
        config_dir: None,
        provider: Some(Provider::LocalMinimald),
        no_input: true,
        vm: None,
    };
    let sock = client::resolve_socket_path(global.minimal_dir.as_deref(), global.use_minvmd())
        .expect("the native daemon's socket path");
    std::fs::create_dir_all(sock.parent().expect("the socket has a dir"))
        .expect("the native daemon's state dir");
    let server = minimald::test_harness::TestServer::new().await;
    server.listen_on_uds(&sock).await;
    let project = tempfile::tempdir().expect("a temp project dir");
    let project_path = project.path().to_str().expect("a UTF-8 project path");
    let mut daemon = server.connect().await;
    let web =
        minimald::test_harness::create_configured_session(&mut daemon, "web", project_path).await;

    // The same steps as `create_configured_session`, with a stored spec.
    let mut create = minimald::test_harness::create_session_req("locked", project_path);
    create.spec = Some(serde_json_lenient::json!({"v": 0, "io": {"exec_enabled": false}}));
    let locked = daemon.call::<CreateSession>(&create).await.unwrap().id;
    minimald::test_harness::unwrap_ready(
        daemon
            .call::<ConfigureLoadout>(&ConfigureLoadoutRequest {
                session_id: locked,
                contribution: Default::default(),
            })
            .await
            .unwrap(),
    );
    match daemon
        .call::<FinalizeSession>(&FinalizeSessionRequest {
            session_id: locked,
            report_shared_port_collisions: false,
        })
        .await
    {
        Errorable::Ok(_) => {}
        Errorable::Err { error } => panic!("FinalizeSession of the locked box: {error}"),
    }
    ExecHost {
        _state: state,
        _server: server,
        _project: project,
        global,
        web,
        locked,
    }
}

/// One `min box exec` run: what it wrote to stdout and stderr, the error
/// it ended with, and the exit code `main` gives that ending.
struct ExecRun {
    stdout: String,
    stderr: String,
    error: Option<anyhow::Error>,
    exit: u8,
}

impl ExecRun {
    fn of(result: Result<i32, anyhow::Error>, stdout: &[u8], stderr: &[u8]) -> Self {
        let (error, exit) = match result {
            Ok(code) => (None, u8::try_from(code).unwrap_or(1)),
            Err(error) => {
                let exit = exec_failure_code(&error);
                (Some(error), exit)
            }
        };
        Self {
            stdout: String::from_utf8_lossy(stdout).into_owned(),
            stderr: String::from_utf8_lossy(stderr).into_owned(),
            error,
            exit,
        }
    }

    /// The error as `main` prints it after `error: `.
    fn message(&self) -> Option<String> {
        self.error.as_ref().map(|e| format!("{e:#}"))
    }
}

impl std::fmt::Display for ExecRun {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "exit: {}", self.exit)?;
        writeln!(f, "error: {:?}", self.message())?;
        writeln!(f, "stdout:\n{}", self.stdout)?;
        writeln!(f, "stderr:\n{}", self.stderr)
    }
}

/// The exit code `main` ends with for `error`, as its `failure_exit_code`
/// maps the `min box exec` failures.
fn exec_failure_code(error: &anyhow::Error) -> u8 {
    if let Some(refusal) = error.downcast_ref::<BoxExecRefusal>() {
        return refusal.exit_code();
    }
    if error.downcast_ref::<BoxExecTimedOut>().is_some() {
        return BoxExecTimedOut::EXIT_CODE;
    }
    if let Some(refusal) = error.downcast_ref::<BoxAddressRefusal>() {
        return refusal.exit_code();
    }
    1
}

/// `min box exec <target> <flags> -- <argv>`, parsed as the CLI parses it.
fn box_exec_request(target: &str, flags: &[&str], argv: &[&str]) -> cmd::BoxExecRequest {
    let mut words = vec!["min", "box", "exec", target];
    words.extend_from_slice(flags);
    words.push("--");
    words.extend_from_slice(argv);
    let cli = Cli::try_parse_from(&words).unwrap_or_else(|e| panic!("{words:?}: {e}"));
    match cli.command {
        Some(Command::Box(BoxArgs {
            command: BoxCommand::Exec(args),
        })) => cmd::BoxExecRequest::from_args(args),
        _ => panic!("{words:?} is not `min box exec`"),
    }
}

/// Runs `min box exec` for `request` against the harness daemon of `host`,
/// with a terminal on stdin when `terminal` is set.
async fn run_box_exec_on_host_with(
    host: &ExecHost,
    request: &cmd::BoxExecRequest,
    terminal: bool,
) -> ExecRun {
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let result = cmd::box_exec_on_hosts(
        local_hosts(&host.global).expect("the local hosts"),
        cmd::daemon_host_kind(&host.global),
        request,
        terminal,
        None,
        &mut stdout,
        &mut stderr,
    )
    .await;
    ExecRun::of(result, &stdout, &stderr)
}

/// [`run_box_exec_on_host_with`] with a terminal on stdin. Each refusal
/// these runs meet comes before a `-t` exec attaches.
async fn run_box_exec_on_host(host: &ExecHost, request: &cmd::BoxExecRequest) -> ExecRun {
    run_box_exec_on_host_with(host, request, true).await
}

/// What one scripted exec channel answers: after `delay`, these messages,
/// then the close.
struct Script {
    delay: std::time::Duration,
    msgs: Vec<russh::ChannelMsg>,
}

/// A daemon's answer on an exec channel: `stdout`, `stderr`, then `status`.
fn answer(stdout: &[u8], stderr: &[u8], status: u32) -> Script {
    let mut msgs = Vec::new();
    if !stdout.is_empty() {
        msgs.push(russh::ChannelMsg::Data {
            data: stdout.to_vec().into(),
        });
    }
    if !stderr.is_empty() {
        msgs.push(russh::ChannelMsg::ExtendedData {
            data: stderr.to_vec().into(),
            ext: 1,
        });
    }
    msgs.push(russh::ChannelMsg::Eof);
    msgs.push(russh::ChannelMsg::ExitStatus {
        exit_status: status,
    });
    Script {
        delay: std::time::Duration::ZERO,
        msgs,
    }
}

/// Exec channels whose daemon answers each channel with the next script,
/// and records the exec form each channel carried.
struct ScriptedChannels {
    opened: Vec<String>,
    scripts: std::collections::VecDeque<Script>,
}

struct ScriptedChannel {
    delay: std::time::Duration,
    msgs: std::collections::VecDeque<russh::ChannelMsg>,
}

impl cmd::ExecChannel for ScriptedChannel {
    async fn wait(&mut self) -> Option<russh::ChannelMsg> {
        if !self.delay.is_zero() {
            tokio::time::sleep(std::mem::take(&mut self.delay)).await;
        }
        self.msgs.pop_front()
    }

    async fn eof(&mut self) -> Result<(), anyhow::Error> {
        Ok(())
    }

    fn input(&self) -> std::pin::Pin<Box<dyn tokio::io::AsyncWrite + Send>> {
        Box::pin(tokio::io::sink())
    }
}

impl cmd::ExecChannels for ScriptedChannels {
    type Channel = ScriptedChannel;

    async fn open(&mut self, wire: &str) -> Result<ScriptedChannel, anyhow::Error> {
        self.opened.push(wire.to_owned());
        let script = self
            .scripts
            .pop_front()
            .unwrap_or_else(|| panic!("no script for channel {wire}"));
        Ok(ScriptedChannel {
            delay: script.delay,
            msgs: script.msgs.into(),
        })
    }
}

/// Runs `request` over channels that answer with `scripts`. Returns the run
/// and the exec form of each channel it opened.
async fn run_scripted_exec(
    request: &cmd::BoxExecRequest,
    scripts: Vec<Script>,
) -> (ExecRun, Vec<minimald_rpc::exec::ExecRequest>) {
    let mut channels = ScriptedChannels {
        opened: Vec::new(),
        scripts: scripts.into(),
    };
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let result = cmd::exec_over(
        &mut channels,
        request,
        cmd::TtyAttach::Pipes,
        None,
        &mut stdout,
        &mut stderr,
    )
    .await;
    let opened = channels
        .opened
        .iter()
        .map(|wire| minimald_rpc::exec::ExecRequest::parse(wire).expect("an exec form"))
        .collect();
    (ExecRun::of(result, &stdout, &stderr), opened)
}

/// An exec id as the daemon mints one.
const AN_EXEC_ID: &str = "01928a3b-4c5d-7e6f-8a9b-0c1d2e3f4a5b";

/// The exec form `min box exec` sends for `argv` in `mode`.
fn exec_form(
    argv: &[&str],
    mode: minimald_rpc::exec::ExecMode,
    timeout_secs: Option<u64>,
) -> minimald_rpc::exec::ExecRequest {
    minimald_rpc::exec::ExecRequest::Exec(minimald_rpc::exec::ExecSpec {
        argv: argv.iter().map(|word| (*word).to_owned()).collect(),
        mode,
        timeout_secs,
    })
}

// BCLI-053: `min box exec web -- <cmd>` sends the command to the box as
// BOX-149's attached exec, relays its stdout and stderr, and exits with its
// code. Against a harness daemon, a box whose spec turns exec off is
// refused with exit 5, and a box that is not running with exit 2, in every
// mode, each in the CLI's own words. The command's span records the verb,
// the box id and the outcome.
#[tokio::test]
async fn box_exec_runs_command_and_exits_with_its_code() {
    use minimald_rpc::exec::ExecMode;

    let argv = ["sh", "-c", "echo out; echo err >&2; exit 3"];
    let (run, opened) = run_scripted_exec(
        &box_exec_request("web", &[], &argv),
        vec![answer(b"out\n", b"err\n", 3)],
    )
    .await;
    assert_eq!(run.exit, 3, "{run}");
    assert!(run.error.is_none(), "{run}");
    assert_eq!(run.stdout, "out\n", "{run}");
    assert_eq!(run.stderr, "err\n", "{run}");
    assert_eq!(opened, [exec_form(&argv, ExecMode::Attached, None)]);

    // A command's own stderr that reads like a refusal is still printed when
    // its code is not the refusal's.
    let (run, _) = run_scripted_exec(
        &box_exec_request("web", &[], &["false"]),
        vec![answer(
            b"",
            b"box web is stopped. Only a running box can run a command.\n",
            1,
        )],
    )
    .await;
    assert_eq!(run.exit, 1, "{run}");
    assert!(run.error.is_none(), "{run}");
    assert!(run.stderr.contains("Only a running box"), "{run}");

    let log = minimald::test_harness::captured_log();
    let host = exec_host().await;
    let marker = tempfile::tempdir().expect("a temp dir");
    let marker = marker.path().join("exec-ran");
    let touch = marker.to_str().expect("a UTF-8 path");
    let modes: [&[&str]; 3] = [&[], &["--detach"], &["-t"]];
    for flags in modes {
        let run =
            run_box_exec_on_host(&host, &box_exec_request("locked", flags, &["touch", touch]))
                .await;
        assert_eq!(run.exit, 5, "{flags:?}\n{run}");
        assert_eq!(
            run.message().as_deref(),
            Some("locked does not allow exec (its spec sets [io] exec_enabled = false)."),
            "{flags:?}\n{run}"
        );
        assert_eq!(run.stdout, "", "{flags:?}\n{run}");
        assert_eq!(run.stderr, "", "{flags:?}: no other words\n{run}");
        assert!(!marker.exists(), "{flags:?}: nothing ran\n{run}");
    }

    let mut out = Vec::new();
    cmd::stop_box_on_hosts(local_hosts(&host.global).unwrap(), &mut out, "web", true)
        .await
        .expect("stop the box");
    for flags in modes {
        let run =
            run_box_exec_on_host(&host, &box_exec_request("web", flags, &["touch", touch])).await;
        assert_eq!(run.exit, 2, "{flags:?}\n{run}");
        assert_eq!(
            run.message().as_deref(),
            Some("web is stopped. Only a running box can run a command."),
            "{flags:?}\n{run}"
        );
        assert_eq!(run.stdout, "", "{flags:?}\n{run}");
        assert_eq!(run.stderr, "", "{flags:?}: no other words\n{run}");
        assert!(!marker.exists(), "{flags:?}: nothing ran\n{run}");
    }

    let log = log.contents();
    for (id, outcome) in [(host.locked, "exec disabled"), (host.web, "not running")] {
        let events = log
            .lines()
            .filter(|line| {
                line.contains("verb=\"box exec\"")
                    && line.contains(&format!("box_id={id}"))
                    && line.contains(&format!("outcome=\"{outcome}\""))
            })
            .count();
        assert_eq!(events, 3, "one `{outcome}` event for each mode\n{log}");
    }
}

// BCLI-053: `min box exec -t` with a stdin that is not a terminal is refused
// with exit 2 before the box resolves. The refusal says why and what to do,
// and no exec starts in the box.
#[tokio::test]
async fn box_exec_tty_refuses_without_a_terminal() {
    let log = minimald::test_harness::captured_log();
    let host = exec_host().await;
    let marker = tempfile::tempdir().expect("a temp dir");
    let marker = marker.path().join("exec-ran");
    let touch = marker.to_str().expect("a UTF-8 path");
    for flags in [&["-t"][..], &["--tty"]] {
        let request = box_exec_request("web", flags, &["touch", touch]);
        let run = run_box_exec_on_host_with(&host, &request, false).await;
        assert_eq!(run.exit, 2, "{flags:?}\n{run}");
        assert_eq!(
            run.message().as_deref(),
            Some(
                "Did not run the command in web: -t needs a terminal. \
                 Stdin is not a terminal. Run `min box exec web -- <command>` \
                 without -t, or run it from a terminal."
            ),
            "{flags:?}\n{run}"
        );
        assert_eq!(run.stdout, "", "{flags:?}\n{run}");
        assert_eq!(run.stderr, "", "{flags:?}: no exec id, no output\n{run}");
        assert!(!marker.exists(), "{flags:?}: nothing ran\n{run}");
    }
    let log = log.contents();
    let refused = log
        .lines()
        .filter(|line| {
            line.contains("verb=\"box exec\"") && line.contains("outcome=\"no terminal\"")
        })
        .count();
    assert_eq!(refused, 2, "one `no terminal` event for each run\n{log}");
}

// BCLI-053: `min box exec -t` starts BOX-149's terminal exec, prints its
// exec id to stderr, then attaches to it by that id and writes nothing but
// the exec's output to stdout. It exits with the exec's code.
#[tokio::test]
async fn box_exec_tty_prints_exec_id_to_stderr() {
    use minimald_rpc::exec::{ExecId, ExecMode, ExecRequest};

    let argv = ["sh", "-c", "echo hello-tty; exit 4"];
    let (run, opened) = run_scripted_exec(
        &box_exec_request("web", &["-t"], &argv),
        vec![
            answer(format!("{AN_EXEC_ID}\n").as_bytes(), b"", 0),
            answer(b"hello-tty\r\n", b"", 4),
        ],
    )
    .await;
    assert_eq!(run.exit, 4, "the exec's code\n{run}");
    assert_eq!(run.stderr, format!("{AN_EXEC_ID}\n"), "{run}");
    assert_eq!(run.stdout, "hello-tty\r\n", "only the exec's output\n{run}");
    assert_eq!(
        opened,
        [
            exec_form(&argv, ExecMode::Tty, None),
            ExecRequest::ExecAttach(ExecId::parse(AN_EXEC_ID).unwrap()),
        ]
    );

    let long = box_exec_request("web", &["--tty"], &["true"]);
    assert_eq!(long.mode, ExecMode::Tty, "--tty is -t");
    assert!(
        Cli::try_parse_from(["min", "box", "exec", "web", "-t", "--detach", "--", "true"]).is_err(),
        "-t and --detach do not go together"
    );
}

// BCLI-053: `min box exec --detach` starts BOX-149's detached exec, prints
// only its exec id to stdout, and returns without waiting for the command.
// A start that runs nothing prints the reason on stderr and its code.
#[tokio::test]
async fn box_exec_detach_prints_id_and_returns() {
    use minimald_rpc::exec::ExecMode;

    let (run, opened) = run_scripted_exec(
        &box_exec_request("web", &["--detach"], &["sleep", "600"]),
        vec![answer(format!("{AN_EXEC_ID}\n").as_bytes(), b"", 0)],
    )
    .await;
    assert_eq!(run.exit, 0, "{run}");
    assert_eq!(
        run.stdout,
        format!("{AN_EXEC_ID}\n"),
        "only the exec id\n{run}"
    );
    assert_eq!(run.stderr, "", "{run}");
    assert_eq!(
        opened,
        [exec_form(&["sleep", "600"], ExecMode::Detached, None)],
        "one channel, and no wait for the command"
    );

    let (run, _) = run_scripted_exec(
        &box_exec_request("web", &["--detach"], &["nope"]),
        vec![answer(
            b"",
            b"the command could not start in the box: nope\n",
            1,
        )],
    )
    .await;
    assert_eq!(run.exit, 1, "{run}");
    assert_eq!(run.stdout, "", "no exec id\n{run}");
    assert_eq!(
        run.stderr, "the command could not start in the box: nope\n",
        "{run}"
    );
}

// BCLI-053: `--timeout <duration>` takes seconds, minutes or hours, refuses
// anything else, and asks for the exec's own timeout (BOX-149) in every
// mode.
#[tokio::test]
async fn box_exec_timeout_flag_requests_exec_timeout() {
    use minimald_rpc::exec::ExecMode;

    for (flag, secs) in [("45", 45), ("30s", 30), ("5m", 300), ("1h", 3600)] {
        let request = box_exec_request("web", &["--timeout", flag], &["sleep", "30"]);
        assert_eq!(request.timeout_secs, Some(secs), "--timeout {flag}");
    }
    for refused in ["0", "0s", "abc", "-1", "1d", "s", ""] {
        let flag = format!("--timeout={refused}");
        let parsed = Cli::try_parse_from(["min", "box", "exec", "web", &flag, "--", "true"]);
        let error = match parsed {
            Ok(_) => panic!("--timeout {refused:?} is refused"),
            Err(error) => error.to_string(),
        };
        assert!(
            error.contains("such as 30s, 5m or 1h"),
            "{refused:?}: {error}"
        );
    }

    let (run, opened) = run_scripted_exec(
        &box_exec_request("web", &["--timeout", "5m"], &["make"]),
        vec![answer(b"", b"", 0)],
    )
    .await;
    assert_eq!(run.exit, 0, "{run}");
    assert_eq!(
        opened,
        [exec_form(&["make"], ExecMode::Attached, Some(300))]
    );
    let (run, opened) = run_scripted_exec(
        &box_exec_request("web", &["--detach", "--timeout", "30"], &["make"]),
        vec![answer(format!("{AN_EXEC_ID}\n").as_bytes(), b"", 0)],
    )
    .await;
    assert_eq!(run.exit, 0, "{run}");
    assert_eq!(opened, [exec_form(&["make"], ExecMode::Detached, Some(30))]);
    let (run, opened) = run_scripted_exec(
        &box_exec_request("web", &["-t", "--timeout", "1h"], &["make"]),
        vec![
            answer(format!("{AN_EXEC_ID}\n").as_bytes(), b"", 0),
            answer(b"", b"", 0),
        ],
    )
    .await;
    assert_eq!(run.exit, 0, "{run}");
    assert_eq!(opened[0], exec_form(&["make"], ExecMode::Tty, Some(3600)));
}

// BCLI-053: an exec that its own timeout ended returns 124 from `min box
// exec` in each mode that waits for it, and from the wait for the exec by
// its id, as the timeout failure that a machine-mode run answers with
// `code = "timeout"`. A command that exits 124 by itself is not one.
#[tokio::test]
async fn exec_timeout_returns_124_from_exec_and_wait_exec() {
    use minimald_rpc::exec::{ExecId, ExecRequest};

    // Attached: the daemon ends the exec with 124 at the timeout.
    let mut ended = answer(b"", b"", 124);
    ended.delay = std::time::Duration::from_secs(1);
    let (run, _) = run_scripted_exec(
        &box_exec_request("web", &["--timeout", "1"], &["sleep", "30"]),
        vec![ended],
    )
    .await;
    assert_eq!(run.exit, 124, "{run}");
    assert!(
        run.error
            .as_ref()
            .is_some_and(|e| e.downcast_ref::<BoxExecTimedOut>().is_some()),
        "{run}"
    );
    assert_eq!(
        run.message().as_deref(),
        Some("The command in web ran for longer than its timeout of 1s and was stopped."),
        "{run}"
    );
    let (run, _) = run_scripted_exec(
        &box_exec_request("web", &["--timeout", "60"], &["sh", "-c", "exit 124"]),
        vec![answer(b"", b"", 124)],
    )
    .await;
    assert_eq!(run.exit, 124, "{run}");
    assert!(run.error.is_none(), "exit 124 before the timeout\n{run}");

    // With a terminal: the attach ends with 124, and the exec's wait says
    // why, in the daemon's words.
    let id = ExecId::parse(AN_EXEC_ID).unwrap();
    let timed_out = format!("exec {AN_EXEC_ID} ran past its timeout and was stopped.\n");
    let (run, opened) = run_scripted_exec(
        &box_exec_request("web", &["-t", "--timeout", "1"], &["sleep", "30"]),
        vec![
            answer(format!("{AN_EXEC_ID}\n").as_bytes(), b"", 0),
            answer(b"", b"", 124),
            answer(b"", timed_out.as_bytes(), 124),
        ],
    )
    .await;
    assert_eq!(run.exit, 124, "{run}");
    assert_eq!(
        run.message().as_deref(),
        Some(
            format!("Exec {AN_EXEC_ID} in web ran for longer than its timeout and was stopped.")
                .as_str()
        ),
        "{run}"
    );
    assert_eq!(opened.last(), Some(&ExecRequest::ExecWait(id.clone())));

    // The wait for an exec by its id, as `min box wait <box> --exec <id>`
    // makes it.
    for (said, status, timeout) in [
        (timed_out.as_str(), 124, true),
        ("", 124, false),
        ("", 7, false),
    ] {
        let mut channels = ScriptedChannels {
            opened: Vec::new(),
            scripts: vec![answer(b"", said.as_bytes(), status)].into(),
        };
        let mut stderr = Vec::new();
        let waited = cmd::wait_exec_over(&mut channels, "web", &id, &mut stderr).await;
        let run = ExecRun::of(waited, b"", &stderr);
        assert_eq!(run.exit, u8::try_from(status).unwrap(), "{run}");
        assert_eq!(
            run.error
                .as_ref()
                .is_some_and(|e| e.downcast_ref::<BoxExecTimedOut>().is_some()),
            timeout,
            "{run}"
        );
        assert_eq!(run.stderr, "", "{run}");
        assert_eq!(
            channels.opened,
            [ExecRequest::ExecWait(id.clone()).encode()],
            "{run}"
        );
    }
}

/// A harness daemon under `state` that the native host's socket serves,
/// with the global flags that select it, as the first-slice test sets
/// them up.
async fn native_box_daemon(
    minimal_dir: &std::path::Path,
    state: tempfile::TempDir,
) -> (minimald::test_harness::TestServer, GlobalArgs) {
    let global = GlobalArgs {
        repo_dir: None,
        minimal_dir: Some(minimal_dir.to_path_buf()),
        config_dir: None,
        provider: Some(Provider::LocalMinimald),
        no_input: true,
        vm: None,
    };
    let sock = client::resolve_socket_path(global.minimal_dir.as_deref(), global.use_minvmd())
        .expect("the native daemon's socket path");
    std::fs::create_dir_all(sock.parent().expect("the socket has a dir"))
        .expect("the native daemon's state dir");
    let server = minimald::test_harness::TestServer::new_in(state).await;
    server.listen_on_uds(&sock).await;
    (server, global)
}

/// `min box events` arguments for `target`, or for the children of
/// `parent`.
fn events_args(target: Option<&str>, parent: Option<&str>, follow: bool) -> BoxEventsArgs {
    BoxEventsArgs {
        target: target.map(str::to_owned),
        parent: parent.map(str::to_owned),
        output: Some(BoxEventsOutputFormat::Jsonl),
        follow,
    }
}

/// Each line `min box events -o jsonl` wrote, as a JSON object.
fn event_lines(out: &[u8]) -> Vec<serde_json_lenient::Value> {
    String::from_utf8_lossy(out)
        .lines()
        .map(|line| serde_json_lenient::from_str(line).expect("each line is one JSON object"))
        .collect()
}

/// A writer that a test reads while a followed command still writes to it.
#[derive(Clone, Default)]
struct SharedOut(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for SharedOut {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl SharedOut {
    fn lines(&self) -> Vec<serde_json_lenient::Value> {
        event_lines(&self.0.lock().unwrap())
    }

    /// Waits until the command wrote more than `count` lines, and returns
    /// them all.
    async fn more_than(&self, count: usize) -> Vec<serde_json_lenient::Value> {
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
        loop {
            let lines = self.lines();
            if lines.len() > count {
                return lines;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "no event after the first {count}: {lines:?}"
            );
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    }
}

// BCLI-062, BOX-017: `min box cp <box>:<path> <local>` copies a file out
// of a stopped box, from the files the box kept, into a local directory
// under the file's own name or to a local file path.
#[tokio::test]
async fn box_cp_reads_stopped_box_as_box_017() {
    let minimal_dir = tempfile::tempdir().expect("a temp minimal state dir");
    let state = tempfile::tempdir().expect("a temp daemon state dir");
    let (server, global) = native_box_daemon(minimal_dir.path(), state).await;
    let project = tempfile::tempdir().expect("a temp project dir");
    let mut daemon = server.connect().await;
    let id = minimald::test_harness::create_configured_session(
        &mut daemon,
        "web",
        project.path().to_str().expect("a UTF-8 project path"),
    )
    .await;
    {
        use tokio::io::AsyncWriteExt as _;
        let sftp = daemon.open_sftp(id).await;
        for (path, contents) in [
            ("notes.txt", b"kept in the home"),
            ("/workbench/tree.txt", b"kept in the tree"),
        ] {
            let mut file = sftp.create(path).await.unwrap();
            file.write_all(contents).await.unwrap();
            file.shutdown().await.unwrap();
        }
    }

    let mut stopped = Vec::new();
    stop_box_on_hosts(local_hosts(&global).unwrap(), &mut stopped, "web", false)
        .await
        .expect("the box stops");
    let host = local_hosts(&global)
        .unwrap()
        .into_iter()
        .find(|host| host.selected)
        .expect("the native host is selected");
    assert_eq!(address_state(&host, "web").await, "stopped");

    let local = tempfile::tempdir().expect("a local dir");
    let written = box_cp_on_hosts(local_hosts(&global).unwrap(), "web:notes.txt", local.path())
        .await
        .expect("the copy out of the stopped box succeeds");
    assert_eq!(written, local.path().join("notes.txt"));
    assert_eq!(std::fs::read(&written).unwrap(), b"kept in the home");

    let file = local.path().join("copied.txt");
    let by_id = format!("{id}:/workbench/tree.txt");
    box_cp_on_hosts(local_hosts(&global).unwrap(), &by_id, &file)
        .await
        .expect("the copy by id succeeds");
    assert_eq!(std::fs::read(&file).unwrap(), b"kept in the tree");

    let missing = box_cp_on_hosts(local_hosts(&global).unwrap(), "web:gone.txt", local.path())
        .await
        .expect_err("a file the box does not have");
    assert!(
        format!("{missing:#}") == "Box web has no file gone.txt.",
        "{missing:#}"
    );
    assert_eq!(
        missing
            .downcast_ref::<BoxFileRefusal>()
            .map(BoxFileRefusal::exit_code),
        Some(4),
        "a missing file ends with the not-found code: {missing:#}"
    );
    assert!(!local.path().join("gone.txt").exists());
    // A failed copy leaves no temporary file beside the destination either.
    assert_eq!(
        std::fs::read_dir(local.path()).unwrap().count(),
        2,
        "only notes.txt and copied.txt"
    );

    // A directory fails after the temporary file exists. The error says
    // the path is a directory, and the temporary file is gone.
    let dir = box_cp_on_hosts(
        local_hosts(&global).unwrap(),
        "web:/workbench",
        local.path(),
    )
    .await
    .expect_err("a directory is not a file");
    assert_eq!(
        format!("{dir:#}"),
        format!(
            "/workbench in box web is a directory, and min box cp copies one file. \
             Run `min box cp web:/workbench/<file> {}`.",
            local.path().join("workbench").display()
        )
    );
    let names: Vec<_> = std::fs::read_dir(local.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert_eq!(names.len(), 2, "only notes.txt and copied.txt: {names:?}");

    let refused = box_cp_on_hosts(local_hosts(&global).unwrap(), "notes.txt", local.path())
        .await
        .expect_err("a source with no box");
    assert!(
        refused
            .to_string()
            .contains("Run `min box cp <box>:<path> "),
        "{refused}"
    );
}

// BCLI-016: `min box events <box> -o jsonl` replays every event the box
// kept, oldest first, also after the box stopped. Each line is one
// `min/v1/event` object with `ts`, `box`, `parent`, `type` and `data`.
#[tokio::test]
async fn events_jsonl_replay_schema_fields() {
    let minimal_dir = tempfile::tempdir().expect("a temp minimal state dir");
    let state = tempfile::tempdir().expect("a temp daemon state dir");
    let (server, global) = native_box_daemon(minimal_dir.path(), state).await;
    let project = tempfile::tempdir().expect("a temp project dir");
    let mut daemon = server.connect().await;
    let id = minimald::test_harness::create_configured_session(
        &mut daemon,
        "web",
        project.path().to_str().expect("a UTF-8 project path"),
    )
    .await;

    let replay = async |args: &BoxEventsArgs| {
        let (mut out, mut err) = (Vec::new(), Vec::new());
        box_events_on_hosts(local_hosts(&global).unwrap(), args, &mut out, &mut err)
            .await
            .expect("the events replay");
        assert_eq!(String::from_utf8_lossy(&err), "", "nothing on stderr");
        event_lines(&out)
    };
    let running = replay(&events_args(Some("web"), None, false)).await;
    assert!(!running.is_empty(), "a created box has events");
    assert_eq!(running[0]["type"], "created", "{running:?}");

    let mut stopped = Vec::new();
    stop_box_on_hosts(local_hosts(&global).unwrap(), &mut stopped, "web", false)
        .await
        .expect("the box stops");
    let lines = replay(&events_args(Some("web"), None, false)).await;
    assert!(
        lines.len() > running.len(),
        "the stop adds an event: {lines:?}"
    );
    assert_eq!(
        lines[..running.len()],
        running[..],
        "the same stream, replayed"
    );
    let mut last_ts = None;
    for line in &lines {
        let object = line.as_object().expect("a JSON object");
        let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            ["box", "data", "parent", "schema", "ts", "type"],
            "{line}"
        );
        assert_eq!(line["schema"], "min/v1/event", "{line}");
        assert_eq!(line["box"], id.to_string(), "{line}");
        assert!(
            line["parent"].is_null(),
            "a box created outside any box: {line}"
        );
        assert!(line["type"].is_string(), "{line}");
        assert!(line["data"].is_object(), "{line}");
        let ts = chrono::DateTime::parse_from_rfc3339(line["ts"].as_str().expect("ts is a string"))
            .expect("ts is RFC 3339");
        assert!(
            line["ts"].as_str().unwrap().ends_with('Z'),
            "ts is UTC: {line}"
        );
        assert!(
            last_ts.is_none_or(|last| ts >= last),
            "oldest first: {lines:?}"
        );
        last_ts = Some(ts);
    }

    // The text form gives one line for each event, with its type.
    let mut text_args = events_args(Some("web"), None, false);
    text_args.output = None;
    let (mut out, mut err) = (Vec::new(), Vec::new());
    box_events_on_hosts(
        local_hosts(&global).unwrap(),
        &text_args,
        &mut out,
        &mut err,
    )
    .await
    .expect("the text replay");
    let text = String::from_utf8_lossy(&out);
    assert_eq!(text.lines().count(), lines.len(), "{text}");
    assert!(
        text.lines()
            .next()
            .is_some_and(|line| line.contains(&format!("  {id}  created"))),
        "{text}"
    );
}

// BCLI-016: `min box events --follow` replays the events the box kept,
// then writes each new one as it happens, and ends when the box is
// removed.
#[tokio::test]
async fn events_follow_replays_then_tails() {
    let minimal_dir = tempfile::tempdir().expect("a temp minimal state dir");
    let state = tempfile::tempdir().expect("a temp daemon state dir");
    let (server, global) = native_box_daemon(minimal_dir.path(), state).await;
    let project = tempfile::tempdir().expect("a temp project dir");
    let mut daemon = server.connect().await;
    minimald::test_harness::create_configured_session(
        &mut daemon,
        "web",
        project.path().to_str().expect("a UTF-8 project path"),
    )
    .await;
    let (mut replay, mut err) = (Vec::new(), Vec::new());
    box_events_on_hosts(
        local_hosts(&global).unwrap(),
        &events_args(Some("web"), None, false),
        &mut replay,
        &mut err,
    )
    .await
    .expect("the replay");
    let replayed = event_lines(&replay);

    let shared = SharedOut::default();
    let args = events_args(Some("web"), None, true);
    let follow = async {
        let (mut out, mut err) = (shared.clone(), Vec::new());
        box_events_on_hosts(local_hosts(&global).unwrap(), &args, &mut out, &mut err).await
    };
    let drive = async {
        let first = shared.more_than(replayed.len() - 1).await;
        assert_eq!(first, replayed, "the follow replays the kept events first");
        let mut stopped = Vec::new();
        stop_box_on_hosts(local_hosts(&global).unwrap(), &mut stopped, "web", false)
            .await
            .expect("the box stops");
        let tailed = shared.more_than(replayed.len()).await;
        assert_eq!(tailed[..replayed.len()], replayed[..]);
        rm_box_on_hosts(local_hosts(&global).unwrap(), "web", false)
            .await
            .expect("the stopped box is removed");
    };
    let (followed, ()) = tokio::time::timeout(std::time::Duration::from_secs(60), async {
        tokio::join!(follow, drive)
    })
    .await
    .expect("the follow ends when the box is removed");
    followed.expect("the follow ends cleanly");
    let lines = shared.lines();
    assert!(lines.len() > replayed.len(), "{lines:?}");
}

/// Sets `parent` in the record of box `id` that the daemon keeps under
/// `state`, as a box created inside `parent` has it.
fn set_record_parent(state: &std::path::Path, id: boxes::SessionId, parent: boxes::SessionId) {
    fn records(dir: &std::path::Path, found: &mut Vec<std::path::PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                records(&path, found);
            } else if path.file_name().is_some_and(|name| name == "record.json") {
                found.push(path);
            }
        }
    }
    let mut found = Vec::new();
    records(state, &mut found);
    for path in found {
        let raw = std::fs::read(&path).unwrap();
        let Ok(mut record) = serde_json_lenient::from_slice::<serde_json_lenient::Value>(&raw)
        else {
            continue;
        };
        if record["id"] == id.to_string() {
            record["parent"] = serde_json_lenient::Value::String(parent.to_string());
            std::fs::write(&path, serde_json_lenient::to_vec(&record).unwrap()).unwrap();
            return;
        }
    }
    panic!("no record of box {id} under {}", state.display());
}

// BCLI-016: `min box events --parent <box>` merges the event streams of
// every child of the box into one, in time order, each event naming its
// box. A box that is not a child is left out.
#[tokio::test]
async fn events_parent_merges_children() {
    let minimal_dir = tempfile::tempdir().expect("a temp minimal state dir");
    let state = tempfile::tempdir().expect("a temp daemon state dir");
    let state_path = state.path().to_path_buf();
    let (server, global) = native_box_daemon(minimal_dir.path(), state).await;
    let project = tempfile::tempdir().expect("a temp project dir");
    let project = project.path().to_str().expect("a UTF-8 project path");
    let mut daemon = server.connect().await;
    let parent =
        minimald::test_harness::create_configured_session(&mut daemon, "lead", project).await;
    let first =
        minimald::test_harness::create_configured_session(&mut daemon, "one", project).await;
    let other =
        minimald::test_harness::create_configured_session(&mut daemon, "other", project).await;
    let second =
        minimald::test_harness::create_configured_session(&mut daemon, "two", project).await;
    for name in ["one", "two"] {
        let mut stopped = Vec::new();
        stop_box_on_hosts(local_hosts(&global).unwrap(), &mut stopped, name, false)
            .await
            .expect("the child stops");
    }
    for child in [first, second] {
        set_record_parent(&state_path, child, parent);
    }

    let (mut out, mut err) = (Vec::new(), Vec::new());
    box_events_on_hosts(
        local_hosts(&global).unwrap(),
        &events_args(None, Some("lead"), false),
        &mut out,
        &mut err,
    )
    .await
    .expect("the merged replay");
    assert_eq!(String::from_utf8_lossy(&err), "");
    let lines = event_lines(&out);
    let boxes_seen: std::collections::BTreeSet<String> = lines
        .iter()
        .map(|line| line["box"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(
        boxes_seen,
        [first.to_string(), second.to_string()].into(),
        "only the children: {lines:?}"
    );
    assert!(!boxes_seen.contains(&other.to_string()));
    assert!(!boxes_seen.contains(&parent.to_string()));
    let ts: Vec<_> = lines
        .iter()
        .map(|line| {
            chrono::DateTime::parse_from_rfc3339(line["ts"].as_str().expect("ts is a string"))
                .expect("ts is RFC 3339")
        })
        .collect();
    assert!(ts.is_sorted(), "one stream in time order: {lines:?}");
    // Each child's own stream keeps its order inside the merge.
    for child in [first, second] {
        let types: Vec<&str> = lines
            .iter()
            .filter(|line| line["box"] == child.to_string())
            .map(|line| line["type"].as_str().unwrap())
            .collect();
        assert_eq!(types.first(), Some(&"created"), "{lines:?}");
        assert!(types.len() > 1, "the stop is in the stream: {lines:?}");
    }

    // A box with no children names the box and its host on stderr, and
    // writes no event.
    let (mut out, mut err) = (Vec::new(), Vec::new());
    box_events_on_hosts(
        local_hosts(&global).unwrap(),
        &events_args(None, Some("other"), false),
        &mut out,
        &mut err,
    )
    .await
    .expect("no children is not a failure");
    assert!(out.is_empty());
    assert!(
        String::from_utf8_lossy(&err)
            .starts_with(&format!("Box {other} has no child boxes on host ")),
        "{}",
        String::from_utf8_lossy(&err)
    );
}

/// A session record carrying `mode` and `box_addresses`, with everything
/// else at its default.
fn hold_record(
    mode: boxes::NetworkMode,
    box_addresses: Option<boxes::BoxAddresses>,
) -> boxes::Record {
    boxes::Record {
        id: boxes::SessionId::nil(),
        name: Some("web".to_string()),
        username: None,
        project_path: paths::HostAbsPath::try_new("/tmp/project").unwrap(),
        network: mode,
        policy: boxes::BoxPolicy::default(),
        task_addresses: Vec::new(),
        box_addresses,
        status: boxes::BoxState::Active,
        reason: None,
        exit_code: None,
        signal: None,
        hooks_enabled: true,
        host_ip_enforcement: None,
        box_id: None,
        host_row_bound: false,
        bound_ports: std::collections::BTreeSet::new(),
        ends_with_run: false,
        sealed_deliveries: Vec::new(),
        root_certificate: None,
        box_type: None,
        parent: None,
        project_root: None,
        attrs: Default::default(),
    }
}

/// NET-046: a named `none` box holds its name on the VM host, so the
/// paths that release or move a hold treat it as a `host_ip` box. The
/// dashboard's destroy (`dash/rpc.rs`) releases a hold only for a record
/// `holds_name` accepts, and `min session rename` and the dashboard's
/// rename move a hold only for such a record. An own-address box owns
/// its name through its row, and holds nothing.
#[test]
fn none_box_hold_is_released_by_destroy_and_moved_by_rename() {
    assert!(
        crate::holds_name(&hold_record(boxes::NetworkMode::NoNet, None)),
        "the dashboard's destroy releases a `none` box's hold, and a rename moves it"
    );
    assert!(
        crate::holds_name(&hold_record(boxes::NetworkMode::HostNet, None)),
        "a `host_ip` box's hold is released and moved as before"
    );
    let row = boxes::BoxAddresses {
        switch_address: std::net::Ipv4Addr::new(10, 0, 0, 2),
        loopback_address: std::net::Ipv4Addr::new(127, 0, 0, 2),
    };
    assert!(
        !crate::holds_name(&hold_record(boxes::NetworkMode::NoNet, Some(row))),
        "a box with a row owns its name through the row"
    );
}

/// NET-022: a held port that frees after the VM start publishes on the VM
/// host daemon only, so the guest reply carries no proxy port. The BOX NAMES
/// row then reads the port the VM host daemon serves on, and says the names
/// open through it, on one VM and across VMs. While the port is held, the
/// row names the cause.
#[test]
fn ls_warning_clears_on_recovery_with_no_guest_port() {
    let mut resp = listing_of(&[("web", None, None)]);
    resp.hostname_proxy_port = None;
    resp.answerer_bound = true;
    let held = minimald_rpc::AnswererStatusReply {
        answerer: minimald_rpc::ZoneAnswererStatus::Registered { port: 7_656 },
        proxy_down: Some(minimald_rpc::ProxyDown {
            port: 7_654,
            cause: minimald_rpc::ProxyDownCause::PortHeldAfterStart {
                holder: Some("pid 4242 (python3)".to_string()),
            },
        }),
    };
    let recovered = minimald_rpc::AnswererStatusReply {
        answerer: minimald_rpc::ZoneAnswererStatus::Registered { port: 7_656 },
        proxy_down: None,
    };
    let render = |reply: minimald_rpc::AnswererStatusReply, ports: &[u16]| {
        let mut out = Vec::new();
        cmd::format_ls_with_proxy_ports_on(
            &mut out,
            &LsArgs {
                raw: false,
                json: false,
            },
            &resp,
            Some(crate::resolver::LiveSurface::Proxy),
            Some(reply),
            ports,
            crate::resolver::HostInstall::default(),
        )
        .expect("rendering the listing");
        String::from_utf8(out).expect("the listing is UTF-8")
    };
    let box_names = |text: &str| {
        text.lines()
            .find(|line| line.starts_with("BOX NAMES:"))
            .map(str::to_string)
            .unwrap_or_else(|| panic!("a BOX NAMES row:\n{text}"))
    };

    let before = render(held.clone(), &[]);
    assert!(
        box_names(&before).contains("the hostname proxy is not serving: pid 4242 (python3)"),
        "the held port names its cause:\n{before}"
    );

    let after = render(recovered.clone(), &[7_654]);
    assert!(
        !after.contains("not serving"),
        "the cause clears once the port frees:\n{after}"
    );
    assert!(
        box_names(&after).contains("127.0.0.1:7654"),
        "the row names the port the proxy serves on:\n{after}"
    );
    assert!(
        after.contains("HOSTNAME PROXY:  listening on 127.0.0.1:7654"),
        "the HOSTNAME PROXY row names the served port:\n{after}"
    );

    // Across VMs, each VM reads its own served ports.
    let listings = [
        cmd::VmListing {
            vm: "default".to_string(),
            resp: resp.clone(),
            control_sock: None,
            running: true,
        },
        cmd::VmListing {
            vm: "other".to_string(),
            resp: resp.clone(),
            control_sock: None,
            running: true,
        },
    ];
    let mut out = Vec::new();
    cmd::format_ls_across_vms_with_proxy_ports_on(
        &mut out,
        &LsArgs {
            raw: false,
            json: false,
        },
        &listings,
        &[
            Some(crate::resolver::LiveSurface::Proxy),
            Some(crate::resolver::LiveSurface::Proxy),
        ],
        &[Some(recovered), Some(held)],
        &[vec![7_654], vec![]],
        crate::resolver::HostInstall::default(),
    )
    .expect("rendering the listing");
    let across = String::from_utf8(out).expect("the listing is UTF-8");
    let rows: Vec<&str> = across
        .lines()
        .filter(|line| line.starts_with("BOX NAMES:"))
        .collect();
    assert_eq!(rows.len(), 2, "one BOX NAMES row per VM:\n{across}");
    assert!(
        rows[0].contains("default") && rows[0].contains("127.0.0.1:7654"),
        "the recovered VM names its served port:\n{across}"
    );
    assert!(
        !rows[0].contains("not serving"),
        "the recovered VM carries no cause:\n{across}"
    );
    assert!(
        rows[1].contains("other") && rows[1].contains("not serving"),
        "the held VM keeps its cause:\n{across}"
    );
}
