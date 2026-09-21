use paths::DaemonAbsPath;

use super::*;
use std::time::Duration;

const DEFAULT_SIZE: WinSize = WinSize {
    rows: 24,
    cols: 80,
    xpixel: 0,
    ypixel: 0,
};

/// Wraps a chunk as a current-generation [`StdinMsg`] for the test
/// harness: hosts here never attach a binding, so the host's active
/// binding generation stays 0.
fn stdin_bytes(b: impl Into<bytes::Bytes>) -> StdinMsg {
    StdinMsg::new(0, StdinMsgKind::Bytes(b.into()))
}

/// Builds the `hakoniwa` account of a normal exit: the inner process
/// reported its own status, so `exit_code` is `Some`.
fn exited(code: i32) -> ExitReason {
    ExitReason {
        code,
        exit_code: Some(code),
        reason: format!("process(/usr/bin/bash) exited with code {code}"),
    }
}

/// Builds the account of a death `hakoniwa` attributes to a signal. Its
/// `new_failure` path leaves `exit_code` `None` and stamps code 125 —
/// the shape a container-level SIGKILL arrives in.
fn signalled(reason: &str) -> ExitReason {
    ExitReason {
        code: 125,
        exit_code: None,
        reason: reason.to_string(),
    }
}

fn eio() -> Option<std::io::Error> {
    Some(std::io::Error::from_raw_os_error(EIO_ON_EXIT))
}

/// The expected teardown, and the reason the prompt is silent by default:
/// a shell the user exited closes the last slave fd, the master reports
/// `EIO`, and the prompt alone tells the whole story.
#[test]
fn a_clean_exit_says_nothing_beyond_the_prompt() {
    let cause = TeardownCause {
        pty_err: eio(),
        exit: Some(exited(0)),
    };
    assert!(
        cause.notices().is_empty(),
        "a clean exit must stay silent: {:?}",
        cause.notices(),
    );
}

/// The regression this all exists for. A SIGKILLed container reaches the
/// binding as the *same* `EIO` a clean exit does, so before the exit
/// reason was carried through it rendered the identical silent prompt —
/// a killed session impersonating one the user ended.
#[test]
fn a_signalled_container_is_named_not_silently_passed_off_as_an_exit() {
    let cause = TeardownCause {
        pty_err: eio(),
        exit: Some(signalled("container received signal SIGKILL")),
    };
    assert_eq!(
        cause.notices(),
        vec!["Session ended abnormally: container received signal SIGKILL"],
        "a signalled container must say so, despite the expected EIO",
    );
}

/// A non-zero *exit* is still the shell exiting under its own control —
/// `exit 1` is not an anomaly, and must not be dressed up as one.
#[test]
fn a_non_zero_exit_is_still_a_normal_exit() {
    let cause = TeardownCause {
        pty_err: eio(),
        exit: Some(exited(1)),
    };
    assert!(
        cause.notices().is_empty(),
        "a non-zero exit is not abnormal: {:?}",
        cause.notices(),
    );
}

/// A master error that is *not* the expected on-exit `EIO` means the
/// session ended without the shell necessarily having died — surfaced as
/// before this change.
#[test]
fn an_unexpected_master_error_is_surfaced() {
    let cause = TeardownCause {
        pty_err: Some(std::io::Error::from_raw_os_error(libc::EINTR)),
        exit: Some(exited(0)),
    };
    let notices = cause.notices();
    assert_eq!(notices.len(), 1, "expected one notice: {notices:?}");
    assert!(
        notices[0].starts_with("Error reading stdout:"),
        "got: {notices:?}",
    );
}

/// The two notices are independent: an unexpected master error and an
/// abnormal end are different facts and both get said.
#[test]
fn both_halves_are_reported_together() {
    let cause = TeardownCause {
        pty_err: Some(std::io::Error::from_raw_os_error(libc::EINTR)),
        exit: Some(signalled("process(/usr/bin/bash) received signal SIGSEGV")),
    };
    let notices = cause.notices();
    assert_eq!(notices.len(), 2, "expected both notices: {notices:?}");
    assert!(notices[0].starts_with("Error reading stdout:"));
    assert_eq!(
        notices[1],
        "Session ended abnormally: process(/usr/bin/bash) received signal SIGSEGV",
    );
}

/// The reap failed, so there is no account of the end. The pty error still
/// governs, and an expected `EIO` still stays silent rather than inventing
/// an anomaly from missing information.
#[test]
fn a_missing_exit_reason_falls_back_to_the_pty_error() {
    let cause = TeardownCause {
        pty_err: eio(),
        exit: None,
    };
    assert!(
        cause.notices().is_empty(),
        "an unknown end is not evidence of an abnormal one: {:?}",
        cause.notices(),
    );
}

/// Which pty failures the host may block on before notifying the binding.
/// Only `EIO` promises a reap that returns; blocking on anything else
/// risks waiting on a live shell, so the user has to be told first.
#[test]
fn only_eio_promises_the_shell_is_already_gone() {
    assert!(
        shell_is_already_gone(&std::io::Error::from_raw_os_error(EIO_ON_EXIT)),
        "EIO is the last slave fd closing — the shell is gone",
    );
    for errno in [libc::EINTR, libc::EBADF, libc::ENXIO] {
        assert!(
            !shell_is_already_gone(&std::io::Error::from_raw_os_error(errno)),
            "errno {errno} can leave a live process; the host must not block on the reap",
        );
    }
}

/// Wires a channel into a host's binding slot and hands back the receiving
/// end, so a test can see exactly what the host tells an attached binding.
/// The join handle is a stand-in — nothing under test awaits it.
fn watch_binding<P: SessionProcess, G: SessionGuard>(
    host: &mut Host<P, G>,
) -> mpsc::Receiver<BindingMsg> {
    let (tx, rx) = mpsc::channel(16);
    host.remote = Some((tx, tokio::spawn(async {})));
    rx
}

/// Drains the binding's queue and returns the teardown it was handed — the
/// cause together with the unwind codes that travel with it — if any.
/// Stdout traffic is noise here — the shell echoes its own prompt.
fn teardown_from(rx: &mut mpsc::Receiver<BindingMsg>) -> Option<(TeardownCause, Vec<u8>)> {
    std::iter::from_fn(|| rx.try_recv().ok()).find_map(|msg| match msg {
        BindingMsg::TeardownDueToProcessExit {
            cause,
            unwind_codes,
        } => Some((cause, unwind_codes)),
        _ => None,
    })
}

/// The reorder this change turns on: the binding is told why it is going
/// away only *after* the process has been reaped, so the notice can carry
/// the reap's account of the end. An exit reason on the message is proof
/// of the ordering — notifying from `step`, as this used to, could not
/// have supplied one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_shell_exit_reaches_the_binding_with_the_reaped_exit_reason() {
    let (mut host, _handle) = Host::build(
        MockLauncher,
        HostParams {
            name: "test-session".to_string(),
            username: "user".to_string(),
            paths: test_paths(),
            sz: DEFAULT_SIZE,
            channel: None,
            control: None,
            delta: None,
            archives_dir: std::env::temp_dir(),
            session_id: sessions::SessionId::nil(),
            composition: None,
            connection_env: ConnectionEnv::new(),
        },
    )
    .await
    .expect("failed to build host");
    let mut rx = watch_binding(&mut host);
    let stdin = host.remote_tx.clone();
    let task = tokio::spawn(host.mainloop());

    stdin
        .send(stdin_bytes(format!("{MOCK_EXIT_LINE}\n").into_bytes()))
        .await
        .expect("failed to send exit line");
    tokio::time::timeout(Duration::from_secs(10), task)
        .await
        .expect("mainloop should terminate after the shell exits")
        .expect("host task should not panic during teardown")
        .expect("mainloop should return the reaped exit status");

    let (cause, _) = teardown_from(&mut rx).expect("the binding must be told the shell exited");
    assert!(
        cause.notices().is_empty(),
        "a clean exit stays silent: {:?}",
        cause.notices(),
    );
    let exit = cause
        .exit
        .as_ref()
        .expect("the teardown must carry the reap's account of the end");
    assert!(
        !exit.is_abnormal(),
        "a shell that exited on its own is not abnormal: {exit:?}",
    );
}

/// A binding whose client transport has stopped draining must not wedge the
/// host loop. The host forwards each pty read into the binding's mailbox;
/// once that mailbox fills, an unbounded send parked the loop for good, so
/// the host could no longer pump the pty, drain its own mailbox, or observe
/// the shell exiting — one dark client froze the whole session. The bounded
/// send sheds the stalled binding instead and keeps serving.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stalled_binding_does_not_wedge_the_host_loop() {
    let (mut host, handle) = Host::build(
        MockLauncher,
        HostParams {
            name: "test-session".to_string(),
            username: "user".to_string(),
            paths: test_paths(),
            sz: DEFAULT_SIZE,
            channel: None,
            control: None,
            delta: None,
            archives_dir: std::env::temp_dir(),
            session_id: sessions::SessionId::nil(),
            composition: None,
            connection_env: ConnectionEnv::new(),
        },
    )
    .await
    .expect("failed to build host");

    // A binding at the production mailbox size, pre-filled to capacity and
    // never drained: the receiver is held open but never read, standing in
    // for a client whose transport has gone dark mid-write. The next
    // forwarded pty read cannot be queued.
    let (tx, _rx_never_drained) = mpsc::channel(4);
    for _ in 0..4 {
        tx.try_send(BindingMsg::Stdin(Vec::new()))
            .expect("pre-fill stays within the mailbox capacity");
    }
    host.remote = Some((tx, tokio::spawn(async {})));

    let stdin = host.remote_tx.clone();
    let task = tokio::spawn(host.mainloop());

    // Make the shell echo so the host reads pty output and tries to forward
    // it to the full binding.
    stdin
        .send(stdin_bytes(b"ping\n".to_vec()))
        .await
        .expect("failed to send line");

    // Proof the loop did not wedge: it still answers its mailbox and has
    // stamped the stdout it read. An unbounded forward-send would have
    // parked the loop, and this probe would hang until the outer deadline.
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let attrs = handle
                .get_attrs()
                .await
                .expect("host must keep answering its mailbox");
            if attrs.stdout_last.is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("a stalled binding must not wedge the host loop");

    // The shed bumped the binding generation, so input still stamped with
    // the shed generation must be discarded rather than reach the shell.
    stdin
        .send(stdin_bytes(format!("{MOCK_EXIT_LINE}\n").into_bytes()))
        .await
        .expect("failed to send stale exit line");
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(
        !task.is_finished(),
        "input from the shed generation must not reach the shell",
    );

    // The same bytes on the post-shed generation still drive the shell to
    // exit: the host keeps serving after shedding the stalled binding.
    stdin
        .send(StdinMsg::new(
            1,
            StdinMsgKind::Bytes(bytes::Bytes::from(
                format!("{MOCK_EXIT_LINE}\n").into_bytes(),
            )),
        ))
        .await
        .expect("failed to send exit line");
    tokio::time::timeout(Duration::from_secs(10), task)
        .await
        .expect("mainloop should terminate after the shell exits")
        .expect("host task should not panic during teardown")
        .expect("mainloop should return the reaped exit status");
}

/// Reads forwarded stdout off the binding channel until `needle` shows up.
/// The host feeds its parser from the same read it forwards, and in that
/// order, so seeing the bytes here proves the screen has already absorbed
/// them — which is what keeps the assertion below off a race with the mock
/// shell's echo.
async fn await_forwarded(rx: &mut mpsc::Receiver<BindingMsg>, needle: &[u8]) {
    let mut seen: Vec<u8> = Vec::new();
    let wait = async {
        while let Some(msg) = rx.recv().await {
            if let BindingMsg::Stdin(b) = msg {
                seen.extend_from_slice(&b);
                if seen.windows(needle.len()).any(|w| w == needle) {
                    return;
                }
            }
        }
        panic!("the binding channel closed before the session echoed {needle:?}");
    };
    tokio::time::timeout(Duration::from_secs(10), wait)
        .await
        .unwrap_or_else(|_| panic!("timed out waiting for the session to echo {needle:?}"));
}

/// #1210: a process that dies while a full-screen app still has mouse
/// reporting on must hand the binding the codes that turn it back off. The
/// exit notices and the shell-exit prompt render into that same terminal,
/// and the user keeps it after answering — so this teardown has to carry
/// the unwind exactly as detach, supercede, and shutdown do.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_shell_exit_hands_the_binding_the_codes_that_leave_mouse_mode() {
    let (mut host, _handle) = Host::build(
        MockLauncher,
        HostParams {
            name: "test-session".to_string(),
            username: "user".to_string(),
            paths: test_paths(),
            sz: DEFAULT_SIZE,
            channel: None,
            control: None,
            delta: None,
            archives_dir: std::env::temp_dir(),
            session_id: sessions::SessionId::nil(),
            composition: None,
            connection_env: ConnectionEnv::new(),
        },
    )
    .await
    .expect("failed to build host");
    let mut rx = watch_binding(&mut host);
    let stdin = host.remote_tx.clone();
    let task = tokio::spawn(host.mainloop());

    // The mock shell echoes every line back, which is how a test drives the
    // host's screen into the state a full-screen app leaves behind: here,
    // any-motion mouse tracking left on.
    const MOUSE_ON: &[u8] = b"\x1b[?1003h";
    const MOUSE_OFF: &[u8] = b"\x1b[?1003l";
    let mut line = MOUSE_ON.to_vec();
    line.push(b'\n');
    stdin
        .send(stdin_bytes(line))
        .await
        .expect("failed to send the mouse-enable line");
    await_forwarded(&mut rx, MOUSE_ON).await;

    stdin
        .send(stdin_bytes(format!("{MOCK_EXIT_LINE}\n").into_bytes()))
        .await
        .expect("failed to send exit line");
    tokio::time::timeout(Duration::from_secs(10), task)
        .await
        .expect("mainloop should terminate after the shell exits")
        .expect("host task should not panic during teardown")
        .expect("mainloop should return the reaped exit status");

    let (_, unwind) = teardown_from(&mut rx).expect("the binding must be told the shell exited");
    assert!(
        unwind.windows(MOUSE_OFF.len()).any(|w| w == MOUSE_OFF),
        "the teardown must leave mouse mode: {unwind:?}",
    );
}

/// The host's unwind codes are deliberately *narrow*: it has a screen
/// model, so it emits only the modes this session actually set. That is
/// the whole reason the daemon-side set is better than the `min` client's
/// blind fallback, and it is what keeps `\x1b[?1049l` — the one sequence
/// that is not inert against a terminal on the normal buffer — off the
/// wire for a session that never left it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unwind_codes_narrow_to_what_the_screen_actually_set() {
    let (host, _handle) = Host::build(
        MockLauncher,
        HostParams {
            name: "test-session".to_string(),
            username: "user".to_string(),
            paths: test_paths(),
            sz: DEFAULT_SIZE,
            channel: None,
            control: None,
            delta: None,
            archives_dir: std::env::temp_dir(),
            session_id: sessions::SessionId::nil(),
            composition: None,
            connection_env: ConnectionEnv::new(),
        },
    )
    .await
    .expect("failed to build host");

    // A pristine screen: no alternate buffer, no hidden cursor, no input
    // modes to diff. Only the two unconditional resets may appear.
    let codes = host.unwind_codes();
    let rendered = String::from_utf8_lossy(&codes).into_owned();
    assert!(
        !rendered.contains(sessions::terminal::LEAVE_ALT_SCREEN),
        "rmcup must not be sent for a session that never left the normal buffer: {rendered:?}",
    );
    assert!(
        !rendered.contains(sessions::terminal::SHOW_CURSOR),
        "the cursor was never hidden, so nothing should unhide it: {rendered:?}",
    );
    assert_eq!(
        rendered,
        format!(
            "{}{}",
            sessions::terminal::SGR_RESET,
            sessions::terminal::FOCUS_REPORTING_OFF
        ),
        "a clean screen unwinds to the two blind resets and nothing else",
    );
}

/// A deliberate kill must not raise a shell-exit prompt: the caller already
/// decided the session's fate. `Message::Kill` returns `Err` from `step`
/// exactly as a pty failure does, so only the absence of a stashed pty
/// error keeps the two apart — an invariant a refactor could quietly drop.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_kill_tells_the_binding_nothing() {
    let (mut host, handle) = Host::build(
        MockLauncher,
        HostParams {
            name: "test-session".to_string(),
            username: "user".to_string(),
            paths: test_paths(),
            sz: DEFAULT_SIZE,
            channel: None,
            control: None,
            delta: None,
            archives_dir: std::env::temp_dir(),
            session_id: sessions::SessionId::nil(),
            composition: None,
            connection_env: ConnectionEnv::new(),
        },
    )
    .await
    .expect("failed to build host");
    let mut rx = watch_binding(&mut host);
    let task = tokio::spawn(host.mainloop());

    handle
        .kill(false)
        .await
        .expect("kill should reach the host");
    tokio::time::timeout(Duration::from_secs(10), task)
        .await
        .expect("host mainloop should terminate after kill")
        .expect("host task should not panic during teardown")
        .expect("mainloop should return the reaped exit status");

    assert!(
        teardown_from(&mut rx).is_none(),
        "a kill is not a shell exit and must raise no prompt",
    );
}

/// Precedence: the launcher `baseline` sits below the client-forwarded
/// `inherited`, which sits below the composition, which sits below the
/// per-connection `connection` facts. Later layers win on a shared key;
/// non-colliding keys from every layer survive.
#[test]
fn layer_session_env_precedence() {
    let sv = |k: &str, v: &str| (k.to_string(), v.to_string());
    let env = layer_session_env(
        // baseline: its LANG is overridden by inherited; NAME survives.
        vec![sv("LANG", "C"), sv("NAME", "box-1")],
        // inherited: LANG is overridden by composition; TZ survives.
        vec![sv("LANG", "de_DE.UTF-8"), sv("TZ", "Europe/Berlin")],
        // composition: beats inherited LANG; its TERM is overridden by the
        // connection; EDITOR survives.
        vec![
            sv("LANG", "fr_FR.UTF-8"),
            sv("TERM", "dumb"),
            sv("EDITOR", "hx"),
        ],
        // connection: authoritative TERM.
        vec![sv("TERM", "xterm-256color")],
    );

    assert_eq!(env.get("LANG").map(String::as_str), Some("fr_FR.UTF-8")); // composition > inherited > baseline
    assert_eq!(env.get("NAME").map(String::as_str), Some("box-1")); // baseline-only survives
    assert_eq!(env.get("TZ").map(String::as_str), Some("Europe/Berlin")); // inherited-only survives
    assert_eq!(env.get("TERM").map(String::as_str), Some("xterm-256color")); // connection > composition
    assert_eq!(env.get("EDITOR").map(String::as_str), Some("hx")); // composition-only survives
    assert_eq!(env.len(), 5);
}

/// A composed `SHELL` reaches the layered map, which is the input
/// the launcher hands [`crate::session_shell::resolve`] to pick the
/// shell it spawns. Nothing else sets the key — the sandbox's
/// `/usr/bin/bash` default lives a layer below this, inside
/// `sandbox2`'s `command_env` — so its absence here is exactly the
/// "no shell was asked for" case that keeps bash the default.
#[test]
fn a_composed_shell_reaches_the_layered_env() {
    let sv = |k: &str, v: &str| (k.to_string(), v.to_string());
    let without = layer_session_env(
        session_baseline_env("box-1", None),
        Vec::new(),
        Vec::new(),
        Vec::new(),
    );
    assert_eq!(
        without.get("SHELL"),
        None,
        "nothing but a composition may name the session's shell",
    );

    let with = layer_session_env(
        session_baseline_env("box-1", None),
        Vec::new(),
        vec![sv("SHELL", "/usr/bin/fish")],
        Vec::new(),
    );
    assert_eq!(with.get("SHELL").map(String::as_str), Some("/usr/bin/fish"));
}

/// The per-attach environment is written in each shell's own syntax, with
/// values quoted so a terminal name carrying shell metacharacters is
/// data rather than code, plus a JSON form for shells that read data
/// instead of evaluating a script. An empty map writes nothing at all: an
/// attach that carries no facts leaves the last known ones standing.
#[tokio::test]
async fn write_connection_env_renders_every_form() {
    let tmp = tempfile::tempdir().unwrap();
    let home =
        DaemonAbsPath::try_new(camino::Utf8PathBuf::try_from(tmp.path().to_path_buf()).unwrap())
            .unwrap();
    let sh = home.sub_path_unchecked(ATTACH_ENV_SH_REL);
    let fish = home.sub_path_unchecked(ATTACH_ENV_FISH_REL);
    let json = home.sub_path_unchecked(ATTACH_ENV_JSON_REL);

    write_connection_env(home.clone(), ConnectionEnv::new()).await;
    for path in [&sh, &json] {
        assert!(
            !std::fs::exists(path.as_str()).unwrap(),
            "an empty attach has nothing to publish"
        );
    }

    let env: ConnectionEnv = [
        ("TERM".to_string(), "xterm-256color".to_string()),
        ("ODD".to_string(), "it's \\ odd".to_string()),
    ]
    .into_iter()
    .collect();
    write_connection_env(home, env).await;

    let sh = std::fs::read_to_string(sh.as_str()).unwrap();
    assert!(sh.contains("export TERM='xterm-256color'"), "{sh}");
    // POSIX has no escape inside single quotes: close, escape, reopen.
    assert!(sh.contains(r"export ODD='it'\''s \ odd'"), "{sh}");

    let fish = std::fs::read_to_string(fish.as_str()).unwrap();
    assert!(fish.contains("set -gx TERM 'xterm-256color'"), "{fish}");
    // fish does take a backslash escape, and escapes the backslash too.
    assert!(fish.contains(r"set -gx ODD 'it\'s \\ odd'"), "{fish}");

    // The JSON form round-trips the values themselves rather than a
    // rendering of them, and carries nothing but the variables — every
    // key in it becomes one, so a "generated by" banner would too.
    let json = std::fs::read_to_string(json.as_str()).unwrap();
    let back: ConnectionEnv = serde_json_lenient::from_str(&json).expect("{json}");
    assert_eq!(back.get("TERM").map(String::as_str), Some("xterm-256color"));
    assert_eq!(back.get("ODD").map(String::as_str), Some("it's \\ odd"));
    assert_eq!(back.len(), 2, "{json}");
}

/// The launcher baseline seeds the session's identity plus the
/// once-only orientation banner pair: the session name verbatim in
/// `MINIMAL_SESSION_NAME`, the self-unsetting `PROMPT_COMMAND`
/// trigger, and a STATIC `MINIMAL_MOTD` template that defers the
/// dynamic parts to print time — env interpolation for the name and
/// loadout list (with `${VAR:-fallback}` unset-safety), a direct
/// in-shell filesystem test of the session workspace for the
/// blueprint clause (never a var: the client can't know the
/// workspace's state).
#[test]
fn layer_session_env_seeds_baseline_banner() {
    let env = layer_session_env(
        session_baseline_env("api-server-4f2a", Some("default (built-in)")),
        vec![],
        vec![],
        vec![],
    );

    assert_eq!(
        env.get("MINIMAL_SESSION_NAME").map(String::as_str),
        Some("api-server-4f2a")
    );
    // The loadout list is seeded daemon-side from the composition's
    // first-class orientation field — never from a user var.
    assert_eq!(
        env.get("MINIMAL_LOADOUTS").map(String::as_str),
        Some("default (built-in)")
    );
    let pc = env.get("PROMPT_COMMAND").expect("baseline PROMPT_COMMAND");
    assert!(pc.contains(r#"eval "$MINIMAL_MOTD""#));
    assert!(pc.contains("unset PROMPT_COMMAND MINIMAL_MOTD"));
    // The banner and the per-attach environment are deliberately not
    // wired together: this variable is composed, so a loadout could
    // replace it (and the MOTD recipe unsets it outright). The refresh
    // lives in the shell hooks `crate::env` installs into the rootfs.
    assert!(
        !pc.contains("MINIMAL_ATTACH_ENV"),
        "the refresh must not ride on a composed variable: {pc}"
    );

    // The paths are still named in the environment, for anything
    // scripting against them; the hooks themselves do not read these.
    assert_eq!(
        env.get("MINIMAL_ATTACH_ENV").map(String::as_str),
        Some("/home/.local/state/minimal/attach-env.sh")
    );
    assert_eq!(
        env.get("MINIMAL_ATTACH_ENV_FISH").map(String::as_str),
        Some("/home/.local/state/minimal/attach-env.fish")
    );
    assert_eq!(
        env.get("MINIMAL_ATTACH_ENV_JSON").map(String::as_str),
        Some("/home/.local/state/minimal/attach-env.json")
    );
    // The POSIX tier's only startup hook. Unlike the other shells' hooks
    // this one has to be a variable, because a plain `sh` reads nothing
    // else — so the baseline names the daemon-owned file.
    assert_eq!(
        env.get("ENV").map(String::as_str),
        Some("/usr/share/minimal/attach-env-posix.sh")
    );

    let motd = env.get("MINIMAL_MOTD").expect("baseline MINIMAL_MOTD");
    assert!(motd.starts_with("[ -t 1 ]"), "banner must be TTY-gated");
    // Static template, dynamic vars: interpolated in-shell, unset-safe.
    assert!(motd.contains("${MINIMAL_SESSION_NAME:-"));
    assert!(motd.contains("${MINIMAL_LOADOUTS:-"));
    // The detach hint is a third %s filled by the negotiated keys var,
    // with the default chord as the unset fallback.
    assert!(motd.contains("detach: %s"));
    assert!(motd.contains("${MINIMAL_DETACH_HINT:-ctrl-] then d}"));
    // The blueprint clause tests the session workspace itself at
    // print time — both mfile layouts — pinned to the same constant
    // that is the shell's initial cwd.
    assert!(motd.contains("[ -f /workbench/minimal.toml ]"));
    assert!(motd.contains("[ -f /workbench/.minimal/minimal.toml ]"));
    assert!(
        !motd.contains("MINIMAL_BLUEPRINT"),
        "blueprint is a session-filesystem fact, not an env var"
    );
    assert!(motd.contains("min init"));
}

/// The detach hint in the orientation banner reflects the negotiated
/// session keys: when the connection layer seeds `MINIMAL_DETACH_HINT`
/// (the daemon does this from the channel's key env vars at attach), the
/// layered env carries it so the banner's `${MINIMAL_DETACH_HINT:-…}`
/// renders the actual chord rather than the default fallback.
#[test]
fn connection_layer_seeds_negotiated_detach_hint() {
    let env = layer_session_env(
        session_baseline_env("box-1", None),
        vec![],
        vec![],
        vec![(
            "MINIMAL_DETACH_HINT".to_string(),
            "ctrl-^ then x".to_string(),
        )],
    );
    assert_eq!(
        env.get("MINIMAL_DETACH_HINT").map(String::as_str),
        Some("ctrl-^ then x"),
    );
}

/// A missing loadout display (old client / no composition) leaves
/// `MINIMAL_LOADOUTS` unset so the templates' own `${…:-}` fallbacks
/// render, each correct for its surface.
#[test]
fn baseline_env_omits_loadouts_var_when_display_unknown() {
    let env = layer_session_env(session_baseline_env("box-1", None), vec![], vec![], vec![]);
    assert!(!env.contains_key("MINIMAL_LOADOUTS"));
    assert!(env.contains_key("MINIMAL_SESSION_NAME"));
}

/// A composed `PROMPT_COMMAND` — a user loadout's, or the built-in
/// default's — overrides the baseline banner trigger cleanly, while
/// the baseline identity vars survive for that override to
/// interpolate.
#[test]
fn composed_prompt_command_overrides_baseline_banner() {
    let env = layer_session_env(
        session_baseline_env("box-1", Some("helix, fish")),
        vec![],
        vec![(
            "PROMPT_COMMAND".to_string(),
            r#"eval "$MY_MOTD""#.to_string(),
        )],
        vec![],
    );

    assert_eq!(
        env.get("PROMPT_COMMAND").map(String::as_str),
        Some(r#"eval "$MY_MOTD""#)
    );
    assert_eq!(
        env.get("MINIMAL_SESSION_NAME").map(String::as_str),
        Some("box-1")
    );
    assert_eq!(
        env.get("MINIMAL_LOADOUTS").map(String::as_str),
        Some("helix, fish")
    );
}

#[test]
fn open_and_get_fds() {
    let pty = Pty::open(DEFAULT_SIZE).expect("failed to open pty");
    assert!(pty.master_fd() >= 0);
    assert!(pty.slave_fd() >= 0);
    assert_ne!(pty.master_fd(), pty.slave_fd());
}

/// A wide glyph occupies two grid cells; the snapshot must emit only the
/// glyph itself, not a placeholder space for its continuation cell, so
/// the flattened row keeps the terminal's display width.
#[test]
fn screen_snapshot_drops_wide_continuation_cells() {
    let mut parser = vt100::Parser::new(2, 10, 0);
    parser.process("abあcd".as_bytes());
    let snapshot = screen_to_snapshot(parser.screen());
    let text: String = snapshot.lines[0].cells.iter().map(|c| c.ch).collect();
    assert_eq!(text.trim_end(), "abあcd");
}

#[test]
fn hvp_positions_like_cup() {
    // btop positions exclusively with HVP (`f`); it must behave like CUP
    // (gominimal/minimal#1197). Guards the gominimal/vt100-rust fork's
    // patch against being dropped.
    let mut parser = vt100::Parser::new(5, 10, 0);
    parser.process("\u{1b}[3;7fX\u{1b}[fY".as_bytes());
    assert_eq!(parser.screen().cell(2, 6).unwrap().contents(), "X");
    assert_eq!(parser.screen().cell(0, 0).unwrap().contents(), "Y");
    assert_eq!(parser.screen().cursor_position(), (0, 1));
}

#[test]
fn open_sets_initial_size() {
    let size = WinSize {
        rows: 40,
        cols: 120,
        xpixel: 0,
        ypixel: 0,
    };
    let pty = Pty::open(size).expect("failed to open pty");

    let got = pty.get_size().expect("failed to get size");
    assert_eq!(got.rows, 40);
    assert_eq!(got.cols, 120);
}

#[test]
fn dup_fd_produces_independent_fd() {
    let pty = Pty::open(DEFAULT_SIZE).expect("failed to open pty");
    let (master, _slave) = pty.into_fds();
    let duped = dup_fd(&master).expect("failed to dup fd");
    assert!(duped.as_raw_fd() >= 0);
    assert_ne!(master.as_raw_fd(), duped.as_raw_fd());
}

#[test]
fn win_size_from_requested_pty_clamps_oversized() {
    let requested = RequestedPty {
        char_sizes: (u32::MAX, u32::MAX),
        pixel_sizes: (0, 0),
        term: String::new(),
        modes: Vec::new(),
    };
    let size = WinSize::from(&requested);
    assert_eq!(size.cols, u16::MAX);
    assert_eq!(size.rows, u16::MAX);
}

#[test]
fn set_and_get_size() {
    let pty = Pty::open(DEFAULT_SIZE).expect("failed to open pty");

    let size = WinSize {
        rows: 50,
        cols: 200,
        xpixel: 0,
        ypixel: 0,
    };
    pty.set_size(size).expect("failed to set size");

    let got = pty.get_size().expect("failed to get size");
    assert_eq!(got.rows, 50);
    assert_eq!(got.cols, 200);
}

/// Drives a host backed by the mock echo program and confirms the terminal
/// attributes are tracked and surfaced via [`HostHandle::get_attrs`]:
/// feeding stdin an OSC "set window title" escape makes the mock echo it
/// back onto the terminal, where the parser records the title; the round
/// trip also stamps the stdin/stdout activity times.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn get_attrs_tracks_title_and_io_times() {
    // Build the host directly (no SSH binding) so the test can feed stdin
    // through a clone of the host's own remote sender, then drive its
    // runtime loop on a background task.
    let (host, handle) = Host::build(
        MockLauncher,
        HostParams {
            name: "test-session".to_string(),
            username: "user".to_string(),
            paths: SessionPaths {
                working: DaemonAbsPath::root(),
                cache: DaemonAbsPath::root(),
                home: DaemonAbsPath::root(),
                patches: DaemonAbsPath::root(),
                hooks: DaemonAbsPath::root(),
            },
            sz: DEFAULT_SIZE,
            channel: None,
            control: None,
            delta: None,
            archives_dir: std::env::temp_dir(),
            session_id: sessions::SessionId::nil(),
            composition: None,
            connection_env: ConnectionEnv::new(),
        },
    )
    .await
    .expect("failed to build host");
    let stdin = host.remote_tx.clone();
    tokio::spawn(host.mainloop());

    // OSC "set window title" (ESC ] 0 ; <title> BEL), sent as one line. The
    // mock echoes the line back (prefixed with `got:`), so the raw escape
    // reaches the host's terminal parser on stdout and fires the set-title
    // callback. The trailing newline is what makes the mock's `read` return
    // and echo via `printf`, carrying the escape bytes through unmangled.
    let title = "hello-title";
    let osc = format!("\x1b]0;{title}\x07\n");
    stdin
        .send(stdin_bytes(osc.into_bytes()))
        .await
        .expect("failed to send stdin");

    // Poll until the title has been recorded (or time out).
    let attrs = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let attrs = handle.get_attrs().await.unwrap();
            if attrs.title.is_some() {
                break attrs;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("timed out waiting for the terminal title to be recorded");

    let (got_title, _when) = attrs.title.expect("title should be set");
    assert_eq!(
        got_title, title,
        "the parsed title should match what was set"
    );

    // The stdin write and the echoed stdout should both have stamped their
    // last-activity times.
    assert!(
        attrs.stdin_last.is_some(),
        "stdin_last should be stamped after feeding stdin",
    );
    assert!(
        attrs.stdout_last.is_some(),
        "stdout_last should be stamped after the echo arrived",
    );
}

/// Killing a host tears it down cleanly: the runtime loop observes the
/// process die (its slave fds close, so the master reports `EIO`), reaps it,
/// and returns — the task terminates without panicking or leaking a zombie.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kill_tears_down_host_and_reaps_process() {
    let (host, handle) = Host::build(
        MockLauncher,
        HostParams {
            name: "test-session".to_string(),
            username: "user".to_string(),
            paths: SessionPaths {
                working: DaemonAbsPath::root(),
                cache: DaemonAbsPath::root(),
                home: DaemonAbsPath::root(),
                patches: DaemonAbsPath::root(),
                hooks: DaemonAbsPath::root(),
            },
            sz: DEFAULT_SIZE,
            channel: None,
            control: None,
            delta: None,
            archives_dir: std::env::temp_dir(),
            session_id: sessions::SessionId::nil(),
            composition: None,
            connection_env: ConnectionEnv::new(),
        },
    )
    .await
    .expect("failed to build host");
    let task = tokio::spawn(host.mainloop());

    handle
        .kill(false)
        .await
        .expect("kill should reach the host");

    // The mainloop must terminate (task resolves) without panicking. A
    // `JoinError` here would mean the host task panicked during teardown.
    let outcome = tokio::time::timeout(Duration::from_secs(10), task)
        .await
        .expect("host mainloop should terminate after kill")
        .expect("host task should not panic during teardown");
    assert!(
        outcome.is_ok(),
        "mainloop should return the reaped exit status, got: {outcome:?}",
    );
}

/// A kill aimed at a host whose loop has stopped draining its mailbox
/// gives up on its own deadline instead of parking forever. Left
/// unbounded, this send blocked once the mailbox filled — the wedged-host
/// hang behind a stuck `min stop` and, via the same send, `min session
/// attach`.
#[tokio::test(start_paused = true)]
async fn kill_to_a_wedged_host_gives_up_instead_of_parking() {
    // Holding the mailbox is what makes the host wedged: it accepts
    // messages up to its capacity and never drains one.
    let (host, _mailbox) = HostHandle::wedged();

    // Queue past the mailbox so the next send has to block trying to
    // enqueue at all — the case an unbounded send never returned from.
    for _ in 0..HOST_MAILBOX_CAPACITY {
        host.kill(false)
            .await
            .expect("queuing into an open mailbox should succeed");
    }

    // Far longer than the send's own deadline, so under the paused clock
    // the send's timeout is the one that fires; reaching this outer bound
    // would mean the send had no deadline at all.
    let outcome = tokio::time::timeout(Duration::from_secs(600), host.kill(false))
        .await
        .expect("a bounded kill must return on its own deadline, not park forever");
    assert!(
        outcome.is_err(),
        "a kill that cannot be queued before the deadline must report failure",
    );
}

/// A [`sandbox2::NetGuard`] that records whether its teardown ran, so a test
/// can assert the session's network is released exactly when the shell
/// process ends — and left up while it is merely detached.
struct RecordingNetGuard {
    torn_down: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl sandbox2::NetGuard for RecordingNetGuard {
    fn teardown(
        self: Box<Self>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> {
        self.torn_down
            .store(true, std::sync::atomic::Ordering::SeqCst);
        Box::pin(async {})
    }
}

/// Like [`MockLauncher`], but attaches a [`RecordingNetGuard`] so a test can
/// observe network teardown. The shared `torn_down` flag lets the test assert
/// when the network is released relative to detach vs. exit.
struct MockLauncherWithNet {
    torn_down: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl SessionLauncher for MockLauncherWithNet {
    type Process = MockProcess;
    type Guard = ();

    async fn launch(
        self,
        _name: String,
        _username: String,
        _paths: SessionPaths,
        sz: WinSize,
    ) -> std::io::Result<Launched<MockProcess, ()>> {
        let pty = Pty::open(sz)?;
        let script = format!(
            r#"while read line; do [ "$line" = {MOCK_EXIT_LINE} ] && exit 0; printf 'got:%s\n' "$line"; done"#
        );
        let mut command = std::process::Command::new("/bin/sh");
        command.arg("-c").arg(&script);
        command.stdin(std::process::Stdio::from(pty.dup_slave_fd()?));
        command.stdout(std::process::Stdio::from(pty.dup_slave_fd()?));
        let tty_path = pty.slave_path().to_path_buf();
        let (master, slave) = pty.into_fds();
        command.stderr(std::process::Stdio::from(slave));
        let process = command.spawn()?;
        Ok(Launched {
            master,
            process: MockProcess {
                child: process,
                exit: None,
            },
            guard: (),
            tty_path,
            cohort_procs: None,
            net_guard: Some(Box::new(RecordingNetGuard {
                torn_down: self.torn_down,
            })),
        })
    }
}

fn test_paths() -> SessionPaths {
    SessionPaths {
        working: DaemonAbsPath::root(),
        cache: DaemonAbsPath::root(),
        home: DaemonAbsPath::root(),
        patches: DaemonAbsPath::root(),
        hooks: DaemonAbsPath::root(),
    }
}

/// The load-bearing half of "detach != exit": when the shell process exits,
/// the session network is torn down. Pins the teardown in `mainloop` so a
/// refactor cannot silently leave a lease/switch attachment leaked after exit.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn exit_releases_the_network() {
    let torn_down = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let (host, _handle) = Host::build(
        MockLauncherWithNet {
            torn_down: torn_down.clone(),
        },
        HostParams {
            name: "test-session".to_string(),
            username: "user".to_string(),
            paths: test_paths(),
            sz: DEFAULT_SIZE,
            channel: None,
            control: None,
            delta: None,
            archives_dir: std::env::temp_dir(),
            session_id: sessions::SessionId::nil(),
            composition: None,
            connection_env: ConnectionEnv::new(),
        },
    )
    .await
    .expect("failed to build host");
    let stdin = host.remote_tx.clone();
    let task = tokio::spawn(host.mainloop());

    // While the shell is alive the network must stay up.
    assert!(
        !torn_down.load(std::sync::atomic::Ordering::SeqCst),
        "network must not be torn down while the shell is running",
    );

    // Make the shell exit; the network must then be released.
    stdin
        .send(stdin_bytes(format!("{MOCK_EXIT_LINE}\n").into_bytes()))
        .await
        .expect("failed to send exit line");
    tokio::time::timeout(Duration::from_secs(10), task)
        .await
        .expect("mainloop should terminate after the shell exits")
        .expect("host task should not panic during teardown")
        .expect("mainloop should return the reaped exit status");
    assert!(
        torn_down.load(std::sync::atomic::Ordering::SeqCst),
        "network must be torn down once the shell exits",
    );
}

/// A `MakeWriter` accumulating everything written into a shared buffer, so a
/// test can assert on the structured fields a `tracing` event emitted. The same
/// shape `net/proxy.rs` captures its warnings with.
#[derive(Clone, Default)]
struct CaptureWriter(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

impl CaptureWriter {
    fn contents(&self) -> String {
        let written = self.0.lock().unwrap();
        String::from_utf8_lossy(&written).into_owned()
    }
}

impl std::io::Write for CaptureWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CaptureWriter {
    type Writer = CaptureWriter;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// BEP-043: a box that stops says so, naming itself, so nothing about a stop is
/// silent — the sealed values the proxy holds for that box must be refused from
/// here on, and this is the daemon's own account of the moment. The submission
/// itself is the client's (`min box rm`, `min auth logout`): the proxy's control
/// socket is the operator's user's on the host, which a guest daemon cannot
/// reach.
///
/// The notice is asserted through a process-wide subscriber rather than a
/// thread-local default because the host loop is polled on a worker thread of
/// its own.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn box_stop_notifies_revocation() {
    let buf = CaptureWriter::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(buf.clone())
        .with_ansi(false)
        .finish();
    // Only this test installs one, and nextest gives each test its own process.
    let _ = tracing::subscriber::set_global_default(subscriber);

    let (host, _handle) = Host::build(
        MockLauncher,
        HostParams {
            name: "revoked-box".to_string(),
            username: "user".to_string(),
            paths: test_paths(),
            sz: DEFAULT_SIZE,
            channel: None,
            control: None,
            delta: None,
            archives_dir: std::env::temp_dir(),
            session_id: sessions::SessionId::nil(),
            composition: None,
            connection_env: ConnectionEnv::new(),
        },
    )
    .await
    .expect("failed to build host");
    let stdin = host.remote_tx.clone();
    let task = tokio::spawn(host.mainloop());

    // A live box has not stopped, so nothing is due yet.
    assert!(
        !buf.contents().contains("revoke_box"),
        "a live box was reported as stopped: {}",
        buf.contents()
    );

    stdin
        .send(stdin_bytes(format!("{MOCK_EXIT_LINE}\n").into_bytes()))
        .await
        .expect("failed to send exit line");
    tokio::time::timeout(Duration::from_secs(10), task)
        .await
        .expect("mainloop should terminate after the shell exits")
        .expect("host task should not panic during teardown")
        .expect("mainloop should return the reaped exit status");

    let logged = buf.contents();
    assert!(
        logged.contains("revoke_box=revoked-box"),
        "the stop did not name the box whose values must be refused: {logged}"
    );
    assert!(
        logged.contains("every sealed value naming it must be refused"),
        "the stop notice does not say what is due: {logged}"
    );
}

/// The other half of "detach != exit": the detach chord (leader then `d`)
/// is swallowed as a detach signal — never forwarded to the shell — and does
/// not end the session or release the network. The shell keeps running (a
/// later line still round-trips) and only an explicit kill/exit releases the
/// network.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn detach_keystroke_holds_the_session_and_network() {
    let torn_down = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let (host, handle) = Host::build(
        MockLauncherWithNet {
            torn_down: torn_down.clone(),
        },
        HostParams {
            name: "test-session".to_string(),
            username: "user".to_string(),
            paths: test_paths(),
            sz: DEFAULT_SIZE,
            channel: None,
            control: None,
            delta: None,
            archives_dir: std::env::temp_dir(),
            session_id: sessions::SessionId::nil(),
            composition: None,
            connection_env: ConnectionEnv::new(),
        },
    )
    .await
    .expect("failed to build host");
    let stdin = host.remote_tx.clone();
    let task = tokio::spawn(host.mainloop());

    // The default detach chord is `ctrl-]` (0x1d, the leader) then `d`.
    // Both bytes are consumed by the command-mode state machine rather
    // than written to the pty: the leader enters command mode, `d`
    // detaches. (The host is built without a binding, so the detach is a
    // no-op on the channel — what matters is that neither byte reaches
    // the shell.)
    stdin
        .send(stdin_bytes(vec![0x1d]))
        .await
        .expect("failed to send leader");
    stdin
        .send(stdin_bytes(b"d".to_vec()))
        .await
        .expect("failed to send detach key");

    // The shell survived the detach: a normal line still echoes back, which
    // stamps stdout activity. (If the chord had been forwarded or had killed
    // the process, no echo would ever arrive.)
    stdin
        .send(stdin_bytes(b"ping\n".to_vec()))
        .await
        .expect("failed to send line after detach");
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let attrs = handle.get_attrs().await.unwrap();
            if attrs.stdout_last.is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("echo should arrive, proving the shell survived the detach keystroke");
    assert!(
        !torn_down.load(std::sync::atomic::Ordering::SeqCst),
        "detach must not tear down the network while the shell is still running",
    );

    // Only now, on an explicit kill (destroy), is the network released.
    handle.kill(true).await.expect("kill should reach the host");
    tokio::time::timeout(Duration::from_secs(10), task)
        .await
        .expect("mainloop should terminate after kill")
        .expect("host task should not panic during teardown")
        .expect("mainloop should return the reaped exit status");
    assert!(
        torn_down.load(std::sync::atomic::Ordering::SeqCst),
        "kill/destroy must release the network",
    );
}

/// The PTY write queue appends: bytes queued later land *after* anything
/// already buffered, so an idle chord-candidate flush can never overwrite
/// forwarded input still waiting on an unwritable pty.
#[test]
fn queue_stdin_appends_after_unwritten_remainder() {
    // Two bytes of a queued chunk written; three still pending. The flush
    // must not resurrect the written prefix or drop either remainder.
    let mut buf = Some((bytes::Bytes::from_static(b"abcde"), 2));
    queue_stdin(&mut buf, vec![0x1b]);
    let (pending, written) = buf.as_ref().unwrap();
    assert_eq!(*written, 0);
    assert_eq!(&pending[..], b"cde\x1b");

    // An empty queue takes the new bytes wholesale.
    let mut buf = None;
    queue_stdin(&mut buf, vec![0x1d, 0x64]);
    let (pending, written) = buf.as_ref().unwrap();
    assert_eq!(*written, 0);
    assert_eq!(&pending[..], b"\x1d\x64");
}

/// Input stamped with a stale binding generation — what a superseded
/// binding left queued in the shared stdin channel — must never reach
/// the shell. (A real supersession attaches a new channel; here no
/// binding ever attaches, so the active generation stays 0 and a manual
/// generation-1 message stands in for the queued leftovers.)
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stale_binding_generation_input_is_discarded() {
    let (host, _handle) = Host::build(
        MockLauncher,
        HostParams {
            name: "test-session".to_string(),
            username: "user".to_string(),
            paths: test_paths(),
            sz: DEFAULT_SIZE,
            channel: None,
            control: None,
            delta: None,
            archives_dir: std::env::temp_dir(),
            session_id: sessions::SessionId::nil(),
            composition: None,
            connection_env: ConnectionEnv::new(),
        },
    )
    .await
    .expect("failed to build host");
    let stdin = host.remote_tx.clone();
    let mut task = tokio::spawn(host.mainloop());

    // The exit sentinel on a stale generation: if this reached the shell
    // the mainloop would reap the process and the task would complete.
    stdin
        .send(StdinMsg::new(
            1,
            StdinMsgKind::Bytes(bytes::Bytes::from(
                format!("{MOCK_EXIT_LINE}\n").into_bytes(),
            )),
        ))
        .await
        .expect("failed to send stale stdin");
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(
        !task.is_finished(),
        "stale-generation input must not reach the shell",
    );

    // The same bytes on the active generation must still go through.
    stdin
        .send(stdin_bytes(format!("{MOCK_EXIT_LINE}\n").into_bytes()))
        .await
        .expect("failed to send stdin");
    tokio::time::timeout(Duration::from_secs(10), &mut task)
        .await
        .expect("mainloop should terminate after the shell exits")
        .expect("host task should not panic during teardown")
        .expect("mainloop should return the reaped exit status");
}

/// BEP-011: the anchor the box spec's grants delivered into the session home
/// (the CLI's patch at `BEP_ANCHOR_PATCH_DEST`) lands in the rootfs trust
/// store directory, byte for byte and world-readable, linked under the
/// subject hash OpenSSL looks it up by; a home carrying no anchor installs
/// nothing and creates no trust store directory.
#[test]
fn anchor_patch_lands_in_trust_store_dir() {
    use std::os::unix::fs::PermissionsExt as _;

    const PEM: &str = include_str!("test_anchor.pem");

    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    let rootfs = tmp.path().join("rootfs");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(&rootfs).unwrap();

    // No anchor delivered: nothing installed, and the trust store untouched.
    assert_eq!(install_trust_anchor(&home, &rootfs).unwrap(), None);
    assert!(!rootfs.join(sessions::BEP_TRUST_STORE_DIR).exists());

    // The anchor, materialized into the home the way `FinalizeSession` does
    // for every patch, with the tight bits an upload may carry.
    let source = home.join(sessions::BEP_ANCHOR_PATCH_DEST);
    std::fs::create_dir_all(source.parent().unwrap()).unwrap();
    std::fs::write(&source, PEM).unwrap();
    std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o600)).unwrap();

    let installed = install_trust_anchor(&home, &rootfs)
        .unwrap()
        .expect("a delivered anchor is installed");
    let expected = rootfs
        .join(sessions::BEP_TRUST_STORE_DIR)
        .join(sessions::BEP_TRUST_STORE_FILE);
    assert_eq!(installed, expected);
    assert_eq!(
        expected,
        rootfs.join("etc/ssl/certs/minimal-bep-anchor.pem")
    );
    assert_eq!(std::fs::read_to_string(&installed).unwrap(), PEM);
    assert_eq!(
        std::fs::metadata(&installed).unwrap().permissions().mode() & 0o777,
        0o644,
        "the anchor must be readable by every process in the box"
    );
    // `openssl x509 -subject_hash` of the test anchor is 42d333ec.
    let link = expected.with_file_name("42d333ec.0");
    assert_eq!(
        std::fs::read_link(&link).unwrap(),
        std::path::Path::new(sessions::BEP_TRUST_STORE_FILE),
        "OpenSSL's directory lookup opens only the subject-hash name"
    );

    // A second launch of the same session installs the same anchor again
    // without complaint.
    assert_eq!(
        install_trust_anchor(&home, &rootfs).unwrap(),
        Some(installed.clone())
    );

    // And the bundle carries it exactly once: the second launch rewrote the
    // bundle this launch wrote, rather than appending to it again.
    let bundle = rootfs
        .join(sessions::BEP_TRUST_STORE_DIR)
        .join(sessions::BEP_TRUST_BUNDLE_FILE);
    assert_eq!(
        std::fs::read_to_string(&bundle)
            .unwrap()
            .matches(PEM)
            .count(),
        1,
        "the anchor is in the bundle once, however often the session launches"
    );
    // And it is linked once: the second launch found its own link.
    assert!(!link.with_file_name("42d333ec.1").exists());
}

/// BEP-011: OpenSSL files certificates sharing a subject hash as `.0`, `.1`,
/// …, so an anchor whose hash another certificate already holds is linked
/// under the next free suffix, and that certificate keeps its own.
#[test]
fn the_anchor_is_linked_past_a_certificate_already_holding_its_hash() {
    const PEM: &str = include_str!("test_anchor.pem");

    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    let rootfs = tmp.path().join("rootfs");
    let dir = rootfs.join(sessions::BEP_TRUST_STORE_DIR);
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("shipped-root.pem"), "shipped").unwrap();
    std::os::unix::fs::symlink("shipped-root.pem", dir.join("42d333ec.0")).unwrap();

    let source = home.join(sessions::BEP_ANCHOR_PATCH_DEST);
    std::fs::create_dir_all(source.parent().unwrap()).unwrap();
    std::fs::write(&source, PEM).unwrap();
    install_trust_anchor(&home, &rootfs).unwrap().unwrap();

    assert_eq!(
        std::fs::read_link(dir.join("42d333ec.0")).unwrap(),
        std::path::Path::new("shipped-root.pem")
    );
    assert_eq!(
        std::fs::read_link(dir.join("42d333ec.1")).unwrap(),
        std::path::Path::new(sessions::BEP_TRUST_STORE_FILE)
    );
}

/// BEP-011, the half that makes the anchor count: a certificate in the trust
/// store directory is trusted by nothing until it is in the bundle the tools
/// read, and the bundle arrives hardlinked out of the package store, so it is
/// replaced rather than appended to.
#[test]
fn the_anchor_joins_the_bundle_without_editing_the_package_store() {
    const PEM: &str = include_str!("test_anchor.pem");
    const SHIPPED: &str = "-----BEGIN CERTIFICATE-----\nc2hpcHBlZA==\n-----END CERTIFICATE-----\n";

    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    let rootfs = tmp.path().join("rootfs");
    let store = tmp.path().join("store");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(rootfs.join(sessions::BEP_TRUST_STORE_DIR)).unwrap();
    std::fs::create_dir_all(&store).unwrap();

    // The bundle as a package delivers it: one file, two names.
    let shipped = store.join("ca-certificates.crt");
    std::fs::write(&shipped, SHIPPED).unwrap();
    let bundle = rootfs
        .join(sessions::BEP_TRUST_STORE_DIR)
        .join(sessions::BEP_TRUST_BUNDLE_FILE);
    std::fs::hard_link(&shipped, &bundle).unwrap();

    let source = home.join(sessions::BEP_ANCHOR_PATCH_DEST);
    std::fs::create_dir_all(source.parent().unwrap()).unwrap();
    std::fs::write(&source, PEM).unwrap();
    install_trust_anchor(&home, &rootfs).unwrap().unwrap();

    // The box now trusts the anchor, and still trusts what it shipped with.
    let trusted = std::fs::read_to_string(&bundle).unwrap();
    assert!(trusted.contains(PEM), "{trusted}");
    assert!(trusted.starts_with(SHIPPED), "{trusted}");

    // The package store's own copy is untouched: an append would have
    // written this host's anchor into every box built from that package.
    assert_eq!(std::fs::read_to_string(&shipped).unwrap(), SHIPPED);
}
