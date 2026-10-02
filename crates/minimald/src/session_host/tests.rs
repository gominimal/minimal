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
    host.remote = Some((tx, tokio::spawn(async {}), CancellationToken::new()));
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
        MockLauncher::default(),
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
            #[cfg(target_os = "linux")]
            name_marker: None,
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
/// the shell exiting — one dark client froze the whole session. The host now
/// stops reading the pty while the mailbox is full, keeps serving, and sheds
/// the binding once the stall bound passes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stalled_binding_does_not_wedge_the_host_loop() {
    let (mut host, handle) = Host::build(
        MockLauncher::default(),
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
            #[cfg(target_os = "linux")]
            name_marker: None,
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
    host.remote = Some((tx, tokio::spawn(async {}), CancellationToken::new()));
    // Short, so the shed this test goes on to rely on comes quickly.
    host.output_stall_timeout = Duration::from_millis(200);

    let stdin = host.remote_tx.clone();
    let task = tokio::spawn(host.mainloop());

    // Make the shell echo so the host has output for the full binding, and
    // reads it once the stalled binding has been shed.
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

/// Stands in for the daemon's connection handler: accepts any client and
/// hands each session channel it opens to the test.
struct ChannelCatcher(mpsc::UnboundedSender<Channel<Msg>>);

impl russh::server::Handler for ChannelCatcher {
    type Error = russh::Error;

    async fn auth_none(&mut self, _: &str) -> Result<russh::server::Auth, Self::Error> {
        Ok(russh::server::Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: russh::server::ChannelOpenHandle,
        _: &mut russh::server::Session,
    ) -> Result<(), Self::Error> {
        let _ = self.0.send(channel);
        reply.accept().await;
        Ok(())
    }
}

struct TrustingClient;

impl russh::client::Handler for TrustingClient {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _: &russh::keys::PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

/// A host whose shell is attached through a real ssh channel and kept busy
/// printing, plus the client end of that channel.
struct FloodedAttach {
    handle: HostHandle,
    task: JoinHandle<Result<i32, std::io::Error>>,
    channel: russh::Channel<russh::client::Msg>,
    feeder: JoinHandle<()>,
    // Held so the ssh connection stays up.
    _client: russh::client::Handle<TrustingClient>,
}

impl FloodedAttach {
    /// Builds the host with `output_stall_timeout`, attaches it over an
    /// in-process ssh connection, and feeds the shell long lines for as long
    /// as the host takes them. Every line comes back twice, as the tty's echo
    /// and the shell's `got:` line.
    ///
    /// The client's receive window and channel buffer are tiny. A client
    /// that stops reading then stops the server within a few tens of KiB,
    /// where the defaults would let megabytes through first.
    async fn start(output_stall_timeout: Duration) -> Self {
        let (mut host, handle) = Host::build(
            MockLauncher::default(),
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
                #[cfg(target_os = "linux")]
                name_marker: None,
            },
        )
        .await
        .expect("failed to build host");
        host.output_stall_timeout = output_stall_timeout;
        let stdin = host.remote_tx.clone();
        let task = tokio::spawn(host.mainloop());

        let (server_side, client_side) = tokio::net::UnixStream::pair().unwrap();
        let key = russh::keys::PrivateKey::random(
            &mut russh::keys::key::safe_rng(),
            russh::keys::Algorithm::Ed25519,
        )
        .unwrap();
        let server_config = Arc::new(russh::server::Config {
            keys: vec![key],
            auth_rejection_time_initial: Some(Duration::ZERO),
            ..Default::default()
        });
        let client_config = Arc::new(russh::client::Config {
            window_size: 16 * 1024,
            channel_buffer_size: 1,
            ..Default::default()
        });
        let (caught_tx, mut caught) = mpsc::unbounded_channel();
        // The server reads the client's ssh id before it returns, so the two
        // halves have to be driven together.
        let (server, client) = tokio::join!(
            russh::server::run_stream(server_config, server_side, ChannelCatcher(caught_tx)),
            russh::client::connect_stream(client_config, client_side, TrustingClient),
        );
        tokio::spawn(server.expect("ssh server handshake"));
        let mut client = client.expect("ssh client handshake");
        let auth = client.authenticate_none("test").await.unwrap();
        assert!(auth.success(), "the test server accepts anyone");
        let channel = client.channel_open_session().await.unwrap();
        let server_channel = caught.recv().await.expect("the server caught the channel");

        assert!(
            handle
                .attach(
                    server_channel,
                    DEFAULT_SIZE,
                    ConnectionEnv::new(),
                    SessionKeys::default(),
                )
                .await
                .is_ok(),
            "the host must take the attach",
        );

        // Stamped with the generation the attach installs. Lines that reach
        // the host before it has processed the attach are dropped as stale,
        // and so is everything after a shed; neither matters here.
        let line = format!("{}\n", "x".repeat(2000));
        let feeder = tokio::spawn(async move {
            while stdin
                .send(StdinMsg::new(
                    1,
                    StdinMsgKind::Bytes(bytes::Bytes::from(line.clone())),
                ))
                .await
                .is_ok()
            {}
        });

        Self {
            handle,
            task,
            channel,
            feeder,
            _client: client,
        }
    }

    async fn stop(self) {
        self.feeder.abort();
        let _ = self.handle.kill(false).await;
        let _ = tokio::time::timeout(Duration::from_secs(10), self.task).await;
    }
}

/// A shed must close the client's channel. The client of a shed binding
/// has stopped reading, but it is still connected, and when it reads again
/// it has to find the attach over: EOF, the shed exit status, and a close,
/// so `min` exits and the user can re-attach. Aborting the binding task, as
/// the shed once did, dropped the channel halves, and russh sends no close
/// for those. The client then stayed connected forever with nothing behind
/// it: no output, keystrokes swallowed, no detach.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shedding_a_stalled_binding_closes_the_client_channel() {
    let mut attach = FloodedAttach::start(Duration::from_millis(200)).await;

    // Read nothing for long enough that the output backs up to the host and
    // the stall bound passes.
    tokio::time::sleep(Duration::from_secs(3)).await;

    let (mut eof, mut exit_status, mut closed) = (false, None, false);
    let drained = tokio::time::timeout(Duration::from_secs(30), async {
        while let Some(msg) = attach.channel.wait().await {
            match msg {
                russh::ChannelMsg::Eof => eof = true,
                russh::ChannelMsg::ExitStatus { exit_status: s } => exit_status = Some(s),
                russh::ChannelMsg::Close => {
                    closed = true;
                    break;
                }
                _ => {}
            }
        }
    })
    .await;
    assert!(
        drained.is_ok() && closed,
        "the shed binding left the client's channel open (eof: {eof}, exit status: {exit_status:?})",
    );
    assert!(eof, "the channel must see EOF before it closes");
    assert_eq!(
        exit_status,
        Some(SHED_EXIT_STATUS),
        "a shed reports the status that has the client restore the terminal",
    );

    // Only the attach was dropped; the session carries on.
    assert!(
        !attach.task.is_finished(),
        "a shed must not end the session"
    );
    tokio::time::timeout(Duration::from_secs(5), attach.handle.get_attrs())
        .await
        .expect("the host keeps answering after a shed")
        .expect("the host is still running");

    attach.stop().await;
}

/// A terminal that falls behind is slowed down, not dropped. The shed used
/// to fire whenever one forward waited longer than the 2 s probe deadline,
/// which any terminal draining under about 800 KB/s hit while a session
/// printed a few megabytes. Now the host stops reading the pty while the
/// binding catches up, answering probes all the while, and the attach
/// carries on once the client reads again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_slow_reader_is_held_back_not_shed() {
    let mut attach = FloodedAttach::start(OUTPUT_STALL_TIMEOUT).await;

    // Stall well past the probe deadline, probing the host throughout.
    let stall = tokio::time::Instant::now() + 2 * crate::session::HOST_PROBE_TIMEOUT;
    while tokio::time::Instant::now() < stall {
        tokio::time::timeout(
            crate::session::HOST_PROBE_TIMEOUT,
            attach.handle.get_attrs(),
        )
        .await
        .expect("a backed-up binding must not stop the host answering probes")
        .expect("the host is still running");
        tokio::time::sleep(Duration::from_millis(250)).await;
    }

    // Reading again, the output keeps coming: far more of it than the
    // stalled pipeline could hold, so the shell was only held up.
    let mut received = 0usize;
    let flowing = tokio::time::timeout(Duration::from_secs(30), async {
        while received < 1024 * 1024 {
            match attach.channel.wait().await {
                Some(russh::ChannelMsg::Data { data }) => received += data.len(),
                Some(russh::ChannelMsg::Eof | russh::ChannelMsg::Close) | None => {
                    panic!("a slow reader was shed after {received} bytes");
                }
                Some(_) => {}
            }
        }
    })
    .await;
    assert!(
        flowing.is_ok(),
        "output stopped after {received} bytes once the client read again",
    );

    attach.stop().await;
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
        MockLauncher::default(),
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
            #[cfg(target_os = "linux")]
            name_marker: None,
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
        MockLauncher::default(),
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
            #[cfg(target_os = "linux")]
            name_marker: None,
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
        MockLauncher::default(),
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
            #[cfg(target_os = "linux")]
            name_marker: None,
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
        MockLauncher::default(),
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
            #[cfg(target_os = "linux")]
            name_marker: None,
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
        MockLauncher::default(),
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
            #[cfg(target_os = "linux")]
            name_marker: None,
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
        MockLauncher::with_net_guard(Box::new(RecordingNetGuard {
            torn_down: torn_down.clone(),
        })),
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
            #[cfg(target_os = "linux")]
            name_marker: None,
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

/// The other half of "detach != exit": the detach chord (leader then `d`)
/// is swallowed as a detach signal — never forwarded to the shell — and does
/// not end the session or release the network. The shell keeps running (a
/// later line still round-trips) and only an explicit kill/exit releases the
/// network.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn detach_keystroke_holds_the_session_and_network() {
    let torn_down = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let (host, handle) = Host::build(
        MockLauncher::with_net_guard(Box::new(RecordingNetGuard {
            torn_down: torn_down.clone(),
        })),
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
            #[cfg(target_os = "linux")]
            name_marker: None,
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
        MockLauncher::default(),
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
            #[cfg(target_os = "linux")]
            name_marker: None,
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

/// A composition with nothing in it. [`Host::hook_plan`] needs a composition
/// to exist before it will plan a hook run, but no hook script is run by the
/// plan itself, so an empty one is enough to test the wiring.
fn bare_composition() -> Arc<sessions::core::compose::Composition> {
    use sessions::wire::request::{COMPOSITION_SNAPSHOT_VERSION, WireComposition};
    Arc::new(
        sessions::core::compose::Composition::try_from(WireComposition {
            version: COMPOSITION_SNAPSHOT_VERSION,
            vars: Vec::new(),
            patches: Vec::new(),
            packages: Vec::new(),
            lifecycle_hooks: Vec::new(),
            orientation: Default::default(),
        })
        .expect("an empty composition snapshot converts back"),
    )
}

/// A launcher that reports the given none-box seal and runs a stand-in shell
/// with exactly one child, so [`Host::session_leader_pid`] resolves the way it
/// does behind a real session.
struct SealingMockLauncher {
    seal_injection: bool,
}

impl SessionLauncher for SealingMockLauncher {
    type Process = MockProcess;
    type Guard = ();

    async fn launch(
        self,
        _guest: bool,
        _session_id: sessions::SessionId,
        _name: String,
        _username: String,
        _paths: SessionPaths,
        sz: WinSize,
    ) -> io::Result<Launched<MockProcess, ()>> {
        let pty = Pty::open(sz)?;
        // The `&` forces a fork, so the shell stays alive holding exactly one
        // child for `session_leader_pid` to resolve.
        let mut command = std::process::Command::new("/bin/sh");
        command.arg("-c").arg("sleep 30 & wait");
        command.stdin(std::process::Stdio::from(pty.dup_slave_fd()?));
        command.stdout(std::process::Stdio::from(pty.dup_slave_fd()?));
        let tty_path = pty.slave_path().to_path_buf();
        let (master, slave) = pty.into_fds();
        command.stderr(std::process::Stdio::from(slave));

        let process = command.spawn()?;

        Ok(Launched {
            master,
            process: MockProcess::new(MockBackend { child: process }),
            guard: (),
            net_guard: None,
            tty_path,
            seal_injection: self.seal_injection,
            // This mock has no sandbox, so no classifier placed it anywhere.
            leaf: None,
            host_ip_enforcement: None,
        })
    }
}

/// The seal a lifecycle hook is injected with follows the session's own.
/// `hook_plan` is the one place the daemon decides what a hook runs in, so it
/// is where the none-box socket-family seal has to arrive: a hook joins the
/// session's namespaces rather than being forked from the filtered shell, so
/// without the flag it would land unfiltered and could open sockets —
/// `AF_VSOCK` to the host included — from inside a sealed box.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hook_injections_carry_the_session_s_none_box_seal() {
    for (sealing, expected) in [(true, true), (false, false)] {
        let (mut host, _handle) = Host::build(
            SealingMockLauncher {
                seal_injection: sealing,
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
                composition: Some(bare_composition()),
                connection_env: ConnectionEnv::new(),
                #[cfg(target_os = "linux")]
                name_marker: None,
            },
        )
        .await
        .expect("failed to build host");

        // The stand-in shell forks its child a moment after `spawn` returns,
        // so the leader may not exist on the first ask. A real session runs
        // its hooks long after launch; give the stand-in the same courtesy,
        // bounded so a session that can never plan says so rather than hang.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        let plan = loop {
            if let Some(plan) = host.hook_plan(crate::hooks::HookEvent::Attach) {
                break plan;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "a live session with a composition never planned a hook run",
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        };
        let _ = host.process.kill();
        assert_eq!(
            plan.commands.seal_none_box, expected,
            "the hook injection must carry the session's none-box seal",
        );
    }
}

// ---------------------------------------------------------------------
// NET-079: the daemon in a classifier leaf of its own, and every box's
// leaf placed in a cohort it is a sibling of.
// ---------------------------------------------------------------------

/// The files the kernel makes when it makes a cgroup — `cgroup.procs`,
/// `cgroup.threads`, `cgroup.subtree_control` — modelled empty over a
/// stand-in tree, which has no kernel behind it to make them. Modelling them
/// is what makes a stand-in the installer's tree: directories delegated to
/// the daemon's account, with the kernel's own files in them, and nothing
/// left for the entry to make but the migration.
const CGROUP_KERNEL_FILES: [&str; 3] = ["cgroup.procs", "cgroup.threads", "cgroup.subtree_control"];

/// Stands in for the kernel over a stand-in tree: writes
/// [`CGROUP_KERNEL_FILES`] into `dir`, empty, as the kernel leaves them when
/// it makes a cgroup.
fn model_cgroup_files(dir: &std::path::Path) {
    for name in CGROUP_KERNEL_FILES {
        std::fs::write(dir.join(name), "")
            .unwrap_or_else(|e| panic!("modeling {name} in {}: {e}", dir.display()));
    }
}

/// The daemon enters a classifier leaf of its own at start: `<root>/daemon`,
/// a **sibling** of every box leaf — never the tree root, where enabling a
/// controller would make the box leaves unusable and where the daemon's own
/// fetches could not be told apart from a box's, and never inside `boxes/`,
/// the cohort that holds boxes and nothing else.
///
/// The placement is this process's pid written to its leaf's `cgroup.procs`,
/// the one migration primitive the whole classifier rests on. Asserted over
/// a stand-in tree because the host running this test may have no cgroup2 of
/// its own: on a real tree the kernel holds the membership, and the write
/// that performs the migration is the same either way. Natively the
/// installer owns the tree — the slice itself delegated to the daemon's
/// account, `daemon/` and `boxes/` made, the kernel's files in them — and a
/// daemon that cannot enter it is left outside, its boxes unenforced; only
/// the guest's pid 1 builds the tree, on the cgroup2 it mounted itself.
#[test]
fn daemon_enters_its_own_leaf() {
    let tree = tempfile::tempdir().expect("a temp dir standing in for the tree");
    let root = tree.path();

    // The installer's tree, as a stand-in holds it: both directories made,
    // and the kernel's files modelled into the daemon's leaf, because
    // nothing behind the stand-in makes them at `mkdir` time.
    std::fs::create_dir_all(sandbox2::classifier::daemon_leaf(root))
        .expect("the installer makes the daemon's leaf");
    std::fs::create_dir_all(root.join(sandbox2::classifier::BOXES_DIR))
        .expect("the installer makes the box cohort");
    model_cgroup_files(&sandbox2::classifier::daemon_leaf(root));

    sandbox2::classifier::enter_daemon_leaf(root)
        .expect("the daemon enters its own leaf in the installer's tree");

    let daemon = sandbox2::classifier::daemon_leaf(root);
    let procs = daemon.join("cgroup.procs");
    assert_eq!(
        std::fs::read_to_string(&procs).expect("reading the daemon leaf's procs file"),
        format!("{}\n", std::process::id()),
        "the daemon is placed by writing its own pid to its leaf's cgroup.procs"
    );
    assert_eq!(
        daemon,
        root.join(sandbox2::classifier::DAEMON_LEAF),
        "the daemon's leaf is one component under the tree root"
    );
    let cohort = root.join(sandbox2::classifier::BOXES_DIR);
    assert!(
        cohort.is_dir(),
        "the cohort directory exists for the boxes to come"
    );

    // The cohort asks the kernel for the memory controller: a box leaf only
    // carries a `memory.max` — the limit a host-side reader or a future
    // box-held view would name — when the cgroup above the leaf carries the
    // controller, and `boxes/` holds no process, so enabling it breaks no
    // internal-process rule.
    assert_eq!(
        std::fs::read_to_string(cohort.join("cgroup.subtree_control"))
            .expect("the daemon enables the memory controller on the cohort"),
        "+memory\n",
        "the leaf must carry the limit a reader would look for in it"
    );

    // The two identities: a box's leaf lives in its verdict's subtree inside
    // the cohort, never beside it and never in the daemon's leaf, so no box
    // is ever placed in the daemon's leaf and the daemon never in a box's.
    let a_box =
        sandbox2::classifier::create_box_leaf(root, "a session", sandbox2::config::Verdict::Deny)
            .expect("creating a box's leaf in the same tree");
    assert_eq!(
        a_box.parent(),
        Some(
            root.join(sandbox2::classifier::BOXES_DIR)
                .join(sandbox2::config::DENY_DIR)
                .as_path()
        ),
        "a box's leaf lives in its verdict's subtree, one level under the \
         cohort — never directly under the cohort, where the refusing rule's \
         match would silently miss it: {}",
        a_box.display()
    );
    assert_ne!(
        a_box.parent(),
        daemon.parent(),
        "a box's leaf and the daemon's are siblings' subtrees apart, never the \
         same directory"
    );

    // Entering again is harmless: a daemon that restarts into the leaf it
    // already holds stays one member, and on a real tree the kernel keeps
    // the membership set — the second write is a no-op there.
    sandbox2::classifier::enter_daemon_leaf(root).expect("re-entering the daemon's leaf");
    let members = std::fs::read_to_string(&procs).expect("re-reading the daemon leaf's procs");
    assert!(
        members
            .lines()
            .any(|member| member == std::process::id().to_string()),
        "the daemon is still a member of its own leaf: {members:?}"
    );

    // And the one daemon that builds the tree itself — the guest's pid 1, on
    // the cgroup2 it mounted — makes both directories where there was
    // nothing, and then reports the stand-in's one gap as what it is: no
    // kernel made the `cgroup.procs` its entry writes into, so the write
    // says the leaf is missing, which over a real tree it never is. Nothing
    // boxes into a tree the entry could not enter.
    let bare = tempfile::tempdir().expect("a bare stand-in tree, nothing installed in it");
    let entry = sandbox2::classifier::enter_daemon_leaf(bare.path())
        .expect_err("over a bare stand-in no kernel made the daemon leaf's cgroup.procs");
    assert_eq!(
        entry.kind(),
        std::io::ErrorKind::NotFound,
        "the entry's write is a migration into a leaf that must already hold \
         its kernel-made files: a missing one is a missing leaf"
    );
    assert!(
        bare.path().join(sandbox2::classifier::BOXES_DIR).is_dir(),
        "the pid-1 entry builds the cohort directory where it has the \
         privilege to"
    );
    assert!(
        sandbox2::classifier::daemon_leaf(bare.path()).is_dir(),
        "the pid-1 entry builds its own leaf where it has the privilege to"
    );
}

/// Only the guest refuses an unplaceable box, and only a host-address one
/// (design §7.1). In the guest, a missing or undelegated cgroup2 tree is a
/// broken image — the daemon's own boot path is the only thing that could
/// have built it — so a box that would speak with the VM's address and no
/// verdict of its own is refused rather than run unenforced. Natively the
/// same state is NET-079's exception: advisory, never a refusal; and a box
/// that isolates its own network is never the box the refusal is for.
#[test]
fn only_the_guest_refuses_an_unplaceable_host_address_box() {
    use sessions::NetworkMode;

    assert!(
        refuses_unenforced_host_address_box(true, NetworkMode::HostNet),
        "a guest that cannot place a host-address box refuses it: it would \
         run with the VM's address and no verdict at all"
    );
    for (guest, mode, why) in [
        (
            true,
            NetworkMode::NoNet,
            "a none box claims no address to speak with",
        ),
        (
            true,
            NetworkMode::OwnIp,
            "an own-IP box's address is the switch's to decide, not the cgroup's",
        ),
        (
            false,
            NetworkMode::HostNet,
            "natively the same state is the exception: advisory, never a refusal",
        ),
        (false, NetworkMode::NoNet, "a native none box, likewise"),
        (false, NetworkMode::OwnIp, "a native own-IP box, likewise"),
    ] {
        assert!(
            !refuses_unenforced_host_address_box(guest, mode),
            "{why}: the box launches, enforced where the tree allowed it and \
             unenforced with a log line where it did not"
        );
    }
}

/// A leaf a fresh launch finds, and what it may be (NET-079): a leftover
/// from a daemon death the start sweep could not have seen — the daemon died
/// between creating the leaf and spawning the box into it — or another
/// session's, which the same session id cannot be. The kernel's own
/// emptiness test tells them apart, and it is the `rmdir` of
/// [`sandbox2::classifier::remove_box_leaf`]: a cgroup holding a process
/// cannot be removed, so a leftover that goes was nobody's and one that
/// stays belongs to a session the daemon no longer knows. Driven over a
/// stand-in tree, where the modelled kernel files stand in for the members:
/// the reclaims are the same code paths, and only the emptiness test is the
/// kernel's.
#[test]
fn a_leftover_leaf_is_reclaimed_but_a_held_one_refuses_the_launch() {
    let tree = tempfile::tempdir().expect("a temp dir standing in for the tree");
    let cohort = tree.path().join(sandbox2::classifier::BOXES_DIR);
    let subtree = cohort.join(sandbox2::config::DENY_DIR);
    std::fs::create_dir_all(&subtree).expect("the cohort directory and its subtree");
    let id = sessions::SessionId::nil();
    // One verdict for the whole proof: the reclaim is the same code path in
    // either subtree, and a box's verdict is fixed at create.
    let verdict = sandbox2::config::Verdict::Deny;
    let named = sandbox2::classifier::box_leaf(tree.path(), &id.to_string(), verdict);

    // The fresh launch: nothing to find, so nothing to reclaim.
    let (leaf, reclaimed) = super::create_or_reclaim_box_leaf(tree.path(), &id, verdict)
        .expect("the fresh launch creates its leaf");
    assert!(!reclaimed, "a fresh launch reclaims nothing");
    assert_eq!(
        leaf, named,
        "the leaf is named by the session that holds it, in its verdict's subtree"
    );

    // The leftover: empty, as a launch that never reached its spawn leaves
    // it. The emptiness test lets it go, and the launch creates the leaf
    // again for this box rather than reusing the directory as-is.
    let (leaf, reclaimed) = super::create_or_reclaim_box_leaf(tree.path(), &id, verdict)
        .expect("an empty leftover is reclaimed");
    assert!(
        reclaimed,
        "an empty leftover is reclaimed: the launch tried its rmdir, the \
         kernel's own test that a cgroup holds no process, and it went"
    );
    assert_eq!(
        leaf, named,
        "the reclaimed leaf is this session's, recreated"
    );

    // A leaf that still holds a session: over a real tree the kernel refuses
    // the rmdir while the cgroup holds a process; over this stand-in the
    // modelled procs file stands in for the members, and the refusal is the
    // same `rmdir`'s. The launch is refused rather than placing this box in
    // another session's cgroup, and the refusal names the test that refused.
    model_cgroup_files(&leaf);
    let held = super::create_or_reclaim_box_leaf(tree.path(), &id, verdict)
        .expect_err("a leaf another session holds is not taken over");
    assert_eq!(
        held.kind(),
        std::io::ErrorKind::AlreadyExists,
        "the held leaf surfaces as the collision it is, not as a leftover"
    );
    for named in [
        "its rmdir",
        "another session holds this one's classifier leaf",
    ] {
        assert!(
            held.to_string().contains(named),
            "the refusal says what would have had to be true for the leaf to \
             have been reclaimable: {held}"
        );
    }
    assert!(
        leaf.is_dir(),
        "the held leaf outlives the launch that would have taken it over"
    );
}

/// What the launch's leaf decision means for the box's egress verdict — the
/// declared-and-enforced attribute a session carries from its launch
/// (design §7.2): a host-address box with a leaf is enforced, a
/// host-address box without one runs with the host's address and no verdict
/// of its own, and a none box or an own-IP box has no host address to decide
/// on at all. Pure over its inputs, so each mapping is pinned where it is
/// written — beside the refusal predicate, the two halves of what a launch
/// says about the box it is about to run.
#[test]
fn host_ip_enforcement_says_what_the_launch_decided() {
    use sessions::NetworkMode;

    let tree = tempfile::tempdir().expect("a temp dir standing in for the tree");
    std::fs::create_dir_all(
        tree.path()
            .join(sandbox2::classifier::BOXES_DIR)
            .join(sandbox2::config::DENY_DIR),
    )
    .expect("the cohort directory and its subtree");
    let leaf = sandbox2::config::ClassifierLeaf::new(
        sandbox2::classifier::create_box_leaf(
            tree.path(),
            "a placed box",
            sandbox2::config::Verdict::Deny,
        )
        .expect("the leaf the launch places its box in"),
    );
    let decided = |mode, leaf: Option<sandbox2::config::ClassifierLeaf>| {
        super::host_ip_enforcement(mode, leaf.as_ref())
    };

    assert_eq!(
        decided(NetworkMode::HostNet, Some(leaf.clone())),
        Some(super::HostIpEnforcement::Enforced),
        "a host-address box with a leaf has its egress verdict decided on it"
    );
    assert_eq!(
        decided(NetworkMode::HostNet, None),
        Some(super::HostIpEnforcement::Unenforced),
        "a host-address box with no leaf runs with the host's address and no \
         verdict of its own — the state the session-start notice names"
    );
    for (mode, why) in [
        (NetworkMode::NoNet, "a none box has no traffic to decide"),
        (
            NetworkMode::OwnIp,
            "an own-IP box's verdict is its own, on the address it holds",
        ),
    ] {
        for leaf in [Some(leaf.clone()), None] {
            assert_eq!(
                decided(mode, leaf),
                None,
                "{why}: there is no host address to decide on, leaf or no leaf"
            );
        }
    }
}

/// A torn-down box's leaf goes when the box's cgroup stops refusing it, not
/// when the teardown's first `rmdir` happens to land: a SIGKILLed box's
/// cgroup answers `EBUSY` for a few milliseconds after the reap, while the
/// kernel empties it, and a leaf that leaked on that window would outlive
/// its box until a later launch of the same session id reclaimed it. Over
/// this stand-in tree the modelled `cgroup.procs` is the obstruction —
/// `rmdir` refuses a non-empty directory the way the kernel refuses a
/// cgroup that still holds a process — and the seam's pause callback clears
/// it between two attempts, so the proof is the retry itself: the removal
/// succeeds on the attempt after the obstruction went, and an obstruction
/// that never goes gives up after the attempts it was given, with the
/// `rmdir`'s own refusal for the caller to warn.
#[test]
fn a_torn_down_boxs_leaf_removal_outlasts_its_last_moments() {
    let tree = tempfile::tempdir().expect("a temp dir standing in for the tree");
    std::fs::create_dir_all(
        tree.path()
            .join(sandbox2::classifier::BOXES_DIR)
            .join(sandbox2::config::DENY_DIR),
    )
    .expect("the cohort directory and its subtree");
    let leaf = sandbox2::classifier::create_box_leaf(
        tree.path(),
        "a torn-down box",
        sandbox2::config::Verdict::Deny,
    )
    .expect("the box's leaf, as its teardown finds it");
    model_cgroup_files(&leaf);

    let outcome = super::remove_box_leaf_patiently(&leaf, 5, |attempt| {
        if attempt == 2 {
            for name in CGROUP_KERNEL_FILES {
                std::fs::remove_file(leaf.join(name))
                    .unwrap_or_else(|e| panic!("clearing {name} in {}: {e}", leaf.display()));
            }
        }
    });
    assert!(
        outcome.is_ok(),
        "the leaf went on the attempt after the box's cgroup stopped \
         refusing its removal: {outcome:?}"
    );
    assert!(
        !leaf.exists(),
        "a leaf whose refusal was only the box's last moments does not \
         outlive the box"
    );

    // A leaf that keeps refusing is warned about, not parked behind: the
    // attempts are spent, and the refusal the caller warns with is the
    // kernel's own test that the cgroup still holds a process — here, the
    // `rmdir`'s ENOTEMPTY over the modelled file.
    let held = sandbox2::classifier::create_box_leaf(
        tree.path(),
        "a box still dying",
        sandbox2::config::Verdict::Deny,
    )
    .expect("the leaf of a box whose teardown could not remove it");
    model_cgroup_files(&held);
    let refused =
        super::remove_box_leaf_patiently(&held, 3, |_| ()).expect_err("the obstruction stays");
    assert_eq!(
        refused.raw_os_error(),
        Some(libc::ENOTEMPTY),
        "the warn a teardown raises names the rmdir's own refusal, not a \
         retry's: {refused}"
    );
    assert!(
        held.is_dir(),
        "a leaf that keeps refusing outlives the teardown that owes it, to \
         be reclaimed by the same session's next launch"
    );
}

/// Which line of a box's closure report settles the box's fate — the one
/// fact the removal of the report rests on. A `failed` line is written by
/// the closure's own exit path and nothing follows it, so the fate is known
/// the moment it is read; a `cover` line is written while the closure is
/// still heading for its exec, and a line the daemon does not read settles
/// nothing at all.
#[test]
fn a_failed_closure_line_settles_the_boxs_fate_a_cover_line_does_not() {
    assert!(
        !super::say_closure_line("cover cgroup2", "a session"),
        "a cover line leaves the closure still heading for its exec, so the \
         file has to stay for the failure that can still replace it"
    );
    assert!(
        !super::say_closure_line("cover tmpfs-fallback errno 22", "a session"),
        "the recorded fallback is as non-terminal as the design's cover"
    );
    assert!(
        super::say_closure_line(
            "failed covering the bound classifier tree errno 1",
            "a session"
        ),
        "a failed line is the closure's own exit path — nothing follows it, \
         so the fate is known and the tree is owed its removal"
    );
    assert!(
        !super::say_closure_line("a line this daemon does not read", "a session"),
        "an unknown line settles nothing: the watch owes the file to the end \
         of its window"
    );
}

/// The closure report is taken away only once the box's fate is known: a
/// `failed` line is terminal, so the file goes the moment it is read, while
/// a `cover` line is not — the closure that covered and then died past that
/// point replaces its line with the diagnosis a bare `127` would otherwise
/// lose, and taking the file on the first read would drop that line into a
/// file nobody reads.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_closure_report_is_removed_only_once_the_boxs_fate_is_known() {
    let dir = tempfile::tempdir().expect("a temp dir for the closure reports");
    let failed = dir.path().join("a-failed-closure");
    std::fs::write(
        &failed,
        "failed joining the box's classifier leaf errno 1\n",
    )
    .expect("the closure's dying line");

    super::report_box_closure(
        failed.clone(),
        "a session".to_string(),
        Duration::from_secs(10),
    )
    .await;
    assert!(
        !failed.exists(),
        "a failed line settles the fate: the removal is owed the moment it \
         is read, not ten seconds later"
    );

    let covered = dir.path().join("a-covered-closure");
    std::fs::write(&covered, "cover cgroup2\n").expect("the cover the closure took");
    let watching = tokio::spawn(super::report_box_closure(
        covered.clone(),
        "a session".to_string(),
        Duration::from_millis(300),
    ));
    // The watch has read the cover line by now — the file is there from the
    // first poll — and still holds it: the fate is not known yet.
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        covered.exists(),
        "a cover line does not settle the fate, so the report stays for the \
         failure that can still replace it"
    );
    watching.await.expect("the watch ends on its own");
    assert!(
        !covered.exists(),
        "the watch's window is the fate known by default: the removal is \
         owed at the end of it, and only then"
    );
}

/// A [`SandboxLauncher`] for the launch-path test: the fakerepo context the
/// channel tests use, a switch client pointed at a binary that is not there,
/// and no composition — everything a launch needs to reach its own
/// decisions, and nothing that could fetch or build. The state dir travels
/// out with the launcher, because the context reads it long after this
/// returns.
fn sandbox_launcher(network_mode: sessions::NetworkMode) -> (SandboxLauncher, tempfile::TempDir) {
    let state = tempfile::tempdir().expect("a state dir for the launcher's context");
    (launcher_in(network_mode, state.path()), state)
}

/// The same launcher over a *given* state dir, so a test that drives more
/// than one launch can hold one daemon's state under all of them — the real
/// daemon builds one launcher per launch, so the per-launch construction is
/// production's shape; only the state dir is shared.
fn launcher_in(
    network_mode: sessions::NetworkMode,
    state_path: &std::path::Path,
) -> SandboxLauncher {
    launcher_with(network_mode, state_path, sessions::SessionPolicy::default())
}

/// The same launcher carrying the session's policy, so a test can launch a
/// box with the declaration it is proving something about: the verdict the
/// classifier decides a host-address box by is read off this policy
/// (NET-079), and nothing else about the launcher changes.
fn launcher_with(
    network_mode: sessions::NetworkMode,
    state_path: &std::path::Path,
    policy: sessions::SessionPolicy,
) -> SandboxLauncher {
    let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let config = mctx::ConfigBuilder::new()
        .with_state_dir(state_path.to_path_buf())
        .with_repo_dir(manifest_dir.join("../mctx/testdata/fakerepo"))
        .with_stdlib_dir(manifest_dir.join("../stdlib/minimal-ncl"))
        .with_no_fetch(true)
        .build()
        .expect("the fakerepo context builds");
    SandboxLauncher {
        ctx: mctx::Context::new(config).expect("the fakerepo context loads"),
        attach_env: AttachEnv::default(),
        network_mode,
        net_switch: std::sync::Arc::new(tokio::sync::Mutex::new(crate::net::SwitchClient::new(
            "/nonexistent/gvproxy",
            state_path.to_path_buf(),
        ))),
        policy,
        own_address: None,
        box_addresses: None,
        composition: None,
        session: crate::session::WeakSessionHandle::dangling(),
        // The tests here drive the session's own launches unless one sets
        // the purpose itself (`a_hook_launch_does_not_advise_unenforced_placement`).
        for_hooks: false,
    }
}

/// The launch-path half of the guest refusal: the predicate says which
/// launch must be refused, and this drives the launcher itself, with the
/// guest flag handed in as production hands it in, so the refusal the
/// predicate names is the one `launch` returns — for the host-address box in
/// the guest, and for no other launch. A none box, an own-IP box and a
/// native host-address box go through the same tree-less host and none is
/// stopped by the classifier: what each returns is whatever its launch
/// found next, because the baseline packages are not materializable in the
/// unit-test environment — which is exactly why the refusal's *absence* is
/// the assertion, and a launched-and-dropped [`Launched`] is what its `Drop`
/// promises it is.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn guest_launch_refuses_only_the_unplaced_host_address_box() {
    use sessions::NetworkMode;

    // The one host state this proof cannot run on: a tree this daemon can
    // place a child in. The refusal it asserts is the guest's answer to a
    // leaf decision that came back `None`, and on a delegated host the launch
    // gets a leaf instead, so the guest's host-address launch proceeds past
    // the gate and the proof's assertions would be measuring a different
    // launch's answer. The placement probe is the same one the launch runs,
    // so the skip is the deployment's own state, printed rather than passed
    // off as a pass.
    if sandbox2::classifier::probe_child_placement(
        std::path::Path::new(sandbox2::classifier::TREE_ROOT),
        // The deny subtree: the strictest verdict's placement is the one
        // these proofs need to be impossible here — if the daemon can place
        // a child in it, a host-address launch gets its leaf and the proof
        // would measure a different launch's answer.
        sandbox2::config::Verdict::Deny,
    )
    .is_ok()
    {
        eprintln!(
            "skipping guest_launch_refuses_only_the_unplaced_host_address_box: this \
             daemon can place a child in its classifier tree, so a guest \
             host-address launch gets a leaf here and is not refused; the refusal \
             is proved on a host with no placeable tree"
        );
        return;
    }

    const REFUSAL: &str = "this guest has no classifier tree to place a host-address box in";
    for (guest, mode, refused, why) in [
        (
            true,
            NetworkMode::HostNet,
            true,
            "a guest's host-address box",
        ),
        (true, NetworkMode::NoNet, false, "a guest's none box"),
        (true, NetworkMode::OwnIp, false, "a guest's own-IP box"),
        (
            false,
            NetworkMode::HostNet,
            false,
            "a native host-address box",
        ),
    ] {
        let (launcher, _state) = sandbox_launcher(mode);
        let outcome = tokio::time::timeout(
            Duration::from_secs(30),
            launcher.launch(
                guest,
                sessions::SessionId::nil(),
                "refusal-proof".to_string(),
                "guest".to_string(),
                test_paths(),
                DEFAULT_SIZE,
            ),
        )
        .await
        .expect("the launch decides within its timeout")
        .map(|launched| {
            // Nothing a launch returns outlives this block: the process and
            // its leaf are what the guard's `Drop` reaps when it goes.
            drop(launched);
        });
        match (outcome, refused) {
            (Err(e), true) => {
                eprintln!("{why}: refused with {e}");
                assert!(
                    e.to_string().contains(REFUSAL),
                    "{why} is refused with the named error, not: {e}"
                );
            }
            (Err(e), false) => {
                eprintln!("{why}: launches past the classifier gate, and stops at {e}");
                assert!(
                    !e.to_string().contains(REFUSAL),
                    "{why} is not a host-address box this guest cannot place, so \
                     it is not refused on that ground: {e}"
                );
            }
            (Ok(()), false) => eprintln!("{why}: launched"),
            (Ok(()), true) => panic!("{why} must be refused, and was launched"),
        }
    }
}

/// NET-079's exception, for the boxes it is written for: on a native host
/// that cannot decide per box, a host-address box declared deny-all or
/// carrying an egress section runs anyway — never refused on the
/// classifier's ground — with no verdict of its own, recorded as unenforced.
/// The gate is the *host's* decision, never the box's declaration: the
/// deny-all box is the one a missing verdict would bite, and it is exactly
/// the one the exception runs.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unenforcing_native_host_runs_host_ip_box_unenforced() {
    use sessions::NetworkMode;

    // The one host state this proof cannot run on: a tree this daemon can
    // place a child in (the guest refusal test's skip, for the same reason).
    // The launch's placement probe and the start-time check must then agree
    // that this host decides nothing per box, because the record the proof
    // reads is the one that agreement produces.
    if sandbox2::classifier::probe_child_placement(
        std::path::Path::new(sandbox2::classifier::TREE_ROOT),
        sandbox2::config::Verdict::Deny,
    )
    .is_ok()
    {
        eprintln!(
            "skipping unenforcing_native_host_runs_host_ip_box_unenforced: this \
             daemon can place a child in its classifier tree, so a native \
             host-address launch gets a leaf here and is enforced; the \
             unenforced run is proved on a host with no placeable tree"
        );
        return;
    }
    let host = crate::net::classifier::decide(
        std::path::Path::new(sandbox2::classifier::TREE_ROOT),
        sandbox2::classifier::own_mountinfo().as_deref(),
        false,
    );
    assert!(
        !host.can_decide_per_box(),
        "the start-time check must agree with the launch's own placement probe"
    );

    // The gate never turns on the declaration: the deny-all verdict the
    // declaration picks is decided, and it refuses nothing by itself — only
    // a *host* that can decide per box has a subtree to enforce it in.
    assert_eq!(
        crate::net::classifier::verdict_of(Some(&sessions::EgressPolicy::deny_all())),
        sandbox2::config::Verdict::Deny,
        "the deny-all declaration still picks the deny subtree"
    );
    assert!(
        !super::refuses_unenforced_host_address_box(false, NetworkMode::HostNet),
        "a native host never refuses a box on the classifier's ground"
    );
    assert_eq!(
        super::host_ip_enforcement(NetworkMode::HostNet, None),
        Some(super::HostIpEnforcement::Unenforced),
        "a host-address box with no leaf is recorded unenforced, whatever it \
         declared"
    );

    // Both boxes NET-079's exception names, driven through the launch on the
    // same undecided host: a deny-all box, and one carrying an egress
    // section. Neither is refused, and each is recorded unenforced in the
    // machine spelling.
    let capture = crate::test_harness::captured_log();
    const REFUSAL: &str = "has no classifier tree to place a host-address box in";
    const RECORD: &str = "the session's host-address box runs unenforced on this host";
    const MACHINE_FIELD: &str = "host_ip_enforcement=none";
    let section = sessions::EgressPolicy {
        allow_subnets: Some(vec!["10.0.0.0/8".to_string()]),
        ..sessions::EgressPolicy::deny_all()
    };
    let state = tempfile::tempdir().expect("a state dir for the daemon's context");
    for (label, name, egress) in [
        (
            "a deny-all box",
            "unenforced-proof-deny-all",
            sessions::EgressPolicy::deny_all(),
        ),
        (
            "a box carrying an egress section",
            "unenforced-proof-section",
            section,
        ),
    ] {
        let launcher = launcher_with(
            NetworkMode::HostNet,
            state.path(),
            sessions::SessionPolicy::new(Some(egress), None),
        );
        let outcome = tokio::time::timeout(
            Duration::from_secs(30),
            launcher.launch(
                false,
                sessions::SessionId::nil(),
                name.to_string(),
                "user".to_string(),
                test_paths(),
                DEFAULT_SIZE,
            ),
        )
        .await
        .expect("the launch decides within its timeout");
        // The box runs: whatever the launch stops at next is its own — this
        // box's unit-test graph cannot materialize its baseline packages —
        // and the classifier is not what stopped it.
        if let Err(e) = &outcome {
            assert!(
                !e.to_string().contains(REFUSAL),
                "{label} is never refused on the classifier's ground: {e}"
            );
        }
        drop(outcome);

        let logged = capture.contents();
        let record = logged
            .lines()
            .find(|line| line.contains(RECORD) && line.contains(&format!("session={name}")))
            .unwrap_or_else(|| {
                panic!("no unenforced record for the {label} launch, got: {logged}")
            });
        assert!(
            record.contains(MACHINE_FIELD),
            "the record carries the decision in the machine spelling: {record}"
        );
    }
}

/// The unenforced-placement record is not a once-per-daemon latch: the
/// resolver-hook advisory it is modelled on (NET-122, design §7.1) advises on
/// every session start, so two launches on one daemon each write the record
/// the launch emits at its placement decision — attributed to its session,
/// carrying the same text the session's banner gets and the decision in the
/// machine spelling a reader greps for (`host_ip_enforcement`, spelled
/// `per_box` / `none`).
///
/// Both forms are the daemon's surfaces, and no client reads either: the
/// record lives on the daemon's log stream — not the session reply, not the
/// CLI's start output — and the banner is written onto the session's own pty,
/// the in-session surface. Carrying the field out to a client over the
/// session reply and `min doctor` is issue #1773, outside this task's layers.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_unenforced_record_fires_on_every_launch_and_carries_the_field() {
    use sessions::NetworkMode;

    // The one host state this proof cannot run on: a tree this daemon can
    // place a child in (the guest refusal test's skip, for the same reason).
    // The record fires only for a native host-address launch that got no
    // leaf, and on a delegated host the launch gets one, so there is nothing
    // to record — the skip is the deployment's own state, printed rather than
    // passed off as a pass.
    if sandbox2::classifier::probe_child_placement(
        std::path::Path::new(sandbox2::classifier::TREE_ROOT),
        // The deny subtree: the strictest verdict's placement is the one
        // these proofs need to be impossible here — if the daemon can place
        // a child in it, a host-address launch gets its leaf and the proof
        // would measure a different launch's answer.
        sandbox2::config::Verdict::Deny,
    )
    .is_ok()
    {
        eprintln!(
            "skipping the_unenforced_record_fires_on_every_launch_and_carries_the_field: \
             this daemon can place a child in its classifier tree, so a native \
             host-address launch gets a leaf here and the record never fires; \
             the record is proved on a host with no placeable tree"
        );
        return;
    }

    let capture = crate::test_harness::captured_log();
    const NOTICE: &str = "this host places no classifier leaf for this session";
    const RECORD: &str = "the session's host-address box runs unenforced on this host";
    const MACHINE_FIELD: &str = "host_ip_enforcement=none";

    // One daemon: one state dir, two launches of it. The real daemon builds
    // its launcher per launch, so the launchers are per-launch while the
    // state they read and write stays the daemon's own.
    let state = tempfile::tempdir().expect("a state dir for the daemon's context");
    for (label, name) in [
        ("first", "notice-proof-first"),
        ("second", "notice-proof-second"),
    ] {
        let outcome = tokio::time::timeout(
            Duration::from_secs(30),
            launcher_in(NetworkMode::HostNet, state.path()).launch(
                // Native: a guest's unplaced host-address box is refused
                // instead of advised, so only the native launch reaches the
                // record.
                false,
                sessions::SessionId::nil(),
                name.to_string(),
                "user".to_string(),
                test_paths(),
                DEFAULT_SIZE,
            ),
        )
        .await
        .expect("the launch decides within its timeout");
        // The launch is driven for its record, which fires at the placement
        // decision — before the env build, which fails on this box's
        // unit-test graph ("no such package: base") — so the launch need not
        // complete, and nothing of it is kept: whatever it returned, its
        // guards run on the drop.
        drop(outcome);

        // The daemon-log record, per launch: this launch's own, attributed
        // and carrying the decision in the machine spelling — a
        // once-per-daemon latch would leave this launch without one.
        let logged = capture.contents();
        let record = logged
            .lines()
            .find(|line| line.contains(RECORD) && line.contains(&format!("session={name}")))
            .unwrap_or_else(|| {
                panic!("no unenforced-placement record for the {label} launch, got: {logged}")
            });
        assert!(
            record.contains(NOTICE),
            "the record carries the same text the session's banner gets: {record}"
        );
        assert!(
            record.contains(MACHINE_FIELD),
            "the record carries the decision in the machine spelling: {record}"
        );
    }
}

/// A launch minted for lifecycle hooks is not a session start, so it advises
/// on neither surface: the record would count one hook run as one session
/// start on the daemon's log, and the banner would be written into a hook pty
/// nobody reads. The same tree-less host, the same native host-address mode:
/// the session's own launch records the advisory, the hook launch — whose box
/// is placed (or left unenforced) exactly like the session's — stays silent.
///
/// The record is the form this box can observe: the banner's write sits after
/// the env build, which fails on this box's unit-test graph before any pty is
/// opened, so the banner is pinned to the same `advise` gate by construction
/// and its suppression is proved at the record.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_hook_launch_does_not_advise_unenforced_placement() {
    use sessions::NetworkMode;

    // The one host state this proof cannot run on: a tree this daemon can
    // place a child in (the guest refusal test's skip, for the same reason).
    // On a delegated host the launch gets a leaf and neither launch advises,
    // so there is nothing to tell apart here.
    if sandbox2::classifier::probe_child_placement(
        std::path::Path::new(sandbox2::classifier::TREE_ROOT),
        // The deny subtree: the strictest verdict's placement is the one
        // these proofs need to be impossible here — if the daemon can place
        // a child in it, a host-address launch gets its leaf and the proof
        // would measure a different launch's answer.
        sandbox2::config::Verdict::Deny,
    )
    .is_ok()
    {
        eprintln!(
            "skipping a_hook_launch_does_not_advise_unenforced_placement: this \
             daemon can place a child in its classifier tree, so a native \
             host-address launch gets a leaf here and neither launch advises; \
             the gate is proved on a host with no placeable tree"
        );
        return;
    }

    let capture = crate::test_harness::captured_log();
    const RECORD: &str = "the session's host-address box runs unenforced on this host";
    // The per-launch note from the placement decision itself — not the
    // advisory, and not gated with it. Which note a tree-less host records
    // depends on what covers the tree root: under no cgroup2 mount the tree
    // is not real; under one with no tree installed — every cgroup2 host,
    // this test's CI runner included — the placement probe's throwaway leaf
    // is what finds the tree missing. Either pins the launch to the same
    // decision point.
    const HOOK_UNGATED_NOTES: [&str; 2] = [
        "this host has no classifier tree to place a box in",
        "the classifier tree is not installed on this host",
    ];
    const SESSION: &str = "advice-proof-session";
    const HOOK: &str = "advice-proof-hook";

    let state = tempfile::tempdir().expect("a state dir for the daemon's context");

    // The session's own launch, first: its record is the control that keeps
    // the absence below honest — if the advisory stopped firing entirely,
    // both launches would be silent and the absence would prove nothing.
    let session_launch = tokio::time::timeout(
        Duration::from_secs(30),
        launcher_in(NetworkMode::HostNet, state.path()).launch(
            false,
            sessions::SessionId::nil(),
            SESSION.to_string(),
            "user".to_string(),
            test_paths(),
            DEFAULT_SIZE,
        ),
    )
    .await
    .expect("the launch decides within its timeout");
    drop(session_launch);
    let logged = capture.contents();
    assert!(
        logged
            .lines()
            .any(|line| line.contains(RECORD) && line.contains(&format!("session={SESSION}"))),
        "the session's own launch records the advisory, got: {logged}"
    );

    // The hook launch: the same launch with the hook purpose on, which is
    // how the session's hook path mints it (`launch_host_for_hooks`).
    let mut hook_launcher = launcher_in(NetworkMode::HostNet, state.path());
    hook_launcher.for_hooks = true;
    let hook_launch = tokio::time::timeout(
        Duration::from_secs(30),
        hook_launcher.launch(
            false,
            sessions::SessionId::nil(),
            HOOK.to_string(),
            "user".to_string(),
            test_paths(),
            DEFAULT_SIZE,
        ),
    )
    .await
    .expect("the launch decides within its timeout");
    drop(hook_launch);

    let logged = capture.contents();
    // The hook launch got to the placement decision: the tree-absent note
    // `create_session_leaf` records per launch is not the advisory and is
    // not gated with it, so its presence pins the launch's path to the same
    // point the session's launch recorded from — the absence below is the
    // gate, not an early exit.
    assert!(
        logged.lines().any(|line| {
            // That note's field is logged as a borrowed string, which
            // tracing quotes (`session="…"`), unlike the advisory's
            // `Display` field this test's other asserts match on.
            HOOK_UNGATED_NOTES.iter().any(|note| line.contains(note))
                && line.contains(&format!("session=\"{HOOK}\""))
        }),
        "the hook launch reached the placement decision, got: {logged}"
    );
    assert!(
        !logged
            .lines()
            .any(|line| line.contains(RECORD) && line.contains(&format!("session={HOOK}"))),
        "a hook launch is not a session start and records no advisory, got: {logged}"
    );
}
