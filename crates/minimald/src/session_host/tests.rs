use paths::DaemonAbsPath;

use super::*;
use std::time::Duration;

use crate::session::tests::{fake_forwarder, finalize_dynamic_ingress_session};
use crate::test_harness::{TestServer, captured_log};

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
            // No launch this mock stands for gathered a listen plan, so
            // the host it builds starts no listener watcher.
            listen_plan: None,
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
    // the cgroup2 it mounted — makes the whole layout where there was
    // nothing, and then reports the stand-in's one gap as what it is: no
    // kernel made the `cgroup.procs` its entry writes into, so the write
    // says the leaf is missing, which over a real tree it never is. Nothing
    // boxes into a tree the entry could not enter.
    //
    // The root is a path that does not exist yet, because that is the
    // guest's actual shape: a cgroup2 mounted with nothing in it, whose
    // `minimald.slice` no other hand makes — the installer is a native
    // host's, and inside the VM there is nobody to run it. An entry that
    // made only the levels below the root would fail on the first one and
    // leave the guest with no tree at all, which is the state every
    // host-address box there is refused on.
    let bare = tempfile::tempdir().expect("a bare stand-in tree, nothing installed in it");
    let slice = std::path::Path::new(sandbox2::classifier::TREE_ROOT)
        .file_name()
        .expect("the tree root is a path with a name");
    let root = bare.path().join(slice);
    let entry = sandbox2::classifier::enter_daemon_leaf(&root)
        .expect_err("over a bare stand-in no kernel made the daemon leaf's cgroup.procs");
    assert_eq!(
        entry.kind(),
        std::io::ErrorKind::NotFound,
        "the entry's write is a migration into a leaf that must already hold \
         its kernel-made files: a missing one is a missing leaf"
    );
    let cohort = root.join(sandbox2::classifier::BOXES_DIR);
    for (dir, level) in [
        (root.as_path(), "the tree root"),
        (cohort.as_path(), "the cohort the subtrees live in"),
        (
            cohort.join(sandbox2::config::DENY_DIR).as_path(),
            "the deny subtree",
        ),
        (
            cohort.join(sandbox2::config::ALLOW_DIR).as_path(),
            "the allow subtree",
        ),
    ] {
        assert!(
            dir.is_dir(),
            "the pid-1 entry builds {level} where it has the privilege to: {}",
            dir.display()
        );
    }
    assert!(
        sandbox2::classifier::daemon_leaf(&root).is_dir(),
        "the pid-1 entry builds its own leaf where it has the privilege to"
    );
}

/// Which undecided host-address boxes a launch refuses, and with what words
/// — the full matrix of the one expression the launch reads (design §7.1,
/// the A2 ruling). In the guest, a missing or undelegated cgroup2 tree is a
/// broken image — the daemon's own boot path is the only thing that could
/// have built it — so a box that would speak with the VM's address and no
/// verdict of its own is refused rather than run unenforced, whatever it
/// declared. So is a deny-all box whose table is not loaded — the interim,
/// guest-side classifier enforcement not being available yet: placed in a
/// leaf that decides nothing, it would run looking refused while nothing
/// refuses its connections. An allow box needs no verdict enforced, so a
/// guest that places it runs it.
///
/// Natively the two probe causes refuse the same box the interim does: a
/// *placed* deny-all box over a table whose marker vouches for a refusal
/// the probe did not read, or whose effect could not be read at all — the
/// one state where the box's own declaration is the thing this host cannot
/// honour, and the only native one, because every other native state is a
/// half a person can still fix from this host and keeps NET-079's advisory
/// posture. The words name the ground they refused on: the image's own
/// halves in the guest, and natively the cause and the command that ends
/// it. Pinned as data here, and driven through the launch by the two proofs
/// beside it — the refusal is a *placed* box's, and the kernel alone makes
/// the leaf a placement needs, so the launch-driven half runs the states a
/// stand-in tree can produce and this pin carries the placed one.
#[test]
fn which_undecided_host_address_boxes_are_refused_and_with_what_words() {
    use crate::net::classifier::{Cause, Decision};
    use sandbox2::config::Verdict;
    use sessions::NetworkMode;

    const BROKEN_IMAGE: &str = "(broken guest image)";
    const INTERIM: &str = "(guest-side classifier enforcement is not available yet)";
    let table_not_in_force: &str = "the table's refusal is not in force";

    // The guest's unplaceable box, either verdict: no leaf means no verdict
    // at all, whatever the declaration picked, and no decision read could
    // change that — the missing tree is the ground itself.
    for verdict in [Verdict::Deny, Verdict::Allow] {
        let refusal = refused_unenforced_host_address_box(
            true,
            NetworkMode::HostNet,
            verdict,
            false,
            Some(&Decision::undecidable(Cause::CannotConfine)),
        )
        .expect("a guest that cannot place a host-address box refuses it");
        assert!(
            refusal.contains(BROKEN_IMAGE),
            "the unplaceable box names the broken image it is: {refusal}"
        );
    }
    // A placed box on a guest whose table is loaded runs: its leaf's verdict
    // is decided on the table the image loaded, deny-all or not.
    assert!(
        refused_unenforced_host_address_box(
            true,
            NetworkMode::HostNet,
            Verdict::Deny,
            true,
            Some(&Decision::decided())
        )
        .is_none(),
        "a guest that placed a deny-all box in a loaded tree runs it, refused \
         by the table rather than by the launch"
    );
    // An allow box needs no verdict enforced, table loaded or not: the cohort
    // identity is all that is carried on its traffic — on either kind of
    // host, and over every cause that leaves the host undecided.
    for cause in [
        Cause::GuestTableNotLoaded,
        Cause::StepNotInstalled,
        Cause::CannotConfine,
        Cause::TableNotEffective,
        Cause::ProbeUnreadable,
    ] {
        let undecidable = Decision::undecidable(cause);
        for guest in [true, false] {
            assert!(
                refused_unenforced_host_address_box(
                    guest,
                    NetworkMode::HostNet,
                    Verdict::Allow,
                    true,
                    Some(&undecidable),
                )
                .is_none(),
                "an allow box needs no verdict enforced, so {guest} runs it over \
                 {cause:?}"
            );
        }
    }
    // The state the interim is refused for: a deny-all box placed on a guest
    // whose table is not loaded — and, on a guest, every undecidable cause
    // refuses it, because the image owns all of them.
    for cause in [
        Cause::GuestTableNotLoaded,
        Cause::StepNotInstalled,
        Cause::CannotConfine,
        Cause::TableNotEffective,
        Cause::ProbeUnreadable,
    ] {
        let refusal = refused_unenforced_host_address_box(
            true,
            NetworkMode::HostNet,
            Verdict::Deny,
            true,
            Some(&Decision::undecidable(cause)),
        )
        .expect("a guest that places a deny-all box while undecided refuses it");
        assert!(
            refusal.contains(INTERIM),
            "the guest's placed deny-all refusal names the interim, over {cause:?} \
             as over every undecided cause: {refusal}"
        );
    }
    // Natively, the two probe causes refuse the placed deny-all box — the
    // A2 ruling's one native refusal — each naming its own cause, and the
    // table's cause naming the command that reloads it.
    let ineffective = refused_unenforced_host_address_box(
        false,
        NetworkMode::HostNet,
        Verdict::Deny,
        true,
        Some(&Decision::undecidable(Cause::TableNotEffective)),
    )
    .expect("a native deny-all box whose marker outlived its table is refused");
    assert!(
        ineffective.contains(table_not_in_force)
            && ineffective.contains(&sandbox2::classifier::install_hint()),
        "the native TableNotEffective refusal names the cause and the command \
         that ends it: {ineffective}"
    );
    let unreadable = refused_unenforced_host_address_box(
        false,
        NetworkMode::HostNet,
        Verdict::Deny,
        true,
        Some(&Decision::undecidable(Cause::ProbeUnreadable)),
    )
    .expect("a native deny-all box whose probe could not read the table is refused");
    assert!(
        unreadable.contains("could not be read"),
        "the native ProbeUnreadable refusal names the unreadable effect it \
         refused on: {unreadable}"
    );
    // The rest of the native matrix keeps NET-079's advisory posture: the
    // causes this host can still fix from itself, the unplaced box (nothing
    // decided-looking to refuse), and the decided host — all run, enforced
    // where the tree and its table allowed it and unenforced with a log
    // line where it did not.
    for (cause, placed, decided, why) in [
        (
            Cause::StepNotInstalled,
            true,
            false,
            "a native host without the step keeps the advisory posture",
        ),
        (
            Cause::CannotConfine,
            true,
            false,
            "a native host that cannot confine a box keeps the advisory posture",
        ),
        (Cause::TableNotEffective, false, false, "the unplaced box"),
        (Cause::ProbeUnreadable, false, false, "the unplaced box"),
        (Cause::StepNotInstalled, false, false, "the unplaced box"),
        (Cause::CannotConfine, false, false, "the unplaced box"),
        (Cause::GuestTableNotLoaded, true, true, "the decided host"),
    ] {
        let decision = if decided {
            Decision::decided()
        } else {
            Decision::undecidable(cause)
        };
        assert!(
            refused_unenforced_host_address_box(
                false,
                NetworkMode::HostNet,
                Verdict::Deny,
                placed,
                Some(&decision),
            )
            .is_none(),
            "natively {why} is never refused, over {cause:?}"
        );
    }
    // And no other network mode is the box the refusal is for, on either
    // host: a none box claims no address to speak with, and an own-IP box's
    // address is the switch's to decide, not the cgroup's.
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
        (false, NetworkMode::NoNet, "a native none box, likewise"),
        (false, NetworkMode::OwnIp, "a native own-IP box, likewise"),
    ] {
        for cause in [
            Some(Decision::undecidable(Cause::TableNotEffective)),
            Some(Decision::undecidable(Cause::CannotConfine)),
            Some(Decision::decided()),
            None,
        ] {
            assert!(
                refused_unenforced_host_address_box(
                    guest,
                    mode,
                    Verdict::Deny,
                    true,
                    cause.as_ref(),
                )
                .is_none(),
                "{why}: the mode is not the box the refusal is for"
            );
        }
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

/// What the launch's leaf placement means for the box's egress record — the
/// declared-and-enforced attribute a session carries from its launch
/// (design §7.2): the placement is the outcome the launch records, never
/// the node fact re-read beside it, because the record is the box's own
/// launch outcome, not the host's state as it stands now. A host-address
/// box with a leaf is recorded `per_box` whatever the table is doing — the
/// reads lower it to the state the host can currently honour
/// (`displayed_host_ip_enforcement`), and when the table comes back the box
/// is in the leaf its launch placed it in. A host-address box without a
/// leaf ran with the host's address and no verdict of its own, recorded
/// `none` for its life; a none box or an own-IP box has no host address to
/// decide on at all. Pure over its inputs, so each mapping is pinned where
/// it is written — beside the refusal predicate, the two halves of what a
/// launch says about the box it is about to run.
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
    let placed = |mode, leaf: Option<sandbox2::config::ClassifierLeaf>| {
        super::host_ip_enforcement(mode, leaf.as_ref())
    };

    assert_eq!(
        placed(NetworkMode::HostNet, Some(leaf.clone())),
        Some(super::HostIpEnforcement::PerBox),
        "a host-address box its launch placed is recorded `per_box` — the \
         leaf is the outcome, and the reads lower it to the state the host \
         can currently honour, never raise a placement the tree did not make"
    );
    assert_eq!(
        placed(NetworkMode::HostNet, None),
        Some(super::HostIpEnforcement::None),
        "a host-address box its launch left unplaced is recorded `none` — it \
         ran with the host's address and no verdict of its own, and no \
         later host state is that launch's to raise it with"
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
                placed(mode, leaf),
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
        !super::say_closure_line("devpts max=1024 errno 22", "a session"),
        "a devpts remount refusal is recorded but non-terminal: the box still \
         runs on the shared PTY pool"
    );
    assert!(
        !super::say_closure_line("cover cgroup2; devpts max=1024 errno 22", "a session"),
        "a devpts refusal carried on the cover line is as non-terminal as both parts"
    );
    assert!(
        !super::say_closure_line(
            "cover tmpfs-fallback errno 22; devpts max=1024 errno 1",
            "a session"
        ),
        "the fallback cover keeps its errno when a devpts refusal rides on it"
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
        !super::say_closure_line("lo-down errno 1", "a session"),
        "a box whose loopback stayed down still heads for its exec — the \
         warn is the whole of it"
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

/// The closure report is read line by line: a `lo-down` line the closure
/// appended below its cover line is said in its own right, and a terminal
/// line behind it still settles the box's fate.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_line_of_a_multi_line_closure_report_is_read() {
    let dir = tempfile::tempdir().expect("a temp dir for the closure report");
    let report = dir.path().join("a-closure-with-two-findings");
    std::fs::write(
        &report,
        "cover cgroup2\nlo-down errno 1\nfailed exec /bin/sh errno 2\n",
    )
    .expect("the closure's lines");
    super::report_box_closure(
        report.clone(),
        "a session".to_string(),
        Duration::from_secs(10),
    )
    .await;
    assert!(
        !report.exists(),
        "the failed line on the report's last line settles the fate on the \
         first read, which only a line-by-line read reaches"
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
        // Production's root; a test that drives the launch over a stand-in
        // tree it built (the unenforced-launch proof) overrides this one
        // field, the same seam the real daemon's every path reads.
        classifier_root: std::path::PathBuf::from(sandbox2::classifier::TREE_ROOT),
        // Production's table: the daemon's own mount table, read live. A
        // launch driven over a stand-in tree overrides this one too, for the
        // same reason — the host's own mount table covers no stand-in tree,
        // so over it every stand-in reads as unconfined.
        classifier_mountinfo: None,
        // The empty set a launch's publications start from: these launches
        // run no runtime expose surface and carry no listen plan, so no
        // publication ever enters it.
        publications: Default::default(),
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
// `allow` rather than `expect` on purpose: this proof can skip, and on a host
// whose tree can place a child it returns before its first await, where an
// expectation the lint never meets would be its own warning.
#[allow(
    clippy::await_holding_lock,
    reason = "the guard spans the launches because each host-address one \
              re-reads the process-global classifier fact"
)]
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

    // The window the launches write the daemon's process-global classifier
    // fact in — every host-address launch re-reads it — taken for the whole
    // proof, so under libtest no concurrent read answers over the state
    // they write.
    let _fact_window = super::PROBE_TEST_MUTEX
        .lock()
        .unwrap_or_else(|p| p.into_inner());

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

/// The mount table an unset knob resolves to is the daemon's own, read
/// live: the knob's `None` is every production path, and the guest's
/// host-address boxes rest on that resolution — a guest's own boot mounts
/// the `nsdelegate` cgroup2 its tree sits on, and a launch that answered
/// over *no* table read that real tree as not real and refused every
/// host-address box in it as a broken image, which is what a native host
/// without a tree never does and why the VM lanes were the only ones to
/// see it. Pinned at the seam both halves of the launch answer over, the
/// same one the stand-in launches above drive through the knob: `None`
/// resolves to the daemon's own table, and a stand-in is answered over as
/// itself, never widened to the host's.
#[test]
fn a_none_mountinfo_knob_answers_over_the_daemons_own_mount_table() {
    let live = sandbox2::classifier::own_mountinfo();
    if live.is_none() {
        eprintln!(
            "skipping a_none_mountinfo_knob_answers_over_the_daemons_own_mount_table: \
             this host's mount table cannot be read, so the live resolution cannot \
             be told apart from a dropped one here"
        );
        return;
    }
    assert_eq!(
        super::launch_mountinfo(None),
        live,
        "a launch with no stand-in answers over the daemon's own, live mount table"
    );
    assert_eq!(
        super::launch_mountinfo(Some("stand-in table".to_string())).as_deref(),
        Some("stand-in table"),
        "a stand-in table is answered over as itself"
    );
}

/// NET-079's exception, for the boxes it is written for: on a native host
/// that cannot decide per box, a host-address box declared deny-all or
/// carrying an egress section runs anyway — never refused on the
/// classifier's ground — with no verdict of its own, recorded as unenforced.
/// The gate is the *host's* decision, never the box's declaration: the
/// deny-all box is the one a missing verdict would bite, and it is exactly
/// the one the exception runs.
///
/// Driven over a stand-in tree the test builds, not the host's own, so the
/// proof runs everywhere: the launcher reads the stand-in's root *and* its
/// mount table, so the launch's facts are the stand-in's whatever the host's
/// own tree is. The stand-in is the state a half-installed step leaves —
/// both subtrees delegated with the kernel's files in them, and the loaded
/// table's presence marker absent — so the start-time check decides nothing
/// per box, the launch reads that same decision fresh over the same tree,
/// and the placement probe is what reports the one thing the stand-in cannot
/// model, the kernel that makes a placement placeable: the record the proof
/// reads is the one that agreement produces.
#[expect(
    clippy::await_holding_lock,
    reason = "the guard spans the launches because each host-address one \
              re-reads the process-global classifier fact"
)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unenforcing_native_host_runs_host_ip_box_unenforced() {
    use sandbox2::config::Verdict;
    use sessions::NetworkMode;

    // The window the launches write the daemon's process-global classifier
    // fact in — every host-address launch re-reads it, and the proof below
    // reads the state they leave — taken for the whole proof, so under
    // libtest no concurrent read answers over the state they write.
    let _fact_window = super::PROBE_TEST_MUTEX
        .lock()
        .unwrap_or_else(|p| p.into_inner());

    // The stand-in tree: the slice under a stand-in cgroup2 mount, named as
    // the production tree is named, with the step's subtrees delegated and
    // the kernel's own files in them — everything but the marker that says
    // the table loaded.
    let scratch = tempfile::tempdir().expect("a scratch dir for the stand-in mount");
    let mountpoint = scratch.path().join("cgroup");
    let root = mountpoint.join(
        std::path::Path::new(sandbox2::classifier::TREE_ROOT)
            .file_name()
            .expect("the tree root is a slice below the cgroup2 mount root"),
    );
    for verdict in [Verdict::Deny, Verdict::Allow] {
        let subtree = root
            .join(sandbox2::classifier::BOXES_DIR)
            .join(verdict.dir_name());
        std::fs::create_dir_all(&subtree).expect("the step makes the subtree");
        model_cgroup_files(&subtree);
    }
    assert!(
        !root.join(sandbox2::classifier::TABLE_MARKER).exists(),
        "the stand-in models the step's half missing: no marker, so no \
         loaded table"
    );
    let mountinfo = format!(
        "35 30 0:26 / {} rw,relatime shared:2 - cgroup2 cgroup2 rw,nsdelegate\n",
        mountpoint.display(),
    );

    // The check over exactly that state: the subtrees are there, the table
    // is not, and nothing is decided per box — the decision the launch then
    // reads for itself, fresh, over the same stand-in root it places its
    // box in. The reading this hands in is a table refusing, so the
    // undecidable answer below is the facts' own: the marker alone is not
    // a fact the probe can turn into a verdict.
    let stand_in = crate::net::classifier::decide(
        &root,
        Some(&mountinfo),
        false,
        // A refusal the probe never observed: the facts gate the probe, so
        // this decides nothing by itself — the pin that the gate reads its
        // facts first, and a tree missing the step's half cannot be decided
        // by a reading that would say anything.
        || crate::net::classifier::Reading::Refused(Vec::new()),
    );
    assert!(
        !stand_in.can_decide_per_box(),
        "a host with the subtrees but no loaded table decides nothing per box"
    );
    assert_eq!(
        stand_in.cause(),
        Some(crate::net::classifier::Cause::StepNotInstalled),
        "the marker is the step's half too: subtrees alone decide nothing"
    );

    // The gate never turns on the declaration: the deny-all verdict the
    // declaration picks is decided, and it refuses nothing by itself — only
    // a *host* that can decide per box has a subtree to enforce it in. And
    // natively the states the gate keys on here keep the exception: the
    // unplaced box, the placed one over the causes this host can still fix
    // from itself, and the fully decided one all run — the one native
    // refusal is the placed deny-all box over the two probe causes, pinned
    // beside this with its words.
    assert_eq!(
        crate::net::classifier::verdict_of(Some(&sessions::EgressPolicy::deny_all())),
        Verdict::Deny,
        "the deny-all declaration still picks the deny subtree"
    );
    for (placed, decision, why) in [
        (
            false,
            crate::net::classifier::Decision::undecidable(
                crate::net::classifier::Cause::StepNotInstalled,
            ),
            "a native host never refuses an unplaced box, whatever it decided",
        ),
        (
            true,
            crate::net::classifier::Decision::undecidable(
                crate::net::classifier::Cause::StepNotInstalled,
            ),
            "a native host without the step keeps the advisory posture",
        ),
        (
            true,
            crate::net::classifier::Decision::undecidable(
                crate::net::classifier::Cause::CannotConfine,
            ),
            "a native host that cannot confine a box keeps the advisory posture",
        ),
        (
            true,
            crate::net::classifier::Decision::decided(),
            "a native host never refuses a decided box",
        ),
    ] {
        assert!(
            super::refused_unenforced_host_address_box(
                false,
                NetworkMode::HostNet,
                Verdict::Deny,
                placed,
                Some(&decision),
            )
            .is_none(),
            "{why}"
        );
    }
    assert_eq!(
        super::host_ip_enforcement(NetworkMode::HostNet, None),
        Some(super::HostIpEnforcement::None),
        "a host-address box with no leaf is recorded unenforced, whatever it \
         declared"
    );

    // Both boxes NET-079's exception names, driven through the launch on the
    // same undecided host: a deny-all box, and one carrying an egress
    // section. Neither is refused — by either refusal the guest answers with
    // — and each is recorded unenforced in the machine spelling.
    let capture = crate::test_harness::captured_log();
    const REFUSALS: [&str; 2] = [
        "has no classifier tree to place a host-address box in",
        "has not loaded the classifier table",
    ];
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
        let mut launcher = launcher_with(
            NetworkMode::HostNet,
            state.path(),
            sessions::SessionPolicy::new(Some(egress), None),
        );
        // The stand-in tree, not the host's: the launch's leaf, its probe
        // and its reclaim all read this one root, and its decision and its
        // tree-is-real check answer over this one mount table (see both
        // fields' docs) — so the launch reads the state this stand-in is,
        // whatever the host's own tree is, and the placement probe is what
        // tells it the kernel behind the stand-in is not there.
        launcher.classifier_root = root.clone();
        launcher.classifier_mountinfo = Some(mountinfo.clone());
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
            for refusal in REFUSALS {
                assert!(
                    !e.to_string().contains(refusal),
                    "{label} is never refused on the classifier's ground: {e}"
                );
            }
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

    // And the launches' re-read is the read that keeps the daemon's one node
    // fact current: the stand-in's own state — the step's half missing, so
    // nothing decided per box — is what the launches left in the fact every
    // read surface answers over, not a start-up reading that would outlive
    // the tree it read.
    let fact = super::host_ip_enforcement_fact();
    assert_eq!(
        fact.enforcement,
        minimald_rpc::HostIpEnforcement::None,
        "a launch over a tree missing the step's half leaves the fact's state \
         `none` — the re-read's own answer"
    );
    assert_eq!(
        fact.cause,
        Some(crate::net::classifier::Cause::StepNotInstalled),
        "the cause the re-read read is the fact's own, so the reads that \
         derive from it name the ground they answer on"
    );
}

/// The two probe causes, driven through the launch (A2's ruling): a native
/// host whose decision is `TableNotEffective` — the step installed, its
/// marker standing, and no refusal behind it, which is what a stand-in tree
/// is and what a host whose reload lost its reboot is — and one whose
/// decision is `ProbeUnreadable`, its probe unable to read the table at
/// all. Over either, a *placed* deny-all box is refused; the placement the
/// refusal needs is the kernel's to make and a stand-in tree has none, so
/// the launches here pin the wiring the ruling rests on: the launch reads
/// its decision fresh over the tree and the mount table it names, the
/// cause it read is the one the probe logged, and the box the exception is
/// written for — deny-all declared or not — runs unplaced and keeps the
/// advisory posture, its record saying `none` and its notice saying what
/// would end the cause. The placed box's refusal is pinned with its words
/// in `which_undecided_host_address_boxes_are_refused_and_with_what_words`,
/// and the reading the refusal turns on is proved against a real loaded
/// table by the root-gated proof in the classifier's module.
#[expect(
    clippy::await_holding_lock,
    reason = "the guard spans the launches because each host-address one \
              re-reads the process-global classifier fact"
)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_native_launch_over_either_probe_cause_runs_records_none_and_advises() {
    use sandbox2::config::Verdict;
    use sessions::NetworkMode;

    // The window the launches write the daemon's process-global classifier
    // fact in — every host-address launch re-reads it — taken for the whole
    // proof, so under libtest no concurrent read answers over the state
    // they write.
    let _fact_window = super::PROBE_TEST_MUTEX
        .lock()
        .unwrap_or_else(|p| p.into_inner());

    // The step's half, installed: both subtrees with the kernel's own files,
    // and the marker that says the table loaded — everything the two probe
    // causes' gate requires, so the launch's probe runs and its reading is
    // the cause.
    let scratch = tempfile::tempdir().expect("a scratch dir for the stand-in mount");
    let mountpoint = scratch.path().join("cgroup");
    let root = mountpoint.join(
        std::path::Path::new(sandbox2::classifier::TREE_ROOT)
            .file_name()
            .expect("the tree root is a slice below the cgroup2 mount root"),
    );
    for verdict in [Verdict::Deny, Verdict::Allow] {
        let subtree = root
            .join(sandbox2::classifier::BOXES_DIR)
            .join(verdict.dir_name());
        std::fs::create_dir_all(&subtree).expect("the step makes the subtree");
        model_cgroup_files(&subtree);
    }
    std::fs::create_dir_all(root.join(sandbox2::classifier::TABLE_MARKER))
        .expect("the step writes the marker");
    std::fs::create_dir_all(root.join("ct-mark-mask-0x30000000"))
        .expect("the step records the ct-mark mask beside the marker");
    let mountinfo = format!(
        "35 30 0:26 / {} rw,relatime shared:2 - cgroup2 cgroup2 rw,nsdelegate\n",
        mountpoint.display(),
    );
    // The probe's own throwaway leaf, named as the launch's probe names it
    // after this process: squatted with a plain file, its `mkdir` fails and
    // the reading is inconclusive — the cause that has no command to name.
    // The launch's *placement* probe is a different throwaway leaf and is
    // left alone, so the box's placement answers honestly over the
    // stand-in: the kernel behind it is not there.
    let squatted = sandbox2::classifier::box_leaf(
        &root,
        &format!("filter-probe-{}", std::process::id()),
        Verdict::Deny,
    );

    let capture = crate::test_harness::captured_log();
    const RECORD: &str = "the session's host-address box runs unenforced on this host";
    const MACHINE_FIELD: &str = "host_ip_enforcement=none";
    const NO_LEAF: &str = "this host places no classifier leaf for this session";
    const REFUSAL: &str = "was refused rather than run unenforced";
    let section = sessions::EgressPolicy {
        allow_subnets: Some(vec!["10.0.0.0/8".to_string()]),
        ..sessions::EgressPolicy::deny_all()
    };
    let state = tempfile::tempdir().expect("a state dir for the daemon's context");
    for (cause, probe_read, name, egress) in [
        (
            "TableNotEffective",
            // The probe ran and read the filter's effect: no table is loaded
            // behind the stand-in, so its legs connected — the probe's own
            // record says so, and the reading settles TableNotEffective.
            "the table did not refuse the probe",
            "probe-cause-proof-ineffective",
            sessions::EgressPolicy::deny_all(),
        ),
        (
            "TableNotEffective",
            "the table did not refuse the probe",
            "probe-cause-proof-ineffective-section",
            section.clone(),
        ),
        (
            "ProbeUnreadable",
            "the table's effect could not be read",
            "probe-cause-proof-unreadable",
            sessions::EgressPolicy::deny_all(),
        ),
        (
            "ProbeUnreadable",
            "the table's effect could not be read",
            "probe-cause-proof-unreadable-section",
            section,
        ),
    ] {
        // The unreadable reading only for the causes that need it: the
        // squat is this test's one lever over the probe, and it is gone
        // before the next launch reads a different cause.
        if cause == "ProbeUnreadable" {
            std::fs::write(&squatted, b"").expect("the probe's leaf is squatted with a file");
        } else {
            let _ = std::fs::remove_file(&squatted);
        }
        let mut launcher = launcher_with(
            NetworkMode::HostNet,
            state.path(),
            sessions::SessionPolicy::new(Some(egress), None),
        );
        launcher.classifier_root = root.clone();
        launcher.classifier_mountinfo = Some(mountinfo.clone());
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
        if let Err(e) = &outcome {
            assert!(
                !e.to_string().contains(REFUSAL),
                "an unplaced box over {cause} keeps the exception, whatever it \
                 declared: {e}"
            );
        }
        drop(outcome);

        // The launch read its decision: the probe's own record for the
        // cause it settled on, on this launch's pass.
        let logged = capture.contents();
        assert!(
            logged.contains(probe_read),
            "the launch over {cause} read the probe's {cause} answer, got: {logged}"
        );
        // ...and answered with the exception's own record: the box runs
        // unenforced, the decision spelled the way a script reads it, and
        // the notice saying what this host owes.
        let record = logged
            .lines()
            .find(|line| line.contains(RECORD) && line.contains(&format!("session={name}")))
            .unwrap_or_else(|| {
                panic!("no unenforced record for the {cause} launch, got: {logged}")
            });
        assert!(
            record.contains(MACHINE_FIELD) && record.contains(NO_LEAF),
            "the {cause} record carries the decision and the notice: {record}"
        );
    }
    let _ = std::fs::remove_file(&squatted);
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
// `allow` rather than `expect` on purpose: this proof can skip, and on a host
// whose tree can place a child it returns before its first await, where an
// expectation the lint never meets would be its own warning.
#[allow(
    clippy::await_holding_lock,
    reason = "the guard spans the launches because each host-address one \
              re-reads the process-global classifier fact"
)]
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

    // The window the launches write the daemon's process-global classifier
    // fact in — every host-address launch re-reads it — taken for the whole
    // proof, so under libtest no concurrent read answers over the state
    // they write.
    let _fact_window = super::PROBE_TEST_MUTEX
        .lock()
        .unwrap_or_else(|p| p.into_inner());

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
// `allow` rather than `expect` on purpose: this proof can skip, and on a host
// whose tree can place a child it returns before its first await, where an
// expectation the lint never meets would be its own warning.
#[allow(
    clippy::await_holding_lock,
    reason = "the guard spans the launches because each host-address one \
              re-reads the process-global classifier fact"
)]
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

    // The window the launches write the daemon's process-global classifier
    // fact in — every host-address launch re-reads it — taken for the whole
    // proof, so under libtest no concurrent read answers over the state
    // they write.
    let _fact_window = super::PROBE_TEST_MUTEX
        .lock()
        .unwrap_or_else(|p| p.into_inner());

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

/// The guest's unenforced host-address box is not a silent state: whatever
/// host it runs on, a box that runs without a verdict of its own is said at
/// its session start. The gate keys on the placement and the decision, and
/// the guest's refusal predicate keys on the placement and the declaration
/// — an unplaceable box, a deny-all box with no table to enforce it — so
/// the two never overlap: what reaches the gate runs, and what is refused
/// never reaches it. The notice is the interim's own words, because no
/// installer exists inside a
/// microVM: the person to tell is the image's builder, not whoever holds
/// the session, so no command is named. Pinned as data, so the gate and
/// the text are decided where they are written.
#[test]
fn the_guests_unenforced_host_address_box_advises_with_the_interim() {
    use sandbox2::config::Verdict;
    use sessions::NetworkMode;
    use std::path::Path;

    // The gate: the placement and the decision, never the host kind. A
    // refusal is `refused_unenforced_host_address_box`'s business, and a
    // box that runs without a verdict of its own advises wherever it runs.
    let undecidable = crate::net::classifier::Decision::undecidable(
        crate::net::classifier::Cause::GuestTableNotLoaded,
    );
    let decided = crate::net::classifier::Decision::decided();
    let leaf = sandbox2::config::ClassifierLeaf::under(
        Path::new(sandbox2::classifier::TREE_ROOT),
        "a session",
        Verdict::Allow,
    );
    assert!(
        super::advises_unenforced_placement(NetworkMode::HostNet, None, Some(&undecidable)),
        "a box nothing placed runs unenforced and says so"
    );
    assert!(
        super::advises_unenforced_placement(NetworkMode::HostNet, Some(&leaf), Some(&undecidable)),
        "the guest's own state: a leaf placed over a table that is not \
         deciding runs unenforced now, and that is what the notice names"
    );
    assert!(
        !super::advises_unenforced_placement(NetworkMode::HostNet, Some(&leaf), Some(&decided)),
        "a placed box on a host that decides per box runs enforced, and has \
         no unenforced state to say"
    );
    assert!(
        !super::advises_unenforced_placement(NetworkMode::OwnIp, Some(&leaf), Some(&undecidable)),
        "a box with no host address has no unenforced state to advise about"
    );
    // The record the same placement writes: the leaf is the outcome — the
    // reads lower it to `none` while the guest cannot decide, never the
    // guest's fact re-read beside it — and an unplaced box records the
    // state it ran in, which no later host state raises.
    assert_eq!(
        super::host_ip_enforcement(NetworkMode::HostNet, None),
        Some(super::HostIpEnforcement::None),
        "a box the launch left unplaced is recorded unenforced — the state \
         the guest's unplaced boxes share with the native host's"
    );

    // The guest's notice: the interim's words, the machine spelling of the
    // state, and no install command — there is no privileged step a person
    // can run inside the microVM the session is in.
    let notice = super::unenforced_placement_notice(true, None);
    assert!(
        notice.contains("guest-side classifier enforcement is not available yet"),
        "the notice names the interim, not a command: {notice}"
    );
    assert!(
        notice.contains("this host-address box runs unenforced"),
        "the notice says what the box does: {notice}"
    );
    assert!(
        notice.contains("host_ip_enforcement=none"),
        "the notice carries the machine spelling of the state: {notice}"
    );
    assert!(
        !notice.contains("sudo") && !notice.contains("install-host-classifier.sh"),
        "the guest's notice names no installer: {notice}"
    );
    // Whatever its leaf looks like: the guest's state is the table's
    // absence, never the leaf's, so the notice is one text.
    assert_eq!(
        super::unenforced_placement_notice(true, Some(&leaf)),
        notice,
        "the guest's notice is the interim's words whatever its leaf is"
    );
    // The native notice still names the step, in both of its own shapes.
    assert!(
        super::unenforced_placement_notice(false, None).contains("install-host-classifier.sh"),
        "an unplaced native box is told to install the step"
    );
    assert!(
        super::unenforced_placement_notice(false, Some(&leaf))
            .contains("install-host-classifier.sh"),
        "a placed native box on a host that cannot decide is told to \
         install the step too"
    );
}

/// The guest's refusal and its advisory never speak over each other: the
/// launch that is refused advises nobody, because the refusal is that
/// launch's whole answer and a record beside it would say the box runs when
/// it does not. Driven on the same tree-less host the refusal proof runs
/// on, for the two verdicts the guest can name — the deny-all box the
/// interim refuses, and the box carrying an egress section, which the
/// missing tree refuses for it here.
// `allow` rather than `expect` on purpose: this proof can skip, and on a host
// whose tree can place a child it returns before its first await, where an
// expectation the lint never meets would be its own warning.
#[allow(
    clippy::await_holding_lock,
    reason = "the guard spans the launches because each host-address one \
              re-reads the process-global classifier fact"
)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_guests_refused_host_address_box_is_refused_and_not_advised() {
    use sessions::NetworkMode;

    // The guest refusal test's skip, for the same reason read for this
    // proof: the assertions below measure a launch the guest *refuses*, so
    // they need a host whose tree cannot place one — on a delegated host
    // every guest host-address launch places and proceeds, and there is
    // nothing here to measure.
    if sandbox2::classifier::probe_child_placement(
        std::path::Path::new(sandbox2::classifier::TREE_ROOT),
        sandbox2::config::Verdict::Deny,
    )
    .is_ok()
    {
        eprintln!(
            "skipping a_guests_refused_host_address_box_is_refused_and_not_advised: \
             this daemon can place a child in its classifier tree, so a guest \
             host-address launch gets a leaf here and is not refused; the \
             silence of a refused launch is proved on a host with no \
             placeable tree"
        );
        return;
    }

    // The window the launches write the daemon's process-global classifier
    // fact in — every host-address launch re-reads it, refused or not —
    // taken for the whole proof, so under libtest no concurrent read
    // answers over the state they write.
    let _fact_window = super::PROBE_TEST_MUTEX
        .lock()
        .unwrap_or_else(|p| p.into_inner());

    let capture = crate::test_harness::captured_log();
    const REFUSALS: [&str; 2] = [
        "has no classifier tree to place a host-address box in",
        "has not loaded the classifier table",
    ];
    const RECORD: &str = "the session's host-address box runs unenforced on this host";
    let section = sessions::EgressPolicy {
        allow_subnets: Some(vec!["10.0.0.0/8".to_string()]),
        ..sessions::EgressPolicy::deny_all()
    };
    let state = tempfile::tempdir().expect("a state dir for the daemon's context");
    for (label, name, egress) in [
        (
            "a deny-all box",
            "guest-silent-proof-deny-all",
            sessions::EgressPolicy::deny_all(),
        ),
        (
            "a box carrying an egress section",
            "guest-silent-proof-section",
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
                // The guest: the one host that refuses what it cannot
                // decide a verdict for.
                true,
                sessions::SessionId::nil(),
                name.to_string(),
                "user".to_string(),
                test_paths(),
                DEFAULT_SIZE,
            ),
        )
        .await
        .expect("the launch decides within its timeout");
        match outcome {
            Err(refusal) => assert!(
                REFUSALS
                    .iter()
                    .any(|ground| refusal.to_string().contains(ground)),
                "{label} is refused on the classifier's ground, not: {refusal}"
            ),
            Ok(launched) => {
                drop(launched);
                panic!("{label} is refused by its guest, and was launched instead");
            }
        }
        let logged = capture.contents();
        assert!(
            !logged
                .lines()
                .any(|line| line.contains(RECORD) && line.contains(&format!("session={name}"))),
            "{label} is refused, and a refused box advises nobody, got: {logged}"
        );
    }
}

/// The guest's host-address boxes that *run* — placed in a real tree by an
/// image that has not loaded its table — say so at their own session start,
/// in the interim's words, and their deny-all sibling is refused on the same
/// host by the gate above.
///
/// No lane that builds this crate can produce that tree: the kernel alone
/// makes a cgroup's `cgroup.procs` appear at a `mkdir`, and over a stand-in
/// tree the placement probe fails on exactly that file by design (pinned in
/// sandbox2's own proof), so a launch-driven placed-guest box exists only on
/// a microVM image that built its tree and skipped its table. Rather than
/// skip on every lane, this proof runs the placed box's assertions where the
/// launch decides them, on every host: the outcome its placed leaf records,
/// the state the reads lower it to when the guest cannot decide per box and
/// the machine spelling the record and the pty banner carry, the gate that
/// refuses exactly the deny-all sibling with the interim's words, and the
/// state a host that decides per box has no advisory for. The halves that
/// need the tree itself stay with
/// the launches that run everywhere: the unplaced guest's refusal and
/// silence
/// (`a_guests_refused_host_address_box_is_refused_and_not_advised`) and the
/// `!for_hooks` fold driven through a real launch
/// (`a_hook_launch_does_not_advise_unenforced_placement`) — the fold is one
/// expression on either host, and the guest's launch goes through it by
/// construction.
#[test]
fn a_guests_placed_unenforced_host_address_box_advises_at_its_start() {
    use sandbox2::config::Verdict;
    use sessions::NetworkMode;

    // A placed leaf of a box that carries an egress section — the one the
    // interim lets run. Its directory is the shape the daemon's placement
    // creates; the mapping below reads only that the leaf is placed.
    let leaf = sandbox2::config::ClassifierLeaf::new(
        std::path::Path::new(sandbox2::classifier::TREE_ROOT)
            .join("boxes/allow/a-guests-placed-proof"),
    );
    let undecidable = crate::net::classifier::Decision::undecidable(
        crate::net::classifier::Cause::GuestTableNotLoaded,
    );

    // The state a guest without its table puts its placed boxes in: the
    // launch records the placement — `per_box`, the leaf is the outcome,
    // whatever the table is doing — and the reads lower it to the
    // unenforced state the table leaves the box in while it cannot decide,
    // never raise the placement to a verdict nothing is enforcing, so the
    // banner spells `none` and the advisory fires at every session start
    // of the box.
    let recorded = super::host_ip_enforcement(NetworkMode::HostNet, Some(&leaf));
    assert_eq!(
        recorded,
        Some(super::HostIpEnforcement::PerBox),
        "a box placed on a guest that has not loaded its table is recorded \
         by its placement — the leaf is the outcome, never the node fact \
         re-read beside it"
    );
    let shown = super::displayed_host_ip_enforcement(
        true,
        NetworkMode::HostNet,
        Verdict::Allow,
        &super::HostIpEnforcementFact {
            enforcement: super::HostIpEnforcement::None,
            cause: Some(crate::net::classifier::Cause::GuestTableNotLoaded),
        },
        recorded,
    );
    assert_eq!(
        shown,
        Some(super::HostIpEnforcement::None),
        "the reads lower the placed box's record to the state its host can \
         currently honour: unenforced, never `per_box` over a refusal that \
         is not there"
    );
    assert_eq!(
        shown.map(super::HostIpEnforcement::machine_str),
        Some("none"),
        "the record and the banner carry the state in the machine spelling"
    );
    assert!(
        super::advises_unenforced_placement(NetworkMode::HostNet, Some(&leaf), Some(&undecidable)),
        "the placed box's unenforced state is said at its own session start"
    );

    // Its deny-all sibling is refused on the same host — the interim
    // refuses exactly the box whose declaration promises a verdict — and a
    // refusal advises nobody: what reaches the advisory runs.
    let refusal = super::refused_unenforced_host_address_box(
        true,
        NetworkMode::HostNet,
        Verdict::Deny,
        true,
        Some(&undecidable),
    )
    .unwrap_or_else(|| {
        panic!("the guest refuses a placed deny-all box over a table it has not loaded")
    });
    assert!(
        refusal.contains("has not loaded the classifier table")
            && refusal.contains("guest-side classifier enforcement is not available yet"),
        "the refusal names the interim that produced it: {refusal}"
    );
    assert!(
        super::refused_unenforced_host_address_box(
            true,
            NetworkMode::HostNet,
            Verdict::Allow,
            true,
            Some(&undecidable),
        )
        .is_none(),
        "a box carrying an egress section promises no verdict, so the \
         interim lets it run: exactly the deny-all sibling is refused"
    );

    // The record's own text: the interim's words and the machine spelling,
    // and no installer — there is no privileged step to run inside the
    // microVM the session is in.
    let notice = super::unenforced_placement_notice(true, Some(&leaf));
    assert!(
        notice.contains("guest-side classifier enforcement is not available yet")
            && notice.contains("host_ip_enforcement=none")
            && !notice.contains("install-host-classifier.sh"),
        "the start-up record is the interim's words, not a command: {notice}"
    );

    // A host that decides per box has no unenforced state to say: its
    // boxes run enforced — the same record, shown as it stands — and the
    // advisory has nothing to fire for.
    let enforced = super::displayed_host_ip_enforcement(
        true,
        NetworkMode::HostNet,
        Verdict::Allow,
        &super::HostIpEnforcementFact {
            enforcement: super::HostIpEnforcement::PerBox,
            cause: None,
        },
        recorded,
    );
    assert_eq!(
        enforced,
        Some(super::HostIpEnforcement::PerBox),
        "a placed box on a host that decided per box runs enforced"
    );
    assert!(!super::advises_unenforced_placement(
        NetworkMode::HostNet,
        Some(&leaf),
        Some(&crate::net::classifier::Decision::decided())
    ));
}

// ---------------------------------------------------------------------------
// The runtime port-publish ask (NET-045) and the decision log (NET-046)
// ---------------------------------------------------------------------------

/// The state the ask tests' boxes publish at, mirroring the session tests'
/// dynamic-ingress boxes: an own-address box whose creator handed it the
/// address pair a publish needs, with the switch lease the publish rides.
const ASK_SWITCH: std::net::Ipv4Addr = std::net::Ipv4Addr::new(100, 64, 128, 21);
const ASK_LOOPBACK: std::net::Ipv4Addr = std::net::Ipv4Addr::new(127, 0, 64, 21);

/// Finalizes one dynamic-ingress box and returns its id alongside a handle to
/// its session actor, which is what a runtime port-publish request reaches.
async fn dynamic_ingress_box(
    server: &TestServer,
    client: &mut crate::test_harness::TestClient,
    name: &str,
    mode: Option<sessions::DynamicIngress>,
    range: Option<(u16, u16)>,
) -> (sessions::SessionId, crate::session::SessionHandle) {
    // The loopback verdict vouches for the handed address, so the registry
    // publishes the box at it — the address a runtime publish binds at.
    let manager = server.state.sessions_manager().await;
    manager.land_range_verdict(crate::net::dns::RangeVerdict::Present);
    let id =
        finalize_dynamic_ingress_session(client, name, ASK_SWITCH, ASK_LOOPBACK, mode, range).await;
    let handle = manager
        .get_session(crate::sessions::SessionKeyPredicate::Id(id))
        .await
        .unwrap()
        .unwrap_or_else(|| panic!("the {name} box should resolve"));
    (id, handle)
}

/// The daemon's local decision log (NET-046) as parsed records, in the order
/// the decisions were made. Only the decisions the test drove are there: a
/// harness server's state dir starts empty.
async fn audit_records(state_dir: &DaemonAbsPath) -> Vec<serde_json_lenient::Value> {
    let logged = tokio::fs::read_to_string(crate::audit::log_path(
        state_dir.as_utf8_path().as_std_path(),
    ))
    .await
    .expect("a decision should have been audited");
    logged
        .lines()
        .map(|line| {
            serde_json_lenient::from_str(line)
                .unwrap_or_else(|e| panic!("one audit line is one record: {e} in {logged}"))
        })
        .collect()
}

/// Reads the attached client's channel until the ask dialog renders, then
/// answers it the way the shell-exit prompt's tests do: a down-arrow off the
/// highlighted deny, then Enter. Returns everything the dialog rendered, so a
/// test can assert the lead-in named the box and the port.
async fn answer_ask_on(channel: &mut russh::Channel<russh::client::Msg>, accept: bool) -> Vec<u8> {
    let mut seen = Vec::new();
    let drained = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            match channel.wait().await {
                Some(russh::ChannelMsg::Data { data }) => {
                    seen.extend_from_slice(&data);
                    if String::from_utf8_lossy(&seen).contains(ASK_PROMPT) {
                        // Deny stands highlighted, so accepting moves once
                        // and confirms; denying — or refusing — confirms the
                        // highlighted deny as it is.
                        let keys = if accept {
                            b"\x1b[B\r".to_vec()
                        } else {
                            b"\r".to_vec()
                        };
                        channel.data_bytes(keys).await.unwrap();
                        return;
                    }
                }
                Some(_) => {}
                None => panic!("the channel closed before the ask dialog rendered"),
            }
        }
    })
    .await;
    assert!(
        drained.is_ok(),
        "the ask dialog never rendered: {}",
        String::from_utf8_lossy(&seen),
    );
    seen
}

/// Reads the attached client's channel until the ask dialog renders, and
/// leaves it standing: for a test that has to let the dialog sit there
/// before answering, which [`answer_ask_on`] has no patience for. Returns
/// everything the channel carried to that point, so a test can assert the
/// lead-in named the box and the port.
async fn await_ask_prompt(channel: &mut russh::Channel<russh::client::Msg>) -> Vec<u8> {
    let mut seen = Vec::new();
    let rendered = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            match channel.wait().await {
                Some(russh::ChannelMsg::Data { data }) => {
                    seen.extend_from_slice(&data);
                    if String::from_utf8_lossy(&seen).contains(ASK_PROMPT) {
                        return;
                    }
                }
                Some(_) => {}
                None => panic!("the channel closed before the ask dialog rendered"),
            }
        }
    })
    .await;
    assert!(
        rendered.is_ok(),
        "the ask dialog never rendered: {}",
        String::from_utf8_lossy(&seen),
    );
    seen
}

/// NET-045's deny half: a human who denies the publish is the box's own deny
/// answer in their hand — the request is refused with the typed deny error,
/// the switch is asked nothing, and the decision lands in the daemon log and
/// the audit record (NET-046) naming the human as the decider. The allow half
/// alone would let an implementation that ignored the answer pass.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn expose_ask_human_deny_refused() {
    let capture = captured_log();
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let (web, handle) = dynamic_ingress_box(
        &server,
        &mut client,
        "web",
        Some(sessions::DynamicIngress::Ask),
        Some((3000, 3999)),
    )
    .await;
    let sock = handle
        .net_switch()
        .await
        .unwrap()
        .lock()
        .await
        .control_socket();
    let (forwarder, served) = fake_forwarder(sock, 200).await;

    // Attach the human the ask will be routed to, and prove the binding is
    // live before asking: the mock shell's echo round-trips through it.
    let mut channel = client.open_shell(web).await;
    channel.data_bytes(b"hello\n".to_vec()).await.unwrap();
    let mut live = Vec::new();
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            match channel.wait().await {
                Some(russh::ChannelMsg::Data { data }) => {
                    live.extend_from_slice(&data);
                    if String::from_utf8_lossy(&live).contains("got:hello") {
                        return;
                    }
                }
                Some(_) => {}
                None => panic!("the channel closed before the shell came up"),
            }
        }
    })
    .await
    .expect("the attached shell should echo within the bound");

    // Ask off the test's own task: the reply waits on the human.
    let asked = tokio::spawn(async move { handle.expose_dynamic(3000).await });

    let rendered = answer_ask_on(&mut channel, false).await;
    let rendered = String::from_utf8_lossy(&rendered);
    assert!(
        rendered.contains("web asks to publish port 3000"),
        "the dialog's lead-in names the box and the port: {rendered}"
    );

    let refused = tokio::time::timeout(Duration::from_secs(30), asked)
        .await
        .expect("the ask should be answered once the human answers")
        .expect("the spawned request should not panic")
        .expect_err("the human's deny refuses the publish");
    match refused {
        crate::net::policy::ExposeFailure::Refused(
            crate::net::policy::ExposeRefusal::DeniedByPolicy,
        ) => {}
        other => panic!("the denial is the typed deny error: {other:?}"),
    }
    forwarder.abort();
    assert!(
        served.lock().expect("served lock").is_empty(),
        "a denied request asks the switch nothing: {:?}",
        served.lock().expect("served lock"),
    );

    // The prompt the human answered says its line, the answer says its own,
    // and the refusal is logged as the human's decision — not the daemon's
    // fail-closed one, which is what a dialog nobody answered would have
    // been.
    let log = capture.contents();
    assert!(
        log.contains("asking the attached client to allow a runtime port publish"),
        "the prompt the human saw says its line: {log}"
    );
    assert!(
        log.contains("the attached client answered the runtime port publish ask"),
        "the answer says its line: {log}"
    );
    assert!(
        log.contains("outcome=\"refused\"") && log.contains("decided_by=attached-human"),
        "the refusal is logged as the human's own decision: {log}"
    );

    // And the decision's own audit record (NET-046): the human decided it,
    // and it names the typed error the in-box caller read.
    let records = audit_records(&server.state.minimal_state_dir().await).await;
    assert_eq!(records.len(), 1, "one ask is one decision: {records:?}");
    assert_eq!(records[0]["box"], "web");
    assert_eq!(records[0]["port"], 3000);
    assert_eq!(records[0]["decision"], "ask");
    assert_eq!(
        records[0]["decided_by"], "attached-human",
        "the human's deny is the decision: {records:?}"
    );
    assert_eq!(records[0]["outcome"], "refused");
    assert_eq!(
        records[0]["reason"], "dynamic ingress is denied for this box",
        "the audit record carries the typed error the caller read: {records:?}"
    );
}

/// NET-045's slow half: taking the time to think must not cost the human
/// their attach. The dialog holds the binding off its own mailbox, so before
/// the dialog drained beside it, a session that printed more than the mailbox
/// holds while the human thought wedged the pty feed behind it — and the
/// stall bound shed the very client the dialog was waiting on, answering the
/// ask as the human's refusal. Here the bound is shortened, the session is
/// made to print throughout the dialog, and the human answers only after the
/// bound has passed: the attach survives, the answer is the one that
/// publishes, the output that printed arrives, and the decision is audited
/// as the human's publish (NET-046) — not as their refusal.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn expose_ask_answered_after_the_stall_bound_publishes() {
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let (web, handle) = dynamic_ingress_box(
        &server,
        &mut client,
        "web",
        Some(sessions::DynamicIngress::Ask),
        Some((3000, 3999)),
    )
    .await;
    let sock = handle
        .net_switch()
        .await
        .unwrap()
        .lock()
        .await
        .control_socket();
    let (forwarder, served) = fake_forwarder(sock, 200).await;

    // Attach the human the ask will be routed to, and prove the binding is
    // live before asking.
    let mut channel = client.open_shell(web).await;
    channel.data_bytes(b"hello\n".to_vec()).await.unwrap();
    let mut live = Vec::new();
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            match channel.wait().await {
                Some(russh::ChannelMsg::Data { data }) => {
                    live.extend_from_slice(&data);
                    if String::from_utf8_lossy(&live).contains("got:hello") {
                        return;
                    }
                }
                Some(_) => {}
                None => panic!("the channel closed before the shell came up"),
            }
        }
    })
    .await
    .expect("the attached shell should echo within the bound");

    // Shorten the stall bound on the live host, so the shed this test guards
    // against would fire in half a second rather than thirty.
    let host = handle
        .ensure_host("user".to_string())
        .await
        .expect("the attached box has a live host");
    host.set_output_stall_timeout(Duration::from_millis(500))
        .await;

    let asked = tokio::spawn(async move { handle.expose_dynamic(3000).await });

    // The dialog has to be up before the session starts printing, so the
    // printing lands inside it — where the binding used to stop draining.
    let rendered = await_ask_prompt(&mut channel).await;
    let rendered = String::from_utf8_lossy(&rendered);
    assert!(
        rendered.contains("web asks to publish port 3000"),
        "the dialog's lead-in names the box and the port: {rendered}"
    );

    // The session prints for the whole time the human is thinking — several
    // mailbox-loads, so a binding that stopped draining would have wedged
    // the pty feed behind it. Fed into the pty rather than the channel,
    // which is the point: the dialog holds the channel's reader.
    host.feed_stdin(format!("{}\n", "x".repeat(120)).repeat(2000).into_bytes())
        .await;

    // The human takes longer than the stall bound to answer.
    tokio::time::sleep(Duration::from_millis(1500)).await;

    // A shed here would have closed the channel; the keys go nowhere then, so
    // the ask's own answer below carries the assertion.
    #[expect(
        clippy::let_underscore_must_use,
        reason = "a shed binding may refuse the write; the ask's answer names the failure"
    )]
    let _ = channel.data_bytes(b"\x1b[B\r".to_vec()).await;
    let mapping = tokio::time::timeout(Duration::from_secs(30), asked)
        .await
        .expect("the ask should be answered once the human answers")
        .expect("the spawned request should not panic")
        .expect("the human's allow publishes the port");
    assert_eq!(
        mapping,
        minimald_rpc::LiveMapping {
            local: format!("{}:3000", ASK_LOOPBACK),
            internal_port: 3000,
            proto: sessions::IpProto::Tcp,
            pending: Some(false),
        },
        "the publish the human allowed is the one an allow box's takes"
    );
    forwarder.abort();
    {
        let served = served.lock().expect("served lock");
        assert_eq!(
            served.len(),
            1,
            "the allowed ask publishes exactly once: {served:?}"
        );
        assert!(
            served[0].starts_with("POST /services/forwarder/expose "),
            "the allowed ask rides the forwarder's expose verb: {served:?}"
        );
    }

    // The attach outlived the dialog. The output that printed while the
    // human thought arrives now that the terminal is the relay's again, and
    // the channel never sees the shed: no EOF, no shed exit status, no
    // close.
    let mut flushed = 0usize;
    let mut shed = None;
    let mut closed = false;
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match channel.wait().await {
                Some(russh::ChannelMsg::Data { data }) => {
                    flushed += data.len();
                    if flushed > 64 * 1024 {
                        return;
                    }
                }
                Some(russh::ChannelMsg::Eof) => shed = Some("eof".to_string()),
                Some(russh::ChannelMsg::ExitStatus { exit_status }) => {
                    shed = Some(format!("exit status {exit_status}"));
                }
                Some(russh::ChannelMsg::Close) => {
                    closed = true;
                    return;
                }
                Some(_) => {}
                None => {
                    closed = true;
                    return;
                }
            }
        }
    })
    .await
    .expect("the output that printed during the dialog should flush back");
    assert!(
        shed.is_none() && !closed,
        "the dialog must not cost the human their attach (shed: {shed:?}, closed: {closed})",
    );
    assert!(
        flushed > 64 * 1024,
        "the output that printed while the human thought reaches them: {flushed} bytes",
    );

    // And the decision is audited as the human's publish (NET-046) — not as
    // the refusal a shed would have answered it with.
    let records = audit_records(&server.state.minimal_state_dir().await).await;
    assert_eq!(records.len(), 1, "one ask is one decision: {records:?}");
    assert_eq!(records[0]["box"], "web");
    assert_eq!(records[0]["port"], 3000);
    assert_eq!(records[0]["decision"], "ask");
    assert_eq!(
        records[0]["decided_by"], "attached-human",
        "the human's late answer is the decision: {records:?}"
    );
    assert_eq!(records[0]["outcome"], "published");
    assert!(records[0].get("reason").is_none());
}

/// A dialog that ends without the human's answer is the daemon's refusal,
/// not the human's (the review thread on `Binding::run`): a binding shed
/// mid-dialog — its client stopped reading, so the host dropped it once the
/// stall bound passed — used to break the dialog loop with the default
/// [`Refused`](AskAnswer::Refused) answer and send that up as the human's
/// own, so the audit recorded `attached-human` for a denial no human made.
/// Here the stall bound is shortened, the dialog is left standing while the
/// session prints more than [`ASK_HELD_OUTPUT`] into the pty and the client
/// reads none of it, and the binding sheds mid-dialog: the ask ends with
/// the typed nobody-is-attached refusal, the switch is asked nothing, and
/// the decision is audited as the daemon's — because no human answered.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn expose_ask_shed_mid_dialog_is_the_daemons_refusal() {
    let capture = captured_log();
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let (web, handle) = dynamic_ingress_box(
        &server,
        &mut client,
        "web",
        Some(sessions::DynamicIngress::Ask),
        Some((3000, 3999)),
    )
    .await;
    let sock = handle
        .net_switch()
        .await
        .unwrap()
        .lock()
        .await
        .control_socket();
    let (forwarder, served) = fake_forwarder(sock, 200).await;

    // Attach the human the ask will be routed to, and prove the binding is
    // live before asking: the mock shell's echo round-trips through it.
    let mut channel = client.open_shell(web).await;
    channel.data_bytes(b"hello\n".to_vec()).await.unwrap();
    let mut live = Vec::new();
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            match channel.wait().await {
                Some(russh::ChannelMsg::Data { data }) => {
                    live.extend_from_slice(&data);
                    if String::from_utf8_lossy(&live).contains("got:hello") {
                        return;
                    }
                }
                Some(_) => {}
                None => panic!("the channel closed before the shell came up"),
            }
        }
    })
    .await
    .expect("the attached shell should echo within the bound");

    // Shorten the stall bound on the live host, so the shed this test drives
    // fires in half a second rather than thirty.
    let host = handle
        .ensure_host("user".to_string())
        .await
        .expect("the attached box has a live host");
    host.set_output_stall_timeout(Duration::from_millis(500))
        .await;

    // Ask off the test's own task: the reply waits on the human.
    let asked = tokio::spawn(async move { handle.expose_dynamic(3000).await });

    // The dialog has to be up before the client stops reading, so the shed
    // lands inside it.
    let rendered = await_ask_prompt(&mut channel).await;
    let rendered = String::from_utf8_lossy(&rendered);
    assert!(
        rendered.contains("web asks to publish port 3000"),
        "the dialog's lead-in names the box and the port: {rendered}"
    );

    // The client reads nothing from here on. The session prints more than
    // one dialog's held-output bound ([`ASK_HELD_OUTPUT`]) into the pty
    // while the human is nowhere, so the drain beside the dialog gives up,
    // the mailbox fills behind it, and the stall bound sheds the binding
    // with the dialog still standing.
    host.feed_stdin(format!("{}\n", "x".repeat(120)).repeat(30000).into_bytes())
        .await;

    // The ask ends with the daemon's typed nobody-is-attached refusal — not
    // the human's deny a shed used to answer with.
    let refused = tokio::time::timeout(Duration::from_secs(30), asked)
        .await
        .expect("a dialog its binding was shed from must end the ask, not park it")
        .expect("the spawned request should not panic")
        .expect_err("a shed mid-dialog fails the ask closed");
    match refused {
        crate::net::policy::ExposeFailure::Refused(
            crate::net::policy::ExposeRefusal::AskNeedsAnswer,
        ) => {}
        other => panic!("the shed's refusal is the typed nobody-is-attached error: {other:?}"),
    }
    forwarder.abort();
    assert!(
        served.lock().expect("served lock").is_empty(),
        "an ask nobody answered asks the switch nothing"
    );

    // The client's channel saw the shed itself — EOF, the shed exit status,
    // and a close — so the refusal above is the one a shed answers with,
    // not one a dialog that ended some other way produced.
    let (mut eof, mut exit_status, mut closed, mut drained) = (false, None, false, Vec::new());
    tokio::time::timeout(Duration::from_secs(30), async {
        while let Some(msg) = channel.wait().await {
            match msg {
                russh::ChannelMsg::Data { data } => drained.extend_from_slice(&data),
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
    .await
    .expect("the shed binding's channel should close within the bound");
    assert!(eof, "the channel must see EOF before it closes");
    assert_eq!(
        exit_status,
        Some(SHED_EXIT_STATUS),
        "a shed reports the status that has the client restore the terminal",
    );
    assert!(closed, "the channel should close after the shed");

    // The shed notice is the channel's last words, and it must survive the
    // write the shed dropped mid-send: russh's channel writer keeps an
    // interrupted write's state and would answer this shorter buffer with
    // the interrupted write's byte count — tokio's `write_all` panics past
    // the notice's end, the binding dies mid-epilogue, and the client hangs
    // on a channel that never closes. The flood above is what put a write
    // mid-send when the shed took it, so this is the proof the binding
    // leaves a usable writer in its place instead.
    let tail = String::from_utf8_lossy(&drained[drained.len().saturating_sub(400)..]);
    assert!(
        tail.contains("the terminal stopped keeping up with session output"),
        "the shed notice should still reach the client after the flood; \
         the channel's last bytes: {tail}"
    );

    // The prompt says its line, and the refusal is logged as the daemon's
    // fail-closed decision — not the human's, which is what a shed used to
    // be recorded as.
    let log = capture.contents();
    assert!(
        log.contains("asking the attached client to allow a runtime port publish"),
        "the prompt the human saw says its line: {log}"
    );
    assert!(
        log.contains("outcome=\"refused\"") && log.contains("decided_by=daemon"),
        "the refusal is logged as the daemon's fail-closed decision: {log}"
    );

    // And one audit record (NET-046) for the decision, naming the daemon as
    // the decider — because the human the dialog was for never answered.
    let records = audit_records(&server.state.minimal_state_dir().await).await;
    assert_eq!(records.len(), 1, "one ask is one decision: {records:?}");
    assert_eq!(records[0]["box"], "web");
    assert_eq!(records[0]["port"], 3000);
    assert_eq!(records[0]["decision"], "ask");
    assert_eq!(
        records[0]["decided_by"], "daemon",
        "a dialog nobody answered is the daemon's decision: {records:?}"
    );
    assert_eq!(records[0]["outcome"], "refused");
    assert_eq!(
        records[0]["reason"], "dynamic ingress is set to ask and nobody is attached to answer",
        "the audit record carries the typed error the caller read: {records:?}"
    );
}

/// The same rule for a teardown mid-dialog: a second client attaching
/// supersedes the binding whose dialog is standing, and the ask it was
/// holding is the daemon's refusal too — not the superseded human's deny,
/// which is what the ended dialog's default answer used to record it as.
/// The first channel sees its supersede farewell, the ask ends with the
/// typed nobody-is-attached refusal, the switch is asked nothing, and the
/// decision is audited as the daemon's (NET-046).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn expose_ask_superseded_mid_dialog_is_the_daemons_refusal() {
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let (web, handle) = dynamic_ingress_box(
        &server,
        &mut client,
        "web",
        Some(sessions::DynamicIngress::Ask),
        Some((3000, 3999)),
    )
    .await;
    let sock = handle
        .net_switch()
        .await
        .unwrap()
        .lock()
        .await
        .control_socket();
    let (forwarder, served) = fake_forwarder(sock, 200).await;

    // Attach the human the ask will be routed to, and prove the binding is
    // live before asking.
    let mut channel = client.open_shell(web).await;
    channel.data_bytes(b"hello\n".to_vec()).await.unwrap();
    let mut live = Vec::new();
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            match channel.wait().await {
                Some(russh::ChannelMsg::Data { data }) => {
                    live.extend_from_slice(&data);
                    if String::from_utf8_lossy(&live).contains("got:hello") {
                        return;
                    }
                }
                Some(_) => {}
                None => panic!("the channel closed before the shell came up"),
            }
        }
    })
    .await
    .expect("the attached shell should echo within the bound");

    // Ask off the test's own task: the reply waits on the human.
    let asked = tokio::spawn(async move { handle.expose_dynamic(3000).await });

    let rendered = await_ask_prompt(&mut channel).await;
    let rendered = String::from_utf8_lossy(&rendered);
    assert!(
        rendered.contains("web asks to publish port 3000"),
        "the dialog's lead-in names the box and the port: {rendered}"
    );

    // A second shell on the same box supersedes the first binding, with its
    // dialog still standing: the teardown it takes cannot wait for a human,
    // so the dialog ends unanswered and the ask ends with it.
    let mut second = client.open_shell(web).await;

    // The ask ends with the daemon's typed nobody-is-attached refusal — not
    // the human's deny the ended dialog's default answer used to send.
    let refused = tokio::time::timeout(Duration::from_secs(30), asked)
        .await
        .expect("a dialog its binding was superseded from must end the ask, not park it")
        .expect("the spawned request should not panic")
        .expect_err("a teardown mid-dialog fails the ask closed");
    match refused {
        crate::net::policy::ExposeFailure::Refused(
            crate::net::policy::ExposeRefusal::AskNeedsAnswer,
        ) => {}
        other => panic!("the supersede's refusal is the typed nobody-is-attached error: {other:?}"),
    }
    forwarder.abort();
    assert!(
        served.lock().expect("served lock").is_empty(),
        "an ask nobody answered asks the switch nothing"
    );

    // The first channel saw the supersede itself — its farewell and a close
    // — so the refusal above is the one a teardown mid-dialog answers with.
    let (mut superseded, mut closed) = (false, false);
    let mut seen = Vec::new();
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            match channel.wait().await {
                Some(russh::ChannelMsg::Data { data }) => {
                    seen.extend_from_slice(&data);
                    if String::from_utf8_lossy(&seen)
                        .contains("session attached to from a different connection")
                    {
                        superseded = true;
                    }
                }
                Some(_) => {}
                None => {
                    closed = true;
                    return;
                }
            }
        }
    })
    .await
    .expect("the superseded binding's channel should close within the bound");
    assert!(
        superseded,
        "the first client saw its supersede farewell: {}",
        String::from_utf8_lossy(&seen)
    );
    assert!(closed, "the channel should close after the supersede");

    // The second binding took the box over, and is live to prove it.
    second.data_bytes(b"still-here\n".to_vec()).await.unwrap();
    let mut echoed = Vec::new();
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            match second.wait().await {
                Some(russh::ChannelMsg::Data { data }) => {
                    echoed.extend_from_slice(&data);
                    if String::from_utf8_lossy(&echoed).contains("got:still-here") {
                        return;
                    }
                }
                Some(_) => {}
                None => panic!("the channel closed before the new shell echoed"),
            }
        }
    })
    .await
    .expect("the superseding client should hold a live shell");

    // And one audit record (NET-046) for the decision, naming the daemon as
    // the decider — no human answered, the dialog was torn down under them.
    let records = audit_records(&server.state.minimal_state_dir().await).await;
    assert_eq!(records.len(), 1, "one ask is one decision: {records:?}");
    assert_eq!(records[0]["box"], "web");
    assert_eq!(records[0]["port"], 3000);
    assert_eq!(records[0]["decision"], "ask");
    assert_eq!(
        records[0]["decided_by"], "daemon",
        "a dialog torn down mid-thought is the daemon's decision: {records:?}"
    );
    assert_eq!(records[0]["outcome"], "refused");
    assert_eq!(
        records[0]["reason"], "dynamic ingress is set to ask and nobody is attached to answer",
        "the audit record carries the typed error the caller read: {records:?}"
    );
}

/// A client that goes away mid-dialog is the daemon's refusal, not the
/// human's deny (the review thread on `ask_prompt`): `async-dialog` reports
/// an input EOF as the same `Selection::Cancelled` a keyed Ctrl-C produces,
/// and the arm that read both as the human's own deny recorded a denial no
/// human made. Under a raw `ssh -tt` tty no keystroke produces channel EOF,
/// so EOF means the connection or client went away — a terminal that can no
/// longer carry the dialog. Here the dialog is up and the client's channel
/// reaches EOF under it: the ask ends with the typed nobody-is-attached
/// refusal, the switch is asked nothing, and the decision is audited as the
/// daemon's, exactly one record for it — because no human answered. A keyed
/// cancel stays the human's own deny; [`expose_ask_human_deny_refused`]
/// proves that half.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn expose_ask_client_eof_mid_dialog_is_the_daemons_refusal() {
    let capture = captured_log();
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let (web, handle) = dynamic_ingress_box(
        &server,
        &mut client,
        "web",
        Some(sessions::DynamicIngress::Ask),
        Some((3000, 3999)),
    )
    .await;
    let sock = handle
        .net_switch()
        .await
        .unwrap()
        .lock()
        .await
        .control_socket();
    let (forwarder, served) = fake_forwarder(sock, 200).await;

    // Attach the human the ask will be routed to, and prove the binding is
    // live before asking: the mock shell's echo round-trips through it.
    let mut channel = client.open_shell(web).await;
    channel.data_bytes(b"hello\n".to_vec()).await.unwrap();
    let mut live = Vec::new();
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            match channel.wait().await {
                Some(russh::ChannelMsg::Data { data }) => {
                    live.extend_from_slice(&data);
                    if String::from_utf8_lossy(&live).contains("got:hello") {
                        return;
                    }
                }
                Some(_) => {}
                None => panic!("the channel closed before the shell came up"),
            }
        }
    })
    .await
    .expect("the attached shell should echo within the bound");

    // Ask off the test's own task: the reply waits on the human.
    let asked = tokio::spawn(async move { handle.expose_dynamic(3000).await });

    // The dialog has to be up before the client goes away, so the EOF lands
    // inside it.
    let rendered = await_ask_prompt(&mut channel).await;
    let rendered = String::from_utf8_lossy(&rendered);
    assert!(
        rendered.contains("web asks to publish port 3000"),
        "the dialog's lead-in names the box and the port: {rendered}"
    );

    // The client's channel reaches EOF with the dialog standing — what a
    // connection or client that went away looks like from the binding's side.
    channel.eof().await.unwrap();

    // The ask ends with the daemon's typed nobody-is-attached refusal — not
    // the human's deny an input EOF used to be answered with.
    let refused = tokio::time::timeout(Duration::from_secs(30), asked)
        .await
        .expect("a dialog whose client went away must end the ask, not park it")
        .expect("the spawned request should not panic")
        .expect_err("an input EOF mid-dialog fails the ask closed");
    match refused {
        crate::net::policy::ExposeFailure::Refused(
            crate::net::policy::ExposeRefusal::AskNeedsAnswer,
        ) => {}
        other => panic!("the EOF's refusal is the typed nobody-is-attached error: {other:?}"),
    }
    forwarder.abort();
    assert!(
        served.lock().expect("served lock").is_empty(),
        "an ask nobody answered asks the switch nothing"
    );

    // The prompt says its line, and the refusal is logged as the daemon's
    // fail-closed decision — not the human's, which is what an input EOF used
    // to be recorded as.
    let log = capture.contents();
    assert!(
        log.contains("asking the attached client to allow a runtime port publish"),
        "the prompt the human saw says its line: {log}"
    );
    assert!(
        log.contains("outcome=\"refused\"") && log.contains("decided_by=daemon"),
        "the refusal is logged as the daemon's fail-closed decision: {log}"
    );

    // And exactly one audit record (NET-046) for the decision, naming the
    // daemon as the decider — because the human the dialog was for never
    // answered.
    let records = audit_records(&server.state.minimal_state_dir().await).await;
    assert_eq!(records.len(), 1, "one ask is one decision: {records:?}");
    assert_eq!(records[0]["box"], "web");
    assert_eq!(records[0]["port"], 3000);
    assert_eq!(records[0]["decision"], "ask");
    assert_eq!(
        records[0]["decided_by"], "daemon",
        "a dialog whose client went away is the daemon's decision: {records:?}"
    );
    assert_eq!(records[0]["outcome"], "refused");
    assert_eq!(
        records[0]["reason"], "dynamic ingress is set to ask and nobody is attached to answer",
        "the audit record carries the typed error the caller read: {records:?}"
    );
}

/// NET-045's no-client case against a live host: the box is up and detached
/// (NET-015), so the refusal has to come from the host that has nobody
/// attached rather than the no-host shortcut. Attaches, detaches, asks — the
/// typed nobody-is-attached refusal, the switch asked nothing, the
/// daemon-decided audit record (NET-046) — and the box still alive to take
/// another attach afterwards.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn expose_ask_after_detaching_is_refused_by_the_live_host() {
    let capture = captured_log();
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let (web, handle) = dynamic_ingress_box(
        &server,
        &mut client,
        "web",
        Some(sessions::DynamicIngress::Ask),
        Some((3000, 3999)),
    )
    .await;
    let sock = handle
        .net_switch()
        .await
        .unwrap()
        .lock()
        .await
        .control_socket();
    let (forwarder, served) = fake_forwarder(sock, 200).await;

    // Attach, prove the shell is live through the binding, then detach: the
    // box stays up with nobody bound to it.
    let mut channel = client.open_shell(web).await;
    channel.data_bytes(b"hello\n".to_vec()).await.unwrap();
    let mut live = Vec::new();
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            match channel.wait().await {
                Some(russh::ChannelMsg::Data { data }) => {
                    live.extend_from_slice(&data);
                    if String::from_utf8_lossy(&live).contains("got:hello") {
                        return;
                    }
                }
                Some(_) => {}
                None => panic!("the channel closed before the shell came up"),
            }
        }
    })
    .await
    .expect("the attached shell should echo within the bound");
    channel.data_bytes(vec![0x1d]).await.unwrap();
    channel.data_bytes(vec![b'd']).await.unwrap();
    let mut detached = Vec::new();
    let mut closed = false;
    while let Ok(msg) = tokio::time::timeout(Duration::from_secs(5), channel.wait()).await {
        match msg {
            Some(russh::ChannelMsg::Data { data }) => detached.extend_from_slice(&data),
            Some(_) => {}
            None => {
                closed = true;
                break;
            }
        }
    }
    let detached = String::from_utf8_lossy(&detached);
    assert!(
        detached.contains("Detaching from session."),
        "the detach says its line: {detached:?}"
    );
    assert!(closed, "the channel should close after the detach chord");

    // The host is live — asserted, not presumed, because a dead host would
    // take the session's no-host shortcut and answer the same words from a
    // different place, and this test exists to pin the live one. The probe
    // goes through the session to the running host, and `Some` answers only
    // from a live host.
    tokio::time::timeout(Duration::from_secs(5), handle.get_attrs())
        .await
        .expect("the detached box's host probe should answer within its own bound")
        .expect("the host that served the detach is still live, nobody attached to it");

    // The host is live and nobody is attached: the ask must be refused with
    // the typed nobody-is-attached error, not parked and not a plain
    // "no session" answer.
    let refused = tokio::time::timeout(Duration::from_secs(30), handle.expose_dynamic(3000))
        .await
        .expect("an ask nobody can answer must be refused, not parked")
        .expect_err("nobody being attached fails the ask closed");
    match refused {
        crate::net::policy::ExposeFailure::Refused(
            crate::net::policy::ExposeRefusal::AskNeedsAnswer,
        ) => {}
        other => panic!("the refusal is the typed nobody-is-attached error: {other:?}"),
    }
    forwarder.abort();
    assert!(
        served.lock().expect("served lock").is_empty(),
        "a refused request asks the switch nothing"
    );

    // Both halves in the daemon log, with the typed reason the in-box caller
    // read.
    let log = capture.contents();
    assert!(
        log.contains("dynamic ingress is set to ask and nobody is attached to answer"),
        "the refusal names why, with the typed error's own words: {log}"
    );
    assert!(
        log.contains("outcome=\"refused\"") && log.contains("decided_by=daemon"),
        "the refusal is logged as the daemon's fail-closed decision: {log}"
    );
    // And the refusal came from the live host's own nobody-attached branch —
    // the plan's one info line per refusal for want of a client, naming the
    // box and the port — which the session's no-host shortcut never says,
    // so this line is what tells the two apart.
    let refusing = log
        .lines()
        .find(|line| {
            line.contains("refusing the runtime port publish ask for want of a client to answer it")
        })
        .unwrap_or_else(|| panic!("the live host that refused the ask should say its line: {log}"));
    assert!(
        refusing.contains("session=web") && refusing.contains("port=3000"),
        "the refusal names the box and the port it was about: {refusing}"
    );

    // And the decision is audited (NET-046): the daemon decided it, because
    // no human was there to.
    let records = audit_records(&server.state.minimal_state_dir().await).await;
    assert_eq!(records.len(), 1, "one request is one decision: {records:?}");
    assert_eq!(records[0]["box"], "web");
    assert_eq!(records[0]["port"], 3000);
    assert_eq!(records[0]["decision"], "ask");
    assert_eq!(records[0]["decided_by"], "daemon");
    assert_eq!(records[0]["outcome"], "refused");
    assert_eq!(
        records[0]["reason"], "dynamic ingress is set to ask and nobody is attached to answer",
        "the audit record carries the typed error the caller read: {records:?}"
    );

    // The box outlived its detached ask (NET-015): it takes another attach
    // and echoes through it.
    let mut again = client.open_shell(web).await;
    again.data_bytes(b"still-here\n".to_vec()).await.unwrap();
    let mut echoed = Vec::new();
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            match again.wait().await {
                Some(russh::ChannelMsg::Data { data }) => {
                    echoed.extend_from_slice(&data);
                    if String::from_utf8_lossy(&echoed).contains("got:still-here") {
                        return;
                    }
                }
                Some(_) => {}
                None => panic!("the channel closed before the reattached shell echoed"),
            }
        }
    })
    .await
    .expect("the detached box should still be alive to reattach to");
}

/// NET-045's ordering: two asks can share a port, and each answer must reach
/// the ask it answers. Keyed by port alone, an answer popped whichever ask
/// parked on that port first — so a fail-closed answer for an ask whose
/// hand-off failed refused a *different* ask while its dialog was still on
/// screen, and the human's answer for that one then published for the ask
/// that had already failed. Here two asks park on one port, the second's
/// continuation arrives first as the answer nobody was attached to give, and
/// then the human answers the dialog that is still standing: the second's
/// caller is refused, the first's publish, each audited as its own decision
/// (NET-046) — and the late real answer for the ended ask reaches no asker
/// and fabricates no third decision.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn expose_ask_answers_reach_their_own_ask_on_a_shared_port() {
    let capture = captured_log();
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let (web, handle) = dynamic_ingress_box(
        &server,
        &mut client,
        "web",
        Some(sessions::DynamicIngress::Ask),
        Some((3000, 3999)),
    )
    .await;
    let sock = handle
        .net_switch()
        .await
        .unwrap()
        .lock()
        .await
        .control_socket();
    let (forwarder, served) = fake_forwarder(sock, 200).await;

    // Attach the human both asks will be routed to.
    let mut channel = client.open_shell(web).await;
    channel.data_bytes(b"hello\n".to_vec()).await.unwrap();
    let mut live = Vec::new();
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            match channel.wait().await {
                Some(russh::ChannelMsg::Data { data }) => {
                    live.extend_from_slice(&data);
                    if String::from_utf8_lossy(&live).contains("got:hello") {
                        return;
                    }
                }
                Some(_) => {}
                None => panic!("the channel closed before the shell came up"),
            }
        }
    })
    .await
    .expect("the attached shell should echo within the bound");

    // Two asks for the same port, parked one at a time — the first's dialog
    // confirmed standing before the second is even sent, so the parked
    // book's order and the binding's dialog order are the same order, and
    // the ids below say whose caller they are.
    let asked_first = tokio::spawn({
        let handle = handle.clone();
        async move { handle.expose_dynamic(3000).await }
    });
    let first_parked = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let parked = handle.pending_ask_ids().await;
            if parked.len() == 1 {
                return parked;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the first ask on the shared port should park");
    let [(first, first_port)] = first_parked
        .try_into()
        .expect("exactly one ask parks first");
    assert_eq!(first_port, 3000, "the first ask is for the shared port");

    let rendered = await_ask_prompt(&mut channel).await;
    let rendered = String::from_utf8_lossy(&rendered);
    assert!(
        rendered.contains("web asks to publish port 3000"),
        "the first dialog's lead-in names the box and the port: {rendered}"
    );

    let asked_second = tokio::spawn({
        let handle = handle.clone();
        async move { handle.expose_dynamic(3000).await }
    });
    let parked = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let parked = handle.pending_ask_ids().await;
            if parked.len() == 2 {
                return parked;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("both asks on the shared port should park");
    let (second, second_port) = parked
        .last()
        .copied()
        .expect("the second ask parks beside the first");
    assert_eq!(
        second_port, 3000,
        "the second ask is for the shared port too"
    );
    assert_ne!(
        first, second,
        "two asks on one port park under their own keys"
    );

    // The second ask's continuation arrives as the answer nobody was
    // attached to give — the shape a failed hand-off comes back in — while
    // the first ask's dialog is still standing on the human's screen.
    // Delivered through the same handle the routed task delivers through, so
    // the interleaving production can race over is the only thing forged
    // here.
    handle.ask_answered(second, 3000, None).await;

    let refused = tokio::time::timeout(Duration::from_secs(30), asked_second)
        .await
        .expect("the ask whose hand-off failed should be refused, not parked")
        .expect("the spawned request should not panic")
        .expect_err("the failed hand-off fails the second ask closed");
    match refused {
        crate::net::policy::ExposeFailure::Refused(
            crate::net::policy::ExposeRefusal::AskNeedsAnswer,
        ) => {}
        other => {
            panic!("the second ask's refusal is the typed nobody-is-attached error: {other:?}")
        }
    }
    let still_parked = handle.pending_ask_ids().await;
    assert_eq!(
        still_parked,
        vec![(first, 3000)],
        "the fail-closed answer must not have popped the ask whose dialog is still up: {still_parked:?}",
    );

    // The human answers the dialog that is still standing — the first ask's,
    // its rendering confirmed before the second was even sent — so that
    // answer belongs to the first ask, and only to it. The prompt is already
    // on screen, so the keys go straight to it.
    channel.data_bytes(b"\x1b[B\r".to_vec()).await.unwrap();
    let mapping = tokio::time::timeout(Duration::from_secs(30), asked_first)
        .await
        .expect("the ask whose dialog was answered should publish, not park")
        .expect("the spawned request should not panic")
        .expect("the human's allow publishes the port their dialog was for");
    assert_eq!(
        mapping,
        minimald_rpc::LiveMapping {
            local: format!("{}:3000", ASK_LOOPBACK),
            internal_port: 3000,
            proto: sessions::IpProto::Tcp,
            pending: Some(false),
        },
        "the publish is the one an allow box's request takes"
    );
    forwarder.abort();
    {
        let served = served.lock().expect("served lock");
        assert_eq!(
            served.len(),
            1,
            "only the answered ask publishes: {served:?}"
        );
        assert!(
            served[0].starts_with("POST /services/forwarder/expose "),
            "the answered ask rides the forwarder's expose verb: {served:?}"
        );
    }

    // One decision per ask, each its own: the daemon's fail-closed refusal
    // for the ask whose hand-off failed, then the human's publish for the ask
    // they answered.
    let records = audit_records(&server.state.minimal_state_dir().await).await;
    assert_eq!(records.len(), 2, "two asks are two decisions: {records:?}");
    assert_eq!(records[0]["box"], "web");
    assert_eq!(records[0]["port"], 3000);
    assert_eq!(records[0]["decision"], "ask");
    assert_eq!(records[0]["decided_by"], "daemon");
    assert_eq!(records[0]["outcome"], "refused");
    assert_eq!(
        records[0]["reason"], "dynamic ingress is set to ask and nobody is attached to answer",
        "the failed hand-off carries the typed error its caller read: {records:?}"
    );
    assert_eq!(records[1]["box"], "web");
    assert_eq!(records[1]["port"], 3000);
    assert_eq!(records[1]["decision"], "ask");
    assert_eq!(records[1]["decided_by"], "attached-human");
    assert_eq!(records[1]["outcome"], "published");
    assert!(records[1].get("reason").is_none());

    // The binding still renders the dialog for the ask that already ended.
    // The dialog answered above redraws its own prompt on the way out, so
    // the lead-in — not the prompt line — is what says a fresh one is
    // standing. Answering it must reach no asker and fabricate no third
    // decision.
    tokio::time::timeout(Duration::from_secs(30), async {
        let mut seen = Vec::new();
        loop {
            match channel.wait().await {
                Some(russh::ChannelMsg::Data { data }) => {
                    seen.extend_from_slice(&data);
                    if String::from_utf8_lossy(&seen).contains("web asks to publish port 3000") {
                        return;
                    }
                }
                Some(_) => {}
                None => panic!("the channel closed before the ended ask's dialog rendered"),
            }
        }
    })
    .await
    .expect("the ended ask's dialog should render too");
    channel.data_bytes(b"\r".to_vec()).await.unwrap();
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if capture
                .contents()
                .contains("a runtime port-publish answer arrived with no ask waiting for it")
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the late answer for the ended ask should say its line");
    let records = audit_records(&server.state.minimal_state_dir().await).await;
    assert_eq!(
        records.len(),
        2,
        "a late answer for an ended ask fabricates no decision: {records:?}"
    );
}

/// NET-045: a runtime port-publish request a box decided `ask` reaches the
/// human attached to it — the dialog renders on their terminal with the box
/// and the port named — and the answer they give is the answer the request
/// gets: an allow publishes, and the publish that follows is the one an
/// `allow` box's request takes. The prompt says its own line in the daemon
/// log, and the decision it produced lands in the local audit log (NET-046)
/// naming who decided it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn expose_ask_prompts_attached_human() {
    let capture = captured_log();
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let (web, handle) = dynamic_ingress_box(
        &server,
        &mut client,
        "web",
        Some(sessions::DynamicIngress::Ask),
        Some((3000, 3999)),
    )
    .await;
    let sock = handle
        .net_switch()
        .await
        .unwrap()
        .lock()
        .await
        .control_socket();
    let (forwarder, served) = fake_forwarder(sock, 200).await;

    // Attach the human the ask will be routed to, and prove the binding is
    // live before asking: the mock shell's echo round-trips through it.
    let mut channel = client.open_shell(web).await;
    channel.data_bytes(b"hello\n".to_vec()).await.unwrap();
    let mut live = Vec::new();
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            match channel.wait().await {
                Some(russh::ChannelMsg::Data { data }) => {
                    live.extend_from_slice(&data);
                    if String::from_utf8_lossy(&live).contains("got:hello") {
                        return;
                    }
                }
                Some(_) => {}
                None => panic!("the channel closed before the shell came up"),
            }
        }
    })
    .await
    .expect("the attached shell should echo within the bound");

    // Ask off the test's own task: the reply waits on the human.
    let asked = tokio::spawn(async move { handle.expose_dynamic(3000).await });

    let rendered = answer_ask_on(&mut channel, true).await;
    let rendered = String::from_utf8_lossy(&rendered);
    assert!(
        rendered.contains("web asks to publish port 3000"),
        "the dialog's lead-in names the box and the port: {rendered}"
    );

    let mapping = tokio::time::timeout(Duration::from_secs(30), asked)
        .await
        .expect("the ask should be answered once the human answers")
        .expect("the spawned request should not panic")
        .expect("the human's allow publishes the port");
    assert_eq!(
        mapping,
        minimald_rpc::LiveMapping {
            local: format!("{}:3000", ASK_LOOPBACK),
            internal_port: 3000,
            proto: sessions::IpProto::Tcp,
            pending: Some(false),
        },
        "the publish the human allowed is the one an allow box's takes"
    );
    forwarder.abort();
    {
        let served = served.lock().expect("served lock");
        assert_eq!(
            served.len(),
            1,
            "the allowed ask publishes exactly once: {served:?}"
        );
        assert!(
            served[0].starts_with("POST /services/forwarder/expose "),
            "the allowed ask rides the forwarder's expose verb: {served:?}"
        );
    }

    // One line for the prompt, and the decision's own line, in the daemon log
    // the diagnostics bundle ships.
    let log = capture.contents();
    assert!(
        log.contains("asking the attached client to allow a runtime port publish"),
        "the prompt the human saw says its line: {log}"
    );
    assert!(
        log.contains("the attached client answered the runtime port publish ask"),
        "the answer says its line: {log}"
    );

    // And one audit record for the decision, naming who made it (NET-046).
    let records = audit_records(&server.state.minimal_state_dir().await).await;
    assert_eq!(records.len(), 1, "one ask is one decision: {records:?}");
    assert_eq!(records[0]["box"], "web");
    assert_eq!(records[0]["port"], 3000);
    assert_eq!(records[0]["decision"], "ask");
    assert_eq!(
        records[0]["decided_by"], "attached-human",
        "the human's answer is the decision: {records:?}"
    );
    assert_eq!(records[0]["outcome"], "published");
    assert!(records[0].get("reason").is_none());
}

/// NET-045's unwanted branch: a box decided `ask` with nobody attached — no
/// client ever bound, so no human to render the dialog to — is refused with
/// the typed error that says nobody is attached to answer, the switch is
/// asked nothing at all, and both facts land in the log and the audit record
/// like every other decision (NET-046).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn expose_ask_without_client_refused() {
    let capture = captured_log();
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let (_web, handle) = dynamic_ingress_box(
        &server,
        &mut client,
        "web",
        Some(sessions::DynamicIngress::Ask),
        Some((3000, 3999)),
    )
    .await;
    let sock = handle
        .net_switch()
        .await
        .unwrap()
        .lock()
        .await
        .control_socket();
    let (forwarder, served) = fake_forwarder(sock, 200).await;

    // Nobody ever attaches: no binding to render the dialog, and the request
    // is refused rather than parked on a human who is not there.
    let refused = tokio::time::timeout(Duration::from_secs(30), handle.expose_dynamic(3000))
        .await
        .expect("an ask nobody can answer must be refused, not parked")
        .expect_err("nobody being attached fails the ask closed");
    match refused {
        crate::net::policy::ExposeFailure::Refused(
            crate::net::policy::ExposeRefusal::AskNeedsAnswer,
        ) => {}
        other => panic!("the refusal is the typed nobody-is-attached error: {other:?}"),
    }
    forwarder.abort();
    assert!(
        served.lock().expect("served lock").is_empty(),
        "a refused request asks the switch nothing"
    );

    // The refusal for want of a client says its line, carrying the typed
    // reason the in-box caller read.
    let log = capture.contents();
    assert!(
        log.contains("dynamic ingress is set to ask and nobody is attached to answer"),
        "the refusal names why, with the typed error's own words: {log}"
    );
    assert!(
        log.contains("outcome=\"refused\"") && log.contains("decided_by=daemon"),
        "the refusal is logged as the daemon's fail-closed decision: {log}"
    );

    // And the decision is audited (NET-046): the daemon decided it, because
    // there was no human to.
    let records = audit_records(&server.state.minimal_state_dir().await).await;
    assert_eq!(records.len(), 1, "one request is one decision: {records:?}");
    assert_eq!(records[0]["box"], "web");
    assert_eq!(records[0]["port"], 3000);
    assert_eq!(records[0]["decision"], "ask");
    assert_eq!(records[0]["decided_by"], "daemon");
    assert_eq!(records[0]["outcome"], "refused");
    assert_eq!(
        records[0]["reason"], "dynamic ingress is set to ask and nobody is attached to answer",
        "the audit record carries the typed error the caller read: {records:?}"
    );
}

/// NET-046: on the un-enrolled host, every dynamic ingress decision lands in
/// the local audit log — the publish an allowing box made and the refusal the
/// deny-all default answered an un-enrolled box with alike — each as one
/// parseable record naming the box, the port, the decision, who decided it,
/// and the outcome, so the log reads without the session it was about.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn expose_unenrolled_decision_audited() {
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let (_web, web_handle) = dynamic_ingress_box(
        &server,
        &mut client,
        "web",
        Some(sessions::DynamicIngress::Allow),
        Some((3000, 3999)),
    )
    .await;
    let (_db, db_handle) = dynamic_ingress_box(
        &server,
        &mut client,
        "db",
        // Declared nothing: the deny-all default the un-enrolled box runs
        // under, which is what "un-enrolled" means for a decision's sake.
        None,
        None,
    )
    .await;
    // A publish needs a box running behind it (NET-047's stopped-box
    // refusal), so the allowing box launches its host first.
    web_handle
        .ensure_host("tester".to_string())
        .await
        .expect("the allowing box launches its host");
    let sock = web_handle
        .net_switch()
        .await
        .unwrap()
        .lock()
        .await
        .control_socket();
    let (forwarder, _served) = fake_forwarder(sock, 200).await;

    web_handle
        .expose_dynamic(3000)
        .await
        .expect("the allowing box publishes");
    match db_handle.expose_dynamic(3000).await {
        Err(crate::net::policy::ExposeFailure::Refused(
            crate::net::policy::ExposeRefusal::DeniedByPolicy,
        )) => {}
        other => panic!("the deny-all default refuses the request: {other:?}"),
    }
    forwarder.abort();

    let records = audit_records(&server.state.minimal_state_dir().await).await;
    assert_eq!(records.len(), 2, "each decision is one record: {records:?}");
    assert_eq!(records[0]["box"], "web");
    assert_eq!(records[0]["port"], 3000);
    assert_eq!(records[0]["decision"], "allow");
    assert_eq!(records[0]["decided_by"], "box-policy");
    assert_eq!(records[0]["outcome"], "published");
    assert!(
        records[0].get("reason").is_none(),
        "a publish has no refusal to name: {records:?}"
    );
    assert_eq!(records[1]["box"], "db");
    assert_eq!(records[1]["port"], 3000);
    assert_eq!(records[1]["decision"], "deny");
    assert_eq!(records[1]["decided_by"], "box-policy");
    assert_eq!(records[1]["outcome"], "refused");
    assert_eq!(
        records[1]["reason"], "dynamic ingress is denied for this box",
        "the refusal carries the typed error's own words: {records:?}"
    );
}

/// The host-level half of NET-045's no-client case: an ask reaching a host
/// nobody is bound to answers no-one rather than parking — the dialog has no
/// terminal to render on — which is the fail-closed answer the session turns
/// into the typed nobody-is-attached refusal.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ask_expose_without_a_binding_answers_no_one() {
    let (host, handle) = Host::build(
        MockLauncher::default(),
        HostParams {
            name: "test-session".to_string(),
            username: "user".to_string(),
            paths: test_paths(),
            sz: DEFAULT_SIZE,
            // No channel and no binding: the host is up, but nobody is
            // attached to it.
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

    let answer = tokio::time::timeout(Duration::from_secs(5), handle.ask_expose(3000))
        .await
        .expect("an ask with nobody attached must answer, not park on a dialog nobody can see");
    assert_eq!(
        answer, None,
        "no binding means nobody is attached to answer the ask"
    );

    // Teardown of the host this test minted. Best-effort both ways: the kill
    // of a host that is fine, and a join that a wedged loop would outrun.
    #[expect(
        clippy::let_underscore_must_use,
        reason = "the host this test minted is not the fact under test; a kill that lands is enough"
    )]
    let _ = handle.kill(false).await;
    #[expect(
        clippy::let_underscore_must_use,
        reason = "the ask already answered is the fact; the loop may outlive the test's bound"
    )]
    let _ = tokio::time::timeout(Duration::from_secs(10), task).await;
}
