use std::time::Duration;

use russh::ChannelMsg;
use sessions::SessionId;

use minimald_rpc::{GetSessionRecord, GetSessionRecordRequest};

use crate::session_host::{HOST_MAILBOX_CAPACITY, HostHandle};
use crate::test_harness::{TestClient, TestServer, create_configured_session};

/// Far longer than [`super::HOST_PROBE_TIMEOUT`], so under a paused
/// clock the probe's own deadline is always the one that fires first.
/// Reaching *this* one means the probe had no deadline at all.
const GIVE_UP: Duration = Duration::from_secs(600);

/// A probe of a host that never answers has to end on its own deadline.
///
/// The session actor forwards `GetHostAttrs`/`GetHostScreen` to a spawned
/// task so the actor stays responsive, but nothing cancels that task:
/// dropping the caller's receiver does not stop a spawned future. Left
/// unbounded, every poll of a wedged host stranded one task forever — and
/// `min dash` polls the focused session on every refresh tick, so the
/// leak is unbounded in exactly the case the timeout exists for.
///
/// Probes well past the mailbox capacity, which covers both places the
/// probe can park: the first `HOST_MAILBOX_CAPACITY` block awaiting a
/// reply that never comes, and the rest block trying to queue at all.
#[tokio::test(start_paused = true)]
async fn a_probe_of_a_wedged_host_ends_instead_of_stranding_its_task() {
    // Holding the mailbox is what makes the host wedged: messages are
    // accepted and none is ever answered.
    let (host, _mailbox) = HostHandle::wedged();
    let alive_before = tokio::runtime::Handle::current()
        .metrics()
        .num_alive_tasks();

    let probes: Vec<_> = (0..3 * HOST_MAILBOX_CAPACITY)
        .map(|_| {
            let host = host.clone();
            tokio::spawn(async move { super::probe_host(host.get_attrs()).await })
        })
        .collect();

    for (i, probe) in probes.into_iter().enumerate() {
        let attrs = tokio::time::timeout(GIVE_UP, probe)
            .await
            .unwrap_or_else(|_| panic!("probe {i} never finished: the await is unbounded"))
            .expect("the probe task should not panic");
        assert!(
            attrs.is_none(),
            "probe {i} of a host that never answers should report no attrs",
        );
    }

    assert_eq!(
        tokio::runtime::Handle::current()
            .metrics()
            .num_alive_tasks(),
        alive_before,
        "every probe task should be gone, not merely abandoned",
    );
}

/// The bounded stop path gives up on a host whose loop accepted the kill
/// but never winds down, detaching the loop task instead of awaiting it
/// forever.
///
/// This is the shape `HostHandle::kill`'s `send_timeout` alone cannot
/// cover: the mailbox has room, so the kill enqueues (`kill` returns
/// `Ok`) and the `!killed` short-circuit does not fire, yet the runtime
/// loop is parked mid-`step()` and never processes the queued kill. The
/// *join* bound — not the kill's own deadline — is what has to return the
/// caller. The task is detached rather than aborted so the `NetGuard`
/// teardown at the end of `mainloop` can still run once the loop drains.
/// `kill_to_a_wedged_host_gives_up_instead_of_parking` covers the
/// saturated-mailbox sibling, where the kill itself times out and the
/// task is aborted.
#[tokio::test(start_paused = true)]
async fn stopping_a_wedged_host_detaches_its_loop_instead_of_parking() {
    // Mailbox held but not saturated: the kill enqueues within its
    // deadline, so the join bound is the branch under test.
    let (host, _mailbox) = HostHandle::wedged();

    // A loop that accepted the kill but never resolves — models the
    // mainloop parked mid-`step()`.
    let mut task = tokio::spawn(std::future::pending::<Result<i32, std::io::Error>>());

    // Far past HOST_PROBE_TIMEOUT: under the paused clock the join bound is
    // the deadline that returns this call. Reaching GIVE_UP would mean the
    // wait was unbounded.
    tokio::time::timeout(
        GIVE_UP,
        super::Session::kill_and_stop_loop(&host, &mut task, true),
    )
    .await
    .expect("the bounded stop path must return, not park on a wedged loop");

    // The loop task is detached, not aborted: awaiting it would park
    // forever (it is `pending()`), but the handle is still valid — the
    // task was not cancelled.
    assert!(
        !task.is_finished(),
        "a loop whose kill landed must be detached, not aborted"
    );
}

/// The `AcceptEnv` allowlist keeps locale + timezone vars and drops
/// everything else — critically the control-plane vars, which must never
/// reach the shell environment.
#[test]
fn inherited_session_env_keeps_only_locale_and_tz() {
    let env: std::collections::BTreeMap<String, String> = [
        ("LANG", "en_US.UTF-8"),
        ("LC_CTYPE", "en_US.UTF-8"),
        ("LC_ALL", "C"),
        ("TZ", "America/New_York"),
        ("MINIMAL_SESSION_ID", "00000000-0000-0000-0000-000000000000"),
        ("TRACEPARENT", "00-abc-def-01"),
        ("PATH", "/evil/bin"),
        ("PS1", "# "),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect();

    let kept: std::collections::BTreeMap<String, String> =
        super::inherited_session_env(&env).into_iter().collect();

    assert_eq!(kept.get("LANG").map(String::as_str), Some("en_US.UTF-8"));
    assert_eq!(
        kept.get("LC_CTYPE").map(String::as_str),
        Some("en_US.UTF-8")
    );
    assert_eq!(kept.get("LC_ALL").map(String::as_str), Some("C"));
    assert_eq!(kept.get("TZ").map(String::as_str), Some("America/New_York"));
    // Control-plane routing/tracing vars and everything else must be dropped.
    assert!(!kept.contains_key("MINIMAL_SESSION_ID"));
    assert!(!kept.contains_key("TRACEPARENT"));
    assert!(!kept.contains_key("PATH"));
    assert!(!kept.contains_key("PS1"));
    assert_eq!(kept.len(), 4, "only LANG, LC_*, and TZ should survive");
}

/// A `LC_`-*prefixed* var is accepted, but a bare `LC` (or one that merely
/// contains `LC_`) is not — the filter is a prefix match, not a substring.
#[test]
fn inherited_session_env_prefix_not_substring() {
    let env: std::collections::BTreeMap<String, String> = [
        ("LC_MESSAGES", "C"),
        ("LC", "nope"),
        ("MYLC_VAR", "nope"),
        ("XLANG", "nope"),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect();

    let kept: std::collections::BTreeMap<String, String> =
        super::inherited_session_env(&env).into_iter().collect();

    assert_eq!(
        kept.keys().cloned().collect::<Vec<_>>(),
        vec!["LC_MESSAGES"]
    );
}

/// Reads the session record for `id`, or `None` once it has been deleted.
async fn record_exists(client: &mut TestClient, id: SessionId) -> bool {
    client
        .call::<GetSessionRecord>(&GetSessionRecordRequest::Id(id))
        .await
        .record
        .is_some()
}

/// Creates a fresh, configured session on the server and returns its id.
async fn create_session(client: &mut TestClient) -> SessionId {
    create_configured_session(client, "shell-test", "/uwu").await
}

/// Attaching to a session whose loadout was never configured must not
/// blow up: nothing is in flight on a bare `Draft`, so the attach
/// configures it with an empty contribution on the way in and mints the
/// shell as usual. Guards the `min session activate` → `min session attach` path against
/// a caller that never reached the compose step (a compose failure
/// leaves the actor `Draft` — attach has to still land it live), and
/// any internal caller that only ever wanted a session to run something
/// in.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn attach_to_an_unconfigured_session_configures_it_rather_than_failing() {
    use crate::test_harness::create_session_req;
    use minimald_rpc::CreateSession;

    let server = TestServer::new().await;
    let mut client = server.connect().await;
    // Bare `CreateSession` — no `ConfigureLoadout` follow-up. The
    // session stays `Draft`; the attach path is the one that has
    // to notice and configure it on the way in.
    let session_id = client
        .call::<CreateSession>(&create_session_req("bare-session", "/uwu"))
        .await
        .unwrap()
        .id;

    let mut channel = client.open_shell(session_id).await;
    channel.data_bytes(b"hello\n".to_vec()).await.unwrap();
    let mut stdout = Vec::new();
    loop {
        match channel.wait().await {
            Some(ChannelMsg::Data { data }) => {
                stdout.extend_from_slice(&data);
                if String::from_utf8_lossy(&stdout).contains("got:hello") {
                    break;
                }
            }
            Some(_) => {}
            None => {
                let stdout = String::from_utf8_lossy(&stdout);
                panic!("attaching to an unconfigured session should mint a shell; got: {stdout:?}");
            }
        }
    }

    // The attach finalized the session on its way in.
    assert_eq!(
        server
            .state
            .sessions_manager()
            .await
            .get_record(crate::sessions::SessionKeyPredicate::Id(session_id))
            .await
            .unwrap()
            .expect("the record should exist")
            .status,
        sessions::SessionStatus::Active,
    );
}

/// Drives the full SSH path into the session host with the mock launcher:
/// create a session, request a pty + shell, feed stdin, observe the echoed
/// stdout, then confirm the host tears down when the process exits.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shell_round_trips_stdin_to_stdout_then_tears_down() {
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let session_id = create_session(&mut client).await;

    let mut channel = client.open_shell(session_id).await;

    // Echo round trip: the mock echoes each line back as `got:<line>`.
    // Read until we observe the echo, proving the stdin -> program ->
    // stdout path works while the process is still alive.
    channel.data_bytes(b"hello\n".to_vec()).await.unwrap();
    let mut stdout = Vec::new();
    loop {
        match channel.wait().await {
            Some(ChannelMsg::Data { data }) => {
                stdout.extend_from_slice(&data);
                if String::from_utf8_lossy(&stdout).contains("got:hello") {
                    break;
                }
            }
            Some(_) => {}
            None => {
                let stdout = String::from_utf8_lossy(&stdout);
                panic!("channel closed before the echo arrived; stdout: {stdout:?}");
            }
        }
    }

    // Now ask the mock to exit. The shell exiting raises the session-exit
    // prompt (see `session_host`), rendered over the channel; answer it by
    // confirming the first option (Enter -> detach) so teardown proceeds and
    // the channel closes.
    channel
        .data_bytes(format!("{}\n", crate::session_host::MOCK_EXIT_LINE).into_bytes())
        .await
        .unwrap();
    let mut saw_exit_status = false;
    let mut closed = false;
    let mut answered_prompt = false;
    let mut prompt_out = Vec::new();
    while let Ok(msg) = tokio::time::timeout(Duration::from_secs(10), channel.wait()).await {
        match msg {
            Some(ChannelMsg::Data { data }) => {
                // Wait for the prompt to render, then confirm the first
                // option. The prompt only appears once the mainloop has
                // stopped reading the channel, so this keypress reaches the
                // prompt rather than the (now-defunct) stdin path.
                prompt_out.extend_from_slice(&data);
                if !answered_prompt
                    && String::from_utf8_lossy(&prompt_out)
                        .contains(crate::session_host::SHELL_EXIT_PROMPT)
                {
                    channel.data_bytes(b"\r".to_vec()).await.unwrap();
                    answered_prompt = true;
                }
            }
            Some(ChannelMsg::ExitStatus { .. }) => saw_exit_status = true,
            Some(_) => {}
            None => {
                closed = true;
                break;
            }
        }
    }
    assert!(
        answered_prompt,
        "expected the session-exit prompt to render"
    );
    assert!(closed, "channel should close once the mock process exits");
    assert!(saw_exit_status, "expected an exit status on teardown");

    // Detach leaves the session alive: its record must still resolve.
    assert!(
        record_exists(&mut client, session_id).await,
        "detach must not delete the session record"
    );
}

/// The shell-exit prompt leads with the files changed since activation:
/// write a file into the session's workspace while the shell is live, then
/// exit it and expect the delta header and the changed-file row above the
/// prompt. Answered with the default (keep), so the session survives.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shell_exit_prompt_lists_files_changed_since_activation() {
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let session_id = create_session(&mut client).await;

    let mut channel = client.open_shell(session_id).await;

    // Prove the shell is live first (mock echoes `got:<line>`); the
    // baseline snapshot is taken before the process launches, so a write
    // from here on is a change.
    channel.data_bytes(b"hello\n".to_vec()).await.unwrap();
    let mut stdout = Vec::new();
    loop {
        match channel.wait().await {
            Some(ChannelMsg::Data { data }) => {
                stdout.extend_from_slice(&data);
                if String::from_utf8_lossy(&stdout).contains("got:hello") {
                    break;
                }
            }
            Some(_) => {}
            None => panic!("channel closed before the echo arrived"),
        }
    }

    // Change the workspace daemon-side, as an in-session shell would.
    let manager = server.state.sessions_manager().await;
    let handle = manager
        .get_session(crate::sessions::SessionKeyPredicate::Id(session_id))
        .await
        .unwrap()
        .expect("session should resolve");
    let paths = handle.paths().await.expect("paths should resolve");
    let scratch = paths
        .working
        .join(&paths::DaemonRelPath::try_new("scratch.txt").unwrap());
    tokio::fs::write(scratch.as_utf8_path(), b"made in session")
        .await
        .unwrap();

    // Exit the shell; the prompt must lead with the delta.
    channel
        .data_bytes(format!("{}\n", crate::session_host::MOCK_EXIT_LINE).into_bytes())
        .await
        .unwrap();
    let mut answered_prompt = false;
    let mut prompt_out = Vec::new();
    while let Ok(msg) = tokio::time::timeout(Duration::from_secs(10), channel.wait()).await {
        match msg {
            Some(ChannelMsg::Data { data }) => {
                prompt_out.extend_from_slice(&data);
                if !answered_prompt
                    && String::from_utf8_lossy(&prompt_out)
                        .contains(crate::session_host::SHELL_EXIT_PROMPT)
                {
                    channel.data_bytes(b"\r".to_vec()).await.unwrap();
                    answered_prompt = true;
                }
            }
            Some(_) => {}
            None => break,
        }
    }
    let prompt_out = String::from_utf8_lossy(&prompt_out);
    assert!(
        answered_prompt,
        "expected the session-exit prompt to render; got: {prompt_out:?}"
    );
    assert!(
        prompt_out.contains("changed since activation:"),
        "prompt should lead with the delta header; got: {prompt_out:?}"
    );
    assert!(
        prompt_out.contains("A scratch.txt"),
        "prompt should list the added file; got: {prompt_out:?}"
    );

    // Keep (the default) must leave the session intact.
    assert!(
        record_exists(&mut client, session_id).await,
        "keep must not delete the session record"
    );
}

/// Resolves a live session's handle and workspace paths.
async fn session_paths(server: &TestServer, session_id: SessionId) -> crate::session::SessionPaths {
    server
        .state
        .sessions_manager()
        .await
        .get_session(crate::sessions::SessionKeyPredicate::Id(session_id))
        .await
        .unwrap()
        .expect("session should resolve")
        .paths()
        .await
        .expect("paths should resolve")
}

/// Drives the shell until the mock echoes the line back, proving the
/// host is live (and the delta baseline armed).
async fn await_echo(channel: &mut russh::Channel<russh::client::Msg>) {
    channel.data_bytes(b"hello\n".to_vec()).await.unwrap();
    let mut stdout = Vec::new();
    loop {
        match channel.wait().await {
            Some(ChannelMsg::Data { data }) => {
                stdout.extend_from_slice(&data);
                if String::from_utf8_lossy(&stdout).contains("got:hello") {
                    break;
                }
            }
            Some(_) => {}
            None => panic!("channel closed before the echo arrived"),
        }
    }
}

/// Without a usable repository the `SessionDelta` RPC falls back to the
/// changed-since-activation baseline: a file seeded before activation
/// and edited during the session comes back as an `M` row, a file
/// created during the session as an `A` row. The workspace carries an
/// empty `.git` marker dir (as the e2e task seed does) to prove a
/// non-repository `.git` degrades to the fallback rather than erroring.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn session_delta_rpc_falls_back_to_activation_delta_without_a_repo() {
    use minimald_rpc::{SessionDelta, SessionDeltaRequest, SessionDeltaResponse};

    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let session_id = create_session(&mut client).await;

    // Seed a file before the host launches, so the baseline snapshot
    // includes it and the in-session edit below reads as `M`. The
    // empty `.git` marker makes VCS mode decline, not fail.
    let paths = session_paths(&server, session_id).await;
    let working = paths.working.as_utf8_path();
    tokio::fs::create_dir(working.join(".git")).await.unwrap();
    tokio::fs::write(working.join("seeded.txt"), b"v1")
        .await
        .unwrap();

    let mut channel = client.open_shell(session_id).await;
    await_echo(&mut channel).await;

    // Change the workspace daemon-side, as an in-session shell would.
    tokio::fs::write(working.join("seeded.txt"), b"v2 longer")
        .await
        .unwrap();
    tokio::fs::write(working.join("scratch.txt"), b"made in session")
        .await
        .unwrap();

    let resp = client
        .call::<SessionDelta>(&SessionDeltaRequest { id: session_id })
        .await;
    let rows = match resp {
        SessionDeltaResponse::ChangedSinceActivation { rows } => rows,
        other => panic!("expected the activation-delta fallback, got {other:?}"),
    };
    assert!(
        rows.contains(&"A scratch.txt".to_string()),
        "expected the added file; got: {rows:?}"
    );
    assert!(
        rows.contains(&"M seeded.txt".to_string()),
        "expected the modified file; got: {rows:?}"
    );
}

/// Regression: the shell-exit prompt's change detection survives a host
/// teardown and rebuild within one session. After a "keep filesystem" exit
/// and a reattach, the workspace baseline is still the one taken at first
/// activation — not re-snapshotted against the now-dirty tree — so a file
/// changed before the first exit is still reported on the second.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn workspace_baseline_survives_keep_exit_and_reattach() {
    use minimald_rpc::{SessionDelta, SessionDeltaRequest, SessionDeltaResponse};

    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let session_id = create_session(&mut client).await;

    // First activation arms the baseline against the pristine workspace.
    let mut channel = client.open_shell(session_id).await;
    await_echo(&mut channel).await;

    // A change made during the session, daemon-side as an in-session shell
    // would: the baseline predates it, so the exit prompt must report it.
    let paths = session_paths(&server, session_id).await;
    let working = paths.working.as_utf8_path();
    tokio::fs::write(working.join("scratch.txt"), b"made in session")
        .await
        .unwrap();

    // Exit the shell and pick the default first option ("keep filesystem"):
    // Enter with no arrow. The host tears down; the session and its files
    // stay in place.
    keep_exit(&mut channel).await;

    // Reattach mints a new host for the same session.
    let mut channel = client.open_shell(session_id).await;
    await_echo(&mut channel).await;

    // The pre-exit change must still be reported: the reattach reused the
    // activation baseline instead of re-arming against the dirty tree.
    let resp = client
        .call::<SessionDelta>(&SessionDeltaRequest { id: session_id })
        .await;
    let rows = match resp {
        SessionDeltaResponse::ChangedSinceActivation { rows } => rows,
        other => panic!("expected the activation-delta fallback, got {other:?}"),
    };
    assert!(
        rows.contains(&"A scratch.txt".to_string()),
        "the pre-exit change must survive reattach; got: {rows:?}"
    );
}

/// Drives a running shell through the "keep filesystem" exit lane:
/// sends the mock exit line, waits for the session-exit prompt, and
/// answers it with Enter (the default first option). Returns once the
/// channel closes, with the host torn down and the session's files kept.
async fn keep_exit(channel: &mut russh::Channel<russh::client::Msg>) {
    channel
        .data_bytes(format!("{}\n", crate::session_host::MOCK_EXIT_LINE).into_bytes())
        .await
        .unwrap();
    let mut answered_prompt = false;
    let mut prompt_out = Vec::new();
    while let Ok(msg) = tokio::time::timeout(Duration::from_secs(10), channel.wait()).await {
        match msg {
            Some(ChannelMsg::Data { data }) => {
                prompt_out.extend_from_slice(&data);
                if !answered_prompt
                    && String::from_utf8_lossy(&prompt_out)
                        .contains(crate::session_host::SHELL_EXIT_PROMPT)
                {
                    channel.data_bytes(b"\r".to_vec()).await.unwrap();
                    answered_prompt = true;
                }
            }
            Some(_) => {}
            None => break,
        }
    }
    assert!(
        answered_prompt,
        "expected the session-exit prompt to render"
    );
}

/// Regression: the baseline also survives a daemon restart. The arm
/// result is persisted to the session's `delta-baseline.json` sidecar,
/// so a second daemon booted on the same state dir reattaches with the
/// activation-time baseline and still reports a change made before the
/// restart — instead of re-snapshotting the dirty tree and calling it
/// clean.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn workspace_baseline_survives_a_daemon_restart() {
    use minimald_rpc::{SessionDelta, SessionDeltaRequest, SessionDeltaResponse};

    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let session_id = create_session(&mut client).await;

    // First activation arms the baseline and persists the sidecar.
    let mut channel = client.open_shell(session_id).await;
    await_echo(&mut channel).await;

    // A pre-restart change the persisted baseline must predate.
    let paths = session_paths(&server, session_id).await;
    let working = paths.working.as_utf8_path();
    tokio::fs::write(working.join("scratch.txt"), b"made before restart")
        .await
        .unwrap();

    keep_exit(&mut channel).await;

    // "Restart the daemon": tear the first server down and boot a
    // second one on the same state dir.
    drop(client);
    let server = TestServer::new_in(server.into_state_dir()).await;
    let mut client = server.connect().await;

    // Reattach on the restarted daemon: the fresh session actor must
    // load the sidecar instead of re-arming against the dirty tree.
    let mut channel = client.open_shell(session_id).await;
    await_echo(&mut channel).await;

    let resp = client
        .call::<SessionDelta>(&SessionDeltaRequest { id: session_id })
        .await;
    let rows = match resp {
        SessionDeltaResponse::ChangedSinceActivation { rows } => rows,
        other => panic!("expected the activation-delta fallback, got {other:?}"),
    };
    assert!(
        rows.contains(&"A scratch.txt".to_string()),
        "the pre-restart change must survive the restart; got: {rows:?}"
    );
}

/// With a real repository in the workspace the `SessionDelta` RPC
/// reports VCS-exact state through the whole stack: committed-and-pushed
/// is proven clean (even though the tree differs from an empty
/// activation baseline), and new work lists as uncommitted rows. The
/// unpushed-commit arm is covered by `session_delta`'s unit tests.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn session_delta_rpc_reports_vcs_state_for_a_git_workspace() {
    use minimald_rpc::{SessionDelta, SessionDeltaRequest, SessionDeltaResponse};

    if std::process::Command::new("git")
        .arg("--version")
        .output()
        .is_err()
    {
        eprintln!("skipping: no git binary in this environment");
        return;
    }

    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let session_id = create_session(&mut client).await;

    let paths = session_paths(&server, session_id).await;
    let working = paths.working.as_utf8_path().as_std_path();
    tokio::fs::write(working.join("tracked.txt"), b"v1")
        .await
        .unwrap();
    let git = |args: &[&str]| {
        let out = std::process::Command::new("git")
            .arg("-C")
            .arg(working)
            .args([
                "-c",
                "user.name=t",
                "-c",
                "user.email=t@example.invalid",
                "-c",
                "commit.gpgsign=false",
            ])
            .args(args)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    };
    let bare = tempfile::tempdir().unwrap();
    let init = std::process::Command::new("git")
        .args(["init", "--bare", "-b", "main"])
        .arg(bare.path())
        .output()
        .unwrap();
    assert!(init.status.success(), "git init --bare failed");
    git(&["init", "-b", "main"]);
    git(&["add", "-A"]);
    git(&["commit", "-m", "initial"]);
    git(&["remote", "add", "origin", bare.path().to_str().unwrap()]);
    git(&["push", "origin", "main"]);

    let mut channel = client.open_shell(session_id).await;
    await_echo(&mut channel).await;

    // Everything committed and pushed: proven clean.
    let resp = client
        .call::<SessionDelta>(&SessionDeltaRequest { id: session_id })
        .await;
    assert_eq!(
        resp,
        SessionDeltaResponse::Vcs {
            uncommitted: vec![],
            unpushed_commits: 0
        },
    );

    // In-session work: an edit and an untracked file are at risk.
    tokio::fs::write(working.join("tracked.txt"), b"v2")
        .await
        .unwrap();
    tokio::fs::write(working.join("wip.txt"), b"unsaved")
        .await
        .unwrap();
    let resp = client
        .call::<SessionDelta>(&SessionDeltaRequest { id: session_id })
        .await;
    assert_eq!(
        resp,
        SessionDeltaResponse::Vcs {
            uncommitted: vec!["M tracked.txt".to_string(), "A wip.txt".to_string()],
            unpushed_commits: 0
        },
    );
}

/// A session without a running host cannot say what is at risk: the RPC
/// answers `Unavailable` (never an error), and the client gates the
/// destroy conservatively without a listing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn session_delta_rpc_is_unavailable_without_a_running_host() {
    use minimald_rpc::{SessionDelta, SessionDeltaRequest, SessionDeltaResponse};

    let server = TestServer::new().await;
    let mut client = server.connect().await;
    // Configured but never attached: no host was minted, as for a
    // stopped session or one recovered after a daemon restart.
    let session_id = create_session(&mut client).await;

    let resp = client
        .call::<SessionDelta>(&SessionDeltaRequest { id: session_id })
        .await;
    assert_eq!(resp, SessionDeltaResponse::Unavailable);
}

/// Selecting "delete" on the shell-exit prompt must tear the connection down
/// *and* destroy the session (record removed), routed through the manager
/// via the binding's weak handle.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn terminate_option_deletes_session_and_closes_channel() {
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let session_id = create_session(&mut client).await;

    let mut channel = client.open_shell(session_id).await;

    // Confirm the shell is live before exiting it (mock echoes `got:<line>`).
    channel.data_bytes(b"hello\n".to_vec()).await.unwrap();
    let mut stdout = Vec::new();
    loop {
        match channel.wait().await {
            Some(ChannelMsg::Data { data }) => {
                stdout.extend_from_slice(&data);
                if String::from_utf8_lossy(&stdout).contains("got:hello") {
                    break;
                }
            }
            Some(_) => {}
            None => panic!("channel closed before the echo arrived"),
        }
    }

    // Exit the shell to raise the prompt, then pick the second option
    // (delete): a down-arrow to move off the default, then Enter.
    channel
        .data_bytes(format!("{}\n", crate::session_host::MOCK_EXIT_LINE).into_bytes())
        .await
        .unwrap();
    let mut closed = false;
    let mut answered_prompt = false;
    let mut prompt_out = Vec::new();
    while let Ok(msg) = tokio::time::timeout(Duration::from_secs(10), channel.wait()).await {
        match msg {
            Some(ChannelMsg::Data { data }) => {
                prompt_out.extend_from_slice(&data);
                if !answered_prompt
                    && String::from_utf8_lossy(&prompt_out)
                        .contains(crate::session_host::SHELL_EXIT_PROMPT)
                {
                    channel.data_bytes(b"\x1b[B\r".to_vec()).await.unwrap();
                    answered_prompt = true;
                }
            }
            Some(_) => {}
            None => {
                closed = true;
                break;
            }
        }
    }

    // Requirement 1: the connection is torn down.
    assert!(
        answered_prompt,
        "expected the session-exit prompt to render"
    );
    assert!(closed, "channel should close after the delete completes");

    // Requirement 2: the session is gone. The binding awaits the destroy
    // before closing the channel, so the record is already removed by the
    // time we observe the close.
    assert!(
        !record_exists(&mut client, session_id).await,
        "delete must remove the session record"
    );
}

/// When files changed since activation, the shell-exit prompt gains a
/// middle save-then-delete lane: selecting it (a down-arrow then Enter,
/// the same keystrokes that pick delete when nothing changed) writes an
/// archive of the changed files under the daemon's archives dir and only
/// then destroys the session, exactly like the delete lane.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn save_option_archives_changed_files_then_deletes_session() {
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let session_id = create_session(&mut client).await;

    let mut channel = client.open_shell(session_id).await;

    // Prove the shell is live first (mock echoes `got:<line>`); the
    // baseline snapshot is taken before the process launches, so a write
    // from here on is a change.
    channel.data_bytes(b"hello\n".to_vec()).await.unwrap();
    let mut stdout = Vec::new();
    loop {
        match channel.wait().await {
            Some(ChannelMsg::Data { data }) => {
                stdout.extend_from_slice(&data);
                if String::from_utf8_lossy(&stdout).contains("got:hello") {
                    break;
                }
            }
            Some(_) => {}
            None => panic!("channel closed before the echo arrived"),
        }
    }

    // Change the workspace daemon-side, as an in-session shell would.
    let manager = server.state.sessions_manager().await;
    let handle = manager
        .get_session(crate::sessions::SessionKeyPredicate::Id(session_id))
        .await
        .unwrap()
        .expect("session should resolve");
    let paths = handle.paths().await.expect("paths should resolve");
    let scratch = paths
        .working
        .join(&paths::DaemonRelPath::try_new("scratch.txt").unwrap());
    tokio::fs::write(scratch.as_utf8_path(), b"made in session")
        .await
        .unwrap();

    // Exit the shell, then pick the middle option (save-then-delete).
    channel
        .data_bytes(format!("{}\n", crate::session_host::MOCK_EXIT_LINE).into_bytes())
        .await
        .unwrap();
    let mut closed = false;
    let mut answered_prompt = false;
    let mut prompt_out = Vec::new();
    while let Ok(msg) = tokio::time::timeout(Duration::from_secs(10), channel.wait()).await {
        match msg {
            Some(ChannelMsg::Data { data }) => {
                prompt_out.extend_from_slice(&data);
                if !answered_prompt
                    && String::from_utf8_lossy(&prompt_out)
                        .contains(crate::session_host::SHELL_EXIT_PROMPT)
                {
                    channel.data_bytes(b"\x1b[B\r".to_vec()).await.unwrap();
                    answered_prompt = true;
                }
            }
            Some(_) => {}
            None => {
                closed = true;
                break;
            }
        }
    }
    let prompt_text = String::from_utf8_lossy(&prompt_out);
    assert!(
        answered_prompt,
        "expected the session-exit prompt to render; got: {prompt_text:?}"
    );
    assert!(
        prompt_text.contains("Save changes to "),
        "a non-empty delta should render the save lane; got: {prompt_text:?}"
    );
    assert!(
        closed,
        "channel should close after the save + delete completes"
    );

    // The session is gone, like the plain delete lane.
    assert!(
        !record_exists(&mut client, session_id).await,
        "save-then-delete must remove the session record"
    );

    // ...and the archive is on disk, named for the session, holding
    // exactly the changed file under its workspace-relative path.
    let archives = server
        .state
        .minimal_state_dir()
        .await
        .as_utf8_path()
        .as_std_path()
        .join("archives");
    let mut entries: Vec<_> = std::fs::read_dir(&archives)
        .expect("the archives dir should have been created")
        .map(|e| e.unwrap().path())
        .collect();
    assert_eq!(
        entries.len(),
        1,
        "expected exactly one archive: {entries:?}"
    );
    let archive_path = entries.pop().unwrap();
    let file_name = archive_path.file_name().unwrap().to_string_lossy();
    assert!(
        file_name.starts_with("shell-test-") && file_name.ends_with(".tar.zst"),
        "archive should be named <session>-<timestamp>.tar.zst; got {file_name:?}"
    );

    use std::io::Read as _;
    let mut archive =
        tar::Archive::new(zstd::Decoder::new(std::fs::File::open(&archive_path).unwrap()).unwrap());
    let mut files = std::collections::BTreeMap::new();
    for entry in archive.entries().unwrap() {
        let mut entry = entry.unwrap();
        let path = entry.path().unwrap().into_owned();
        let mut contents = String::new();
        entry.read_to_string(&mut contents).unwrap();
        files.insert(path, contents);
    }
    assert_eq!(
        files,
        [(
            std::path::PathBuf::from("scratch.txt"),
            "made in session".to_string(),
        )]
        .into_iter()
        .collect(),
    );
}

/// A second shell request to the same session takes over the running host:
/// the new channel is flushed the current terminal state (so it sees the
/// earlier `hello` output), and the original channel is disconnected.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn second_shell_takes_over_session_and_closes_the_first() {
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let session_id = create_session(&mut client).await;

    // First attachment: drive an echo so the host's terminal state holds
    // `got:hello`, confirming it before we take the session over.
    let mut first = client.open_shell(session_id).await;
    first.data_bytes(b"hello\n".to_vec()).await.unwrap();
    let mut first_out = Vec::new();
    loop {
        match first.wait().await {
            Some(ChannelMsg::Data { data }) => {
                first_out.extend_from_slice(&data);
                if String::from_utf8_lossy(&first_out).contains("got:hello") {
                    break;
                }
            }
            Some(_) => {}
            None => {
                let first_out = String::from_utf8_lossy(&first_out);
                panic!("first channel closed before the echo arrived; got: {first_out:?}");
            }
        }
    }

    // Second attachment to the same session takes over.
    let mut second = client.open_shell(session_id).await;

    // The takeover flushes the current terminal state to the new channel,
    // so the earlier `got:hello` shows up in what it's sent on attach. The
    // session stays live (no teardown), so read with a timeout rather than
    // draining to close.
    let mut flushed = Vec::new();
    while let Ok(Some(msg)) = tokio::time::timeout(Duration::from_secs(5), second.wait()).await {
        if let ChannelMsg::Data { data } = msg {
            flushed.extend_from_slice(&data);
            if String::from_utf8_lossy(&flushed).contains("got:hello") {
                break;
            }
        }
    }
    let flushed = String::from_utf8_lossy(&flushed);
    assert!(
        flushed.contains("got:hello"),
        "takeover should flush prior terminal state to the new channel, got: {flushed:?}",
    );

    // The original channel should have been disconnected by the takeover.
    let mut first_closed = false;
    while let Ok(msg) = tokio::time::timeout(Duration::from_secs(5), first.wait()).await {
        if msg.is_none() {
            first_closed = true;
            break;
        }
    }
    assert!(
        first_closed,
        "first channel should be closed once the session is taken over",
    );
}

/// The detach chord (leader `ctrl-]` then `d`) detaches the current
/// channel — sending a detach notice down it before it closes — without
/// tearing the session down, so a later channel resumes it (the earlier
/// `got:hello` is flushed on reattach). The default keys apply because the
/// test's `open_shell` sends no session-key env vars.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn detach_chord_detaches_channel_then_session_resumes_on_reattach() {
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let session_id = create_session(&mut client).await;

    // First attachment: drive an echo so the terminal state holds
    // `got:hello` before we detach.
    let mut first = client.open_shell(session_id).await;
    first.data_bytes(b"hello\n".to_vec()).await.unwrap();
    let mut first_out = Vec::new();
    loop {
        match first.wait().await {
            Some(ChannelMsg::Data { data }) => {
                first_out.extend_from_slice(&data);
                if String::from_utf8_lossy(&first_out).contains("got:hello") {
                    break;
                }
            }
            Some(_) => {}
            None => {
                let first_out = String::from_utf8_lossy(&first_out);
                panic!("first channel closed before the echo arrived; got: {first_out:?}");
            }
        }
    }

    // Send the detach chord as two separate chunks — the leader (0x1d)
    // enters command mode (swallowed), then `d` detaches. (The streaming
    // matcher also handles the two bytes coalesced into one chunk; split
    // sends exercise the cross-chunk pending path instead.)
    first.data_bytes(vec![0x1d]).await.unwrap();
    first.data_bytes(vec![b'd']).await.unwrap();
    let mut detach_out = Vec::new();
    let mut first_closed = false;
    while let Ok(msg) = tokio::time::timeout(Duration::from_secs(5), first.wait()).await {
        match msg {
            Some(ChannelMsg::Data { data }) => detach_out.extend_from_slice(&data),
            Some(_) => {}
            None => {
                first_closed = true;
                break;
            }
        }
    }
    let detach_out = String::from_utf8_lossy(&detach_out);
    assert!(
        detach_out.contains("Detaching from session."),
        "expected a detach notice on the channel before it closed, got: {detach_out:?}",
    );
    assert!(first_closed, "channel should close after the detach chord");

    // Reattach: a second channel resumes the same (still-live) session, so
    // the earlier `got:hello` is flushed to it on connect.
    let mut second = client.open_shell(session_id).await;
    let mut flushed = Vec::new();
    while let Ok(Some(msg)) = tokio::time::timeout(Duration::from_secs(5), second.wait()).await {
        if let ChannelMsg::Data { data } = msg {
            flushed.extend_from_slice(&data);
            if String::from_utf8_lossy(&flushed).contains("got:hello") {
                break;
            }
        }
    }
    let flushed = String::from_utf8_lossy(&flushed);
    assert!(
        flushed.contains("got:hello"),
        "reattaching should flush prior terminal state, got: {flushed:?}",
    );
}

/// A remapped leader (negotiated via env vars at attach) is honored: the
/// old default leader (`ctrl-]`, `0x1d`) no longer detaches — it forwards to
/// the shell — while the remapped leader (`ctrl-^`, `0x1e`) then the
/// remapped detach key (`x`) does. Proves the per-channel negotiation and
/// the dynamic matcher end-to-end through the real attach path.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn remapped_leader_detaches_old_leader_forwards() {
    use sessions::keys::{DETACH_KEY_ENV, LEADER_ENV};

    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let session_id = create_session(&mut client).await;

    // Attach with a remapped leader (ctrl-^) and detach key (x).
    let mut ch = client
        .open_shell_with_keys(session_id, &[(LEADER_ENV, "ctrl-^"), (DETACH_KEY_ENV, "x")])
        .await;

    // The old default leader (0x1d, ctrl-]) must no longer detach: it
    // forwards to the shell. Send it, then a normal line; the shell echoes
    // both back, proving the channel survived (no detach fired).
    ch.data_bytes(vec![0x1d]).await.unwrap();
    ch.data_bytes(b"ping\n".to_vec()).await.unwrap();
    let mut out = Vec::new();
    loop {
        match tokio::time::timeout(Duration::from_secs(5), ch.wait()).await {
            Ok(Some(ChannelMsg::Data { data })) => {
                out.extend_from_slice(&data);
                if String::from_utf8_lossy(&out).contains("got:") {
                    break;
                }
            }
            Ok(Some(_)) => {}
            Ok(None) => {
                let out = String::from_utf8_lossy(&out);
                panic!(
                    "channel closed after the old leader; it should have forwarded, got: {out:?}"
                );
            }
            Err(_) => panic!("timed out waiting for echo after the old leader"),
        }
    }

    // The remapped leader (0x1e, ctrl-^) enters command mode (swallowed),
    // then `x` detaches — sent as two separate chunks here to exercise the
    // cross-chunk pending path; the coalesced form is covered by
    // `reattach_renegotiates_the_chord_per_channel`.
    ch.data_bytes(vec![0x1e]).await.unwrap();
    ch.data_bytes(vec![b'x']).await.unwrap();
    let mut detach_out = Vec::new();
    let mut closed = false;
    while let Ok(msg) = tokio::time::timeout(Duration::from_secs(5), ch.wait()).await {
        match msg {
            Some(ChannelMsg::Data { data }) => detach_out.extend_from_slice(&data),
            Some(_) => {}
            None => {
                closed = true;
                break;
            }
        }
    }
    let detach_out = String::from_utf8_lossy(&detach_out);
    assert!(
        detach_out.contains("Detaching from session."),
        "remapped chord should detach, got: {detach_out:?}",
    );
    assert!(
        closed,
        "channel should close after the remapped detach chord"
    );
}

/// Drives `ch` until `needle` appears in its stdout (the mock echoes each
/// input line as `got:<line>`), panicking if the channel closes or stalls
/// first. Returns everything received anew.
async fn recv_until(ch: &mut russh::Channel<russh::client::Msg>, needle: &str) -> String {
    let mut out = Vec::new();
    loop {
        match tokio::time::timeout(Duration::from_secs(5), ch.wait()).await {
            Ok(Some(ChannelMsg::Data { data })) => {
                out.extend_from_slice(&data);
                let text = String::from_utf8_lossy(&out);
                if text.contains(needle) {
                    return text.into_owned();
                }
            }
            Ok(Some(_)) => {}
            Ok(None) => panic!("channel closed before {needle:?} appeared; got {out:?}"),
            Err(_) => panic!("timed out waiting for {needle:?}; got {out:?}"),
        }
    }
}

/// Drains `ch` until it closes (e.g. after a detach chord), returning
/// everything received. Panics if the channel stays open.
async fn collect_to_close(ch: &mut russh::Channel<russh::client::Msg>) -> String {
    let mut out = Vec::new();
    while let Ok(msg) = tokio::time::timeout(Duration::from_secs(5), ch.wait()).await {
        match msg {
            Some(ChannelMsg::Data { data }) => out.extend_from_slice(&data),
            Some(_) => {}
            None => return String::from_utf8_lossy(&out).into_owned(),
        }
    }
    panic!("channel did not close within the timeout; got {out:?}");
}

/// A client negotiating an unsafe leader (`ctrl-c`) hits the daemon's
/// silent backstop: the leader falls back to `ctrl-]` while the valid
/// detach remap (`x`) survives — the fallback is field-scoped, so the
/// effective chord is `ctrl-]` then `x`. The unsafe byte forwards as data.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rejected_leader_falls_back_to_default_chord() {
    use sessions::keys::{DETACH_KEY_ENV, LEADER_ENV};

    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let session_id = create_session(&mut client).await;

    let mut ch = client
        .open_shell_with_keys(session_id, &[(LEADER_ENV, "ctrl-c"), (DETACH_KEY_ENV, "x")])
        .await;

    // 0x03 must NOT enter command mode: it is data (the shell renders it
    // `^C` and it never reaches the echoed line). If it had entered, the
    // `x` below would be the detach subcommand and the channel would
    // close; instead the mock echoes the line back.
    ch.data_bytes(vec![0x03]).await.unwrap();
    ch.data_bytes(b"xping\n".to_vec()).await.unwrap();
    recv_until(&mut ch, "got:xping").await;

    // The fallback chord — default leader, surviving detach remap — fires.
    ch.data_bytes(vec![0x1d]).await.unwrap();
    ch.data_bytes(b"x".to_vec()).await.unwrap();
    let out = collect_to_close(&mut ch).await;
    assert!(
        out.contains("Detaching from session."),
        "fallback leader + surviving detach remap should detach, got {out:?}"
    );
}

/// Two channels on one session each get their own negotiated chord. The
/// first attach uses the defaults; the second negotiates `ctrl-^`/`x`,
/// finds its *own* old leader bytes (0x1d here) reduced to inert data,
/// and detaches via the remapped chord. Both chords are sent COALESCED —
// single SSH data messages exercising the streaming matcher's
// coalescing path.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reattach_renegotiates_the_chord_per_channel() {
    use sessions::keys::{DETACH_KEY_ENV, LEADER_ENV};

    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let session_id = create_session(&mut client).await;

    // First attach: defaults — detach via the coalesced `\x1dd` chord.
    let mut first = client.open_shell(session_id).await;
    first.data_bytes(b"boot\n".to_vec()).await.unwrap();
    recv_until(&mut first, "got:boot").await;
    first.data_bytes(b"\x1dd".to_vec()).await.unwrap();
    let out = collect_to_close(&mut first).await;
    assert!(
        out.contains("Detaching from session."),
        "coalesced default chord should detach, got {out:?}"
    );

    // Reattach with negotiated keys: the per-channel renegotiation.
    let mut second = client
        .open_shell_with_keys(session_id, &[(LEADER_ENV, "ctrl-^"), (DETACH_KEY_ENV, "x")])
        .await;
    // The old leader 0x1d is inert data on this channel: if it entered
    // command mode, the `ping\n` below would be swallowed/mistaken; the
    // mock echo proves it flowed as data instead.
    second.data_bytes(vec![0x1d]).await.unwrap();
    second.data_bytes(b"ping\n".to_vec()).await.unwrap();
    recv_until(&mut second, "got:\u{1d}ping").await;
    // The remapped chord, coalesced, detaches.
    second.data_bytes(b"\x1ex".to_vec()).await.unwrap();
    let out = collect_to_close(&mut second).await;
    assert!(
        out.contains("Detaching from session."),
        "coalesced remapped chord should detach, got {out:?}"
    );
}

/// An unbound subcommand key is swallowed and cancels command mode: the
/// key never reaches the shell, the line after forwards normally, and the
/// real chord still works afterwards.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unbound_subcommand_swallows_and_cancels_command_mode() {
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let session_id = create_session(&mut client).await;

    let mut ch = client.open_shell(session_id).await;
    ch.data_bytes(b"boot\n".to_vec()).await.unwrap();
    recv_until(&mut ch, "got:boot").await;

    // Leader enters command mode; `q` is unbound: swallowed, mode
    // cancelled. The next line must arrive as plain `ping` — a leaked `q`
    // would echo as `got:qping` and this would time out.
    ch.data_bytes(vec![0x1d]).await.unwrap();
    ch.data_bytes(b"q".to_vec()).await.unwrap();
    ch.data_bytes(b"ping\n".to_vec()).await.unwrap();
    recv_until(&mut ch, "got:ping").await;

    // The real chord is unaffected by the cancelled attempt.
    ch.data_bytes(vec![0x1d]).await.unwrap();
    ch.data_bytes(b"d".to_vec()).await.unwrap();
    let out = collect_to_close(&mut ch).await;
    assert!(
        out.contains("Detaching from session."),
        "the chord should still detach after a cancelled command mode, got {out:?}"
    );
}

/// A session's composition persists across a daemon restart: the
/// sidecar written at composition-assembly time is read back when
/// the actor is respawned from disk, so the launcher sees the same
/// packages and vars instead of falling back to the baseline set.
/// This is the core fix for issue #849 — "session composition state
/// is in-memory only: daemon restart drops loadout packages/vars
/// for existing sessions."
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn composition_survives_actor_restart() {
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let session_id = create_session(&mut client).await;

    // The actor was spawned during `create_configured_session`
    // and holds the composition in memory. Verify it's present.
    let manager = server.state.sessions_manager().await;
    let handle = manager
        .get_session(crate::sessions::SessionKeyPredicate::Id(session_id))
        .await
        .unwrap()
        .expect("session should resolve while actor is running");
    assert!(
        handle.peek_composition().await.is_some(),
        "freshly configured session should hold its composition in memory"
    );

    // Stop the actor and evict it from the running map so the
    // next `get_session` spawns a fresh actor from the on-disk
    // record — simulating a daemon restart.
    handle.stop().await;
    manager.evict(session_id).await;

    // Re-resolve: spawns a new actor from disk. The composition
    // should be restored from the sidecar, not None.
    let handle = manager
        .get_session(crate::sessions::SessionKeyPredicate::Id(session_id))
        .await
        .unwrap()
        .expect("session should resolve after eviction");
    assert!(
        handle.peek_composition().await.is_some(),
        "re-spawned session should have its composition restored from \
             the sidecar, not fall back to baseline"
    );
}

/// When the sidecar is missing (e.g. a session that predated the
/// sidecar, or a corrupt filesystem), the actor still spawns — but
/// with no composition, so the launcher falls back to its baseline
/// set. The operator sees a warning log rather than a silent drop.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn missing_sidecar_falls_back_to_baseline() {
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let session_id = create_session(&mut client).await;

    let manager = server.state.sessions_manager().await;
    let handle = manager
        .get_session(crate::sessions::SessionKeyPredicate::Id(session_id))
        .await
        .unwrap()
        .expect("session should resolve");

    // Delete the sidecar to simulate a pre-sidecar session or a
    // corrupt filesystem. The composition sidecar lives at
    // `<session-root>/composition.json`, a sibling of `record.json`;
    // derive it from the workspace path (`<root>/tree`).
    let paths = handle.paths().await.expect("paths should resolve");
    let composition_file = paths
        .working
        .parent()
        .expect("workspace path has a parent")
        .join(&paths::DaemonRelPath::try_new("composition.json").unwrap());
    tokio::fs::remove_file(composition_file.as_utf8_path())
        .await
        .expect("sidecar should exist to delete");

    handle.stop().await;
    manager.evict(session_id).await;

    // Re-resolve: spawns from disk with no sidecar. The
    // composition should be None — loud fallback to baseline.
    let handle = manager
        .get_session(crate::sessions::SessionKeyPredicate::Id(session_id))
        .await
        .unwrap()
        .expect("session should resolve after eviction");
    assert!(
        handle.peek_composition().await.is_none(),
        "session with a missing sidecar should fall back to baseline \
             (composition None), not hold a stale composition"
    );
}

/// An exec request needs the session's sandbox up, not a terminal: a
/// session sitting idle with nobody attached must still be able to launch
/// a host, and a second request must reuse it rather than starting a
/// second shell in the same session.
#[tokio::test]
async fn ensure_host_launches_an_unattached_host_and_then_reuses_it() {
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let session_id = create_configured_session(&mut client, "ensure-host", "/tmp").await;

    let manager = server.state.sessions_manager().await;
    let handle = manager
        .get_session(crate::sessions::SessionKeyPredicate::Id(session_id))
        .await
        .unwrap()
        .expect("session should resolve");

    assert!(
        handle.get_attrs().await.is_none(),
        "no client has attached, so the session should have no host yet"
    );

    let host = handle
        .ensure_host("tester".to_string())
        .await
        .expect("an Active session should be able to launch a host");
    assert!(host.is_alive());
    assert!(
        handle.get_attrs().await.is_some(),
        "the session should now be holding the host it launched"
    );

    let again = handle
        .ensure_host("tester".to_string())
        .await
        .expect("a second request should be served by the running host");
    assert!(
        again.same_host(&host),
        "a second exec request minted a second host instead of reusing the first"
    );
}

/// NET-079's "recorded as such" is not best-effort: a host-address box
/// whose launch cannot write its outcome onto the session record does not
/// run as though it had one. The launch kills the box it minted and fails
/// with `LaunchRecordUnwritable`, the session holds no host, and the record
/// keeps no outcome — so no read surface ever answers for a box that ran
/// without one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_launch_whose_record_cannot_be_written_kills_its_box() {
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let session_id = create_configured_session(&mut client, "unrecorded-launch", "/tmp").await;
    let torn_down = crate::session::launch_record_seam::fail_writes_for(session_id);

    let manager = server.state.sessions_manager().await;
    let handle = manager
        .get_session(crate::sessions::SessionKeyPredicate::Id(session_id))
        .await
        .unwrap()
        .expect("session should resolve");

    match handle.ensure_host("tester".to_string()).await {
        Err(crate::session::AttachError::LaunchRecordUnwritable(_)) => {}
        Err(other) => panic!("the launch failed for another reason: {other}"),
        Ok(_) => panic!("a launch whose outcome could not be recorded handed its box back"),
    }
    tokio::time::timeout(Duration::from_secs(10), async {
        while !torn_down.load(std::sync::atomic::Ordering::SeqCst) {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the launch kills the box it could not record, tearing its network down");
    assert!(
        handle.get_attrs().await.is_none(),
        "the session holds no host after a launch it could not record"
    );
    let record = client
        .call::<GetSessionRecord>(&GetSessionRecordRequest::Id(session_id))
        .await
        .record
        .expect("the session's record is readable");
    assert_eq!(
        record.host_ip_enforcement, None,
        "a launch that could not record its outcome left none on the record"
    );
}

// ---- lifecycle hooks -------------------------------------------------
//
// Hooks run inside the session, which under test means the host-side
// command `session_host::Host::command_in_session` builds for the mock
// launcher. What these cover is the wiring above that: which transitions
// run hooks, when they run relative to teardown, and whether a session
// with no live host gets one minted first.

/// A hook body that records having run by creating `marker`. A redirect
/// rather than `touch(1)`: a hook gets only the session's own
/// environment, so nothing here should depend on inheriting a PATH.
fn marker_body(marker: &std::path::Path) -> String {
    format!("echo ran > {}", marker.display())
}

/// An inline hook script. The timeout is generous because a loaded box
/// slowing a hook down should not read as a hook that didn't fire.
fn inline(body: String) -> sessions::wire::primitives::WireHookScript {
    sessions::wire::primitives::WireHookScript::Inline {
        body,
        timeout_secs: 60,
    }
}

/// Creates an `Active` session whose composition carries `hook`.
///
/// The hook is delivered through the client contribution, the way a
/// loadout's are — no policy gate applies to those — so these tests
/// drive the actor's hook wiring without also driving the project-hook
/// approval flow. Provenance doesn't change how a hook is run.
/// A client contribution carrying one hook, sourced from a loadout —
/// no policy gate applies to those, so a test drives the actor's hook
/// wiring without also driving the project-approval flow.
fn contribution_with_hook(
    hook: sessions::wire::primitives::WireLifecycleHook,
) -> sessions::wire::request::WireContribution {
    sessions::wire::request::WireContribution {
        lifecycle_hooks: vec![sessions::wire::primitives::WireProvenancedHook {
            hook,
            source: sessions::wire::primitives::WireSource::UserLoadout {
                name: "test".to_string(),
            },
        }],
        ..Default::default()
    }
}

/// The session's on-disk status, or `None` once it is gone.
async fn record_status(client: &mut TestClient, id: SessionId) -> Option<sessions::SessionStatus> {
    client
        .call::<GetSessionRecord>(&GetSessionRecordRequest::Id(id))
        .await
        .record
        .map(|r| r.status)
}

async fn session_with_hook(
    client: &mut TestClient,
    name: &str,
    hook: sessions::wire::primitives::WireLifecycleHook,
) -> SessionId {
    use crate::test_harness::{create_session_req, unwrap_ready};
    use minimald_rpc::{
        ConfigureLoadout, ConfigureLoadoutRequest, CreateSession, Errorable, FinalizeSession,
        FinalizeSessionRequest,
    };

    let id = client
        .call::<CreateSession>(&create_session_req(name, "/uwu"))
        .await
        .unwrap()
        .id;
    unwrap_ready(
        client
            .call::<ConfigureLoadout>(&ConfigureLoadoutRequest {
                session_id: id,
                contribution: sessions::wire::request::WireContribution {
                    lifecycle_hooks: vec![sessions::wire::primitives::WireProvenancedHook {
                        hook,
                        source: sessions::wire::primitives::WireSource::UserLoadout {
                            name: "test".to_string(),
                        },
                    }],
                    ..Default::default()
                },
            })
            .await
            .unwrap(),
    );
    match client
        .call::<FinalizeSession>(&FinalizeSessionRequest { session_id: id })
        .await
    {
        Errorable::Ok(_) => id,
        Errorable::Err { error } => panic!("FinalizeSession failed: {error}"),
    }
}

/// Destroys `id` through the RPC surface a client uses.
async fn destroy_session(
    client: &mut TestClient,
    id: SessionId,
) -> minimald_rpc::DestroySessionResponse {
    use minimald_rpc::{DestroySession, DestroySessionRequest, Errorable};
    match client
        .call::<DestroySession>(&DestroySessionRequest { id })
        .await
    {
        Errorable::Ok(resp) => resp,
        Errorable::Err { error } => panic!("DestroySession failed: {error}"),
    }
}

/// Waits for `marker` to appear, so a test can observe a hook that runs
/// off the path it is driving (a detach is reported by the departing
/// binding, not by the RPC the test called).
async fn await_marker(marker: &std::path::Path) -> bool {
    for _ in 0..100 {
        if marker.exists() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    false
}

/// The finalize gate waits only for scripts that actually arrive by
/// upload.
///
/// The client stages *loadout* scripts; a project's ride along with
/// the project tree, which the activation already uploads. Counting
/// a project's external script here would demand an upload nobody
/// sends — and no project could declare one at all, because the
/// session would fail to finalize every time.
#[test]
fn only_uploaded_hook_scripts_gate_the_finalize() {
    use super::{Composition, composition_needs_staged_scripts};
    use sessions::core::lifecyclehook::{HookScript, LifecycleHook};
    use sessions::core::source::{ProvenancedHook, Source};
    use sessions::wire::primitives::WireProvenancedHook;
    use sessions::wire::request::{COMPOSITION_SNAPSHOT_VERSION, WireComposition};

    let composition_of = |hook: ProvenancedHook| {
        Composition::try_from(WireComposition {
            version: COMPOSITION_SNAPSHOT_VERSION,
            vars: Vec::new(),
            patches: Vec::new(),
            packages: Vec::new(),
            lifecycle_hooks: vec![WireProvenancedHook::from(hook)],
            orientation: Default::default(),
        })
        .expect("a hook with a script converts back")
    };
    let with_activate = |script: HookScript, source: Source| {
        composition_of(ProvenancedHook::new(
            LifecycleHook::builder()
                .with_on_activate(script)
                .build()
                .unwrap(),
            source,
        ))
    };
    let external = || HookScript::try_external("scripts/setup.sh").unwrap();
    let project = || Source::Project {
        path: paths::HostPath::try_new("/home/dev/proj").unwrap(),
    };
    let loadout = || Source::UserLoadout {
        name: "dev".to_string(),
    };

    assert!(
        !composition_needs_staged_scripts(&with_activate(external(), project())),
        "a project's script arrives with the project tree, not the hook-script upload",
    );
    assert!(
        composition_needs_staged_scripts(&with_activate(external(), loadout())),
        "a loadout's script only ever arrives by upload",
    );
    // An inline hook uploads nothing, whoever declared it.
    assert!(!composition_needs_staged_scripts(&with_activate(
        HookScript::inline("true"),
        loadout()
    )));
}

/// Activation runs `on_activate`, and the session it hands back is
/// attachable.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn activation_runs_its_activate_hooks() {
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("activated");

    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let session_id = session_with_hook(
        &mut client,
        "activate-hooks",
        sessions::wire::primitives::WireLifecycleHook {
            on_activate: Some(inline(marker_body(&marker))),
            ..Default::default()
        },
    )
    .await;

    assert!(marker.exists(), "on_activate did not run");
    assert_eq!(
        record_status(&mut client, session_id).await,
        Some(sessions::SessionStatus::Active),
        "a session whose activate hook succeeded should be attachable",
    );
}

/// A successful activate hook's captured output must reach the client
/// over `FinalizeSession`, not just its author-supplied description.
/// The rpc-crate round-trip test proves `RanHook.output` serializes;
/// this proves the daemon actually populates it from the hook outcome,
/// which is what the CLI echoes as the hook's receipt.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn activate_hook_output_reaches_the_client() {
    use crate::test_harness::{create_session_req, unwrap_ready};
    use minimald_rpc::{
        ConfigureLoadout, ConfigureLoadoutRequest, CreateSession, Errorable, FinalizeSession,
        FinalizeSessionRequest,
    };

    let server = TestServer::new().await;
    let mut client = server.connect().await;

    let id = client
        .call::<CreateSession>(&create_session_req("activate-hook-output", "/uwu"))
        .await
        .unwrap()
        .id;
    unwrap_ready(
        client
            .call::<ConfigureLoadout>(&ConfigureLoadoutRequest {
                session_id: id,
                contribution: contribution_with_hook(
                    sessions::wire::primitives::WireLifecycleHook {
                        on_activate: Some(inline("echo HOOK_SAID_HELLO".to_string())),
                        ..Default::default()
                    },
                ),
            })
            .await
            .unwrap(),
    );

    let ran = match client
        .call::<FinalizeSession>(&FinalizeSessionRequest { session_id: id })
        .await
    {
        Errorable::Ok(ok) => ok.activate_hooks,
        Errorable::Err { error } => panic!("FinalizeSession failed: {error}"),
    };

    assert!(
        ran.iter().any(|h| h.output.contains("HOOK_SAID_HELLO")),
        "the captured activate-hook output should reach the client; got: {ran:?}",
    );
}

/// The POSIX form of the per-attach environment the host republishes into
/// the session's home. Empty when nothing has been published yet.
async fn published_attach_env(server: &TestServer, session_id: SessionId) -> String {
    let paths = session_paths(server, session_id).await;
    let path = paths
        .home
        .sub_path_unchecked(".local/state/minimal/attach-env.sh");
    tokio::fs::read_to_string(path.as_str())
        .await
        .unwrap_or_default()
}

/// An attach publishes the terminal it arrived from, so the session shell
/// can pick it up at its next prompt.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn attach_publishes_the_terminal_it_arrived_from() {
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let session_id = create_session(&mut client).await;

    let mut channel = client
        .open_shell_with_term(session_id, "xterm-256color")
        .await;
    await_echo(&mut channel).await;

    let published = published_attach_env(&server, session_id).await;
    assert!(
        published.contains("export TERM='xterm-256color'"),
        "the attaching terminal should be published; got: {published:?}"
    );
}

/// `TERM` is a per-attach fact, not a per-shell one: a client attaching
/// from a different terminal than the one that minted the shell gets its
/// own terminal described, not the previous client's.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reattaching_from_another_terminal_republishes_term() {
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let session_id = create_session(&mut client).await;

    let mut first = client.open_shell_with_term(session_id, "xterm").await;
    await_echo(&mut first).await;
    assert!(
        published_attach_env(&server, session_id)
            .await
            .contains("export TERM='xterm'")
    );

    // Same session, same shell — a different terminal.
    let mut second = client.open_shell_with_term(session_id, "wezterm").await;
    await_echo(&mut second).await;

    let published = published_attach_env(&server, session_id).await;
    assert!(
        published.contains("export TERM='wezterm'"),
        "a re-attach must republish, not keep the minting terminal's TERM; \
             got: {published:?}"
    );
}

/// A client that says nothing about its terminal — OpenSSH sends an empty
/// pty-req term string when its own `TERM` is unset — leaves the last
/// published value standing rather than clearing it. An absent value is
/// not an assertion that there is no terminal, and a session that had a
/// good `TERM` must not lose it to a client that could not describe one.
///
/// This is the case `Session::attach` logs, because on the wire it looks
/// exactly like "nothing changed".
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_attach_with_no_terminal_keeps_the_last_published_one() {
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let session_id = create_session(&mut client).await;

    let mut first = client.open_shell_with_term(session_id, "wezterm").await;
    await_echo(&mut first).await;
    assert!(
        published_attach_env(&server, session_id)
            .await
            .contains("export TERM='wezterm'")
    );

    // Same session, a client with no terminal to declare.
    let mut second = client.open_shell_with_term(session_id, "").await;
    await_echo(&mut second).await;

    let published = published_attach_env(&server, session_id).await;
    assert!(
        published.contains("export TERM='wezterm'"),
        "an attach with no terminal must not clear the last one; got: {published:?}"
    );
}

/// Renaming a running session republishes the new `MINIMAL_SESSION_NAME`
/// through the per-attach environment channel, so the already-running
/// shell picks it up at its next prompt without a restart.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rename_session_republishes_minimal_session_name() {
    use minimald_rpc::{Errorable, RenameSession, RenameSessionRequest, RenameSessionResponse};

    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let session_id = create_session(&mut client).await;

    // Attach so the host is live and the attach-env files exist.
    let mut channel = client.open_shell(session_id).await;
    await_echo(&mut channel).await;

    // Rename the session.
    let resp = client
        .call::<RenameSession>(&RenameSessionRequest {
            id: session_id,
            new_name: "renamed".to_string(),
        })
        .await;
    assert_eq!(resp, Errorable::Ok(RenameSessionResponse));

    // The republished attach-env now carries the new name. The RPC returns
    // once the rename is queued to the host, which publishes afterwards, so
    // poll for the write rather than reading once.
    let mut renamed = String::new();
    for _ in 0..50 {
        renamed = published_attach_env(&server, session_id).await;
        if renamed.contains("export MINIMAL_SESSION_NAME='renamed'") {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(
        renamed.contains("export MINIMAL_SESSION_NAME='renamed'"),
        "the attach-env should carry the new name after rename; got: {renamed:?}"
    );

    // The data form is published too, after the shell form, so poll it the
    // same way.
    let json_path = session_paths(&server, session_id)
        .await
        .home
        .sub_path_unchecked(".local/state/minimal/attach-env.json");
    let mut name = None;
    for _ in 0..50 {
        let body = tokio::fs::read_to_string(json_path.as_str())
            .await
            .unwrap_or_default();
        name = serde_json_lenient::from_str::<serde_json_lenient::Value>(&body)
            .ok()
            .and_then(|v| v["MINIMAL_SESSION_NAME"].as_str().map(str::to_string));
        if name.as_deref() == Some("renamed") {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert_eq!(
        name.as_deref(),
        Some("renamed"),
        "attach-env.json should carry the new name after rename"
    );
}

/// Regression: a session shell minted headlessly — by the activation
/// hooks, with no terminal anywhere in the picture — used to keep that
/// terminal-less environment for the session's whole life, because
/// `TERM` was applied only when the shell was *minted* and every later
/// attach reused the shell. A session whose loadout declared an
/// `on_activate` hook therefore ran with no `TERM` at all, and `less`
/// in it fell back to ncurses' generic `unknown` entry
/// (`'unknown': I need something more specific.`).
///
/// The attaching terminal must win over a shell that was minted without
/// one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_hook_launched_shell_takes_the_attaching_terminals_term() {
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("activated");

    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let session_id = session_with_hook(
        &mut client,
        "hook-then-attach",
        sessions::wire::primitives::WireLifecycleHook {
            on_activate: Some(inline(marker_body(&marker))),
            ..Default::default()
        },
    )
    .await;
    assert!(
        marker.exists(),
        "the activate hook should have brought a host up headlessly"
    );
    assert!(
        published_attach_env(&server, session_id).await.is_empty(),
        "a headless launch has no terminal to describe"
    );

    let mut channel = client
        .open_shell_with_term(session_id, "xterm-256color")
        .await;
    await_echo(&mut channel).await;

    let published = published_attach_env(&server, session_id).await;
    assert!(
        published.contains("export TERM='xterm-256color'"),
        "a hook-launched shell must still take the attaching terminal's \
             TERM; got: {published:?}"
    );
}

/// A failing `on_activate` fails the *activation*: the session does
/// not become attachable, and the error names the hook's source and
/// what it printed. Unlike every other transition, this one is a gate
/// — a development environment whose setup script failed is not the
/// environment that was asked for.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failing_activate_hook_blocks_the_session() {
    use crate::test_harness::create_session_req;
    use minimald_rpc::{
        ConfigureLoadout, ConfigureLoadoutRequest, CreateSession, Errorable, FinalizeSession,
        FinalizeSessionRequest,
    };

    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let id = client
        .call::<CreateSession>(&create_session_req("activate-fails", "/uwu"))
        .await
        .unwrap()
        .id;
    crate::test_harness::unwrap_ready(
        client
            .call::<ConfigureLoadout>(&ConfigureLoadoutRequest {
                session_id: id,
                contribution: contribution_with_hook(
                    sessions::wire::primitives::WireLifecycleHook {
                        on_activate: Some(inline("echo ACTIVATE_SAID_NO >&2; exit 3".to_string())),
                        ..Default::default()
                    },
                ),
            })
            .await
            .unwrap(),
    );

    let error = match client
        .call::<FinalizeSession>(&FinalizeSessionRequest { session_id: id })
        .await
    {
        Errorable::Err { error } => error,
        Errorable::Ok(_) => panic!("finalize should have failed on the activate hook"),
    };
    assert!(
        error.contains("ACTIVATE_SAID_NO"),
        "the error should carry what the hook printed: {error}",
    );
    assert!(
        error.contains("test"),
        "the error should name where the hook was declared: {error}",
    );
    assert!(
        error.contains("exited with status 3"),
        "the error should describe the failure in words: {error}",
    );
    assert!(
        !error.contains("Failed {"),
        "the error should not leak debug formatting: {error}",
    );
    // The gate that matters: not attachable.
    assert_ne!(
        record_status(&mut client, id).await,
        Some(sessions::SessionStatus::Active),
        "a session whose activate hook failed must not be attachable",
    );
}

// `on_attach` has no unit test here, deliberately. It is the one
// transition that runs in the user's shell rather than headlessly, so
// it goes through `Host::hook_plan`, which resolves the sandbox's
// session leader out of `/proc` — and the mock launcher's program is a
// plain childless `/bin/sh`, so there is no leader to find. Faking one
// would need a second test seam in `InjectedCommands` and would then
// prove only that the call happens, not the property the transition
// exists for: that the hook's output reaches the attached terminal.
// The session e2e asserts exactly that, against a real sandbox and a
// real pty ("lifecycle hooks: the four transitions").
//
/// Destroy runs the session's `on_destroy` hooks in the ordinary case:
/// a session with a live host, which the hooks join rather than
/// replace. `DestroySession` answers only once they have run, so the
/// marker is there by the time the call returns — no polling.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn destroy_runs_its_destroy_hooks_against_a_live_host() {
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("destroyed");

    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let session_id = session_with_hook(
        &mut client,
        "destroy-hooks",
        sessions::wire::primitives::WireLifecycleHook {
            on_destroy: Some(inline(marker_body(&marker))),
            ..Default::default()
        },
    )
    .await;

    // Bring a host up and leave it running, so destroy meets the state
    // it has always handled: a session with somewhere to run.
    let manager = server.state.sessions_manager().await;
    let handle = manager
        .get_session(crate::sessions::SessionKeyPredicate::Id(session_id))
        .await
        .unwrap()
        .expect("the session should be retrievable");
    let host = handle
        .ensure_host("tester".to_string())
        .await
        .expect("an Active session should be able to launch a host");
    assert!(host.is_alive());
    drop(handle);

    destroy_session(&mut client, session_id).await;

    assert!(marker.exists(), "destroy did not run its on_destroy hook");
    assert!(
        !record_exists(&mut client, session_id).await,
        "the session record should be gone after a destroy"
    );
}

/// The regression this exists for: a session whose shell has exited
/// still holds a *handle* to a host that can no longer run anything, so
/// destroy has to mint one rather than reuse the corpse. Before the fix
/// the hook came back `NotRun { "session host stopped ..." }` and the
/// session was destroyed silently.
///
/// Drives the reported flow exactly: attach, exit the shell, keep the
/// session at the prompt, then destroy.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn destroy_runs_its_hooks_after_the_session_shell_has_exited() {
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("destroyed");

    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let session_id = session_with_hook(
        &mut client,
        "destroy-after-exit",
        sessions::wire::primitives::WireLifecycleHook {
            on_destroy: Some(inline(marker_body(&marker))),
            ..Default::default()
        },
    )
    .await;

    // Exit the shell and answer the prompt with the default (keep), the
    // way the reported repro does. This is what leaves the stale handle.
    let mut channel = client.open_shell(session_id).await;
    channel
        .data_bytes(format!("{}\n", crate::session_host::MOCK_EXIT_LINE).into_bytes())
        .await
        .unwrap();
    let mut prompt_out = Vec::new();
    let mut answered = false;
    while let Ok(msg) = tokio::time::timeout(Duration::from_secs(10), channel.wait()).await {
        match msg {
            Some(ChannelMsg::Data { data }) => {
                prompt_out.extend_from_slice(&data);
                if !answered
                    && String::from_utf8_lossy(&prompt_out)
                        .contains(crate::session_host::SHELL_EXIT_PROMPT)
                {
                    channel.data_bytes(b"\r".to_vec()).await.unwrap();
                    answered = true;
                }
            }
            Some(_) => {}
            None => break,
        }
    }
    assert!(answered, "expected the session-exit prompt to render");
    assert!(
        record_exists(&mut client, session_id).await,
        "keeping at the prompt must leave the session alive"
    );

    destroy_session(&mut client, session_id).await;

    assert!(
        marker.exists(),
        "destroy skipped its hooks for a session whose shell had exited"
    );
}

/// A session that was never attached has no host at all — the same hole
/// from the other side. Nothing here declares an `on_activate`, so
/// finalize mints nothing and destroy is the first transition that needs
/// a sandbox.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn destroy_runs_its_hooks_for_a_session_that_was_never_attached() {
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("destroyed");

    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let session_id = session_with_hook(
        &mut client,
        "destroy-never-attached",
        sessions::wire::primitives::WireLifecycleHook {
            on_destroy: Some(inline(marker_body(&marker))),
            ..Default::default()
        },
    )
    .await;

    destroy_session(&mut client, session_id).await;

    assert!(
        marker.exists(),
        "destroy skipped its hooks for a session that never had a host"
    );
}

/// A destroy hook that fails is reported, not obeyed: the session is
/// still torn down and its record still deleted, and the destroying
/// client is told which hook failed and how. A session that a bad hook
/// could pin would be unremovable.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failing_destroy_hook_still_destroys_the_session() {
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("destroyed");

    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let session_id = session_with_hook(
        &mut client,
        "destroy-hook-fails",
        sessions::wire::primitives::WireLifecycleHook {
            on_destroy: Some(inline(format!("{}; exit 3", marker_body(&marker)))),
            ..Default::default()
        },
    )
    .await;

    let resp = destroy_session(&mut client, session_id).await;
    assert_eq!(
        resp.hook_failures.len(),
        1,
        "the failed hook should be reported: {:?}",
        resp.hook_failures,
    );
    let failure = &resp.hook_failures[0];
    assert!(
        failure.contains("test"),
        "the report should name where the hook was declared: {failure}",
    );
    assert!(
        failure.contains("exited with status 3"),
        "the report should describe the failure in words: {failure}",
    );

    assert!(marker.exists(), "the hook should still have run");
    assert!(
        !record_exists(&mut client, session_id).await,
        "a failing destroy hook must not keep the session alive"
    );
}

/// Leaving a session that outlives the binding runs its `on_detach`
/// hooks — including on the shell-exit path, where the shell that would
/// once have run them is exactly what has gone away.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn detach_runs_its_detach_hooks_after_the_shell_exits() {
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("detached");

    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let session_id = session_with_hook(
        &mut client,
        "detach-hooks",
        sessions::wire::primitives::WireLifecycleHook {
            on_detach: Some(inline(marker_body(&marker))),
            ..Default::default()
        },
    )
    .await;

    let mut channel = client.open_shell(session_id).await;
    channel
        .data_bytes(format!("{}\n", crate::session_host::MOCK_EXIT_LINE).into_bytes())
        .await
        .unwrap();
    let mut prompt_out = Vec::new();
    let mut answered = false;
    while let Ok(msg) = tokio::time::timeout(Duration::from_secs(10), channel.wait()).await {
        match msg {
            Some(ChannelMsg::Data { data }) => {
                prompt_out.extend_from_slice(&data);
                if !answered
                    && String::from_utf8_lossy(&prompt_out)
                        .contains(crate::session_host::SHELL_EXIT_PROMPT)
                {
                    channel.data_bytes(b"\r".to_vec()).await.unwrap();
                    answered = true;
                }
            }
            Some(_) => {}
            None => break,
        }
    }
    assert!(answered, "expected the session-exit prompt to render");

    // Reported by the departing binding rather than by anything this
    // test called, so it lands shortly after the channel closes.
    assert!(
        await_marker(&marker).await,
        "keeping the session at the exit prompt did not run its detach hooks"
    );
}

/// A session that declares nothing for a transition runs nothing — and
/// in particular is not made to pay for a sandbox launch on the way out.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_session_with_no_destroy_hook_runs_nothing_on_destroy() {
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("should-not-exist");

    let server = TestServer::new().await;
    let mut client = server.connect().await;
    // Declares an `on_attach` only: the composition carries a hook, but
    // not one destroy should reach for.
    let session_id = session_with_hook(
        &mut client,
        "no-destroy-hook",
        sessions::wire::primitives::WireLifecycleHook {
            on_attach: Some(inline(marker_body(&marker))),
            ..Default::default()
        },
    )
    .await;

    destroy_session(&mut client, session_id).await;

    assert!(
        !marker.exists(),
        "destroy ran a hook declared for another transition"
    );
    assert!(!record_exists(&mut client, session_id).await);
}

/// The staged patch's permission bits reach the session home. This
/// is the last hop of the chain that keeps a patched script
/// executable — the uploader puts the source's mode on the tar
/// header, the unpacker applies it to the staged file, and this
/// copy has to carry it the rest of the way.
///
/// Pins the `fs::copy` in [`super::materialize_patches_into_home`]:
/// a hand-rolled read-then-write there would pass this test's
/// content assertions while silently flattening every mode.
#[tokio::test]
async fn materializing_patches_carries_their_modes_into_the_home() {
    use std::os::unix::fs::PermissionsExt as _;

    use paths::{DaemonAbsPath, HostAbsPath, SandboxRelPath};
    use sessions::core::compose::Composition;
    use sessions::wire::primitives::{WireResolvedPatch, WireSessionPatch, WireSource};
    use sessions::wire::request::{COMPOSITION_SNAPSHOT_VERSION, WireComposition};

    let tmp = tempfile::tempdir().unwrap();
    let root = camino::Utf8Path::from_path(tmp.path()).unwrap();
    let patches_dir = root.join("patches");
    let home_dir = root.join("home");
    std::fs::create_dir_all(patches_dir.join(".local/bin").as_std_path()).unwrap();
    std::fs::create_dir_all(home_dir.as_std_path()).unwrap();

    // Two staged patches: one executable, one private. Modes are set
    // on the staged files the way the unpacker sets them.
    let staged = [(".local/bin/tool", 0o755), (".config/secret.toml", 0o600)];
    for (rel, mode) in staged {
        let path = patches_dir.join(rel);
        std::fs::create_dir_all(path.parent().unwrap().as_std_path()).unwrap();
        std::fs::write(path.as_std_path(), b"x").unwrap();
        std::fs::set_permissions(path.as_std_path(), std::fs::Permissions::from_mode(mode))
            .unwrap();
    }

    let composition = Composition::try_from(WireComposition {
        version: COMPOSITION_SNAPSHOT_VERSION,
        vars: Vec::new(),
        patches: staged
            .iter()
            .map(|(rel, _)| WireSessionPatch {
                patch: WireResolvedPatch {
                    // The host path is not read here — the copy
                    // sources from the staged tree, keyed by
                    // destination — but the wire type requires one.
                    host_path: HostAbsPath::try_new(patches_dir.join(rel)).unwrap(),
                    destination: SandboxRelPath::try_new(*rel).unwrap(),
                },
                source: WireSource::UserLoadout {
                    name: "dev".to_string(),
                },
            })
            .collect(),
        packages: Vec::new(),
        lifecycle_hooks: Vec::new(),
        orientation: Default::default(),
    })
    .expect("a patch-only composition converts back");

    super::materialize_patches_into_home(
        &DaemonAbsPath::try_new(patches_dir.clone()).unwrap(),
        &DaemonAbsPath::try_new(home_dir.clone()).unwrap(),
        &composition,
    )
    .await
    .expect("materializing staged patches");

    for (rel, mode) in staged {
        let meta = std::fs::metadata(home_dir.join(rel).as_std_path())
            .unwrap_or_else(|e| panic!("`{rel}` should have landed in the home: {e}"));
        assert_eq!(
            meta.permissions().mode() & 0o7777,
            mode,
            "`{rel}` lost its mode on the way into the session home",
        );
    }
}

// ---- a box outlives its client (NET-015) -----------------------------
//
// A box runs from activation until destroy whether or not a client is
// attached. Three observations, one per clause: a running box with no
// client anywhere keeps running; a client lost *abruptly* mid-attach
// changes nothing about the entrypoint; and no idle interval ever stops
// a box — stop is always something a client asked for.

/// A whole `Server::run` daemon on a real UDS in `dir`, spawned for the
/// caller, alongside the socket path clients dial. The in-memory
/// [`TestServer::connect`] harness discards the connection task's outcome,
/// so the connection-level lines the accept loop logs — the client-loss
/// record — never reach a capture wired to it; a test that asserts on
/// them drives the real loop, the way `server`'s own tests do.
async fn spawn_run_server(
    dir: &tempfile::TempDir,
) -> (
    tokio::task::JoinHandle<Result<(), std::io::Error>>,
    std::path::PathBuf,
) {
    let sock = dir.path().join("minimald.sock");
    let listener = tokio::net::UnixListener::bind(&sock).unwrap();
    let run = tokio::spawn(crate::server::Server::run(
        crate::server::test_config(dir.path()),
        listener,
        None,
    ));
    (run, sock)
}

/// NET-015: a box keeps running whether or not a client is attached.
///
/// The box here is a headless one — `ensure_host` launches its
/// entrypoint with nobody attached, the closed-laptop state — and the
/// only client connection that ever existed is dropped outright. The
/// shell keeps running (`is_alive` on the handle minted before the
/// drop), and a brand-new client can attach and drive it. Nothing about
/// the entrypoint depended on its creator's connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn box_survives_without_client() {
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let session_id = create_session(&mut client).await;

    // Launch the entrypoint with no client attached.
    let manager = server.state.sessions_manager().await;
    let handle = manager
        .get_session(crate::sessions::SessionKeyPredicate::Id(session_id))
        .await
        .unwrap()
        .expect("session should resolve");
    let host = handle
        .ensure_host("tester".to_string())
        .await
        .expect("an Active session should be able to launch a headless host");
    assert!(host.is_alive());

    // The only client connection ever is gone, abruptly.
    drop(client);

    // The box neither noticed nor stopped.
    assert!(host.is_alive(), "the headless shell must keep running");

    // A later attach lands on it and drives the same shell.
    let mut fresh = server.connect().await;
    let mut shell = fresh.open_shell(session_id).await;
    await_echo(&mut shell).await;
    assert!(
        host.is_alive(),
        "the later attach must land on the pre-drop host, not a relaunched one",
    );

    assert_eq!(
        record_status(&mut fresh, session_id).await,
        Some(sessions::SessionStatus::Active),
        "a box that outlived its client is still an Active record",
    );
}

/// NET-015, lost-client clause: the attached client of a PTY box dies
/// abruptly and the box's entrypoint keeps running, accepting a later
/// attach — which finds the *same* shell, its pre-loss terminal state
/// flushed on connect. A relaunched entrypoint would have an empty
/// screen; seeing `got:hello` is the proof the old one never stopped.
///
/// Driven through a real `Server::run` accept loop so the connection's
/// own close is logged the way the daemon logs it: the client-loss info
/// line a diagnostic bundle's log tail reads the hang-up from.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn abrupt_client_loss_keeps_task() {
    use crate::test_harness::connect_uds;

    let capture = crate::test_harness::captured_log();

    let dir = tempfile::tempdir().unwrap();
    let (run, sock) = spawn_run_server(&dir).await;

    let mut client = connect_uds(&sock).await;
    let session_id = create_session(&mut client).await;

    // Attach and drive the shell, so the terminal state holds
    // `got:hello` when the client is lost.
    let mut shell = client.open_shell(session_id).await;
    await_echo(&mut shell).await;

    // The client dies without a farewell: the channel and the connection
    // both go with it.
    drop(shell);
    drop(client);

    // The daemon logs the loss as what it is, not as an incident.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let logged = capture.contents();
        if logged.contains("connection closed by peer") {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the daemon must log the abrupt client loss, got: {logged}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    // A brand-new client attaches and finds the entrypoint still running:
    // the pre-loss terminal state is flushed to it...
    let mut fresh = connect_uds(&sock).await;
    let mut shell = fresh.open_shell(session_id).await;
    let flushed = recv_until(&mut shell, "got:hello").await;
    assert!(
        flushed.contains("got:hello"),
        "the later attach must see the same shell's earlier output, got: {flushed:?}"
    );

    // ...and the shell answers as itself.
    shell.data_bytes(b"ping\n".to_vec()).await.unwrap();
    let echoed = recv_until(&mut shell, "got:ping").await;
    assert!(
        echoed.contains("got:ping"),
        "the shell the lost client left running must still answer, got: {echoed:?}"
    );

    assert_eq!(
        record_status(&mut fresh, session_id).await,
        Some(sessions::SessionStatus::Active),
    );

    use minimald_rpc::{Shutdown, ShutdownRequest};
    let _ = fresh
        .call::<Shutdown>(&ShutdownRequest { force: false })
        .await;
    drop(fresh);
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), run).await;
}

/// NET-015, stop-policy clause: a box stops only when its client asks,
/// when its entrypoint exits, when the run it was created for ends, or
/// when the host tears it down by force — never because it sat idle.
///
/// The box is detached by its client's own chord (the only kind of
/// departure that leaves a session outliving its binding), then left
/// with no client anywhere for an idle window. Any idle stop faster
/// than the window would have fired; the daemon defines none at all, and
/// the window's close finds the entrypoint still answering. The stop
/// paths' log lines are asserted absent, not just the outcome — a silent
/// kill would otherwise pass as a healthy idle.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn box_has_no_idle_stop() {
    let server = TestServer::new().await;
    let capture = crate::test_harness::captured_log();

    let mut client = server.connect().await;
    let session_id = create_configured_session(&mut client, "idle-stop-test", "/uwu").await;

    // Attach, drive, then detach by the client's own chord.
    let mut shell = client.open_shell(session_id).await;
    await_echo(&mut shell).await;
    shell.data_bytes(vec![0x1d]).await.unwrap();
    shell.data_bytes(vec![b'd']).await.unwrap();
    let detach_out = collect_to_close(&mut shell).await;
    assert!(
        detach_out.contains("Detaching from session."),
        "expected a detach notice before the channel closed, got: {detach_out:?}"
    );

    // The departure is logged, naming the session — the detach line the
    // diagnostic bundle reads.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let logged = capture.contents();
        let detach_line = logged
            .lines()
            .find(|line| {
                line.contains("binding leaving mainloop") && line.contains("idle-stop-test")
            })
            .map(str::to_string);
        if let Some(line) = detach_line {
            assert!(
                line.contains("Detach"),
                "the binding's exit must be logged as a detach, got: {line}"
            );
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the daemon must log the binding's detach, naming the session, got: {logged}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    // Idle: no client attached to anything. Five seconds — every daemon
    // timer that could plausibly reap an idle box would have fired, and
    // none is defined in the first place.
    drop(client);
    tokio::time::sleep(Duration::from_secs(5)).await;

    // The box is exactly where the client left it.
    let manager = server.state.sessions_manager().await;
    let handle = manager
        .get_session(crate::sessions::SessionKeyPredicate::Id(session_id))
        .await
        .unwrap()
        .expect("session should resolve");
    assert!(
        handle.get_attrs().await.is_some(),
        "an idle box's entrypoint must still be running"
    );
    assert_eq!(
        record_status(&mut server.connect().await, session_id).await,
        Some(sessions::SessionStatus::Active),
    );

    // And none of the stop paths' lines is in the log for this session.
    // Scoped to lines naming it (by name, or by id for the reap line, which
    // carries no name): under libtest the buffer is shared with neighbours.
    let session_str = session_id.to_string();
    let logged: String = capture
        .contents()
        .lines()
        .filter(|line| line.contains("idle-stop-test") || line.contains(&session_str))
        .map(|line| format!("{line}\n"))
        .collect();
    for stop_line in [
        "session host killed on request",
        "session process exited; reaped by the host loop",
        "run box ended",
        "reaped unfinalized session after its connection closed",
    ] {
        assert!(
            !logged.contains(stop_line),
            "an idle box must not be stopped, but the log carries {stop_line:?}:\n{logged}"
        );
    }
}

/// An Ethernet II frame carrying an IPv4 packet to `dst` under `proto`, with
/// `dst_port` where the L4 header has one — the shape
/// [`sessions::core::egress::summarize`] extracts a verdict's inputs from.
/// Everything the verdict reads is filled in; the unread fields are zeroes.
fn ipv4_frame(proto: u8, dst: [u8; 4], dst_port: u16) -> Vec<u8> {
    let mut f = Vec::new();
    f.extend_from_slice(&[0x52, 0x54, 0x00, 0x00, 0x00, 0x01]); // dst MAC
    f.extend_from_slice(&[0x52, 0x54, 0x00, 0x00, 0x00, 0x02]); // src MAC
    f.extend_from_slice(&0x0800u16.to_be_bytes()); // EtherType: IPv4
    // IPv4 header, IHL = 5 (20 bytes), fragment offset 0.
    f.push(0x45);
    f.push(0x00);
    f.extend_from_slice(&40u16.to_be_bytes()); // total length (unread)
    f.extend_from_slice(&0u16.to_be_bytes()); // identification
    f.extend_from_slice(&0u16.to_be_bytes()); // flags + fragment offset
    f.push(64); // TTL
    f.push(proto);
    f.extend_from_slice(&0u16.to_be_bytes()); // header checksum (unread)
    f.extend_from_slice(&[10, 0, 0, 5]); // src: the box itself
    f.extend_from_slice(&dst);
    // L4 header: enough of one for the port to be readable.
    f.extend_from_slice(&40000u16.to_be_bytes()); // src port
    f.extend_from_slice(&dst_port.to_be_bytes());
    f.extend_from_slice(&[0u8; 12]); // seq/ack (unread)
    f
}

/// NET-074: an own-address box created with no `egress` section reaches
/// nothing outside itself, once the deny-all default is in force. The phase
/// is passed explicitly — this build ships the default as announced
/// (NET-076), so the in-force posture is proven by name, not by whatever
/// the shipped constant happens to be — and the launcher's gate policy under
/// it is the deny-all section, whose compiled rules drop every external
/// destination in every transport, while the resolver Minimal owns for the
/// box still answers, at its address *and* its port (NET-079). The
/// session-start line names the phase, the opt-out, and the posture this
/// build actually leaves in force, so a diagnostics bundle's log tail can
/// say why the box reaches what it does.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn own_ip_default_deny_all() {
    use minimald_rpc::{CreateSession, CreateSessionRequest};
    use sessions::core::egress::{EgressRules, FrameVerdict};

    // The address of the resolver Minimal owns for a box: the switch
    // gateway, as the relay hands it to the gate.
    let resolver = [100, 64, 0, 1];
    // Something the box did not declare: an address out in the world.
    let external = [93, 184, 216, 34];
    // The box's lease — the source address `ipv4_frame` writes, so the
    // verdicts below turn on the egress dimension alone. The lease check
    // itself (NET-084) is proven in `sessions::core::egress`.
    let lease = [10, 0, 0, 5];

    // The launcher's resolution for an own-address box that declared
    // nothing, once the default is in force: the deny-all section, egress
    // only touched, ingress kept.
    let declared = sessions::SessionPolicy::default();
    let effective = super::effective_session_policy(
        &declared,
        sessions::NetworkMode::OwnIp,
        sessions::EgressDefaultPhase::InForce,
        false,
    );
    assert_eq!(
        effective.egress,
        Some(sessions::EgressPolicy::deny_all()),
        "the gate's egress for an absent section is the deny-all section",
    );
    assert_eq!(effective.ingress, None);

    // What that section enforces: every frame to an external address drops,
    // in every transport — the carve-out excepted, keyed to both the
    // resolver's address and DNS's port, so no other address at :53 and no
    // other port on the resolver slips through.
    let rules = EgressRules::from_policy(effective.egress.as_ref(), resolver, lease);
    let verdict_on = |proto: u8, dst: [u8; 4], port: u16| {
        sessions::core::egress::verdict(
            &sessions::core::egress::summarize(&ipv4_frame(proto, dst, port)),
            &rules,
        )
    };
    for (proto, name) in [(6u8, "tcp"), (17, "udp"), (1, "icmp")] {
        assert!(
            matches!(verdict_on(proto, external, 443), FrameVerdict::Drop(_)),
            "a deny-all box must not reach an external address over {name}",
        );
    }
    assert!(
        matches!(verdict_on(17, external, 53), FrameVerdict::Drop(_)),
        "the carve-out is keyed to the resolver's address: DNS's port alone \
         admits nothing",
    );
    assert!(
        matches!(verdict_on(17, resolver, 54), FrameVerdict::Drop(_)),
        "the carve-out is keyed to DNS's port: the resolver's address alone \
         admits nothing",
    );
    assert!(
        matches!(verdict_on(17, resolver, 53), FrameVerdict::Admit),
        "a deny-all box must still resolve (NET-079)",
    );

    // The same posture, observed where a diagnostics bundle reads it: the
    // one line every session start logs, naming all three facts as this
    // build ships them — the rollout phase it is in, the opt-out the daemon
    // was started with, and the egress they leave this bare box with. The
    // values follow the shipped constant, so a phase flip keeps this
    // assertion honest about whatever the flip leaves in force.
    let capture = crate::test_harness::captured_log();
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    client
        .call::<CreateSession>(&CreateSessionRequest {
            config: minimald_rpc::SessionConfig {
                name: Some("own-ip-bare".to_string()),
                project_path: paths::HostAbsPath::try_new("/uwu").unwrap(),
                network: sessions::NetworkMode::OwnIp,
                policy: sessions::SessionPolicy::default(),
                box_addresses: None,
                hooks_enabled: true,
                attrs: Default::default(),
            },
            must_match_version: None,
        })
        .await
        .unwrap();
    let logged = capture.contents();
    let start_line = logged
        .lines()
        .find(|line| line.contains("session starts") && line.contains("own-ip-bare"))
        .unwrap_or_else(|| panic!("the session start must be logged, got: {logged}"));
    for fact in [
        format!("egress_default_phase={:?}", sessions::EGRESS_DEFAULT_PHASE),
        "deny_all_opt_out=false".to_string(),
        format!(
            "effective_egress={:?}",
            sessions::effective_egress(
                None,
                sessions::NetworkMode::OwnIp,
                sessions::EGRESS_DEFAULT_PHASE,
                false
            )
        ),
    ] {
        assert!(
            start_line.contains(&fact),
            "the start line must name {fact}, got: {start_line}",
        );
    }
}

// ---------------------------------------------------------------------------
// Per-box loopback addresses and the name's finalize-to-destroy lifecycle
// (NET-010 to NET-013)
// ---------------------------------------------------------------------------

/// An own-address session's config: a box that declares one published port —
/// the ingress a publish is made of (NET-010) — under the session `name`.
fn own_ip_session_req(name: &str) -> minimald_rpc::CreateSessionRequest {
    minimald_rpc::CreateSessionRequest {
        config: minimald_rpc::SessionConfig {
            name: Some(name.to_string()),
            project_path: paths::HostAbsPath::try_new("/uwu").unwrap(),
            network: sessions::NetworkMode::OwnIp,
            policy: sessions::SessionPolicy {
                egress: None,
                ingress: Some(sessions::IngressPolicy {
                    port_mappings: vec![sessions::PortMapping {
                        external_port: 18080,
                        internal_port: 80,
                        proto: sessions::IpProto::Tcp,
                    }],
                    ..Default::default()
                }),
                credentialed_upstream: None,
            },
            box_addresses: None,
            hooks_enabled: true,
            attrs: Default::default(),
        },
        must_match_version: None,
    }
}

/// The same request with the hand a real creator sends: the registration's
/// `box_addresses` row names the box's switch lease and the host loopback
/// address its publishes bind — the T66 hand — which under the hand model
/// (NET-010/NET-011) is the only way a box gets a published address. A
/// request that hands nothing publishes nothing and registers no name.
fn own_ip_handed_session_req(
    name: &str,
    switch: std::net::Ipv4Addr,
    loopback: std::net::Ipv4Addr,
) -> minimald_rpc::CreateSessionRequest {
    let mut request = own_ip_session_req(name);
    request.config.box_addresses = Some(sessions::BoxAddresses {
        switch_address: switch,
        loopback_address: loopback,
    });
    request
}

/// Drives Create → ConfigureLoadout → FinalizeSession for an own-address box
/// and returns its id. No attach ever happens along the way: the box is
/// finalised and its name registered while no client has connected — the
/// condition NET-013 answers under.
async fn finalize_own_ip_session(client: &mut TestClient, name: &str) -> SessionId {
    let id = create_own_ip_session(client, name).await;
    finalize_session(client, id).await;
    id
}

/// The finalize above, for a box whose creator handed it an address: the
/// hand rides the create, and finalize publishes and registers at exactly
/// it (NET-011's hand model).
async fn finalize_handed_own_ip_session(
    client: &mut TestClient,
    name: &str,
    switch: std::net::Ipv4Addr,
    loopback: std::net::Ipv4Addr,
) -> SessionId {
    let id = create_handed_own_ip_session(client, name, switch, loopback).await;
    finalize_session(client, id).await;
    id
}

/// The FinalizeSession step of the helpers above, on its own — for the
/// tests that send it from a second connection while the daemon's
/// registration waits on the range verdict, so the walk can land inside
/// that bounded wait (NET-123 §7.1).
async fn finalize_session(client: &mut TestClient, id: SessionId) {
    use minimald_rpc::{Errorable, FinalizeSession, FinalizeSessionRequest};
    match client
        .call::<FinalizeSession>(&FinalizeSessionRequest { session_id: id })
        .await
    {
        Errorable::Ok(_) => {}
        Errorable::Err { error } => panic!("FinalizeSession failed: {error}"),
    }
}

/// Drives Create → ConfigureLoadout for an own-address box nobody handed
/// an address, leaving the finalize to the caller. Split from
/// [`finalize_own_ip_session`] for the tests that drive the finalize
/// against a landing's timing.
async fn create_own_ip_session(client: &mut TestClient, name: &str) -> SessionId {
    use minimald_rpc::{ConfigureLoadout, ConfigureLoadoutRequest, CreateSession};
    let id = client
        .call::<CreateSession>(&own_ip_session_req(name))
        .await
        .unwrap()
        .id;
    crate::test_harness::unwrap_ready(
        client
            .call::<ConfigureLoadout>(&ConfigureLoadoutRequest {
                session_id: id,
                contribution: Default::default(),
            })
            .await
            .unwrap(),
    );
    id
}

/// [`create_own_ip_session`], for a box whose creator handed it an address:
/// the hand rides the create, and the finalize the caller drives publishes
/// and registers at exactly it (NET-011's hand model).
async fn create_handed_own_ip_session(
    client: &mut TestClient,
    name: &str,
    switch: std::net::Ipv4Addr,
    loopback: std::net::Ipv4Addr,
) -> SessionId {
    use minimald_rpc::{ConfigureLoadout, ConfigureLoadoutRequest, CreateSession};
    let id = client
        .call::<CreateSession>(&own_ip_handed_session_req(name, switch, loopback))
        .await
        .unwrap()
        .id;
    crate::test_harness::unwrap_ready(
        client
            .call::<ConfigureLoadout>(&ConfigureLoadoutRequest {
                session_id: id,
                contribution: Default::default(),
            })
            .await
            .unwrap(),
    );
    id
}

/// Waits until a registration is parked on the range verdict, so the
/// landing a test makes next provably answers a waiter rather than a
/// registration that has not yet begun to wait (NET-123 §7.1).
#[cfg(target_os = "linux")]
async fn await_verdict_waiter(manager: &crate::sessions::ManagerHandle) {
    for _ in 0..12_000 {
        if manager.verdict_waiters() >= 1 {
            return;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    panic!("no registration began to wait on the range verdict");
}

/// The A answer a live box's name carries, and the session that owns it —
/// `None` when the name is absent (NXDOMAIN, NET-125).
async fn zone_answer_for(server: &TestServer, name: &str) -> Option<(String, std::net::Ipv4Addr)> {
    let registry = server.state.sessions_manager().await.hostnames();
    match registry
        .read()
        .expect("registry lock")
        .zone_entry(name, &[])
    {
        crate::net::dns::ZoneEntry::Held { owner, address } => Some((
            owner,
            address.expect("a live box's name answers with an A record"),
        )),
        crate::net::dns::ZoneEntry::Absent => None,
    }
}

/// Whether `addr` falls inside the reserved local range a published box's own
/// address is leased from (NET-010): the design's `127.0.64.0/24`, read from
/// the one definition the allocator carves rather than restated as literals —
/// so the assertion below follows the range if the design moves it again.
fn in_reserved_local_range(addr: std::net::Ipv4Addr) -> bool {
    let (network, prefix) = sessions::core::loopback::RESERVED_LOCAL_RANGE;
    let mask = u32::MAX << (32 - u32::from(prefix));
    u32::from(network) & mask == u32::from(addr) & mask
}

/// NET-011: a session's finalisation is what registers its box's
/// `<name>.min.internal` — the reply to `FinalizeSession` comes back with the
/// name already held, at the address the box's creator handed it, and the
/// publish is the registry's record of that same hand: the two surfaces that
/// must agree (the route a proxy follows and the address a resolver answers)
/// name one address. A creator that hands nothing still publishes — at the
/// answerer's grant, the shape the test below this one drives — so no
/// surface here chooses an address on the box's behalf: the hand or the
/// grant names it, and both are said out loud. The registration is in the
/// daemon log, naming the box and the address — the line a diagnostics
/// bundle's log tail carries.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn name_registered_at_finalize() {
    // The hand a real creator sends: a switch lease and the reserved-range
    // loopback address the box's publishes bind.
    let handed = std::net::Ipv4Addr::new(127, 0, 64, 9);
    let switch = std::net::Ipv4Addr::new(100, 64, 128, 9);
    let capture = crate::test_harness::captured_log();
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let id = finalize_handed_own_ip_session(&mut client, "web", switch, handed).await;

    // No attach has happened — the name is held at the handed address.
    let (owner, address) = zone_answer_for(&server, "web.min.internal")
        .await
        .expect("the name is held at finalize");
    assert_eq!(owner, "web", "the session owns its box name");
    assert_eq!(
        address, handed,
        "the name answers at the address the creator handed, exactly"
    );
    assert!(
        in_reserved_local_range(address),
        "the handed address comes from the reserved local range, got {address}"
    );

    // The registry's publish and the zone's answer are one address — the two
    // halves of the same publish (NET-010) cannot disagree.
    let registry = server.state.sessions_manager().await.hostnames();
    assert_eq!(
        registry
            .read()
            .expect("registry lock")
            .published_own_address(id),
        Some(address),
        "the address the name answers at is the one the finalize published"
    );

    // The registration is said out loud, naming the box and the address.
    let logged = capture.contents();
    let registered_line = logged
        .lines()
        .find(|line| {
            line.contains("registered PTask hostname") && line.contains(&format!("session_id={id}"))
        })
        .unwrap_or_else(|| panic!("the registration must be logged, got: {logged}"));
    assert!(
        registered_line.contains(&format!("ip={address}")),
        "the registration line names the handed address, got: {registered_line}"
    );
}

/// NET-011's other half, at the session level: a box nobody handed an
/// address — a native launch, whose creator is the daemon itself (NET-040:
/// a fresh install's `--network own_ip --ingress` publishes on the host) —
/// publishes at the address the answerer's record granted it. Finalize
/// still asks the host-global allocation (NET-010: arbitrated through the
/// answerer's authenticated channel, never a daemon's own choice): the name
/// is held from finalize, at the granted address, the route and the zone
/// answer name one address, and the publish is recorded for the attach path
/// to bind its forwards at. The withheld-grant shapes a fault makes — a
/// spent pool, an unreadable record — register no name and fail the attach
/// with "no published address handed" (proved in the gvproxy network
/// proofs); the shapes the host's publish surface makes — an absent range,
/// a verdict still walking — publish the box on the `127.0.0.1` interim
/// (NET-123), which the dns proofs pin beside the hand's verdict gate.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_box_nobody_handed_an_address_publishes_at_the_answerers_grant() {
    let capture = crate::test_harness::captured_log();
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let id = finalize_own_ip_session(&mut client, "web").await;

    // No attach has happened — the name is held at the granted address.
    let (owner, address) = zone_answer_for(&server, "web.min.internal")
        .await
        .expect("a box nobody handed an address publishes at the grant");
    assert_eq!(owner, "web", "the session owns its box name");
    assert_eq!(
        address,
        sessions::core::loopback::POOL_FIRST,
        "an empty record's first grant is the pool's first address, got {address}"
    );
    assert!(
        in_reserved_local_range(address),
        "the granted address comes from the reserved local range, got {address}"
    );

    // The registry's publish and the zone's answer are one address — and the
    // publish is what the attach path will read to bind its forwards at.
    let registry = server.state.sessions_manager().await.hostnames();
    let routes = registry.read().expect("registry lock");
    assert_eq!(
        routes.published_own_address(id),
        Some(address),
        "the publish the attach path binds forwards at is the grant"
    );
    let route = routes
        .resolve("web.min.internal")
        .expect("the name routes at the grant");
    assert_eq!(
        route.address(),
        address,
        "the route a proxy follows answers at the granted address, exactly"
    );

    // The grant is said out loud, naming the box and the address.
    let logged = capture.contents();
    let lease_line = logged
        .lines()
        .find(|line| {
            line.contains("action=\"loopback-lease\"") && line.contains(&format!("session_id={id}"))
        })
        .unwrap_or_else(|| panic!("the lease must be logged, got: {logged}"));
    assert!(
        lease_line.contains(&format!("ip={address}")),
        "the lease line names the address it granted, got: {lease_line}"
    );
}

/// NET-010, runtime half: two own-address boxes that declare the *same* port
/// are each handed a host loopback address of their own — the registration's
/// rows hand from the reserved local range, one per box — so both publish, at
/// their own addresses and their own port numbers, never translated, where
/// one loopback address would have made the second box's port a collision.
/// NET-129's sub-requirement (report, don't translate) covers the boxes that
/// *do* share an address; this is the case the shared-address mode exists to
/// avoid.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn each_box_gets_own_loopback_address() {
    let alpha_handed = std::net::Ipv4Addr::new(127, 0, 64, 9);
    let beta_handed = std::net::Ipv4Addr::new(127, 0, 64, 10);
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let _alpha = finalize_handed_own_ip_session(
        &mut client,
        "alpha",
        std::net::Ipv4Addr::new(100, 64, 128, 9),
        alpha_handed,
    )
    .await;
    let _beta = finalize_handed_own_ip_session(
        &mut client,
        "beta",
        std::net::Ipv4Addr::new(100, 64, 128, 10),
        beta_handed,
    )
    .await;

    let (_, alpha_address) = zone_answer_for(&server, "alpha.min.internal")
        .await
        .expect("alpha's name is held");
    let (_, beta_address) = zone_answer_for(&server, "beta.min.internal")
        .await
        .expect("beta's name is held");
    assert_ne!(
        alpha_address, beta_address,
        "two live boxes on one daemon must never share a loopback address"
    );
    for (name, address) in [("alpha", alpha_address), ("beta", beta_address)] {
        assert!(
            in_reserved_local_range(address),
            "{name}'s address comes from the reserved local range, got {address}"
        );
    }

    // The same declared port is published at both addresses at the port
    // number each box asked for — no translation, no remap around the pair.
    let registry = server.state.sessions_manager().await.hostnames();
    let routes = registry.read().expect("registry lock");
    for (name, address) in [("alpha", alpha_address), ("beta", beta_address)] {
        let route = routes
            .resolve(&format!("{name}.min.internal"))
            .unwrap_or_else(|| panic!("{name}'s name routes"));
        assert_eq!(
            route.upstream(18080),
            Some(std::net::SocketAddr::new(
                std::net::IpAddr::V4(address),
                18080
            )),
            "{name}'s own port number is published at its own address, not translated"
        );
        assert_eq!(
            route.upstream(9000),
            None,
            "a port outside {name}'s declaration routes nowhere"
        );
    }
}

/// NET-010's cross-record collision report, at the moment the design puts it
/// (design §7.1: cross-node collisions are reported at session start, like a
/// port collision). The daemon's own start takes the same report once, over
/// whatever was live before it came up; this is the half that catches a
/// publish a second state root's daemon made **after** this one booted, which
/// no report this daemon ran at its start can ever see again. The stand-in
/// for that second root's publish is a live listener at an address this
/// daemon's record never names — the shape no `EADDRINUSE` ever reports,
/// because the collision is on the address, not a port — bound here *after*
/// the daemon has started, so the report that names it below can only be the
/// session's.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_session_start_reports_a_publish_no_grant_names() {
    let handed = std::net::Ipv4Addr::new(127, 0, 64, 9);
    let capture = crate::test_harness::captured_log();
    let server = TestServer::new().await;
    let mut client = server.connect().await;

    // The range's last address: inside the reserved slice, so nothing rules
    // it out on shape, and not one this daemon's empty record has named — a
    // second root's publish, as the kernel's socket table sees it.
    let foreign = sessions::core::loopback::POOL_LAST;
    let _listener = std::net::TcpListener::bind((foreign, 0))
        .unwrap_or_else(|error| panic!("the unrecorded address binds: {error}"));

    // Everything the buffer holds here predates the box, so a line naming
    // the address in what follows is the session-start report's — the
    // daemon-start report ran at `TestServer::new`, before the bind.
    let before_finalize = capture.contents().len();
    let _web = finalize_handed_own_ip_session(
        &mut client,
        "web",
        std::net::Ipv4Addr::new(100, 64, 128, 9),
        handed,
    )
    .await;
    let logged = &capture.contents()[before_finalize..];
    assert!(
        logged.lines().any(|line| {
            line.contains("loopback-publish-collision") && line.contains(&format!("ip={foreign}"))
        }),
        "a session start must report the live publish no record names: {logged}"
    );

    // And the box itself is untouched by the report: it is advisory, so the
    // box published at the address its hand named, as though the other root
    // were not there.
    let (_, address) = zone_answer_for(&server, "web.min.internal")
        .await
        .expect("the box's name answers at its own address");
    assert_eq!(
        address, handed,
        "the collision report costs the box nothing: its hand stands"
    );
}

/// NET-013: a box's name answers whether or not a client is attached. The
/// finalize above attached nothing; the answer here is a full A record at the
/// box's own address — held, in-zone, at the port the box declared — and the
/// route a request follows reaches the same address at the same port, so a
/// client that resolves the name and one that connects through the hostname
/// proxy are told one and the same place.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn name_answers_without_attached_client() {
    let handed = std::net::Ipv4Addr::new(127, 0, 64, 9);
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let _id = finalize_handed_own_ip_session(
        &mut client,
        "web",
        std::net::Ipv4Addr::new(100, 64, 128, 9),
        handed,
    )
    .await;

    // No attach: the zone answers A, not NODATA and not NXDOMAIN.
    let (_, address) = zone_answer_for(&server, "web.min.internal")
        .await
        .expect("the name answers with no client");

    // And the routing half says the same address at the box's own port.
    let registry = server.state.sessions_manager().await.hostnames();
    let route = registry
        .read()
        .expect("registry lock")
        .resolve("web.min.internal:18080")
        .expect("the name routes with no client attached");
    assert_eq!(
        route.upstream(18080),
        Some(std::net::SocketAddr::new(
            std::net::IpAddr::V4(address),
            18080
        )),
        "a request for the box's declared port is forwarded to the box's own address"
    );
}

/// NET-012: destroying the box is what ends the name. Every later lookup
/// answers NXDOMAIN — held while the box existed (NET-013), absent the moment
/// it is destroyed — and the publish goes with the name: the address was the
/// host-side creator's to take back, not this daemon's pool to release
/// (NET-010), so destroy withdraws the registry's record of it and nothing
/// answers at it again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn destroyed_box_name_is_nxdomain() {
    let handed = std::net::Ipv4Addr::new(127, 0, 64, 9);
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let id = finalize_handed_own_ip_session(
        &mut client,
        "web",
        std::net::Ipv4Addr::new(100, 64, 128, 9),
        handed,
    )
    .await;
    let (_, address) = zone_answer_for(&server, "web.min.internal")
        .await
        .expect("the name answers while the box lives");
    assert_eq!(
        address, handed,
        "the box's name answers at the hand while it lives"
    );

    use minimald_rpc::{DestroySession, DestroySessionRequest, Errorable};
    match client
        .call::<DestroySession>(&DestroySessionRequest { id })
        .await
    {
        Errorable::Ok(_) => {}
        Errorable::Err { error } => panic!("DestroySession failed: {error}"),
    }

    // The name is gone: a later lookup is told NXDOMAIN, not a stale address.
    assert_eq!(
        zone_answer_for(&server, "web.min.internal").await,
        None,
        "a destroyed box's name must answer NXDOMAIN"
    );
    let registry = server.state.sessions_manager().await.hostnames();
    let routes = registry.read().expect("registry lock");
    assert_eq!(
        routes.resolve("web.min.internal"),
        None,
        "and nothing routes to a destroyed box"
    );
    assert_eq!(
        routes.published_own_address(id),
        None,
        "the publish is withdrawn with the name: no later session, and no \
         later name, answers at the destroyed box's address"
    );
}

/// NET-128 session path: a shared-address box stopped through the actor
/// answers NODATA, not NXDOMAIN — the name stays held, so the zone never
/// says the box never existed, but the node's own listener at that port
/// must not answer for a dead box. The existing unit test
/// `stopped_shared_address_box_is_nodata` calls `mark_stopped` directly;
/// this test drives the actor's Stop path end-to-end.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stopped_shared_address_box_is_nodata_through_actor() {
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let manager = server.state.sessions_manager().await;
    manager.land_range_verdict(crate::net::dns::RangeVerdict::Present);
    // The NODATA gate in zone_answer requires the box's address to equal the
    // node's address (NET-128). After the verdict lands, the node address is
    // the granted address from the loopback lease book — use it as the shared
    // address so the stopped box triggers the NODATA path.
    let shared = manager
        .hostnames()
        .read()
        .expect("registry lock")
        .node_address();
    let id = finalize_handed_own_ip_session(
        &mut client,
        "sharedbox",
        std::net::Ipv4Addr::new(100, 64, 128, 9),
        shared,
    )
    .await;

    // The name answers while the box runs.
    let (_, address) = zone_answer_for(&server, "sharedbox.min.internal")
        .await
        .expect("the name answers while the box runs");
    assert_eq!(
        address, shared,
        "the box's name answers at the shared address while it runs"
    );

    // Stop the box through the actor — the path the issue reports.
    let handle = manager
        .get_session(crate::sessions::SessionKeyPredicate::Id(id))
        .await
        .unwrap()
        .expect("the box resolves while it runs");
    handle.stop().await;

    // The name is still held (not NXDOMAIN) but answers NODATA — the
    // shared-address box is stopped, so the node's own listener at that
    // port must not answer for a dead box.
    let registry = server.state.sessions_manager().await.hostnames();
    let entry = registry
        .read()
        .expect("registry lock")
        .zone_entry("sharedbox.min.internal", &[]);
    assert_eq!(
        entry,
        crate::net::dns::ZoneEntry::Held {
            owner: "sharedbox".to_string(),
            address: None,
        },
        "a stopped shared-address box answers NODATA, not NXDOMAIN"
    );
}

/// NET-010's durability half (design §7.1): the hand is the record's row,
/// not the daemon's memory — a creator wrote the box's addresses into the
/// session's record at create, and the registry's publish is derived from
/// it — so a daemon that restarts re-derives its live boxes' published
/// addresses from the record rather than starting from an empty table. The
/// restarted daemon below adopts nothing by itself: a box's resumed session
/// asks again the moment its actor comes up, and the record answers with
/// the address it already holds, so the box's name answers at the same
/// address from before the restart to long after it, from finalize to
/// destroy (NET-011), with no client ever attached (NET-013).
///
/// The restart below is a real one: `shutdown(true)` **stops** both boxes —
/// the manager's shutdown path, which is a stop and not a delete — before
/// the first server is torn down. A stop keeps the record (NET-013: the
/// address is the box's own from finalize to destroy, and a stopped box
/// that resumes must find it where it left it), so the record the second
/// daemon reads still names both boxes' hands. Resuming the **second** box
/// first is the check that keeps this from being vacuous: if the stop had
/// dropped its row, the resumed box would have nothing to publish at, and
/// only the recorded address it kept proves the row survived the stop and
/// the restart.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_restarted_daemon_re_derives_the_box_s_address_from_the_answerer() {
    use minimald_rpc::{SessionDelta, SessionDeltaRequest};

    let alpha_handed = std::net::Ipv4Addr::new(127, 0, 64, 9);
    let beta_handed = std::net::Ipv4Addr::new(127, 0, 64, 10);
    let capture = crate::test_harness::captured_log();
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let alpha = finalize_handed_own_ip_session(
        &mut client,
        "alpha",
        std::net::Ipv4Addr::new(100, 64, 128, 9),
        alpha_handed,
    )
    .await;
    let beta = finalize_handed_own_ip_session(
        &mut client,
        "beta",
        std::net::Ipv4Addr::new(100, 64, 128, 10),
        beta_handed,
    )
    .await;
    let (_, alpha_address) = zone_answer_for(&server, "alpha.min.internal")
        .await
        .expect("alpha's name answers at the first daemon");
    let (_, beta_address) = zone_answer_for(&server, "beta.min.internal")
        .await
        .expect("beta's name answers at the first daemon");
    assert_eq!(
        alpha_address, alpha_handed,
        "the first box publishes at the address it was handed"
    );
    assert_eq!(
        beta_address, beta_handed,
        "the second box publishes at its own hand, not the first box's"
    );

    // "Restart the daemon": stop every session the way a daemon that is
    // going down stops them — records kept, publishes kept; a stop is not
    // a destroy — then tear the first server down and boot a second one on
    // the same state root, whose record still carries every box's hand.
    server
        .state
        .sessions_manager()
        .await
        .shutdown(true)
        .await
        .expect("a forced shutdown has nothing left to refuse it");
    let stopped = capture.contents();
    // Scoped by session name, not by word alone: the capture buffer is
    // process-wide and under libtest (`just test-cross`, minimald's macOS
    // coverage) every test in the binary shares it, so a scoped assertion is
    // the honest form even when no other test here releases. What this check
    // owns is these two boxes: neither alpha nor beta may be released by a
    // stop.
    assert!(
        !stopped.lines().any(|line| {
            line.contains("loopback-release")
                && (line.contains("session_name=\"alpha\"")
                    || line.contains("session_name=\"beta\""))
        }),
        "shutdown stops the boxes without releasing their grants: {stopped}"
    );
    drop(client);
    let state = server.into_state_dir();
    let server = TestServer::new_in(state).await;
    let mut client = server.connect().await;

    // Bring beta's session up on the restarted daemon **first** — the
    // resume path any RPC that names the session takes, which registers
    // its name before the actor is observable. The reply's shape is not
    // the point here; the actor being up is.
    let _ = client
        .call::<SessionDelta>(&SessionDeltaRequest { id: beta })
        .await;

    // Beta answers at the address the record already held it — the
    // re-derivation, and a stop that had dropped the row would have left
    // the name absent instead, which is a difference this test can see.
    let (owner, resumed_beta) = zone_answer_for(&server, "beta.min.internal")
        .await
        .expect("beta's name answers after the restart");
    assert_eq!(
        owner, "beta",
        "the session owns its box name across the restart"
    );
    assert_eq!(
        resumed_beta, beta_address,
        "the restarted daemon re-derives the box's recorded address, not a fresh one"
    );
    assert_ne!(
        resumed_beta, alpha_address,
        "the resumed box was not handed the first box's address"
    );

    // And alpha too: both boxes are where the record left them, each with
    // the record's line it always had — the re-ask spent nothing, and the
    // pair still holds one address between them.
    let _ = client
        .call::<SessionDelta>(&SessionDeltaRequest { id: alpha })
        .await;
    let (_, resumed_alpha) = zone_answer_for(&server, "alpha.min.internal")
        .await
        .expect("alpha's name answers after the restart");
    assert_eq!(
        resumed_alpha, alpha_address,
        "the first box's recorded address survived the stop and the restart too"
    );

    let registry = server.state.sessions_manager().await.hostnames();
    let routes = registry.read().expect("registry lock");
    assert_eq!(
        routes.published_own_address(beta),
        Some(resumed_beta),
        "the registry the restarted daemon built answers with the recorded address"
    );
    assert_eq!(
        routes.published_own_address(alpha),
        Some(resumed_alpha),
        "and so does the first box's"
    );
}

/// NET-013 inside the deferred probe's window, without the wait §7.1 keeps
/// for a first finalize. A microVM daemon cannot measure the range its
/// publishes bind on — the host's loopback, a machine the guest cannot see —
/// so its verdict comes from the forwarder-conducted walk, and that walk is
/// long enough that the daemon must not hold its accept loop for it: the
/// book opens **pending** and the walk lands when it lands. A daemon
/// restarted with a live own-address box is therefore serving the RPC that
/// brings the box's actor up — an attach right after `min up` — before its
/// own verdict has, and that actor's registration is the resumed box's.
///
/// That registration runs inside the manager's own message handling, so it
/// must not wait: a wait there would park every other session's operation
/// behind it. The hand it finds on the record is not vouched for yet, so the
/// box publishes at the `127.0.0.1` interim at once — the RPC returns well
/// inside a deadline held open for a minute — and the walk's present landing
/// moves it to its own hand.
///
/// The window is held here by hand: the harness daemon is a native one, whose
/// own loopback *is* its publish surface, so it reads the probe's answer
/// before the book opens — its verdict has to be put back in the pending state
/// the daemon inside a microVM holds its book in.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_resumed_handed_box_publishes_the_interim_without_waiting_and_takes_its_hand_on_present()
{
    use minimald_rpc::{SessionDelta, SessionDeltaRequest};

    let handed = std::net::Ipv4Addr::new(127, 0, 64, 9);
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let web = finalize_handed_own_ip_session(
        &mut client,
        "resumed-hand",
        std::net::Ipv4Addr::new(100, 64, 128, 9),
        handed,
    )
    .await;
    let (_, address) = zone_answer_for(&server, "resumed-hand.min.internal")
        .await
        .expect("the box's name answers at the first daemon");
    assert_eq!(
        address, handed,
        "the box publishes at the address it was handed"
    );

    // "Restart the daemon" — the same shape the restart test above drives: a
    // stop, not a destroy, so the record keeps the box's hand — then a second
    // daemon on the same state root, held in the pending verdict a VM daemon
    // whose walk has not answered holds its book in, with a deadline far
    // longer than any resume may take.
    server
        .state
        .sessions_manager()
        .await
        .shutdown(true)
        .await
        .expect("a forced shutdown has nothing left to refuse it");
    drop(client);
    let state = server.into_state_dir();
    let server = TestServer::new_in(state).await;
    let manager = server.state.sessions_manager().await;
    manager.hold_range_verdict_pending();
    manager.reset_hand_verdict_deadline(DEADLINE_HELD_OPEN_MS);

    // Resume inside the window: the first RPC that names the box brings its
    // actor up, and the registration that actor runs is the resumed box's.
    // It does not wait for the verdict.
    let mut client = server.connect().await;
    let started = std::time::Instant::now();
    let _ = client
        .call::<SessionDelta>(&SessionDeltaRequest { id: web })
        .await;
    assert!(
        started.elapsed() < NO_WAIT_BOUND,
        "a resume never waits for the verdict, took {:?}",
        started.elapsed()
    );
    assert_eq!(
        manager.verdict_waiters(),
        0,
        "nothing is parked on the verdict after the resume"
    );
    let registry = manager.hostnames();
    assert_eq!(
        registry
            .read()
            .expect("registry lock")
            .published_own_address(web),
        Some(std::net::Ipv4Addr::LOCALHOST),
        "the resumed box publishes at the interim while the verdict is pending"
    );

    // The walk lands present: the box moves to its own hand, never a grant.
    manager.land_range_verdict(crate::net::dns::RangeVerdict::Present);
    assert_eq!(
        registry
            .read()
            .expect("registry lock")
            .published_own_address(web),
        Some(handed),
        "the present landing moves the resumed box to its own hand"
    );
    let (owner, standing) = zone_answer_for(&server, "resumed-hand.min.internal")
        .await
        .expect("the resumed box's name answers after the landing");
    assert_eq!(
        owner, "resumed-hand",
        "the session owns its box name across the restart"
    );
    assert_eq!(standing, handed, "the name answers at the hand");
    assert_eq!(
        registry
            .read()
            .expect("registry lock")
            .resolve("resumed-hand.min.internal:18080")
            .expect("the name routes once the verdict lands")
            .upstream(18080),
        Some(std::net::SocketAddr::new(
            std::net::IpAddr::V4(handed),
            18080
        )),
        "the box's own port number is published at its own address, not translated"
    );
}

/// A deadline held open far longer than any registration that does not wait
/// can take, so a test tells "did not wait" from "waited" by the clock.
#[cfg(target_os = "linux")]
const DEADLINE_HELD_OPEN_MS: u64 = 60_000;

/// What "did not wait" means against [`DEADLINE_HELD_OPEN_MS`]: half of it,
/// generous for an RPC under emulation, and still a whole half-minute short
/// of a registration that waited.
#[cfg(target_os = "linux")]
const NO_WAIT_BOUND: Duration = Duration::from_secs(30);

/// Q2's one rule, for a box nobody handed an address (NET-013, NET-123): no
/// reserved-range address publishes under anything but a landed present
/// verdict — not even the grant the record already holds for a resumed box.
/// A daemon restarted inside its pending window publishes the resumed box at
/// the `127.0.0.1` interim, and keeps the record's line, so the present
/// landing restores the box to the very address it held before the restart.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_resumed_box_publishes_the_interim_until_present_restores_its_recorded_address() {
    use minimald_rpc::{SessionDelta, SessionDeltaRequest};

    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let web = finalize_own_ip_session(&mut client, "resumed-grant").await;
    let (_, recorded) = zone_answer_for(&server, "resumed-grant.min.internal")
        .await
        .expect("the box's name answers at the first daemon");
    assert!(
        in_reserved_local_range(recorded),
        "a present daemon grants the box an address of the range, got {recorded}"
    );

    server
        .state
        .sessions_manager()
        .await
        .shutdown(true)
        .await
        .expect("a forced shutdown has nothing left to refuse it");
    drop(client);
    let state = server.into_state_dir();
    let server = TestServer::new_in(state).await;
    let manager = server.state.sessions_manager().await;
    manager.hold_range_verdict_pending();

    let mut client = server.connect().await;
    let _ = client
        .call::<SessionDelta>(&SessionDeltaRequest { id: web })
        .await;
    let registry = manager.hostnames();
    assert_eq!(
        registry
            .read()
            .expect("registry lock")
            .published_own_address(web),
        Some(std::net::Ipv4Addr::LOCALHOST),
        "under a pending verdict the resumed box publishes the interim, not \
         its recorded range address"
    );

    manager.land_range_verdict(crate::net::dns::RangeVerdict::Present);
    assert_eq!(
        registry
            .read()
            .expect("registry lock")
            .published_own_address(web),
        Some(recorded),
        "the present landing restores the box's recorded address"
    );
    let (_, standing) = zone_answer_for(&server, "resumed-grant.min.internal")
        .await
        .expect("the name answers after the landing");
    assert_eq!(
        standing, recorded,
        "the name answers at the recorded address"
    );
}

/// The destroy of a box whose actor is down brings the actor up to run its
/// hooks — inside the manager's own message handling — and that bring-up
/// must not wait for the verdict either (NET-123 §7.1): the destroy returns
/// well inside a deadline held open for a minute, its registration stands
/// the handed box at the interim for the moment it lives, and a present
/// landing afterwards resurrects nothing.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_destroy_under_a_pending_verdict_does_not_wait_and_publishes_the_interim() {
    let capture = crate::test_harness::captured_log();
    let handed = std::net::Ipv4Addr::new(127, 0, 64, 9);
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let doomed = finalize_handed_own_ip_session(
        &mut client,
        "doomed",
        std::net::Ipv4Addr::new(100, 64, 128, 9),
        handed,
    )
    .await;

    // A restarted daemon: the box's actor is down, so the destroy below is
    // the one that brings it up to run its hooks.
    server
        .state
        .sessions_manager()
        .await
        .shutdown(true)
        .await
        .expect("a forced shutdown has nothing left to refuse it");
    drop(client);
    let state = server.into_state_dir();
    let server = TestServer::new_in(state).await;
    let manager = server.state.sessions_manager().await;
    manager.hold_range_verdict_pending();
    manager.reset_hand_verdict_deadline(DEADLINE_HELD_OPEN_MS);

    let mut client = server.connect().await;
    let started = std::time::Instant::now();
    destroy_session(&mut client, doomed).await;
    assert!(
        started.elapsed() < NO_WAIT_BOUND,
        "a destroy's hook bring-up never waits for the verdict, took {:?}",
        started.elapsed()
    );
    // The bring-up stood the handed box at the interim, said out loud.
    let logged = capture.contents();
    let moved = logged
        .lines()
        .find(|line| {
            line.contains("loopback-hand-to-interim") && line.contains("session_name=\"doomed\"")
        })
        .unwrap_or_else(|| {
            panic!("the bring-up's hand→interim move must be logged, got: {logged}")
        });
    assert!(
        moved.contains(&format!("from={handed}")) && moved.contains("to=127.0.0.1"),
        "the move names both addresses, got: {moved}"
    );

    // The landing that follows finds nothing to move: the destroy withdrew
    // the publish, and the name stays absent.
    manager.land_range_verdict(crate::net::dns::RangeVerdict::Present);
    assert_eq!(
        manager
            .hostnames()
            .read()
            .expect("registry lock")
            .published_own_address(doomed),
        None,
        "a destroyed box is not resurrected by the landing"
    );
    assert!(
        zone_answer_for(&server, "doomed.min.internal")
            .await
            .is_none(),
        "the destroyed box's name stays absent"
    );
}

/// The daemon's verdict deadline is one instant, not a wait per finalize
/// (NET-123 §7.1): handed boxes finalized one after another under a pending
/// verdict that never lands are all answered by the same deadline, so the
/// finalizes together take about one wait — not one wait each — and every
/// box stands at the interim until the present landing moves each to its
/// own hand.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn handed_finalizes_share_one_verdict_deadline() {
    const BOXES: u8 = 3;
    const WAIT_MS: u64 = 8_000;
    let server = TestServer::new().await;
    let manager = server.state.sessions_manager().await;
    manager.hold_range_verdict_pending();
    let mut client = server.connect().await;
    let mut boxes = Vec::new();
    for n in 0..BOXES {
        let hand = std::net::Ipv4Addr::new(127, 0, 64, 9 + n);
        let id = create_handed_own_ip_session(
            &mut client,
            &format!("deadline{n}"),
            std::net::Ipv4Addr::new(100, 64, 128, 9 + n),
            hand,
        )
        .await;
        boxes.push((id, hand));
    }

    manager.reset_hand_verdict_deadline(WAIT_MS);
    let started = std::time::Instant::now();
    for (id, _) in &boxes {
        finalize_session(&mut client, *id).await;
    }
    let elapsed = started.elapsed();
    let per_call_total = Duration::from_millis(WAIT_MS * u64::from(BOXES));
    assert!(
        elapsed < per_call_total,
        "the finalizes shared one deadline ({WAIT_MS} ms), not one wait each \
         ({per_call_total:?}): took {elapsed:?}"
    );
    let registry = manager.hostnames();
    for (id, _) in &boxes {
        assert_eq!(
            registry
                .read()
                .expect("registry lock")
                .published_own_address(*id),
            Some(std::net::Ipv4Addr::LOCALHOST),
            "a deadline that passes stands each handed box at the interim"
        );
    }

    manager.land_range_verdict(crate::net::dns::RangeVerdict::Present);
    for (id, hand) in &boxes {
        assert_eq!(
            registry
                .read()
                .expect("registry lock")
                .published_own_address(*id),
            Some(*hand),
            "the present landing moves each handed box to its own hand"
        );
    }
}

/// Where a handed box publishes is the verdict's to say (NET-123 §7.1), and
/// every move between the two addresses it can stand at is said out loud.
/// Inside the deferred walk's window the finalize's registration waits for
/// the verdict, bounded by the session-start deadline: an **absent** landing
/// inside the bound publishes the box on the `127.0.0.1` interim — the hand
/// names an address the surface cannot bind, so it is never published, not
/// even briefly — and the hand→interim move is one warn line naming the box
/// and both addresses. The two arms of a landing then move the box the
/// other way over a live publish: a **present** landing takes a box
/// standing at the interim back to its own hand, and an **absent** one
/// stands a box down at the interim again — the knob drives the two
/// landings over one live box the way a single production landing never
/// will, and each move is logged with the box and both addresses.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_handed_box_pending_at_finalize_publishes_the_interim_when_the_verdict_lands_absent() {
    let capture = crate::test_harness::captured_log();
    let server = TestServer::new().await;
    let manager = server.state.sessions_manager().await;
    manager.hold_range_verdict_pending();
    // Far off, so the finalize reaches its wait whatever the load: the
    // landing below answers it long before the deadline would.
    manager.reset_hand_verdict_deadline(DEADLINE_HELD_OPEN_MS);
    let mut client = server.connect().await;
    let handed = std::net::Ipv4Addr::new(127, 0, 64, 9);
    let web = create_handed_own_ip_session(
        &mut client,
        "web",
        std::net::Ipv4Addr::new(100, 64, 128, 9),
        handed,
    )
    .await;
    let registry = manager.hostnames();

    // The finalize goes out on its own connection so the walk can land
    // inside the registration's bounded wait — the shape a finalize meets
    // when the deferred probe answers while it is asking.
    let mut finalize_client = server.connect().await;
    let finalize = tokio::spawn(async move { finalize_session(&mut finalize_client, web).await });
    await_verdict_waiter(&manager).await;
    manager.land_range_verdict(crate::net::dns::RangeVerdict::Absent);
    finalize.await.expect("the finalize's task runs to its end");

    // The verdict landed absent inside the wait: the hand is unvouched, so
    // the box publishes on the interim — never at the hand, which the
    // surface cannot bind.
    assert_eq!(
        registry
            .read()
            .expect("registry lock")
            .published_own_address(web),
        Some(std::net::Ipv4Addr::LOCALHOST),
        "an absent landing inside the wait publishes the box on the interim"
    );
    let (_, address) = zone_answer_for(&server, "web.min.internal")
        .await
        .expect("the name answers once the wait ends");
    assert_eq!(
        address,
        std::net::Ipv4Addr::LOCALHOST,
        "the name answers at the interim, the address the surface can bind"
    );
    // The hand→interim move is said out loud, naming the box and both
    // addresses (§7.1): the diagnostics bundle reads the move, not just the
    // verdict that caused it.
    let logged = capture.contents();
    let moved = logged
        .lines()
        .find(|line| {
            line.contains("loopback-hand-to-interim") && line.contains(&format!("session_id={web}"))
        })
        .unwrap_or_else(|| panic!("the hand→interim move must be logged, got: {logged}"));
    assert!(
        moved.contains(&format!("from={handed}")) && moved.contains("to=127.0.0.1"),
        "the move names both addresses, got: {moved}"
    );
    // And the name was published once: no registration ever named the hand.
    let registered = logged
        .lines()
        .find(|line| {
            line.contains("registered PTask hostname")
                && line.contains(&format!("session_id={web}"))
        })
        .unwrap_or_else(|| panic!("the publish's registration must be logged, got: {logged}"));
    assert!(
        registered.contains("ip=127.0.0.1"),
        "the single registration names the interim, never the hand it was not vouched for, \
         got: {registered}"
    );

    // A present landing moves a box standing at the interim back to its own
    // hand — the hand the registration recorded for it, never a grant drawn
    // from the pool.
    manager.land_range_verdict(crate::net::dns::RangeVerdict::Present);
    assert_eq!(
        registry
            .read()
            .expect("registry lock")
            .published_own_address(web),
        Some(handed),
        "a present landing moves a handed box back to its own hand"
    );
    let (_, upgraded) = zone_answer_for(&server, "web.min.internal")
        .await
        .expect("the name survives the landing");
    assert_eq!(
        upgraded, handed,
        "the name answers at the hand, moved with the publish"
    );
    let logged = capture.contents();
    let upgraded_line = logged
        .lines()
        .find(|line| {
            line.contains("loopback-range-present-box")
                && line.contains(&format!("session_id={web}"))
        })
        .unwrap_or_else(|| panic!("the interim→hand move must be logged, got: {logged}"));
    assert!(
        upgraded_line.contains("from=127.0.0.1") && upgraded_line.contains(&format!("to={handed}")),
        "the interim→hand move names both addresses, got: {upgraded_line}"
    );

    // An absent landing stands a box down at the interim again — the arm
    // NET-123 keeps for exactly this publish: an address the surface cannot
    // bind is not publishable, whatever handed it, and the landing is the
    // one moment the daemon holds both facts.
    manager.land_range_verdict(crate::net::dns::RangeVerdict::Absent);
    assert_eq!(
        registry
            .read()
            .expect("registry lock")
            .published_own_address(web),
        Some(std::net::Ipv4Addr::LOCALHOST),
        "an absent landing moves a reserved-range publish back onto the interim"
    );
    let (_, stood_down) = zone_answer_for(&server, "web.min.internal")
        .await
        .expect("the name survives the landing");
    assert_eq!(
        stood_down,
        std::net::Ipv4Addr::LOCALHOST,
        "the name answers at the interim again, never at the unbindable hand"
    );
    let logged = capture.contents();
    let stood_down_line = logged
        .lines()
        .find(|line| {
            line.contains("loopback-range-absent-box")
                && line.contains(&format!("session_id={web}"))
        })
        .unwrap_or_else(|| panic!("the absent arm's move must be logged, got: {logged}"));
    assert!(
        stood_down_line.contains(&format!("from={handed}"))
            && stood_down_line.contains("to=127.0.0.1"),
        "the absent arm's move names both addresses, got: {stood_down_line}"
    );
}

/// The interim must not outstay the window that made it: a box nobody handed
/// an address, finalized inside the deferred walk's window, publishes at the
/// ask's own answer for a verdict that has not landed — the `127.0.0.1`
/// interim. The landing that replaces the verdict is the moment that ask
/// upgrades: when the walk lands present, every box standing at the interim
/// is re-asked and re-published at its grant, name and route with it, so the
/// box takes an address of its own instead of standing at the interim until
/// destroy. The interim→grant move is one warn line naming the box and both
/// addresses (§7.1), so the diagnostics bundle reads the move and not only
/// the verdict that caused it.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_interim_publish_takes_its_grant_when_the_verdict_lands_present() {
    let capture = crate::test_harness::captured_log();
    let server = TestServer::new().await;
    let manager = server.state.sessions_manager().await;
    manager.hold_range_verdict_pending();
    let mut client = server.connect().await;
    let web = finalize_own_ip_session(&mut client, "web").await;

    // Inside the window: the ask answers pending, so the box publishes on
    // the interim — reachable, at the one address the surface can always
    // bind.
    let registry = manager.hostnames();
    assert_eq!(
        registry
            .read()
            .expect("registry lock")
            .published_own_address(web),
        Some(std::net::Ipv4Addr::LOCALHOST),
        "inside the pending window the ask publishes the box on the interim"
    );

    // The walk lands present: the interim was the ask's answer for a verdict
    // that had not landed, so the landing re-asks and the publish moves to
    // the grant.
    manager.land_range_verdict(crate::net::dns::RangeVerdict::Present);
    let granted = {
        let routes = registry.read().expect("registry lock");
        routes
            .published_own_address(web)
            .expect("the landing upgrades the interim publish to a grant")
    };
    assert_ne!(
        granted,
        std::net::Ipv4Addr::LOCALHOST,
        "the box no longer stands at the interim"
    );
    assert!(
        in_reserved_local_range(granted),
        "the upgrade is a grant from the reserved local range, got {granted}"
    );
    let (_, address) = zone_answer_for(&server, "web.min.internal")
        .await
        .expect("the name survives the landing");
    assert_eq!(
        address, granted,
        "the name answers at the granted address, moved with the publish"
    );
    let logged = capture.contents();
    let moved = logged
        .lines()
        .find(|line| {
            line.contains("loopback-range-present-box")
                && line.contains(&format!("session_id={web}"))
        })
        .unwrap_or_else(|| panic!("the interim→grant move must be logged, got: {logged}"));
    assert!(
        moved.contains("from=127.0.0.1") && moved.contains(&format!("to={granted}")),
        "the move names the box and both addresses, got: {moved}"
    );
}

/// The present landing's resurrect window, closed (§7.1): the draw of a
/// landing's move runs outside every registry lock — the grant it draws is
/// a read-modify-write of the answerer's record under the record's own
/// lock file — and a box that dies inside that window must not have its
/// move applied. Names are first-writer-owned: a destroyed box's
/// re-registered name would block the next box that takes it, and the
/// move would resurrect the publish rows the destroy's own path had just
/// withdrawn. The apply therefore re-checks, under the write lock, that
/// the box still holds its name and still stands at the interim — a box
/// that fails either check has the grant drawn for it released back
/// through the answerer's channel and nothing published.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_box_destroyed_inside_the_landing_window_is_not_resurrected() {
    let capture = crate::test_harness::captured_log();
    let server = TestServer::new().await;
    let manager = server.state.sessions_manager().await;
    manager.hold_range_verdict_pending();
    let mut client = server.connect().await;
    let web = finalize_own_ip_session(&mut client, "web").await;
    let registry = manager.hostnames();
    assert_eq!(
        registry
            .read()
            .expect("registry lock")
            .published_own_address(web),
        Some(std::net::Ipv4Addr::LOCALHOST),
        "inside the pending window the ask publishes the box on the interim"
    );

    // The walk's landing, with its two halves held apart the way a single
    // landing never is: the state moves, the draw runs and grants the box
    // an address — and the box is destroyed between the grant and the
    // publish.
    let book = manager.loopback_book();
    book.set_range_verdict(crate::net::dns::RangeVerdict::Present);
    let drawn = crate::sessions::draw_interim_upgrades(book, &registry);
    let upgrade = drawn
        .first()
        .expect("the draw found the box standing at the interim");
    let granted = upgrade.address;
    assert!(
        !upgrade.hand,
        "a box nobody handed an address is drawn a grant from the pool"
    );
    destroy_session(&mut client, web).await;
    // The destroy released the line the draw wrote. The window's other
    // order — the destroy running between the draw's enumeration and its
    // grant, so the destroy's release finds nothing and the grant writes
    // the line after it — leaves the record naming the dead box when the
    // apply runs; the grant is idempotent by namespace, so asking again
    // here puts the record in exactly that state, and the release below
    // is then provably the discard's own.
    assert_eq!(
        book.grant(crate::net::dns::LeaseNamespace::Box { session: web }),
        crate::net::dns::LoopbackGrant::Granted(granted),
        "the draw's grant, written after the destroy's release"
    );

    // The apply re-checks and publishes nothing: the name the destroy
    // withdrew stays withdrawn, the publish stays withdrawn, and the grant
    // drawn inside the window is released rather than left spoken for.
    let applied = crate::sessions::apply_interim_upgrade(book, &registry, upgrade);
    assert!(
        !applied,
        "a box destroyed inside the landing's window is not resurrected"
    );
    assert!(
        zone_answer_for(&server, "web.min.internal").await.is_none(),
        "no name is registered for the destroyed box"
    );
    assert_eq!(
        registry
            .read()
            .expect("registry lock")
            .published_own_address(web),
        None,
        "no publish is resurrected for the destroyed box"
    );
    let logged = capture.contents();
    let discarded = logged
        .lines()
        .find(|line| {
            line.contains("loopback-lease-discarded") && line.contains(&format!("session_id={web}"))
        })
        .unwrap_or_else(|| panic!("the discarded grant must be logged, got: {logged}"));
    assert!(
        discarded.contains(&format!("to={granted}"))
            && discarded.contains(&format!("released=Some({granted})")),
        "the discard itself released the grant drawn for the dead box, got: {discarded}"
    );
    assert_eq!(
        book.release(crate::net::dns::LeaseNamespace::Box { session: web }),
        None,
        "the discard took the dead box's line; nothing is left to release"
    );

    // The grant is back in the pool: a fresh namespace's ask draws the very
    // address the landing drew and released — the lowest free one — so the
    // dead box's window spent nothing.
    let regranted = book.grant(crate::net::dns::LeaseNamespace::Box {
        session: SessionId::nil(),
    });
    assert!(
        matches!(
            regranted,
            crate::net::dns::LoopbackGrant::Granted(address) if address == granted
        ),
        "the grant drawn inside the window was released back into the pool, \
         got: {regranted:?}"
    );
}

/// The present landing runs on the deferred walk's own task, off every
/// mailbox, so it is unordered against a destroy; this pins the shape the
/// apply's runtime re-check exists for, in the order it happens. The
/// landing's enumeration finds the box standing at the interim, the box is
/// destroyed — its release finds no line, since the pending window granted
/// it none — and only then does the draw's grant write a line for it. The
/// apply must publish nothing and release that grant itself, exactly once.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_box_destroyed_between_enumeration_and_grant_is_released_once() {
    let capture = crate::test_harness::captured_log();
    let server = TestServer::new().await;
    let manager = server.state.sessions_manager().await;
    manager.hold_range_verdict_pending();
    let mut client = server.connect().await;
    let id = finalize_own_ip_session(&mut client, "torn").await;
    let registry = manager.hostnames();
    let book = manager.loopback_book();

    // The landing's first step: the verdict moves and the enumeration runs.
    book.set_range_verdict(crate::net::dns::RangeVerdict::Present);
    let standing = registry
        .read()
        .expect("registry lock")
        .interim_own_publishes()
        .into_iter()
        .find(|publish| publish.session == id)
        .expect("the enumeration finds the box at the interim");

    // The destroy lands inside the window, before the draw's grant.
    destroy_session(&mut client, id).await;

    // The draw's grant, for the box the enumeration found.
    let granted = match book.grant(crate::net::dns::LeaseNamespace::Box { session: id }) {
        crate::net::dns::LoopbackGrant::Granted(address) => address,
        other => panic!("a present book grants the drawn box: {other:?}"),
    };
    let upgrade = crate::sessions::InterimUpgrade {
        session: standing.session,
        name: standing.name,
        ports: standing.ports,
        address: granted,
        hand: false,
    };

    assert!(
        !crate::sessions::apply_interim_upgrade(book, &registry, &upgrade),
        "a box destroyed inside the window is not re-published"
    );
    assert_eq!(
        registry
            .read()
            .expect("registry lock")
            .published_own_address(id),
        None,
        "no publish is resurrected"
    );
    assert!(
        zone_answer_for(&server, "torn.min.internal")
            .await
            .is_none(),
        "no name is registered for the destroyed box"
    );

    // Released exactly once: the destroy found no line to release, the
    // discard released the grant, and nothing is left for a second release.
    let logged = capture.contents();
    let scoped = |action: &str| -> Vec<String> {
        logged
            .lines()
            .filter(|line| {
                line.contains(&format!("action=\"{action}\""))
                    && line.contains(&format!("session_id={id}"))
            })
            .map(str::to_owned)
            .collect()
    };
    assert!(
        scoped("loopback-release").is_empty(),
        "the destroy ran before the grant, so it released nothing"
    );
    let discarded = scoped("loopback-lease-discarded");
    assert_eq!(discarded.len(), 1, "one discard: {discarded:?}");
    assert!(
        discarded[0].contains(&format!("released=Some({granted})")),
        "the discard released the grant, got: {}",
        discarded[0]
    );
    assert_eq!(
        book.release(crate::net::dns::LeaseNamespace::Box { session: id }),
        None,
        "nothing is left to release a second time"
    );
}

/// The registration's own promotion is ordered against a destroy by the
/// session's mailbox, not by a runtime check: a first finalize waiting at
/// the verdict deadline holds the actor, so a destroy sent meanwhile queues
/// behind it. When the present landing wakes the wait, the box publishes at
/// its hand first and the queued destroy removes it after — and no name is
/// left.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_destroy_queued_behind_a_waiting_finalize_runs_after_the_promotion() {
    let capture = crate::test_harness::captured_log();
    let server = TestServer::new().await;
    let manager = server.state.sessions_manager().await;
    manager.hold_range_verdict_pending();
    manager.reset_hand_verdict_deadline(DEADLINE_HELD_OPEN_MS);
    let mut client = server.connect().await;
    let handed = std::net::Ipv4Addr::new(127, 0, 64, 9);
    let id = create_handed_own_ip_session(
        &mut client,
        "queued",
        std::net::Ipv4Addr::new(100, 64, 128, 9),
        handed,
    )
    .await;

    let mut finalize_client = server.connect().await;
    let finalize = tokio::spawn(async move { finalize_session(&mut finalize_client, id).await });
    await_verdict_waiter(&manager).await;
    let mut destroy_client = server.connect().await;
    let destroy = tokio::spawn(async move { destroy_session(&mut destroy_client, id).await });
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        !destroy.is_finished(),
        "the destroy queues behind the finalize waiting on the verdict"
    );

    manager.land_range_verdict(crate::net::dns::RangeVerdict::Present);
    finalize.await.expect("the finalize's task runs to its end");
    destroy.await.expect("the destroy's task runs to its end");

    let logged = capture.contents();
    let lines: Vec<&str> = logged
        .lines()
        .filter(|line| line.contains(&format!("session_id={id}")))
        .collect();
    let registered = lines
        .iter()
        .position(|line| {
            line.contains("action=\"registered\"") && line.contains(&format!("ip={handed}"))
        })
        .unwrap_or_else(|| panic!("the promotion to the hand must be logged, got: {lines:?}"));
    let removed = lines
        .iter()
        .position(|line| line.contains("action=\"deregistered\""))
        .unwrap_or_else(|| panic!("the destroy's removal must be logged, got: {lines:?}"));
    assert!(
        registered < removed,
        "the promotion happens before the removal: {lines:?}"
    );
    assert_eq!(
        manager
            .hostnames()
            .read()
            .expect("registry lock")
            .published_own_address(id),
        None,
        "the destroy withdrew the publish"
    );
    assert!(
        zone_answer_for(&server, "queued.min.internal")
            .await
            .is_none(),
        "no name is left"
    );
}

/// The discard's other half: a box that moved off the interim through its
/// own re-registration inside the landing's window — a rename here, whose
/// re-ask is answered with the very grant the draw recorded, the grant
/// being idempotent by namespace — stands at that address when the apply
/// runs. The apply discards the stale move (the box no longer holds the
/// name it was drawn under) but must not release the grant: the box is
/// published at it, and freeing it would hand a live box's address to the
/// next ask.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_box_re_registered_inside_the_landing_window_keeps_its_grant() {
    use minimald_rpc::{Errorable, RenameSession, RenameSessionRequest};

    let capture = crate::test_harness::captured_log();
    let server = TestServer::new().await;
    let manager = server.state.sessions_manager().await;
    manager.hold_range_verdict_pending();
    let mut client = server.connect().await;
    let web = finalize_own_ip_session(&mut client, "keeper").await;
    let registry = manager.hostnames();

    let book = manager.loopback_book();
    book.set_range_verdict(crate::net::dns::RangeVerdict::Present);
    let drawn = crate::sessions::draw_interim_upgrades(book, &registry);
    let upgrade = drawn
        .iter()
        .find(|upgrade| upgrade.session == web)
        .expect("the draw found the box standing at the interim");
    let granted = upgrade.address;

    // The box re-registers inside the window: the rename's re-ask answers
    // with the grant the draw recorded, and the box publishes at it.
    match client
        .call::<RenameSession>(&RenameSessionRequest {
            id: web,
            new_name: "keeper2".to_string(),
        })
        .await
    {
        Errorable::Ok(_) => {}
        Errorable::Err { error } => panic!("RenameSession failed: {error}"),
    }
    assert_eq!(
        registry
            .read()
            .expect("registry lock")
            .published_own_address(web),
        Some(granted),
        "the renamed box publishes at the grant the draw recorded"
    );

    let applied = crate::sessions::apply_interim_upgrade(book, &registry, upgrade);
    assert!(!applied, "the stale move is discarded");
    assert_eq!(
        registry
            .read()
            .expect("registry lock")
            .published_own_address(web),
        Some(granted),
        "the box keeps the address it re-registered onto"
    );
    let logged = capture.contents();
    let discarded = logged
        .lines()
        .find(|line| {
            line.contains("loopback-lease-discarded") && line.contains("session_name=\"keeper\"")
        })
        .unwrap_or_else(|| panic!("the discarded move must be logged, got: {logged}"));
    assert!(
        discarded.contains("released=None"),
        "the discard releases nothing for a box still standing at its grant, got: {discarded}"
    );

    // The record still names the box's grant: a fresh namespace's ask is
    // handed a different address, never the one the box stands at.
    match book.grant(crate::net::dns::LeaseNamespace::Box {
        session: SessionId::nil(),
    }) {
        crate::net::dns::LoopbackGrant::Granted(other) => assert_ne!(
            other, granted,
            "a live box's grant is not handed to the next ask"
        ),
        other => panic!("a present book grants the fresh ask: {other:?}"),
    }
    let (owner, address) = zone_answer_for(&server, "keeper2.min.internal")
        .await
        .expect("the renamed box's name answers");
    assert_eq!(owner, "keeper2");
    assert_eq!(address, granted, "the renamed box answers at its grant");
}

/// The expiry half of §7.1: a handed box whose deadline expired — the walk
/// never answered inside the session-start bound — stands at the interim,
/// and the landing that finally vouches for the hand moves the publish to
/// **it**: its own hand, never a grant drawn from the pool, because the
/// hand is the host-side table's row and the attach path's forwards name
/// it as their `local` — a hand is only ever replaced by `127.0.0.1`.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_interim_handed_publish_takes_its_hand_when_the_verdict_lands_late() {
    let server = TestServer::new().await;
    let manager = server.state.sessions_manager().await;
    manager.hold_range_verdict_pending();
    // The deadline is shrunk so the expiry runs inside the test's patience;
    // the walk then lands well after it.
    manager.reset_hand_verdict_deadline(100);
    let mut client = server.connect().await;
    let handed = std::net::Ipv4Addr::new(127, 0, 64, 9);
    let web = finalize_handed_own_ip_session(
        &mut client,
        "web",
        std::net::Ipv4Addr::new(100, 64, 128, 9),
        handed,
    )
    .await;
    let registry = manager.hostnames();
    assert_eq!(
        registry
            .read()
            .expect("registry lock")
            .published_own_address(web),
        Some(std::net::Ipv4Addr::LOCALHOST),
        "the deadline expired with the walk still out, so the box stands at \
         the interim"
    );

    // The walk lands present — late, after the deadline the registration
    // waited out — and the landing's sweep moves the handed box to its own
    // hand, not to a grant.
    manager.land_range_verdict(crate::net::dns::RangeVerdict::Present);
    assert_eq!(
        registry
            .read()
            .expect("registry lock")
            .published_own_address(web),
        Some(handed),
        "a late present landing upgrades the interim publish to the box's \
         own hand, never to a grant from the pool"
    );
    let (_, address) = zone_answer_for(&server, "web.min.internal")
        .await
        .expect("the name survives the landing");
    assert_eq!(
        address, handed,
        "the name answers at the hand, moved with the publish"
    );
    assert_eq!(
        registry
            .read()
            .expect("registry lock")
            .resolve("web.min.internal:18080")
            .expect("the name routes at the hand")
            .upstream(18080),
        Some(std::net::SocketAddr::new(
            std::net::IpAddr::V4(handed),
            18080
        )),
        "the box's declared port is published at its own hand, exactly where \
         the attach path binds its forwards"
    );
}

/// The wiring test for the hand's verdict gate (the `.filter(vouches_for)`
/// and the bounded wait on the hand's read, §7.1): a handed reserved address
/// finalizes to `published_own_address == 127.0.0.1` under an absent book —
/// the hand names an address the surface cannot bind, so it publishes
/// nothing and the ask answers with the interim — to the hand under a
/// pending book whose walk lands **present inside the session-start
/// deadline** the registration waits bounded by, and to the interim again
/// when that deadline expires with the walk still out. Remove the gate and
/// the absent half fails at the hand; remove the wait and the second half
/// publishes the interim a verdict that has not answered was never asked to.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_handed_reserved_address_waits_for_the_verdict_before_it_publishes() {
    // An absent book: the landing ran before any box existed, so its sweep
    // found nothing and only the verdict is in play.
    {
        let server = TestServer::new().await;
        let manager = server.state.sessions_manager().await;
        manager.land_range_verdict(crate::net::dns::RangeVerdict::Absent);
        let mut client = server.connect().await;
        let handed = std::net::Ipv4Addr::new(127, 0, 64, 9);
        let web = finalize_handed_own_ip_session(
            &mut client,
            "web",
            std::net::Ipv4Addr::new(100, 64, 128, 9),
            handed,
        )
        .await;
        assert_eq!(
            manager
                .hostnames()
                .read()
                .expect("registry lock")
                .published_own_address(web),
            Some(std::net::Ipv4Addr::LOCALHOST),
            "under an absent book the hand is unvouched, so the finalize \
             publishes the interim"
        );
        let (_, address) = zone_answer_for(&server, "web.min.internal")
            .await
            .expect("the name is held under an absent book");
        assert_eq!(
            address,
            std::net::Ipv4Addr::LOCALHOST,
            "the name answers at the interim, never at the unbindable hand"
        );
    }

    // A pending book whose walk lands present inside the deadline: the
    // finalize's registration waits for it, and the hand it vouches for is
    // the address the name publishes at — once, never the interim first.
    {
        let server = TestServer::new().await;
        let manager = server.state.sessions_manager().await;
        manager.hold_range_verdict_pending();
        // Far off, so the finalize reaches its wait whatever the load: the
        // landing below answers it long before the deadline would.
        manager.reset_hand_verdict_deadline(DEADLINE_HELD_OPEN_MS);
        let mut client = server.connect().await;
        let handed = std::net::Ipv4Addr::new(127, 0, 64, 9);
        let web = create_handed_own_ip_session(
            &mut client,
            "web",
            std::net::Ipv4Addr::new(100, 64, 128, 9),
            handed,
        )
        .await;
        let mut finalize_client = server.connect().await;
        let finalize =
            tokio::spawn(async move { finalize_session(&mut finalize_client, web).await });
        await_verdict_waiter(&manager).await;
        manager.land_range_verdict(crate::net::dns::RangeVerdict::Present);
        finalize.await.expect("the finalize's task runs to its end");
        assert_eq!(
            manager
                .hostnames()
                .read()
                .expect("registry lock")
                .published_own_address(web),
            Some(handed),
            "a verdict that lands present inside the deadline publishes the \
             hand it vouches for"
        );
        let (_, address) = zone_answer_for(&server, "web.min.internal")
            .await
            .expect("the name is held once the wait ends");
        assert_eq!(
            address, handed,
            "the name answers at the hand — the interim was never published"
        );
    }

    // A pending book whose walk never answers: the deadline expires and the
    // box publishes the interim, the address the surface can always bind —
    // the landing's sweep upgrades it to the hand if the walk ever lands.
    {
        let server = TestServer::new().await;
        let manager = server.state.sessions_manager().await;
        manager.hold_range_verdict_pending();
        // The deadline is shrunk to the test's patience: the expiry shape is
        // the one being driven, not the real five seconds of it.
        manager.reset_hand_verdict_deadline(100);
        let mut client = server.connect().await;
        let handed = std::net::Ipv4Addr::new(127, 0, 64, 9);
        let web = finalize_handed_own_ip_session(
            &mut client,
            "web",
            std::net::Ipv4Addr::new(100, 64, 128, 9),
            handed,
        )
        .await;
        assert_eq!(
            manager
                .hostnames()
                .read()
                .expect("registry lock")
                .published_own_address(web),
            Some(std::net::Ipv4Addr::LOCALHOST),
            "a verdict that never lands inside the deadline publishes the \
             interim, so the box has an address at all"
        );
        let (_, address) = zone_answer_for(&server, "web.min.internal")
            .await
            .expect("the name is held on the interim");
        assert_eq!(
            address,
            std::net::Ipv4Addr::LOCALHOST,
            "the name answers at the interim while the walk is still out"
        );
    }
}

/// NET-129 session path: two own-address boxes whose creators hand them the
/// *same* address — the shared-address mode — and that declare the same port.
/// The collision is intrinsic to the mode (the boxes were told to publish at
/// one place), so it is reported as a `shared-address-port-collision` warn at
/// the second finalize (the diagnostics contract) and never fixed by
/// translating a port. Both publishes stand: each box's record names the
/// address, each name answers at it, and the report is the operator's, not
/// the registry's, to act on.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shared_address_port_collision_reported_at_finalize_without_attached_client() {
    let shared = std::net::Ipv4Addr::new(127, 0, 64, 9);
    let server = TestServer::new().await;
    let capture = crate::test_harness::captured_log();
    let mut client = server.connect().await;

    let first = finalize_handed_own_ip_session(
        &mut client,
        "first",
        std::net::Ipv4Addr::new(100, 64, 128, 9),
        shared,
    )
    .await;
    let second = finalize_handed_own_ip_session(
        &mut client,
        "second",
        std::net::Ipv4Addr::new(100, 64, 128, 10),
        shared,
    )
    .await;

    // Both names answer at the one shared address while no client is attached.
    let (_, first_address) = zone_answer_for(&server, "first.min.internal")
        .await
        .expect("first's name answers on the shared address");
    let (_, second_address) = zone_answer_for(&server, "second.min.internal")
        .await
        .expect("second's name answers on the shared address");
    assert_eq!(
        first_address, second_address,
        "both shared-address boxes publish at the address they were handed"
    );
    assert_eq!(
        first_address, shared,
        "the shared address is the hand, exactly"
    );

    // Both publishes are recorded as the boxes' own: a shared hand is still
    // each box's hand, and neither publish is dropped for the collision's
    // sake — the report is advisory, the registry keeps what it was told.
    let registry = server.state.sessions_manager().await.hostnames();
    let routes = registry.read().expect("registry lock");
    assert_eq!(
        routes.published_own_address(first),
        Some(shared),
        "a shared-address box records the handed address as its own"
    );
    assert_eq!(
        routes.published_own_address(second),
        Some(shared),
        "the second shared-address box records the same hand"
    );
    assert_eq!(
        routes
            .resolve("first.min.internal:18080")
            .expect("first's name routes")
            .upstream(18080),
        Some(std::net::SocketAddr::new(
            std::net::IpAddr::V4(first_address),
            18080,
        )),
        "the first box's port is published at the number it asked for"
    );
    assert_eq!(
        routes
            .resolve("second.min.internal:18080")
            .expect("second's name routes")
            .upstream(18080),
        Some(std::net::SocketAddr::new(
            std::net::IpAddr::V4(second_address),
            18080,
        )),
        "the second box's port is published at the number it asked for"
    );
    // First-come: the collision is recorded on the box that yields the port —
    // the second — naming the port and the box that holds it, and never on
    // the holder. The second box's attach reads this record and skips that
    // forward, so its spawn never fails on the forwarder's refusal and its
    // other forwards bind (the attach half is
    // `a_yielded_shared_address_port_is_skipped_and_the_attach_succeeds`).
    assert_eq!(
        routes.shared_port_collisions(second),
        vec![crate::net::dns::SharedPortCollision {
            port: 18080,
            other: "first.min.internal".to_string(),
        }],
        "the second box records the port it yields and the box that holds it"
    );
    assert!(
        routes.shared_port_collisions(first).is_empty(),
        "the box that published first holds its port and yields nothing"
    );
    drop(routes);

    // The collision reached the log and named both boxes and the port.
    let logged = capture.contents();
    let collision_lines: Vec<_> = logged
        .lines()
        .filter(|line| {
            line.contains("action=\"shared-address-port-collision\"")
                && line.contains("port=18080")
                && (line.contains(&format!("session_id={first}"))
                    || line.contains(&format!("session_id={second}")))
        })
        .collect();
    assert_eq!(
        collision_lines.len(),
        1,
        "one warn line reports the collision, naming one box and the port: {collision_lines:?}"
    );
    assert!(
        collision_lines[0].contains("session_name=\"second\"")
            && collision_lines[0].contains("other=first.min.internal"),
        "the collision line names the publishing box and the other box: {}",
        collision_lines[0]
    );
}

/// NET-129 across a daemon restart: the shared-address collision is still
/// first-come, and still reported, once the boxes come back. A restarted
/// daemon rebuilds its registry from each box's registration as its session
/// comes up, so the box that held the port before the restart holds it after
/// it, the box that yielded it records the yield again — the record its next
/// spawn's attach reads to skip that forward rather than fail on it — and
/// the report is said again at that session's start.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shared_address_port_collision_survives_a_daemon_restart() {
    use minimald_rpc::{SessionDelta, SessionDeltaRequest};

    let shared = std::net::Ipv4Addr::new(127, 0, 64, 9);
    let capture = crate::test_harness::captured_log();
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let first = finalize_handed_own_ip_session(
        &mut client,
        "holds",
        std::net::Ipv4Addr::new(100, 64, 128, 9),
        shared,
    )
    .await;
    let second = finalize_handed_own_ip_session(
        &mut client,
        "yields",
        std::net::Ipv4Addr::new(100, 64, 128, 10),
        shared,
    )
    .await;
    let collision_lines_for_second = |log: &str| {
        log.lines()
            .filter(|line| {
                line.contains("action=\"shared-address-port-collision\"")
                    && line.contains("port=18080")
                    && line.contains(&format!("session_id={second}"))
            })
            .count()
    };
    assert_eq!(
        collision_lines_for_second(&capture.contents()),
        1,
        "the collision is reported at the second box's finalize"
    );

    // Restart: a stop, not a destroy, then a second daemon on the same state
    // root.
    server
        .state
        .sessions_manager()
        .await
        .shutdown(true)
        .await
        .expect("a forced shutdown has nothing left to refuse it");
    drop(client);
    let state = server.into_state_dir();
    let server = TestServer::new_in(state).await;
    let mut client = server.connect().await;
    for id in [first, second] {
        let _ = client
            .call::<SessionDelta>(&SessionDeltaRequest { id })
            .await;
    }

    let registry = server.state.sessions_manager().await.hostnames();
    let routes = registry.read().expect("registry lock");
    assert_eq!(
        routes.shared_port_collisions(second),
        vec![crate::net::dns::SharedPortCollision {
            port: 18080,
            other: "holds.min.internal".to_string(),
        }],
        "after the restart the second box still yields the port to the first"
    );
    assert!(
        routes.shared_port_collisions(first).is_empty(),
        "and the first box still holds it"
    );
    drop(routes);
    assert_eq!(
        collision_lines_for_second(&capture.contents()),
        2,
        "the collision is reported again when the second box's session starts"
    );
}

/// The write-lock promotion `register_hostname` runs after its wait, driven
/// directly with no timers: a registration that took the `127.0.0.1` interim
/// moves to its hand once the verdict vouches for it — whether the name is
/// still unregistered (a first finalize) or already its own (a resume) —
/// and stays on the interim under an absent verdict, or when another session
/// holds the name.
#[test]
fn the_write_lock_promotion_moves_an_interim_to_a_vouched_hand_only() {
    use crate::net::dns::{HostnameRegistry, LoopbackLeaseBook, RangeVerdict};
    use std::collections::BTreeSet;
    use std::net::Ipv4Addr;

    let tmp = tempfile::tempdir().unwrap();
    let state_root = paths::DaemonAbsPath::try_new(tmp.path().to_str().unwrap()).unwrap();
    let present = LoopbackLeaseBook::open(&state_root, RangeVerdict::Present).unwrap();
    let absent_tmp = tempfile::tempdir().unwrap();
    let absent_root = paths::DaemonAbsPath::try_new(absent_tmp.path().to_str().unwrap()).unwrap();
    let absent = LoopbackLeaseBook::open(&absent_root, RangeVerdict::Absent).unwrap();

    let me = SessionId::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
    let other = SessionId::parse_str("00000000-0000-0000-0000-000000000002").unwrap();
    let hand = Ipv4Addr::new(127, 0, 64, 9);
    let interim = Some(Ipv4Addr::LOCALHOST);
    let mut reg = HostnameRegistry::new("dev", false);

    // Present, name not yet registered (a first finalize): the hand.
    assert_eq!(
        super::promote_interim_to_hand(&reg, &present, me, "promo", interim, Some(hand)),
        Some(hand)
    );
    // Absent: the hand is not vouched for, so the interim stands.
    assert_eq!(
        super::promote_interim_to_hand(&reg, &absent, me, "promo", interim, Some(hand)),
        None
    );
    // Only an interim publish with a hand behind it moves.
    assert_eq!(
        super::promote_interim_to_hand(&reg, &present, me, "promo", Some(hand), Some(hand)),
        None
    );
    assert_eq!(
        super::promote_interim_to_hand(&reg, &present, me, "promo", interim, None),
        None
    );

    // Present, the name already this session's own (a resume): the hand.
    reg.publish_own_address(me, "promo", Ipv4Addr::LOCALHOST, BTreeSet::new());
    reg.register_own_ip(me, "promo", BTreeSet::new());
    assert!(reg.name_held_by(me, "promo"));
    assert_eq!(
        super::promote_interim_to_hand(&reg, &present, me, "promo", interim, Some(hand)),
        Some(hand)
    );

    // Present, but the session no longer holds the name — another box
    // took it: no promotion over that box's name.
    reg.withdraw_own_name(me, "promo");
    reg.publish_own_address(
        other,
        "promo",
        Ipv4Addr::new(127, 0, 64, 10),
        BTreeSet::new(),
    );
    reg.register_own_ip(other, "promo", BTreeSet::new());
    assert!(reg.name_held_by(other, "promo"));
    assert_eq!(
        super::promote_interim_to_hand(&reg, &present, me, "promo", interim, Some(hand)),
        None
    );
}

/// The call that helper was extracted from, driven through
/// `register_hostname` itself rather than `promote_interim_to_hand` on its
/// own ([`the_write_lock_promotion_moves_an_interim_to_a_vouched_hand_only`]
/// pins the decision; this pins that the registration makes the call): a
/// registration whose ask the unvouched verdict answered with the
/// `127.0.0.1` interim publishes at its hand instead when the verdict
/// lands present before the write lock — the window the re-read under the
/// lock exists for, so a registration that skips the call leaves the box
/// standing at the interim.
///
/// The window is driven deterministically, with no timer deciding
/// anything: the box's first finalize is the one registration that waits
/// for the verdict, and that wait — the one await between the ask and the
/// publish — is where the test takes the registry's write lock. An
/// **absent** landing wakes the ask, which answers the interim (one
/// `loopback-hand-to-interim` line) and parks the registration on the
/// held lock; the waiters count reaching zero is the proof the ask
/// consumed the absent answer before the next landing is stored. A
/// **present** landing then goes in through the raw verdict store — the
/// half of a real landing that runs *before* its sweep takes this very
/// lock, so the sweep cannot be what moves the box; the sweep's own move
/// is [`an_interim_handed_publish_takes_its_hand_when_the_verdict_lands_late`]'s
/// to pin. The whole window is one synchronous region — the registration
/// is the task parked, on a worker, and the write lock is never held
/// across an await. Releasing the lock lets the registration publish, and
/// it must take its hand.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn register_hostname_promotes_an_interim_to_its_vouched_hand() {
    let capture = crate::test_harness::captured_log();
    let server = TestServer::new().await;
    let manager = server.state.sessions_manager().await;
    manager.hold_range_verdict_pending();
    // Far out, so nothing here is decided by the deadline: the window's two
    // ends are landings, not expiries.
    manager.reset_hand_verdict_deadline(DEADLINE_HELD_OPEN_MS);
    let mut client = server.connect().await;
    let handed = std::net::Ipv4Addr::new(127, 0, 64, 9);
    let web = create_handed_own_ip_session(
        &mut client,
        "web",
        std::net::Ipv4Addr::new(100, 64, 128, 9),
        handed,
    )
    .await;

    // The finalize's registration parks on the pending verdict — past its
    // read of the registry, ahead of its publish.
    let mut finalize_client = server.connect().await;
    let finalize = tokio::spawn(async move { finalize_session(&mut finalize_client, web).await });
    await_verdict_waiter(&manager).await;

    // The registry's write lock, held across both landings in one
    // synchronous region — the registration is the task that parks here,
    // with the interim answer in hand, so the lock is never held across an
    // await: the parked registration has already read the registry, and
    // this is exactly the spot its re-read under the lock exists for.
    let registry = manager.hostnames();
    {
        let parked = registry.write().expect("registry lock");

        // The ask answers the interim: an absent landing wakes the parked
        // waiter with "not vouched", and the registration heads for
        // `127.0.0.1`.
        manager
            .loopback_book()
            .set_range_verdict(crate::net::dns::RangeVerdict::Absent);
        // The ask has consumed the absent answer only once its waiter is
        // gone — before that, a present landing could still be the one it
        // reads. Waited out synchronously: the registration parks on this
        // very lock while this thread waits, and the lock must not cross
        // an await.
        for _ in 0..12_000 {
            if manager.verdict_waiters() == 0 {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(
            manager.verdict_waiters(),
            0,
            "the registration left its wait on the absent landing"
        );

        // The verdict lands present through the raw store — not the
        // landing's sweep, which would take this very lock — so the
        // registration's own re-read is the only thing that can move the
        // box.
        manager
            .loopback_book()
            .set_range_verdict(crate::net::dns::RangeVerdict::Present);

        // The registration, parked on this lock since its ask answered the
        // interim, takes it now.
        drop(parked);
    }

    finalize.await.expect("the finalize's task runs to its end");

    // The hand is the published address — never the interim the ask
    // answered with — and the name answers with it.
    assert_eq!(
        registry
            .read()
            .expect("registry lock")
            .published_own_address(web),
        Some(handed),
        "a registration headed for the interim publishes at its own hand"
    );
    let (_, address) = zone_answer_for(&server, "web.min.internal")
        .await
        .expect("the name is held once the registration ends");
    assert_eq!(
        address, handed,
        "the name answers at the hand, moved with the publish"
    );
    assert_eq!(
        registry
            .read()
            .expect("registry lock")
            .resolve("web.min.internal:18080")
            .expect("the name routes at the hand")
            .upstream(18080),
        Some(std::net::SocketAddr::new(
            std::net::IpAddr::V4(handed),
            18080
        )),
        "the box's declared port is published at its own hand, exactly where \
         the attach path binds its forwards"
    );

    // The two lines the drive leaves: the interim answer it took under the
    // unvouched verdict, and the promotion that moved it — the one line
    // only the re-read emits, naming both addresses and the box.
    let logged = capture.contents();
    let interim_line = logged
        .lines()
        .find(|line| {
            line.contains("action=\"loopback-hand-to-interim\"")
                && line.contains("session_name=\"web\"")
        })
        .unwrap_or_else(|| panic!("the ask's interim answer must be logged, got: {logged}"));
    assert!(
        interim_line.contains(&format!("from={handed}")) && interim_line.contains("to=127.0.0.1"),
        "the interim answer names the hand it refused and the interim it \
         took: {interim_line}"
    );
    let promotion_line = logged
        .lines()
        .find(|line| {
            line.contains("action=\"loopback-range-present-box\"")
                && line.contains("session_name=\"web\"")
        })
        .unwrap_or_else(|| panic!("the promotion must be logged, got: {logged}"));
    assert!(
        promotion_line.contains("from=127.0.0.1")
            && promotion_line.contains(&format!("to={handed}")),
        "the promotion names the interim it moved off and the hand it moved \
         to: {promotion_line}"
    );
}

/// The box a `min net expose` request is decided against: an own-address box
/// whose ingress declares a dynamic-ingress mode and port range, and whose
/// creator handed it the address pair a publish needs (the T66 hand) — so the
/// tests below pin the decision and the publish it leads to, not the
/// plumbing around them. `mode: None` is the deny-all default a box that
/// declared nothing runs under.
pub(crate) fn dynamic_ingress_session_req(
    name: &str,
    switch: std::net::Ipv4Addr,
    loopback: std::net::Ipv4Addr,
    mode: Option<sessions::DynamicIngress>,
    range: Option<(u16, u16)>,
) -> minimald_rpc::CreateSessionRequest {
    let mut request = own_ip_session_req(name);
    let ingress = request
        .config
        .policy
        .ingress
        .as_mut()
        .expect("own_ip_session_req always declares an ingress policy");
    ingress.port_mappings.clear();
    ingress.dynamic_ingress = mode;
    ingress.dynamic_allowed_range = range;
    request.config.box_addresses = Some(sessions::BoxAddresses {
        switch_address: switch,
        loopback_address: loopback,
    });
    request
}

/// Drives Create → ConfigureLoadout → FinalizeSession for a
/// [`dynamic_ingress_session_req`] box and returns its id.
pub(crate) async fn finalize_dynamic_ingress_session(
    client: &mut TestClient,
    name: &str,
    switch: std::net::Ipv4Addr,
    loopback: std::net::Ipv4Addr,
    mode: Option<sessions::DynamicIngress>,
    range: Option<(u16, u16)>,
) -> SessionId {
    use minimald_rpc::{ConfigureLoadout, ConfigureLoadoutRequest, CreateSession};
    let id = client
        .call::<CreateSession>(&dynamic_ingress_session_req(
            name, switch, loopback, mode, range,
        ))
        .await
        .unwrap()
        .id;
    crate::test_harness::unwrap_ready(
        client
            .call::<ConfigureLoadout>(&ConfigureLoadoutRequest {
                session_id: id,
                contribution: Default::default(),
            })
            .await
            .unwrap(),
    );
    finalize_session(client, id).await;
    id
}

/// The box an expose reply's honesty is decided against: an own-address box
/// that declares one published port *and* allows dynamic ingress over a range
/// containing it, with the hand a publish needs — so one box's flow reaches
/// both halves of the reply's predicate (NET-047): the declared port, which
/// the gate admitted when the box attached, and a runtime-only port inside
/// the range, which is still waiting for it. [`dynamic_ingress_session_req`]
/// clears the declared mappings because its tests decide only runtime ones;
/// this keeps one, which is the point.
fn declared_and_dynamic_ingress_session_req(
    name: &str,
    switch: std::net::Ipv4Addr,
    loopback: std::net::Ipv4Addr,
) -> minimald_rpc::CreateSessionRequest {
    let mut request = own_ip_session_req(name);
    let ingress = request
        .config
        .policy
        .ingress
        .as_mut()
        .expect("own_ip_session_req always declares an ingress policy");
    ingress.port_mappings = vec![sessions::PortMapping {
        external_port: 3000,
        internal_port: 3000,
        proto: sessions::IpProto::Tcp,
    }];
    ingress.dynamic_ingress = Some(sessions::DynamicIngress::Allow);
    ingress.dynamic_allowed_range = Some((3000, 3999));
    request.config.box_addresses = Some(sessions::BoxAddresses {
        switch_address: switch,
        loopback_address: loopback,
    });
    request
}

/// Drives Create → ConfigureLoadout → FinalizeSession for a
/// [`declared_and_dynamic_ingress_session_req`] box and returns its id.
/// `pub(crate)`: the env channel's tests drive a real session's publish to
/// read the reply the box's own `min net expose` gets.
pub(crate) async fn finalize_declared_dynamic_ingress_session(
    client: &mut TestClient,
    name: &str,
    switch: std::net::Ipv4Addr,
    loopback: std::net::Ipv4Addr,
) -> SessionId {
    use minimald_rpc::{ConfigureLoadout, ConfigureLoadoutRequest, CreateSession};
    let id = client
        .call::<CreateSession>(&declared_and_dynamic_ingress_session_req(
            name, switch, loopback,
        ))
        .await
        .unwrap()
        .id;
    crate::test_harness::unwrap_ready(
        client
            .call::<ConfigureLoadout>(&ConfigureLoadoutRequest {
                session_id: id,
                contribution: Default::default(),
            })
            .await
            .unwrap(),
    );
    finalize_session(client, id).await;
    id
}

/// Reads one control request off `stream` — its head through the blank line,
/// then exactly its `Content-Length` of body — mirroring the keep-alive
/// framing [`crate::net::policy`] writes, so the stand-in forwarder below
/// never blocks reading past what the daemon sent. `None` when the client
/// went away mid-request.
async fn read_control_request(stream: &mut tokio::net::UnixStream) -> Option<String> {
    use tokio::io::AsyncReadExt;
    let mut buf = Vec::with_capacity(256);
    let mut scratch = [0u8; 512];
    let head_end = loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
        let n = stream.read(&mut scratch).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&scratch[..n]);
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
    let body_len = head
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.trim()
                .eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())?
        })
        .unwrap_or(0);
    let mut body = buf[head_end..].to_vec();
    while body.len() < body_len {
        let n = stream.read(&mut scratch).await.ok()?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&scratch[..n]);
    }
    let request_line = head.lines().next().unwrap_or_default().to_string();
    Some(format!(
        "{request_line}\n{}",
        String::from_utf8_lossy(&body)
    ))
}

/// A stand-in for the host gvproxy, bound at the daemon's switch control
/// socket: serves one request per connection, answering each with `status`,
/// and records every request it served as `"<request line>\n<body>"`. The
/// harness never spawns a real forwarder, so binding here is what puts a
/// control channel behind the publish verbs — a 500 answers the way the real
/// forwarder answers a bind it cannot make. `pub(crate)`: the env channel's
/// tests drive a real session's publish through the same stand-in.
pub(crate) async fn fake_forwarder(
    sock: std::path::PathBuf,
    status: u16,
) -> (
    tokio::task::JoinHandle<()>,
    std::sync::Arc<std::sync::Mutex<Vec<String>>>,
) {
    scripted_forwarder(sock, vec![status]).await
}

/// A stand-in for the host gvproxy that answers each request with the next
/// status of `script`, keeping the last for any request past them — so a test
/// can have the switch accept one bind and refuse the next, the way the real
/// forwarder answers a duplicate of a bind another forward already holds.
/// Everything else is [`fake_forwarder`]'s contract: one request per
/// connection, each recorded as `"<request line>\n<body>"`.
async fn scripted_forwarder(
    sock: std::path::PathBuf,
    script: Vec<u16>,
) -> (
    tokio::task::JoinHandle<()>,
    std::sync::Arc<std::sync::Mutex<Vec<String>>>,
) {
    use tokio::io::AsyncWriteExt;
    if let Some(parent) = sock.parent() {
        std::fs::create_dir_all(parent).expect("create the switch state dir");
    }
    let listener = tokio::net::UnixListener::bind(&sock).expect("bind the control socket");
    let served = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let recorded = served.clone();
    let server = tokio::spawn(async move {
        let mut script: std::collections::VecDeque<u16> = script.into();
        // The last status answers anything past the script, so a stand-in
        // scripted for two requests still answers a third.
        let last = *script.back().unwrap_or(&500);
        // Sequential on purpose: the publish verbs open a fresh connection
        // per request, so one connection served at a time is their shape.
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let Some(request) = read_control_request(&mut stream).await else {
                continue;
            };
            recorded.lock().expect("served lock").push(request);
            let status = script.pop_front().unwrap_or(last);
            let reason = if (200..300).contains(&status) {
                "OK"
            } else {
                "Internal Server Error"
            };
            // The request is what the test wants; a peer that closed before the
            // answer drained ends the round, which the next accept serves.
            #[expect(
                clippy::let_underscore_must_use,
                reason = "the answer's fate is not what the stand-in records; the request is"
            )]
            let _ = stream
                .write_all(
                    format!("HTTP/1.1 {status} {reason}\r\nContent-Length: 0\r\n\r\n").as_bytes(),
                )
                .await;
        }
    });
    (server, served)
}

/// What the gated stand-in below answers one request with.
#[derive(Clone)]
enum GateAnswer {
    /// Answer the request with this status, the way [`scripted_forwarder`]
    /// answers its script's.
    With(u16),
    /// Record the request but hold the answer — the connection stays open,
    /// the client stays awaiting its bind — until the test's gate counter
    /// passes the held answers the stand-in has already resolved, then
    /// answer with this status. A bind the stand-in holds is a bind the
    /// reserving surface is in flight across: the window in which the
    /// other surface must lose to the reservation, never to the switch.
    Held(u16),
}

/// [`scripted_forwarder`], with [`GateAnswer::Held`] answers a test times
/// itself: the stand-in serves one request per connection, recording each,
/// and a held answer is not sent until the test advances the returned gate
/// past the held answers it has already resolved — first held answer waits
/// for the counter to pass 0, the second for it to pass 1, and so on, so
/// sequential phases each open and close one in-flight bind of their own.
/// Returns the server, the record of every request it served, and the
/// gate a test advances to resolve the holds.
///
/// The script is keyed by port: a request is answered by the first entry
/// left for the port its `local` names, and a request for any other port is
/// answered 200 without touching the script. The watcher reads the host's
/// whole socket table, so a wildcard listener another test holds inside the
/// box's range is published too; keyed, its request can never take the
/// answer — or the hold — a phase scripted for its own port.
async fn gated_forwarder(
    sock: std::path::PathBuf,
    script: Vec<(u16, GateAnswer)>,
) -> (
    tokio::task::JoinHandle<()>,
    std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    tokio::sync::watch::Sender<u64>,
) {
    use tokio::io::AsyncWriteExt;
    if let Some(parent) = sock.parent() {
        std::fs::create_dir_all(parent).expect("create the switch state dir");
    }
    let listener = tokio::net::UnixListener::bind(&sock).expect("bind the control socket");
    let served = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let recorded = served.clone();
    let (gate_tx, gate_rx) = tokio::sync::watch::channel(0u64);
    let server = tokio::spawn(async move {
        let mut script = script;
        // Requests are read and recorded one at a time, in arrival order,
        // and each hold is numbered in that order; the answers are sent from
        // a task per connection, so a held bind never parks a request for
        // any other port behind it — the watcher's publish of a listener
        // another test holds is answered while a phase's hold is open.
        let mut held: u64 = 0;
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let Some(request) = read_control_request(&mut stream).await else {
                continue;
            };
            let port = request_port(&request);
            recorded.lock().expect("served lock").push(request);
            let scripted = script
                .iter()
                .position(|(scripted, _)| Some(*scripted) == port)
                .map(|at| script.remove(at).1);
            let (status, hold) = match scripted.unwrap_or(GateAnswer::With(200)) {
                GateAnswer::With(status) => (status, None),
                GateAnswer::Held(status) => {
                    // This is held request number `held + 1`: it waits for
                    // the gate to pass the `held` resolved before it.
                    held += 1;
                    (status, Some(held - 1))
                }
            };
            let mut gate_rx = gate_rx.clone();
            tokio::spawn(async move {
                if let Some(before) = hold {
                    // A dropped gate (the test gone) answers rather than
                    // parks the answer forever.
                    while *gate_rx.borrow() <= before {
                        if gate_rx.changed().await.is_err() {
                            break;
                        }
                    }
                }
                let reason = if (200..300).contains(&status) {
                    "OK"
                } else {
                    "Internal Server Error"
                };
                #[expect(
                    clippy::let_underscore_must_use,
                    reason = "the answer's fate is not what the stand-in records; the request is"
                )]
                let _ = stream
                    .write_all(
                        format!("HTTP/1.1 {status} {reason}\r\nContent-Length: 0\r\n\r\n")
                            .as_bytes(),
                    )
                    .await;
            });
        }
    });
    (server, served, gate_tx)
}

/// The port a control request's `local` names, if it names one.
fn request_port(request: &str) -> Option<u16> {
    let (_, rest) = request.split_once("\"local\":\"")?;
    let (local, _) = rest.split_once('"')?;
    local.rsplit_once(':')?.1.parse().ok()
}

/// NET-043: the session-create info line names the dynamic ingress stance
/// and the range the record holds, resolved the way the box runs them —
/// an absent stance reads as the deny the policy module evaluates it as,
/// not as a missing fact — so a diagnostics bundle's daemon-log tail shows
/// which setting a box was created with, beside the egress facts that were
/// already on the line. Both halves of the declaration are named: the mode
/// the box's creator chose for it, and the range that bounds the dynamic
/// requests the mode admits.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn create_logs_dynamic_ingress() {
    let capture = crate::test_harness::captured_log();
    let server = TestServer::new().await;
    let mut client = server.connect().await;

    use minimald_rpc::{CreateSession, CreateSessionRequest};
    // The allowing box over a range, and a bare box that declared nothing —
    // the two halves a bundle has to tell apart, by the lines they left.
    client
        .call::<CreateSession>(&dynamic_ingress_session_req(
            "dyn-allow-logged",
            std::net::Ipv4Addr::new(100, 64, 128, 31),
            std::net::Ipv4Addr::new(127, 0, 64, 31),
            Some(sessions::DynamicIngress::Allow),
            Some((3000, 3999)),
        ))
        .await
        .unwrap();
    client
        .call::<CreateSession>(&CreateSessionRequest {
            config: minimald_rpc::SessionConfig {
                name: Some("dyn-bare-logged".to_string()),
                project_path: paths::HostAbsPath::try_new("/uwu").unwrap(),
                network: sessions::NetworkMode::OwnIp,
                policy: sessions::SessionPolicy::default(),
                box_addresses: None,
                hooks_enabled: true,
                attrs: Default::default(),
            },
            must_match_version: None,
        })
        .await
        .unwrap();

    let logged = capture.contents();
    for (name, facts) in [
        (
            "dyn-allow-logged",
            [
                "dynamic_ingress=allow",
                "dynamic_allowed_range=Some((3000, 3999))",
            ],
        ),
        (
            "dyn-bare-logged",
            ["dynamic_ingress=deny", "dynamic_allowed_range=None"],
        ),
    ] {
        let start_line = logged
            .lines()
            .find(|line| line.contains("session starts") && line.contains(name))
            .unwrap_or_else(|| {
                panic!("the session start must be logged for {name}, got: {logged}")
            });
        for fact in facts {
            assert!(
                start_line.contains(fact),
                "the start line must name {fact}, got: {start_line}"
            );
        }
    }
}

/// NET-043: a port-publish request from inside a box is decided against the
/// box's own `dynamic_ingress` setting, on the local daemon — the un-enrolled
/// host's shape, where the same daemon that owns the switch answers the box
/// with no host in the middle. A box that allows publishes its port; a box
/// that declared nothing answers the deny-all default, and the switch is
/// asked nothing at all for it. The channel hop the in-box `min net expose`
/// takes is pinned by the session-channel test in `env`; this pins the
/// decision that hop lands on, and the request a publish rides: exactly the
/// shape a declared mapping with the same numbers takes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn expose_unenrolled_local_rpc_evaluates_dynamic_ingress() {
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    // The hand vouched for, so the registry publishes it: the publish below
    // binds at the address the box's name answers at, deterministically.
    let manager = server.state.sessions_manager().await;
    manager.land_range_verdict(crate::net::dns::RangeVerdict::Present);
    let web = finalize_dynamic_ingress_session(
        &mut client,
        "web",
        std::net::Ipv4Addr::new(100, 64, 128, 21),
        std::net::Ipv4Addr::new(127, 0, 64, 21),
        Some(sessions::DynamicIngress::Allow),
        Some((3000, 3999)),
    )
    .await;
    let db = finalize_dynamic_ingress_session(
        &mut client,
        "db",
        std::net::Ipv4Addr::new(100, 64, 128, 22),
        std::net::Ipv4Addr::new(127, 0, 64, 22),
        None,
        None,
    )
    .await;
    let web_handle = manager
        .get_session(crate::sessions::SessionKeyPredicate::Id(web))
        .await
        .unwrap()
        .expect("the allowing box resolves");
    let db_handle = manager
        .get_session(crate::sessions::SessionKeyPredicate::Id(db))
        .await
        .unwrap()
        .expect("the unenrolled box resolves");
    // A publish needs a box standing behind it, so the allowing box runs one.
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
    let (forwarder, served) = fake_forwarder(sock, 200).await;

    // The allowing box publishes; the unenrolled box answers the deny-all
    // default.
    web_handle
        .expose_dynamic(3000)
        .await
        .expect("a port the box's dynamic_ingress allows is published");
    match db_handle.expose_dynamic(3000).await {
        Err(crate::net::policy::ExposeFailure::Refused(
            crate::net::policy::ExposeRefusal::DeniedByPolicy,
        )) => {}
        other => panic!("the deny-all default refuses the request: {other:?}"),
    }
    forwarder.abort();

    // Exactly one request reached the switch — the allowing box's — and it is
    // the request a declared mapping with the same numbers takes: the
    // runtime publish rides the same wire shape the declaration does.
    let served = served.lock().expect("served lock");
    assert_eq!(
        served.len(),
        1,
        "a denied request asks the switch nothing: {served:?}"
    );
    let (line, body) = served[0]
        .split_once('\n')
        .expect("the served request carries its request line and body");
    assert!(
        line.starts_with("POST /services/forwarder/expose "),
        "the publish rides the forwarder's expose verb: {served:?}"
    );
    let declared = crate::net::policy::expose_request(
        &sessions::PortMapping {
            external_port: 3000,
            internal_port: 3000,
            proto: sessions::IpProto::Tcp,
        },
        std::net::Ipv4Addr::new(127, 0, 64, 21),
        std::net::Ipv4Addr::new(100, 64, 128, 21),
    );
    assert_eq!(
        body,
        String::from_utf8(serde_json_lenient::to_vec(&declared).unwrap()).unwrap(),
        "the runtime publish is the request a declared mapping with the same \
         numbers takes"
    );
}

/// NET-044: the allowing box's publish is a fact, not a permission — the
/// port is bound through the switch, the mapping is listed where
/// `min session policy` reads it, and a second request for the same live port
/// is refused as the duplicate it is, with the switch asked nothing for it.
/// The publish says its own line in the daemon log, naming the box, the port,
/// the decision, and the outcome.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn expose_allow_publishes_and_lists() {
    let capture = crate::test_harness::captured_log();
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    // The hand vouched for, so the registry publishes it and the publish
    // binds at the address the box's name answers at.
    let manager = server.state.sessions_manager().await;
    manager.land_range_verdict(crate::net::dns::RangeVerdict::Present);
    let web = finalize_dynamic_ingress_session(
        &mut client,
        // This test's own box name: under the shared capture every test's
        // lines ride one buffer, so each assertion finds its line by the
        // box it names.
        "listweb",
        std::net::Ipv4Addr::new(100, 64, 128, 21),
        std::net::Ipv4Addr::new(127, 0, 64, 21),
        Some(sessions::DynamicIngress::Allow),
        Some((3000, 3999)),
    )
    .await;
    let handle = manager
        .get_session(crate::sessions::SessionKeyPredicate::Id(web))
        .await
        .unwrap()
        .expect("the allowing box resolves");
    handle
        .ensure_host("tester".to_string())
        .await
        .expect("the allowing box launches its host");
    let sock = handle
        .net_switch()
        .await
        .unwrap()
        .lock()
        .await
        .control_socket();
    let (forwarder, served) = fake_forwarder(sock, 200).await;

    let mapping = handle
        .expose_dynamic(3000)
        .await
        .expect("the allowed port publishes");
    let expected = minimald_rpc::LiveMapping {
        local: "127.0.64.21:3000".to_string(),
        internal_port: 3000,
        proto: sessions::IpProto::Tcp,
        pending: Some(false),
    };
    assert_eq!(
        mapping, expected,
        "the mapping names the box's own address at its own port number"
    );

    // The port is published already, live: a second request for it would
    // double-bind the same address, so it is refused as the duplicate it is.
    match handle.expose_dynamic(3000).await {
        Err(crate::net::policy::ExposeFailure::Refused(
            crate::net::policy::ExposeRefusal::AlreadyPublished {
                port: 3000,
                owner: crate::net::listeners::PublicationOwner::Expose,
            },
        )) => {}
        other => panic!("a second request for a live port is a duplicate: {other:?}"),
    }
    forwarder.abort();
    assert_eq!(
        served.lock().expect("served lock").len(),
        1,
        "one mapping is one request"
    );

    // The publish is listed where `min session policy` reads it, by name and
    // by id alike — and it reads as what it is: pending, because the box's
    // relay gate admits the ports the *declaration* named, and this port
    // was published at runtime, outside it.
    let listed = minimald_rpc::LiveMapping {
        pending: Some(true),
        ..mapping.clone()
    };
    let by_name: minimald_rpc::Errorable<Vec<minimald_rpc::LiveMapping>> = client
        .call::<minimald_rpc::GetLiveIngress>(&minimald_rpc::GetLiveIngressRequest::Name(
            "listweb".to_string(),
        ))
        .await;
    assert_eq!(
        by_name,
        minimald_rpc::Errorable::Ok(vec![listed.clone()]),
        "the live mapping is listed beside the declaration, by name"
    );
    let by_id: minimald_rpc::Errorable<Vec<minimald_rpc::LiveMapping>> = client
        .call::<minimald_rpc::GetLiveIngress>(&minimald_rpc::GetLiveIngressRequest::Id(web))
        .await;
    assert_eq!(
        by_id,
        minimald_rpc::Errorable::Ok(vec![listed]),
        "the live mapping is listed beside the declaration, by id"
    );

    // The one line the request leaves in the log, with the box, the port, the
    // decision the box's setting made, and the outcome — found by this
    // test's own box name, the shared capture holding every test's lines.
    let logged = capture.contents();
    let line = logged
        .lines()
        .find(|line| {
            line.contains("dynamic ingress expose")
                && line.contains("name=listweb")
                && line.contains("outcome=\"published\"")
        })
        .unwrap_or_else(|| panic!("the publish must be logged, got: {logged}"));
    assert!(
        line.contains("port=3000")
            && line.contains("decision=allow")
            && line.contains("local=127.0.64.21:3000"),
        "the publish line names the box, the port, the decision and the \
         outcome: {line}"
    );
}

/// A stand-in for the VM host daemon's guest report door (T94, NET-138): a
/// UDS bound at `door`, speaking the door's own wire — one JSON request line
/// in, one JSON reply line back, the connection held open until the
/// reporter closes it, the real door's own posture — with the test holding
/// the one thing the real door's grant decides. Each request the stand-in
/// reads is handed to the test over `requests`, and each reply it writes is
/// the test's own word on `replies`, so a test can answer a report, refuse
/// it, or hold it — and observe a publish waiting on the answer.
pub(crate) async fn fake_report_door(
    door: impl Into<std::path::PathBuf>,
) -> (
    tokio::task::JoinHandle<()>,
    tokio::sync::mpsc::UnboundedReceiver<minimald_rpc::BoxControlRequest>,
    tokio::sync::mpsc::UnboundedSender<minimald_rpc::BoxControlReply>,
) {
    use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _};
    let door = door.into();
    if let Some(parent) = door.parent() {
        std::fs::create_dir_all(parent).expect("create the report door's dir");
    }
    let listener = tokio::net::UnixListener::bind(&door).expect("bind the report door stand-in");
    let (requests_tx, requests) = tokio::sync::mpsc::unbounded_channel();
    let (replies, mut replies_rx) =
        tokio::sync::mpsc::unbounded_channel::<minimald_rpc::BoxControlReply>();
    let door_task = tokio::spawn(async move {
        // One connection at a time, the real door's own posture: the door
        // serves serially and holds each connection open until the
        // reporter, which has its reply, closes from its side.
        while let Ok((stream, _)) = listener.accept().await {
            let (read, mut write) = stream.into_split();
            let mut reader = tokio::io::BufReader::new(read);
            let mut line = String::new();
            if reader.read_line(&mut line).await.is_err() || line.trim().is_empty() {
                // A connect and leave: nothing to answer and nothing in
                // the connection, so the door takes the next one.
                continue;
            }
            let request =
                serde_json_lenient::from_str::<minimald_rpc::BoxControlRequest>(line.trim())
                    .expect("the report door's request line parses");
            #[expect(
                clippy::let_underscore_must_use,
                reason = "the test may drop its receiver once it has its answer"
            )]
            let _ = requests_tx.send(request);
            let Some(reply) = replies_rx.recv().await else {
                // The test closed the door's answering side, so the door
                // ends rather than answer a report with nothing.
                return;
            };
            let mut reply_line =
                serde_json_lenient::to_string(&reply).expect("the report reply serialises");
            reply_line.push('\n');
            if write.write_all(reply_line.as_bytes()).await.is_err() {
                continue;
            }
            // The real door never closes a connection first (G-N8): it
            // waits for the reporter's close, so the stand-in drains the
            // connection until the reporter drops it.
            let mut sink = [0u8; 512];
            loop {
                match reader.read(&mut sink).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
            }
        }
    });
    (door_task, requests, replies)
}

/// T94, NET-138: on a VM-backed host an expose decided allow is a report
/// first and a publish second. The switch's forward is bound, and then the
/// VM host daemon's grant decides the report over the guest report door —
/// the publish is reported to the caller only once the door vouched for
/// the port, so while the door holds its reply the caller has heard
/// nothing at all, and the report the door read names the row's own key
/// (the box's switch address), the port, the protocol and the side that
/// reported it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn vm_backed_expose_reports_admission_to_host() {
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    // The hand vouched for, so the registry publishes it and the publish
    // below binds at the address the box's name answers at.
    let manager = server.state.sessions_manager().await;
    manager.land_range_verdict(crate::net::dns::RangeVerdict::Present);
    let web = finalize_dynamic_ingress_session(
        &mut client,
        "vmrepweb",
        std::net::Ipv4Addr::new(100, 64, 128, 21),
        std::net::Ipv4Addr::new(127, 0, 64, 21),
        Some(sessions::DynamicIngress::Allow),
        Some((3000, 3999)),
    )
    .await;
    let handle = manager
        .get_session(crate::sessions::SessionKeyPredicate::Id(web))
        .await
        .unwrap()
        .expect("the allowing box resolves");
    handle
        .ensure_host("tester".to_string())
        .await
        .expect("the allowing box launches its host");
    let sock = handle
        .net_switch()
        .await
        .unwrap()
        .lock()
        .await
        .control_socket();
    let (forwarder, served) = fake_forwarder(sock.clone(), 200).await;
    let door_sock = sock.with_file_name("report-door.sock");
    let (door, mut reports, replies) = fake_report_door(&door_sock).await;
    crate::net::listeners::seed_vm_report_door_for_tests(&sock, &door_sock);

    // The report is the caller's gate and the switch's: the door holds its
    // reply, and the publish has asked the switch nothing yet — the host's
    // egress gate admits a bind only for a port the grant holds — nor is it
    // the caller's word until the door answers.
    let reporting = handle.clone();
    let expose = tokio::spawn(async move { reporting.expose_dynamic(3000).await });
    let request = tokio::time::timeout(Duration::from_secs(5), reports.recv())
        .await
        .expect("an expose decided allow reaches the VM host daemon's report door")
        .expect("the report door stand-in lives");
    assert!(
        !expose.is_finished(),
        "the publish is reported to the caller only after the VM host daemon \
         answered the port report"
    );
    assert!(
        served.lock().expect("served lock").is_empty(),
        "the switch is asked to bind only after the VM host daemon admitted \
         the port: {:?}",
        served.lock().expect("served lock")
    );
    assert_eq!(
        request,
        minimald_rpc::BoxControlRequest::AdmitPort(minimald_rpc::AdmitPortRequest {
            switch_address: std::net::Ipv4Addr::new(100, 64, 128, 21),
            port: 3000,
            proto: sessions::IpProto::Tcp,
            source: minimald_rpc::PortReportSource::Expose,
        }),
        "the report carries the row's own key, the port, the protocol and the \
         side that reported it"
    );

    // The door vouches for the port, and only then does the caller hear
    // the mapping it published.
    replies
        .send(minimald_rpc::BoxControlReply::PortRecorded {
            port: 3000,
            proto: sessions::IpProto::Tcp,
        })
        .expect("the report door stand-in lives");
    let mapping = expose
        .await
        .expect("the expose task should not panic")
        .expect("the port the VM host daemon admitted publishes");
    assert_eq!(
        mapping,
        minimald_rpc::LiveMapping {
            local: "127.0.64.21:3000".to_string(),
            internal_port: 3000,
            proto: sessions::IpProto::Tcp,
            pending: Some(false),
        },
        "the caller hears the mapping the host vouched for"
    );

    // The switch was asked once — the forwarder's bind — and nothing else:
    // the report rides the door, never the switch's control socket.
    forwarder.abort();
    let served = served.lock().expect("served lock");
    assert_eq!(
        served.len(),
        1,
        "one publish is one request of the switch: {served:?}"
    );
    assert!(
        served[0].starts_with("POST /services/forwarder/expose "),
        "the one switch request is the forward's bind: {served:?}"
    );
    drop(served);
    drop(replies);
    door.abort();
    crate::net::listeners::clear_vm_report_door_for_tests(&sock);
}

/// T94, NET-138: a report the VM host daemon's grant refuses publishes
/// nothing — the switch is never asked to bind, the reservation the
/// publish held is given back, the live
/// listing names nothing, and a caller that asks again is asking for a
/// port nothing holds, never an `AlreadyPublished` a leaked entry would
/// answer with. The refusal the caller hears carries the grant's own
/// reason, and the daemon says the one warn line a refused report owes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refused_admission_report_leaves_no_partial_mapping() {
    let capture = crate::test_harness::captured_log();
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let manager = server.state.sessions_manager().await;
    manager.land_range_verdict(crate::net::dns::RangeVerdict::Present);
    let web = finalize_dynamic_ingress_session(
        &mut client,
        "vmrefweb",
        std::net::Ipv4Addr::new(100, 64, 128, 21),
        std::net::Ipv4Addr::new(127, 0, 64, 21),
        Some(sessions::DynamicIngress::Allow),
        Some((3000, 3999)),
    )
    .await;
    let handle = manager
        .get_session(crate::sessions::SessionKeyPredicate::Id(web))
        .await
        .unwrap()
        .expect("the allowing box resolves");
    handle
        .ensure_host("tester".to_string())
        .await
        .expect("the allowing box launches its host");
    let sock = handle
        .net_switch()
        .await
        .unwrap()
        .lock()
        .await
        .control_socket();
    let (forwarder, served) = fake_forwarder(sock.clone(), 200).await;
    let door_sock = sock.with_file_name("report-door.sock");
    let (door, mut reports, replies) = fake_report_door(&door_sock).await;
    crate::net::listeners::seed_vm_report_door_for_tests(&sock, &door_sock);

    // The grant refuses the report, and the refusal is the caller's answer:
    // the publish failed, carrying the grant's own reason.
    let reporting = handle.clone();
    let expose = tokio::spawn(async move { reporting.expose_dynamic(3000).await });
    let request = tokio::time::timeout(Duration::from_secs(5), reports.recv())
        .await
        .expect("the publish reaches the VM host daemon's report door")
        .expect("the report door stand-in lives");
    assert_eq!(
        request,
        minimald_rpc::BoxControlRequest::AdmitPort(minimald_rpc::AdmitPortRequest {
            switch_address: std::net::Ipv4Addr::new(100, 64, 128, 21),
            port: 3000,
            proto: sessions::IpProto::Tcp,
            source: minimald_rpc::PortReportSource::Expose,
        }),
        "the refused report is the same shape an admitted one is: the row's \
         own key, the port, the protocol and the reporting side"
    );
    let refusal = "the box's host-held grant does not admit this port";
    replies
        .send(minimald_rpc::BoxControlReply::Error {
            error: refusal.to_string(),
        })
        .expect("the report door stand-in lives");
    match expose.await.expect("the expose task should not panic") {
        Err(crate::net::policy::ExposeFailure::Publish { port, source }) => {
            assert_eq!(port, 3000, "the failed publish names its port");
            assert!(
                source.to_string().contains(refusal),
                "the refused publish carries the grant's own reason: {source}"
            );
        }
        other => panic!("a report the grant refused must fail the publish: {other:?}"),
    }
    // The refused report asked the switch nothing (T94's ordering): the bind
    // waits on the grant, so a refused grant leaves nothing to unbind.
    assert!(
        served.lock().expect("served lock").is_empty(),
        "a publish whose report the grant refused never asks the switch: {:?}",
        served.lock().expect("served lock")
    );

    // No partial mapping, the listing first: the row the policy surfaces
    // read names nothing the refused publish left behind (NET-047).
    let listed: minimald_rpc::Errorable<Vec<minimald_rpc::LiveMapping>> = client
        .call::<minimald_rpc::GetLiveIngress>(&minimald_rpc::GetLiveIngressRequest::Name(
            "vmrefweb".to_string(),
        ))
        .await;
    assert_eq!(
        listed,
        minimald_rpc::Errorable::Ok(vec![]),
        "a publish the host refused leaves no live mapping listed"
    );

    // And no partial mapping the set's way either: the port the refusal
    // unwound is owed again, so a second ask reaches the door afresh —
    // never the `AlreadyPublished` a leaked reservation would answer with.
    let reporting = handle.clone();
    let expose = tokio::spawn(async move { reporting.expose_dynamic(3000).await });
    let request = tokio::time::timeout(Duration::from_secs(5), reports.recv())
        .await
        .expect("the second ask reaches the VM host daemon's report door")
        .expect("the report door stand-in lives");
    assert_eq!(
        request,
        minimald_rpc::BoxControlRequest::AdmitPort(minimald_rpc::AdmitPortRequest {
            switch_address: std::net::Ipv4Addr::new(100, 64, 128, 21),
            port: 3000,
            proto: sessions::IpProto::Tcp,
            source: minimald_rpc::PortReportSource::Expose,
        }),
        "the port the refusal unwound is publishable again: the set gave it back"
    );
    replies
        .send(minimald_rpc::BoxControlReply::PortRecorded {
            port: 3000,
            proto: sessions::IpProto::Tcp,
        })
        .expect("the report door stand-in lives");
    expose
        .await
        .expect("the expose task should not panic")
        .expect("the port the host admitted on the second ask publishes");

    // The refused report asked the switch nothing; the second ask's bind is
    // the only switch request — the report never rode it.
    forwarder.abort();
    let served = served.lock().expect("served lock");
    assert_eq!(
        served.len(),
        1,
        "the refused publish never asked the switch to bind: {served:?}"
    );
    assert!(
        served[0].starts_with("POST /services/forwarder/expose "),
        "the second ask binds afresh: {served:?}"
    );
    drop(served);
    drop(replies);
    door.abort();
    crate::net::listeners::clear_vm_report_door_for_tests(&sock);

    // The one warn line a refused report owes (T94's diagnostics): the box,
    // the port and the grant's reason.
    let logged = capture.contents();
    let line = logged
        .lines()
        .find(|line| {
            line.contains("the VM host daemon did not admit the port report")
                && line.contains("name=Some(\"vmrefweb\")")
        })
        .unwrap_or_else(|| panic!("the refused report must say its warn line, got: {logged}"));
    assert!(
        line.contains("port=3000")
            && line.contains("reason")
            && line.contains(refusal)
            && line.contains("source=Expose"),
        "the refused report's line names the box, the port, the reporting \
         side and the reason: {line}"
    );
}

/// Drives Create → ConfigureLoadout → FinalizeSession for a native host's
/// self-allocated box: the [`dynamic_ingress_session_req`] declaration with
/// no `box_addresses` handed, so finalize publishes it at the answerer's
/// grant and the hostname registry is the only place its address lives.
async fn finalize_self_allocated_dynamic_ingress_session(
    client: &mut TestClient,
    name: &str,
    mode: Option<sessions::DynamicIngress>,
    range: Option<(u16, u16)>,
) -> SessionId {
    use minimald_rpc::{ConfigureLoadout, ConfigureLoadoutRequest, CreateSession};
    let mut request = dynamic_ingress_session_req(
        name,
        std::net::Ipv4Addr::UNSPECIFIED,
        std::net::Ipv4Addr::UNSPECIFIED,
        mode,
        range,
    );
    request.config.box_addresses = None;
    let id = client.call::<CreateSession>(&request).await.unwrap().id;
    crate::test_harness::unwrap_ready(
        client
            .call::<ConfigureLoadout>(&ConfigureLoadoutRequest {
                session_id: id,
                contribution: Default::default(),
            })
            .await
            .unwrap(),
    );
    finalize_session(client, id).await;
    id
}

/// NET-044 on a native host: a self-allocated box carries no `box_addresses`,
/// so its runtime publish rides what the hostname registry holds for its
/// session (design §7.1) — the address the box published at, where its
/// declared ports bind and its name answers, and the lease its running PTask
/// reported, which those forwards deliver to. The request the switch is asked
/// is exactly the one a declared mapping at that pair takes, and the mapping
/// is listed where `min session policy` reads it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn expose_self_allocated_box_publishes_at_its_registered_address() {
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let web = finalize_self_allocated_dynamic_ingress_session(
        &mut client,
        "selfweb",
        Some(sessions::DynamicIngress::Allow),
        Some((3000, 3999)),
    )
    .await;
    let manager = server.state.sessions_manager().await;
    let registry = manager.hostnames();
    let published = registry
        .read()
        .expect("registry lock")
        .published_own_address(web)
        .expect("finalize publishes a self-allocated box at the answerer's grant");
    // The stand-in for the box's attach: its PTask reports the lease it
    // attached with, as `finish_own_ip_attach` does.
    let lease = std::net::Ipv4Addr::new(100, 64, 128, 41);
    registry.write().expect("registry lock").report_own_address(
        web,
        "selfweb",
        lease,
        std::collections::BTreeMap::new(),
    );
    let handle = manager
        .get_session(crate::sessions::SessionKeyPredicate::Id(web))
        .await
        .unwrap()
        .expect("the allowing box resolves");
    handle
        .ensure_host("tester".to_string())
        .await
        .expect("the allowing box launches its host");
    let sock = handle
        .net_switch()
        .await
        .unwrap()
        .lock()
        .await
        .control_socket();
    let (forwarder, served) = fake_forwarder(sock, 200).await;

    let mapping = handle
        .expose_dynamic(3000)
        .await
        .expect("a self-allocated box's allowed port publishes");
    forwarder.abort();
    assert_eq!(
        mapping,
        minimald_rpc::LiveMapping {
            local: format!("{published}:3000"),
            internal_port: 3000,
            proto: sessions::IpProto::Tcp,
            pending: Some(false),
        },
        "the mapping names the box's registered address at its own port number"
    );

    // The publish is the request a declared mapping at the same pair takes:
    // bound at the registered address, delivered to the reported lease.
    let served = served.lock().expect("served lock").clone();
    assert_eq!(served.len(), 1, "one mapping is one request: {served:?}");
    let (line, body) = served[0]
        .split_once('\n')
        .expect("the served request carries its request line and body");
    assert!(
        line.starts_with("POST /services/forwarder/expose "),
        "the publish rides the forwarder's expose verb: {served:?}"
    );
    let declared = crate::net::policy::expose_request(
        &sessions::PortMapping {
            external_port: 3000,
            internal_port: 3000,
            proto: sessions::IpProto::Tcp,
        },
        published,
        lease,
    );
    assert_eq!(
        body,
        String::from_utf8(serde_json_lenient::to_vec(&declared).unwrap()).unwrap(),
        "the runtime publish binds where the declared ports bind"
    );

    let live: minimald_rpc::Errorable<Vec<minimald_rpc::LiveMapping>> = client
        .call::<minimald_rpc::GetLiveIngress>(&minimald_rpc::GetLiveIngressRequest::Name(
            "selfweb".to_string(),
        ))
        .await;
    // The row reads as what it is: pending, the gate not having admitted a
    // runtime-published port yet.
    assert_eq!(
        live,
        minimald_rpc::Errorable::Ok(vec![minimald_rpc::LiveMapping {
            pending: Some(true),
            ..mapping
        }]),
        "the live mapping is listed beside the declaration"
    );
}

/// The typed refusals a self-allocated box still answers when the registry
/// holds no address pair for it, each naming the half that is missing: no
/// PTask has reported a lease to deliver to — the box is not attached yet,
/// which starting it fixes — or the box holds no published address to bind
/// at, a capability gap the daemon has no default to stand in for (NET-010).
/// Neither is a policy deny, the switch is asked nothing, and no mapping is
/// listed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn expose_self_allocated_box_without_a_registered_address_is_refused() {
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let web = finalize_self_allocated_dynamic_ingress_session(
        &mut client,
        "selfweb",
        Some(sessions::DynamicIngress::Allow),
        Some((3000, 3999)),
    )
    .await;
    let manager = server.state.sessions_manager().await;
    let registry = manager.hostnames();
    let handle = manager
        .get_session(crate::sessions::SessionKeyPredicate::Id(web))
        .await
        .unwrap()
        .expect("the allowing box resolves");
    // The two refusals below are about the address pair, not about the box
    // running: a live host, so the not-running refusal is not the one they
    // exercise.
    handle
        .ensure_host("tester".to_string())
        .await
        .expect("the allowing box launches its host");
    let sock = handle
        .net_switch()
        .await
        .unwrap()
        .lock()
        .await
        .control_socket();
    let (forwarder, served) = fake_forwarder(sock, 200).await;

    // Published at the grant, but no PTask has reported a lease.
    match handle.expose_dynamic(3000).await {
        Err(crate::net::policy::ExposeFailure::Refused(
            crate::net::policy::ExposeRefusal::NotAttached,
        )) => {}
        other => panic!("a box with no reported lease is refused as not attached: {other:?}"),
    }

    // A lease reported, but the box's publish withdrawn.
    {
        let mut routes = registry.write().expect("registry lock");
        routes.report_own_address(
            web,
            "selfweb",
            std::net::Ipv4Addr::new(100, 64, 128, 42),
            std::collections::BTreeMap::new(),
        );
        routes.unpublish_own_address(web);
    }
    match handle.expose_dynamic(3000).await {
        Err(crate::net::policy::ExposeFailure::Refused(
            crate::net::policy::ExposeRefusal::NoPublishedAddress,
        )) => {}
        other => panic!("a box with no published address is refused: {other:?}"),
    }
    forwarder.abort();
    assert!(
        served.lock().expect("served lock").is_empty(),
        "a refused request asks the switch nothing"
    );

    let live: minimald_rpc::Errorable<Vec<minimald_rpc::LiveMapping>> = client
        .call::<minimald_rpc::GetLiveIngress>(&minimald_rpc::GetLiveIngressRequest::Id(web))
        .await;
    assert_eq!(
        live,
        minimald_rpc::Errorable::Ok(vec![]),
        "a refused box lists nothing"
    );
}

/// NET-044's deny arm: a denied request answers with the typed refusal, not a
/// bare message — a caller can tell "this box denies dynamic ingress" apart
/// from every other reason without parsing prose. Both halves of the default
/// refuse: a box that declares deny explicitly, and a box that declared
/// nothing at all. Neither asks the switch anything, and neither lists a
/// mapping.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn expose_deny_typed_error() {
    let capture = crate::test_harness::captured_log();
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    // This test's own box names: under the shared capture every test's lines
    // ride one buffer, so each assertion finds its lines by the box they
    // name.
    let closed = finalize_dynamic_ingress_session(
        &mut client,
        "denyclosed",
        std::net::Ipv4Addr::new(100, 64, 128, 31),
        std::net::Ipv4Addr::new(127, 0, 64, 31),
        Some(sessions::DynamicIngress::Deny),
        Some((3000, 3999)),
    )
    .await;
    let bare = finalize_dynamic_ingress_session(
        &mut client,
        "denybare",
        std::net::Ipv4Addr::new(100, 64, 128, 32),
        std::net::Ipv4Addr::new(127, 0, 64, 32),
        None,
        None,
    )
    .await;
    let manager = server.state.sessions_manager().await;
    let handles = [
        manager
            .get_session(crate::sessions::SessionKeyPredicate::Id(closed))
            .await
            .unwrap()
            .expect("the denying box resolves"),
        manager
            .get_session(crate::sessions::SessionKeyPredicate::Id(bare))
            .await
            .unwrap()
            .expect("the unenrolled box resolves"),
    ];
    let sock = handles[0]
        .net_switch()
        .await
        .unwrap()
        .lock()
        .await
        .control_socket();
    let (forwarder, served) = fake_forwarder(sock, 200).await;

    for handle in &handles {
        match handle.expose_dynamic(3000).await {
            Err(crate::net::policy::ExposeFailure::Refused(
                crate::net::policy::ExposeRefusal::DeniedByPolicy,
            )) => {}
            other => panic!("a denied request answers the typed refusal: {other:?}"),
        }
    }
    forwarder.abort();
    assert!(
        served.lock().expect("served lock").is_empty(),
        "a denied request asks the switch nothing"
    );

    // Neither box lists a mapping: the refusal published nothing.
    let live: minimald_rpc::Errorable<Vec<minimald_rpc::LiveMapping>> = client
        .call::<minimald_rpc::GetLiveIngress>(&minimald_rpc::GetLiveIngressRequest::Id(closed))
        .await;
    assert_eq!(
        live,
        minimald_rpc::Errorable::Ok(vec![]),
        "the denying box lists nothing"
    );
    let live: minimald_rpc::Errorable<Vec<minimald_rpc::LiveMapping>> = client
        .call::<minimald_rpc::GetLiveIngress>(&minimald_rpc::GetLiveIngressRequest::Name(
            "denybare".to_string(),
        ))
        .await;
    assert_eq!(
        live,
        minimald_rpc::Errorable::Ok(vec![]),
        "the unenrolled box lists nothing"
    );

    // Both refusals say their line, each naming the box, the port, the
    // decision the box's setting made, and the reason — counted and taken
    // per box name, the shared capture holding every test's refused lines.
    let logged = capture.contents();
    for name in ["denyclosed", "denybare"] {
        let refused: Vec<&str> = logged
            .lines()
            .filter(|line| {
                line.contains("dynamic ingress expose") && line.contains(&format!("name={name}"))
            })
            .collect();
        assert_eq!(
            refused.len(),
            1,
            "one refused line per request for {name}, got: {logged}"
        );
        assert!(
            refused[0].contains("port=3000")
                && refused[0].contains("decision=deny")
                && refused[0].contains("reason=dynamic ingress is denied for this box"),
            "the refusal names the port, the decision and the reason: {}",
            refused[0]
        );
    }
}

/// NET-047: a request that does not end in a publish leaves nothing behind —
/// no half-bound port, no row the policy surfaces would lie about. The two
/// ways a request fails: refused before the switch is asked (the port outside
/// the box's declared range) and a publish the switch itself refused. The
/// first asks the switch nothing; the second is one request that failed, and
/// after it the list is empty and the port free to be asked again — a failed
/// bind does not quietly claim its port as live.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn expose_rejected_leaves_no_partial_mapping() {
    let capture = crate::test_harness::captured_log();
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let web = finalize_dynamic_ingress_session(
        &mut client,
        "web",
        std::net::Ipv4Addr::new(100, 64, 128, 23),
        std::net::Ipv4Addr::new(127, 0, 64, 23),
        Some(sessions::DynamicIngress::Allow),
        Some((3000, 3999)),
    )
    .await;
    let manager = server.state.sessions_manager().await;
    let handle = manager
        .get_session(crate::sessions::SessionKeyPredicate::Id(web))
        .await
        .unwrap()
        .expect("the allowing box resolves");
    // The in-range request below reaches the switch, so a box must be
    // standing behind it.
    handle
        .ensure_host("tester".to_string())
        .await
        .expect("the allowing box launches its host");
    let sock = handle
        .net_switch()
        .await
        .unwrap()
        .lock()
        .await
        .control_socket();
    // The forwarder refuses every bind: the in-range request reaches it and
    // fails there.
    let (forwarder, served) = fake_forwarder(sock, 500).await;

    // Out of range: refused before the switch is asked anything.
    match handle.expose_dynamic(4500).await {
        Err(crate::net::policy::ExposeFailure::Refused(
            crate::net::policy::ExposeRefusal::OutOfRange {
                requested: 4500,
                range: (3000, 3999),
            },
        )) => {}
        other => panic!("a port outside the declared range is refused: {other:?}"),
    }
    assert!(
        served.lock().expect("served lock").is_empty(),
        "an out-of-range request asks the switch nothing"
    );

    // In range, and the switch refuses the bind: the publish fails.
    match handle.expose_dynamic(3000).await {
        Err(crate::net::policy::ExposeFailure::Publish { port: 3000, .. }) => {}
        other => panic!("a bind the switch refuses fails the publish: {other:?}"),
    }
    assert_eq!(
        served.lock().expect("served lock").len(),
        1,
        "one mapping is one request, and a failed one leaves nothing to undo"
    );

    // Nothing is left behind: the list is empty, and the port is free to be
    // asked again — the failed bind did not record itself as live.
    let live: minimald_rpc::Errorable<Vec<minimald_rpc::LiveMapping>> = client
        .call::<minimald_rpc::GetLiveIngress>(&minimald_rpc::GetLiveIngressRequest::Id(web))
        .await;
    assert_eq!(
        live,
        minimald_rpc::Errorable::Ok(vec![]),
        "a rejected publish leaves no partial mapping"
    );
    match handle.expose_dynamic(3000).await {
        Err(crate::net::policy::ExposeFailure::Publish { port: 3000, .. }) => {}
        other => panic!("the failed bind left the port free to be asked again: {other:?}"),
    }
    assert_eq!(
        served.lock().expect("served lock").len(),
        2,
        "the retry reached the switch again: nothing was recorded as live"
    );
    forwarder.abort();

    // Both outcomes say their line, each naming why.
    let logged = capture.contents();
    let refused_line = logged
        .lines()
        .find(|line| {
            line.contains("dynamic ingress expose")
                && line.contains("outcome=\"refused\"")
                && line.contains("port=4500")
        })
        .unwrap_or_else(|| panic!("the out-of-range refusal must be logged, got: {logged}"));
    assert!(
        refused_line
            .contains("reason=port 4500 is outside this box's declared dynamic range 3000-3999"),
        "the refusal names the port and the declared range: {refused_line}"
    );
    let failed_line = logged
        .lines()
        .find(|line| {
            line.contains("dynamic ingress expose")
                && line.contains("outcome=\"publish failed\"")
                && line.contains("port=3000")
        })
        .unwrap_or_else(|| panic!("the failed publish must be logged, got: {logged}"));
    assert!(
        failed_line.contains("returned HTTP 500"),
        "the failed publish names the switch's refusal: {failed_line}"
    );
}

/// NET-044 on the shared-address interim: under an absent range verdict every
/// box publishes at `127.0.0.1`, so a runtime expose of a port another box
/// already holds there cannot be made — the switch refuses the duplicate
/// bind — and the refusal is the typed publish failure naming the port,
/// never a fallback to another address and never a success for a forward
/// nobody owns. The colliding box keeps no forward and lists no mapping, and
/// the box that holds the address keeps its publish.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn expose_colliding_on_shared_address_is_a_bind_error() {
    let capture = crate::test_harness::captured_log();
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    // An absent range: the interim both boxes publish at, so one address's
    // port carries one forward at most.
    let manager = server.state.sessions_manager().await;
    manager.land_range_verdict(crate::net::dns::RangeVerdict::Absent);
    let web = finalize_dynamic_ingress_session(
        &mut client,
        // This test's own box names: under the shared capture every test's
        // lines ride one buffer, so the assertion below finds the failed
        // publish by the box it names.
        "clashweb",
        std::net::Ipv4Addr::new(100, 64, 128, 31),
        std::net::Ipv4Addr::new(127, 0, 64, 31),
        Some(sessions::DynamicIngress::Allow),
        Some((3000, 3999)),
    )
    .await;
    let db = finalize_dynamic_ingress_session(
        &mut client,
        "clashdb",
        std::net::Ipv4Addr::new(100, 64, 128, 32),
        std::net::Ipv4Addr::new(127, 0, 64, 32),
        Some(sessions::DynamicIngress::Allow),
        Some((3000, 3999)),
    )
    .await;
    let web_handle = manager
        .get_session(crate::sessions::SessionKeyPredicate::Id(web))
        .await
        .unwrap()
        .expect("the first box resolves");
    let db_handle = manager
        .get_session(crate::sessions::SessionKeyPredicate::Id(db))
        .await
        .unwrap()
        .expect("the second box resolves");
    // Both boxes run: a publish needs a box standing behind it, and the
    // collision below is one two live boxes make, not a box that cannot
    // publish at all.
    web_handle
        .ensure_host("tester".to_string())
        .await
        .expect("the first box launches its host");
    db_handle
        .ensure_host("tester".to_string())
        .await
        .expect("the second box launches its host");
    let sock = web_handle
        .net_switch()
        .await
        .unwrap()
        .lock()
        .await
        .control_socket();
    // The switch accepts the first box's bind of the shared address's port
    // and refuses the second box's bind of the same one — a 500, the way the
    // real forwarder answers a bind it cannot make because another forward
    // already holds the address.
    let (forwarder, served) = scripted_forwarder(sock, vec![200, 500]).await;

    let held = web_handle
        .expose_dynamic(3000)
        .await
        .expect("the first box's publish holds the shared address's port");
    assert_eq!(
        held.local, "127.0.0.1:3000",
        "under an absent range both boxes publish at the interim"
    );

    // The second box exposes the port the first holds: one address:port
    // carries one forward, so this bind cannot be made, and the failure is
    // the typed publish failure naming the port.
    match db_handle.expose_dynamic(3000).await {
        Err(crate::net::policy::ExposeFailure::Publish { port: 3000, source }) => {
            assert!(
                source.to_string().contains("returned HTTP 500"),
                "the bind failure names the switch's refusal: {source}"
            );
        }
        other => panic!("a bind on an address another box holds is the publish failure: {other:?}"),
    }
    forwarder.abort();

    // The refused bind asked for exactly what it meant to bind — the shared
    // address, delivered to the second box's own switch address — and asked
    // nothing else: no retry at a fallback address.
    let served = served.lock().expect("served lock").clone();
    assert_eq!(
        served.len(),
        2,
        "one request per publish, and no third for a fallback: {served:?}"
    );
    let (line, body) = served[1]
        .split_once('\n')
        .expect("the served request carries its request line and body");
    assert!(
        line.starts_with("POST /services/forwarder/expose "),
        "the colliding publish rides the forwarder's expose verb: {served:?}"
    );
    let colliding = crate::net::policy::expose_request(
        &sessions::PortMapping {
            external_port: 3000,
            internal_port: 3000,
            proto: sessions::IpProto::Tcp,
        },
        std::net::Ipv4Addr::LOCALHOST,
        std::net::Ipv4Addr::new(100, 64, 128, 32),
    );
    assert_eq!(
        body,
        String::from_utf8(serde_json_lenient::to_vec(&colliding).unwrap()).unwrap(),
        "the refused bind is the request at the shared address, never a \
         fallback one"
    );

    // No forward and no listed mapping for the colliding box; the box that
    // holds the address keeps its publish.
    let db_live: minimald_rpc::Errorable<Vec<minimald_rpc::LiveMapping>> = client
        .call::<minimald_rpc::GetLiveIngress>(&minimald_rpc::GetLiveIngressRequest::Id(db))
        .await;
    assert_eq!(
        db_live,
        minimald_rpc::Errorable::Ok(vec![]),
        "the colliding box lists no mapping: its bind was never made"
    );
    let web_live: minimald_rpc::Errorable<Vec<minimald_rpc::LiveMapping>> = client
        .call::<minimald_rpc::GetLiveIngress>(&minimald_rpc::GetLiveIngressRequest::Id(web))
        .await;
    assert_eq!(
        web_live,
        minimald_rpc::Errorable::Ok(vec![minimald_rpc::LiveMapping {
            local: "127.0.0.1:3000".to_string(),
            internal_port: 3000,
            proto: sessions::IpProto::Tcp,
            // The box declared no port mappings, so its relay gate admits
            // nothing: the runtime publish reads pending.
            pending: Some(true),
        }]),
        "the first box's publish is untouched by the collision"
    );

    // The one line the failed publish owes the log: the box, the port, the
    // decision its setting made, and the switch's refusal.
    let logged = capture.contents();
    let line = logged
        .lines()
        .find(|line| line.contains("dynamic ingress expose") && line.contains("name=clashdb"))
        .unwrap_or_else(|| panic!("the failed publish must be logged, got: {logged}"));
    assert!(
        line.contains("port=3000")
            && line.contains("decision=allow")
            && line.contains("outcome=\"publish failed\"")
            && line.contains("returned HTTP 500"),
        "the failed publish names the box, the port, the decision and the \
         switch's refusal: {line}"
    );
}

/// NET-044's address, on a hand the loopback verdict has not vouched for:
/// the runtime publish binds at the hostname registry's published own
/// address — the one source the declared path reads too, through
/// `OwnAddressReporter::published_address` — and never at the raw handed
/// loopback address. The hand names an address the publish surface cannot
/// bind under an absent range, so the finalize published the box at the
/// `127.0.0.1` interim (NET-123 §7.1), which is where its declared ports
/// bind and its name answers: the runtime publish rides the same address a
/// connection actually reaches, while the hand's `switch_address` stays
/// what the forward delivers to.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn expose_publishes_at_the_registered_address() {
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    // An absent range: the hand is unvouched, so the finalize publishes the
    // interim — the hand stands only in the record.
    let manager = server.state.sessions_manager().await;
    manager.land_range_verdict(crate::net::dns::RangeVerdict::Absent);
    let web = finalize_dynamic_ingress_session(
        &mut client,
        "web",
        std::net::Ipv4Addr::new(100, 64, 128, 9),
        std::net::Ipv4Addr::new(127, 0, 64, 9),
        Some(sessions::DynamicIngress::Allow),
        Some((3000, 3999)),
    )
    .await;
    assert_eq!(
        manager
            .hostnames()
            .read()
            .expect("registry lock")
            .published_own_address(web),
        Some(std::net::Ipv4Addr::LOCALHOST),
        "under an absent range the hand is unvouched, so the finalize \
         publishes the interim — the address the registry holds"
    );
    let handle = manager
        .get_session(crate::sessions::SessionKeyPredicate::Id(web))
        .await
        .unwrap()
        .expect("the allowing box resolves");
    handle
        .ensure_host("tester".to_string())
        .await
        .expect("the allowing box launches its host");
    let sock = handle
        .net_switch()
        .await
        .unwrap()
        .lock()
        .await
        .control_socket();
    let (forwarder, served) = fake_forwarder(sock, 200).await;

    let mapping = handle
        .expose_dynamic(3000)
        .await
        .expect("the allowed port publishes at the registered address");
    forwarder.abort();
    assert_eq!(
        mapping.local, "127.0.0.1:3000",
        "the mapping names the registered address — the interim the box \
         publishes at — never the raw handed loopback address"
    );

    // The request the switch is asked: bound at the registered address,
    // delivered to the hand's switch address.
    let served = served.lock().expect("served lock").clone();
    assert_eq!(served.len(), 1, "one mapping is one request: {served:?}");
    let (line, body) = served[0]
        .split_once('\n')
        .expect("the served request carries its request line and body");
    assert!(
        line.starts_with("POST /services/forwarder/expose "),
        "the publish rides the forwarder's expose verb: {served:?}"
    );
    let declared = crate::net::policy::expose_request(
        &sessions::PortMapping {
            external_port: 3000,
            internal_port: 3000,
            proto: sessions::IpProto::Tcp,
        },
        std::net::Ipv4Addr::LOCALHOST,
        std::net::Ipv4Addr::new(100, 64, 128, 9),
    );
    assert_eq!(
        body,
        String::from_utf8(serde_json_lenient::to_vec(&declared).unwrap()).unwrap(),
        "the publish binds where the declared ports bind — the registry's \
         published address — and delivers to the hand's switch address"
    );

    // The mapping is listed where `min session policy` reads it, naming that
    // address.
    let live: minimald_rpc::Errorable<Vec<minimald_rpc::LiveMapping>> = client
        .call::<minimald_rpc::GetLiveIngress>(&minimald_rpc::GetLiveIngressRequest::Name(
            "web".to_string(),
        ))
        .await;
    assert_eq!(
        live,
        minimald_rpc::Errorable::Ok(vec![minimald_rpc::LiveMapping {
            local: "127.0.0.1:3000".to_string(),
            internal_port: 3000,
            proto: sessions::IpProto::Tcp,
            // The box declared no port mappings, so its relay gate admits
            // nothing: the runtime publish reads pending.
            pending: Some(true),
        }]),
        "the live mapping names the registered address the publish bound at"
    );
}

/// The stopped-box half of the publish: Stop keeps the record `active`, its
/// grant and its publish row (NET-013), so the session still resolves — but
/// the actor its record resurrects holds no host, and a publish needs a box
/// standing behind it. The request is refused with the not-running typed
/// error, the switch is asked nothing, no mapping is listed, and the one
/// line the request owes the log says what happened to it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn expose_on_stopped_box_refused() {
    let capture = crate::test_harness::captured_log();
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let manager = server.state.sessions_manager().await;
    manager.land_range_verdict(crate::net::dns::RangeVerdict::Present);
    let web = finalize_dynamic_ingress_session(
        &mut client,
        // This test's own box name: under the shared capture every test's
        // lines ride one buffer, so the assertion below finds the refusal
        // by the box it names.
        "stopweb",
        std::net::Ipv4Addr::new(100, 64, 128, 9),
        std::net::Ipv4Addr::new(127, 0, 64, 9),
        Some(sessions::DynamicIngress::Allow),
        Some((3000, 3999)),
    )
    .await;
    let handle = manager
        .get_session(crate::sessions::SessionKeyPredicate::Id(web))
        .await
        .unwrap()
        .expect("the box resolves while it runs");
    handle
        .ensure_host("tester".to_string())
        .await
        .expect("the box launches its host");
    let sock = handle
        .net_switch()
        .await
        .unwrap()
        .lock()
        .await
        .control_socket();
    let (forwarder, served) = fake_forwarder(sock, 200).await;

    // Stop the box, then reach the fresh actor its still-active record
    // resurrects — the shape a `min net expose` finds after a Stop.
    handle.stop().await;
    manager.evict(web).await;
    let stopped = manager
        .get_session(crate::sessions::SessionKeyPredicate::Id(web))
        .await
        .unwrap()
        .expect("a stopped box's record still resolves, still active");
    match stopped.expose_dynamic(3000).await {
        Err(crate::net::policy::ExposeFailure::Refused(
            crate::net::policy::ExposeRefusal::NotRunning,
        )) => {}
        other => panic!("an expose on a stopped box is refused as not running: {other:?}"),
    }
    forwarder.abort();
    assert!(
        served.lock().expect("served lock").is_empty(),
        "a stopped box asks the switch nothing: no forward is bound for a \
         box that is not running"
    );
    let live: minimald_rpc::Errorable<Vec<minimald_rpc::LiveMapping>> = client
        .call::<minimald_rpc::GetLiveIngress>(&minimald_rpc::GetLiveIngressRequest::Id(web))
        .await;
    assert_eq!(
        live,
        minimald_rpc::Errorable::Ok(vec![]),
        "a stopped box lists no mapping"
    );

    // The one line the request owes the log: the box, the port, the decision
    // its setting made, and the refusal that answered it — found by this
    // test's own box name, the shared capture holding every test's lines.
    let logged = capture.contents();
    let line = logged
        .lines()
        .find(|line| line.contains("dynamic ingress expose") && line.contains("name=stopweb"))
        .unwrap_or_else(|| panic!("the refused request must be logged, got: {logged}"));
    assert!(
        line.contains("port=3000")
            && line.contains("decision=allow")
            && line.contains("outcome=\"refused\"")
            && line.contains("reason=this box is not running; start the box and try again"),
        "the refusal names the box, the port, the decision and the reason: {line}"
    );
}

/// The no-published-address refusal is its own typed error, never a policy
/// deny: a box whose `dynamic_ingress` allows but whose publish the
/// registry no longer holds is refused for the capability gap it is (NET-010
/// — the daemon has no default address to stand in with), and the log says
/// both facts: the decision was allow, and the refusal was the missing
/// publish, so a diagnostics bundle cannot misread it as the box denying.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn expose_without_published_address_is_not_a_policy_deny() {
    let capture = crate::test_harness::captured_log();
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let web = finalize_self_allocated_dynamic_ingress_session(
        &mut client,
        // This test's own box name: under the shared capture every test's
        // lines ride one buffer, so the assertion below finds the refusal
        // by the box it names.
        "nopubweb",
        Some(sessions::DynamicIngress::Allow),
        Some((3000, 3999)),
    )
    .await;
    let manager = server.state.sessions_manager().await;
    let registry = manager.hostnames();
    let handle = manager
        .get_session(crate::sessions::SessionKeyPredicate::Id(web))
        .await
        .unwrap()
        .expect("the allowing box resolves");
    handle
        .ensure_host("tester".to_string())
        .await
        .expect("the box launches its host");
    let sock = handle
        .net_switch()
        .await
        .unwrap()
        .lock()
        .await
        .control_socket();
    let (forwarder, served) = fake_forwarder(sock, 200).await;

    // The lease reported, the publish withdrawn: the box has somewhere to
    // deliver to and nowhere to bind at.
    registry.write().expect("registry lock").report_own_address(
        web,
        "nopubweb",
        std::net::Ipv4Addr::new(100, 64, 128, 42),
        std::collections::BTreeMap::new(),
    );
    registry
        .write()
        .expect("registry lock")
        .unpublish_own_address(web);
    match handle.expose_dynamic(3000).await {
        Err(crate::net::policy::ExposeFailure::Refused(
            crate::net::policy::ExposeRefusal::NoPublishedAddress,
        )) => {}
        Err(crate::net::policy::ExposeFailure::Refused(
            crate::net::policy::ExposeRefusal::DeniedByPolicy,
        )) => panic!(
            "a missing publish is a capability gap, not the box denying: \
             the refusal must not read as a policy deny"
        ),
        other => panic!("a box with no published address is refused as such: {other:?}"),
    }
    forwarder.abort();
    assert!(
        served.lock().expect("served lock").is_empty(),
        "a refused request asks the switch nothing"
    );

    // The log's answer is not a misreading waiting to happen: the decision
    // was allow, and the refusal names the missing publish — found by this
    // test's own box name, the shared capture holding every test's lines.
    let logged = capture.contents();
    let line = logged
        .lines()
        .find(|line| line.contains("dynamic ingress expose") && line.contains("name=nopubweb"))
        .unwrap_or_else(|| panic!("the refused request must be logged, got: {logged}"));
    assert!(
        line.contains("port=3000")
            && line.contains("decision=allow")
            && line.contains("outcome=\"refused\"")
            && line
                .contains("reason=this box has no published address on file to expose a port at"),
        "the line says the decision was allow and the refusal was the missing \
         publish: {line}"
    );
}

/// NET-044's observability, for the outcomes the actor sees: every expose
/// request leaves exactly one line, naming the box, the port, the decision
/// its setting made, and the outcome — the publish that succeeded, the
/// policy refusal, the duplicate refusal, and the publish that failed. The
/// paths no actor ever sees leave their one line in the env channel instead,
/// pinned beside the channel that owns them (the channel test in `env`).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn expose_logs_every_path() {
    let capture = crate::test_harness::captured_log();
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let manager = server.state.sessions_manager().await;
    manager.land_range_verdict(crate::net::dns::RangeVerdict::Present);

    // A box that publishes, and then refuses its own duplicate. The three
    // boxes are this test's own names: under the shared capture every
    // test's lines ride one buffer, so each request's line below is found
    // and counted by the box it names.
    let web = finalize_dynamic_ingress_session(
        &mut client,
        "pathweb",
        std::net::Ipv4Addr::new(100, 64, 128, 25),
        std::net::Ipv4Addr::new(127, 0, 64, 25),
        Some(sessions::DynamicIngress::Allow),
        Some((3000, 3999)),
    )
    .await;
    let web_handle = manager
        .get_session(crate::sessions::SessionKeyPredicate::Id(web))
        .await
        .unwrap()
        .expect("the allowing box resolves");
    web_handle
        .ensure_host("tester".to_string())
        .await
        .expect("the allowing box launches its host");
    let (web_forwarder, web_served) = fake_forwarder(
        web_handle
            .net_switch()
            .await
            .unwrap()
            .lock()
            .await
            .control_socket(),
        200,
    )
    .await;
    web_handle
        .expose_dynamic(3000)
        .await
        .expect("the allowed port publishes");
    match web_handle.expose_dynamic(3000).await {
        Err(crate::net::policy::ExposeFailure::Refused(
            crate::net::policy::ExposeRefusal::AlreadyPublished {
                port: 3000,
                owner: crate::net::listeners::PublicationOwner::Expose,
            },
        )) => {}
        other => panic!("the second request for a live port is a duplicate: {other:?}"),
    }

    // A box that declared nothing: the deny-all default refuses it.
    let closed = finalize_dynamic_ingress_session(
        &mut client,
        "pathclosed",
        std::net::Ipv4Addr::new(100, 64, 128, 26),
        std::net::Ipv4Addr::new(127, 0, 64, 26),
        None,
        None,
    )
    .await;
    let closed_handle = manager
        .get_session(crate::sessions::SessionKeyPredicate::Id(closed))
        .await
        .unwrap()
        .expect("the unenrolled box resolves");
    match closed_handle.expose_dynamic(3000).await {
        Err(crate::net::policy::ExposeFailure::Refused(
            crate::net::policy::ExposeRefusal::DeniedByPolicy,
        )) => {}
        other => panic!("the deny-all default refuses the request: {other:?}"),
    }
    // No switch stand-in was bound for this box, so the typed refusal is
    // also the proof the switch was never asked: a request that reached one
    // would fail with a connection error, not answer as a policy denial.

    // A box whose switch refuses the bind: the publish that failed. The
    // daemon's switch control socket is one shared path, so the 500 stand-in
    // takes it over from the 200 one that served the publish above.
    let broken = finalize_dynamic_ingress_session(
        &mut client,
        "pathbroken",
        std::net::Ipv4Addr::new(100, 64, 128, 27),
        std::net::Ipv4Addr::new(127, 0, 64, 27),
        Some(sessions::DynamicIngress::Allow),
        Some((3000, 3999)),
    )
    .await;
    let broken_handle = manager
        .get_session(crate::sessions::SessionKeyPredicate::Id(broken))
        .await
        .unwrap()
        .expect("the broken box resolves");
    broken_handle
        .ensure_host("tester".to_string())
        .await
        .expect("the broken box launches its host");
    web_forwarder.abort();
    let broken_sock = broken_handle
        .net_switch()
        .await
        .unwrap()
        .lock()
        .await
        .control_socket();
    std::fs::remove_file(&broken_sock).ok();
    let (broken_forwarder, broken_served) = fake_forwarder(broken_sock, 500).await;
    match broken_handle.expose_dynamic(3000).await {
        Err(crate::net::policy::ExposeFailure::Publish { port: 3000, .. }) => {}
        other => panic!("a bind the switch refuses fails the publish: {other:?}"),
    }
    broken_forwarder.abort();
    assert_eq!(
        web_served.lock().expect("served lock").len(),
        1,
        "one mapping is one request"
    );
    assert_eq!(
        broken_served.lock().expect("served lock").len(),
        1,
        "the failed publish asked the switch once"
    );

    // One line per request — four requests, four lines among this test's
    // own boxes, no strays from any test sharing the process-wide capture —
    // each naming the box, the port, the decision, and the outcome.
    let logged = capture.contents();
    let lines_for = |name: &str| -> Vec<&str> {
        logged
            .lines()
            .filter(|line| {
                line.contains("dynamic ingress expose") && line.contains(&format!("name={name}"))
            })
            .collect()
    };
    assert_eq!(
        lines_for("pathweb").len(),
        2,
        "one line per request at the publishing box, got: {logged}"
    );
    assert_eq!(
        lines_for("pathclosed").len(),
        1,
        "the unenrolled box's refusal says its one line, got: {logged}"
    );
    assert_eq!(
        lines_for("pathbroken").len(),
        1,
        "the broken box's failed publish says its one line, got: {logged}"
    );
    let line_for = |name: &str, outcome: &str| {
        logged
            .lines()
            .find(|line| {
                line.contains("dynamic ingress expose")
                    && line.contains(&format!("name={name}"))
                    && line.contains(&format!("outcome=\"{outcome}\""))
            })
            .unwrap_or_else(|| panic!("a line per outcome, got: {logged}"))
    };
    let published = line_for("pathweb", "published");
    assert!(
        published.contains("port=3000")
            && published.contains("decision=allow")
            && published.contains("local=127.0.64.25:3000"),
        "the publish line names the box, the port, the decision and the \
         address it bound: {published}"
    );
    let duplicate = line_for("pathweb", "refused");
    assert!(
        duplicate.contains("port=3000")
            && duplicate.contains("decision=allow")
            && duplicate.contains("reason=port 3000 is published already by this box"),
        "the duplicate refusal names the port and the reason: {duplicate}"
    );
    let denied = line_for("pathclosed", "refused");
    assert!(
        denied.contains("port=3000")
            && denied.contains("decision=deny")
            && denied.contains("reason=dynamic ingress is denied for this box"),
        "the policy refusal names the decision and the reason: {denied}"
    );
    let failed = line_for("pathbroken", "publish failed");
    assert!(
        failed.contains("port=3000")
            && failed.contains("decision=allow")
            && failed.contains("returned HTTP 500"),
        "the failed publish names the switch's refusal: {failed}"
    );
}

/// The ingress policy a seeded listen plan's gate is built over: the same
/// shape the box's record carries — allow, over `range`, declaring nothing
/// — so the watcher's verdicts are the box's own.
fn listen_policy_over(range: (u16, u16)) -> sessions::SessionPolicy {
    sessions::SessionPolicy::new(
        None,
        Some(sessions::IngressPolicy {
            port_mappings: vec![],
            dynamic_allowed_range: Some(range),
            dynamic_ingress: Some(sessions::DynamicIngress::Allow),
        }),
    )
}

/// A listening socket on the any address — the bind a publication's forward
/// can deliver to, so a box's watcher sees the port as the box's own
/// listener.
fn listening_socket() -> std::net::TcpListener {
    std::net::TcpListener::bind((std::net::Ipv4Addr::UNSPECIFIED, 0))
        .expect("bind a listening socket")
}

/// The port `listener` holds.
fn port_of(listener: &std::net::TcpListener) -> u16 {
    listener
        .local_addr()
        .expect("a bound listener names its address")
        .port()
}

/// Awaits `what` until it holds, or fails the proof: the box's watcher polls
/// on its own cadence, so a fact it owes arrives on a later poll, never on
/// the one the caller just missed.
async fn soon(mut what: impl FnMut() -> bool) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while !what() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the box did not reach the awaited state in the bound"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

/// The control requests the fake forwarder served that name `published:port`
/// as their bind — the expose and unexpose verbs of one publication, from
/// whichever of the box's two runtime surfaces sent them.
fn served_naming(
    served: &std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    published: std::net::Ipv4Addr,
    port: u16,
) -> Vec<String> {
    served
        .lock()
        .expect("served lock")
        .iter()
        .filter(|record| record.contains(&format!("\"local\":\"{published}:{port}\"")))
        .cloned()
        .collect()
}

/// The box whose two runtime publishing surfaces are one publication set's
/// two halves (NET-044, NET-047): an own-address box that allows dynamic
/// ingress over `range`, launched with the listen plan a test seeds into its
/// mock launch — the lease, published address and control channel its
/// record and switch already name, and a gate over the policy the record
/// carries — so the host its launch builds starts the box's listen watcher
/// the way a real launch's host does. The switch's control socket is one
/// shared path, so the fake forwarder bound here before the launch serves
/// every control request either surface sends. Returns the box's handle,
/// the seeded gate (the watcher's verdicts and admissions run through it),
/// and the forwarder's record of every request it served.
///
/// One box per call: the forwarder this binds takes the control socket over,
/// so a test that needs a second box builds it itself.
async fn box_with_listen_plan(
    client: &mut TestClient,
    manager: &crate::sessions::ManagerHandle,
    name: &str,
    switch: std::net::Ipv4Addr,
    loopback: std::net::Ipv4Addr,
    range: (u16, u16),
) -> (
    crate::session::SessionHandle,
    std::sync::Arc<crate::net::switch::SessionGate>,
    std::sync::Arc<std::sync::Mutex<Vec<String>>>,
) {
    let (handle, gate, served, _gate, _id) =
        box_with_scripted_plan(client, manager, name, switch, loopback, range, Vec::new()).await;
    (handle, gate, served)
}

/// [`box_with_listen_plan`], over a gated stand-in: the forwarder bound
/// before the launch answers each request with the next answer `script`
/// holds for its port — held answers wait on the gate a test advances, so a
/// test can hold one surface's bind in flight while the other races it for
/// the port — and the box's session id comes back with it, so a test can reach the
/// publication set its launch is running on through the seam.
async fn box_with_scripted_plan(
    client: &mut TestClient,
    manager: &crate::sessions::ManagerHandle,
    name: &str,
    switch: std::net::Ipv4Addr,
    loopback: std::net::Ipv4Addr,
    range: (u16, u16),
    script: Vec<(u16, GateAnswer)>,
) -> (
    crate::session::SessionHandle,
    std::sync::Arc<crate::net::switch::SessionGate>,
    std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    tokio::sync::watch::Sender<u64>,
    sessions::SessionId,
) {
    // The hand vouched for, so the registry publishes the loopback hand's
    // address: both surfaces' forwards bind at the address the box's name
    // answers at, exactly as they do for a production box.
    manager.land_range_verdict(crate::net::dns::RangeVerdict::Present);
    let id = finalize_dynamic_ingress_session(
        client,
        name,
        switch,
        loopback,
        Some(sessions::DynamicIngress::Allow),
        Some(range),
    )
    .await;
    let handle = manager
        .get_session(crate::sessions::SessionKeyPredicate::Id(id))
        .await
        .unwrap()
        .expect("the box resolves");
    // Bound before the launch, so the watcher's first publish reaches a
    // forwarder instead of a refused connection and a backoff.
    let sock = handle
        .net_switch()
        .await
        .unwrap()
        .lock()
        .await
        .control_socket();
    let (_forwarder, served, gate_sender) = gated_forwarder(sock.clone(), script).await;
    // The plan a real launch gathers itself, seeded into this one: the facts
    // a box's host builds its watcher from, riding the mock's `Launched` the
    // way a real launch's plan rides its own.
    let gate = std::sync::Arc::new(crate::net::switch::SessionGate::for_session(
        name.to_string(),
        switch,
        &listen_policy_over(range),
        crate::net::SwitchSubnet::default(),
        None,
    ));
    crate::session::listen_plan_seam::seed(
        id,
        crate::session::listen_plan_seam::Seeded {
            lease: switch,
            published: loopback,
            control: crate::net::policy::ControlChannel::Unix(sock),
            gate: std::sync::Arc::clone(&gate),
        },
    );
    handle
        .ensure_host("tester".to_string())
        .await
        .expect("the box launches its host");
    (handle, gate, served, gate_sender, id)
}

/// NET-047, the port one surface already holds: whichever of the box's two
/// runtime surfaces reaches a port first, the port is bound once. A port the
/// listen watcher published, asked for by `min net expose`, is answered with
/// the typed already-published refusal — the switch asked nothing — and a
/// port `min net expose` published is skipped silently by the watcher: one
/// settlement line, never a bind, never a retry under backoff. Each surface
/// withdraws only its own: the watcher unpublishes its port when the
/// listener closes, and the expose's port comes down only with the box's
/// teardown, never with the other surface's.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn listen_publish_and_runtime_expose_never_double_bind() {
    let capture = crate::test_harness::captured_log();
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let manager = server.state.sessions_manager().await;

    // Two ports the box's range covers: one its process listens on before
    // the host builds, one free until the runtime expose asks for it.
    let listen_port_socket = listening_socket();
    let listen_port = port_of(&listen_port_socket);
    let exposed_port = port_of(&listening_socket());
    let range = (listen_port.min(exposed_port), listen_port.max(exposed_port));
    let switch = std::net::Ipv4Addr::new(100, 64, 128, 71);
    let loopback = std::net::Ipv4Addr::new(127, 0, 64, 71);
    let (handle, gate, served) =
        box_with_listen_plan(&mut client, &manager, "ownboth", switch, loopback, range).await;

    // The watcher publishes the port the box listens on — the publication is
    // written into the box's shared set before the gate admits it, so waiting
    // on the admission is waiting on the record the refusal below reads.
    soon(|| gate.admits_tcp(listen_port)).await;
    assert_eq!(
        served_naming(&served, loopback, listen_port).len(),
        1,
        "the listening port is published once: {:?}",
        served.lock().expect("served lock")
    );

    // The runtime expose asks for the port the watcher holds: the typed
    // duplicate refusal, with nothing bound for it and nothing asked of the
    // switch — the one request so far is the watcher's own publish.
    match handle.expose_dynamic(listen_port).await {
        Err(crate::net::policy::ExposeFailure::Refused(
            crate::net::policy::ExposeRefusal::AlreadyPublished {
                port: asked,
                owner: crate::net::listeners::PublicationOwner::Listen,
            },
        )) => assert_eq!(asked, listen_port),
        other => panic!("a port the watcher published is a typed duplicate: {other:?}"),
    }
    assert_eq!(
        served_naming(&served, loopback, listen_port).len(),
        1,
        "the refused request asks the switch nothing: {:?}",
        served.lock().expect("served lock")
    );

    // The runtime expose publishes the free port, and then the box's own
    // process listens on the same number: the watcher sees a listener on a
    // port the expose surface already holds, and settles on skipping it.
    let mapping = handle
        .expose_dynamic(exposed_port)
        .await
        .expect("the free port publishes");
    assert_eq!(
        mapping,
        minimald_rpc::LiveMapping {
            local: format!("{loopback}:{exposed_port}"),
            internal_port: exposed_port,
            proto: sessions::IpProto::Tcp,
            pending: Some(false),
        },
        "the expose binds where the box's watcher binds, at its own port number"
    );
    assert_eq!(
        handle.live_ingress().await.expect("the actor answers"),
        vec![mapping],
        "the runtime publish is listed as the box's live ingress"
    );
    let second_listener =
        std::net::TcpListener::bind((std::net::Ipv4Addr::UNSPECIFIED, exposed_port))
            .expect("the box's process listens on the exposed port");
    soon(|| {
        let logged = capture.contents();
        logged.lines().any(|line| {
            line.contains("left a listening port the runtime expose already published")
                && line.contains("session=ownboth")
                && line.contains(&format!("port={exposed_port}"))
        })
    })
    .await;

    // Several poll intervals past the skip: the settlement is one line —
    // never retried under backoff — and one request, the expose's own; the
    // watcher asked the switch nothing for the port it does not own.
    tokio::time::sleep(Duration::from_millis(900)).await;
    assert_eq!(
        served_naming(&served, loopback, exposed_port).len(),
        1,
        "the expose's publication is the only forward the port ever got: {:?}",
        served.lock().expect("served lock")
    );
    let logged = capture.contents();
    assert_eq!(
        logged
            .lines()
            .filter(|line| {
                line.contains("left a listening port the runtime expose already published")
                    && line.contains("session=ownboth")
            })
            .count(),
        1,
        "the skip is one line, not one per poll: {logged}"
    );

    // The listening process closes its port: the watcher withdraws its own
    // publication — the request the expose's refusal never made — and the
    // shared set gives the port back.
    drop(listen_port_socket);
    soon(|| served_naming(&served, loopback, listen_port).len() == 2).await;
    let listen_records = served_naming(&served, loopback, listen_port);
    assert!(
        listen_records[1].starts_with("POST /services/forwarder/unexpose "),
        "the watcher's own withdrawal unpublishes its port: {listen_records:?}"
    );

    // The listener on the expose's port closes too — and nothing happens: the
    // publication is the expose surface's, held until the box does, and the
    // watcher never withdraws the other surface's.
    drop(second_listener);
    tokio::time::sleep(Duration::from_millis(900)).await;
    assert_eq!(
        served_naming(&served, loopback, exposed_port).len(),
        1,
        "no surface withdraws a publication it does not own: {:?}",
        served.lock().expect("served lock")
    );

    // The box stops: each publication comes down with whoever published it.
    // The watcher's is down already; the expose's is unbound by the box's own
    // teardown sweep, not by anything the watcher did.
    handle.stop().await;
    assert_eq!(
        served_naming(&served, loopback, listen_port).len(),
        2,
        "the watcher's publication came down when its listener closed, and \
         nothing else ever named the port: {:?}",
        served.lock().expect("served lock")
    );
    let exposed_records = served_naming(&served, loopback, exposed_port);
    assert_eq!(
        exposed_records.len(),
        2,
        "the expose's publication comes down once, with the box: {exposed_records:?}"
    );
    assert!(
        exposed_records[1].starts_with("POST /services/forwarder/unexpose "),
        "the publisher's own withdrawal is the one that came down: {exposed_records:?}"
    );

    // The daemon log's tail reads whose publication every port is: the
    // watcher's publish, the expose's publish, the typed refusal the expose
    // answered with, and the skip the watcher settled on — each naming its
    // owner.
    let logged = capture.contents();
    let publish_line = logged
        .lines()
        .find(|line| {
            line.contains("session=ownboth")
                && line.contains("published a listening port on the box's address")
                && line.contains(&format!("port={listen_port}"))
        })
        .unwrap_or_else(|| panic!("the watcher's publish is one line, got: {logged}"));
    assert!(
        publish_line.contains("owner=listen"),
        "the publication line names the surface that owns it: {publish_line}"
    );
    let skip_line = logged
        .lines()
        .find(|line| {
            line.contains("session=ownboth")
                && line.contains("left a listening port the runtime expose already published")
        })
        .unwrap_or_else(|| panic!("the skip is one line, got: {logged}"));
    assert!(
        skip_line.contains("owner=expose") && skip_line.contains(&format!("port={exposed_port}")),
        "the skip line names the expose surface's publication and the port it \
         holds: {skip_line}"
    );
    let refusal_line = logged
        .lines()
        .find(|line| {
            line.contains("name=ownboth")
                && line.contains("dynamic ingress expose")
                && line.contains("outcome=\"refused\"")
                && line.contains(&format!("port={listen_port}"))
        })
        .unwrap_or_else(|| panic!("the duplicate refusal is one line, got: {logged}"));
    assert!(
        refusal_line.contains("owner=listen")
            && refusal_line.contains(&format!(
                "reason=port {listen_port} is published already by this box (listen)"
            )),
        "the refusal names the owner that holds the port and the reason it \
         gave: {refusal_line}"
    );
    let expose_line = logged
        .lines()
        .find(|line| {
            line.contains("name=ownboth")
                && line.contains("dynamic ingress expose")
                && line.contains("outcome=\"published\"")
                && line.contains(&format!("port={exposed_port}"))
        })
        .unwrap_or_else(|| panic!("the expose's publish is one line, got: {logged}"));
    assert!(
        expose_line.contains("owner=expose"),
        "the expose's publication line names its owner: {expose_line}"
    );
}

/// NET-047's refusal half, alone: a port the box's listen watcher published,
/// asked for by the box's own `min net expose`, is refused as the typed
/// duplicate it is — the switch is asked nothing, the refusal is one line
/// naming the owner that holds the port, and the publication stands until
/// the box stops, when its publisher takes it down.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn expose_on_listen_published_port_is_already_published() {
    let capture = crate::test_harness::captured_log();
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let manager = server.state.sessions_manager().await;

    // One port, listened on before the box's host builds: the watcher owns
    // it from its first poll.
    let listener = listening_socket();
    let port = port_of(&listener);
    let switch = std::net::Ipv4Addr::new(100, 64, 128, 72);
    let loopback = std::net::Ipv4Addr::new(127, 0, 64, 72);
    let (handle, gate, served) = box_with_listen_plan(
        &mut client,
        &manager,
        "ownlisten",
        switch,
        loopback,
        (port, port),
    )
    .await;

    // The watcher publishes the port; the refusal reads the shared set the
    // publication wrote, so wait on the admission that follows it.
    soon(|| gate.admits_tcp(port)).await;
    match handle.expose_dynamic(port).await {
        Err(crate::net::policy::ExposeFailure::Refused(
            crate::net::policy::ExposeRefusal::AlreadyPublished {
                port: asked,
                owner: crate::net::listeners::PublicationOwner::Listen,
            },
        )) => assert_eq!(asked, port),
        other => panic!("the runtime expose is refused as the duplicate it is: {other:?}"),
    }

    // One request, the watcher's publish: the refused request bound nothing,
    // and the box lists no live ingress for the port.
    let requests = served_naming(&served, loopback, port);
    assert_eq!(requests.len(), 1, "the port was bound once: {requests:?}");
    assert!(
        requests[0].starts_with("POST /services/forwarder/expose "),
        "the one bind is the watcher's publish: {requests:?}"
    );
    assert_eq!(
        handle.live_ingress().await.expect("the actor answers"),
        Vec::new(),
        "the refused request published nothing the box lists"
    );

    // The refusal is one line naming the port, the owner that holds it, and
    // the reason the surface gave.
    let logged = capture.contents();
    let refusal = logged
        .lines()
        .find(|line| {
            line.contains("dynamic ingress expose")
                && line.contains("name=ownlisten")
                && line.contains("outcome=\"refused\"")
        })
        .unwrap_or_else(|| panic!("the refusal is one line, got: {logged}"));
    assert!(
        refusal.contains(&format!("port={port}"))
            && refusal.contains("owner=listen")
            && refusal.contains(&format!(
                "reason=port {port} is published already by this box (listen)"
            )),
        "the refusal names the port, the owner holding it, and the reason: {refusal}"
    );

    // The publication stands — still one request — and comes down once, with
    // the box: the publisher's own withdrawal, the session's sweep holding
    // nothing of it.
    handle.stop().await;
    let requests = served_naming(&served, loopback, port);
    assert_eq!(
        requests.len(),
        2,
        "the watcher's publication comes down once, with the box: {requests:?}"
    );
    assert!(
        requests[1].starts_with("POST /services/forwarder/unexpose "),
        "the withdrawal is the publisher's own: {requests:?}"
    );
    drop(listener);
}

/// NET-047's other order: a port the box's runtime expose published, then
/// listened on by the box's own process, is skipped by the watcher — never
/// bound, never retried under backoff, never withdrawn — and its publication
/// comes down only with the box, the expose surface's own teardown.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn listen_watcher_skips_an_expose_owned_port() {
    let capture = crate::test_harness::captured_log();
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let manager = server.state.sessions_manager().await;

    // One port, free until the box's expose asks for it.
    let port = port_of(&listening_socket());
    let switch = std::net::Ipv4Addr::new(100, 64, 128, 73);
    let loopback = std::net::Ipv4Addr::new(127, 0, 64, 73);
    let (handle, _gate, served) = box_with_listen_plan(
        &mut client,
        &manager,
        "ownexpose",
        switch,
        loopback,
        (port, port),
    )
    .await;

    // The runtime expose publishes the port, and only then does the box's
    // own process listen on it: whatever the watcher sees from here on, the
    // port is the expose surface's.
    handle
        .expose_dynamic(port)
        .await
        .expect("the free port publishes");
    let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::UNSPECIFIED, port))
        .expect("the box's process listens on the exposed port");

    // The watcher settles the appearance: one skip line, no bind, no backoff
    // retry — and the only request the port ever got is the expose's own.
    soon(|| {
        let logged = capture.contents();
        logged.lines().any(|line| {
            line.contains("left a listening port the runtime expose already published")
                && line.contains("session=ownexpose")
                && line.contains(&format!("port={port}"))
        })
    })
    .await;
    tokio::time::sleep(Duration::from_millis(900)).await;
    let requests = served_naming(&served, loopback, port);
    assert_eq!(
        requests.len(),
        1,
        "the expose's publish is the only bind the port got: {requests:?}"
    );
    assert!(
        requests[0].starts_with("POST /services/forwarder/expose "),
        "the one bind is the expose surface's: {requests:?}"
    );
    let logged = capture.contents();
    assert_eq!(
        logged
            .lines()
            .filter(|line| {
                line.contains("left a listening port the runtime expose already published")
                    && line.contains("session=ownexpose")
            })
            .count(),
        1,
        "the skip is said once, never retried under backoff: {logged}"
    );

    // The listener closes and nothing comes down: the publication is the
    // expose surface's, held until the box stops, because the publisher is
    // the one who withdraws.
    drop(listener);
    tokio::time::sleep(Duration::from_millis(900)).await;
    assert_eq!(
        served_naming(&served, loopback, port).len(),
        1,
        "no surface withdraws a publication it does not own: {:?}",
        served.lock().expect("served lock")
    );

    // The box stops and the expose's publication comes down with it — the
    // session's own teardown sweep, the publisher's withdrawal.
    handle.stop().await;
    let requests = served_naming(&served, loopback, port);
    assert_eq!(
        requests.len(),
        2,
        "the publication comes down once, with the box: {requests:?}"
    );
    assert!(
        requests[1].starts_with("POST /services/forwarder/unexpose "),
        "the withdrawal is the publisher's own: {requests:?}"
    );
}

/// The plan's one handoff: a launch carries its box's listen plan inside its
/// own `Launched` — the host that launch builds is the only thing that can
/// read it — so a launch whose box's facts gathered one starts the box's
/// watcher, and a launch that gathered none starts nothing: no plan ever
/// reaches a spawn that did not gather it, and the seeded box's two surfaces
/// read the one set the plan carried.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn listen_plan_travels_in_launched() {
    let capture = crate::test_harness::captured_log();
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let manager = server.state.sessions_manager().await;

    // The seeded box's own port, listened on before its host builds, and a
    // second port the bare box's range covers but the seeded box's does not.
    let seeded_socket = listening_socket();
    let seeded_port = port_of(&seeded_socket);
    let bare_socket = listening_socket();
    let bare_port = port_of(&bare_socket);
    let seeded_switch = std::net::Ipv4Addr::new(100, 64, 128, 74);
    let seeded_loopback = std::net::Ipv4Addr::new(127, 0, 64, 74);
    let (seeded, gate, served) = box_with_listen_plan(
        &mut client,
        &manager,
        "ownseed",
        seeded_switch,
        seeded_loopback,
        (seeded_port, seeded_port),
    )
    .await;

    // A second box, launched with no plan seeded: its launch's `Launched`
    // carries none, so no watcher starts for it — and nothing of another
    // box's can reach it, the way the plan's travels never did.
    let bare_id = finalize_dynamic_ingress_session(
        &mut client,
        "ownbare",
        std::net::Ipv4Addr::new(100, 64, 128, 75),
        std::net::Ipv4Addr::new(127, 0, 64, 75),
        Some(sessions::DynamicIngress::Allow),
        Some((seeded_port.min(bare_port), seeded_port.max(bare_port))),
    )
    .await;
    let bare = manager
        .get_session(crate::sessions::SessionKeyPredicate::Id(bare_id))
        .await
        .unwrap()
        .expect("the bare box resolves");
    bare.ensure_host("tester".to_string())
        .await
        .expect("the bare box launches its host");

    // The seeded plan traveled: the host its launch built runs a watcher
    // that publishes the box's own port at the plan's own addresses.
    soon(|| gate.admits_tcp(seeded_port)).await;
    let seeded_records = served_naming(&served, seeded_loopback, seeded_port);
    assert_eq!(
        seeded_records.len(),
        1,
        "the seeded plan's watcher publishes its box's port: {seeded_records:?}"
    );
    assert!(
        seeded_records[0].contains(&format!("\"remote\":\"{seeded_switch}:{seeded_port}\"")),
        "the publication delivers to the plan's lease: {seeded_records:?}"
    );

    // The set traveled with the plan: the actor's runtime expose reads the
    // same one the watcher wrote, and answers the typed duplicate.
    match seeded.expose_dynamic(seeded_port).await {
        Err(crate::net::policy::ExposeFailure::Refused(
            crate::net::policy::ExposeRefusal::AlreadyPublished {
                port: asked,
                owner: crate::net::listeners::PublicationOwner::Listen,
            },
        )) => assert_eq!(asked, seeded_port),
        other => panic!("the seeded box's two surfaces read one set: {other:?}"),
    }

    // The bare box's launch carried no plan, so no watcher ran for it: its
    // own listening port was published by nothing — and the seeded box's
    // watcher, which can see the port too, leaves it alone as outside its
    // box's range. Several poll intervals pass with no request from either.
    tokio::time::sleep(Duration::from_millis(900)).await;
    let served_records = served.lock().expect("served lock").clone();
    assert!(
        served_records
            .iter()
            .all(|record| !record.contains("127.0.64.75")),
        "no surface published anything at the bare box's address: {served_records:?}"
    );
    assert!(
        served_naming(&served, seeded_loopback, bare_port).is_empty(),
        "the seeded box's watcher leaves a port outside its range alone: {served_records:?}"
    );
    // No watcher ever ran for the launch that carried no plan — not even one
    // that could not resolve its leader: the bare box's name is on no
    // watcher line at all, of the phrases a watcher says on any path it has.
    let logged = capture.contents();
    let watcher_phrases = [
        "published a listening port",
        "left a listening port",
        "withdrew a listening port",
        "resolving the box's leader",
        "publishing a listening port on the switch failed",
        "unpublishing a listening port on the switch failed",
    ];
    let bare_watcher_lines = logged
        .lines()
        .filter(|line| line.contains("session=ownbare"))
        .filter(|line| watcher_phrases.iter().any(|phrase| line.contains(phrase)))
        .count();
    assert_eq!(
        bare_watcher_lines, 0,
        "no watcher ever ran for the launch that carried no plan: {logged}"
    );
    seeded.stop().await;
    bare.stop().await;
    drop(seeded_socket);
    drop(bare_socket);
}

/// NET-047's race, both orders, closed by the reservation: the box's two
/// runtime surfaces reach one port together and the port is bound once, by
/// whichever surface's reservation won. The loser is answered before it
/// asks the switch anything — the expose with the typed already-published
/// refusal naming the owner that holds the port, the watcher with the
/// settle-and-skip that names it — never a switch error, never a retry
/// under backoff. A winner whose bind the switch refuses releases its
/// reservation, so the other surface's next observation publishes the port
/// normally; and none of it lets a listener the box's ingress does not
/// permit ride on any publication (NET-016): the watcher leaves such a
/// port unpublished, and nothing asks the switch for it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_expose_and_listen_publish_bind_once() {
    let capture = crate::test_harness::captured_log();
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let manager = server.state.sessions_manager().await;

    // Four ports, drawn and sorted so the smallest sits outside the range
    // the other three make: the box's own process holds that one from
    // before the launch, and the box's ingress does not permit it — the
    // port no surface may publish. The three in range stay free until each
    // phase binds its own listener on them.
    let mut probes: Vec<std::net::TcpListener> = (0..4).map(|_| listening_socket()).collect();
    probes.sort_by_key(port_of);
    let denied_socket = probes.remove(0);
    let denied_port = port_of(&denied_socket);
    let a_port = port_of(&probes[0]);
    let b_port = port_of(&probes[1]);
    let c_port = port_of(&probes[2]);
    let range = (a_port, c_port);
    drop(probes);
    let switch = std::net::Ipv4Addr::new(100, 64, 128, 81);
    let loopback = std::net::Ipv4Addr::new(127, 0, 64, 81);
    // The stand-in's answers, keyed by port, in the order each port's
    // requests are sent: the expose's bind on `a` and the watcher's bind on `b` are
    // held — each a reservation's in-flight window, wide enough to observe
    // the other surface losing inside it — and the expose's bind on `c` is
    // refused, the watcher's publish of `c` accepted.
    let (handle, gate, served, gate_sender, _id) = box_with_scripted_plan(
        &mut client,
        &manager,
        "ownrace",
        switch,
        loopback,
        range,
        vec![
            (a_port, GateAnswer::Held(200)), // 1: the expose's bind on `a`
            (b_port, GateAnswer::Held(200)), // 2: the watcher's bind on `b`
            (c_port, GateAnswer::With(500)), // 3: the expose's bind on `c`, refused
            (c_port, GateAnswer::With(200)), // 4: the watcher's publish of `c`
        ],
    )
    .await;

    // The port the box's ingress does not permit is listened on from before
    // the launch: the watcher denies it — one line, no bind, and no request
    // ever names it, whichever of the box's publications stands.
    soon(|| {
        capture.contents().lines().any(|line| {
            line.contains("session=ownrace")
                && line.contains("left a listening port unpublished")
                && line.contains(&format!("port={denied_port}"))
        })
    })
    .await;
    assert!(
        served_naming(&served, loopback, denied_port).is_empty(),
        "no surface asks the switch for a port the box's ingress does not \
         permit: {:?}",
        served.lock().expect("served lock")
    );

    // Either order, one port each. The expose surface first: it reserves
    // `a` and binds — held at the stand-in — before the box's process ever
    // listens on the port, so the watcher reading that listener arrives at
    // a port the expose's reservation already holds.
    let exposing = {
        let handle = handle.clone();
        tokio::spawn(async move { handle.expose_dynamic(a_port).await })
    };
    soon(|| served_naming(&served, loopback, a_port).len() == 1).await;
    let a_listener = std::net::TcpListener::bind((std::net::Ipv4Addr::UNSPECIFIED, a_port))
        .expect("the box's process listens on the expose's port");
    // The watcher loses to the pending reservation, never to the switch:
    // the contention is said once while the bind is in flight, and the
    // port is never asked of the switch at all.
    soon(|| {
        capture.contents().lines().any(|line| {
            line.contains("session=ownrace")
                && line.contains("left a listening port the runtime expose is publishing")
                && line.contains(&format!("port={a_port}"))
        })
    })
    .await;
    assert_eq!(
        served_naming(&served, loopback, a_port).len(),
        1,
        "the expose's held bind is the only request the port has: {:?}",
        served.lock().expect("served lock")
    );
    // The bind resolves, the reservation commits, and the watcher's next
    // observation settles on the skip: the publication that stands is the
    // expose's own, never the watcher's, and the skip admits nothing.
    gate_sender
        .send(1)
        .expect("the gate opens for the held bind");
    let mapping = exposing
        .await
        .expect("the exposing task ends")
        .expect("the held bind stood, so the expose publishes its port");
    assert_eq!(
        mapping.local,
        format!("{loopback}:{a_port}"),
        "the expose binds at its own address at its own port number"
    );
    soon(|| {
        capture.contents().lines().any(|line| {
            line.contains("session=ownrace")
                && line.contains("left a listening port the runtime expose already published")
                && line.contains(&format!("port={a_port}"))
        })
    })
    .await;
    assert_eq!(
        served_naming(&served, loopback, a_port).len(),
        1,
        "the watcher never asks the switch for a port the expose's \
         reservation won: {:?}",
        served.lock().expect("served lock")
    );
    assert!(
        !gate.admits_tcp(a_port),
        "the skip admits nothing for the port: the expose's publication is \
         served by its own forward, never by an admission the watcher made"
    );
    let logged = capture.contents();
    assert_eq!(
        logged
            .lines()
            .filter(|line| {
                line.contains("session=ownrace")
                    && line.contains("left a listening port the runtime expose is publishing")
                    && line.contains(&format!("port={a_port}"))
            })
            .count(),
        1,
        "the contention is said once while the bind is in flight, never \
         once per poll: {logged}"
    );
    assert!(
        !logged.lines().any(|line| {
            line.contains("session=ownrace")
                && line.contains("publishing a listening port on the switch failed")
                && line.contains(&format!("port={a_port}"))
        }),
        "the loser is answered by the reservation, never by a switch error: {logged}"
    );
    assert!(
        !logged.lines().any(|line| {
            line.contains("session=ownrace")
                && line.contains("published a listening port on the box's address")
                && line.contains(&format!("port={a_port}"))
        }),
        "the watcher never publishes the port the expose's reservation won: {logged}"
    );

    // The other order: the watcher first. The box's process listens on `b`,
    // the watcher reserves it and binds — held at the stand-in — and the
    // expose asked for the port inside that window is refused by the
    // reservation, naming the owner whose bind is still in flight.
    let b_listener = std::net::TcpListener::bind((std::net::Ipv4Addr::UNSPECIFIED, b_port))
        .expect("the box's process listens on its own port");
    soon(|| served_naming(&served, loopback, b_port).len() == 1).await;
    match handle.expose_dynamic(b_port).await {
        Err(crate::net::policy::ExposeFailure::Refused(
            crate::net::policy::ExposeRefusal::AlreadyPublished {
                port: asked,
                owner: crate::net::listeners::PublicationOwner::Listen,
            },
        )) => assert_eq!(asked, b_port),
        other => panic!(
            "the expose loses to the watcher's pending reservation, not to the \
             switch: {other:?}"
        ),
    }
    gate_sender
        .send(2)
        .expect("the gate opens for the held bind");
    soon(|| gate.admits_tcp(b_port)).await;
    assert_eq!(
        served_naming(&served, loopback, b_port).len(),
        1,
        "the watcher's held bind is the only request the port has: {:?}",
        served.lock().expect("served lock")
    );
    let logged = capture.contents();
    let b_refusal = logged
        .lines()
        .find(|line| {
            line.contains("dynamic ingress expose")
                && line.contains("name=ownrace")
                && line.contains("outcome=\"refused\"")
                && line.contains(&format!("port={b_port}"))
        })
        .unwrap_or_else(|| panic!("the refusal is one line: {logged}"));
    assert!(
        b_refusal.contains("owner=listen")
            && b_refusal.contains(&format!(
                "reason=port {b_port} is published already by this box (listen)"
            )),
        "the refusal names the owner holding the port and the reason it \
         gave: {b_refusal}"
    );
    // The watcher admits before it says so, so the line is awaited too.
    soon(|| {
        capture.contents().lines().any(|line| {
            line.contains("session=ownrace")
                && line.contains("published a listening port on the box's address")
                && line.contains("owner=listen")
                && line.contains(&format!("port={b_port}"))
        })
    })
    .await;

    // A winner's bind can fail: the switch refuses the expose's bind on
    // `c`, the failure releases the reservation it held, and the box's
    // process listening on the port afterwards is published by the watcher
    // — the loser's port ends up published, by its own publisher.
    match handle.expose_dynamic(c_port).await {
        Err(crate::net::policy::ExposeFailure::Publish { port, .. }) => assert_eq!(port, c_port),
        other => panic!("the refused bind is a publish failure: {other:?}"),
    }
    let logged = capture.contents();
    let c_failure = logged
        .lines()
        .find(|line| {
            line.contains("dynamic ingress expose")
                && line.contains("name=ownrace")
                && line.contains("outcome=\"publish failed\"")
                && line.contains(&format!("port={c_port}"))
        })
        .unwrap_or_else(|| panic!("the failed bind is one line: {logged}"));
    assert!(
        c_failure.contains("owner=expose"),
        "the publish-failure line names the surface that held the \
         reservation: {c_failure}"
    );
    let c_listener = std::net::TcpListener::bind((std::net::Ipv4Addr::UNSPECIFIED, c_port))
        .expect("the box's process listens on the port the expose failed to bind");
    soon(|| gate.admits_tcp(c_port)).await;
    let c_records = served_naming(&served, loopback, c_port);
    assert_eq!(
        c_records.len(),
        2,
        "the failed bind and the watcher's publish of the freed port: {c_records:?}"
    );
    assert!(
        c_records[1].starts_with("POST /services/forwarder/expose "),
        "the watcher's publish is the bind that stood: {c_records:?}"
    );
    // The watcher's next observation publishes the port the failed bind
    // released; it admits before it says so, so the line is awaited.
    soon(|| {
        capture.contents().lines().any(|line| {
            line.contains("session=ownrace")
                && line.contains("published a listening port on the box's address")
                && line.contains(&format!("port={c_port}"))
        })
    })
    .await;
    assert!(
        served_naming(&served, loopback, denied_port).is_empty(),
        "the unpermitted listener never rode on any of it: {:?}",
        served.lock().expect("served lock")
    );

    handle.stop().await;
    drop(a_listener);
    drop(b_listener);
    drop(c_listener);
    drop(denied_socket);
}

/// A reservation is released by its cancellation: a publish dropped
/// mid-bind — the future that held it aborted — gives the port back, so
/// the watcher that lost to the pending reservation publishes the port on
/// its next observation. The actor's own turn is not abortable from its
/// handles (a dropped reply future abandons the answer, not the work), so
/// the reservation a cancelled publish drops is driven here through the
/// seam the launch hands its publication set back on: the same set the
/// box's two surfaces read, holding the same guard the expose path's
/// publish holds across its bind, dropped the same way a cancelled bind's
/// future drops it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_publish_releases_its_reservation() {
    let capture = crate::test_harness::captured_log();
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let manager = server.state.sessions_manager().await;

    // One port the box's range covers, with nothing listening on it yet.
    let port = port_of(&listening_socket());
    let switch = std::net::Ipv4Addr::new(100, 64, 128, 82);
    let loopback = std::net::Ipv4Addr::new(127, 0, 64, 82);
    let (handle, gate, served, _gate_sender, id) = box_with_scripted_plan(
        &mut client,
        &manager,
        "owncancel",
        switch,
        loopback,
        (port, port),
        Vec::new(),
    )
    .await;
    let publications = crate::session::listen_plan_seam::publications_of(id)
        .expect("the launch handed its publication set back");

    // The publish a cancellation drops: a reservation on the box's real
    // set, held across a bind that never resolves — the shape of the
    // expose path's own in-flight bind, aborted before it could record.
    let holder = {
        let publications = publications.clone();
        tokio::spawn(async move {
            let _reservation = publications
                .reserve(port, crate::net::listeners::PublicationOwner::Expose)
                .expect("nothing holds the port yet");
            std::future::pending::<()>().await
        })
    };

    // The box's process starts listening: the watcher loses to the pending
    // reservation — nothing is asked of the switch, and the contention is
    // said once — for as long as the reservation stands.
    let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::UNSPECIFIED, port))
        .expect("the box's process listens on the port");
    soon(|| {
        capture.contents().lines().any(|line| {
            line.contains("session=owncancel")
                && line.contains("left a listening port the runtime expose is publishing")
                && line.contains(&format!("port={port}"))
        })
    })
    .await;
    assert!(
        served_naming(&served, loopback, port).is_empty(),
        "the watcher asks the switch nothing for a port a pending \
         reservation holds: {:?}",
        served.lock().expect("served lock")
    );
    assert!(
        !gate.admits_tcp(port),
        "a pending reservation is not a mapping: nothing is admitted for it"
    );

    // The publish is cancelled: the task holding the reservation is
    // aborted mid-bind, the guard drops, and the port is free again — the
    // watcher's next observation publishes it normally.
    holder.abort();
    soon(|| gate.admits_tcp(port)).await;
    let records = served_naming(&served, loopback, port);
    assert_eq!(
        records.len(),
        1,
        "the port is published once, by the watcher the reservation held \
         off: {records:?}"
    );
    assert!(
        records[0].starts_with("POST /services/forwarder/expose "),
        "the one request is the watcher's publish: {records:?}"
    );
    // The watcher's next observation publishes the freed port; it admits
    // before it says so, so the line is awaited.
    soon(|| {
        capture.contents().lines().any(|line| {
            line.contains("session=owncancel")
                && line.contains("published a listening port on the box's address")
                && line.contains(&format!("port={port}"))
        })
    })
    .await;
    let logged = capture.contents();
    assert!(
        !logged.lines().any(|line| {
            line.contains("session=owncancel")
                && line.contains("publishing a listening port on the switch failed")
        }),
        "the contention was never a switch error, and the publish that \
         followed never failed: {logged}"
    );
    assert_eq!(
        logged
            .lines()
            .filter(|line| {
                line.contains("session=owncancel")
                    && line.contains("left a listening port the runtime expose is publishing")
            })
            .count(),
        1,
        "the contention is said once, then settled by the publish: {logged}"
    );
    handle.stop().await;
    drop(listener);
}

/// Ingress revocation unbinds (design §7.1), including a bind it could not
/// see: a revocation that clears the box's publication set while a surface's
/// bind is in flight leaves that surface holding a forward nobody else
/// names. The surface that bound it unbinds it itself, so no forward
/// outlives the revocation. The expose answers with the typed not-attached
/// refusal; the watcher admits nothing and settles, never retrying the
/// revoked port.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn revocation_during_in_flight_bind_leaves_no_forward() {
    let capture = crate::test_harness::captured_log();
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let manager = server.state.sessions_manager().await;

    // Two ports in the box's range, with nothing listening on either yet.
    let mut probes: Vec<std::net::TcpListener> = (0..2).map(|_| listening_socket()).collect();
    probes.sort_by_key(port_of);
    let a_port = port_of(&probes[0]);
    let b_port = port_of(&probes[1]);
    drop(probes);
    let switch = std::net::Ipv4Addr::new(100, 64, 128, 83);
    let loopback = std::net::Ipv4Addr::new(127, 0, 64, 83);
    let (handle, gate, served, gate_sender, id) = box_with_scripted_plan(
        &mut client,
        &manager,
        "ownrevoke",
        switch,
        loopback,
        (a_port, b_port),
        vec![
            (a_port, GateAnswer::Held(200)), // 1: the expose's bind on `a`
            (b_port, GateAnswer::Held(200)), // 2: the watcher's bind on `b`
        ],
    )
    .await;
    let publications = crate::session::listen_plan_seam::publications_of(id)
        .expect("the launch handed its publication set back");

    // The expose surface: its bind on `a` is held at the stand-in, the set
    // is revoked under it, and the bind then stands.
    let exposing = {
        let handle = handle.clone();
        tokio::spawn(async move { handle.expose_dynamic(a_port).await })
    };
    soon(|| served_naming(&served, loopback, a_port).len() == 1).await;
    publications.revoke_all();
    gate_sender
        .send(1)
        .expect("the gate opens for the held bind");
    match exposing.await.expect("the exposing task ends") {
        Err(crate::net::policy::ExposeFailure::Refused(
            crate::net::policy::ExposeRefusal::NotAttached,
        )) => {}
        other => panic!("a publish revoked mid-bind is refused as not attached: {other:?}"),
    }
    let a_records = served_naming(&served, loopback, a_port);
    assert_eq!(
        a_records.len(),
        2,
        "the bind and the expose's own unbind of it: {a_records:?}"
    );
    assert!(
        a_records[0].starts_with("POST /services/forwarder/expose ")
            && a_records[1].starts_with("POST /services/forwarder/unexpose "),
        "the forward the revocation never saw is unbound by its binder: {a_records:?}"
    );
    assert!(
        publications.held_by(a_port).is_none(),
        "the revoked publish writes nothing back into the set"
    );
    assert!(
        !gate.admits_tcp(a_port),
        "nothing is admitted for a publish revoked mid-bind"
    );

    // The watcher: the box's process listens on `b`, the watcher's bind is
    // held at the stand-in, the set is revoked under it, and the bind then
    // stands.
    let b_listener = std::net::TcpListener::bind((std::net::Ipv4Addr::UNSPECIFIED, b_port))
        .expect("the box's process listens on its own port");
    soon(|| served_naming(&served, loopback, b_port).len() == 1).await;
    publications.revoke_all();
    gate_sender
        .send(2)
        .expect("the gate opens for the held bind");
    soon(|| served_naming(&served, loopback, b_port).len() == 2).await;
    // Several poll intervals with the listener still standing: the watcher
    // settled the revoked port, so it neither admits nor binds it again.
    tokio::time::sleep(Duration::from_millis(900)).await;
    let b_records = served_naming(&served, loopback, b_port);
    assert_eq!(
        b_records.len(),
        2,
        "the bind and the watcher's own unbind of it, never a retry: {b_records:?}"
    );
    assert!(
        b_records[0].starts_with("POST /services/forwarder/expose ")
            && b_records[1].starts_with("POST /services/forwarder/unexpose "),
        "the forward the revocation never saw is unbound by its binder: {b_records:?}"
    );
    assert!(
        !gate.admits_tcp(b_port),
        "the watcher admits nothing for a publish revoked mid-bind"
    );
    assert!(
        publications.held_by(b_port).is_none(),
        "the revoked publish writes nothing back into the set"
    );
    let logged = capture.contents();
    assert!(
        !logged.lines().any(|line| {
            line.contains("session=ownrevoke")
                && line.contains("published a listening port on the box's address")
                && line.contains(&format!("port={b_port}"))
        }),
        "the watcher never reports a revoked publish as published: {logged}"
    );
    // The line follows the unbind's answer, so it is awaited.
    soon(|| {
        capture.contents().lines().any(|line| {
            line.contains("session=ownrevoke")
                && line.contains("unbound a listening port whose publication was revoked mid-bind")
                && line.contains(&format!("port={b_port}"))
        })
    })
    .await;

    handle.stop().await;
    drop(b_listener);
}

/// The box's stop is a revocation, not a publisher's withdrawal: it unbinds
/// every runtime publication the box holds — the watcher's and the
/// expose's alike, whichever owner holds each port — and the publication
/// set the launch ran on names nothing after it. Neither ownership rule
/// could take both down (the watcher never withdraws the expose's; the
/// session's own sweep never sees the watcher's), so the revocation is the
/// one path that owns both, and it answers to neither.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn revocation_withdraws_regardless_of_owner() {
    let _capture = crate::test_harness::captured_log();
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let manager = server.state.sessions_manager().await;

    // Two ports the box's range covers: one its process listens on from
    // before the launch — the watcher publishes it — and one only the
    // runtime expose asks for.
    let listen_socket = listening_socket();
    let listen_port = port_of(&listen_socket);
    let exposed_port = port_of(&listening_socket());
    let range = (listen_port.min(exposed_port), listen_port.max(exposed_port));
    let switch = std::net::Ipv4Addr::new(100, 64, 128, 83);
    let loopback = std::net::Ipv4Addr::new(127, 0, 64, 83);
    let (handle, gate, served, _gate_sender, id) = box_with_scripted_plan(
        &mut client,
        &manager,
        "ownrevoke",
        switch,
        loopback,
        range,
        Vec::new(),
    )
    .await;

    // Both owners' publications stand: the watcher's on the port the box's
    // process listens on, the expose's on the port its user asked for.
    soon(|| gate.admits_tcp(listen_port)).await;
    handle
        .expose_dynamic(exposed_port)
        .await
        .expect("the free port publishes");

    // The box stops, and the stop is a revocation: both publications come
    // down, each exactly once — the watcher's by its own withdrawal, the
    // expose's by the session's sweep — and the set the launch ran on
    // names neither port afterwards, whoever owned them.
    handle.stop().await;
    let listen_records = served_naming(&served, loopback, listen_port);
    assert_eq!(
        listen_records.len(),
        2,
        "the watcher's publication came down with the box: {listen_records:?}"
    );
    assert!(
        listen_records[1].starts_with("POST /services/forwarder/unexpose "),
        "the withdrawal took the watcher's own publication down: {listen_records:?}"
    );
    let exposed_records = served_naming(&served, loopback, exposed_port);
    assert_eq!(
        exposed_records.len(),
        2,
        "the expose's publication came down with the box: {exposed_records:?}"
    );
    assert!(
        exposed_records[1].starts_with("POST /services/forwarder/unexpose "),
        "the session's sweep took the expose's own publication down: {exposed_records:?}"
    );
    assert!(
        !gate.admits_tcp(listen_port),
        "the gate refuses the revoked port: no new connection rides on it"
    );
    let publications = crate::session::listen_plan_seam::publications_of(id)
        .expect("the launch handed its publication set back");
    assert_eq!(
        publications.held_by(listen_port),
        None,
        "the revocation cleared the watcher's entry without an owner check"
    );
    assert_eq!(
        publications.held_by(exposed_port),
        None,
        "the revocation cleared the expose's entry without an owner check"
    );
    drop(listen_socket);
}

/// A respawn frees the ports its predecessor published: the publication
/// set belongs to one launch, so the ports a dead spawn published never
/// answer for its successor — the same port is exposable again after the
/// respawn, and listen-publishable: the respawned box's watcher publishes
/// it once the box's process binds it, and the expose asking then is the
/// duplicate the fresh set says it is.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn respawn_frees_published_ports() {
    let _capture = crate::test_harness::captured_log();
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let manager = server.state.sessions_manager().await;

    // One port the box's range covers, with nothing listening on it.
    let port = port_of(&listening_socket());
    let switch = std::net::Ipv4Addr::new(100, 64, 128, 84);
    let loopback = std::net::Ipv4Addr::new(127, 0, 64, 84);
    let (handle, gate, served, _gate_sender, id) = box_with_scripted_plan(
        &mut client,
        &manager,
        "ownrespawn",
        switch,
        loopback,
        (port, port),
        Vec::new(),
    )
    .await;

    // The first launch publishes the port at runtime, and its set holds it.
    handle
        .expose_dynamic(port)
        .await
        .expect("the first box publishes the port");
    assert_eq!(
        served_naming(&served, loopback, port).len(),
        1,
        "the first publish is one bind: {:?}",
        served.lock().expect("served lock")
    );

    // The launch's spawn ends — its host is killed — and the box's next
    // launch respawns it: the plan the next launch carries is seeded again,
    // the way a real launch gathers its own facts for every launch it runs.
    let host = handle
        .ensure_host("tester".to_string())
        .await
        .expect("the box's host resolves");
    host.kill(false).await.expect("the box's spawn ends");
    soon(|| !host.is_alive()).await;
    let sock = handle
        .net_switch()
        .await
        .unwrap()
        .lock()
        .await
        .control_socket();
    crate::session::listen_plan_seam::seed(
        id,
        crate::session::listen_plan_seam::Seeded {
            lease: switch,
            published: loopback,
            control: crate::net::policy::ControlChannel::Unix(sock),
            gate: std::sync::Arc::clone(&gate),
        },
    );
    handle
        .ensure_host("tester".to_string())
        .await
        .expect("the box respawns its host");

    // The respawn's expose of the same port publishes again: the launch
    // that runs a box starts from an empty set, so the port the dead spawn
    // published answers free for its successor.
    handle
        .expose_dynamic(port)
        .await
        .expect("the respawned box publishes the port the dead spawn held");
    assert_eq!(
        served_naming(&served, loopback, port).len(),
        2,
        "the second publish is one more bind: {:?}",
        served.lock().expect("served lock")
    );

    // The second spawn ends and respawns once more, and this time the box's
    // own process binds the port: the respawn's watcher publishes it — the
    // port is listen-publishable again, owned by the listen surface now —
    // and the expose asking after it is the typed duplicate the fresh set
    // says it is.
    let host = handle
        .ensure_host("tester".to_string())
        .await
        .expect("the box's host resolves again");
    host.kill(false).await.expect("the second spawn ends");
    soon(|| !host.is_alive()).await;
    let sock = handle
        .net_switch()
        .await
        .unwrap()
        .lock()
        .await
        .control_socket();
    crate::session::listen_plan_seam::seed(
        id,
        crate::session::listen_plan_seam::Seeded {
            lease: switch,
            published: loopback,
            control: crate::net::policy::ControlChannel::Unix(sock),
            gate: std::sync::Arc::clone(&gate),
        },
    );
    handle
        .ensure_host("tester".to_string())
        .await
        .expect("the box respawns its host again");
    let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::UNSPECIFIED, port))
        .expect("the respawned box's process listens on the port");
    soon(|| gate.admits_tcp(port)).await;
    match handle.expose_dynamic(port).await {
        Err(crate::net::policy::ExposeFailure::Refused(
            crate::net::policy::ExposeRefusal::AlreadyPublished {
                port: asked,
                owner: crate::net::listeners::PublicationOwner::Listen,
            },
        )) => assert_eq!(asked, port),
        other => panic!("the respawn's watcher owns the port it published: {other:?}"),
    }
    assert_eq!(
        served_naming(&served, loopback, port).len(),
        3,
        "the watcher's publish is the only new bind of the third launch: {:?}",
        served.lock().expect("served lock")
    );
    handle.stop().await;
    drop(listener);
}

/// Launches a VM-shaped allow box for the T94 ordering tests: a fake
/// forwarder answering `status` on the box's switch control socket, and a
/// fake report door seeded for it.
struct VmBackedBox {
    _server: TestServer,
    handle: crate::session::SessionHandle,
    sock: std::path::PathBuf,
    forwarder: tokio::task::JoinHandle<()>,
    served: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    door: tokio::task::JoinHandle<()>,
    reports: tokio::sync::mpsc::UnboundedReceiver<minimald_rpc::BoxControlRequest>,
    replies: tokio::sync::mpsc::UnboundedSender<minimald_rpc::BoxControlReply>,
}

async fn vm_backed_allow_box(name: &str, octet: u8, status: u16) -> VmBackedBox {
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let manager = server.state.sessions_manager().await;
    manager.land_range_verdict(crate::net::dns::RangeVerdict::Present);
    let id = finalize_dynamic_ingress_session(
        &mut client,
        name,
        std::net::Ipv4Addr::new(100, 64, 128, octet),
        std::net::Ipv4Addr::new(127, 0, 64, octet),
        Some(sessions::DynamicIngress::Allow),
        Some((3000, 3999)),
    )
    .await;
    let handle = manager
        .get_session(crate::sessions::SessionKeyPredicate::Id(id))
        .await
        .unwrap()
        .expect("the allowing box resolves");
    handle
        .ensure_host("tester".to_string())
        .await
        .expect("the allowing box launches its host");
    let sock = handle
        .net_switch()
        .await
        .unwrap()
        .lock()
        .await
        .control_socket();
    let (forwarder, served) = fake_forwarder(sock.clone(), status).await;
    let door_sock = sock.with_file_name("report-door.sock");
    let (door, reports, replies) = fake_report_door(&door_sock).await;
    crate::net::listeners::seed_vm_report_door_for_tests(&sock, &door_sock);
    VmBackedBox {
        _server: server,
        handle,
        sock,
        forwarder,
        served,
        door,
        reports,
        replies,
    }
}

/// Awaits the report door's next request, or fails the proof.
async fn next_report(
    reports: &mut tokio::sync::mpsc::UnboundedReceiver<minimald_rpc::BoxControlRequest>,
) -> minimald_rpc::BoxControlRequest {
    tokio::time::timeout(Duration::from_secs(10), reports.recv())
        .await
        .expect("the report reaches the VM host daemon's door within the bound")
        .expect("the report door stand-in lives")
}

/// T94: a bind the switch fails after the host admitted the port gives the
/// admission back. The withdrawal follows the failed bind — the door reads
/// it only once the switch has answered — and the failed bind left nothing
/// bound, so nothing is unexposed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bind_failure_withdraws_the_admitted_report() {
    let VmBackedBox {
        _server,
        handle,
        sock,
        forwarder,
        served,
        door,
        mut reports,
        replies,
    } = vm_backed_allow_box("vmbindfail", 23, 500).await;

    let reporting = handle.clone();
    let expose = tokio::spawn(async move { reporting.expose_dynamic(3000).await });
    assert!(
        matches!(
            next_report(&mut reports).await,
            minimald_rpc::BoxControlRequest::AdmitPort(_)
        ),
        "the publish reports the port before it binds"
    );
    replies
        .send(minimald_rpc::BoxControlReply::PortRecorded {
            port: 3000,
            proto: sessions::IpProto::Tcp,
        })
        .expect("the report door stand-in lives");
    let withdrawal = next_report(&mut reports).await;
    assert_eq!(
        withdrawal,
        minimald_rpc::BoxControlRequest::WithdrawPort(minimald_rpc::WithdrawPortRequest {
            switch_address: std::net::Ipv4Addr::new(100, 64, 128, 23),
            port: 3000,
            proto: sessions::IpProto::Tcp,
            source: minimald_rpc::PortReportSource::Expose,
        }),
        "a bind that failed gives the host's admission back"
    );
    {
        // The door holds the withdrawal's reply, so what the switch saw by
        // now is everything the publish asked of it before withdrawing.
        let served = served.lock().expect("served lock");
        assert_eq!(
            served.len(),
            1,
            "the failed bind is the switch's one request: {served:?}"
        );
        assert!(
            served[0].starts_with("POST /services/forwarder/expose "),
            "the withdrawal follows the failed bind: {served:?}"
        );
    }
    replies
        .send(minimald_rpc::BoxControlReply::PortRecorded {
            port: 3000,
            proto: sessions::IpProto::Tcp,
        })
        .expect("the report door stand-in lives");
    assert!(
        matches!(
            expose.await.expect("the expose task should not panic"),
            Err(crate::net::policy::ExposeFailure::Publish { port: 3000, .. })
        ),
        "a failed bind fails the publish"
    );

    forwarder.abort();
    door.abort();
    crate::net::listeners::clear_vm_report_door_for_tests(&sock);
}

/// T94: a forward that is coming down is unexposed at the switch before the
/// host's admission is withdrawn — the host's gate applies a runtime port's
/// retraction only while its row still holds the port. Proved on the stop
/// path's sweep: while the door holds the withdrawal's reply, the switch has
/// already seen the unexpose.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stop_unexposes_before_withdrawing_the_report() {
    let VmBackedBox {
        _server,
        handle,
        sock,
        forwarder,
        served,
        door,
        mut reports,
        replies,
    } = vm_backed_allow_box("vmstoporder", 24, 200).await;

    let reporting = handle.clone();
    let expose = tokio::spawn(async move { reporting.expose_dynamic(3000).await });
    assert!(matches!(
        next_report(&mut reports).await,
        minimald_rpc::BoxControlRequest::AdmitPort(_)
    ));
    replies
        .send(minimald_rpc::BoxControlReply::PortRecorded {
            port: 3000,
            proto: sessions::IpProto::Tcp,
        })
        .expect("the report door stand-in lives");
    expose
        .await
        .expect("the expose task should not panic")
        .expect("the admitted port publishes");

    let stopping = handle.clone();
    let stop = tokio::spawn(async move { stopping.stop().await });
    let withdrawal = next_report(&mut reports).await;
    assert!(
        matches!(
            withdrawal,
            minimald_rpc::BoxControlRequest::WithdrawPort(minimald_rpc::WithdrawPortRequest {
                port: 3000,
                ..
            })
        ),
        "the stop withdraws the host's admission: {withdrawal:?}"
    );
    {
        let served = served.lock().expect("served lock");
        assert!(
            served
                .iter()
                .any(|line| line.starts_with("POST /services/forwarder/unexpose ")),
            "the switch's unexpose precedes the report's withdrawal: {served:?}"
        );
    }
    replies
        .send(minimald_rpc::BoxControlReply::PortRecorded {
            port: 3000,
            proto: sessions::IpProto::Tcp,
        })
        .expect("the report door stand-in lives");
    tokio::time::timeout(Duration::from_secs(30), stop)
        .await
        .expect("the stop finishes once the withdrawal is answered")
        .expect("the stop task should not panic");

    forwarder.abort();
    door.abort();
    crate::net::listeners::clear_vm_report_door_for_tests(&sock);
}
