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
/// but never winds down, aborting the loop task instead of awaiting it
/// forever.
///
/// This is the shape `HostHandle::kill`'s `send_timeout` alone cannot
/// cover: the mailbox has room, so the kill enqueues (`kill` returns
/// `Ok`) and the `!killed` short-circuit does not fire, yet the runtime
/// loop is parked mid-`step()` and never processes the queued kill. The
/// *join* bound — not the kill's own deadline — is what has to return the
/// caller and abort the loop. `kill_to_a_wedged_host_gives_up_instead_of_parking`
/// covers the saturated-mailbox sibling, where the kill itself times out.
#[tokio::test(start_paused = true)]
async fn stopping_a_wedged_host_aborts_its_loop_instead_of_parking() {
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

    // The loop task is torn down, not left running behind a detached
    // handle: awaiting it yields a cancelled join.
    let outcome = task.await;
    assert!(
        outcome.is_err_and(|e| e.is_cancelled()),
        "a loop that never wound down within the deadline must be aborted",
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
async fn destroy_session(client: &mut TestClient, id: SessionId) {
    use minimald_rpc::{DestroySession, DestroySessionRequest, Errorable};
    match client
        .call::<DestroySession>(&DestroySessionRequest { id })
        .await
    {
        Errorable::Ok(_) => {}
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
/// still torn down and its record still deleted. A session that a bad
/// hook could pin would be unremovable.
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

    destroy_session(&mut client, session_id).await;

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
    let session_id = create_session(&mut client).await;

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
            .find(|line| line.contains("binding leaving mainloop") && line.contains("shell-test"))
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

    // And none of the stop paths' lines is in the log.
    let logged = capture.contents();
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
