use std::time::Duration;

use boxes::SessionId;
use russh::ChannelMsg;

use minimald_rpc::{GetSessionRecord, GetSessionRecordRequest};

use crate::box_runtime::{HOST_MAILBOX_CAPACITY, HostHandle};
use crate::test_harness::{TestClient, TestServer, create_configured_session};

/// Far longer than [`super::HOST_PROBE_TIMEOUT`], so under a paused
/// clock the probe's own deadline is always the one that fires first.
/// Reaching *this* one means the probe had no deadline at all.
const GIVE_UP: Duration = Duration::from_secs(600);

/// A probe of a host that never answers has to end on its own deadline.
///
/// The session actor forwards `GetHostScreen` (and, through the host slot,
/// the listing's attrs probe takes the same bounded path) to a spawned
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
            crate::traced::spawn(async move { super::probe_host(host.get_attrs()).await })
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
    let mut task = crate::traced::spawn(std::future::pending::<
        Result<crate::box_runtime::HostExit, std::io::Error>,
    >());

    // Far past HOST_PROBE_TIMEOUT: under the paused clock the join bound is
    // the deadline that returns this call. Reaching GIVE_UP would mean the
    // wait was unbounded.
    tokio::time::timeout(
        GIVE_UP,
        super::BoxActor::kill_and_stop_loop(&host, &mut task, true),
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

/// A spawn failure with no probe diagnosis keeps the bare symptom — the
/// exact message the pre-hint daemon surfaced, so an unrestricted host (or
/// an off-Linux one, where no probe runs) sees no change.
#[test]
fn spawn_failed_error_without_a_hint_keeps_the_bare_symptom() {
    assert_eq!(
        super::spawn_failed_error(None).to_string(),
        "the session's sandbox process exited before the attach could connect to it"
    );
}

/// A spawn failure with a probe diagnosis names it: the symptom stays (the
/// host did exit before attaching) and the restriction + fix the startup
/// probe logged follow it, so the error a client sees on a userns-
/// restricted host explains itself.
#[test]
fn spawn_failed_error_with_a_hint_names_the_restriction_and_fix() {
    let hint = "kernel.apparmor_restrict_unprivileged_userns=1 and this \
                 process is unconfined — fix: install minimald's AppArmor \
                 profile (one-time, needs root)";
    let msg = super::spawn_failed_error(Some(hint)).to_string();
    assert!(
        msg.starts_with(
            "the session's sandbox process exited before the attach could connect to it — "
        ),
        "the symptom must stay the error's lead: {msg}"
    );
    assert!(msg.contains(hint), "the diagnosis must travel whole: {msg}");
}

/// A launch failure keeps its own message and kind, and gains the
/// diagnosis only when the probe found one.
#[test]
fn with_userns_hint_appends_the_diagnosis_and_keeps_the_kind() {
    let base = || std::io::Error::new(std::io::ErrorKind::PermissionDenied, "uid_map write");
    let bare = super::with_userns_hint(base(), None);
    assert_eq!(bare.kind(), std::io::ErrorKind::PermissionDenied);
    assert_eq!(bare.to_string(), "uid_map write");

    let hinted = super::with_userns_hint(base(), Some("restricted — fix: x"));
    assert_eq!(hinted.kind(), std::io::ErrorKind::PermissionDenied);
    assert_eq!(
        hinted.to_string(),
        "uid_map write — likely cause: restricted — fix: x"
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
            .get_record(crate::box_manager::BoxKeyPredicate::Id(session_id))
            .await
            .unwrap()
            .expect("the record should exist")
            .status,
        boxes::BoxState::Active,
    );
}

/// Attaching while the session's `WorkspaceFilesTarZst` upload is still
/// streaming must be refused, not shortcut into `configure_loadout`:
/// mid-upload the workspace is half-populated, and the default the
/// Draft shortcut scaffolds against it conflicts with the layout the
/// upload is about to land — wedging the session behind a layout
/// error no retry can clear. The refusal leaves the workspace
/// untouched (nothing is scaffolded). Two overlapping uploads keep
/// attaches refused until both have finished, and an upload whose guard
/// is dropped without finishing (a panic, a torn-down task) still clears
/// its mark, so the same attach then goes through.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn attach_while_a_workspace_upload_streams_is_refused_without_scaffolding() {
    use crate::test_harness::create_session_req;
    use minimald_rpc::CreateSession;

    let server = TestServer::new().await;
    let mut client = server.connect().await;
    // Bare `CreateSession` — the actor stays `Draft`, exactly the state
    // a client is in while it streams the workspace upload.
    let session_id = client
        .call::<CreateSession>(&create_session_req("uploading-session", "/uwu"))
        .await
        .unwrap()
        .id;

    // Stand in for two overlapping in-flight uploads: the RPC handler
    // takes this guard before it pulls the first byte, and finishes it
    // once the unpack ends on either arm.
    let manager = server.state.sessions_manager().await;
    let handle = manager
        .get_session(crate::box_manager::BoxKeyPredicate::Id(session_id))
        .await
        .unwrap()
        .expect("session should resolve");
    let first = crate::rpc::WorkspaceUploadInFlight::begin(handle.clone())
        .await
        .expect("first upload mark should land");
    let second = crate::rpc::WorkspaceUploadInFlight::begin(handle.clone())
        .await
        .expect("second upload mark should land");

    // The attach is refused with the in-flight message, not shortcut
    // into a configure.
    let mut channel = client.open_shell(session_id).await;
    let refusal = collect_to_close(&mut channel).await;
    assert!(
        refusal.contains("Error attaching to session:"),
        "expected an attach refusal, got: {refusal:?}"
    );
    assert!(
        refusal.contains("session is still receiving its workspace upload"),
        "expected the in-flight-upload refusal, got: {refusal:?}"
    );

    // The refusal happened before the Draft shortcut, so the workspace
    // holds no scaffolded root `minimal.toml`.
    let paths = handle.paths().await.expect("paths should resolve");
    assert!(
        !paths.working.as_utf8_path().join("minimal.toml").exists(),
        "a refused attach must not scaffold the workspace"
    );

    // One upload finishing does not re-admit attaches while the other
    // is still unpacking.
    first
        .finish()
        .await
        .expect("first upload mark should clear");
    let mut channel = client.open_shell(session_id).await;
    let refusal = collect_to_close(&mut channel).await;
    assert!(
        refusal.contains("session is still receiving its workspace upload"),
        "an attach must stay refused while any upload streams, got: {refusal:?}"
    );

    // The second upload never reaches its finish — dropping the guard
    // stands in for a panic or a torn-down task — and the same attach
    // then lands the session live.
    drop(second);
    let mut channel = client.open_shell(session_id).await;
    await_hello_echo(&mut channel, "attach after the upload").await;

    // The attach that landed ran the Draft shortcut, which scaffolds the
    // root `minimal.toml` in this harness — so its absence after the
    // refusals above is the refusal's doing, not the harness's.
    assert!(
        paths
            .working
            .as_utf8_path()
            .join(mfile::MFILE_NAME)
            .exists(),
        "the attach that landed should have scaffolded the workspace"
    );
}

/// Serializes `(path, contents)` entries into the zstd-compressed tarball a
/// client streams over `WorkspaceFilesTarZst`.
async fn workspace_tar_zst(entries: &[(&str, &[u8])]) -> Vec<u8> {
    use tokio::io::AsyncWriteExt as _;
    let mut tar = async_tar::Builder::new(Vec::new());
    for (path, contents) in entries {
        let mut header = async_tar::Header::new_gnu();
        header.set_size(contents.len() as u64);
        header.set_mode(0o644);
        tar.append_data(&mut header, path, *contents).await.unwrap();
    }
    let tar_bytes = tar.into_inner().await.unwrap();
    let mut encoder = async_compression::tokio::write::ZstdEncoder::new(Vec::new());
    encoder.write_all(&tar_bytes).await.unwrap();
    encoder.shutdown().await.unwrap();
    encoder.into_inner()
}

/// Streams `payload` through the real `WorkspaceFilesTarZst` subsystem on
/// `client`, waits for the daemon to close the channel (the unpack, and the
/// clear of its in-flight mark, are done by then), and returns its stderr.
async fn upload_workspace(
    client: &mut TestClient,
    session_id: SessionId,
    payload: &[u8],
) -> String {
    let mut channel = client
        .open_subsystem(
            crate::rpc::STREAM_WORKSPACE_FILES,
            &[(crate::MINIMAL_SESSION_ID_ENV, &session_id.to_string())],
        )
        .await;
    channel.data(payload).await.unwrap();
    channel.eof().await.unwrap();
    let mut stderr = Vec::new();
    while let Some(msg) = channel.wait().await {
        if let ChannelMsg::ExtendedData { data, ext: 1 } = msg {
            stderr.extend_from_slice(&data);
        }
    }
    String::from_utf8_lossy(&stderr).into_owned()
}

/// Reads `channel` until the mock shell echoes `got:hello`, panicking if it
/// closes first.
async fn await_hello_echo(channel: &mut russh::Channel<russh::client::Msg>, what: &str) {
    channel.data_bytes(b"hello\n".to_vec()).await.unwrap();
    let mut stdout = Vec::new();
    loop {
        match channel.wait().await {
            Some(ChannelMsg::Data { data }) => {
                stdout.extend_from_slice(&data);
                if String::from_utf8_lossy(&stdout).contains("got:hello") {
                    return;
                }
            }
            Some(_) => {}
            None => {
                let stdout = String::from_utf8_lossy(&stdout);
                panic!("{what} should mint a shell; got: {stdout:?}");
            }
        }
    }
}

/// While the creating connection is still mid-activation, an attach from
/// any other connection is refused, not shortcut into `configure_loadout`
/// — before the workspace upload, and after it but before the creator's
/// `ConfigureLoadout`. Either shortcut would compose an empty contribution
/// against a workspace the creator has not finished with and then refuse the
/// creator's own configure. Once the creator has configured and finalized,
/// the same attach lands.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn attach_from_elsewhere_during_activation_is_refused_until_the_creator_finishes() {
    use crate::test_harness::{create_session_req, unwrap_ready};
    use minimald_rpc::{
        ConfigureLoadout, ConfigureLoadoutRequest, CreateSession, FinalizeSession,
        FinalizeSessionRequest,
    };

    let server = TestServer::new().await;
    let mut creator = server.connect().await;
    let mut other = server.connect().await;
    let session_id = creator
        .call::<CreateSession>(&create_session_req("activating", "/uwu"))
        .await
        .unwrap()
        .id;
    let paths = server
        .state
        .sessions_manager()
        .await
        .get_session(crate::box_manager::BoxKeyPredicate::Id(session_id))
        .await
        .unwrap()
        .expect("session should resolve")
        .paths()
        .await
        .expect("paths should resolve");
    let scaffolded = paths.working.as_utf8_path().join(mfile::MFILE_NAME);

    // Before the upload.
    let mut channel = other.open_shell(session_id).await;
    let refusal = collect_to_close(&mut channel).await;
    assert!(
        refusal.contains("session isn't attachable yet"),
        "an attach before the creator's upload must be refused, got: {refusal:?}"
    );
    assert!(!scaffolded.exists(), "a refused attach must not scaffold");

    // The creator's upload, through the real subsystem.
    let payload = workspace_tar_zst(&[("hello.txt", b"hello\n")]).await;
    let stderr = upload_workspace(&mut creator, session_id, &payload).await;
    assert!(stderr.is_empty(), "the upload should land, got: {stderr:?}");
    assert!(paths.working.as_utf8_path().join("hello.txt").exists());

    // After the upload, before the creator's `ConfigureLoadout`.
    let mut channel = other.open_shell(session_id).await;
    let refusal = collect_to_close(&mut channel).await;
    assert!(
        refusal.contains("session isn't attachable yet"),
        "an attach between the upload and the configure must be refused, got: {refusal:?}"
    );
    assert!(!scaffolded.exists(), "a refused attach must not scaffold");

    // The creator finishes its activation; nothing refused it.
    unwrap_ready(
        creator
            .call::<ConfigureLoadout>(&ConfigureLoadoutRequest {
                session_id,
                contribution: Default::default(),
            })
            .await
            .unwrap(),
    );
    match creator
        .call::<FinalizeSession>(&FinalizeSessionRequest {
            session_id,
            report_shared_port_collisions: false,
        })
        .await
    {
        minimald_rpc::Errorable::Ok(_) => {}
        minimald_rpc::Errorable::Err { error } => panic!("FinalizeSession failed: {error}"),
    }

    let mut channel = other.open_shell(session_id).await;
    await_hello_echo(&mut channel, "an attach after the activation").await;
}

/// An upload that fails mid-stream, sent through the real
/// `WorkspaceFilesTarZst` subsystem, clears its in-flight mark on the way
/// out: the next attach lands rather than being refused forever.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_workspace_upload_does_not_leave_attaches_refused() {
    use crate::test_harness::create_session_req;
    use minimald_rpc::CreateSession;

    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let session_id = client
        .call::<CreateSession>(&create_session_req("failed-upload", "/uwu"))
        .await
        .unwrap()
        .id;

    // A truncated archive: the head of a real one, cut off mid-stream.
    let noise: Vec<u8> = (0..64 * 1024u32)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
        .collect();
    let payload = workspace_tar_zst(&[("big.bin", noise.as_slice())]).await;
    let stderr = upload_workspace(&mut client, session_id, &payload[..payload.len() / 2]).await;
    assert!(
        stderr.contains("unpack failed"),
        "the truncated upload should fail its unpack, got: {stderr:?}"
    );

    let mut channel = client.open_shell(session_id).await;
    await_hello_echo(&mut channel, "an attach after a failed upload").await;
}

/// An attach that arrives while a real `WorkspaceFilesTarZst` stream is
/// half-sent is refused, and the same attach lands once the rest of the
/// stream and its EOF have arrived: the subsystem itself marks the upload in
/// flight before it unpacks the first byte, and clears the mark at the end.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn attach_while_a_real_workspace_upload_is_half_sent_is_refused_then_lands() {
    use crate::test_harness::create_session_req;
    use minimald_rpc::CreateSession;

    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let session_id = client
        .call::<CreateSession>(&create_session_req("half-sent-upload", "/uwu"))
        .await
        .unwrap()
        .id;
    let paths = server
        .state
        .sessions_manager()
        .await
        .get_session(crate::box_manager::BoxKeyPredicate::Id(session_id))
        .await
        .unwrap()
        .expect("session should resolve")
        .paths()
        .await
        .expect("paths should resolve");
    let working = paths.working.as_utf8_path();

    // A small file ahead of incompressible noise several zstd blocks long,
    // so the first half of the payload already carries the small file whole.
    let noise: Vec<u8> = (0..512 * 1024u32)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
        .collect();
    let payload =
        workspace_tar_zst(&[("first.txt", b"first\n"), ("big.bin", noise.as_slice())]).await;
    let (head, tail) = payload.split_at(payload.len() / 2);

    let mut upload = client
        .open_subsystem(
            crate::rpc::STREAM_WORKSPACE_FILES,
            &[(crate::MINIMAL_SESSION_ID_ENV, &session_id.to_string())],
        )
        .await;
    upload.data(head).await.unwrap();
    // The small file landing proves the unpack is underway, so the upload
    // is marked in flight by now.
    tokio::time::timeout(Duration::from_secs(10), async {
        while !working.join("first.txt").exists() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the first half of the upload should start unpacking");

    let mut channel = client.open_shell(session_id).await;
    let refusal = collect_to_close(&mut channel).await;
    assert!(
        refusal.contains("session is still receiving its workspace upload"),
        "an attach mid-stream must be refused, got: {refusal:?}"
    );
    assert!(
        !working.join(mfile::MFILE_NAME).exists(),
        "a refused attach must not scaffold the workspace"
    );

    upload.data(tail).await.unwrap();
    upload.eof().await.unwrap();
    let mut stderr = Vec::new();
    while let Some(msg) = upload.wait().await {
        if let ChannelMsg::ExtendedData { data, ext: 1 } = msg {
            stderr.extend_from_slice(&data);
        }
    }
    let stderr = String::from_utf8_lossy(&stderr);
    assert!(stderr.is_empty(), "the upload should land, got: {stderr:?}");
    assert!(working.join("big.bin").exists());

    let mut channel = client.open_shell(session_id).await;
    await_hello_echo(&mut channel, "an attach after the upload").await;
}

/// `ConfigureLoadout` is refused while a workspace upload streams, the same
/// as the attach shortcut that runs it: composing mid-upload would scaffold
/// against a half-populated tree and let the session go `Active` with the
/// upload still landing. Once the upload has ended the same configure lands.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn configure_while_a_workspace_upload_streams_is_refused() {
    use crate::test_harness::{create_session_req, unwrap_ready};
    use minimald_rpc::{ConfigureLoadout, ConfigureLoadoutRequest, CreateSession, Errorable};

    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let session_id = client
        .call::<CreateSession>(&create_session_req("configure-mid-upload", "/uwu"))
        .await
        .unwrap()
        .id;
    let handle = server
        .state
        .sessions_manager()
        .await
        .get_session(crate::box_manager::BoxKeyPredicate::Id(session_id))
        .await
        .unwrap()
        .expect("session should resolve");
    let paths = handle.paths().await.expect("paths should resolve");
    let upload = crate::rpc::WorkspaceUploadInFlight::begin(handle)
        .await
        .expect("upload mark should land");

    let request = ConfigureLoadoutRequest {
        session_id,
        contribution: Default::default(),
    };
    match client.call::<ConfigureLoadout>(&request).await {
        Errorable::Err { error } => assert!(
            error.contains("session is still receiving its workspace upload"),
            "expected the in-flight-upload refusal, got: {error:?}"
        ),
        Errorable::Ok(_) => panic!("a configure mid-upload must be refused"),
    }
    assert!(
        !paths
            .working
            .as_utf8_path()
            .join(mfile::MFILE_NAME)
            .exists(),
        "a refused configure must not scaffold the workspace"
    );

    upload.finish().await.expect("upload mark should clear");
    unwrap_ready(client.call::<ConfigureLoadout>(&request).await.unwrap());
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
    // prompt (see `box_runtime`), rendered over the channel; answer it by
    // confirming the first option (Enter -> detach) so teardown proceeds and
    // the channel closes.
    channel
        .data_bytes(format!("{}\n", crate::box_runtime::MOCK_EXIT_LINE).into_bytes())
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
                        .contains(crate::box_runtime::SHELL_EXIT_PROMPT)
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
        .get_session(crate::box_manager::BoxKeyPredicate::Id(session_id))
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
        .data_bytes(format!("{}\n", crate::box_runtime::MOCK_EXIT_LINE).into_bytes())
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
                        .contains(crate::box_runtime::SHELL_EXIT_PROMPT)
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
async fn session_paths(server: &TestServer, session_id: SessionId) -> crate::box_actor::BoxPaths {
    server
        .state
        .sessions_manager()
        .await
        .get_session(crate::box_manager::BoxKeyPredicate::Id(session_id))
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
        .data_bytes(format!("{}\n", crate::box_runtime::MOCK_EXIT_LINE).into_bytes())
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
                        .contains(crate::box_runtime::SHELL_EXIT_PROMPT)
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
/// unpushed-commit arm is covered by `workspace_delta`'s unit tests.
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
        .data_bytes(format!("{}\n", crate::box_runtime::MOCK_EXIT_LINE).into_bytes())
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
                        .contains(crate::box_runtime::SHELL_EXIT_PROMPT)
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
        .get_session(crate::box_manager::BoxKeyPredicate::Id(session_id))
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
        .data_bytes(format!("{}\n", crate::box_runtime::MOCK_EXIT_LINE).into_bytes())
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
                        .contains(crate::box_runtime::SHELL_EXIT_PROMPT)
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
    use boxes::keys::{DETACH_KEY_ENV, LEADER_ENV};

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
    use boxes::keys::{DETACH_KEY_ENV, LEADER_ENV};

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
    use boxes::keys::{DETACH_KEY_ENV, LEADER_ENV};

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
        .get_session(crate::box_manager::BoxKeyPredicate::Id(session_id))
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
        .get_session(crate::box_manager::BoxKeyPredicate::Id(session_id))
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
        .get_session(crate::box_manager::BoxKeyPredicate::Id(session_id))
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
        .get_session(crate::box_manager::BoxKeyPredicate::Id(session_id))
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
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ensure_host_launches_an_unattached_host_and_then_reuses_it() {
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let session_id = create_configured_session(&mut client, "ensure-host", "/tmp").await;

    let manager = server.state.sessions_manager().await;
    let handle = manager
        .get_session(crate::box_manager::BoxKeyPredicate::Id(session_id))
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
        "the session should now be holding the host it launched: the slot is \
         published before `ensure_host` replies, on a multi-thread runtime too"
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
    let torn_down = crate::box_actor::launch_record_seam::fail_writes_for(session_id);

    let manager = server.state.sessions_manager().await;
    let handle = manager
        .get_session(crate::box_manager::BoxKeyPredicate::Id(session_id))
        .await
        .unwrap()
        .expect("session should resolve");

    match handle.ensure_host("tester".to_string()).await {
        Err(crate::box_actor::AttachError::LaunchRecordUnwritable(_)) => {}
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

/// A mint whose host dies between launch and attach must not say the host
/// "exited" out of a channel that never wedged: the death is a spawn
/// failure, and the client reads it as one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_mint_whose_host_dies_before_attach_reports_a_spawn_failure() {
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let id = create_configured_session(&mut client, "mint-died", "/tmp").await;
    super::mint_attach_seam::seed(id, super::mint_attach_seam::Failure::HostDiedBeforeAttach);

    let mut channel = client.open_shell(id).await;
    let refusal = collect_to_close(&mut channel).await;
    assert!(
        refusal.contains("Error attaching to session:"),
        "the refused attach should surface its error to the client, got: {refusal:?}"
    );
    assert!(
        refusal
            .contains("the session's sandbox process exited before the attach could connect to it"),
        "a host that died before its channel attached reads as a spawn failure, got: {refusal:?}"
    );
}

/// A mint whose host wedges between launch and attach is alive but busy:
/// calling it dead would mint a second host over a healthy, busy one. The
/// refusal must name the wedged case, not the exited one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_mint_whose_host_wedges_reports_busy_instead_of_death() {
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let id = create_configured_session(&mut client, "mint-wedged", "/tmp").await;
    super::mint_attach_seam::seed(id, super::mint_attach_seam::Failure::HostWedged);

    let mut channel = client.open_shell(id).await;
    let refusal = collect_to_close(&mut channel).await;
    assert!(
        refusal.contains("Error attaching to session:"),
        "the refused attach should surface its error to the client, got: {refusal:?}"
    );
    assert!(
        refusal.contains("the session is busy; run the attach again in a moment"),
        "a host that wedged before its channel attached reads as busy, not exited, got: {refusal:?}"
    );
    assert!(
        !refusal.contains("exited before"),
        "a wedged host must not be reported as exited, got: {refusal:?}"
    );

    // The busy refusal asks for a retry, so the retry must reach the wedged
    // host: kept in the slot, it refuses busy again rather than a fresh host
    // being minted over it (the seam is taken once, so a second mint would
    // launch an ordinary host and the retry would attach).
    let mut retry = client.open_shell(id).await;
    let refusal = collect_to_close(&mut retry).await;
    assert!(
        refusal.contains("the session is busy; run the attach again in a moment"),
        "a retry must reach the kept wedged host, not mint a second one, got: {refusal:?}"
    );
}

// ---- lifecycle hooks -------------------------------------------------
//
// Hooks run inside the session, which under test means the host-side
// command `box_runtime::Host::command_in_session` builds for the mock
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
fn inline(body: String) -> boxes::wire::primitives::WireHookScript {
    boxes::wire::primitives::WireHookScript::Inline {
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
    hook: boxes::wire::primitives::WireLifecycleHook,
) -> boxes::wire::request::WireContribution {
    boxes::wire::request::WireContribution {
        lifecycle_hooks: vec![boxes::wire::primitives::WireProvenancedHook {
            hook,
            source: boxes::wire::primitives::WireSource::UserLoadout {
                name: "test".to_string(),
            },
        }],
        ..Default::default()
    }
}

/// The session's on-disk status, or `None` once it is gone.
async fn record_status(client: &mut TestClient, id: SessionId) -> Option<boxes::BoxState> {
    client
        .call::<GetSessionRecord>(&GetSessionRecordRequest::Id(id))
        .await
        .record
        .map(|r| r.status)
}

async fn session_with_hook(
    client: &mut TestClient,
    name: &str,
    hook: boxes::wire::primitives::WireLifecycleHook,
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
                contribution: boxes::wire::request::WireContribution {
                    lifecycle_hooks: vec![boxes::wire::primitives::WireProvenancedHook {
                        hook,
                        source: boxes::wire::primitives::WireSource::UserLoadout {
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

/// Destroys `id` through the RPC surface a client uses.
async fn destroy_session(
    client: &mut TestClient,
    id: SessionId,
) -> minimald_rpc::DestroySessionResponse {
    use minimald_rpc::{DestroySession, DestroySessionRequest, Errorable};
    match client
        .call::<DestroySession>(&DestroySessionRequest {
            id,
            only_if_unfinalized: false,
        })
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
    use boxes::core::lifecyclehook::{HookScript, LifecycleHook};
    use boxes::core::source::{ProvenancedHook, Source};
    use boxes::wire::primitives::WireProvenancedHook;
    use boxes::wire::request::{COMPOSITION_SNAPSHOT_VERSION, WireComposition};

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
        boxes::wire::primitives::WireLifecycleHook {
            on_activate: Some(inline(marker_body(&marker))),
            ..Default::default()
        },
    )
    .await;

    assert!(marker.exists(), "on_activate did not run");
    assert_eq!(
        record_status(&mut client, session_id).await,
        Some(boxes::BoxState::Active),
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
                contribution: contribution_with_hook(boxes::wire::primitives::WireLifecycleHook {
                    on_activate: Some(inline("echo HOOK_SAID_HELLO".to_string())),
                    ..Default::default()
                }),
            })
            .await
            .unwrap(),
    );

    let ran = match client
        .call::<FinalizeSession>(&FinalizeSessionRequest {
            session_id: id,
            report_shared_port_collisions: false,
        })
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
/// This is the case `BoxActor::attach` logs, because on the wire it looks
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

/// BOX-010 through the actor: a rename writes exactly one `renamed` event
/// with the old and new names, keyed on the box's id. A rename to a name a
/// running box holds, or to `self`, is refused, names the holder or
/// `self`, and writes no event.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rename_through_the_actor_writes_one_renamed_event() {
    use boxes::events::BoxEventType;
    use minimald_rpc::{Errorable, RenameSession, RenameSessionRequest, RenameSessionResponse};

    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let holder = create_configured_session(&mut client, "rename-holder", "/uwu").await;
    let id = create_configured_session(&mut client, "rename-box", "/uwu").await;
    let before = event_kinds(&server, id).await;

    let resp = client
        .call::<RenameSession>(&RenameSessionRequest {
            id,
            new_name: "rename-new".to_string(),
        })
        .await;
    assert_eq!(resp, Errorable::Ok(RenameSessionResponse));

    let after = event_kinds(&server, id).await;
    assert_eq!(&after[..before.len()], &before[..], "earlier events stay");
    let added = &after[before.len()..];
    assert_eq!(added.len(), 1, "one event per rename: {added:?}");
    assert_eq!(added[0].kind, BoxEventType::Renamed);
    assert_eq!(added[0].box_id, id);
    assert_eq!(added[0].data["old_name"], "rename-box");
    assert_eq!(added[0].data["new_name"], "rename-new");
    let record = read_record(&server, id).await;
    assert_eq!(record.id, id);
    assert_eq!(record.name.as_deref(), Some("rename-new"));

    // Refused: a name the running holder has, under any case, and `self`.
    for (new_name, named) in [
        ("rename-holder", holder.to_string()),
        ("RENAME-HOLDER", holder.to_string()),
        ("self", "`self`".to_string()),
    ] {
        let resp = client
            .call::<RenameSession>(&RenameSessionRequest {
                id,
                new_name: new_name.to_string(),
            })
            .await;
        let Errorable::Err { error } = resp else {
            panic!("a rename to `{new_name}` must be refused: {resp:?}");
        };
        assert!(error.contains(&named), "`{named}` missing from: {error}");
    }
    assert_eq!(
        event_kinds(&server, id).await,
        after,
        "a refusal writes no event"
    );
    assert_eq!(
        read_record(&server, id).await.name.as_deref(),
        Some("rename-new")
    );
    assert_eq!(
        read_record(&server, holder).await.name.as_deref(),
        Some("rename-holder")
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
        boxes::wire::primitives::WireLifecycleHook {
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
                contribution: contribution_with_hook(boxes::wire::primitives::WireLifecycleHook {
                    on_activate: Some(inline("echo ACTIVATE_SAID_NO >&2; exit 3".to_string())),
                    ..Default::default()
                }),
            })
            .await
            .unwrap(),
    );

    let error = match client
        .call::<FinalizeSession>(&FinalizeSessionRequest {
            session_id: id,
            report_shared_port_collisions: false,
        })
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
        Some(boxes::BoxState::Active),
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
        boxes::wire::primitives::WireLifecycleHook {
            on_destroy: Some(inline(marker_body(&marker))),
            ..Default::default()
        },
    )
    .await;

    // Bring a host up and leave it running, so destroy meets the state
    // it has always handled: a session with somewhere to run.
    let manager = server.state.sessions_manager().await;
    let handle = manager
        .get_session(crate::box_manager::BoxKeyPredicate::Id(session_id))
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
        boxes::wire::primitives::WireLifecycleHook {
            on_destroy: Some(inline(marker_body(&marker))),
            ..Default::default()
        },
    )
    .await;

    // Exit the shell and answer the prompt with the default (keep), the
    // way the reported repro does. This is what leaves the stale handle.
    let mut channel = client.open_shell(session_id).await;
    channel
        .data_bytes(format!("{}\n", crate::box_runtime::MOCK_EXIT_LINE).into_bytes())
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
                        .contains(crate::box_runtime::SHELL_EXIT_PROMPT)
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
        boxes::wire::primitives::WireLifecycleHook {
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
        boxes::wire::primitives::WireLifecycleHook {
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
        boxes::wire::primitives::WireLifecycleHook {
            on_detach: Some(inline(marker_body(&marker))),
            ..Default::default()
        },
    )
    .await;

    let mut channel = client.open_shell(session_id).await;
    channel
        .data_bytes(format!("{}\n", crate::box_runtime::MOCK_EXIT_LINE).into_bytes())
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
                        .contains(crate::box_runtime::SHELL_EXIT_PROMPT)
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
        boxes::wire::primitives::WireLifecycleHook {
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

    use boxes::core::compose::Composition;
    use boxes::wire::primitives::{WireResolvedPatch, WireSessionPatch, WireSource};
    use boxes::wire::request::{COMPOSITION_SNAPSHOT_VERSION, WireComposition};
    use paths::{DaemonAbsPath, HostAbsPath, SandboxRelPath};

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
    let run = crate::traced::spawn(crate::server::Server::run(
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
        .get_session(crate::box_manager::BoxKeyPredicate::Id(session_id))
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
        Some(boxes::BoxState::Active),
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
        Some(boxes::BoxState::Active),
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
        .get_session(crate::box_manager::BoxKeyPredicate::Id(session_id))
        .await
        .unwrap()
        .expect("session should resolve");
    assert!(
        handle.get_attrs().await.is_some(),
        "an idle box's entrypoint must still be running"
    );
    assert_eq!(
        record_status(&mut server.connect().await, session_id).await,
        Some(boxes::BoxState::Active),
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
/// [`boxes::core::egress::summarize`] extracts a verdict's inputs from.
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
/// nothing outside itself, and this build ships the deny-all default in
/// force (asserted first, so the constant cannot slip back unnoticed). The
/// phase is also passed explicitly to the resolver, so the in-force posture
/// is proven by name, and the launcher's gate policy under it is the
/// deny-all section, whose compiled rules drop every external
/// destination in every transport, while the resolver Minimal owns for the
/// box still answers, at its address *and* its port (NET-079). The
/// session-start line names the phase, the opt-out, and the posture this
/// build actually leaves in force, so a diagnostics bundle's log tail can
/// say why the box reaches what it does.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn own_ip_default_deny_all() {
    use boxes::core::egress::{EgressRules, FrameVerdict};
    use minimald_rpc::{CreateSession, CreateSessionRequest};

    // The address of the resolver Minimal owns for a box: the switch
    // gateway, as the relay hands it to the gate.
    let resolver = [100, 64, 0, 1];
    // Something the box did not declare: an address out in the world.
    let external = [93, 184, 216, 34];
    // The box's lease — the source address `ipv4_frame` writes, so the
    // verdicts below turn on the egress dimension alone. The lease check
    // itself (NET-084) is proven in `boxes::core::egress`.
    let lease = [10, 0, 0, 5];

    assert_eq!(
        boxes::EGRESS_DEFAULT_PHASE,
        boxes::EgressDefaultPhase::InForce,
        "this build ships the deny-all default in force (NET-074)",
    );

    // The launcher's resolution for an own-address box that declared
    // nothing, once the default is in force: the deny-all section, egress
    // only touched, ingress kept.
    let declared = boxes::BoxPolicy::default();
    let effective = super::effective_session_policy(
        &declared,
        boxes::NetworkMode::OwnIp,
        boxes::EgressDefaultPhase::InForce,
        false,
    );
    assert_eq!(
        effective.egress,
        Some(boxes::EgressPolicy::deny_all()),
        "the gate's egress for an absent section is the deny-all section",
    );
    assert_eq!(effective.ingress, None);

    // What that section enforces: every frame to an external address drops,
    // in every transport — the carve-out excepted, keyed to both the
    // resolver's address and DNS's port, so no other address at :53 and no
    // other port on the resolver slips through.
    let rules = EgressRules::from_policy(effective.egress.as_ref(), resolver, lease);
    let verdict_on = |proto: u8, dst: [u8; 4], port: u16| {
        boxes::core::egress::verdict(
            &boxes::core::egress::summarize(&ipv4_frame(proto, dst, port)),
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
        .call::<CreateSession>(&CreateSessionRequest::new(
            "own-ip-bare",
            paths::HostAbsPath::try_new("/uwu").unwrap(),
            boxes::NetworkMode::OwnIp,
            boxes::BoxPolicy::default(),
        ))
        .await
        .unwrap();
    let logged = capture.contents();
    let start_line = logged
        .lines()
        .find(|line| line.contains("session starts") && line.contains("own-ip-bare"))
        .unwrap_or_else(|| panic!("the session start must be logged, got: {logged}"));
    for fact in [
        format!("egress_default_phase={:?}", boxes::EGRESS_DEFAULT_PHASE),
        "deny_all_opt_out=false".to_string(),
        format!(
            "effective_egress={:?}",
            boxes::effective_egress(
                None,
                boxes::NetworkMode::OwnIp,
                boxes::EGRESS_DEFAULT_PHASE,
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

/// The running test's [`declared_port`] and the lock file that holds its
/// lease. nextest runs each test in a process of its own, so one lease per
/// process is one port per test, whichever thread asks for it: the test's
/// own thread or a task it spawned onto a runtime worker. The lock is
/// released when the process exits.
static DECLARED_PORT: std::sync::OnceLock<(u16, std::fs::File)> = std::sync::OnceLock::new();

/// The ports [`declared_port`] leases from. The band sits below the kernel's
/// default ephemeral range (`net.ipv4.ip_local_port_range` starts at 32768),
/// so no other process's `bind(0)` or outbound `connect` is handed one
/// between the lease and the finalize's probe, and no fixed port in the tree
/// falls inside it. A host that widens the ephemeral range down into this
/// band loses that guarantee.
const DECLARED_PORTS: std::ops::Range<u16> = 23_000..24_000;

/// Leases a port from [`DECLARED_PORTS`]: the first one whose lock file this
/// process can lock, among every test process the same user runs on the
/// host, and that nothing already listens on at `127.0.0.1`. The lock files
/// live in a directory of the user's own, so another user's run cannot leave
/// files this one cannot open; a file that still cannot be opened counts as
/// leased. The probe checks `127.0.0.1` only: a listener on `0.0.0.0` also
/// fails it, but one bound to a specific `127.0.64.x` address does not. The
/// port itself stays unbound, because the finalize under test must find it
/// free.
fn lease_declared_port() -> (u16, std::fs::File) {
    let dir = std::env::temp_dir().join(format!("minimald-test-ports-{}", nix::unistd::getuid()));
    std::fs::create_dir_all(&dir)
        .unwrap_or_else(|e| panic!("create the port lease directory {dir:?}: {e}"));
    for port in DECLARED_PORTS {
        let Ok(lock) = std::fs::File::create(dir.join(format!("{port}.lock"))) else {
            continue;
        };
        if lock.try_lock().is_ok()
            && std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port)).is_ok()
        {
            return (port, lock);
        }
    }
    panic!("every port in {DECLARED_PORTS:?} is leased, in use, or has no lease file in {dir:?}");
}

/// The host port every own-address box of the running test declares, in
/// place of one fixed number. A finalize refuses a declared port that
/// something else holds at the box's published address (NET-144), and
/// nextest runs tests side by side on one host: two tests declaring one
/// fixed port at `127.0.0.1` can refuse each other's box. So each test
/// leases its own port, and every box within the test shares it, which the
/// collision tests need.
fn declared_port() -> u16 {
    DECLARED_PORT.get_or_init(lease_declared_port).0
}

/// An own-address session's config: a box that declares one published port —
/// the ingress a publish is made of (NET-010) — under the session `name`.
fn own_ip_session_req(name: &str) -> minimald_rpc::CreateSessionRequest {
    minimald_rpc::CreateSessionRequest::new(
        name,
        paths::HostAbsPath::try_new("/uwu").unwrap(),
        boxes::NetworkMode::OwnIp,
        boxes::BoxPolicy {
            egress: None,
            ingress: Some(boxes::IngressPolicy {
                port_mappings: vec![boxes::PortMapping {
                    external_port: declared_port(),
                    internal_port: 80,
                    proto: boxes::IpProto::Tcp,
                }],
                ..Default::default()
            }),
            credentialed_upstream: None,
            quic443: None,
        },
    )
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
    request.config.box_addresses = Some(boxes::BoxAddresses {
        switch_address: switch,
        loopback_address: loopback,
    });
    request.config.box_id = Some(HANDED_BOX_ID);
    request
}

/// The box id every handed session in these tests was registered as.
const HANDED_BOX_ID: minimald_rpc::BoxId = minimald_rpc::BoxId::from_bytes([0x42; 16]);

/// The control socket of `server`'s switch: the key a stand-in report
/// door is seeded under. Read before any box exists, so a fixture can seed
/// the door that hands a box its id at the create.
async fn daemon_switch_control(server: &TestServer) -> std::path::PathBuf {
    server
        .state
        .minimal_state_dir()
        .await
        .as_utf8_path()
        .join("gvproxy")
        .join(server.state.daemon_id().await)
        .join("gvproxy-api.sock")
        .into_std_path_buf()
}

/// A stand-in VM host report door at `server`'s switch, and a handed
/// own-address box finalized with its id handed over it (BOX-002). The door
/// answers the create's mint with [`HANDED_BOX_ID`], the id the box's
/// registration minted, so the record and the host row name one id. The
/// door is unseeded again before the finalize, so the box publishes the
/// way a native-shaped test box does. Returns the box's id, the switch
/// control socket and the door, which a test seeds again to drive its
/// row reads.
async fn finalize_door_handed_own_ip_session(
    server: &TestServer,
    client: &mut TestClient,
    name: &str,
    switch: std::net::Ipv4Addr,
    loopback: std::net::Ipv4Addr,
) -> (
    SessionId,
    std::path::PathBuf,
    std::path::PathBuf,
    (
        tokio::task::JoinHandle<()>,
        tokio::sync::mpsc::UnboundedReceiver<minimald_rpc::BoxControlRequest>,
        tokio::sync::mpsc::UnboundedSender<minimald_rpc::BoxControlReply>,
    ),
) {
    use minimald_rpc::{ConfigureLoadout, ConfigureLoadoutRequest, CreateSession};
    let sock = daemon_switch_control(server).await;
    let door_sock = sock.with_file_name("row-door.sock");
    let (door, mut reads, replies) = fake_report_door(&door_sock).await;
    replies
        .send(minimald_rpc::BoxControlReply::BoxIdMinted {
            minted_box_id: HANDED_BOX_ID,
        })
        .expect("the report door stand-in lives");
    crate::net::listeners::seed_vm_report_door_for_tests(&sock, &door_sock);
    let id = client
        .call::<CreateSession>(&own_ip_handed_session_req(name, switch, loopback))
        .await
        .unwrap()
        .id;
    crate::net::listeners::clear_vm_report_door_for_tests(&sock);
    assert_eq!(id, HANDED_BOX_ID, "the box takes the VM host daemon's id");
    match reads.recv().await.expect("the report door stand-in lives") {
        minimald_rpc::BoxControlRequest::MintBoxId(ask) => {
            assert_eq!(
                ask.switch_address,
                Some(switch),
                "the create asks for its row's id by its switch address"
            );
            assert!(ask.create_token.is_some(), "the create sends its token");
        }
        other => panic!("expected a mint ask, got {other:?}"),
    }
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
    (id, sock, door_sock, (door, reads, replies))
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
/// that bounded wait (NET-123 §7.1). Returns the reply, so a test can
/// read what the finalize reported — the collisions a shared-address box
/// yielded among them. Asks for that list, as the current `min` does.
async fn finalize_session(
    client: &mut TestClient,
    id: SessionId,
) -> minimald_rpc::FinalizeSessionResponse {
    finalize_session_asking(client, id, true).await
}

/// [`finalize_session`] with the request's
/// `report_shared_port_collisions` flag chosen by the caller — `false` is
/// the request a client that predates the flag sends.
async fn finalize_session_asking(
    client: &mut TestClient,
    id: SessionId,
    report_shared_port_collisions: bool,
) -> minimald_rpc::FinalizeSessionResponse {
    use minimald_rpc::{Errorable, FinalizeSession, FinalizeSessionRequest};
    match client
        .call::<FinalizeSession>(&FinalizeSessionRequest {
            session_id: id,
            report_shared_port_collisions,
        })
        .await
    {
        Errorable::Ok(ok) => ok,
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

/// The finalize of a box whose declared port is held fails with the typed
/// refusal (NET-144). Then the destroy the client's activate cleanup sends
/// removes the box, which proves it never reached `Active`, and no record is
/// left behind.
#[cfg(target_os = "linux")]
async fn assert_refused_and_cleaned_up(
    client: &mut TestClient,
    id: SessionId,
    expected: minimald_rpc::PortInUseRefusal,
) {
    use minimald_rpc::{
        DestroySession, DestroySessionRequest, Errorable, FinalizeSession, FinalizeSessionRequest,
        ListSessions,
    };
    let reply = client
        .call::<FinalizeSession>(&FinalizeSessionRequest {
            session_id: id,
            report_shared_port_collisions: true,
        })
        .await;
    match reply {
        Errorable::Err { error } => {
            assert_eq!(
                minimald_rpc::PortInUseRefusal::find_in(&error),
                Some(expected.clone()),
                "the refusal names the port and its holder, got: {error}"
            );
            assert!(
                error.contains(&expected.to_string()),
                "the daemon's text is the refusal's own text, got: {error}"
            );
        }
        Errorable::Ok(ok) => panic!("finalize must fail on a held port, got {ok:?}"),
    }
    // `only_if_unfinalized` is the client's activate cleanup: it removes
    // only a box that never reached `Active`.
    match client
        .call::<DestroySession>(&DestroySessionRequest {
            id,
            only_if_unfinalized: true,
        })
        .await
    {
        Errorable::Ok(_) => {}
        Errorable::Err { error } => panic!("the activate cleanup's destroy failed: {error}"),
    }
    let listed = client.call::<ListSessions>(&()).await;
    assert!(
        listed.sessions.iter().all(|entry| entry.id != id),
        "a refused activation leaves no record: {:?}",
        listed.sessions
    );
}

/// NET-121, NET-144, design §7.1: a declared TCP host port that a program
/// outside Minimal already holds at the box's published address fails the
/// finalize. The refusal names the port and the host as its holder, and
/// the box leaves no record.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn activation_refused_when_declared_port_is_held_by_a_host_program() {
    let capture = crate::test_harness::captured_log();
    let handed = std::net::Ipv4Addr::new(127, 0, 64, 77);
    let switch = std::net::Ipv4Addr::new(100, 64, 128, 77);
    // Another process holds the declared host port at the handed address.
    let _holder =
        std::net::TcpListener::bind((handed, declared_port())).expect("hold the declared port");
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let id = create_handed_own_ip_session(&mut client, "taken", switch, handed).await;
    assert_refused_and_cleaned_up(
        &mut client,
        id,
        minimald_rpc::PortInUseRefusal {
            port: declared_port(),
            box_port: 80,
            holder: minimald_rpc::PortHolder::Host,
        },
    )
    .await;
    let logged = capture.contents();
    assert!(
        logged.lines().any(|line| line.contains("host-port-in-use")
            && line.contains(&format!("session={id}"))
            && line.contains(&format!("port={}", declared_port()))
            && line.contains("127.0.64.77")
            && line.contains("holder=host")),
        "one warn line names the session, port, address and holder, got: {logged}"
    );
}

/// NET-144: at the shared `127.0.0.1` fallback a declared port that another
/// box already holds fails the second box's activation, naming the box that
/// holds it, where before the second box yielded the port. The first box
/// keeps the port, and the second leaves no record.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn activation_refused_when_declared_port_is_held_by_another_box_at_the_fallback() {
    let capture = crate::test_harness::captured_log();
    let server = TestServer::new().await;
    let manager = server.state.sessions_manager().await;
    // No reserved range on this host: every box publishes at `127.0.0.1`.
    manager.land_range_verdict(crate::net::dns::RangeVerdict::Absent);
    let mut client = server.connect().await;
    let first = create_handed_own_ip_session(
        &mut client,
        "first",
        std::net::Ipv4Addr::new(100, 64, 128, 78),
        std::net::Ipv4Addr::new(127, 0, 64, 78),
    )
    .await;
    finalize_session(&mut client, first).await;
    let second = create_handed_own_ip_session(
        &mut client,
        "second",
        std::net::Ipv4Addr::new(100, 64, 128, 79),
        std::net::Ipv4Addr::new(127, 0, 64, 79),
    )
    .await;
    let registry = manager.hostnames();
    assert_eq!(
        registry
            .read()
            .expect("registry lock")
            .published_own_address(first),
        Some(std::net::Ipv4Addr::LOCALHOST),
        "the first box publishes at the fallback"
    );
    assert_refused_and_cleaned_up(
        &mut client,
        second,
        minimald_rpc::PortInUseRefusal {
            port: declared_port(),
            box_port: 80,
            holder: minimald_rpc::PortHolder::Box("first".to_string()),
        },
    )
    .await;
    assert_eq!(
        registry
            .read()
            .expect("registry lock")
            .own_port_holder(std::net::Ipv4Addr::LOCALHOST, declared_port())
            .map(|(holder, _)| holder),
        Some(first),
        "the first box keeps the port"
    );
    let logged = capture.contents();
    assert!(
        logged.lines().any(|line| line.contains("host-port-in-use")
            && line.contains(&format!("session={second}"))
            && line.contains("holder=box:first")),
        "the warn line names the holding box, got: {logged}"
    );
}

/// NET-144, under a pending range verdict: a second box at the `127.0.0.1`
/// interim yields the declared port the first box holds there, because a
/// present landing moves both to their own addresses. When the verdict
/// lands absent, the second box stays at the fallback with the port unbound,
/// and the daemon log reports it with the port and the holder. The first
/// box, which holds the port, is not reported.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn activation_refused_when_declared_port_is_held_reported_when_the_verdict_lands_absent() {
    let capture = crate::test_harness::captured_log();
    let server = TestServer::new().await;
    let manager = server.state.sessions_manager().await;
    manager.hold_range_verdict_pending();
    // The bound is shrunk so both finalizes publish at the interim.
    manager.reset_hand_verdict_deadline(100);
    let mut client = server.connect().await;
    let first = finalize_handed_own_ip_session(
        &mut client,
        "first",
        std::net::Ipv4Addr::new(100, 64, 128, 81),
        std::net::Ipv4Addr::new(127, 0, 64, 81),
    )
    .await;
    let second = create_handed_own_ip_session(
        &mut client,
        "second",
        std::net::Ipv4Addr::new(100, 64, 128, 82),
        std::net::Ipv4Addr::new(127, 0, 64, 82),
    )
    .await;
    let finalized = finalize_session(&mut client, second).await;
    assert!(
        finalized
            .shared_port_collisions
            .iter()
            .any(|collision| collision.port == declared_port()
                && collision.held_by.starts_with("first")),
        "under the pending verdict the second box yields the port: {finalized:?}"
    );
    let registry = manager.hostnames();
    for id in [first, second] {
        assert_eq!(
            registry
                .read()
                .expect("registry lock")
                .published_own_address(id),
            Some(std::net::Ipv4Addr::LOCALHOST),
            "both boxes stand at the interim while the verdict walks"
        );
    }
    let reported = |logged: &str, id: SessionId| {
        logged.lines().any(|line| {
            line.contains("host-port-in-use")
                && line.contains("127.0.0.1 fallback")
                && line.contains(&format!("session={id}"))
        })
    };
    assert!(
        !reported(&capture.contents(), second),
        "nothing is reported while the verdict is pending"
    );

    manager.land_range_verdict(crate::net::dns::RangeVerdict::Absent);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !reported(&capture.contents(), second) && std::time::Instant::now() < deadline {
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    let logged = capture.contents();
    assert!(
        logged.lines().any(|line| line.contains("host-port-in-use")
            && line.contains("127.0.0.1 fallback")
            && line.contains(&format!("session={second}"))
            && line.contains(&format!("port={}", declared_port()))
            && line.contains("address=127.0.0.1")
            && line.contains("holder=box:first")),
        "the absent landing reports the held port, the address and the holder, got: {logged}"
    );
    assert!(
        !reported(&logged, first),
        "the box that holds the port is not reported: {logged}"
    );
}

/// Waits until a registration is parked on the range verdict, so the
/// landing a test makes next provably answers a waiter rather than a
/// registration that has not yet begun to wait (NET-123 §7.1).
#[cfg(target_os = "linux")]
async fn await_verdict_waiter(manager: &crate::box_manager::BoxManagerHandle) {
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
    let (network, prefix) = boxes::core::loopback::RESERVED_LOCAL_RANGE;
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
        boxes::core::loopback::POOL_FIRST,
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
///
/// The boxes are created after the range lands the way a microVM daemon
/// lands it once `min finalize-install` ran: the daemon-start walk found the
/// range absent, and the first create's session-start walk finds it present.
/// A stand-in walk stands in for the host forwarder's binds.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn each_box_gets_own_loopback_address() {
    let alpha_handed = std::net::Ipv4Addr::new(127, 0, 64, 9);
    let beta_handed = std::net::Ipv4Addr::new(127, 0, 64, 10);
    let server = TestServer::new().await;
    let manager = server.state.sessions_manager().await;
    manager.install_range_walk_standin(|| {
        let hosts = ::switch::loopback::range_hosts().count();
        crate::net::loopback::RangeProbe {
            bound: hosts,
            probed: hosts,
            first_failure: None,
        }
    });
    manager.land_range_verdict(crate::net::dns::RangeVerdict::Absent);
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
    // Each box stands at its own hand, not the interim: the publish is the
    // address the attach path binds the box's forwards at.
    for (name, id, handed, address) in [
        ("alpha", alpha, alpha_handed, alpha_address),
        ("beta", beta, beta_handed, beta_address),
    ] {
        assert_eq!(
            routes.published_own_address(id),
            Some(handed),
            "{name}'s forwards bind at the address it was handed, after the range landed"
        );
        assert_eq!(address, handed, "{name}'s name answers at its own address");
    }
    for (name, address) in [("alpha", alpha_address), ("beta", beta_address)] {
        let route = routes
            .resolve(&format!("{name}.min.internal"))
            .unwrap_or_else(|| panic!("{name}'s name routes"));
        assert_eq!(
            route.upstream(declared_port()),
            Some(std::net::SocketAddr::new(
                std::net::IpAddr::V4(address),
                declared_port()
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
    let foreign = boxes::core::loopback::POOL_LAST;
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
        .resolve(&format!("web.min.internal:{}", declared_port()))
        .expect("the name routes with no client attached");
    assert_eq!(
        route.upstream(declared_port()),
        Some(std::net::SocketAddr::new(
            std::net::IpAddr::V4(address),
            declared_port()
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
        .call::<DestroySession>(&DestroySessionRequest {
            id,
            only_if_unfinalized: false,
        })
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

/// Drives Create → ConfigureLoadout for an own-address box with a declared
/// ingress, a handed address, and `hook` in its composition, leaving the
/// finalize to the caller — the shape `min session activate --network
/// own_ip --ingress …` takes for a project or loadout with an `on_activate`
/// hook (#2070).
#[cfg(target_os = "linux")]
async fn create_handed_own_ip_session_with_hook(
    client: &mut TestClient,
    name: &str,
    switch: std::net::Ipv4Addr,
    loopback: std::net::Ipv4Addr,
    hook: boxes::wire::primitives::WireLifecycleHook,
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
                contribution: contribution_with_hook(hook),
            })
            .await
            .unwrap(),
    );
    id
}

/// #2070: an own-address box that declares ingress *and* carries an
/// activate hook activates. Finalize launches the box to run the hook, and
/// that launch is the box's first attach — which binds the declared
/// forwards at the box's published address and fails with "no published
/// address handed" when there is none (NET-010, NET-121). So finalize
/// publishes the address and registers the name before the hook launch:
/// the launch finds the hand already published, the hook runs, the session
/// comes back `Active`, and its name answers at the hand.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_activate_hook_launch_finds_the_box_s_address_already_published() {
    let handed = std::net::Ipv4Addr::new(127, 0, 64, 21);
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("activated");
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let id = create_handed_own_ip_session_with_hook(
        &mut client,
        "hooked-web",
        std::net::Ipv4Addr::new(100, 64, 128, 21),
        handed,
        boxes::wire::primitives::WireLifecycleHook {
            on_activate: Some(inline(marker_body(&marker))),
            ..Default::default()
        },
    )
    .await;
    assert!(
        super::launch_publish_seam::observed(id).is_empty(),
        "nothing launches the box before its finalize"
    );

    finalize_session(&mut client, id).await;

    assert!(marker.exists(), "on_activate did not run");
    assert_eq!(
        super::launch_publish_seam::observed(id).first().copied(),
        Some(Some(handed)),
        "the activate hook's launch — the box's first attach — must find the \
         hand already published, or the attach of a box that declared \
         ingress fails with \"no published address handed\""
    );
    assert_eq!(
        record_status(&mut client, id).await,
        Some(boxes::BoxState::Active),
        "a box with ingress and an activate hook activates"
    );
    let (owner, address) = zone_answer_for(&server, "hooked-web.min.internal")
        .await
        .expect("the name is held from finalize");
    assert_eq!(owner, "hooked-web");
    assert_eq!(address, handed, "the name answers at the hand, exactly");
}

/// A box whose record carries host-handed addresses (T66) has a host-side
/// row keyed on that address. When its host loop ends — the shell exited —
/// the row ends with it (NET-138), and only the box's creator resumes it. No
/// VM host daemon answers here that the row stands — as for a client that
/// does not resume, or a resume that failed — so re-minting a fresh host
/// would re-attach "rowless": the host gate silently drops the box's frames
/// from an unregistered source. The attach must refuse with the typed
/// `BoxHostRowEnded` refusal (surfaced to the client on the channel) instead
/// of re-minting, and no second host may launch — the hands are the
/// host-side creator's, and re-registering a row is exactly what a daemon
/// must never do. The standing-row relaunch is
/// `ensure_host_relaunches_a_registered_box_while_its_host_row_stands`.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_box_holding_a_host_row_refuses_remint_after_its_host_loop_ends() {
    let handed = std::net::Ipv4Addr::new(127, 0, 64, 23);
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let id = finalize_handed_own_ip_session(
        &mut client,
        "web",
        std::net::Ipv4Addr::new(100, 64, 128, 23),
        handed,
    )
    .await;

    // The first attach mints the host and arms the mock shell.
    let mut channel = client.open_shell(id).await;
    await_echo(&mut channel).await;
    assert_eq!(
        super::launch_publish_seam::observed(id).len(),
        1,
        "the first attach is the box's one and only launch so far"
    );

    // Exit the shell: the host loop ends, withdrawing the host-side row.
    keep_exit(&mut channel).await;

    // Re-attaching must refuse rather than re-mint a rowless host. The
    // refusal rides the channel as an attach error, then the channel closes.
    let mut second = client.open_shell(id).await;
    let refusal = collect_to_close(&mut second).await;
    assert!(
        refusal.contains("Error attaching to session:"),
        "the refusal must be surfaced as an attach error; got: {refusal:?}"
    );
    assert!(
        refusal.contains("the VM host daemon released this session's network addresses"),
        "the refusal must name the host-row cause; got: {refusal:?}"
    );
    assert!(
        refusal.contains("min session activate"),
        "the refusal must name the step that registers a box again; got: {refusal:?}"
    );
    assert!(
        refusal.contains("min session destroy <session>"),
        "the refusal must name the session argument the destroy step takes; got: {refusal:?}"
    );
    assert!(
        refusal.contains("run the same command again"),
        "the refusal must name the re-run that resumes the row; got: {refusal:?}"
    );
    assert_eq!(
        super::launch_publish_seam::observed(id).len(),
        1,
        "no second host may be minted for a box whose host row was withdrawn"
    );
}

/// Asserts that an attach to `id` is refused with the typed
/// `BoxHostRowEnded` refusal, surfaced on the channel before it closes.
async fn assert_attach_refused_rowless(client: &mut TestClient, id: SessionId) {
    let mut channel = client.open_shell(id).await;
    let refusal = collect_to_close(&mut channel).await;
    assert!(
        refusal.contains("Error attaching to session:")
            && refusal.contains("the VM host daemon released this session's network addresses"),
        "the attach must be refused for the ended host-side row; got: {refusal:?}"
    );
}

/// A registered box's shell exits with the files kept, and its `on_detach`
/// hook still runs (spec 11): the actor launches a host over the dead one for
/// it. That hook host is alive in the slot, but it is not the launch that
/// bound the box's host-side row (NET-138), so the next attach refuses rather
/// than keeping a rowless host for the terminal.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_detach_hook_host_of_a_registered_box_is_refused_to_the_next_attach() {
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("detached");
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let id = create_handed_own_ip_session_with_hook(
        &mut client,
        "hooked-detach",
        std::net::Ipv4Addr::new(100, 64, 128, 24),
        std::net::Ipv4Addr::new(127, 0, 64, 24),
        boxes::wire::primitives::WireLifecycleHook {
            on_detach: Some(inline(marker_body(&marker))),
            ..Default::default()
        },
    )
    .await;
    finalize_session(&mut client, id).await;

    let mut channel = client.open_shell(id).await;
    await_echo(&mut channel).await;
    keep_exit(&mut channel).await;
    assert!(
        await_marker(&marker).await,
        "the detach hook runs even though the box's row has ended"
    );
    soon(|| super::launch_publish_seam::observed(id).len() == 2).await;

    assert_attach_refused_rowless(&mut client, id).await;
    assert_eq!(
        super::launch_publish_seam::observed(id).len(),
        2,
        "the refused attach launches nothing"
    );
}

/// The exec path's half: a registered box whose host is gone is not
/// relaunched by `ensure_host` — the relaunch would run rowless.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ensure_host_refuses_a_registered_box_whose_host_ended() {
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let id = finalize_handed_own_ip_session(
        &mut client,
        "exec-rowless",
        std::net::Ipv4Addr::new(100, 64, 128, 25),
        std::net::Ipv4Addr::new(127, 0, 64, 25),
    )
    .await;
    let manager = server.state.sessions_manager().await;
    let handle = manager
        .get_session(crate::box_manager::BoxKeyPredicate::Id(id))
        .await
        .unwrap()
        .expect("the box resolves");
    let host = handle
        .ensure_host("tester".to_string())
        .await
        .expect("the box's first launch binds its row");
    let again = handle
        .ensure_host("tester".to_string())
        .await
        .expect("the live binding host is reused");
    assert!(again.same_host(&host), "the binding host is the one reused");

    host.kill(false).await.expect("the box's host ends");
    soon(|| !host.is_alive()).await;
    match handle.ensure_host("tester".to_string()).await {
        Err(crate::box_actor::AttachError::BoxHostRowEnded) => {}
        Err(other) => panic!("refused for another reason: {other}"),
        Ok(_) => panic!("a registered box was relaunched rowless"),
    }
}

/// NET-138: the VM host daemon detaches a box's row at the end of its
/// attachment and withdraws it only after a grace, and the box's creator may
/// resume a withdrawn one, so a registered box whose host ended is
/// relaunched while the host says its row stands — the host's own table,
/// read over the report door — and refused once the host says it does not.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ensure_host_relaunches_a_registered_box_while_its_host_row_stands() {
    let switch_address = std::net::Ipv4Addr::new(100, 64, 128, 28);
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let (id, sock, door_sock, (door, mut reads, replies)) = finalize_door_handed_own_ip_session(
        &server,
        &mut client,
        "exec-resumed",
        switch_address,
        std::net::Ipv4Addr::new(127, 0, 64, 28),
    )
    .await;
    let manager = server.state.sessions_manager().await;
    let handle = manager
        .get_session(crate::box_manager::BoxKeyPredicate::Id(id))
        .await
        .unwrap()
        .expect("the box resolves");
    let host = handle
        .ensure_host("tester".to_string())
        .await
        .expect("the box's first launch binds its row");
    assert_eq!(
        sock,
        handle
            .net_switch()
            .await
            .unwrap()
            .lock()
            .await
            .control_socket(),
        "the door was seeded at the box's switch"
    );
    crate::net::listeners::seed_vm_report_door_for_tests(&sock, &door_sock);

    host.kill(false).await.expect("the box's host ends");
    soon(|| !host.is_alive()).await;
    // Once before the relaunch, and again once its host is up.
    for _ in 0..2 {
        replies
            .send(minimald_rpc::BoxControlReply::RowStanding {
                switch_address,
                row_standing: true,
            })
            .expect("the report door stand-in lives");
    }
    let relaunched = handle
        .ensure_host("tester".to_string())
        .await
        .expect("a box whose host row stands is relaunched");
    assert!(
        !relaunched.same_host(&host),
        "a fresh host, not the ended one"
    );
    let read = tokio::time::timeout(Duration::from_secs(5), reads.recv())
        .await
        .expect("the relaunch asked the VM host daemon first")
        .expect("the report door stand-in lives");
    assert_eq!(
        read,
        minimald_rpc::BoxControlRequest::RowStanding(minimald_rpc::RowStandingRequest {
            switch_address,
            box_id: Some(HANDED_BOX_ID),
        }),
        "the read names the row's own key and the box's id, nothing else"
    );

    relaunched
        .kill(false)
        .await
        .expect("the relaunched host ends");
    soon(|| !relaunched.is_alive()).await;
    replies
        .send(minimald_rpc::BoxControlReply::RowStanding {
            switch_address,
            row_standing: false,
        })
        .expect("the report door stand-in lives");
    match handle.ensure_host("tester".to_string()).await {
        Err(crate::box_actor::AttachError::BoxHostRowEnded) => {}
        Err(other) => panic!("refused for another reason: {other}"),
        Ok(_) => panic!("a box the host holds no row for was relaunched rowless"),
    }
    crate::net::listeners::clear_vm_report_door_for_tests(&sock);
    door.abort();
}

/// NET-138: the row-standing read is not a reservation. A row the VM host
/// daemon withdraws at its grace's end between the read that confirmed it
/// and the relaunch's host coming up is read again before the slot is
/// marked as holding it: the relaunch is refused and its host ended, and
/// the slot is not left marked, so the next exec asks again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ensure_host_refuses_a_relaunch_whose_row_ended_while_it_launched() {
    let switch_address = std::net::Ipv4Addr::new(100, 64, 128, 31);
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let (id, sock, door_sock, (door, mut reads, replies)) = finalize_door_handed_own_ip_session(
        &server,
        &mut client,
        "exec-row-expired",
        switch_address,
        std::net::Ipv4Addr::new(127, 0, 64, 31),
    )
    .await;
    let manager = server.state.sessions_manager().await;
    let handle = manager
        .get_session(crate::box_manager::BoxKeyPredicate::Id(id))
        .await
        .unwrap()
        .expect("the box resolves");
    let host = handle
        .ensure_host("tester".to_string())
        .await
        .expect("the box's first launch binds its row");
    assert_eq!(
        sock,
        handle
            .net_switch()
            .await
            .unwrap()
            .lock()
            .await
            .control_socket(),
        "the door was seeded at the box's switch"
    );
    crate::net::listeners::seed_vm_report_door_for_tests(&sock, &door_sock);

    host.kill(false).await.expect("the box's host ends");
    soon(|| !host.is_alive()).await;
    // Standing when the relaunch asks first; withdrawn by the time its
    // host is up.
    for row_standing in [true, false] {
        replies
            .send(minimald_rpc::BoxControlReply::RowStanding {
                switch_address,
                row_standing,
            })
            .expect("the report door stand-in lives");
    }
    match handle.ensure_host("tester".to_string()).await {
        Err(crate::box_actor::AttachError::BoxHostRowEnded) => {}
        Err(other) => panic!("refused for another reason: {other}"),
        Ok(_) => panic!("a relaunch whose row ended while it launched was kept rowless"),
    }
    for _ in 0..2 {
        tokio::time::timeout(Duration::from_secs(5), reads.recv())
            .await
            .expect("the relaunch read the row before and after its launch")
            .expect("the report door stand-in lives");
    }

    // The slot was not marked as holding a row: the next exec asks again.
    replies
        .send(minimald_rpc::BoxControlReply::RowStanding {
            switch_address,
            row_standing: false,
        })
        .expect("the report door stand-in lives");
    match handle.ensure_host("tester".to_string()).await {
        Err(crate::box_actor::AttachError::BoxHostRowEnded) => {}
        Err(other) => panic!("refused for another reason: {other}"),
        Ok(_) => panic!("the refused relaunch's host was reused as holding a row"),
    }
    tokio::time::timeout(Duration::from_secs(5), reads.recv())
        .await
        .expect("the next exec asked the VM host daemon again")
        .expect("the report door stand-in lives");
    crate::net::listeners::clear_vm_report_door_for_tests(&sock);
    door.abort();
}

/// NET-138: a registered box whose record names no box id cannot be told
/// from another box the host handed its address, so its ended host is not
/// relaunched even while the host would say a row stands at the address:
/// the read is never asked, and the box is refused as rowless.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ensure_host_refuses_a_registered_box_whose_record_names_no_box_id() {
    let switch_address = std::net::Ipv4Addr::new(100, 64, 128, 30);
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let mut request = own_ip_handed_session_req(
        "exec-unnamed-id",
        switch_address,
        std::net::Ipv4Addr::new(127, 0, 64, 30),
    );
    request.config.box_id = None;
    use minimald_rpc::{ConfigureLoadout, ConfigureLoadoutRequest, CreateSession};
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
    finalize_session(&mut client, id).await;
    let manager = server.state.sessions_manager().await;
    let handle = manager
        .get_session(crate::box_manager::BoxKeyPredicate::Id(id))
        .await
        .unwrap()
        .expect("the box resolves");
    let host = handle
        .ensure_host("tester".to_string())
        .await
        .expect("the box's first launch binds its row");
    let sock = handle
        .net_switch()
        .await
        .unwrap()
        .lock()
        .await
        .control_socket();
    let door_sock = sock.with_file_name("row-door.sock");
    let (door, mut reads, replies) = fake_report_door(&door_sock).await;
    crate::net::listeners::seed_vm_report_door_for_tests(&sock, &door_sock);

    host.kill(false).await.expect("the box's host ends");
    soon(|| !host.is_alive()).await;
    replies
        .send(minimald_rpc::BoxControlReply::RowStanding {
            switch_address,
            row_standing: true,
        })
        .expect("the report door stand-in lives");
    match handle.ensure_host("tester".to_string()).await {
        Err(crate::box_actor::AttachError::BoxHostRowEnded) => {}
        Err(other) => panic!("refused for another reason: {other}"),
        Ok(_) => panic!("a box with no id was relaunched on an address-only read"),
    }
    assert!(
        reads.try_recv().is_err(),
        "no row read was asked without a box id"
    );
    crate::net::listeners::clear_vm_report_door_for_tests(&sock);
    door.abort();
}

/// NET-138: a relaunch the VM host daemon confirmed a standing row for
/// rejoins that row, so the slot marks its host as holding it. A later exec
/// reuses that live host without asking the host again, and so still runs
/// when the report door no longer answers.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ensure_host_reuses_a_relaunched_host_without_the_report_door() {
    let switch_address = std::net::Ipv4Addr::new(100, 64, 128, 29);
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let (id, sock, door_sock, (door, _reads, replies)) = finalize_door_handed_own_ip_session(
        &server,
        &mut client,
        "exec-rejoined",
        switch_address,
        std::net::Ipv4Addr::new(127, 0, 64, 29),
    )
    .await;
    let manager = server.state.sessions_manager().await;
    let handle = manager
        .get_session(crate::box_manager::BoxKeyPredicate::Id(id))
        .await
        .unwrap()
        .expect("the box resolves");
    let host = handle
        .ensure_host("tester".to_string())
        .await
        .expect("the box's first launch binds its row");
    assert_eq!(
        sock,
        handle
            .net_switch()
            .await
            .unwrap()
            .lock()
            .await
            .control_socket(),
        "the door was seeded at the box's switch"
    );
    crate::net::listeners::seed_vm_report_door_for_tests(&sock, &door_sock);

    host.kill(false).await.expect("the box's host ends");
    soon(|| !host.is_alive()).await;
    for _ in 0..2 {
        replies
            .send(minimald_rpc::BoxControlReply::RowStanding {
                switch_address,
                row_standing: true,
            })
            .expect("the report door stand-in lives");
    }
    let relaunched = handle
        .ensure_host("tester".to_string())
        .await
        .expect("a box whose host row stands is relaunched");

    // The report door goes away: a read now answers nothing, which reads
    // as no row. The live relaunched host holds its row all the same.
    crate::net::listeners::clear_vm_report_door_for_tests(&sock);
    door.abort();
    let again = handle
        .ensure_host("tester".to_string())
        .await
        .expect("the live relaunched host is reused without a read");
    assert!(
        again.same_host(&relaunched),
        "the relaunched host is the one reused"
    );
}

/// A daemon restart ends every PTask, and with them the host-side rows. The
/// record remembers that a launch bound this box's row, so the restarted
/// actor — no host in its slot — refuses the attach instead of minting.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_restarted_registered_box_whose_row_was_bound_refuses_the_attach() {
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let id = finalize_handed_own_ip_session(
        &mut client,
        "restart-rowless",
        std::net::Ipv4Addr::new(100, 64, 128, 26),
        std::net::Ipv4Addr::new(127, 0, 64, 26),
    )
    .await;
    let manager = server.state.sessions_manager().await;
    let handle = manager
        .get_session(crate::box_manager::BoxKeyPredicate::Id(id))
        .await
        .unwrap()
        .expect("the box resolves");
    handle
        .ensure_host("tester".to_string())
        .await
        .expect("the box's first launch binds its row");

    // Stop the actor and evict it, so the next lookup spawns a fresh one
    // from the on-disk record — a daemon restart.
    handle.stop().await;
    manager.evict(id).await;
    let handle = manager
        .get_session(crate::box_manager::BoxKeyPredicate::Id(id))
        .await
        .unwrap()
        .expect("the box resolves after the restart");
    let record = handle.record().await.expect("the record reads back");
    assert_eq!(record.status, boxes::BoxState::Active);
    assert!(record.host_row_bound, "the binding survives the restart");

    assert_attach_refused_rowless(&mut client, id).await;
    match handle.ensure_host("tester".to_string()).await {
        Err(crate::box_actor::AttachError::BoxHostRowEnded) => {}
        Err(other) => panic!("refused for another reason: {other}"),
        Ok(_) => panic!("a restarted registered box was launched rowless"),
    }
}

/// A registered box that activated without launching (no activate hook) has
/// no row bound yet: its first attach mints normally, and that launch binds
/// the row, recorded on the record a restarted actor reads.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_registered_box_never_launched_mints_and_binds_its_row() {
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let id = finalize_handed_own_ip_session(
        &mut client,
        "first-launch",
        std::net::Ipv4Addr::new(100, 64, 128, 27),
        std::net::Ipv4Addr::new(127, 0, 64, 27),
    )
    .await;
    let manager = server.state.sessions_manager().await;
    let handle = manager
        .get_session(crate::box_manager::BoxKeyPredicate::Id(id))
        .await
        .unwrap()
        .expect("the box resolves");
    let record = handle.record().await.expect("the record reads back");
    assert!(record.box_addresses.is_some(), "the box is registered");
    assert!(!record.host_row_bound, "no launch has bound the row yet");

    let mut channel = client.open_shell(id).await;
    await_echo(&mut channel).await;
    assert!(
        handle
            .record()
            .await
            .expect("the record reads back")
            .host_row_bound,
        "the first launch binds the row"
    );

    // Persisted, not only held by this actor: a fresh actor reads it back.
    drop(channel);
    handle.stop().await;
    manager.evict(id).await;
    let handle = manager
        .get_session(crate::box_manager::BoxKeyPredicate::Id(id))
        .await
        .unwrap()
        .expect("the box resolves after the restart");
    assert!(
        handle
            .record()
            .await
            .expect("the record reads back")
            .host_row_bound,
        "the binding is on the on-disk record"
    );
}

/// #2070's error path: the publish now precedes the activate hooks, so a
/// hook that fails leaves it standing on the unpromoted record — and the
/// destroy the client's activate cleanup sends withdraws it with the name,
/// so nothing the failed activation published outlives it (NET-010,
/// NET-012).
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_activate_hook_s_publish_is_withdrawn_by_the_destroy() {
    use minimald_rpc::{Errorable, FinalizeSession, FinalizeSessionRequest};

    let handed = std::net::Ipv4Addr::new(127, 0, 64, 22);
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let id = create_handed_own_ip_session_with_hook(
        &mut client,
        "hooked-fails",
        std::net::Ipv4Addr::new(100, 64, 128, 22),
        handed,
        boxes::wire::primitives::WireLifecycleHook {
            on_activate: Some(inline("exit 3".to_string())),
            ..Default::default()
        },
    )
    .await;
    match client
        .call::<FinalizeSession>(&FinalizeSessionRequest {
            session_id: id,
            report_shared_port_collisions: false,
        })
        .await
    {
        Errorable::Err { .. } => {}
        Errorable::Ok(_) => panic!("finalize should have failed on the activate hook"),
    }
    assert_ne!(
        record_status(&mut client, id).await,
        Some(boxes::BoxState::Active),
        "a box whose activate hook failed is not promoted"
    );

    destroy_session(&mut client, id).await;

    assert_eq!(
        zone_answer_for(&server, "hooked-fails.min.internal").await,
        None,
        "the failed activation's name is gone after the destroy"
    );
    let registry = server.state.sessions_manager().await.hostnames();
    let routes = registry.read().expect("registry lock");
    assert_eq!(routes.resolve("hooked-fails.min.internal"), None);
    assert_eq!(
        routes.published_own_address(id),
        None,
        "the failed activation's publish is withdrawn by the destroy"
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
        .get_session(crate::box_manager::BoxKeyPredicate::Id(id))
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
    // The host-side proxy keeps the same gate: the route is held, but nothing
    // is forwarded to the node's own listener for the stopped box.
    assert_eq!(
        registry
            .read()
            .expect("registry lock")
            .resolve("sharedbox.min.internal"),
        None,
        "the proxy must not forward a stopped shared-address box to the node"
    );
}

/// NET-128's resume half: a shared-address box stopped through the actor
/// resumes at its address — the stop is a state, not an end. The actor's
/// Stop arm marks the name stopped (NODATA at the shared address), and the
/// resume path — a fresh actor re-registering the name, then a host start
/// clearing the marker — brings the name back to answering A at the same
/// address. The re-registration is not refused as "name taken": the
/// registry's register overwrites the route, so the resumed box's name is
/// held again rather than dropped.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stopped_shared_address_box_resumes_at_its_address_through_actor() {
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let manager = server.state.sessions_manager().await;
    manager.land_range_verdict(crate::net::dns::RangeVerdict::Present);
    let shared = manager
        .hostnames()
        .read()
        .expect("registry lock")
        .node_address();
    let id = finalize_handed_own_ip_session(
        &mut client,
        "resumebox",
        std::net::Ipv4Addr::new(100, 64, 128, 9),
        shared,
    )
    .await;

    // The name answers while the box runs.
    let (_, address) = zone_answer_for(&server, "resumebox.min.internal")
        .await
        .expect("the name answers while the box runs");
    assert_eq!(
        address, shared,
        "the box's name answers at the shared address while it runs"
    );

    // Stop the box through the actor — the path the issue reports. The Stop
    // arm must not panic; it marks the name stopped and returns.
    let handle = manager
        .get_session(crate::box_manager::BoxKeyPredicate::Id(id))
        .await
        .unwrap()
        .expect("the box resolves while it runs");
    handle.stop().await;

    let registry = server.state.sessions_manager().await.hostnames();
    assert_eq!(
        registry
            .read()
            .expect("registry lock")
            .zone_entry("resumebox.min.internal", &[]),
        crate::net::dns::ZoneEntry::Held {
            owner: "resumebox".to_string(),
            address: None,
        },
        "a stopped shared-address box answers NODATA, not NXDOMAIN"
    );
    assert_eq!(
        registry
            .read()
            .expect("registry lock")
            .resolve("resumebox.min.internal"),
        None,
        "the proxy must not forward a stopped shared-address box to the node"
    );

    // Resume: evict the dead actor and re-resolve, so a fresh actor comes up
    // from the record and re-registers the name — the registration is not
    // refused as "name taken". Then launch a host, whose start clears the
    // stopped marker, and the name answers again at the same address.
    manager.evict(id).await;
    let handle = manager
        .get_session(crate::box_manager::BoxKeyPredicate::Id(id))
        .await
        .unwrap()
        .expect("the box resolves after eviction");
    handle
        .ensure_host("tester".to_string())
        .await
        .expect("an Active session should be able to launch a host");

    // The host's `mainloop` marks the name running on its own spawned task,
    // so poll the zone until the marker is cleared rather than racing it.
    let (owner, resumed) = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let registry = server.state.sessions_manager().await.hostnames();
            if let crate::net::dns::ZoneEntry::Held {
                owner,
                address: Some(address),
            } = registry
                .read()
                .expect("registry lock")
                .zone_entry("resumebox.min.internal", &[])
            {
                return (owner, address);
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the name answers again after the host starts");
    assert_eq!(
        owner, "resumebox",
        "the session owns its box name across the resume"
    );
    assert_eq!(
        resumed, shared,
        "the resumed box answers at the address it held before the stop"
    );
    // The host-side proxy follows the same marker: once the host start has
    // cleared it, the resumed box's name routes again.
    assert!(
        server
            .state
            .sessions_manager()
            .await
            .hostnames()
            .read()
            .expect("registry lock")
            .resolve("resumebox.min.internal")
            .is_some(),
        "the proxy routes to the resumed box again"
    );
}

/// NET-128 fail-closed: a Stop whose session record cannot be read still
/// marks the box's name stopped. The marker is keyed by the session id the
/// actor holds without the record, so a shared-address name never keeps
/// answering (or routing) for a box that is no longer there.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stop_with_unreadable_record_still_marks_name_stopped() {
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let manager = server.state.sessions_manager().await;
    manager.land_range_verdict(crate::net::dns::RangeVerdict::Present);
    let shared = manager
        .hostnames()
        .read()
        .expect("registry lock")
        .node_address();
    let id = finalize_handed_own_ip_session(
        &mut client,
        "unreadbox",
        std::net::Ipv4Addr::new(100, 64, 128, 9),
        shared,
    )
    .await;
    let handle = manager
        .get_session(crate::box_manager::BoxKeyPredicate::Id(id))
        .await
        .unwrap()
        .expect("the box resolves while it runs");

    // Make the record unreadable: the store reads `record.json` from disk on
    // every get, so garbage there turns the Stop arm's read into an `Err`.
    let sessions_dir = server
        .state
        .minimal_state_dir()
        .await
        .as_utf8_path()
        .as_std_path()
        .join("sessions");
    let mut corrupted = 0;
    for entry in std::fs::read_dir(&sessions_dir).expect("the sessions dir exists") {
        let record = entry.unwrap().path().join("record.json");
        if record.is_file() {
            std::fs::write(&record, b"not json").expect("overwrite the record");
            corrupted += 1;
        }
    }
    assert_eq!(corrupted, 1, "exactly the one box's record is corrupted");

    // The Stop arm must neither panic nor leave the name answering.
    handle.stop().await;

    let registry = server.state.sessions_manager().await.hostnames();
    assert_eq!(
        registry
            .read()
            .expect("registry lock")
            .zone_entry("unreadbox.min.internal", &[]),
        crate::net::dns::ZoneEntry::Held {
            owner: "unreadbox".to_string(),
            address: None,
        },
        "an unreadable record still leaves the stopped box answering NODATA"
    );
    assert_eq!(
        registry
            .read()
            .expect("registry lock")
            .resolve("unreadbox.min.internal"),
        None,
        "the proxy must not forward a stopped box whose record is unreadable"
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

/// The session that owns `name`'s route in `server`'s registry, if any.
#[cfg(target_os = "linux")]
async fn route_owner(server: &TestServer, name: &str) -> Option<String> {
    server
        .state
        .sessions_manager()
        .await
        .hostnames()
        .read()
        .expect("registry lock")
        .resolve(name)
        .map(|route| route.session().to_owned())
}

/// Stops every session the way a daemon going down does (records kept),
/// then boots a second server on the same state root. The harness never
/// runs `Server::run`, so nothing on the new server is resumed yet.
#[cfg(target_os = "linux")]
async fn restart(server: TestServer, client: TestClient) -> TestServer {
    server
        .state
        .sessions_manager()
        .await
        .shutdown(true)
        .await
        .expect("a forced shutdown has nothing left to refuse it");
    drop(client);
    TestServer::new_in(server.into_state_dir()).await
}

/// A restarted daemon does not route the names of the boxes it found
/// `running`: its start set each one `stopped` (BOX-154), and the resume at
/// start brings none back. An attach resumes a box (BOX-025), and its name
/// routes again from then on. The other box stays stopped and unrouted.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_restarted_daemon_routes_a_restored_name_once_an_attach_resumes_it() {
    use boxes::core::record::{RecordState, StopEnding};

    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let alpha = create_configured_session(&mut client, "restored-alpha", "/uwu").await;
    let beta = create_configured_session(&mut client, "restored-beta", "/uwu").await;
    assert_eq!(
        route_owner(&server, "restored-alpha.min.internal").await,
        Some("restored-alpha".to_owned()),
        "the name routes at the first daemon"
    );

    let server = restart(server, client).await;
    let mut client = server.connect().await;
    let manager = server.state.sessions_manager().await;
    assert_eq!(
        manager.resume_active_sessions().await.unwrap(),
        0,
        "the restart brings no box back"
    );
    assert_eq!(manager.running_count().await, 0);
    for id in [alpha, beta] {
        assert_eq!(
            read_record(&server, id).await.state().unwrap(),
            RecordState::Stopped(StopEnding::AtDaemonStart)
        );
    }
    for name in ["restored-alpha", "restored-beta"] {
        assert_eq!(
            route_owner(&server, &format!("{name}.min.internal")).await,
            None,
            "{name}'s name does not route while the box is stopped"
        );
    }

    attach_and_echo(&mut client, alpha)
        .await
        .expect("an attach resumes the stopped box");
    assert_eq!(
        read_record(&server, alpha).await.state().unwrap(),
        RecordState::Running
    );
    assert_eq!(
        route_owner(&server, "restored-alpha.min.internal").await,
        Some("restored-alpha".to_owned()),
        "the resumed box's name routes to its own session"
    );
    assert_eq!(
        read_record(&server, beta).await.state().unwrap(),
        RecordState::Stopped(StopEnding::AtDaemonStart),
        "the box nobody attached to stays stopped"
    );
}

/// BOX-154 and BOX-025 across a daemon restart: a `running` record whose
/// box has no process left reads `stopped` after the restart, with no exit
/// code and no signal, and with an `exited` event that says so. An attach
/// then resumes the box with its files, its id and its name.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restart_stops_running_record_and_attach_resumes_it() {
    use boxes::core::record::{RecordState, StopEnding};
    use boxes::events::BoxEventType;

    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let id = create_session_with_spec(
        &mut client,
        Some("restart-box"),
        "/uwu",
        Some(resume_spec(true)),
    )
    .await;
    let paths = session_paths(&server, id).await;
    let kept = std::path::Path::new(paths.working.as_str()).join("kept.txt");
    std::fs::write(&kept, "still here").unwrap();
    assert_eq!(
        read_record(&server, id).await.state().unwrap(),
        RecordState::Running
    );

    // The restart: every process of the first daemon's boxes is gone.
    let server = restart(server, client).await;
    let mut client = server.connect().await;
    assert_eq!(
        server
            .state
            .sessions_manager()
            .await
            .resume_active_sessions()
            .await
            .unwrap(),
        0,
        "the restart brings no box back"
    );

    let record = read_record(&server, id).await;
    assert_eq!(
        record.state().unwrap(),
        RecordState::Stopped(StopEnding::AtDaemonStart)
    );
    assert_eq!(record.status, boxes::BoxState::Stopped);
    assert_eq!((record.exit_code, record.signal), (None, None));
    let events = event_kinds(&server, id).await;
    let exited = events
        .iter()
        .rposition(|e| e.kind == BoxEventType::Exited)
        .expect("the restart records an exited event");
    assert_eq!(events[exited].data["reason"], "stopped");
    assert!(
        !events[exited].data.contains_key("signal"),
        "{:?}",
        events[exited].data
    );
    assert!(
        !events[exited].data.contains_key("exit_code"),
        "{:?}",
        events[exited].data
    );

    attach_and_echo(&mut client, id)
        .await
        .expect("an attach resumes the box the restart stopped");
    let record = read_record(&server, id).await;
    assert_eq!(record.state().unwrap(), RecordState::Running);
    assert_eq!(record.id, id, "the box keeps its id");
    assert_eq!(record.name.as_deref(), Some("restart-box"), "and its name");
    assert_eq!(
        std::fs::read_to_string(&kept).unwrap(),
        "still here",
        "and its files"
    );
    let events = event_kinds(&server, id).await;
    let resumed = events
        .iter()
        .rposition(|e| e.kind == BoxEventType::Resumed)
        .expect("the resume records a resumed event");
    assert!(exited < resumed);
    assert_eq!(events[resumed].data["from"], "stopped");
}

/// BOX-154 with a destroy: a box the first daemon composed reads `stopped`
/// after a restart, and no actor hosts it. Its destroy still runs its
/// `on_destroy` hook from the stored composition, once, without a resume.
/// Then its record goes.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn on_destroy_runs_once_for_a_box_stopped_by_a_restart() {
    use boxes::core::record::{RecordState, StopEnding};

    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("destroyed");
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let id = session_with_hook(
        &mut client,
        "restart-destroy-hook",
        boxes::wire::primitives::WireLifecycleHook {
            on_destroy: Some(inline(format!("echo ran >> {}", marker.display()))),
            ..Default::default()
        },
    )
    .await;

    let server = restart(server, client).await;
    let mut client = server.connect().await;
    let manager = server.state.sessions_manager().await;
    assert_eq!(manager.resume_active_sessions().await.unwrap(), 0);
    assert_eq!(
        read_record(&server, id).await.state().unwrap(),
        RecordState::Stopped(StopEnding::AtDaemonStart)
    );
    assert!(!marker.exists(), "no hook ran before the destroy");

    destroy_session(&mut client, id).await;

    assert_eq!(
        std::fs::read_to_string(&marker).unwrap_or_default(),
        "ran\n",
        "the destroy runs the stored on_destroy hook exactly once"
    );
    assert!(
        manager
            .get_session(crate::box_manager::BoxKeyPredicate::Id(id))
            .await
            .unwrap()
            .is_none(),
        "the record is gone after the destroy"
    );
}

/// A restarted daemon launches no host for a box it found `running`: the
/// restart set the box `stopped` (BOX-154). An attach resumes the
/// own-address box (BOX-025) with its network mode and its recorded
/// address, and the registry publishes it at that address again.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_restarted_daemon_resumes_an_own_ip_box_on_attach_with_its_address() {
    use boxes::core::record::{RecordState, StopEnding};

    let handed = std::net::Ipv4Addr::new(127, 0, 64, 10);
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let web = finalize_handed_own_ip_session(
        &mut client,
        "restored-own-ip",
        std::net::Ipv4Addr::new(100, 64, 128, 10),
        handed,
    )
    .await;
    let before = read_record(&server, web).await;

    let server = restart(server, client).await;
    let mut client = server.connect().await;
    let manager = server.state.sessions_manager().await;
    assert_eq!(
        manager.resume_active_sessions().await.unwrap(),
        0,
        "the restart brings no box back"
    );
    assert_eq!(manager.running_count().await, 0, "and launches no host");
    assert_eq!(
        read_record(&server, web).await.state().unwrap(),
        RecordState::Stopped(StopEnding::AtDaemonStart)
    );

    attach_and_echo(&mut client, web)
        .await
        .expect("an attach resumes the own-address box");
    let record = read_record(&server, web).await;
    assert_eq!(record.state().unwrap(), RecordState::Running);
    assert_eq!(record.network, boxes::NetworkMode::OwnIp);
    assert_eq!(
        record.box_addresses, before.box_addresses,
        "the box keeps its recorded address"
    );
    assert_eq!(
        manager
            .hostnames()
            .read()
            .expect("registry lock")
            .published_own_address(web),
        Some(handed),
        "the registry publishes the box at its address again"
    );
}

/// One restored box whose resume fails costs only itself. The restart set
/// both boxes `stopped` (BOX-154). The attach to the broken one fails and
/// leaves it stopped. The attach to the healthy one resumes it, and its
/// name routes.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_restored_session_that_fails_to_resume_does_not_stop_the_others() {
    use boxes::core::record::{RecordState, StopEnding};

    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let broken = create_configured_session(&mut client, "resume-broken", "/uwu").await;
    let healthy = create_configured_session(&mut client, "resume-healthy", "/uwu").await;
    let home = session_paths(&server, broken).await.home;

    let server = restart(server, client).await;
    let mut client = server.connect().await;
    // A file where the session's home directory belongs: the actor's
    // bring-up cannot create its directories, so it fails to start.
    std::fs::remove_dir_all(home.as_utf8_path()).unwrap();
    std::fs::write(home.as_utf8_path(), b"not a directory").unwrap();

    attach_and_echo(&mut client, broken)
        .await
        .expect_err("the broken box reaches no shell");
    assert_eq!(
        read_record(&server, broken).await.state().unwrap(),
        RecordState::Stopped(StopEnding::AtDaemonStart),
        "the broken box stays stopped"
    );
    assert_eq!(
        route_owner(&server, "resume-broken.min.internal").await,
        None,
        "the broken session's name stays unregistered"
    );

    attach_and_echo(&mut client, healthy)
        .await
        .expect("the healthy box resumes");
    assert_eq!(
        read_record(&server, healthy).await.state().unwrap(),
        RecordState::Running
    );
    assert_eq!(
        route_owner(&server, "resume-healthy.min.internal").await,
        Some("resume-healthy".to_owned()),
        "the healthy session's name routes"
    );
}

/// Two restored sessions whose box names fold to one hostname (two unnamed
/// sessions whose project directories' basenames differ only in case). The
/// restart sets both `stopped` (BOX-154). The first attach resumes its box
/// and routes the name. The second attach is refused with exit status 2
/// (BOX-025), so the name does not move.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_restored_hostname_collision_is_refused_on_resume() {
    use boxes::core::record::{RecordState, StopEnding};
    use minimald_rpc::{CreateSession, Errorable, FinalizeSession, FinalizeSessionRequest};

    let capture = crate::test_harness::captured_log();
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let mut ids = Vec::new();
    for project in ["/x/FoldApp", "/y/foldapp"] {
        let mut request = crate::test_harness::create_session_req("unused", project);
        request.config.name = None;
        let id = client.call::<CreateSession>(&request).await.unwrap().id;
        crate::test_harness::unwrap_ready(
            client
                .call::<minimald_rpc::ConfigureLoadout>(&minimald_rpc::ConfigureLoadoutRequest {
                    session_id: id,
                    contribution: Default::default(),
                })
                .await
                .unwrap(),
        );
        match client
            .call::<FinalizeSession>(&FinalizeSessionRequest {
                session_id: id,
                report_shared_port_collisions: false,
            })
            .await
        {
            Errorable::Ok(_) => {}
            Errorable::Err { error } => panic!("FinalizeSession failed: {error}"),
        }
        ids.push(id);
    }

    let server = restart(server, client).await;
    let mut client = server.connect().await;
    let manager = server.state.sessions_manager().await;
    assert_eq!(
        manager.resume_active_sessions().await.unwrap(),
        0,
        "the restart brings neither box back"
    );

    attach_and_echo(&mut client, ids[0])
        .await
        .expect("the first attach resumes its box");
    assert_eq!(
        route_owner(&server, "foldapp.min.internal").await,
        Some("FoldApp".to_owned()),
        "the name routes for the resumed box"
    );
    assert_resume_refused(
        &server,
        &mut client,
        ids[1],
        RecordState::Stopped(StopEnding::AtDaemonStart),
        &["The running session `FoldApp` holds the name `foldapp`"],
        2,
    )
    .await;
    assert_eq!(
        route_owner(&server, "foldapp.min.internal").await,
        Some("FoldApp".to_owned()),
        "the refused resume does not move the name"
    );
    let logged = capture.contents();
    assert!(
        logged
            .lines()
            .any(|line| line.contains("resume: a running box holds the name")
                && line.contains("holder=FoldApp")),
        "the refusal is logged naming the holder, got: {logged}"
    );
}
/// Two restored sessions that share one registry name outright: two unnamed
/// sessions whose project directories share a basename, the pair the
/// store's name-uniqueness check never sees. The restart sets both
/// `stopped` (BOX-154). The first attach resumes its box and routes the
/// name. The second attach is refused with exit status 2 (BOX-025), so the
/// name does not move.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_restored_session_sharing_another_sessions_registry_name_is_refused_on_resume() {
    use boxes::core::record::{RecordState, StopEnding};
    use minimald_rpc::{CreateSession, Errorable, FinalizeSession, FinalizeSessionRequest};

    let capture = crate::test_harness::captured_log();
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let mut ids = Vec::new();
    for project in ["/a/twins", "/b/twins"] {
        let mut request = crate::test_harness::create_session_req("unused", project);
        request.config.name = None;
        let id = client.call::<CreateSession>(&request).await.unwrap().id;
        crate::test_harness::unwrap_ready(
            client
                .call::<minimald_rpc::ConfigureLoadout>(&minimald_rpc::ConfigureLoadoutRequest {
                    session_id: id,
                    contribution: Default::default(),
                })
                .await
                .unwrap(),
        );
        match client
            .call::<FinalizeSession>(&FinalizeSessionRequest {
                session_id: id,
                report_shared_port_collisions: false,
            })
            .await
        {
            Errorable::Ok(_) => {}
            Errorable::Err { error } => panic!("FinalizeSession failed: {error}"),
        }
        ids.push(id);
    }

    let server = restart(server, client).await;
    let mut client = server.connect().await;
    let manager = server.state.sessions_manager().await;
    assert_eq!(
        manager.resume_active_sessions().await.unwrap(),
        0,
        "the restart brings neither box back"
    );

    attach_and_echo(&mut client, ids[0])
        .await
        .expect("the first attach resumes its box");
    assert_eq!(
        route_owner(&server, "twins.min.internal").await,
        Some("twins".to_owned()),
        "the name routes for the resumed box"
    );
    assert_resume_refused(
        &server,
        &mut client,
        ids[1],
        RecordState::Stopped(StopEnding::AtDaemonStart),
        &["The running session `twins` holds the name `twins`"],
        2,
    )
    .await;
    assert_eq!(
        route_owner(&server, "twins.min.internal").await,
        Some("twins".to_owned()),
        "the refused resume does not move the name"
    );
    let logged = capture.contents();
    assert!(
        logged
            .lines()
            .any(|line| line.contains("resume: a running box holds the name")
                && line.contains("holder=twins")),
        "the refusal is logged naming the holder, got: {logged}"
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
            .resolve(&format!("resumed-hand.min.internal:{}", declared_port()))
            .expect("the name routes once the verdict lands")
            .upstream(declared_port()),
        Some(std::net::SocketAddr::new(
            std::net::IpAddr::V4(handed),
            declared_port()
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
    let finalize =
        crate::traced::spawn(async move { finalize_session(&mut finalize_client, web).await });
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
    let drawn = crate::box_manager::draw_interim_upgrades(book, &registry);
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
    let applied = crate::box_manager::apply_interim_upgrade(book, &registry, upgrade);
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
    let upgrade = crate::box_manager::InterimUpgrade {
        session: standing.session,
        name: standing.name,
        ports: standing.ports,
        address: granted,
        hand: false,
    };

    assert!(
        !crate::box_manager::apply_interim_upgrade(book, &registry, &upgrade),
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
    let finalize =
        crate::traced::spawn(async move { finalize_session(&mut finalize_client, id).await });
    await_verdict_waiter(&manager).await;
    let mut destroy_client = server.connect().await;
    let destroy =
        crate::traced::spawn(async move { destroy_session(&mut destroy_client, id).await });
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
    let drawn = crate::box_manager::draw_interim_upgrades(book, &registry);
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

    let applied = crate::box_manager::apply_interim_upgrade(book, &registry, upgrade);
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
            .resolve(&format!("web.min.internal:{}", declared_port()))
            .expect("the name routes at the hand")
            .upstream(declared_port()),
        Some(std::net::SocketAddr::new(
            std::net::IpAddr::V4(handed),
            declared_port()
        )),
        "the box's declared port is published at its own hand, exactly where \
         the attach path binds its forwards"
    );
}

/// #2748, the fresh install on a VM-backed host: the daemon-start walk
/// lands absent, so a handed box finalizes at the `127.0.0.1` interim and
/// its running attach binds its forwards there. The host then gains the
/// range, and the next session start's walk lands present. The landing
/// moves the box's name to its own hand, and the box's forward follows it:
/// the running box binds its declared port at the hand, toward its switch
/// lease, so the name and the forward answer at one address. Once that bind
/// stands, the forward its attach bound at the interim is unbound, so no
/// listener is left on the shared interim for another box's bind to meet.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_present_landing_moves_a_running_interim_boxs_forward_to_its_hand() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    let server = TestServer::new().await;
    let manager = server.state.sessions_manager().await;
    let installed = Arc::new(AtomicBool::new(false));
    {
        let installed = Arc::clone(&installed);
        manager.install_range_walk_standin(move || {
            let hosts = ::switch::loopback::range_hosts().count();
            if installed.load(Ordering::SeqCst) {
                crate::net::loopback::RangeProbe {
                    bound: hosts,
                    probed: hosts,
                    first_failure: None,
                }
            } else {
                crate::net::loopback::RangeProbe {
                    bound: 0,
                    probed: hosts,
                    first_failure: Some((
                        std::net::Ipv4Addr::new(127, 0, 64, 1),
                        std::io::ErrorKind::AddrNotAvailable,
                    )),
                }
            }
        });
    }
    // The daemon-start walk's verdict on a host without the range.
    manager.land_range_verdict(crate::net::dns::RangeVerdict::Absent);
    let mut client = server.connect().await;
    let handed = std::net::Ipv4Addr::new(127, 0, 64, 2);
    let lease = std::net::Ipv4Addr::new(100, 64, 128, 2);
    let web = finalize_handed_own_ip_session(&mut client, "web", lease, handed).await;
    let registry = manager.hostnames();
    assert_eq!(
        registry
            .read()
            .expect("registry lock")
            .published_own_address(web),
        Some(std::net::Ipv4Addr::LOCALHOST),
        "the absent verdict stands the handed box on the interim"
    );
    let handle = manager
        .get_session(crate::box_manager::BoxKeyPredicate::Id(web))
        .await
        .unwrap()
        .expect("the box resolves");
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
    let (forwarder, served) = fake_forwarder(sock.clone(), 200).await;
    let mapping = boxes::PortMapping {
        external_port: declared_port(),
        internal_port: 80,
        proto: boxes::IpProto::Tcp,
    };
    // The declared forward the box's attach bound at the interim, as the
    // attach shares it with the box's actor. The mock launch binds none.
    let interim = std::net::Ipv4Addr::LOCALHOST;
    let control = crate::net::policy::ControlChannel::Unix(sock);
    let Ok(crate::net::policy::HandedBind::Bound(attached)) =
        crate::net::policy::bind_handed_port(&control, interim, lease, &mapping, None).await
    else {
        panic!("the stand-in binds the attach's forward");
    };
    let (ingress, _) = handle.ingress_cells().await.expect("the actor answers");
    ingress.record_attached(std::slice::from_ref(&attached));

    // `min finalize-install` applies the range, and the next session start
    // walks it again.
    installed.store(true, Ordering::SeqCst);
    let answer = manager
        .session_start_range_walk()
        .await
        .expect("the daemon walks the range through the forwarder");
    assert_eq!(answer.moved, 1, "the landing moves the box off the interim");

    assert_eq!(
        registry
            .read()
            .expect("registry lock")
            .published_own_address(web),
        Some(handed),
        "the present landing moves the box's publish to its own hand"
    );
    let (_, address) = zone_answer_for(&server, "web.min.internal")
        .await
        .expect("the name survives the landing");
    assert_eq!(address, handed, "the name answers at the hand");

    // The attach's bind, the hand's bind, then the interim's unbind.
    let requests = await_served(&served, 3).await;
    forwarder.abort();
    let (line, body) = requests[1]
        .split_once('\n')
        .expect("the served request carries its request line and body");
    assert!(
        line.starts_with("POST /services/forwarder/expose "),
        "the landing binds the running box's forward at its hand: {requests:?}"
    );
    let declared = crate::net::policy::expose_request(&mapping, handed, lease);
    assert_eq!(
        body,
        String::from_utf8(serde_json_lenient::to_vec(&declared).unwrap()).unwrap(),
        "the forward listens where the name answers, toward the box's lease"
    );
    assert!(
        requests[2].starts_with("POST /services/forwarder/unexpose ")
            && requests[2].contains(&format!("\"local\":\"{interim}:{}\"", declared_port())),
        "the forward at the interim is unbound after the hand's bind stands: {requests:?}"
    );
    assert!(
        attached.is_revoked(),
        "the attach's teardown asks nothing more of the forward unbound here"
    );
}

/// #2748, a declared port whose bind at the hand fails: the landing moves the
/// box's name to its hand, but the switch refuses the declared port's bind
/// there. The forward the attach bound at the interim is the only one that
/// serves the port, so it stays bound: it is unbound only once the bind at
/// the hand stands.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_declared_port_whose_bind_at_the_hand_fails_keeps_its_interim_forward() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    let server = TestServer::new().await;
    let manager = server.state.sessions_manager().await;
    let installed = Arc::new(AtomicBool::new(false));
    {
        let installed = Arc::clone(&installed);
        manager.install_range_walk_standin(move || {
            let hosts = ::switch::loopback::range_hosts().count();
            if installed.load(Ordering::SeqCst) {
                crate::net::loopback::RangeProbe {
                    bound: hosts,
                    probed: hosts,
                    first_failure: None,
                }
            } else {
                crate::net::loopback::RangeProbe {
                    bound: 0,
                    probed: hosts,
                    first_failure: Some((
                        std::net::Ipv4Addr::new(127, 0, 64, 1),
                        std::io::ErrorKind::AddrNotAvailable,
                    )),
                }
            }
        });
    }
    manager.land_range_verdict(crate::net::dns::RangeVerdict::Absent);
    let mut client = server.connect().await;
    let handed = std::net::Ipv4Addr::new(127, 0, 64, 8);
    let lease = std::net::Ipv4Addr::new(100, 64, 128, 8);
    let interim = std::net::Ipv4Addr::LOCALHOST;
    let web = finalize_handed_own_ip_session(&mut client, "web", lease, handed).await;
    let handle = manager
        .get_session(crate::box_manager::BoxKeyPredicate::Id(web))
        .await
        .unwrap()
        .expect("the box resolves");
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
    // The switch binds everything at the interim and nothing at the hand.
    let refused_at = format!("\"local\":\"{handed}:");
    let (forwarder, served) =
        deciding_forwarder(sock.clone(), move |request| !request.contains(&refused_at)).await;
    let mapping = boxes::PortMapping {
        external_port: declared_port(),
        internal_port: 80,
        proto: boxes::IpProto::Tcp,
    };
    let control = crate::net::policy::ControlChannel::Unix(sock);
    let Ok(crate::net::policy::HandedBind::Bound(attached)) =
        crate::net::policy::bind_handed_port(&control, interim, lease, &mapping, None).await
    else {
        panic!("the stand-in binds the attach's forward");
    };
    let (ingress, _) = handle.ingress_cells().await.expect("the actor answers");
    ingress.record_attached(std::slice::from_ref(&attached));

    installed.store(true, Ordering::SeqCst);
    let answer = manager
        .session_start_range_walk()
        .await
        .expect("the daemon walks the range through the forwarder");
    assert_eq!(answer.moved, 1, "the landing moves the box off the interim");
    // The actor asked for the port at the hand, and the switch refused it.
    soon(|| {
        served_naming(&served, handed, declared_port())
            .iter()
            .any(|request| request.starts_with("POST /services/forwarder/expose "))
    })
    .await;
    // The move's handling ends in the actor's own turn: a round trip to it
    // after the refused bind is after the release would have been asked.
    handle.live_ingress().await.expect("the actor answers");
    forwarder.abort();
    assert!(
        served_naming(&served, interim, declared_port())
            .iter()
            .all(|request| !request.starts_with("POST /services/forwarder/unexpose ")),
        "the forward at the interim is not unbound while no bind at the hand stands: {:?}",
        served.lock().expect("served lock")
    );
    assert!(
        !attached.is_revoked(),
        "the attach's forward at the interim still serves the port"
    );
}

/// #2748, the runtime publications: a handed box standing on the
/// `127.0.0.1` interim publishes one port with `min net expose` and one by
/// listening on it, and both forwards bind at the interim. When the range
/// lands present and the box's name moves to its hand, both forwards move
/// with it: each is bound at the hand toward the box's lease and unbound at
/// the interim, the listed rows name the hand, and the listened port's hold
/// of record moves to the hand. The box declares no port, so no declared
/// hand-over is what moves them.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_present_landing_moves_a_running_interim_boxs_runtime_publications_to_its_hand() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    let server = TestServer::new().await;
    let manager = server.state.sessions_manager().await;
    let installed = Arc::new(AtomicBool::new(false));
    {
        let installed = Arc::clone(&installed);
        manager.install_range_walk_standin(move || {
            let hosts = ::switch::loopback::range_hosts().count();
            if installed.load(Ordering::SeqCst) {
                crate::net::loopback::RangeProbe {
                    bound: hosts,
                    probed: hosts,
                    first_failure: None,
                }
            } else {
                crate::net::loopback::RangeProbe {
                    bound: 0,
                    probed: hosts,
                    first_failure: Some((
                        std::net::Ipv4Addr::new(127, 0, 64, 1),
                        std::io::ErrorKind::AddrNotAvailable,
                    )),
                }
            }
        });
    }
    manager.land_range_verdict(crate::net::dns::RangeVerdict::Absent);
    let mut client = server.connect().await;
    // One port the box listens on, and a free one it exposes.
    let listener = listening_socket();
    let listened = port_of(&listener);
    let exposed = port_of(&listening_socket());
    let range = (listened.min(exposed), listened.max(exposed));
    let interim = std::net::Ipv4Addr::LOCALHOST;
    let handed = std::net::Ipv4Addr::new(127, 0, 64, 3);
    let lease = std::net::Ipv4Addr::new(100, 64, 128, 3);
    let web = finalize_dynamic_ingress_session(
        &mut client,
        "web",
        lease,
        handed,
        Some(boxes::DynamicIngress::Allow),
        Some(range),
    )
    .await;
    let registry = manager.hostnames();
    assert_eq!(
        registry
            .read()
            .expect("registry lock")
            .published_own_address(web),
        Some(interim),
        "the absent verdict stands the handed box on the interim"
    );
    let handle = manager
        .get_session(crate::box_manager::BoxKeyPredicate::Id(web))
        .await
        .unwrap()
        .expect("the box resolves");
    let sock = handle
        .net_switch()
        .await
        .unwrap()
        .lock()
        .await
        .control_socket();
    let (forwarder, served) = fake_forwarder(sock.clone(), 200).await;
    let gate = Arc::new(crate::net::switch::BoxGate::for_session(
        "web".to_string(),
        lease,
        &listen_policy_over(range),
        crate::net::SwitchSubnet::default(),
        None,
    ));
    crate::box_actor::listen_plan_seam::seed(
        web,
        crate::box_actor::listen_plan_seam::Seeded {
            lease,
            published: interim,
            control: crate::net::policy::ControlChannel::Unix(sock),
            gate,
        },
    );
    handle
        .ensure_host("tester".to_string())
        .await
        .expect("the box launches its host");
    handle
        .expose_dynamic(exposed)
        .await
        .expect("a port in the box's range is exposed");
    let at = |address: std::net::Ipv4Addr, port: u16| format!("{address}:{port}");
    listed_once(&handle, |rows| {
        rows.exposed
            .iter()
            .any(|row| row.local == at(interim, exposed))
            && rows
                .listened
                .iter()
                .any(|row| row.local == at(interim, listened))
    })
    .await;
    assert_eq!(
        registry
            .read()
            .expect("registry lock")
            .shared_port_holder(interim, listened),
        Some(web),
        "the listened port is held at the interim"
    );

    // `min finalize-install` applies the range, and the next session start
    // walks it again.
    installed.store(true, Ordering::SeqCst);
    let answer = manager
        .session_start_range_walk()
        .await
        .expect("the daemon walks the range through the forwarder");
    assert_eq!(answer.moved, 1, "the landing moves the box off the interim");

    let rows = listed_once(&handle, |rows| {
        rows.exposed
            .iter()
            .any(|row| row.local == at(handed, exposed))
            && rows
                .listened
                .iter()
                .any(|row| row.local == at(handed, listened))
    })
    .await;
    assert!(
        rows.exposed
            .iter()
            .chain(&rows.listened)
            .all(|row| !row.local.starts_with("127.0.0.1:")),
        "no row names the interim after the move: {rows:?}"
    );
    for port in [exposed, listened] {
        soon(|| {
            served_naming(&served, interim, port)
                .iter()
                .any(|request| request.starts_with("POST /services/forwarder/unexpose "))
        })
        .await;
        let moved = served_naming(&served, handed, port);
        assert!(
            moved.iter().any(
                |request| request.starts_with("POST /services/forwarder/expose ")
                    && request.contains(&format!("\"remote\":\"{lease}:{port}\""))
            ),
            "the port is bound at the hand toward the box's lease: {moved:?}"
        );
    }
    {
        let registry = registry.read().expect("registry lock");
        assert_eq!(
            registry.shared_port_holder(handed, listened),
            Some(web),
            "the listened port is held where the box serves it now"
        );
        assert_eq!(
            registry.shared_port_holder(interim, listened),
            None,
            "the interim hold is released"
        );
    }
    forwarder.abort();
    drop(listener);
}

/// #2748, a listen-published port whose move fails: the box's name moved to
/// its hand, but the switch refuses the port's bind there, so the forward and
/// the box's hold of record stay at the `127.0.0.1` interim. A box that
/// publishes the port at the interim then yields to that hold. When the
/// listener closes, the hold is released where the forward was bound, and
/// the port passes to the box that was waiting on it.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_listen_port_whose_move_failed_releases_its_hold_where_it_was_bound() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    let server = TestServer::new().await;
    let manager = server.state.sessions_manager().await;
    let installed = Arc::new(AtomicBool::new(false));
    {
        let installed = Arc::clone(&installed);
        manager.install_range_walk_standin(move || {
            let hosts = ::switch::loopback::range_hosts().count();
            if installed.load(Ordering::SeqCst) {
                crate::net::loopback::RangeProbe {
                    bound: hosts,
                    probed: hosts,
                    first_failure: None,
                }
            } else {
                crate::net::loopback::RangeProbe {
                    bound: 0,
                    probed: hosts,
                    first_failure: Some((
                        std::net::Ipv4Addr::new(127, 0, 64, 1),
                        std::io::ErrorKind::AddrNotAvailable,
                    )),
                }
            }
        });
    }
    manager.land_range_verdict(crate::net::dns::RangeVerdict::Absent);
    let mut client = server.connect().await;
    let listener = listening_socket();
    let listened = port_of(&listener);
    let interim = std::net::Ipv4Addr::LOCALHOST;
    let handed = std::net::Ipv4Addr::new(127, 0, 64, 4);
    let lease = std::net::Ipv4Addr::new(100, 64, 128, 4);
    let web = finalize_dynamic_ingress_session(
        &mut client,
        "web",
        lease,
        handed,
        Some(boxes::DynamicIngress::Allow),
        Some((listened, listened)),
    )
    .await;
    let handle = manager
        .get_session(crate::box_manager::BoxKeyPredicate::Id(web))
        .await
        .unwrap()
        .expect("the box resolves");
    let sock = handle
        .net_switch()
        .await
        .unwrap()
        .lock()
        .await
        .control_socket();
    // The switch binds everything at the interim and nothing at the hand.
    let refused_at = format!("\"local\":\"{handed}:");
    let (forwarder, served) =
        deciding_forwarder(sock.clone(), move |request| !request.contains(&refused_at)).await;
    crate::box_actor::listen_plan_seam::seed(
        web,
        crate::box_actor::listen_plan_seam::Seeded {
            lease,
            published: interim,
            control: crate::net::policy::ControlChannel::Unix(sock),
            gate: Arc::new(crate::net::switch::BoxGate::for_session(
                "web".to_string(),
                lease,
                &listen_policy_over((listened, listened)),
                crate::net::SwitchSubnet::default(),
                None,
            )),
        },
    );
    handle
        .ensure_host("tester".to_string())
        .await
        .expect("the box launches its host");
    let at_interim = format!("{interim}:{listened}");
    listed_once(&handle, |rows| {
        rows.listened.iter().any(|row| row.local == at_interim)
    })
    .await;

    installed.store(true, Ordering::SeqCst);
    let answer = manager
        .session_start_range_walk()
        .await
        .expect("the daemon walks the range through the forwarder");
    assert_eq!(answer.moved, 1, "the landing moves the box off the interim");
    // The watcher asked for the port at the hand, and the switch refused it.
    soon(|| {
        served_naming(&served, handed, listened)
            .iter()
            .any(|request| request.starts_with("POST /services/forwarder/expose "))
    })
    .await;
    let registry = manager.hostnames();
    {
        let registry = registry.read().expect("registry lock");
        assert_eq!(
            registry.shared_port_holder(interim, listened),
            Some(web),
            "the hold stays where the forward is still bound"
        );
        assert_eq!(
            registry.shared_port_holder(handed, listened),
            None,
            "nothing is held at the hand while no forward is bound there"
        );
    }
    let rows = handle.live_ingress().await.expect("the actor answers");
    assert!(
        rows.listened.iter().any(|row| row.local == at_interim),
        "the row names where the forward is still bound: {rows:?}"
    );

    // Another box publishes the port at the interim and yields to the hold.
    let waiting = SessionId::parse_str("00000000-0000-0000-0000-0000000000db").unwrap();
    registry
        .write()
        .expect("registry lock")
        .publish_own_address(
            waiting,
            "db",
            interim,
            std::collections::BTreeSet::from([listened]),
        );
    assert_eq!(
        registry
            .read()
            .expect("registry lock")
            .shared_port_holder(interim, listened),
        Some(web),
        "the waiting box yields to the box serving the port"
    );

    // The listener closes: the forward comes down at the interim, and the
    // hold there passes to the waiting box.
    drop(listener);
    soon(|| {
        served_naming(&served, interim, listened)
            .iter()
            .any(|request| request.starts_with("POST /services/forwarder/unexpose "))
    })
    .await;
    soon(|| {
        registry
            .read()
            .expect("registry lock")
            .shared_port_holder(interim, listened)
            == Some(waiting)
    })
    .await;
    forwarder.abort();
}

/// #2748, a listen port whose new address another box holds: an absent
/// landing moves a box at its range address onto the shared `127.0.0.1`
/// interim, where a box with no forward behind it, such as a stopped one,
/// declared the port first. The listening port does not move there: the
/// other box keeps the port of record, and the forward stays at the old
/// address. Once that box gives the port up, the next poll moves it.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_listen_port_does_not_move_onto_a_port_another_box_holds() {
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let manager = server.state.sessions_manager().await;
    let listener = listening_socket();
    let listened = port_of(&listener);
    let interim = std::net::Ipv4Addr::LOCALHOST;
    let handed = std::net::Ipv4Addr::new(127, 0, 64, 6);
    let (handle, _gate, served, _gate_sender, web) = box_with_scripted_plan(
        &mut client,
        &manager,
        "web",
        true,
        std::net::Ipv4Addr::new(100, 64, 128, 6),
        handed,
        (listened, listened),
        Vec::new(),
    )
    .await;
    let at_hand = format!("{handed}:{listened}");
    listed_once(&handle, |rows| {
        rows.listened.iter().any(|row| row.local == at_hand)
    })
    .await;
    // Another box declared the port at the interim and binds nothing there.
    let registry = manager.hostnames();
    let other = SessionId::parse_str("00000000-0000-0000-0000-0000000000db").unwrap();
    registry
        .write()
        .expect("registry lock")
        .publish_own_address(
            other,
            "db",
            interim,
            std::collections::BTreeSet::from([listened]),
        );

    manager.land_range_verdict(crate::net::dns::RangeVerdict::Absent);
    assert_eq!(
        registry
            .read()
            .expect("registry lock")
            .published_own_address(web),
        Some(interim),
        "the absent landing moves the box onto the interim"
    );
    // A few of the watcher's polls.
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert!(
        served_naming(&served, interim, listened).is_empty(),
        "the listening port is not bound where another box holds it"
    );
    assert_eq!(
        registry
            .read()
            .expect("registry lock")
            .shared_port_holder(interim, listened),
        Some(other),
        "the other box keeps the port of record"
    );
    let rows = handle.live_ingress().await.expect("the actor answers");
    assert!(
        rows.listened.iter().any(|row| row.local == at_hand),
        "the row names where the forward is still bound: {rows:?}"
    );

    // The other box gives the port up, and the port follows the box.
    let (_, hand_overs) = registry
        .write()
        .expect("registry lock")
        .unpublish_own_address(other);
    assert!(hand_overs.is_empty(), "no box waits on the port");
    soon(|| {
        served_naming(&served, interim, listened)
            .iter()
            .any(|request| request.starts_with("POST /services/forwarder/expose "))
    })
    .await;
    soon(|| {
        registry
            .read()
            .expect("registry lock")
            .shared_port_holder(interim, listened)
            == Some(web)
    })
    .await;
    drop(listener);
}

/// #2748: a range walk that ends inconclusive, as one whose probe round the
/// VM host's gate kept contended past the walk's budget does, never replaces
/// a present verdict. Every box keeps its range address, so a guest that
/// holds a probe round cannot move the host's boxes back to the interim.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_contended_walk_never_replaces_a_present_verdict() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    let server = TestServer::new().await;
    let manager = server.state.sessions_manager().await;
    let contended = Arc::new(AtomicBool::new(false));
    {
        let contended = Arc::clone(&contended);
        manager.install_range_walk_standin(move || {
            let hosts = ::switch::loopback::range_hosts().count();
            if contended.load(Ordering::SeqCst) {
                crate::net::loopback::RangeProbe {
                    bound: hosts - 1,
                    probed: hosts,
                    first_failure: Some((
                        std::net::Ipv4Addr::new(127, 0, 64, 5),
                        std::io::ErrorKind::TimedOut,
                    )),
                }
            } else {
                crate::net::loopback::RangeProbe {
                    bound: hosts,
                    probed: hosts,
                    first_failure: None,
                }
            }
        });
    }
    manager.land_range_verdict(crate::net::dns::RangeVerdict::Present);
    let mut client = server.connect().await;
    let handed = std::net::Ipv4Addr::new(127, 0, 64, 7);
    let web = finalize_handed_own_ip_session(
        &mut client,
        "web",
        std::net::Ipv4Addr::new(100, 64, 128, 7),
        handed,
    )
    .await;
    let registry = manager.hostnames();
    assert_eq!(
        registry
            .read()
            .expect("registry lock")
            .published_own_address(web),
        Some(handed),
        "the present verdict publishes the box at its hand"
    );

    contended.store(true, Ordering::SeqCst);
    let answer = manager
        .session_start_range_walk()
        .await
        .expect("the daemon walks the range through the forwarder");
    assert_eq!(answer.moved, 0, "an inconclusive walk moves nothing");
    assert_eq!(
        registry
            .read()
            .expect("registry lock")
            .published_own_address(web),
        Some(handed),
        "the box keeps its range address over an inconclusive walk"
    );
}

/// #2748, a box with no actor: the present landing moves every box standing
/// on the `127.0.0.1` interim, stopped ones included, and the move of a
/// box's publish is passed only to a live actor, with the hand-over for
/// each port the box declares. A box whose actor is not running has no
/// forward to move, so the landing starts none for it, not even for the
/// port it declares, and its next attach binds at the new address.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_present_landing_starts_no_actor_for_a_box_without_one() {
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let handed = std::net::Ipv4Addr::new(127, 0, 64, 5);
    // The box declares its test's declared port.
    let web = finalize_handed_own_ip_session(
        &mut client,
        "web",
        std::net::Ipv4Addr::new(100, 64, 128, 5),
        handed,
    )
    .await;
    let declared = std::collections::BTreeSet::from([declared_port()]);
    // A restarted daemon that has not resumed the box: its record stands,
    // and no actor runs for it.
    let server = restart(server, client).await;
    let manager = server.state.sessions_manager().await;
    manager.install_range_walk_standin(|| {
        let hosts = ::switch::loopback::range_hosts().count();
        crate::net::loopback::RangeProbe {
            bound: hosts,
            probed: hosts,
            first_failure: None,
        }
    });
    manager.land_range_verdict(crate::net::dns::RangeVerdict::Absent);
    // The box stands on the interim with its hand, as a box that published
    // under the absent verdict does.
    {
        let registry = manager.hostnames();
        let mut registry = registry.write().expect("registry lock");
        registry.record_own_hand(web, handed);
        registry.publish_own_address(web, "web", std::net::Ipv4Addr::LOCALHOST, declared.clone());
        registry.register_own_ip(web, "web", declared.clone());
    }
    assert_eq!(
        manager.running_count().await,
        0,
        "no actor runs for the box"
    );

    let answer = manager
        .session_start_range_walk()
        .await
        .expect("the daemon walks the range through the forwarder");
    assert_eq!(answer.moved, 1, "the landing moves the box off the interim");
    {
        let registry = manager.hostnames();
        let registry = registry.read().expect("registry lock");
        assert_eq!(
            registry.published_own_address(web),
            Some(handed),
            "the box's publish moves to its hand"
        );
        assert!(
            registry.holds_shared_port(web, handed, declared_port()),
            "the box holds its declared port at the hand, so the move made its hand-over"
        );
    }
    // The move is passed on off the landing's task: give it the time an
    // actor's start would take, then read that none started.
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(
        manager.running_count().await,
        0,
        "the landing starts no actor for a box without one"
    );
}

/// A stand-in for the host gvproxy that answers each request 200 when
/// `accept` takes it and 500 when it does not, recording every request as
/// [`fake_forwarder`] does — so a test can have the switch refuse binds at
/// one address for as long as it runs, however often they are asked.
#[cfg(target_os = "linux")]
async fn deciding_forwarder(
    sock: std::path::PathBuf,
    accept: impl Fn(&str) -> bool + Send + 'static,
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
    let server = crate::traced::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let Some(request) = read_control_request(&mut stream).await else {
                continue;
            };
            let answer = if accept(&request) {
                "200 OK"
            } else {
                "500 Internal Server Error"
            };
            recorded.lock().expect("served lock").push(request);
            #[expect(
                clippy::let_underscore_must_use,
                reason = "the answer's fate is not what the stand-in records; the request is"
            )]
            let _ = stream
                .write_all(format!("HTTP/1.1 {answer}\r\nContent-Length: 0\r\n\r\n").as_bytes())
                .await;
        }
    });
    (server, served)
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
            crate::traced::spawn(async move { finalize_session(&mut finalize_client, web).await });
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
async fn shared_address_port_collision_reported_not_translated() {
    let shared = std::net::Ipv4Addr::new(127, 0, 64, 9);
    let server = TestServer::new().await;
    let capture = crate::test_harness::captured_log();
    let mut client = server.connect().await;

    // Each box's finalize runs directly, not through the combined helper,
    // because the reply is half of what this test pins: the collision list
    // the daemon hands the activating client, so it can warn without
    // reading the daemon log.
    let first = create_handed_own_ip_session(
        &mut client,
        "first",
        std::net::Ipv4Addr::new(100, 64, 128, 9),
        shared,
    )
    .await;
    let first_finalize_reply = finalize_session(&mut client, first).await;
    let second = create_handed_own_ip_session(
        &mut client,
        "second",
        std::net::Ipv4Addr::new(100, 64, 128, 10),
        shared,
    )
    .await;
    let second_reply = finalize_session(&mut client, second).await;

    // A client that predates the field did not ask for the list, and its
    // reply type refuses a key it does not know — so the daemon leaves the
    // list off that reply even though the box yields, instead of failing
    // the older client's activation over a report it cannot read.
    let third = create_handed_own_ip_session(
        &mut client,
        "third",
        std::net::Ipv4Addr::new(100, 64, 128, 11),
        shared,
    )
    .await;
    let older_client_reply = finalize_session_asking(&mut client, third, false).await;
    assert!(
        older_client_reply.shared_port_collisions.is_empty(),
        "a client that did not ask gets no collision list: {older_client_reply:?}"
    );
    assert!(
        !server
            .state
            .sessions_manager()
            .await
            .hostnames()
            .read()
            .expect("registry lock")
            .shared_port_collisions(third)
            .is_empty(),
        "the third box still yields the port; only the report is withheld"
    );

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
            .resolve(&format!("first.min.internal:{}", declared_port()))
            .expect("first's name routes")
            .upstream(declared_port()),
        Some(std::net::SocketAddr::new(
            std::net::IpAddr::V4(first_address),
            declared_port(),
        )),
        "the first box's port is published at the number it asked for"
    );
    assert_eq!(
        routes
            .resolve(&format!("second.min.internal:{}", declared_port()))
            .expect("second's name routes")
            .upstream(declared_port()),
        Some(std::net::SocketAddr::new(
            std::net::IpAddr::V4(second_address),
            declared_port(),
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
            port: declared_port(),
            other: "first.min.internal".to_string(),
        }],
        "the second box records the port it yields and the box that holds it"
    );
    assert!(
        routes.shared_port_collisions(first).is_empty(),
        "the box that published first holds its port and yields nothing"
    );
    drop(routes);

    // The finalize reply carries the same list to the activating client —
    // the reply half of the report, so the client can warn at the activate
    // the user reads instead of the daemon log the user does not. The box
    // that holds the port answered a reply with no list, the client-side
    // silence of the registry record asserted above.
    assert_eq!(
        second_reply.shared_port_collisions,
        vec![minimald_rpc::SharedPortCollision {
            port: declared_port(),
            held_by: "first.min.internal".to_string(),
        }],
        "the finalize reply names the yielded port and the box that holds it"
    );
    assert!(
        first_finalize_reply.shared_port_collisions.is_empty(),
        "the box that holds its port yields nothing, and its reply says so"
    );

    // The collision reached the log and named both boxes and the port.
    let logged = capture.contents();
    let collision_lines: Vec<_> = logged
        .lines()
        .filter(|line| {
            line.contains("action=\"shared-address-port-collision\"")
                && line.contains(&format!("port={}", declared_port()))
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
                    && line.contains(&format!("port={}", declared_port()))
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
            port: declared_port(),
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

/// NET-129 after a daemon restart: the restart sets both boxes `stopped`
/// (BOX-154), and the resume at start brings neither back, so neither holds
/// the shared-address port. Each attach resumes its box (BOX-025) with its
/// address and its declared port. Resumed in creation order, the box created
/// earliest holds the port again and the newer box yields to it.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shared_address_holder_kept_when_boxes_resume_in_creation_order() {
    use boxes::core::record::{RecordState, StopEnding};

    let shared = std::net::Ipv4Addr::new(127, 0, 64, 9);
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let older = finalize_handed_own_ip_session(
        &mut client,
        "box-0",
        std::net::Ipv4Addr::new(100, 64, 128, 9),
        shared,
    )
    .await;
    let newer = finalize_handed_own_ip_session(
        &mut client,
        "box-1",
        std::net::Ipv4Addr::new(100, 64, 128, 10),
        shared,
    )
    .await;
    let held_by_older = vec![crate::net::dns::SharedPortCollision {
        port: declared_port(),
        other: "box-0.min.internal".to_owned(),
    }];
    {
        let registry = server.state.sessions_manager().await.hostnames();
        let routes = registry.read().expect("registry lock");
        assert!(routes.shared_port_collisions(older).is_empty());
        assert_eq!(routes.shared_port_collisions(newer), held_by_older);
    }

    let server = restart(server, client).await;
    let mut client = server.connect().await;
    let manager = server.state.sessions_manager().await;
    assert_eq!(
        manager.resume_active_sessions().await.unwrap(),
        0,
        "the restart brings neither box back"
    );
    for id in [older, newer] {
        assert_eq!(
            read_record(&server, id).await.state().unwrap(),
            RecordState::Stopped(StopEnding::AtDaemonStart)
        );
    }
    for id in [older, newer] {
        attach_and_echo(&mut client, id)
            .await
            .expect("an attach resumes the box");
    }
    let registry = manager.hostnames();
    let routes = registry.read().expect("registry lock");
    assert!(
        routes.shared_port_collisions(older).is_empty(),
        "the box created earliest holds the port after the restart"
    );
    assert_eq!(
        routes.shared_port_collisions(newer),
        held_by_older,
        "and the newer box yields to it"
    );
}

/// NET-129 across a daemon restart, when the boxes did not publish in
/// creation order: a box's id is minted at create and it publishes at
/// finalize, so a box created later can finalize first and hold the port.
/// Once that box has launched — bound the port's forward — it holds the
/// port after a restart too. The restart sets both boxes `stopped`
/// (BOX-154), and the box that bound the port keeps it on its record. Each
/// box publishes again when an RPC that names it brings it up, the older
/// one first, and the newer box takes the port back at its own publish. The
/// older box then resumes on its attach and still yields. The newer box's
/// own attach waits for its client to restore its row (NET-138), which this
/// harness does not do.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shared_address_port_stays_with_the_box_that_bound_it_across_a_restart() {
    use boxes::core::record::{RecordState, StopEnding};

    let shared = std::net::Ipv4Addr::new(127, 0, 64, 9);
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let older = create_handed_own_ip_session(
        &mut client,
        "older",
        std::net::Ipv4Addr::new(100, 64, 128, 9),
        shared,
    )
    .await;
    let newer = create_handed_own_ip_session(
        &mut client,
        "newer",
        std::net::Ipv4Addr::new(100, 64, 128, 10),
        shared,
    )
    .await;
    assert!(older < newer, "ids are minted in creation order");

    // The newer box finalizes first and launches; the older one finalizes
    // after it and yields.
    finalize_session(&mut client, newer).await;
    let mut channel = client.open_shell(newer).await;
    await_echo(&mut channel).await;
    finalize_session(&mut client, older).await;
    let held_by_newer = vec![crate::net::dns::SharedPortCollision {
        port: declared_port(),
        other: "newer.min.internal".to_string(),
    }];
    {
        let registry = server.state.sessions_manager().await.hostnames();
        let routes = registry.read().expect("registry lock");
        assert!(routes.shared_port_collisions(newer).is_empty());
        assert_eq!(routes.shared_port_collisions(older), held_by_newer);
    }
    drop(channel);

    let server = restart(server, client).await;
    let mut client = server.connect().await;
    let manager = server.state.sessions_manager().await;
    assert_eq!(
        manager.resume_active_sessions().await.unwrap(),
        0,
        "the restart brings neither box back"
    );
    let record = read_record(&server, newer).await;
    assert_eq!(
        record.state().unwrap(),
        RecordState::Stopped(StopEnding::AtDaemonStart)
    );
    assert_eq!(
        record.bound_ports,
        std::collections::BTreeSet::from([std::net::SocketAddrV4::new(shared, declared_port())]),
        "the stopped box keeps the port it bound on its record"
    );

    for id in [older, newer] {
        manager
            .get_session(crate::box_manager::BoxKeyPredicate::Id(id))
            .await
            .unwrap()
            .expect("the box resolves");
    }
    attach_and_echo(&mut client, older)
        .await
        .expect("an attach resumes the older box");
    assert_eq!(
        read_record(&server, older).await.state().unwrap(),
        RecordState::Running
    );
    let registry = manager.hostnames();
    let routes = registry.read().expect("registry lock");
    assert!(
        routes.shared_port_collisions(newer).is_empty(),
        "the box that bound the port before the restart holds it after"
    );
    assert_eq!(
        routes.shared_port_collisions(older),
        held_by_newer,
        "and the older box still yields to it, though it resumed first"
    );
}

/// Two boxes handed one loopback address, both declaring the test's port: the
/// first to finalize holds it and the second yields. Returns the manager,
/// the two ids, and the shared address the registry publishes them at.
#[cfg(target_os = "linux")]
async fn shared_port_pair(
    server: &TestServer,
    client: &mut TestClient,
) -> (
    crate::box_manager::BoxManagerHandle,
    SessionId,
    SessionId,
    std::net::Ipv4Addr,
) {
    let shared = std::net::Ipv4Addr::new(127, 0, 64, 9);
    let manager = server.state.sessions_manager().await;
    let holder = finalize_handed_own_ip_session(
        client,
        "holder",
        std::net::Ipv4Addr::new(100, 64, 128, 9),
        shared,
    )
    .await;
    let yielder = finalize_handed_own_ip_session(
        client,
        "yielder",
        std::net::Ipv4Addr::new(100, 64, 128, 10),
        shared,
    )
    .await;
    let published = {
        let registry = manager.hostnames();
        let routes = registry.read().expect("registry lock");
        assert!(routes.shared_port_collisions(holder).is_empty());
        assert_eq!(routes.shared_port_collisions(yielder).len(), 1);
        routes
            .published_own_address(yielder)
            .expect("the yielding box publishes")
    };
    (manager, holder, yielder, published)
}

/// Waits until the stand-in forwarder has served `count` requests.
#[cfg(target_os = "linux")]
async fn await_served(served: &std::sync::Mutex<Vec<String>>, count: usize) -> Vec<String> {
    for _ in 0..1_000 {
        {
            let served = served.lock().expect("served lock");
            if served.len() >= count {
                return served.clone();
            }
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    panic!(
        "the switch was asked fewer than {count} request(s): {:?}",
        served.lock().expect("served lock")
    );
}

/// NET-129, live: when the box holding a shared-address port is destroyed,
/// the running box that takes the port over has its forward bound at once,
/// with no new attach. The daemon posts the expose the box's own attach
/// would have posted, toward its lease at the inside port its declaration
/// maps, records the port on the box's record as one it bound, and unbinds
/// the forward when that box stops.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_destroyed_holders_shared_port_is_bound_for_the_running_box_that_takes_it() {
    let capture = crate::test_harness::captured_log();
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let (manager, holder, yielder, published) = shared_port_pair(&server, &mut client).await;
    let handle = manager
        .get_session(crate::box_manager::BoxKeyPredicate::Id(yielder))
        .await
        .unwrap()
        .expect("the yielding box resolves");
    handle
        .ensure_host("tester".to_string())
        .await
        .expect("the yielding box launches its host");
    let sock = handle
        .net_switch()
        .await
        .unwrap()
        .lock()
        .await
        .control_socket();
    let (forwarder, served) = fake_forwarder(sock, 200).await;

    destroy_session(&mut client, holder).await;

    let requests = await_served(&served, 1).await;
    let (line, body) = requests[0]
        .split_once('\n')
        .expect("the served request carries its request line and body");
    assert!(
        line.starts_with("POST /services/forwarder/expose "),
        "the hand-over binds the new holder's forward: {requests:?}"
    );
    let declared = crate::net::policy::expose_request(
        &boxes::PortMapping {
            external_port: declared_port(),
            internal_port: 80,
            proto: boxes::IpProto::Tcp,
        },
        published,
        std::net::Ipv4Addr::new(100, 64, 128, 10),
    );
    assert_eq!(
        body,
        String::from_utf8(serde_json_lenient::to_vec(&declared).unwrap()).unwrap(),
        "the expose is the one the box's own attach posts for the port"
    );
    {
        let registry = manager.hostnames();
        let routes = registry.read().expect("registry lock");
        assert!(
            routes.shared_port_collisions(yielder).is_empty(),
            "the box holds the port of record"
        );
    }
    let bound =
        std::collections::BTreeSet::from([std::net::SocketAddrV4::new(published, declared_port())]);
    let mut recorded = false;
    for _ in 0..1_000 {
        if handle
            .record()
            .await
            .expect("the record reads back")
            .bound_ports
            == bound
        {
            recorded = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(
        recorded,
        "the box's record names the port it bound at the hand-over"
    );

    // The hand-over says its info line with the plain box name, the one a
    // diagnostics bundle's grep is written against — never a Debug-rendered
    // Option.
    let logged = capture.contents();
    let hand_over_line = logged
        .lines()
        .find(|line| {
            line.contains("bound the shared-address port this box took over while it runs")
        })
        .unwrap_or_else(|| panic!("the hand-over must say its info line, got: {logged}"));
    assert!(
        hand_over_line.contains("session_name=\"yielder\""),
        "the hand-over names the box that took the port over: {hand_over_line}"
    );

    // The box stops for good: the forward bound at the hand-over comes down
    // with it, as the forwards its own attach bound do.
    destroy_session(&mut client, yielder).await;
    let requests = await_served(&served, 2).await;
    forwarder.abort();
    let (line, body) = requests[1]
        .split_once('\n')
        .expect("the served request carries its request line and body");
    assert!(
        line.starts_with("POST /services/forwarder/unexpose "),
        "the stop unbinds the handed-over forward: {requests:?}"
    );
    assert!(
        body.contains(&format!("\"local\":\"{published}:{}\"", declared_port())),
        "the unexpose names the handed-over listener: {body}"
    );
    assert_eq!(requests.len(), 2, "nothing else was asked: {requests:?}");
}

/// NET-129: a box that takes a shared-address port over while it is not
/// running has nothing bound for it. It holds the port of record, and its
/// next attach binds the forward, as before.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_destroyed_holders_shared_port_is_not_bound_for_a_box_that_is_not_running() {
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let (manager, holder, yielder, _published) = shared_port_pair(&server, &mut client).await;
    let handle = manager
        .get_session(crate::box_manager::BoxKeyPredicate::Id(yielder))
        .await
        .unwrap()
        .expect("the yielding box resolves");
    let sock = handle
        .net_switch()
        .await
        .unwrap()
        .lock()
        .await
        .control_socket();
    let (forwarder, served) = fake_forwarder(sock, 200).await;

    destroy_session(&mut client, holder).await;

    {
        let registry = manager.hostnames();
        let routes = registry.read().expect("registry lock");
        assert!(
            routes.shared_port_collisions(yielder).is_empty(),
            "the box holds the port of record"
        );
    }
    // The hand-over reaches the box's actor behind the destroy; an answer
    // from the actor after it proves the hand-over was handled first.
    tokio::time::sleep(Duration::from_millis(300)).await;
    let _record = handle.record().await.expect("the record reads back");
    forwarder.abort();
    assert!(
        served.lock().expect("served lock").is_empty(),
        "a box with no host running asks the switch nothing"
    );
}

/// NET-129: a hand-over's bind the switch refuses loses nothing. The box
/// still holds the port of record, no forward is tracked for it, and its
/// record names no port it did not bind, so its next attach binds the port
/// as it would have without the hand-over.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_hand_over_bind_the_switch_refuses_leaves_the_election_standing() {
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let (manager, holder, yielder, _published) = shared_port_pair(&server, &mut client).await;
    let handle = manager
        .get_session(crate::box_manager::BoxKeyPredicate::Id(yielder))
        .await
        .unwrap()
        .expect("the yielding box resolves");
    handle
        .ensure_host("tester".to_string())
        .await
        .expect("the yielding box launches its host");
    let sock = handle
        .net_switch()
        .await
        .unwrap()
        .lock()
        .await
        .control_socket();
    let (forwarder, served) = fake_forwarder(sock, 500).await;

    destroy_session(&mut client, holder).await;

    let requests = await_served(&served, 1).await;
    assert!(
        requests[0].starts_with("POST /services/forwarder/expose "),
        "the hand-over asked for the bind: {requests:?}"
    );
    // An answer from the actor after the refused bind was served proves the
    // hand-over's turn has ended.
    let record = handle.record().await.expect("the record reads back");
    assert!(
        record.bound_ports.is_empty(),
        "a refused bind is not recorded as bound"
    );
    {
        let registry = manager.hostnames();
        let routes = registry.read().expect("registry lock");
        assert!(
            routes.shared_port_collisions(yielder).is_empty(),
            "the election stands: the box still holds the port of record"
        );
    }

    // Nothing is tracked for the refused bind: the box's stop unbinds nothing.
    destroy_session(&mut client, yielder).await;
    forwarder.abort();
    let requests = served.lock().expect("served lock").clone();
    assert_eq!(
        requests.len(),
        1,
        "the stop asks the switch for nothing: {requests:?}"
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
        super::naming::promote_interim_to_hand(&reg, &present, me, "promo", interim, Some(hand)),
        Some(hand)
    );
    // Absent: the hand is not vouched for, so the interim stands.
    assert_eq!(
        super::naming::promote_interim_to_hand(&reg, &absent, me, "promo", interim, Some(hand)),
        None
    );
    // Only an interim publish with a hand behind it moves.
    assert_eq!(
        super::naming::promote_interim_to_hand(&reg, &present, me, "promo", Some(hand), Some(hand)),
        None
    );
    assert_eq!(
        super::naming::promote_interim_to_hand(&reg, &present, me, "promo", interim, None),
        None
    );

    // Present, the name already this session's own (a resume): the hand.
    reg.publish_own_address(me, "promo", Ipv4Addr::LOCALHOST, BTreeSet::new());
    reg.register_own_ip(me, "promo", BTreeSet::new());
    assert!(reg.name_held_by(me, "promo"));
    assert_eq!(
        super::naming::promote_interim_to_hand(&reg, &present, me, "promo", interim, Some(hand)),
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
        super::naming::promote_interim_to_hand(&reg, &present, me, "promo", interim, Some(hand)),
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
    let finalize =
        crate::traced::spawn(async move { finalize_session(&mut finalize_client, web).await });
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
            .resolve(&format!("web.min.internal:{}", declared_port()))
            .expect("the name routes at the hand")
            .upstream(declared_port()),
        Some(std::net::SocketAddr::new(
            std::net::IpAddr::V4(handed),
            declared_port()
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
    mode: Option<boxes::DynamicIngress>,
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
    request.config.box_addresses = Some(boxes::BoxAddresses {
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
    mode: Option<boxes::DynamicIngress>,
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
    ingress.port_mappings = vec![boxes::PortMapping {
        external_port: 3000,
        internal_port: 3000,
        proto: boxes::IpProto::Tcp,
    }];
    ingress.dynamic_ingress = Some(boxes::DynamicIngress::Allow);
    ingress.dynamic_allowed_range = Some((3000, 3999));
    request.config.box_addresses = Some(boxes::BoxAddresses {
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
pub(crate) async fn read_control_request(stream: &mut tokio::net::UnixStream) -> Option<String> {
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
/// connection, each recorded as `"<request line>\n<body>"`. `pub(crate)`:
/// the fail-closed audit tests drive an unaudited publish's withdrawal
/// through the same stand-in, one whose unexpose the switch refuses.
pub(crate) async fn scripted_forwarder(
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
    let server = crate::traced::spawn(async move {
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
    let server = crate::traced::spawn(async move {
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
            crate::traced::spawn(async move {
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
            Some(boxes::DynamicIngress::Allow),
            Some((3000, 3999)),
        ))
        .await
        .unwrap();
    client
        .call::<CreateSession>(&CreateSessionRequest::new(
            "dyn-bare-logged",
            paths::HostAbsPath::try_new("/uwu").unwrap(),
            boxes::NetworkMode::OwnIp,
            boxes::BoxPolicy::default(),
        ))
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
        Some(boxes::DynamicIngress::Allow),
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
        .get_session(crate::box_manager::BoxKeyPredicate::Id(web))
        .await
        .unwrap()
        .expect("the allowing box resolves");
    let db_handle = manager
        .get_session(crate::box_manager::BoxKeyPredicate::Id(db))
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
        &boxes::PortMapping {
            external_port: 3000,
            internal_port: 3000,
            proto: boxes::IpProto::Tcp,
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
    // Addresses no other test's box uses: the live-gate table the proxy and
    // the expose both read is process-wide.
    let switch = std::net::Ipv4Addr::new(100, 64, 128, 96);
    let loopback = std::net::Ipv4Addr::new(127, 0, 64, 96);
    let web = finalize_dynamic_ingress_session(
        &mut client,
        // This test's own box name: under the shared capture every test's
        // lines ride one buffer, so each assertion finds its line by the
        // box it names.
        "listweb",
        switch,
        loopback,
        Some(boxes::DynamicIngress::Allow),
        Some((3000, 3999)),
    )
    .await;
    let handle = manager
        .get_session(crate::box_manager::BoxKeyPredicate::Id(web))
        .await
        .unwrap()
        .expect("the allowing box resolves");
    handle
        .ensure_host("tester".to_string())
        .await
        .expect("the allowing box launches its host");
    // The box's relay gate, registered under its switch address as the
    // relay's spawn registers it, and the lease its attach reports to the
    // hostname registry: what a direct connection and the proxy both meet.
    let gate = std::sync::Arc::new(crate::net::switch::BoxGate::for_session(
        "listweb".to_string(),
        switch,
        &boxes::BoxPolicy::default(),
        crate::net::SwitchSubnet::default(),
        None,
    ));
    crate::net::switch::register_live_gate_for_test(switch, &gate);
    let hostnames = manager.hostnames();
    hostnames
        .write()
        .expect("registry lock")
        .report_own_address(web, "listweb", switch, std::collections::BTreeMap::new());
    // Before the expose, the proxy refuses the port with the refusal a
    // direct connection gets: the box published nothing at it.
    let before = {
        let route = hostnames
            .read()
            .expect("registry lock")
            .resolve("listweb.min.internal")
            .expect("the box's name resolves");
        crate::net::switch::proxied_request_verdict(None, &route, 3000)
    };
    assert!(
        matches!(before, crate::net::switch::ProxiedRequest::Refused(_)),
        "an unpublished port is refused through the proxy: {before:?}"
    );
    assert!(!gate.admits_tcp(3000));
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
        local: "127.0.64.96:3000".to_string(),
        internal_port: 3000,
        proto: boxes::IpProto::Tcp,
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
                pending: false,
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
    // by id alike — and it reads as reachable: the publish admitted the port
    // at the box's relay gate (NET-044).
    let listed = mapping.clone();
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
            && line.contains("local=127.0.64.96:3000"),
        "the publish line names the box, the port, the decision and the \
         outcome: {line}"
    );
    // The publish is reachable through the hostname proxy at once (NET-044,
    // NET-069): the box's gate admits the port, so the proxy forwards a
    // request for it to the forward the publish bound — the mapping's own
    // `local` — and a request through the proxy reaches what listens there.
    assert!(
        gate.admits_tcp(3000),
        "the publish admits the port at the gate"
    );
    let route = hostnames
        .read()
        .expect("registry lock")
        .resolve("listweb.min.internal")
        .expect("the box's name resolves");
    assert_eq!(
        route.source(3000),
        Some(crate::net::dns::RouteSource::Runtime),
        "the route carries the exposed port as a runtime publish"
    );
    let local: std::net::SocketAddr = mapping.local.parse().expect("the mapping names a socket");
    assert_eq!(
        crate::net::switch::proxied_request_verdict(None, &route, 3000),
        crate::net::switch::ProxiedRequest::Forward(local),
        "the proxy forwards the exposed port to the forward the publish bound"
    );
    // The fake forwarder bound nothing, so this test stands in for the box
    // behind the forward, at the mapping's own address.
    let backend = tokio::net::TcpListener::bind(local)
        .await
        .expect("the mapping's address is free to stand in for the forward");
    crate::traced::spawn(async move {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        while let Ok((mut sock, _)) = backend.accept().await {
            let mut scratch = [0u8; 1024];
            let _ = sock.read(&mut scratch).await;
            let _ = sock
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .await;
        }
    });
    let proxy = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("the proxy binds");
    let proxy_addr = proxy.local_addr().expect("the proxy has an address");
    crate::traced::spawn(crate::net::proxy::serve(
        proxy,
        crate::net::proxy::Router::new(
            std::sync::Arc::clone(&hostnames),
            crate::net::switch::proxied_request_verdict,
        ),
    ));
    let reached = crate::net::proxy::proxy_get(proxy_addr, "listweb.min.internal:3000").await;
    assert!(
        reached.contains("200 OK"),
        "the exposed port opens through the hostname proxy: {reached}"
    );
}

/// NET-044: an expose decided `allow` admits its port at the box's relay
/// gate in the same turn it publishes — reachable, never a bound forward the
/// gate refuses — while a port nobody published stays refused, and the box's
/// stop (the expose's revocation) withdraws the admission. The gate is
/// registered under the box's switch address the way its relay's spawn
/// registers it, so the publish finds it exactly as it does in production.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn expose_allow_admits_the_port_at_the_box_gate_until_stop() {
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let manager = server.state.sessions_manager().await;
    manager.land_range_verdict(crate::net::dns::RangeVerdict::Present);
    // An address no other test's box uses: the live-gate table is
    // process-wide.
    let switch = std::net::Ipv4Addr::new(100, 64, 128, 91);
    let web = finalize_dynamic_ingress_session(
        &mut client,
        "gateweb",
        switch,
        std::net::Ipv4Addr::new(127, 0, 64, 91),
        Some(boxes::DynamicIngress::Allow),
        Some((3000, 3999)),
    )
    .await;
    let handle = manager
        .get_session(crate::box_manager::BoxKeyPredicate::Id(web))
        .await
        .unwrap()
        .expect("the allowing box resolves");
    handle
        .ensure_host("tester".to_string())
        .await
        .expect("the allowing box launches its host");
    let gate = std::sync::Arc::new(crate::net::switch::BoxGate::for_session(
        "gateweb".to_string(),
        switch,
        &boxes::BoxPolicy::default(),
        crate::net::SwitchSubnet::default(),
        None,
    ));
    crate::net::switch::register_live_gate_for_test(switch, &gate);
    let sock = handle
        .net_switch()
        .await
        .unwrap()
        .lock()
        .await
        .control_socket();
    let (forwarder, _served) = fake_forwarder(sock, 200).await;

    assert!(!gate.admits_tcp(3000), "nothing is published yet");
    handle
        .expose_dynamic(3000)
        .await
        .expect("the allowed port publishes");
    assert!(
        gate.admits_tcp(3000),
        "the published port is admitted at the box's relay gate"
    );
    assert!(
        !gate.admits_tcp(3001),
        "a port nobody published stays refused"
    );

    handle.stop().await;
    forwarder.abort();
    assert!(
        !gate.admits_tcp(3000),
        "the box's stop revokes the expose and withdraws its admission"
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
    let door_task = crate::traced::spawn(async move {
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
        Some(boxes::DynamicIngress::Allow),
        Some((3000, 3999)),
    )
    .await;
    let handle = manager
        .get_session(crate::box_manager::BoxKeyPredicate::Id(web))
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
    let expose = crate::traced::spawn(async move { reporting.expose_dynamic(3000).await });
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
            proto: boxes::IpProto::Tcp,
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
            proto: boxes::IpProto::Tcp,
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
            proto: boxes::IpProto::Tcp,
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
        Some(boxes::DynamicIngress::Allow),
        Some((3000, 3999)),
    )
    .await;
    let handle = manager
        .get_session(crate::box_manager::BoxKeyPredicate::Id(web))
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
    let expose = crate::traced::spawn(async move { reporting.expose_dynamic(3000).await });
    let request = tokio::time::timeout(Duration::from_secs(5), reports.recv())
        .await
        .expect("the publish reaches the VM host daemon's report door")
        .expect("the report door stand-in lives");
    assert_eq!(
        request,
        minimald_rpc::BoxControlRequest::AdmitPort(minimald_rpc::AdmitPortRequest {
            switch_address: std::net::Ipv4Addr::new(100, 64, 128, 21),
            port: 3000,
            proto: boxes::IpProto::Tcp,
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
            assert!(
                source
                    .to_string()
                    .contains("the request to open the port was refused"),
                "the refused publish says who refused it: {source}"
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
    let expose = crate::traced::spawn(async move { reporting.expose_dynamic(3000).await });
    let request = tokio::time::timeout(Duration::from_secs(5), reports.recv())
        .await
        .expect("the second ask reaches the VM host daemon's report door")
        .expect("the report door stand-in lives");
    assert_eq!(
        request,
        minimald_rpc::BoxControlRequest::AdmitPort(minimald_rpc::AdmitPortRequest {
            switch_address: std::net::Ipv4Addr::new(100, 64, 128, 21),
            port: 3000,
            proto: boxes::IpProto::Tcp,
            source: minimald_rpc::PortReportSource::Expose,
        }),
        "the port the refusal unwound is publishable again: the set gave it back"
    );
    replies
        .send(minimald_rpc::BoxControlReply::PortRecorded {
            port: 3000,
            proto: boxes::IpProto::Tcp,
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
                && line.contains("session_name=\"vmrefweb\"")
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
    mode: Option<boxes::DynamicIngress>,
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
        Some(boxes::DynamicIngress::Allow),
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
        .get_session(crate::box_manager::BoxKeyPredicate::Id(web))
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
            proto: boxes::IpProto::Tcp,
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
        &boxes::PortMapping {
            external_port: 3000,
            internal_port: 3000,
            proto: boxes::IpProto::Tcp,
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
    // The row reads as reachable: the publish admitted the port at the
    // box's relay gate (NET-044).
    assert_eq!(
        live,
        minimald_rpc::Errorable::Ok(vec![minimald_rpc::LiveMapping {
            pending: Some(false),
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
        Some(boxes::DynamicIngress::Allow),
        Some((3000, 3999)),
    )
    .await;
    let manager = server.state.sessions_manager().await;
    let registry = manager.hostnames();
    let handle = manager
        .get_session(crate::box_manager::BoxKeyPredicate::Id(web))
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
        Some(boxes::DynamicIngress::Deny),
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
            .get_session(crate::box_manager::BoxKeyPredicate::Id(closed))
            .await
            .unwrap()
            .expect("the denying box resolves"),
        manager
            .get_session(crate::box_manager::BoxKeyPredicate::Id(bare))
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

/// NET-070: the session actor registers a host-address box's caller facts
/// through the production path, so the hostname proxy can decide the box's
/// requests from the node's address by its egress rules.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn host_address_box_registers_its_caller_facts() {
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    // The harness default: a host-address box.
    let id = create_configured_session(&mut client, "hostcaller", "/uwu").await;
    let manager = server.state.sessions_manager().await;
    let handle = manager
        .get_session(crate::box_manager::BoxKeyPredicate::Id(id))
        .await
        .unwrap()
        .expect("the host-address box resolves");
    let record = handle.record().await.expect("the record reads");
    assert_eq!(record.network, boxes::NetworkMode::HostNet);

    let registry = manager.hostnames();
    let registry = registry.read().expect("registry lock");
    assert!(
        registry.has_unleased_callers(),
        "a host-address box is a caller with no switch lease"
    );
    assert!(
        registry
            .caller_owning(record.id, std::net::Ipv4Addr::LOCALHOST)
            .is_some(),
        "the proxy can name the host-address box by the socket it owns"
    );
}

/// A host-address box is answered before its stance is read: its record can
/// carry no `dynamic_ingress`, so the stance check alone would deny every
/// request — true of the setting, and wrong about the port, which already
/// answers on the host's network. The answer is the typed needs-no-exposing
/// refusal, not the deny; it makes no decision, so nothing is audited
/// (NET-046), and the request's one info line says what became of it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn expose_host_address_answers_before_the_stance() {
    let capture = crate::test_harness::captured_log();
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    // The harness default: a host-address box that declared nothing.
    let id = create_configured_session(&mut client, "hostweb", "/uwu").await;
    let manager = server.state.sessions_manager().await;
    let handle = manager
        .get_session(crate::box_manager::BoxKeyPredicate::Id(id))
        .await
        .unwrap()
        .expect("the host-address box resolves");
    let record = handle.record().await.expect("the record reads");
    assert_eq!(record.network, boxes::NetworkMode::HostNet);

    match handle.expose_dynamic(3001).await {
        Err(crate::net::policy::ExposeFailure::Refused(
            crate::net::policy::ExposeRefusal::NeedsNoExposing {
                port: 3001,
                // The harness daemon is native, so the host's loopback
                // answers too.
                host_loopback: true,
            },
        )) => {}
        other => panic!("a host-address box's port needs no exposing: {other:?}"),
    }

    let logged = capture.contents();
    let lines: Vec<&str> = logged
        .lines()
        .filter(|line| line.contains("dynamic ingress expose") && line.contains("name=hostweb"))
        .collect();
    assert_eq!(lines.len(), 1, "one line per request, got: {logged}");
    assert!(
        lines[0].contains("port=3001")
            && lines[0].contains("outcome=\"needs no exposing\"")
            && !lines[0].contains("denied"),
        "the line says the port needs no exposing, not that it was denied: {}",
        lines[0]
    );
    let audit = crate::audit::log_path(
        server
            .state
            .minimal_state_dir()
            .await
            .as_utf8_path()
            .as_std_path(),
    );
    assert!(
        tokio::fs::metadata(&audit).await.is_err(),
        "no decision was made, so none is audited"
    );
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
        Some(boxes::DynamicIngress::Allow),
        Some((3000, 3999)),
    )
    .await;
    let manager = server.state.sessions_manager().await;
    let handle = manager
        .get_session(crate::box_manager::BoxKeyPredicate::Id(web))
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
                && line.contains("outcome=\"refused: out of range\"")
                && line.contains("port=4500")
        })
        .unwrap_or_else(|| panic!("the out-of-range refusal must be logged, got: {logged}"));
    assert!(
        refused_line.contains("reason=port 4500 is outside this box's --dynamic-range 3000-3999"),
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

/// NET-047: a port outside the box's `--dynamic-range` is refused with the
/// range named, for an `allow` box and an `ask` box alike. The `ask` box
/// refuses it before any prompt is routed: the same box's in-range request
/// is routed, and with nobody attached it ends as the nobody-to-answer
/// refusal, which an out-of-range request never reaches. Neither box keeps a
/// mapping, and the request's info line says `refused: out of range`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn expose_out_of_range_refusal_names_range() {
    let capture = crate::test_harness::captured_log();
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let manager = server.state.sessions_manager().await;
    for (name, stance, octet) in [
        ("rangeallow", boxes::DynamicIngress::Allow, 41),
        ("rangeask", boxes::DynamicIngress::Ask, 42),
    ] {
        let id = finalize_dynamic_ingress_session(
            &mut client,
            name,
            std::net::Ipv4Addr::new(100, 64, 128, octet),
            std::net::Ipv4Addr::new(127, 0, 64, octet),
            Some(stance),
            Some((3000, 3999)),
        )
        .await;
        let handle = manager
            .get_session(crate::box_manager::BoxKeyPredicate::Id(id))
            .await
            .unwrap()
            .expect("the box resolves");
        let refusal = match handle.expose_dynamic(4500).await {
            Err(crate::net::policy::ExposeFailure::Refused(
                refusal @ crate::net::policy::ExposeRefusal::OutOfRange {
                    requested: 4500,
                    range: (3000, 3999),
                },
            )) => refusal,
            other => panic!("{name}: a port outside the range is refused by range: {other:?}"),
        };
        assert_eq!(
            refusal.for_caller(name, boxes::NetworkMode::OwnIp, 4500),
            "port 4500 is outside this box's --dynamic-range 3000-3999. Nothing was published.",
            "{name}: the refusal names the port and the range"
        );
        if stance == boxes::DynamicIngress::Ask {
            // The in-range ask is routed, and nobody is attached to answer:
            // the out-of-range one above never got that far.
            match handle.expose_dynamic(3000).await {
                Err(crate::net::policy::ExposeFailure::Refused(
                    crate::net::policy::ExposeRefusal::AskNeedsAnswer,
                )) => {}
                other => panic!("an in-range ask is routed to a prompt: {other:?}"),
            }
        }
        let live: minimald_rpc::Errorable<Vec<minimald_rpc::LiveMapping>> = client
            .call::<minimald_rpc::GetLiveIngress>(&minimald_rpc::GetLiveIngressRequest::Id(id))
            .await;
        assert_eq!(
            live,
            minimald_rpc::Errorable::Ok(vec![]),
            "{name}: a refused request leaves no mapping"
        );
    }
    let logged = capture.contents();
    for (name, decision) in [("rangeallow", "allow"), ("rangeask", "ask")] {
        let line = logged
            .lines()
            .find(|line| {
                line.contains("dynamic ingress expose")
                    && line.contains(&format!("name={name}"))
                    && line.contains("port=4500")
            })
            .unwrap_or_else(|| panic!("{name}: the refusal must be logged, got: {logged}"));
        assert!(
            line.contains("outcome=\"refused: out of range\"")
                && line.contains(&format!("decision={decision}"))
                && line
                    .contains("reason=port 4500 is outside this box's --dynamic-range 3000-3999"),
            "{name}: the line names the outcome, the port and the range: {line}"
        );
    }
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
        Some(boxes::DynamicIngress::Allow),
        Some((3000, 3999)),
    )
    .await;
    let db = finalize_dynamic_ingress_session(
        &mut client,
        "clashdb",
        std::net::Ipv4Addr::new(100, 64, 128, 32),
        std::net::Ipv4Addr::new(127, 0, 64, 32),
        Some(boxes::DynamicIngress::Allow),
        Some((3000, 3999)),
    )
    .await;
    let web_handle = manager
        .get_session(crate::box_manager::BoxKeyPredicate::Id(web))
        .await
        .unwrap()
        .expect("the first box resolves");
    let db_handle = manager
        .get_session(crate::box_manager::BoxKeyPredicate::Id(db))
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
        &boxes::PortMapping {
            external_port: 3000,
            internal_port: 3000,
            proto: boxes::IpProto::Tcp,
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
            proto: boxes::IpProto::Tcp,
            // The publish admitted the port at the box's relay gate
            // (NET-044), so the row is never pending.
            pending: Some(false),
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
        Some(boxes::DynamicIngress::Allow),
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
        .get_session(crate::box_manager::BoxKeyPredicate::Id(web))
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
        &boxes::PortMapping {
            external_port: 3000,
            internal_port: 3000,
            proto: boxes::IpProto::Tcp,
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
            proto: boxes::IpProto::Tcp,
            // The publish admitted the port at the box's relay gate
            // (NET-044), so the row is never pending.
            pending: Some(false),
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
        Some(boxes::DynamicIngress::Allow),
        Some((3000, 3999)),
    )
    .await;
    let handle = manager
        .get_session(crate::box_manager::BoxKeyPredicate::Id(web))
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
        .get_session(crate::box_manager::BoxKeyPredicate::Id(web))
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
            && line
                .contains("reason=this box is not running, so there is nothing to open a port on"),
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
        Some(boxes::DynamicIngress::Allow),
        Some((3000, 3999)),
    )
    .await;
    let manager = server.state.sessions_manager().await;
    let registry = manager.hostnames();
    let handle = manager
        .get_session(crate::box_manager::BoxKeyPredicate::Id(web))
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
            && line.contains("reason=this box was given no address on the host to open a port at"),
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
        Some(boxes::DynamicIngress::Allow),
        Some((3000, 3999)),
    )
    .await;
    let web_handle = manager
        .get_session(crate::box_manager::BoxKeyPredicate::Id(web))
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
                pending: false,
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
        .get_session(crate::box_manager::BoxKeyPredicate::Id(closed))
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
        Some(boxes::DynamicIngress::Allow),
        Some((3000, 3999)),
    )
    .await;
    let broken_handle = manager
        .get_session(crate::box_manager::BoxKeyPredicate::Id(broken))
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
fn listen_policy_over(range: (u16, u16)) -> boxes::BoxPolicy {
    boxes::BoxPolicy::new(
        None,
        Some(boxes::IngressPolicy {
            port_mappings: vec![],
            dynamic_allowed_range: Some(range),
            dynamic_ingress: Some(boxes::DynamicIngress::Allow),
        }),
    )
}

/// A listening socket on the any address — the bind a publication's forward
/// can deliver to, so a box's watcher sees the port as the box's own
/// listener.
pub(crate) fn listening_socket() -> std::net::TcpListener {
    std::net::TcpListener::bind((std::net::Ipv4Addr::UNSPECIFIED, 0))
        .expect("bind a listening socket")
}

/// The port `listener` holds.
pub(crate) fn port_of(listener: &std::net::TcpListener) -> u16 {
    listener
        .local_addr()
        .expect("a bound listener names its address")
        .port()
}

/// Awaits `what` until it holds, or fails the proof: the box's watcher polls
/// on its own cadence, so a fact it owes arrives on a later poll, never on
/// the one the caller just missed.
pub(crate) async fn soon(mut what: impl FnMut() -> bool) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while !what() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the box did not reach the awaited state in the bound"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

/// The box's live ingress rows, read until `holds` accepts them, or fails the
/// proof: the watcher commits and withdraws its rows on its own cadence, so a
/// row it owes is read on a later poll, never on the one the caller missed.
async fn listed_once(
    handle: &crate::box_actor::BoxHandle,
    holds: impl Fn(&crate::box_actor::LiveIngressRows) -> bool,
) -> crate::box_actor::LiveIngressRows {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let rows = handle.live_ingress().await.expect("the actor answers");
        if holds(&rows) {
            return rows;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the box's live ingress did not reach the awaited rows in the bound: {rows:?}"
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
pub(crate) async fn box_with_listen_plan(
    client: &mut TestClient,
    manager: &crate::box_manager::BoxManagerHandle,
    name: &str,
    switch: std::net::Ipv4Addr,
    loopback: std::net::Ipv4Addr,
    range: (u16, u16),
) -> (
    crate::box_actor::BoxHandle,
    std::sync::Arc<crate::net::switch::BoxGate>,
    std::sync::Arc<std::sync::Mutex<Vec<String>>>,
) {
    let (handle, gate, served, _gate, _id) = box_with_scripted_plan(
        client,
        manager,
        name,
        true,
        switch,
        loopback,
        range,
        Vec::new(),
    )
    .await;
    (handle, gate, served)
}

/// [`box_with_listen_plan`], over a gated stand-in: the forwarder bound
/// before the launch answers each request with the next answer `script`
/// holds for its port — held answers wait on the gate a test advances, so a
/// test can hold one surface's bind in flight while the other races it for
/// the port — and the box's session id comes back with it, so a test can reach the
/// publication set its launch is running on through the seam.
///
/// `handed` says whether the box is a registered one, its creator handing it
/// `switch` and `loopback` (T66), or a self-allocated one whose registry row
/// the fixture pins at the same pair. A registered box's first launch binds
/// its host-side row and no later launch may run (NET-138), so a test that
/// relaunches the box builds it unhanded.
#[expect(
    clippy::too_many_arguments,
    reason = "a test fixture; each caller names every fact of the box it builds"
)]
async fn box_with_scripted_plan(
    client: &mut TestClient,
    manager: &crate::box_manager::BoxManagerHandle,
    name: &str,
    handed: bool,
    switch: std::net::Ipv4Addr,
    loopback: std::net::Ipv4Addr,
    range: (u16, u16),
    script: Vec<(u16, GateAnswer)>,
) -> (
    crate::box_actor::BoxHandle,
    std::sync::Arc<crate::net::switch::BoxGate>,
    std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    tokio::sync::watch::Sender<u64>,
    boxes::SessionId,
) {
    // The hand vouched for, so the registry publishes the loopback hand's
    // address: both surfaces' forwards bind at the address the box's name
    // answers at, exactly as they do for a production box.
    manager.land_range_verdict(crate::net::dns::RangeVerdict::Present);
    let id = if handed {
        finalize_dynamic_ingress_session(
            client,
            name,
            switch,
            loopback,
            Some(boxes::DynamicIngress::Allow),
            Some(range),
        )
        .await
    } else {
        let id = finalize_self_allocated_dynamic_ingress_session(
            client,
            name,
            Some(boxes::DynamicIngress::Allow),
            Some(range),
        )
        .await;
        // The registry is the only place a self-allocated box's addresses
        // live: pin its publish at `loopback` and its lease at `switch`, so
        // the runtime publish reads the same pair a handed box carries.
        let registry = manager.hostnames();
        let mut registry = registry.write().expect("registry lock");
        registry.publish_own_address(id, name, loopback, std::collections::BTreeSet::new());
        registry.report_own_address(id, name, switch, std::collections::BTreeMap::new());
        id
    };
    let handle = manager
        .get_session(crate::box_manager::BoxKeyPredicate::Id(id))
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
    let gate = std::sync::Arc::new(crate::net::switch::BoxGate::for_session(
        name.to_string(),
        switch,
        &listen_policy_over(range),
        crate::net::SwitchSubnet::default(),
        None,
    ));
    crate::box_actor::listen_plan_seam::seed(
        id,
        crate::box_actor::listen_plan_seam::Seeded {
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

/// NET-046 fails a listen-publish closed, and the failure is not silent:
/// while the audit log refuses the allow's record the runtime-facts reply
/// `min session policy` reads names the permitted port left unpublished,
/// with the log it could not write, and lists no reachable row for it; once
/// the log takes records again the watcher publishes afresh and the
/// warning clears.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn runtime_facts_name_a_listen_the_audit_log_refused() {
    use minimald_rpc::{GetSessionRuntimeFacts, GetSessionRuntimeFactsRequest};
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let manager = server.state.sessions_manager().await;

    // A free port number for the box's range; the listener binds it only
    // once the audit log refuses, so the box's own creation audits freely.
    let port = port_of(&listening_socket());
    let switch = std::net::Ipv4Addr::new(100, 64, 128, 94);
    let loopback = std::net::Ipv4Addr::new(127, 0, 64, 94);
    let (handle, gate, _served, _gate_sender, id) = box_with_scripted_plan(
        &mut client,
        &manager,
        "unaudited",
        true,
        switch,
        loopback,
        (port, port),
        Vec::new(),
    )
    .await;
    let state_dir = server.state.minimal_state_dir().await;
    let state_dir = state_dir.as_utf8_path().as_std_path().to_path_buf();
    let planted = state_dir.join("planted");
    std::fs::create_dir_all(&planted).unwrap();
    std::os::unix::fs::symlink(&planted, state_dir.join("audit")).unwrap();
    let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::UNSPECIFIED, port))
        .expect("bind the box's listener on its range's port");

    listed_once(&handle, |rows| rows.unaudited_listen_ports == vec![port]).await;
    let facts = client
        .call::<GetSessionRuntimeFacts>(&GetSessionRuntimeFactsRequest::Id(id))
        .await
        .unwrap();
    assert_eq!(facts.unaudited_listen_ports, vec![port]);
    assert_eq!(
        facts.audit_log.as_deref(),
        Some(
            crate::audit::log_path(&state_dir)
                .display()
                .to_string()
                .as_str()
        ),
        "the warning names the log that refused the record"
    );
    assert!(
        !gate.admits_tcp(port),
        "the unaudited listen is not admitted"
    );
    assert!(
        handle
            .live_ingress()
            .await
            .expect("the actor answers")
            .listened
            .is_empty(),
        "no reachable row is listed for a port the gate refuses"
    );

    std::fs::remove_file(state_dir.join("audit")).unwrap();
    soon(|| gate.admits_tcp(port)).await;
    listed_once(&handle, |rows| rows.unaudited_listen_ports.is_empty()).await;
    let facts = client
        .call::<GetSessionRuntimeFacts>(&GetSessionRuntimeFactsRequest::Id(id))
        .await
        .unwrap();
    assert!(facts.unaudited_listen_ports.is_empty());
    assert!(facts.audit_log.is_none());
    drop(listener);
}

/// NET-047, the port one surface already holds: whichever of the box's two
/// runtime surfaces reaches a port first, the port is bound once. A port the
/// listen watcher published, asked for by `min net expose`, is answered as
/// published already, at the watcher's address — the switch asked nothing —
/// and a
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

    // The runtime expose asks for the port the watcher holds: answered as
    // published already, at the watcher's address, with nothing bound for
    // it and nothing asked of the switch — the one request so far is the
    // watcher's own publish.
    match handle.expose_dynamic(listen_port).await {
        Err(crate::net::policy::ExposeFailure::Refused(
            crate::net::policy::ExposeRefusal::ListenPublished { port: asked, local },
        )) => {
            assert_eq!(asked, listen_port);
            assert_eq!(local, std::net::SocketAddr::from((loopback, listen_port)));
        }
        other => panic!("a port the watcher published is published already: {other:?}"),
    }
    assert_eq!(
        served_naming(&served, loopback, listen_port).len(),
        1,
        "the answered request asks the switch nothing: {:?}",
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
            proto: boxes::IpProto::Tcp,
            pending: Some(false),
        },
        "the expose binds where the box's watcher binds, at its own port number"
    );
    // Both surfaces' publications are listed (NET-044), each once, by the
    // surface that owns it: the runtime expose's row, and the watcher's row
    // for the in-range listen its box's `allow` stance published. The range
    // spans two ephemeral ports, so other tests' listeners can land in it
    // and be listed too: the listen rows are read for this test's ports.
    let rows = handle.live_ingress().await.expect("the actor answers");
    assert_eq!(
        rows.exposed,
        vec![mapping],
        "the runtime publish is listed as the box's live ingress: {rows:?}"
    );
    assert_eq!(
        rows.listened
            .iter()
            .filter(|row| row.internal_port == listen_port)
            .collect::<Vec<_>>(),
        vec![&minimald_rpc::LiveMapping {
            local: format!("{loopback}:{listen_port}"),
            internal_port: listen_port,
            proto: boxes::IpProto::Tcp,
            pending: Some(false),
        }],
        "the listen publication is listed once as the box's live ingress: {rows:?}"
    );
    assert!(
        rows.listened
            .iter()
            .all(|row| row.internal_port != exposed_port),
        "the exposed port is never also a listen row: {rows:?}"
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
    // The listen's row goes with its publication, and the expose's stays:
    // the set gives the port back once the unexpose stood, so the row is
    // awaited, not assumed.
    let rows = listed_once(&handle, |rows| {
        rows.listened
            .iter()
            .all(|row| row.internal_port != listen_port)
    })
    .await;
    assert_eq!(
        rows.exposed
            .iter()
            .map(|row| row.internal_port)
            .collect::<Vec<_>>(),
        vec![exposed_port],
        "the expose's row outlives the listen's: {rows:?}"
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
    // watcher's publish, the expose's publish, the published-already answer
    // the expose gave, and the skip the watcher settled on — each naming its
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
    let answer_line = logged
        .lines()
        .find(|line| {
            line.contains("name=ownboth")
                && line.contains("dynamic ingress expose")
                && line.contains("outcome=\"published already\"")
                && line.contains(&format!("port={listen_port}"))
        })
        .unwrap_or_else(|| panic!("the published-already answer is one line, got: {logged}"));
    assert!(
        answer_line.contains("owner=listen")
            && answer_line.contains(&format!(
                "reason=port {listen_port} is published already at {loopback}:{listen_port}"
            )),
        "the answer names the owner that holds the port and the reason it \
         gave: {answer_line}"
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

/// A port the box's listen watcher published, asked for by the box's own
/// `min net expose`, is the goal met rather than a refusal: the request is
/// answered with the address the port answers at, the switch is asked
/// nothing, the request is one line naming the listener's publication as
/// the one standing, and its decision is one `published` record (NET-046).
/// The publication stays the listener's: when the listener closes, the
/// watcher withdraws it (NET-017), and the expose left nothing of its own
/// to outlive it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn expose_on_listen_published_port_answers_published_already() {
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

    // The watcher publishes the port; the answer reads the shared set the
    // publication wrote, so wait on the admission that follows it.
    soon(|| gate.admits_tcp(port)).await;
    match handle.expose_dynamic(port).await {
        Err(crate::net::policy::ExposeFailure::Refused(
            refusal @ crate::net::policy::ExposeRefusal::ListenPublished { port: asked, local },
        )) => {
            assert_eq!(asked, port);
            assert_eq!(
                local,
                std::net::SocketAddr::from((loopback, port)),
                "the answer names where the listener's publication answers"
            );
            assert_eq!(
                refusal.for_caller("ownlisten", boxes::NetworkMode::OwnIp, port),
                format!(
                    "port {port} is published already at {loopback}:{port}, because a \
                     process in this box is listening on it. It is unpublished when that \
                     process stops listening on it."
                ),
                "the in-box line says the port is published, and for how long"
            );
        }
        other => panic!("the runtime expose answers the listener's publication: {other:?}"),
    }

    // One request, the watcher's publish: the expose bound nothing, and the
    // box lists the port once — the watcher's row for the listen its
    // `allow` stance published (NET-044), never a row for the expose.
    let requests = served_naming(&served, loopback, port);
    assert_eq!(requests.len(), 1, "the port was bound once: {requests:?}");
    assert!(
        requests[0].starts_with("POST /services/forwarder/expose "),
        "the one bind is the watcher's publish: {requests:?}"
    );
    assert_eq!(
        handle.live_ingress().await.expect("the actor answers"),
        crate::box_actor::LiveIngressRows {
            exposed: Vec::new(),
            listened: vec![minimald_rpc::LiveMapping {
                local: format!("{loopback}:{port}"),
                internal_port: port,
                proto: boxes::IpProto::Tcp,
                pending: Some(false),
            }],
            unaudited_listen_ports: Vec::new(),
        },
        "the expose published nothing of its own; the listen's publication is listed once"
    );

    // The request is one line naming the port, the owner whose publication
    // stands, and the reason it is answered as published.
    let logged = capture.contents();
    let line = logged
        .lines()
        .find(|line| {
            line.contains("dynamic ingress expose")
                && line.contains("name=ownlisten")
                && line.contains("outcome=\"published already\"")
        })
        .unwrap_or_else(|| panic!("the request is one line, got: {logged}"));
    assert!(
        line.contains(&format!("port={port}"))
            && line.contains("owner=listen")
            && line.contains(&format!(
                "reason=port {port} is published already at {loopback}:{port}"
            )),
        "the line names the port, the owner holding it, and the reason: {line}"
    );

    // The decision is recorded beside the watcher's own record: published,
    // decided by the box's policy, with the reason the caller read.
    let log = crate::audit::log_path(
        server
            .state
            .minimal_state_dir()
            .await
            .as_utf8_path()
            .as_std_path(),
    );
    let text = tokio::fs::read_to_string(&log).await.unwrap_or_default();
    let records: Vec<serde_json_lenient::Value> = text
        .lines()
        .map(|line| serde_json_lenient::from_str(line).expect("one line is one record"))
        .filter(|record: &serde_json_lenient::Value| {
            record["box"] == "ownlisten" && record["reason"].is_string()
        })
        .collect();
    assert_eq!(records.len(), 1, "the expose is one record: {text}");
    assert_eq!(records[0]["port"], port);
    assert_eq!(records[0]["decision"], "allow");
    assert_eq!(records[0]["decided_by"], "box-policy");
    assert_eq!(records[0]["outcome"], "published");

    // A closing listener's withdrawal refuses the port at the gate before
    // its row leaves the set. In that gap the expose is not answered as
    // published: the port is not reachable, so it is the refusal. The
    // relay publishes its gate under the box's switch address at spawn;
    // this harness has no relay, so the test publishes the plan's gate.
    crate::net::switch::register_live_gate_for_test(switch, &gate);
    gate.withdraw_published(port);
    match handle.expose_dynamic(port).await {
        Err(crate::net::policy::ExposeFailure::Refused(
            crate::net::policy::ExposeRefusal::AlreadyPublished { port: asked, .. },
        )) => assert_eq!(asked, port),
        other => panic!("a withdrawing listen's port is not published: {other:?}"),
    }

    // The listener closes: the watcher withdraws its publication (NET-017),
    // the gate stops admitting the port, and no row is left — the expose
    // held nothing that outlives the listener.
    drop(listener);
    soon(|| served_naming(&served, loopback, port).len() == 2).await;
    let requests = served_naming(&served, loopback, port);
    assert!(
        requests[1].starts_with("POST /services/forwarder/unexpose "),
        "the withdrawal is the listener's own: {requests:?}"
    );
    soon(|| !gate.admits_tcp(port)).await;
    listed_once(&handle, |rows| {
        rows.listened.is_empty() && rows.exposed.is_empty()
    })
    .await;

    // The box stops with nothing of the port left to take down.
    handle.stop().await;
    assert_eq!(
        served_naming(&served, loopback, port).len(),
        2,
        "nothing else ever named the port: {:?}",
        served.lock().expect("served lock")
    );
}

/// NET-044 and NET-046 for the listen surface: an in-range listen under
/// `allow` is a dynamic ingress request the box's stance decided, so the
/// publication the watcher makes of it is listed by `min session policy`'s
/// RPC — reachable, because the watcher admitted it at the gate — until the
/// listener closes, and its decision lands in the daemon's audit log as one
/// record, decided by the box's policy, outcome published.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn listen_publication_is_listed_and_audited() {
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let manager = server.state.sessions_manager().await;

    let listener = listening_socket();
    let port = port_of(&listener);
    let switch = std::net::Ipv4Addr::new(100, 64, 128, 76);
    let loopback = std::net::Ipv4Addr::new(127, 0, 64, 76);
    let (handle, gate, served) = box_with_listen_plan(
        &mut client,
        &manager,
        "listedlisten",
        switch,
        loopback,
        (port, port),
    )
    .await;
    soon(|| gate.admits_tcp(port)).await;

    // The listing: the RPC `min session policy` reads serves the watcher's
    // row, by name, reachable.
    let row = minimald_rpc::LiveMapping {
        local: format!("{loopback}:{port}"),
        internal_port: port,
        proto: boxes::IpProto::Tcp,
        pending: Some(false),
    };
    let listed: minimald_rpc::Errorable<Vec<minimald_rpc::LiveMapping>> = client
        .call::<minimald_rpc::GetLiveIngress>(&minimald_rpc::GetLiveIngressRequest::Name(
            "listedlisten".to_string(),
        ))
        .await;
    assert_eq!(
        listed,
        minimald_rpc::Errorable::Ok(vec![row]),
        "the in-range listen is listed as the box's live ingress"
    );

    // The audit: one record for the one publish. The record follows the
    // gate's admission inside the same poll, so it is awaited, not assumed.
    let log = crate::audit::log_path(
        server
            .state
            .minimal_state_dir()
            .await
            .as_utf8_path()
            .as_std_path(),
    );
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let text = loop {
        let text = tokio::fs::read_to_string(&log).await.unwrap_or_default();
        if text.contains("\"listedlisten\"") {
            break text;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the publish was never audited: {text}"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    };
    let records: Vec<serde_json_lenient::Value> = text
        .lines()
        .map(|line| serde_json_lenient::from_str(line).expect("one line is one record"))
        .filter(|record: &serde_json_lenient::Value| record["box"] == "listedlisten")
        .collect();
    assert_eq!(records.len(), 1, "one publish, one record: {text}");
    assert_eq!(records[0]["port"], port);
    assert_eq!(records[0]["decision"], "allow");
    assert_eq!(records[0]["decided_by"], "box-policy");
    assert_eq!(records[0]["outcome"], "published");

    // The close: the row goes with the listener.
    drop(listener);
    soon(|| served_naming(&served, loopback, port).len() == 2).await;
    listed_once(&handle, |rows| rows.listened.is_empty()).await;
    let after: minimald_rpc::Errorable<Vec<minimald_rpc::LiveMapping>> = client
        .call::<minimald_rpc::GetLiveIngress>(&minimald_rpc::GetLiveIngressRequest::Name(
            "listedlisten".to_string(),
        ))
        .await;
    assert_eq!(
        after,
        minimald_rpc::Errorable::Ok(Vec::new()),
        "a closed listener's publication is no longer listed"
    );
    handle.stop().await;
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

/// One port, one row: a port the box's runtime expose published and its own
/// process then listens on is listed once, as the expose's row. The watcher
/// never lists it as a listen and never audits a listen publish of it, and
/// the listener's close leaves the expose's row standing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_exposed_port_listened_on_is_one_expose_row() {
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let manager = server.state.sessions_manager().await;

    let port = port_of(&listening_socket());
    let switch = std::net::Ipv4Addr::new(100, 64, 128, 77);
    let loopback = std::net::Ipv4Addr::new(127, 0, 64, 77);
    let (handle, _gate, served) = box_with_listen_plan(
        &mut client,
        &manager,
        "onerow",
        switch,
        loopback,
        (port, port),
    )
    .await;

    handle
        .expose_dynamic(port)
        .await
        .expect("the free port publishes");
    let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::UNSPECIFIED, port))
        .expect("the box's process listens on the exposed port");

    // Every read across several of the watcher's polls, with the listener
    // standing and after it closes: the expose's row, and no listen row.
    let mut listener = Some(listener);
    for phase in ["listening", "listener closed"] {
        if phase == "listener closed" {
            drop(listener.take());
        }
        let until = tokio::time::Instant::now() + Duration::from_millis(900);
        while tokio::time::Instant::now() < until {
            let rows = handle.live_ingress().await.expect("the actor answers");
            let exposed: Vec<u16> = rows.exposed.iter().map(|row| row.internal_port).collect();
            assert!(
                rows.listened.is_empty() && exposed == vec![port],
                "{phase}: one expose row, no listen row: {rows:?}"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
    assert_eq!(
        served_naming(&served, loopback, port).len(),
        1,
        "the expose's bind is the only request the port got"
    );

    // The audit log holds the expose's one decision for the port, and no
    // listen publish record beside it.
    let log = crate::audit::log_path(
        server
            .state
            .minimal_state_dir()
            .await
            .as_utf8_path()
            .as_std_path(),
    );
    let text = tokio::fs::read_to_string(&log)
        .await
        .expect("the expose was audited");
    let records: Vec<serde_json_lenient::Value> = text
        .lines()
        .map(|line| serde_json_lenient::from_str(line).expect("one line is one record"))
        .filter(|record: &serde_json_lenient::Value| record["box"] == "onerow")
        .collect();
    assert_eq!(records.len(), 1, "the expose's record alone: {text}");
    assert_eq!(records[0]["port"], port);
    assert_eq!(records[0]["outcome"], "published");

    handle.stop().await;
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
        Some(boxes::DynamicIngress::Allow),
        Some((seeded_port.min(bare_port), seeded_port.max(bare_port))),
    )
    .await;
    let bare = manager
        .get_session(crate::box_manager::BoxKeyPredicate::Id(bare_id))
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
    // same one the watcher wrote, and answers it published already.
    match seeded.expose_dynamic(seeded_port).await {
        Err(crate::net::policy::ExposeFailure::Refused(
            crate::net::policy::ExposeRefusal::ListenPublished { port: asked, .. },
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
        true,
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
        crate::traced::spawn(async move { handle.expose_dynamic(a_port).await })
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
                pending: true,
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
                "reason=port {b_port} is being published by this box (listen)"
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
        true,
        switch,
        loopback,
        (port, port),
        Vec::new(),
    )
    .await;
    let publications = crate::box_actor::listen_plan_seam::publications_of(id)
        .expect("the launch handed its publication set back");

    // The publish a cancellation drops: a reservation on the box's real
    // set, held across a bind that never resolves — the shape of the
    // expose path's own in-flight bind, aborted before it could record.
    let holder = {
        let publications = publications.clone();
        crate::traced::spawn(async move {
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
        true,
        switch,
        loopback,
        (a_port, b_port),
        vec![
            (a_port, GateAnswer::Held(200)), // 1: the expose's bind on `a`
            (b_port, GateAnswer::Held(200)), // 2: the watcher's bind on `b`
        ],
    )
    .await;
    let publications = crate::box_actor::listen_plan_seam::publications_of(id)
        .expect("the launch handed its publication set back");

    // The expose surface: its bind on `a` is held at the stand-in, the set
    // is revoked under it, and the bind then stands.
    let exposing = {
        let handle = handle.clone();
        crate::traced::spawn(async move { handle.expose_dynamic(a_port).await })
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
        true,
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
    let publications = crate::box_actor::listen_plan_seam::publications_of(id)
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
/// duplicate the fresh set says it is. The box is unhanded: a registered
/// box is never relaunched (NET-138), and the set's ownership does not
/// depend on registration.
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
        false,
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
    crate::box_actor::listen_plan_seam::seed(
        id,
        crate::box_actor::listen_plan_seam::Seeded {
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
    // and the expose asking after it is answered published already, as the
    // fresh set says it is.
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
    crate::box_actor::listen_plan_seam::seed(
        id,
        crate::box_actor::listen_plan_seam::Seeded {
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
            crate::net::policy::ExposeRefusal::ListenPublished { port: asked, .. },
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
    handle: crate::box_actor::BoxHandle,
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
        Some(boxes::DynamicIngress::Allow),
        Some((3000, 3999)),
    )
    .await;
    let handle = manager
        .get_session(crate::box_manager::BoxKeyPredicate::Id(id))
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
    let expose = crate::traced::spawn(async move { reporting.expose_dynamic(3000).await });
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
            proto: boxes::IpProto::Tcp,
        })
        .expect("the report door stand-in lives");
    let withdrawal = next_report(&mut reports).await;
    assert_eq!(
        withdrawal,
        minimald_rpc::BoxControlRequest::WithdrawPort(minimald_rpc::WithdrawPortRequest {
            switch_address: std::net::Ipv4Addr::new(100, 64, 128, 23),
            port: 3000,
            proto: boxes::IpProto::Tcp,
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
            proto: boxes::IpProto::Tcp,
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
    let expose = crate::traced::spawn(async move { reporting.expose_dynamic(3000).await });
    assert!(matches!(
        next_report(&mut reports).await,
        minimald_rpc::BoxControlRequest::AdmitPort(_)
    ));
    replies
        .send(minimald_rpc::BoxControlReply::PortRecorded {
            port: 3000,
            proto: boxes::IpProto::Tcp,
        })
        .expect("the report door stand-in lives");
    expose
        .await
        .expect("the expose task should not panic")
        .expect("the admitted port publishes");

    let stopping = handle.clone();
    let stop = crate::traced::spawn(async move { stopping.stop().await });
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
            proto: boxes::IpProto::Tcp,
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

/// A `Hooks`-origin host whose record holds a registered host-side row is not
/// replaced for an attaching terminal: ending its PTask would end the shuttle
/// connection the row is tied to, and the in-VM daemon cannot re-register it.
#[test]
fn replaces_host_for_terminal_skips_a_registered_box() {
    use super::{HostOrigin, replaces_host_for_terminal};
    assert!(!replaces_host_for_terminal(HostOrigin::Hooks, true, true));
}

/// Without a host-side row the respawn behaviour is unchanged: a
/// `Hooks`-origin host with a terminal-declaring attach is replaced, and no
/// other origin is replaced regardless.
#[test]
fn replaces_host_for_terminal_keeps_native_respawn() {
    use super::{HostOrigin, replaces_host_for_terminal};
    assert!(replaces_host_for_terminal(HostOrigin::Hooks, true, false));
    assert!(!replaces_host_for_terminal(HostOrigin::Hooks, false, false));
    assert!(!replaces_host_for_terminal(HostOrigin::Exec, true, false));
    assert!(!replaces_host_for_terminal(
        HostOrigin::Interactive,
        true,
        false
    ));
}

/// The wiring behind `replaces_host_for_terminal_skips_a_registered_box`: a
/// hook-launched host for a box whose record holds a host-side row (its
/// creator handed it `box_addresses`) is kept when a terminal attaches, so the
/// box is launched exactly once, and the terminal's `TERM` reaches the kept
/// shell through the republished attach-env file instead. The box without a
/// row is `a_hook_launched_shell_takes_the_attaching_terminals_term`.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_hook_launched_shell_of_a_registered_box_is_kept_for_a_terminal() {
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("activated");
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let id = create_handed_own_ip_session_with_hook(
        &mut client,
        "hooked-kept",
        std::net::Ipv4Addr::new(100, 64, 128, 23),
        std::net::Ipv4Addr::new(127, 0, 64, 23),
        boxes::wire::primitives::WireLifecycleHook {
            on_activate: Some(inline(marker_body(&marker))),
            ..Default::default()
        },
    )
    .await;
    finalize_session(&mut client, id).await;
    assert!(
        marker.exists(),
        "the activate hook should have brought a host up headlessly"
    );
    assert_eq!(
        super::launch_publish_seam::observed(id).len(),
        1,
        "the activate hook launches the box once"
    );

    let mut channel = client.open_shell_with_term(id, "xterm-256color").await;
    await_echo(&mut channel).await;

    assert_eq!(
        super::launch_publish_seam::observed(id).len(),
        1,
        "a terminal attach must not relaunch a box that holds a host-side row"
    );
    let published = published_attach_env(&server, id).await;
    assert!(
        published.contains("export TERM='xterm-256color'"),
        "the kept shell takes the terminal's TERM through the republished \
         attach-env; got: {published:?}"
    );
}

/// BEP-015: a GitHub grant box carries a git credential helper. With the
/// launch's command-scope git configuration, `git credential fill` answers
/// for each grant host with the sealed value as the password, so git sends
/// it in an `Authorization` header the proxy substitutes. The helper is
/// git's sole helper for those hosts: a `store` helper in `~/.gitconfig` and
/// in a repository configuration does not run for them, so `git credential
/// approve` writes nothing to `~/.git-credentials` (Gatehouse §6.4 line
/// 718). A host outside the grant gets no answer from the helper. Each
/// answer is logged by host, never by value. The box's git configuration
/// files stay as they are. A box with no grant, or with a value that a shell
/// can read as code, gets no helper and no git configuration.
#[test]
fn grant_box_git_credential_helper_answers_for_grant_hosts() {
    use super::bep_git_helper::{
        HELPER_CONFIG_REL, HELPER_DIR_REL, HELPER_LOG_MAX_BYTES, HELPER_LOG_REL, HELPER_REL,
        Installed, grant_hosts, install, launch_git_config_env,
    };
    const SEALED: &str = "eyJ0eXAiOiJ4In0..aXY.Y3Q.dGFn";
    let delivery = |sealed: &str| boxes::SealedDelivery {
        variable: "GH_TOKEN".to_string(),
        sealed: sealed.to_string(),
    };
    let hosts = grant_hosts();
    assert_eq!(hosts.len(), bep::module::GITHUB.hosts.len());
    assert!(hosts.iter().any(|host| host == "github.com"), "{hosts:?}");

    let home = tempfile::tempdir().unwrap();
    // The box's own configuration: a `store` helper in `~/.gitconfig` and in
    // a repository, which must not run for a grant host.
    let gitconfig = home.path().join(".gitconfig");
    let own_config = "[user]\n\tname = Box User\n[credential]\n\thelper = store\n";
    std::fs::write(&gitconfig, own_config).unwrap();
    let repo = home.path().join("repo");
    std::fs::create_dir_all(&repo).unwrap();
    let init = std::process::Command::new("git")
        .args(["init", "-q"])
        .current_dir(&repo)
        .env("HOME", home.path())
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .unwrap();
    assert!(init.status.success(), "{init:?}");
    let repo_config = repo.join(".git/config");
    let mut config = std::fs::read_to_string(&repo_config).unwrap();
    config.push_str("[credential]\n\thelper = store\n");
    std::fs::write(&repo_config, config).unwrap();
    let credentials = home.path().join(".git-credentials");

    // No helper yet, so the launch sets no git configuration.
    assert!(launch_git_config_env(home.path(), 0, [SEALED]).is_empty());
    assert_eq!(
        install(home.path(), &[delivery(SEALED)]).unwrap(),
        Installed::Written
    );
    assert_eq!(
        install(home.path(), &[delivery(SEALED)]).unwrap(),
        Installed::Written
    );
    assert_eq!(std::fs::read_to_string(&gitconfig).unwrap(), own_config);
    assert!(!home.path().join(".config/git/config").exists());

    // The pairs follow the ones the box environment already holds.
    let shifted = launch_git_config_env(home.path(), 2, [SEALED]);
    assert!(
        shifted.contains(&(
            "GIT_CONFIG_COUNT".to_string(),
            (2 + hosts.len() * 2).to_string()
        )),
        "{shifted:?}"
    );
    assert!(
        shifted.iter().any(|(key, _)| key == "GIT_CONFIG_KEY_2"),
        "{shifted:?}"
    );
    let git_env = launch_git_config_env(home.path(), 0, [SEALED]);
    assert!(
        git_env.contains(&(
            "GIT_CONFIG_COUNT".to_string(),
            (hosts.len() * 2).to_string()
        )),
        "{git_env:?}"
    );
    let git = |verb: &str, input: String| {
        let mut child = std::process::Command::new("git")
            .args(["credential", verb])
            .current_dir(&repo)
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("HOME", home.path())
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_TERMINAL_PROMPT", "0")
            .envs(git_env.iter().cloned())
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("git runs");
        std::io::Write::write_all(child.stdin.as_mut().unwrap(), input.as_bytes()).unwrap();
        child.wait_with_output().unwrap()
    };
    let fill = |host: &str| git("fill", format!("protocol=https\nhost={host}\n\n"));
    let approve = |host: &str| {
        git(
            "approve",
            format!("protocol=https\nhost={host}\nusername=x-access-token\npassword={SEALED}\n\n"),
        )
    };
    for host in &hosts {
        let output = fill(host);
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success(),
            "{host}: {stdout} {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            stdout.contains(&format!("password={SEALED}\n")),
            "{host}: {stdout}"
        );
        assert!(
            stdout.contains("username=x-access-token\n"),
            "{host}: {stdout}"
        );
        let output = approve(host);
        assert!(output.status.success(), "{host}: {output:?}");
        assert!(
            !credentials.exists(),
            "{host}: a store helper ran and wrote {}",
            std::fs::read_to_string(&credentials).unwrap_or_default()
        );
    }
    let output = fill("example.com");
    assert!(
        !String::from_utf8_lossy(&output.stdout).contains(SEALED),
        "a host outside the grant gets the sealed value"
    );
    assert!(
        !output.status.success(),
        "git found a credential for example.com"
    );
    // The box's own `store` helper still runs for a host outside the grant,
    // so the checks above are not empty.
    assert!(approve("example.com").status.success());
    let stored = std::fs::read_to_string(&credentials).unwrap();
    assert!(stored.contains("example.com"), "{stored}");
    assert!(!stored.contains("github.com"), "{stored}");

    let log = std::fs::read_to_string(home.path().join(HELPER_LOG_REL)).unwrap();
    assert_eq!(log.lines().count(), hosts.len(), "{log}");
    for host in &hosts {
        assert!(
            log.contains(&format!("answered for host {host}\n")),
            "{log}"
        );
    }
    assert!(!log.contains(SEALED), "the log holds the value: {log}");

    // The log does not grow without bound: past its cap it moves to `.1`.
    let log_path = home.path().join(HELPER_LOG_REL);
    std::fs::write(&log_path, vec![b'x'; HELPER_LOG_MAX_BYTES as usize + 1]).unwrap();
    assert!(fill("github.com").status.success());
    let log = std::fs::read_to_string(&log_path).unwrap();
    assert_eq!(log.lines().count(), 1, "{log}");
    assert!(log.contains("answered for host github.com\n"), "{log}");
    let rotated = std::fs::metadata(log_path.with_extension("log.1")).unwrap();
    assert_eq!(rotated.len(), HELPER_LOG_MAX_BYTES + 1);

    // A box with no grant, or a value that is not inert, gets no helper.
    let plain = tempfile::tempdir().unwrap();
    assert_eq!(install(plain.path(), &[]).unwrap(), Installed::NoGrant);
    assert_eq!(
        install(plain.path(), &[delivery("x'; touch /tmp/owned #")]).unwrap(),
        Installed::Refused
    );
    assert!(!plain.path().join(HELPER_REL).exists());
    assert!(launch_git_config_env(plain.path(), 0, [SEALED]).is_empty());

    // A start that no longer has a usable grant removes the helper an
    // earlier start wrote.
    assert_eq!(
        install(home.path(), &[delivery("x'; touch /tmp/owned #")]).unwrap(),
        Installed::Refused
    );
    assert!(!home.path().join(HELPER_REL).exists());
    assert!(!home.path().join(HELPER_CONFIG_REL).exists());
    assert!(launch_git_config_env(home.path(), 0, [SEALED]).is_empty());
    assert_eq!(
        install(home.path(), &[delivery(SEALED)]).unwrap(),
        Installed::Written
    );
    assert_eq!(install(home.path(), &[]).unwrap(), Installed::NoGrant);
    assert!(!home.path().join(HELPER_REL).exists());

    // A write that fails removes the helper an earlier start wrote, so the
    // launch does not name it: here a directory sits at the config's name.
    assert_eq!(
        install(home.path(), &[delivery(SEALED)]).unwrap(),
        Installed::Written
    );
    std::fs::remove_file(home.path().join(HELPER_CONFIG_REL)).unwrap();
    std::fs::create_dir_all(home.path().join(HELPER_CONFIG_REL).join("blocker")).unwrap();
    assert!(install(home.path(), &[delivery(SEALED)]).is_err());
    assert!(!home.path().join(HELPER_REL).exists());
    assert!(launch_git_config_env(home.path(), 0, [SEALED]).is_empty());
    std::fs::remove_dir_all(home.path().join(HELPER_CONFIG_REL)).unwrap();

    // A helper that this start did not write does not count: the launch
    // names the helper only when it answers with a value this launch
    // places, as when a removal after a failed write fails too.
    assert_eq!(
        install(home.path(), &[delivery(SEALED)]).unwrap(),
        Installed::Written
    );
    assert!(launch_git_config_env(home.path(), 0, ["eyJuZXcifQ..bmV3.dmFs.dGFn"]).is_empty());
    assert!(launch_git_config_env(home.path(), 0, std::iter::empty()).is_empty());
    assert!(!launch_git_config_env(home.path(), 0, ["GH_HOST", SEALED]).is_empty());

    // The box's user owns its home. A symbolic link on a path the helper
    // writes is refused, and nothing is written through it.
    let outside = tempfile::tempdir().unwrap();
    let linked_dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(linked_dir.path().join(".local/state")).unwrap();
    std::os::unix::fs::symlink(outside.path(), linked_dir.path().join(HELPER_DIR_REL)).unwrap();
    assert!(install(linked_dir.path(), &[delivery(SEALED)]).is_err());
    assert!(install(linked_dir.path(), &[]).is_err());
    assert_eq!(std::fs::read_dir(outside.path()).unwrap().count(), 0);
    assert!(launch_git_config_env(linked_dir.path(), 0, [SEALED]).is_empty());

    let linked_helper = tempfile::tempdir().unwrap();
    let helper_target = outside.path().join("helper");
    std::fs::write(&helper_target, "keep").unwrap();
    std::fs::create_dir_all(linked_helper.path().join(HELPER_DIR_REL)).unwrap();
    std::os::unix::fs::symlink(&helper_target, linked_helper.path().join(HELPER_REL)).unwrap();
    assert_eq!(
        install(linked_helper.path(), &[delivery(SEALED)]).unwrap(),
        Installed::Written
    );
    assert_eq!(std::fs::read_to_string(&helper_target).unwrap(), "keep");
    assert!(
        !std::fs::symlink_metadata(linked_helper.path().join(HELPER_REL))
            .unwrap()
            .file_type()
            .is_symlink()
    );
}

/// The events of one package build named `package`, whose output ends in
/// `lines`, as the build side-op's pump sees them (NET-155).
fn build_events(package: &str, lines: &[&str]) -> Vec<orchestrator::BuildEvent> {
    let start = orchestrator::BuildEvent {
        idx: 7,
        inner: orchestrator::BuildEventInner::Start {
            name: package.to_string(),
            full_build: true,
            spec_hash: "0".repeat(64),
        },
    };
    std::iter::once(start)
        .chain(lines.iter().map(|line| orchestrator::BuildEvent {
            idx: 7,
            inner: orchestrator::BuildEventInner::Log {
                is_stderr: true,
                line: (*line).to_string(),
            },
        }))
        .collect()
}

/// NET-155: a box's package build runs in the box's own classifier leaf,
/// so the box's egress verdict decides it. A deny-all box's build that
/// cannot reach its download is reported as refused by the box's rules. A
/// box allowed the destination is placed in its allow leaf, and its build
/// is never reported as refused. A box never placed in a leaf builds in the
/// daemon's own cgroup, as before. A placed box whose leaf is gone has its
/// build refused, never run outside its egress verdict.
#[test]
fn box_package_build_under_box_egress_verdict() {
    use crate::box_ops::{BuildPlacement, BuildTap};
    use sandbox::config::Verdict;

    let tree = tempfile::tempdir().unwrap();
    let root = tree.path();
    // A box never placed in a leaf builds in the daemon's own cgroup.
    assert_eq!(
        super::setup::box_build_leaf(root, "sealed", "sealed", false),
        Ok(None)
    );
    // A placed box whose leaf is gone fails closed: its build is refused.
    assert_eq!(
        super::setup::box_build_leaf(root, "sealed", "sealed", true),
        Err(
            "the build for box sealed did not start: box sealed runs under \
             egress rules, and its shell is not running to apply them to the \
             build. Run `min session attach sealed` to start its shell, then \
             run the build again."
                .to_string()
        )
    );

    let deny_dir = sandbox::classifier::box_leaf(root, "sealed", Verdict::Deny);
    std::fs::create_dir_all(&deny_dir).unwrap();
    let allow_dir = sandbox::classifier::box_leaf(root, "open", Verdict::Allow);
    std::fs::create_dir_all(&allow_dir).unwrap();

    let sealed = super::setup::box_build_leaf(root, "sealed", "sealed", true)
        .unwrap()
        .expect("the deny-all box's leaf");
    assert_eq!(sealed.dir(), deny_dir);
    assert!(sealed.is_deny());
    let open = super::setup::box_build_leaf(root, "open", "open", true)
        .unwrap()
        .expect("the allowed box's leaf");
    assert_eq!(open.dir(), allow_dir);
    assert!(!open.is_deny());

    let download = [
        "curl: (6) Could not resolve host: downloads.example.org",
        "build command failed",
    ];
    // The error the build returns, as the daemon receives it.
    let failed = |package: &str| {
        mctx::Error::from(orchestrator::Error::BuildFailed(
            package.to_string(),
            op::Error::Other(anyhow::anyhow!("build command failed")),
        ))
        .to_string()
    };
    let run = |name: &str, leaf| {
        let placement = BuildPlacement {
            box_name: name.to_string(),
            leaf,
            network: None,
        };
        let mut tap = BuildTap::default();
        for event in build_events("fetcher", &download) {
            tap.observe(&event, &placement);
        }
        tap.refusal(&placement, &failed("fetcher"))
    };
    assert_eq!(
        run("sealed", Some(sealed.clone())).as_deref(),
        Some(
            "the build of fetcher could not reach downloads.example.org: \
             the egress rules of box sealed do not allow it"
        )
    );
    assert_eq!(run("open", Some(open)), None);
    assert_eq!(run("unplaced", None), None);

    // Only the build that failed is read. A package that printed a failed
    // download and still built is not blamed when another package fails.
    let placement = BuildPlacement {
        box_name: "sealed".to_string(),
        leaf: Some(sealed),
        network: None,
    };
    let mut tap = BuildTap::default();
    let other = build_events("compiler", &["error: cc failed"])
        .into_iter()
        .map(|mut event| {
            event.idx = 8;
            event
        });
    for event in build_events("fetcher", &download).into_iter().chain(other) {
        tap.observe(&event, &placement);
    }
    assert_eq!(tap.refusal(&placement, &failed("compiler")), None);
    assert!(tap.refusal(&placement, &failed("fetcher")).is_some());
    // An error that names no build reports no refusal.
    assert_eq!(tap.refusal(&placement, "the build was cancelled"), None);
}

/// NET-155: a package that declares a web source fetches it in its box's
/// classifier leaf, so the box's egress verdict decides the fetch. The build
/// of a deny-all box fails, and its error names the source host and the box,
/// on the build side operation and on the in-box patched build. A box whose
/// leaf allows the host builds the package. The fetcher stands in for the
/// kernel's verdict: a leaf in the deny subtree is refused the connection,
/// in the words the placed download reports.
#[tokio::test]
async fn box_build_web_source_under_box_verdict() {
    use crate::box_ops::{BuildPlacement, BuildTap};
    use crate::env::{LineTap, build_denies_all, patched_build_refusal};
    use op::Runnable;
    use sandbox::config::{ClassifierLeaf, Verdict};
    use std::sync::{Arc, Mutex};

    #[derive(Debug)]
    struct VerdictFetcher(std::path::PathBuf, Mutex<Vec<Option<ClassifierLeaf>>>);

    impl op::SourceFetcher for VerdictFetcher {
        async fn download_web(
            &self,
            url: &str,
            _sha256: &str,
            leaf: Option<&ClassifierLeaf>,
            _op: &ot::OpTracker,
        ) -> anyhow::Result<std::path::PathBuf> {
            self.1.lock().unwrap().push(leaf.cloned());
            assert!(url.starts_with("https://downloads.example.org/"), "{url}");
            match leaf {
                Some(leaf) if leaf.is_deny() => anyhow::bail!(
                    "could not connect to downloads.example.org:443: \
                     Connection refused (os error 111)"
                ),
                Some(_) => Ok(self.0.clone()),
                None => anyhow::bail!("the fetch ran outside the box's leaf"),
            }
        }

        async fn download_gcs(
            &self,
            _bucket_id: String,
            _file: &str,
            _sha256: &str,
            _op: &ot::OpTracker,
        ) -> anyhow::Result<std::path::PathBuf> {
            unreachable!("the package declares a web source only")
        }
    }

    let tmp = tempfile::tempdir().unwrap();
    let archive = tmp.path().join("fetcher-1.0.tar.zst");
    {
        let enc = zstd::Encoder::new(std::fs::File::create(&archive).unwrap(), 1).unwrap();
        let mut tar = tar::Builder::new(enc);
        let body = b"fetched";
        let mut header = tar::Header::new_gnu();
        header.set_path("README").unwrap();
        header.set_size(body.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar.append(&header, &body[..]).unwrap();
        tar.into_inner().unwrap().finish().unwrap();
    }
    let graph = graph::Graph::new()
        .ingest(
            decode::Layer::new_for_test(
                r#"
                let {BuildSpec, Source, OutputLib, ..} = import "minimal.ncl" in
                {
                    name = "fetcher",
                    prebuilt = true,
                    build_deps = [
                        {
                            url = "https://downloads.example.org/fetcher-1.0.tar.zst",
                            sha256 = "0000000000000000000000000000000000000000000000000000000000000000",
                            extract = true,
                        } | Source,
                    ],
                    runtime_deps = [],
                    outputs = { docs = { glob = "*" } | OutputLib },
                } | BuildSpec
                "#
                .to_string(),
            )
            .unwrap(),
        )
        .unwrap();
    let bsr = *graph.by_name("fetcher").unwrap();
    std::fs::create_dir(tmp.path().join("cache")).unwrap();
    let opts = op::Options {
        cache: lcache::Cache::at_dir(tmp.path().join("cache")).unwrap(),
        graph: &graph,
        exec_base: tmp.path().to_path_buf(),
        ot: None,
        daemon_id: None,
    };
    let fetcher = VerdictFetcher(archive, Mutex::default());
    let root = std::path::Path::new("/sys/fs/cgroup/minimald.slice");
    let sealed = ClassifierLeaf::under(root, "sealed", Verdict::Deny);
    let open = ClassifierLeaf::under(root, "open", Verdict::Allow);

    let build = |leaf: ClassifierLeaf| {
        let lines = Arc::new(Mutex::new(std::collections::VecDeque::new()));
        let spec_build = op::SpecBuild {
            spec: &bsr,
            override_deps: None,
            remote_fetcher: &fetcher,
            stdout_writer: None,
            stderr_writer: Some(Box::new(LineTap::new(tokio::io::sink(), lines.clone()))),
            cancel: tokio_util::sync::CancellationToken::new(),
            cpu_weight: None,
            classifier_leaf: Some(leaf),
            box_network: None,
        };
        (spec_build, lines)
    };
    let expected = "the build of fetcher could not reach downloads.example.org: \
                    the egress rules of box sealed do not allow it";

    // The deny-all box: its build fails, naming the host and the box.
    let (mut spec_build, lines) = build(sealed.clone());
    let refused = match spec_build.run(&opts).await {
        Ok(_) => panic!("a deny-all box's fetch of its web source is refused"),
        Err(e) => e,
    };
    drop(spec_build);
    let lines: Vec<String> = lines.lock().unwrap().iter().cloned().collect();
    let lines: Vec<&str> = lines.iter().map(String::as_str).collect();
    // The in-box patched build reads its own error and the build's output.
    assert_eq!(
        patched_build_refusal(
            build_denies_all(Some(&sealed), None),
            "fetcher",
            "sealed",
            &refused.to_string(),
            lines.iter().copied(),
        )
        .as_deref(),
        Some(expected),
        "{lines:?}"
    );
    // The build side operation reads the build's events.
    let placement = |name: &str, leaf: &ClassifierLeaf| BuildPlacement {
        box_name: name.to_string(),
        leaf: Some(leaf.clone()),
        network: None,
    };
    let failed = mctx::Error::from(orchestrator::Error::BuildFailed(
        "fetcher".to_string(),
        refused,
    ))
    .to_string();
    let mut tap = BuildTap::default();
    for event in build_events("fetcher", &lines) {
        tap.observe(&event, &placement("sealed", &sealed));
    }
    assert_eq!(
        tap.refusal(&placement("sealed", &sealed), &failed)
            .as_deref(),
        Some(expected)
    );

    // The box its rules allow the host: the package builds from the source.
    let (mut spec_build, lines) = build(open.clone());
    let built = spec_build
        .run(&opts)
        .await
        .expect("a box allowed the host builds the package");
    assert_eq!(
        std::fs::read_to_string(built.outputs.path().join("README")).unwrap(),
        "fetched"
    );
    drop(spec_build);
    assert!(lines.lock().unwrap().is_empty(), "no fetch failed");

    assert_eq!(
        *fetcher.1.lock().unwrap(),
        vec![Some(sealed), Some(open)],
        "each fetch ran in its box's leaf"
    );

    // A fetch that failed for another reason names no refused destination.
    assert_eq!(
        crate::env::refused_destination([
            "could not fetch the source https://downloads.example.org/fetcher-1.0.tar.zst: \
             other: the sha256 of the download does not match",
        ]),
        None
    );
}

/// NET-155: a materialize reports the error of a package build it started
/// the way the build side operation does. A build in a deny leaf whose
/// output names a refused destination fails with the refusal, which names
/// the destination and the box, before the build's own error.
#[test]
fn box_package_build_refusal_names_destination_and_box_for_materialize() {
    use crate::box_ops::{BuildPlacement, BuildTap};
    use sandbox::config::{ClassifierLeaf, Verdict};

    let root = std::path::Path::new("/sys/fs/cgroup/minimald.slice");
    let placement = BuildPlacement {
        box_name: "sealed".to_string(),
        leaf: Some(ClassifierLeaf::under(root, "sealed", Verdict::Deny)),
        network: None,
    };
    let mut tap = BuildTap::default();
    for event in build_events(
        "fetcher",
        &[
            "curl: (6) Could not resolve host: downloads.example.org",
            "build command failed",
        ],
    ) {
        tap.observe(&event, &placement);
    }
    let failed = mctx::Error::from(orchestrator::Error::BuildFailed(
        "fetcher".to_string(),
        op::Error::Other(anyhow::anyhow!("build command failed")),
    ))
    .to_string();
    assert_eq!(
        tap.failure(&placement, failed.clone()),
        format!(
            "the build of fetcher could not reach downloads.example.org: \
             the egress rules of box sealed do not allow it\n{failed}"
        )
    );
}

/// NET-155: a materialize build in a deny leaf that fails for a reason other
/// than the box's egress rules keeps the build's own error, unchanged.
#[test]
fn box_package_build_refusal_names_destination_and_box_for_materialize_only_when_refused() {
    use crate::box_ops::{BuildPlacement, BuildTap};
    use sandbox::config::{ClassifierLeaf, Verdict};

    let root = std::path::Path::new("/sys/fs/cgroup/minimald.slice");
    let placement = BuildPlacement {
        box_name: "sealed".to_string(),
        leaf: Some(ClassifierLeaf::under(root, "sealed", Verdict::Deny)),
        network: None,
    };
    let mut tap = BuildTap::default();
    for event in build_events("compiler", &["cc -c hello.c", "error: cc failed"]) {
        tap.observe(&event, &placement);
    }
    let failed = mctx::Error::from(orchestrator::Error::BuildFailed(
        "compiler".to_string(),
        op::Error::Other(anyhow::anyhow!("build command failed")),
    ))
    .to_string();
    assert_eq!(tap.failure(&placement, failed.clone()), failed);
}

/// NET-155: the error of a build the box's egress rules refused names the
/// destination the build could not reach and the box whose rules refused
/// it, for the failure lines of `curl`, `wget` and `git`.
#[test]
fn box_package_build_refusal_names_destination_and_box() {
    use crate::env::{build_denies_all, egress_refusal, refused_destination};
    use sandbox::config::{ClassifierLeaf, Verdict};

    let root = std::path::Path::new("/sys/fs/cgroup/minimald.slice");
    let deny = ClassifierLeaf::under(root, "b1", Verdict::Deny);
    let allow = ClassifierLeaf::under(root, "b1", Verdict::Allow);

    let cases: [(&str, &str); 6] = [
        (
            "curl: (7) Failed to connect to example.com port 443 after 2 ms: Couldn't connect to server",
            "example.com:443",
        ),
        (
            "curl: (6) Could not resolve host: example.com",
            "example.com",
        ),
        (
            "fatal: unable to access 'https://github.com/o/r/': Could not resolve host: github.com",
            "github.com",
        ),
        (
            "Resolving example.com (example.com)... failed: Temporary failure in name resolution.",
            "example.com",
        ),
        (
            "Connecting to example.com (example.com)|93.184.215.14|:443... failed: No route to host.",
            "example.com:443",
        ),
        (
            "Connecting to 93.184.215.14:80... failed: No route to host.",
            "93.184.215.14:80",
        ),
    ];
    for (line, destination) in cases {
        assert_eq!(
            refused_destination(["make: entering", line]).as_deref(),
            Some(destination),
            "{line}"
        );
        assert_eq!(
            egress_refusal(
                build_denies_all(Some(&deny), None),
                "hello",
                "my-box",
                [line]
            ),
            Some(format!(
                "the build of hello could not reach {destination}: \
                 the egress rules of box my-box do not allow it"
            )),
        );
        // An allowed box's failure is the destination's, not the rules'.
        assert_eq!(
            egress_refusal(
                build_denies_all(Some(&allow), None),
                "hello",
                "my-box",
                [line]
            ),
            None
        );
        assert_eq!(
            egress_refusal(build_denies_all(None, None), "hello", "my-box", [line]),
            None
        );
    }
    // An earlier tolerated failure does not hide the one that ended the build.
    assert_eq!(
        refused_destination([
            "curl: (6) Could not resolve host: optional.example",
            "make: entering",
            "curl: (7) Failed to connect to example.com port 443 after 2 ms: Couldn't connect to server",
        ])
        .as_deref(),
        Some("example.com:443"),
    );
    // A failure that names no destination is left as the build said it.
    assert_eq!(
        egress_refusal(
            build_denies_all(Some(&deny), None),
            "hello",
            "my-box",
            ["error: cc failed"]
        ),
        None
    );
    // Box-zone names are not subject to egress rules: a deny box that cannot
    // resolve or reach one was not refused by its rules.
    for line in [
        "curl: (6) Could not resolve host: web.min.internal",
        "curl: (7) Failed to connect to host.min.internal port 8080 after 1 ms: Couldn't connect to server",
        "curl: (6) Could not resolve host: min.internal",
    ] {
        assert_eq!(
            egress_refusal(
                build_denies_all(Some(&deny), None),
                "hello",
                "my-box",
                [line]
            ),
            None,
            "{line}"
        );
    }
    // A name that only ends in the apex text is not in the zone.
    assert!(
        egress_refusal(
            build_denies_all(Some(&deny), None),
            "hello",
            "my-box",
            ["curl: (6) Could not resolve host: evilmin.internal"]
        )
        .is_some()
    );
}

/// NET-155: the in-box patched build reports a refusal only when the
/// build's own error carries the refused destination. A deny box whose build
/// tolerated a failed download and then failed to compile keeps the compile
/// error.
#[test]
fn box_package_build_refusal_names_destination_and_box_only_for_the_error() {
    use crate::env::{build_denies_all, patched_build_refusal};
    use sandbox::config::{ClassifierLeaf, Verdict};

    let root = std::path::Path::new("/sys/fs/cgroup/minimald.slice");
    let deny = ClassifierLeaf::under(root, "b1", Verdict::Deny);
    let denies_all = build_denies_all(Some(&deny), None);
    let download = "curl: (7) Failed to connect to example.com port 443 after 2 ms: Couldn't connect to server";

    // The download ended the build: its error carries the failed download.
    let failure = format!("Invocation 0 failed with exit code 7: exit status\nstderr:\n{download}");
    assert_eq!(
        patched_build_refusal(
            denies_all,
            "hello",
            "my-box",
            &failure,
            ["make: entering", download]
        ),
        Some(
            "the build of hello could not reach example.com:443: \
             the egress rules of box my-box do not allow it"
                .to_string()
        )
    );

    // A compile failure after a tolerated download is the build's own error.
    let failure = "Invocation 0 failed with exit code 1: exit status\nstderr:\nerror: cc failed";
    assert_eq!(
        patched_build_refusal(
            denies_all,
            "hello",
            "my-box",
            failure,
            [download, "cc -c hello.c", "error: cc failed"]
        ),
        None
    );
}

/// NET-155: the build output tap ends a line at `\r` as well as `\n`, holds
/// a bounded part of an unfinished line, and keeps the last unfinished line
/// when it shuts down, so a final failure with no newline is still read.
#[tokio::test]
async fn box_package_build_refusal_names_destination_and_box_from_unfinished_output() {
    use crate::env::{LineTap, refused_destination};
    use tokio::io::AsyncWriteExt;

    let lines = std::sync::Arc::new(std::sync::Mutex::new(std::collections::VecDeque::new()));
    let mut tap = LineTap::new(tokio::io::sink(), lines.clone());
    for pct in 0..1000 {
        tap.write_all(format!("  {pct:>3}% [=====>      ] 1.2MB/s\r").as_bytes())
            .await
            .unwrap();
        assert_eq!(tap.pending(), 0);
    }
    // A long run with no line end at all keeps only a bounded tail.
    tap.write_all(&vec![b'#'; 64 * 1024]).await.unwrap();
    assert!(tap.pending() <= 4096, "held {} bytes", tap.pending());
    tap.write_all(b"\n").await.unwrap();
    tap.write_all(b"curl: (7) Failed to connect to example.com port 443")
        .await
        .unwrap();
    tap.shutdown().await.unwrap();

    let lines = lines.lock().unwrap();
    assert!(lines.len() <= 64);
    assert_eq!(
        refused_destination(lines.iter().map(String::as_str)).as_deref(),
        Some("example.com:443")
    );
}

/// NET-155: a task of a box whose launch placed it in a classifier leaf is
/// refused when the task's context has no leaf, with the same text the build
/// side operation gives. Its builds never run outside the box's egress verdict.
#[test]
fn box_package_build_under_box_egress_verdict_refuses_task_of_placed_box_without_leaf() {
    let refusal =
        crate::exec::task_build_refusal(Some(boxes::HostIpEnforcement::PerBox), "sealed", false)
            .expect_err("a placed box with no leaf has its task refused");
    assert_eq!(refusal.kind(), std::io::ErrorKind::PermissionDenied);
    assert_eq!(
        refusal.to_string(),
        "the build for box sealed did not start: box sealed runs under \
         egress rules, and its shell is not running to apply them to the \
         build. Run `min session attach sealed` to start its shell, then \
         run the build again."
    );
    assert_eq!(
        Err(refusal.to_string()),
        super::setup::box_build_leaf(
            tempfile::tempdir().unwrap().path(),
            "sealed",
            "sealed",
            true
        ),
        "the task refusal and the build refusal say the same thing"
    );
    // A placed box with its leaf builds in that leaf.
    crate::exec::task_build_refusal(Some(boxes::HostIpEnforcement::PerBox), "sealed", true)
        .expect("a placed box with its leaf builds");
}

/// NET-155: a task of a box that was never placed in a leaf still builds,
/// in the daemon's own cgroup, as before.
#[test]
fn box_package_build_under_box_egress_verdict_builds_task_of_box_never_placed() {
    for enforcement in [None, Some(boxes::HostIpEnforcement::None)] {
        crate::exec::task_build_refusal(enforcement, "plain", false)
            .expect("a box that was never placed builds without a leaf");
    }
}

/// The handle of the box `id` on `server`.
async fn box_handle(server: &TestServer, id: SessionId) -> crate::box_actor::BoxHandle {
    server
        .state
        .sessions_manager()
        .await
        .get_session(crate::box_manager::BoxKeyPredicate::Id(id))
        .await
        .unwrap()
        .expect("session should resolve")
}

/// NET-155: `min check` on a box whose launch placed it in a classifier leaf
/// is refused when that leaf is gone, with the same text a task gives. Its
/// package builds never run in the daemon's own cgroup.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn box_package_build_under_box_egress_verdict_refuses_check_of_placed_box_without_leaf() {
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let id = create_configured_session(&mut client, "check-sealed", "/uwu").await;
    rewrite_record(&server, id, |record| {
        record.host_ip_enforcement = Some(boxes::HostIpEnforcement::PerBox);
    })
    .await;

    let refusal = box_handle(&server, id)
        .await
        .start_check(crate::box_ops::CheckOpts::from_args("").unwrap())
        .await
        .expect_err("a placed box with no leaf has its check refused");
    assert_eq!(refusal.kind(), std::io::ErrorKind::PermissionDenied);
    assert_eq!(
        refusal.to_string(),
        super::placed_box_build_refusal("check-sealed")
    );
}

/// NET-155: `min check` on a box that was never placed in a leaf still
/// starts, and its builds run in the daemon's own cgroup, as before.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn box_package_build_under_box_egress_verdict_starts_check_of_box_never_placed() {
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let id = create_configured_session(&mut client, "check-plain", "/uwu").await;
    assert_eq!(read_record(&server, id).await.host_ip_enforcement, None);

    box_handle(&server, id)
        .await
        .start_check(crate::box_ops::CheckOpts::from_args("").unwrap())
        .await
        .expect("a box that was never placed starts a check");
}

/// A box record for the NET-155 tests, in `mode` and under `egress`.
fn build_record(mode: boxes::NetworkMode, egress: Option<boxes::EgressPolicy>) -> boxes::Record {
    boxes::Record {
        id: boxes::SessionId::nil(),
        name: Some("sealed".to_string()),
        username: None,
        project_path: paths::HostAbsPath::try_new("/tmp/project").unwrap(),
        network: mode,
        policy: boxes::BoxPolicy::new(egress, None),
        task_addresses: Vec::new(),
        box_addresses: None,
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

/// A switch on a VM host, which a test never reaches.
fn build_switch() -> std::sync::Arc<tokio::sync::Mutex<crate::net::SwitchClient>> {
    std::sync::Arc::new(tokio::sync::Mutex::new(
        crate::net::SwitchClient::new("/usr/bin/gvproxy", "/run/minimal/gvproxy").with_transport(
            crate::net::SwitchTransport::HostShuttle {
                cid: crate::net::VSOCK_HOST_CID,
                port: crate::net::VSOCK_GVPROXY_SHUTTLE_PORT,
            },
        ),
    ))
}

/// NET-155: an own-address box has no classifier leaf. Its package build
/// runs on the box's own network, under the box's egress rules, and never
/// as the daemon's own traffic. A deny-all box's build that cannot reach its
/// download is reported as refused by the box's rules. A box allowed the
/// destination is never reported as refused. Before each build attaches,
/// the network asks whether the box's host-side row stands, as a task run
/// does, so a build never attaches under another box's row.
#[tokio::test]
async fn box_package_build_under_box_egress_verdict_runs_own_address_box_on_its_network() {
    use crate::box_ops::{BuildPlacement, BuildTap};
    let switch = build_switch();

    let sealed = build_record(
        boxes::NetworkMode::OwnIp,
        Some(boxes::EgressPolicy::deny_all()),
    );
    let network = super::setup::own_address_build_network(&sealed, &switch, false)
        .expect("an own-address box builds on its own network");
    assert!(network.denies_all());
    assert!(format!("{:?}", network.network()).contains("OwnAddressBuildNetwork"));
    // With no `egress` section, the deny-all default applies to the build.
    let defaulted = build_record(boxes::NetworkMode::OwnIp, None);
    assert!(
        super::setup::own_address_build_network(&defaulted, &switch, false)
            .unwrap()
            .denies_all()
    );

    let open = build_record(
        boxes::NetworkMode::OwnIp,
        Some(boxes::EgressPolicy {
            allow_subnets: Some(Vec::new()),
            allow_dns_hosts: Some(vec!["downloads.example.org".to_string()]),
            allow_protocols: None,
            deny_subnets: None,
        }),
    );
    let open_network = super::setup::own_address_build_network(&open, &switch, false)
        .expect("an allowed own-address box builds on its own network");
    assert!(!open_network.denies_all());

    let download = [
        "curl: (6) Could not resolve host: downloads.example.org",
        "build command failed",
    ];
    let failed = mctx::Error::from(orchestrator::Error::BuildFailed(
        "fetcher".to_string(),
        op::Error::Other(anyhow::anyhow!("build command failed")),
    ))
    .to_string();
    let run = |network: op::BuildNetwork| {
        let placement = BuildPlacement {
            box_name: "sealed".to_string(),
            leaf: None,
            network: Some(network),
        };
        let mut tap = BuildTap::default();
        for event in build_events("fetcher", &download) {
            tap.observe(&event, &placement);
        }
        tap.refusal(&placement, &failed)
    };
    assert_eq!(
        run(network.clone()).as_deref(),
        Some(
            "the build of fetcher could not reach downloads.example.org: \
             the egress rules of box sealed do not allow it"
        )
    );
    assert_eq!(run(open_network), None);

    // A box the VM host registered, whose row the host cannot confirm, has
    // its build's network refused before anything attaches.
    let mut registered = sealed.clone();
    registered.box_addresses = Some(boxes::BoxAddresses {
        switch_address: std::net::Ipv4Addr::new(192, 168, 127, 10),
        loopback_address: std::net::Ipv4Addr::new(127, 77, 0, 10),
    });
    let network = super::setup::own_address_build_network(&registered, &switch, false).unwrap();
    let refused = network
        .network()
        .plan()
        .await
        .expect_err("a build of a box whose row is not confirmed does not attach");
    assert!(
        refused.to_string().contains("could not confirm"),
        "{refused}"
    );
}

/// NET-155: a host-address box with no per-box enforcement has no leaf and
/// no network of its own. Its build runs in the daemon's own cgroup, because
/// the box has no enforcement, and no failure is reported as the box's rules.
#[test]
fn box_package_build_under_box_egress_verdict_builds_unenforced_box_without_rules() {
    use crate::box_ops::{BuildPlacement, BuildTap};
    let switch = build_switch();
    let mut record = build_record(
        boxes::NetworkMode::HostNet,
        Some(boxes::EgressPolicy::deny_all()),
    );
    record.host_ip_enforcement = Some(boxes::HostIpEnforcement::None);
    assert!(super::setup::own_address_build_network(&record, &switch, false).is_none());
    assert_eq!(
        super::setup::box_build_leaf(
            tempfile::tempdir().unwrap().path(),
            "sealed",
            "sealed",
            false
        ),
        Ok(None)
    );
    let placement = BuildPlacement {
        box_name: "sealed".to_string(),
        leaf: None,
        network: None,
    };
    assert!(!placement.denies_all());
    let mut tap = BuildTap::default();
    for event in build_events(
        "fetcher",
        &["curl: (6) Could not resolve host: downloads.example.org"],
    ) {
        tap.observe(&event, &placement);
    }
    assert_eq!(
        tap.refusal(
            &placement,
            "`fetcher` failed to build: build command failed"
        ),
        None
    );
}

/// Spawns a stand-in box: `/bin/sh` sets `trap`, then loops on `sleep`.
/// It answers once the shell set the trap and started its first `sleep`, so
/// a stop never reaches a shell that still has the default SIGTERM action.
fn spawn_stand_in_box(trap: &str) -> std::process::Child {
    use std::io::BufRead;
    let mut child = std::process::Command::new("/bin/sh")
        .arg("-c")
        .arg(format!(
            "{trap}; sleep 0.05 & echo ready; wait; while :; do sleep 0.05; done"
        ))
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("spawn the stand-in box");
    let stdout = child.stdout.take().expect("the stand-in box's stdout");
    let mut line = String::new();
    std::io::BufReader::new(stdout)
        .read_line(&mut line)
        .expect("read the stand-in box's ready line");
    assert_eq!(line.trim(), "ready", "the stand-in box set its trap");
    child
}

/// A stand-in host loop for `child`: it reaps the child and reports the end
/// as `hakoniwa` does. A signalled child has no exit status of its own and
/// carries the container's 125.
fn stand_in_entrypoint(
    child: std::process::Child,
) -> tokio::task::JoinHandle<Result<crate::box_runtime::HostExit, std::io::Error>> {
    crate::traced::spawn_blocking(move || {
        use std::os::unix::process::ExitStatusExt;
        let mut child = child;
        let status = child.wait()?;
        let reason = match status.code() {
            Some(code) => crate::box_runtime::ExitReason {
                code,
                exit_code: Some(code),
                reason: format!("process(stand-in) exited with code {code}"),
            },
            None => crate::box_runtime::ExitReason {
                code: 125,
                exit_code: None,
                reason: format!(
                    "container received signal {}",
                    status.signal().unwrap_or_default()
                ),
            },
        };
        Ok(crate::box_runtime::HostExit {
            code: reason.code,
            reason: Some(reason),
        })
    })
}

/// BOX-013: a stop sends SIGTERM to every process in the box, waits the
/// grace period, sends SIGKILL to those still running, and the record ends
/// `stopped` with an `exited` event that carries `reason = "stopped"` and
/// the signal that ended the entrypoint.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stop_sends_term_then_kill_and_records_exited_stopped_with_signal() {
    use boxes::core::record::{RecordState, StopEnding};

    // A box that ignores SIGTERM: the grace runs out and SIGKILL ends it.
    let child = spawn_stand_in_box("trap '' TERM");
    let processes = crate::box_runtime::BoxProcesses::of_container(child.id());
    let entrypoint = stand_in_entrypoint(child);
    assert!(
        !processes.pids().is_empty(),
        "the stand-in box should be running"
    );
    let started = std::time::Instant::now();
    let outcome = super::stop_box_processes(
        SessionId::mint(),
        Some(processes),
        entrypoint,
        false,
        Duration::from_millis(500),
        &std::sync::atomic::AtomicBool::new(false),
    )
    .await;
    assert!(
        started.elapsed() >= Duration::from_millis(500),
        "a graceful stop waits the grace period before SIGKILL"
    );
    assert_eq!(outcome.sent, vec![libc::SIGTERM, libc::SIGKILL]);
    assert_eq!(
        outcome.ending,
        StopEnding::Signalled {
            signal: libc::SIGKILL
        }
    );
    assert!(outcome.unfinished.is_none());
    assert!(
        processes.pids().is_empty(),
        "no process of the box outlives the stop"
    );

    // Through the daemon: the mock shell ends on SIGTERM, and the record
    // and its events keep that signal.
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let session_id = create_session(&mut client).await;
    let manager = server.state.sessions_manager().await;
    let handle = manager
        .get_session(crate::box_manager::BoxKeyPredicate::Id(session_id))
        .await
        .unwrap()
        .expect("session should resolve");
    let host = handle
        .ensure_host("tester".to_string())
        .await
        .expect("an Active session should be able to launch a headless host");
    assert!(host.is_alive());

    let ending = handle
        .stop_box(false, Duration::from_secs(5))
        .await
        .expect("the stop succeeds");
    assert_eq!(
        ending,
        StopEnding::Signalled {
            signal: libc::SIGTERM
        }
    );
    host.closed().await;

    let record = manager
        .get_record(crate::box_manager::BoxKeyPredicate::Id(session_id))
        .await
        .unwrap()
        .expect("a stopped box keeps its record");
    assert_eq!(record.state().unwrap(), RecordState::Stopped(ending));
    assert_eq!(record.signal, Some(libc::SIGTERM));
    assert_eq!(record.exit_code, None);

    let mut events = manager.box_events(session_id).await.unwrap();
    let events = events.read_new().unwrap();
    let exited = events
        .iter()
        .find(|e| e.kind == boxes::events::BoxEventType::Exited)
        .expect("the stop records an exited event");
    assert_eq!(exited.data["reason"], "stopped");
    assert_eq!(exited.data["signal"], libc::SIGTERM);
    assert!(!exited.data.contains_key("exit_code"));
}

/// BOX-013: a forced stop kills every process in the box at once, without
/// the grace period.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stop_force_kills_at_once() {
    use boxes::core::record::StopEnding;

    let child = spawn_stand_in_box("trap '' TERM");
    let processes = crate::box_runtime::BoxProcesses::of_container(child.id());
    let entrypoint = stand_in_entrypoint(child);

    let started = std::time::Instant::now();
    let outcome = super::stop_box_processes(
        SessionId::mint(),
        Some(processes),
        entrypoint,
        true,
        Duration::from_secs(60),
        &std::sync::atomic::AtomicBool::new(false),
    )
    .await;
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "a forced stop does not wait the grace period: {:?}",
        started.elapsed()
    );
    assert_eq!(outcome.sent, vec![libc::SIGKILL]);
    assert_eq!(
        outcome.ending,
        StopEnding::Signalled {
            signal: libc::SIGKILL
        }
    );
    assert!(
        processes.pids().is_empty(),
        "no process of the box outlives the forced stop"
    );
}

/// BOX-013: a forced stop that arrives while a graceful stop waits out its
/// grace period ends the grace. The graceful stop sends SIGKILL at once, and
/// the box does not wait the rest of the grace.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stop_forced_during_a_graceful_stop_kills_at_once() {
    use boxes::core::record::StopEnding;

    let child = spawn_stand_in_box("trap '' TERM");
    let processes = crate::box_runtime::BoxProcesses::of_container(child.id());
    let entrypoint = stand_in_entrypoint(child);
    let forced = super::StopForce::default();

    // The forced stop arrives inside the graceful stop's grace period.
    let setter = std::sync::Arc::clone(&forced);
    crate::traced::spawn(async move {
        tokio::time::sleep(Duration::from_millis(300)).await;
        setter.store(true, std::sync::atomic::Ordering::SeqCst);
    });
    let started = std::time::Instant::now();
    let outcome = super::stop_box_processes(
        SessionId::mint(),
        Some(processes),
        entrypoint,
        false,
        Duration::from_secs(60),
        &forced,
    )
    .await;
    let elapsed = started.elapsed();
    assert!(
        elapsed >= Duration::from_millis(300),
        "the graceful stop waited until the forced stop arrived: {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_secs(10),
        "a forced stop cuts the grace period short: {elapsed:?}"
    );
    assert_eq!(outcome.sent, vec![libc::SIGTERM, libc::SIGKILL]);
    assert_eq!(
        outcome.ending,
        StopEnding::Signalled {
            signal: libc::SIGKILL
        }
    );
    assert!(
        processes.pids().is_empty(),
        "no process of the box outlives the forced stop"
    );
}

/// BOX-013: an entrypoint that exits 125 on SIGTERM inside the grace period
/// keeps its own exit status. `hakoniwa` reports 125 for a signalled
/// container as well, so only the reaped reason tells the two apart.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stop_records_an_entrypoint_exit_125_as_its_exit_code() {
    use boxes::core::record::{RecordState, StopEnding};

    let child = spawn_stand_in_box("trap 'exit 125' TERM");
    let processes = crate::box_runtime::BoxProcesses::of_container(child.id());
    let entrypoint = stand_in_entrypoint(child);

    let outcome = super::stop_box_processes(
        SessionId::mint(),
        Some(processes),
        entrypoint,
        false,
        Duration::from_secs(5),
        &std::sync::atomic::AtomicBool::new(false),
    )
    .await;
    assert_eq!(outcome.sent[0], libc::SIGTERM);
    let ending = outcome.ending;
    assert_eq!(ending, StopEnding::ExitedFirst { exit_code: 125 });
    assert!(outcome.unfinished.is_none());

    // The record and the event the stop writes for this ending.
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let session_id = create_session(&mut client).await;
    let manager = server.state.sessions_manager().await;
    let mut record = manager
        .get_record(crate::box_manager::BoxKeyPredicate::Id(session_id))
        .await
        .unwrap()
        .expect("the box has a record");
    record.set_state(RecordState::Stopped(ending));
    assert_eq!(record.exit_code, Some(125));
    assert_eq!(record.signal, None);

    let exited = super::stopped_event_data(ending);
    assert_eq!(exited["reason"], "stopped");
    assert_eq!(exited["exit_code"], 125);
    assert!(!exited.contains_key("signal"));
}

/// BOX-013: a stop that ends the processes and cannot write the `stopped`
/// record keeps the box hosted. No launch starts new processes in it until a
/// retried stop writes the record with the ending of the first stop.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stop_with_an_unwritable_record_refuses_launches_until_retried() {
    use boxes::core::record::RecordState;

    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let session_id = create_session(&mut client).await;
    let manager = server.state.sessions_manager().await;
    let handle = manager
        .get_session(crate::box_manager::BoxKeyPredicate::Id(session_id))
        .await
        .unwrap()
        .expect("session should resolve");
    let host = handle
        .ensure_host("tester".to_string())
        .await
        .expect("an Active session should be able to launch a headless host");

    // A directory where the record's staging file belongs: every record
    // write fails, and record reads still work.
    let sessions = server
        .state
        .minimal_state_dir()
        .await
        .as_utf8_path()
        .join("sessions");
    let mut staged = Vec::new();
    for entry in std::fs::read_dir(&sessions).unwrap() {
        let dir = entry.unwrap().path();
        if dir.is_dir() {
            let tmp = dir.join("record.json.tmp");
            let _ = std::fs::remove_file(&tmp);
            std::fs::create_dir(&tmp).unwrap();
            staged.push(tmp);
        }
    }
    assert_eq!(staged.len(), 1, "the server holds one box");

    handle
        .stop_box(false, Duration::from_secs(5))
        .await
        .expect_err("a stop that cannot write the record fails");
    host.closed().await;

    let refused = handle
        .ensure_host("tester".to_string())
        .await
        .expect_err("no launch while the stop's record is unwritten");
    assert!(
        refused
            .to_string()
            .contains("stopped state is not saved yet"),
        "the refusal says why: {refused}"
    );

    for tmp in &staged {
        std::fs::remove_dir(tmp).unwrap();
    }
    let ending = handle
        .stop_box(false, Duration::from_secs(5))
        .await
        .expect("the retried stop writes the record");
    assert_eq!(
        ending,
        boxes::core::record::StopEnding::Signalled {
            signal: libc::SIGTERM
        },
        "the retried stop keeps how the first stop ended the box"
    );
    let record = manager
        .get_record(crate::box_manager::BoxKeyPredicate::Id(session_id))
        .await
        .unwrap()
        .expect("a stopped box keeps its record");
    assert_eq!(record.state().unwrap(), RecordState::Stopped(ending));
}

/// NET-128 fail-closed: a stop that ends the box's processes and cannot
/// write the `stopped` record still marks the box's name stopped. A
/// shared-address name does not keep answering for a box with no process.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stop_box_with_an_unwritable_record_still_marks_name_stopped() {
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let manager = server.state.sessions_manager().await;
    manager.land_range_verdict(crate::net::dns::RangeVerdict::Present);
    let shared = manager
        .hostnames()
        .read()
        .expect("registry lock")
        .node_address();
    let id = finalize_handed_own_ip_session(
        &mut client,
        "unwritbox",
        std::net::Ipv4Addr::new(100, 64, 128, 10),
        shared,
    )
    .await;
    let handle = manager
        .get_session(crate::box_manager::BoxKeyPredicate::Id(id))
        .await
        .unwrap()
        .expect("the box resolves while it runs");

    // A directory where the record's staging file belongs: every record
    // write fails, and record reads still work.
    let sessions = server
        .state
        .minimal_state_dir()
        .await
        .as_utf8_path()
        .join("sessions");
    let mut staged = 0;
    for entry in std::fs::read_dir(&sessions).unwrap() {
        let dir = entry.unwrap().path();
        if dir.is_dir() {
            let tmp = dir.join("record.json.tmp");
            let _ = std::fs::remove_file(&tmp);
            std::fs::create_dir(&tmp).unwrap();
            staged += 1;
        }
    }
    assert_eq!(staged, 1, "the server holds one box");

    handle
        .stop_box(false, Duration::from_secs(5))
        .await
        .expect_err("a stop that cannot write the record fails");

    let registry = server.state.sessions_manager().await.hostnames();
    assert_eq!(
        registry
            .read()
            .expect("registry lock")
            .zone_entry("unwritbox.min.internal", &[]),
        crate::net::dns::ZoneEntry::Held {
            owner: "unwritbox".to_string(),
            address: None,
        },
        "a failed record write still leaves the stopped box answering NODATA"
    );
    assert_eq!(
        registry
            .read()
            .expect("registry lock")
            .resolve("unwritbox.min.internal"),
        None,
        "the proxy does not forward a box whose stop could not write its record"
    );
}

/// BOX-013: the `stopped` record is the step a stop cannot skip. When the
/// `exited` event cannot be written, the stop still answers with its ending
/// and the record still reads `stopped`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stop_with_a_failing_event_write_still_records_stopped() {
    use boxes::core::record::RecordState;

    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let session_id = create_session(&mut client).await;
    let manager = server.state.sessions_manager().await;
    let handle = manager
        .get_session(crate::box_manager::BoxKeyPredicate::Id(session_id))
        .await
        .unwrap()
        .expect("session should resolve");
    let host = handle
        .ensure_host("tester".to_string())
        .await
        .expect("an Active session should be able to launch a headless host");

    // A directory where the events file belongs: every append fails.
    let sessions = server
        .state
        .minimal_state_dir()
        .await
        .as_utf8_path()
        .join("sessions");
    let mut broken = 0;
    for entry in std::fs::read_dir(&sessions).unwrap() {
        let dir = entry.unwrap().path();
        if !dir.is_dir() {
            continue;
        }
        let events = dir.join("events.jsonl");
        let _ = std::fs::remove_file(&events);
        std::fs::create_dir(&events).unwrap();
        broken += 1;
    }
    assert_eq!(broken, 1, "the server holds one box");

    let ending = handle
        .stop_box(false, Duration::from_secs(5))
        .await
        .expect("a failed event write does not fail the stop");
    host.closed().await;

    let record = manager
        .get_record(crate::box_manager::BoxKeyPredicate::Id(session_id))
        .await
        .unwrap()
        .expect("a stopped box keeps its record");
    assert_eq!(record.state().unwrap(), RecordState::Stopped(ending));
}

/// BOX-013: a container supervisor that already exited and was reaped has
/// no readable namespace. Its pid can belong to an unrelated process by
/// then, so the stop finds no process of the box and signals nothing.
#[test]
fn of_container_on_a_reaped_supervisor_signals_nothing() {
    let mut child = std::process::Command::new("/bin/true")
        .spawn()
        .expect("spawn the stand-in supervisor");
    let pid = child.id();
    child.wait().expect("reap the stand-in supervisor");

    for root in [pid, u32::try_from(i32::MAX).unwrap()] {
        let processes = crate::box_runtime::BoxProcesses::of_container(root);
        assert!(
            processes.pids().is_empty(),
            "a supervisor with no readable namespace has no processes"
        );
        // Signal 0 checks delivery and sends nothing, so a reused pid is safe.
        assert_eq!(processes.signal(0), 0, "no process is signalled");
    }
}

/// BOX-013: a pid in the daemon's own namespace that is not the daemon's
/// child is not a supervisor the daemon spawned. A reaped supervisor's pid
/// can be reused by such a process, so the stop signals nothing.
#[test]
fn of_container_on_a_pid_the_daemon_did_not_spawn_signals_nothing() {
    use std::io::BufRead as _;

    // The shell's background `sleep` is a grandchild: its parent is the shell.
    let mut shell = std::process::Command::new("/bin/sh")
        .args(["-c", "sleep 30 & echo $!; wait"])
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("spawn the stand-in shell");
    let mut line = String::new();
    std::io::BufReader::new(shell.stdout.take().expect("piped stdout"))
        .read_line(&mut line)
        .expect("read the grandchild's pid");
    let grandchild: u32 = line.trim().parse().expect("a pid");

    let processes = crate::box_runtime::BoxProcesses::of_container(grandchild);
    assert!(
        processes.pids().is_empty(),
        "a process the daemon did not spawn is not the box's supervisor"
    );
    assert_eq!(processes.signal(0), 0, "no process is signalled");

    // The grandchild is still alive: the stop did not reach it.
    // SAFETY: `kill` reads no memory of ours.
    assert_eq!(
        unsafe { libc::kill(i32::try_from(grandchild).unwrap(), 0) },
        0
    );
    // SAFETY: as above. This ends the stand-in before the shell is reaped.
    unsafe { libc::kill(i32::try_from(grandchild).unwrap(), libc::SIGKILL) };
    shell.wait().expect("reap the stand-in shell");
}

/// A session spec as a create sends it (BOX-068), with `pty_enabled` as
/// given and every other setting at its default.
fn resume_spec(pty_enabled: bool) -> serde_json_lenient::Value {
    let mut spec = mfile::spec::BoxSpec::for_session(None, mfile::spec::SpecFlags::default());
    spec.pty_enabled = pty_enabled;
    serde_json_lenient::to_value(&spec).expect("a spec serializes")
}

/// Creates an `Active` session through the whole create flow. Its create
/// carries `spec`, and `name: None` creates an unnamed session.
async fn create_session_with_spec(
    client: &mut TestClient,
    name: Option<&str>,
    project: &str,
    spec: Option<serde_json_lenient::Value>,
) -> SessionId {
    use crate::test_harness::{create_session_req, unwrap_ready};
    use minimald_rpc::{
        ConfigureLoadout, ConfigureLoadoutRequest, CreateSession, Errorable, FinalizeSession,
        FinalizeSessionRequest,
    };

    let mut req = create_session_req(name.unwrap_or("unnamed"), project);
    if name.is_none() {
        req.config.name = None;
    }
    req.spec = spec;
    let id = client.call::<CreateSession>(&req).await.unwrap().id;
    unwrap_ready(
        client
            .call::<ConfigureLoadout>(&ConfigureLoadoutRequest {
                session_id: id,
                contribution: Default::default(),
            })
            .await
            .unwrap(),
    );
    match client
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

/// Stops the box `id` through the daemon (BOX-013), and waits until the
/// manager no longer holds its actor, so the next attach brings one up
/// from the stopped record.
async fn stop_through_daemon(
    server: &TestServer,
    id: SessionId,
) -> boxes::core::record::StopEnding {
    let manager = server.state.sessions_manager().await;
    let before = manager.running_count().await;
    manager
        .get_session(crate::box_manager::BoxKeyPredicate::Id(id))
        .await
        .unwrap()
        .expect("the session resolves")
        .ensure_host("tester".to_string())
        .await
        .expect("an Active session launches a headless host");
    let ending = manager
        .stop_box_with_grace(id, true, Duration::from_secs(5))
        .await
        .expect("the stop succeeds");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    while manager.running_count().await >= before {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the stopped box's actor was not evicted"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    ending
}

/// The directory that holds the record of `id`.
async fn record_dir(server: &TestServer, id: SessionId) -> std::path::PathBuf {
    let sessions = server
        .state
        .minimal_state_dir()
        .await
        .as_utf8_path()
        .join("sessions");
    for entry in std::fs::read_dir(&sessions).unwrap() {
        let dir = entry.unwrap().path();
        let Ok(bytes) = std::fs::read(dir.join("record.json")) else {
            continue;
        };
        let record: boxes::Record = serde_json_lenient::from_slice(&bytes).unwrap();
        if record.id == id {
            return dir;
        }
    }
    panic!("no record directory holds {id}");
}

/// Changes the record of `id` on disk, as a change made while the box ran
/// or an ending this build has no path for leaves it. The store reads the
/// record from disk on every read.
async fn rewrite_record(
    server: &TestServer,
    id: SessionId,
    change: impl FnOnce(&mut boxes::Record),
) {
    let path = record_dir(server, id).await.join("record.json");
    let mut record: boxes::Record =
        serde_json_lenient::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    change(&mut record);
    std::fs::write(&path, serde_json_lenient::to_vec(&record).unwrap()).unwrap();
}

/// Overwrites the spec stored beside the record of `id`.
async fn rewrite_spec(server: &TestServer, id: SessionId, spec: &serde_json_lenient::Value) {
    let path = record_dir(server, id).await.join("spec.json");
    std::fs::write(path, serde_json_lenient::to_vec(spec).unwrap()).unwrap();
}

/// Attaches to `id` and sends a line. `Ok` when the shell echoes it, and
/// `Err` with what the channel carried when it closes first, and the
/// `ChannelMsg::ExitStatus` it saw, if any.
async fn attach_and_echo(
    client: &mut TestClient,
    id: SessionId,
) -> Result<(), (String, Option<u32>)> {
    let mut channel = client.open_shell(id).await;
    let _ = channel.data_bytes(b"hello\n".to_vec()).await;
    let mut out = Vec::new();
    let mut exit_status = None;
    loop {
        match tokio::time::timeout(Duration::from_secs(30), channel.wait()).await {
            Ok(Some(ChannelMsg::Data { data })) => {
                out.extend_from_slice(&data);
                if String::from_utf8_lossy(&out).contains("got:hello") {
                    return Ok(());
                }
            }
            Ok(Some(ChannelMsg::ExitStatus { exit_status: code })) => exit_status = Some(code),
            Ok(Some(_)) => {}
            Ok(None) | Err(_) => {
                return Err((String::from_utf8_lossy(&out).into_owned(), exit_status));
            }
        }
    }
}

async fn read_record(server: &TestServer, id: SessionId) -> boxes::Record {
    server
        .state
        .sessions_manager()
        .await
        .get_record(crate::box_manager::BoxKeyPredicate::Id(id))
        .await
        .unwrap()
        .expect("the box keeps its record")
}

async fn event_kinds(server: &TestServer, id: SessionId) -> Vec<boxes::events::BoxEvent> {
    server
        .state
        .sessions_manager()
        .await
        .box_events(id)
        .await
        .unwrap()
        .read_new()
        .unwrap()
}

/// BOX-025: an attach to a stopped PTY box starts it again from the spec
/// stored at its creation, from its retained files, under the same id and
/// name, and records a `resumed` event. A change made to the record's
/// settings while the box ran does not carry into the restart.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn resume_restarts_from_stored_spec_same_id_and_name() {
    use boxes::core::record::RecordState;

    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let id = create_session_with_spec(
        &mut client,
        Some("resume-box"),
        "/uwu",
        Some(resume_spec(true)),
    )
    .await;
    let paths = session_paths(&server, id).await;
    let kept = std::path::Path::new(paths.working.as_str()).join("kept.txt");
    std::fs::write(&kept, "still here").unwrap();
    // A change while the box runs: the stored spec has hooks on.
    rewrite_record(&server, id, |record| record.hooks_enabled = false).await;

    let ending = stop_through_daemon(&server, id).await;
    assert_eq!(
        read_record(&server, id).await.state().unwrap(),
        RecordState::Stopped(ending)
    );

    attach_and_echo(&mut client, id)
        .await
        .expect("an attach to a stopped PTY box resumes it");

    let record = read_record(&server, id).await;
    assert_eq!(record.id, id, "the box keeps its id");
    assert_eq!(
        record.name.as_deref(),
        Some("resume-box"),
        "the box keeps its name"
    );
    assert_eq!(record.state().unwrap(), RecordState::Running);
    assert_eq!(
        (record.reason.is_none(), record.exit_code, record.signal),
        (true, None, None)
    );
    assert!(
        record.hooks_enabled,
        "the box restarts from its stored spec, not the record's change"
    );
    assert_eq!(std::fs::read_to_string(&kept).unwrap(), "still here");

    let events = event_kinds(&server, id).await;
    let kinds: Vec<_> = events.iter().map(|e| e.kind).collect();
    let exited = kinds
        .iter()
        .position(|k| *k == boxes::events::BoxEventType::Exited)
        .expect("the stop records an exited event");
    let resumed = kinds
        .iter()
        .position(|k| *k == boxes::events::BoxEventType::Resumed)
        .expect("the resume records a resumed event");
    assert!(exited < resumed, "{kinds:?}");
    assert_eq!(events[resumed].box_id, id);
    assert_eq!(events[resumed].data["from"], "stopped");
}

/// BOX-025: a resume whose launch fails writes back the record it read,
/// byte for byte, and records no `resumed` event, so the box never reads
/// as running with no processes and keeps the settings it had. The next
/// attach resumes it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn resume_launch_failure_keeps_stopped_state() {
    use boxes::core::record::RecordState;

    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let id = create_session_with_spec(
        &mut client,
        Some("resume-fails"),
        "/uwu",
        Some(resume_spec(true)),
    )
    .await;
    // A setting the stored spec changes on resume: the stored spec has
    // hooks on.
    rewrite_record(&server, id, |record| record.hooks_enabled = false).await;
    let ending = stop_through_daemon(&server, id).await;
    let record_path = record_dir(&server, id).await.join("record.json");
    let before = std::fs::read(&record_path).unwrap();
    assert!(!read_record(&server, id).await.hooks_enabled);

    super::mint_attach_seam::seed(id, super::mint_attach_seam::Failure::HostDiedBeforeAttach);
    attach_and_echo(&mut client, id)
        .await
        .expect_err("the attach whose launch fails reaches no shell");
    assert_eq!(
        read_record(&server, id).await.state().unwrap(),
        RecordState::Stopped(ending),
        "a failed launch leaves the box stopped"
    );
    assert_eq!(
        String::from_utf8_lossy(&std::fs::read(&record_path).unwrap()),
        String::from_utf8_lossy(&before),
        "a failed launch leaves the record as it was"
    );
    assert!(
        !event_kinds(&server, id)
            .await
            .iter()
            .any(|e| e.kind == boxes::events::BoxEventType::Resumed),
        "a failed launch records no resumed event"
    );

    attach_and_echo(&mut client, id)
        .await
        .expect("the next attach resumes the box");
    assert_eq!(
        read_record(&server, id).await.state().unwrap(),
        RecordState::Running
    );
}

/// BOX-030: a PTY box resumes from `stopped` and from `exited`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pty_box_resumes_from_stopped_and_exited() {
    use boxes::core::record::{ExitEnding, RecordState};

    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let id = create_session_with_spec(
        &mut client,
        Some("pty-box"),
        "/uwu",
        Some(resume_spec(true)),
    )
    .await;

    stop_through_daemon(&server, id).await;
    attach_and_echo(&mut client, id)
        .await
        .expect("a stopped PTY box resumes");
    assert_eq!(
        read_record(&server, id).await.state().unwrap(),
        RecordState::Running
    );

    // No path in this build ends a box `exited`, so the record is set so
    // after a stop.
    stop_through_daemon(&server, id).await;
    rewrite_record(&server, id, |record| {
        record.set_state(RecordState::Exited(ExitEnding::Exit { exit_code: 3 }));
    })
    .await;
    attach_and_echo(&mut client, id)
        .await
        .expect("an exited PTY box resumes");
    assert_eq!(
        read_record(&server, id).await.state().unwrap(),
        RecordState::Running
    );

    let froms: Vec<_> = event_kinds(&server, id)
        .await
        .into_iter()
        .filter(|e| e.kind == boxes::events::BoxEventType::Resumed)
        .map(|e| e.data["from"].clone())
        .collect();
    assert_eq!(froms, ["stopped", "exited"]);
}

/// Asserts that the resume of `id` was refused: the attach closed with
/// `words`, no shell and the exit status `code`, the record is still
/// `state`, and no `resumed` event was written.
async fn assert_resume_refused(
    server: &TestServer,
    client: &mut TestClient,
    id: SessionId,
    state: boxes::core::record::RecordState,
    words: &[&str],
    code: u32,
) {
    let (out, exit_status) = attach_and_echo(client, id)
        .await
        .expect_err("the resume is refused");
    assert_eq!(exit_status, Some(code), "{out:?}");
    for word in words {
        assert!(out.contains(word), "{word:?} not in {out:?}");
    }
    assert!(out.contains("cannot resume"), "{out:?}");
    assert_eq!(read_record(server, id).await.state().unwrap(), state);
    assert!(
        event_kinds(server, id)
            .await
            .iter()
            .all(|e| e.kind != boxes::events::BoxEventType::Resumed),
        "a refused resume writes no resumed event"
    );
}

/// BOX-025: a resume whose stored spec this daemon cannot start from is
/// refused with the kind a create of that spec gives, and the box stays
/// stopped.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn resume_refuses_unsatisfiable_spec_keeps_state() {
    use boxes::core::record::RecordState;

    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let id = create_session_with_spec(
        &mut client,
        Some("old-spec"),
        "/uwu",
        Some(resume_spec(true)),
    )
    .await;
    let ending = stop_through_daemon(&server, id).await;
    let mut spec = resume_spec(true);
    spec["v"] = 99.into();
    rewrite_spec(&server, id, &spec).await;

    assert_resume_refused(
        &server,
        &mut client,
        id,
        RecordState::Stopped(ending),
        &[
            "session `old-spec`",
            "version 99",
            "min session destroy old-spec",
        ],
        3,
    )
    .await;

    // A spec that does not parse is refused the same way.
    rewrite_spec(
        &server,
        id,
        &serde_json_lenient::json!({"v": 0, "io": {"pty_enabled": true}}),
    )
    .await;
    assert_resume_refused(
        &server,
        &mut client,
        id,
        RecordState::Stopped(ending),
        &["cannot be read"],
        3,
    )
    .await;
}

/// BOX-025: a resume is refused while a running box holds the box's name,
/// naming that box, and the name check comes before the spec check.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn resume_refuses_when_name_held_by_running_box() {
    use boxes::core::record::RecordState;

    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let stopped =
        create_session_with_spec(&mut client, Some("proj"), "/a/x", Some(resume_spec(true))).await;
    let ending = stop_through_daemon(&server, stopped).await;
    // An unnamed box answers to its project directory's name.
    let holder = create_session_with_spec(&mut client, None, "/b/proj", None).await;
    assert_eq!(
        read_record(&server, holder).await.state().unwrap(),
        RecordState::Running
    );
    // Also unsatisfiable, so the refusal shows which check decides.
    let mut spec = resume_spec(true);
    spec["v"] = 99.into();
    rewrite_spec(&server, stopped, &spec).await;

    assert_resume_refused(
        &server,
        &mut client,
        stopped,
        RecordState::Stopped(ending),
        &[
            "The running session `proj` holds the name `proj`",
            &format!("min session rename {holder} <new-name>"),
        ],
        2,
    )
    .await;
}

/// BOX-025, BOX-005: two stopped boxes that share a name resume at once.
/// Each has its own actor, so the name check claims the name in the
/// manager. Exactly one box runs. The other is refused with exit status 2
/// and keeps its `stopped` record.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn resume_concurrent_same_name_runs_exactly_one() {
    use boxes::core::record::RecordState;

    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let mut boxes_ = Vec::new();
    // Unnamed boxes answer to their project directory's name, a pair the
    // store's name-uniqueness check never sees.
    for project in ["/a/pair", "/b/pair"] {
        let id =
            create_session_with_spec(&mut client, None, project, Some(resume_spec(true))).await;
        let ending = stop_through_daemon(&server, id).await;
        boxes_.push((id, ending));
    }
    let mut first = server.connect().await;
    let mut second = server.connect().await;
    let (a, b) = tokio::join!(
        attach_and_echo(&mut first, boxes_[0].0),
        attach_and_echo(&mut second, boxes_[1].0),
    );

    let (ran, refused, out) = match (a, b) {
        (Ok(()), Err(out)) => (boxes_[0], boxes_[1], out),
        (Err(out), Ok(())) => (boxes_[1], boxes_[0], out),
        other => panic!("exactly one resume must run: {other:?}"),
    };
    let (text, exit_status) = out;
    assert_eq!(exit_status, Some(2), "{text:?}");
    assert!(text.contains("cannot resume"), "{text:?}");
    assert_eq!(
        read_record(&server, ran.0).await.state().unwrap(),
        RecordState::Running
    );
    assert_eq!(
        read_record(&server, refused.0).await.state().unwrap(),
        RecordState::Stopped(refused.1)
    );
    assert!(
        event_kinds(&server, refused.0)
            .await
            .iter()
            .all(|e| e.kind != boxes::events::BoxEventType::Resumed),
        "a refused resume writes no resumed event"
    );
}

/// BOX-025: a record the name check cannot read can belong to a running
/// box that holds the name, so the resume is refused and the box stays
/// stopped.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn resume_refuses_when_another_record_is_unreadable() {
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let stopped =
        create_session_with_spec(&mut client, Some("proj"), "/a/x", Some(resume_spec(true))).await;
    let ending = stop_through_daemon(&server, stopped).await;
    let other = create_session_with_spec(&mut client, Some("other"), "/b/y", None).await;
    let path = record_dir(&server, other).await.join("record.json");
    std::fs::write(&path, b"not a record").unwrap();

    assert_resume_refused(
        &server,
        &mut client,
        stopped,
        boxes::core::record::RecordState::Stopped(ending),
        &[&format!("The record of session `{other}` cannot be read")],
        2,
    )
    .await;
}

/// BOX-030: a resume of a box whose spec does not set `pty_enabled` is
/// refused, and the box stays stopped. The terminal check comes first.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn resume_non_pty_box_refuses_keeps_state() {
    use boxes::core::record::RecordState;

    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let id = create_session_with_spec(
        &mut client,
        Some("no-pty"),
        "/uwu",
        Some(resume_spec(false)),
    )
    .await;
    let ending = stop_through_daemon(&server, id).await;
    // Also unsatisfiable, so the refusal shows which check decides.
    let mut spec = resume_spec(false);
    spec["v"] = 99.into();
    rewrite_spec(&server, id, &spec).await;

    assert_resume_refused(
        &server,
        &mut client,
        id,
        RecordState::Stopped(ending),
        &["session `no-pty`", "runs without a terminal"],
        2,
    )
    .await;
}

/// BOX-027: a resume runs no lifecycle hook but `on_attach`, on the attach
/// that resumes the box. The box's `on_activate` ran once, at activation,
/// and does not run again when the box resumes. The resume itself runs
/// no hook. The `on_attach` run is the attach's own, and the mock launcher
/// cannot show it (see the note above
/// `destroy_runs_its_destroy_hooks_against_a_live_host`).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn resume_runs_only_on_attach_hook() {
    let dir = tempfile::tempdir().unwrap();
    let activated = dir.path().join("activated");
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let id = session_with_hook(
        &mut client,
        "resume-hooks",
        boxes::wire::primitives::WireLifecycleHook {
            on_activate: Some(inline(format!("echo ran >> {}", activated.display()))),
            ..Default::default()
        },
    )
    .await;
    assert_eq!(std::fs::read_to_string(&activated).unwrap(), "ran\n");

    stop_through_daemon(&server, id).await;
    attach_and_echo(&mut client, id)
        .await
        .expect("the stopped box resumes");
    assert_eq!(
        std::fs::read_to_string(&activated).unwrap(),
        "ran\n",
        "on_activate ran again on resume"
    );
}
