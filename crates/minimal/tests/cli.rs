//! Integration tests for minimal CLI commands.
//!
//! Each test spins up a real minimald `TestServer` on a UDS, then calls
//! the `cmd_*` functions from the `minimal` library as if the user had
//! invoked the CLI. The daemon's state is inspected directly (via
//! `TestClient`) to verify side-effects.

mod common;

use common::setup;
use minimal::*;
use minimald_rpc::{ListSessionsResponse, ResourcePool};
use sessions::SessionId;

use minimald::test_harness::unwrap_ready;

use serde_json_lenient::Value;

// --- version ---

#[tokio::test]
async fn version_succeeds_with_daemon_running() {
    let (_daemon, args) = setup().await;
    cmd_version(&args).await.unwrap();
}

#[tokio::test]
async fn version_succeeds_without_daemon() {
    let args = GlobalArgs {
        repo_dir: None,
        minimal_dir: Some(std::path::PathBuf::from("/nonexistent")),
        config_dir: None,
        provider: None,
        no_input: false,
    };
    // Should print client version and note daemon is unreachable, but return Ok.
    cmd_version(&args).await.unwrap();
}

// --- ls ---

#[test]
fn ls_shows_shared_resource_pool() {
    let resp = ListSessionsResponse {
        resource_pool: Some(ResourcePool {
            cpu_cores: 8,
            memory_bytes: 16 * 1024 * 1024 * 1024,
        }),
        sessions: vec![minimald_rpc::ListSessionsEntry {
            id: SessionId::nil(),
            name: None,
            project_path: Some(paths::HostAbsPath::try_new("/p").unwrap()),
            status: sessions::SessionStatus::Active,
            attrs: None,
        }],
    };
    let mut out = Vec::new();

    format_ls(
        &mut out,
        &LsArgs {
            raw: false,
            json: false,
        },
        &resp,
    )
    .unwrap();

    let text = String::from_utf8(out).unwrap();
    assert!(
        text.starts_with("RESOURCE POOL:  8 CPU cores · 16 GiB memory · shared by 1 session\n\n")
    );
}

#[test]
fn ls_table_exposes_project_path_and_status() {
    let resp = ListSessionsResponse {
        resource_pool: None,
        sessions: vec![minimald_rpc::ListSessionsEntry {
            id: SessionId::nil(),
            name: Some("s1".to_string()),
            project_path: Some(paths::HostAbsPath::try_new("/work/proj").unwrap()),
            status: sessions::SessionStatus::Active,
            attrs: None,
        }],
    };
    let mut out = Vec::new();

    format_ls(
        &mut out,
        &LsArgs {
            raw: false,
            json: false,
        },
        &resp,
    )
    .unwrap();

    let text = String::from_utf8(out).unwrap();
    assert!(text.contains("STATUS"), "header should list STATUS: {text}");
    assert!(
        text.contains("PROJECT PATH"),
        "header should list PROJECT PATH: {text}"
    );
    assert!(text.contains("active"), "row should show status: {text}");
    assert!(
        text.contains("/work/proj"),
        "row should show project path: {text}"
    );
}

#[tokio::test]
async fn ls_empty() {
    let (_daemon, args) = setup().await;
    let mut client = connect_daemon(&args).await.unwrap();
    use minimald_rpc::ListSessions;
    let resp = client.oneshot_rpc::<ListSessions>(()).await.unwrap();

    let mut out = Vec::new();
    format_ls(
        &mut out,
        &LsArgs {
            raw: false,
            json: false,
        },
        &resp,
    )
    .unwrap();
    let text = String::from_utf8(out).unwrap();
    assert!(text.contains("No active sessions."));
}

#[tokio::test]
async fn ls_raw_empty() {
    let (_daemon, args) = setup().await;
    let mut client = connect_daemon(&args).await.unwrap();
    use minimald_rpc::ListSessions;
    let resp = client.oneshot_rpc::<ListSessions>(()).await.unwrap();

    let mut out = Vec::new();
    format_ls(
        &mut out,
        &LsArgs {
            raw: true,
            json: false,
        },
        &resp,
    )
    .unwrap();
    let text = String::from_utf8(out).unwrap();
    assert!(
        text.is_empty(),
        "raw output should be empty with no sessions"
    );
}

#[tokio::test]
async fn ls_json_empty() {
    let (_daemon, args) = setup().await;
    let mut client = connect_daemon(&args).await.unwrap();
    use minimald_rpc::ListSessions;
    let resp = client.oneshot_rpc::<ListSessions>(()).await.unwrap();

    let mut out = Vec::new();
    format_ls(
        &mut out,
        &LsArgs {
            raw: false,
            json: true,
        },
        &resp,
    )
    .unwrap();
    let text = String::from_utf8(out).unwrap();
    let parsed: Value =
        serde_json_lenient::from_str(&text).expect("json output should be valid JSON");
    assert!(parsed["resource_pool"]["cpu_cores"].as_u64().unwrap() > 0);
    assert!(parsed["resource_pool"]["memory_bytes"].as_u64().unwrap() > 0);
    assert!(parsed["sessions"].is_array());
    assert!(parsed["sessions"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn ls_json_with_sessions() {
    let (daemon, args) = setup().await;
    let id1 = create_session(&daemon, "json-1").await;
    let id2 = create_session(&daemon, "json-2").await;

    let mut client = connect_daemon(&args).await.unwrap();
    use minimald_rpc::ListSessions;
    let resp = client.oneshot_rpc::<ListSessions>(()).await.unwrap();

    let mut out = Vec::new();
    format_ls(
        &mut out,
        &LsArgs {
            raw: false,
            json: true,
        },
        &resp,
    )
    .unwrap();
    let text = String::from_utf8(out).unwrap();
    let parsed: Value =
        serde_json_lenient::from_str(&text).expect("json output should be valid JSON");
    let sessions = parsed["sessions"]
        .as_array()
        .expect("sessions should be an array");
    assert_eq!(sessions.len(), 2);
    let ids: Vec<&str> = sessions.iter().map(|s| s["id"].as_str().unwrap()).collect();
    assert!(ids.contains(&id1.to_string().as_str()));
    assert!(ids.contains(&id2.to_string().as_str()));
}

#[tokio::test]
async fn ls_raw_with_sessions() {
    let (daemon, args) = setup().await;
    let id1 = create_session(&daemon, "raw-1").await;
    let id2 = create_session(&daemon, "raw-2").await;

    let mut client = connect_daemon(&args).await.unwrap();
    use minimald_rpc::ListSessions;
    let resp = client.oneshot_rpc::<ListSessions>(()).await.unwrap();

    let mut out = Vec::new();
    format_ls(
        &mut out,
        &LsArgs {
            raw: true,
            json: false,
        },
        &resp,
    )
    .unwrap();
    let text = String::from_utf8(out).unwrap();
    let lines: Vec<&str> = text.trim_end().lines().collect();
    assert_eq!(lines.len(), 2, "raw output should be one line per session");
    assert!(lines.contains(&id1.to_string().as_str()));
    assert!(lines.contains(&id2.to_string().as_str()));
}

// --- activate + ls ---

#[tokio::test]
async fn activate_creates_session() {
    let (daemon, args) = setup().await;

    // Create a temp project dir with a minimal.toml so the
    // missing-mfile prompt doesn't fire. Mark it as a VCS root so
    // the non-VCS upload confirmation (#790) short-circuits instead
    // of blocking on stdin when the test binary is attached to a TTY.
    let project = tempfile::TempDir::new().unwrap();
    std::fs::create_dir(project.path().join(".git")).unwrap();
    std::fs::write(
        project.path().join("minimal.toml"),
        "# test minimal.toml\n[upstream]\nrepo = \"https://github.com/gominimal/pkgs\"\nbranch = \"main\"\n\n[stack]\nuse = \"shell\"\n",
    )
    .unwrap();

    let activate_args = ActivateArgs {
        name: Some("test-session".to_string()),
        path: Some(project.path().to_string_lossy().to_string()),
        sync: Some(SyncMode::Tarball),
        network: CliNetworkMode::NoNet,
        ingress: vec![],
        loadout: vec![],
        no_loadouts: false,
        no_hooks: false,
        no_prompt: false,
        attach: false,
    };
    cmd_activate(&args, activate_args).await.unwrap();

    // Verify the session was created via TestClient.
    let mut client = daemon.server.connect().await;
    use minimald_rpc::ListSessions;
    let resp = client.call::<ListSessions>(&()).await;
    assert_eq!(resp.sessions.len(), 1);
    assert_eq!(resp.sessions[0].name.as_deref(), Some("test-session"));
}

// --- activate uploads project files ---

#[tokio::test]
async fn activate_uploads_project_files() {
    let (daemon, args) = setup().await;

    // Create a temp project dir with a minimal.toml and some files.
    // Mark it as a VCS root so the non-VCS upload confirmation (#790)
    // short-circuits instead of blocking on stdin when the test
    // binary is attached to a TTY.
    let project = tempfile::TempDir::new().unwrap();
    std::fs::create_dir(project.path().join(".git")).unwrap();
    std::fs::write(
        project.path().join("minimal.toml"),
        "# test\n[upstream]\nrepo = \"https://github.com/gominimal/pkgs\"\nbranch = \"main\"\n\n[stack]\nuse = \"shell\"\n",
    )
    .unwrap();
    std::fs::write(project.path().join("hello.txt"), "hello world").unwrap();
    std::fs::create_dir_all(project.path().join("subdir")).unwrap();
    std::fs::write(project.path().join("subdir/nested.txt"), "nested").unwrap();

    let activate_args = ActivateArgs {
        name: Some("upload-test".to_string()),
        path: Some(project.path().to_string_lossy().to_string()),
        sync: Some(SyncMode::Tarball),
        network: CliNetworkMode::NoNet,
        ingress: vec![],
        loadout: vec![],
        no_loadouts: false,
        no_hooks: false,
        no_prompt: false,
        attach: false,
    };
    cmd_activate(&args, activate_args).await.unwrap();

    // Look up the session and verify the uploaded files landed in the
    // session's workspace directory by reading them back over SFTP. The
    // workspace is spelled out: SFTP starts a client at the session's home,
    // so a relative path would name the wrong one of the two exports.
    let mut sftp_client = daemon.server.connect().await;
    let sessions = {
        use minimald_rpc::ListSessions;
        let resp = sftp_client.call::<ListSessions>(&()).await;
        resp.sessions
    };
    assert_eq!(sessions.len(), 1);
    let session_id: SessionId = sessions[0].id;

    let sftp = sftp_client.open_sftp(session_id).await;

    let hello = sftp.read("/workbench/hello.txt").await.unwrap();
    assert_eq!(hello, b"hello world");

    let nested = sftp.read("/workbench/subdir/nested.txt").await.unwrap();
    assert_eq!(nested, b"nested");

    let mfile = sftp.read("/workbench/minimal.toml").await.unwrap();
    assert!(mfile.starts_with(b"# test"));
}

/// A workspace upload whose unpack fails on the daemon must surface as an
/// `Err`, not a silent success. The daemon relays the failure on
/// extended-data stream 1 and only then closes the channel; the client reads
/// to that close, so the failure cannot be swallowed. Regression test for the
/// silent-upload-failure half of #824.
#[tokio::test]
async fn upload_workspace_files_surfaces_daemon_unpack_error() {
    let (_daemon, args) = setup().await;
    let mut client = connect_daemon(&args).await.unwrap();

    // A well-formed but unknown session id: the daemon can't resolve a
    // destination for the upload, reports the failure, and closes.
    let project = tempfile::TempDir::new().unwrap();
    std::fs::write(project.path().join("hello.txt"), "hello world").unwrap();

    let result = client
        .upload_workspace_files(SessionId::nil(), project.path())
        .await;
    assert!(
        result.is_err(),
        "upload to an unknown session must fail, not report success: {result:?}"
    );
}

// --- attach (smart resolution) ---

/// `min session activate` with no positional path but `-C/--repo-dir` set uploads
/// from the repo-dir directory, not the process cwd (#873).
#[tokio::test]
async fn activate_uses_repo_dir_when_no_positional_path() {
    let (daemon, mut global) = setup().await;

    let project = tempfile::TempDir::new().unwrap();
    std::fs::create_dir(project.path().join(".git")).unwrap();
    std::fs::write(
        project.path().join("minimal.toml"),
        "# test minimal.toml\n[upstream]\nrepo = \"https://github.com/gominimal/pkgs\"\nbranch = \"main\"\n\n[stack]\nuse = \"shell\"\n",
    )
    .unwrap();
    std::fs::write(project.path().join("hello.txt"), "hello world").unwrap();

    global.repo_dir = Some(project.path().to_path_buf());

    let activate_args = ActivateArgs {
        name: Some("repo-dir-test".to_string()),
        path: None,
        sync: Some(SyncMode::Tarball),
        network: CliNetworkMode::NoNet,
        ingress: vec![],
        loadout: vec![],
        no_loadouts: false,
        no_hooks: false,
        no_prompt: false,
        attach: false,
    };
    cmd_activate(&global, activate_args).await.unwrap();

    let mut client = daemon.server.connect().await;
    use minimald_rpc::ListSessions;
    let resp = client.call::<ListSessions>(&()).await;
    assert_eq!(resp.sessions.len(), 1);
    let session = &resp.sessions[0];

    let project_canon = project.path().canonicalize().unwrap();
    let session_path = session.project_path.as_ref().unwrap();
    assert_eq!(
        session_path.as_str(),
        project_canon.to_str().unwrap(),
        "session project_path should match -C/--repo-dir, not cwd"
    );

    // Spelled out for the same reason as above: the upload lands in the
    // workspace, but SFTP's relative paths resolve against the home.
    let sftp = client.open_sftp(session.id).await;
    let hello = sftp.read("/workbench/hello.txt").await.unwrap();
    assert_eq!(hello, b"hello world");
}

/// `min session attach` with no session argument and `--no-input` errors cleanly when
/// no sessions exist, rather than hanging or shelling out to ssh. The error
/// surfaces before any ssh exec, so it is deterministic in a test environment.
#[tokio::test]
async fn attach_with_no_session_errors_when_no_sessions_exist() {
    let (_daemon, mut global) = setup().await;
    global.no_input = true;

    let err = cmd_attach(&global, AttachArgs { session: None })
        .await
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("no sessions exist"),
        "expected a 'no sessions' error, got: {err}"
    );
}

/// `min session attach` with no session argument and `--no-input` errors with a list
/// of candidates when more than one session shares the current directory,
/// rather than opening a picker. Both sessions are built from the same
/// canonicalized tempdir so the cwd match is deterministic across platforms.
#[tokio::test]
async fn attach_with_no_session_errors_when_ambiguous_and_no_input() {
    let (daemon, mut global) = setup().await;

    // Two sessions built from the same directory make the choice ambiguous.
    let cwd = tempfile::TempDir::new().unwrap();
    let cwd_canon = cwd.path().canonicalize().unwrap();
    let cwd_str = camino::Utf8PathBuf::from_path_buf(cwd_canon).unwrap();
    let abs_path = paths::HostAbsPath::try_new(cwd_str).unwrap();
    create_session_at(&daemon, "amb-1", abs_path.clone()).await;
    create_session_at(&daemon, "amb-2", abs_path).await;

    global.no_input = true;
    // `--repo-dir` overrides the cwd used for matching; canonicalized by the
    // resolver, it equals the sessions' project_path above.
    global.repo_dir = Some(cwd.path().to_path_buf());

    let err = cmd_attach(&global, AttachArgs { session: None })
        .await
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("Multiple sessions match"),
        "expected an ambiguity error, got: {err}"
    );
    assert!(err.contains("amb-1"), "candidates list names: {err}");
    assert!(err.contains("amb-2"), "candidates list names: {err}");
    assert!(
        err.contains("min session attach <id>"),
        "should suggest explicit attach, got: {err}"
    );
}

// --- destroy ---

#[tokio::test]
async fn destroy_removes_session() {
    let (daemon, mut args) = setup().await;
    // Pin the gate headless. It reads `no_input || !stdin.is_terminal()`, and
    // stdin here is whatever the runner handed us: `/dev/null` under nextest
    // and CI, but a live terminal under a bare `cargo test` — where the gate
    // would prompt and the test would sit waiting for a keystroke instead.
    args.no_input = true;

    // Create a session via TestClient.
    let session_id = create_session(&daemon, "doomed").await;

    // The session has no running host, so its at-risk state is unknowable,
    // and the gate is headless, so the destroy must refuse without --force,
    // naming the escape hatch.
    let err = cmd_destroy(
        &args,
        DestroyArgs {
            session: Some(session_id.to_string()),
            all: false,
            force: false,
        },
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(err.contains("--force"), "refusal must name --force: {err}");

    // The refusal must leave the session untouched.
    let mut client = daemon.server.connect().await;
    use minimald_rpc::ListSessions;
    let resp = client.call::<ListSessions>(&()).await;
    assert_eq!(resp.sessions.len(), 1, "refusal must not destroy anything");

    // --force skips the gate and destroys it.
    cmd_destroy(
        &args,
        DestroyArgs {
            session: Some(session_id.to_string()),
            all: false,
            force: true,
        },
    )
    .await
    .unwrap();

    // Verify the session is gone.
    let resp = client.call::<ListSessions>(&()).await;
    assert!(resp.sessions.is_empty());
}

#[tokio::test]
async fn destroy_by_name() {
    let (daemon, mut args) = setup().await;
    // Headless by construction, not by whatever stdin the runner gave us —
    // see `destroy_removes_session`.
    args.no_input = true;
    let _ = create_session(&daemon, "by-name").await;

    // Name resolution precedes the gate: the headless refusal (unknowable
    // at-risk state, no input) proves the name resolved...
    let err = cmd_destroy(
        &args,
        DestroyArgs {
            session: Some("by-name".to_string()),
            all: false,
            force: false,
        },
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(err.contains("--force"), "refusal must name --force: {err}");

    // ...and --force destroys by name.
    cmd_destroy(
        &args,
        DestroyArgs {
            session: Some("by-name".to_string()),
            all: false,
            force: true,
        },
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn destroy_unknown_session_fails() {
    let (_daemon, args) = setup().await;
    let result = cmd_destroy(
        &args,
        DestroyArgs {
            session: Some("nonexistent".to_string()),
            all: false,
            force: false,
        },
    )
    .await;
    assert!(result.is_err());
}

#[tokio::test]
async fn destroy_all_removes_every_session() {
    let (daemon, args) = setup().await;
    let _ = create_session(&daemon, "first").await;
    let _ = create_session(&daemon, "second").await;

    cmd_destroy(
        &args,
        DestroyArgs {
            session: None,
            all: true,
            force: true,
        },
    )
    .await
    .unwrap();

    let mut client = daemon.server.connect().await;
    use minimald_rpc::ListSessions;
    let resp = client.call::<ListSessions>(&()).await;
    assert!(resp.sessions.is_empty());
}

#[tokio::test]
async fn destroy_all_succeeds_when_there_are_no_sessions() {
    let (_daemon, args) = setup().await;

    cmd_destroy(
        &args,
        DestroyArgs {
            session: None,
            all: true,
            force: true,
        },
    )
    .await
    .unwrap();
}

// --- stop ---

#[tokio::test]
async fn stop_succeeds_when_no_sessions() {
    let (_daemon, args) = setup().await;
    cmd_stop(&args, StopArgs { force: false }).await.unwrap();
}

#[tokio::test]
async fn stop_succeeds_with_idle_session() {
    let (daemon, args) = setup().await;
    let session_id = create_session(&daemon, "idle").await;
    daemon.server.bring_session_up(session_id).await;

    // An idle session (actor up, but no shell hosted and no create flow in
    // flight) does not block an unforced stop; its record survives for the
    // next daemon start.
    cmd_stop(&args, StopArgs { force: false }).await.unwrap();
}

#[tokio::test]
async fn stop_refuses_with_pending_session() {
    let (daemon, args) = setup().await;
    // A Pending session (mid create flow, awaiting the client's verdict) is
    // busy: an unforced stop must refuse rather than strand the flow.
    let _id = create_pending_session(&daemon, "mid-create").await;

    let result = cmd_stop(&args, StopArgs { force: false }).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn stop_force_succeeds_with_live_session() {
    let (daemon, args) = setup().await;
    let session_id = create_session(&daemon, "active").await;
    daemon.server.bring_session_up(session_id).await;

    cmd_stop(&args, StopArgs { force: true }).await.unwrap();
}

// --- rename ---

#[tokio::test]
async fn rename_session() {
    let (daemon, args) = setup().await;
    let session_id = create_session(&daemon, "old-name").await;

    cmd_rename(
        &args,
        RenameArgs {
            session: session_id.to_string(),
            new_name: "new-name".to_string(),
        },
    )
    .await
    .unwrap();

    // Verify the rename via TestClient.
    let mut client = daemon.server.connect().await;
    use minimald_rpc::{GetSessionRecord, GetSessionRecordRequest};
    let resp = client
        .call::<GetSessionRecord>(&GetSessionRecordRequest::Id(session_id))
        .await;
    assert_eq!(resp.record.unwrap().name.as_deref(), Some("new-name"));
}

#[tokio::test]
async fn rename_by_name() {
    let (daemon, args) = setup().await;
    let _ = create_session(&daemon, "before").await;

    cmd_rename(
        &args,
        RenameArgs {
            session: "before".to_string(),
            new_name: "after".to_string(),
        },
    )
    .await
    .unwrap();
}

// --- session policy ---

#[tokio::test]
async fn session_policy_succeeds() {
    let (daemon, args) = setup().await;
    let session_id = create_session(&daemon, "policy-test").await;

    cmd_session_policy(
        &args,
        PolicyArgs {
            session: session_id.to_string(),
        },
    )
    .await
    .unwrap();
}

// --- helpers ---

/// Creates a session whose workspace mfile declares a `[session.vars]`
/// entry, which the daemon must route back to the client for gating — so
/// configuring its loadout returns `Pending` and the session actor parks in
/// its Draft state awaiting a verdict. Returns its ID.
async fn create_pending_session(daemon: &common::TestDaemon, name: &str) -> SessionId {
    let mut client = daemon.server.connect().await;
    let project_path =
        camino::Utf8PathBuf::from_path_buf(std::env::current_dir().unwrap()).unwrap();
    let config = minimald_rpc::SessionConfig {
        name: Some(name.to_string()),
        project_path: paths::HostAbsPath::try_new(project_path).unwrap(),
        network: sessions::NetworkMode::NoNet,
        policy: Default::default(),
        hooks_enabled: true,
        attrs: Default::default(),
    };

    use minimald_rpc::{
        ConfigureLoadout, ConfigureLoadoutRequest, ConfigureLoadoutResponse, CreateSession,
        CreateSessionRequest,
    };
    let id = client
        .call::<CreateSession>(&CreateSessionRequest { config })
        .await
        .unwrap()
        .id;
    daemon
        .server
        .seed_workspace_mfile(id, "[session.vars]\nRUST_LOG = \"info\"\n")
        .await;
    let resp = client
        .call::<ConfigureLoadout>(&ConfigureLoadoutRequest {
            session_id: id,
            contribution: Default::default(),
        })
        .await;
    match resp {
        minimald_rpc::Errorable::Ok(ConfigureLoadoutResponse::Pending { .. }) => id,
        other => panic!("expected a Pending loadout, got {other:?}"),
    }
}

async fn create_session(daemon: &common::TestDaemon, name: &str) -> SessionId {
    let project_path =
        camino::Utf8PathBuf::from_path_buf(std::env::current_dir().unwrap()).unwrap();
    let abs_path = paths::HostAbsPath::try_new(project_path).unwrap();
    create_session_at(daemon, name, abs_path).await
}

/// Like [`create_session`] but builds the session from `project_path` instead
/// of the test process's current directory. Used to place sessions at a known
/// path so smart-attach resolution can match against it deterministically.
async fn create_session_at(
    daemon: &common::TestDaemon,
    name: &str,
    project_path: paths::HostAbsPath,
) -> SessionId {
    let mut client = daemon.server.connect().await;

    let config = minimald_rpc::SessionConfig {
        name: Some(name.to_string()),
        project_path,
        network: sessions::NetworkMode::NoNet,
        policy: Default::default(),
        hooks_enabled: true,
        attrs: Default::default(),
    };

    use minimald_rpc::{
        ConfigureLoadout, ConfigureLoadoutRequest, CreateSession, CreateSessionRequest,
        FinalizeSession, FinalizeSessionRequest,
    };
    let id = match client
        .call::<CreateSession>(&CreateSessionRequest { config })
        .await
    {
        minimald_rpc::Errorable::Ok(r) => r.id,
        minimald_rpc::Errorable::Err { error } => {
            panic!("CreateSession failed: {error}")
        }
    };
    // Configure the loadout, then finalize — the workspace is
    // empty so the composition has no patches and Finalize takes
    // the empty-composition short-circuit past the marker check.
    match client
        .call::<ConfigureLoadout>(&ConfigureLoadoutRequest {
            session_id: id,
            contribution: Default::default(),
        })
        .await
    {
        minimald_rpc::Errorable::Ok(r) => unwrap_ready(r),
        minimald_rpc::Errorable::Err { error } => {
            panic!("ConfigureLoadout failed: {error}")
        }
    }
    match client
        .call::<FinalizeSession>(&FinalizeSessionRequest { session_id: id })
        .await
    {
        minimald_rpc::Errorable::Ok(_) => {}
        minimald_rpc::Errorable::Err { error } => {
            panic!("FinalizeSession failed: {error}")
        }
    }
    id
}
