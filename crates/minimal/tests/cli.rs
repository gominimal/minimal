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
        daemon_version: None,
        hostname_routing_unavailable: None,
        hostname_proxy_port: None,
        zone_answerer_port: None,
        resource_pool: Some(ResourcePool {
            cpu_cores: 8,
            memory_bytes: 16 * 1024 * 1024 * 1024,
        }),
        sessions: vec![minimald_rpc::ListSessionsEntry {
            id: SessionId::nil(),
            name: None,
            project_path: Some(paths::HostAbsPath::try_new("/p").unwrap()),
            status: sessions::SessionStatus::Active,
            git: None,
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
        daemon_version: None,
        hostname_routing_unavailable: None,
        hostname_proxy_port: None,
        zone_answerer_port: None,
        resource_pool: None,
        sessions: vec![minimald_rpc::ListSessionsEntry {
            id: SessionId::nil(),
            name: Some("s1".to_string()),
            project_path: Some(paths::HostAbsPath::try_new("/work/proj").unwrap()),
            status: sessions::SessionStatus::Active,
            git: None,
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
        allow_subnets: vec![],
        allow_dns_hosts: vec![],
        allow_protocols: vec![],
        deny_subnets: vec![],
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
        allow_subnets: vec![],
        allow_dns_hosts: vec![],
        allow_protocols: vec![],
        deny_subnets: vec![],
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
        allow_subnets: vec![],
        allow_dns_hosts: vec![],
        allow_protocols: vec![],
        deny_subnets: vec![],
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

/// `min session activate` puts a session id on stdout only for a session
/// that can actually run `exec`. When the daemon refuses to compose one,
/// the activation must fail with stdout untouched — otherwise a script's
/// `id=$(min session activate)` captures an id whose every `min session
/// exec` then fails — and the error must name the directory the user ran
/// from rather than the daemon-side step that broke (#581).
///
/// Driven through the compiled binary, not `cmd_activate`: the contract
/// under test is what reaches the process's stdout. The composition is
/// broken by a project var inheriting a name no environment defines — the
/// daemon routes it back for gating and resolving it fails, which is the
/// way an activation actually reaches a composition failure today.
#[tokio::test]
async fn activate_prints_no_session_id_when_composition_fails() {
    let (_daemon, args) = setup().await;
    let minimal_dir = args.minimal_dir.clone().expect("setup points at a tempdir");

    // `.git` marks a VCS root so the upload gate doesn't prompt; the
    // var name is unique enough that no environment defines it.
    let project = tempfile::TempDir::new().unwrap();
    std::fs::create_dir(project.path().join(".git")).unwrap();
    std::fs::write(
        project.path().join("minimal.toml"),
        "[session.vars]\nMIN_UNRESOLVABLE_INHERIT_581 = { inherit = true }\n",
    )
    .unwrap();
    let project_canon = project.path().canonicalize().unwrap();

    // An empty config dir keeps the developer's own loadouts and policy
    // out of the run.
    let config_dir = tempfile::TempDir::new().unwrap();
    let out = tokio::process::Command::new(env!("CARGO_BIN_EXE_min"))
        .args(["--minimal-dir".as_ref(), minimal_dir.as_os_str()])
        .args(["--config-dir".as_ref(), config_dir.path().as_os_str()])
        .arg("--no-input")
        .args(["session", "activate"])
        .arg(&project_canon)
        .args(["--name", "composition-failure", "--sync", "tarball"])
        .arg("--no-prompt")
        .output()
        .await
        .expect("the min binary should be invocable");

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success(),
        "activation must fail: stdout={stdout} stderr={stderr}"
    );
    assert!(
        stdout.trim().is_empty(),
        "a session that cannot compose must put nothing on stdout, got: {stdout}"
    );
    assert!(
        stderr.contains(project_canon.to_str().unwrap()),
        "the error must name the directory the activation ran from: {stderr}"
    );
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

/// `min session policy` shows the effective egress rules (NET-061): the four
/// egress fields the session was activated with, each unset dimension
/// resolved to its default instead of a bare `null`. The policy is stored
/// through the daemon and fetched the way the command fetches it;
/// `format_policy` is the rendering the command prints. The same egress on a
/// host-address box is still shown, but with no ingress block, and a none
/// box shows no blocks at all — just the note the TUI shows in their place.
#[tokio::test]
async fn policy_shows_effective_egress() {
    let (daemon, args) = setup().await;
    let egress = sessions::EgressPolicy {
        allow_subnets: Some(vec!["10.0.0.0/8".to_string()]),
        allow_dns_hosts: Some(vec!["github.com".to_string()]),
        allow_protocols: Some(vec![sessions::IpProto::Tcp]),
        deny_subnets: Some(vec!["169.254.169.254/32".to_string()]),
    };
    let session_id = create_session_with_policy(
        &daemon,
        "egress-policy",
        sessions::NetworkMode::OwnIp,
        sessions::SessionPolicy::new(Some(egress.clone()), None),
    )
    .await;

    let mut client = connect_daemon(&args).await.unwrap();
    use minimald_rpc::{GetSessionPolicy, GetSessionPolicyRequest};
    let resp = client
        .oneshot_rpc::<GetSessionPolicy>(GetSessionPolicyRequest::Id(session_id))
        .await
        .unwrap();
    let policy = match resp {
        minimald_rpc::Errorable::Ok(policy) => policy,
        minimald_rpc::Errorable::Err { error } => panic!("GetSessionPolicy failed: {error}"),
    };
    assert_eq!(
        policy.egress,
        Some(egress.clone()),
        "the stored egress must survive the record round trip"
    );

    let mut out = Vec::new();
    format_policy(&mut out, &policy, sessions::NetworkMode::OwnIp).unwrap();
    let text = String::from_utf8(out).unwrap();
    assert!(
        text.contains("subnets  10.0.0.0/8"),
        "allowed subnets missing:\n{text}"
    );
    assert!(
        text.contains("dns hosts  github.com"),
        "allowed hosts missing:\n{text}"
    );
    assert!(
        text.contains("protocols  tcp"),
        "allowed protocols missing:\n{text}"
    );
    assert!(
        text.contains("deny subnets  169.254.169.254/32"),
        "denied subnets missing:\n{text}"
    );

    // The same egress is accepted on a host-address box (NET-120), but the
    // ingress block is suppressed there: a host-address session shares its
    // host's namespace, so minimald applies no per-session ingress to it and
    // a `deny all` row would claim a deny-rule that does not exist. The TUI's
    // detail pane suppresses the block for the same reason.
    let host_id = create_session_with_policy(
        &daemon,
        "egress-policy-host",
        sessions::NetworkMode::HostNet,
        sessions::SessionPolicy::new(Some(egress.clone()), None),
    )
    .await;
    let resp = client
        .oneshot_rpc::<GetSessionPolicy>(GetSessionPolicyRequest::Id(host_id))
        .await
        .unwrap();
    let policy = match resp {
        minimald_rpc::Errorable::Ok(policy) => policy,
        minimald_rpc::Errorable::Err { error } => panic!("GetSessionPolicy failed: {error}"),
    };
    let mut out = Vec::new();
    format_policy(&mut out, &policy, sessions::NetworkMode::HostNet).unwrap();
    let text = String::from_utf8(out).unwrap();
    assert!(
        text.contains("subnets  10.0.0.0/8"),
        "the host-address egress rules are still shown:\n{text}"
    );
    assert!(
        !text.contains("ingress"),
        "a host-address session has no per-session ingress policy to show:\n{text}"
    );

    // A none box has no network, so it can carry no egress or ingress
    // declaration at all — the whole policy is replaced by the one-line
    // note the TUI's detail pane shows, since `egress / allow all` there
    // would claim a reach a box with no network does not have.
    let none_id = create_session_with_policy(
        &daemon,
        "egress-policy-none",
        sessions::NetworkMode::NoNet,
        sessions::SessionPolicy::default(),
    )
    .await;
    let resp = client
        .oneshot_rpc::<GetSessionPolicy>(GetSessionPolicyRequest::Id(none_id))
        .await
        .unwrap();
    let policy = match resp {
        minimald_rpc::Errorable::Ok(policy) => policy,
        minimald_rpc::Errorable::Err { error } => panic!("GetSessionPolicy failed: {error}"),
    };
    let mut out = Vec::new();
    format_policy(&mut out, &policy, sessions::NetworkMode::NoNet).unwrap();
    let text = String::from_utf8(out).unwrap();
    assert_eq!(
        text, "No network policy (NoNet)\n",
        "a none session prints the note in place of both blocks:\n{text}"
    );
}

// --- hostname routing warning (NET-020/NET-021/NET-022) ---
//
// The startup retry lives in `minimald::server` behind the Linux gate with the
// `net` module it drives, so this section is Linux-only too: it holds a port,
// runs the real retry loop against it, and reads what `min ls` and
// `min session activate` print while the proxy is down and after it recovers.

/// Runs the compiled `min` with the harness daemon's `--minimal-dir`, an empty
/// `--config-dir` (the developer's own loadouts and policy stay out of the
/// run), and `--no-input`, plus `extra` as the command, and returns its
/// captured output.
#[cfg(target_os = "linux")]
async fn run_min(args: &GlobalArgs, extra: &[&str]) -> std::process::Output {
    let minimal_dir = args
        .minimal_dir
        .as_ref()
        .expect("setup points at a tempdir");
    let config_dir = tempfile::TempDir::new().unwrap();
    tokio::process::Command::new(env!("CARGO_BIN_EXE_min"))
        .args(["--minimal-dir".as_ref(), minimal_dir.as_os_str()])
        .args(["--config-dir".as_ref(), config_dir.path().as_os_str()])
        .arg("--no-input")
        .args(extra)
        .output()
        .await
        .expect("the min binary should be invocable")
}

/// [`run_min`]'s stderr — the warning path's tests read what the user sees.
#[cfg(target_os = "linux")]
async fn run_min_stderr(args: &GlobalArgs, extra: &[&str]) -> String {
    String::from_utf8_lossy(&run_min(args, extra).await.stderr).into_owned()
}

/// Polls `ListSessions` until the daemon reports hostname routing down — the
/// startup retry's first failed bind has landed on its note — and returns the
/// reason.
#[cfg(target_os = "linux")]
async fn wait_for_routing_failure(args: &GlobalArgs) -> String {
    use minimald_rpc::ListSessions;

    let mut client = connect_daemon(args).await.unwrap();
    for _ in 0..200 {
        let resp = client.oneshot_rpc::<ListSessions>(()).await.unwrap();
        if let Some(reason) = resp.hostname_routing_unavailable {
            return reason;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("the daemon never reported hostname routing down");
}

/// Holds a fresh port and starts the daemon's hostname-proxy startup retry
/// against it — the real loop `start_host_proxies` spawns, with a compressed
/// backoff — so the note `min ls` warns from is set exactly the way an
/// occupied proxy port sets it, without holding the production `:7654`.
/// Dropping the held listener frees the port; the returned task resolves once
/// the proxy is serving again and the note is cleared.
#[cfg(target_os = "linux")]
async fn hold_proxy_port_and_start_retry(
    state: &minimald::server::ServerStateHandle,
) -> (tokio::net::TcpListener, tokio::task::JoinHandle<()>) {
    use minimald::server::{RetryBackoff, retry_hostname_proxy_until_serving};

    let held = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    let addr = held.local_addr().unwrap();
    let retry = tokio::spawn(retry_hostname_proxy_until_serving(
        state.clone(),
        addr,
        RetryBackoff::new(
            std::time::Duration::from_millis(5),
            std::time::Duration::from_millis(40),
        ),
    ));
    (held, retry)
}

/// NET-020: with the proxy port occupied, both `min ls` and `min session
/// activate` print the failure's reason and the remedy for it, and say the
/// daemon recovers on its own. Driven through the compiled binary so the
/// assertion is on what the user actually sees.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn listener_failure_reported_with_remedy() {
    let (daemon, args) = setup().await;
    let (held, retry) = hold_proxy_port_and_start_retry(&daemon.server.state).await;
    let reason = wait_for_routing_failure(&args).await;

    let ls_stderr = run_min_stderr(&args, &["ls"]).await;
    assert!(
        ls_stderr.contains("warning: session hostnames will not route"),
        "ls must warn about hostname routing, got: {ls_stderr}"
    );
    assert!(
        ls_stderr.contains(&reason),
        "ls must print the daemon's reason, got: {ls_stderr}"
    );
    assert!(
        ls_stderr.contains("Remedy"),
        "ls must print the remedy, got: {ls_stderr}"
    );
    assert!(
        ls_stderr.contains("retries"),
        "ls must say the daemon recovers on its own, got: {ls_stderr}"
    );
    assert!(
        ls_stderr.contains("run `min ls` again to check"),
        "ls must name the command its warning rides on, got: {ls_stderr}"
    );

    // `min session activate` prints the same report on its path.
    let project = tempfile::TempDir::new().unwrap();
    std::fs::create_dir(project.path().join(".git")).unwrap();
    std::fs::write(
        project.path().join("minimal.toml"),
        "# test minimal.toml\n[upstream]\nrepo = \"https://github.com/gominimal/pkgs\"\nbranch = \"main\"\n\n[stack]\nuse = \"shell\"\n",
    )
    .unwrap();
    let activate_stderr = run_min_stderr(
        &args,
        &[
            "session",
            "activate",
            project.path().to_str().unwrap(),
            "--name",
            "remedy-report",
            "--sync",
            "tarball",
            "--no-prompt",
        ],
    )
    .await;
    assert!(
        activate_stderr.contains("warning: session hostnames will not route"),
        "activate must warn about hostname routing, got: {activate_stderr}"
    );
    assert!(
        activate_stderr.contains(&reason),
        "activate must print the daemon's reason, got: {activate_stderr}"
    );
    assert!(
        activate_stderr.contains("Remedy"),
        "activate must print the remedy, got: {activate_stderr}"
    );
    assert!(
        activate_stderr.contains("run `min session activate` again to check"),
        "activate must name the command its warning rides on, got: {activate_stderr}"
    );

    drop(held);
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), retry).await;
}

/// NET-022: once the port frees and the listener recovers, `min ls` stops
/// carrying the warning — against the same daemon process, with no restart.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn ls_warning_clears_on_recovery() {
    let (daemon, args) = setup().await;
    let (held, retry) = hold_proxy_port_and_start_retry(&daemon.server.state).await;
    let _reason = wait_for_routing_failure(&args).await;

    let before = run_min_stderr(&args, &["ls"]).await;
    assert!(
        before.contains("warning: session hostnames will not route"),
        "ls must warn while the port is held, got: {before}"
    );

    // Free the port: the startup retry binds (a native daemon has no
    // host-loopback publish gate) and clears the note.
    drop(held);
    tokio::time::timeout(std::time::Duration::from_secs(5), retry)
        .await
        .expect("the startup retry must finish once the port frees")
        .expect("the startup retry must not panic");

    let after = run_min_stderr(&args, &["ls"]).await;
    assert!(
        !after.contains("warning: session hostnames will not route"),
        "the warning must clear without a daemon restart, got: {after}"
    );
}

/// NET-026: a daemon that auto-selected its hostname-proxy port tells `min`
/// which one it landed on, and `min ls` prints the address — the one an
/// `HTTP(S)_PROXY` export needs, and the thing that cannot stay a constant on
/// a machine running two daemons. The box-zone answerer's UDP port prints
/// beside it, since pointing the host's resolver at that port is the other
/// half of the same discovery. Driven through the compiled binary so the
/// assertion is on what the user actually sees.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn min_prints_discovered_proxy_port() {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use minimald::server::{
        RetryBackoff, retry_hostname_proxy_until_serving, retry_zone_answerer_until_serving,
    };
    use minimald_rpc::ListSessions;

    let (daemon, args) = setup().await;
    // Auto-select — no port configured — through the same startup loop
    // `start_host_proxies` spawns, with a compressed backoff.
    let compressed = RetryBackoff::new(
        std::time::Duration::from_millis(5),
        std::time::Duration::from_millis(40),
    );
    tokio::join!(
        retry_hostname_proxy_until_serving(
            daemon.server.state.clone(),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            compressed,
        ),
        retry_zone_answerer_until_serving(
            daemon.server.state.clone(),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            compressed,
        ),
    );

    // The reply `min ls` renders carries the ports both listeners bound.
    let mut client = connect_daemon(&args).await.unwrap();
    let resp = client.oneshot_rpc::<ListSessions>(()).await.unwrap();
    let port = resp
        .hostname_proxy_port
        .expect("the daemon must report the port its proxy ended up on");
    assert_ne!(port, 0, "port 0 is a request for a port, not an answer");
    let answerer_port = resp
        .zone_answerer_port
        .expect("the daemon must report the port its answerer ended up on");
    assert_ne!(
        answerer_port, 0,
        "port 0 is a request for a port, not an answer"
    );
    assert!(
        resp.hostname_routing_unavailable.is_none(),
        "auto-selecting a port is not a fault, got: {:?}",
        resp.hostname_routing_unavailable
    );

    // The printed addresses are real: the proxy accepts on its port.
    tokio::net::TcpStream::connect(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port))
        .await
        .expect("the discovered port must be listening");

    let out = run_min(&args, &["ls"]).await;
    let ls_stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(
        ls_stdout.contains(&format!("HOSTNAME PROXY:  listening on 127.0.0.1:{port}")),
        "`min ls` must print the discovered port, got: {ls_stdout}"
    );
    assert!(
        ls_stdout.contains("routes through it"),
        "the line must say what the port is for, got: {ls_stdout}"
    );
    assert!(
        ls_stdout.contains(&format!(
            "ZONE ANSWERER:   listening on 127.0.0.1:{answerer_port} (UDP)"
        )),
        "`min ls` must print the answerer's port beside the proxy's, got: {ls_stdout}"
    );
    assert!(
        ls_stdout.contains("point the host's resolver at it"),
        "the answerer line must say what the port is for, got: {ls_stdout}"
    );
}

// --- retired surfaces (NET-109 / NET-110) ---

/// No build of the daemon carries the retired mTLS reverse proxy, its
/// client-certificate RPC, or the `ssh-forward` feature that compiled
/// `direct-tcpip` out (NET-109, NET-110). A client crate cannot reach the
/// daemon's build flags from here, so assert on its sources and manifests —
/// the same source-scan approach `minimal`'s own `login_mints_no_certificate`
/// uses to prove a verb dropped a surface.
#[test]
fn retired_surfaces_absent() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("crates/minimal sits two levels below the workspace root");

    let source = |rel: &str| {
        std::fs::read_to_string(root.join(rel))
            .unwrap_or_else(|e| panic!("readable source {rel}: {e}"))
    };

    let retired_surfaces: &[(&str, &[&str])] = &[
        // The proxy serves plain HTTP only: no TLS port, no certificate
        // authority, no TLS-terminating serve loop, no TLS deps.
        (
            "crates/minimald/src/net/proxy.rs",
            &[
                "HTTPS_PROXY_PORT",
                "CertAuthority",
                "serve_https",
                "tokio_rustls",
                "networking-proxy",
            ],
        ),
        // The daemon opens one routing listener and keeps no proxy state.
        (
            "crates/minimald/src/server.rs",
            &["mtls", "7655", "cert_authority", "networking-proxy"],
        ),
        // No client-certificate RPC handler or dispatch arm, and no
        // mTLS field on the replies.
        (
            "crates/minimald/src/rpc.rs",
            &[
                "IssueClientCert",
                "mtls_proxy_unavailable",
                "networking-proxy",
            ],
        ),
        // No crypto-provider install for the removed feature, and no
        // second-proxy comment in the startup path.
        ("crates/minimald/src/main.rs", &["networking-proxy", "7655"]),
        // direct-tcpip is served in every build: neither the handler nor
        // the relay is behind a feature gate anymore.
        (
            "crates/minimald/src/connection.rs",
            &[
                "feature = \"ssh-forward\"",
                "feature = \"networking-proxy\"",
            ],
        ),
        // Both features and their optional TLS deps are gone from the
        // manifest, so no build can turn them back on.
        (
            "crates/minimald/Cargo.toml",
            &[
                "networking-proxy",
                "ssh-forward",
                "rcgen",
                "rustls",
                "tokio-rustls",
            ],
        ),
        // The wire contract carries no client-certificate types and no
        // mTLS-unavailable fields.
        (
            "crates/minimald-rpc/src/lib.rs",
            &["IssueClientCert", "mtls_proxy_unavailable"],
        ),
        // The workspace drops the certificate generator only minimald used.
        ("Cargo.toml", &["rcgen"]),
        // Nothing passes a removed feature to the daemon builds.
        ("justfile", &["networking-proxy", "{{features}}"]),
    ];
    for (rel, retired) in retired_surfaces.iter().copied() {
        let text = source(rel);
        for &token in retired {
            assert!(
                !text.contains(token),
                "{rel} still names the retired surface `{token}` (NET-109)"
            );
        }
    }
}

/// The daemon's `ListSessions` reply no longer carries the mTLS field, and a
/// reply without it decodes: `min ls` keeps reading the list, and never
/// prints an mTLS warning again (NET-109). A reply from an older daemon that
/// still sends the field decodes too — an unknown field is skipped, so the
/// version skew never breaks the list.
#[test]
fn session_list_decodes_without_mtls_field() {
    let resp = ListSessionsResponse {
        daemon_version: Some("test".to_string()),
        hostname_routing_unavailable: None,
        hostname_proxy_port: None,
        zone_answerer_port: None,
        resource_pool: None,
        sessions: vec![],
    };

    // The reply this build's daemon sends carries no mtls field.
    let json = serde_json_lenient::to_string(&resp).unwrap();
    assert!(
        !json.contains("mtls_proxy_unavailable"),
        "the serialized reply must not carry the retired field: {json}"
    );

    // And it decodes back through the client's own type.
    let decoded: ListSessionsResponse = serde_json_lenient::from_str(&json).unwrap();
    assert_eq!(decoded.daemon_version.as_deref(), Some("test"));
    assert!(decoded.sessions.is_empty());

    // An older daemon's reply, still carrying the field, decodes as well:
    // the extra field is ignored rather than fatal.
    let older = r#"{"daemon_version":"old","mtls_proxy_unavailable":"still here","sessions":[]}"#;
    let from_older: ListSessionsResponse = serde_json_lenient::from_str(older).unwrap();
    assert_eq!(from_older.daemon_version.as_deref(), Some("old"));
    assert!(from_older.sessions.is_empty());
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
        .call::<CreateSession>(&CreateSessionRequest {
            config,
            must_match_version: None,
        })
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
    create_session_with(
        daemon,
        name,
        project_path,
        sessions::NetworkMode::NoNet,
        sessions::SessionPolicy::default(),
    )
    .await
}

/// Like [`create_session`] but with the network mode and policy the caller
/// chooses, so a test can store a policy the CLI surfaces must render.
async fn create_session_with(
    daemon: &common::TestDaemon,
    name: &str,
    project_path: paths::HostAbsPath,
    network: sessions::NetworkMode,
    policy: sessions::SessionPolicy,
) -> SessionId {
    let mut client = daemon.server.connect().await;

    let config = minimald_rpc::SessionConfig {
        name: Some(name.to_string()),
        project_path,
        network,
        policy,
        hooks_enabled: true,
        attrs: Default::default(),
    };

    use minimald_rpc::{
        ConfigureLoadout, ConfigureLoadoutRequest, CreateSession, CreateSessionRequest,
        FinalizeSession, FinalizeSessionRequest,
    };
    let id = match client
        .call::<CreateSession>(&CreateSessionRequest {
            config,
            must_match_version: None,
        })
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

/// Like [`create_session`] but with the network mode and policy the caller
/// chooses.
async fn create_session_with_policy(
    daemon: &common::TestDaemon,
    name: &str,
    network: sessions::NetworkMode,
    policy: sessions::SessionPolicy,
) -> SessionId {
    let project_path =
        camino::Utf8PathBuf::from_path_buf(std::env::current_dir().unwrap()).unwrap();
    let abs_path = paths::HostAbsPath::try_new(project_path).unwrap();
    create_session_with(daemon, name, abs_path, network, policy).await
}
