//! Integration tests for minimal CLI commands.
//!
//! Each test spins up a real minimald `TestServer` on a UDS, then calls
//! the `cmd_*` functions from the `minimal` library as if the user had
//! invoked the CLI. The daemon's state is inspected directly (via
//! `TestClient`) to verify side-effects.

mod common;

use common::setup;
use minimal::*;
use sessions::SessionId;

use minimald::test_harness::unwrap_ready;

use serde_json::Value;

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
        minvmd: false,
    };
    // Should print client version and note daemon is unreachable, but return Ok.
    cmd_version(&args).await.unwrap();
}

// --- ls ---

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
    let parsed: Value = serde_json::from_str(&text).expect("json output should be valid JSON");
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
    let parsed: Value = serde_json::from_str(&text).expect("json output should be valid JSON");
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

    let activate_args = ActivateArgs {
        name: Some("test-session".to_string()),
        path: ".".to_string(),
        network: CliNetworkMode::NoNet,
        ingress: vec![],
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

// --- destroy ---

#[tokio::test]
async fn destroy_removes_session() {
    let (daemon, args) = setup().await;

    // Create a session via TestClient.
    let session_id = create_session(&daemon, "doomed").await;

    // Destroy it via cmd_destroy.
    cmd_destroy(
        &args,
        DestroyArgs {
            session: session_id.to_string(),
        },
    )
    .await
    .unwrap();

    // Verify the session is gone.
    let mut client = daemon.server.connect().await;
    use minimald_rpc::ListSessions;
    let resp = client.call::<ListSessions>(&()).await;
    assert!(resp.sessions.is_empty());
}

#[tokio::test]
async fn destroy_by_name() {
    let (daemon, args) = setup().await;
    let _ = create_session(&daemon, "by-name").await;

    cmd_destroy(
        &args,
        DestroyArgs {
            session: "by-name".to_string(),
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
            session: "nonexistent".to_string(),
        },
    )
    .await;
    assert!(result.is_err());
}

// --- stop ---

#[tokio::test]
async fn stop_succeeds_when_no_sessions() {
    let (_daemon, args) = setup().await;
    cmd_stop(&args, StopArgs { force: false }).await.unwrap();
}

#[tokio::test]
async fn stop_refuses_with_live_session() {
    let (daemon, args) = setup().await;
    let session_id = create_session(&daemon, "active").await;
    daemon.server.bring_session_up(session_id).await;

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

/// Create a session on the daemon via TestClient and return its ID.
async fn create_session(daemon: &common::TestDaemon, name: &str) -> SessionId {
    let mut client = daemon.server.connect().await;

    let project_path =
        camino::Utf8PathBuf::from_path_buf(std::env::current_dir().unwrap()).unwrap();
    let abs_path = paths::HostAbsPath::try_new(project_path).unwrap();

    let config = minimald_rpc::SessionConfig {
        name: Some(name.to_string()),
        project_path: abs_path,
        network: sessions::NetworkMode::NoNet,
        policy: Default::default(),
        attrs: Default::default(),
    };

    use minimald_rpc::{CreateSession, CreateSessionRequest};
    let resp = client
        .call::<CreateSession>(&CreateSessionRequest {
            config,
            contribution: Default::default(),
        })
        .await;
    match resp {
        minimald_rpc::Errorable::Ok(r) => unwrap_ready(r),
        minimald_rpc::Errorable::Err { error } => {
            panic!("CreateSession failed: {error}")
        }
    }
}
