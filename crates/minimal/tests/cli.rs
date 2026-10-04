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
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

// --- version ---

#[tokio::test]
async fn version_succeeds_with_daemon_running() {
    let (_daemon, args) = setup().await;
    cmd_version(&args, &mut std::io::stdout()).await.unwrap();
}

#[tokio::test]
async fn version_succeeds_without_daemon() {
    let args = GlobalArgs {
        repo_dir: None,
        minimal_dir: Some(std::path::PathBuf::from("/nonexistent")),
        config_dir: None,
        provider: None,
        no_input: false,
        vm: None,
    };
    // Should print client version and note daemon is unreachable, but return Ok.
    cmd_version(&args, &mut std::io::stdout()).await.unwrap();
}

/// A writer whose reader has gone away, as `min version | head -1` leaves
/// stdout once `head` exits.
struct ClosedPipe;

impl std::io::Write for ClosedPipe {
    fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
        Err(std::io::ErrorKind::BrokenPipe.into())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[tokio::test]
async fn version_reports_broken_pipe_when_output_is_closed() {
    let args = GlobalArgs {
        repo_dir: None,
        minimal_dir: Some(std::path::PathBuf::from("/nonexistent")),
        config_dir: None,
        provider: None,
        no_input: false,
        vm: None,
    };
    // The first line fails before any daemon contact, so no daemon is needed.
    let err = cmd_version(&args, &mut ClosedPipe).await.unwrap_err();
    assert!(err.chain().any(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .is_some_and(|io| io.kind() == std::io::ErrorKind::BrokenPipe)
    }));
}

// --- ls ---

#[test]
fn ls_shows_shared_resource_pool() {
    let resp = ListSessionsResponse {
        daemon_version: None,
        hostname_routing_unavailable: None,
        hostname_proxy_port: None,
        zone_answerer_port: None,
        answerer_bound: false,
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
            host_ip_enforcement: None,
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
        None,
        None,
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
        answerer_bound: false,
        resource_pool: None,
        sessions: vec![minimald_rpc::ListSessionsEntry {
            id: SessionId::nil(),
            name: Some("s1".to_string()),
            project_path: Some(paths::HostAbsPath::try_new("/work/proj").unwrap()),
            status: sessions::SessionStatus::Active,
            git: None,
            host_ip_enforcement: None,
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
        None,
        None,
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

/// NET-079's proof names the listing: a host-address box that runs
/// unenforced shows egress enforcement `none` in the human `min ls`, not
/// only in `--json`; one decided per box shows `per_box`; a box the daemon
/// reports no enforcement for shows `-`.
#[test]
fn ls_table_shows_host_address_enforcement() {
    let entry = |name: &str, n: u64, enforcement| minimald_rpc::ListSessionsEntry {
        id: SessionId::parse_str(&format!("00000000-0000-0000-0000-{n:012}")).unwrap(),
        name: Some(name.to_string()),
        project_path: Some(paths::HostAbsPath::try_new("/work/proj").unwrap()),
        status: sessions::SessionStatus::Active,
        git: None,
        host_ip_enforcement: enforcement,
        attrs: None,
    };
    let resp = ListSessionsResponse {
        daemon_version: None,
        hostname_routing_unavailable: None,
        hostname_proxy_port: None,
        zone_answerer_port: None,
        answerer_bound: false,
        resource_pool: None,
        sessions: vec![
            entry("decided", 1, Some(minimald_rpc::HostIpEnforcement::PerBox)),
            entry("unenforced", 2, Some(minimald_rpc::HostIpEnforcement::None)),
            entry("own-address", 3, None),
        ],
    };
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
    .unwrap();

    let text = String::from_utf8(out).unwrap();
    let cells_of = |name: &str| -> Vec<String> {
        text.lines()
            .find(|l| l.contains(name))
            .unwrap_or_else(|| panic!("a row for {name} in:\n{text}"))
            .split_whitespace()
            .map(str::to_string)
            .collect()
    };
    assert!(text.contains("EGRESS"), "header should list EGRESS: {text}");
    assert_eq!(cells_of("decided")[3], "per_box", "got:\n{text}");
    assert_eq!(cells_of("unenforced")[3], "none", "got:\n{text}");
    assert_eq!(cells_of("own-address")[3], "-", "got:\n{text}");
}

/// The multi-VM table carries the same EGRESS cell, one column right of the
/// single-VM one because each row leads with its VM.
#[test]
fn ls_across_vms_table_shows_host_address_enforcement() {
    let entry = |name: &str, n: u64, enforcement| minimald_rpc::ListSessionsEntry {
        id: SessionId::parse_str(&format!("00000000-0000-0000-0000-{n:012}")).unwrap(),
        name: Some(name.to_string()),
        project_path: Some(paths::HostAbsPath::try_new("/work/proj").unwrap()),
        status: sessions::SessionStatus::Active,
        git: None,
        host_ip_enforcement: enforcement,
        attrs: None,
    };
    let listing = |vm: &str, sessions| VmListing {
        vm: vm.to_string(),
        resp: ListSessionsResponse {
            daemon_version: None,
            hostname_routing_unavailable: None,
            hostname_proxy_port: None,
            zone_answerer_port: None,
            answerer_bound: false,
            resource_pool: None,
            sessions,
        },
        control_sock: None,
    };
    let listings = vec![
        listing(
            "default",
            vec![
                entry("decided", 1, Some(minimald_rpc::HostIpEnforcement::PerBox)),
                entry("own-address", 3, None),
            ],
        ),
        listing(
            "alpha",
            vec![entry(
                "unenforced",
                2,
                Some(minimald_rpc::HostIpEnforcement::None),
            )],
        ),
    ];
    let mut out = Vec::new();

    format_ls_across_vms(
        &mut out,
        &LsArgs {
            raw: false,
            json: false,
        },
        &listings,
        &[None, None],
        &[None, None],
    )
    .unwrap();

    let text = String::from_utf8(out).unwrap();
    let cells_of = |name: &str| -> Vec<String> {
        text.lines()
            .find(|l| l.contains(name))
            .unwrap_or_else(|| panic!("a row for {name} in:\n{text}"))
            .split_whitespace()
            .map(str::to_string)
            .collect()
    };
    assert!(text.contains("EGRESS"), "header should list EGRESS: {text}");
    assert_eq!(cells_of("decided")[4], "per_box", "got:\n{text}");
    assert_eq!(cells_of("unenforced")[4], "none", "got:\n{text}");
    assert_eq!(cells_of("own-address")[4], "-", "got:\n{text}");
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
        None,
        None,
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
        None,
        None,
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
        None,
        None,
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
        None,
        None,
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
        None,
        None,
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
        "# test minimal.toml\n[stack]\nuse = \"shell\"\n",
    )
    .unwrap();

    let activate_args = ActivateArgs {
        name: Some("test-session".to_string()),
        path: Some(project.path().to_string_lossy().to_string()),
        sync: Some(SyncMode::Tarball),
        network: CliNetworkMode::NoNet,
        ingress: vec![],
        dynamic_ingress: None,
        dynamic_range: None,
        allow_subnets: vec![],
        allow_dns_hosts: vec![],
        allow_protocols: vec![],
        deny_subnets: vec![],
        deny_all_egress: false,
        credentialed_upstream: false,
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
        "# test\n[stack]\nuse = \"shell\"\n",
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
        dynamic_ingress: None,
        dynamic_range: None,
        allow_subnets: vec![],
        allow_dns_hosts: vec![],
        allow_protocols: vec![],
        deny_subnets: vec![],
        deny_all_egress: false,
        credentialed_upstream: false,
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
        "# test minimal.toml\n[stack]\nuse = \"shell\"\n",
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
        dynamic_ingress: None,
        dynamic_range: None,
        allow_subnets: vec![],
        allow_dns_hosts: vec![],
        allow_protocols: vec![],
        deny_subnets: vec![],
        deny_all_egress: false,
        credentialed_upstream: false,
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

// --- dynamic ingress declaration (NET-043/NET-044) ---

/// NET-043: `min session create` carries the box's dynamic ingress stance
/// into the create request's `IngressPolicy`. `--dynamic-ingress allow
/// --dynamic-range 8000-8443` reaches the record the daemon holds as
/// exactly that — mode and range — and the stance alone makes the ingress
/// declaration (no static mapping was given), while a create that set
/// nothing keeps `ingress` `None`: the deny-all default, not an empty
/// declaration. Read back through `GetSessionPolicy`, so what is asserted
/// is the declaration the record stores, not the args the client parsed.
#[tokio::test]
async fn create_carries_dynamic_ingress() {
    let (_daemon, args) = setup().await;

    for (name, dynamic_ingress, dynamic_range) in [
        (
            "dyn-allow",
            Some(sessions::DynamicIngress::Allow),
            Some((8000, 8443)),
        ),
        // The mode alone, with no range and no static mapping, still makes
        // the declaration.
        ("dyn-ask", Some(sessions::DynamicIngress::Ask), None),
        ("dyn-bare", None, None),
    ] {
        let project = tempfile::TempDir::new().unwrap();
        std::fs::create_dir(project.path().join(".git")).unwrap();
        std::fs::write(
            project.path().join("minimal.toml"),
            "# test minimal.toml\n[stack]\nuse = \"shell\"\n",
        )
        .unwrap();
        cmd_activate(
            &args,
            ActivateArgs {
                name: Some(name.to_string()),
                path: Some(project.path().to_string_lossy().to_string()),
                sync: Some(SyncMode::Tarball),
                network: CliNetworkMode::OwnIp,
                ingress: vec![],
                dynamic_ingress,
                dynamic_range,
                allow_subnets: vec![],
                allow_dns_hosts: vec![],
                allow_protocols: vec![],
                deny_subnets: vec![],
                deny_all_egress: false,
                credentialed_upstream: false,
                loadout: vec![],
                no_loadouts: false,
                no_hooks: false,
                no_prompt: false,
                attach: false,
            },
        )
        .await
        .unwrap_or_else(|error| panic!("activating {name} must succeed: {error:#}"));
    }

    let mut client = connect_daemon(&args).await.unwrap();
    use minimald_rpc::{GetSessionPolicy, GetSessionPolicyRequest};
    for (name, declared) in [
        (
            "dyn-allow",
            Some((sessions::DynamicIngress::Allow, Some((8000, 8443)))),
        ),
        ("dyn-ask", Some((sessions::DynamicIngress::Ask, None))),
        ("dyn-bare", None),
    ] {
        let resp = client
            .oneshot_rpc::<GetSessionPolicy>(GetSessionPolicyRequest::Name(name.to_string()))
            .await
            .unwrap();
        let policy = match resp {
            minimald_rpc::Errorable::Ok(policy) => policy,
            minimald_rpc::Errorable::Err { error } => {
                panic!("GetSessionPolicy failed for {name}: {error}")
            }
        };
        match declared {
            Some((mode, range)) => {
                let ingress = policy.ingress.unwrap_or_else(|| {
                    panic!("the stance alone must make {name}'s ingress declaration")
                });
                assert_eq!(
                    ingress.dynamic_ingress,
                    Some(mode),
                    "the record must hold the mode the flag named"
                );
                assert_eq!(
                    ingress.dynamic_allowed_range, range,
                    "the record must hold the range the flag named"
                );
                assert!(
                    ingress.port_mappings.is_empty(),
                    "no static mapping was given, so none may appear"
                );
            }
            None => assert!(
                policy.ingress.is_none(),
                "nothing set must keep ingress None, the deny-all default"
            ),
        }
    }
}

/// NET-043's create-time errors, each named at the flag it belongs to: a
/// malformed range (no `-`, a non-numeric end) and an inverted one (`hi`
/// below `lo`) are refused by the range's own parser, and a range with no
/// mode is refused by the flag's `requires` — the half-declared stance can
/// never read as a deliberate allow. Driven through the compiled binary so
/// the assertion is on the create the user runs: the process exits nonzero
/// with the reason on stderr, and no session is left behind a rejected
/// flag.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn create_rejects_bad_dynamic_range() {
    let (_daemon, args) = setup().await;
    let project = tempfile::TempDir::new().unwrap();
    std::fs::create_dir(project.path().join(".git")).unwrap();
    std::fs::write(
        project.path().join("minimal.toml"),
        "# test minimal.toml\n[stack]\nuse = \"shell\"\n",
    )
    .unwrap();

    let project_path = project.path().to_str().unwrap();
    for (extra, needle) in [
        (
            &["--dynamic-ingress", "allow", "--dynamic-range", "8000"][..],
            "expected LO-HI",
        ),
        (
            &["--dynamic-ingress", "allow", "--dynamic-range", "abc-8443"][..],
            "'abc' is not a valid port number",
        ),
        (
            &["--dynamic-ingress", "allow", "--dynamic-range", "8443-8000"][..],
            "the upper end must not be below the lower end",
        ),
        (
            &["--dynamic-ingress", "allow", "--dynamic-range", "80-90"][..],
            "minimald refuses to publish host ports below 1024",
        ),
        // A range with no mode: clap's `requires` names the missing flag, so
        // the stance the range would imply is spelled by the person, not
        // defaulted by the parser.
        (&["--dynamic-range", "8000-8443"][..], "--dynamic-ingress"),
    ] {
        let mut argv = vec![
            "session",
            "activate",
            project_path,
            "--name",
            "bad-range",
            "--network",
            "own_ip",
            "--no-input",
        ];
        argv.extend(extra.iter().copied());
        let out = run_min(&args, &argv).await;
        assert!(
            !out.status.success(),
            "the create with {extra:?} must fail, but the binary exited \
             {}:\n{}",
            out.status,
            String::from_utf8_lossy(&out.stderr),
        );
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains(needle),
            "the refusal must say {needle:?}, got:\n{stderr}"
        );
    }
}

/// NET-043/NET-044: `min session policy` shows the resolved dynamic ingress
/// stance — in the text render and in the JSON document, on the deny-all
/// default as much as on a declared one. The `allow` stance a box was
/// created with over a range reads as its row and its key with the range
/// beside it; a box that set nothing reads as deny, the evaluation the
/// absent setting takes, in both surfaces — the deny_all kind and the
/// text's deny-all line carry the resolved key too, so a parser of either
/// surface answers "which stance does this box run under" without
/// defaulting a null itself. An explicit `deny` reads the same, through
/// the declared kind.
#[tokio::test]
async fn policy_shows_resolved_dynamic_ingress() {
    let (daemon, args) = setup().await;
    let allowed_id = create_session_with_policy(
        &daemon,
        "dyn-allow-policy",
        sessions::NetworkMode::OwnIp,
        sessions::SessionPolicy::new(
            None,
            Some(sessions::IngressPolicy {
                port_mappings: vec![],
                dynamic_allowed_range: Some((8000, 8443)),
                dynamic_ingress: Some(sessions::DynamicIngress::Allow),
            }),
        ),
    )
    .await;
    let declared_deny_id = create_session_with_policy(
        &daemon,
        "dyn-explicit-deny-policy",
        sessions::NetworkMode::OwnIp,
        sessions::SessionPolicy::new(
            None,
            Some(sessions::IngressPolicy {
                port_mappings: vec![],
                dynamic_allowed_range: None,
                dynamic_ingress: Some(sessions::DynamicIngress::Deny),
            }),
        ),
    )
    .await;
    let bare_id = create_session_with_policy(
        &daemon,
        "dyn-bare-policy",
        sessions::NetworkMode::OwnIp,
        sessions::SessionPolicy::default(),
    )
    .await;

    let mut client = connect_daemon(&args).await.unwrap();
    use minimald_rpc::{GetEffectiveSessionPolicy, GetEffectiveSessionPolicyRequest};
    for (name, id, (mode, range, declared)) in [
        (
            "the allow stance over a range",
            allowed_id,
            (
                sessions::DynamicIngress::Allow,
                Some((8000u16, 8443u16)),
                true,
            ),
        ),
        (
            "the explicit deny stance",
            declared_deny_id,
            (sessions::DynamicIngress::Deny, None, true),
        ),
        (
            "no dynamic flag given",
            bare_id,
            (sessions::DynamicIngress::Deny, None, false),
        ),
    ] {
        let resp = client
            .oneshot_rpc::<GetEffectiveSessionPolicy>(GetEffectiveSessionPolicyRequest::Id(id))
            .await
            .unwrap();
        let policy = match resp {
            minimald_rpc::Errorable::Ok(policy) => policy,
            minimald_rpc::Errorable::Err { error } => {
                panic!("GetEffectiveSessionPolicy failed for {name}: {error}")
            }
        };

        let mut out = Vec::new();
        format_policy(&mut out, &policy, sessions::NetworkMode::OwnIp, None, None).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(
            text.contains(&format!("  dynamic ingress  {mode}")),
            "{name}: the resolved stance must show in the text:\n{text}"
        );
        if let Some((lo, hi)) = range {
            assert!(
                text.contains(&format!("  dynamic ports  {lo}–{hi}")),
                "{name}: the range must show in the text:\n{text}"
            );
        }

        let mut out = Vec::new();
        write_policy_json(
            &mut out,
            &policy,
            sessions::NetworkMode::OwnIp,
            None,
            Ok(vec![]),
        )
        .unwrap();
        let document: Value = serde_json_lenient::from_slice(&out).unwrap();
        let ingress = &document["ingress"];
        assert_eq!(
            ingress["dynamic_ingress"],
            mode.to_string(),
            "{name}: the resolved stance must show in the document:\n{document}"
        );
        if declared {
            assert_eq!(
                ingress["kind"], "declared",
                "{name}: a declared stance keeps the declared kind:\n{document}"
            );
        } else {
            assert_eq!(
                ingress["kind"], "deny_all",
                "{name}: no declaration reads as the deny_all kind:\n{document}"
            );
        }
        match range {
            Some((lo, hi)) => {
                let carried = ingress["dynamic_allowed_range"]
                    .as_array()
                    .unwrap_or_else(|| panic!("{name}: the range rides as an array:\n{document}"));
                assert_eq!(
                    (carried[0].as_u64(), carried[1].as_u64(),),
                    (Some(u64::from(lo)), Some(u64::from(hi))),
                    "{name}: the range's ends must survive the document:\n{document}"
                );
            }
            None => {
                if declared {
                    assert_eq!(
                        ingress["dynamic_allowed_range"],
                        Value::Null,
                        "{name}: no range declared carries null, not a phantom \
                         one:\n{document}"
                    );
                }
            }
        }
    }
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

#[tokio::test]
async fn rename_to_self_is_an_error() {
    let (daemon, args) = setup().await;
    let session_id = create_session(&daemon, "same-name").await;

    let err = cmd_rename(
        &args,
        RenameArgs {
            session: session_id.to_string(),
            new_name: "same-name".to_string(),
        },
    )
    .await
    .unwrap_err();

    assert!(
        err.to_string().contains("session is already named"),
        "expected a rename-to-self error, got: {err}"
    );
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
            output: None,
        },
    )
    .await
    .unwrap();
}

/// `min session policy -o json` writes one `min/v1/session-policy` document:
/// the schema stamp a client checks before anything else, the policy's
/// blocks as keys, and the live mappings as the wire's own rows with each
/// one's `pending` state carried (NET-044) — a port published at runtime
/// that the relay gate has not admitted must not read as reachable to
/// something parsing the document, and the port the declaration named must
/// read as the admitted forward it is. Driven through `write_policy_json`,
/// the renderer the command goes through, with the effective policy fetched
/// the way the command fetches it (the effective-policy RPC, NET-074) from
/// a real session that really declares the port that reads `pending:
/// false` — so the two rows are grounded in a declaration, not in a
/// hand-built pair.
#[tokio::test]
async fn policy_json_carries_schema_and_pending() {
    let (daemon, args) = setup().await;
    let session_id = create_session_with_policy(
        &daemon,
        "policy-json",
        sessions::NetworkMode::OwnIp,
        sessions::SessionPolicy::new(
            None,
            Some(sessions::IngressPolicy {
                port_mappings: vec![sessions::PortMapping {
                    external_port: 3000,
                    internal_port: 3000,
                    proto: sessions::IpProto::Tcp,
                }],
                dynamic_allowed_range: None,
                dynamic_ingress: None,
            }),
        ),
    )
    .await;

    let mut client = connect_daemon(&args).await.unwrap();
    use minimald_rpc::{GetEffectiveSessionPolicy, GetEffectiveSessionPolicyRequest};
    let resp = client
        .oneshot_rpc::<GetEffectiveSessionPolicy>(GetEffectiveSessionPolicyRequest::Id(session_id))
        .await
        .unwrap();
    let policy = match resp {
        minimald_rpc::Errorable::Ok(policy) => policy,
        minimald_rpc::Errorable::Err { error } => {
            panic!("GetEffectiveSessionPolicy failed: {error}")
        }
    };
    assert!(
        policy
            .ingress
            .as_ref()
            .is_some_and(|ingress| ingress.port_mappings.len() == 1),
        "the stored declaration must survive the record round trip"
    );

    // The live rows the way the daemon serves them: a runtime-only port the
    // declaration never named, beside the declared one.
    let live = vec![
        minimald_rpc::LiveMapping {
            local: "127.0.0.1:3200".to_string(),
            internal_port: 3200,
            proto: sessions::IpProto::Tcp,
            pending: Some(true),
        },
        minimald_rpc::LiveMapping {
            local: "127.0.0.1:3000".to_string(),
            internal_port: 3000,
            proto: sessions::IpProto::Tcp,
            pending: Some(false),
        },
    ];

    let mut out = Vec::new();
    write_policy_json(
        &mut out,
        &policy,
        sessions::NetworkMode::OwnIp,
        None,
        Ok(live),
    )
    .unwrap();
    let document: Value = serde_json_lenient::from_slice(&out).unwrap();
    assert_eq!(
        document["schema"], "min/v1/session-policy",
        "the document must open with the schema stamp:\n{document}"
    );
    assert_eq!(
        document["network"], "own_ip",
        "the mode names which surface the policy describes:\n{document}"
    );
    assert_eq!(
        document["ingress"]["kind"], "declared",
        "the declared block is carried as the declaration:\n{document}"
    );
    let declared = document["ingress"]["port_mappings"]
        .as_array()
        .unwrap_or_else(|| panic!("the declared mappings ride as an array: {document}"));
    assert_eq!(
        declared[0]["internal_port"].as_u64(),
        Some(3000),
        "the declaration the pending rows are measured against:\n{document}"
    );

    let live_rows = document["live_ingress"]
        .as_array()
        .unwrap_or_else(|| panic!("the live mappings ride as an array: {document}"));
    assert_eq!(live_rows.len(), 2, "every mapping carried: {document}");
    let pending_of = |port: u16| {
        live_rows
            .iter()
            .find(|row| row["internal_port"].as_u64() == Some(u64::from(port)))
            .unwrap_or_else(|| panic!("no live row for port {port}: {document}"))["pending"]
            .clone()
    };
    assert_eq!(
        pending_of(3200).as_bool(),
        Some(true),
        "a port the declaration never named is carried as pending:\n{document}"
    );
    assert_eq!(
        pending_of(3000).as_bool(),
        Some(false),
        "the port the declaration named is carried as admitted:\n{document}"
    );

    // A row from a daemon that predates the field — one that carried no
    // `pending` key — rides the document as `null`, the JSON surface's own
    // way of saying the state is unknown rather than reachable (NET-044).
    let pre_field = minimald_rpc::LiveMapping {
        local: "127.0.0.1:3400".to_string(),
        internal_port: 3400,
        proto: sessions::IpProto::Tcp,
        pending: None,
    };
    let mut out = Vec::new();
    write_policy_json(
        &mut out,
        &policy,
        sessions::NetworkMode::OwnIp,
        None,
        Ok(vec![pre_field]),
    )
    .unwrap();
    let document: Value = serde_json_lenient::from_slice(&out).unwrap();
    let rows = document["live_ingress"]
        .as_array()
        .unwrap_or_else(|| panic!("the live mappings ride as an array: {document}"));
    assert_eq!(
        rows[0]["pending"],
        Value::Null,
        "a pre-field row's unknown state rides the document as null, never as a bool:\n{document}"
    );
}

/// The `live_ingress` key carries three states a client must be able to tell
/// apart, because each says a different thing: the rows the daemon served —
/// an empty list included, which is the claim that the box published
/// nothing — `null` for the view the daemon could not serve, which is no
/// claim at all (the box may have published anything, and the run cannot
/// warn in prose: a `-o json` run's stderr is the error object's alone), and
/// no key at all for a mode without the surface. A degraded fetch — an
/// older daemon without the subsystem, a session mid-teardown — is the
/// middle one, never collapsed into the first.
#[test]
fn policy_json_distinguishes_unavailable_live_rows_from_none_published() {
    let policy = sessions::EffectiveSessionPolicy {
        egress: sessions::EffectiveEgress::AllowAll,
        ingress: None,
    };

    // A box that published nothing: the empty list is an authoritative
    // claim about the box.
    let mut out = Vec::new();
    write_policy_json(
        &mut out,
        &policy,
        sessions::NetworkMode::OwnIp,
        None,
        Ok(Vec::new()),
    )
    .unwrap();
    let document: Value = serde_json_lenient::from_slice(&out).unwrap();
    assert_eq!(
        document.get("live_ingress"),
        Some(&Value::Array(Vec::new())),
        "a served empty view is the box's own claim that it published nothing:\n{document}"
    );

    // A view the daemon could not serve: `null`, the document's unknown —
    // present as a key, so it is not the mode's absence either.
    let mut out = Vec::new();
    write_policy_json(
        &mut out,
        &policy,
        sessions::NetworkMode::OwnIp,
        None,
        Err("live port mappings are unavailable: no session found".to_string()),
    )
    .unwrap();
    let document: Value = serde_json_lenient::from_slice(&out).unwrap();
    assert_eq!(
        document.get("live_ingress"),
        Some(&Value::Null),
        "an unavailable live view rides the document as null, never as an empty list:\n{document}"
    );

    // A mode without the surface: no key at all, a third state again.
    let mut out = Vec::new();
    write_policy_json(
        &mut out,
        &policy,
        sessions::NetworkMode::NoNet,
        None,
        Ok(Vec::new()),
    )
    .unwrap();
    let document: Value = serde_json_lenient::from_slice(&out).unwrap();
    assert_eq!(
        document.get("live_ingress"),
        None,
        "a mode without a live-ingress surface leaves the key out entirely:\n{document}"
    );
}

/// A `-o json` run that fails answers with the mode's error contract, not a
/// plain-text line: the failure crosses to `main` as the typed
/// `MachineModeFailure` — the generic payload every `-o json` command fails
/// into, which `main`'s machine-mode error emitter (keyed on the output
/// mode, shared by every command that takes `-o json`) writes as the one
/// `min/v1/error` object on stderr, its one-object shape pinned by `main`'s
/// own unit test. A missing session carries the architecture's `not_found`
/// code — never a policy-specific spelling — with the kind of thing that
/// was missing, a session, in the message and the hint.
#[tokio::test]
async fn policy_json_failure_answers_with_the_error_contract() {
    let (_daemon, args) = setup().await;
    let err = cmd_session_policy(
        &args,
        PolicyArgs {
            session: "no-such-session".to_string(),
            output: Some(PolicyOutputFormat::Json),
        },
    )
    .await
    .unwrap_err();
    let failure = err
        .downcast_ref::<MachineModeFailure>()
        .expect("the failure crosses as the payload the emitter writes, not a message");
    assert_eq!(
        failure.code(),
        "not_found",
        "a missing session is the architecture's not-found code: {err:#}"
    );
    assert!(
        failure.message().contains("session"),
        "the message names the kind of thing that was missing: {}",
        failure.message()
    );
    assert!(
        failure.hint().contains("session"),
        "the hint names the kind of thing that was missing: {}",
        failure.hint()
    );
}

/// `min session policy` shows the effective egress rules (NET-061): the four
/// egress fields the session was activated with, each unset dimension
/// resolved to its default instead of a bare `null`. The policy is stored
/// through the daemon and fetched the way the command fetches it — the
/// effective-policy RPC (NET-074) — and `format_policy` is the rendering the
/// command prints. The same egress on a host-address box is still shown,
/// but with no ingress block, and a none box shows no blocks at all — just
/// the note the TUI shows in their place.
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
    use minimald_rpc::{GetEffectiveSessionPolicy, GetEffectiveSessionPolicyRequest};
    let resp = client
        .oneshot_rpc::<GetEffectiveSessionPolicy>(GetEffectiveSessionPolicyRequest::Id(session_id))
        .await
        .unwrap();
    let policy = match resp {
        minimald_rpc::Errorable::Ok(policy) => policy,
        minimald_rpc::Errorable::Err { error } => {
            panic!("GetEffectiveSessionPolicy failed: {error}")
        }
    };
    assert_eq!(
        policy.egress,
        sessions::EffectiveEgress::Declared(egress.clone()),
        "the stored egress must survive the record round trip"
    );

    let mut out = Vec::new();
    format_policy(&mut out, &policy, sessions::NetworkMode::OwnIp, None, None).unwrap();
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
    // a `deny-all` row would claim a deny-rule that does not exist. The TUI's
    // detail pane suppresses the block for the same reason.
    let host_id = create_session_with_policy(
        &daemon,
        "egress-policy-host",
        sessions::NetworkMode::HostNet,
        sessions::SessionPolicy::new(Some(egress.clone()), None),
    )
    .await;
    let resp = client
        .oneshot_rpc::<GetEffectiveSessionPolicy>(GetEffectiveSessionPolicyRequest::Id(host_id))
        .await
        .unwrap();
    let policy = match resp {
        minimald_rpc::Errorable::Ok(policy) => policy,
        minimald_rpc::Errorable::Err { error } => {
            panic!("GetEffectiveSessionPolicy failed: {error}")
        }
    };
    let mut out = Vec::new();
    format_policy(
        &mut out,
        &policy,
        sessions::NetworkMode::HostNet,
        None,
        None,
    )
    .unwrap();
    let text = String::from_utf8(out).unwrap();
    assert!(
        text.contains("subnets  10.0.0.0/8"),
        "the host-address egress rules are still shown:\n{text}"
    );
    assert!(
        !text.contains("ingress"),
        "a host-address session has no per-session ingress policy to show:\n{text}"
    );

    // NET-079: the per-box enforcement state rides its own runtime-facts
    // reply beside the rules — never a field on the policy, whose strict
    // shape an older `min` would reject over a key it has no field for —
    // and the row the render prints is the state that reply carried, in the
    // machine spelling. Whatever this host actually decides is what shows:
    // the assertion is on the agreement between the reply and the row, not
    // on the state, which is the host's to answer.
    use minimald_rpc::{GetSessionRuntimeFacts, GetSessionRuntimeFactsRequest};
    let resp = client
        .oneshot_rpc::<GetSessionRuntimeFacts>(GetSessionRuntimeFactsRequest::Id(host_id))
        .await
        .unwrap();
    let facts = match resp {
        minimald_rpc::Errorable::Ok(facts) => facts,
        minimald_rpc::Errorable::Err { error } => {
            panic!("GetSessionRuntimeFacts failed: {error}")
        }
    };
    let host_ip_enforcement = facts
        .host_ip_enforcement
        .expect("a host-address session answers a state");
    let mut out = Vec::new();
    format_policy(
        &mut out,
        &policy,
        sessions::NetworkMode::HostNet,
        Some(host_ip_enforcement),
        None,
    )
    .unwrap();
    let text = String::from_utf8(out).unwrap();
    assert!(
        text.contains(&format!(
            "  per-box enforcement  {}\n",
            host_ip_enforcement.machine_str()
        )),
        "the enforcement row must carry the runtime-facts reply's state, in \
         its own machine spelling:\n{text}"
    );

    // A none box has no network, so it can carry no egress or ingress
    // declaration at all — the whole policy is replaced by the one-line
    // note the TUI's detail pane shows, since `egress / allow-all` there
    // would claim a reach a box with no network does not have.
    let none_id = create_session_with_policy(
        &daemon,
        "egress-policy-none",
        sessions::NetworkMode::NoNet,
        sessions::SessionPolicy::default(),
    )
    .await;
    let resp = client
        .oneshot_rpc::<GetEffectiveSessionPolicy>(GetEffectiveSessionPolicyRequest::Id(none_id))
        .await
        .unwrap();
    let policy = match resp {
        minimald_rpc::Errorable::Ok(policy) => policy,
        minimald_rpc::Errorable::Err { error } => {
            panic!("GetEffectiveSessionPolicy failed: {error}")
        }
    };
    let mut out = Vec::new();
    format_policy(&mut out, &policy, sessions::NetworkMode::NoNet, None, None).unwrap();
    let text = String::from_utf8(out).unwrap();
    assert_eq!(
        text, "No network policy (NoNet)\n",
        "a none session prints the note in place of both blocks:\n{text}"
    );
}

/// `min session policy` shows the default in force for a bare own-address
/// box (NET-075): the deny-all egress the daemon's gate enforces once the
/// default is in force (NET-074), rendered the way the command renders it —
/// with the phase passed explicitly, because this build ships the default as
/// announced (NET-076), so the deny-all rendering is proven against the
/// in-force resolution the rollout ends at, while the wire reply is asserted
/// against the phase this build ships. A declared section still reads as its
/// own rules, and the default is scoped to own-address boxes — a bare
/// host-address box keeps the shipped allow-all, because the deny-all is a
/// gate on the session's own address, not on its host's namespace.
#[tokio::test]
async fn policy_shows_deny_all_default() {
    let (daemon, args) = setup().await;
    let bare_id = create_session_with_policy(
        &daemon,
        "bare-own-ip",
        sessions::NetworkMode::OwnIp,
        sessions::SessionPolicy::default(),
    )
    .await;

    let mut client = connect_daemon(&args).await.unwrap();
    use minimald_rpc::{GetEffectiveSessionPolicy, GetEffectiveSessionPolicyRequest};
    let resp = client
        .oneshot_rpc::<GetEffectiveSessionPolicy>(GetEffectiveSessionPolicyRequest::Id(bare_id))
        .await
        .unwrap();
    let policy = match resp {
        minimald_rpc::Errorable::Ok(policy) => policy,
        minimald_rpc::Errorable::Err { error } => {
            panic!("GetEffectiveSessionPolicy failed: {error}")
        }
    };
    // Over the wire, the daemon answers the resolution the phase this build
    // ships leaves in force — announced, so a bare box still allows all
    // (NET-076), and the command's data path carries that answer.
    assert_eq!(
        policy.egress,
        sessions::effective_egress(
            None,
            sessions::NetworkMode::OwnIp,
            sessions::EGRESS_DEFAULT_PHASE,
            false,
        ),
        "the daemon must answer the shipped phase's resolution for a bare box"
    );

    // The default's own posture, with the phase passed explicitly: once in
    // force, a bare own-address box resolves to deny-all, and the command's
    // renderer prints it as that — and nothing else.
    let in_force = sessions::EffectiveSessionPolicy {
        egress: sessions::effective_egress(
            None,
            sessions::NetworkMode::OwnIp,
            sessions::EgressDefaultPhase::InForce,
            false,
        ),
        ingress: None,
    };
    assert_eq!(
        in_force.egress,
        sessions::EffectiveEgress::DenyAll,
        "the in-force default for a bare own-address box is deny-all"
    );
    let mut out = Vec::new();
    format_policy(
        &mut out,
        &in_force,
        sessions::NetworkMode::OwnIp,
        None,
        None,
    )
    .unwrap();
    let text = String::from_utf8(out).unwrap();
    assert!(
        text.contains("egress\n  deny-all (default)\n"),
        "a bare own-address box must print deny-all once in force, marked \
         as the default it resolved to:\n{text}"
    );
    assert!(
        !text.contains("allow-all"),
        "deny-all must not also print the allow-all row:\n{text}"
    );

    // The strict policy is untouched: the box declared nothing, and the
    // record still holds that absence — only the effective view carries the
    // default. `min session policy` shows the effective rules; the strict
    // shape stays what the session was activated with.
    use minimald_rpc::{GetSessionPolicy, GetSessionPolicyRequest};
    let strict = client
        .oneshot_rpc::<GetSessionPolicy>(GetSessionPolicyRequest::Id(bare_id))
        .await
        .unwrap();
    match strict {
        minimald_rpc::Errorable::Ok(strict) => assert_eq!(
            strict.egress, None,
            "the stored policy must keep the absence the box declared"
        ),
        minimald_rpc::Errorable::Err { error } => panic!("GetSessionPolicy failed: {error}"),
    }

    // The default is scoped to own-address boxes (NET-074): a bare
    // host-address session shares its host's namespace and the gate has no
    // own address to hold, so it keeps the shipped allow-all.
    let host_id = create_session_with_policy(
        &daemon,
        "bare-host-net",
        sessions::NetworkMode::HostNet,
        sessions::SessionPolicy::default(),
    )
    .await;
    let resp = client
        .oneshot_rpc::<GetEffectiveSessionPolicy>(GetEffectiveSessionPolicyRequest::Id(host_id))
        .await
        .unwrap();
    let policy = match resp {
        minimald_rpc::Errorable::Ok(policy) => policy,
        minimald_rpc::Errorable::Err { error } => {
            panic!("GetEffectiveSessionPolicy failed: {error}")
        }
    };
    assert_eq!(policy.egress, sessions::EffectiveEgress::AllowAll);
    let mut out = Vec::new();
    format_policy(
        &mut out,
        &policy,
        sessions::NetworkMode::HostNet,
        None,
        None,
    )
    .unwrap();
    let text = String::from_utf8(out).unwrap();
    assert!(
        text.contains("egress\n  allow-all (default)\n"),
        "a bare host-address box keeps the shipped allow-all, marked as the \
         default:\n{text}"
    );
}

/// `--deny-all-egress` declares the deny-all section (NET-075's CLI half):
/// the activation's record carries `sessions::EgressPolicy::deny_all()` —
/// every allow list present and empty, nothing denied on top — the shape the
/// host-address classifier decides its deny verdict on (NET-079), not four
/// absent lists: present-and-empty is the declaration that reaches nothing,
/// `None` is the allow-all default, and a box that declared deny-all by flag
/// must read in the record exactly like one that declared it in its
/// `minimal.toml`.
#[tokio::test]
async fn deny_all_egress_flag_declares_every_allow_list_empty() {
    let (_daemon, args) = setup().await;

    // The project dir ritual every `cmd_activate` test carries: a minimal.toml
    // so the missing-mfile prompt doesn't fire, a `.git` root so the non-VCS
    // upload confirmation short-circuits.
    let project = tempfile::TempDir::new().unwrap();
    std::fs::create_dir(project.path().join(".git")).unwrap();
    std::fs::write(
        project.path().join("minimal.toml"),
        "# test minimal.toml\n[stack]\nuse = \"shell\"\n",
    )
    .unwrap();

    cmd_activate(
        &args,
        ActivateArgs {
            name: Some("flag-declared-deny-all".to_string()),
            path: Some(project.path().to_string_lossy().to_string()),
            sync: Some(SyncMode::Tarball),
            network: CliNetworkMode::HostNet,
            ingress: vec![],
            dynamic_ingress: None,
            dynamic_range: None,
            allow_subnets: vec![],
            allow_dns_hosts: vec![],
            allow_protocols: vec![],
            deny_subnets: vec![],
            deny_all_egress: true,
            credentialed_upstream: false,
            loadout: vec![],
            no_loadouts: false,
            no_hooks: false,
            no_prompt: true,
            attach: false,
        },
    )
    .await
    .expect("a deny-all declaration is accepted wherever egress declarations are");

    let mut client = connect_daemon(&args).await.unwrap();
    use minimald_rpc::{GetSessionPolicy, GetSessionPolicyRequest};
    let strict = client
        .oneshot_rpc::<GetSessionPolicy>(GetSessionPolicyRequest::Name(
            "flag-declared-deny-all".to_string(),
        ))
        .await
        .unwrap();
    let strict = match strict {
        minimald_rpc::Errorable::Ok(strict) => strict,
        minimald_rpc::Errorable::Err { error } => {
            panic!("GetSessionPolicy failed: {error}")
        }
    };
    // Every allow list present and empty, `deny_subnets` unset: the one
    // `EgressRules::from_policy` shape that admits nothing, with nothing
    // left to subtract from.
    assert_eq!(
        strict.egress,
        Some(sessions::EgressPolicy::deny_all()),
        "the flag must declare the deny-all section, every allow list \
         present and empty"
    );

    // The effective answer keeps the declaration's verdict: a declared
    // section resolves to itself whatever the rollout phase is doing, so
    // `min session policy` renders it as the deny-all name (the declared
    // case of NET-075's rendering) rather than the default's.
    use minimald_rpc::{GetEffectiveSessionPolicy, GetEffectiveSessionPolicyRequest};
    let resp = client
        .oneshot_rpc::<GetEffectiveSessionPolicy>(GetEffectiveSessionPolicyRequest::Name(
            "flag-declared-deny-all".to_string(),
        ))
        .await
        .unwrap();
    let policy = match resp {
        minimald_rpc::Errorable::Ok(policy) => policy,
        minimald_rpc::Errorable::Err { error } => {
            panic!("GetEffectiveSessionPolicy failed: {error}")
        }
    };
    assert_eq!(
        policy.egress,
        sessions::EffectiveEgress::Declared(sessions::EgressPolicy::deny_all()),
        "a declared deny-all box's effective egress is its declaration, never \
         the default"
    );
}

/// An empty value for an egress rule flag stays a typed validation error,
/// never an empty list (NET-075's CLI half): `Some(vec![])` on an allow
/// dimension is the deny-all section, so a value that silently vanished
/// would turn a typo into deny-all — the strongest posture the box can
/// carry, reached by accident. The CIDR dimensions are refused by the
/// daemon's policy validation naming the entry; the protocol dimension by
/// the CLI's own parser; and the hostname dimension, which has no syntax
/// to validate (any name is a host name, resolved at connect), keeps the
/// empty value as the entry it was typed — never a silently emptied list.
#[tokio::test]
async fn empty_egress_flag_value_is_a_validation_error() {
    let (_daemon, args) = setup().await;

    let project = tempfile::TempDir::new().unwrap();
    std::fs::create_dir(project.path().join(".git")).unwrap();
    std::fs::write(
        project.path().join("minimal.toml"),
        "# test minimal.toml\n[stack]\nuse = \"shell\"\n",
    )
    .unwrap();
    let project_path = project.path().to_string_lossy().to_string();

    let activate_args = |allow_subnets: Vec<String>,
                         allow_dns_hosts: Vec<String>,
                         allow_protocols: Vec<String>,
                         deny_subnets: Vec<String>| {
        ActivateArgs {
            name: Some("empty-egress-value".to_string()),
            path: Some(project_path.clone()),
            sync: Some(SyncMode::Tarball),
            network: CliNetworkMode::HostNet,
            ingress: vec![],
            dynamic_ingress: None,
            dynamic_range: None,
            allow_subnets,
            allow_dns_hosts,
            allow_protocols,
            deny_subnets,
            deny_all_egress: false,
            credentialed_upstream: false,
            loadout: vec![],
            no_loadouts: false,
            no_hooks: false,
            no_prompt: true,
            attach: false,
        }
    };

    // `--allow-subnets ""`: an invalid CIDR, named by the daemon's typed
    // validation rather than dropped into an empty allow list.
    let err = cmd_activate(
        &args,
        activate_args(vec![String::new()], vec![], vec![], vec![]),
    )
    .await
    .expect_err("an empty allow-subnets value is not a CIDR");
    let rendered = format!("{err:#}");
    assert!(
        rendered.contains("allow_subnets entry"),
        "the refusal must name the dimension: {rendered}"
    );
    assert!(
        rendered.contains("is not a valid CIDR prefix"),
        "the refusal must name the typed reason: {rendered}"
    );

    // `--deny-subnets ""`: the same check on the denied dimension.
    let err = cmd_activate(
        &args,
        activate_args(vec![], vec![], vec![], vec![String::new()]),
    )
    .await
    .expect_err("an empty deny-subnets value is not a CIDR");
    let rendered = format!("{err:#}");
    assert!(
        rendered.contains("deny_subnets entry"),
        "the refusal must name the dimension: {rendered}"
    );
    assert!(
        rendered.contains("is not a valid CIDR prefix"),
        "the refusal must name the typed reason: {rendered}"
    );

    // `--allow-protocols ""`: refused by the CLI's own parser, before any
    // declaration is built.
    let err = cmd_activate(
        &args,
        activate_args(vec![], vec![], vec![String::new()], vec![]),
    )
    .await
    .expect_err("an empty allow-protocols value is not a protocol");
    let rendered = format!("{err:#}");
    assert!(
        rendered.contains("unsupported protocol"),
        "the refusal must name the typed reason: {rendered}"
    );

    // `--allow-dns-hosts ""`: no syntax to validate, so the entry stands as
    // typed — a declared host that resolves nothing, and a list that is
    // still the caller's one entry, never an emptied one.
    cmd_activate(
        &args,
        activate_args(vec![], vec![String::new()], vec![], vec![]),
    )
    .await
    .expect("a host name has no syntax to refuse");
    let mut client = connect_daemon(&args).await.unwrap();
    use minimald_rpc::{GetSessionPolicy, GetSessionPolicyRequest};
    let strict = client
        .oneshot_rpc::<GetSessionPolicy>(GetSessionPolicyRequest::Name(
            "empty-egress-value".to_string(),
        ))
        .await
        .unwrap();
    let strict = match strict {
        minimald_rpc::Errorable::Ok(strict) => strict,
        minimald_rpc::Errorable::Err { error } => {
            panic!("GetSessionPolicy failed: {error}")
        }
    };
    let egress = strict.egress.expect("the flag values declared a section");
    assert_eq!(
        egress.allow_dns_hosts,
        Some(vec![String::new()]),
        "the empty hostname stays the entry it was typed, never an empty list"
    );
}

/// A box with no egress section shows its effective default by name in
/// `min session policy` (NET-075): never the dimension rows a declared
/// section prints, and never nothing — the default the daemon resolved the
/// absence to, which is the shipped phase's answer for an own-address box
/// and the allow-all a host-address box always keeps, marked as a default
/// on the row itself so it never reads as a declaration, while the strict
/// record keeps the absence. The same distinction rides the JSON document
/// as `source`, asserted here against a declared deny-all box rendered
/// beside the unset one: the default's row carries the mark and the
/// `default` source, the declared box's a bare row and the `declared`
/// source, so neither a person reading the text nor a consumer parsing
/// the document can mistake one for the other. On a host-address box the
/// name sits beside the per-box enforcement value the runtime-facts reply
/// carries (T73).
#[tokio::test]
async fn policy_shows_unset_egress_as_named_default() {
    let (daemon, args) = setup().await;
    let mut client = connect_daemon(&args).await.unwrap();
    use minimald_rpc::{GetEffectiveSessionPolicy, GetEffectiveSessionPolicyRequest};

    // Own-address, no section: the shipped phase's resolution, rendered by
    // its own name — whatever the phase this build ships resolves the
    // absence to, the render must say that name, marked as the default it
    // is, never dimension rows.
    let own_id = create_session_with_policy(
        &daemon,
        "unset-own-ip",
        sessions::NetworkMode::OwnIp,
        sessions::SessionPolicy::default(),
    )
    .await;
    let resp = client
        .oneshot_rpc::<GetEffectiveSessionPolicy>(GetEffectiveSessionPolicyRequest::Id(own_id))
        .await
        .unwrap();
    let own_policy = match resp {
        minimald_rpc::Errorable::Ok(policy) => policy,
        minimald_rpc::Errorable::Err { error } => {
            panic!("GetEffectiveSessionPolicy failed: {error}")
        }
    };
    assert_eq!(
        own_policy.egress,
        sessions::effective_egress(
            None,
            sessions::NetworkMode::OwnIp,
            sessions::EGRESS_DEFAULT_PHASE,
            false
        ),
        "a box with no section resolves to the shipped phase's default"
    );
    let mut out = Vec::new();
    format_policy(
        &mut out,
        &own_policy,
        sessions::NetworkMode::OwnIp,
        None,
        None,
    )
    .unwrap();
    let own_text = String::from_utf8(out).unwrap();
    let name = match own_policy.egress {
        sessions::EffectiveEgress::DenyAll => "  deny-all (default)\n",
        sessions::EffectiveEgress::AllowAll => "  allow-all (default)\n",
        sessions::EffectiveEgress::Declared(_) => {
            panic!("a box with no section must never resolve to a declaration")
        }
    };
    assert!(
        own_text.contains(&format!("egress\n{name}")),
        "the unset box's default must render by name, marked as the \
         default: {own_text}"
    );
    for row in ["  subnets", "  dns hosts", "  protocols"] {
        assert!(
            !own_text.contains(row),
            "an unset box must not render as declaration rows: {own_text}"
        );
    }
    // The document a `-o json` run writes carries the same distinction
    // (NET-075): the verdict's name in `effective`, its origin in `source`,
    // so a consumer never recomputes the rollout rule to know the row it
    // read was a default and not a declaration.
    let mut out = Vec::new();
    write_policy_json(
        &mut out,
        &own_policy,
        sessions::NetworkMode::OwnIp,
        None,
        Ok(Vec::new()),
    )
    .unwrap();
    let own_document: Value = serde_json_lenient::from_slice(&out).unwrap();
    let own_name = match own_policy.egress {
        sessions::EffectiveEgress::DenyAll => "deny-all",
        sessions::EffectiveEgress::AllowAll => "allow-all",
        sessions::EffectiveEgress::Declared(_) => {
            panic!("a box with no section must never resolve to a declaration")
        }
    };
    assert_eq!(
        own_document["egress"]["effective"], own_name,
        "the document names the default by the token the text row prints:\n{own_document}"
    );
    assert_eq!(
        own_document["egress"]["source"], "default",
        "a resolved default says so in the document, so no consumer \
         recomputes the rollout rule:\n{own_document}"
    );

    // Host-address, no section: the shipped allow-all — the default is
    // scoped to own-address boxes (NET-074) — beside the per-box
    // enforcement value the facts reply carries, in its machine spelling.
    let host_id = create_session_with_policy(
        &daemon,
        "unset-host-ip",
        sessions::NetworkMode::HostNet,
        sessions::SessionPolicy::default(),
    )
    .await;
    let resp = client
        .oneshot_rpc::<GetEffectiveSessionPolicy>(GetEffectiveSessionPolicyRequest::Id(host_id))
        .await
        .unwrap();
    let host_policy = match resp {
        minimald_rpc::Errorable::Ok(policy) => policy,
        minimald_rpc::Errorable::Err { error } => {
            panic!("GetEffectiveSessionPolicy failed: {error}")
        }
    };
    assert_eq!(
        host_policy.egress,
        sessions::EffectiveEgress::AllowAll,
        "a bare host-address box keeps the shipped allow-all"
    );
    use minimald_rpc::{GetSessionRuntimeFacts, GetSessionRuntimeFactsRequest};
    let resp = client
        .oneshot_rpc::<GetSessionRuntimeFacts>(GetSessionRuntimeFactsRequest::Id(host_id))
        .await
        .unwrap();
    let facts = match resp {
        minimald_rpc::Errorable::Ok(facts) => facts,
        minimald_rpc::Errorable::Err { error } => {
            panic!("GetSessionRuntimeFacts failed: {error}")
        }
    };
    let enforcement = facts
        .host_ip_enforcement
        .expect("a host-address session answers a state");
    let mut out = Vec::new();
    format_policy(
        &mut out,
        &host_policy,
        sessions::NetworkMode::HostNet,
        Some(enforcement),
        None,
    )
    .unwrap();
    let text = String::from_utf8(out).unwrap();
    assert!(
        text.contains(&format!(
            "egress\n  allow-all (default)\n  per-box enforcement  {}\n",
            enforcement.machine_str()
        )),
        "the host-address default sits beside the per-box enforcement value: {text}"
    );

    // A declared deny-all box beside the unset one: the same surface, a
    // different origin, and both the render and the document carry the
    // difference — the declared row is bare where the default's is marked,
    // and the declared `source` says `declared` where the default's says
    // `default` — so a default never reads as something the box chose.
    let declared_id = create_session_with_policy(
        &daemon,
        "unset-beside-declared-deny-all",
        sessions::NetworkMode::OwnIp,
        sessions::SessionPolicy::new(Some(sessions::EgressPolicy::deny_all()), None),
    )
    .await;
    let resp = client
        .oneshot_rpc::<GetEffectiveSessionPolicy>(GetEffectiveSessionPolicyRequest::Id(declared_id))
        .await
        .unwrap();
    let declared_policy = match resp {
        minimald_rpc::Errorable::Ok(policy) => policy,
        minimald_rpc::Errorable::Err { error } => {
            panic!("GetEffectiveSessionPolicy failed: {error}")
        }
    };
    assert_eq!(
        declared_policy.egress,
        sessions::EffectiveEgress::Declared(sessions::EgressPolicy::deny_all()),
        "a declared deny-all box's effective egress is its declaration"
    );
    let mut out = Vec::new();
    format_policy(
        &mut out,
        &declared_policy,
        sessions::NetworkMode::OwnIp,
        None,
        None,
    )
    .unwrap();
    let declared_text = String::from_utf8(out).unwrap();
    assert!(
        declared_text.contains("egress\n  deny-all\n"),
        "the declared box's row is the name, bare:\n{declared_text}"
    );
    assert!(
        !declared_text.contains("(default)"),
        "the declared row carries no default mark, so it never reads as \
         one:\n{declared_text}"
    );
    assert_ne!(
        own_text, declared_text,
        "the default and the declared renders must differ"
    );
    let mut out = Vec::new();
    write_policy_json(
        &mut out,
        &declared_policy,
        sessions::NetworkMode::OwnIp,
        None,
        Ok(Vec::new()),
    )
    .unwrap();
    let declared_document: Value = serde_json_lenient::from_slice(&out).unwrap();
    assert_eq!(
        declared_document["egress"]["effective"], "deny-all",
        "the declared verdict is named by the same token:\n{declared_document}"
    );
    assert_eq!(
        declared_document["egress"]["source"], "declared",
        "the declared box's document says declared:\n{declared_document}"
    );
    assert_ne!(
        own_document["egress"]["source"], declared_document["egress"]["source"],
        "the default and the declared documents must differ in their source"
    );

    // And the strict record keeps the absence, which is what marks the row
    // above as the default: the box declared nothing, and the render is the
    // gate's resolution of that, never a section the box carries.
    use minimald_rpc::{GetSessionPolicy, GetSessionPolicyRequest};
    let strict = client
        .oneshot_rpc::<GetSessionPolicy>(GetSessionPolicyRequest::Id(host_id))
        .await
        .unwrap();
    let strict = match strict {
        minimald_rpc::Errorable::Ok(strict) => strict,
        minimald_rpc::Errorable::Err { error } => {
            panic!("GetSessionPolicy failed: {error}")
        }
    };
    assert_eq!(
        strict.egress, None,
        "the record must keep the absence the render resolved to a default"
    );
}

/// `min session policy` shows the node-plane baseline set beside the box's
/// rules (NET-130): the helper's built-in enumeration of the categories the
/// in-VM daemon's own traffic may reach, one row per category, on an
/// own-address box, headed by the posture the host-side gate decides the
/// daemon's own fetches under — announced, the shipped posture, the run
/// path's allow-all interim node row still decides those fetches, so the
/// rows are what the set will bound, not what bounds them today; in force,
/// it decides them whatever the box's own declaration resolves to. The set
/// is shown where the fabric the helper gates is named — the microVM
/// backend's plan — and nowhere it is not: a host-address box shares its
/// host's namespace and has no switch fabric, and a backend with no
/// host-side helper beside its switch (the native daemon's own per-daemon
/// switch, a plan the reply does not carry) names no fabric either, so the
/// block is left out there rather than printed from a plan the session does
/// not attach to.
#[test]
fn policy_shows_baseline_set() {
    // The deny-all resolution the rollout ends at (NET-075), rendered the
    // way the command renders it: the box's own rules, and the helper's
    // enumeration beside them — the microVM backend's fabric, the plan the
    // helper's run path builds its registry and this set from.
    let deny_all = sessions::EffectiveSessionPolicy {
        egress: sessions::effective_egress(
            None,
            sessions::NetworkMode::OwnIp,
            sessions::EgressDefaultPhase::InForce,
            false,
        ),
        ingress: None,
    };
    let fabric = switch::SwitchSubnet::default();
    let mut out = Vec::new();
    format_policy(
        &mut out,
        &deny_all,
        sessions::NetworkMode::OwnIp,
        None,
        Some(fabric),
    )
    .unwrap();
    let text = String::from_utf8(out).unwrap();
    assert!(
        text.contains("egress\n  deny-all (default)\n"),
        "the box's own rules are shown:\n{text}"
    );
    // The posture is spelled beside the set, the way the daemon's start-up
    // line spells it. The shipped posture is announced — the run path's
    // allow-all interim node row still decides the daemon's own fetches — so
    // the display must not present the rows as what bounds them. The flip of
    // `NODE_BASELINE_PHASE` updates this assertion with the rest of the
    // cutover.
    assert!(
        text.contains(
            "node-plane baseline set (helper enumeration) — announced (node row's allow-all interim)"
        ),
        "the helper's baseline set is shown beside the box's rules, headed by the \
         gate's announced posture:\n{text}"
    );

    // The rows are the enumeration the helper carries, one per category —
    // the set the host-side gate decides the daemon's own frames by once the
    // baseline is in force.
    let baseline = minvmd::net::NodePlaneBaseline::built_in(fabric);
    let rendered_baseline = baseline
        .entries()
        .iter()
        .map(|entry| {
            format!(
                "  {}  {}",
                entry.category().as_str(),
                entry.endpoints().join(", ")
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        text.contains(&rendered_baseline),
        "the baseline rows are the enumeration's entries, one per category:\n{text}"
    );
    // Beside, not instead: the egress block comes first, the baseline set
    // after it, the ingress block last.
    let egress_at = text.find("egress").expect("the egress block renders");
    let baseline_at = text
        .find("node-plane baseline set")
        .expect("the baseline set renders");
    let ingress_at = text.find("ingress").expect("the ingress block renders");
    assert!(
        egress_at < baseline_at && baseline_at < ingress_at,
        "the baseline set renders beside the rules, between egress and ingress:\n{text}"
    );

    // A host-address box has no switch fabric, so the baseline set has
    // nothing to describe there — even with a fabric named.
    let mut out = Vec::new();
    format_policy(
        &mut out,
        &deny_all,
        sessions::NetworkMode::HostNet,
        None,
        Some(fabric),
    )
    .unwrap();
    let text = String::from_utf8(out).unwrap();
    assert!(
        !text.contains("node-plane baseline set"),
        "a host-address box carries no baseline set:\n{text}"
    );

    // A backend with no helper beside its switch — the native daemon's own
    // per-daemon switch, a plan the reply does not carry — names no fabric,
    // and the set is left out rather than printed from the microVM plan the
    // session does not attach to.
    let mut out = Vec::new();
    format_policy(
        &mut out,
        &deny_all,
        sessions::NetworkMode::OwnIp,
        None,
        None,
    )
    .unwrap();
    let text = String::from_utf8(out).unwrap();
    assert!(
        !text.contains("node-plane baseline set"),
        "an unnamed fabric carries no baseline set:\n{text}"
    );
}

/// While the deny-all egress default is announced but not yet in force,
/// `min session activate` prints the coming change (NET-076) — what turns
/// for a bare own-address box, and how to keep the shipped default. Driven
/// through the compiled binary so the assertion is on what the user actually
/// sees; the phase this build ships is announced, so the notice is the
/// shipped path, and its scoping is exercised with it: a bare own-address
/// activate prints, a host-address one (a box the change does not reach)
/// does not, and a daemon that opted out (NET-077 — a deployment the change
/// is not coming for, and one that has already taken the remedy the notice
/// names) is not announced at either. The other phase is gated by
/// construction — once the default is in force the change is no longer
/// coming, and the notice is `None`.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn deny_all_announcement_printed() {
    let (_daemon, args) = setup().await;
    let project = tempfile::TempDir::new().unwrap();
    std::fs::create_dir(project.path().join(".git")).unwrap();
    std::fs::write(
        project.path().join("minimal.toml"),
        "# test minimal.toml\n[stack]\nuse = \"shell\"\n",
    )
    .unwrap();

    // The shipped path: activating a bare own-address box succeeds and
    // prints the notice — the change, its scope, and the way to keep the
    // default.
    let own_ip = run_min(
        &args,
        &[
            "session",
            "activate",
            project.path().to_str().unwrap(),
            "--name",
            "notice-own-ip",
            "--network",
            "own_ip",
            "--sync",
            "tarball",
            "--no-prompt",
        ],
    )
    .await;
    assert!(
        own_ip.status.success(),
        "activating a bare own-address box must succeed, but the binary \
         exited {}:\n{}",
        own_ip.status,
        String::from_utf8_lossy(&own_ip.stderr),
    );
    let own_ip_stderr = String::from_utf8_lossy(&own_ip.stderr).into_owned();
    assert!(
        own_ip_stderr.contains("Heads-up: the next release denies all external reach"),
        "activating a bare own-address box must print the coming change:\n{own_ip_stderr}"
    );
    assert!(
        own_ip_stderr.contains("own-address"),
        "the notice must scope the change to own-address sessions:\n{own_ip_stderr}"
    );
    assert!(
        own_ip_stderr.contains("--egress-deny-all-opt-out"),
        "the notice must say how to keep the shipped default:\n{own_ip_stderr}"
    );

    // Scoped to the boxes the change would reach: a host-address box
    // shares its host's namespace and owns no address to deny from, so
    // its activate announces nothing.
    let host_net_stderr = run_min_stderr(
        &args,
        &[
            "session",
            "activate",
            project.path().to_str().unwrap(),
            "--name",
            "notice-host-net",
            "--network",
            "host_ip",
            "--sync",
            "tarball",
            "--no-prompt",
        ],
    )
    .await;
    assert!(
        !host_net_stderr.contains("Heads-up"),
        "a host-address box the change does not reach must not be announced \
         at:\n{host_net_stderr}"
    );

    // And scoped to the daemons the change is coming for: an opted-out
    // daemon (NET-077) has already chosen to keep the shipped default —
    // the exact remedy this notice names — so announcing at it would tell
    // it to do what it has done. The opt-out is the daemon's own fact, so
    // this half runs against a second daemon started with the flag.
    let (_opted_out, opted_out_args, _opted_out_dir) = setup_opted_out().await;
    let opted_out = run_min(
        &opted_out_args,
        &[
            "session",
            "activate",
            project.path().to_str().unwrap(),
            "--name",
            "notice-opted-out",
            "--network",
            "own_ip",
            "--sync",
            "tarball",
            "--no-prompt",
        ],
    )
    .await;
    assert!(
        opted_out.status.success(),
        "activating a bare own-address box must still succeed on an opted-out \
         daemon, but the binary exited {}:\n{}",
        opted_out.status,
        String::from_utf8_lossy(&opted_out.stderr),
    );
    let opted_out_stderr = String::from_utf8_lossy(&opted_out.stderr).into_owned();
    assert!(
        !opted_out_stderr.contains("Heads-up"),
        "a daemon that has already taken the notice's remedy must not be \
         told to take it:\n{opted_out_stderr}"
    );

    // The other phase, gated by construction: once the default is in
    // force the change is no longer coming, and nothing prints.
    assert!(
        deny_all_default_notice(sessions::EgressDefaultPhase::InForce).is_none(),
        "the notice must not print once the default is in force"
    );
}

/// [`setup`] on a daemon that opted out of the deny-all egress default
/// (NET-077): the same UDS-listening harness server, but one whose boxes
/// with no `egress` section keep the shipped allow-all. Only the
/// announcement test needs a daemon with the other rollout posture, so the
/// builder stays here beside it rather than in the shared harness.
///
/// The caller must keep both returned values alive for as long as it talks
/// to the daemon: the server owns the daemon's state, the tempdir the
/// socket path lives in.
#[cfg(target_os = "linux")]
async fn setup_opted_out() -> (
    minimald::test_harness::TestServer,
    GlobalArgs,
    tempfile::TempDir,
) {
    let server = minimald::test_harness::TestServer::new_opted_out_in(
        tempfile::TempDir::new().expect("the harness's tempdir for the opted-out daemon"),
    )
    .await;
    let temp = tempfile::TempDir::new().expect("a tempdir for the client side of the test");
    let sock_dir = temp.path().join("providers/local-minimald0");
    std::fs::create_dir_all(&sock_dir).expect("the provider socket dir is a fresh tempdir path");
    server.listen_on_uds(&sock_dir.join("ssh.sock")).await;
    let args = GlobalArgs {
        repo_dir: None,
        minimal_dir: Some(temp.path().to_path_buf()),
        config_dir: None,
        provider: None,
        no_input: false,
        vm: None,
    };
    (server, args, temp)
}

// --- session hooks ---

/// `min session hooks` names the session it could not find, like every other
/// session command: the error is `No session found matching '<name>'` rather
/// than the daemon's bare `no session found`.
#[tokio::test]
async fn session_hooks_missing_session_names_the_lookup() {
    let (_daemon, args) = setup().await;

    let err = cmd_session_hooks(
        &args,
        HooksArgs {
            session: "nosuch".to_string(),
            json: false,
        },
    )
    .await
    .unwrap_err();

    assert_eq!(
        err.to_string(),
        "No session found matching 'nosuch'",
        "a missing session must be named in the error"
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
/// captured output. The tempdir holding that `--config-dir` lives until the
/// function returns, so it outlives the child it is spelled into.
#[cfg(target_os = "linux")]
async fn run_min(args: &GlobalArgs, extra: &[&str]) -> std::process::Output {
    let minimal_dir = args
        .minimal_dir
        .as_ref()
        .expect("setup points at a tempdir");
    let config_dir = tempfile::TempDir::new().unwrap();
    let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_min"));
    command
        .args(["--minimal-dir".as_ref(), minimal_dir.as_os_str()])
        .args(["--config-dir".as_ref(), config_dir.path().as_os_str()])
        .arg("--no-input")
        .args(extra);
    command
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
        "# test minimal.toml\n[stack]\nuse = \"shell\"\n",
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

/// NET-018: `min ls` and `min session activate` report which surface a
/// `*.min.internal` name resolves through, decided in the one function both
/// verbs share — the three facts: this host's resolver hook routing the
/// zone to the answerer (with no stub-bypass blocker making that hook
/// configuration no host process consults), the daemon's answerer bound,
/// and the reserved local range present on this host's loopback. With the
/// answerer bound and no hook (this host), both verbs must name the
/// *proxy* as the live surface and print the NET-122 advisory beside it;
/// with the hook and the range present too, the same decision says native
/// and the advisory goes quiet.
///
/// The daemon's half is brought up the way its start path brings it — the
/// proxy and the answerer driven to serving on OS-selected ports — and the
/// reply is checked first, as the field, not as the wording. The native arm
/// cannot be driven through the binary hermetically: the blocker reads
/// `/etc/resolv.conf` and the `hosts:` chain directly, host files no PATH
/// stand-in can stand in for, so what a stand-in `resolvectl` proves
/// depends on the host it runs on. The decision is pure, so its table —
/// the native arm, and the dead-hook case that must not print native on a
/// hook no host process consults — lives beside the function in
/// `resolver`'s tests, where every arm runs on every host. `resolver`'s own
/// Linux test `activate_and_ls_report_native_surface_verdict_on_host` runs
/// the positive arm against a real host loopback, where the range always
/// reads present, and shares this test's name so the verify line runs both.
///
/// The positive arm's *words* run here as the in-process arm: the binary
/// cannot reach them on this host, because the verdict reads the host's own
/// resolver files, which no test may rewrite — so the native verdict is fed
/// straight to the formatter `cmd_ls` prints from, over this daemon's live
/// reply, and what a host whose three facts all hold is told is asserted
/// all the same.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn activate_and_ls_report_native_surface() {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use minimald::server::{
        RetryBackoff, retry_hostname_proxy_until_serving, retry_zone_answerer_until_serving,
    };
    use minimald_rpc::ListSessions;

    let (daemon, args) = setup().await;
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

    // The daemon's half, deployed and reported: the reply says the answerer
    // is bound — the one fact that is the daemon's to know — and carries
    // the port the proxy's half of the line names, and the port a hook
    // would have to route to.
    let mut client = connect_daemon(&args).await.unwrap();
    let resp = client.oneshot_rpc::<ListSessions>(()).await.unwrap();
    let port = resp
        .hostname_proxy_port
        .expect("the proxy must report the port it landed on");
    let _answerer_port = resp
        .zone_answerer_port
        .expect("the answerer must report the port it landed on");
    assert!(
        resp.answerer_bound,
        "a daemon whose answerer serves reports it bound"
    );

    // The host's half, absent: NET-018's WHERE is the host's — a daemon
    // inside a VM-backed host's guest cannot speak for the host's resolver,
    // and this host's own reads say nothing routes the zone to the answerer
    // — so both verbs name the proxy as the live surface, with where it
    // serves, and neither prints the native words.
    let out = run_min(&args, &["ls"]).await;
    let ls_stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(
        ls_stdout.contains("NAME SURFACE:    the hostname proxy is the live name surface"),
        "`min ls` must report the proxy as the live surface on a hook-less host, got: {ls_stdout}"
    );
    assert!(
        ls_stdout.contains(&format!("routes through it on 127.0.0.1:{port}")),
        "the surface line must name where the proxy serves: {ls_stdout}"
    );
    assert!(
        !ls_stdout.contains("native DNS is the live name surface"),
        "a host with no hook must not be told native DNS is live: {ls_stdout}"
    );

    // `min session activate`, at the moment the user is about to rely on the
    // names — and before the upload and the loadout, so the line is not lost
    // above a failed activate's output. The advisory rides beside the line
    // (NET-122): this host cannot resolve the zone natively, so the session
    // start must say what is missing — the exact command to run, or the
    // host fact that makes one dead — and never a prompt.
    let project = tempfile::TempDir::new().unwrap();
    std::fs::create_dir(project.path().join(".git")).unwrap();
    std::fs::write(
        project.path().join("minimal.toml"),
        "# test minimal.toml\n[stack]\nuse = \"shell\"\n",
    )
    .unwrap();
    let activate_stderr = run_min_stderr(
        &args,
        &[
            "session",
            "activate",
            project.path().to_str().unwrap(),
            "--name",
            "native-surface",
            "--sync",
            "tarball",
            "--no-prompt",
        ],
    )
    .await;
    assert!(
        activate_stderr.contains("the hostname proxy is the live name surface"),
        "activate must report the proxy as the live surface on a hook-less host, got: {activate_stderr}"
    );
    assert!(
        activate_stderr.contains(&format!("routes through it on 127.0.0.1:{port}")),
        "activate's line must name where the proxy serves: {activate_stderr}"
    );
    assert!(
        !activate_stderr.contains("native DNS is the live name surface"),
        "a host with no hook must not be told native DNS is live: {activate_stderr}"
    );
    assert!(
        activate_stderr.contains("note:"),
        "activate must print the naming advisory beside the surface line, got: {activate_stderr}"
    );
    assert!(
        activate_stderr.contains("Configure the host's resolver for the zone")
            || activate_stderr.contains("bypass systemd-resolved"),
        "the advisory names what is missing — the command to run, or the host fact that \
         makes one dead: {activate_stderr}"
    );

    // The positive arm, in process (see the test's doc): the native verdict
    // fed to the formatter `cmd_ls` prints through, over this daemon's live
    // reply — which carries the real proxy port the line's second half
    // names. A host whose three facts all hold is told native DNS is the
    // live surface, the proxy's half stays beside it (NET-019), and the
    // NET-122 advisory a native host no longer needs does not ride it.
    let mut native_out = Vec::new();
    format_ls(
        &mut native_out,
        &LsArgs {
            raw: false,
            json: false,
        },
        &resp,
        Some(resolver::LiveSurface::Native),
        None,
    )
    .unwrap();
    let native_ls = String::from_utf8(native_out).unwrap();
    assert!(
        native_ls.contains("NAME SURFACE:    native DNS is the live name surface"),
        "`min ls` must say native DNS is the live surface when the three facts hold, got: \
         {native_ls}"
    );
    assert!(
        native_ls.contains(&format!(
            "the hostname proxy still serves on 127.0.0.1:{port}"
        )),
        "the native arm keeps the proxy's half beside it (NET-019): {native_ls}"
    );
    assert!(
        !native_ls.contains("note:") && !native_ls.contains("Configure the host's resolver"),
        "a host the verdict calls native is a configured one: no advisory rides its list, \
         got: {native_ls}"
    );
    // And the words are activate's: one function renders the line for both
    // verbs, so the native words `min ls` printed are the words the session
    // start prints at the moment the user relies on the names.
    let activate_words = resolver::name_surface_line(resolver::LiveSurface::Native, Some(port));
    assert!(
        native_ls.contains(&activate_words),
        "`min ls` and activate print the same native words: {native_ls} vs {activate_words}"
    );
}

// --- the VM-backed host's answerer lines (NET-138) ---

/// `min ls` on a VM-backed host: the daemon behind the list reports no
/// answerer of its own (a VM's daemon starts none), so the ZONE ANSWERER
/// line prints from the state the VM host daemon's control socket
/// answered — saying the zone is answered by the VM host daemon and naming
/// the holder — while `--json` and `--raw` stay machine-readable-only, the
/// native daemon's own line keeps its place on a native host, and the
/// pre-acquisition state prints nothing and forces no blank line. Pinned
/// here as a pure formatting call because the session e2e greps a real
/// host's `min ls` for exactly this line.
#[test]
fn ls_names_the_vm_host_daemon_as_the_zone_answerer() {
    let resp = ListSessionsResponse {
        daemon_version: None,
        hostname_routing_unavailable: None,
        hostname_proxy_port: None,
        zone_answerer_port: None,
        answerer_bound: false,
        resource_pool: None,
        sessions: Vec::new(),
    };

    // The lone-holder shape: this VM's minvmd holds the port.
    let mut out = Vec::new();
    format_ls(
        &mut out,
        &LsArgs {
            raw: false,
            json: false,
        },
        &resp,
        Some(resolver::LiveSurface::Native),
        Some(minimald_rpc::ZoneAnswererStatus::Holder { port: 7_656 }),
    )
    .unwrap();
    let holder_ls = String::from_utf8(out).unwrap();
    assert!(
        holder_ls
            .contains("ZONE ANSWERER:   answered by the VM host daemon (single-operator interim)"),
        "the list names who answers the zone on a VM-backed host: {holder_ls}"
    );
    assert!(
        holder_ls.contains("this VM's minvmd holds it on 127.0.0.1:7656 (UDP)"),
        "the line names this VM's minvmd as the holder: {holder_ls}"
    );
    // The verdict beside it: the query proved the answerer live and this
    // host's facts held, so the surface the CLI computed prints through —
    // the same `NAME SURFACE` line the native host's list carries.
    assert!(
        holder_ls.contains("NAME SURFACE:    native DNS is the live name surface"),
        "the VM-host verdict rides the list like a native one: {holder_ls}"
    );
    assert!(
        holder_ls.contains("\n\nNo active sessions."),
        "the answerer lines are separated from the list body by a blank line: {holder_ls}"
    );

    // The no-channel shape: the holder is a process no channel reaches, so
    // the line says the names are not answered on the host and must not
    // claim the VM host daemon answers them.
    let mut out = Vec::new();
    format_ls(
        &mut out,
        &LsArgs {
            raw: false,
            json: false,
        },
        &resp,
        Some(resolver::LiveSurface::Proxy),
        Some(minimald_rpc::ZoneAnswererStatus::PortHeldNoChannel { port: 7_656 }),
    )
    .unwrap();
    let held_ls = String::from_utf8(out).unwrap();
    assert!(
        held_ls.contains("ZONE ANSWERER:   not answered on the host"),
        "a port held by a process no channel reaches is not an answered zone: {held_ls}"
    );
    assert!(
        !held_ls.contains("answered by the VM host daemon (single-operator interim)"),
        "the no-channel arm must not claim an answer: {held_ls}"
    );
    assert!(
        held_ls.contains("NAME SURFACE:    the hostname proxy is the live name surface"),
        "the no-channel verdict reads the proxy: {held_ls}"
    );

    // `--raw` is machine-readable-only: the host fact rides no pipeline.
    let mut out = Vec::new();
    format_ls(
        &mut out,
        &LsArgs {
            raw: true,
            json: false,
        },
        &resp,
        None,
        Some(minimald_rpc::ZoneAnswererStatus::Holder { port: 7_656 }),
    )
    .unwrap();
    let raw_ls = String::from_utf8(out).unwrap();
    assert!(
        !raw_ls.contains("ZONE ANSWERER"),
        "a raw list carries no answerer line: {raw_ls}"
    );

    // The pre-acquisition state prints no line — and, because nothing
    // printed, forces no blank line either.
    let mut out = Vec::new();
    format_ls(
        &mut out,
        &LsArgs {
            raw: false,
            json: false,
        },
        &resp,
        None,
        Some(minimald_rpc::ZoneAnswererStatus::Starting),
    )
    .unwrap();
    let starting_ls = String::from_utf8(out).unwrap();
    assert_eq!(
        starting_ls, "No active sessions.\n",
        "a status with nothing to say yet prints nothing: {starting_ls}"
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
        answerer_bound: false,
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
        box_addresses: None,
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
        box_addresses: None,
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

// --- net forward (NET-104/NET-105) ---

/// The service the forward reaches: a loopback echo server, bound to an
/// ephemeral port, echoing every accepted connection back byte for byte.
async fn spawn_echo_server() -> (u16, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        loop {
            let Ok((conn, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let (mut read, mut write) = tokio::io::split(conn);
                let _ = tokio::io::copy(&mut read, &mut write).await;
            });
        }
    });
    (port, server)
}

/// A loopback port nothing is bound to, for the forward's laptop-side
/// listener. Probed rather than guessed: bind :0, read the port, drop the
/// socket.
async fn free_loopback_port() -> u16 {
    let probe = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    let port = probe.local_addr().unwrap().port();
    drop(probe);
    port
}

/// Connects to `127.0.0.1:port`, retrying briefly: the forward runs as a
/// concurrent task, so its listener appears a moment after the spawn.
async fn connect_with_retry(port: u16) -> tokio::net::TcpStream {
    let mut last = None;
    for _ in 0..500 {
        match tokio::net::TcpStream::connect(("127.0.0.1", port)).await {
            Ok(stream) => return stream,
            Err(e) => {
                last = Some(e);
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        }
    }
    panic!("nothing ever listened on 127.0.0.1:{port}: {last:?}");
}

/// A `GlobalArgs` pointing at the same daemon as `args`, but built to move
/// into a spawned task: the shared one stays with the test body.
fn global_args_for_task(args: &GlobalArgs) -> GlobalArgs {
    GlobalArgs {
        minimal_dir: args.minimal_dir.clone(),
        ..Default::default()
    }
}

/// `min net forward web 8080:3000` answers on `localhost:8080` (NET-104):
/// the session is `host_ip`, so the box shares this process's network
/// namespace, and the echo server below stands in for the in-box service the
/// forward reaches. Bytes written to the laptop-side port come back over the
/// session's SSH channel, on the forward's own connections — twice, to show
/// each accepted connection gets its own channel.
#[tokio::test]
async fn net_forward_relays_over_ssh_channel() {
    let (daemon, args) = setup().await;
    let _id = create_session_with_policy(
        &daemon,
        "web",
        sessions::NetworkMode::HostNet,
        sessions::SessionPolicy::default(),
    )
    .await;

    let (box_port, echo) = spawn_echo_server().await;
    let local_port = free_loopback_port().await;
    let forward_args = global_args_for_task(&args);
    let forward = tokio::spawn(async move {
        cmd_net_forward(
            &forward_args,
            NetForwardArgs {
                session: "web".to_string(),
                spec: format!("{local_port}:{box_port}"),
            },
        )
        .await
    });

    for round in 0..2 {
        let mut conn = connect_with_retry(local_port).await;
        conn.write_all(b"ping").await.expect("write to the forward");
        let mut echoed = [0u8; 4];
        conn.read_exact(&mut echoed)
            .await
            .expect("read the box's answer back through the forward");
        assert_eq!(
            echoed, *b"ping",
            "connection {round} must relay through the box port"
        );
    }

    forward.abort();
    echo.abort();
}

/// A connection whose box port refuses ends that connection and nothing
/// else (NET-104): the channel open runs in the connection's own task, so a
/// refused dial costs one connection while the listener keeps accepting —
/// and the very next connection, once the box port has a listener, relays.
#[tokio::test]
async fn net_forward_survives_a_refused_box_port() {
    let (daemon, args) = setup().await;
    let _id = create_session_with_policy(
        &daemon,
        "web",
        sessions::NetworkMode::HostNet,
        sessions::SessionPolicy::default(),
    )
    .await;

    // Nothing is listening on the box port yet: the first connection's dial
    // is refused by the box.
    let box_port = free_loopback_port().await;
    let local_port = free_loopback_port().await;
    let forward_args = global_args_for_task(&args);
    let forward = tokio::spawn(async move {
        cmd_net_forward(
            &forward_args,
            NetForwardArgs {
                session: "web".to_string(),
                spec: format!("{local_port}:{box_port}"),
            },
        )
        .await
    });

    // The refused connection is accepted — the forward's listener is up — and
    // then closed by the refusal, not hung. It ends with a reset or with a
    // clean EOF, whichever side of the race the bytes the client sent land
    // on: a socket dropped with unread data in its receive queue resets,
    // one dropped after the bytes arrived and were read ends cleanly. Either
    // way the connection is over, which is the point.
    let mut refused = connect_with_retry(local_port).await;
    refused.write_all(b"ping").await.unwrap();
    let mut seen = Vec::new();
    match refused.read_to_end(&mut seen).await {
        Ok(n) => assert_eq!(
            n, 0,
            "a refused dial must close the connection, got: {seen:?}"
        ),
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {}
        Err(e) => panic!("a refused dial must close the connection, got: {e}"),
    }
    drop(refused);

    // The service comes up on the box port, and the forward that survived
    // the refusal reaches it.
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", box_port))
        .await
        .expect("the box port is free for the service to take");
    let echo = tokio::spawn(async move {
        loop {
            let Ok((conn, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let (mut read, mut write) = tokio::io::split(conn);
                let _ = tokio::io::copy(&mut read, &mut write).await;
            });
        }
    });

    let mut conn = connect_with_retry(local_port).await;
    conn.write_all(b"ping").await.expect("write to the forward");
    let mut echoed = [0u8; 4];
    conn.read_exact(&mut echoed)
        .await
        .expect("read the box's answer back through the forward");
    assert_eq!(echoed, *b"ping", "the forward must relay after a refusal");

    forward.abort();
    echo.abort();
}

/// The forward closes with its session (NET-105): once `min session destroy`
/// takes the session down, the forward's future ends on its own — the
/// listener goes with it rather than outliving the session it forwards for.
#[tokio::test]
async fn net_forward_closes_with_session() {
    let (daemon, args) = setup().await;
    let _id = create_session_with_policy(
        &daemon,
        "web",
        sessions::NetworkMode::HostNet,
        sessions::SessionPolicy::default(),
    )
    .await;

    let (box_port, echo) = spawn_echo_server().await;
    let local_port = free_loopback_port().await;
    let forward_args = global_args_for_task(&args);
    let forward = tokio::spawn(async move {
        cmd_net_forward(
            &forward_args,
            NetForwardArgs {
                session: "web".to_string(),
                spec: format!("{local_port}:{box_port}"),
            },
        )
        .await
    });

    // The listener is up: the forward is live, not just spawned.
    let mut conn = connect_with_retry(local_port).await;
    conn.write_all(b"ping").await.unwrap();
    let mut echoed = [0u8; 4];
    conn.read_exact(&mut echoed).await.unwrap();
    assert_eq!(echoed, *b"ping");
    drop(conn);

    cmd_destroy(
        &args,
        DestroyArgs {
            session: Some("web".to_string()),
            all: false,
            force: true,
        },
    )
    .await
    .unwrap();

    tokio::time::timeout(std::time::Duration::from_secs(5), forward)
        .await
        .expect("the forward must end once its session is destroyed")
        .expect("the forward task must not panic")
        .expect("the forward must exit cleanly");
    echo.abort();
}

// --- task run stdin pipe (gominimal/inbox#746) ---

/// `min task run` must exit once the task exits, even when its stdin is a
/// pipe whose writer stays open. The old bridge pumped stdin through
/// `tokio::io::stdin()`, a blocking `read(0)` parked on tokio's blocking
/// pool that `pump.abort()` cannot interrupt — so a held-open pipe kept the
/// runtime alive forever after the task's exit status arrived. Driven
/// through the compiled binary with the write end deliberately held open,
/// so the assertion is on the process actually terminating.
///
/// Linux-only for the same reason as [`run_min`]: the spawned binary resolves
/// the native `local-minimald` provider socket, which the harness daemon
/// serves on a UDS; macOS resolves `local-minvmd` instead.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn task_run_exits_with_held_open_stdin_pipe() {
    let (_daemon, args) = setup().await;
    let minimal_dir = args
        .minimal_dir
        .as_ref()
        .expect("setup points at a tempdir");

    // A VCS root so the headless upload gate passes, and a declared echo
    // task that exits on its own without reading stdin.
    let project = tempfile::TempDir::new().unwrap();
    std::fs::create_dir(project.path().join(".git")).unwrap();
    std::fs::write(
        project.path().join("minimal.toml"),
        "[tasks.e2e-echo]\necho = \"TASK_RUN_STDIN_OK\"\n",
    )
    .unwrap();

    let config_dir = tempfile::TempDir::new().unwrap();
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_min"))
        .args(["--minimal-dir".as_ref(), minimal_dir.as_os_str()])
        .args(["--config-dir".as_ref(), config_dir.path().as_os_str()])
        .arg("--no-input")
        .args(["-C".as_ref(), project.path().as_os_str()])
        .args(["task", "run", "e2e-echo"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("the min binary should be invocable");

    // Hold the write end open for the whole run: this is the pipe whose
    // writer "stays open" in the report. Dropping it would EOF the child's
    // stdin and mask the hang.
    let _held_stdin = child.stdin.take().expect("stdin is piped");

    let status = tokio::time::timeout(std::time::Duration::from_secs(30), child.wait())
        .await
        .expect("min task run must exit even though its stdin pipe stays open")
        .expect("waiting for min task run");

    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    tokio::io::AsyncReadExt::read_to_end(
        &mut child.stdout.take().expect("stdout is piped"),
        &mut stdout,
    )
    .await
    .unwrap();
    tokio::io::AsyncReadExt::read_to_end(
        &mut child.stderr.take().expect("stderr is piped"),
        &mut stderr,
    )
    .await
    .unwrap();

    assert!(
        status.success(),
        "task run must exit 0: stderr={}",
        String::from_utf8_lossy(&stderr)
    );
    assert!(
        String::from_utf8_lossy(&stdout).contains("TASK_RUN_STDIN_OK"),
        "task output must stream back: stdout={}",
        String::from_utf8_lossy(&stdout)
    );
}
