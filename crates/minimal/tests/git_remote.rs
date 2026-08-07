//! End-to-end test for the `git-remote-min` helper mode of the `min` binary.
//!
//! Drives a real `git push min://<session-id>` through the compiled `min`
//! binary symlinked as `git-remote-min` on PATH: git speaks the remote-helper
//! protocol to it over stdio, and the helper bridges the pack conversation to
//! a minimald `TestServer` listening on the UDS at the default (XDG-derived)
//! socket path.

use minimald::test_harness::{TestServer, create_configured_session};

async fn run_git(cwd: &std::path::Path, args: &[&str]) {
    let out = tokio::process::Command::new("git")
        .current_dir(cwd)
        .args(args)
        .output()
        .await
        .expect("git should be invocable");
    assert!(
        out.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr),
    );
}

#[tokio::test]
async fn git_push_through_min_binary_lands_commit_in_workspace() {
    // The helper resolves the daemon socket from the default state dir, so
    // point XDG_STATE_HOME at a tempdir and serve the UDS where
    // `resolve_socket_path(None)` will look.
    let state_home = tempfile::TempDir::new().unwrap();
    let sock_dir = state_home.path().join("minimal/providers/local-minimald0");
    std::fs::create_dir_all(&sock_dir).unwrap();

    let server = TestServer::new().await;
    server.listen_on_uds(&sock_dir.join("ssh.sock")).await;

    let mut client = server.connect().await;
    let session_id = create_configured_session(&mut client, "git-push-target", "/tmp").await;

    // Symlink the built `min` binary as `git-remote-min` so git's `min://`
    // scheme dispatch finds it via PATH — exercising the argv[0] detection.
    let helpers = tempfile::TempDir::new().unwrap();
    std::os::unix::fs::symlink(
        env!("CARGO_BIN_EXE_min"),
        helpers.path().join("git-remote-min"),
    )
    .unwrap();

    // Source repo with a single commit on `main`. Local user.email/user.name
    // keep the test independent of any global git config.
    let src_dir = tempfile::TempDir::new().unwrap();
    let src = src_dir.path();
    run_git(src, &["init", "-q", "-b", "main"]).await;
    run_git(src, &["config", "user.email", "t@example.com"]).await;
    run_git(src, &["config", "user.name", "Test"]).await;
    tokio::fs::write(src.join("hello.txt"), b"hi there\n")
        .await
        .unwrap();
    run_git(src, &["add", "hello.txt"]).await;
    run_git(src, &["commit", "-q", "-m", "first commit"]).await;

    let inherited_path = std::env::var("PATH").unwrap_or_default();
    let push = tokio::process::Command::new("git")
        .current_dir(src)
        .env(
            "PATH",
            format!("{}:{inherited_path}", helpers.path().display()),
        )
        .env("XDG_STATE_HOME", state_home.path())
        .args(["push", &format!("min://{session_id}"), "main"])
        .output()
        .await
        .expect("git push should run");
    assert!(
        push.status.success(),
        "git push failed: stdout={} stderr={}",
        String::from_utf8_lossy(&push.stdout),
        String::from_utf8_lossy(&push.stderr),
    );

    // The daemon's post-receive hook checks out the pushed branch into the
    // session worktree; read the file back over SFTP to prove it landed. The
    // worktree is spelled out because SFTP's relative paths resolve against
    // the session's home, not its workspace.
    let sftp = client.open_sftp(session_id).await;
    let contents = sftp.read("/workbench/hello.txt").await.unwrap();
    assert_eq!(contents, b"hi there\n");
}
