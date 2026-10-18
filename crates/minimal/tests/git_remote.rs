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

/// `git push <url> <refs>...` from `src`, with the `git-remote-min` helper
/// in `helpers` first on PATH and the daemon socket under `state_home`.
/// Returns the push's stderr, which carries the hook's `remote:` lines.
async fn push_refs(
    src: &std::path::Path,
    helpers: &std::path::Path,
    state_home: &std::path::Path,
    url: &str,
    refs: &[&str],
) -> String {
    let inherited_path = std::env::var("PATH").unwrap_or_default();
    let out = tokio::process::Command::new("git")
        .current_dir(src)
        .env("PATH", format!("{}:{inherited_path}", helpers.display()))
        .env("XDG_STATE_HOME", state_home)
        .arg("push")
        .arg(url)
        .args(refs)
        .output()
        .await
        .expect("git push should run");
    assert!(
        out.status.success(),
        "git push {refs:?} failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// The commit `rev` names in the repo at `cwd`.
async fn rev_parse(cwd: &std::path::Path, rev: &str) -> String {
    let out = tokio::process::Command::new("git")
        .current_dir(cwd)
        .args(["rev-parse", rev])
        .output()
        .await
        .expect("git rev-parse should run");
    assert!(out.status.success(), "git rev-parse {rev} failed");
    String::from_utf8(out.stdout).unwrap().trim().to_string()
}

#[tokio::test]
async fn git_push_of_other_branch_leaves_workspace_on_current_branch() {
    // Same harness shape as the push test above: TestServer on the default
    // socket path, helper symlinked on PATH.
    let state_home = tempfile::TempDir::new().unwrap();
    let sock_dir = state_home.path().join("minimal/providers/local-minimald0");
    std::fs::create_dir_all(&sock_dir).unwrap();

    let server = TestServer::new().await;
    server.listen_on_uds(&sock_dir.join("ssh.sock")).await;

    let mut client = server.connect().await;
    let session_id = create_configured_session(&mut client, "git-push-other-branch", "/tmp").await;

    let helpers = tempfile::TempDir::new().unwrap();
    std::os::unix::fs::symlink(
        env!("CARGO_BIN_EXE_min"),
        helpers.path().join("git-remote-min"),
    )
    .unwrap();

    // Source repo: `main` with one commit, then a `feature` branch with a
    // second commit on top.
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
    run_git(src, &["checkout", "-q", "-b", "feature"]).await;
    tokio::fs::write(src.join("feature.txt"), b"feature\n")
        .await
        .unwrap();
    run_git(src, &["add", "feature.txt"]).await;
    run_git(src, &["commit", "-q", "-m", "second commit"]).await;
    let feature_tip = rev_parse(src, "feature").await;

    let session_url = format!("min://{session_id}");
    for remote_ref in ["main", "feature"] {
        push_refs(
            src,
            helpers.path(),
            state_home.path(),
            &session_url,
            &[remote_ref],
        )
        .await;
    }

    // The pushes ran in order: the first populated the workspace with
    // `main` checked out; the second pushed `feature`, a branch that is
    // NOT the checked-out one. HEAD must stay on main ...

    let sftp = client.open_sftp(session_id).await;
    let head = sftp.read("/workbench/.git/HEAD").await.unwrap();
    assert_eq!(head, b"ref: refs/heads/main\n");
    // ... the worktree still shows main's files and not feature's ...
    let hello = sftp.read("/workbench/hello.txt").await.unwrap();
    assert_eq!(hello, b"hi there\n");
    assert!(sftp.read("/workbench/feature.txt").await.is_err());
    // ... and the feature ref landed at the pushed tip.
    let feature_ref = sftp
        .read("/workbench/.git/refs/heads/feature")
        .await
        .unwrap();
    assert_eq!(String::from_utf8_lossy(&feature_ref).trim(), feature_tip);
}

#[tokio::test]
async fn git_push_of_several_refs_syncs_only_the_current_branch() {
    // Same harness shape as the tests above.
    let state_home = tempfile::TempDir::new().unwrap();
    let sock_dir = state_home.path().join("minimal/providers/local-minimald0");
    std::fs::create_dir_all(&sock_dir).unwrap();

    let server = TestServer::new().await;
    server.listen_on_uds(&sock_dir.join("ssh.sock")).await;

    let mut client = server.connect().await;
    let session_id = create_configured_session(&mut client, "git-push-several-refs", "/tmp").await;

    let helpers = tempfile::TempDir::new().unwrap();
    std::os::unix::fs::symlink(
        env!("CARGO_BIN_EXE_min"),
        helpers.path().join("git-remote-min"),
    )
    .unwrap();
    let url = format!("min://{session_id}");

    // Populate the workspace with `main` checked out.
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
    push_refs(src, helpers.path(), state_home.path(), &url, &["main"]).await;

    // Advance `main`, and grow a new `feature` branch off the first commit.
    tokio::fs::write(src.join("main2.txt"), b"main two\n")
        .await
        .unwrap();
    run_git(src, &["add", "main2.txt"]).await;
    run_git(src, &["commit", "-q", "-m", "main second commit"]).await;
    run_git(src, &["checkout", "-q", "-b", "feature", "HEAD~1"]).await;
    tokio::fs::write(src.join("feature.txt"), b"feature\n")
        .await
        .unwrap();
    run_git(src, &["add", "feature.txt"]).await;
    run_git(src, &["commit", "-q", "-m", "feature commit"]).await;
    let feature_tip = rev_parse(src, "feature").await;

    // One push carrying both refs: the checked-out `main` syncs into the
    // worktree, while `feature` only moves its ref.
    push_refs(
        src,
        helpers.path(),
        state_home.path(),
        &url,
        &["main", "feature"],
    )
    .await;

    let sftp = client.open_sftp(session_id).await;
    let head = sftp.read("/workbench/.git/HEAD").await.unwrap();
    assert_eq!(head, b"ref: refs/heads/main\n");
    let main2 = sftp.read("/workbench/main2.txt").await.unwrap();
    assert_eq!(main2, b"main two\n");
    assert!(sftp.read("/workbench/feature.txt").await.is_err());
    let feature_ref = sftp
        .read("/workbench/.git/refs/heads/feature")
        .await
        .unwrap();
    assert_eq!(String::from_utf8_lossy(&feature_ref).trim(), feature_tip);
}

#[tokio::test]
async fn git_first_push_of_several_refs_checks_out_only_the_first() {
    // Same harness shape as the tests above.
    let state_home = tempfile::TempDir::new().unwrap();
    let sock_dir = state_home.path().join("minimal/providers/local-minimald0");
    std::fs::create_dir_all(&sock_dir).unwrap();

    let server = TestServer::new().await;
    server.listen_on_uds(&sock_dir.join("ssh.sock")).await;

    let mut client = server.connect().await;
    let session_id = create_configured_session(&mut client, "git-first-push-several", "/tmp").await;

    let helpers = tempfile::TempDir::new().unwrap();
    std::os::unix::fs::symlink(
        env!("CARGO_BIN_EXE_min"),
        helpers.path().join("git-remote-min"),
    )
    .unwrap();

    // Source repo: `main` with one commit, then `feature` one commit ahead.
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
    run_git(src, &["checkout", "-q", "-b", "feature"]).await;
    tokio::fs::write(src.join("feature.txt"), b"feature\n")
        .await
        .unwrap();
    run_git(src, &["add", "feature.txt"]).await;
    run_git(src, &["commit", "-q", "-m", "feature commit"]).await;
    let feature_tip = rev_parse(src, "feature").await;

    // The very first push into the fresh workspace carries both branches,
    // `main` first. The hook checks out `main` to populate the worktree;
    // `feature`, arriving second, only moves its ref.
    let url = format!("min://{session_id}");
    push_refs(
        src,
        helpers.path(),
        state_home.path(),
        &url,
        &["main", "feature"],
    )
    .await;

    let sftp = client.open_sftp(session_id).await;
    let head = sftp.read("/workbench/.git/HEAD").await.unwrap();
    assert_eq!(head, b"ref: refs/heads/main\n");
    let hello = sftp.read("/workbench/hello.txt").await.unwrap();
    assert_eq!(hello, b"hi there\n");
    assert!(sftp.read("/workbench/feature.txt").await.is_err());
    let feature_ref = sftp
        .read("/workbench/.git/refs/heads/feature")
        .await
        .unwrap();
    assert_eq!(String::from_utf8_lossy(&feature_ref).trim(), feature_tip);
}

#[tokio::test]
async fn git_push_into_detached_head_moves_ref_and_says_so() {
    // Same harness shape as the tests above.
    let state_home = tempfile::TempDir::new().unwrap();
    let sock_dir = state_home.path().join("minimal/providers/local-minimald0");
    std::fs::create_dir_all(&sock_dir).unwrap();

    let server = TestServer::new().await;
    server.listen_on_uds(&sock_dir.join("ssh.sock")).await;

    let mut client = server.connect().await;
    let session_id = create_configured_session(&mut client, "git-push-detached", "/tmp").await;

    let helpers = tempfile::TempDir::new().unwrap();
    std::os::unix::fs::symlink(
        env!("CARGO_BIN_EXE_min"),
        helpers.path().join("git-remote-min"),
    )
    .unwrap();
    let url = format!("min://{session_id}");

    // Populate the workspace with `main` checked out.
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
    let first = rev_parse(src, "main").await;
    push_refs(src, helpers.path(), state_home.path(), &url, &["main"]).await;

    // Detach the workspace HEAD at the first commit. The detached form is
    // longer than `ref: refs/heads/main\n`, so a plain write replaces it.
    let sftp = client.open_sftp(session_id).await;
    sftp.write("/workbench/.git/HEAD", format!("{first}\n").as_bytes())
        .await
        .unwrap();

    // Advance `main` and push it.
    tokio::fs::write(src.join("main2.txt"), b"main two\n")
        .await
        .unwrap();
    run_git(src, &["add", "main2.txt"]).await;
    run_git(src, &["commit", "-q", "-m", "main second commit"]).await;
    let main_tip = rev_parse(src, "main").await;
    let stderr = push_refs(src, helpers.path(), state_home.path(), &url, &["main"]).await;

    // The push says HEAD is detached ...
    assert!(
        stderr.contains("remote worktree HEAD is detached; moved refs without checking out"),
        "push stderr should note the detached HEAD: {stderr}",
    );
    // ... HEAD stays detached at the first commit and the worktree is
    // unchanged ...
    let head = sftp.read("/workbench/.git/HEAD").await.unwrap();
    assert_eq!(String::from_utf8_lossy(&head).trim(), first);
    assert!(sftp.read("/workbench/main2.txt").await.is_err());
    // ... and the main ref landed at the pushed tip.
    let main_ref = sftp.read("/workbench/.git/refs/heads/main").await.unwrap();
    assert_eq!(String::from_utf8_lossy(&main_ref).trim(), main_tip);
}
