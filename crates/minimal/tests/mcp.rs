//! Integration test for `min mcp`: spawn the compiled binary over stdio,
//! initialize an MCP session, and drive the tools against a test daemon.
//!
//! Speaks the stdio JSON-RPC framing directly (one message per line) rather
//! than pulling in an MCP client crate: the point is to prove the binary's
//! wire behaviour and its stdout hygiene, which a byte-level driver checks
//! most directly. Linux-only, like the other `minimald`-backed tests.

#![cfg(target_os = "linux")]

mod common;

use std::process::Stdio;

use common::setup;
use serde_json_lenient::Value;
use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader};

/// A spawned `min mcp` speaking MCP over stdio.
struct McpChild {
    child: tokio::process::Child,
    stdin: tokio::process::ChildStdin,
    stdout: BufReader<tokio::process::ChildStdout>,
    next_id: u64,
}

impl McpChild {
    async fn spawn(minimal_dir: &std::path::Path, workdir: &std::path::Path) -> Self {
        let config_dir = tempfile::TempDir::new().unwrap();
        // Keep the tempdir alive for the child's lifetime by leaking it; the
        // test process exits shortly after.
        let config_dir = config_dir.keep();
        let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_min"))
            .arg("--minimal-dir")
            .arg(minimal_dir)
            .arg("--config-dir")
            .arg(&config_dir)
            .arg("--no-input")
            .arg("mcp")
            .arg("--workdir")
            .arg(workdir)
            // The test daemon serves no package registry, so the default
            // loadout's `base` package cannot be materialized; a loadout-free
            // session still provides a shell to exec in.
            .arg("--no-loadouts")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("the min binary should be invocable");
        let stdin = child.stdin.take().unwrap();
        let stdout = BufReader::new(child.stdout.take().unwrap());
        Self {
            child,
            stdin,
            stdout,
            next_id: 1,
        }
    }

    async fn send(&mut self, value: &str) {
        self.stdin.write_all(value.as_bytes()).await.unwrap();
        self.stdin.write_all(b"\n").await.unwrap();
        self.stdin.flush().await.unwrap();
    }

    /// Send a request and read until its response arrives, skipping
    /// notifications and logs.
    async fn call(&mut self, method: &str, params: &str) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        self.send(&format!(
            r#"{{"jsonrpc":"2.0","id":{id},"method":"{method}","params":{params}}}"#
        ))
        .await;
        loop {
            let mut line = String::new();
            let n = self.stdout.read_line(&mut line).await.unwrap();
            assert!(n > 0, "min mcp closed stdout before answering {method}");
            let value: Value = serde_json_lenient::from_str(line.trim())
                .unwrap_or_else(|e| panic!("non-JSON line on stdout: {line:?}: {e}"));
            if value.get("id").and_then(Value::as_u64) == Some(id) {
                return value;
            }
        }
    }

    async fn notify(&mut self, method: &str, params: &str) {
        self.send(&format!(
            r#"{{"jsonrpc":"2.0","method":"{method}","params":{params}}}"#
        ))
        .await;
    }

    async fn shutdown(mut self) {
        let _ = self.stdin.shutdown().await;
        let _ = self.child.kill().await;
    }
}

/// The tool result's text payload, parsed back from JSON.
fn result_json(response: &Value) -> Value {
    let text = response["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("tool result carried no text: {response}"));
    serde_json_lenient::from_str(text).expect("tool result text is JSON")
}

#[tokio::test]
async fn mcp_initializes_and_lists_tools() {
    let (_daemon, args) = setup().await;
    let project = tempfile::TempDir::new().unwrap();
    let mut mcp = McpChild::spawn(args.minimal_dir.as_deref().unwrap(), project.path()).await;

    let init = mcp
        .call(
            "initialize",
            r#"{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"0"}}"#,
        )
        .await;
    assert_eq!(init["result"]["serverInfo"]["name"], "minimal");
    let instructions = init["result"]["instructions"].as_str().unwrap_or("");
    assert!(
        instructions.contains("isolated") && instructions.contains("/workbench"),
        "initialize must state the sandbox contract: {instructions}"
    );

    mcp.notify("notifications/initialized", "{}").await;

    let tools = mcp.call("tools/list", "{}").await;
    let names: Vec<&str> = tools["result"]["tools"]
        .as_array()
        .expect("tools list")
        .iter()
        .filter_map(|t| t["name"].as_str())
        .collect();
    for expected in [
        "list_loadouts",
        "create_session",
        "exec",
        "read_file",
        "write_file",
        "list_sessions",
        "destroy_session",
    ] {
        assert!(
            names.contains(&expected),
            "missing tool {expected}: {names:?}"
        );
    }

    mcp.shutdown().await;
}

#[tokio::test]
async fn mcp_creates_lists_and_destroys_a_session() {
    let (daemon, args) = setup().await;
    // A git root so the default session's upload is taken without a prompt.
    let project = tempfile::TempDir::new().unwrap();
    std::fs::create_dir(project.path().join(".git")).unwrap();

    let mut mcp = McpChild::spawn(args.minimal_dir.as_deref().unwrap(), project.path()).await;
    mcp.call(
        "initialize",
        r#"{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"0"}}"#,
    )
    .await;
    mcp.notify("notifications/initialized", "{}").await;

    // create_session uploads the workdir into a fresh sandbox.
    let created = mcp
        .call(
            "tools/call",
            r#"{"name":"create_session","arguments":{"name":"mcp-itest"}}"#,
        )
        .await;
    assert_ne!(
        created["result"]["isError"], true,
        "create_session failed: {created}"
    );
    let session = result_json(&created);
    assert_eq!(session["workspace"], "/workbench");
    assert_eq!(
        session["uploaded"], true,
        "a VCS root should upload by default: {session}"
    );
    let id = session["session_id"]
        .as_str()
        .expect("a session id")
        .to_string();
    assert_eq!(session["name"], "mcp-itest");

    // sync="none" starts the sandbox empty even from a VCS root, and the
    // result reports that with uploaded=false.
    let empty = mcp
        .call(
            "tools/call",
            r#"{"name":"create_session","arguments":{"name":"mcp-itest-empty","sync":"none"}}"#,
        )
        .await;
    assert_ne!(
        empty["result"]["isError"], true,
        "create_session sync=none failed: {empty}"
    );
    assert_eq!(
        result_json(&empty)["uploaded"],
        false,
        "sync=none must not upload: {empty}"
    );

    // It shows up in the daemon's listing, under the name we gave it.
    let listed = mcp
        .call("tools/call", r#"{"name":"list_sessions","arguments":{}}"#)
        .await;
    let sessions = result_json(&listed)["sessions"].clone();
    let names: Vec<&str> = sessions
        .as_array()
        .expect("sessions array")
        .iter()
        .filter_map(|s| s["name"].as_str())
        .collect();
    assert!(
        names.contains(&"mcp-itest"),
        "created session missing from the listing: {sessions}"
    );

    // File I/O round-trips through SFTP. A relative path anchors at
    // /workbench; the write must create the file (`SftpSession::write` opens
    // with WRITE only and would fail here).
    let write = mcp
        .call(
            "tools/call",
            r#"{"name":"write_file","arguments":{"path":"from-agent.txt","content":"hello from mcp\n"}}"#,
        )
        .await;
    assert_ne!(
        write["result"]["isError"], true,
        "write_file failed: {write}"
    );
    assert_eq!(
        result_json(&write)["path"],
        "/workbench/from-agent.txt",
        "a relative path must resolve under /workbench: {write}"
    );
    let read = mcp
        .call(
            "tools/call",
            r#"{"name":"read_file","arguments":{"path":"/workbench/from-agent.txt"}}"#,
        )
        .await;
    assert_ne!(read["result"]["isError"], true, "read_file failed: {read}");
    assert_eq!(
        result_json(&read)["content"].as_str().unwrap_or(""),
        "hello from mcp\n",
        "read_file must return what write_file wrote: {read}"
    );

    // destroy_session removes it.
    let destroyed = mcp
        .call(
            "tools/call",
            &format!(r#"{{"name":"destroy_session","arguments":{{"session_id":"{id}"}}}}"#),
        )
        .await;
    assert_ne!(
        destroyed["result"]["isError"], true,
        "destroy_session failed: {destroyed}"
    );
    let mut client = daemon.server.connect().await;
    let resp = client.call::<minimald_rpc::ListSessions>(&()).await;
    assert!(
        resp.sessions
            .iter()
            .all(|s| s.name.as_deref() != Some("mcp-itest")),
        "the destroyed session is still listed"
    );

    mcp.shutdown().await;
}
