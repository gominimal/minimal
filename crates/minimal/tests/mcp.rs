//! Integration test for `min mcp`: spawn the compiled binary over stdio or
//! streamable HTTP, initialize an MCP session, and drive the tools against a
//! test daemon.
//!
//! Speaks the JSON-RPC framing directly (one message per line over stdio; JSON
//! or SSE over HTTP) rather than pulling in an MCP client crate: the point is
//! to prove the binary's wire behaviour and its stdout hygiene, which a
//! byte-level driver checks most directly. Linux-only, like the other
//! `minimald`-backed tests.

#![cfg(target_os = "linux")]

mod common;

use std::process::Stdio;
use std::time::Duration;

use common::setup;
use serde_json_lenient::Value;
use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader};

/// The base `min mcp` invocation both transports share: the test daemon's
/// directory, a throwaway config dir, the workdir the default session uploads,
/// and no loadouts.
fn mcp_command(
    minimal_dir: &std::path::Path,
    config_dir: &std::path::Path,
    workdir: &std::path::Path,
) -> tokio::process::Command {
    let mut cmd = tokio::process::Command::new(env!("CARGO_BIN_EXE_min"));
    cmd.arg("--minimal-dir")
        .arg(minimal_dir)
        .arg("--config-dir")
        .arg(config_dir)
        .arg("--no-input")
        .arg("mcp")
        .arg("--workdir")
        .arg(workdir)
        // The test daemon serves no package registry, so the default loadout's
        // `base` package cannot be materialized; a loadout-free session still
        // provides a shell to exec in.
        .arg("--no-loadouts");
    cmd
}

/// A leaked tempdir for a child's `--config-dir`. The test process exits
/// shortly after the child, so keeping it for the child's lifetime is enough.
fn config_dir() -> std::path::PathBuf {
    tempfile::TempDir::new().unwrap().keep()
}

/// A spawned `min mcp` speaking MCP over stdio.
struct McpChild {
    child: tokio::process::Child,
    stdin: tokio::process::ChildStdin,
    stdout: BufReader<tokio::process::ChildStdout>,
    next_id: u64,
}

impl McpChild {
    async fn spawn(minimal_dir: &std::path::Path, workdir: &std::path::Path) -> Self {
        let mut child = mcp_command(minimal_dir, &config_dir(), workdir)
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

/// One reply from the streamable-HTTP endpoint.
struct HttpReply {
    status: reqwest::StatusCode,
    content_type: String,
    session_id: Option<String>,
    body: String,
}

/// A spawned `min mcp --transport http`.
struct McpHttpChild {
    child: tokio::process::Child,
    client: reqwest::Client,
    url: String,
    session_id: String,
    next_id: u64,
}

impl McpHttpChild {
    async fn spawn(minimal_dir: &std::path::Path, workdir: &std::path::Path) -> Self {
        let mut child = mcp_command(minimal_dir, &config_dir(), workdir)
            .arg("--transport")
            .arg("http")
            // Port 0: the OS picks a free port and the child announces it on
            // stderr, so the test never races another listener for a fixed one.
            .arg("--bind")
            .arg("127.0.0.1:0")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("the min binary should be invocable");

        // The address is only knowable from stderr (stdout is not a transport
        // here), so read until the announcement line, then stop reading.
        let stderr = child.stderr.take().unwrap();
        let url = tokio::time::timeout(Duration::from_secs(60), async move {
            let mut lines = BufReader::new(stderr).lines();
            while let Some(line) = lines.next_line().await.unwrap() {
                if let Some((_, rest)) = line.split_once("serving streamable HTTP at ") {
                    return rest.trim().to_string();
                }
            }
            panic!("min mcp exited before announcing its HTTP address");
        })
        .await
        .expect("min mcp should announce its HTTP address");

        Self {
            child,
            client: reqwest::Client::new(),
            url,
            session_id: String::new(),
            next_id: 1,
        }
    }

    /// Send a request and return its response message.
    async fn call(&mut self, method: &str, params: &str) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        let message: Value = serde_json_lenient::from_str(&format!(
            r#"{{"jsonrpc":"2.0","id":{id},"method":"{method}","params":{params}}}"#
        ))
        .unwrap();
        let reply = self.post(&message).await;
        assert!(
            reply.status.is_success(),
            "{method} failed with {}: {}",
            reply.status,
            reply.body
        );
        // initialize is the request that mints the session; every later
        // request must echo its id back.
        if reply.session_id.is_some() {
            self.session_id = reply.session_id.clone().unwrap();
        }
        response_for(&reply, id)
    }

    async fn notify(&mut self, method: &str, params: &str) {
        let message: Value = serde_json_lenient::from_str(&format!(
            r#"{{"jsonrpc":"2.0","method":"{method}","params":{params}}}"#
        ))
        .unwrap();
        let reply = self.post(&message).await;
        assert!(
            reply.status.is_success(),
            "{method} failed with {}: {}",
            reply.status,
            reply.body
        );
    }

    async fn post(&self, message: &Value) -> HttpReply {
        let mut req = self
            .client
            .post(&self.url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header(
                reqwest::header::ACCEPT,
                "application/json, text/event-stream",
            )
            .json(message);
        if !self.session_id.is_empty() {
            req = req.header("mcp-session-id", &self.session_id);
        }
        let resp = req.send().await.expect("HTTP request to min mcp");
        let status = resp.status();
        let content_type = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        let session_id = resp
            .headers()
            .get("mcp-session-id")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let body = resp.text().await.expect("HTTP response body");
        HttpReply {
            status,
            content_type,
            session_id,
            body,
        }
    }

    async fn shutdown(mut self) {
        let _ = self.child.kill().await;
    }
}

/// The JSON-RPC message for `id` out of an HTTP reply body. The streamable
/// transport answers with SSE, so scan its `data:` lines; a plain JSON body is
/// handled too, in case a future config switches to it.
fn response_for(reply: &HttpReply, id: u64) -> Value {
    let is_sse = reply.content_type.contains("text/event-stream");
    let candidates = if is_sse {
        reply
            .body
            .lines()
            .filter_map(|line| line.strip_prefix("data:").map(str::trim))
            .filter(|data| !data.is_empty())
            .collect::<Vec<_>>()
    } else {
        vec![reply.body.trim()]
    };
    candidates
        .iter()
        .filter_map(|candidate| serde_json_lenient::from_str::<Value>(candidate).ok())
        .find(|message| message.get("id").and_then(Value::as_u64) == Some(id))
        .unwrap_or_else(|| panic!("no reply with id {id} in body: {:?}", reply.body))
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

#[tokio::test]
async fn mcp_serves_over_streamable_http() {
    let (_daemon, args) = setup().await;
    let project = tempfile::TempDir::new().unwrap();
    let mut mcp = McpHttpChild::spawn(args.minimal_dir.as_deref().unwrap(), project.path()).await;

    let init = mcp
        .call(
            "initialize",
            r#"{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"0"}}"#,
        )
        .await;
    assert_eq!(init["result"]["serverInfo"]["name"], "minimal");
    assert!(
        !mcp.session_id.is_empty(),
        "initialize over HTTP must establish a session"
    );

    mcp.notify("notifications/initialized", "{}").await;

    // A tool call proves the HTTP transport drives the same server as stdio,
    // not just the handshake.
    let tools = mcp.call("tools/list", "{}").await;
    let names: Vec<&str> = tools["result"]["tools"]
        .as_array()
        .expect("tools list")
        .iter()
        .filter_map(|t| t["name"].as_str())
        .collect();
    for expected in ["create_session", "exec", "read_file"] {
        assert!(
            names.contains(&expected),
            "missing tool {expected}: {names:?}"
        );
    }

    mcp.shutdown().await;
}
