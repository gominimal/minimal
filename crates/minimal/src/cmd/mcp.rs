//! `min mcp` — a Model Context Protocol server over the minimal session plane.
//!
//! Speaks MCP over stdio and exposes the session infrastructure as a
//! shell-execution surface for an agent harness. Each tool delegates to the
//! existing client layer: session creation goes through the shared activation
//! core, exec through [`minimal_client::Client::exec_collect`], and file I/O
//! through SFTP.
//!
//! ## The usage contract
//!
//! A session is a fully isolated sandbox. Creating one uploads a named working
//! directory into it; the uploaded tree lands in `/workbench`. The first
//! `exec`/file call without a `session_id` lazily creates a *default* session
//! from `--workdir` and reuses it, while sessions created explicitly are
//! independent. Sessions persist until destroyed. [`McpServer::instructions`]
//! states this to the model at initialize time; each tool repeats the
//! essentials.
//!
//! ## stdout is the protocol
//!
//! The JSON-RPC channel is stdout. Logging is routed to stderr
//! (`stdout_is_data_contract` in `main.rs`), and the activation core's uploads
//! are quiet — nothing here may print to stdout except the transport.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use rmcp::{
    ErrorData as McpError, ServerHandler, ServiceExt,
    handler::server::wrapper::Parameters,
    model::{CallToolResult, ContentBlock},
    serde_json::{self, Value, json},
    tool, tool_handler, tool_router,
    transport::stdio,
};
use schemars::JsonSchema;
use serde::Deserialize;

use crate::GlobalArgs;
use crate::{CliNetworkMode, McpArgs, parse_network_mode};
use sessions::SessionId;

/// The MCP `instructions` field: the contract a model needs before it uses any
/// tool. Static so the wording is one thing, asserted by a test.
pub const INSTRUCTIONS: &str = "\
Every session is a fully isolated sandbox: it has its own filesystem, its own \
process tree, and none of your host's state. Creating a session uploads the \
named working directory into it, and that tree lands at /workbench inside the \
sandbox. The first exec or file call that omits a session_id creates a default \
session from the server's --workdir and reuses it for later calls; sessions \
you create explicitly with create_session are independent of each other and of \
the default. Sessions persist until you destroy them, so create one per unit of \
work and destroy it when you are done. Use list_loadouts to see the available \
environments before choosing one for create_session.";

/// The server's fixed per-invocation options, from `McpArgs` plus the global
/// flags. Cloned into every request.
struct McpOptions {
    workdir: Option<PathBuf>,
    network: CliNetworkMode,
    loadout: Vec<String>,
    no_loadouts: bool,
    no_hooks: bool,
    timeout: Duration,
}

/// Shared server state. The daemon connection is opened per request (a local
/// UDS handshake is cheap); only the lazily-created default session id has to
/// outlive a call.
struct McpState {
    global: GlobalArgs,
    opts: McpOptions,
    default_session: tokio::sync::Mutex<Option<SessionId>>,
}

/// The MCP server. `Clone` because `rmcp` clones it per request; the state
/// behind the `Arc` is shared.
#[derive(Clone)]
pub struct McpServer {
    state: Arc<McpState>,
}

impl McpServer {
    fn new(global: GlobalArgs, args: McpArgs) -> Self {
        Self {
            state: Arc::new(McpState {
                global,
                opts: McpOptions {
                    workdir: args.workdir,
                    network: args.network,
                    loadout: args.loadout,
                    no_loadouts: args.no_loadouts,
                    no_hooks: args.no_hooks,
                    timeout: Duration::from_secs(args.timeout),
                },
                default_session: tokio::sync::Mutex::new(None),
            }),
        }
    }

    /// Run the stdio server until the client disconnects.
    pub async fn serve_stdio(global: GlobalArgs, args: McpArgs) -> Result<(), anyhow::Error> {
        let service = McpServer::new(global, args).serve(stdio()).await?;
        service.waiting().await?;
        Ok(())
    }

    /// Start the daemon if needed and open a fresh authenticated connection.
    ///
    /// Goes through `connect_daemon`, so every tool call is version-gated —
    /// these paths mutate daemon state and must not run against a skewed pair.
    async fn connect(&self) -> Result<minimal_client::Client, anyhow::Error> {
        crate::ensure_daemon(&self.state.global)?;
        crate::connect_daemon(&self.state.global).await
    }

    /// Resolve the session a tool should act on: the named one when given, or
    /// the default — lazily created from `--workdir` on first use.
    async fn session_for(
        &self,
        client: &mut minimal_client::Client,
        requested: Option<&str>,
    ) -> Result<SessionId, anyhow::Error> {
        if let Some(name) = requested {
            return Ok(crate::resolve_session_version_gated(client, name).await?.id);
        }
        let mut default = self.state.default_session.lock().await;
        if let Some(id) = *default {
            return Ok(id);
        }
        let activated = self.create(None, None).await?;
        *default = Some(activated.id);
        Ok(activated.id)
    }

    /// Create a session through the shared activation core, headless: the
    /// gate refuses a `Pending` composition (the server has no prompt) and
    /// aborts the draft.
    async fn create(
        &self,
        working_dir: Option<PathBuf>,
        name: Option<String>,
    ) -> Result<crate::cmd::session::ActivatedSession, anyhow::Error> {
        let path = working_dir
            .or_else(|| self.state.opts.workdir.clone())
            // With neither, the CLI's own default (the cwd) applies.
            .map(|p| p.to_string_lossy().into_owned());
        let args = crate::ActivateArgs {
            name,
            path,
            sync: None,
            network: self.state.opts.network,
            ingress: Vec::new(),
            allow_subnets: Vec::new(),
            allow_dns_hosts: Vec::new(),
            allow_protocols: Vec::new(),
            deny_subnets: Vec::new(),
            loadout: self.state.opts.loadout.clone(),
            no_loadouts: self.state.opts.no_loadouts,
            no_hooks: self.state.opts.no_hooks,
            // The server can't prompt: a `Pending` composition refuses with the
            // `user_policy.toml` snippet rather than hanging on a terminal.
            no_prompt: true,
            attach: false,
        };
        crate::cmd::session::create_headless_session(&self.state.global, args, false).await
    }

    /// Render one session's summary as JSON.
    fn session_json(entry: &minimald_rpc::ListSessionsEntry) -> Value {
        json!({
            "id": entry.id.to_string(),
            "name": entry.name,
            "project": entry.project_path.as_ref().map(|p| p.as_utf8_path().to_string()),
            "state": format!("{:?}", entry.status).to_lowercase(),
        })
    }
}

/// Wrap a JSON value as a tool's successful text result.
fn json_result(value: &Value) -> CallToolResult {
    let text = serde_json::to_string_pretty(value).unwrap_or_else(|_| value.to_string());
    CallToolResult::success(vec![ContentBlock::text(text)])
}

/// A tool-level failure the model should see (the daemon refused, a file was
/// missing). The message is the diagnostic.
fn tool_error(message: impl Into<String>) -> CallToolResult {
    CallToolResult::error(vec![ContentBlock::text(message.into())])
}

/// Quote one argv element for `/bin/sh`.
fn shell_quote(arg: &str) -> String {
    let safe = !arg.is_empty()
        && arg
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._/@%+:,=".contains(&b));
    if safe {
        arg.to_string()
    } else {
        format!("'{}'", arg.replace('\'', "'\\''"))
    }
}

// ── Tool parameters ─────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, JsonSchema)]
struct ListLoadoutsParams {}

#[derive(Debug, Deserialize, JsonSchema)]
struct CreateSessionParams {
    /// Directory whose tree is uploaded into the new sandbox and becomes its
    /// /workbench. Defaults to the server's --workdir.
    #[serde(default)]
    working_dir: Option<PathBuf>,
    /// Optional typable session name.
    #[serde(default)]
    name: Option<String>,
    /// Loadout environments to apply (see list_loadouts). Empty means the
    /// server's configured loadouts.
    #[serde(default)]
    loadouts: Vec<String>,
    /// Network mode for the sandbox: `none`, `host_ip` (default), or `own_ip`.
    #[serde(default)]
    network: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct ExecParams {
    /// Session to run in. Omitted, the default session (created on demand).
    #[serde(default)]
    session_id: Option<String>,
    /// Shell command to run. Mutually exclusive with `argv`.
    #[serde(default)]
    command: Option<String>,
    /// Program and arguments, run without a shell. Mutually exclusive with
    /// `command`.
    #[serde(default)]
    argv: Option<Vec<String>>,
    /// Bytes written to the command's stdin, then EOF. Omitted, an immediate
    /// EOF.
    #[serde(default)]
    stdin: Option<String>,
    /// Seconds to allow. Defaults to the server's `--timeout`.
    #[serde(default)]
    timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct ReadFileParams {
    #[serde(default)]
    session_id: Option<String>,
    /// Path inside the sandbox, resolved at the session home (/workbench holds
    /// the uploaded tree).
    path: String,
    /// Byte offset to start at.
    #[serde(default)]
    offset: Option<u64>,
    /// Maximum bytes to return.
    #[serde(default)]
    limit: Option<u64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct WriteFileParams {
    #[serde(default)]
    session_id: Option<String>,
    /// Path inside the sandbox, resolved at the session home.
    path: String,
    content: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct DestroySessionParams {
    session_id: String,
}

// ── Tools ───────────────────────────────────────────────────────────────────

#[tool_router]
impl McpServer {
    /// List the loadout environments available for `create_session`.
    #[tool(description = "List the environments a session can be created with. \
                       Each entry has a name (pass it to create_session's \
                       loadouts), a description, and the packages, variables, \
                       and file patches it contributes.")]
    async fn list_loadouts(
        &self,
        Parameters(_): Parameters<ListLoadoutsParams>,
    ) -> Result<CallToolResult, McpError> {
        let defaults: std::collections::HashSet<String> =
            match crate::config::read_client_config(&self.state.global) {
                Ok(cfg) => cfg.loadouts.default_loadouts.into_iter().collect(),
                Err(e) => return Ok(tool_error(format!("reading client config failed: {e}"))),
            };
        let dir = crate::loadouts::default_loadouts_dir(&self.state.global);
        let listing = match crate::loadouts::loadout_listing(&dir, &defaults) {
            Ok(l) => l,
            Err(e) => return Ok(tool_error(format!("listing loadouts failed: {e}"))),
        };
        let rows: Vec<Value> = listing
            .summaries
            .iter()
            .map(|s| {
                json!({
                    "name": s.name,
                    "description": s.description,
                    "packages": s.packages,
                    "vars": s.vars,
                    "patches": s.patches,
                    "builtin": s.builtin,
                    "default": s.is_default,
                })
            })
            .collect();
        Ok(json_result(&Value::Array(rows)))
    }

    /// Create an isolated sandbox, uploading the named directory into it.
    #[tool(description = "Create a new isolated sandbox and upload a working \
                       directory into it. Returns the session id, its name, \
                       and the workspace path (/workbench). The sandbox \
                       persists until destroy_session; it is independent of \
                       the default session.")]
    async fn create_session(
        &self,
        Parameters(p): Parameters<CreateSessionParams>,
    ) -> Result<CallToolResult, McpError> {
        let network = match p.network.as_deref() {
            Some(raw) => match parse_network_mode(raw) {
                Ok(mode) => mode,
                Err(e) => return Ok(tool_error(format!("invalid network: {e}"))),
            },
            None => self.state.opts.network,
        };
        // A per-call network override becomes the server's network for the
        // activation carried out here.
        let session = if network == self.state.opts.network && p.loadouts.is_empty() {
            self.create(p.working_dir.clone(), p.name.clone()).await
        } else {
            let args = crate::ActivateArgs {
                name: p.name.clone(),
                path: p
                    .working_dir
                    .clone()
                    .or_else(|| self.state.opts.workdir.clone())
                    .map(|p| p.to_string_lossy().into_owned()),
                sync: None,
                network,
                ingress: Vec::new(),
                allow_subnets: Vec::new(),
                allow_dns_hosts: Vec::new(),
                allow_protocols: Vec::new(),
                deny_subnets: Vec::new(),
                loadout: if p.loadouts.is_empty() {
                    self.state.opts.loadout.clone()
                } else {
                    p.loadouts.clone()
                },
                no_loadouts: self.state.opts.no_loadouts,
                no_hooks: self.state.opts.no_hooks,
                no_prompt: true,
                attach: false,
            };
            crate::cmd::session::create_headless_session(&self.state.global, args, false).await
        };
        let session = match session {
            Ok(s) => s,
            Err(e) => return Ok(tool_error(format!("{e:#}"))),
        };
        Ok(json_result(&json!({
            "session_id": session.id.to_string(),
            "name": session.name,
            "workspace": "/workbench",
        })))
    }

    /// Run a command in a sandbox and collect its output.
    #[tool(description = "Run a shell command (or an argv program) inside a \
                       sandbox and return its stdout, stderr, and exit code. \
                       There is no PTY: commands run non-interactively, and \
                       stdin is sent once then closed. Omit session_id to use \
                       the default session.")]
    async fn exec(
        &self,
        Parameters(p): Parameters<ExecParams>,
    ) -> Result<CallToolResult, McpError> {
        let command = match (p.command.as_deref(), p.argv.as_deref()) {
            (Some(_), Some(_)) => {
                return Err(McpError::invalid_params(
                    "pass either `command` or `argv`, not both",
                    None,
                ));
            }
            (Some(c), None) => c.to_string(),
            (None, Some(argv)) if !argv.is_empty() => argv
                .iter()
                .map(|a| shell_quote(a))
                .collect::<Vec<_>>()
                .join(" "),
            (None, _) => {
                return Err(McpError::invalid_params(
                    "one of `command` or `argv` is required",
                    None,
                ));
            }
        };

        let mut client = match self.connect().await {
            Ok(c) => c,
            Err(e) => {
                return Ok(tool_error(format!(
                    "connecting to the daemon failed: {e:#}"
                )));
            }
        };
        let id = match self.session_for(&mut client, p.session_id.as_deref()).await {
            Ok(id) => id,
            Err(e) => return Ok(tool_error(format!("{e:#}"))),
        };
        let timeout = p
            .timeout_secs
            .map(Duration::from_secs)
            .unwrap_or(self.state.opts.timeout);
        let output = match client
            .exec_collect(
                id,
                &command,
                p.stdin.as_deref().map(str::as_bytes),
                Some(timeout),
            )
            .await
        {
            Ok(o) => o,
            Err(e) => return Ok(tool_error(format!("exec failed: {e:#}"))),
        };
        Ok(json_result(&json!({
            "stdout": String::from_utf8_lossy(&output.stdout),
            "stderr": String::from_utf8_lossy(&output.stderr),
            "exit_code": output.exit_code,
        })))
    }

    /// Read a file inside a sandbox.
    #[tool(description = "Read a file inside a sandbox. Paths resolve at the \
                       session home; the uploaded working tree is at \
                       /workbench. Omit session_id to use the default session.")]
    async fn read_file(
        &self,
        Parameters(p): Parameters<ReadFileParams>,
    ) -> Result<CallToolResult, McpError> {
        let mut client = match self.connect().await {
            Ok(c) => c,
            Err(e) => {
                return Ok(tool_error(format!(
                    "connecting to the daemon failed: {e:#}"
                )));
            }
        };
        let id = match self.session_for(&mut client, p.session_id.as_deref()).await {
            Ok(id) => id,
            Err(e) => return Ok(tool_error(format!("{e:#}"))),
        };
        let sftp = match client.open_sftp(id).await {
            Ok(s) => s,
            Err(e) => return Ok(tool_error(format!("opening SFTP failed: {e:#}"))),
        };
        let bytes = match sftp.read(&p.path).await {
            Ok(b) => b,
            Err(e) => return Ok(tool_error(format!("reading {}: {e}", p.path))),
        };
        let offset = usize::try_from(p.offset.unwrap_or(0)).unwrap_or(usize::MAX);
        let start = offset.min(bytes.len());
        let end = match p.limit {
            Some(limit) => start
                .saturating_add(usize::try_from(limit).unwrap_or(usize::MAX))
                .min(bytes.len()),
            None => bytes.len(),
        };
        let slice = &bytes[start..end];
        Ok(json_result(&json!({
            "content": String::from_utf8_lossy(slice),
            "offset": start,
            "bytes_read": slice.len(),
            "eof": end >= bytes.len(),
        })))
    }

    /// Write a file inside a sandbox.
    #[tool(description = "Write a file inside a sandbox, replacing it if it \
                       exists. Paths resolve at the session home; the uploaded \
                       working tree is at /workbench. Omit session_id to use \
                       the default session.")]
    async fn write_file(
        &self,
        Parameters(p): Parameters<WriteFileParams>,
    ) -> Result<CallToolResult, McpError> {
        let mut client = match self.connect().await {
            Ok(c) => c,
            Err(e) => {
                return Ok(tool_error(format!(
                    "connecting to the daemon failed: {e:#}"
                )));
            }
        };
        let id = match self.session_for(&mut client, p.session_id.as_deref()).await {
            Ok(id) => id,
            Err(e) => return Ok(tool_error(format!("{e:#}"))),
        };
        let sftp = match client.open_sftp(id).await {
            Ok(s) => s,
            Err(e) => return Ok(tool_error(format!("opening SFTP failed: {e:#}"))),
        };
        let written = p.content.len();
        if let Err(e) = sftp.write(&p.path, p.content.as_bytes()).await {
            return Ok(tool_error(format!("writing {}: {e}", p.path)));
        }
        Ok(json_result(
            &json!({ "path": p.path, "bytes_written": written }),
        ))
    }

    /// List the sessions this daemon is hosting.
    #[tool(description = "List the sessions on this daemon: id, name, project \
                       directory, and state. Sessions created by this server \
                       and unrelated ones both appear.")]
    async fn list_sessions(
        &self,
        Parameters(_): Parameters<ListLoadoutsParams>,
    ) -> Result<CallToolResult, McpError> {
        let mut client = match self.connect().await {
            Ok(c) => c,
            Err(e) => {
                return Ok(tool_error(format!(
                    "connecting to the daemon failed: {e:#}"
                )));
            }
        };
        match crate::list_sessions_version_gated(&mut client).await {
            Ok(resp) => Ok(json_result(&json!({
                "sessions": resp.sessions.iter().map(McpServer::session_json).collect::<Vec<_>>(),
            }))),
            Err(e) => Ok(tool_error(format!("listing sessions failed: {e:#}"))),
        }
    }

    /// Destroy a session and everything in it.
    #[tool(description = "Destroy a session, discarding its sandbox and every \
                       file in it. Irreversible.")]
    async fn destroy_session(
        &self,
        Parameters(p): Parameters<DestroySessionParams>,
    ) -> Result<CallToolResult, McpError> {
        let mut client = match self.connect().await {
            Ok(c) => c,
            Err(e) => {
                return Ok(tool_error(format!(
                    "connecting to the daemon failed: {e:#}"
                )));
            }
        };
        let id = match crate::resolve_session_version_gated(&mut client, &p.session_id).await {
            Ok(record) => record.id,
            Err(e) => return Ok(tool_error(format!("{e:#}"))),
        };
        let mut default = self.state.default_session.lock().await;
        if *default == Some(id) {
            *default = None;
        }
        drop(default);
        match client
            .oneshot_rpc::<minimald_rpc::DestroySession>(minimald_rpc::DestroySessionRequest { id })
            .await
        {
            Ok(minimald_rpc::Errorable::Ok(_)) => {
                Ok(json_result(&json!({ "destroyed": p.session_id })))
            }
            Ok(minimald_rpc::Errorable::Err { error }) => Ok(tool_error(error)),
            Err(e) => Ok(tool_error(format!("{e:#}"))),
        }
    }
}

#[tool_handler]
impl ServerHandler for McpServer {
    /// The macro skips generating `get_info` when the impl supplies one; this
    /// is where the server's name, version, and model-facing instructions
    /// come from.
    fn get_info(&self) -> rmcp::model::ServerConfig {
        rmcp::model::ServerConfig::new(
            rmcp::model::ServerCapabilities::builder()
                .enable_tools()
                .build(),
        )
        .with_server_info(rmcp::model::Implementation::new(
            "minimal",
            env!("CARGO_PKG_VERSION"),
        ))
        .with_instructions(INSTRUCTIONS)
    }
}

/// Entry point for `min mcp`.
pub async fn cmd_mcp(global: &GlobalArgs, args: McpArgs) -> Result<(), anyhow::Error> {
    McpServer::serve_stdio(global.clone(), args).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shell_quotes_only_what_needs_it() {
        assert_eq!(shell_quote("ls"), "ls");
        assert_eq!(shell_quote("-la"), "-la");
        assert_eq!(shell_quote("a b"), "'a b'");
        assert_eq!(shell_quote("it's"), "'it'\\''s'");
        assert_eq!(shell_quote(""), "''");
        assert_eq!(shell_quote("$(rm -rf /)"), "'$(rm -rf /)'");
    }

    #[test]
    fn instructions_state_the_contract() {
        for needle in [
            "isolated",
            "/workbench",
            "session_id",
            "destroy",
            "list_loadouts",
        ] {
            assert!(
                INSTRUCTIONS.contains(needle),
                "instructions must mention {needle}: {INSTRUCTIONS}"
            );
        }
    }

    #[test]
    fn exec_params_reject_command_and_argv_together() {
        let params: ExecParams =
            serde_json::from_value(json!({ "command": "ls", "argv": ["ls"] })).unwrap();
        assert!(params.command.is_some() && params.argv.is_some());
    }
}
