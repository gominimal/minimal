//! The minimal CLI which pairs/talks-with minimald.

use clap::{Args, CommandFactory, Parser, Subcommand};
use clap_complete::Shell;
use std::os::unix::process::CommandExt as _;
use std::path::PathBuf;
use tokio::io::AsyncWriteExt as _;
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

mod autospawn;
mod client;

#[derive(Parser)]
#[command(name = "minimal", version = env!("CARGO_PKG_VERSION"), long_version = env!("LONG_VERSION"))]
#[command(about = "The Minimal CLI")]
struct Cli {
    #[command(subcommand)]
    command: Command,

    #[command(flatten)]
    global_args: GlobalArgs,
}

#[derive(Subcommand)]
enum Command {
    /// List sessions
    Ls(LsArgs),
    /// Activate (create) a new session
    Activate(ActivateArgs),
    /// Attach to an existing session
    Attach(AttachArgs),
    /// Destroy (terminate) a session
    Destroy(DestroyArgs),
    /// Session inspection subcommands
    Session(SessionArgs),
    /// Proxy stdio to a daemon UDS socket (used as an SSH ProxyCommand).
    #[command(hide = true)]
    Proxy(ProxyArgs),
    /// Generate shell completion script
    #[command(
        long_about = "Generate a shell tab-completion script for the minimal CLI.\nSupported shells include bash, zsh, elvish and fish.\n\n   source <(minimal completions bash)"
    )]
    Completions(CompletionsArgs),
}

#[derive(Debug, Args)]
struct SessionArgs {
    #[command(subcommand)]
    command: SessionCommand,
}

#[derive(Debug, Subcommand)]
enum SessionCommand {
    /// Print the effective networking policy for a session as JSON
    Policy(PolicyArgs),
}

#[derive(Debug, Args)]
struct PolicyArgs {
    /// Session identifier (UUID or session name)
    session: String,
}

/// Shared arguments all subcommands
#[derive(Debug, Args)]
pub struct GlobalArgs {
    /// Override the base directory used for operations (default: ~/.cache/minimal)
    #[arg(long)]
    minimal_dir: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct ActivateArgs {
    /// Optional session name
    #[arg(long, short)]
    name: Option<String>,
    /// Project path to activate (defaults to current directory)
    #[arg(default_value = ".")]
    path: String,
    /// Automatically attach after creation
    #[arg(long)]
    attach: bool,
}

#[derive(Debug, Args)]
struct AttachArgs {
    /// Session identifier (UUID or session name)
    session: String,
    /// Command to exec in the session context (non-interactive)
    #[arg(long, short)]
    command: Option<String>,
}

#[derive(Debug, Args)]
struct LsArgs {
    /// Output raw session IDs (one per line) for piping into scripts
    #[arg(long)]
    raw: bool,
}

#[derive(Debug, Args)]
struct DestroyArgs {
    /// Session identifier (UUID or session name)
    session: String,
}

#[derive(Debug, Args)]
struct ProxyArgs {
    /// UDS socket path to connect to
    #[arg(long)]
    socket: String,
}

#[derive(Debug, clap::Args)]
struct CompletionsArgs {
    /// The shell type for a CLI completion script should be printed
    #[arg(value_parser)]
    shell: Shell,
}

#[tokio::main]
async fn main() -> Result<(), ()> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        EnvFilter::new("info")
            .add_directive("topiary=off".parse().unwrap())
            .add_directive("libcgroups=off".parse().unwrap())
    });

    tracing_subscriber::registry()
        .with(fmt::layer().with_writer(ot::StdoutWriter::new))
        .with(filter)
        .init();

    let cli = Cli::parse();

    match cli.command {
        Command::Ls(args) => cmd_ls(&cli.global_args, args).await,
        Command::Activate(args) => cmd_activate(&cli.global_args, args).await,
        Command::Attach(args) => cmd_attach(&cli.global_args, args).await,
        Command::Destroy(args) => cmd_destroy(&cli.global_args, args).await,
        Command::Session(SessionArgs {
            command: SessionCommand::Policy(args),
        }) => cmd_session_policy(&cli.global_args, args).await,
        Command::Proxy(args) => cmd_proxy(args).await,
        Command::Completions(CompletionsArgs { shell }) => {
            let mut cmd = Cli::command();
            let name = cmd.get_name().to_string();
            clap_complete::generate(shell, &mut cmd, name, &mut std::io::stdout());
            Ok(())
        }
    }
}

/// Connect to the daemon, resolving the socket path from global args.
async fn connect_daemon(global: &GlobalArgs) -> Result<client::Client, ()> {
    let sock = client::resolve_socket_path(global.minimal_dir.as_deref())
        .map_err(|e| eprintln!("Failed to resolve daemon socket path: {e}"))?;

    client::Client::connect(&sock)
        .await
        .map_err(|e| eprintln!("Failed to connect to minimald: {e}"))
}

/// Bidirectionally pipe stdio to a daemon UDS socket.
///
/// Intended for use as an SSH `ProxyCommand`: ssh writes to our stdin and
/// reads from our stdout, while we bridge both directions to the UDS.
async fn cmd_proxy(args: ProxyArgs) -> Result<(), ()> {
    let stream = tokio::net::UnixStream::connect(&args.socket)
        .await
        .map_err(|e| eprintln!("connect to {}: {e}", args.socket))?;

    let (mut rx, mut tx) = stream.into_split();
    let mut stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();

    let to_sock = async {
        tokio::io::copy(&mut stdin, &mut tx).await?;
        tx.shutdown().await
    };
    let from_sock = tokio::io::copy(&mut rx, &mut stdout);

    tokio::try_join!(to_sock, from_sock).map_err(|e| eprintln!("proxy: {e}"))?;
    Ok(())
}

/// List sessions via the `ListSessions` RPC.
async fn cmd_ls(global: &GlobalArgs, args: LsArgs) -> Result<(), ()> {
    if let Err(e) = autospawn::ensure_minvmd_running() {
        eprintln!("Failed to ensure minvmd is running: {e}");
        return Err(());
    }

    let mut client = connect_daemon(global).await?;

    use minimald_rpc::ListSessions;
    let resp = client
        .oneshot_rpc::<ListSessions>(())
        .await
        .map_err(|e| eprintln!("ListSessions RPC failed: {e}"))?;

    if resp.sessions.is_empty() {
        if !args.raw {
            println!("No active sessions.");
        }
        return Ok(());
    }

    if args.raw {
        for entry in &resp.sessions {
            println!("{}", entry.id);
        }
        return Ok(());
    }

    // Format as a table: ID, Name, Title, Last Activity.
    // Widths chosen to fit a standard 80-col terminal.
    println!(
        "{:<36}  {:<20}  {:<20}  LAST ACTIVITY",
        "SESSION ID", "NAME", "TITLE"
    );
    println!("{:-<36}  {:-<20}  {:-<20}  {:-<24}", "", "", "", "");

    for entry in &resp.sessions {
        let id = entry.id.to_string();
        let name = entry.name.as_deref().unwrap_or("-");
        let (title, last_activity) = match &entry.attrs {
            Some(attrs) => {
                let title = attrs
                    .title
                    .as_ref()
                    .map(|t| t.value.as_str())
                    .unwrap_or("-");
                let last = attrs
                    .last_stdout
                    .or(attrs.last_stdin)
                    .map(|dt| {
                        let local = dt.with_timezone(&chrono::Local);
                        local.format("%Y-%m-%d %H:%M:%S").to_string()
                    })
                    .unwrap_or_else(|| "-".to_string());
                (title, last)
            }
            None => ("-", "-".to_string()),
        };
        println!("{id:<36}  {name:<20}  {title:<20}  {last_activity}");
    }

    Ok(())
}

/// Create a new session via the `CreateSession` RPC.
async fn cmd_activate(global: &GlobalArgs, args: ActivateArgs) -> Result<(), ()> {
    if let Err(e) = autospawn::ensure_minvmd_running() {
        eprintln!("Failed to ensure minvmd is running: {e}");
        return Err(());
    }

    let project_path = std::fs::canonicalize(&args.path)
        .map_err(|e| eprintln!("Cannot resolve project path '{}': {e}", args.path))?;

    let utf8_path = camino::Utf8PathBuf::from_path_buf(project_path)
        .map_err(|_| eprintln!("Project path is not valid UTF-8"))?;
    let abs_path = paths::HostAbsPath::try_new(utf8_path)
        .map_err(|e| eprintln!("Invalid project path: {e}"))?;

    let username = std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .ok();

    let record = sessions::Record {
        id: sessions::SessionId::nil(),
        name: args.name.clone(),
        username,
        project_path: abs_path,
        network: sessions::NetworkMode::default(),
        attrs: Default::default(),
    };

    let mut client = connect_daemon(global).await?;

    use minimald_rpc::{CreateSession, CreateSessionRequest};
    let req = CreateSessionRequest { record };
    let resp = client
        .oneshot_rpc::<CreateSession>(req)
        .await
        .map_err(|e| eprintln!("CreateSession RPC failed: {e}"))?;

    let created = match resp.ok() {
        Some(r) => r,
        None => {
            eprintln!("CreateSession returned an error from the daemon");
            return Err(());
        }
    };

    println!("{}", created.id);

    if args.attach {
        // Chain into attach.
        let attach_args = AttachArgs {
            session: created.id.to_string(),
            command: None,
        };
        return cmd_attach(global, attach_args).await;
    }

    Ok(())
}

/// Shell-quote a string for safe interpolation into `sh -c`.
fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\"'\"'"))
}

/// Attach to an existing session. Both interactive and `--command` paths
/// shell out to `ssh` — the daemon's shell_request handler mints a PTY-backed
/// session shell, and ssh handles termios/PTY management for us.
async fn cmd_attach(global: &GlobalArgs, args: AttachArgs) -> Result<(), ()> {
    if let Err(e) = autospawn::ensure_minvmd_running() {
        eprintln!("Failed to ensure minvmd is running: {e}");
        return Err(());
    }

    let sock = client::resolve_socket_path(global.minimal_dir.as_deref())
        .map_err(|e| eprintln!("Failed to resolve daemon socket path: {e}"))?;

    // Resolve the session: if it looks like a UUID, query by ID; otherwise by name.
    use minimald_rpc::{GetSessionRecord, GetSessionRecordRequest};
    let mut client = client::Client::connect(&sock)
        .await
        .map_err(|e| eprintln!("Failed to connect to minimald: {e}"))?;

    let lookup = if let Ok(id) = sessions::SessionId::parse_str(&args.session) {
        GetSessionRecordRequest::Id(id)
    } else {
        GetSessionRecordRequest::Name(args.session.clone())
    };

    let resp = client
        .oneshot_rpc::<GetSessionRecord>(lookup)
        .await
        .map_err(|e| eprintln!("GetSessionRecord RPC failed: {e}"))?;

    let record = match resp.record {
        Some(r) => r,
        None => {
            eprintln!("No session found matching '{}'", args.session);
            return Err(());
        }
    };

    tracing::info!(
        session_id = %record.id,
        session_name = ?record.name,
        "found session"
    );

    // Shell out to ssh for both interactive and --command attachment.
    // ProxyCommand points at our own `proxy` subcommand so we don't
    // depend on socat or nc being installed.
    let exe =
        std::env::current_exe().map_err(|e| eprintln!("cannot determine current exe: {e}"))?;
    let proxy_cmd = format!(
        "{} proxy --socket {}",
        shell_quote(&exe.display().to_string()),
        shell_quote(&sock.display().to_string()),
    );

    let mut ssh = std::process::Command::new("ssh");
    ssh.env("MINIMAL_SESSION_ID", record.id.to_string()).args([
        "-o",
        "SendEnv=MINIMAL_SESSION_ID",
        "-o",
        &format!("ProxyCommand={proxy_cmd}"),
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "local-0",
    ]);

    // If a command was provided, pass it to ssh (non-interactive exec).
    // Otherwise, ssh opens an interactive shell via shell_request.
    if let Some(ref cmd) = args.command {
        ssh.arg(cmd);
    }

    let err = ssh.exec();
    // exec() only returns on failure
    eprintln!("failed to exec ssh: {err}");
    Err(())
}

/// Print the effective networking policy for a session as JSON.
async fn cmd_session_policy(global: &GlobalArgs, args: PolicyArgs) -> Result<(), ()> {
    if let Err(e) = autospawn::ensure_minvmd_running() {
        eprintln!("Failed to ensure minvmd is running: {e}");
        return Err(());
    }

    let mut client = connect_daemon(global).await?;

    use minimald_rpc::{GetSessionPolicy, GetSessionPolicyRequest};
    let lookup = if let Ok(id) = sessions::SessionId::parse_str(&args.session) {
        GetSessionPolicyRequest::Id(id)
    } else {
        GetSessionPolicyRequest::Name(args.session.clone())
    };

    let resp = client
        .oneshot_rpc::<GetSessionPolicy>(lookup)
        .await
        .map_err(|e| eprintln!("GetSessionPolicy RPC failed: {e}"))?;

    match resp.ok() {
        Some(policy) => {
            let json = serde_json::to_string(&policy)
                .map_err(|e| eprintln!("Failed to serialize policy: {e}"))?;
            println!("{json}");
            Ok(())
        }
        None => {
            eprintln!("No session found matching '{}'", args.session);
            Err(())
        }
    }
}

/// Destroy (terminate) a session.
async fn cmd_destroy(global: &GlobalArgs, args: DestroyArgs) -> Result<(), ()> {
    if let Err(e) = autospawn::ensure_minvmd_running() {
        eprintln!("Failed to ensure minvmd is running: {e}");
        return Err(());
    }

    let mut client = connect_daemon(global).await?;

    // Resolve the session: if it looks like a UUID, query by ID; otherwise by name.
    use minimald_rpc::{
        DestroySession, DestroySessionRequest, GetSessionRecord, GetSessionRecordRequest,
    };
    let lookup = if let Ok(id) = sessions::SessionId::parse_str(&args.session) {
        GetSessionRecordRequest::Id(id)
    } else {
        GetSessionRecordRequest::Name(args.session.clone())
    };

    let resp = client
        .oneshot_rpc::<GetSessionRecord>(lookup)
        .await
        .map_err(|e| eprintln!("GetSessionRecord RPC failed: {e}"))?;

    let record = match resp.record {
        Some(r) => r,
        None => {
            eprintln!("No session found matching '{}'", args.session);
            return Err(());
        }
    };

    let resp = client
        .oneshot_rpc::<DestroySession>(DestroySessionRequest { id: record.id })
        .await
        .map_err(|e| eprintln!("DestroySession RPC failed: {e}"))?;

    if resp.ok().is_some() {
        println!(
            "Destroyed session {} ({})",
            record.id,
            record.name.as_deref().unwrap_or("-")
        );
    } else {
        eprintln!("DestroySession returned an error from the daemon");
        return Err(());
    }

    Ok(())
}
