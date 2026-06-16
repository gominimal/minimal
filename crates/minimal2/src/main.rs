//! The minimal CLI which pairs/talks-with minimald.

use clap::{Args, CommandFactory, Parser, Subcommand};
use clap_complete::Shell;
use std::path::PathBuf;
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
    Ls,
    /// Activate (create) a new session
    Activate(ActivateArgs),
    /// Attach to an existing session
    Attach(AttachArgs),
    /// Destroy (terminate) a session
    Destroy(DestroyArgs),
    /// Interactive session dashboard (k9s-like TUI)
    #[command(hide = true)]
    Dash,
    /// Generate shell completion script
    #[command(
        long_about = "Generate a shell tab-completion script for the minimal CLI.\nSupported shells include bash, zsh, elvish and fish.\n\n   source <(minimal completions bash)"
    )]
    Completions(CompletionsArgs),
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
struct DestroyArgs {
    /// Session identifier (UUID or session name)
    session: String,
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
        Command::Ls => cmd_ls(&cli.global_args).await,
        Command::Activate(args) => cmd_activate(&cli.global_args, args).await,
        Command::Attach(args) => cmd_attach(&cli.global_args, args).await,
        Command::Destroy(args) => cmd_destroy(&cli.global_args, args).await,
        Command::Dash => {
            // TODO(#159): implement k9s-like TUI session dashboard
            eprintln!("[#159] dash: not yet implemented");
            Ok(())
        }
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

/// List sessions via the `ListSessions` RPC.
async fn cmd_ls(global: &GlobalArgs) -> Result<(), ()> {
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
        println!("No active sessions.");
        return Ok(());
    }

    // Format as a table: ID, Name, Title, Last Activity.
    // Widths chosen to fit a standard 80-col terminal.
    println!("{:<36}  {:<20}  {:<20}  {}", 
        "SESSION ID", "NAME", "TITLE", "LAST ACTIVITY");
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

/// Attach to an existing session via exec (PTY bridging not yet supported by daemon).
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

    // If a command was provided, exec it in the session context.
    // PTY interactive shell is blocked on daemon PTY support (see exec.rs:650-654).
    if let Some(ref cmd) = args.command {
        let (stdout, exit) = client
            .exec_in_session(&record.id.to_string(), cmd)
            .await
            .map_err(|e| eprintln!("exec failed: {e}"))?;
        print!("{stdout}");
        if let Some(code) = exit
            && code != 0
        {
            eprintln!("Command exited with status {code}");
        }
    } else {
        eprintln!("Session {}  |  Name: {}", record.id, record.name.as_deref().unwrap_or("-"));
        eprintln!("\nPTY-based interactive attachment is not yet supported by the daemon.");
        eprintln!("Use 'minimal attach <session> --exec <command>' to run a command.");
    }

    Ok(())
}
/// Destroy (terminate) a session.
async fn cmd_destroy(global: &GlobalArgs, args: DestroyArgs) -> Result<(), ()> {
    if let Err(e) = autospawn::ensure_minvmd_running() {
        eprintln!("Failed to ensure minvmd is running: {e}");
        return Err(());
    }

    let _client = connect_daemon(global).await?;

    // TODO(#159): no DestroySession RPC exists in the wire contract yet.
    // May need an exec-channel approach or a new RPC addition.
    eprintln!(
        "[#159] Destroying session '{}' is not yet wired (no DestroySession RPC).",
        args.session
    );
    Ok(())
}
