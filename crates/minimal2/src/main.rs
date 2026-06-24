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
    /// WireGuard mesh: join, leave, and inspect remote-access state
    Mesh(MeshArgs),
    /// Proxy stdio to a daemon UDS socket (used as an SSH ProxyCommand).
    #[command(hide = true)]
    Proxy(ProxyArgs),
    /// Forward a local TCP port to a remote address inside a PTask via SSH
    /// (R4.8, R4.9).
    ///
    /// Sets up an SSH `LocalForward` (`-L`) tunnel through the minimald SSH
    /// server so traffic sent to `<local-port>` on the host is relayed to
    /// `<remote-host>:<remote-port>` from inside the named PTask's network
    /// namespace. Useful when WireGuard (`networking-wg` feature) is
    /// unavailable (e.g., on corporate networks that block UDP).
    ///
    /// Examples:
    ///
    ///   # Forward host port 18080 to the webserver inside the "dev" session:
    ///   minimal ssh-forward dev 18080:127.0.0.1:80
    ///
    ///   # Then access it from the host:
    ///   curl http://localhost:18080/
    #[command(name = "ssh-forward", visible_alias = "forward")]
    SshForward(SshForwardArgs),
    /// Obtain an mTLS client certificate from minimald for use with the HTTPS
    /// reverse proxy (R4.4, R4.5).
    ///
    /// Connects to minimald, generates a fresh client certificate signed by
    /// the daemon's internal CA, and saves the certificate and private key to
    /// `~/.config/minimal/client.pem` / `~/.config/minimal/client.key`. Also
    /// saves the CA certificate to `~/.config/minimal/ca.pem` so tools like
    /// `curl` can trust the HTTPS proxy.
    ///
    /// Example:
    ///
    ///   minimal login
    ///   curl --cacert ~/.config/minimal/ca.pem \
    ///        --cert ~/.config/minimal/client.pem \
    ///        --key  ~/.config/minimal/client.key \
    ///        https://localhost:7655/
    Login(LoginArgs),
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

/// WireGuard mesh subcommands for authenticated remote PTask access (UC7 /
/// UC2b). The mesh lets a laptop, or another host's PTasks, reach this host's
/// PTasks over an encrypted tunnel.
#[derive(Debug, Args)]
struct MeshArgs {
    #[command(subcommand)]
    command: MeshCommand,
}

#[derive(Debug, Subcommand)]
enum MeshCommand {
    /// Enrol this machine into a remote minimald's WireGuard mesh
    ///
    /// v1 uses manual key exchange: this records the target and prints the
    /// steps to swap public keys. Once enrolled you can reach the remote
    /// host's own-IP PTasks by their switch IPs over the tunnel.
    ///
    /// Example:
    ///
    ///   minimal mesh join mesh.example.com:51820
    #[command(verbatim_doc_comment)]
    Join(MeshJoinArgs),
    /// Leave the WireGuard mesh and drop this machine's local enrolment
    ///
    /// Removes the local enrolment record written by `minimal mesh join`.
    /// Peer entries on the remote minimald must be removed there (manual v1).
    ///
    /// Example:
    ///
    ///   minimal mesh leave
    #[command(verbatim_doc_comment)]
    Leave,
    /// Show this minimald's mesh status: public key, advertised subnets, peers
    ///
    /// Queries the local minimald for its WireGuard public key, the switch
    /// subnets it advertises to the mesh, and each peer's last handshake.
    ///
    /// Example:
    ///
    ///   minimal mesh status
    #[command(verbatim_doc_comment)]
    Status,
}

#[derive(Debug, Args)]
struct MeshJoinArgs {
    /// Address of the remote minimald exposing the mesh (`host:port`)
    address: String,
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

/// Arguments for `minimal ssh-forward`.
#[derive(Debug, Args)]
struct SshForwardArgs {
    /// Session identifier (UUID or session name)
    session: String,
    /// Port-forward specification: `<local-port>:<remote-host>:<remote-port>`
    ///
    /// Example: `18080:127.0.0.1:80` to forward local port 18080 to port 80
    /// on the loopback address as seen from inside the session.
    #[arg(value_name = "LOCAL:REMOTE_HOST:REMOTE_PORT")]
    forward: String,
}

/// Arguments for `minimal login`.
#[derive(Debug, Args)]
struct LoginArgs {
    /// Override the directory where client cert files are written
    /// (default: `~/.config/minimal/`).
    #[arg(long)]
    cert_dir: Option<PathBuf>,
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
        Command::Mesh(MeshArgs { command }) => match command {
            MeshCommand::Status => cmd_mesh_status(&cli.global_args).await,
            MeshCommand::Join(args) => cmd_mesh_join(&cli.global_args, args),
            MeshCommand::Leave => cmd_mesh_leave(&cli.global_args),
        },
        Command::Proxy(args) => cmd_proxy(args).await,
        Command::SshForward(args) => cmd_ssh_forward(&cli.global_args, args).await,
        Command::Login(args) => cmd_login(&cli.global_args, args).await,
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
        policy: Default::default(),
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

    match resp {
        minimald_rpc::Errorable::Ok(policy) => {
            let json = serde_json::to_string(&policy)
                .map_err(|e| eprintln!("Failed to serialize policy: {e}"))?;
            println!("{json}");
            Ok(())
        }
        minimald_rpc::Errorable::Err { error } => {
            eprintln!("{error}");
            Err(())
        }
    }
}

/// The local mesh-enrolment record path. Honors `--minimal-dir`, else falls
/// back to the user config dir.
fn mesh_enrolment_path(global: &GlobalArgs) -> Result<PathBuf, ()> {
    let base = match &global.minimal_dir {
        Some(dir) => dir.clone(),
        None => dirs::config_dir()
            .map(|c| c.join("minimal"))
            .ok_or_else(|| eprintln!("cannot determine config directory; set --minimal-dir"))?,
    };
    Ok(base.join("mesh-enrolment"))
}

/// Show this minimald's WireGuard mesh status (R4.6): own public key, the
/// switch subnets it advertises, and each peer's last handshake.
async fn cmd_mesh_status(global: &GlobalArgs) -> Result<(), ()> {
    if let Err(e) = autospawn::ensure_minvmd_running() {
        eprintln!("Failed to ensure minvmd is running: {e}");
        return Err(());
    }

    let mut client = connect_daemon(global).await?;

    use minimald_rpc::GetMeshStatus;
    let resp = client
        .oneshot_rpc::<GetMeshStatus>(())
        .await
        .map_err(|e| eprintln!("GetMeshStatus RPC failed: {e}"))?;

    if !resp.configured {
        println!("No WireGuard mesh is configured on this minimald.");
        return Ok(());
    }

    println!(
        "public key:  {}",
        resp.own_public_key.as_deref().unwrap_or("-")
    );
    if resp.advertised_subnets.is_empty() {
        println!("advertised:  (none)");
    } else {
        println!("advertised:  {}", resp.advertised_subnets.join(", "));
    }

    if resp.peers.is_empty() {
        println!("peers:       (none)");
        return Ok(());
    }

    println!("peers:");
    println!("  {:<20}  {:<46}  LAST HANDSHAKE", "NAME", "PUBLIC KEY");
    for p in &resp.peers {
        let handshake = match p.last_handshake_secs {
            Some(secs) => format!("{secs}s ago"),
            None => "never".to_string(),
        };
        println!("  {:<20}  {:<46}  {handshake}", p.name, p.public_key);
    }

    Ok(())
}

/// Record this machine's enrolment into a remote minimald's mesh (R4.3, v1
/// manual key exchange) and print the steps to complete the key swap.
fn cmd_mesh_join(global: &GlobalArgs, args: MeshJoinArgs) -> Result<(), ()> {
    // Validate the endpoint at the point of entry so a typo never lands a bad
    // enrolment on disk for a later consumer to choke on. The CLI contract is
    // `host:port`; require a non-empty host and a parseable u16 port.
    let Some((host, port)) = args.address.rsplit_once(':') else {
        eprintln!("mesh join address must be host:port, e.g. mesh.example.com:51820");
        return Err(());
    };
    if host.is_empty() || port.parse::<u16>().is_err() {
        eprintln!("mesh join address must include a non-empty host and valid port");
        return Err(());
    }

    let path = mesh_enrolment_path(global)?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| eprintln!("creating {}: {e}", parent.display()))?;
    }
    std::fs::write(&path, format!("{}\n", args.address))
        .map_err(|e| eprintln!("writing {}: {e}", path.display()))?;

    println!(
        "Recorded mesh enrolment for {} at {}.",
        args.address,
        path.display()
    );
    println!();
    println!("v1 uses manual key exchange. To complete the join:");
    println!("  1. Run `minimal mesh status` on the remote host to read its public key.");
    println!("  2. Add this machine's WireGuard public key to the remote minimald's peers.");
    println!("  3. Add the remote's public key and endpoint to this machine's mesh config.");
    Ok(())
}

/// Drop this machine's local mesh enrolment (R4.3). Remote peer entries are
/// removed on the remote host (manual v1).
fn cmd_mesh_leave(global: &GlobalArgs) -> Result<(), ()> {
    let path = mesh_enrolment_path(global)?;
    match std::fs::remove_file(&path) {
        Ok(()) => {
            println!(
                "Left the mesh; removed local enrolment at {}.",
                path.display()
            );
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            println!("No local mesh enrolment to remove.");
            Ok(())
        }
        Err(e) => {
            eprintln!("removing {}: {e}", path.display());
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

/// Establish an SSH `LocalForward` tunnel from a local port to a remote
/// address inside the named PTask's network namespace (R4.8, R4.9).
///
/// The forward spec is `<local-port>:<remote-host>:<remote-port>`. The
/// command shells out to `ssh -L` (the same mechanism as `cmd_attach`).
/// The `-N` flag keeps the tunnel alive without opening an interactive
/// shell.
async fn cmd_ssh_forward(global: &GlobalArgs, args: SshForwardArgs) -> Result<(), ()> {
    if let Err(e) = autospawn::ensure_minvmd_running() {
        eprintln!("Failed to ensure minvmd is running: {e}");
        return Err(());
    }

    let sock = client::resolve_socket_path(global.minimal_dir.as_deref())
        .map_err(|e| eprintln!("Failed to resolve daemon socket path: {e}"))?;

    // Look up the session to validate it exists and to obtain its UUID for the
    // server-side auth gate (passed as the SSH username so `direct-tcpip` can
    // verify the session without a per-channel env handshake).
    use minimald_rpc::{GetSessionRecord, GetSessionRecordRequest};
    let mut daemon_client = client::Client::connect(&sock)
        .await
        .map_err(|e| eprintln!("Failed to connect to minimald: {e}"))?;

    let lookup = if let Ok(id) = sessions::SessionId::parse_str(&args.session) {
        GetSessionRecordRequest::Id(id)
    } else {
        GetSessionRecordRequest::Name(args.session.clone())
    };

    let resp = daemon_client
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

    // Validate the forward spec format: local:remote_host:remote_port.
    // We accept either `local_port:host:port` (3 components, last two joined by
    // the final colon) or the more compact form where host is an IPv4 address.
    let parts: Vec<&str> = args.forward.splitn(3, ':').collect();
    if parts.len() != 3 {
        eprintln!(
            "invalid forward spec {:?}: expected LOCAL_PORT:REMOTE_HOST:REMOTE_PORT",
            args.forward
        );
        return Err(());
    }
    let local_port = parts[0];
    let remote_host = parts[1];
    let remote_port = parts[2];
    let forward_arg = format!("{local_port}:{remote_host}:{remote_port}");

    let exe =
        std::env::current_exe().map_err(|e| eprintln!("cannot determine current exe: {e}"))?;
    let proxy_cmd = format!(
        "{} proxy --socket {}",
        shell_quote(&exe.display().to_string()),
        shell_quote(&sock.display().to_string()),
    );

    let session_id = record.id.to_string();
    // Use `-N` (no command) so the foreground ssh keeps the tunnel alive after
    // `exec()` replaces this process. `-o ExitOnForwardFailure=yes` makes ssh
    // exit immediately if the local port cannot be bound rather than silently
    // succeeding without a tunnel.
    let mut ssh = std::process::Command::new("ssh");
    ssh.args([
        "-L",
        &forward_arg,
        "-N",
        "-l",
        &session_id,
        "-o",
        "ExitOnForwardFailure=yes",
        "-o",
        &format!("ProxyCommand={proxy_cmd}"),
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "local-0",
    ]);

    // exec() replaces the process, so this call only returns on failure.
    let err = std::os::unix::process::CommandExt::exec(&mut ssh);
    eprintln!("failed to exec ssh: {err}");
    Err(())
}

/// Obtain an mTLS client certificate from minimald (R4.4).
///
/// Calls the `IssueClientCert` RPC, which has minimald generate a key pair,
/// sign the certificate with its internal CA, and return both. The cert, key,
/// and CA cert are written to `<cert_dir>/{client.pem,client.key,ca.pem}`.
async fn cmd_login(global: &GlobalArgs, args: LoginArgs) -> Result<(), ()> {
    if let Err(e) = autospawn::ensure_minvmd_running() {
        eprintln!("Failed to ensure minvmd is running: {e}");
        return Err(());
    }

    let mut client = connect_daemon(global).await?;

    let subject_cn = std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_else(|_| "minimal-client".to_string());

    use minimald_rpc::{IssueClientCert, IssueClientCertRequest};
    let resp = client
        .oneshot_rpc::<IssueClientCert>(IssueClientCertRequest { subject_cn })
        .await
        .map_err(|e| eprintln!("IssueClientCert RPC failed: {e}"))?;

    let cert_resp = match resp {
        minimald_rpc::Errorable::Ok(r) => r,
        minimald_rpc::Errorable::Err { error } => {
            eprintln!("IssueClientCert failed: {error}");
            return Err(());
        }
    };

    // Determine the cert directory.
    let cert_dir = match args.cert_dir {
        Some(d) => d,
        None => {
            let config_dir =
                dirs::config_dir().ok_or_else(|| eprintln!("cannot determine config directory"))?;
            config_dir.join("minimal")
        }
    };
    std::fs::create_dir_all(&cert_dir)
        .map_err(|e| eprintln!("cannot create cert dir {}: {e}", cert_dir.display()))?;

    let client_cert_path = cert_dir.join("client.pem");
    let client_key_path = cert_dir.join("client.key");
    let ca_cert_path = cert_dir.join("ca.pem");

    std::fs::write(&client_cert_path, cert_resp.cert_pem.as_bytes())
        .map_err(|e| eprintln!("writing {}: {e}", client_cert_path.display()))?;
    {
        use std::io::Write as _;
        #[cfg(unix)]
        use std::os::unix::fs::OpenOptionsExt as _;
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        opts.mode(0o600);
        let mut f = opts
            .open(&client_key_path)
            .map_err(|e| eprintln!("writing {}: {e}", client_key_path.display()))?;
        f.write_all(cert_resp.key_pem.as_bytes())
            .map_err(|e| eprintln!("writing {}: {e}", client_key_path.display()))?;
    }
    std::fs::write(&ca_cert_path, cert_resp.ca_cert_pem.as_bytes())
        .map_err(|e| eprintln!("writing {}: {e}", ca_cert_path.display()))?;

    println!("Saved client certificate to {}", client_cert_path.display());
    println!("Saved client key to {}", client_key_path.display());
    println!("Saved CA certificate to {}", ca_cert_path.display());
    println!();
    println!(
        "To use the HTTPS proxy:\n  curl --cacert {} --cert {} --key {} https://localhost:7655/",
        ca_cert_path.display(),
        client_cert_path.display(),
        client_key_path.display(),
    );

    Ok(())
}
