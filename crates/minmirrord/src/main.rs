//! `minmirrord`: the mirror daemon's command line.

use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use clap::{Parser, Subcommand};
use mirror_client::MirrorDirs;
use tracing_subscriber::prelude::*;

/// The environment variable a detached child carries, so it logs to its file
/// and not to the terminal that is gone.
const DETACHED_ENV: &str = "MINMIRRORD_DETACHED";

#[derive(Parser)]
#[command(name = "minmirrord", version, about = "The mirror daemon")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(clap::Args)]
struct Dirs {
    /// The mirror's state directory; defaults to the user's state directory.
    #[arg(long)]
    state_dir: Option<PathBuf>,
    /// The mirror's store; defaults to the user's cache directory.
    #[arg(long)]
    store: Option<PathBuf>,
}

impl Dirs {
    fn resolve(&self) -> MirrorDirs {
        let defaults = MirrorDirs::resolve(None);
        MirrorDirs::new(
            self.state_dir.clone().unwrap_or(defaults.state),
            self.store.clone().unwrap_or(defaults.store),
        )
    }
}

#[derive(Subcommand)]
enum Command {
    /// Run the daemon.
    Run {
        /// Start in the background and return once the mirror answers.
        #[arg(long)]
        detach: bool,
        #[command(flatten)]
        dirs: Dirs,
    },
    /// Stop a running daemon.
    Stop {
        #[command(flatten)]
        dirs: Dirs,
    },
    /// Print the running daemon's status document.
    Status {
        #[command(flatten)]
        dirs: Dirs,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Run { detach, dirs } => {
            let dirs = dirs.resolve();
            if let Err(e) = check_git() {
                eprintln!("{e}");
                return ExitCode::from(1);
            }
            if detach {
                return match spawn_detached(&dirs) {
                    Ok(()) => ExitCode::SUCCESS,
                    Err(e) => {
                        eprintln!("{e}");
                        ExitCode::from(1)
                    }
                };
            }
            run_foreground(dirs)
        }
        Command::Stop { dirs } => stop(&dirs.resolve()),
        Command::Status { dirs } => status(&dirs.resolve()),
    }
}

/// The two lines a missing git refuses with (MIR-070).
fn check_git() -> Result<(), String> {
    match std::process::Command::new("git")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
    {
        Ok(status) if status.success() => Ok(()),
        _ => Err(
            "git is not installed.\nThe mirror needs it to copy package repositories.".to_string(),
        ),
    }
}

fn init_logging(
    dirs: &MirrorDirs,
    detached: bool,
) -> Option<tracing_appender::non_blocking::WorkerGuard> {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(dirs.log_file())
        .ok();
    match file {
        Some(file) => {
            let (writer, guard) = tracing_appender::non_blocking(file);
            let registry = tracing_subscriber::registry()
                .with(filter)
                .with(mlog::json_file_layer(writer, "minmirrord"));
            if detached {
                registry.init();
            } else {
                registry
                    .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
                    .init();
            }
            Some(guard)
        }
        None => {
            tracing_subscriber::registry()
                .with(filter)
                .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
                .init();
            None
        }
    }
}

fn run_foreground(dirs: MirrorDirs) -> ExitCode {
    if let Err(e) = std::fs::create_dir_all(&dirs.state) {
        eprintln!("the mirror could not create {}: {e}", dirs.state.display());
        return ExitCode::from(1);
    }
    let detached = std::env::var_os(DETACHED_ENV).is_some();
    let _guard = init_logging(&dirs, detached);
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("the mirror could not start its runtime: {e}");
            return ExitCode::from(1);
        }
    };
    match runtime.block_on(minmirrord::run(dirs)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!(error = %e, "the mirror stopped with an error");
            eprintln!("the mirror could not start: {e:#}");
            ExitCode::from(1)
        }
    }
}

/// Starts the daemon in its own session with its standard error in the run
/// log, and waits until it answers or exits (MIR-020, MIR-070).
fn spawn_detached(dirs: &MirrorDirs) -> Result<(), String> {
    use std::os::unix::process::CommandExt as _;

    if let Some(state) = mirror_client::running(dirs) {
        tracing::debug!(pid = state.pid, "mirror already running");
        return Ok(());
    }
    std::fs::create_dir_all(&dirs.state)
        .map_err(|e| format!("the mirror could not create {}: {e}", dirs.state.display()))?;
    let exe = std::env::current_exe().map_err(|e| format!("resolving the daemon's path: {e}"))?;
    let run_log = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(dirs.run_log())
        .map_err(|e| format!("opening {}: {e}", dirs.run_log().display()))?;
    let mut cmd = std::process::Command::new(exe);
    cmd.arg("run")
        .arg("--state-dir")
        .arg(&dirs.state)
        .arg("--store")
        .arg(&dirs.store)
        .env(DETACHED_ENV, "1")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(run_log);
    // SAFETY: setsid is async-signal-safe; in the child it starts a new
    // session so the daemon outlives the process that started it.
    unsafe {
        cmd.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = cmd
        .spawn()
        .map_err(|e| format!("starting the mirror: {e}"))?;
    let deadline = Instant::now() + mirror_client::START_TIMEOUT;
    loop {
        if let Ok(Some(status)) = child.try_wait() {
            let log = std::fs::read_to_string(dirs.run_log()).unwrap_or_default();
            let cause = log
                .lines()
                .find(|l| !l.trim().is_empty())
                .map(str::to_string)
                .unwrap_or_else(|| format!("exited with {status}"));
            // Every line the child wrote follows, so the starter can relay them.
            let mut message = cause;
            for line in log.lines().skip(1) {
                message.push('\n');
                message.push_str(line);
            }
            return Err(message);
        }
        if mirror_client::running(dirs).is_some() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "no answer on {} within {:?}",
                dirs.host_socket().display(),
                mirror_client::START_TIMEOUT
            ));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn stop(dirs: &MirrorDirs) -> ExitCode {
    let Some(state) = mirror_client::running(dirs) else {
        println!("mirror: stopped");
        return ExitCode::SUCCESS;
    };
    // SAFETY: kill sends one signal to the pid the lifecycle file names; it
    // reads no memory of ours.
    let rc = unsafe { libc::kill(state.pid as libc::pid_t, libc::SIGTERM) };
    if rc != 0 {
        eprintln!(
            "the mirror could not be signalled: {}",
            std::io::Error::last_os_error()
        );
        return ExitCode::from(1);
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if !mirror_client::socket_answers(&state.host_socket) {
            return ExitCode::SUCCESS;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    eprintln!("the mirror is still answering after 5 s.");
    ExitCode::from(1)
}

fn status(dirs: &MirrorDirs) -> ExitCode {
    let Some(state) = mirror_client::running(dirs) else {
        println!("mirror: stopped");
        return ExitCode::from(1);
    };
    match mirror_client::blocking::get(
        &mirror_client::MirrorEndpoint::Unix(state.host_socket),
        "/-/status",
    ) {
        Ok(reply) if reply.status == 200 => {
            let _ = std::io::stdout().write_all(&reply.body);
            let _ = std::io::stdout().write_all(b"\n");
            ExitCode::SUCCESS
        }
        Ok(reply) => {
            eprintln!("the mirror answered {}: {}", reply.status, reply.text());
            ExitCode::from(1)
        }
        Err(e) => {
            eprintln!("{e}");
            ExitCode::from(1)
        }
    }
}
