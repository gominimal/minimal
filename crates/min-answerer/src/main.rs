//! `min-answerer`: the host's box-zone answerer service (NET-122's host
//! service), as a program of its own.
//!
//! The privileged step copies this binary to a root-owned path and installs
//! the service units that run it: the service manager runs it as the
//! operator, never root, and hands it the two sockets it holds — the hook
//! port's listener and the machine-global channel. It carries the answerer
//! and nothing else: no VM management sits behind the hooked port, and a
//! host can ship it without the VM host daemon. It reads no configuration
//! beyond what its unit passes it.
//!
//! The same copy carries the handover's two client verbs the privileged
//! step runs as root, `release` and `release-cancel`, each over the control
//! sockets the step names: they talk to the operator's VM host daemons, and
//! never to anything on the hooked port.

use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

#[derive(Parser)]
#[command(name = "min-answerer", version = version::VERSION, long_version = version::LONG_VERSION)]
#[command(about = "The host's box-zone answerer service, run by the service manager")]
struct Cli {
    /// Print the answerer channel protocol version this copy speaks and exit.
    #[arg(long)]
    protocol_version: bool,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Ask each VM host daemon to release its interim answerer, then wait
    /// for the hook port to be free.
    Release {
        /// A VM host daemon's control socket (repeatable); an absent one is
        /// a daemon that is not running.
        #[arg(long = "control", value_name = "SOCK", required = true)]
        controls: Vec<PathBuf>,
        /// The hook port the answerer service takes.
        #[arg(long, default_value_t = minvmd::net::answerer::DEFAULT_ANSWERER_PORT)]
        port: u16,
    },
    /// Ask each VM host daemon to re-bind its interim answerer at once.
    ReleaseCancel {
        /// A VM host daemon's control socket (repeatable).
        #[arg(long = "control", value_name = "SOCK", required = true)]
        controls: Vec<PathBuf>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    // The service's lines go to stderr, which the service manager's journal
    // reads; the verbs print their own sentences there too.
    tracing_subscriber::registry()
        .with(fmt::layer().with_writer(std::io::stderr).with_ansi(false))
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();
    match cli.command {
        Some(Command::Release { controls, port }) => {
            minvmd::cmd::answerer::release(&controls, port)
        }
        Some(Command::ReleaseCancel { controls }) => {
            minvmd::cmd::answerer::release_cancel(&controls);
            Ok(())
        }
        None => minvmd::cmd::answerer::run(cli.protocol_version),
    }
}
