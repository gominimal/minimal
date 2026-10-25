//! `minzoned`: the host's box-zone answerer service (NET-122's host
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
//!
//! On macOS the same copy carries one more verb, `reserve-local-range`: the
//! program of the boot-time unit that adds the reserved local range to the
//! host loopback, as root. It is a verb of this program, not a script of its
//! own, because macOS lists a launchd job under an app's name only when the
//! job's program is signed code inside that app's bundle.

use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

#[derive(Parser)]
#[command(name = "minzoned", version = version::VERSION, long_version = version::LONG_VERSION)]
#[command(
    about = "The Minimal box-name service (DNS and addresses for boxes), run by the service manager"
)]
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
    /// Add the loopback IPs boxes use to lo0, skipping the ones it already
    /// carries.
    #[cfg(target_os = "macos")]
    ReserveLocalRange,
}

/// The mask `ifconfig` prints for a `/32` alias.
#[cfg(any(test, target_os = "macos"))]
const HOST_MASK: &str = "0xffffffff";

/// The reserved range's addresses that `ifconfig lo0 inet` output does not
/// list with the `/32` mask: the ones the verb still has to apply. An
/// address is carried when a line reads `inet <address> netmask 0xffffffff`,
/// so `127.0.64.1` is not found in `127.0.64.10`, and an address carried
/// with any other mask is applied again.
#[cfg(any(test, target_os = "macos"))]
fn missing_range_addresses(present: &str) -> Vec<std::net::Ipv4Addr> {
    let carried: std::collections::HashSet<&str> = present
        .lines()
        .filter_map(|line| {
            let mut words = line.split_whitespace();
            match (words.next(), words.next(), words.next(), words.next()) {
                (Some("inet"), Some(addr), Some("netmask"), Some(HOST_MASK)) => Some(addr),
                _ => None,
            }
        })
        .collect();
    switch::loopback::range_hosts()
        .filter(|addr| !carried.contains(addr.to_string().as_str()))
        .collect()
}

/// The `reserve-local-range` verb: add every address of the reserved local
/// range that lo0 does not carry yet, one `/32` alias each, and fail on the
/// first address that cannot be added. The mask is given with `netmask`:
/// without the keyword `ifconfig` reads it as a destination address and the
/// alias takes the `/8` of its class. The range is compiled in, and the verb
/// takes no argument and reads no environment variable and no file: its one
/// read is the interface's own state, from the same absolute-path system tool
/// the aliases are added with, run with an empty environment. So nothing a
/// user can write changes what root applies. An address lo0 already carries
/// with the `/32` mask is skipped, so a re-run adds only the missing ones and
/// removes nothing; one carried with another mask is applied again, which
/// sets its mask.
#[cfg(target_os = "macos")]
fn reserve_local_range() -> Result<()> {
    use anyhow::{Context as _, ensure};
    const IFCONFIG: &str = "/sbin/ifconfig";
    let present = std::process::Command::new(IFCONFIG)
        .args(["lo0", "inet"])
        .env_clear()
        .output()
        .with_context(|| format!("{IFCONFIG} did not run"))?;
    ensure!(
        present.status.success(),
        "{IFCONFIG} lo0 inet exited with {}",
        present.status
    );
    for addr in missing_range_addresses(&String::from_utf8_lossy(&present.stdout)) {
        let status = std::process::Command::new(IFCONFIG)
            .args([
                "lo0",
                "alias",
                &addr.to_string(),
                "netmask",
                "255.255.255.255",
            ])
            .env_clear()
            .status()
            .with_context(|| format!("{IFCONFIG} did not run"))?;
        ensure!(
            status.success(),
            "{IFCONFIG} lo0 alias {addr} exited with {status}"
        );
    }
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    // Before the log setup, which reads its filter from the environment:
    // this verb runs as root and reads no environment variable.
    #[cfg(target_os = "macos")]
    if matches!(cli.command, Some(Command::ReserveLocalRange)) {
        return reserve_local_range();
    }
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
        #[cfg(target_os = "macos")]
        Some(Command::ReserveLocalRange) => reserve_local_range(),
        None => minvmd::cmd::answerer::run(cli.protocol_version),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The verb adds exactly the reserved range's addresses that lo0 does
    /// not carry with the /32 mask: all 254 on a bare loopback, none on a
    /// complete one, all 254 again where they carry a wider mask, and an
    /// address is carried only as a whole word, never as a prefix of another.
    #[test]
    fn reserve_local_range_adds_only_missing_addresses() {
        let bare = "lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384\n\
                    \tinet 127.0.0.1 netmask 0xff000000\n";
        let all: Vec<_> = switch::loopback::range_hosts().collect();
        assert_eq!(all.len(), 254);
        assert_eq!(missing_range_addresses(bare), all);

        let complete: String = all
            .iter()
            .map(|addr| format!("\tinet {addr} netmask 0xffffffff\n"))
            .collect();
        assert!(missing_range_addresses(&complete).is_empty());

        let partial = "\tinet 127.0.64.10 netmask 0xffffffff\n";
        let missing = missing_range_addresses(partial);
        assert_eq!(missing.len(), 253);
        assert!(missing.contains(&std::net::Ipv4Addr::new(127, 0, 64, 1)));
        assert!(!missing.contains(&std::net::Ipv4Addr::new(127, 0, 64, 10)));

        // An address carried with the /8 an earlier install gave it is
        // applied again.
        let wide: String = all
            .iter()
            .map(|addr| format!("\tinet {addr} netmask 0xff000000\n"))
            .collect();
        assert_eq!(missing_range_addresses(&wide), all);
    }
}
