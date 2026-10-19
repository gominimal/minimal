//! `bep`: the Box Egress Proxy on this host.
//!
//! At start it loads the proxy's keys from the host keychain and publishes
//! their public halves (BEP-059, BEP-072). `bep --replace-key <role>` is the
//! operator's command that replaces a key (BEP-060). It reads no file, so it
//! works when the proxy itself does not start.

use std::path::PathBuf;
use std::process::ExitCode;

use bep::keys::{self, KeyStore, Role};
use bep::publish::Identity;
use clap::Parser;

/// Runs the box egress proxy on this host.
#[derive(Debug, Parser)]
#[command(name = "bep")]
struct Args {
    /// Make a new key for ROLE and delete the old key. ROLE is sealing, root
    /// or signing.
    #[arg(long, value_name = "ROLE")]
    replace_key: Option<Role>,

    /// Where to write the proxy's public keys and fingerprints.
    /// [default: ~/.minimal/bep/identity.json]
    #[arg(long, value_name = "PATH")]
    identity: Option<PathBuf>,
}

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
    let args = Args::parse();

    #[cfg(target_os = "macos")]
    {
        run(&keys::Keychain, &args)
    }
    #[cfg(not(target_os = "macos"))]
    {
        // OQ4: v1 binds the macOS Keychain alone.
        let _ = &args;
        eprintln!(
            "bep keeps its keys in the macOS Keychain. This host has no key store that bep can use."
        );
        ExitCode::FAILURE
    }
}

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn run<S: KeyStore>(store: &S, args: &Args) -> ExitCode {
    if let Some(role) = args.replace_key {
        return match keys::replace(store, role) {
            Ok(_) => {
                println!("{}", keys::replacement_report(role));
                ExitCode::SUCCESS
            }
            Err(err) => {
                eprintln!("The {role} key was not replaced: {err}.");
                ExitCode::FAILURE
            }
        };
    }

    let loaded = match keys::load(store) {
        Ok(loaded) => loaded,
        Err(err) => {
            eprintln!("{err}");
            return ExitCode::FAILURE;
        }
    };
    let Some(path) = args.identity.clone().or_else(default_identity_path) else {
        eprintln!(
            "bep did not find your home directory. Give the file with `bep --identity <PATH>`."
        );
        return ExitCode::FAILURE;
    };
    if let Err(err) = Identity::of(&loaded).publish(&path) {
        eprintln!("{err}");
        return ExitCode::FAILURE;
    }
    tracing::info!(path = %path.display(), "published the proxy identity");
    ExitCode::SUCCESS
}

fn default_identity_path() -> Option<PathBuf> {
    std::env::home_dir().map(|home| home.join(".minimal/bep/identity.json"))
}
