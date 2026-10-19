//! `bep`: the Box Egress Proxy on this host.
//!
//! At start it loads the proxy's keys from the host keychain and publishes
//! their public halves (BEP-059, BEP-072). `bep --replace-key <role>` is the
//! operator's command that replaces a key (BEP-060). It reads no file, so it
//! works when the proxy itself does not start. After the replacement it
//! publishes the new public key, so a mint stops sealing to the old one.

use std::path::PathBuf;
use std::process::ExitCode;

use bep::keys::{self, KeyStore, ReplaceError, Role};
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
        match keys::replace(store, role) {
            Ok(_) => println!("{}", keys::replacement_report(role)),
            Err(ReplaceError::Remove(err)) => {
                eprintln!("The {role} key was not replaced. The old key is still in use: {err}.");
                return ExitCode::FAILURE;
            }
            Err(ReplaceError::Generate(err)) => {
                eprintln!(
                    "The old {role} key was deleted, but no new key was made: {err}. Run `bep --replace-key {role}` again."
                );
                return ExitCode::FAILURE;
            }
        }
        // The identity file still names the old key. Publish the new one now,
        // so that a mint never seals to a deleted key.
        return match publish(store, args) {
            Ok(path) => {
                println!("Published the new public key to {}.", path.display());
                ExitCode::SUCCESS
            }
            Err(err) => {
                eprintln!("{err}");
                eprintln!(
                    "The published identity still names the old {role} key. Run `bep` to publish the new one."
                );
                ExitCode::FAILURE
            }
        };
    }

    match publish(store, args) {
        Ok(_) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("{err}");
            ExitCode::FAILURE
        }
    }
}

/// Loads the keys and publishes their public halves. Returns the file it
/// wrote, or the text to print.
fn publish<S: KeyStore>(store: &S, args: &Args) -> Result<PathBuf, String> {
    let loaded = keys::load(store).map_err(|err| err.to_string())?;
    let path = args
        .identity
        .clone()
        .or_else(default_identity_path)
        .ok_or_else(|| {
            "bep did not find your home directory. Give the file with `bep --identity <PATH>`."
                .to_owned()
        })?;
    Identity::of(&loaded)
        .publish(&path)
        .map_err(|err| err.to_string())?;
    tracing::info!(path = %path.display(), "published the proxy identity");
    Ok(path)
}

fn default_identity_path() -> Option<PathBuf> {
    std::env::home_dir().map(|home| home.join(".minimal/bep/identity.json"))
}
