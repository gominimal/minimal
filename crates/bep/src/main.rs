//! `bep`: the Box Egress Proxy on this host.
//!
//! At start it loads the proxy's keys from the host keychain and publishes
//! their public halves (BEP-059, BEP-072). `bep --replace-key <role>` is the
//! operator's command that replaces a key (BEP-060). It needs no file and no
//! other key, so it works when the proxy itself does not start. After the
//! replacement it publishes the new public key, so a mint stops sealing to
//! the old one.

use std::io;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use bep::keys::{self, KeyStore, ReplaceError, Role};
use bep::publish::{Identity, PublishError};
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
            "bep runs only on macOS, because it keeps its keys in the macOS Keychain. Neither `bep` nor `bep --replace-key` can run on this host."
        );
        ExitCode::FAILURE
    }
}

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn run<S: KeyStore>(store: &S, args: &Args) -> ExitCode {
    let path = match identity_path(args) {
        Ok(path) => path,
        Err(err) => {
            eprintln!("{err}");
            return ExitCode::FAILURE;
        }
    };
    if let Some(role) = args.replace_key {
        return replace_key(store, role, &path);
    }
    match start(store, &path) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("{err}");
            ExitCode::FAILURE
        }
    }
}

/// `bep --replace-key <role>`. It needs no other key and no file, so it
/// works when the proxy does not start.
fn replace_key<S: KeyStore>(store: &S, role: Role, path: &Path) -> ExitCode {
    let key = match keys::replace(store, role) {
        Ok(key) => key,
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
    };
    println!("{}", keys::replacement_report(role));
    // The identity file still names the old key. Publish the new one now, so
    // that a mint never seals to a deleted key. The other roles come from
    // the store, or from the old file when the store refuses them.
    // BEP-060: a file that is there and not read can name a role whose key
    // the store lost. A file written without that role makes the next start
    // generate the key silently, so the file is left as it is.
    let previous = match Identity::read(path) {
        Ok(identity) => Some(identity),
        Err(PublishError::Io { source, .. }) if source.kind() == io::ErrorKind::NotFound => None,
        Err(err) => {
            eprintln!("{err}");
            eprintln!(
                "The published identity was not changed, so it still names the old {role} key. Correct the problem above, then run `bep` to publish the new key."
            );
            return ExitCode::FAILURE;
        }
    };
    match Identity::after_replacement(store, role, &key, previous.as_ref()).publish(path) {
        Ok(()) => {
            tracing::info!(path = %path.display(), "published the proxy identity");
            println!("Published the new public key to {}.", path.display());
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("{err}");
            eprintln!(
                "The published identity still names the old {role} key. Correct the problem above, then run `bep` to publish the new key."
            );
            ExitCode::FAILURE
        }
    }
}

/// A proxy start: reads the published identity, loads the keys and
/// publishes their public halves again.
fn start<S: KeyStore>(store: &S, path: &Path) -> Result<(), String> {
    // BEP-060: a role the identity names had a key before, so the start
    // refuses when the store lost it. With no file, `keys::load` still
    // refuses a lost key when the store holds a key for another role.
    let published = match Identity::read(path) {
        Ok(identity) => identity.roles(),
        Err(PublishError::Io { source, .. }) if source.kind() == io::ErrorKind::NotFound => {
            Vec::new()
        }
        Err(err) => return Err(err.to_string()),
    };
    let loaded = keys::load(store, &published).map_err(|err| err.to_string())?;
    Identity::of(&loaded)
        .publish(path)
        .map_err(|err| err.to_string())?;
    tracing::info!(path = %path.display(), "published the proxy identity");
    Ok(())
}

fn identity_path(args: &Args) -> Result<PathBuf, &'static str> {
    args.identity
        .clone()
        .or_else(|| std::env::home_dir().map(|home| home.join(".minimal/bep/identity.json")))
        .ok_or("bep did not find your home directory. Give the file with `bep --identity <PATH>`.")
}
