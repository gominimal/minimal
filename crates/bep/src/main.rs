//! `bep`: the Box Egress Proxy on this host.
//!
//! At start it loads the proxy's keys from the host keychain and publishes
//! their public halves (BEP-059, BEP-072). `bep --replace-key <role>` is the
//! operator's command that replaces a key (BEP-060). It needs no file and no
//! other key, so it works when the proxy itself does not start. After the
//! replacement it publishes the new public key, so a mint stops sealing to
//! the old one.
//!
//! `bep serve` starts the proxy the same way, then serves box connections on
//! the listener socket ([`bep::listener`]) and client key registrations on
//! the control socket ([`bep::control`]). It reads the per-boot token from
//! standard input.

use std::io;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use bep::audit::{self, AuditLog};
use bep::ca::{CaError, Leaf};
use bep::control::{Control, Registry};
use bep::keys::{self, KeyError, KeyStore, ReplaceError, Role};
use bep::listener::{Listener, PeerAttested, TOKEN_LEN};
use bep::module::GITHUB;
use bep::proxy::{self, Admission, LeafIssuer, Proxy, SystemResolver};
use bep::publish::{Identity, PublishError};
use clap::{Parser, Subcommand};

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

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Start the proxy and serve box connections. Give the connection token
    /// on standard input, as 64 hex digits.
    Serve(ServeArgs),
}

#[derive(Debug, clap::Args)]
struct ServeArgs {
    /// The socket that box connections arrive on.
    #[arg(long, value_name = "PATH")]
    listener: PathBuf,

    /// The socket that takes key registrations from `min`.
    /// [default: ~/.minimal/bep/control.sock]
    #[arg(long, value_name = "PATH")]
    control: Option<PathBuf>,
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
        if args.command.is_some() {
            eprintln!(
                "`bep --replace-key` and `bep serve` do not run together. Run `bep --replace-key {role}` first, then `bep serve`."
            );
            return ExitCode::FAILURE;
        }
        return replace_key(store, role, &path);
    }
    let started = start(store, &path).and_then(|()| match &args.command {
        Some(Command::Serve(serve_args)) => serve(serve_args),
        None => Ok(()),
    });
    match started {
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

/// The leaf issuer `bep serve` has today. The root and signing CA keys are
/// in the Keychain, but no Keychain key can sign a certificate yet
/// (<https://github.com/gominimal/minimal/issues/2440>). Until one can,
/// every leaf is refused, and the proxy answers an admitted CONNECT with
/// `502`.
///
/// This issuer is also the only thing that keeps `bep serve` off
/// `proxy::relay`, which forwards requests with no per-request decision, no
/// handle redemption and no admit audit record (Gatehouse §6.10). A signing
/// Keychain key (#2440) alone does not lift this interim. `bep serve` must
/// not reach `relay` until the redemption decision is wired into it, which
/// is T11 (<https://github.com/gominimal/minimal/issues/2272>).
struct NoSigningKey;

impl LeafIssuer for NoSigningKey {
    fn issue(&self, _hostname: &str, _now: SystemTime) -> Result<Leaf, CaError> {
        Err(CaError::Key(KeyError::Store {
            role: Role::Signing,
            detail: "the Keychain key cannot sign certificates in this version of bep".into(),
        }))
    }
}

/// `bep serve`: the listener and the control socket, until one fails.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn serve(args: &ServeArgs) -> Result<(), String> {
    let token = read_token(io::stdin().lock())?;
    let control = args
        .control
        .clone()
        .or_else(|| std::env::home_dir().map(|home| home.join(".minimal/bep/control.sock")))
        .ok_or("bep did not find your home directory. Give the socket with `bep serve --control <PATH>`.")?;
    let dir = audit::default_dir()
        .ok_or("bep did not find your home directory, which holds the audit log.")?;
    let segment = audit::segments(&dir)
        .map_err(|err| format!("bep did not read the audit log in {}: {err}", dir.display()))?
        .pop()
        .unwrap_or_else(|| dir.join(audit::segment_name(0)));
    let log = AuditLog::open(&segment).map_err(|err| {
        format!(
            "bep did not open the audit log {}: {err}",
            segment.display()
        )
    })?;
    let roots = proxy::native_roots()
        .map_err(|err| format!("bep did not load the host's root certificates: {err}."))?;
    // The store rules' authorities join the admitted set when
    // `[secret-store-rules]` is read at start, which is T25
    // (https://github.com/gominimal/minimal/issues/2280). Until it lands the
    // GitHub module's host set is the set, so a CONNECT to a registered store
    // authority is refused and audited `off_module`.
    let proxy = Proxy::new(
        Admission::new(&[GITHUB], [("", 0); 0]),
        Arc::new(NoSigningKey),
        roots,
        Arc::new(SystemResolver),
        Arc::new(Mutex::new(log)),
    )
    .map_err(|err| err.to_string())?;
    let proxy = Arc::new(proxy);
    let runtime = tokio::runtime::Runtime::new().map_err(|err| err.to_string())?;
    runtime.block_on(async {
        let listener = Listener::bind(&args.listener, token, Arc::new(PeerAttested))
            .map_err(|err| format!("bep did not listen on {}: {err}", args.listener.display()))?;
        // The proxy does not read this registry yet: it redeems no store
        // handles until the store rules join the admitted set. Until a later
        // task gives `Proxy` the same registry, a registration is kept here
        // and has no effect on what the proxy admits.
        let control_socket = Control::bind(&control, Registry::default())
            .map_err(|err| format!("bep did not listen on {}: {err}", control.display()))?;
        tracing::warn!(
            "no CA key can sign a leaf certificate yet, so every admitted CONNECT is answered 502. \
             A signing key (#2440) alone must not lift this: requests reach the upstream only \
             after the redemption decision is wired into the relay (#2272)"
        );
        tracing::info!(
            listener = %args.listener.display(),
            control = %control.display(),
            audit = %segment.display(),
            "the proxy is serving"
        );
        let served = tokio::select! {
            served = listener.run(move |delivery, stream| {
                let proxy = Arc::clone(&proxy);
                async move { proxy.serve(delivery, stream).await }
            }) => served,
            served = control_socket.run() => served,
        };
        served.map_err(|err| format!("bep stopped serving: {err}"))
    })
}

/// The per-boot token, 64 hex digits on the first line of `input`.
fn read_token(mut input: impl io::BufRead) -> Result<[u8; TOKEN_LEN], String> {
    let refused = || {
        format!(
            "bep serve did not get its connection token. Give it on standard input, as {} hex digits.",
            TOKEN_LEN * 2
        )
    };
    let mut line = String::new();
    input.read_line(&mut line).map_err(|_| refused())?;
    let hex = line.trim();
    if hex.len() != TOKEN_LEN * 2 || !hex.is_ascii() {
        return Err(refused());
    }
    let mut token = [0u8; TOKEN_LEN];
    for (byte, pair) in token.iter_mut().zip(hex.as_bytes().chunks(2)) {
        let pair = std::str::from_utf8(pair).map_err(|_| refused())?;
        *byte = u8::from_str_radix(pair, 16).map_err(|_| refused())?;
    }
    Ok(token)
}

fn identity_path(args: &Args) -> Result<PathBuf, &'static str> {
    args.identity
        .clone()
        .or_else(|| std::env::home_dir().map(|home| home.join(".minimal/bep/identity.json")))
        .ok_or("bep did not find your home directory. Give the file with `bep --identity <PATH>`.")
}
