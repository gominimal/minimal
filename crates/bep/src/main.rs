//! `bep`: the Box Egress Proxy on this host.
//!
//! At start it loads the proxy's keys from the host keychain, issues the
//! root certificate under the root key, and publishes the certificate with
//! the keys' public halves (BEP-013, BEP-059, BEP-072).
//! `bep --replace-key <role>` is the operator's command that replaces a key
//! (BEP-060). It needs no file and no other key, so it works when the proxy
//! itself does not start. After the replacement it publishes the new public
//! key, so a mint stops sealing to the old one. A new root key also gets a
//! new root certificate.
//!
//! `bep --rotate-signing` asks the running `bep serve` for a new signing
//! certificate under the unchanged root (BEP-061), and waits until it reports
//! one. The signing certificate lives in the serving proxy alone. A box
//! trusts the root alone, so nothing inside a running box changes.
//!
//! `bep serve` starts the proxy the same way, then serves box connections on
//! the listener socket ([`bep::listener`]), and client key and box
//! registrations on the control socket ([`bep::control`]). It reads the
//! per-boot token from standard input. With `--exit-on-stdin-close` it
//! stops when standard input closes, which is how a supervisor's death stops
//! it ([`bep::supervisor`]). Each request inside a box connection
//! goes to the redemption decision ([`bep::redeemer`]), which reads the
//! boxes the control socket registers. The root certificate the start
//! issued is the anchor of the CA that signs each leaf.

use std::io::{self, Read as _, Write as _};
use std::net::{TcpStream, ToSocketAddrs as _};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant, SystemTime};

use bep::audit::{self, AuditLog};
use bep::boxes::BoxRegistry;
use bep::ca::{Ca, CaError, CaKey, RootCertificate, Union};
use bep::control::{Control, Registry, RotationReply, RotationRequest};
use bep::forward::Redeemer;
use bep::keys::{self, HeldKey, KeyError, KeyStore, ProxyKeys, ReplaceError, Role};
use bep::listener::{Listener, PeerAttested, TOKEN_LEN};
use bep::module::GITHUB;
use bep::proxy::{self, Admission, AuditWriter, Proxy, SystemResolver};
use bep::publish::{Identity, PublishError, certificate_fingerprint};
use bep::redeemer::{BoxRedeemer, Revocations};
use bep::revoke;
use bep::signin::{self, HostKeychain, Keychain, RefreshError, Refreshed, TokenEndpoint};
use clap::{Parser, Subcommand};
use zeroize::{Zeroize as _, Zeroizing};

/// Runs the box egress proxy on this host.
#[derive(Debug, Parser)]
#[command(name = "bep")]
struct Args {
    /// Make a new key for ROLE and delete the old key. ROLE is sealing, root
    /// or signing.
    #[arg(long, value_name = "ROLE")]
    replace_key: Option<Role>,

    /// Make the running `bep serve` issue a new signing certificate under
    /// the same root certificate. Running boxes keep working, because they
    /// trust only the root.
    #[arg(long, conflicts_with = "replace_key")]
    rotate_signing: bool,

    /// The control socket of the `bep serve` to rotate. Give the same path
    /// as `bep serve --control`.
    /// [default: ~/.minimal/bep/control.sock]
    #[arg(long, value_name = "PATH", requires = "rotate_signing")]
    control: Option<PathBuf>,

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

    /// Stop serving when standard input closes. A supervisor keeps its end
    /// of the pipe open after the token, so the proxy stops when the
    /// supervisor exits, even when it is killed.
    #[arg(long)]
    exit_on_stdin_close: bool,
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
fn run<S: KeyStore>(store: &S, args: &Args) -> ExitCode
where
    S::Key: CaKey + Send + Sync + 'static,
{
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
    if args.rotate_signing {
        if args.command.is_some() {
            eprintln!(
                "`bep --rotate-signing` and `bep serve` do not run together. A running `bep serve` renews its own signing certificate before it expires."
            );
            return ExitCode::FAILURE;
        }
        // The signing CA lives in the serving proxy alone, so the rotation
        // happens there (BEP-061).
        let rotated = args
            .control
            .clone()
            .or_else(default_control)
            .ok_or_else(|| {
                "bep did not find your home directory. Give the socket with `bep --rotate-signing --control <PATH>`."
                    .to_string()
            })
            .and_then(|control| request_rotation(&control, ROTATE_TIMEOUT));
        return match rotated {
            Ok(report) => {
                println!("{report}");
                ExitCode::SUCCESS
            }
            Err(err) => {
                eprintln!("{err}");
                ExitCode::FAILURE
            }
        };
    }
    let started = start(store, &path).and_then(|(keys, root)| match &args.command {
        Some(Command::Serve(serve_args)) => serve(serve_args, keys, root),
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
fn replace_key<S: KeyStore>(store: &S, role: Role, path: &Path) -> ExitCode
where
    S::Key: CaKey,
{
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
    // BEP-005: only a new root key starts a known validity. A new sealing or
    // signing key leaves the root's end as the previous identity gave it.
    let root_made_at = if role == Role::Root {
        match unix_now() {
            Ok(now) => Some(now),
            Err(err) => {
                // The store already holds the new root key. A later `bep`
                // start publishes no validity end for a root it did not
                // make, so only a new replacement gives the root its end.
                eprintln!("{err}");
                eprintln!(
                    "The published identity was not changed, so it still names the old root key. Set the system clock, then run `bep --replace-key root` again."
                );
                return ExitCode::FAILURE;
            }
        }
    } else {
        None
    };
    let identity = Identity::after_replacement(store, role, &key, previous.as_ref())
        .with_root_validity(previous.as_ref(), root_made_at);
    // BEP-072: a new root key gets a new root certificate. Another role
    // keeps the certificate the identity already carries.
    let mut issued = true;
    let identity = if role == Role::Root {
        match identity
            .clone()
            .issuing_root(&key, registered_union(), SystemTime::now())
        {
            Ok((identity, root)) => {
                log_root(&root);
                identity
            }
            Err(err) => {
                // The public key is still published, so a mint never seals
                // to the deleted key. A later start issues the certificate.
                eprintln!("The new root key did not issue a root certificate: {err}.");
                issued = false;
                identity
            }
        }
    } else {
        identity
    };
    match identity.publish(path) {
        Ok(()) if !issued => {
            tracing::info!(path = %path.display(), "published the proxy identity with no root certificate");
            println!("Published the new public key to {}.", path.display());
            eprintln!(
                "The published identity has no root certificate, so boxes with a GitHub grant cannot be created. Correct the problem above, then run `bep` to issue the certificate."
            );
            ExitCode::FAILURE
        }
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

/// A proxy start: reads the published identity, loads the keys, issues the
/// root certificate, and publishes the certificate and the keys' public
/// halves again. Gives the loaded keys and the root certificate.
fn start<S: KeyStore>(
    store: &S,
    path: &Path,
) -> Result<(ProxyKeys<S::Key>, RootCertificate), String>
where
    S::Key: CaKey,
{
    // BEP-060: a role the identity names had a key before, so the start
    // refuses when the store lost it. With no file, `keys::load` still
    // refuses a lost key when the store holds a key for another role.
    let previous = match Identity::read(path) {
        Ok(identity) => Some(identity),
        Err(PublishError::Io { source, .. }) if source.kind() == io::ErrorKind::NotFound => None,
        Err(err) => return Err(err.to_string()),
    };
    let published = previous.as_ref().map(Identity::roles).unwrap_or_default();
    // BEP-005: the store keeps no creation time. A root key that the store
    // does not hold before `keys::load` is one this start generates, so its
    // validity starts now. A root key loaded from the store has an unknown
    // age, and its end rides the identity while the root key stays the same.
    let root_absent = matches!(store.find(Role::Root), Ok(None));
    // The clock is read before `keys::load`, so a clock fault stops the
    // start before it generates a root key with no known validity.
    let root_made_at = if root_absent { Some(unix_now()?) } else { None };
    let loaded = keys::load(store, &published).map_err(|err| err.to_string())?;
    // BEP-013, BEP-072: each start issues the root from the held root key,
    // so a changed set of registered names reaches the next box created.
    let (identity, root) = Identity::of(&loaded)
        .with_root_validity(previous.as_ref(), root_made_at)
        .issuing_root(&loaded.root, registered_union(), SystemTime::now())
        .map_err(root_refusal)?;
    log_root(&root);
    identity.publish(path).map_err(|err| err.to_string())?;
    tracing::info!(path = %path.display(), "published the proxy identity");
    Ok((loaded, root))
}

/// The names the root permits: the configured modules' hosts, less the
/// deny set. The store rules' authorities join them when
/// `[secret-store-rules]` is read at start, which is T25
/// (<https://github.com/gominimal/minimal/issues/2280>).
fn registered_union() -> Union {
    Union::new(&[GITHUB], [""; 0])
}

/// The one start line for the root certificate. It names the certificate's
/// fingerprint and the count of its permitted names, never a key.
fn log_root(root: &RootCertificate) {
    tracing::info!(
        fingerprint = %certificate_fingerprint(root.der()),
        permitted_names = root.union().names().count(),
        "issued the root CA certificate"
    );
}

/// What `bep --rotate-signing` prints when the rotation is done. It names
/// the signing certificate the rotation replaced and the one now in use. The
/// earlier task text fixes the last sentence (BEP-061).
fn rotated_signing(old_fingerprint: &str, new_fingerprint: &str) -> String {
    format!(
        "Signing certificate rotated from {old_fingerprint} to {new_fingerprint}. \
         Running boxes keep working; nothing inside them changes."
    )
}

/// How long `bep --rotate-signing` waits for the serving proxy to answer.
/// The rotation signs through the keychain, which can wait for a prompt.
const ROTATE_TIMEOUT: Duration = Duration::from_secs(60);

/// The control socket of `bep serve` when `--control` names none.
fn default_control() -> Option<PathBuf> {
    std::env::home_dir().map(|home| home.join(".minimal/bep/control.sock"))
}

/// `bep --rotate-signing`: asks the `bep serve` on the control socket
/// `control` to rotate its signing CA, and waits up to `timeout` for the
/// answer. Gives the line to print, which names the old and the new
/// fingerprint (BEP-061).
fn request_rotation(control: &Path, timeout: Duration) -> Result<String, String> {
    use std::io::BufRead as _;
    let socket = control.display();
    let mut stream = match std::os::unix::net::UnixStream::connect(control) {
        Ok(stream) => stream,
        Err(err)
            if matches!(
                err.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
            ) =>
        {
            return Err(format!(
                "The signing certificate was not rotated, because no `bep serve` listens on {socket}. \
                 Give the control socket of the running `bep serve` with `bep --rotate-signing --control <PATH>`. \
                 Each `bep serve` issues a new signing certificate when it starts."
            ));
        }
        Err(err) => {
            return Err(format!(
                "The signing certificate was not rotated, because bep did not connect to {socket}: {err}."
            ));
        }
    };
    let mut request =
        serde_json::to_vec(&RotationRequest::RotateSigning).map_err(|err| err.to_string())?;
    request.push(b'\n');
    let sent = stream
        .set_read_timeout(Some(timeout))
        .and_then(|()| stream.set_write_timeout(Some(timeout)))
        .and_then(|()| stream.write_all(&request));
    if let Err(err) = sent {
        return Err(format!(
            "The signing certificate was not rotated, because bep did not send the request to {socket}: {err}."
        ));
    }
    let mut line = String::new();
    match io::BufReader::new(&stream).read_line(&mut line) {
        Ok(0) => {
            return Err(format!(
                "The signing certificate was not rotated: `bep serve` on {socket} closed the connection with no answer. \
                 `bep serve` closes a connection from another user, and its log says why."
            ));
        }
        Ok(_) => {}
        Err(err)
            if matches!(
                err.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ) =>
        {
            return Err(format!(
                "`bep serve` on {socket} did not answer within {} seconds. \
                 The signing certificate can still rotate. The log of `bep serve` says if it did.",
                timeout.as_secs()
            ));
        }
        Err(err) => {
            return Err(format!(
                "bep did not read the answer of `bep serve` on {socket}: {err}. \
                 The log of `bep serve` says if the signing certificate rotated."
            ));
        }
    }
    let reply: RotationReply = serde_json::from_str(&line).map_err(|err| {
        format!(
            "bep did not understand the answer of `bep serve` on {socket}: {err}. \
             The log of `bep serve` says if the signing certificate rotated."
        )
    })?;
    match reply {
        RotationReply {
            ok: true,
            old_fingerprint: Some(old),
            new_fingerprint: Some(new),
            ..
        } => Ok(rotated_signing(&old, &new)),
        RotationReply {
            ok: false,
            error: Some(error),
            ..
        } => Err(format!("The signing certificate was not rotated: {error}.")),
        _ => Err(format!(
            "bep did not understand the answer of `bep serve` on {socket}. \
             The log of `bep serve` says if the signing certificate rotated."
        )),
    }
}

/// How long before the signing CA expires `bep serve` renews it.
const RENEW_BEFORE_EXPIRY: Duration = Duration::from_secs(30 * 24 * 60 * 60);

/// The longest `bep serve` sleeps before it checks the signing CA expiry
/// again.
const RENEW_CHECK: Duration = Duration::from_secs(60 * 60);

/// How long `bep serve` waits to try again after a renewal fails.
const RENEW_RETRY: Duration = Duration::from_secs(60 * 60);

/// How long to wait at `now` before the signing CA that ends at `expiry` is
/// due for renewal. Zero when it is due now.
fn renewal_wait(expiry: SystemTime, now: SystemTime) -> Duration {
    expiry
        .checked_sub(RENEW_BEFORE_EXPIRY)
        .and_then(|due| due.duration_since(now).ok())
        .unwrap_or(Duration::ZERO)
}

/// Renews the signing CA of a serving proxy before each expiry, so the
/// proxy keeps signing leaves past one signing CA validity. The root does
/// not change, so running boxes see no change (BEP-061). `Ca::renew_signing`
/// logs the old and the new fingerprint.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn keep_signing_renewed<K: CaKey + Send + Sync + 'static>(ca: Arc<Mutex<Ca<'static, K>>>) {
    let expiry_of = |ca: &Mutex<Ca<'static, K>>| {
        ca.lock()
            .unwrap_or_else(PoisonError::into_inner)
            .signing_expiry()
    };
    std::thread::spawn(move || {
        loop {
            let expiry = expiry_of(&ca);
            // Sleep in short steps and read the clock again after each. A
            // sleep does not count the time a machine is suspended, and a
            // rotation on request moves the expiry.
            let wait = renewal_wait(expiry, SystemTime::now());
            if !wait.is_zero() {
                std::thread::sleep(wait.min(RENEW_CHECK));
                continue;
            }
            let renewed = ca
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .renew_signing(SystemTime::now());
            match renewed {
                Ok(()) if expiry_of(&ca) > expiry => {}
                Ok(()) => {
                    // The signing CA never outlives the root, so a renewal
                    // near the root's end gains nothing. Stop here.
                    tracing::warn!(
                        root_expiry = ?expiry_of(&ca),
                        "the signing CA ends with the root CA; run `bep --replace-key root` before then"
                    );
                    return;
                }
                Err(CaError::RootExpired(at)) => {
                    tracing::error!(%at, "the signing CA did not renew: the root CA expired; run `bep --replace-key root`");
                    return;
                }
                Err(err) => {
                    tracing::warn!(error = %err, retry_secs = RENEW_RETRY.as_secs(), "the signing CA did not renew");
                    std::thread::sleep(RENEW_RETRY);
                }
            }
        }
    });
}

/// What a start says when the root key did not issue the root certificate.
fn root_refusal(err: CaError) -> String {
    match err {
        // BEP-060: a refused key gets the replacement command, in the same
        // words as a key refused at load.
        CaError::Key(KeyError::Refused { role, .. }) => keys::StartError::Unusable {
            refused: vec![role],
            missing: Vec::new(),
        }
        .to_string(),
        CaError::Key(err @ KeyError::Store { .. }) => format!(
            "The proxy did not start: the keychain did not sign the root certificate with the root key: {err}. \
             If the keychain is locked, unlock it and run `bep` again. \
             If it stays refused, run `bep --replace-key root` to make a new root key. Boxes created before then must be re-created."
        ),
        CaError::RootExpired(at) => format!(
            "The proxy did not start: the root CA expired at {at}. \
             Run `bep --replace-key root` to make a new root key. Boxes created before then must be re-created."
        ),
        other => format!("The proxy did not start: {other}."),
    }
}

/// The time now, in seconds since the Unix epoch. A clock that reads
/// before 1970 is an error, so the root's validity end never starts at 0.
fn unix_now() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|since| since.as_secs())
        .map_err(|_| {
            "This machine's clock reads a time before 1970, so the root key's validity cannot start. Set the system clock to the correct time.".to_owned()
        })
}

/// What `bep serve` shares between the control socket and the proxy: the
/// registered client keys, the registered boxes, and the redeemer that
/// reads both.
struct Wiring {
    clients: Registry,
    boxes: BoxRegistry,
    revocations: Revocations,
    redeemer: Arc<dyn Redeemer>,
}

/// The redeemer over the proxy key `sealing` and the sign-in item in
/// `keychain`, and the registries it reads. The Box Host a sealed value and
/// its handle name is this proxy's sealing key fingerprint, which the
/// published identity carries. `restored` is the box ids that the
/// revocations recorded before this start name.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn wire<K, C>(
    sealing: K,
    keychain: C,
    endpoint: Arc<dyn TokenEndpoint>,
    restored: Vec<String>,
) -> Wiring
where
    K: HeldKey + Send + Sync + 'static,
    C: Keychain + Send + Sync + 'static,
{
    let node = sealing.public().kid();
    let clients = Registry::default();
    // `min` sends `register_box` when it creates a box with a GitHub grant
    // (`crates/minimal/src/cmd/boxes/create.rs`). `minvmd` sends
    // `revoke_box` and then `forget_box` when a live box is destroyed
    // (`crates/minvmd/src/box_registry.rs`).
    let boxes = BoxRegistry::default();
    // The revocations `revoke_box` records over the control socket, which
    // the redeemer reads at each request (BEP-043, BEP-071). The set starts
    // with the revocations restored from every retained audit segment
    // (BEP-068).
    let revocations: Revocations = Arc::new(std::sync::RwLock::new(restored));
    //
    // Interim: the redeemer reads no store rules until T25
    // (https://github.com/gominimal/minimal/issues/2280) reads
    // `[secret-store-rules]`, so a store-handle member is never admitted yet.
    let redeemer = Arc::new(
        BoxRedeemer::new(
            sealing,
            node,
            GITHUB,
            Arc::clone(&clients),
            Arc::clone(&boxes),
            keychain,
        )
        .with_revocations(Arc::clone(&revocations))
        // BEP-069: an expiring sign-in renews here, at the proxy.
        .with_token_endpoint(endpoint),
    );
    Wiring {
        clients,
        boxes,
        revocations,
        redeemer,
    }
}

impl Wiring {
    /// `proxy`, with this redeemer as its per-request decision.
    fn install(&self, proxy: Proxy, control: &Path) -> Proxy {
        tracing::info!(
            registry = %control.display(),
            "installed the redemption decision; boxes register their declared egress on the control socket"
        );
        proxy.with_redeemer(Arc::clone(&self.redeemer))
    }

    /// The control socket at `path`, which registers into this wiring and
    /// appends its mint and revocation records to `audit`, the log the
    /// proxy's decisions go to (BEP-067).
    fn control(&self, path: &Path, audit: Arc<dyn AuditWriter>) -> io::Result<Control> {
        Ok(
            Control::bind(path, Arc::clone(&self.clients), Arc::clone(&self.boxes))?
                .with_revocations(Arc::clone(&self.revocations))
                .with_audit(audit),
        )
    }
}

/// Refuses the start when the audit log holds a complete line that does not
/// parse. That line can be a revocation, and a start without it redeems a
/// value for a destroyed box (BEP-068). The partial last line of a torn
/// write is cut when the log opens, so it is not counted here.
fn refuse_unreadable(restored: &revoke::Restored) -> Result<(), String> {
    if restored.skipped == 0 {
        return Ok(());
    }
    tracing::error!(
        skipped = restored.skipped,
        segments = ?restored.unreadable,
        "refused the start: audit log lines did not parse, and one can be a revocation"
    );
    let segments: Vec<String> = restored
        .unreadable
        .iter()
        .map(|path| format!("  {}", path.display()))
        .collect();
    let (lines, these) = if restored.skipped == 1 {
        ("1 line".to_owned(), "that line")
    } else {
        (format!("{} lines", restored.skipped), "those lines")
    };
    Err(format!(
        "bep did not start. The audit log has {lines} that bep cannot read, in:\n{}\n\
         A line that bep cannot read can record a destroyed box. \
         Without it, bep cannot keep refusing that box.\n\
         Repair or remove {these}, then run `bep serve` again.",
        segments.join("\n")
    ))
}

/// Opens the audit log in `dir` for `bep serve`. The log holds the
/// directory, so a second `bep serve` on it is refused.
fn open_audit_log(dir: &Path) -> Result<AuditLog, String> {
    AuditLog::open_dir(dir, audit::Rotation::default()).map_err(|err| {
        if err.kind() == io::ErrorKind::WouldBlock {
            tracing::error!(audit = %dir.display(), error = %err, "refused the start: the audit log has another writer");
            format!(
                "bep did not start. Another `bep serve` writes the audit log in {}.\n\
                 Only one `bep serve` can write the audit log at a time.\n\
                 Stop the other `bep serve`, then run `bep serve` again.",
                dir.display()
            )
        } else {
            format!("bep did not open the audit log in {}: {err}", dir.display())
        }
    })
}

/// `bep serve`: the listener and the control socket, until one fails.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn serve<K: CaKey + Send + Sync + 'static>(
    args: &ServeArgs,
    keys: ProxyKeys<K>,
    root: RootCertificate,
) -> Result<(), String> {
    let token = read_token(io::stdin().lock())?;
    // Watched from here, so a supervisor that dies while the proxy starts
    // stops it as soon as it serves (#2501).
    let supervisor = if args.exit_on_stdin_close {
        Some(
            bep::supervisor::watch_until_closed(io::stdin())
                .map_err(|err| format!("bep did not watch its standard input: {err}"))?,
        )
    } else {
        None
    };
    let control = args.control.clone().or_else(default_control).ok_or(
        "bep did not find your home directory. Give the socket with `bep serve --control <PATH>`.",
    )?;
    let dir = audit::default_dir()
        .ok_or("bep did not find your home directory, which holds the audit log.")?;
    // Locked first, so no other writer rotates the segments under the read.
    let log = open_audit_log(&dir)?;
    // BEP-068: the log rotates its segments, and the revocations in every
    // retained segment are in force again from this start.
    let restored = revoke::restore(&dir)
        .map_err(|err| format!("bep did not read the audit log in {}: {err}", dir.display()))?;
    tracing::info!(
        count = restored.box_ids.len(),
        box_ids = ?restored.box_ids,
        audit = %dir.display(),
        "restored the revocations recorded in the audit log"
    );
    refuse_unreadable(&restored)?;
    let segment = log.path().to_path_buf();
    let roots = proxy::native_roots()
        .map_err(|err| format!("bep did not load the host's root certificates: {err}."))?;
    // The store rules' authorities join the admitted set when
    // `[secret-store-rules]` is read at start, which is T25
    // (https://github.com/gominimal/minimal/issues/2280). Until it lands the
    // GitHub module's host set is the set, so a CONNECT to a registered store
    // authority is refused and audited `off_module`.
    let ProxyKeys {
        sealing,
        root: root_key,
        signing,
    } = keys;
    // The CA lives as long as the process, and it borrows its keys.
    let root_key: &'static K = Box::leak(Box::new(root_key));
    let signing: &'static K = Box::leak(Box::new(signing));
    // The published root is the anchor. The signing CA is issued under it.
    let ca = Ca::with_root(root_key, signing, root, SystemTime::now())
        .map_err(|err| format!("bep did not issue its signing CA: {err}."))?;
    let endpoint = GitHubTokenEndpoint::new(roots.clone())?;
    let ca = Arc::new(Mutex::new(ca));
    // One log, one writer: the proxy's decisions and the control socket's
    // mint and revocation records share the chain (BEP-067).
    let log: Arc<Mutex<AuditLog>> = Arc::new(Mutex::new(log));
    let proxy = Proxy::new(
        Admission::new(&[GITHUB], [("", 0); 0]),
        ca.clone(),
        roots,
        Arc::new(SystemResolver),
        log.clone(),
    )
    .map_err(|err| err.to_string())?;
    let wiring = wire(sealing, HostKeychain, Arc::new(endpoint), restored.box_ids);
    let proxy = Arc::new(wiring.install(proxy, &control));
    let runtime = tokio::runtime::Runtime::new().map_err(|err| err.to_string())?;
    runtime.block_on(async {
        keep_signing_renewed(Arc::clone(&ca));
        let listener = Listener::bind(&args.listener, token, Arc::new(PeerAttested))
            .map_err(|err| format!("bep did not listen on {}: {err}", args.listener.display()))?;
        // The redeemer reads the client keys and the boxes this socket
        // registers, at each request.
        // The same socket takes `bep --rotate-signing`, which rotates the
        // signing CA the proxy signs leaves with (BEP-061).
        let control_socket = wiring
            .control(&control, log)
            .map_err(|err| format!("bep did not listen on {}: {err}", control.display()))?
            .with_rotation(ca);
        tracing::warn!("A store-handle member is not admitted until #2280 lands.");
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
            closed = supervised(supervisor) => {
                match closed {
                    Ok(()) => tracing::info!("standard input closed, so the supervisor is gone; the proxy stops"),
                    Err(err) => tracing::warn!(%err, "standard input failed, so the supervisor is taken for gone; the proxy stops"),
                }
                Ok(())
            }
        };
        served.map_err(|err| format!("bep stopped serving: {err}"))
    })
}

/// Resolves when the supervisor's pipe closes, or never when `bep serve`
/// runs without `--exit-on-stdin-close`.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
async fn supervised(
    watch: Option<tokio::sync::oneshot::Receiver<bep::supervisor::Closed>>,
) -> bep::supervisor::Closed {
    match watch {
        // A watch thread that ended without a word cannot see the pipe any
        // more, so it counts as closed.
        Some(watch) => watch.await.unwrap_or(Ok(())),
        None => std::future::pending().await,
    }
}

/// The client id of the Minimal-published GitHub App. `min auth login`
/// signs in under the same id.
const GITHUB_APP_CLIENT_ID: &str = "Iv23liv6KetAFJp4Eb5K";

/// The App's client secret, embedded at build time from the
/// `MINIMAL_GITHUB_APP_CLIENT_SECRET` variable, as `min` embeds its own
/// (`BUILT_IN_SECRET` in `crates/minimal/src/cmd/auth.rs`). A browser-flow
/// sign-in renews under it (Gatehouse §6.10). A build without it renews
/// only device-flow sign-ins.
const BUILT_IN_SECRET: Option<&str> = option_env!("MINIMAL_GITHUB_APP_CLIENT_SECRET");

/// The environment variable that overrides [`BUILT_IN_SECRET`] at run time.
/// No launcher sets it: the embedded secret is the default, and this is for
/// a build or a test that runs under another App secret.
const CLIENT_SECRET_ENV: &str = "MINIMAL_GITHUB_APP_CLIENT_SECRET";

/// How long one renewal has, in all, to look up GitHub, connect, send and
/// read the answer.
const TOKEN_TIMEOUT: Duration = Duration::from_secs(30);

/// The largest answer the token endpoint reads.
const TOKEN_REPLY_MAX: usize = 64 * 1024;

/// GitHub's OAuth token endpoint, which renews a sign-in at the proxy from
/// its refresh token (BEP-069). A device-flow sign-in renews with the
/// client id alone. A browser-flow one also needs the client secret.
struct GitHubTokenEndpoint {
    host: &'static str,
    config: Arc<rustls::ClientConfig>,
    client_secret: Option<Zeroizing<String>>,
}

impl GitHubTokenEndpoint {
    /// The endpoint at `github.com`, trusting `roots`. The client secret is
    /// the one embedded at build time ([`BUILT_IN_SECRET`]). A non-empty
    /// [`CLIENT_SECRET_ENV`] at run time overrides it.
    ///
    /// # Errors
    ///
    /// When the TLS client is not built.
    fn new(roots: rustls::RootCertStore) -> Result<Self, String> {
        let run_time = std::env::var(CLIENT_SECRET_ENV).ok();
        let client_secret = client_secret(BUILT_IN_SECRET, run_time);
        if client_secret.is_none() {
            tracing::info!(
                env = CLIENT_SECRET_ENV,
                "this build embeds no GitHub App client secret and none was given; a browser-flow sign-in will not renew at the proxy"
            );
        }
        Self::with_secret(roots, client_secret)
    }

    /// The endpoint at `github.com`, trusting `roots`, with `client_secret`
    /// for a browser-flow sign-in.
    ///
    /// # Errors
    ///
    /// When the TLS client is not built.
    fn with_secret(
        roots: rustls::RootCertStore,
        client_secret: Option<Zeroizing<String>>,
    ) -> Result<Self, String> {
        let config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|err| format!("bep did not set up its connection to GitHub: {err}."))?
        .with_root_certificates(roots)
        .with_no_client_auth();
        Ok(Self {
            host: "github.com",
            config: Arc::new(config),
            client_secret,
        })
    }

    /// POST `body` to the token endpoint, and give the answer's status code
    /// and body.
    fn post(&self, body: &str) -> Result<(u16, Zeroizing<Vec<u8>>), String> {
        // One deadline for the whole exchange: the lookup, the connect, the
        // send and every read share TOKEN_TIMEOUT.
        let deadline = Instant::now() + TOKEN_TIMEOUT;
        let remaining = || {
            deadline
                .checked_duration_since(Instant::now())
                .filter(|d| !d.is_zero())
                .ok_or_else(|| format!("GitHub did not answer within {}s", TOKEN_TIMEOUT.as_secs()))
        };
        // The system lookup has no timeout of its own, so it runs on a thread
        // that the exchange stops waiting for at the deadline.
        let (tx, rx) = std::sync::mpsc::channel();
        let host = self.host;
        std::thread::Builder::new()
            .name("bep-token-dns".into())
            .spawn(move || {
                let _ = tx.send((host, 443).to_socket_addrs().map(|mut a| a.next()));
            })
            .map_err(|e| format!("{} was not looked up: {e}", self.host))?;
        let addr = rx
            .recv_timeout(remaining()?)
            .map_err(|_| format!("{} did not resolve in time", self.host))?
            .map_err(|e| format!("{} did not resolve: {e}", self.host))?
            .ok_or_else(|| format!("{} did not resolve", self.host))?;
        let tcp = TcpStream::connect_timeout(&addr, remaining()?)
            .map_err(|e| format!("{} was not reached: {e}", self.host))?;
        // The TLS handshake reads during the send, so both timeouts are set.
        let left = remaining()?;
        tcp.set_read_timeout(Some(left))
            .and_then(|()| tcp.set_write_timeout(Some(left)))
            .map_err(|e| e.to_string())?;
        let name = rustls::pki_types::ServerName::try_from(self.host)
            .map_err(|e| e.to_string())?
            .to_owned();
        let conn = rustls::ClientConnection::new(Arc::clone(&self.config), name)
            .map_err(|e| e.to_string())?;
        let mut tls = rustls::StreamOwned::new(conn, tcp);
        let request = Zeroizing::new(format!(
            "POST /login/oauth/access_token HTTP/1.1\r\nHost: {}\r\nAccept: application/json\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nUser-Agent: bep/{}\r\nConnection: close\r\n\r\n{body}",
            self.host,
            body.len(),
            env!("CARGO_PKG_VERSION"),
        ));
        tls.write_all(request.as_bytes())
            .and_then(|()| tls.flush())
            .map_err(|e| format!("the renewal was not sent: {e}"))?;
        let mut reply = Zeroizing::new(Vec::new());
        let mut chunk = Zeroizing::new([0u8; 4096]);
        loop {
            tls.sock
                .set_read_timeout(Some(remaining()?))
                .map_err(|e| e.to_string())?;
            match tls.read(&mut chunk[..]) {
                Ok(0) => break,
                Ok(n) => {
                    reply.extend_from_slice(&chunk[..n]);
                    if reply.len() > TOKEN_REPLY_MAX {
                        return Err("the answer is too large".into());
                    }
                }
                // A server that closes without a TLS close_notify ends the
                // answer here. `Connection: close` frames it.
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof && !reply.is_empty() => break,
                Err(e) => return Err(format!("the answer was not read: {e}")),
            }
        }
        parse_reply(&reply)
    }
}

/// The status code and body of an HTTP/1.1 answer that `Connection: close`
/// frames.
fn parse_reply(reply: &[u8]) -> Result<(u16, Zeroizing<Vec<u8>>), String> {
    let end = reply
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or("the answer has no complete head")?;
    let head = std::str::from_utf8(&reply[..end]).map_err(|_| "the answer head is not text")?;
    let status = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse().ok())
        .ok_or("the answer has no status code")?;
    let chunked = head.lines().skip(1).any(|l| {
        l.split_once(':').is_some_and(|(k, v)| {
            k.trim().eq_ignore_ascii_case("transfer-encoding")
                && v.trim().eq_ignore_ascii_case("chunked")
        })
    });
    let body = &reply[end + 4..];
    if !chunked {
        return Ok((status, Zeroizing::new(body.to_vec())));
    }
    let mut out = Zeroizing::new(Vec::new());
    let mut rest = body;
    loop {
        let line_end = rest
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or("a chunk has no size line")?;
        let size = std::str::from_utf8(&rest[..line_end])
            .ok()
            .and_then(|l| usize::from_str_radix(l.split(';').next()?.trim(), 16).ok())
            .ok_or("a chunk size does not parse")?;
        rest = &rest[line_end + 2..];
        if size == 0 {
            return Ok((status, out));
        }
        let data = rest.get(..size).ok_or("a chunk is cut short")?;
        out.extend_from_slice(data);
        rest = rest.get(size + 2..).ok_or("a chunk is cut short")?;
    }
}

/// `value`, form-urlencoded.
fn form_encode(value: &str) -> String {
    value
        .bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
                char::from(b).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

impl TokenEndpoint for GitHubTokenEndpoint {
    fn refresh(&self, flow: signin::Flow, refresh_token: &str) -> Result<Refreshed, RefreshError> {
        let body = self.refresh_body(flow, refresh_token)?;
        self.exchange(&body)
    }
}

impl GitHubTokenEndpoint {
    /// The form body of a refresh of `refresh_token`. A browser-flow sign-in
    /// carries the client secret, and without one the renewal is refused.
    fn refresh_body(
        &self,
        flow: signin::Flow,
        refresh_token: &str,
    ) -> Result<Zeroizing<String>, RefreshError> {
        let mut body = Zeroizing::new(format!(
            "client_id={GITHUB_APP_CLIENT_ID}&grant_type=refresh_token&refresh_token={}",
            form_encode(refresh_token)
        ));
        if flow == signin::Flow::Browser {
            let Some(secret) = &self.client_secret else {
                return Err(RefreshError::Failed(
                    "a browser-flow sign-in renews under the App's client secret, and this build has none"
                        .into(),
                ));
            };
            body.push_str("&client_secret=");
            body.push_str(&form_encode(secret));
        }
        Ok(body)
    }

    /// Send the refresh `body` to GitHub, and read the renewed token.
    fn exchange(&self, body: &str) -> Result<Refreshed, RefreshError> {
        #[derive(serde::Deserialize)]
        struct Reply {
            access_token: Option<String>,
            refresh_token: Option<String>,
            expires_in: Option<u64>,
            refresh_token_expires_in: Option<u64>,
            error: Option<String>,
        }
        let (status, reply) = self.post(body).map_err(RefreshError::Failed)?;
        let parsed: Reply = serde_json::from_slice(&reply).map_err(|_| {
            RefreshError::Failed(format!(
                "GitHub answered {status} with a body that is not a token"
            ))
        })?;
        if let Some(error) = parsed.error {
            return Err(RefreshError::Refused(error));
        }
        match parsed {
            Reply {
                access_token: Some(access_token),
                refresh_token: Some(refresh_token),
                expires_in: Some(expires_in),
                refresh_token_expires_in: Some(refresh_token_expires_in),
                ..
            } => Ok(Refreshed {
                access_token,
                refresh_token,
                expires_in,
                refresh_token_expires_in,
            }),
            mut other => {
                if let Some(t) = other.access_token.as_mut() {
                    t.zeroize();
                }
                if let Some(t) = other.refresh_token.as_mut() {
                    t.zeroize();
                }
                Err(RefreshError::Failed(format!(
                    "GitHub answered {status} without a complete token"
                )))
            }
        }
    }
}

/// The client secret the proxy renews under: a non-empty `run_time` value
/// overrides the `built_in` one, and an empty value counts as none.
fn client_secret(built_in: Option<&str>, run_time: Option<String>) -> Option<Zeroizing<String>> {
    run_time
        .filter(|s| !s.is_empty())
        .map(Zeroizing::new)
        .or_else(|| {
            built_in
                .filter(|s| !s.is_empty())
                .map(|s| Zeroizing::new(s.to_owned()))
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

#[cfg(test)]
mod tests {

    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use bep::audit::Decision;
    use bep::boxes::Stance;
    use bep::control::{Reply, Request};
    use bep::forward::Verdict;
    use bep::handle::{self, Claims};
    use bep::redeem::{Authority, RequestAuthority};
    use bep::seal::{self, Breadth, Context, Member, MemberKind, MemberList, Mode, ProxyPublicKey};
    use bep::signin::{Flow, Material, MemoryKeychain, Metadata};
    use p256::SecretKey;
    use p256::ecdsa::SigningKey;
    use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader};
    use tokio::net::UnixStream;
    use zeroize::Zeroizing;

    use super::*;
    use bep::ca::Leaf;
    use bep::proxy::LeafIssuer;

    // BEP-068: a line that does not parse can be a revocation, so the start
    // fails closed and names the segment that holds it.
    #[test]
    fn serve_refuses_start_on_unreadable_audit_line() {
        assert_eq!(refuse_unreadable(&revoke::Restored::default()), Ok(()));
        let restored = revoke::Restored {
            box_ids: Vec::new(),
            skipped: 2,
            unreadable: vec![PathBuf::from("/audit/audit-0.jsonl")],
        };
        let err = refuse_unreadable(&restored).unwrap_err();
        assert_eq!(
            err,
            "bep did not start. The audit log has 2 lines that bep cannot read, in:\n  \
             /audit/audit-0.jsonl\n\
             A line that bep cannot read can record a destroyed box. \
             Without it, bep cannot keep refusing that box.\n\
             Repair or remove those lines, then run `bep serve` again."
        );
    }

    // BEP-068: a second `bep serve` on the same audit directory is refused,
    // so two writers never fork the chain.
    #[test]
    fn serve_refuses_a_second_writer_of_the_audit_log() {
        let dir = tempfile::tempdir().unwrap();
        let audit = dir.path().join("audit");
        let first = open_audit_log(&audit).unwrap();
        let err = open_audit_log(&audit).unwrap_err();
        assert_eq!(
            err,
            format!(
                "bep did not start. Another `bep serve` writes the audit log in {}.\n\
                 Only one `bep serve` can write the audit log at a time.\n\
                 Stop the other `bep serve`, then run `bep serve` again.",
                audit.display()
            )
        );
        drop(first);
        open_audit_log(&audit).unwrap();
    }

    /// A leaf issuer that signs no leaf, so the test opens no tunnel.
    struct NoSigningKey;

    impl LeafIssuer for NoSigningKey {
        fn issue(&self, _hostname: &str, _now: SystemTime) -> Result<Leaf, CaError> {
            Err(CaError::Key(KeyError::Store {
                role: Role::Signing,
                detail: "the test signs no leaf".into(),
            }))
        }
    }

    const INSTANCE: &str = "0123456789abcdef0123456789abcdef";
    const TOKEN: &str = "ghu_serve_token";
    const BOX: &str = "0190f0e0a1b2c3d4e5f60718293a4b5c";

    /// A sealing key held in memory, in place of the Keychain's.
    struct TestKey(SecretKey);

    impl HeldKey for TestKey {
        fn role(&self) -> Role {
            Role::Sealing
        }

        fn public(&self) -> ProxyPublicKey {
            ProxyPublicKey::from_sec1_bytes(&self.0.public_key().to_sec1_bytes()).unwrap()
        }

        fn exportable(&self) -> bool {
            false
        }

        fn agree(&self, peer: &ProxyPublicKey) -> Result<Zeroizing<Vec<u8>>, KeyError> {
            let peer = p256::PublicKey::from_sec1_bytes(&peer.to_sec1_bytes()).unwrap();
            let shared = p256::ecdh::diffie_hellman(self.0.to_nonzero_scalar(), peer.as_affine());
            Ok(Zeroizing::new(shared.raw_secret_bytes().to_vec()))
        }

        fn probe(&self) -> Result<(), KeyError> {
            Ok(())
        }
    }

    /// A software CA key in place of a keychain key.
    struct CaTestKey {
        role: Role,
        pair: rcgen::KeyPair,
    }

    impl CaTestKey {
        fn new(role: Role) -> Self {
            Self {
                role,
                pair: rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap(),
            }
        }
    }

    impl HeldKey for CaTestKey {
        fn role(&self) -> Role {
            self.role
        }

        fn public(&self) -> ProxyPublicKey {
            ProxyPublicKey::from_sec1_bytes(self.pair.public_key_raw()).unwrap()
        }

        fn exportable(&self) -> bool {
            false
        }

        fn agree(&self, _peer: &ProxyPublicKey) -> Result<Zeroizing<Vec<u8>>, KeyError> {
            Err(KeyError::Store {
                role: self.role,
                detail: "a CA test key does no key agreement".into(),
            })
        }

        fn probe(&self) -> Result<(), KeyError> {
            Ok(())
        }
    }

    impl CaKey for CaTestKey {
        fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, KeyError> {
            rcgen::SigningKey::sign(&self.pair, msg).map_err(|err| KeyError::Store {
                role: self.role,
                detail: err.to_string(),
            })
        }
    }

    // BEP-061: `bep --rotate-signing` refuses when no `bep serve` listens on
    // the control socket. `bep serve` also renews its signing CA before it
    // expires.
    #[test]
    fn signing_ca_rotation_invisible_to_boxes() {
        let dir = tempfile::tempdir().unwrap();
        let control = dir.path().join("custom/one.sock");
        let refused = request_rotation(&control, ROTATE_TIMEOUT);
        assert_eq!(
            refused.unwrap_err(),
            format!(
                "The signing certificate was not rotated, because no `bep serve` listens on {}. \
                 Give the control socket of the running `bep serve` with `bep --rotate-signing --control <PATH>`. \
                 Each `bep serve` issues a new signing certificate when it starts.",
                control.display()
            )
        );

        let root_key = CaTestKey::new(Role::Root);
        let signing_key = CaTestKey::new(Role::Signing);
        let at = SystemTime::now();
        let root = bep::ca::issue_root(&root_key, registered_union(), at).unwrap();
        let ca = Ca::with_root(&root_key, &signing_key, root, at).unwrap();
        let expiry = ca.signing_expiry();
        let at = SystemTime::now();
        assert!(expiry > at + RENEW_BEFORE_EXPIRY);
        let wait = renewal_wait(expiry, at);
        assert!(wait > Duration::ZERO);
        assert_eq!(
            at + wait + RENEW_BEFORE_EXPIRY,
            expiry,
            "renewal is due before the signing CA expires"
        );
        assert_eq!(renewal_wait(expiry, expiry), Duration::ZERO);
    }

    /// A CA key that notes the thread of each signature.
    struct ThreadNotingKey {
        inner: CaTestKey,
        signed_on: Mutex<Vec<std::thread::ThreadId>>,
    }

    impl HeldKey for ThreadNotingKey {
        fn role(&self) -> Role {
            self.inner.role()
        }

        fn public(&self) -> ProxyPublicKey {
            self.inner.public()
        }

        fn exportable(&self) -> bool {
            self.inner.exportable()
        }

        fn agree(&self, peer: &ProxyPublicKey) -> Result<Zeroizing<Vec<u8>>, KeyError> {
            self.inner.agree(peer)
        }

        fn probe(&self) -> Result<(), KeyError> {
            self.inner.probe()
        }
    }

    impl CaKey for ThreadNotingKey {
        fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, KeyError> {
            self.signed_on
                .lock()
                .unwrap()
                .push(std::thread::current().id());
            self.inner.sign(msg)
        }
    }

    /// Whether `leaf` validates for `hostname` at `at` against `root` alone,
    /// as a box that holds only the root checks it.
    fn validates(
        root: &rustls::pki_types::CertificateDer<'_>,
        leaf: &Leaf,
        hostname: &str,
        at: SystemTime,
    ) -> bool {
        use rustls::pki_types::{ServerName, UnixTime};
        let anchors = [webpki::anchor_from_trusted_cert(root).unwrap()];
        let ee = webpki::EndEntityCert::try_from(&leaf.chain[0]).unwrap();
        let time = UnixTime::since_unix_epoch(at.duration_since(SystemTime::UNIX_EPOCH).unwrap());
        let path = ee.verify_for_usage(
            &[webpki::ring::ECDSA_P256_SHA256],
            &anchors,
            &leaf.chain[1..],
            time,
            webpki::KeyUsage::server_auth(),
            None,
            None,
        );
        let name = ServerName::try_from(hostname.to_owned()).unwrap();
        path.is_ok() && ee.verify_is_valid_for_subject_name(&name).is_ok()
    }

    // BEP-061: `bep --rotate-signing` reaches the serving proxy over its
    // control socket, which issues a new signing CA under the root it
    // already had. The command prints the old and the new fingerprint. A
    // leaf issued before the rotation and one issued after both validate
    // against the root a box holds. The keychain signature runs on a
    // blocking thread, never on a runtime thread.
    #[tokio::test(flavor = "current_thread")]
    async fn rotate_signing_over_control_socket_keeps_leaves_valid() {
        let runtime_thread = std::thread::current().id();
        let root_key: &'static ThreadNotingKey = Box::leak(Box::new(ThreadNotingKey {
            inner: CaTestKey::new(Role::Root),
            signed_on: Mutex::new(Vec::new()),
        }));
        let signing_key: &'static ThreadNotingKey = Box::leak(Box::new(ThreadNotingKey {
            inner: CaTestKey::new(Role::Signing),
            signed_on: Mutex::new(Vec::new()),
        }));
        let at = SystemTime::now();
        let root = bep::ca::issue_root(root_key, registered_union(), at).unwrap();
        let ca = Arc::new(Mutex::new(
            Ca::with_root(root_key, signing_key, root, at).unwrap(),
        ));
        let (box_trust, in_use, before) = {
            let ca = ca.lock().unwrap();
            let before = ca.issue_leaf("api.github.com", at).unwrap();
            (ca.root().clone(), ca.signing().clone(), before)
        };
        root_key.signed_on.lock().unwrap().clear();

        let dir = tempfile::tempdir().unwrap();
        let control = dir.path().join("bep/control.sock");
        let socket = Control::bind(&control, Registry::default(), BoxRegistry::default())
            .unwrap()
            .with_rotation(Arc::clone(&ca) as _);
        tokio::spawn(socket.run());

        let asking = control.clone();
        let printed =
            tokio::task::spawn_blocking(move || request_rotation(&asking, ROTATE_TIMEOUT))
                .await
                .unwrap()
                .unwrap();

        let (signing_now, after) = {
            let ca = ca.lock().unwrap();
            assert_eq!(*ca.root(), box_trust, "the root changed");
            let after = ca.issue_leaf("api.github.com", SystemTime::now()).unwrap();
            (ca.signing().clone(), after)
        };
        assert_ne!(signing_now, in_use, "the signing CA did not rotate");
        assert_eq!(
            printed,
            format!(
                "Signing certificate rotated from {} to {}. \
                 Running boxes keep working; nothing inside them changes.",
                certificate_fingerprint(&in_use),
                certificate_fingerprint(&signing_now)
            )
        );
        assert_eq!(before.chain[1], in_use);
        assert_eq!(after.chain[1], signing_now);
        let check_at = SystemTime::now();
        assert!(
            validates(&box_trust, &before, "api.github.com", check_at),
            "the leaf issued before the rotation no longer validates against the root"
        );
        assert!(
            validates(&box_trust, &after, "api.github.com", check_at),
            "the leaf issued after the rotation does not validate against the root"
        );

        let signed_on = root_key.signed_on.lock().unwrap().clone();
        assert!(!signed_on.is_empty(), "the rotation signed nothing");
        assert!(
            signed_on.iter().all(|thread| *thread != runtime_thread),
            "the rotation signed on the runtime thread"
        );

        // A control socket that holds no CA refuses the rotation.
        let bare = dir.path().join("bare/control.sock");
        let socket = Control::bind(&bare, Registry::default(), BoxRegistry::default()).unwrap();
        tokio::spawn(socket.run());
        let refused = tokio::task::spawn_blocking(move || request_rotation(&bare, ROTATE_TIMEOUT))
            .await
            .unwrap();
        assert_eq!(
            refused.unwrap_err(),
            "The signing certificate was not rotated: this proxy does not rotate its signing certificate."
        );
    }

    fn now() -> u64 {
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    async fn ask(stream: &mut BufReader<UnixStream>, request: &Request) -> Reply {
        let mut line = serde_json::to_string(request).unwrap();
        line.push('\n');
        stream.get_mut().write_all(line.as_bytes()).await.unwrap();
        let mut reply = String::new();
        stream.read_line(&mut reply).await.unwrap();
        serde_json::from_str(&reply).unwrap()
    }

    // BEP-019, BEP-022, BEP-025: `bep serve` gives the proxy the redeemer,
    // and the redeemer reads the client keys and the boxes that the control
    // socket registers.
    #[tokio::test]
    async fn serve_installs_the_redeemer_and_registry() {
        let key = TestKey(SecretKey::from_slice(&[5u8; 32]).unwrap());
        let sealing = key.public();
        let keychain = MemoryKeychain::default();
        let now = now();
        keychain
            .write(
                &Metadata {
                    account: "octocat".into(),
                    instance: INSTANCE.into(),
                    flow: Flow::Device,
                    token_expires_at: now + 3600,
                    refresh_expires_at: now + 7200,
                },
                &Material {
                    instance: INSTANCE.into(),
                    access_token: TOKEN.into(),
                    refresh_token: "ghr_refresh".into(),
                },
            )
            .unwrap();
        let wiring = wire(key, keychain, Arc::new(signin::NoTokenEndpoint), Vec::new());

        let proxy = Proxy::new(
            Admission::new(&[GITHUB], [("", 0); 0]),
            Arc::new(NoSigningKey),
            rustls::RootCertStore::empty(),
            Arc::new(SystemResolver),
            Arc::new(Mutex::new(Vec::<Decision>::new())),
        )
        .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bep/control.sock");
        let _proxy = wiring.install(proxy, &path);
        tokio::spawn(
            wiring
                .control(&path, Arc::new(Mutex::new(Vec::<Decision>::new())))
                .unwrap()
                .run(),
        );

        let client = SigningKey::from_bytes(&[3u8; 32].into()).unwrap();
        let mut stream = BufReader::new(UnixStream::connect(&path).await.unwrap());
        let registered = ask(
            &mut stream,
            &Request::RegisterClientKey {
                key: URL_SAFE_NO_PAD.encode(client.verifying_key().to_sec1_bytes()),
            },
        )
        .await;
        assert!(registered.ok, "{registered:?}");
        let registered = ask(
            &mut stream,
            &Request::RegisterBox {
                box_id: BOX.into(),
                egress: vec!["api.github.com".into()],
                stance: Stance::OwnIp,
            },
        )
        .await;
        assert!(registered.ok, "{registered:?}");

        let api = Authority {
            host: "api.github.com".to_owned(),
            port: 443,
        };
        assert_eq!(wiring.redeemer.egress(BOX), vec![api.clone()]);

        // The value and its handle name this proxy's sealing key
        // fingerprint as the Box Host.
        let node = sealing.kid();
        let jws = handle::sign(
            &client,
            &Claims {
                sub: BOX.into(),
                node_id: node.clone(),
                store: GITHUB.id.into(),
                id: INSTANCE.into(),
                upstream: vec!["api.github.com".into()],
                inject: None,
                iat: now,
                exp: now + 3600,
                jti: "jti".into(),
            },
        );
        let sealed = seal::seal(
            &sealing,
            &Context {
                box_id: BOX.into(),
                host: node,
                module: GITHUB.id.into(),
                host_set_version: GITHUB.host_set_version,
                mode: Mode::User,
                iat: now,
                expiry: now + 600,
                kid: sealing.kid(),
            },
            &MemberList {
                members: vec![Member {
                    kind: MemberKind::SignIn,
                    breadth: Breadth::Full,
                    jws: Zeroizing::new(jws),
                    exp: None,
                }],
                default_owner: None,
            },
        )
        .unwrap();
        let request = RequestAuthority {
            host: Some(api.clone()),
            target: None,
        };
        match wiring.redeemer.redeem(BOX, &api, &request, &sealed) {
            Verdict::Admit { credential, .. } => assert_eq!(credential.as_str(), TOKEN),
            Verdict::Refuse(marker) => panic!("refused {marker}"),
        }

        // At destroy the box is forgotten, and its value is refused.
        let forgot = ask(&mut stream, &Request::ForgetBox { box_id: BOX.into() }).await;
        assert!(forgot.ok, "{forgot:?}");
        assert!(wiring.redeemer.egress(BOX).is_empty());
        assert!(matches!(
            wiring.redeemer.redeem(BOX, &api, &request, &sealed),
            Verdict::Refuse("no_live_box")
        ));
    }

    /// #2501: a supervisor asks for the lifeline with a flag, so a person
    /// who pipes the token in by hand keeps a proxy that outlives the pipe.
    #[test]
    fn serve_watches_standard_input_only_when_asked() {
        let parsed = |extra: &[&str]| {
            let args = Args::try_parse_from(
                ["bep", "serve", "--listener", "/tmp/bep.sock"]
                    .into_iter()
                    .chain(extra.iter().copied()),
            )
            .expect("the arguments parse");
            match args.command {
                Some(Command::Serve(serve)) => serve.exit_on_stdin_close,
                None => panic!("no serve command"),
            }
        };
        assert!(!parsed(&[]), "a hand-run proxy outlives its input");
        assert!(parsed(&["--exit-on-stdin-close"]));
    }

    /// #2501: the serve loop stops when the supervisor's pipe closes, and
    /// never on that branch without the flag.
    #[tokio::test]
    async fn the_serve_loop_stops_when_the_supervisor_pipe_closes() {
        let quiet = std::time::Duration::from_millis(200);
        assert!(
            tokio::time::timeout(quiet, supervised(None)).await.is_err(),
            "with no watch, the branch never fires"
        );

        let (reader, writer) = io::pipe().expect("pipe");
        let watch = bep::supervisor::watch_until_closed(reader).expect("watch");
        let mut stop = Box::pin(supervised(Some(watch)));
        assert!(
            tokio::time::timeout(quiet, &mut stop).await.is_err(),
            "an open pipe keeps the proxy serving"
        );
        drop(writer);
        let closed = tokio::time::timeout(std::time::Duration::from_secs(10), stop)
            .await
            .expect("a closed pipe stops the proxy");
        assert!(closed.is_ok(), "{closed:?}");
    }

    // BEP-069 (Gatehouse §6.10): a browser-flow sign-in renews under the
    // App secret that the build embeds. With no secret, the renewal is
    // refused `github_sign_in_required` before GitHub is called. With one,
    // the exchange carries it. A run-time value overrides the embedded one.
    #[test]
    fn a_browser_sign_in_renews_under_the_embedded_secret() {
        let keychain = MemoryKeychain::default();
        keychain
            .write(
                &Metadata {
                    account: "octocat".into(),
                    instance: INSTANCE.into(),
                    flow: Flow::Browser,
                    token_expires_at: 1_000,
                    refresh_expires_at: 100_000,
                },
                &Material {
                    instance: INSTANCE.into(),
                    access_token: "ghu_held".into(),
                    refresh_token: "ghr_held".into(),
                },
            )
            .unwrap();
        let unset = GitHubTokenEndpoint::with_secret(
            rustls::RootCertStore::empty(),
            client_secret(None, None),
        )
        .unwrap();
        // `RenewError::SignInRequired` is the refusal the proxy audits as
        // `github_sign_in_required`.
        assert_eq!(
            signin::renew(&keychain, &unset, INSTANCE, 2_000).unwrap_err(),
            signin::RenewError::SignInRequired
        );
        assert!(unset.refresh_body(Flow::Browser, "ghr_held").is_err());
        let device = unset.refresh_body(Flow::Device, "ghr_held").unwrap();
        assert!(!device.contains("client_secret"), "{}", *device);

        let set = GitHubTokenEndpoint::with_secret(
            rustls::RootCertStore::empty(),
            client_secret(Some("embedded+secret"), None),
        )
        .unwrap();
        let body = set.refresh_body(Flow::Browser, "ghr_held").unwrap();
        assert!(
            body.contains("&client_secret=embedded%2Bsecret"),
            "{}",
            *body
        );
        assert!(body.contains("refresh_token=ghr_held"), "{}", *body);

        let chosen = |built_in, run_time: Option<&str>| {
            client_secret(built_in, run_time.map(str::to_owned)).map(|s| s.to_string())
        };
        assert_eq!(chosen(Some("embedded"), None).as_deref(), Some("embedded"));
        assert_eq!(
            chosen(Some("embedded"), Some("override")).as_deref(),
            Some("override")
        );
        assert_eq!(
            chosen(Some("embedded"), Some("")).as_deref(),
            Some("embedded")
        );
        assert_eq!(chosen(Some(""), None), None);
        assert_eq!(chosen(None, None), None);
    }
}
