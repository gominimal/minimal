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
//! the listener socket ([`bep::listener`]), and client key and box
//! registrations on the control socket ([`bep::control`]). It reads the
//! per-boot token from standard input. Each request inside a box connection
//! goes to the redemption decision ([`bep::redeemer`]), which reads the
//! boxes the control socket registers.

use std::io;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use bep::audit::{self, AuditLog};
use bep::boxes::BoxRegistry;
use bep::ca::{CaError, Leaf};
use bep::control::{Control, Registry};
use bep::forward::Redeemer;
use bep::keys::{self, HeldKey, KeyError, KeyStore, ProxyKeys, ReplaceError, Role};
use bep::listener::{Listener, PeerAttested, TOKEN_LEN};
use bep::module::GITHUB;
use bep::proxy::{self, Admission, LeafIssuer, Proxy, SystemResolver};
use bep::publish::{Identity, PublishError};
use bep::redeemer::BoxRedeemer;
use bep::signin::{HostKeychain, Keychain};
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
fn run<S: KeyStore>(store: &S, args: &Args) -> ExitCode
where
    S::Key: Send + Sync + 'static,
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
    let started = start(store, &path).and_then(|keys| match &args.command {
        Some(Command::Serve(serve_args)) => serve(serve_args, keys.sealing),
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
    match identity.publish(path) {
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
/// publishes their public halves again. Gives the loaded keys.
fn start<S: KeyStore>(store: &S, path: &Path) -> Result<ProxyKeys<S::Key>, String> {
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
    Identity::of(&loaded)
        .with_root_validity(previous.as_ref(), root_made_at)
        .publish(path)
        .map_err(|err| err.to_string())?;
    tracing::info!(path = %path.display(), "published the proxy identity");
    Ok(loaded)
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

/// The leaf issuer `bep serve` has today. The root and signing CA keys are
/// in the Keychain, but no Keychain key can sign a certificate yet
/// (<https://github.com/gominimal/minimal/issues/2440>). Until one can,
/// every leaf is refused, and the proxy answers an admitted CONNECT with
/// `502`.
///
/// This issuer signs no leaf, so no tunnel opens and no request inside one
/// reaches the redeemer that [`wire`] installs.
struct NoSigningKey;

impl LeafIssuer for NoSigningKey {
    fn issue(&self, _hostname: &str, _now: SystemTime) -> Result<Leaf, CaError> {
        Err(CaError::Key(KeyError::Store {
            role: Role::Signing,
            detail: "the Keychain key cannot sign certificates in this version of bep".into(),
        }))
    }
}

/// What `bep serve` shares between the control socket and the proxy: the
/// registered client keys, the registered boxes, and the redeemer that
/// reads both.
struct Wiring {
    clients: Registry,
    boxes: BoxRegistry,
    redeemer: Arc<dyn Redeemer>,
}

/// The redeemer over the proxy key `sealing` and the sign-in item in
/// `keychain`, and the registries it reads. The Box Host a sealed value and
/// its handle name is this proxy's sealing key fingerprint, which the
/// published identity carries.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn wire<K, C>(sealing: K, keychain: C) -> Wiring
where
    K: HeldKey + Send + Sync + 'static,
    C: Keychain + Send + Sync + 'static,
{
    let node = sealing.public().kid();
    let clients = Registry::default();
    // `min` sends `register_box` when it creates a box with a GitHub grant
    // (`crates/minimal/src/cmd/boxes/create.rs`). Interim: nothing sends
    // `forget_box` at destroy until T20
    // (https://github.com/gominimal/minimal/issues/2277), in
    // `crates/minvmd/src/box_registry.rs`.
    let boxes = BoxRegistry::default();
    // Interim: `BoxRedeemer::new` starts with no revocation in force, and
    // nothing here gives it one. T20
    // (https://github.com/gominimal/minimal/issues/2277) records revocations
    // over the control socket. T33
    // (https://github.com/gominimal/minimal/issues/2290) restores them from
    // every retained audit segment at start, the BEP-068 restore-on-start
    // sub-requirement. Those two are the flip.
    //
    // Interim: the redeemer reads no store rules until T25
    // (https://github.com/gominimal/minimal/issues/2280) reads
    // `[secret-store-rules]`, so a store-handle member is never admitted yet.
    let redeemer = Arc::new(BoxRedeemer::new(
        sealing,
        node,
        GITHUB,
        Arc::clone(&clients),
        Arc::clone(&boxes),
        keychain,
    ));
    Wiring {
        clients,
        boxes,
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

    /// The control socket at `path`, which registers into this wiring.
    fn control(&self, path: &Path) -> io::Result<Control> {
        Control::bind(path, Arc::clone(&self.clients), Arc::clone(&self.boxes))
    }
}

/// `bep serve`: the listener and the control socket, until one fails.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn serve<K: HeldKey + Send + Sync + 'static>(args: &ServeArgs, sealing: K) -> Result<(), String> {
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
    let wiring = wire(sealing, HostKeychain);
    let proxy = Arc::new(wiring.install(proxy, &control));
    let runtime = tokio::runtime::Runtime::new().map_err(|err| err.to_string())?;
    runtime.block_on(async {
        let listener = Listener::bind(&args.listener, token, Arc::new(PeerAttested))
            .map_err(|err| format!("bep did not listen on {}: {err}", args.listener.display()))?;
        // The redeemer reads the client keys and the boxes this socket
        // registers, at each request.
        let control_socket = wiring
            .control(&control)
            .map_err(|err| format!("bep did not listen on {}: {err}", control.display()))?;
        tracing::warn!(
            "no CA key can sign a leaf certificate yet (#2440), so every admitted CONNECT is answered 502. \
             A token that renews at the proxy is refused github_sign_in_required until #2279 lands. \
             A store-handle member is not admitted until #2280 lands. \
             No revocation is in force until #2277 and #2290 land. \
             Nothing forgets a destroyed box's declared egress until #2277 lands."
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
        let wiring = wire(key, keychain);

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
        tokio::spawn(wiring.control(&path).unwrap().run());

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
}
