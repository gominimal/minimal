//! The sign-in reference that a box with a GitHub grant carries, and the
//! box's registration with the Box Egress Proxy (BEP-003, BEP-005).
//!
//! On a host that is not enrolled, `min` mints one member for each GitHub
//! grant when it creates the box. The member is a sign-in reference: a
//! handle in the store-handle wire format ([`bep::handle`]), signed under
//! the client's key. The handle names the held sign-in item by the module
//! and the item's instance identifier. It carries the module's authorities
//! as its upstream set and no injection form, and it expires when the
//! proxy's root CA does. It carries no token. The proxy resolves the
//! reference against the sign-in item at each request.
//!
//! The client's key is made for each creation and held in memory only. It
//! is registered with the proxy over the proxy's control socket before any
//! handle signed under it leaves this process (BEP-063).
//!
//! The member is sealed from the proxy's published identity
//! ([`bep::publish`]): sealing is public-key work, so a mint never opens the
//! proxy's key store. The Box Host a value binds is the fingerprint of the
//! proxy's sealing key, which is the name `bep serve` redeems under.
//!
//! The same control socket then registers the box with its declared egress
//! and its address stance, so the proxy admits the box's requests to those
//! authorities.

use std::fmt;
use std::io::{self, BufRead as _, BufReader, Write as _};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bep::boxes::Stance;
use bep::control::{Reply, Request};
use bep::handle::{self, Claims};
use bep::module::{GITHUB, Module};
use bep::publish::{Identity, PublishError};
use bep::seal::{Breadth, Context, Member, MemberKind, MemberList, Mode};
use bep::signin::{Keychain, SignInError};
use p256::ecdsa::SigningKey;
use zeroize::Zeroizing;

/// How long a control socket request waits for the proxy.
const CONTROL_TIMEOUT: Duration = Duration::from_secs(10);

/// How long the forget of a failed creation waits for the proxy. It is
/// short, so a stuck proxy does not hold up the end of the creation.
const FORGET_TIMEOUT: Duration = Duration::from_secs(2);

/// `~/.minimal/bep/identity.json`, where the proxy publishes its keys.
#[must_use]
pub fn identity_path() -> Option<PathBuf> {
    std::env::home_dir().map(|home| home.join(".minimal/bep/identity.json"))
}

/// `~/.minimal/bep/control.sock`, the proxy's control socket.
#[must_use]
pub fn control_path() -> Option<PathBuf> {
    std::env::home_dir().map(|home| home.join(".minimal/bep/control.sock"))
}

/// Why a box's members were not minted, or the box was not registered.
#[derive(Debug)]
pub enum MintError {
    /// The host keychain did not give the sign-in item's metadata.
    SignIn(SignInError),
    /// No GitHub sign-in is held.
    NoSignIn,
    /// The proxy's published identity was not read, or is not usable.
    Identity {
        /// The identity file.
        path: PathBuf,
        /// Why.
        error: PublishError,
    },
    /// Nothing answers on the control socket.
    NotRunning {
        /// The control socket.
        path: PathBuf,
        /// Why.
        error: io::Error,
    },
    /// The control socket connection failed during a request.
    Control(io::Error),
    /// The proxy refused a request.
    Refused {
        /// What was asked.
        what: &'static str,
        /// The proxy's reason.
        error: String,
    },
    /// The box id is not 32 hex digits or a UUID.
    BoxId(String),
    /// The host has no random source for the client key or the handle id.
    Random,
}

impl fmt::Display for MintError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SignIn(error) => write!(
                f,
                "Cannot start the box: the GitHub sign-in was not read from the host keychain: {error}"
            ),
            // The same text as the refusal at creation (BEP-003).
            Self::NoSignIn => write!(
                f,
                "{}",
                boxes::core::bep::BepRefusal::SignInRequired { grants: Vec::new() }
            ),
            Self::Identity {
                path,
                error: PublishError::Io { source, .. },
            } if source.kind() == io::ErrorKind::NotFound => write!(
                f,
                "Cannot start the box: it declares a GitHub grant, and the Box Egress Proxy \
                 has not published its keys at {}.",
                path.display()
            ),
            Self::Identity { error, .. } => {
                write!(
                    f,
                    "Cannot start the box: it declares a GitHub grant. {error}"
                )
            }
            Self::NotRunning { path, error } => write!(
                f,
                "Cannot start the box: it declares a GitHub grant, and the Box Egress Proxy \
                 does not answer on {}: {error}.",
                path.display()
            ),
            Self::Control(error) => write!(
                f,
                "Cannot start the box: the connection to the Box Egress Proxy failed: {error}."
            ),
            Self::Refused { what, error } => write!(
                f,
                "Cannot start the box: the Box Egress Proxy refused to register {what}: {error}."
            ),
            Self::BoxId(id) => write!(
                f,
                "Cannot start the box: its id {id} is not one the Box Egress Proxy accepts."
            ),
            Self::Random => write!(
                f,
                "Cannot start the box: this machine gave no random bytes for the GitHub grant's key."
            ),
        }
    }
}

impl std::error::Error for MintError {}

/// The client's handle-signing key, made for one creation and held in
/// memory only.
///
/// Interim: a new key for each creation. The flip is T27
/// (https://github.com/gominimal/minimal/issues/2288), which keeps the
/// client's one local key and registers it with the proxy at first use and
/// across proxy restarts.
pub struct ClientKey(SigningKey);

impl fmt::Debug for ClientKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ClientKey").field(&self.kid()).finish()
    }
}

impl ClientKey {
    /// A new key from the operating system's random source.
    ///
    /// # Errors
    ///
    /// [`MintError::Random`] when the host gives no random bytes.
    pub fn generate() -> Result<Self, MintError> {
        // A random 32-byte string is a valid scalar except with negligible
        // odds. Draw again in that case.
        for _ in 0..8 {
            let mut bytes = Zeroizing::new([0u8; 32]);
            getrandom::fill(bytes.as_mut()).map_err(|_| MintError::Random)?;
            if let Ok(key) = SigningKey::from_bytes(&(*bytes).into()) {
                return Ok(Self(key));
            }
        }
        Err(MintError::Random)
    }

    /// The SEC1 encoding of the public half, unpadded base64url, as the
    /// control socket takes it.
    #[must_use]
    pub fn public(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.0.verifying_key().to_sec1_bytes())
    }

    /// The key's thumbprint, which a handle's `kid` carries.
    #[must_use]
    pub fn kid(&self) -> String {
        handle::kid(self.0.verifying_key())
    }
}

/// One connection to the proxy's control socket.
pub struct ControlClient {
    path: PathBuf,
    stream: BufReader<UnixStream>,
}

impl ControlClient {
    /// Connects to the control socket at `path`.
    ///
    /// # Errors
    ///
    /// [`MintError::NotRunning`] when nothing answers there.
    pub fn connect(path: &Path) -> Result<Self, MintError> {
        Self::connect_with_timeout(path, CONTROL_TIMEOUT)
    }

    /// Connects to the control socket at `path`, and waits at most
    /// `timeout` for each read and write.
    fn connect_with_timeout(path: &Path, timeout: Duration) -> Result<Self, MintError> {
        let not_running = |error| MintError::NotRunning {
            path: path.to_owned(),
            error,
        };
        let stream = UnixStream::connect(path).map_err(not_running)?;
        stream
            .set_read_timeout(Some(timeout))
            .map_err(not_running)?;
        stream
            .set_write_timeout(Some(timeout))
            .map_err(not_running)?;
        Ok(Self {
            path: path.to_owned(),
            stream: BufReader::new(stream),
        })
    }

    fn ask(&mut self, request: &Request, what: &'static str) -> Result<Reply, MintError> {
        let mut line = serde_json_lenient::to_string(request).map_err(|error| {
            MintError::Control(io::Error::new(io::ErrorKind::InvalidData, error))
        })?;
        line.push('\n');
        self.stream
            .get_mut()
            .write_all(line.as_bytes())
            .map_err(MintError::Control)?;
        let mut answer = String::new();
        let read = self
            .stream
            .read_line(&mut answer)
            .map_err(MintError::Control)?;
        if read == 0 {
            return Err(MintError::Control(io::ErrorKind::UnexpectedEof.into()));
        }
        let reply: Reply = serde_json_lenient::from_str(&answer).map_err(|error| {
            MintError::Control(io::Error::new(io::ErrorKind::InvalidData, error))
        })?;
        if reply.ok {
            Ok(reply)
        } else {
            Err(MintError::Refused {
                what,
                error: reply.error.unwrap_or_default(),
            })
        }
    }

    /// Registers `key` with the proxy, so it verifies handles signed under
    /// it (BEP-063).
    ///
    /// # Errors
    ///
    /// [`MintError::Control`] when the connection fails, and
    /// [`MintError::Refused`] when the proxy refuses the key.
    pub fn register_client_key(&mut self, key: &ClientKey) -> Result<(), MintError> {
        self.ask(
            &Request::RegisterClientKey { key: key.public() },
            "the box's signing key",
        )?;
        Ok(())
    }

    /// Tells the proxy to forget the box `box_id`.
    ///
    /// # Errors
    ///
    /// [`MintError::Control`] when the connection fails, and
    /// [`MintError::Refused`] when the proxy refuses the request.
    pub fn forget_box(&mut self, box_id: &str) -> Result<(), MintError> {
        self.ask(
            &Request::ForgetBox {
                box_id: box_id.to_owned(),
            },
            "the box's removal",
        )?;
        tracing::debug!(box_id, "withdrew the box's declared egress from the proxy");
        Ok(())
    }

    /// Registers the box `box_id` with its declared egress and its address
    /// stance.
    ///
    /// # Errors
    ///
    /// [`MintError::Control`] when the connection fails, and
    /// [`MintError::Refused`] when the proxy refuses the registration.
    pub fn register_box(
        &mut self,
        box_id: &str,
        egress: &[String],
        stance: Stance,
    ) -> Result<(), MintError> {
        self.ask(
            &Request::RegisterBox {
                box_id: box_id.to_owned(),
                egress: egress.to_vec(),
                stance,
            },
            "the box",
        )?;
        tracing::debug!(
            box_id,
            authorities = egress.len(),
            "registered the box's declared egress with the proxy"
        );
        Ok(())
    }
}

/// A box id as the proxy names a box: 32 lowercase hex digits. A UUID loses
/// its hyphens.
///
/// # Errors
///
/// [`MintError::BoxId`] for any other text.
pub fn box_id_hex(box_id: &str) -> Result<String, MintError> {
    let digits: String = box_id.trim().chars().filter(|c| *c != '-').collect();
    if digits.len() == 32 && digits.bytes().all(|b| b.is_ascii_hexdigit()) {
        Ok(digits.to_ascii_lowercase())
    } else {
        Err(MintError::BoxId(box_id.to_owned()))
    }
}

/// A unique handle id: 128 random bits as lowercase hex.
fn handle_id() -> Result<String, MintError> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| MintError::Random)?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

/// The authorities of `module`, each `host` or `host:port`, as a handle's
/// `upstream` carries them.
fn upstream(module: &Module) -> Vec<String> {
    module
        .hosts
        .iter()
        .map(|authority| {
            if authority.port == bep::module::HTTPS_PORT {
                authority.host.to_owned()
            } else {
                format!("{}:{}", authority.host, authority.port)
            }
        })
        .collect()
}

/// The claims of a sign-in reference for box `box_id` on Box Host `node`:
/// the module as its store, the sign-in's `instance` as its identifier, the
/// module's authorities as its upstream set, no injection form, and
/// `expiry` as its expiry.
#[must_use]
pub fn sign_in_claims(
    box_id: &str,
    node: &str,
    module: &Module,
    instance: &str,
    now: u64,
    expiry: u64,
    jti: String,
) -> Claims {
    Claims {
        sub: box_id.to_owned(),
        node_id: node.to_owned(),
        store: module.id.to_owned(),
        id: instance.to_owned(),
        upstream: upstream(module),
        inject: None,
        iat: now,
        exp: expiry,
        jti,
    }
}

/// One grant's sealed value.
pub struct Minted {
    /// The grant: the environment variable the value is for.
    pub grant: String,
    /// The sealed value. The create request carries it to the box, which
    /// holds it in the grant's environment variable (BEP-007).
    pub sealed: Zeroizing<String>,
    /// The member's expiry, in seconds since the Unix epoch: the end of the
    /// root CA's validity.
    pub expiry: u64,
}

impl fmt::Debug for Minted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Minted")
            .field("grant", &self.grant)
            .field("sealed", &"<redacted>")
            .field("expiry", &self.expiry)
            .finish()
    }
}

/// A box with GitHub grants, as the mint and the registration read it.
#[derive(Debug, Clone)]
pub struct GrantBox {
    /// The box id the host minted for this creation.
    pub box_id: String,
    /// The GitHub grants, by the environment variable each one lands in.
    pub grants: Vec<String>,
    /// The authorities the box's declared egress admits.
    pub egress: Vec<String>,
    /// The box's address stance.
    pub stance: Stance,
}

/// Mints and seals a sign-in reference for each of `grant_box`'s grants
/// under `key`, and registers the box and then the key with the proxy over
/// `control` (BEP-005, BEP-063). `now` is the time of the mint, in seconds
/// since the Unix epoch.
///
/// The client's key is registered last, after every other step succeeded,
/// so a failed mint leaves no key the proxy trusts and no box uses. When
/// the key's registration fails, the box is forgotten again, so a failed
/// mint leaves neither a key nor a box behind. The
/// sealed values leave this process only after this function returns, so
/// no handle is delivered under a key the proxy does not know. Nothing
/// here asks for a sign-in: the keychain gives the item's metadata only.
///
/// # Errors
///
/// [`MintError::NoSignIn`] when no sign-in is held, [`MintError::SignIn`]
/// when the keychain does not give it, [`MintError::Identity`] when the
/// identity has no usable sealing key or root validity, and the control
/// socket's errors.
pub fn mint_and_register(
    keychain: &dyn Keychain,
    identity: &Identity,
    identity_path: &Path,
    control: &mut ControlClient,
    key: &ClientKey,
    grant_box: &GrantBox,
    now: u64,
) -> Result<Vec<Minted>, MintError> {
    let box_id = box_id_hex(&grant_box.box_id)?;
    let held = keychain
        .metadata()
        .map_err(MintError::SignIn)?
        .ok_or(MintError::NoSignIn)?;
    let identity_error = |error| MintError::Identity {
        path: identity_path.to_owned(),
        error,
    };
    let sealing = identity
        .key(bep::keys::Role::Sealing)
        .map_err(identity_error)?;
    // BEP-005: the member lives as long as the root it is trusted under.
    let expiry = identity.root_not_after().map_err(identity_error)?;
    // The Box Host is the sealing key's fingerprint, the name `bep serve`
    // opens values under.
    let node = sealing.kid();

    let mut minted = Vec::with_capacity(grant_box.grants.len());
    for grant in &grant_box.grants {
        let claims = sign_in_claims(
            &box_id,
            &node,
            &GITHUB,
            &held.instance,
            now,
            expiry,
            handle_id()?,
        );
        let jws = Zeroizing::new(handle::sign(&key.0, &claims));
        let context = Context {
            box_id: box_id.clone(),
            host: node.clone(),
            module: GITHUB.id.to_owned(),
            host_set_version: GITHUB.host_set_version,
            mode: Mode::User,
            iat: now,
            expiry,
            kid: node.clone(),
        };
        let members = MemberList {
            members: vec![Member {
                kind: MemberKind::SignIn,
                breadth: Breadth::Full,
                jws,
                exp: Some(expiry),
            }],
            default_owner: None,
        };
        let sealed = Zeroizing::new(identity.seal(&context, &members).map_err(identity_error)?);
        tracing::info!(
            box_id = %box_id,
            module = GITHUB.id,
            expiry,
            "minted a GitHub sign-in reference"
        );
        minted.push(Minted {
            grant: grant.clone(),
            sealed,
            expiry,
        });
    }

    if let Err(error) = control.register_box(&box_id, &grant_box.egress, grant_box.stance) {
        // BEP-003: a reply that fails, a read timeout for one, can follow a
        // box the proxy stored. That connection can still carry the late
        // reply, so the forget goes over a new one.
        if !matches!(error, MintError::NotRunning { .. }) {
            forget_on_a_new_connection(&control.path, &box_id, "its registration failed");
        }
        return Err(error);
    }
    // BEP-063: the key is registered before a handle signed under it is
    // delivered. It goes last, so no failed step leaves it registered.
    // A failed key reply, a read timeout for one, can leave the late reply
    // on this connection, so the forget goes over a new one here too.
    if let Err(error) = control.register_client_key(key) {
        forget_on_a_new_connection(&control.path, &box_id, "its key was refused");
        return Err(error);
    }
    Ok(minted)
}

/// Tells the proxy at `path` to forget `box_id` over a new connection, so
/// no late reply to an earlier request reads as the forget's answer. A
/// forget that fails is logged with `after` as its cause.
fn forget_on_a_new_connection(path: &Path, box_id: &str, after: &str) {
    let forgot = ControlClient::connect_with_timeout(path, FORGET_TIMEOUT)
        .and_then(|mut fresh| fresh.forget_box(box_id));
    if let Err(forget) = forgot {
        tracing::warn!(
            box_id = %box_id,
            error = %forget,
            "the proxy did not forget the box after {after}"
        );
    }
}

/// A box the proxy holds for a creation that has not finished. Dropped
/// before [`ProxyRegistration::keep`], it tells the proxy to forget the
/// box, so a creation that fails after the mint leaves no declared egress
/// behind (BEP-003).
///
/// The client's key stays registered: the control socket has no request
/// that withdraws a key. The flip is T27
/// (https://github.com/gominimal/minimal/issues/2288).
///
/// The forget runs only on a failed creation. A Ctrl-C ends the process
/// in `std::process::exit`, which runs no destructor, so it leaves the box
/// at the proxy until the box's destroy forgets it
/// (https://github.com/gominimal/minimal/issues/2277). Inside a
/// tokio runtime it runs on a blocking thread, so it never holds up a
/// runtime worker. It waits at most [`FORGET_TIMEOUT`] for each read and
/// write.
#[must_use = "a dropped registration forgets the box at the proxy"]
#[derive(Debug)]
pub struct ProxyRegistration {
    control_path: PathBuf,
    box_id: Option<String>,
}

impl ProxyRegistration {
    /// A registration of the box `box_id` with the proxy that serves
    /// `control_path`.
    ///
    /// # Errors
    ///
    /// [`MintError::BoxId`] when `box_id` is not a box id.
    pub fn new(control_path: PathBuf, box_id: &str) -> Result<Self, MintError> {
        Ok(Self {
            control_path,
            box_id: Some(box_id_hex(box_id)?),
        })
    }

    /// Keeps the box at the proxy: the creation finished.
    pub fn keep(mut self) {
        self.box_id = None;
    }
}

impl Drop for ProxyRegistration {
    fn drop(&mut self) {
        let Some(box_id) = self.box_id.take() else {
            return;
        };
        let control_path = std::mem::take(&mut self.control_path);
        let forget = move || {
            let forgot = ControlClient::connect_with_timeout(&control_path, FORGET_TIMEOUT)
                .and_then(|mut control| control.forget_box(&box_id));
            if let Err(error) = forgot {
                tracing::warn!(
                    box_id = %box_id,
                    error = %error,
                    "the proxy did not forget the box after its creation failed"
                );
            }
        };
        match tokio::runtime::Handle::try_current() {
            // The runtime waits for its blocking threads before it shuts
            // down, so a runtime shutdown does not lose the forget. A
            // Ctrl-C exits the process with no drop, and #2277 forgets
            // that box at its destroy.
            Ok(runtime) => drop(runtime.spawn_blocking(forget)),
            Err(_) => forget(),
        }
    }
}
