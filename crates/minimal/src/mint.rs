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
//! A store reference is a handle of the same wire format, signed under the
//! same key: the store, the item's identifier, the rule's registered
//! authorities and injection form, and the root CA's validity end as its
//! expiry ([`mint_store_handle`], BEP-063).
//!
//! The client's key is registered with the proxy over the proxy's control
//! socket before any handle signed under it leaves this process (BEP-063).
//! The proxy keeps the registration across its restarts. The target is one
//! local key that a [`ClientKeyStore`] keeps. When the store refuses this
//! program that key, [`local_client_key`] replaces it, and the mint registers
//! the replacement before it delivers a handle.
//!
//! Box creation reads that key from the host keychain
//! ([`HostClientKeyStore`]), so every creation signs under one key and the
//! proxy keeps one registration for this client.
//! [`mint_store_handle`] has no caller yet: the sealed member list has no
//! `store` kind to carry a handle to the box.
//! <https://github.com/gominimal/minimal/issues/2525> owns that kind, and
//! <https://github.com/gominimal/minimal/issues/2526> owns the
//! `min box spec` store references.
//!
//! A mint refuses a root CA whose validity ended: every handle minted under
//! it would be expired already.
//!
//! The member is sealed from the proxy's published identity
//! ([`bep::publish`]): sealing is public-key work, so a mint never opens the
//! proxy's key store. The Box Host a value binds is the fingerprint of the
//! proxy's sealing key, which is the name `bep serve` redeems under.
//!
//! The same control socket then registers the box with its declared egress
//! and its address stance, so the proxy admits the box's requests to those
//! authorities. Last, it records one `mint` record per member in the
//! proxy's audit log, the log the proxy's decisions go to (BEP-067).

use std::fmt;
use std::io::{self, BufRead as _, BufReader, Write as _};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bep::boxes::Stance;
use bep::control::{Reply, Request};
use bep::handle::{self, Claims, StoreRule};
use bep::module::{GITHUB, Module};
use bep::publish::{Identity, PublishError};
use bep::seal::{Breadth, Context, Member, MemberKind, MemberList, Mode};
use bep::signin::{Keychain, SignInError};
use p256::ecdsa::SigningKey;
use zeroize::{Zeroize as _, Zeroizing};

/// How long a control socket request waits for the proxy.
const CONTROL_TIMEOUT: Duration = Duration::from_secs(10);

/// How long the forget of a failed creation waits for the proxy. It is
/// short, so a stuck proxy does not hold up the end of the creation.
const FORGET_TIMEOUT: Duration = Duration::from_secs(2);

/// What a refused client key registration names, in [`MintError::Refused`].
const CLIENT_KEY: &str = "this client's signing key";

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
    /// The root CA's validity ended at or before the mint.
    RootExpired,
    /// The client key store failed for a reason other than a refusal.
    KeyStore(String),
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
            // The exact text the task fixes for a refused key registration.
            // The proxy's reason goes to the log.
            Self::Refused { what, .. } if *what == CLIENT_KEY => write!(
                f,
                "The proxy did not accept this client's signing key, so the box was not created."
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
            Self::RootExpired => write!(
                f,
                "Cannot start the box: the Box Egress Proxy's root certificate is expired. \
                 Run `bep --replace-key root` to make a new one."
            ),
            Self::KeyStore(detail) => write!(
                f,
                "Cannot start the box: the host keychain did not give this client's signing key: {detail}."
            ),
        }
    }
}

impl std::error::Error for MintError {}

/// The client's handle-signing key. [`local_client_key`] gives the one key a
/// [`ClientKeyStore`] keeps, and box creation reads it from
/// [`HostClientKeyStore`].
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

    /// The key from its 32-byte secret scalar, as a [`ClientKeyStore`] keeps
    /// it. `None` when the bytes are not a valid scalar.
    #[must_use]
    pub fn from_secret(bytes: &[u8; 32]) -> Option<Self> {
        SigningKey::from_bytes(&(*bytes).into()).ok().map(Self)
    }

    /// The 32-byte secret scalar, for a [`ClientKeyStore`] to keep.
    #[must_use]
    pub fn secret(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.0.to_bytes().into())
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

/// Why a [`ClientKeyStore`] did not give the client's key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientKeyError {
    /// The store holds the key and refused this program its use.
    Refused(String),
    /// The store failed for another reason, as a locked keychain does.
    Store(String),
}

/// The store that keeps the client's one handle-signing key across
/// creations, the host keychain on a laptop.
pub trait ClientKeyStore {
    /// The key the store keeps, or `None` when it keeps none.
    ///
    /// # Errors
    ///
    /// [`ClientKeyError::Refused`] when the store holds a key and refuses
    /// it to this program.
    fn find(&self) -> Result<Option<ClientKey>, ClientKeyError>;

    /// Keeps `key` in place of any key the store holds.
    ///
    /// # Errors
    ///
    /// [`ClientKeyError::Store`] when the store does not keep it.
    fn replace(&self, key: &ClientKey) -> Result<(), ClientKeyError>;
}

/// The client's local key from `store`. A store that keeps no key gets a
/// new one. A store that refuses this program its key gets a replacement
/// (BEP-063): the key signs handles only, and every mint registers the key
/// it signs under, so the replacement needs no step from the operator.
///
/// # Errors
///
/// [`MintError::Random`] when the host gives no random bytes, and
/// [`MintError::KeyStore`] when the store fails for another reason.
pub fn local_client_key(store: &dyn ClientKeyStore) -> Result<ClientKey, MintError> {
    let store_error = |error| match error {
        ClientKeyError::Refused(detail) | ClientKeyError::Store(detail) => {
            MintError::KeyStore(detail)
        }
    };
    match store.find() {
        Ok(Some(key)) => return Ok(key),
        Ok(None) => {}
        Err(ClientKeyError::Refused(detail)) => {
            tracing::warn!(%detail, "the keychain refused the client's signing key; replacing it");
        }
        Err(error) => return Err(store_error(error)),
    }
    let key = ClientKey::generate()?;
    store.replace(&key).map_err(store_error)?;
    tracing::info!(kid = %key.kid(), "made a new client signing key");
    Ok(key)
}

/// The keychain item that keeps the client's key: its service.
const CLIENT_KEY_SERVICE: &str = "dev.minimal.client-key";

/// The keychain item that keeps the client's key: its account.
const CLIENT_KEY_ACCOUNT: &str = "minimal";

/// The keychain item that keeps the client's key: its label.
const CLIENT_KEY_LABEL: &str = "Minimal client signing key";

/// The host keychain as a [`ClientKeyStore`]: the login keychain through
/// `/usr/bin/security` on macOS, the Secret Service through `secret-tool`
/// on Linux. The item holds the key's secret scalar, unpadded base64url.
/// The secret goes to the tool on its stdin, never on a command line.
#[derive(Debug, Default, Clone, Copy)]
pub struct HostClientKeyStore;

impl HostClientKeyStore {
    /// The key from the item's text. An item that holds no valid key is
    /// refused, so [`local_client_key`] replaces it.
    fn decode(text: &mut Vec<u8>) -> Result<ClientKey, ClientKeyError> {
        let decoded = std::str::from_utf8(text)
            .ok()
            .and_then(|text| URL_SAFE_NO_PAD.decode(text.trim()).ok())
            .map(Zeroizing::new);
        text.zeroize();
        decoded
            .and_then(|bytes| {
                <[u8; 32]>::try_from(bytes.as_slice())
                    .ok()
                    .map(Zeroizing::new)
            })
            .and_then(|bytes| ClientKey::from_secret(&bytes))
            .ok_or_else(|| ClientKeyError::Refused("the kept item holds no valid key".into()))
    }
}

impl ClientKeyStore for HostClientKeyStore {
    fn find(&self) -> Result<Option<ClientKey>, ClientKeyError> {
        match host_key::find()? {
            Some(mut text) => Self::decode(&mut text).map(Some),
            None => Ok(None),
        }
    }

    fn replace(&self, key: &ClientKey) -> Result<(), ClientKeyError> {
        let secret = Zeroizing::new(URL_SAFE_NO_PAD.encode(key.secret().as_slice()));
        host_key::store(&secret)?;
        // Read the key back: a keychain tool can exit 0 and store nothing.
        match self.find() {
            Ok(Some(kept)) if kept.kid() == key.kid() => Ok(()),
            _ => Err(ClientKeyError::Store(
                "the keychain does not hold the new key after the write".into(),
            )),
        }
    }
}

/// How long a keychain tool can run. The tool can wait on an unlock or
/// access prompt that nobody answers, as in an SSH session, and box
/// creation must not wait for it forever.
const KEY_TOOL_TIMEOUT: Duration = Duration::from_secs(60);

/// Runs a keychain tool with `stdin` on its standard input, and gives its
/// output. A tool that runs past `timeout` is killed. The child is reaped
/// on every path.
fn run_key_tool(
    tool: &str,
    cmd: std::process::Command,
    stdin: Option<&str>,
) -> Result<std::process::Output, ClientKeyError> {
    run_key_tool_within(tool, cmd, stdin, KEY_TOOL_TIMEOUT)
}

fn run_key_tool_within(
    tool: &str,
    mut cmd: std::process::Command,
    stdin: Option<&str>,
    timeout: Duration,
) -> Result<std::process::Output, ClientKeyError> {
    use std::io::Read as _;
    use std::process::Stdio;
    cmd.stdin(if stdin.is_some() {
        Stdio::piped()
    } else {
        Stdio::null()
    })
    .stdout(Stdio::piped())
    .stderr(Stdio::piped());
    let mut child = cmd.spawn().map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            ClientKeyError::Store(format!("`{tool}` is not installed"))
        } else {
            ClientKeyError::Store(format!("`{tool}` did not start: {error}"))
        }
    })?;
    let stop = |child: &mut std::process::Child| {
        let _ = child.kill();
        let _ = child.wait();
    };
    if let (Some(input), Some(mut pipe)) = (stdin, child.stdin.take())
        && let Err(error) = pipe.write_all(input.as_bytes())
    {
        drop(pipe);
        stop(&mut child);
        return Err(ClientKeyError::Store(format!(
            "`{tool}` did not take its input: {error}"
        )));
    }
    // The pipes are read on their own threads, so a full pipe never stops
    // the tool while this thread waits on the deadline.
    let reader = |pipe: Option<Box<dyn io::Read + Send>>| {
        std::thread::spawn(move || {
            let mut bytes = Vec::new();
            if let Some(mut pipe) = pipe {
                let _ = pipe.read_to_end(&mut bytes);
            }
            bytes
        })
    };
    let stdout = reader(
        child
            .stdout
            .take()
            .map(|pipe| Box::new(pipe) as Box<dyn io::Read + Send>),
    );
    let stderr = reader(
        child
            .stderr
            .take()
            .map(|pipe| Box::new(pipe) as Box<dyn io::Read + Send>),
    );
    let deadline = std::time::Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if std::time::Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(20));
            }
            Ok(None) => {
                stop(&mut child);
                let _ = (stdout.join(), stderr.join());
                return Err(ClientKeyError::Store(format!(
                    "`{tool}` did not finish in {} seconds. The keychain can be locked, \
                     or it can wait for an answer to a prompt",
                    timeout.as_secs()
                )));
            }
            Err(error) => {
                stop(&mut child);
                let _ = (stdout.join(), stderr.join());
                return Err(ClientKeyError::Store(error.to_string()));
            }
        }
    };
    Ok(std::process::Output {
        status,
        stdout: stdout.join().unwrap_or_default(),
        stderr: stderr.join().unwrap_or_default(),
    })
}

/// The text a keychain tool printed on its standard error.
fn key_tool_error(stderr: &[u8]) -> String {
    String::from_utf8_lossy(stderr).trim().to_owned()
}

#[cfg(target_os = "macos")]
mod host_key {
    use std::process::Command;

    use zeroize::{Zeroize as _, Zeroizing};

    use super::{
        CLIENT_KEY_ACCOUNT, CLIENT_KEY_LABEL, CLIENT_KEY_SERVICE, ClientKeyError, key_tool_error,
        run_key_tool,
    };

    const SECURITY: &str = "/usr/bin/security";
    /// `security` exits with the low byte of the keychain status. No item
    /// matched: `errSecItemNotFound`.
    const NOT_FOUND: i32 = 44;
    /// The keychain holds the item and refused it to this program:
    /// `errSecAuthFailed`, `errSecNoAccessForItem` and `userCanceled`.
    const REFUSED: [i32; 3] = [51, 101, 128];

    pub(super) fn find() -> Result<Option<Vec<u8>>, ClientKeyError> {
        let mut cmd = Command::new(SECURITY);
        cmd.args([
            "find-generic-password",
            "-s",
            CLIENT_KEY_SERVICE,
            "-a",
            CLIENT_KEY_ACCOUNT,
            "-w",
        ]);
        let mut out = run_key_tool(SECURITY, cmd, None)?;
        match out.status.code() {
            _ if out.status.success() => Ok(Some(out.stdout)),
            Some(NOT_FOUND) => {
                out.stdout.zeroize();
                Ok(None)
            }
            Some(code) if REFUSED.contains(&code) => {
                out.stdout.zeroize();
                Err(ClientKeyError::Refused(key_tool_error(&out.stderr)))
            }
            _ => {
                out.stdout.zeroize();
                Err(ClientKeyError::Store(key_tool_error(&out.stderr)))
            }
        }
    }

    pub(super) fn store(secret: &str) -> Result<(), ClientKeyError> {
        // A replacement follows only a missing or a refused item. An item
        // whose access list refuses this program can refuse an update in
        // place too, so the old item goes first and a new one is added.
        delete()?;
        // Every part is quoted, and none carries a quote or a backslash:
        // the names are fixed, and the secret is base64url.
        let line = Zeroizing::new(format!(
            "add-generic-password -s \"{CLIENT_KEY_SERVICE}\" -a \"{CLIENT_KEY_ACCOUNT}\" \
             -l \"{CLIENT_KEY_LABEL}\" -w \"{secret}\"\n"
        ));
        let mut cmd = Command::new(SECURITY);
        cmd.arg("-i");
        let out = run_key_tool(SECURITY, cmd, Some(&line))?;
        if out.status.success() {
            Ok(())
        } else {
            Err(ClientKeyError::Store(key_tool_error(&out.stderr)))
        }
    }

    /// Deletes the kept item. No item to delete is no error.
    fn delete() -> Result<(), ClientKeyError> {
        let mut cmd = Command::new(SECURITY);
        cmd.args([
            "delete-generic-password",
            "-s",
            CLIENT_KEY_SERVICE,
            "-a",
            CLIENT_KEY_ACCOUNT,
        ]);
        let out = run_key_tool(SECURITY, cmd, None)?;
        if out.status.success() || out.status.code() == Some(NOT_FOUND) {
            Ok(())
        } else {
            Err(ClientKeyError::Store(key_tool_error(&out.stderr)))
        }
    }
}

#[cfg(not(target_os = "macos"))]
mod host_key {
    use std::path::{Path, PathBuf};
    use std::process::Command;

    use zeroize::Zeroize as _;

    use super::{
        CLIENT_KEY_ACCOUNT, CLIENT_KEY_LABEL, CLIENT_KEY_SERVICE, ClientKeyError, key_tool_error,
        run_key_tool,
    };

    const SECRET_TOOL: &str = "secret-tool";

    /// The system directories `secret-tool` is taken from. The tool sees
    /// the client's key, so it is never found through `PATH`, where a
    /// project directory can put a program of the same name first.
    const SYSTEM_DIRS: [&str; 3] = ["/usr/bin", "/bin", "/run/current-system/sw/bin"];

    /// The first `secret-tool` in [`SYSTEM_DIRS`].
    fn secret_tool() -> Result<Command, ClientKeyError> {
        trusted_tool(&SYSTEM_DIRS).map(Command::new).ok_or_else(|| {
            ClientKeyError::Store(format!(
                "`{SECRET_TOOL}` is not installed in {}",
                SYSTEM_DIRS.join(", ")
            ))
        })
    }

    pub(super) fn trusted_tool(dirs: &[&str]) -> Option<PathBuf> {
        dirs.iter()
            .map(|dir| Path::new(dir).join(SECRET_TOOL))
            .find(|path| path.is_file())
    }

    pub(super) fn find() -> Result<Option<Vec<u8>>, ClientKeyError> {
        let mut cmd = secret_tool()?;
        cmd.args([
            "lookup",
            "service",
            CLIENT_KEY_SERVICE,
            "account",
            CLIENT_KEY_ACCOUNT,
        ]);
        let mut out = run_key_tool(SECRET_TOOL, cmd, None)?;
        if out.status.success() && !out.stdout.is_empty() {
            return Ok(Some(out.stdout));
        }
        out.stdout.zeroize();
        // `secret-tool` exits 1 with nothing on stderr when no item matches.
        if out.stderr.is_empty() {
            Ok(None)
        } else {
            Err(ClientKeyError::Store(key_tool_error(&out.stderr)))
        }
    }

    pub(super) fn store(secret: &str) -> Result<(), ClientKeyError> {
        // The Secret Service replaces the item whose attributes all match.
        let mut cmd = secret_tool()?;
        cmd.args([
            "store",
            &format!("--label={CLIENT_KEY_LABEL}"),
            "service",
            CLIENT_KEY_SERVICE,
            "account",
            CLIENT_KEY_ACCOUNT,
        ]);
        let out = run_key_tool(SECRET_TOOL, cmd, Some(secret))?;
        if out.status.success() {
            Ok(())
        } else {
            Err(ClientKeyError::Store(key_tool_error(&out.stderr)))
        }
    }
}

/// The end of the root CA's validity, the expiry of every handle minted
/// under it. A root whose validity ends at or before `now` mints nothing.
fn root_expiry(identity: &Identity, identity_path: &Path, now: u64) -> Result<u64, MintError> {
    let not_after = identity
        .root_not_after()
        .map_err(|error| MintError::Identity {
            path: identity_path.to_owned(),
            error,
        })?;
    if not_after <= now {
        tracing::error!(not_after, now, "refused a mint under an expired root CA");
        return Err(MintError::RootExpired);
    }
    Ok(not_after)
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
        let kid = key.kid();
        match self.ask(
            &Request::RegisterClientKey { key: key.public() },
            CLIENT_KEY,
        ) {
            Ok(_) => {
                // The info line is at the key's first use, in
                // [`local_client_key`]. Each mint registers the key again.
                tracing::debug!(kid, "registered the client signing key with the proxy");
                Ok(())
            }
            Err(error) => {
                if let MintError::Refused { error: reason, .. } = &error {
                    tracing::warn!(kid, reason, "the proxy refused the client signing key");
                }
                Err(error)
            }
        }
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

    /// Records the mint of the member `identifier` for the box `box_id` in
    /// the proxy's audit log (BEP-067).
    ///
    /// # Errors
    ///
    /// [`MintError::Control`] when the connection fails, and
    /// [`MintError::Refused`] when the proxy refuses the record.
    pub fn record_mint(&mut self, box_id: &str, identifier: &str) -> Result<(), MintError> {
        self.ask(
            &Request::RecordMint {
                box_id: box_id.to_owned(),
                identifier: identifier.to_owned(),
            },
            "the mint record",
        )?;
        tracing::debug!(box_id, identifier, "recorded the mint with the proxy");
        Ok(())
    }

    /// Revokes every sealed value that names the box `box_id`, and records
    /// the revocation in the proxy's audit log (BEP-043, BEP-067). `minvmd`
    /// sends this request when a live box is destroyed, and `min` never
    /// does, so only the tests use it here.
    ///
    /// # Errors
    ///
    /// [`MintError::Control`] when the connection fails, and
    /// [`MintError::Refused`] when the proxy refuses the revocation.
    #[cfg(test)]
    pub(crate) fn revoke_box(&mut self, box_id: &str) -> Result<(), MintError> {
        self.ask(
            &Request::RevokeBox {
                box_id: box_id.to_owned(),
            },
            "the box's revocation",
        )?;
        tracing::debug!(box_id, "revoked the box's sealed values at the proxy");
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
/// so a failed mint leaves no key the proxy trusts and no box uses. After
/// it, one `mint` record per member goes to the proxy's audit log
/// (BEP-067). A record the proxy does not take is a warn line, and the
/// mint stands: the box and its key are registered by then. When
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
    let expiry = root_expiry(identity, identity_path, now)?;
    // The Box Host is the sealing key's fingerprint, the name `bep serve`
    // opens values under.
    let node = sealing.kid();

    let mut minted = Vec::with_capacity(grant_box.grants.len());
    let mut identifiers = Vec::with_capacity(grant_box.grants.len());
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
        identifiers.push(claims.identifier());
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
    // BEP-067: one `mint` record per member, through the proxy, the log's
    // only writer.
    for identifier in &identifiers {
        if let Err(error) = control.record_mint(&box_id, identifier) {
            tracing::warn!(
                box_id = %box_id,
                identifier = %identifier,
                error = %error,
                "the proxy did not record the mint"
            );
        }
    }
    Ok(minted)
}

/// The claims of a store handle for box `box_id` on Box Host `node`, under
/// `rule`: its store and identifier, its registered authorities as the
/// upstream set, its injection form, and `expiry` as the expiry.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "no caller until the sealed member list has a `store` kind (https://github.com/gominimal/minimal/issues/2525)"
    )
)]
#[must_use]
pub fn store_claims(
    box_id: &str,
    node: &str,
    rule: &StoreRule,
    now: u64,
    expiry: u64,
    jti: String,
) -> Claims {
    Claims {
        sub: box_id.to_owned(),
        node_id: node.to_owned(),
        store: rule.store.clone(),
        id: rule.id.clone(),
        upstream: rule.upstream.clone(),
        inject: Some(rule.inject.clone()),
        iat: now,
        exp: expiry,
        jti,
    }
}

/// One minted store handle.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "no caller until the sealed member list has a `store` kind (https://github.com/gominimal/minimal/issues/2525)"
    )
)]
pub struct StoreHandle {
    /// The handle, a JWS of `typ` `gatehouse-store-handle+jws`.
    pub jws: Zeroizing<String>,
    /// The handle's unique id.
    pub jti: String,
    /// The handle's expiry, in seconds since the Unix epoch: the end of the
    /// root CA's validity.
    pub expiry: u64,
}

impl fmt::Debug for StoreHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StoreHandle")
            .field("jws", &"<redacted>")
            .field("jti", &self.jti)
            .field("expiry", &self.expiry)
            .finish()
    }
}

/// Mints a store handle for the box `box_id` under `rule`, signed under
/// `key`, and registers `key` with the proxy over `control` before it
/// returns the handle (BEP-063). `now` is the time of the mint, in seconds
/// since the Unix epoch.
///
/// The handle's Box Host is the fingerprint of the proxy's sealing key, and
/// its expiry is the end of the root CA's validity. The handle carries no
/// value: the proxy reads the value from the store at each request.
///
/// # Errors
///
/// [`MintError::BoxId`] for a box id that is not one,
/// [`MintError::Identity`] when the identity has no usable sealing key or
/// root validity, [`MintError::RootExpired`] when that validity ended, and
/// the control socket's errors. A refused key is [`MintError::Refused`].
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "no caller until the sealed member list has a `store` kind (https://github.com/gominimal/minimal/issues/2525)"
    )
)]
pub fn mint_store_handle(
    identity: &Identity,
    identity_path: &Path,
    control: &mut ControlClient,
    key: &ClientKey,
    box_id: &str,
    rule: &StoreRule,
    now: u64,
) -> Result<StoreHandle, MintError> {
    let box_id = box_id_hex(box_id)?;
    let node = identity
        .key(bep::keys::Role::Sealing)
        .map_err(|error| MintError::Identity {
            path: identity_path.to_owned(),
            error,
        })?
        .kid();
    let expiry = root_expiry(identity, identity_path, now)?;
    let jti = handle_id()?;
    let claims = store_claims(&box_id, &node, rule, now, expiry, jti.clone());
    let jws = Zeroizing::new(handle::sign(&key.0, &claims));
    // BEP-063: the key is registered before the handle leaves this process.
    control.register_client_key(key)?;
    tracing::info!(
        box_id = %box_id,
        store = %rule.store,
        id = %rule.id,
        upstream = ?rule.upstream,
        jti,
        expiry,
        "minted a store handle"
    );
    Ok(StoreHandle { jws, jti, expiry })
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
/// that withdraws a key. The client keeps that key for its next mint.
///
/// The forget runs only on a failed creation. A Ctrl-C ends the process
/// in `std::process::exit`, which runs no destructor, so it leaves the box
/// at the proxy until the box's destroy forgets it: `minvmd` revokes and
/// forgets a live box when it withdraws the box's row. Inside a
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
            // Ctrl-C exits the process with no drop, and the box's
            // destroy forgets that box.
            Ok(runtime) => drop(runtime.spawn_blocking(forget)),
            Err(_) => forget(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::sync::Arc;

    use bep::boxes::BoxRegistry;
    use bep::control::{Control, Registry};
    use bep::handle::Inject;
    use bep::publish::PublishedKey;
    use bep::seal::{ProxyKey, ProxyPublicKey};

    use super::*;

    const BOX_ID: &str = "0192f0c1-7a2b-7c3d-8e4f-a0b1c2d3e4f5";
    const BOX_HEX: &str = "0192f0c17a2b7c3d8e4fa0b1c2d3e4f5";
    const NOW: u64 = 1_800_000_000;
    const ROOT_END: u64 = 2_000_000_000;

    fn published(key: &ProxyPublicKey) -> PublishedKey {
        PublishedKey {
            public: URL_SAFE_NO_PAD.encode(key.to_sec1_bytes()),
            kid: key.kid(),
        }
    }

    fn proxy_identity(root_not_after: u64) -> (ProxyKey, Identity) {
        let sealing = ProxyKey::generate().unwrap();
        let identity = Identity {
            sealing: Some(published(&sealing.public())),
            root: Some(published(&ProxyKey::generate().unwrap().public())),
            signing: Some(published(&ProxyKey::generate().unwrap().public())),
            root_not_after: Some(root_not_after),
            root_certificate: None,
        };
        (sealing, identity)
    }

    fn rule() -> StoreRule {
        StoreRule {
            store: "keychain".into(),
            id: "npm-token".into(),
            upstream: vec!["registry.npmjs.org".into()],
            inject: Inject::Header {
                name: "Authorization".into(),
                prefix: Some("Bearer ".into()),
            },
        }
    }

    /// A key store that refuses its key once, as a keychain does to a
    /// rebuilt program, and keeps the replacement.
    #[derive(Default)]
    struct RefusingOnce {
        refused: RefCell<bool>,
        kept: RefCell<Option<[u8; 32]>>,
    }

    impl ClientKeyStore for RefusingOnce {
        fn find(&self) -> Result<Option<ClientKey>, ClientKeyError> {
            if !self.refused.replace(true) {
                return Err(ClientKeyError::Refused("not this program".into()));
            }
            Ok(self.kept.borrow().and_then(|b| ClientKey::from_secret(&b)))
        }

        fn replace(&self, key: &ClientKey) -> Result<(), ClientKeyError> {
            *self.kept.borrow_mut() = Some(*key.secret());
            Ok(())
        }
    }

    /// A key store that is locked: it gives no key and keeps none.
    struct Locked;

    impl ClientKeyStore for Locked {
        fn find(&self) -> Result<Option<ClientKey>, ClientKeyError> {
            Err(ClientKeyError::Store("locked".into()))
        }

        fn replace(&self, _: &ClientKey) -> Result<(), ClientKeyError> {
            Err(ClientKeyError::Store("locked".into()))
        }
    }

    /// A control socket that refuses every request, on a thread of its own.
    fn serve_refusing(path: &Path) {
        let listener = std::os::unix::net::UnixListener::bind(path).unwrap();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { return };
                let mut read = BufReader::new(stream.try_clone().unwrap());
                let mut write = stream;
                let mut line = String::new();
                while read.read_line(&mut line).unwrap_or(0) > 0 {
                    let _ = write.write_all(b"{\"ok\":false,\"error\":\"refused\"}\n");
                    line.clear();
                }
            }
        });
    }

    // BEP-063: a store handle is a `gatehouse-store-handle+jws` signed under
    // the client's key, with the box, the host, the rule and the root's
    // validity end, and the key is registered before the handle returns.
    #[test]
    fn store_handle_signed_and_key_registered() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bep/control.sock");
        let clients = Registry::default();
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        let control = runtime
            .block_on(async { Control::bind(&path, Arc::clone(&clients), BoxRegistry::default()) })
            .unwrap();
        runtime.spawn(control.run());

        // A keychain that refuses the key gets a replacement, kept for the
        // next mint.
        let store = RefusingOnce::default();
        let key = local_client_key(&store).unwrap();
        assert_eq!(local_client_key(&store).unwrap().kid(), key.kid());
        assert!(!clients.read().unwrap().contains(&key.kid()));
        // A locked keychain is not a refusal: no key is replaced.
        let err = local_client_key(&Locked).unwrap_err();
        assert!(matches!(err, MintError::KeyStore(_)), "{err}");

        let (sealing, identity) = proxy_identity(ROOT_END);
        let identity_path = Path::new("identity.json");
        let mut client = ControlClient::connect(&path).unwrap();
        let minted = mint_store_handle(
            &identity,
            identity_path,
            &mut client,
            &key,
            BOX_ID,
            &rule(),
            NOW,
        )
        .unwrap();
        assert!(clients.read().unwrap().contains(&key.kid()));
        assert_eq!(minted.expiry, ROOT_END);

        let header = minted.jws.split('.').next().unwrap();
        let header: serde_json_lenient::Value =
            serde_json_lenient::from_slice(&URL_SAFE_NO_PAD.decode(header).unwrap()).unwrap();
        assert_eq!(header["typ"], handle::TYP);
        assert_eq!(header["kid"], key.kid());
        let claims = handle::verify(&minted.jws, &clients.read().unwrap()).unwrap();
        assert_eq!(
            claims,
            Claims {
                sub: BOX_HEX.into(),
                node_id: sealing.public().kid(),
                store: "keychain".into(),
                id: "npm-token".into(),
                upstream: vec!["registry.npmjs.org".into()],
                inject: rule().inject.into(),
                iat: NOW,
                exp: ROOT_END,
                jti: minted.jti.clone(),
            }
        );
        let again = mint_store_handle(
            &identity,
            identity_path,
            &mut client,
            &key,
            BOX_ID,
            &rule(),
            NOW,
        )
        .unwrap();
        assert_ne!(again.jti, minted.jti);

        // A root whose validity ended mints nothing and names the command
        // that replaces it.
        let (_, expired) = proxy_identity(NOW);
        let err = mint_store_handle(
            &expired,
            identity_path,
            &mut client,
            &key,
            BOX_ID,
            &rule(),
            NOW,
        )
        .unwrap_err();
        assert!(matches!(err, MintError::RootExpired), "{err}");
        assert!(
            err.to_string().contains("`bep --replace-key root`"),
            "{err}"
        );

        // A proxy that refuses the key gets no handle, and the person reads
        // why the box was not created.
        let refusing = dir.path().join("refusing.sock");
        serve_refusing(&refusing);
        let mut client = ControlClient::connect(&refusing).unwrap();
        let err = mint_store_handle(
            &identity,
            identity_path,
            &mut client,
            &key,
            BOX_ID,
            &rule(),
            NOW,
        )
        .unwrap_err();
        assert!(matches!(err, MintError::Refused { .. }), "{err}");
        assert_eq!(
            err.to_string(),
            "The proxy did not accept this client's signing key, so the box was not created."
        );
    }

    /// A key store that keeps its key in memory.
    #[derive(Default)]
    struct Kept(RefCell<Option<[u8; 32]>>);

    impl ClientKeyStore for Kept {
        fn find(&self) -> Result<Option<ClientKey>, ClientKeyError> {
            Ok(self.0.borrow().and_then(|b| ClientKey::from_secret(&b)))
        }

        fn replace(&self, key: &ClientKey) -> Result<(), ClientKeyError> {
            *self.0.borrow_mut() = Some(*key.secret());
            Ok(())
        }
    }

    fn signed_in() -> bep::signin::MemoryKeychain {
        use bep::signin::{Completed, Flow, Material, MemoryKeychain, store_sign_in};
        let keychain = MemoryKeychain::default();
        store_sign_in(
            &keychain,
            &Completed {
                account: "octocat".into(),
                flow: Flow::Device,
                material: Material {
                    instance: String::new(),
                    access_token: "ghu_secret_token_value".into(),
                    refresh_token: "ghr_secret_refresh_value".into(),
                },
                token_expires_at: NOW + 3_600,
                refresh_expires_at: NOW + 86_400,
            },
        )
        .unwrap();
        keychain
    }

    fn grant_box(box_id: &str) -> GrantBox {
        GrantBox {
            box_id: box_id.into(),
            grants: vec!["GH_TOKEN".into()],
            egress: vec!["github.com".into(), "api.github.com".into()],
            stance: Stance::OwnIp,
        }
    }

    /// A control socket at `path` on a runtime of its own, and the client
    /// keys it registers.
    fn serve_control(path: &Path) -> (tokio::runtime::Runtime, Registry) {
        let clients = Registry::default();
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        let control = runtime
            .block_on(async { Control::bind(path, Arc::clone(&clients), BoxRegistry::default()) })
            .unwrap();
        runtime.spawn(control.run());
        (runtime, clients)
    }

    /// The client keys the proxy at `path` keeps across its restarts.
    fn kept_registrations(path: &Path) -> Vec<String> {
        std::fs::read_to_string(bep::control::client_keys_path(path))
            .unwrap()
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(str::to_owned)
            .collect()
    }

    /// One creation as `mint_grants` does it: the key from `store`, then
    /// the mint and the registrations over a new connection.
    fn create(
        store: &dyn ClientKeyStore,
        identity: &Identity,
        path: &Path,
        box_id: &str,
    ) -> Result<(ClientKey, Vec<Minted>), MintError> {
        let key = local_client_key(store)?;
        let mut control = ControlClient::connect(path)?;
        let minted = mint_and_register(
            &signed_in(),
            identity,
            Path::new("identity.json"),
            &mut control,
            &key,
            &grant_box(box_id),
            NOW,
        )?;
        Ok((key, minted))
    }

    // BEP-063: every creation signs under the client's one kept key, so two
    // creations leave one client key at the proxy, not one for each box.
    #[test]
    fn two_creations_register_one_client_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bep/control.sock");
        let (_runtime, clients) = serve_control(&path);
        let (_, identity) = proxy_identity(ROOT_END);
        let store = Kept::default();

        let (first, minted) = create(&store, &identity, &path, BOX_ID).unwrap();
        assert_eq!(minted.len(), 1);
        let (second, minted) = create(
            &store,
            &identity,
            &path,
            "0192f0c1-7a2b-7c3d-8e4f-a0b1c2d3e4f6",
        )
        .unwrap();
        assert_eq!(minted.len(), 1);

        assert_eq!(first.kid(), second.kid());
        assert!(clients.read().unwrap().contains(&first.kid()));
        assert_eq!(kept_registrations(&path), vec![first.public()]);
    }

    // A keychain tool that waits on a prompt nobody answers is killed at
    // the deadline, and creation gets an error, not a hang.
    #[test]
    fn a_key_tool_past_its_deadline_is_killed() {
        let mut cmd = std::process::Command::new("sleep");
        cmd.arg("30");
        let started = std::time::Instant::now();
        let err = run_key_tool_within("sleep", cmd, None, Duration::from_millis(200)).unwrap_err();
        assert!(started.elapsed() < Duration::from_secs(10));
        assert!(
            matches!(&err, ClientKeyError::Store(detail) if detail.contains("did not finish")),
            "{err:?}"
        );
    }

    #[test]
    fn a_key_tool_gives_its_output_and_takes_its_input() {
        let cmd = std::process::Command::new("cat");
        let out = run_key_tool_within("cat", cmd, Some("secret"), Duration::from_secs(10)).unwrap();
        assert!(out.status.success());
        assert_eq!(out.stdout, b"secret");
    }

    // The tool that sees the client's key is taken from a system directory,
    // never from a `PATH` entry.
    #[cfg(not(target_os = "macos"))]
    #[test]
    fn secret_tool_is_taken_from_the_listed_directories_only() {
        let listed = tempfile::tempdir().unwrap();
        let empty = tempfile::tempdir().unwrap();
        let tool = listed.path().join("secret-tool");
        std::fs::write(&tool, b"").unwrap();
        let listed_dir = listed.path().to_str().unwrap();
        let empty_dir = empty.path().to_str().unwrap();
        assert_eq!(host_key::trusted_tool(&[empty_dir]), None);
        assert_eq!(host_key::trusted_tool(&[empty_dir, listed_dir]), Some(tool));
    }

    // BEP-063: a key the keychain refuses this program is replaced, kept for
    // the next creation, and registered before the mint gives a sealed value.
    #[test]
    fn a_refused_client_key_is_replaced_and_registered_before_the_mint() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bep/control.sock");
        let (_runtime, clients) = serve_control(&path);
        let (_, identity) = proxy_identity(ROOT_END);

        // An earlier creation kept and registered this key.
        let old = ClientKey::generate().unwrap();
        ControlClient::connect(&path)
            .unwrap()
            .register_client_key(&old)
            .unwrap();
        let store = RefusingOnce {
            refused: RefCell::new(false),
            kept: RefCell::new(Some(*old.secret())),
        };

        let (replacement, minted) = create(&store, &identity, &path, BOX_ID).unwrap();
        assert_eq!(minted.len(), 1);
        assert_ne!(replacement.kid(), old.kid());
        // The replacement is registered by the time the sealed value leaves
        // the mint, and the old key still verifies the handles under it.
        assert!(clients.read().unwrap().contains(&replacement.kid()));
        assert!(clients.read().unwrap().contains(&old.kid()));
        assert_eq!(
            kept_registrations(&path),
            vec![old.public(), replacement.public()]
        );
        // The keychain keeps the replacement for the next creation.
        assert_eq!(local_client_key(&store).unwrap().kid(), replacement.kid());

        // A proxy that refuses the replacement gets no sealed value.
        let refusing = dir.path().join("refusing.sock");
        serve_refusing(&refusing);
        let err = create(&store, &identity, &refusing, BOX_ID).unwrap_err();
        assert!(matches!(err, MintError::Refused { .. }), "{err}");
    }
}
