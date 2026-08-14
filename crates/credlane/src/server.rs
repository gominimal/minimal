//! The broker process: its two listeners, the control protocol `min` speaks to
//! it, and the supervisor the owning daemon drives it with.
//!
//! The broker ships as a hidden subcommand of a daemon that already ships —
//! `minvmd broker` on the microVM platforms, `minimald broker` on native Linux
//! — so nothing here spawns a new binary; [`BrokerProcess`] re-execs whichever
//! daemon owns the machine's gvproxy.
//!
//! Two sockets, and they are different kinds on purpose:
//!
//! - The **box-facing** listener is TCP on the owning process's loopback. A box
//!   reaches it through the switch's host alias (see [`crate::endpoint`]), which
//!   gvproxy NATs to that loopback. Every request on it is authenticated by
//!   token.
//! - The **control** listener is a filesystem UDS, and registration over it
//!   carries no token at all. Its placement and mode are therefore the entire
//!   access control: it must not resolve under any path bind-mounted into a
//!   sandbox (`sandbox2` mounts a sandbox's state dir at `/state` and its
//!   `run` dir at `/run`, both under the minimal state dir), which is why the
//!   path is derived from the *runtime* dir and never from the state dir.
//!
//! See `docs/specs/12-spec-credential-lane/12-spec-credential-lane.md`.

use std::collections::HashMap;
use std::io;
use std::net::Ipv4Addr;
use std::os::unix::fs::{DirBuilderExt as _, FileTypeExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use sessions::SessionId;
use sessions::core::primitives::{CredentialError, validate_credential_lane_name};
use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _, BufReader};
use tokio::net::{TcpListener, UnixListener, UnixStream};
use url::Url;

use crate::lane::{Inject, Lane, Secret};
use crate::proxy::{self, LaneTable, TlsUpstream};
use crate::token::{Refused, RegistrationHandle, Token, TokenStore};

/// Structured-log component for everything the broker process does.
const COMPONENT: &str = "credential-broker";

/// The subcommand both daemons expose the broker as, and which
/// [`BrokerProcess`] re-execs.
pub const SUBCOMMAND: &str = "broker";

/// The box-facing loopback port.
///
/// Deliberately clear of the egress proxy's 7654 and the HTTPS proxy's 7655
/// (`crates/minimald/src/net/proxy.rs`): all three can be live on one host at
/// once, and a collision would hand a box one service under another's name.
pub const DEFAULT_PORT: u16 = 7656;

/// How long a minted token stays valid.
///
/// Teardowns the client does not drive — a connection-close reap, an aborted
/// create, a killed CLI — never revoke, so this is the only bound on those.
/// Long enough for a working day's session, short enough that an abandoned one
/// does not outlive the machine's uptime.
pub const DEFAULT_TOKEN_TTL: Duration = Duration::from_hours(12);

/// Overrides the directory holding the control socket. Set by the harnesses
/// that run a broker per checkout; a parallel checkout that shared one control
/// socket would register its lanes with the other's broker.
pub const RUNTIME_DIR_ENV: &str = "MINIMAL_CREDLANE_RUNTIME_DIR";

/// Name of the control socket within the runtime dir.
const CONTROL_SOCK_FILE: &str = "credlane.sock";

/// Largest control request accepted, in bytes. A registration carries resolved
/// credential values, so it is not tiny; it is also not unbounded.
const MAX_CONTROL_REQUEST: u64 = 256 * 1024;

/// How long [`BrokerProcess::spawn`] waits for the child to bind its control
/// socket before giving up and reaping it.
const CONTROL_READY_TIMEOUT: Duration = Duration::from_secs(10);

/// How long a stopping broker gets to exit on `SIGTERM` before `SIGKILL`.
const TERM_GRACE: Duration = Duration::from_secs(2);

/// Usable bytes in `sockaddr_un.sun_path`, excluding the NUL terminator.
#[cfg(target_os = "macos")]
const SUN_PATH_MAX: usize = 103;
#[cfg(not(target_os = "macos"))]
const SUN_PATH_MAX: usize = 107;

/// The control socket path, derived identically by `min` and by the daemon that
/// owns the broker — one function so the two cannot drift onto two sockets.
///
/// Resolution: [`RUNTIME_DIR_ENV`], else `$XDG_RUNTIME_DIR/minimal`, else
/// `~/.minimal/run`. Never the minimal state dir: sandboxes bind-mount subtrees
/// of it, and a box that can open this socket can register a lane of its own.
///
/// # Errors
///
/// When no home directory can be resolved for the fallback, or when the
/// resulting path exceeds the platform's unix-socket path limit.
pub fn control_socket_path() -> io::Result<PathBuf> {
    let dir = absolute_env(RUNTIME_DIR_ENV)
        .or_else(|| absolute_env("XDG_RUNTIME_DIR").map(|dir| dir.join("minimal")))
        .or_else(|| dirs::home_dir().map(|home| home.join(".minimal").join("run")))
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "no home directory to place the credential broker's control socket under; \
                     set {RUNTIME_DIR_ENV} or XDG_RUNTIME_DIR"
                ),
            )
        })?;
    let path = dir.join(CONTROL_SOCK_FILE);
    check_path_len(&path)?;
    Ok(path)
}

/// A directory named by `var`, if it is set to an absolute path. A relative one
/// is ignored rather than resolved against the cwd, which the XDG spec requires
/// and which keeps the path independent of where a client was invoked.
fn absolute_env(var: &str) -> Option<PathBuf> {
    std::env::var_os(var)
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
}

/// One lane as the client registers it: everything the broker needs to serve
/// it, and nothing the box supplied.
///
/// Carries a plaintext credential: its `Debug` is safe only because [`Secret`]
/// redacts itself, and nothing may serialize one into a log or an error.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LaneRegistration {
    /// The lane name, which is also the selector a box's URL leads with.
    pub lane: String,
    /// The upstream the *user's* binding named. The project never names one.
    pub upstream: Url,
    /// How the credential enters the outbound request.
    pub inject: Inject,
    /// The resolved credential value.
    pub secret: Secret,
}

/// A control request. One per connection, one line of JSON.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    /// Registers a set of lanes and mints a token scoped to exactly them.
    Register {
        /// The session the lanes are registered for. Known because
        /// registration happens at gate time, after `CreateSession`, and it is
        /// the only name a later teardown has for this registration.
        session_id: SessionId,
        /// The lanes this registration serves.
        lanes: Vec<LaneRegistration>,
    },
    /// Drops a registration, refusing every later use of its token.
    Revoke {
        /// The handle [`Response::Registered`] returned.
        handle: RegistrationHandle,
    },
    /// Drops every registration a session made, for a teardown that holds no
    /// handle: the process that activated the session has exited, and
    /// `min session destroy` is a separate invocation.
    RevokeSession {
        /// The session whose registrations to drop.
        session_id: SessionId,
    },
}

/// A control response.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum Response {
    /// The lanes were registered.
    Registered {
        /// The bearer token the box presents. Returned once and never stored.
        token: Token,
        /// The handle that revokes this registration.
        handle: RegistrationHandle,
    },
    /// The registration was dropped; `live` reports whether it still existed.
    ///
    /// A control-path answer for the client that holds the handle, never
    /// surfaced to a box.
    Revoked {
        /// Whether the handle named a live registration.
        live: bool,
    },
    /// The session's registrations were dropped; `live` reports how many
    /// existed. As with [`Self::Revoked`], a control-path answer only.
    SessionRevoked {
        /// How many live registrations the session had.
        live: usize,
    },
    /// The request was rejected. Control-path only: unlike the box-facing
    /// path's single refusal, this says what was wrong, because the caller is
    /// the client that owns the lanes.
    Failed {
        /// Why, for the client to print.
        error: String,
    },
}

/// Why a registration was rejected.
///
/// Both variants describe a lane that could never serve a request: one the
/// selector grammar cannot name, or one the broker would have to reach in
/// plaintext. Refusing them here tells the client which lane is wrong, where
/// the box-facing path could only answer with its one indistinguishable
/// refusal.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum RegisterError {
    /// The lane name is outside the grammar a selector is parsed with.
    #[error("lane {lane}: {source}")]
    Name {
        /// The offending lane.
        lane: String,
        /// What the grammar said.
        source: CredentialError,
    },
    /// The bound upstream is not `https://`.
    #[error("lane {lane}: upstream must be https://, got {scheme}://")]
    Upstream {
        /// The offending lane.
        lane: String,
        /// The scheme it was bound with.
        scheme: String,
    },
}

/// The broker's live registrations: the token store plus the lanes each
/// registration holds.
///
/// Lanes are keyed by registration rather than globally so two sessions may
/// register the same lane name with different values, and neither can reach the
/// other's — a global table would collapse them onto whichever registered last.
pub struct Broker {
    state: Mutex<State>,
    ttl: Duration,
}

struct State {
    tokens: TokenStore,
    lanes: HashMap<RegistrationHandle, HashMap<String, Lane>>,
}

impl Broker {
    /// An empty broker minting tokens that live `ttl`.
    #[must_use]
    pub fn new(ttl: Duration) -> Self {
        Self {
            state: Mutex::new(State {
                tokens: TokenStore::new(),
                lanes: HashMap::new(),
            }),
            ttl,
        }
    }

    /// Registers `lanes`, minting a token scoped to their names.
    ///
    /// # Errors
    ///
    /// The reason the registration was rejected, for the client to print. A
    /// name a box could never select, or an upstream the broker would have to
    /// reach in plaintext, is refused here rather than left to fail per-request
    /// as an indistinguishable box-facing refusal.
    pub fn register(
        &self,
        session_id: SessionId,
        lanes: impl IntoIterator<Item = LaneRegistration>,
    ) -> Result<(Token, RegistrationHandle), RegisterError> {
        let lanes: HashMap<String, Lane> = lanes
            .into_iter()
            .map(|reg| {
                validate_credential_lane_name(&reg.lane).map_err(|source| RegisterError::Name {
                    lane: reg.lane.clone(),
                    source,
                })?;
                if reg.upstream.scheme() != "https" {
                    return Err(RegisterError::Upstream {
                        lane: reg.lane,
                        scheme: reg.upstream.scheme().to_owned(),
                    });
                }
                Ok((
                    reg.lane.clone(),
                    Lane::new(reg.lane, reg.upstream, reg.inject, reg.secret),
                ))
            })
            .collect::<Result<_, RegisterError>>()?;

        let mut state = self.lock();
        let names: Vec<String> = lanes.keys().cloned().collect();
        let (token, handle) = state
            .tokens
            .mint(session_id, names, Instant::now(), self.ttl);
        state.lanes.insert(handle.clone(), lanes);
        Ok((token, handle))
    }

    /// Drops a registration and its lanes. Returns whether it was still live.
    pub fn revoke(&self, handle: &RegistrationHandle) -> bool {
        let mut state = self.lock();
        state.lanes.remove(handle);
        state.tokens.revoke(handle)
    }

    /// Drops every registration `session_id` made, and their lanes. Returns
    /// how many were live.
    pub fn revoke_session(&self, session_id: SessionId) -> usize {
        let mut state = self.lock();
        let revoked = state.tokens.revoke_session(session_id);
        for handle in &revoked {
            state.lanes.remove(handle);
        }
        revoked.len()
    }

    /// A poisoned lock means a panic mid-mutation, which for a process whose
    /// whole job is authorisation is not a state to keep serving from.
    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state
            .lock()
            .expect("broker state poisoned by a panic; refusing to keep authorising")
    }
}

impl LaneTable for Broker {
    fn resolve(&self, token: &str, lane: &str, now: Instant) -> Result<Lane, Refused> {
        let state = self.lock();
        let handle = state.tokens.authorize(token, lane, now)?;
        state
            .lanes
            .get(&handle)
            .and_then(|lanes| lanes.get(lane))
            .cloned()
            .ok_or(Refused)
    }
}

/// Where a broker listens and how long its tokens live.
#[derive(Debug, Clone)]
pub struct BrokerConfig {
    control_socket: PathBuf,
    port: u16,
    ttl: Duration,
}

impl BrokerConfig {
    /// A configuration serving the control socket at `control_socket`, with the
    /// default port and TTL.
    #[must_use]
    pub fn new(control_socket: impl Into<PathBuf>) -> Self {
        Self {
            control_socket: control_socket.into(),
            port: DEFAULT_PORT,
            ttl: DEFAULT_TOKEN_TTL,
        }
    }

    /// Overrides the box-facing loopback port.
    #[must_use]
    pub fn with_port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    /// Overrides the token TTL.
    #[must_use]
    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.ttl = ttl;
        self
    }

    /// The control socket clients register over.
    #[must_use]
    pub fn control_socket(&self) -> &Path {
        &self.control_socket
    }

    /// The box-facing loopback port.
    #[must_use]
    pub fn port(&self) -> u16 {
        self.port
    }
}

/// Runs the broker until one of its listeners fails.
///
/// # Errors
///
/// Binding either listener, or an accept failure on either once bound.
pub async fn run(config: BrokerConfig) -> io::Result<()> {
    let broker = Arc::new(Broker::new(config.ttl));
    let connector = Arc::new(TlsUpstream::new().map_err(io::Error::other)?);
    let box_facing = TcpListener::bind((Ipv4Addr::LOCALHOST, config.port)).await?;
    let control = bind_control_socket(&config.control_socket)?;
    tracing::info!(
        component = COMPONENT,
        port = config.port,
        control = %config.control_socket.display(),
        "credential broker listening"
    );

    let result = tokio::select! {
        result = proxy::serve(box_facing, Arc::clone(&broker), connector) => result,
        result = serve_control(control, Arc::clone(&broker)) => result,
    };
    // Leaving the socket behind makes the next run's stale-socket removal do
    // the work; removing it here keeps a dead broker from looking reachable.
    let _ = std::fs::remove_file(&config.control_socket);
    result
}

/// Binds the control socket: parent dir `0700`, stale socket cleared, mode
/// `0600`.
///
/// The bind-then-chmod window is covered by the `0700` parent — nothing else
/// can traverse into the directory to reach the socket while it is briefly
/// wider than `0600`.
fn bind_control_socket(path: &Path) -> io::Result<UnixListener> {
    check_path_len(path)?;
    if let Some(parent) = path.parent() {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)?;
        // A pre-existing dir keeps whatever mode it had, and this one is the
        // whole access control, so tighten it rather than trust it.
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
    }
    remove_stale_socket(path)?;
    let listener = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

/// Removes a socket left by a previous run so `bind` does not fail `EEXIST`.
/// Refuses to unlink anything that is not a socket: the path is
/// operator-supplied, and clobbering an unrelated file is not this process's
/// business. A missing path is a no-op.
fn remove_stale_socket(path: &Path) -> io::Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_socket() => std::fs::remove_file(path),
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!(
                "{} exists and is not a socket; refusing to remove",
                path.display()
            ),
        )),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// Fails fast when `path` exceeds the platform unix-socket path limit, which
/// `bind` would otherwise report as a bare `EINVAL`.
fn check_path_len(path: &Path) -> io::Result<()> {
    let len = path.as_os_str().as_encoded_bytes().len();
    if len > SUN_PATH_MAX {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "control socket path {} is {len} bytes, over the {SUN_PATH_MAX}-byte unix \
                 socket limit; use a shorter {RUNTIME_DIR_ENV}",
                path.display(),
            ),
        ));
    }
    Ok(())
}

/// Serves the control listener, one task per connection.
///
/// # Errors
///
/// Returns the accept error if the listener fails.
pub async fn serve_control(listener: UnixListener, broker: Arc<Broker>) -> io::Result<()> {
    loop {
        let (stream, _peer) = listener.accept().await?;
        let broker = Arc::clone(&broker);
        tokio::spawn(async move {
            if let Err(error) = handle_control(stream, &broker).await {
                tracing::debug!(component = COMPONENT, %error, "control connection failed");
            }
        });
    }
}

/// Handles one control connection: one request line in, one response line out.
///
/// One request per connection rather than a session: registration and
/// revocation are single round trips minutes apart, and a connection that
/// carried both would have to be held open across the life of a box.
async fn handle_control(mut stream: UnixStream, broker: &Broker) -> io::Result<()> {
    let (reader, mut writer) = stream.split();
    let mut raw = String::new();
    BufReader::new(reader.take(MAX_CONTROL_REQUEST))
        .read_line(&mut raw)
        .await?;

    let response = match serde_json_lenient::from_str::<Request>(&raw) {
        Ok(Request::Register { session_id, lanes }) => match broker.register(session_id, lanes) {
            Ok((token, handle)) => {
                tracing::info!(component = COMPONENT, %handle, %session_id, "registered a credential lane set");
                Response::Registered { token, handle }
            }
            Err(error) => {
                tracing::warn!(component = COMPONENT, %error, "registration refused");
                Response::Failed {
                    error: error.to_string(),
                }
            }
        },
        Ok(Request::Revoke { handle }) => {
            let live = broker.revoke(&handle);
            tracing::info!(component = COMPONENT, %handle, live, "revoked a registration");
            Response::Revoked { live }
        }
        Ok(Request::RevokeSession { session_id }) => {
            let live = broker.revoke_session(session_id);
            tracing::info!(
                component = COMPONENT,
                %session_id,
                live,
                "revoked a session's registrations"
            );
            Response::SessionRevoked { live }
        }
        // The body may carry credential values, so the log says nothing about
        // what arrived beyond the parse error itself.
        Err(error) => Response::Failed {
            error: format!("unreadable control request: {error}"),
        },
    };

    let mut encoded = serde_json_lenient::to_string(&response).map_err(io::Error::other)?;
    encoded.push('\n');
    writer.write_all(encoded.as_bytes()).await?;
    writer.flush().await
}

/// Sends one control request and reads its response.
///
/// The client half of the protocol, here rather than in the CLI so both ends
/// encode through the same types.
///
/// # Errors
///
/// Connect, write, or read failures, and a response the broker did not encode
/// as one line of JSON. A refusal the broker *did* encode arrives as
/// [`Response::Failed`], not an error.
pub async fn call(control_socket: &Path, request: &Request) -> io::Result<Response> {
    let mut stream = UnixStream::connect(control_socket).await?;
    let mut encoded = serde_json_lenient::to_string(request).map_err(io::Error::other)?;
    encoded.push('\n');
    stream.write_all(encoded.as_bytes()).await?;
    // Half-close: the broker reads to end-of-line, but a peer that never shuts
    // down its write half leaves a truncated request looking like a slow one.
    stream.shutdown().await?;

    let mut line = String::new();
    BufReader::new(stream.take(MAX_CONTROL_REQUEST))
        .read_line(&mut line)
        .await?;
    serde_json_lenient::from_str(&line).map_err(io::Error::other)
}

/// A broker child process, supervised by the daemon that owns the machine's
/// gvproxy.
///
/// Follows `minimald`'s `SwitchClient`: a `tokio` [`Command`] with
/// `kill_on_drop`, readiness proved by connecting to the socket the child binds,
/// and `SIGTERM` before `SIGKILL` on stop.
///
/// [`Command`]: tokio::process::Command
#[derive(Debug)]
pub struct BrokerProcess {
    child: Option<tokio::process::Child>,
    control_socket: PathBuf,
}

impl BrokerProcess {
    /// Spawns `<daemon> broker` and returns once its control socket accepts a
    /// connection.
    ///
    /// `daemon` is the path to the daemon binary that carries the subcommand —
    /// the caller's own `current_exe()` in production.
    ///
    /// # Errors
    ///
    /// A spawn failure, a child that exits during startup, or a control socket
    /// that never accepts within the readiness timeout. In the latter two cases
    /// the child is reaped before returning, so a half-started broker is never
    /// left holding the port.
    pub async fn spawn(daemon: &Path, config: &BrokerConfig) -> io::Result<Self> {
        let mut cmd = tokio::process::Command::new(daemon);
        cmd.arg(SUBCOMMAND)
            .arg("--control-socket")
            .arg(&config.control_socket)
            .arg("--port")
            .arg(config.port.to_string())
            .stdin(std::process::Stdio::null())
            // Inherited rather than null'd: the child logs through its own
            // console subscriber, so a foreground daemon's terminal is the only
            // place its records show up. Under a detached daemon this inherits
            // that daemon's `/dev/null`, which is the gap a broker log file of
            // its own would close.
            .stdout(std::process::Stdio::inherit())
            .stderr(std::process::Stdio::inherit())
            // A supervisor dropped without a clean `stop` (an error path or a
            // panic) must not orphan a process holding the control socket.
            .kill_on_drop(true);

        tracing::info!(
            component = COMPONENT,
            daemon = %daemon.display(),
            port = config.port,
            "spawning the credential broker"
        );
        let mut process = Self {
            child: Some(cmd.spawn()?),
            control_socket: config.control_socket.clone(),
        };
        if let Err(e) = process.wait_until_ready().await {
            let _ = process.stop().await;
            return Err(e);
        }
        Ok(process)
    }

    /// The control socket the spawned broker binds.
    #[must_use]
    pub fn control_socket(&self) -> &Path {
        &self.control_socket
    }

    /// Stops the broker with `SIGTERM`, escalating to `SIGKILL` after the
    /// grace period. Idempotent.
    ///
    /// # Errors
    ///
    /// Propagates I/O errors from awaiting the child.
    pub async fn stop(&mut self) -> io::Result<()> {
        let Some(mut child) = self.child.take() else {
            return Ok(());
        };
        if let Some(pid) = child.id().and_then(|pid| libc::pid_t::try_from(pid).ok()) {
            tracing::info!(
                component = COMPONENT,
                pid,
                "stopping the credential broker (SIGTERM)"
            );
            // SAFETY: kill(pid, SIGTERM) only delivers a signal to the named,
            // still-owned child process; it has no other effect and cannot
            // violate any memory invariant.
            unsafe {
                libc::kill(pid, libc::SIGTERM);
            }
        }
        match tokio::time::timeout(TERM_GRACE, child.wait()).await {
            Ok(Ok(status)) => {
                tracing::info!(component = COMPONENT, ?status, "credential broker stopped");
            }
            Ok(Err(e)) => return Err(e),
            Err(_elapsed) => {
                tracing::warn!(
                    component = COMPONENT,
                    "broker ignored SIGTERM; sending SIGKILL"
                );
                let _ = child.start_kill();
                let _ = child.wait().await;
            }
        }
        Ok(())
    }

    /// Polls the control socket with a real connect until the child accepts.
    /// `bind` creates the path before `listen` runs, so existence alone would
    /// report ready while a connect still failed.
    async fn wait_until_ready(&mut self) -> io::Result<()> {
        let deadline = tokio::time::Instant::now() + CONTROL_READY_TIMEOUT;
        loop {
            match UnixStream::connect(&self.control_socket).await {
                Ok(_) => return Ok(()),
                Err(e)
                    if e.kind() == io::ErrorKind::ConnectionRefused
                        || e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
            // A child that died during startup never binds, so surface its exit
            // rather than spinning until the timeout says something vaguer.
            if let Some(child) = self.child.as_mut()
                && let Some(status) = child.try_wait()?
            {
                self.child = None;
                return Err(io::Error::other(format!(
                    "credential broker exited during startup ({status})"
                )));
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!(
                        "credential broker did not bind {} within {CONTROL_READY_TIMEOUT:?}",
                        self.control_socket.display()
                    ),
                ));
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex as StdMutex;

    use super::*;

    /// Serializes the tests that mutate the environment the control path is
    /// derived from.
    static ENV_LOCK: StdMutex<()> = StdMutex::new(());

    const TTL: Duration = Duration::from_mins(5);

    fn registration(lane: &str, upstream: &str) -> LaneRegistration {
        registration_with(lane, upstream, "sk-live-hunter2")
    }

    fn registration_with(lane: &str, upstream: &str, secret: &str) -> LaneRegistration {
        LaneRegistration {
            lane: lane.to_owned(),
            upstream: Url::parse(upstream).unwrap(),
            inject: Inject::new("Authorization", "Bearer "),
            secret: Secret::new(secret),
        }
    }

    /// A distinct session id per `n`, standing in for the id the client learns
    /// from `CreateSession` and registers under.
    fn session(n: u8) -> SessionId {
        SessionId::parse_str(&format!("00000000-0000-0000-0000-0000000000{n:02}")).unwrap()
    }

    /// Runs `f` with `var` set to `value` (or unset), restoring it after.
    fn with_env<T>(vars: &[(&str, Option<&str>)], f: impl FnOnce() -> T) -> T {
        let _guard = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let restore: Vec<_> = vars
            .iter()
            .map(|(var, _)| (*var, std::env::var_os(var)))
            .collect();
        for (var, value) in vars {
            match value {
                Some(value) => unsafe { std::env::set_var(var, value) },
                None => unsafe { std::env::remove_var(var) },
            }
        }
        let out = f();
        for (var, value) in restore {
            match value {
                Some(value) => unsafe { std::env::set_var(var, value) },
                None => unsafe { std::env::remove_var(var) },
            }
        }
        out
    }

    /// Registers one lane over the control socket, yielding its token.
    async fn register_one(path: &Path, session_id: SessionId, lane: &LaneRegistration) -> Token {
        match call(
            path,
            &Request::Register {
                session_id,
                lanes: vec![lane.clone()],
            },
        )
        .await
        .unwrap()
        {
            Response::Registered { token, .. } => token,
            other => panic!("registration failed: {other:?}"),
        }
    }

    /// Starts a control server on a temp socket, returning the broker it shares
    /// with the caller so a test can assert what a registration did to it.
    fn control_server(dir: &Path) -> (PathBuf, Arc<Broker>) {
        let path = dir.join("credlane.sock");
        let broker = Arc::new(Broker::new(TTL));
        let listener = bind_control_socket(&path).unwrap();
        tokio::spawn(serve_control(listener, Arc::clone(&broker)));
        (path, broker)
    }

    /// R2.2a: `sandbox2` bind-mounts a sandbox's state dir at `/state` and its
    /// `run` dir at `/run`, both under the minimal state dir, and registration
    /// carries no token — so a control socket anywhere under that tree would be
    /// a box's own lane registry.
    #[test]
    fn the_control_socket_never_lands_under_the_bind_mounted_state_tree() {
        let state = tempfile::tempdir().unwrap();
        let runtime = tempfile::tempdir().unwrap();
        let state_home = state.path().to_str().unwrap();

        for runtime_dir in [Some(runtime.path().to_str().unwrap()), None] {
            let (path, mounted) = with_env(
                &[
                    ("XDG_STATE_HOME", Some(state_home)),
                    ("XDG_RUNTIME_DIR", runtime_dir),
                    (RUNTIME_DIR_ENV, None),
                ],
                || {
                    (
                        control_socket_path().unwrap(),
                        PathBuf::from(paths::minimal_state_dir().as_str()),
                    )
                },
            );
            assert!(
                !path.starts_with(&mounted),
                "control socket {} is under the state tree {}",
                path.display(),
                mounted.display(),
            );
        }
    }

    #[test]
    fn the_runtime_dir_override_wins_over_xdg() {
        let path = with_env(
            &[
                (RUNTIME_DIR_ENV, Some("/tmp/credlane-test")),
                ("XDG_RUNTIME_DIR", Some("/tmp/ignored")),
            ],
            || control_socket_path().unwrap(),
        );
        assert_eq!(path, PathBuf::from("/tmp/credlane-test/credlane.sock"));
    }

    /// A relative runtime dir would resolve against whatever cwd the client was
    /// invoked from, so `min` and the daemon would derive two sockets.
    #[test]
    fn a_relative_runtime_dir_is_ignored_rather_than_resolved() {
        let path = with_env(
            &[
                (RUNTIME_DIR_ENV, Some("relative/dir")),
                ("XDG_RUNTIME_DIR", Some("/tmp/xdg-runtime")),
            ],
            || control_socket_path().unwrap(),
        );
        assert_eq!(
            path,
            PathBuf::from("/tmp/xdg-runtime/minimal/credlane.sock")
        );
    }

    /// All three loopback services can be live at once; two on one port would
    /// hand a box one under the other's name.
    #[test]
    fn the_box_facing_port_collides_with_neither_egress_proxy() {
        const EGRESS_PROXY_PORT: u16 = 7654;
        const HTTPS_PROXY_PORT: u16 = 7655;
        assert_ne!(DEFAULT_PORT, EGRESS_PROXY_PORT);
        assert_ne!(DEFAULT_PORT, HTTPS_PROXY_PORT);
    }

    #[tokio::test]
    async fn the_control_socket_is_owner_only_inside_an_owner_only_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("nested");
        let path = dir.join("credlane.sock");
        let _listener = bind_control_socket(&path).unwrap();

        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&path), 0o600, "socket must be owner-only");
        assert_eq!(mode(&dir), 0o700, "parent dir must be owner-only");
    }

    #[tokio::test]
    async fn binding_replaces_a_stale_socket_but_refuses_a_regular_file() {
        let tmp = tempfile::tempdir().unwrap();
        let stale = tmp.path().join("stale.sock");
        drop(std::os::unix::net::UnixListener::bind(&stale).unwrap());
        bind_control_socket(&stale).expect("a stale socket is this broker's to replace");

        let occupied = tmp.path().join("not-a-socket");
        std::fs::write(&occupied, b"someone else's file").unwrap();
        let err = bind_control_socket(&occupied).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        assert!(occupied.exists(), "a non-socket must be left in place");
    }

    #[tokio::test]
    async fn a_registered_lane_resolves_for_the_token_the_registration_minted() {
        let tmp = tempfile::tempdir().unwrap();
        let (path, broker) = control_server(tmp.path());

        let response = call(
            &path,
            &Request::Register {
                session_id: session(1),
                lanes: vec![registration("anthropic", "https://api.anthropic.com/v1/")],
            },
        )
        .await
        .unwrap();
        let Response::Registered { token, .. } = response else {
            panic!("expected a registration, got {response:?}");
        };

        let lane = broker
            .resolve(token.expose(), "anthropic", Instant::now())
            .expect("the minted token authorises the lane it was minted for");
        assert_eq!(lane.upstream().as_str(), "https://api.anthropic.com/v1/");
        assert_eq!(
            lane.inject().header_value(lane.secret()),
            "Bearer sk-live-hunter2"
        );
    }

    #[tokio::test]
    async fn a_revoked_registration_refuses_its_token_and_forgets_its_lane() {
        let tmp = tempfile::tempdir().unwrap();
        let (path, broker) = control_server(tmp.path());

        let Response::Registered { token, handle } = call(
            &path,
            &Request::Register {
                session_id: session(1),
                lanes: vec![registration("anthropic", "https://api.anthropic.com/v1/")],
            },
        )
        .await
        .unwrap() else {
            panic!("registration failed");
        };

        let revoked = call(
            &path,
            &Request::Revoke {
                handle: handle.clone(),
            },
        )
        .await
        .unwrap();
        assert!(
            matches!(revoked, Response::Revoked { live: true }),
            "{revoked:?}"
        );
        assert!(
            broker
                .resolve(token.expose(), "anthropic", Instant::now())
                .is_err(),
            "a revoked registration's token must not resolve its lane"
        );

        let again = call(&path, &Request::Revoke { handle }).await.unwrap();
        assert!(
            matches!(again, Response::Revoked { live: false }),
            "revoking twice reports nothing live, and does not fail: {again:?}"
        );
    }

    /// Two boxes may hold the same lane name with different credentials; a
    /// global lane table would collapse them onto whichever registered last.
    #[tokio::test]
    async fn one_registrations_token_never_reaches_another_registrations_lane() {
        let tmp = tempfile::tempdir().unwrap();
        let (path, broker) = control_server(tmp.path());

        let first = register_one(
            &path,
            session(1),
            &registration("anthropic", "https://api.anthropic.com/v1/"),
        )
        .await;
        let second = register_one(
            &path,
            session(2),
            &registration("github-mcp", "https://api.github.com/mcp/"),
        )
        .await;

        assert!(
            broker
                .resolve(first.expose(), "github-mcp", Instant::now())
                .is_err(),
            "one registration's token must not reach another's lane"
        );
        assert!(
            broker
                .resolve(second.expose(), "github-mcp", Instant::now())
                .is_ok()
        );
    }

    /// R3.4: destroy runs in a process that never held the handle, so it names
    /// the session — and two boxes sharing a lane name must not share its fate
    /// or its credential.
    #[tokio::test]
    async fn revoking_a_session_drops_its_lane_and_leaves_the_other_sessions_working() {
        let tmp = tempfile::tempdir().unwrap();
        let (path, broker) = control_server(tmp.path());
        let upstream = "https://api.anthropic.com/v1/";

        let doomed = register_one(
            &path,
            session(1),
            &registration_with("anthropic", upstream, "sk-doomed"),
        )
        .await;
        let kept = register_one(
            &path,
            session(2),
            &registration_with("anthropic", upstream, "sk-kept"),
        )
        .await;

        let each_lane = |token: &Token| {
            broker
                .resolve(token.expose(), "anthropic", Instant::now())
                .map(|lane| lane.inject().header_value(lane.secret()))
        };
        assert_eq!(each_lane(&doomed).unwrap(), "Bearer sk-doomed");
        assert_eq!(
            each_lane(&kept).unwrap(),
            "Bearer sk-kept",
            "one lane name, two sessions, two credentials"
        );

        let revoked = call(
            &path,
            &Request::RevokeSession {
                session_id: session(1),
            },
        )
        .await
        .unwrap();
        assert!(
            matches!(revoked, Response::SessionRevoked { live: 1 }),
            "{revoked:?}"
        );
        assert!(
            each_lane(&doomed).is_err(),
            "a destroyed session's token must not resolve its lane"
        );
        assert_eq!(each_lane(&kept).unwrap(), "Bearer sk-kept");
    }

    /// Every destroy revokes, and most sessions never had a lane at all.
    #[tokio::test]
    async fn revoking_a_session_that_never_registered_answers_rather_than_fails() {
        let tmp = tempfile::tempdir().unwrap();
        let (path, _broker) = control_server(tmp.path());

        let response = call(
            &path,
            &Request::RevokeSession {
                session_id: session(7),
            },
        )
        .await
        .unwrap();
        assert!(
            matches!(response, Response::SessionRevoked { live: 0 }),
            "{response:?}"
        );
    }

    #[tokio::test]
    async fn a_plaintext_upstream_is_refused_at_registration() {
        let tmp = tempfile::tempdir().unwrap();
        let (path, _broker) = control_server(tmp.path());

        let response = call(
            &path,
            &Request::Register {
                session_id: session(1),
                lanes: vec![registration("anthropic", "http://api.anthropic.com/v1/")],
            },
        )
        .await
        .unwrap();
        let Response::Failed { error } = response else {
            panic!("a plaintext upstream must not register: {response:?}");
        };
        assert!(error.contains("https"), "{error}");
    }

    /// A lane name the selector grammar rejects could never be reached, so it
    /// is refused where the client can still be told why.
    #[tokio::test]
    async fn a_lane_name_a_box_could_never_select_is_refused_at_registration() {
        let tmp = tempfile::tempdir().unwrap();
        let (path, _broker) = control_server(tmp.path());

        let response = call(
            &path,
            &Request::Register {
                session_id: session(1),
                lanes: vec![registration(
                    "Anthropic/../etc",
                    "https://api.anthropic.com/",
                )],
            },
        )
        .await
        .unwrap();
        assert!(matches!(response, Response::Failed { .. }), "{response:?}");
    }

    #[tokio::test]
    async fn a_garbled_control_request_is_answered_rather_than_hung_on() {
        let tmp = tempfile::tempdir().unwrap();
        let (path, _broker) = control_server(tmp.path());

        let mut stream = UnixStream::connect(&path).await.unwrap();
        stream.write_all(b"{not json at all\n").await.unwrap();
        stream.shutdown().await.unwrap();
        let mut line = String::new();
        BufReader::new(stream).read_line(&mut line).await.unwrap();

        let response: Response = serde_json_lenient::from_str(&line).unwrap();
        assert!(matches!(response, Response::Failed { .. }), "{response:?}");
    }

    #[tokio::test]
    async fn spawning_a_broker_that_cannot_run_reports_the_exit_not_a_timeout() {
        let tmp = tempfile::tempdir().unwrap();
        let config = BrokerConfig::new(tmp.path().join("credlane.sock"));
        let err = BrokerProcess::spawn(Path::new("/bin/false"), &config)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("exited during startup"), "{err}");
    }
}
