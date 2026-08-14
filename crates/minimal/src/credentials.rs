//! Host-side credential resolution and broker registration.
//!
//! A bound lane's value is read here, in `min`, on the host: `min` is the only
//! process that runs host-side on all three deployment models, and `minimald`
//! is guest-side on the microVM ones. What leaves this module is a token and a
//! revocation handle. The value itself goes over the broker's control socket
//! and nowhere else — not onto a wire type, not to the daemon, not into a log.
//!
//! See `docs/specs/12-spec-credential-lane/12-spec-credential-lane.md`, Unit 5.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use credlane::{Inject, LaneRegistration, RegistrationHandle, Request, Response, Secret, Token};
use sessions::SessionId;
use sessions::core::compose::ComposeError;
use sessions::core::primitives::{CredentialBindings, CredentialSource};
use sessions::wire::policy::WireCredentialVerdict;
use sessions::wire::primitives::WirePendingCredential;
use sessions::wire::request::ContributionVerdict;
use url::Url;

use crate::{GlobalArgs, config};

/// Why a lane could not be registered.
///
/// No variant carries a resolved value: an error is printed, and a credential
/// that reached a terminal is a credential in a scrollback buffer.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The project declared a lane the user never bound.
    #[error(
        "credential lane `{lane}` is not bound; add a `[{lane}]` entry with \
         `upstream` and `source` to {}",
        path.display()
    )]
    Unbound {
        /// The declared lane.
        lane: String,
        /// The binding file a `[lane]` entry belongs in.
        path: PathBuf,
    },
    /// The bound source could not be read.
    #[error("credential lane `{lane}`: {source}")]
    Resolve {
        /// The lane whose source failed.
        lane: String,
        /// What the resolver said.
        #[source]
        source: ResolveError,
    },
    /// The bound upstream is not a URL the broker can originate against.
    #[error("credential lane `{lane}`: upstream `{upstream}` is not a URL: {source}")]
    Upstream {
        /// The lane whose binding is malformed.
        lane: String,
        /// The upstream as the binding wrote it.
        upstream: String,
        /// What the parser said.
        #[source]
        source: url::ParseError,
    },
    /// The broker's control socket could not be reached.
    #[error("reaching the credential broker: {source}")]
    Broker {
        /// The I/O failure connecting or talking to it.
        #[source]
        source: std::io::Error,
    },
    /// The broker declined the registration and said why.
    #[error("the credential broker refused the registration: {0}")]
    Refused(String),
    /// The broker answered a registration with something other than a
    /// registration result.
    #[error("the credential broker answered a registration with {0}")]
    Protocol(&'static str),
}

/// Why a bound source could not be turned into a value.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum ResolveError {
    /// The named variable is unset or not UTF-8.
    #[error("environment variable `{name}`: {source}")]
    Env {
        /// The variable the binding named.
        name: String,
        /// What the lookup said.
        #[source]
        source: std::env::VarError,
    },
    /// A relative path would resolve against whatever directory `min` was
    /// invoked from.
    #[error("`{path}` is relative; use an absolute or `~/` path")]
    Relative {
        /// The path as the binding wrote it.
        path: String,
    },
    /// Only the current user's home is expanded, as for a patch source.
    #[error("`{path}` uses `~name/` form; only `~/...` is expanded — use an explicit path")]
    TildeUser {
        /// The path as the binding wrote it.
        path: String,
    },
    /// There is no home directory to expand a leading `~` against.
    #[error("no home directory to expand `~` in `{path}`")]
    NoHome {
        /// The path as the binding wrote it.
        path: String,
    },
    /// A component of the path is a symlink.
    #[error("`{}` is a symlink, which is not allowed in a credential file path", component.display())]
    Symlink {
        /// The component that is a link.
        component: PathBuf,
    },
    /// The path exists but is not a regular file — a fifo would block the
    /// read forever, a directory cannot be read at all.
    #[error("`{}` is not a regular file", path.display())]
    NotAFile {
        /// The offending path.
        path: PathBuf,
    },
    /// Stat or read failed.
    #[error("reading `{}`: {source}", path.display())]
    Io {
        /// The path being read.
        path: PathBuf,
        /// The underlying failure.
        #[source]
        source: std::io::Error,
    },
    /// The source resolved to nothing. Registering it would produce a lane
    /// that authenticates with an empty header, which fails at the upstream
    /// with a much less obvious message than this one.
    #[error("resolved to an empty value")]
    Empty,
    /// The value cannot be sent as a header. Reported without the value: a
    /// credential must not reach a terminal.
    #[error("resolved to a value containing a control character, which cannot be sent as a header")]
    ControlChars,
}

/// The user's credential bindings and the file they came from.
///
/// The path travels with the bindings because it is half the answer to "this
/// lane is not bound": the lane name alone does not tell anyone where a
/// binding would go, and `sessions` — where the gate detects the miss — has no
/// idea where the client keeps the file.
#[derive(Debug, Clone)]
pub struct Bindings {
    path: PathBuf,
    bindings: CredentialBindings,
}

impl Bindings {
    /// Reads the user's bindings from the resolved config dir.
    ///
    /// # Errors
    ///
    /// A binding file that exists but does not parse. A missing one is an
    /// empty set — see [`config::read_credential_bindings`].
    pub fn read(global: &GlobalArgs) -> Result<Self, anyhow::Error> {
        Ok(Self {
            path: config::credentials_path(global),
            bindings: config::read_credential_bindings(global)?,
        })
    }

    /// Pairs an already-parsed set with the file it came from.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>, bindings: CredentialBindings) -> Self {
        Self {
            path: path.into(),
            bindings,
        }
    }

    /// The bindings themselves, for the gate that matches lanes against them.
    #[must_use]
    pub fn bindings(&self) -> &CredentialBindings {
        &self.bindings
    }

    /// The file the bindings were read from.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Renders a gating failure, naming the binding file when the failure was
    /// a lane nobody bound.
    ///
    /// [`ComposeError::UnboundCredentialLane`] names the lane and the project
    /// that declared it, which is everything `sessions` knows; the file to fix
    /// is client-side knowledge, and without it the operator is told what is
    /// wrong but not where to say otherwise.
    #[must_use]
    pub fn gating_failure(&self, error: &ComposeError) -> anyhow::Error {
        match error {
            ComposeError::UnboundCredentialLane { lane, .. } => anyhow::anyhow!(
                "Composition gating failed: {error}\n\n\
                 Add to {}:\n\n\
                 [{lane}]\n\
                 upstream = \"https://...\"\n\
                 source = {{ env = \"...\" }}\n",
                self.path.display(),
            ),
            _ => anyhow::anyhow!("Composition gating failed: {error}"),
        }
    }
}

/// Reads one credential value from the host.
///
/// One implementation per [`CredentialSource`] variant; keychain and vault
/// sources are later implementations of this same trait.
pub trait Resolver {
    /// Reads the value `reference` names — a variable name for
    /// [`EnvResolver`], a path for [`FileResolver`].
    ///
    /// # Errors
    ///
    /// See [`ResolveError`].
    fn resolve(&self, reference: &str) -> Result<Secret, ResolveError>;
}

/// Reads the value from the client's own process environment.
///
/// Takes the lookup rather than calling [`std::env::var`] directly, as the
/// composition gate's `env` parameter already does: a resolver that reads the
/// ambient environment can only be tested by mutating it.
pub struct EnvResolver<'a> {
    lookup: &'a dyn Fn(&str) -> Result<String, std::env::VarError>,
}

impl<'a> EnvResolver<'a> {
    /// A resolver reading through `lookup`.
    #[must_use]
    pub fn new(lookup: &'a dyn Fn(&str) -> Result<String, std::env::VarError>) -> Self {
        Self { lookup }
    }
}

impl Resolver for EnvResolver<'_> {
    fn resolve(&self, reference: &str) -> Result<Secret, ResolveError> {
        let raw = (self.lookup)(reference).map_err(|source| ResolveError::Env {
            name: reference.to_owned(),
            source,
        })?;
        secret_from(&raw)
    }
}

/// Reads the value from a host file, refusing a symlink at any component.
pub struct FileResolver {
    home: Option<PathBuf>,
}

impl FileResolver {
    /// A resolver expanding a leading `~` to `home`.
    #[must_use]
    pub fn new(home: Option<PathBuf>) -> Self {
        Self { home }
    }

    /// Expands a leading `~`, exactly as a patch source's is expanded: bare
    /// `~` and `~/...` only. `~name/` is refused rather than left literal,
    /// where it would quietly become a relative path.
    fn expand(&self, raw: &str) -> Result<PathBuf, ResolveError> {
        let path = match raw.strip_prefix('~') {
            None => PathBuf::from(raw),
            Some(rest) if rest.is_empty() || rest.starts_with('/') => {
                let home = self.home.as_ref().ok_or_else(|| ResolveError::NoHome {
                    path: raw.to_owned(),
                })?;
                home.join(rest.trim_start_matches('/'))
            }
            Some(_) => {
                return Err(ResolveError::TildeUser {
                    path: raw.to_owned(),
                });
            }
        };
        if path.is_absolute() {
            Ok(path)
        } else {
            Err(ResolveError::Relative {
                path: raw.to_owned(),
            })
        }
    }
}

impl Resolver for FileResolver {
    fn resolve(&self, reference: &str) -> Result<Secret, ResolveError> {
        let path = self.expand(reference)?;
        refuse_symlinked_components(&path)?;
        let raw = std::fs::read_to_string(&path).map_err(|source| ResolveError::Io {
            path: path.clone(),
            source,
        })?;
        secret_from(&raw)
    }
}

/// Walks `path` component by component, refusing a symlink at any of them and
/// a leaf that is not a regular file.
///
/// Every component is stat'd with `symlink_metadata` as the path is walked,
/// the way hook script paths already are
/// (`sessions::client::hookscripts::resolve_under_anchor`). Canonicalizing
/// instead would *follow* the links: it can say where a path ends up, never
/// that it took a link to get there, which is the thing being refused.
fn refuse_symlinked_components(path: &Path) -> Result<(), ResolveError> {
    let mut current = PathBuf::new();
    let mut components = path.components().peekable();
    while let Some(component) = components.next() {
        current.push(component);
        let meta = std::fs::symlink_metadata(&current).map_err(|source| ResolveError::Io {
            path: current.clone(),
            source,
        })?;
        // Checked on the leaf too: a symlinked file is as capable of pointing
        // somewhere else as a symlinked directory partway down.
        if meta.file_type().is_symlink() {
            return Err(ResolveError::Symlink { component: current });
        }
        if components.peek().is_none() && !meta.is_file() {
            return Err(ResolveError::NotAFile { path: current });
        }
    }
    Ok(())
}

/// Turns a resolved string into a [`Secret`], refusing the two shapes that
/// cannot become a header value.
///
/// Trailing whitespace is trimmed because a token file written by an editor
/// ends in a newline, and a newline in a header value forges header lines.
/// Anything else control-shaped is refused rather than silently sanitised.
fn secret_from(raw: &str) -> Result<Secret, ResolveError> {
    let value = raw.trim();
    if value.is_empty() {
        return Err(ResolveError::Empty);
    }
    if value.chars().any(char::is_control) {
        return Err(ResolveError::ControlChars);
    }
    Ok(Secret::new(value))
}

/// Resolves a bound source to its value, on this host.
///
/// # Errors
///
/// See [`ResolveError`].
pub fn resolve(
    source: &CredentialSource,
    env: &dyn Fn(&str) -> Result<String, std::env::VarError>,
) -> Result<Secret, ResolveError> {
    match source {
        CredentialSource::Env(name) => EnvResolver::new(env).resolve(name),
        CredentialSource::File(path) => FileResolver::new(dirs::home_dir()).resolve(path),
    }
}

/// A live registration: the token the box presents, and the handle that drops
/// it again.
///
/// The token is deliberately not stored anywhere on this side either — it is
/// held for the life of the activation and handed to the daemon in memory.
#[derive(Debug)]
pub struct Registration {
    token: Token,
    handle: RegistrationHandle,
    lanes: Vec<String>,
}

impl Registration {
    /// The bearer token the box presents to the broker. It travels to the
    /// daemon as a wire-only field on the create request and is written to no
    /// file on either side.
    #[must_use]
    pub fn token(&self) -> &Token {
        &self.token
    }

    /// The handle [`Self::revoke`] drops this registration by.
    #[must_use]
    pub fn handle(&self) -> &RegistrationHandle {
        &self.handle
    }

    /// The lanes this registration serves, in registration order.
    #[must_use]
    pub fn lanes(&self) -> &[String] {
        &self.lanes
    }

    /// Drops the registration, refusing every later use of its token.
    ///
    /// # Errors
    ///
    /// Failing to reach the broker. A registration that cannot be revoked is
    /// still bounded by the token's expiry, so callers on a teardown path
    /// should report this rather than fail on it.
    pub async fn revoke(&self) -> Result<(), Error> {
        let socket = credlane::control_socket_path().map_err(|source| Error::Broker { source })?;
        match credlane::server::call(
            &socket,
            &Request::Revoke {
                handle: self.handle.clone(),
            },
        )
        .await
        .map_err(|source| Error::Broker { source })?
        {
            Response::Revoked { .. } => Ok(()),
            Response::Failed { error } => Err(Error::Refused(error)),
            Response::Registered { .. }
            | Response::SessionRevoked { .. }
            | Response::SessionLanes { .. } => Err(Error::Protocol("a registration")),
        }
    }
}

/// Drops every registration the broker holds for `session`, returning how many
/// were live.
///
/// The teardown path's revocation, and the only one available to it: the
/// process that activated the session held the handle and has since exited, so
/// `min session destroy` names the session instead.
///
/// # Errors
///
/// Failing to reach the broker — which on this path includes the ordinary case
/// of no broker running at all. A session that never registered a lane is not
/// an error; it revokes nothing and says so.
pub async fn revoke_session(session: SessionId) -> Result<usize, Error> {
    let socket = credlane::control_socket_path().map_err(|source| Error::Broker { source })?;
    match credlane::server::call(
        &socket,
        &Request::RevokeSession {
            session_id: session,
        },
    )
    .await
    .map_err(|source| Error::Broker { source })?
    {
        Response::SessionRevoked { live } => Ok(live),
        Response::Failed { error } => Err(Error::Refused(error)),
        Response::Registered { .. } | Response::Revoked { .. } | Response::SessionLanes { .. } => {
            Err(Error::Protocol("a single-registration answer"))
        }
    }
}

/// One composed lane's broker state, as `min session credentials` renders it
/// (R7.1).
///
/// Three states, not two: a broker that cannot be reached knows nothing about
/// any lane, which is a different fact from a broker that answered and holds no
/// registration. Collapsing them would render every lane on a host with no
/// broker as dead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaneState {
    /// The broker holds a live registration for the lane; a box's request on it
    /// would resolve.
    Live,
    /// The broker answered and holds none. Broker state is in memory and dies
    /// with its supervisor while sessions survive, so this is what a daemon or
    /// VM restart leaves behind — as well as what a revoke does.
    Dead,
    /// No broker answered, so nothing is known. The broker is best-effort: its
    /// supervisor warns and continues if it will not start, and on the
    /// host-side deployment models the control socket may simply not exist.
    Unknown,
}

impl LaneState {
    /// Where `lane` stands against the answer [`live_lanes`] returned.
    #[must_use]
    pub fn of(live: Option<&HashSet<String>>, lane: &str) -> Self {
        match live {
            Some(live) if live.contains(lane) => Self::Live,
            Some(_) => Self::Dead,
            None => Self::Unknown,
        }
    }

    /// The word the table and `--json` both render, so the two cannot drift.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Live => "live",
            Self::Dead => "dead",
            Self::Unknown => "unknown",
        }
    }
}

impl std::fmt::Display for LaneState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl serde::Serialize for LaneState {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

/// The lanes the broker still holds live registrations for, or `None` when no
/// broker answered.
///
/// Deliberately infallible. Every way this can fail — no control socket, no
/// broker listening, a broker that answered something else — means the same
/// thing to a caller that is only reporting: nothing is known. Returning an
/// error instead would fail a read-only command on the ordinary case of a host
/// that never started a broker, and returning an empty set would report every
/// lane dead on it.
pub async fn live_lanes(session: SessionId) -> Option<HashSet<String>> {
    let socket = credlane::control_socket_path().ok()?;
    match credlane::server::call(
        &socket,
        &Request::SessionLanes {
            session_id: session,
        },
    )
    .await
    {
        Ok(Response::SessionLanes { live }) => Some(live.into_iter().collect()),
        Ok(other) => {
            tracing::debug!(
                ?other,
                "the credential broker answered a lane listing with something else"
            );
            None
        }
        Err(error) => {
            tracing::debug!(%error, "no credential broker answered; lane state is unknown");
            None
        }
    }
}

/// Resolves and registers every lane the gate approved.
///
/// `pending` is the lane set the daemon shipped, snapshotted before the gate
/// consumed the response; `verdict` says which of them survived it. A lane the
/// policy denied or ignored is simply absent — it is never bound, never
/// resolved, and the user is never asked for a credential the box will not be
/// given.
///
/// Returns `None` when no lane was approved: with nothing to serve there is
/// nothing to register, and an activation that asked for no credential must
/// not require a broker to be running.
///
/// The registration is indexed by the verdict's own session id rather than one
/// passed alongside it — the two could not disagree, and it is what a later
/// [`revoke_session`] has to name it by.
///
/// # Errors
///
/// See [`Error`]. A declared-but-unbound lane fails here rather than
/// registering a lane with no destination.
pub async fn register_approved(
    pending: &[WirePendingCredential],
    verdict: &ContributionVerdict,
    bindings: &Bindings,
    env: &dyn Fn(&str) -> Result<String, std::env::VarError>,
) -> Result<Option<Registration>, Error> {
    let approved: HashSet<_> = verdict
        .credentials
        .iter()
        .filter_map(|v| match v {
            WireCredentialVerdict::Approved { id, .. } => Some(*id),
            WireCredentialVerdict::Denied { .. } | WireCredentialVerdict::Ignored { .. } => None,
        })
        .collect();

    let lanes = pending
        .iter()
        .filter(|p| approved.contains(&p.id))
        .map(|p| lane_registration(p, bindings, env))
        .collect::<Result<Vec<_>, Error>>()?;
    if lanes.is_empty() {
        return Ok(None);
    }

    let names: Vec<String> = lanes.iter().map(|lane| lane.lane.clone()).collect();
    let session_id = verdict.session_id;
    let socket = credlane::control_socket_path().map_err(|source| Error::Broker { source })?;
    match credlane::server::call(&socket, &Request::Register { session_id, lanes })
        .await
        .map_err(|source| Error::Broker { source })?
    {
        Response::Registered { token, handle } => {
            tracing::debug!(lanes = names.join(","), %handle, %session_id, "registered credential lanes");
            Ok(Some(Registration {
                token,
                handle,
                lanes: names,
            }))
        }
        Response::Failed { error } => Err(Error::Refused(error)),
        Response::Revoked { .. }
        | Response::SessionRevoked { .. }
        | Response::SessionLanes { .. } => Err(Error::Protocol("a revocation")),
    }
}

/// Builds one lane's registration from the declaration the gate approved and
/// the binding the user made for its name.
///
/// The upstream is read from the binding, not from the verdict that carries a
/// copy of it: the binding file is the one authority on where a credential may
/// be sent, and the project has no upstream field to disagree with it. The
/// method set comes from there for the same reason — narrowing a grant is the
/// grantor's — while the injection shape is the project's declaration.
fn lane_registration(
    pending: &WirePendingCredential,
    bindings: &Bindings,
    env: &dyn Fn(&str) -> Result<String, std::env::VarError>,
) -> Result<LaneRegistration, Error> {
    let binding = bindings
        .bindings()
        .get(&pending.lane)
        .ok_or_else(|| Error::Unbound {
            lane: pending.lane.clone(),
            path: bindings.path().to_owned(),
        })?;
    let upstream = Url::parse(&binding.upstream).map_err(|source| Error::Upstream {
        lane: pending.lane.clone(),
        upstream: binding.upstream.clone(),
        source,
    })?;
    let secret = resolve(&binding.source, env).map_err(|source| Error::Resolve {
        lane: pending.lane.clone(),
        source,
    })?;
    Ok(LaneRegistration {
        lane: pending.lane.clone(),
        upstream,
        inject: Inject::new(&pending.header, &pending.prefix).with_also(pending.also.clone()),
        secret,
        methods: binding.methods.clone(),
    })
}

#[cfg(test)]
mod tests {
    use std::env::VarError;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use credlane::{Broker, LaneTable as _};
    use sessions::core::source::Source;
    use sessions::wire::primitives::{PendingId, WireSource};

    use super::*;

    /// Serializes the tests that mutate the environment
    /// [`credlane::control_socket_path`] is derived from. Async, because
    /// the variable has to stay set across the registration's `await`.
    static ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    fn env_of(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Result<String, VarError> + use<> {
        let pairs: Vec<(String, String)> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        move |name| {
            pairs
                .iter()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.clone())
                .ok_or(VarError::NotPresent)
        }
    }

    #[test]
    fn the_env_resolver_reads_a_set_variable() {
        let env = env_of(&[("ANTHROPIC_API_KEY", "sk-live-hunter2")]);
        let secret = EnvResolver::new(&env).resolve("ANTHROPIC_API_KEY").unwrap();
        assert_eq!(secret.expose(), "sk-live-hunter2");
    }

    #[test]
    fn the_env_resolver_names_the_variable_that_was_not_set() {
        let env = env_of(&[]);
        let err = EnvResolver::new(&env)
            .resolve("ANTHROPIC_API_KEY")
            .unwrap_err();
        assert!(err.to_string().contains("ANTHROPIC_API_KEY"), "{err}");
    }

    /// A file written by an editor ends in a newline; a newline in a header
    /// value forges header lines, so it must not survive resolution.
    #[test]
    fn the_file_resolver_reads_a_file_without_its_trailing_newline() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().canonicalize().unwrap();
        let path = dir.join("token");
        std::fs::write(&path, b"sk-live-hunter2\n").unwrap();

        let secret = FileResolver::new(None)
            .resolve(path.to_str().unwrap())
            .unwrap();
        assert_eq!(secret.expose(), "sk-live-hunter2");
    }

    /// A symlink is the one way a path that passes every other check still
    /// reads a file the user did not name — at the leaf or anywhere above it.
    #[test]
    fn the_file_resolver_refuses_a_symlinked_component_at_any_level() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().canonicalize().unwrap();
        let real = dir.join("real");
        std::fs::create_dir(&real).unwrap();
        std::fs::write(real.join("token"), b"sk-live-hunter2\n").unwrap();

        std::os::unix::fs::symlink(&real, dir.join("linked-dir")).unwrap();
        std::os::unix::fs::symlink(real.join("token"), dir.join("linked-file")).unwrap();

        for candidate in [
            dir.join("linked-dir").join("token"),
            dir.join("linked-file"),
        ] {
            let err = FileResolver::new(None)
                .resolve(candidate.to_str().unwrap())
                .unwrap_err();
            assert!(
                matches!(err, ResolveError::Symlink { .. }),
                "{} must be refused, got {err}",
                candidate.display()
            );
        }
    }

    #[test]
    fn the_file_resolver_expands_a_leading_tilde_against_the_home_it_was_given() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().canonicalize().unwrap();
        std::fs::write(home.join("token"), b"sk-live-hunter2").unwrap();

        let secret = FileResolver::new(Some(home)).resolve("~/token").unwrap();
        assert_eq!(secret.expose(), "sk-live-hunter2");
    }

    /// Resolving against the invoking shell's cwd would make the same binding
    /// file mean different things from different directories.
    #[test]
    fn the_file_resolver_refuses_a_relative_path() {
        let err = FileResolver::new(None)
            .resolve("secrets/token")
            .unwrap_err();
        assert!(matches!(err, ResolveError::Relative { .. }), "{err}");
    }

    /// R5.3: the lane and the file to fix both have to be in the message —
    /// the lane name alone does not tell anyone where a binding goes.
    #[test]
    fn an_unbound_declared_lane_names_the_lane_and_the_binding_file() {
        let bindings = Bindings::new(
            "/home/dev/.config/minimal/credentials.toml",
            CredentialBindings::default(),
        );
        let error = ComposeError::UnboundCredentialLane {
            lane: "anthropic".into(),
            from: Source::UserLoadout { name: "dev".into() },
        };

        let rendered = bindings.gating_failure(&error).to_string();
        assert!(rendered.contains("anthropic"), "{rendered}");
        assert!(
            rendered.contains("/home/dev/.config/minimal/credentials.toml"),
            "{rendered}"
        );
    }

    fn pending(id: u32, lane: &str) -> WirePendingCredential {
        WirePendingCredential {
            id: PendingId::new(id),
            lane: lane.to_owned(),
            header: "Authorization".into(),
            prefix: "Bearer ".into(),
            also: std::collections::BTreeMap::new(),
            endpoint_var: None,
            source: WireSource::UserLoadout { name: "dev".into() },
        }
    }

    /// A distinct session id per `n`: the id the daemon allocated, which the
    /// verdict carries and the registration is indexed by.
    fn session(n: u8) -> SessionId {
        SessionId::parse_str(&format!("00000000-0000-0000-0000-0000000000{n:02}")).unwrap()
    }

    fn verdict_for(session: SessionId, items: Vec<WireCredentialVerdict>) -> ContributionVerdict {
        ContributionVerdict {
            session_id: session,
            vars: Vec::new(),
            patches: Vec::new(),
            lifecycle_hooks: Vec::new(),
            credentials: items,
        }
    }

    /// Bindings as the user writes them: one `[lane]` per triple of lane,
    /// upstream, and the variable its value comes from.
    fn bindings_of(lanes: &[(&str, &str, &str)]) -> Bindings {
        let toml = lanes
            .iter()
            .map(|(lane, upstream, var)| {
                format!("[{lane}]\nupstream = \"{upstream}\"\nsource = {{ env = \"{var}\" }}\n")
            })
            .collect::<String>();
        Bindings::new(
            "/config/credentials.toml",
            CredentialBindings::from_toml_str(&toml).unwrap(),
        )
    }

    #[tokio::test]
    async fn a_lane_the_gate_denied_is_never_resolved_or_registered() {
        let denied = verdict_for(
            session(1),
            vec![WireCredentialVerdict::Denied {
                id: PendingId::new(1),
            }],
        );
        let bindings = bindings_of(&[(
            "anthropic",
            "https://api.anthropic.com/v1/",
            "ANTHROPIC_API_KEY",
        )]);
        // Unset: a denied lane that reached its resolver would fail here
        // instead of registering nothing.
        let env = env_of(&[]);

        let registered = register_approved(&[pending(1, "anthropic")], &denied, &bindings, &env)
            .await
            .expect("a denied lane leaves nothing to register");
        assert!(registered.is_none(), "no lane, so no broker contact");
    }

    #[tokio::test]
    async fn an_approved_lane_the_user_never_bound_names_the_lane_and_the_file() {
        let approved = verdict_for(
            session(1),
            vec![WireCredentialVerdict::Approved {
                id: PendingId::new(1),
                upstream: "https://api.anthropic.com/v1/".into(),
            }],
        );
        let env = env_of(&[]);

        let err = register_approved(
            &[pending(1, "anthropic")],
            &approved,
            &bindings_of(&[]),
            &env,
        )
        .await
        .unwrap_err();

        let rendered = err.to_string();
        assert!(rendered.contains("anthropic"), "{rendered}");
        assert!(rendered.contains("/config/credentials.toml"), "{rendered}");
    }

    /// Runs `body` against a broker listening on the very socket
    /// [`credlane::control_socket_path`] resolves to, so a test exercises the
    /// path resolution the client really uses.
    ///
    /// The runtime-dir override is process-wide, so the lock is held across the
    /// body's awaits rather than around the two `set_var` calls alone.
    async fn with_broker<Fut: std::future::Future<Output = ()>>(
        body: impl FnOnce(Arc<Broker>) -> Fut,
    ) {
        let tmp = tempfile::tempdir().unwrap();
        let _guard = ENV_LOCK.lock().await;
        // SAFETY: the lock above serializes this against every other test that
        // reads the variable, and it is restored before returning.
        unsafe { std::env::set_var(credlane::server::RUNTIME_DIR_ENV, tmp.path()) };

        let socket = credlane::control_socket_path().unwrap();
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        let broker = Arc::new(Broker::new(Duration::from_secs(60)));
        tokio::spawn(credlane::server::serve_control(
            listener,
            Arc::clone(&broker),
        ));

        body(broker).await;
        // SAFETY: as above — still under `_guard`.
        unsafe { std::env::remove_var(credlane::server::RUNTIME_DIR_ENV) };
    }

    /// One lane, registered for a session, with the value this host resolved.
    async fn register_lane(session: SessionId, lane: &str, var: &str, value: &str) -> Registration {
        let approved = verdict_for(
            session,
            vec![WireCredentialVerdict::Approved {
                id: PendingId::new(1),
                upstream: "https://api.anthropic.com/v1/".into(),
            }],
        );
        let bindings = bindings_of(&[(lane, "https://api.anthropic.com/v1/", var)]);
        register_approved(
            &[pending(1, lane)],
            &approved,
            &bindings,
            &env_of(&[(var, value)]),
        )
        .await
        .expect("registration")
        .expect("an approved lane registers")
    }

    /// R5.2 and R5.4 together: what the broker ends up holding is the value
    /// this host resolved, bound to the upstream the *binding* names — not the
    /// one the verdict happens to carry a copy of.
    #[tokio::test]
    async fn registering_hands_the_broker_the_bound_upstream_and_the_resolved_value() {
        with_broker(|broker| async move {
            let approved = verdict_for(
                session(1),
                vec![
                    WireCredentialVerdict::Approved {
                        id: PendingId::new(1),
                        upstream: "https://impostor.example/".into(),
                    },
                    WireCredentialVerdict::Ignored {
                        id: PendingId::new(2),
                    },
                ],
            );
            let bindings = bindings_of(&[
                (
                    "anthropic",
                    "https://api.anthropic.com/v1/",
                    "ANTHROPIC_API_KEY",
                ),
                ("github-mcp", "https://api.github.com/mcp/", "GH_PAT"),
            ]);
            let env = env_of(&[("ANTHROPIC_API_KEY", "sk-live-hunter2\n")]);

            let registration = register_approved(
                &[pending(1, "anthropic"), pending(2, "github-mcp")],
                &approved,
                &bindings,
                &env,
            )
            .await
            .expect("registration")
            .expect("an approved lane registers");

            let lane = broker
                .resolve(registration.token().expose(), "anthropic", Instant::now())
                .expect("the minted token authorises the approved lane");
            assert_eq!(
                lane.upstream().as_str(),
                "https://api.anthropic.com/v1/",
                "the binding's upstream wins over the verdict's copy"
            );
            assert_eq!(
                lane.inject().header_value(lane.secret()),
                "Bearer sk-live-hunter2"
            );
            assert!(
                lane.allows_method("GET"),
                "a binding with no `methods` covers every one"
            );
            assert!(
                broker
                    .resolve(registration.token().expose(), "github-mcp", Instant::now())
                    .is_err(),
                "an ignored lane must not be registered"
            );
        })
        .await;
    }

    /// R10.4 and R10.3 on the registration path: the verb set is the user's,
    /// read from the binding, and the extra headers are the project's, read
    /// from the declaration. Both are constraints, so both have to survive
    /// the trip to the broker — dropping either widens the grant silently.
    #[tokio::test]
    async fn registering_carries_the_bound_methods_and_the_declared_extra_headers() {
        with_broker(|broker| async move {
            let approved = verdict_for(
                session(1),
                vec![WireCredentialVerdict::Approved {
                    id: PendingId::new(1),
                    upstream: "https://api.github.com/gists".into(),
                }],
            );
            let bindings = Bindings::new(
                "/config/credentials.toml",
                CredentialBindings::from_toml_str(
                    "[gist-sink]\n\
                     upstream = \"https://api.github.com/gists\"\n\
                     source = { env = \"GH_PAT\" }\n\
                     methods = [\"POST\"]\n",
                )
                .unwrap(),
            );
            let mut declared = pending(1, "gist-sink");
            declared.also = std::collections::BTreeMap::from([(
                "X-MCP-Readonly".to_owned(),
                "true".to_owned(),
            )]);

            let registration = register_approved(
                &[declared],
                &approved,
                &bindings,
                &env_of(&[("GH_PAT", "ghp-live-hunter2")]),
            )
            .await
            .expect("registration")
            .expect("an approved lane registers");

            let lane = broker
                .resolve(registration.token().expose(), "gist-sink", Instant::now())
                .expect("the minted token authorises the approved lane");
            assert!(lane.allows_method("POST"));
            assert!(
                !lane.allows_method("GET"),
                "a method outside the binding's set must not be covered"
            );
            assert_eq!(
                lane.inject()
                    .also()
                    .get("X-MCP-Readonly")
                    .map(String::as_str),
                Some("true")
            );
        })
        .await;
    }

    /// R3.4: `min session destroy` runs in a process that never held the
    /// handle, so it revokes by session id — and one box's teardown must not
    /// touch another box's lane of the same name.
    #[tokio::test]
    async fn revoking_by_session_id_refuses_that_sessions_token_and_no_others() {
        with_broker(|broker| async move {
            let doomed = register_lane(session(1), "anthropic", "KEY_A", "sk-doomed").await;
            let kept = register_lane(session(2), "anthropic", "KEY_B", "sk-kept").await;
            let header = |reg: &Registration| {
                broker
                    .resolve(reg.token().expose(), "anthropic", Instant::now())
                    .map(|lane| lane.inject().header_value(lane.secret()))
            };
            assert_eq!(header(&doomed).unwrap(), "Bearer sk-doomed");
            assert_eq!(
                header(&kept).unwrap(),
                "Bearer sk-kept",
                "one lane name, two sessions, two credentials"
            );

            assert_eq!(revoke_session(session(1)).await.unwrap(), 1);
            assert!(
                header(&doomed).is_err(),
                "a destroyed session's token must stop resolving"
            );
            assert_eq!(header(&kept).unwrap(), "Bearer sk-kept");
        })
        .await;
    }

    /// Every destroy revokes, and most sessions never registered a lane at all.
    #[tokio::test]
    async fn revoking_a_session_that_never_registered_reports_nothing_live() {
        with_broker(|_broker| async move {
            assert_eq!(revoke_session(session(9)).await.unwrap(), 0);
        })
        .await;
    }

    /// R7.1: the lane a box can actually reach reports live, and one the same
    /// session never registered reports dead rather than sharing its fate.
    #[tokio::test]
    async fn a_lane_the_broker_still_holds_reports_live_and_an_unregistered_one_reports_dead() {
        with_broker(|_broker| async move {
            let _registration = register_lane(session(1), "anthropic", "KEY_A", "sk-live").await;

            let live = live_lanes(session(1)).await;
            assert_eq!(LaneState::of(live.as_ref(), "anthropic"), LaneState::Live);
            assert_eq!(LaneState::of(live.as_ref(), "github-mcp"), LaneState::Dead);
        })
        .await;
    }

    /// The state a restarted daemon or VM leaves behind — its registrations
    /// died with it while the session lived on — reached here by the one path
    /// a test can drive deterministically.
    #[tokio::test]
    async fn a_lane_whose_registration_is_gone_reports_dead_while_another_sessions_stays_live() {
        with_broker(|_broker| async move {
            let _doomed = register_lane(session(1), "anthropic", "KEY_A", "sk-doomed").await;
            let _kept = register_lane(session(2), "anthropic", "KEY_B", "sk-kept").await;
            assert_eq!(revoke_session(session(1)).await.unwrap(), 1);

            let doomed = live_lanes(session(1)).await;
            assert_eq!(LaneState::of(doomed.as_ref(), "anthropic"), LaneState::Dead);
            let kept = live_lanes(session(2)).await;
            assert_eq!(LaneState::of(kept.as_ref(), "anthropic"), LaneState::Live);
        })
        .await;
    }

    /// The broker is best-effort — its supervisor warns and continues if it
    /// will not start — so a host with none is ordinary, and must render as
    /// "nothing is known" rather than failing the command or claiming every
    /// lane is dead.
    #[tokio::test]
    async fn an_absent_broker_leaves_a_lane_unknown_rather_than_dead() {
        let tmp = tempfile::tempdir().unwrap();
        let _guard = ENV_LOCK.lock().await;
        // SAFETY: the lock serializes this against every other test reading the
        // variable, and it is restored before returning. The directory is real
        // but empty, so the control socket resolves and simply is not there.
        unsafe { std::env::set_var(credlane::server::RUNTIME_DIR_ENV, tmp.path()) };

        let live = live_lanes(session(1)).await;
        assert!(live.is_none(), "an absent broker answers nothing");
        assert_eq!(
            LaneState::of(live.as_ref(), "anthropic"),
            LaneState::Unknown
        );

        // SAFETY: as above — still under `_guard`.
        unsafe { std::env::remove_var(credlane::server::RUNTIME_DIR_ENV) };
    }

    /// The table and `--json` must not drift into two vocabularies for one
    /// state; the JSON form is the string the column shows.
    #[test]
    fn a_lane_state_serializes_as_the_word_the_table_prints() {
        for state in [LaneState::Live, LaneState::Dead, LaneState::Unknown] {
            assert_eq!(
                serde_json_lenient::to_string(&state).unwrap(),
                format!("\"{}\"", state.as_str())
            );
        }
    }
}
