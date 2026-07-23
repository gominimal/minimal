//! Realm-tagged path types.
//!
//! `PathBuf` carries no information about *which* filesystem a path belongs
//! to. In a system that bridges the user's host, the sandbox rootfs, and
//! (eventually) the minimald daemon, that ambiguity is a footgun: it is easy
//! to pass a host path to code that expects a sandbox-internal path, and the
//! type checker will not stop you.
//!
//! This crate encodes the filesystem a path belongs to as a *phantom type
//! parameter*, splits absolute and relative paths into distinct types, and
//! requires crossing realms to go through an explicit [`Translator`].
//!
//! # Quick tour
//!
//! - [`Realm`] is a marker trait; [`Host`], [`Sandbox`], [`Daemon`], and
//!   [`ConfigRelative`] are the zero-sized implementors.
//! - [`AbsPath<R>`] is an absolute UTF-8 path tagged with realm `R`.
//! - [`RelPath<R>`] is a relative UTF-8 path tagged with the realm it will
//!   eventually resolve in.
//! - [`AbsPath::join`] only accepts a [`RelPath`], which kills the "join an
//!   absolute onto an absolute and silently drop the base" footgun by
//!   construction.
//! - [`RelPath<ConfigRelative>::bind_to_host`] is the one sanctioned way to
//!   leave the [`ConfigRelative`] realm.
//!
//! # Example
//!
//! ```
//! use paths::{AbsPath, Host, RelPath};
//!
//! let base: AbsPath<Host> = AbsPath::try_new("/etc/minimal").unwrap();
//! let rel: RelPath<Host> = RelPath::try_new("hooks/cleanup.sh").unwrap();
//!
//! let joined = base.join(&rel);
//! assert_eq!(joined.as_utf8_path().as_str(), "/etc/minimal/hooks/cleanup.sh");
//!
//! // Passing an absolute string to `RelPath::try_new` is a *compile-time*-shaped
//! // error: it fails at construction, so `AbsPath::join` cannot silently
//! // override its base.
//! assert!(RelPath::<Host>::try_new("/oops/absolute").is_err());
//! ```

use camino::{Utf8Components, Utf8Path, Utf8PathBuf};
use core::fmt;
use core::marker::PhantomData;
use std::borrow::Borrow;
use std::cmp::Ordering;
use std::path::Path;
use std::str::FromStr;

/// Marker trait for filesystem realms.
///
/// Implementors are zero-sized; instances never exist at runtime — the realm
/// is encoded purely in the type system. `NAME` is used in [`fmt::Debug`]
/// output so logs and panics are unambiguous about which realm a path belongs
/// to.
pub trait Realm: 'static {
    /// Lowercase identifier used in [`fmt::Debug`] output.
    const NAME: &'static str;
}

/// The user's host filesystem.
#[derive(Debug, Copy, Clone)]
pub struct Host;
impl Realm for Host {
    const NAME: &'static str = "host";
}

/// A sandbox rootfs constructed by `sandbox2`.
#[derive(Debug, Copy, Clone)]
pub struct Sandbox;
impl Realm for Sandbox {
    const NAME: &'static str = "sandbox";
}

/// The minimald daemon's filesystem view (future).
#[derive(Debug, Copy, Clone)]
pub struct Daemon;
impl Realm for Daemon {
    const NAME: &'static str = "daemon";
}

/// A path whose anchor is "the directory of the config file it was decoded
/// from".
///
/// [`ConfigRelative`] paths cannot be used directly — they must be bound to a
/// concrete host directory via
/// [`RelPath::<ConfigRelative>::bind_to_host`].
#[derive(Debug, Copy, Clone)]
pub struct ConfigRelative;
impl Realm for ConfigRelative {
    const NAME: &'static str = "config-relative";
}

/// Absolute path on the user's host filesystem.
pub type HostAbsPath = AbsPath<Host>;
/// Relative path resolved against a [`Host`]-realm anchor.
pub type HostRelPath = RelPath<Host>;
/// Either an absolute or relative path in the [`Host`] realm.
pub type HostPath = EitherPath<Host>;
/// Absolute path inside a sandbox rootfs.
pub type SandboxAbsPath = AbsPath<Sandbox>;
/// Relative path resolved against a [`Sandbox`]-realm anchor.
pub type SandboxRelPath = RelPath<Sandbox>;
/// Either an absolute or relative path in the [`Sandbox`] realm.
pub type SandboxPath = EitherPath<Sandbox>;
/// Absolute path in the minimald daemon's filesystem view.
pub type DaemonAbsPath = AbsPath<Daemon>;
/// Relative path resolved against a [`Daemon`]-realm anchor.
pub type DaemonRelPath = RelPath<Daemon>;
/// Either an absolute or relative path in the [`Daemon`] realm.
pub type DaemonPath = EitherPath<Daemon>;
/// Relative path anchored to the directory of the config file it was decoded
/// from. There is no absolute variant — config-relative paths only make
/// sense as relatives waiting to be bound via
/// [`RelPath::<ConfigRelative>::bind_to_host`].
pub type ConfigRelPath = RelPath<ConfigRelative>;

/// Returns minimal's default cache directory, `<cache>/minimal`.
///
/// The base is the platform cache directory (e.g. `$XDG_CACHE_HOME` or
/// `~/.cache` on Linux), falling back to `~/.cache` when it cannot be
/// determined.
///
/// # Panics
///
/// Panics if neither a cache directory nor a home directory can be resolved,
/// or if the resulting path is not valid UTF-8.
pub fn minimal_cache_dir() -> DaemonAbsPath {
    default_dir(dirs::cache_dir, ".cache")
}

/// Returns minimal's default state directory, `<state>/minimal`.
///
/// The base is `$XDG_STATE_HOME` when set (honored on all platforms;
/// `dirs::state_dir` ignores it on macOS), else the platform state directory,
/// else `~/.local/state`.
///
/// # Panics
///
/// Panics if neither a state directory nor a home directory can be resolved,
/// or if the resulting path is not valid UTF-8.
pub fn minimal_state_dir() -> DaemonAbsPath {
    let explicit = std::env::var_os("XDG_STATE_HOME")
        .map(std::path::PathBuf::from)
        .filter(|p| p.is_absolute());
    default_dir(|| explicit.or_else(dirs::state_dir), ".local/state")
}

/// File name of the daemon SSH socket in a provider instance dir. Served by
/// native minimald or by the minvmd host↔guest bridge — one endpoint either way.
pub const SSH_SOCK_FILE: &str = "ssh.sock";
/// File name of the SSH `known_hosts` in a provider instance dir, recording the
/// daemon's host key under the `local-<instance>` hostname. Written at startup
/// by native minimald, and by minvmd from the guest's boot beacon.
pub const KNOWN_HOSTS_FILE: &str = "known_hosts";
/// Remove any existing `known_hosts` lines in `path` whose host field is
/// `host`, so a freshly recorded key for that host replaces — rather than
/// accumulates alongside — the prior entry.
///
/// `russh`'s `learn_known_hosts_path` only ever appends, so without pruning
/// first, a daemon that re-records its host key on every spawn grows the file
/// without bound; and when the guest rotates its key on each boot the file also
/// keeps every stale key. Call this immediately before `learn_known_hosts_path`
/// (issue #782).
///
/// A missing file is not an error (nothing to prune), and the file is left
/// byte-for-byte untouched when no line matches. The host field is the first
/// whitespace-delimited token; both the bare `host` (port 22) and the
/// `[host]:port` forms `russh` emits are matched.
///
/// # Errors
///
/// Returns any I/O error from reading or rewriting the file, except a
/// not-found read, which is treated as an empty file and yields `Ok`.
pub fn prune_known_hosts_host(path: impl AsRef<Path>, host: &str) -> std::io::Result<()> {
    let path = path.as_ref();
    let contents = match std::fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(err),
    };
    let kept: Vec<&str> = contents
        .lines()
        .filter(|line| !known_hosts_line_matches_host(line, host))
        .collect();
    // Nothing matched: leave the file (and its exact bytes) untouched.
    if kept.len() == contents.lines().count() {
        return Ok(());
    }
    let rewritten = if kept.is_empty() {
        String::new()
    } else {
        format!("{}\n", kept.join("\n"))
    };
    std::fs::write(path, rewritten)
}

/// Whether a single `known_hosts` line's host field equals `host`, matching
/// both the bare `host` and the bracketed `[host]:port` forms.
fn known_hosts_line_matches_host(line: &str, host: &str) -> bool {
    line.split_whitespace().next().is_some_and(|field| {
        field == host
            || field
                .strip_prefix('[')
                .and_then(|rest| rest.split_once("]:"))
                .is_some_and(|(bracketed, _)| bracketed == host)
    })
}

/// Native minimald's single-instance lock, held for the daemon's lifetime.
pub const MINIMALD_LOCK_FILE: &str = "minimald.lock";
/// The minvmd supervisor's alive lock, held for the daemon's lifetime.
pub const MINVMD_LOCK_FILE: &str = "minvmd.lock";

/// `<state_dir>/providers/local-<instance>` — the directory holding the
/// sockets, locks, and state files a client needs to reach one local daemon
/// instance.
pub fn provider_instance_dir(state_dir: &DaemonAbsPath, instance: u32) -> DaemonAbsPath {
    sub_path!(state_dir, "providers").sub_path_unchecked(&format!("local-{instance}"))
}

/// Returns minimal's default config directory, `<config>/minimal`.
///
/// The base is `$XDG_CONFIG_HOME` when set to an absolute path, otherwise
/// `~/.config` on every platform. Deliberately does not use
/// [`dirs::config_dir`]: on macOS that would produce
/// `~/Library/Application Support`, diverging from how the rest of minimal's
/// on-disk state is laid out ([`minimal_state_dir`] already falls through to
/// `~/.local/state`). One layout everywhere is easier to document, and users
/// who genuinely want the platform-native location can override with the
/// CLI's `--config-dir` flag.
///
/// # Panics
///
/// Panics if neither `$XDG_CONFIG_HOME` nor a home directory can be
/// resolved, or if the resulting path is not valid UTF-8.
pub fn minimal_config_dir() -> DaemonAbsPath {
    default_dir(xdg_config_home, ".config")
}

/// Return `$XDG_CONFIG_HOME` if it's set to an absolute path. Matches the
/// spec: [XDG Base Directory Specification, "XDG_CONFIG_HOME"](https://specifications.freedesktop.org/basedir-spec/basedir-spec-latest.html)
/// says relative paths are invalid and should be ignored.
fn xdg_config_home() -> Option<std::path::PathBuf> {
    std::env::var_os("XDG_CONFIG_HOME")
        .map(std::path::PathBuf::from)
        .filter(|p| p.is_absolute())
}

/// Returns minimal's default data directory, `<data>/minimal`.
///
/// The base is `$XDG_DATA_HOME` when set to an absolute path, otherwise
/// `~/.local/share` on every platform — the same resolution
/// `scripts/install.sh` uses for `data`-prefix components, so paths derived
/// here point at what the installer actually shipped. Like
/// [`minimal_config_dir`], deliberately not [`dirs::data_dir`]: on macOS that
/// would be `~/Library/Application Support`.
///
/// # Panics
///
/// Panics if neither `$XDG_DATA_HOME` nor a home directory can be resolved,
/// or if the resulting path is not valid UTF-8.
pub fn minimal_data_dir() -> DaemonAbsPath {
    default_dir(xdg_data_home, ".local/share")
}

/// Return `$XDG_DATA_HOME` if it's set to an absolute path, per the XDG
/// spec's rule that relative paths are invalid and should be ignored.
fn xdg_data_home() -> Option<std::path::PathBuf> {
    std::env::var_os("XDG_DATA_HOME")
        .map(std::path::PathBuf::from)
        .filter(|p| p.is_absolute())
}

/// Computes `<base>/minimal`, where `base` comes from `base_dir` or, failing
/// that, `~/<home_fallback>`.
fn default_dir(
    base_dir: impl FnOnce() -> Option<std::path::PathBuf>,
    home_fallback: &str,
) -> DaemonAbsPath {
    let base = base_dir().unwrap_or_else(|| {
        dirs::home_dir()
            .expect("could not determine home directory")
            .join(home_fallback)
    });
    let path = Utf8PathBuf::from_path_buf(base.join("minimal"))
        .expect("default directory path is not valid UTF-8");
    DaemonAbsPath::try_new(path).expect("default directory path is not absolute")
}

/// Errors produced when constructing a path.
#[non_exhaustive]
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// An [`AbsPath`] was constructed from a non-absolute input.
    #[error("expected an absolute path, got: {0}")]
    NotAbsolute(Utf8PathBuf),
    /// A [`RelPath`] was constructed from an absolute input.
    #[error("expected a relative path, got: {0}")]
    IsAbsolute(Utf8PathBuf),
    /// A [`RelPath`] contained a `..` component, which would let it
    /// escape whatever base it was joined against. Rejected at
    /// construction so any caller who joins the path against a
    /// sensitive root (e.g. a sandbox home dir) doesn't have to
    /// re-validate.
    #[error("path contains a `..` traversal component: {0}")]
    ContainsParentDir(Utf8PathBuf),
}

#[doc(hidden)]
pub const fn _validate_subdir(s: &str) {
    let bytes = s.as_bytes();
    assert!(!bytes.is_empty(), "`sub_path` component must not be empty");
    let mut i = 0;
    while i < bytes.len() {
        assert!(
            bytes[i] != b'/',
            "`sub_path` component must not contain `/`"
        );
        i += 1;
    }
    assert!(
        !(bytes.len() == 2 && bytes[0] == b'.' && bytes[1] == b'.'),
        "`sub_path` component must not be `..`"
    );
}

/// Joins a literal representing a sub-component onto the end of a path. Will
/// emit a compile-time error if the component is not valid, for instance if
/// it contains multiple components, is absolute, or attempts directory traversal.
#[macro_export]
macro_rules! sub_path {
    ($base:expr, $dir:literal) => {{
        #[allow(clippy::used_underscore_items)]
        const _: () = $crate::_validate_subdir($dir);
        ($base).sub_path_unchecked($dir)
    }};
}

/// An *absolute* UTF-8 path in realm `R`.
///
/// Invariant: `inner.is_absolute()` is always true. Construction goes through
/// [`AbsPath::try_new`], which validates the input.
///
/// The realm parameter is phantom: `AbsPath<Host>` and `AbsPath<Sandbox>` are
/// distinct types that the compiler will not mix. Crossing realms requires a
/// [`Translator`].
#[must_use]
pub struct AbsPath<R: Realm> {
    inner: Utf8PathBuf,
    _realm: PhantomData<fn() -> R>,
}

impl<R: Realm> AbsPath<R> {
    /// Constructs an [`AbsPath`] after verifying the input is absolute.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotAbsolute`] if `p` is relative.
    pub fn try_new(p: impl Into<Utf8PathBuf>) -> Result<Self, Error> {
        let inner = p.into();
        if inner.is_absolute() {
            Ok(Self {
                inner,
                _realm: PhantomData,
            })
        } else {
            Err(Error::NotAbsolute(inner))
        }
    }

    /// Construct an [`AbsPath`] without verifying that `p` is
    /// absolute.
    ///
    /// Use only when the caller has already proven absoluteness by
    /// other means (e.g. the path came from `walkdir::WalkDir::new`
    /// rooted at an absolute path). A `debug_assert!` catches misuse
    /// in development builds; release builds skip the check.
    pub fn new_unchecked(p: impl Into<Utf8PathBuf>) -> Self {
        let p = p.into();
        debug_assert!(p.is_absolute());
        Self {
            inner: p,
            _realm: PhantomData,
        }
    }

    /// Returns the root path (`/`), assuming a POSIX-like system.
    ///
    /// This is a convenience for places that need a known-absolute
    /// root in the [`Realm`] of the caller. Not appropriate on
    /// Windows, where the root concept differs.
    pub fn root() -> Self {
        Self {
            inner: Utf8PathBuf::from("/"),
            _realm: PhantomData,
        }
    }

    /// Borrows the underlying UTF-8 path.
    #[must_use]
    pub fn as_utf8_path(&self) -> &Utf8Path {
        &self.inner
    }

    /// Borrows the underlying path as a `&str`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.inner.as_str()
    }

    /// Joins a relative path *in the same realm*, producing a new
    /// [`AbsPath<R>`].
    ///
    /// Unlike [`Utf8PathBuf::join`], this cannot be passed an absolute path:
    /// [`RelPath`] is constructively non-absolute, so the "join overrides
    /// base" footgun is unreachable.
    pub fn join(&self, rel: &RelPath<R>) -> AbsPath<R> {
        AbsPath {
            inner: self.inner.join(&rel.inner),
            _realm: PhantomData,
        }
    }

    /// Joins a single sub-component *in the same realm*, producing a new
    /// [`AbsPath<R>`].
    ///
    /// Trusts the caller; prefer the [`sub_path!`] macro at literal call
    /// sites so the constraint is enforced at compile time.
    pub fn sub_path_unchecked(&self, dir: &str) -> AbsPath<R> {
        AbsPath {
            inner: self.inner.join(dir),
            _realm: PhantomData,
        }
    }

    /// Returns the parent directory, if any.
    #[must_use]
    pub fn parent(&self) -> Option<AbsPath<R>> {
        self.inner.parent().map(|p| AbsPath {
            inner: p.to_owned(),
            _realm: PhantomData,
        })
    }

    /// Strips `base` from the front of this path and returns the suffix as
    /// a [`RelPath<R>`].
    ///
    /// # Errors
    ///
    /// Returns [`std::path::StripPrefixError`] when `base` is not a prefix.
    pub fn strip_prefix(
        &self,
        base: &AbsPath<R>,
    ) -> Result<RelPath<R>, std::path::StripPrefixError> {
        self.inner.strip_prefix(&base.inner).map(|p| RelPath {
            inner: p.to_owned(),
            _realm: PhantomData,
        })
    }

    /// The final component of the path, if any.
    #[must_use]
    pub fn file_name(&self) -> Option<&str> {
        self.inner.file_name()
    }

    /// The extension of the final component, if any.
    #[must_use]
    pub fn extension(&self) -> Option<&str> {
        self.inner.extension()
    }

    /// Iterator over the path's components.
    pub fn components(&self) -> Utf8Components<'_> {
        self.inner.components()
    }

    /// Returns an absolute path representing the current
    /// working directory in the current realm.
    ///
    /// # Errors
    ///
    ///  * The current directory is not accessible
    ///  * The current directory contains non-UTF8 characters.
    pub fn from_cwd() -> Result<Self, std::io::Error> {
        let Ok(cwd) = Utf8PathBuf::from_path_buf(std::env::current_dir()?) else {
            return Err(std::io::Error::other("cwd contains not-utf8 characters"));
        };
        Ok(Self {
            inner: cwd,
            _realm: PhantomData,
        })
    }
}

impl<R: Realm> Clone for AbsPath<R> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            _realm: PhantomData,
        }
    }
}

impl<R: Realm> PartialEq for AbsPath<R> {
    fn eq(&self, other: &Self) -> bool {
        self.inner == other.inner
    }
}

impl<R: Realm> Eq for AbsPath<R> {}

impl<R: Realm> std::hash::Hash for AbsPath<R> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.inner.hash(state);
    }
}

impl<R: Realm> PartialOrd for AbsPath<R> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<R: Realm> Ord for AbsPath<R> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.inner.cmp(&other.inner)
    }
}

impl<R: Realm> AsRef<Utf8Path> for AbsPath<R> {
    fn as_ref(&self) -> &Utf8Path {
        &self.inner
    }
}

impl<R: Realm> AsRef<Path> for AbsPath<R> {
    fn as_ref(&self) -> &Path {
        self.inner.as_std_path()
    }
}

impl<R: Realm> AsRef<str> for AbsPath<R> {
    fn as_ref(&self) -> &str {
        self.inner.as_str()
    }
}

impl<R: Realm> Borrow<Utf8Path> for AbsPath<R> {
    fn borrow(&self) -> &Utf8Path {
        &self.inner
    }
}

impl<R: Realm> FromStr for AbsPath<R> {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_new(s)
    }
}

impl<R: Realm> fmt::Debug for AbsPath<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AbsPath<{}>({})", R::NAME, self.inner)
    }
}

impl<R: Realm> fmt::Display for AbsPath<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.inner, f)
    }
}

impl<R: Realm> serde::Serialize for AbsPath<R> {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        self.inner.serialize(ser)
    }
}

impl<'de, R: Realm> serde::Deserialize<'de> for AbsPath<R> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let p = Utf8PathBuf::deserialize(deserializer)?;
        Self::try_new(p).map_err(serde::de::Error::custom)
    }
}

/// A *relative* UTF-8 path, tagged with the realm it will resolve in.
///
/// Invariant: `inner.is_absolute()` is always false. Construction goes
/// through [`RelPath::new`], which validates the input.
#[must_use]
pub struct RelPath<R: Realm> {
    inner: Utf8PathBuf,
    _realm: PhantomData<fn() -> R>,
}

impl<R: Realm> RelPath<R> {
    /// Constructs a [`RelPath`] after verifying the input is neither
    /// absolute nor contains a `..` traversal component.
    ///
    /// The `..` rejection is what lets callers like the daemon
    /// composer trust a [`SandboxRelPath`] arriving over the wire —
    /// joining it against the sandbox home can't produce a path
    /// outside that home.
    ///
    /// # Errors
    ///
    /// - [`Error::IsAbsolute`] if `p` is an absolute path.
    /// - [`Error::ContainsParentDir`] if any component is `..`.
    pub fn try_new(p: impl Into<Utf8PathBuf>) -> Result<Self, Error> {
        let inner = p.into();
        if inner.is_absolute() {
            return Err(Error::IsAbsolute(inner));
        }
        if inner
            .components()
            .any(|c| matches!(c, camino::Utf8Component::ParentDir))
        {
            return Err(Error::ContainsParentDir(inner));
        }
        Ok(Self {
            inner,
            _realm: PhantomData,
        })
    }

    /// Construct a [`RelPath`] without verifying that `p` is
    /// relative.
    ///
    /// Use only when the caller has already proven relativity by other
    /// means (e.g. the path was produced by `strip_prefix` against a
    /// known absolute root). A `debug_assert!` catches misuse in
    /// development builds; release builds skip the check.
    pub fn new_unchecked(p: impl Into<Utf8PathBuf>) -> Self {
        let p = p.into();
        debug_assert!(p.is_relative());
        debug_assert!(
            !p.components()
                .any(|c| matches!(c, camino::Utf8Component::ParentDir)),
            "`RelPath::new_unchecked` fed a path with a `..` component: {p}"
        );
        Self {
            inner: p,
            _realm: PhantomData,
        }
    }

    /// Borrows the underlying UTF-8 path.
    #[must_use]
    pub fn as_utf8_path(&self) -> &Utf8Path {
        &self.inner
    }

    /// Borrows the underlying path as a `&str`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.inner.as_str()
    }

    /// Joins another relative path in the same realm.
    pub fn join(&self, other: &RelPath<R>) -> RelPath<R> {
        RelPath {
            inner: self.inner.join(&other.inner),
            _realm: PhantomData,
        }
    }

    /// Joins a single sub-component *in the same realm*, producing a new
    /// [`RelPath<R>`].
    ///
    /// Trusts the caller; prefer the [`sub_path!`] macro at literal call
    /// sites so the constraint is enforced at compile time.
    pub fn sub_path_unchecked(&self, dir: &str) -> RelPath<R> {
        RelPath {
            inner: self.inner.join(dir),
            _realm: PhantomData,
        }
    }

    /// Resolves this relative path against an absolute base in the *same*
    /// realm.
    ///
    /// To cross realms, see [`Translator`] (or, for [`ConfigRelative`],
    /// [`RelPath::<ConfigRelative>::bind_to_host`]).
    pub fn resolve_against(&self, base: &AbsPath<R>) -> AbsPath<R> {
        base.join(self)
    }

    /// Returns the parent directory, if any.
    #[must_use]
    pub fn parent(&self) -> Option<RelPath<R>> {
        self.inner.parent().map(|p| RelPath {
            inner: p.to_owned(),
            _realm: PhantomData,
        })
    }

    /// The final component of the path, if any.
    #[must_use]
    pub fn file_name(&self) -> Option<&str> {
        self.inner.file_name()
    }

    /// The extension of the final component, if any.
    #[must_use]
    pub fn extension(&self) -> Option<&str> {
        self.inner.extension()
    }

    /// Iterator over the path's components.
    pub fn components(&self) -> Utf8Components<'_> {
        self.inner.components()
    }
}

impl RelPath<ConfigRelative> {
    /// Anchors a config-relative path against a host-side config directory,
    /// producing a host-realm absolute path.
    ///
    /// This is the one sanctioned way to leave the [`ConfigRelative`] realm.
    /// Lifecycle hooks decoded from a `minimal.toml` start life as
    /// `RelPath<ConfigRelative>`; once the decoder knows the directory of
    /// the file they came from, it calls `bind_to_host` to produce something
    /// the executor can actually run.
    ///
    /// The returned path is *not* canonicalized — interior `.` or `..`
    /// components survive. If a caller needs a canonical path, it must run
    /// the result through `std::fs::canonicalize` (or similar) itself.
    pub fn bind_to_host(&self, config_dir: &AbsPath<Host>) -> AbsPath<Host> {
        AbsPath {
            inner: config_dir.inner.join(&self.inner),
            _realm: PhantomData,
        }
    }
}

impl<R: Realm> Clone for RelPath<R> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            _realm: PhantomData,
        }
    }
}

impl<R: Realm> PartialEq for RelPath<R> {
    fn eq(&self, other: &Self) -> bool {
        self.inner == other.inner
    }
}

impl<R: Realm> Eq for RelPath<R> {}

impl<R: Realm> std::hash::Hash for RelPath<R> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.inner.hash(state);
    }
}

impl<R: Realm> PartialOrd for RelPath<R> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<R: Realm> Ord for RelPath<R> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.inner.cmp(&other.inner)
    }
}

impl<R: Realm> AsRef<Utf8Path> for RelPath<R> {
    fn as_ref(&self) -> &Utf8Path {
        &self.inner
    }
}

impl<R: Realm> AsRef<Path> for RelPath<R> {
    fn as_ref(&self) -> &Path {
        self.inner.as_std_path()
    }
}

impl<R: Realm> AsRef<str> for RelPath<R> {
    fn as_ref(&self) -> &str {
        self.inner.as_str()
    }
}

impl<R: Realm> Borrow<Utf8Path> for RelPath<R> {
    fn borrow(&self) -> &Utf8Path {
        &self.inner
    }
}

impl<R: Realm> FromStr for RelPath<R> {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_new(s)
    }
}

impl<R: Realm> fmt::Debug for RelPath<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RelPath<{}>({})", R::NAME, self.inner)
    }
}

impl<R: Realm> fmt::Display for RelPath<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.inner, f)
    }
}

impl<R: Realm> serde::Serialize for RelPath<R> {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        self.inner.serialize(ser)
    }
}

impl<'de, R: Realm> serde::Deserialize<'de> for RelPath<R> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let p = Utf8PathBuf::deserialize(deserializer)?;
        Self::try_new(p).map_err(serde::de::Error::custom)
    }
}

/// Either an [`AbsPath<R>`] or a [`RelPath<R>`], for config fields where the
/// user may legitimately supply either.
///
/// Resolving the relative case against some realm-appropriate base is the
/// caller's responsibility — `EitherPath` only encodes the choice.
///
/// # Wire form
///
/// Serializes as a bare path string. Deserialization auto-detects: a leading
/// `/` parses as [`Abs`](Self::Abs), anything else as [`Rel`](Self::Rel). No
/// tag is needed — every UTF-8 path is unambiguously one or the other.
///
/// ```
/// use paths::HostPath;
///
/// let abs: HostPath = toml::from_str::<Wrap>(r#"x = "/etc/minimal""#).unwrap().x;
/// let rel: HostPath = toml::from_str::<Wrap>(r#"x = "etc/minimal""#).unwrap().x;
/// assert!(abs.is_absolute());
/// assert!(!rel.is_absolute());
/// # #[derive(serde::Deserialize)] struct Wrap { x: HostPath }
/// ```
pub enum EitherPath<R: Realm> {
    /// Absolute variant.
    Abs(AbsPath<R>),
    /// Relative variant.
    Rel(RelPath<R>),
}

impl<R: Realm> Clone for EitherPath<R> {
    fn clone(&self) -> Self {
        match self {
            Self::Abs(p) => Self::Abs(p.clone()),
            Self::Rel(p) => Self::Rel(p.clone()),
        }
    }
}

impl<R: Realm> PartialEq for EitherPath<R> {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Abs(a), Self::Abs(b)) => a == b,
            (Self::Rel(a), Self::Rel(b)) => a == b,
            _ => false,
        }
    }
}

impl<R: Realm> Eq for EitherPath<R> {}

impl<R: Realm> std::hash::Hash for EitherPath<R> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        std::mem::discriminant(self).hash(state);
        match self {
            Self::Abs(p) => p.hash(state),
            Self::Rel(p) => p.hash(state),
        }
    }
}

impl<R: Realm> fmt::Debug for EitherPath<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Abs(p) => write!(f, "EitherPath::Abs({p:?})"),
            Self::Rel(p) => write!(f, "EitherPath::Rel({p:?})"),
        }
    }
}

impl<R: Realm> EitherPath<R> {
    /// Constructs an `EitherPath` by inspecting whether `p` is absolute.
    ///
    /// Infallible: every UTF-8 path is either absolute or relative, so the
    /// invariants of both [`AbsPath::new`] and [`RelPath::new`] are
    /// guaranteed to hold for exactly one variant.
    pub fn new(p: impl Into<Utf8PathBuf>) -> Self {
        let inner = p.into();
        if inner.is_absolute() {
            Self::Abs(AbsPath {
                inner,
                _realm: PhantomData,
            })
        } else {
            Self::Rel(RelPath {
                inner,
                _realm: PhantomData,
            })
        }
    }

    /// Borrows the underlying UTF-8 path regardless of variant.
    #[must_use]
    pub fn as_utf8_path(&self) -> &Utf8Path {
        match self {
            Self::Abs(p) => p.as_utf8_path(),
            Self::Rel(p) => p.as_utf8_path(),
        }
    }

    /// Borrows the underlying path as a `&str`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.as_utf8_path().as_str()
    }

    /// Returns `true` if this is the [`Abs`](Self::Abs) variant.
    #[must_use]
    pub fn is_absolute(&self) -> bool {
        matches!(self, Self::Abs(_))
    }

    /// Returns the absolute variant, if any.
    #[must_use]
    pub fn as_abs(&self) -> Option<&AbsPath<R>> {
        match self {
            Self::Abs(p) => Some(p),
            Self::Rel(_) => None,
        }
    }

    /// Returns the relative variant, if any.
    #[must_use]
    pub fn as_rel(&self) -> Option<&RelPath<R>> {
        match self {
            Self::Abs(_) => None,
            Self::Rel(p) => Some(p),
        }
    }

    /// The final component of the path, if any.
    #[must_use]
    pub fn file_name(&self) -> Option<&str> {
        self.as_utf8_path().file_name()
    }

    /// The extension of the final component, if any.
    #[must_use]
    pub fn extension(&self) -> Option<&str> {
        self.as_utf8_path().extension()
    }

    /// Iterator over the path's components.
    pub fn components(&self) -> Utf8Components<'_> {
        self.as_utf8_path().components()
    }
}

impl<R: Realm> PartialOrd for EitherPath<R> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<R: Realm> Ord for EitherPath<R> {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (Self::Abs(a), Self::Abs(b)) => a.cmp(b),
            (Self::Rel(a), Self::Rel(b)) => a.cmp(b),
            (Self::Abs(_), Self::Rel(_)) => Ordering::Less,
            (Self::Rel(_), Self::Abs(_)) => Ordering::Greater,
        }
    }
}

impl<R: Realm> AsRef<Utf8Path> for EitherPath<R> {
    fn as_ref(&self) -> &Utf8Path {
        self.as_utf8_path()
    }
}

impl<R: Realm> AsRef<Path> for EitherPath<R> {
    fn as_ref(&self) -> &Path {
        self.as_utf8_path().as_std_path()
    }
}

impl<R: Realm> AsRef<str> for EitherPath<R> {
    fn as_ref(&self) -> &str {
        self.as_utf8_path().as_str()
    }
}

impl<R: Realm> FromStr for EitherPath<R> {
    type Err = core::convert::Infallible;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self::new(s))
    }
}

impl<R: Realm> From<AbsPath<R>> for EitherPath<R> {
    fn from(p: AbsPath<R>) -> Self {
        Self::Abs(p)
    }
}

impl<R: Realm> From<RelPath<R>> for EitherPath<R> {
    fn from(p: RelPath<R>) -> Self {
        Self::Rel(p)
    }
}

impl<R: Realm> fmt::Display for EitherPath<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Abs(p) => fmt::Display::fmt(p, f),
            Self::Rel(p) => fmt::Display::fmt(p, f),
        }
    }
}

impl<R: Realm> serde::Serialize for EitherPath<R> {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        self.as_utf8_path().serialize(ser)
    }
}

impl<'de, R: Realm> serde::Deserialize<'de> for EitherPath<R> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let p = Utf8PathBuf::deserialize(deserializer)?;
        Ok(Self::new(p))
    }
}

// =====================================================================
// CwdResolvable + CwdRelative
// =====================================================================

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::Host {}
    impl Sealed for super::Daemon {}
}

/// Marker trait for realms where relative paths can be resolved against
/// the process current working directory.
///
/// Sealed — only [`Host`] and [`Daemon`] qualify. The [`Sandbox`] realm
/// has no meaningful cwd: the host process's cwd is not a path inside
/// the sandbox rootfs, and resolving against it would silently produce a
/// nonsense path. Crossing into the sandbox requires a [`Translator`].
pub trait CwdResolvable: Realm + sealed::Sealed {}

impl CwdResolvable for Host {}
impl CwdResolvable for Daemon {}

/// Errors produced when resolving a [`CwdRelative`] against the
/// process current working directory.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum CwdResolveError {
    /// `std::env::current_dir` failed.
    #[error("failed to read the current working directory")]
    Cwd(#[source] std::io::Error),
    /// The cwd is not valid UTF-8.
    #[error("current working directory `{}` is not valid UTF-8", .0.display())]
    NonUtf8Cwd(std::path::PathBuf),
    /// The cwd is somehow not absolute (an OS-level invariant violation).
    #[error("current working directory `{0}` is not absolute")]
    CwdNotAbsolute(Utf8PathBuf),
}

/// A CLI-supplied path: absolute is taken as-is, relative is captured
/// for later resolution against the process current working directory.
///
/// Designed for direct use in clap derive contexts:
///
/// ```ignore
/// #[derive(clap::Parser)]
/// struct Args {
///     #[arg(long)]
///     minimal_dir: Option<paths::CwdRelative<paths::Daemon>>,
/// }
/// ```
///
/// [`FromStr`] does not touch the filesystem — call [`Self::resolve`]
/// when you're ready to commit to a base. Typical pattern: parse args,
/// then resolve once at CLI entry. This way the cwd is read at a single
/// well-defined point instead of as a side effect of `clap::parse`.
///
/// `R: CwdResolvable` rules out [`Sandbox`] at compile time —
/// `CwdRelative<Sandbox>` is not spellable:
///
/// ```compile_fail
/// use paths::{CwdRelative, Sandbox};
/// let _: CwdRelative<Sandbox>;
/// ```
pub struct CwdRelative<R: CwdResolvable>(EitherPath<R>);

impl<R: CwdResolvable> CwdRelative<R> {
    /// The path as supplied by the user, before resolution.
    #[must_use]
    pub fn as_either(&self) -> &EitherPath<R> {
        &self.0
    }

    /// `true` if the wrapped path was absolute (i.e. [`Self::resolve`]
    /// will not consult the cwd).
    #[must_use]
    pub fn is_absolute(&self) -> bool {
        self.0.is_absolute()
    }

    /// Resolve to an [`AbsPath<R>`]: absolute as-is, relative joined
    /// against the current working directory.
    ///
    /// # Errors
    ///
    /// Returns [`CwdResolveError`] if `getcwd` fails, returns a
    /// non-UTF-8 path, or somehow returns a non-absolute path.
    pub fn resolve(&self) -> Result<AbsPath<R>, CwdResolveError> {
        match &self.0 {
            EitherPath::Abs(p) => Ok(p.clone()),
            EitherPath::Rel(r) => {
                let cwd = std::env::current_dir().map_err(CwdResolveError::Cwd)?;
                let cwd = Utf8PathBuf::from_path_buf(cwd).map_err(CwdResolveError::NonUtf8Cwd)?;
                let cwd_abs = AbsPath::<R>::try_new(cwd.clone())
                    .map_err(|_| CwdResolveError::CwdNotAbsolute(cwd))?;
                Ok(cwd_abs.join(r))
            }
        }
    }
}

impl<R: CwdResolvable> FromStr for CwdRelative<R> {
    type Err = core::convert::Infallible;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(EitherPath::new(s)))
    }
}

impl<R: CwdResolvable> From<AbsPath<R>> for CwdRelative<R> {
    fn from(value: AbsPath<R>) -> Self {
        Self(EitherPath::Abs(value))
    }
}

impl<R: CwdResolvable> Clone for CwdRelative<R> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<R: CwdResolvable> PartialEq for CwdRelative<R> {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl<R: CwdResolvable> Eq for CwdRelative<R> {}

impl<R: CwdResolvable> std::hash::Hash for CwdRelative<R> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl<R: CwdResolvable> fmt::Debug for CwdRelative<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CwdRelative<{}>({})", R::NAME, self.0.as_utf8_path())
    }
}

impl<R: CwdResolvable> fmt::Display for CwdRelative<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

/// Translates absolute paths from one realm into another.
///
/// Crossing realms is fallible by default: a host path may not have a
/// sandbox image, an in-sandbox path may not round-trip back to the host,
/// etc. Implementors expose their mapping rules through this trait.
pub trait Translator<Src: Realm, Dst: Realm> {
    /// Reason translation failed.
    type Error;

    /// Translates `src` from realm `Src` into realm `Dst`.
    ///
    /// # Errors
    ///
    /// Implementations decide what counts as a failure (no mapping, path
    /// outside the mapped subtree, etc.).
    fn translate(&self, src: &AbsPath<Src>) -> Result<AbsPath<Dst>, Self::Error>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn abs_path_rejects_relative_input() {
        let err = AbsPath::<Host>::try_new("relative/thing").unwrap_err();
        assert!(matches!(err, Error::NotAbsolute(_)));
    }

    #[test]
    fn rel_path_rejects_absolute_input() {
        let err = RelPath::<Host>::try_new("/absolute/thing").unwrap_err();
        assert!(matches!(err, Error::IsAbsolute(_)));
    }

    #[test]
    fn abs_join_only_accepts_relpath_so_base_is_preserved() {
        // The original PathBuf footgun: PathBuf::from("/a").join("/b") == "/b".
        // The compile-time analogue is unreachable here because join takes
        // &RelPath<R>, and RelPath::new("/b") would have already failed.
        let base = AbsPath::<Host>::try_new("/etc/minimal").unwrap();
        let rel = RelPath::<Host>::try_new("hooks/run.sh").unwrap();
        assert_eq!(
            base.join(&rel).as_utf8_path().as_str(),
            "/etc/minimal/hooks/run.sh",
        );
    }

    #[test]
    fn resolve_against_is_join_in_reverse() {
        let base = AbsPath::<Host>::try_new("/etc/minimal").unwrap();
        let rel = RelPath::<Host>::try_new("hooks/run.sh").unwrap();
        assert_eq!(rel.resolve_against(&base), base.join(&rel));
    }

    #[test]
    fn parent_of_root_is_none() {
        let root = AbsPath::<Host>::try_new("/").unwrap();
        assert!(root.parent().is_none());
    }

    #[test]
    fn parent_of_nested_drops_last_component() {
        let p = AbsPath::<Host>::try_new("/a/b/c").unwrap();
        assert_eq!(p.parent().unwrap().as_utf8_path().as_str(), "/a/b");
    }

    #[test]
    fn config_relative_binds_only_to_host() {
        let cfg_dir = AbsPath::<Host>::try_new("/home/u/project").unwrap();
        let hook = RelPath::<ConfigRelative>::try_new("./scripts/cleanup.sh").unwrap();
        let bound = hook.bind_to_host(&cfg_dir);
        assert_eq!(
            bound.as_utf8_path().as_str(),
            "/home/u/project/./scripts/cleanup.sh",
        );
    }

    #[test]
    fn debug_includes_realm_tag() {
        let host = AbsPath::<Host>::try_new("/x").unwrap();
        let sandbox = AbsPath::<Sandbox>::try_new("/x").unwrap();
        assert_eq!(format!("{host:?}"), "AbsPath<host>(/x)");
        assert_eq!(format!("{sandbox:?}"), "AbsPath<sandbox>(/x)");
    }

    #[test]
    fn display_omits_realm_tag() {
        let p = AbsPath::<Host>::try_new("/x/y").unwrap();
        assert_eq!(format!("{p}"), "/x/y");
    }

    #[test]
    fn equality_and_hash_ignore_realm_phantom() {
        // Same realm, same path → equal.
        let a = AbsPath::<Host>::try_new("/x").unwrap();
        let b = AbsPath::<Host>::try_new("/x").unwrap();
        assert_eq!(a, b);

        // Equality across realms does not even typecheck — this is the
        // whole point. (Uncommenting the next line would be a compile error.)
        // let sandbox = AbsPath::<Sandbox>::try_new("/x").unwrap();
        // let _ = a == sandbox;
    }

    #[derive(Debug, serde::Deserialize, serde::Serialize)]
    struct Wrap<T> {
        x: T,
    }

    #[test]
    fn abs_path_serializes_as_bare_string() {
        let p = HostAbsPath::try_new("/etc/minimal").unwrap();
        let s = toml::to_string(&Wrap { x: p }).unwrap();
        assert_eq!(s.trim(), r#"x = "/etc/minimal""#);
    }

    #[test]
    fn abs_path_round_trips_through_toml() {
        let original = HostAbsPath::try_new("/etc/minimal").unwrap();
        let s = toml::to_string(&Wrap {
            x: original.clone(),
        })
        .unwrap();
        let parsed: Wrap<HostAbsPath> = toml::from_str(&s).unwrap();
        assert_eq!(parsed.x, original);
    }

    #[test]
    fn abs_path_deserialize_rejects_relative_input() {
        let err = toml::from_str::<Wrap<HostAbsPath>>(r#"x = "etc/minimal""#).unwrap_err();
        assert!(err.to_string().contains("absolute"), "got: {err}");
    }

    #[test]
    fn rel_path_round_trips_through_toml() {
        let original = ConfigRelPath::try_new("hooks/cleanup.sh").unwrap();
        let s = toml::to_string(&Wrap {
            x: original.clone(),
        })
        .unwrap();
        let parsed: Wrap<ConfigRelPath> = toml::from_str(&s).unwrap();
        assert_eq!(parsed.x, original);
    }

    #[test]
    fn rel_path_deserialize_rejects_absolute_input() {
        let err = toml::from_str::<Wrap<HostRelPath>>(r#"x = "/etc/minimal""#).unwrap_err();
        assert!(err.to_string().contains("relative"), "got: {err}");
    }

    #[test]
    fn realm_aliases_resolve_to_the_underlying_generic_types() {
        // These assignments would be type errors if the aliases drifted.
        let _: HostAbsPath = AbsPath::<Host>::try_new("/h").unwrap();
        let _: HostRelPath = RelPath::<Host>::try_new("h").unwrap();
        let _: SandboxAbsPath = AbsPath::<Sandbox>::try_new("/s").unwrap();
        let _: SandboxRelPath = RelPath::<Sandbox>::try_new("s").unwrap();
        let _: DaemonAbsPath = AbsPath::<Daemon>::try_new("/d").unwrap();
        let _: DaemonRelPath = RelPath::<Daemon>::try_new("d").unwrap();
        let _: ConfigRelPath = RelPath::<ConfigRelative>::try_new("c").unwrap();
        let _: HostPath = EitherPath::<Host>::new("/h");
        let _: SandboxPath = EitherPath::<Sandbox>::new("s");
        let _: DaemonPath = EitherPath::<Daemon>::new("/d");
    }

    #[test]
    fn either_path_new_routes_by_absoluteness() {
        let abs: HostPath = EitherPath::new("/etc/minimal");
        let rel: HostPath = EitherPath::new("etc/minimal");
        assert!(abs.is_absolute());
        assert!(!rel.is_absolute());
        assert!(abs.as_abs().is_some());
        assert!(abs.as_rel().is_none());
        assert!(rel.as_rel().is_some());
        assert!(rel.as_abs().is_none());
    }

    #[test]
    fn either_path_deserializes_absolute_into_abs_variant() {
        let parsed: Wrap<HostPath> = toml::from_str(r#"x = "/etc/minimal""#).unwrap();
        assert!(matches!(parsed.x, EitherPath::Abs(_)));
        assert_eq!(parsed.x.as_utf8_path().as_str(), "/etc/minimal");
    }

    #[test]
    fn either_path_deserializes_relative_into_rel_variant() {
        let parsed: Wrap<HostPath> = toml::from_str(r#"x = "etc/minimal""#).unwrap();
        assert!(matches!(parsed.x, EitherPath::Rel(_)));
        assert_eq!(parsed.x.as_utf8_path().as_str(), "etc/minimal");
    }

    #[test]
    fn either_path_round_trips_through_toml() {
        let abs: HostPath = EitherPath::new("/etc/minimal");
        let rel: HostPath = EitherPath::new("hooks/run.sh");
        for original in [abs, rel] {
            let s = toml::to_string(&Wrap {
                x: original.clone(),
            })
            .unwrap();
            let parsed: Wrap<HostPath> = toml::from_str(&s).unwrap();
            assert_eq!(parsed.x, original);
        }
    }

    #[test]
    fn either_path_serializes_as_bare_string_without_tag() {
        let abs: HostPath = EitherPath::new("/etc/minimal");
        let s = toml::to_string(&Wrap { x: abs }).unwrap();
        assert_eq!(s.trim(), r#"x = "/etc/minimal""#);
    }

    #[test]
    fn either_path_from_impls_lift_either_variant() {
        let abs = HostAbsPath::try_new("/h").unwrap();
        let rel = HostRelPath::try_new("h").unwrap();
        let lifted_abs: HostPath = abs.clone().into();
        let lifted_rel: HostPath = rel.clone().into();
        assert_eq!(lifted_abs.as_abs(), Some(&abs));
        assert_eq!(lifted_rel.as_rel(), Some(&rel));
    }

    // ---- AsRef / Borrow ----

    fn takes_path(p: impl AsRef<Path>) -> std::path::PathBuf {
        p.as_ref().to_path_buf()
    }

    #[test]
    fn as_ref_into_std_path_works_for_owned_types() {
        let abs = HostAbsPath::try_new("/etc/minimal").unwrap();
        let rel = HostRelPath::try_new("hooks/run.sh").unwrap();
        let either: HostPath = EitherPath::new("/etc/minimal");
        assert_eq!(takes_path(&abs), Path::new("/etc/minimal"));
        assert_eq!(takes_path(&rel), Path::new("hooks/run.sh"));
        assert_eq!(takes_path(&either), Path::new("/etc/minimal"));
    }

    #[test]
    fn as_ref_str_returns_inner_path_string() {
        let p = HostAbsPath::try_new("/etc/minimal").unwrap();
        let s: &str = p.as_ref();
        assert_eq!(s, "/etc/minimal");
        assert_eq!(p.as_str(), "/etc/minimal");
    }

    #[test]
    fn borrow_supports_map_lookup_by_utf8_path() {
        use std::collections::HashMap;
        let mut m: HashMap<HostAbsPath, u8> = HashMap::new();
        m.insert(HostAbsPath::try_new("/x").unwrap(), 1);
        let key = Utf8Path::new("/x");
        assert_eq!(m.get(key).copied(), Some(1));
    }

    // ---- FromStr ----

    #[test]
    fn from_str_parses_abs_and_rel() {
        let abs: HostAbsPath = "/etc/minimal".parse().unwrap();
        let rel: HostRelPath = "hooks/run.sh".parse().unwrap();
        let either: HostPath = "/etc/minimal".parse().unwrap();
        assert_eq!(abs.as_str(), "/etc/minimal");
        assert_eq!(rel.as_str(), "hooks/run.sh");
        assert!(either.is_absolute());
    }

    #[test]
    fn from_str_rejects_wrong_orientation() {
        assert!("etc/minimal".parse::<HostAbsPath>().is_err());
        assert!("/etc/minimal".parse::<HostRelPath>().is_err());
    }

    // ---- Ord ----

    #[test]
    fn ord_sorts_lexicographically_within_a_realm() {
        let mut v = [
            HostAbsPath::try_new("/b").unwrap(),
            HostAbsPath::try_new("/a/b").unwrap(),
            HostAbsPath::try_new("/a").unwrap(),
        ];
        v.sort();
        let strs: Vec<_> = v.iter().map(HostAbsPath::as_str).collect();
        assert_eq!(strs, ["/a", "/a/b", "/b"]);
    }

    #[test]
    fn either_path_ord_puts_abs_before_rel() {
        let abs: HostPath = EitherPath::new("/zz");
        let rel: HostPath = EitherPath::new("aa");
        assert!(abs < rel);
    }

    // ---- strip_prefix ----

    #[test]
    fn strip_prefix_yields_a_relpath_in_the_same_realm() {
        let base = HostAbsPath::try_new("/home/u").unwrap();
        let full = HostAbsPath::try_new("/home/u/projects/minimal").unwrap();
        let rel = full.strip_prefix(&base).unwrap();
        assert_eq!(rel.as_str(), "projects/minimal");
    }

    #[test]
    fn strip_prefix_returns_err_when_not_a_prefix() {
        let base = HostAbsPath::try_new("/var").unwrap();
        let full = HostAbsPath::try_new("/home/u").unwrap();
        assert!(full.strip_prefix(&base).is_err());
    }

    // ---- file_name / extension / components ----

    #[test]
    fn file_name_extension_and_components() {
        let p = HostAbsPath::try_new("/a/b/c.txt").unwrap();
        assert_eq!(p.file_name(), Some("c.txt"));
        assert_eq!(p.extension(), Some("txt"));
        let parts: Vec<_> = p.components().map(|c| c.as_str().to_owned()).collect();
        assert_eq!(parts, ["/", "a", "b", "c.txt"]);
    }

    // ---- CwdRelative ----
    //
    // Sandbox-realm rejection is enforced at compile time by `CwdResolvable`'s
    // sealed-trait bound; see the `compile_fail` doctest on the type itself.

    #[test]
    fn cwd_relative_from_str_is_infallible_and_routes_to_either() {
        let abs: CwdRelative<Host> = "/etc/minimal".parse().unwrap();
        let rel: CwdRelative<Host> = "config/foo".parse().unwrap();
        assert!(abs.is_absolute());
        assert!(!rel.is_absolute());
        assert!(matches!(abs.as_either(), EitherPath::Abs(_)));
        assert!(matches!(rel.as_either(), EitherPath::Rel(_)));
    }

    #[test]
    fn cwd_relative_resolve_passes_absolute_through_unchanged() {
        let cli: CwdRelative<Host> = "/etc/minimal".parse().unwrap();
        let resolved = cli
            .resolve()
            .expect("resolve does not consult cwd for abs paths");
        assert_eq!(resolved.as_str(), "/etc/minimal");
    }

    #[test]
    fn cwd_relative_resolve_joins_relative_to_process_cwd() {
        let cli: CwdRelative<Host> = "config/foo".parse().unwrap();
        let resolved = cli.resolve().expect("test process cwd is well-defined");

        let cwd_std = std::env::current_dir().unwrap();
        let cwd_utf8 = Utf8PathBuf::from_path_buf(cwd_std).unwrap();
        let expected = HostAbsPath::try_new(cwd_utf8)
            .unwrap()
            .join(&HostRelPath::try_new("config/foo").unwrap());
        assert_eq!(resolved, expected);
    }

    #[test]
    fn cwd_relative_clone_and_equality() {
        let a: CwdRelative<Daemon> = "/var/lib/x".parse().unwrap();
        let b = a.clone();
        assert_eq!(a, b);

        let c: CwdRelative<Daemon> = "/var/lib/y".parse().unwrap();
        assert_ne!(a, c);
    }

    #[test]
    fn cwd_relative_works_for_host_and_daemon_realms() {
        // Compile-time check that both realms satisfy CwdResolvable.
        let _: CwdRelative<Host> = "/h".parse().unwrap();
        let _: CwdRelative<Daemon> = "/d".parse().unwrap();
    }

    #[test]
    fn cwd_relative_debug_includes_realm_tag() {
        let p: CwdRelative<Host> = "/x".parse().unwrap();
        assert_eq!(format!("{p:?}"), "CwdRelative<host>(/x)");
    }

    #[test]
    fn provider_instance_dir_layout() {
        let state = DaemonAbsPath::try_new("/state/minimal").unwrap();
        assert_eq!(
            provider_instance_dir(&state, 0).as_str(),
            "/state/minimal/providers/local-0",
        );
        assert_eq!(
            provider_instance_dir(&state, 3).as_str(),
            "/state/minimal/providers/local-3",
        );
    }

    #[test]
    fn minimal_state_dir_honors_xdg_state_home() {
        // Only this test reads XDG_STATE_HOME; restore to avoid surprising a
        // developer's environment leaking into other assertions.
        let prev = std::env::var_os("XDG_STATE_HOME");
        unsafe { std::env::set_var("XDG_STATE_HOME", "/custom/state") };
        let dir = minimal_state_dir();
        match prev {
            Some(v) => unsafe { std::env::set_var("XDG_STATE_HOME", v) },
            None => unsafe { std::env::remove_var("XDG_STATE_HOME") },
        }
        assert_eq!(dir.as_str(), "/custom/state/minimal");
    }

    #[test]
    fn sub_path_abs() {
        let p = HostAbsPath::try_new("/silly").unwrap();
        assert_eq!(
            sub_path!(p, "goose"),
            HostAbsPath::try_new("/silly/goose").unwrap()
        );
    }
    #[test]
    fn sub_path_rel() {
        let p = HostRelPath::try_new("silly").unwrap();
        assert_eq!(
            sub_path!(p, "moose"),
            HostRelPath::try_new("silly/moose").unwrap()
        );
    }

    /// Shared lock for every test in this file that mutates
    /// `std::env`. Cargo runs `#[test]`s in parallel, and every
    /// test in the process shares one process env — a second env-
    /// touching test added anywhere in this crate must acquire this
    /// lock too, or the runs will race. `Mutex` (not `PoisonError`-
    /// aware) is fine because a panicking test would poison it and
    /// downstream env tests would fail with a clear error, which is
    /// what we want.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// `xdg_config_home` reflects `$XDG_CONFIG_HOME` when it's an
    /// absolute path (per the XDG spec) and yields `None` otherwise,
    /// so the caller can fall through to `$HOME/.config`. Three
    /// assertions kept in one test to minimize env-lock contention.
    #[test]
    fn xdg_config_home_resolution() {
        let _lock = ENV_LOCK.lock().unwrap();
        // SAFETY: `ENV_LOCK` serializes every env-touching test in
        // this crate; the block runs single-threaded w.r.t. any
        // sibling test that might read or write these vars.
        unsafe { std::env::remove_var("XDG_CONFIG_HOME") };
        assert_eq!(xdg_config_home(), None, "unset → None");

        unsafe { std::env::set_var("XDG_CONFIG_HOME", "not/absolute") };
        assert_eq!(xdg_config_home(), None, "relative → ignored per spec");

        unsafe { std::env::set_var("XDG_CONFIG_HOME", "/some/absolute/xdg") };
        assert_eq!(
            xdg_config_home(),
            Some(std::path::PathBuf::from("/some/absolute/xdg")),
            "absolute → returned verbatim",
        );

        unsafe { std::env::remove_var("XDG_CONFIG_HOME") };
    }

    #[test]
    fn known_hosts_line_match_covers_bare_and_bracketed_forms() {
        assert!(known_hosts_line_matches_host(
            "local-0 ssh-ed25519 AAAA",
            "local-0"
        ));
        assert!(known_hosts_line_matches_host(
            "[local-0]:2222 ssh-ed25519 AAAA",
            "local-0"
        ));
        assert!(!known_hosts_line_matches_host(
            "local-1 ssh-ed25519 AAAA",
            "local-0"
        ));
        assert!(!known_hosts_line_matches_host("", "local-0"));
    }

    #[test]
    fn prune_removes_only_the_named_host_and_bounds_growth() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(KNOWN_HOSTS_FILE);

        // Simulate the pre-fix accumulation: three appended entries for the
        // same host (as `learn_known_hosts_path` would leave), plus one entry
        // for an unrelated host that must survive.
        std::fs::write(
            &path,
            "local-0 ssh-ed25519 AAAAold1\n\
             local-0 ssh-ed25519 AAAAold2\n\
             other-host ssh-ed25519 AAAAkeep\n\
             local-0 ssh-ed25519 AAAAold3\n",
        )
        .unwrap();

        prune_known_hosts_host(&path, "local-0").unwrap();

        let after = std::fs::read_to_string(&path).unwrap();
        assert_eq!(after, "other-host ssh-ed25519 AAAAkeep\n");
    }

    #[test]
    fn prune_to_empty_yields_a_zero_byte_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(KNOWN_HOSTS_FILE);
        // The steady state: the per-instance file holds only this host's
        // entries, so a pre-record prune empties it entirely.
        std::fs::write(
            &path,
            "local-0 ssh-ed25519 AAAAold1\nlocal-0 ssh-ed25519 AAAAold2\n",
        )
        .unwrap();
        prune_known_hosts_host(&path, "local-0").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "");
    }

    #[test]
    fn prune_is_a_noop_when_file_is_absent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(KNOWN_HOSTS_FILE);
        prune_known_hosts_host(&path, "local-0").unwrap();
        assert!(!path.exists(), "prune must not create the file");
    }

    #[test]
    fn prune_leaves_file_untouched_when_nothing_matches() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(KNOWN_HOSTS_FILE);
        // No trailing newline: proves the untouched path preserves exact bytes.
        std::fs::write(&path, "other-host ssh-ed25519 AAAAkeep").unwrap();
        prune_known_hosts_host(&path, "local-0").unwrap();
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "other-host ssh-ed25519 AAAAkeep"
        );
    }
}
