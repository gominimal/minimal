//! On-disk store for GitHub authentication grants (spec R1.3, R6.4).
//!
//! One JSON file per grant, under a directory the daemon injects (it will pass
//! `minimal_state_dir()/github/grants/`, mirroring the `Store` actor pattern
//! for session records at `crates/minimald/src/store.rs`). Multiple grants can
//! coexist on disk at once — the substrate the future `GrantManager` needs for
//! reuse-or-mint (spec R1.3, R6.4): a subsequent sandbox can either reuse an
//! existing grant or mint a fresh, separately-scoped one, and both then live
//! side by side.
//!
//! # Security posture
//!
//! - **File layout**: the directory is created/kept at mode `0700`, each
//!   grant file at `0600`. Both are re-asserted (`chmod`) every time this
//!   store opens the directory or reads an existing file, so permissions that
//!   drifted (a stale daemon version, a manual `cp`, an odd umask) are
//!   corrected rather than silently trusted.
//! - **Atomic writes**: [`GrantStore::save`] never writes the destination
//!   path directly. It writes a sibling temp file (created with `0600` from
//!   the first `open(2)`, mode re-asserted immediately after in case the
//!   process umask widened it) and `rename(2)`s it into place. A crash or
//!   error at any point before the rename leaves the previous file (or no
//!   file) exactly as it was — never a half-written grant.
//! - **Secrets stay [`SecretString`]**: `access_token` and `refresh_token`
//!   are the only fields carrying token material, and both are named with
//!   `token` in the key, so the diagnostics redaction denylist
//!   (`SENSITIVE_KEY_PARTS` in `crates/diagnostics/src/redact.rs`) masks them
//!   by key name wherever this store's JSON is dumped (spec R6.2), on top of
//!   `SecretString`'s own `Debug`/`Display` redaction. [`SecretString`] itself
//!   carries no `serde` impl (see `secret.rs`); the (de)serialization for
//!   those two fields is opted into explicitly here, via
//!   `#[serde(with = "secret_codec")]`, so a token round-trips to disk without
//!   ever widening `SecretString`'s own surface.
//! - **[`GrantStore::list`] returns [`GrantSummary`]**, a type that
//!   structurally has no token field — token material never leaves this
//!   module except through [`GrantStore::get`], which yields a full
//!   [`Grant`] for the one caller that legitimately needs it (a future
//!   `GrantManager` building an authenticated request).
//! - **Grant ids are filesystem components.** [`GrantId`] permits any
//!   non-empty string; this store additionally requires ids to be safe as a
//!   bare filename (ASCII alphanumerics, `-`, `_`) and fails closed
//!   ([`std::io::ErrorKind::InvalidInput`]) on anything else, so a
//!   maliciously- or accidentally-crafted grant id can never traverse out of
//!   the grants directory.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::scopes::ScopeSet;
use crate::secret::SecretString;
use crate::types::GrantId;

/// Permission bits asserted on the grants directory.
#[cfg(unix)]
const DIR_MODE: u32 = 0o700;
/// Permission bits asserted on each grant file.
#[cfg(unix)]
const FILE_MODE: u32 = 0o600;

/// Lifecycle state of a stored grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantState {
    /// The grant's tokens are, as far as this store knows, still usable.
    Valid,
    /// The refresh token has expired or been revoked; the user must
    /// re-authenticate (spec R1.2) before this grant can be used again.
    NeedsReauth,
}

/// A stored GitHub authentication grant: the user + refresh tokens plus
/// enough metadata to display, refresh, and manage it (spec R1.3, R6.4).
///
/// `Debug` is safe to log: the two `SecretString` fields render as
/// `[REDACTED:gh]` (see `secret.rs`), and every other field is non-secret
/// (a login, a numeric id, scope grants, and timestamps).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Grant {
    /// Opaque id naming this grant (spec R6.4 reuse-or-mint); also the
    /// on-disk file's stem.
    #[serde(with = "grant_id_codec")]
    pub grant_id: GrantId,
    /// The authenticated GitHub login (spec R1.4, G4 real-user attribution).
    pub github_login: String,
    /// The authenticated GitHub user's numeric id.
    pub github_user_id: u64,
    /// The permission set this grant was minted with (spec R5).
    #[serde(with = "scope_set_codec")]
    pub scopes: ScopeSet,
    /// The user-to-server access token (~8h lifetime). Never logged, never
    /// enters a sandbox (spec R6.1).
    #[serde(with = "secret_codec")]
    pub access_token: SecretString,
    /// Expiry of `access_token`.
    pub access_token_expires_at: DateTime<Utc>,
    /// The rotating refresh token (~6mo lifetime). Never logged, never
    /// enters a sandbox (spec R6.1).
    #[serde(with = "secret_codec")]
    pub refresh_token: SecretString,
    /// Expiry of `refresh_token`; past this point the grant needs re-auth
    /// rather than a silent refresh (spec R1.2).
    pub refresh_token_expires_at: DateTime<Utc>,
    /// When this grant was first minted.
    pub created_at: DateTime<Utc>,
    /// When `access_token` was last refreshed (initially equal to
    /// `created_at`).
    pub last_refreshed_at: DateTime<Utc>,
    /// Whether the grant is usable or needs re-authentication.
    pub state: GrantState,
}

/// Metadata-only view of a [`Grant`], with no field that can carry token
/// material — the shape [`GrantStore::list`] returns, so enumerating grants
/// (e.g. for `min github status`) can never leak a token (spec R6.1, R6.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantSummary {
    /// See [`Grant::grant_id`].
    #[serde(with = "grant_id_codec")]
    pub grant_id: GrantId,
    /// See [`Grant::github_login`].
    pub github_login: String,
    /// See [`Grant::github_user_id`].
    pub github_user_id: u64,
    /// See [`Grant::scopes`].
    #[serde(with = "scope_set_codec")]
    pub scopes: ScopeSet,
    /// See [`Grant::access_token_expires_at`].
    pub access_token_expires_at: DateTime<Utc>,
    /// See [`Grant::refresh_token_expires_at`].
    pub refresh_token_expires_at: DateTime<Utc>,
    /// See [`Grant::created_at`].
    pub created_at: DateTime<Utc>,
    /// See [`Grant::last_refreshed_at`].
    pub last_refreshed_at: DateTime<Utc>,
    /// See [`Grant::state`].
    pub state: GrantState,
}

impl From<&Grant> for GrantSummary {
    fn from(g: &Grant) -> Self {
        Self {
            grant_id: g.grant_id.clone(),
            github_login: g.github_login.clone(),
            github_user_id: g.github_user_id,
            scopes: g.scopes.clone(),
            access_token_expires_at: g.access_token_expires_at,
            refresh_token_expires_at: g.refresh_token_expires_at,
            created_at: g.created_at,
            last_refreshed_at: g.last_refreshed_at,
            state: g.state,
        }
    }
}

/// `serde(with = ...)` bridge for [`GrantId`]. `GrantId` deliberately has no
/// `serde` derive of its own (it is a domain type shared far beyond this
/// store); this module opts a `Grant`/`GrantSummary` field into a plain
/// string encoding without widening `GrantId`'s own surface.
mod grant_id_codec {
    use serde::{Deserialize, Deserializer, Serializer};

    use crate::types::GrantId;

    pub fn serialize<S: Serializer>(id: &GrantId, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(id.as_str())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<GrantId, D::Error> {
        let raw = String::deserialize(d)?;
        GrantId::new(raw).map_err(serde::de::Error::custom)
    }
}

/// `serde(with = ...)` bridge for [`ScopeSet`], using its existing compact
/// `attrs`-style encoding (`contents:rw,pull_requests:rw,...`) as the on-disk
/// form too, so the two codecs (session `attrs`, grant store) never drift.
mod scope_set_codec {
    use serde::{Deserialize, Deserializer, Serializer};

    use crate::scopes::ScopeSet;

    pub fn serialize<S: Serializer>(scopes: &ScopeSet, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&scopes.to_attr_value())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<ScopeSet, D::Error> {
        let raw = String::deserialize(d)?;
        ScopeSet::from_attr_value(&raw).map_err(serde::de::Error::custom)
    }
}

/// `serde(with = ...)` bridge for [`SecretString`]. `SecretString`
/// deliberately carries no `serde` impl of its own (see `secret.rs`) — this
/// is the one place, opted into explicitly and by name, where a token is
/// allowed to round-trip through a string for on-disk storage.
mod secret_codec {
    use serde::{Deserialize, Deserializer, Serializer};

    use crate::secret::SecretString;

    pub fn serialize<S: Serializer>(secret: &SecretString, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(secret.expose_secret())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<SecretString, D::Error> {
        let raw = String::deserialize(d)?;
        Ok(SecretString::new(raw))
    }
}

/// Validates that `grant_id` is safe to use as a bare filename component:
/// non-empty, ASCII alphanumerics/`-`/`_` only, bounded length. `GrantId`
/// itself only guarantees non-empty (it is a general-purpose domain type),
/// so this store adds its own fail-closed check rather than trusting an
/// arbitrary string into a path — the input is not echoed, since grant ids
/// may originate from paths not fully under this crate's control.
fn filename_component(grant_id: &GrantId) -> io::Result<&str> {
    let s = grant_id.as_str();
    let safe = !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'));
    if !safe {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "grant id is not safe for use as a filename (only ASCII letters, digits, `-`, \
             and `_` are allowed)",
        ));
    }
    Ok(s)
}

/// Re-asserts `0700` on a directory. No-op on non-Unix targets (this store's
/// production use is Linux/macOS only, per the workspace's platform matrix).
#[cfg(unix)]
fn assert_dir_mode(dir: &Path) -> io::Result<()> {
    fs::set_permissions(dir, fs::Permissions::from_mode(DIR_MODE))
}
#[cfg(not(unix))]
fn assert_dir_mode(_dir: &Path) -> io::Result<()> {
    Ok(())
}

/// Re-asserts `0600` on a file, by path. No-op on non-Unix targets.
#[cfg(unix)]
fn assert_file_mode(path: &Path) -> io::Result<()> {
    fs::set_permissions(path, fs::Permissions::from_mode(FILE_MODE))
}
#[cfg(not(unix))]
fn assert_file_mode(_path: &Path) -> io::Result<()> {
    Ok(())
}

/// Re-asserts `0600` on an already-open file. Preferred over the path-based
/// [`assert_file_mode`] when a file handle is already in hand (`get`,
/// `list`): it corrects the permissions of the exact inode just opened,
/// rather than re-resolving the path (which could, in principle, now name
/// something else). No-op on non-Unix targets.
#[cfg(unix)]
fn assert_file_mode_fd(file: &fs::File) -> io::Result<()> {
    file.set_permissions(fs::Permissions::from_mode(FILE_MODE))
}
#[cfg(not(unix))]
fn assert_file_mode_fd(_file: &fs::File) -> io::Result<()> {
    Ok(())
}

/// Opens a fresh file at `path` for writing, refusing if something is
/// already there (the caller is responsible for clearing a stale temp file
/// first). Created at `0600` directly (via `open(2)`'s mode argument) and
/// then `chmod`'d again immediately, closing the (typically zero-width)
/// window a permissive umask could otherwise leave open.
fn create_private_file(path: &Path) -> io::Result<fs::File> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(FILE_MODE);
    let file = options.open(path)?;
    assert_file_mode(path)?;
    Ok(file)
}

/// On-disk store for GitHub authentication [`Grant`]s: one JSON file per
/// grant under an injected directory. See the module docs for the security
/// properties this type maintains.
#[derive(Debug, Clone)]
pub struct GrantStore {
    dir: PathBuf,
}

impl GrantStore {
    /// Opens (creating if necessary) a grant store rooted at `dir`. Asserts
    /// the directory exists at mode `0700`, correcting it if it already
    /// existed with different permissions.
    ///
    /// # Errors
    ///
    /// I/O error if the directory cannot be created or its permissions
    /// cannot be set.
    pub fn open(dir: impl Into<PathBuf>) -> io::Result<Self> {
        let dir = dir.into();
        fs::create_dir_all(&dir)?;
        assert_dir_mode(&dir)?;
        Ok(Self { dir })
    }

    /// The directory this store is rooted at.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The path a grant's JSON file would live at.
    fn path_for(&self, grant_id: &GrantId) -> io::Result<PathBuf> {
        Ok(self
            .dir
            .join(format!("{}.json", filename_component(grant_id)?)))
    }

    /// The path a grant's write-in-progress temp file lives at, alongside
    /// (never inside) the final path so the closing `rename(2)` is same-
    /// directory and therefore atomic.
    fn tmp_path_for(&self, grant_id: &GrantId) -> io::Result<PathBuf> {
        Ok(self
            .dir
            .join(format!("{}.json.tmp", filename_component(grant_id)?)))
    }

    /// Writes `grant` to disk, atomically. A prior grant at the same id is
    /// replaced only once the new content is fully written and `fsync`'d —
    /// a crash or error at any earlier point leaves the previous file (or no
    /// file) untouched, never a partially written one.
    ///
    /// # Errors
    ///
    /// I/O error if `grant.grant_id` isn't filename-safe, or if the
    /// temp-file write, `fsync`, or rename fails.
    pub fn save(&self, grant: &Grant) -> io::Result<()> {
        let final_path = self.path_for(&grant.grant_id)?;
        let tmp_path = self.tmp_path_for(&grant.grant_id)?;

        // Clear any stale temp file left by a previous crash before writing
        // a fresh one; `create_private_file` refuses to write over an
        // existing path. Anything else in the way (e.g. the path
        // unexpectedly being a directory) is a real error, not something to
        // paper over.
        if let Err(e) = fs::remove_file(&tmp_path)
            && e.kind() != io::ErrorKind::NotFound
        {
            return Err(e);
        }

        let file = create_private_file(&tmp_path)?;
        let write_result = serde_json::to_writer_pretty(&file, grant)
            .map_err(io::Error::from)
            .and_then(|()| file.sync_all());
        drop(file);
        if let Err(e) = write_result {
            // Best-effort cleanup of the half-written temp file; the final
            // path was never touched, so the store's visible state is
            // unchanged regardless of whether this cleanup succeeds.
            let _ = fs::remove_file(&tmp_path);
            return Err(e);
        }

        fs::rename(&tmp_path, &final_path)?;
        self.sync_dir()
    }

    /// `fsync`s the grants directory itself, making the just-completed
    /// `rename(2)` durable. Without this, a power loss shortly after `save`
    /// returns could resurrect the *previous* file — which, for a refresh-
    /// token **rotation** (see `refresh.rs`), would mean a refresh token
    /// GitHub has already invalidated: a bricked grant. No-op on non-Unix
    /// targets (directories aren't openable there; this store's production
    /// use is Linux/macOS only).
    #[cfg(unix)]
    fn sync_dir(&self) -> io::Result<()> {
        fs::File::open(&self.dir)?.sync_all()
    }
    #[cfg(not(unix))]
    fn sync_dir(&self) -> io::Result<()> {
        Ok(())
    }

    /// Reads back a single grant by id, or `None` if no grant with that id
    /// is stored.
    ///
    /// Re-asserts `0600` on the file before reading it, in case its
    /// permissions drifted since it was written.
    ///
    /// # Errors
    ///
    /// I/O error if `grant_id` isn't filename-safe, if the file exists but
    /// its permissions can't be corrected, or if it can't be read/parsed as
    /// a [`Grant`].
    pub fn get(&self, grant_id: &GrantId) -> io::Result<Option<Grant>> {
        let path = self.path_for(grant_id)?;
        let file = match fs::File::open(&path) {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        assert_file_mode_fd(&file)?;
        let grant: Grant = serde_json::from_reader(file).map_err(io::Error::from)?;
        Ok(Some(grant))
    }

    /// Lists every stored grant as metadata-only [`GrantSummary`] values, in
    /// grant-id order. Token material is never read into a `GrantSummary`
    /// (see the module docs).
    ///
    /// # Errors
    ///
    /// I/O error if the directory can't be enumerated, or if a stored grant
    /// file's permissions can't be corrected or it can't be read/parsed.
    pub fn list(&self) -> io::Result<Vec<GrantSummary>> {
        let mut out = Vec::new();
        let entries = match fs::read_dir(&self.dir) {
            Ok(rd) => rd,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(out),
            Err(e) => return Err(e),
        };
        for entry in entries {
            let entry = entry?;
            if !entry.file_type()?.is_file() {
                continue;
            }
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            // Only well-formed `<id>.json` grant files; skips index-less
            // leftovers such as a crashed `.json.tmp` write.
            if !name.ends_with(".json") {
                continue;
            }
            let path = entry.path();
            let file = fs::File::open(&path)?;
            assert_file_mode_fd(&file)?;
            let grant: Grant = serde_json::from_reader(file).map_err(io::Error::from)?;
            out.push(GrantSummary::from(&grant));
        }
        out.sort_by(|a, b| a.grant_id.cmp(&b.grant_id));
        Ok(out)
    }

    /// Deletes a stored grant. Deleting an id that isn't stored is not an
    /// error (idempotent).
    ///
    /// # Errors
    ///
    /// I/O error if `grant_id` isn't filename-safe or the file can't be
    /// removed for a reason other than already being absent.
    pub fn delete(&self, grant_id: &GrantId) -> io::Result<()> {
        let path = self.path_for(grant_id)?;
        match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn sample_grant(id: &str, login: &str, token: &str) -> Grant {
        let now = DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        Grant {
            grant_id: GrantId::new(id).unwrap(),
            github_login: login.to_string(),
            github_user_id: 42,
            scopes: ScopeSet::defaults(),
            access_token: SecretString::new(format!("ghu_{token}")),
            access_token_expires_at: now + chrono::Duration::hours(8),
            refresh_token: SecretString::new(format!("ghr_{token}")),
            refresh_token_expires_at: now + chrono::Duration::days(180),
            created_at: now,
            last_refreshed_at: now,
            state: GrantState::Valid,
        }
    }

    fn grants_dir(tmp: &TempDir) -> PathBuf {
        tmp.path().join("github").join("grants")
    }

    #[test]
    fn round_trips_every_field() {
        let tmp = TempDir::new().unwrap();
        let store = GrantStore::open(grants_dir(&tmp)).unwrap();

        let grant = sample_grant("grant-1", "octocat", "secrettoken123");
        store.save(&grant).unwrap();

        let loaded = store.get(&grant.grant_id).unwrap().expect("grant present");
        assert_eq!(loaded.grant_id, grant.grant_id);
        assert_eq!(loaded.github_login, grant.github_login);
        assert_eq!(loaded.github_user_id, grant.github_user_id);
        assert_eq!(loaded.scopes, grant.scopes);
        assert_eq!(
            loaded.access_token.expose_secret(),
            grant.access_token.expose_secret()
        );
        assert_eq!(
            loaded.access_token_expires_at,
            grant.access_token_expires_at
        );
        assert_eq!(
            loaded.refresh_token.expose_secret(),
            grant.refresh_token.expose_secret()
        );
        assert_eq!(
            loaded.refresh_token_expires_at,
            grant.refresh_token_expires_at
        );
        assert_eq!(loaded.created_at, grant.created_at);
        assert_eq!(loaded.last_refreshed_at, grant.last_refreshed_at);
        assert_eq!(loaded.state, grant.state);
    }

    #[test]
    fn get_of_unknown_grant_is_none_not_error() {
        let tmp = TempDir::new().unwrap();
        let store = GrantStore::open(grants_dir(&tmp)).unwrap();
        assert!(
            store
                .get(&GrantId::new("does-not-exist").unwrap())
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn multiple_grants_coexist() {
        let tmp = TempDir::new().unwrap();
        let store = GrantStore::open(grants_dir(&tmp)).unwrap();

        let a = sample_grant("grant-a", "alice", "tok-a");
        let b = sample_grant("grant-b", "bob", "tok-b");
        store.save(&a).unwrap();
        store.save(&b).unwrap();

        // Both are independently readable...
        assert_eq!(
            store.get(&a.grant_id).unwrap().unwrap().github_login,
            "alice"
        );
        assert_eq!(store.get(&b.grant_id).unwrap().unwrap().github_login, "bob");

        // ...and both show up in the listing.
        let logins: Vec<String> = store
            .list()
            .unwrap()
            .into_iter()
            .map(|s| s.github_login)
            .collect();
        assert_eq!(logins, vec!["alice".to_string(), "bob".to_string()]);
    }

    #[test]
    fn deleting_one_grant_leaves_others_intact() {
        let tmp = TempDir::new().unwrap();
        let store = GrantStore::open(grants_dir(&tmp)).unwrap();

        let a = sample_grant("grant-a", "alice", "tok-a");
        let b = sample_grant("grant-b", "bob", "tok-b");
        store.save(&a).unwrap();
        store.save(&b).unwrap();

        store.delete(&a.grant_id).unwrap();

        assert!(store.get(&a.grant_id).unwrap().is_none());
        assert_eq!(store.get(&b.grant_id).unwrap().unwrap().github_login, "bob");
        assert_eq!(store.list().unwrap().len(), 1);
    }

    #[test]
    fn delete_of_unknown_grant_is_not_an_error() {
        let tmp = TempDir::new().unwrap();
        let store = GrantStore::open(grants_dir(&tmp)).unwrap();
        store
            .delete(&GrantId::new("never-existed").unwrap())
            .unwrap();
    }

    #[test]
    fn list_summary_carries_no_token_field() {
        let tmp = TempDir::new().unwrap();
        let store = GrantStore::open(grants_dir(&tmp)).unwrap();

        let secret_marker = "very-secret-marker-xyz";
        store
            .save(&sample_grant("grant-1", "octocat", secret_marker))
            .unwrap();

        let summaries = store.list().unwrap();
        assert_eq!(summaries.len(), 1);

        // Structural guarantee (GrantSummary has no `access_token` /
        // `refresh_token` field: only their non-secret `*_expires_at`
        // timestamps) plus a belt-and-suspenders check that the actual
        // secret value never made it into the serialized summary.
        let encoded = serde_json::to_string(&summaries[0]).unwrap();
        assert!(!encoded.contains(secret_marker));
        assert!(!encoded.contains("\"access_token\""));
        assert!(!encoded.contains("\"refresh_token\""));
    }

    #[test]
    fn debug_of_loaded_grant_leaks_nothing() {
        let tmp = TempDir::new().unwrap();
        let store = GrantStore::open(grants_dir(&tmp)).unwrap();

        let secret_marker = "leak-would-show-up-here";
        let grant = sample_grant("grant-1", "octocat", secret_marker);
        store.save(&grant).unwrap();
        let loaded = store.get(&grant.grant_id).unwrap().unwrap();

        let debugged = format!("{loaded:?}");
        assert!(!debugged.contains(secret_marker));
        assert!(debugged.contains(crate::secret::REDACTED));
    }

    #[cfg(unix)]
    #[test]
    fn directory_and_file_modes_are_asserted() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = TempDir::new().unwrap();
        let store = GrantStore::open(grants_dir(&tmp)).unwrap();
        store
            .save(&sample_grant("grant-1", "octocat", "t"))
            .unwrap();

        let dir_mode = fs::metadata(store.dir()).unwrap().permissions().mode() & 0o777;
        assert_eq!(dir_mode, 0o700, "grants dir must be 0700");

        let file_mode = fs::metadata(store.dir().join("grant-1.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(file_mode, 0o600, "grant file must be 0600");
    }

    #[cfg(unix)]
    #[test]
    fn dir_mode_is_reasserted_on_reopen() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = TempDir::new().unwrap();
        let dir = grants_dir(&tmp);
        GrantStore::open(&dir).unwrap();

        // Simulate permission drift, then reopen.
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        GrantStore::open(&dir).unwrap();

        let mode = fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o700,
            "reopening must correct drifted dir permissions"
        );
    }

    #[cfg(unix)]
    #[test]
    fn file_mode_is_reasserted_on_open_of_pre_existing_file() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = TempDir::new().unwrap();
        let store = GrantStore::open(grants_dir(&tmp)).unwrap();
        let grant = sample_grant("grant-1", "octocat", "t");
        store.save(&grant).unwrap();

        let file_path = store.dir().join("grant-1.json");
        // Simulate permission drift on an already-written grant file.
        fs::set_permissions(&file_path, fs::Permissions::from_mode(0o644)).unwrap();

        // A single `get` must correct it back to 0600.
        store.get(&grant.grant_id).unwrap();
        let mode = fs::metadata(&file_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "get() must correct drifted file permissions");

        // Drift again and prove `list` corrects it too.
        fs::set_permissions(&file_path, fs::Permissions::from_mode(0o644)).unwrap();
        store.list().unwrap();
        let mode = fs::metadata(&file_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "list() must correct drifted file permissions");
    }

    #[test]
    fn atomic_write_leaves_no_partial_file_on_simulated_failure() {
        let tmp = TempDir::new().unwrap();
        let store = GrantStore::open(grants_dir(&tmp)).unwrap();

        let original = sample_grant("grant-1", "octocat", "original-token");
        store.save(&original).unwrap();

        let final_path = store.dir().join("grant-1.json");
        let before = fs::read(&final_path).unwrap();

        // Force the write to fail partway through: put a directory where the
        // temp file needs to be created. `create_private_file`'s
        // `create_new` open then fails before a single byte of the new
        // content is written, and the final path is never touched.
        let tmp_path = store.dir().join("grant-1.json.tmp");
        fs::create_dir(&tmp_path).unwrap();

        let mut updated = original.clone();
        updated.github_login = "attacker-controlled-update".to_string();
        // The exact `ErrorKind` a directory-in-the-way produces isn't the
        // point here (it varies: removing a directory via `remove_file`
        // doesn't uniformly map to one kind); what matters is that the save
        // fails and never touches the destination.
        store.save(&updated).unwrap_err();

        // The destination file is untouched: same bytes as before the failed
        // save, and still parses as the *original* grant, not a partial or
        // updated one.
        let after = fs::read(&final_path).unwrap();
        assert_eq!(
            before, after,
            "final file must be untouched by a failed write"
        );
        let reread = store.get(&original.grant_id).unwrap().unwrap();
        assert_eq!(reread.github_login, "octocat");

        // Nothing masquerading as the temp file: it's still the directory we
        // planted, never replaced by a (partial or complete) regular file.
        assert!(tmp_path.is_dir());
    }

    #[test]
    fn rejects_grant_id_unsafe_as_a_filename() {
        let tmp = TempDir::new().unwrap();
        let store = GrantStore::open(grants_dir(&tmp)).unwrap();

        // `GrantId` itself only forbids empty strings, so a traversal-shaped
        // id can reach the store; the store must still refuse it rather than
        // resolve it into a path outside its own directory.
        let traversal_id = GrantId::new("../../etc/passwd").unwrap();
        let mut grant = sample_grant("placeholder", "octocat", "t");
        grant.grant_id = traversal_id.clone();

        let err = store.save(&grant).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(store.get(&traversal_id).is_err());
        assert!(store.delete(&traversal_id).is_err());

        // Nothing escaped the grants directory.
        assert!(!tmp.path().join("etc").exists());
    }
}
